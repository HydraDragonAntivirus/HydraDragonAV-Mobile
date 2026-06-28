//! Isolation Forest — one-class anomaly scoring over the dense feature vectors.
//!
//! Trained purely on malware: a new APK that *resembles* the training corpus
//! gets a LOW anomaly score (it is "in distribution" for malware), while an
//! unrelated APK scores HIGH. Detection therefore fires when the score sits at
//! or below a learned percentile of the training scores.

use serde::{Deserialize, Serialize};

const EULER_GAMMA: f64 = 0.577_215_664_901_532_9;

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn next_f64(state: &mut u64) -> f64 {
    // 53-bit mantissa in [0, 1).
    (splitmix64(state) >> 11) as f64 / (1u64 << 53) as f64
}

/// Average external path length adjustment for a subsample of size `n`.
fn c_factor(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let n = n as f64;
    2.0 * ((n - 1.0).ln() + EULER_GAMMA) - 2.0 * (n - 1.0) / n
}

#[derive(Serialize, Deserialize)]
enum Node {
    Internal {
        feature: usize,
        split: f32,
        left: u32,
        right: u32,
    },
    External {
        size: usize,
    },
}

#[derive(Serialize, Deserialize)]
struct Tree {
    nodes: Vec<Node>,
}

#[derive(Serialize, Deserialize)]
pub struct IForest {
    trees: Vec<Tree>,
    sample_size: usize,
}

struct Builder<'a> {
    data: &'a [Vec<f32>],
    nodes: Vec<Node>,
    height_limit: usize,
    rng: u64,
}

impl<'a> Builder<'a> {
    fn build(&mut self, idx: &[u32], depth: usize) -> u32 {
        let id = self.nodes.len() as u32;
        if depth >= self.height_limit || idx.len() <= 1 {
            self.nodes.push(Node::External { size: idx.len() });
            return id;
        }
        let dim = self.data[0].len();
        let feature = (splitmix64(&mut self.rng) as usize) % dim;

        let mut min = f32::INFINITY;
        let mut max = f32::NEG_INFINITY;
        for &i in idx {
            let v = self.data[i as usize][feature];
            min = min.min(v);
            max = max.max(v);
        }
        if (max - min).abs() < f32::EPSILON {
            self.nodes.push(Node::External { size: idx.len() });
            return id;
        }
        let split = min + (max - min) * next_f64(&mut self.rng) as f32;

        let (mut left_idx, mut right_idx) = (Vec::new(), Vec::new());
        for &i in idx {
            if self.data[i as usize][feature] < split {
                left_idx.push(i);
            } else {
                right_idx.push(i);
            }
        }

        // Reserve this node's slot, then fill after children exist.
        self.nodes.push(Node::External { size: idx.len() });
        let left = self.build(&left_idx, depth + 1);
        let right = self.build(&right_idx, depth + 1);
        self.nodes[id as usize] = Node::Internal {
            feature,
            split,
            left,
            right,
        };
        id
    }
}

impl IForest {
    /// Train `n_trees` on subsamples of `sample_size` rows each.
    pub fn train(data: &[Vec<f32>], n_trees: usize, sample_size: usize, seed: u64) -> IForest {
        let n = data.len();
        let psi = sample_size.min(n).max(2);
        let height_limit = (psi as f64).log2().ceil() as usize;
        let mut rng = seed;
        let mut trees = Vec::with_capacity(n_trees);

        for _ in 0..n_trees {
            // Sample `psi` distinct-ish row indices (sampling with replacement
            // is acceptable for iForest and keeps this cheap).
            let mut idx = Vec::with_capacity(psi);
            for _ in 0..psi {
                idx.push((splitmix64(&mut rng) as usize % n) as u32);
            }
            let mut builder = Builder {
                data,
                nodes: Vec::new(),
                height_limit,
                rng,
            };
            builder.build(&idx, 0);
            rng = builder.rng;
            trees.push(Tree {
                nodes: builder.nodes,
            });
        }

        IForest {
            trees,
            sample_size: psi,
        }
    }

    fn path_length(tree: &Tree, x: &[f32]) -> f64 {
        let mut id = 0u32;
        let mut depth = 0.0;
        loop {
            match &tree.nodes[id as usize] {
                Node::External { size } => return depth + c_factor(*size),
                Node::Internal {
                    feature,
                    split,
                    left,
                    right,
                } => {
                    depth += 1.0;
                    id = if x[*feature] < *split { *left } else { *right };
                }
            }
        }
    }

    /// Anomaly score in `(0, 1)`. Higher = more anomalous (less malware-like).
    pub fn score(&self, x: &[f32]) -> f64 {
        if self.trees.is_empty() {
            return 0.5;
        }
        let avg: f64 = self
            .trees
            .iter()
            .map(|t| Self::path_length(t, x))
            .sum::<f64>()
            / self.trees.len() as f64;
        let c = c_factor(self.sample_size);
        if c <= 0.0 {
            return 0.5;
        }
        2f64.powf(-avg / c)
    }
}
