//! HydraDragon one-class APK malware model.
//!
//! Pipeline: [`features`] turns an APK into a token set + dense vector;
//! [`minhash`] does near-duplicate / variant matching (the generalising
//! successor to the per-file YARA set); [`iforest`] gives a one-class
//! "malware-likeness" anomaly score. Trained on malware only — no benign set.
//!
//! A scan is flagged malicious when EITHER signal fires:
//!   * MinHash Jaccard to some known sample >= `jaccard_threshold`, or
//!   * Isolation Forest anomaly score <= `anomaly_threshold`.
//!
//! Because the deployment whitelists known-good apps upstream, thresholds are
//! tuned for recall, not precision.

pub mod features;
pub mod iforest;
pub mod minhash;

use serde::{Deserialize, Serialize};

use features::ApkFeatures;
use iforest::IForest;
use minhash::LshIndex;

/// Default: flag as a variant when >= this fraction of MinHash slots match.
pub const DEFAULT_JACCARD_THRESHOLD: f32 = 0.55;
/// Default Isolation Forest training params.
pub const DEFAULT_N_TREES: usize = 150;
pub const DEFAULT_SAMPLE_SIZE: usize = 256;
/// Anomaly threshold is learned as this percentile of training scores.
pub const DEFAULT_ANOMALY_PERCENTILE: f64 = 0.97;

#[derive(Serialize, Deserialize)]
pub struct Model {
    /// MinHash signature per training sample.
    signatures: Vec<Vec<u64>>,
    /// Optional human label (sha/filename) per training sample, for reporting.
    labels: Vec<String>,
    iforest: IForest,
    jaccard_threshold: f32,
    anomaly_threshold: f64,

    #[serde(skip)]
    lsh: Option<LshIndex>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub malicious: bool,
    pub best_jaccard: f32,
    /// Label of the closest known sample (if any candidate was found).
    pub nearest: Option<String>,
    pub anomaly_score: f64,
    /// Which signal(s) fired.
    pub by_minhash: bool,
    pub by_iforest: bool,
}

/// One training sample: its features plus a label for reporting.
pub struct TrainSample {
    pub label: String,
    pub features: ApkFeatures,
}

impl Model {
    /// Train from extracted features. Computes signatures, builds the LSH
    /// index, trains the forest, and learns the anomaly threshold from the
    /// training-score distribution.
    pub fn train(
        samples: Vec<TrainSample>,
        jaccard_threshold: f32,
        n_trees: usize,
        sample_size: usize,
        anomaly_percentile: f64,
        seed: u64,
    ) -> Model {
        let signatures: Vec<Vec<u64>> = samples
            .iter()
            .map(|s| minhash::signature(&s.features.tokens))
            .collect();
        let labels: Vec<String> = samples.iter().map(|s| s.label.clone()).collect();
        let dense: Vec<Vec<f32>> = samples.iter().map(|s| s.features.dense.clone()).collect();

        let iforest = IForest::train(&dense, n_trees, sample_size, seed);

        // Learn anomaly threshold = given percentile of training scores, so that
        // an unseen APK at least as malware-like as that fraction is flagged.
        let mut scores: Vec<f64> = dense.iter().map(|d| iforest.score(d)).collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let k = ((scores.len() as f64) * anomaly_percentile).floor() as usize;
        let anomaly_threshold = scores.get(k.min(scores.len().saturating_sub(1))).copied().unwrap_or(0.5);

        let lsh = LshIndex::build(&signatures);

        Model {
            signatures,
            labels,
            iforest,
            jaccard_threshold,
            anomaly_threshold,
            lsh: Some(lsh),
        }
    }

    /// Rebuild the (non-serialised) LSH index after loading.
    fn ensure_index(&mut self) {
        if self.lsh.is_none() {
            self.lsh = Some(LshIndex::build(&self.signatures));
        }
    }

    /// Binary (bincode-next) model.
    pub fn save_bin(&self, path: &std::path::Path) -> std::io::Result<()> {
        let bytes = bincode_next::serde::encode_to_vec(self, bincode_next::config::standard())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, bytes)
    }

    pub fn load_bin(path: &std::path::Path) -> std::io::Result<Model> {
        let bytes = std::fs::read(path)?;
        let (mut model, _): (Model, usize) =
            bincode_next::serde::decode_from_slice(&bytes, bincode_next::config::standard())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        model.ensure_index();
        Ok(model)
    }

    /// Score raw APK bytes.
    pub fn scan(&self, apk: &[u8]) -> Option<ScanResult> {
        let feats = features::extract(apk)?;
        Some(self.scan_features(&feats))
    }

    pub fn scan_features(&self, feats: &ApkFeatures) -> ScanResult {
        let sig = minhash::signature(&feats.tokens);

        let mut best_jaccard = 0.0f32;
        let mut nearest: Option<String> = None;
        if let Some(lsh) = &self.lsh {
            for id in lsh.candidates(&sig) {
                let j = minhash::jaccard(&sig, &self.signatures[id as usize]);
                if j > best_jaccard {
                    best_jaccard = j;
                    nearest = self.labels.get(id as usize).cloned();
                }
            }
        }

        let anomaly_score = self.iforest.score(&feats.dense);

        let by_minhash = best_jaccard >= self.jaccard_threshold;
        let by_iforest = anomaly_score <= self.anomaly_threshold;

        ScanResult {
            malicious: by_minhash || by_iforest,
            best_jaccard,
            nearest,
            anomaly_score,
            by_minhash,
            by_iforest,
        }
    }

    pub fn anomaly_threshold(&self) -> f64 {
        self.anomaly_threshold
    }
    pub fn jaccard_threshold(&self) -> f32 {
        self.jaccard_threshold
    }
    pub fn len(&self) -> usize {
        self.signatures.len()
    }
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}
