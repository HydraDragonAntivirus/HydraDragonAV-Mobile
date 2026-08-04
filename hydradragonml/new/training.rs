//! Burn-train plumbing for `ApkClassifier`.
//!
//! This lives in the library crate (not the `hydradragonml-train` binary)
//! because of Rust's orphan rule: `TrainStep`/`InferenceStep` are defined in
//! `burn_train`, and `ApkClassifier` is defined here, so the impls below can
//! only be written in a crate that owns at least one of those two types —
//! which is this crate, not the binary.
//!
//! Mirrors the shape of Burn's own `simple-regression` example
//! (`RegressionModel` + `RegressionOutput` + manual BCE instead of MSE),
//! adapted to `ApkClassifier`'s existing `forward_batch` API.

use crate::features::ENGINE_FEATURE_COUNT;
use crate::model::ApkClassifier;

use burn::data::dataloader::batcher::Batcher;
use burn::tensor::backend::{AutodiffBackend, Backend};
use burn::tensor::{Float, Int, Tensor, TensorData};
use burn::train::{InferenceStep, RegressionOutput, TrainOutput, TrainStep};

/// One training example: tokenized APK content, the 18 real
/// `EngineFeatures::to_vec()` values, and a `1.0` (malware) / `0.0`
/// (benign) label.
#[derive(Clone, Debug)]
pub struct ApkItem {
    pub tokens: Vec<i64>,
    pub engine: Vec<f32>,
    pub label: f32,
}

/// Stateless batcher: pads token sequences to the batch's longest sequence
/// (short sequences padded with vocab id `0`, i.e. `<UNK>`) and stacks the
/// fixed-size engine-feature vectors and labels directly.
///
/// Note: `ApkClassifier::forward_batch` mean-pools the *entire* padded
/// embedding row with no attention mask, so padding slightly biases the
/// pooled vector of short sequences toward the `<UNK>` embedding. Fixing
/// this properly would mean adding mask support to `forward_batch` itself
/// (out of scope here — this batcher just matches the pooling `model.rs`
/// already implements).
#[derive(Clone, Debug, Default)]
pub struct ApkBatcher;

#[derive(Clone, Debug)]
pub struct ApkBatch<B: Backend> {
    pub tokens: Tensor<B, 2, Int>,
    pub engine: Tensor<B, 2, Float>,
    pub targets: Tensor<B, 2, Float>,
}

impl<B: Backend> Batcher<B, ApkItem, ApkBatch<B>> for ApkBatcher {
    fn batch(&self, items: Vec<ApkItem>, device: &B::Device) -> ApkBatch<B> {
        let max_len = items
            .iter()
            .map(|item| item.tokens.len())
            .max()
            .unwrap_or(1)
            .max(1);

        let mut token_flat = Vec::with_capacity(items.len() * max_len);
        for item in &items {
            for i in 0..max_len {
                token_flat.push(*item.tokens.get(i).unwrap_or(&0));
            }
        }
        let tokens = Tensor::<B, 2, Int>::from_data(
            TensorData::new(token_flat, [items.len(), max_len]),
            device,
        );

        let mut engine_flat = Vec::with_capacity(items.len() * ENGINE_FEATURE_COUNT);
        for item in &items {
            engine_flat.extend_from_slice(&item.engine);
        }
        let engine = Tensor::<B, 2, Float>::from_data(
            TensorData::new(engine_flat, [items.len(), ENGINE_FEATURE_COUNT]),
            device,
        );

        let labels: Vec<f32> = items.iter().map(|item| item.label).collect();
        let targets =
            Tensor::<B, 2, Float>::from_data(TensorData::new(labels, [items.len(), 1]), device);

        ApkBatch {
            tokens,
            engine,
            targets,
        }
    }
}

/// Binary cross-entropy computed directly on the model's own sigmoid
/// output (the model already ends in `sigmoid`, so this operates on
/// probabilities rather than logits — unlike `MseLoss`/`CrossEntropyLoss`,
/// Burn has no built-in "BCE on probabilities" loss, so this is written by
/// hand).
fn bce_loss<B: Backend>(pred: Tensor<B, 2, Float>, target: Tensor<B, 2, Float>) -> Tensor<B, 1> {
    let eps = 1e-7;
    let p = pred.clamp(eps, 1.0 - eps);
    let ones = p.ones_like();
    let one_minus_target = ones.clone() - target.clone();
    let one_minus_p = ones - p.clone();
    let per_example = target * p.log() + one_minus_target * one_minus_p.log();
    -per_example.mean()
}

fn forward_step<B: Backend>(model: &ApkClassifier<B>, batch: ApkBatch<B>) -> RegressionOutput<B> {
    let output = model.forward_batch(batch.tokens, batch.engine);
    let loss = bce_loss(output.clone(), batch.targets.clone());
    RegressionOutput::new(loss, output, batch.targets)
}

impl<B: AutodiffBackend> TrainStep for ApkClassifier<B> {
    type Input = ApkBatch<B>;
    type Output = RegressionOutput<B>;

    fn step(&self, batch: ApkBatch<B>) -> TrainOutput<RegressionOutput<B>> {
        let item = forward_step(self, batch);
        TrainOutput::new(self, item.loss.backward(), item)
    }
}

impl<B: Backend> InferenceStep for ApkClassifier<B> {
    type Input = ApkBatch<B>;
    type Output = RegressionOutput<B>;

    fn step(&self, batch: ApkBatch<B>) -> RegressionOutput<B> {
        forward_step(self, batch)
    }
}
