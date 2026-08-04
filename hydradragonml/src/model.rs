use burn::backend::Autodiff;
use burn::module::Module;
use burn::nn::{Embedding, EmbeddingConfig, Linear, LinearConfig, Relu, Sigmoid};
use burn::record::{CompactRecorder, Recorder};
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor};
use burn::train::{ClassificationOutput, InferenceStep, TrainOutput, TrainStep};

use crate::features::{EMBED_DIM, ENGINE_FEATURE_COUNT, VOCAB_SIZE};

#[derive(Module, Debug)]
pub struct ApkClassifier<B: Backend> {
    embedding: Embedding<B>,
    linear1: Linear<B>,
    linear2: Linear<B>,
    output: Linear<B>,
    activation: Relu,
    sigmoid: Sigmoid,
}

impl<B: Backend> ApkClassifier<B> {
    pub fn new(device: &B::Device) -> Self {
        let embedding = EmbeddingConfig::new(VOCAB_SIZE, EMBED_DIM).init(device);
        let linear1 = LinearConfig::new(EMBED_DIM + ENGINE_FEATURE_COUNT, 64).init(device);
        let linear2 = LinearConfig::new(64, 32).init(device);
        let output = LinearConfig::new(32, 1).init(device);

        Self {
            embedding,
            linear1,
            linear2,
            output,
            activation: Relu::new(),
            sigmoid: Sigmoid::new(),
        }
    }

    pub fn forward_batch(
        &self,
        tokens: Tensor<B, 2, Int>,
        engine: Tensor<B, 2, Float>,
    ) -> Tensor<B, 2, Float> {
        let [batch, seq_len] = tokens.dims();
        let tok_emb = self.embedding.forward(tokens.clone()); // [B, L, EMBED_DIM]

        // Masked mean-pool: average only over non-padding positions (token id != 0).
        // mask: [B, L, 1] — 1.0 where token != 0, 0.0 for padding.
        let zero = Tensor::<B, 2, Int>::zeros([batch, seq_len], &tok_emb.device());
        let mask = tokens
            .not_equal(zero) // [B, L] bool
            .float() // [B, L] f32
            .unsqueeze_dim(2); // [B, L, 1]

        let masked = tok_emb * mask.clone(); // zero out padding rows
        let sum = masked.sum_dim(1).squeeze_dim(1); // [B, EMBED_DIM]
        // clamp denominator to 1 to avoid div-by-zero on all-padding sequences
        let counts = mask.sum_dim(1).squeeze_dim(1).clamp(1.0, f32::MAX); // [B, 1]
        let tok_pooled = sum / counts; // [B, EMBED_DIM]

        let combined = Tensor::cat(vec![tok_pooled, engine], 1);
        let x = self.linear1.forward(combined);
        let x = self.activation.forward(x);
        let x = self.linear2.forward(x);
        let x = self.activation.forward(x);
        let x = self.output.forward(x);
        self.sigmoid.forward(x)
    }

    pub fn forward(
        &self,
        tokens: Tensor<B, 1, Int>,
        engine: Tensor<B, 1, Float>,
    ) -> Tensor<B, 1, Float> {
        let len = tokens.dims()[0];
        let tok_batch = tokens.reshape([1, len]);
        let eng_len = engine.dims()[0];
        let eng_batch = engine.reshape([1, eng_len]);
        let out_batch = self.forward_batch(tok_batch, eng_batch);
        out_batch.reshape([1])
    }

    pub fn save_weights(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let recorder = CompactRecorder::new();
        let record = self.clone().into_record();
        recorder.record(record, path.into())?;
        Ok(())
    }

    pub fn load_weights(
        path: &str,
        device: &B::Device,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let recorder = CompactRecorder::new();
        let record = recorder.load(path.into(), device)?;
        Ok(Self::new(device).load_record(record))
    }
}

/// A padded mini-batch fed to one training/validation step: token ids, engine
/// features, float labels (for BCE) and integer class targets (for the
/// accuracy metric). Produced by the batcher in `hydradragonml-train`.
#[derive(Clone, Debug)]
pub struct ApkBatch<B: Backend> {
    pub tokens: Tensor<B, 2, Int>,
    pub engine: Tensor<B, 2, Float>,
    pub labels: Tensor<B, 2, Float>,
    pub targets: Tensor<B, 1, Int>,
}

/// Binary cross-entropy over the model's own sigmoid output (the model already
/// ends in `sigmoid`, so this operates on probabilities directly). Returns a
/// rank-1 tensor holding the mean loss over the batch.
fn bce_loss<B: Backend>(pred: Tensor<B, 2, Float>, labels: Tensor<B, 2, Float>) -> Tensor<B, 1> {
    let eps = 1e-7;
    let p = pred.clamp(eps, 1.0 - eps);
    let one = Tensor::ones_like(&p);
    let logp = p.clone().log();
    let log1p = (one.clone() - p).log();
    let per_example = labels.clone() * logp + (one - labels) * log1p;
    -per_example.mean()
}

/// Turns the single sigmoid output `[b, 1]` into two-class probabilities
/// `[b, 2]` (`[1-p, p]`) so the classification metrics argmax correctly.
fn to_two_class<B: Backend>(pred: Tensor<B, 2, Float>) -> Tensor<B, 2, Float> {
    let one_minus = Tensor::ones_like(&pred) - pred.clone();
    Tensor::cat(vec![one_minus, pred], 1)
}

impl<B: Backend> TrainStep for ApkClassifier<Autodiff<B>> {
    type Input = ApkBatch<Autodiff<B>>;
    type Output = ClassificationOutput<Autodiff<B>>;

    fn step(&self, item: Self::Input) -> TrainOutput<Self::Output> {
        let pred = self.forward_batch(item.tokens, item.engine);
        let loss = bce_loss(pred.clone(), item.labels);
        let grads = loss.clone().backward();
        TrainOutput::new(
            self,
            grads,
            ClassificationOutput::new(loss, to_two_class(pred), item.targets),
        )
    }
}

impl<B: Backend> InferenceStep for ApkClassifier<B> {
    type Input = ApkBatch<B>;
    type Output = ClassificationOutput<B>;

    fn step(&self, item: Self::Input) -> Self::Output {
        let pred = self.forward_batch(item.tokens, item.engine);
        let loss = bce_loss(pred.clone(), item.labels);
        ClassificationOutput::new(loss, to_two_class(pred), item.targets)
    }
}
