use burn::module::Module;
use burn::nn::{Embedding, EmbeddingConfig, Linear, LinearConfig, Relu};
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder, Recorder};
use burn::tensor::activation::sigmoid;
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor};

use crate::features::{EMBED_DIM, ENGINE_FEATURE_COUNT, VOCAB_SIZE};

/// Text-branch hidden width: mean-pooled embedding vector is projected down
/// to this size before being concatenated with the engine branch.
const TEXT_HIDDEN: usize = 32;
/// Engine-branch hidden width (over the 11 corpus-normalized engine
/// features).
const ENGINE_HIDDEN: usize = 32;
/// Hidden width of the fused head (over the concatenated text+engine vector).
const FUSED_HIDDEN: usize = 32;

/// Mean-pooled-token-embedding + engine-feature MLP classifier described in
/// the crate README:
///
/// - text branch: `Embedding(VOCAB_SIZE -> EMBED_DIM) -> mean-pool over
///   sequence -> Linear(EMBED_DIM -> 32) -> ReLU`
/// - engine branch: `Linear(ENGINE_FEATURE_COUNT -> 32) -> ReLU`
/// - fused head: `cat([text, engine]) -> Linear(64 -> 32) -> ReLU ->
///   Linear(32 -> 1) -> Sigmoid`
///
/// The output is a single probability `p(malware)` in `[0, 1]`; the
/// `training.rs` glue computes binary cross-entropy directly on this sigmoid
/// output, so no logits-to-probability conversion is done here.
#[derive(Module, Debug)]
pub struct ApkClassifier<B: Backend> {
    embedding: Embedding<B>,
    fc_text: Linear<B>,
    fc_engine: Linear<B>,
    fc_fused: Linear<B>,
    fc_out: Linear<B>,
    activation: Relu,
}

impl<B: Backend> ApkClassifier<B> {
    pub fn new(device: &B::Device) -> Self {
        Self {
            embedding: EmbeddingConfig::new(VOCAB_SIZE, EMBED_DIM).init(device),
            fc_text: LinearConfig::new(EMBED_DIM, TEXT_HIDDEN).init(device),
            fc_engine: LinearConfig::new(ENGINE_FEATURE_COUNT, ENGINE_HIDDEN).init(device),
            fc_fused: LinearConfig::new(TEXT_HIDDEN + ENGINE_HIDDEN, FUSED_HIDDEN).init(device),
            fc_out: LinearConfig::new(FUSED_HIDDEN, 1).init(device),
            activation: Relu::new(),
        }
    }

    /// Batch forward used by training/validation and by the single-sample
    /// path below. `tokens` is the padded `[B, seq]` id tensor, `engine` the
    /// stacked `[B, 11]` percentile-normalized feature tensor; returns
    /// `[B, 1]` sigmoid probabilities.
    pub fn forward_batch(
        &self,
        tokens: Tensor<B, 2, Int>,
        engine: Tensor<B, 2, Float>,
    ) -> Tensor<B, 2, Float> {
        let pooled = self
            .embedding
            .forward(tokens)
            .mean_dim(1)
            .squeeze_dim::<2>(1); // [B, EMBED_DIM]
        let text = self.activation.forward(self.fc_text.forward(pooled)); // [B, 32]
        let eng = self.activation.forward(self.fc_engine.forward(engine)); // [B, 32]
        let fused = Tensor::cat(vec![text, eng], 1); // [B, 64]
        let out = self.fc_out.forward(self.activation.forward(self.fc_fused.forward(fused)));
        sigmoid(out) // [B, 1]
    }

    /// Single-sample inference used by `Model::scan_with_features`: expects a
    /// rank-1 token sequence and a rank-1 feature vector and returns a
    /// rank-1 tensor of one probability.
    pub fn forward(
        &self,
        tokens: Tensor<B, 1, Int>,
        engine: Tensor<B, 1, Float>,
    ) -> Tensor<B, 1, Float> {
        let out = self.forward_batch(tokens.unsqueeze::<2>(), engine.unsqueeze::<2>());
        out.squeeze_dim::<1>(0)
    }

    pub fn save_weights(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let recorder = NamedMpkFileRecorder::<FullPrecisionSettings>::new();
        let record = self.clone().into_record();
        recorder.record(record, path.into())?;
        Ok(())
    }

    pub fn load_weights(
        path: &str,
        device: &B::Device,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let recorder = NamedMpkFileRecorder::<FullPrecisionSettings>::new();
        let record = recorder.load(path.into(), device)?;
        Ok(Self::new(device).load_record(record))
    }
}
