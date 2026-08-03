//! Structural + text-token APK classifier.
//!
//! Architecture (see README):
//! - text branch: `Embedding(VOCAB_SIZE → EMBED_DIM) → mean-pool → Linear(EMBED_DIM → HIDDEN) → ReLU`
//! - engine branch: `Linear(ENGINE_FEATURE_COUNT → HIDDEN) → ReLU`
//! - fused: `concat → Linear(2*HIDDEN → HIDDEN) → ReLU → Linear(HIDDEN → 1) → Sigmoid`

use crate::features;
use burn::module::Module;
use burn::nn::{Embedding, EmbeddingConfig, Linear, LinearConfig};
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder, Recorder};
use burn::tensor::activation::{relu, sigmoid};
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor};

pub const HIDDEN_DIM: usize = 32;

#[derive(Module, Debug)]
pub struct ApkClassifier<B: Backend> {
    embedding: Embedding<B>,
    fc_text: Linear<B>,
    fc_engine: Linear<B>,
    fc_combine: Linear<B>,
    fc_out: Linear<B>,
}

impl<B: Backend> ApkClassifier<B> {
    pub fn new(device: &B::Device) -> Self {
        let embed_dim = features::EMBED_DIM;
        Self {
            embedding: EmbeddingConfig::new(features::VOCAB_SIZE, embed_dim).init(device),
            fc_text: LinearConfig::new(embed_dim, HIDDEN_DIM).init(device),
            fc_engine: LinearConfig::new(features::ENGINE_FEATURE_COUNT, HIDDEN_DIM).init(device),
            fc_combine: LinearConfig::new(HIDDEN_DIM * 2, HIDDEN_DIM).init(device),
            fc_out: LinearConfig::new(HIDDEN_DIM, 1).init(device),
        }
    }

    /// Single-sample inference over one token sequence (mean-pooled) fused with
    /// one engine-feature vector.
    pub fn forward(
        &self,
        token_ids: Tensor<B, 1, Int>,
        engine_features: Tensor<B, 1, Float>,
    ) -> Tensor<B, 2, Float> {
        self.forward_batch(
            token_ids.unsqueeze::<2>(),
            engine_features.unsqueeze::<2>(),
        )
    }

    /// Batched inference. `token_ids` is `[batch, seq_len]` (already padded to
    /// the batch's max length); the text branch mean-pools each row. Each row
    /// of `engine_features` is one APK's 18 normalized engine features.
/// Batched inference. `token_ids` is `[batch, seq_len]` (already padded to
/// the batch's max length); the text branch mean-pools each row. Each row
/// of `engine_features` is one APK's 18 normalized engine features.
pub fn forward_batch(
        &self,
        token_ids: Tensor<B, 2, Int>,
        engine_features: Tensor<B, 2, Float>,
    ) -> Tensor<B, 2, Float> {
        // id 0 (UNK/padding) is excluded from the text signal.
        let tok_float = token_ids.clone().float();
        let valid = tok_float.greater_elem(0.0_f32); // [n, seq_len] Bool
        let valid_f: Tensor<B, 3, Float> = valid.unsqueeze_dim::<3>(2).float(); // [n, seq_len, 1]

        let embedded = self.embedding.forward(token_ids); // [n, seq_len, embed_dim]
        let embedded = embedded * valid_f.clone(); // zero out padding positions

        let summed = embedded.sum_dim(1); // [n, 1, embed_dim]
        let summed = summed.squeeze_dim::<2>(1); // [n, embed_dim]
        let denom = valid_f.sum_dim(1).squeeze_dim::<2>(1).clamp_min(1.0_f32); // [n, 1]
        let pooled = summed / denom; // [n, embed_dim]

        let text = relu(self.fc_text.forward(pooled)); // [n, hidden]
        let engine = relu(self.fc_engine.forward(engine_features)); // [n, hidden]
        let fused_input = Tensor::cat(vec![text, engine], 1); // [n, 2*hidden]
        let fused = relu(self.fc_combine.forward(fused_input));
        sigmoid(self.fc_out.forward(fused))
    }

    pub fn save_weights(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        NamedMpkFileRecorder::<FullPrecisionSettings>::new()
            .record(self.clone().into_record(), path.into())?;
        Ok(())
    }

    pub fn load_weights(
        path: &str,
        device: &B::Device,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let record =
            NamedMpkFileRecorder::<FullPrecisionSettings>::new().load(path.into(), device)?;
        Ok(Self::new(device).load_record(record))
    }
}