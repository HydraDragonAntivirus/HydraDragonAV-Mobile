use crate::features;
use burn::module::Module;
use burn::nn::{Embedding, EmbeddingConfig, Linear, LinearConfig};
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder, Recorder};
use burn::tensor::activation::{relu, sigmoid};
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor};

pub const VOCAB_SIZE: usize = 20000;
pub const EMBED_DIM: usize = 64;
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
        Self {
            embedding: EmbeddingConfig::new(VOCAB_SIZE, EMBED_DIM).init(device),
            fc_text: LinearConfig::new(EMBED_DIM, HIDDEN_DIM).init(device),
            fc_engine: LinearConfig::new(features::ENGINE_FEATURE_COUNT, HIDDEN_DIM).init(device),
            fc_combine: LinearConfig::new(HIDDEN_DIM * 2, HIDDEN_DIM).init(device),
            fc_out: LinearConfig::new(HIDDEN_DIM, 1).init(device),
        }
    }

    pub fn forward(
        &self,
        tokens: Tensor<B, 1, Int>,
        engine_features: Tensor<B, 1, Float>,
    ) -> Tensor<B, 2, Float> {
        self.forward_batch(tokens.unsqueeze::<2>(), engine_features.unsqueeze::<2>())
    }

    /// Batched forward pass. `tokens` is `[batch, token_len]` (padded to a
    /// common length) and `engine_features` is `[batch, ENGINE_FEATURE_COUNT]`.
    /// Returns `[batch, 1]` sigmoid probabilities.
    pub fn forward_batch(
        &self,
        tokens: Tensor<B, 2, Int>,
        engine_features: Tensor<B, 2, Float>,
    ) -> Tensor<B, 2, Float> {
        let emb = self.embedding.forward(tokens);
        let pooled = emb.mean_dim(1).squeeze_dim::<2>(1); // [batch, EMBED_DIM]
        let text_h = relu(self.fc_text.forward(pooled));
        let engine_h = relu(self.fc_engine.forward(engine_features));
        let combined = Tensor::cat(vec![text_h, engine_h], 1);
        sigmoid(self.fc_out.forward(relu(self.fc_combine.forward(combined))))
    }

    pub fn save_weights(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        NamedMpkFileRecorder::<FullPrecisionSettings>::new()
            .record(self.clone().into_record(), path.into())?;
        Ok(())
    }

    pub fn load_weights(path: &str, device: &B::Device) -> Result<Self, Box<dyn std::error::Error>> {
        let record = NamedMpkFileRecorder::<FullPrecisionSettings>::new()
            .load(path.into(), device)?;
        Ok(Self::new(device).load_record(record))
    }
}
