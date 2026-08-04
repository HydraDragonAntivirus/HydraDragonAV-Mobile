use burn::module::Module;
use burn::nn::{Embedding, EmbeddingConfig, Linear, LinearConfig, Relu, Sigmoid};
use burn::record::{CompactRecorder, Recorder};
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor};

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
        let tok_emb = self.embedding.forward(tokens); // [B, L, EMBED_DIM]
        let tok_pooled = tok_emb.mean_dim(1).squeeze(); // [B, EMBED_DIM]

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

    pub fn load_weights(path: &str, device: &B::Device) -> Result<Self, Box<dyn std::error::Error>> {
        let recorder = CompactRecorder::new();
        let record = recorder.load(path.into(), device)?;
        Ok(Self::new(device).load_record(record))
    }
}
