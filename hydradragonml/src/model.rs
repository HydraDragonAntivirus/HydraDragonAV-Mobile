use burn::backend::Autodiff;
use burn::module::Module;
use burn::nn::loss::CrossEntropyLoss;
use burn::nn::{Dropout, DropoutConfig, Linear, LinearConfig, Relu};
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder, Recorder};
use burn::tensor::backend::Backend;
use burn::tensor::{Float, Int, Tensor};
use burn::train::{ClassificationOutput, InferenceStep, TrainOutput, TrainStep};

use crate::features::ENGINE_FEATURE_COUNT;

/// Two-class output (benign / malware), matching the original HydraDragon
/// `MalwareNet`: the classifier emits logits and training uses
/// CrossEntropyLoss; inference applies softmax and reads class 1 (malware).
const NUM_CLASSES: usize = 2;
/// Dropout probability applied after each ReLU during training (0.3 — same as
/// the original HydraDragon trainer). It is a no-op at inference because the
/// scan backend (`NdArray`) has autodiff disabled.
const DROPOUT_PROB: f64 = 0.3;
/// Hidden-layer width, identical to the original HydraDragon `MalwareNet`
/// PE configuration (`input_dim -> 512 -> 256 -> num_classes`).
const HIDDEN_DIM: usize = 512;

/// Pure engine-feature MLP mirroring the original HydraDragon `MalwareNet`
/// architecture: `features -> fc1(512) -> relu -> dropout(0.3) -> fc2(256) ->
/// relu -> dropout(0.3) -> fc3(2)`. No tokenizer/embedding — the classifier
/// only ever sees the content-derived DEX/ELF/manifest feature vector, exactly
/// like the PE/JS trainer.
#[derive(Module, Debug)]
pub struct ApkClassifier<B: Backend> {
    fc1: Linear<B>,
    fc2: Linear<B>,
    fc3: Linear<B>,
    activation: Relu,
    dropout: Dropout,
}

impl<B: Backend> ApkClassifier<B> {
    pub fn new(device: &B::Device) -> Self {
        let fc1 = LinearConfig::new(ENGINE_FEATURE_COUNT, HIDDEN_DIM).init(device);
        let fc2 = LinearConfig::new(HIDDEN_DIM, HIDDEN_DIM / 2).init(device);
        let fc3 = LinearConfig::new(HIDDEN_DIM / 2, NUM_CLASSES).init(device);

        Self {
            fc1,
            fc2,
            fc3,
            activation: Relu::new(),
            dropout: DropoutConfig::new(DROPOUT_PROB).init(),
        }
    }

    pub fn forward_batch(&self, engine: Tensor<B, 2, Float>) -> Tensor<B, 2, Float> {
        let x = self.activation.forward(self.fc1.forward(engine));
        let x = self.dropout.forward(x);
        let x = self.activation.forward(self.fc2.forward(x));
        let x = self.dropout.forward(x);
        self.fc3.forward(x) // [B, 2] logits
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

/// A padded mini-batch fed to one training/validation step: the engine-feature
/// vectors and integer class targets (0 = benign, 1 = malware) consumed by
/// CrossEntropyLoss + the accuracy metric. Produced by the batcher in
/// `hydradragonml-train`.
#[derive(Clone, Debug)]
pub struct ApkBatch<B: Backend> {
    pub engine: Tensor<B, 2, Float>,
    pub targets: Tensor<B, 1, Int>,
}

impl<B: Backend> TrainStep for ApkClassifier<Autodiff<B>> {
    type Input = ApkBatch<Autodiff<B>>;
    type Output = ClassificationOutput<Autodiff<B>>;

    fn step(&self, item: Self::Input) -> TrainOutput<Self::Output> {
        let output = self.forward_batch(item.engine); // [B, 2] logits
        let loss_fn = CrossEntropyLoss::new(None, &output.device());
        let loss = loss_fn.forward(output.clone(), item.targets.clone());
        let grads = loss.clone().backward();
        TrainOutput::new(
            self,
            grads,
            ClassificationOutput::new(loss, output, item.targets),
        )
    }
}

impl<B: Backend> InferenceStep for ApkClassifier<B> {
    type Input = ApkBatch<B>;
    type Output = ClassificationOutput<B>;

    fn step(&self, item: Self::Input) -> Self::Output {
        let output = self.forward_batch(item.engine); // [B, 2] logits
        let loss_fn = CrossEntropyLoss::new(None, &output.device());
        let loss = loss_fn.forward(output.clone(), item.targets.clone());
        ClassificationOutput::new(loss, output, item.targets)
    }
}