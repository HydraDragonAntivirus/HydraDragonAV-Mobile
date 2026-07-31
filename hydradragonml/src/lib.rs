pub mod features;
pub mod model;

use burn::tensor::{Float, Int, Tensor};
use burn_wgpu::{Wgpu, WgpuDevice};

pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.95;
pub const SUSPICIOUS_THRESHOLD: f32 = 0.90;

type B = Wgpu;

pub struct Model {
    classifier: model::ApkClassifier<B>,
    tokenizer: features::Tokenizer,
    confidence_threshold: f32,
    device: WgpuDevice,
}

#[derive(Debug)]
pub struct ScanResult {
    pub malicious: bool,
    pub suspicious: bool,
    pub confidence: f32,
}

impl Model {
    pub fn load(
        model_bytes: &[u8],
        vocab_bytes: &[u8],
        device: WgpuDevice,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tokenizer = features::Tokenizer::load_json(vocab_bytes)
            .ok_or("failed to parse vocab.json")?;
        let tmp = tempfile::Builder::new().suffix(".mpk").tempfile()?;
        std::fs::write(tmp.path(), model_bytes)?;
        let classifier = model::ApkClassifier::load_weights(
            tmp.path().to_str().ok_or("invalid path")?,
            &device,
        )?;
        Ok(Model {
            classifier,
            tokenizer,
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            device,
        })
    }

    pub fn load_from_path(
        model_path: &str,
        vocab_bytes: &[u8],
        device: WgpuDevice,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tokenizer = features::Tokenizer::load_json(vocab_bytes)
            .ok_or("failed to parse vocab.json")?;
        let classifier = model::ApkClassifier::load_weights(model_path, &device)?;
        Ok(Model {
            classifier,
            tokenizer,
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            device,
        })
    }

    pub fn set_threshold(&mut self, t: f32) {
        self.confidence_threshold = t.clamp(0.0, 1.0);
    }

    pub fn scan(&self, apk: &[u8]) -> Option<ScanResult> {
        self.scan_with_features(apk, &features::EngineFeatures::default())
    }

    pub fn scan_with_features(
        &self,
        apk: &[u8],
        engine_feats: &features::EngineFeatures,
    ) -> Option<ScanResult> {
        let indices = self.tokenizer.tokenize(apk)?;
        let token_tensor = Tensor::<B, 1, Int>::from_data(indices.as_slice(), &self.device);
        let feat_vec = engine_feats.to_vec();
        let feat_tensor = Tensor::<B, 1, Float>::from_data(feat_vec.as_slice(), &self.device);
        let output = self.classifier.forward(token_tensor, feat_tensor);
        let confidence = output.into_scalar().clamp(0.0, 1.0);
        let malicious = confidence >= self.confidence_threshold;
        let suspicious = !malicious && confidence >= SUSPICIOUS_THRESHOLD;
        Some(ScanResult { malicious, suspicious, confidence })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_test_apk() {
        let bytes = std::fs::read("../com.ttech.android.onlineislem_base.apk")
            .expect("APK not found");
        let mut vocab = std::collections::HashMap::new();
        vocab.insert("test".to_string(), 1);
        let tok = features::Tokenizer::new(vocab);
        let result = tok.tokenize(&bytes);
        assert!(result.is_some());
        let ids = result.unwrap();
        assert!(!ids.is_empty());
    }

    #[test]
    fn load_vocab_from_json() {
        let json = br#"{"<UNK>": 0, "hello": 1, "world": 2}"#;
        let tok = features::Tokenizer::load_json(json).expect("should parse");
        let ids = tok.tokenize(b"hello world");
        assert!(ids.is_none());
    }

    #[test]
    fn engine_features_normalized() {
        let feats = features::EngineFeatures {
            dex_class_count: 1000.0,
            dex_api_call_count: 3000.0,
            manifest_dangerous_permissions: 15.0,
            manifest_target_sdk: 33.0,
            is_testkey: 1.0,
            benign_jaccard: 0.9,
            ..Default::default()
        };
        let v = feats.to_vec();
        assert_eq!(v.len(), features::ENGINE_FEATURE_COUNT);
        assert!(v.iter().all(|&x| (0.0..=1.0).contains(&x)));
        assert!((v[0] - 0.2).abs() < 0.01);
        assert!((v[2] - 0.6).abs() < 0.01);
    }

    #[test]
    fn all_features_normalized() {
        let feats = features::EngineFeatures::default();
        let v = feats.to_vec();
        assert_eq!(v.len(), features::ENGINE_FEATURE_COUNT);
        assert!(v.iter().all(|&x| (0.0..=1.0).contains(&x)));
    }
}
