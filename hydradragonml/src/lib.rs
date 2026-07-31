pub mod features;

use std::io::Cursor;

use tract_onnx::prelude::*;

pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.95;
pub const SUSPICIOUS_THRESHOLD: f32 = 0.90;

pub struct Model {
    plan: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    tokenizer: features::Tokenizer,
    confidence_threshold: f32,
}

#[derive(Debug)]
pub struct ScanResult {
    pub malicious: bool,
    pub suspicious: bool,
    pub confidence: f32,
}

impl Model {
    pub fn load(model_bytes: &[u8], vocab_bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let tokenizer = features::Tokenizer::load_json(vocab_bytes)
            .ok_or("failed to parse vocab.json")?;
        let tract_model = onnx()
            .model_for_read(&mut Cursor::new(model_bytes))?
            .with_input_fact(0, InferenceFact::dt_shape(i64::datum_type(), tvec!(0)))?
            .into_optimized()?
            .into_runnable()?;
        Ok(Model {
            plan: tract_model,
            tokenizer,
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
        })
    }

    pub fn set_threshold(&mut self, t: f32) {
        self.confidence_threshold = t.clamp(0.0, 1.0);
    }

    pub fn scan(&self, apk: &[u8]) -> Option<ScanResult> {
        let indices = self.tokenizer.tokenize(apk)?;
        let input = tract_ndarray::Array1::from_vec(indices);
        let result = self.plan.run(tvec!(input.into_tensor().into()));
        let confidence = match result {
            Ok(outputs) => {
                let output = outputs[0].to_array_view::<f32>().ok();
                match output {
                    Some(arr) => arr.iter().copied().next().unwrap_or(0.0).clamp(0.0, 1.0),
                    None => 0.0,
                }
            }
            Err(_) => 0.0,
        };
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
        // Without a loaded vocab, we can't test full pipeline, but we can
        // at least verify the Tokenizer loads a dummy vocab.
        let mut vocab = std::collections::HashMap::new();
        vocab.insert("test".to_string(), 1);
        let tok = features::Tokenizer::new(vocab);
        // Tokenizing should work — all tokens will map to UNK (0) since vocab is empty.
        let result = tok.tokenize(&bytes);
        assert!(result.is_some());
        let ids = result.unwrap();
        assert!(!ids.is_empty(), "should produce at least some tokens");
    }

    #[test]
    fn load_vocab_from_json() {
        let json = br#"{"<UNK>": 0, "hello": 1, "world": 2}"#;
        let tok = features::Tokenizer::load_json(json).expect("should parse");
        let ids = tok.tokenize(b"hello world");
        assert!(ids.is_none(), "not a zip, should return None");
    }
}
