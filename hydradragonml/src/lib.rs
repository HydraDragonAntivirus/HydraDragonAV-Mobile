pub mod features;

use std::io::Cursor;

use tract_onnx::prelude::*;

/// Minimum confidence to flag a sample as malicious.
pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.95;
/// Minimum confidence to flag a sample as suspicious (below malicious threshold).
pub const SUSPICIOUS_THRESHOLD: f32 = 0.90;

pub struct Model {
    plan: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    confidence_threshold: f32,
}

#[derive(Debug)]
pub struct ScanResult {
    pub malicious: bool,
    /// Confidence is >= SUSPICIOUS_THRESHOLD but < confidence_threshold.
    pub suspicious: bool,
    /// Malware confidence 0.0 (benign) – 1.0 (malware).
    pub confidence: f32,
}

impl Model {
    /// Load an ONNX model from bytes.
    pub fn load_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let tract_model = onnx()
            .model_for_read(&mut Cursor::new(bytes))?
            .with_input_fact(0, InferenceFact::dt_shape(f32::datum_type(), tvec!(1, features::DENSE_DIM)))?
            .into_optimized()?
            .into_runnable()?;
        Ok(Model {
            plan: tract_model,
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
        })
    }

    /// Load an ONNX model from a file path.
    pub fn load_bin(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        Self::load_bytes(&bytes)
    }

    /// Override the confidence threshold (default: 0.5).
    pub fn set_threshold(&mut self, t: f32) {
        self.confidence_threshold = t.clamp(0.0, 1.0);
    }

    /// Score raw APK bytes.
    pub fn scan(&self, apk: &[u8]) -> Option<ScanResult> {
        let feats = features::extract(apk)?;
        Some(self.scan_features(&feats))
    }

    /// Score pre-extracted features.
    pub fn scan_features(&self, feats: &features::ApkFeatures) -> ScanResult {
        let input = tract_ndarray::Array2::from_shape_vec(
            (1, features::DENSE_DIM),
            feats.dense.clone(),
        )
        .unwrap();
        let result = self.plan.run(tvec!(input.into_tensor().into()));
        let confidence = match result {
            Ok(outputs) => {
                let output = outputs[0].to_array_view::<f32>().ok();
                match output {
                    Some(arr) => {
                        let val = arr.iter().copied().next().unwrap_or(0.0);
                        if val > 1.0 {
                            1.0
                        } else if val < 0.0 {
                            0.0
                        } else {
                            val
                        }
                    }
                    None => 0.0,
                }
            }
            Err(_) => 0.0,
        };
        let malicious = confidence >= self.confidence_threshold;
        let suspicious = !malicious && confidence >= SUSPICIOUS_THRESHOLD;
        ScanResult {
            malicious,
            suspicious,
            confidence,
        }
    }
}
