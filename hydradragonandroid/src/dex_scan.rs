//! DEX string + static-analysis extraction (FossRust dex-parser-analyzer).

use dex_analysis::{analyze_dex, AnalysisConfig, Severity};
use dex_core::parse_dex;

const MAX_TEXT: usize = 8 * 1024 * 1024;
const MAX_FINDINGS: usize = 64;

pub struct DexScan {
    /// Decoded string pool: strings + method/class/field names, '\n'-joined.
    pub text: String,
    /// (severity, "id: message") static-analysis findings.
    pub findings: Vec<(Severity, String)>,
}

/// Parse a DEX buffer once: decode its string pool and run static analysis.
pub fn scan(bytes: &[u8]) -> Option<DexScan> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dex = parse_dex(bytes).ok()?;
        let mut text = String::new();
        for s in dex.strings() {
            text.push_str(s);
            text.push('\n');
            if text.len() >= MAX_TEXT {
                break;
            }
        }
        let report = analyze_dex(&dex, &AnalysisConfig::default());
        let findings = report
            .findings
            .into_iter()
            .take(MAX_FINDINGS)
            .map(|f| (f.severity, format!("{}: {}", f.id, f.message)))
            .collect();
        Some(DexScan { text, findings })
    }))
    .ok()
    .flatten()
}

/// High/Critical findings are treated as malicious detections; lower ones aren't.
pub fn is_severe(sev: Severity) -> bool {
    matches!(sev, Severity::High | Severity::Critical)
}
