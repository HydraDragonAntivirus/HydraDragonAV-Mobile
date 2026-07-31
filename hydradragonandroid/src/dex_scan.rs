//! DEX string + static-analysis extraction (FossRust dex-parser-analyzer).
//! Also extracts every unique API call (method invocation) for the
//! `hydradragon.api_call()` YARA-X module function.

use dex_analysis::{analyze_dex, AnalysisConfig, Severity};
use dex_core::{parse_dex, graphs, semantics};

const MAX_TEXT: usize = 8 * 1024 * 1024;
const MAX_FINDINGS: usize = 64;
const MAX_API_CALLS: usize = 4096;

pub struct DexScan {
    /// Decoded string pool: strings + method/class/field names, '\n'-joined.
    pub text: String,
    /// Static-analysis findings, any severity.
    pub findings: Vec<DexFinding>,
    /// Unique API call signatures invoked by this DEX buffer, in
    /// `Lpkg/Cls;->method(params)return` format.
    pub api_calls: Vec<String>,
}

/// One static-analysis finding, flattened from `dex_analysis::Finding` so it
/// can be both checked with `is_severe` and serialized into the
/// `hydradragon` YARA-X module metadata (see `lib.rs`).
pub struct DexFinding {
    pub severity: Severity,
    pub kind: String,
    pub class_descriptor: String,
    pub message: String,
}

/// Parse a DEX buffer once: decode its string pool, run static analysis,
/// and extract all invoked API calls.
pub fn scan(bytes: &[u8]) -> Option<DexScan> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dex = parse_dex(bytes).ok()?;
        let mut text = String::new();
        for s in dex.strings().flatten() {
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
            .map(|f| DexFinding {
                severity: f.severity,
                kind: format!("{:?}", f.kind),
                class_descriptor: f.location.class_descriptor,
                message: format!("{}: {}", f.id, f.message),
            })
            .collect();

        // Count every method invocation across all methods, returning
        // "Lpkg/Cls;->method(params)return" -> count pairs so YARA rules
        // can query either presence or frequency.
        let mut api_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        if let Ok(xrefs) = graphs::build_xrefs(&dex) {
            for (_, callee_idx) in &xrefs.method_calls {
                if api_counts.len() >= MAX_API_CALLS {
                    break;
                }
                let midx = dex_core::format::MethodIdx::new(*callee_idx);
                if let Ok(sig) = semantics::pretty_method(&dex, midx) {
                    *api_counts.entry(sig).or_insert(0) += 1;
                }
            }
        }
        // Serialise as an array of "name:count" strings; YARA rules
        // parse the count via `hydradragon.api_call(regex)` which now
        // returns the SUM of counts for matching signatures.
        let mut api_calls: Vec<String> = api_counts
            .into_iter()
            .map(|(sig, cnt)| format!("{sig}\t{cnt}"))
            .collect();
        api_calls.shrink_to_fit();

        Some(DexScan { text, findings, api_calls })
    }))
    .ok()
    .flatten()
}

/// Only Critical findings are treated as malicious detections — High and
/// below are too false-positive-prone (legitimate obfuscated/reflection-heavy
/// SDKs routinely trip them) to count toward a verdict on their own.
pub fn is_severe(sev: Severity) -> bool {
    matches!(sev, Severity::Critical)
}
