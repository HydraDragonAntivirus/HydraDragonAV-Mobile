use crate::scanner::ScanMatch;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Android-relevant ClamAV target types that get YARA scanning.
///
/// Includes HTML (3), Graphics (5), ELF (6), ASCII text (7), PDF (10).
/// Excludes PE (1), OLE2 (2), Mail (4), Mach-O (9), SWF (11), Java (12) and
/// other desktop-only formats. Email formats are unsupported on Android.
/// Unknown types (None) are scanned by default since they could be APK/ZIP
/// archives or other Android-relevant containers.
const ALLOWED_TARGETS: [u32; 5] = [3, 5, 6, 7, 10];

/// Returns `true` if files matching the given ClamAV target should be
/// scanned with YARA rules.
pub fn is_target_allowed(target: Option<u32>) -> bool {
    match target {
        None => true,
        Some(t) => ALLOWED_TARGETS.contains(&t),
    }
}

/// A compiled YARA ruleset ready for scanning.
#[derive(Debug)]
pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    /// Compile a YARA source file and build the engine.
    ///
    /// Returns `None` if the file does not exist or compilation fails
    /// (the caller should degrade gracefully rather than abort the scan).
    pub fn from_source_file(path: impl AsRef<Path>) -> Option<Self> {
        let src = std::fs::read_to_string(path.as_ref()).ok()?;
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(src.as_str()).ok()?;
        let rules = compiler.build();
        Some(Self { rules })
    }

    /// Compile YARA source directly.
    pub fn from_source(source: &str) -> Option<Self> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).ok()?;
        let rules = compiler.build();
        Some(Self { rules })
    }

    /// Load a pre-compiled `.yrc` ruleset (produced by `Rules::serialize`).
    ///
    /// Far faster than compiling source on-device — the Android app bundles
    /// compiled `.yrc` assets and deserialises them at startup instead of
    /// compiling thousands of rules every launch.
    pub fn from_compiled(bytes: &[u8]) -> Option<Self> {
        let rules = yara_x::Rules::deserialize(bytes).ok()?;
        Some(Self { rules })
    }

    /// Load a pre-compiled `.yrc` file from disk.
    pub fn from_compiled_file(path: impl AsRef<Path>) -> Option<Self> {
        let bytes = std::fs::read(path.as_ref()).ok()?;
        Self::from_compiled(&bytes)
    }

    /// Scan `data` with the compiled rules and return any matches.
    pub fn scan(
        &self,
        data: &[u8],
        object_path: &str,
        androguard: Option<&[u8]>,
    ) -> Vec<ScanMatch> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        // Feed the androguard JSON report (if any) to the `androguard` module so
        // its functions (permission/url/activity/...) can query it.
        let results = if let Some(meta) = androguard {
            let mut opts = yara_x::ScanOptions::new();
            opts = opts.set_module_metadata("androguard", meta);
            match scanner.scan_with_options(data, opts) {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            }
        } else {
            match scanner.scan(data) {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            }
        };
        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            matches.push(ScanMatch {
                name: format!("YARA.{}", rule.identifier()),
                kind: crate::scanner::SignatureKind::Yara,
                source: crate::database::SourceLocation {
                    path: Arc::from(PathBuf::from("yara")),
                    line: 0,
                },
                object_path: object_path.to_string(),
                view: crate::scanner::ScanView::Raw,
                arenas: Vec::new(),
            });
        }
        matches
    }
}
