use crate::scanner::ScanMatch;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// One cached `yara_x::Scanner` per `YaraEngine`, per thread. `Scanner::new`
    /// is not free (it allocates its own match-tracking state and instantiates
    /// a WASM runtime for the rules' compiled condition bytecode) — the scan
    /// path calls `YaraEngine::scan` once per (ruleset × extracted buffer ×
    /// normalized view), so building a brand-new `Scanner` on every single one
    /// of those calls was multiplying that non-trivial setup cost by a factor
    /// that scales with how many nested files an APK contains, on top of the
    /// actual scanning work — this is why the native engine measured
    /// (FILE_ENGINE_TIMING) as consistently and disproportionately slow.
    /// Reusing one `Scanner` per ruleset per thread amortizes that setup cost
    /// across every scan instead of paying it every time.
    static SCANNER_CACHE: RefCell<HashMap<u64, yara_x::Scanner<'static>>> =
        RefCell::new(HashMap::new());
}

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
    id: u64,
    pub name: String,
    rules: yara_x::Rules,
}

impl YaraEngine {
    fn new(rules: yara_x::Rules, name: String) -> Self {
        Self { id: NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed), name, rules }
    }

    /// Compile a YARA source file and build the engine.
    ///
    /// Returns `None` if the file does not exist or compilation fails
    /// (the caller should degrade gracefully rather than abort the scan).
    pub fn from_source_file(path: impl AsRef<Path>) -> Option<Self> {
        let src = std::fs::read_to_string(path.as_ref()).ok()?;
        let name = path.as_ref().file_name()?.to_string_lossy().to_string();
        Self::from_source(&src, name)
    }

    /// Compile YARA source directly.
    pub fn from_source(source: &str, name: String) -> Option<Self> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).ok()?;
        Some(Self::new(compiler.build(), name))
    }

    /// Load a pre-compiled `.yrc` ruleset (produced by `Rules::serialize`).
    ///
    /// Far faster than compiling source on-device — the Android app bundles
    /// compiled `.yrc` assets and deserialises them at startup instead of
    /// compiling thousands of rules every launch.
    pub fn from_compiled(bytes: &[u8], name: String) -> Option<Self> {
        let rules = yara_x::Rules::deserialize(bytes).ok()?;
        Some(Self::new(rules, name))
    }

    /// Load a pre-compiled `.yrc` file from disk.
    pub fn from_compiled_file(path: impl AsRef<Path>) -> Option<Self> {
        let bytes = std::fs::read(path.as_ref()).ok()?;
        let name = path.as_ref().file_name()?.to_string_lossy().to_string();
        Self::from_compiled(&bytes, name)
    }

    /// Scan `data` with the compiled rules and return any matches.
    pub fn scan(
        &self,
        data: &[u8],
        object_path: &str,
        module_meta: &[(&str, &[u8])],
    ) -> Vec<ScanMatch> {
        SCANNER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            let scanner = cache.entry(self.id).or_insert_with(|| {
                // SAFETY: `self.rules` lives inside a `YaraEngine` that is
                // itself only ever constructed once, up front, into the
                // process-global `static ENGINE: OnceLock<RwLock<Engine>>`
                // (see hydradragonandroid/src/lib.rs) — `ENGINE.set()` is
                // called exactly once and there is no reload/replace path,
                // so this `Rules` value is never dropped or moved for the
                // remaining lifetime of the process. Extending the borrow to
                // 'static here is therefore sound: every thread-local
                // `Scanner` cached against it is genuinely outlived by the
                // `Rules` it borrows from.
                let rules_static: &'static yara_x::Rules =
                    unsafe { std::mem::transmute::<&yara_x::Rules, &'static yara_x::Rules>(&self.rules) };
                let mut scanner = yara_x::Scanner::new(rules_static);
                scanner.fast_scan(true);
                scanner
            });

            // Feed any per-module JSON reports (androguard manifest report,
            // hydradragon live-network report, ...) so those modules'
            // functions can query them.
            let results = if module_meta.is_empty() {
                match scanner.scan(data) {
                    Ok(r) => r,
                    Err(_) => return Vec::new(),
                }
            } else {
                let mut opts = yara_x::ScanOptions::new();
                for (name, meta) in module_meta {
                    opts = opts.set_module_metadata(name, meta);
                }
                match scanner.scan_with_options(data, opts) {
                    Ok(r) => r,
                    Err(_) => return Vec::new(),
                }
            };
            let mut matches = Vec::new();
            for rule in results.matching_rules() {
                matches.push(ScanMatch {
                    name: format!("YARA-X.{}", rule.identifier()),
                    kind: crate::scanner::SignatureKind::Yara,
                    source: crate::database::SourceLocation {
                        path: Arc::from(PathBuf::from("yara-x")),
                        line: 0,
                    },
                    object_path: object_path.to_string(),
                    view: crate::scanner::ScanView::Raw,
                    arenas: Vec::new(),
                });
            }
            matches
        })
    }
}
