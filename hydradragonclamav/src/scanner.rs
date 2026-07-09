use crate::database::{Database, OffsetAnchor, OffsetSpec, SourceLocation};
use crate::logical::Subsignature;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

/// Per-scan timing breakdown: ClamAV and per-YARA-ruleset elapsed nanoseconds.
#[derive(Clone, Debug, Default)]
pub struct TimingBreakdown {
    pub clamav_ns: u128,
    pub yara_per_engine: Vec<(String, u128)>,
}

impl TimingBreakdown {
    /// Merge another breakdown into this one (add ClamAV time, append YARA entries).
    pub fn accumulate(&mut self, other: TimingBreakdown) {
        self.clamav_ns = self.clamav_ns.saturating_add(other.clamav_ns);
        self.yara_per_engine.extend(other.yara_per_engine);
    }
}

#[derive(Debug)]
pub struct Engine {
    pub database: Database,
    /// Atom prefilter: selects the few signatures worth fully evaluating per
    /// buffer instead of scanning all of them linearly, and threads the atom
    /// match offsets into verification. It also owns the per-logical-signature
    /// gating info (see `AtomPrefilter::logical_gate`), kept there so the gating
    /// subsignature is exactly the one whose atoms were indexed — that alignment
    /// is what makes threading the gate's offsets correct.
    prefilter: crate::prefilter::AtomPrefilter,
    /// YARA-x engines for scanning with compiled YARA rules (Android-relevant
    /// types only, see `yara_scan::is_target_allowed`). Multiple rulesets can be
    /// loaded (e.g. clean / valhalla / AndroidOS); all are run.
    pub yara: Vec<crate::yara_scan::YaraEngine>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    pub scan_archives: bool,
    pub max_recursion: usize,
    pub max_child_size: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_archives: true,
            max_recursion: 16,
            max_child_size: 650 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanMatch {
    pub name: String,
    pub kind: SignatureKind,
    pub source: SourceLocation,
    pub object_path: String,
    pub view: ScanView,
}

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    );
}
const ANDROID_LOG_INFO: std::os::raw::c_int = 4;
fn android_log(msg: &str) {
    use std::ffi::CString;
    let (Ok(tag), Ok(text)) = (
        CString::new("HydraDragon-RustTiming"),
        CString::new(msg),
    ) else {
        return;
    };
    unsafe { __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr()) };
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureKind {
    Extended,
    Logical,
    Container,
    /// Phishing heuristic (`.pdb`/`.gdb`/`.wdb` driven spoofed-domain check).
    Phishing,
    /// YARA-x rule match.
    Yara,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanView {
    Raw,
}

pub(crate) struct ScanContext<'a> {
    pub data: &'a [u8],
    /// Target derived from `.ftm` file-type magic.
    pub detected_target: Option<u32>,
    pub object_path: &'a str,
    pub view: ScanView,
    /// ClamAV `CL_TYPE_*` of this object's IMMEDIATE parent container (the type
    /// of the archive it was extracted from), or `None` at the top level. Used to
    /// evaluate logical signatures' `Container:` TDB constraint, mirroring
    /// ClamAV's `cli_recursion_stack_get_type(ctx, -2)`.
    pub container_type: Option<&'static str>,
    /// The file's image fuzzy hash (perceptual pHash), computed lazily once and
    /// only when a `fuzzy_img#` subsignature is actually evaluated. `None` inside
    /// the cell means "computed, not a decodable image".
    pub image_fuzzy_hash: std::cell::OnceCell<Option<[u8; 8]>>,
}

impl ScanContext<'_> {
    /// Lazily compute (and cache) this file's image fuzzy hash, mirroring
    /// ClamAV's per-fmap `fuzzy_hash_calculate_image`. Guarded by an image-magic
    /// check so non-image files never pay the decode cost.
    pub(crate) fn image_fuzzy_hash(&self) -> Option<[u8; 8]> {
        *self.image_fuzzy_hash.get_or_init(|| {
            if looks_like_image(self.data) {
                crate::fuzzy::calculate_image(self.data)
            } else {
                None
            }
        })
    }
}

/// Quick magic-byte test for the raster formats the `image` crate decodes, so we
/// only attempt the (relatively expensive) fuzzy-hash decode on plausible images.
fn looks_like_image(d: &[u8]) -> bool {
    d.starts_with(b"\x89PNG\r\n\x1a\n")            // PNG
        || d.starts_with(&[0xFF, 0xD8, 0xFF])      // JPEG
        || d.starts_with(b"GIF87a")
        || d.starts_with(b"GIF89a")
        || d.starts_with(b"BM")                    // BMP
        || (d.len() >= 12 && d.starts_with(b"RIFF") && &d[8..12] == b"WEBP")
}

struct ScanState {
    matches: Vec<ScanMatch>,
}

/// Reusable per-call buffers for `scan_one_logical` — the outer `scan_logical`
/// allocates them once and passes `&mut` so the backing store is reused across
/// every candidate, avoiding ~4 heap allocations per logical-sig evaluation.
struct LogicalScanBufs {
    counts: Vec<usize>,
    last_offsets: Vec<Option<usize>>,
    evaluated: Vec<bool>,
    /// Per-subsig timing/shape breakdown collected during the last
    /// `scan_one_logical` call, for the `[SIG-DETAIL]` log — cleared and
    /// refilled every call, only formatted into a log line when the caller
    /// decides the signature was slow enough to be worth the detail.
    detail: Vec<SubsigDetail>,
}

/// One phase-1 subsig's contribution to a slow logical-signature scan.
struct SubsigDetail {
    subsig: usize,
    /// "gate", "restricted" (window-restricted via prefilter hints), or "full" (whole
    /// buffer scanned, no hints available).
    kind: &'static str,
    elapsed_us: u128,
    count: usize,
    ranges: usize,
}

impl Engine {
    /// Prefilter heap breakdown, for `--mem-stats` profiling.
    pub fn prefilter_mem_report(&self) -> String {
        self.prefilter.mem_report()
    }

    /// Load from a filesystem directory (original path-based loading).
    pub fn from_database_dir(path: impl AsRef<Path>) -> io::Result<(Self, crate::LoadReport)> {
        let path = path.as_ref();
        let t0 = Instant::now();
        let (mut database, mut report) = Database::load_dir(path)?;
        let load_ms = t0.elapsed().as_millis();
        android_log(&format!("from_database_dir :: load_dir={load_ms}ms files={} ext={} logical={} container={}",
            report.files_seen, database.extended.len(), database.logical.len(), database.container.len()));
        let bc = crate::bytecode::BytecodeSet::load_from_dir(path);
        Ok(Self::finish_engine_init(&mut database, &mut report, bc, t0))
    }

    /// Load from a pre-read map of filename → file contents (AAssetManager path).
    /// The caller reads every asset file into `HashMap<filename, Vec<u8>>` and
    /// passes it here — no filesystem I/O needed at init time.
    pub fn from_bytes_map(
        files: &std::collections::HashMap<String, Vec<u8>>,
    ) -> (Self, crate::LoadReport) {
        let t0 = Instant::now();
        let (mut database, mut report) = Database::from_bytes_map(files);
        let load_ms = t0.elapsed().as_millis();
        android_log(&format!("from_bytes_map :: load_dir={load_ms}ms files={} ext={} logical={} container={}",
            report.files_seen, database.extended.len(), database.logical.len(), database.container.len()));
        let bc = crate::bytecode::BytecodeSet::from_bytes_map(files);
        let (engine, report) = Self::finish_engine_init(&mut database, &mut report, bc, t0);
        (engine, report)
    }

    /// Shared bytecode + prefilter init used by both `from_database_dir` and
    /// `from_bytes_map`.
    fn finish_engine_init(
        database: &mut Database,
        report: &mut crate::LoadReport,
        bc: crate::bytecode::BytecodeSet,
        t0: std::time::Instant,
    ) -> (Self, crate::LoadReport) {
        let t_bc = Instant::now();
        report.bytecodes_loaded = bc.report.loaded;
        for prog in bc.bytecodes {
            let decoded = match crate::bytecode_vm::decode_bytecode(&prog.source) {
                Ok(Some(mut decoded)) => {
                    if decoded.prepare_interpreter().is_err() {
                        continue;
                    }
                    decoded
                }
                _ => continue,
            };
            let Some(trigger_line) = prog.trigger else {
                continue;
            };
            let source_loc = crate::database::SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("bytecode")),
                line: 0,
            };
            if let Ok((mut sig, _warnings)) =
                crate::logical::parse_logical_signature(&trigger_line, source_loc)
            {
                let bc_idx = database.bytecode_programs.len();
                database.bytecode_programs.push(decoded);
                sig.bytecode = Some(bc_idx);
                database.logical.push(sig);
            }
        }
        let bc_ms = t_bc.elapsed().as_millis();
        android_log(&format!("from_database_dir :: bytecode={bc_ms}ms loaded={}", report.bytecodes_loaded));
        let t_pf = Instant::now();
        let prefilter = crate::prefilter::AtomPrefilter::build(database);
        let pf_ms = t_pf.elapsed().as_millis();
        android_log(&format!("from_database_dir :: prefilter_build={pf_ms}ms"));
        let total_ms = t0.elapsed().as_millis();
        android_log(&format!("from_database_dir :: TOTAL={total_ms}ms"));
        let database = std::mem::take(database);
        (Self { database, prefilter, yara: Vec::new() }, std::mem::take(report))
    }

    /// Replace all YARA rulesets with a single one compiled from source.
    /// Returns `None` when the rules file cannot be loaded or compiled.
    pub fn load_yara_rules(&mut self, path: impl AsRef<Path>) -> Option<()> {
        let engine = crate::yara_scan::YaraEngine::from_source_file(path)?;
        self.yara = vec![engine];
        Some(())
    }

    /// Add a YARA ruleset compiled from source (keeps existing ones).
    pub fn add_yara_source_file(&mut self, path: impl AsRef<Path>) -> Option<()> {
        self.yara
            .push(crate::yara_scan::YaraEngine::from_source_file(path)?);
        Some(())
    }

    /// Add a pre-compiled `.yrc` YARA ruleset (keeps existing ones). Far faster
    /// on-device than compiling source.
    pub fn add_compiled_yara_file(&mut self, path: impl AsRef<Path>) -> Option<()> {
        self.yara
            .push(crate::yara_scan::YaraEngine::from_compiled_file(path)?);
        Some(())
    }

    /// Add an already-loaded YARA engine (parsed from compiled bytes).
    /// Useful when the `.yrc` was read + parsed in a background thread to
    /// parallelise the init phase — the caller passes back the ready engine
    /// and this method just pushes it onto the engine list (no I/O, no parse).
    pub fn add_compiled_yara(&mut self, engine: crate::yara_scan::YaraEngine) {
        self.yara.push(engine);
    }

    pub fn scan_path(
        &self,
        path: impl AsRef<Path>,
        options: ScanOptions,
    ) -> io::Result<Vec<ScanMatch>> {
        let path = path.as_ref();
        let data = fs::read(path)?;
        Ok(self.scan_bytes_named(&data, &path.display().to_string(), options, &[]))
    }

    pub fn scan_bytes(&self, data: &[u8], options: ScanOptions) -> Vec<ScanMatch> {
        self.scan_bytes_named(data, "root", options, &[])
    }

    pub fn scan_bytes_named(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
    ) -> Vec<ScanMatch> {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        self.scan_object(data, object_path, None, 0, options, module_meta, &mut state, &mut None);
        state.matches
    }

    /// Same as `scan_bytes_named` but also returns a per-engine timing breakdown
    /// (ClamAV + each YARA ruleset) in nanoseconds.
    pub fn scan_bytes_named_with_breakdown(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
    ) -> (Vec<ScanMatch>, TimingBreakdown) {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        let mut breakdown = TimingBreakdown::default();
        self.scan_object(data, object_path, None, 0, options, module_meta, &mut state, &mut Some(&mut breakdown));
        (state.matches, breakdown)
    }

    fn scan_object(
        &self,
        data: &[u8],
        object_path: &str,
        container_type: Option<&'static str>,
        _depth: usize,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
        state: &mut ScanState,
        timing: &mut Option<&mut TimingBreakdown>,
    ) {
        if data.len() > options.max_child_size {
            return;
        }

        let detected_target = if !self.database.file_type_magic.is_empty()
        {
            self.detect_clamav_type(data).and_then(clamav_type_to_target)
        } else {
            None
        };

        let ctx = ScanContext {
            data,
            detected_target,
            object_path,
            view: ScanView::Raw,
            container_type,
            image_fuzzy_hash: Default::default(),
        };

        // Skip raw scan for archives we cannot extract — scanning compressed
        // random bytes against 500k+ signatures triggers pathological backtracking
        // in the gap-matching loop. The actual unpacker in hydradragonextractor
        // handles only gz/zip/xz/lzma/tar/7z; anything else is skipped here.
        if is_unsupported_archive(data) {
            return;
        }

        // Only run the ClamAV engine (prefilter + extended + logical) on files
        // positively identified as a supported type. Every other case — a
        // confidently-typed desktop-only format (PE, OLE2, Mail, Mach-O, SWF,
        // Java, ...) or a type we simply fail to classify — is skipped outright,
        // instead of paying for the whole-buffer atom prefilter and then having
        // `target_matches` reject each candidate signature one by one.
        let confident_target = detected_target.or_else(|| detect_builtin_target(&ctx));
        if clamav_target_allowed(confident_target) {
            // Time ClamAV scan_context
            let t_clamav = timing.as_ref().map(|_| Instant::now());
            self.scan_context(&ctx, &mut state.matches);
            if let (Some(t), Some(bt)) = (t_clamav, timing.as_mut()) {
                bt.clamav_ns = bt.clamav_ns.saturating_add(t.elapsed().as_nanos());
            }
        }

        // YARA-x scan for Android-relevant file types — run every loaded ruleset,
        // timing each YARA ruleset individually.
        if !self.yara.is_empty()
            && crate::yara_scan::is_target_allowed(confident_target)
        {
            for yara in &self.yara {
                let t_yara = timing.as_ref().map(|_| Instant::now());
                for m in yara.scan(data, object_path, module_meta) {
                    state.matches.push(m);
                }
                if let (Some(t), Some(bt)) = (t_yara, timing.as_mut()) {
                    bt.yara_per_engine.push((yara.name.clone(), t.elapsed().as_nanos()));
                }
            }
        }



        // Phishing heuristic: harvest `<a href>` link pairs from HTML/email and
        // flag spoofed protected domains (.pdb/.gdb gated by .wdb allow list).
        // Only meaningful for HTML, and only when a protected-domain DB is loaded.
        if !self.database.phishing.protected.is_empty()
            && looks_like_html(data)
        {
            self.scan_phishing(data, object_path, &mut state.matches);
        }
    }

    /// Run the phishing heuristic over an HTML/email object's link pairs,
    /// appending one `ScanMatch` per detected spoof (`Heuristics.Phishing.*`).
    fn scan_phishing(
        &self,
        data: &[u8],
        object_path: &str,
        matches: &mut Vec<ScanMatch>,
    ) {
        for hit in self.database.phishing.scan_html(data) {
            matches.push(ScanMatch {
                name: hit.name.to_string(),
                kind: SignatureKind::Phishing,
                source: hit.source,
                object_path: object_path.to_string(),
                view: ScanView::Raw,
            });
        }
    }

    /// Identify the ClamAV file type (`CL_TYPE_*`) of `data` via `.ftm` magic.
    /// Detect the ClamAV target type of `data` using the loaded file-type magic
    /// database — the exact same detection the scanner uses internally. Returns
    /// the ClamAV target number, or `None` for "any file"/unrecognised.
    ///
    /// Combine with [`crate::yara_scan::is_target_allowed`] to decide whether a
    /// file is a supported/scannable type before scanning it.
    pub fn detect_target(&self, data: &[u8]) -> Option<u32> {
        self.detect_clamav_type(data).and_then(clamav_type_to_target)
    }

    fn detect_clamav_type(&self, data: &[u8]) -> Option<&str> {
        for magic in &self.database.file_type_magic {
            let ranges = magic.offset.scan_ranges(data.len());
            if ranges.is_empty() {
                continue;
            }
            if magic
                .patterns
                .iter()
                .any(|pattern| !pattern.find_all(data, &ranges, 1).is_empty())
            {
                return Some(&magic.clamav_type);
            }
        }
        None
    }

    fn scan_context(
        &self,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
    ) {
        // One Aho-Corasick pass picks the candidate signatures for this buffer;
        // both phases then evaluate only those instead of all ~500k. Always
        // timed and logged to logcat (was previously gated behind HDA_PROF).
        use std::time::Instant;
        let t0 = Instant::now();
        let (ext_cands, log_cands) = self.prefilter.candidates(ctx.data);
        let t1 = Instant::now();
        let (ne, nl) = (ext_cands.len(), log_cands.len());
        let (te, tl) = (ext_cands.threaded_count(), log_cands.threaded_count());
        self.scan_extended(ctx, matches, &ext_cands);
        let t2 = Instant::now();
        self.scan_logical(ctx, matches, &log_cands);
        let t3 = Instant::now();
        android_log(&format!(
            "scan_context :: {}KB view={:?} ext_cands={ne}(threaded {te}) log_cands={nl}(threaded {tl}) prefilter={}ms ext_scan={}ms log_scan={}ms",
            ctx.data.len() / 1024,
            ctx.view,
            (t1 - t0).as_millis(),
            (t2 - t1).as_millis(),
            (t3 - t2).as_millis(),
        ));
    }


    fn scan_extended(
        &self,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
        cands: &crate::prefilter::Candidates,
    ) {
        // Static dispatch (two concrete loops) instead of a `Box<dyn Iterator>`:
        // the candidate list carries per-signature atom offsets to thread into
        // verification. An empty offset slice (or the `All` arm) means "no
        // threading — full scan".
        match cands {
            crate::prefilter::Candidates::All => {
                for si in 0..self.database.extended.len() {
                    self.scan_one_extended(si, None, ctx, matches);
                }
            }
            crate::prefilter::Candidates::List(set) => {
                for (sig, offsets) in set.iter() {
                    let hints = (!offsets.is_empty()).then_some(offsets);
                    self.scan_one_extended(sig as usize, hints, ctx, matches);
                }
            }
        }
    }

    /// Evaluate a single extended signature. `hints`, when `Some`, are the buffer
    /// offsets where this signature's atom occurred — verification is restricted
    /// to those positions (`find_all_at`); `None` means a full window scan.
    fn scan_one_extended(
        &self,
        si: usize,
        hints: Option<&[u32]>,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
    ) {
        let signature = &self.database.extended[si];
        if !target_matches(signature.target, ctx) {
            return;
        }
        if matches!(
            signature.offset.anchor,
            OffsetAnchor::Unsupported(_) | OffsetAnchor::MacroGroup(_)
            | OffsetAnchor::VersionInfo
        ) {
            return;
        }
        let ranges = signature.offset.scan_ranges(ctx.data.len());
        if ranges.is_empty() {
            return;
        }
        let t_ext = std::time::Instant::now();
        let mut count = 0usize;
        for pattern in &signature.patterns {
            let hits = match hints {
                Some(h) => pattern.find_all_at(ctx.data, &ranges, usize::MAX, h),
                None => pattern.find_all(ctx.data, &ranges, usize::MAX),
            };
            count += hits.len();
        }
        let ms = t_ext.elapsed().as_millis();
        if ms >= 20 {
            android_log(&format!(
                "[SLOW-EXT] {ms}ms {} ({}:{}) hints={}",
                self.database.ext_name(signature),
                signature.source.path.display(),
                signature.source.line,
                hints.map_or(0, |h| h.len()),
            ));
        }
        if count > 0 {
            matches.push(ScanMatch {
                name: self.database.ext_name(signature).to_string(),
                kind: SignatureKind::Extended,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
            });
        }
    }

    fn scan_logical(
        &self,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
        cands: &crate::prefilter::Candidates,
    ) {
        // Static dispatch (mirrors scan_extended): thread the gating subsig's
        // atom offsets into its verification when available.
        let mut bufs = LogicalScanBufs {
            counts: Vec::new(),
            last_offsets: Vec::new(),
            evaluated: Vec::new(),
            detail: Vec::new(),
        };
        match cands {
            crate::prefilter::Candidates::All => {
                for si in 0..self.database.logical.len() {
                    self.scan_one_logical(si, None, None, ctx, matches, &mut bufs);
                }
            }
            crate::prefilter::Candidates::List(set) => {
                for (sig, offsets) in set.iter() {
                    let hints = (!offsets.is_empty()).then_some(offsets);
                    let t = std::time::Instant::now();
                    self.scan_one_logical(sig as usize, hints, Some(set), ctx, matches, &mut bufs);
                    let ms = t.elapsed().as_millis();
                    if ms >= 50 {
                        android_log(&format!("[SLOW-LOG] {ms}ms {}", self.database.logical[sig as usize].name));
                    }
                    // Only worth the string-building cost once a signature is
                    // already known to be slow — this is the log that answers
                    // "which subsig, and why" instead of just "this sig was slow".
                    if ms >= 20 && !bufs.detail.is_empty() {
                        let mut line = format!(
                            "[SIG-DETAIL] {ms}ms {} subsigs=",
                            self.database.logical[sig as usize].name
                        );
                        for d in &bufs.detail {
                            line.push_str(&format!(
                                "[{}:{}:{}us,cnt={},ranges={}]",
                                d.subsig, d.kind, d.elapsed_us, d.count, d.ranges
                            ));
                        }
                        android_log(&line);
                    }
                }
            }
        }
    }

    /// Evaluate a single logical signature. `hints`, when `Some`, are the buffer
    /// offsets of the gating subsignature's atom — threaded into that subsig's
    /// verification when the gate is `threadable` (i.e. the prefilter indexed
    /// exactly that subsig, so the offsets correspond to it). `cand_set`, when
    /// `Some`, is the full candidate set `hints` was drawn from — used to look up
    /// a body subsig's OWN atom occurrences (`subsig_hints`) for OR-indexed
    /// signatures, narrower than the whole-signature union in `hints`.
    fn scan_one_logical(
        &self,
        si: usize,
        hints: Option<&[u32]>,
        cand_set: Option<&crate::prefilter::CandidateSet>,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
        bufs: &mut LogicalScanBufs,
    ) {
        let signature = &self.database.logical[si];
        if !target_matches(signature.target, ctx) {
            return;
        }
        // TDB gating (ClamAV's target description block). A signature only fires
        // when these context constraints hold; matching the body alone would
        // false-positive on every file satisfying the body.
        //
        // `tdb_unsupported` covers constraints we can't yet evaluate (IconGroup,
        // HandlerType, …) — skip entirely. The rest we evaluate from context.
        if signature.tdb_unsupported {
            return;
        }
        if let Some((min, max)) = signature.file_size {
            let len = ctx.data.len() as u64;
            if len < min || len > max {
                return;
            }
        }
        if let Some(want) = signature.container.as_deref() {
            // ClamAV: the immediate parent container type must match (or the sig
            // accepts any container via CL_TYPE_ANY). A top-level object has no
            // parent container, so a container-constrained sig can't fire on it.
            let parent = ctx.container_type;
            let ok = match parent {
                Some(t) => want == "CL_TYPE_ANY" || want == t,
                None => false,
            };
            if !ok {
                return;
            }
        }
        if !signature.intermediates.is_empty() {
            // ClamAV intermediates_eval: the ancestor container-type chain must
            // match the recursion stack (innermost = the immediate parent). We
            // track only the immediate parent, so a single-level intermediate is
            // checked against it; a multi-level chain we cannot confirm and so do
            // not fire on (avoids a false positive, never alerts spuriously).
            let inner = signature.intermediates.last().map(String::as_str).unwrap_or("");
            let inner_ok = inner == "CL_TYPE_ANY" || ctx.container_type == Some(inner);
            if !inner_ok || signature.intermediates.len() > 1 {
                return;
            }
        }
        if signature.nos.is_some() || signature.ep.is_some()
            || signature.icongrp1.is_some() || signature.icongrp2.is_some()
        {
            return;
        }
        let subsigs = &signature.subsignatures;
        let n = subsigs.len();
        bufs.counts.clear();
        bufs.counts.resize(n, 0);
        bufs.last_offsets.clear();
        bufs.last_offsets.resize(n, None);
        bufs.evaluated.clear();
        bufs.evaluated.resize(n, false);
        bufs.detail.clear();
        let counts = &mut bufs.counts;
        let last_offsets = &mut bufs.last_offsets;
        let evaluated = &mut bufs.evaluated;

        let t_debug = std::time::Instant::now();

        // Early cutoff: evaluate the gating subsig first; if the gate is absent
        // the expression can't match, so skip every other subsig of this
        // signature (the big win on logical-heavy databases / large files, where
        // most candidates are prefilter false positives). The gate comes from the
        // prefilter, which guarantees it is exactly the subsig whose atoms were
        // indexed — so when `threadable` the candidate's offsets verify it with
        // no whole-buffer rescan.
        // OR-indexed signatures (no single required subsig) carry the UNION of all
        // their subsignatures' atom offsets as `hints`. Because a subsig match must
        // contain one of its atoms — whose every occurrence is in that union (it is
        // empty, never partial, on overflow) — each subsig need only be scanned in
        // small windows around those offsets, not over the whole buffer. This is
        // the logical-scan analogue of the threaded extended path; without it these
        // signatures (e.g. 30+ `TwinWave.EvilDoc.*` doc sigs with ~31 keyword
        // subsigs each) rescan the entire buffer once per subsignature.
        let all_indexed =
            self.prefilter.logical_all_indexed(si) && hints.is_some_and(|h| !h.is_empty());

        let gate = self.prefilter.logical_gate(si);
        let mut gating_done: Option<usize> = None;
        // When every subsig is restricted to the union windows below, the separate
        // non-threadable gate cutoff (a full buffer rescan) is redundant.
        if let Some(g) = gate.filter(|_| !all_indexed) {
            let gi = g.subsig as usize;
            if let Some(Subsignature::Body { offset, patterns }) = subsigs.get(gi) {
                let default_offset = OffsetSpec::any();
                let offset = offset.as_deref().unwrap_or(&default_offset);
                let ranges = offset.scan_ranges(ctx.data.len());
                if !ranges.is_empty() {
                    let gate_hints = if g.threadable { hints } else { None };
                    let t_gate = std::time::Instant::now();
                    let (count, last_off) = body_matches(
                        patterns,
                        ctx.data,
                        &ranges,
                        usize::MAX,
                        gate_hints,
                    );
                    let ms = t_gate.elapsed().as_millis();
                    if ms >= 20 {
                        android_log(&format!(
                            "[SLOW-GATE] {ms}ms {} ({}):{} hints={} threadable={}",
                            signature.name,
                            signature.source.path.display(),
                            signature.source.line,
                            gate_hints.map_or(0, |h| h.len()),
                            g.threadable,
                        ));
                    }
                    bufs.detail.push(SubsigDetail {
                        subsig: gi,
                        kind: "gate",
                        elapsed_us: t_gate.elapsed().as_micros(),
                        count,
                        ranges: ranges.len(),
                    });
                    if count == 0 {
                        return; // gate absent → signature cannot match
                    }
                    counts[gi] = count;
                    last_offsets[gi] = last_off;
                    evaluated[gi] = true;
                    gating_done = Some(gi);
                }
            }
        }

        // Whether the expression can be trusted to short-circuit on an
        // already-decided outcome (see `is_definitely_matched`/`can_still_match`):
        // unsound through a `Compare` node, since those aren't monotone in the counts.
        // Also unsound whenever a bytecode program is attached: `run_bytecode` below
        // hands the VM the FULL `counts` array (ClamAV's `lsigcnt`), which a program
        // can inspect for any subsig regardless of which branch satisfied the boolean
        // expression — breaking early would feed it stale zeros for un-evaluated
        // subsigs that actually matched.
        let monotone =
            !signature.expression.has_nonmonotone_compare() && signature.bytecode.is_none();

        let t_after_gate = std::time::Instant::now();
        let debug_gate_us = t_after_gate.duration_since(t_debug).as_micros();

        // Phase 1: body subsignatures (the gate, if any, is already done).
        for (i, subsig) in subsigs.iter().enumerate() {
            if Some(i) == gating_done {
                continue; // already evaluated above as the gate
            }
            if let Subsignature::Body {
                offset, patterns, ..
            } = subsig
            {
                let any = OffsetSpec::any();
                let offset = offset.as_deref().unwrap_or(&any);
                if matches!(
                    offset.anchor,
                    OffsetAnchor::Unsupported(_) | OffsetAnchor::MacroGroup(_)
                ) {
                    continue;
                }
                let base_ranges = offset.scan_ranges(ctx.data.len());
                if base_ranges.is_empty() {
                    continue;
                }
                // For OR-indexed sigs, restrict this subsig's scan to windows around
                // its OWN atom occurrences when the prefilter tagged them separately
                // (`subsig_hints`) — far narrower than the whole signature's union
                // when a sibling subsig's atom is much more common than this one's.
                // Falls back to the union `hints` when no per-subsig split exists
                // (e.g. more than `MAX_TAGGED_SUBSIG` subsigs, or this subsig's
                // offsets overflowed the per-signature atom cap).
                // A SIMD scan of those small windows beats threading each subsig
                // against the FULL union hint set (most of which belong to other
                // subsigs and just fail to verify). `None` max length (open gap)
                // can't be bounded → keep the full scan.
                let t_sub = std::time::Instant::now();
                let restricted;
                let mut was_restricted = false;
                // Prefer this subsig's OWN tagged atom occurrences (populated for
                // both OR-indexed and gated signatures — see `AtomPrefilter::build`)
                // over the whole-signature union `hints`, and over `all_indexed`,
                // which only gates the union fallback: a gated signature has no
                // union hints for its non-gate subsigs, but may still have per-subsig
                // hints for some of them individually.
                let use_hints = cand_set
                    .and_then(|s| s.subsig_hints(si as u32, i as u32))
                    .or_else(|| if all_indexed { hints } else { None });
                let ranges: &[(usize, usize)] = match (use_hints, subsig_max_match_len(patterns)) {
                    (Some(h), Some(ml)) if !h.is_empty() => {
                        restricted = restrict_ranges(&base_ranges, h, ml, ctx.data.len());
                        was_restricted = true;
                        &restricted
                    }
                    _ => &base_ranges,
                };
                let (count, last_off) = body_matches(
                    patterns,
                    ctx.data,
                    ranges,
                    usize::MAX,
                    None,
                );
                bufs.detail.push(SubsigDetail {
                    subsig: i,
                    kind: if was_restricted { "restricted" } else { "full" },
                    elapsed_us: t_sub.elapsed().as_micros(),
                    count,
                    ranges: ranges.len(),
                });
                counts[i] = count;
                last_offsets[i] = last_off;
                evaluated[i] = true;
                // Short-circuit: if this absent subsig already makes the signature
                // unsatisfiable (a missing AND term), skip every remaining subsig.
                if !signature.expression.can_still_match(counts, evaluated) {
                    return;
                }
                // Success short-circuit: an OR-branch is already fully satisfied, so
                // the remaining subsigs (e.g. an expensive wildcard-heavy body in a
                // sibling branch) can no longer change the outcome — stop scanning.
                if monotone && signature.expression.is_definitely_matched(counts, evaluated) {
                    break;
                }
            }
        }

        let t_after_p1 = std::time::Instant::now();
        let debug_p1_us = t_after_p1.duration_since(t_after_gate).as_micros();

        // Image fuzzy-hash subsignatures: match when the file's perceptual image
        // hash equals the subsig hash exactly (ClamAV's `fuzzy_hash_check`, which
        // supports only hamming distance 0). The hash is computed once per file.
        for (i, subsig) in subsigs.iter().enumerate() {
            if let Subsignature::Fuzzy(hash) = subsig {
                if ctx.image_fuzzy_hash() == Some(*hash) {
                    counts[i] = 1;
                }
            }
        }

        let t_after_fuzzy = std::time::Instant::now();
        let debug_fuzzy_us = t_after_fuzzy.duration_since(t_after_p1).as_micros();

        // Phase 2: PCRE and byte-compare subsignatures, whose triggers
        // reference the phase-1 body results.
        //
        // On very large buffers (> 10 MB) the regex engine (especially the
        // PikeVM fallback for non-DFA‑friendly patterns) can become
        // pathologically slow — scanning 162 MB of binary APK data for
        // text‑oriented ransomware patterns achieves nothing while costing
        // 100+ ms per PCRE.  We cap the searchable region to the first
        // `PCRE_MAX_SCAN_BYTES` bytes of the buffer; content beyond that
        // is almost certainly not a text‑mode indicator.
        const PCRE_MAX_SCAN_BYTES: usize = 10_000_000;
        let pcre_needle = if ctx.data.len() > PCRE_MAX_SCAN_BYTES {
            &ctx.data[..PCRE_MAX_SCAN_BYTES]
        } else {
            ctx.data
        };
        for (i, subsig) in subsigs.iter().enumerate() {
            match subsig {
                Subsignature::Pcre(pcre) => {
                    if pcre.trigger.eval(counts).matched {
                        // Compile the regex on first trigger (lazy — most PCREs
                        // never fire, so they stay uncompiled and cost no RAM).
                        if let Some(re) = pcre.regex.get() {
                            counts[i] = if pcre.global {
                                re.find_iter(pcre_needle).count()
                            } else {
                                usize::from(pcre.regex.is_match(pcre_needle))
                            };
                        }
                    }
                }
                Subsignature::ByteCompare(spec) => {
                    // ClamAV (cli_bcomp_scanbuf): the referenced subsig must have
                    // matched, then anchor at its LAST match offset, coercing a
                    // missing offset (CLI_OFF_NONE) to 0 rather than skipping.
                    let trigger_hit = counts.get(spec.trigger_subsig).copied().unwrap_or(0) > 0;
                    if trigger_hit {
                        let base = last_offsets
                            .get(spec.trigger_subsig)
                            .copied()
                            .flatten()
                            .unwrap_or(0);
                        if spec.evaluate(ctx.data, base) {
                            counts[i] = 1;
                        }
                    }
                }
                _ => {}
            }
        }

        let t_after_p2 = std::time::Instant::now();
        let debug_p2_us = t_after_p2.duration_since(t_after_fuzzy).as_micros();

        let eval_matched = signature.expression.eval(counts).matched;
        let debug_eval_us = std::time::Instant::now().duration_since(t_after_p2).as_micros();

        let debug_total_us = std::time::Instant::now().duration_since(t_debug).as_micros();
        android_log(&format!(
            "[SCAN-DEBUG] {} gate={}us p1_body={}us fuzzy={}us p2_pcre_bc={}us eval={}us total={}us subsig_sum={}us",
            signature.name,
            debug_gate_us,
            debug_p1_us,
            debug_fuzzy_us,
            debug_p2_us,
            debug_eval_us,
            debug_total_us,
            bufs.detail.iter().map(|d| d.elapsed_us).sum::<u128>(),
        ));

        if eval_matched {
            // HandlerType (ClamAV lsig_eval): a matching signature does NOT alert.
            // Instead ClamAV re-types the file and rescans as `handlertype`. We
            // faithfully suppress the alert; the re-typed rescan would only surface
            // a *different* nested detection, never this signature's name.
            if signature.handlertype.is_some() {
                return;
            }
            // A bytecode trigger does not alert on its own — it runs the ClamBC
            // program, which decides the verdict via setvirusname (cli_bytecode_runlsig).
            if let Some(bc_idx) = signature.bytecode {
                if let Some(name) = self.run_bytecode(bc_idx, counts, ctx) {
                    matches.push(ScanMatch {
                        name,
                        kind: SignatureKind::Logical,
                        source: signature.source.clone(),
                        object_path: ctx.object_path.to_string(),
                        view: ctx.view,
                    });
                }
                return;
            }
            matches.push(ScanMatch {
                name: signature.name.to_string(),
                kind: SignatureKind::Logical,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
            });
        }
    }

    /// Run a ClamBC program for a matched trigger, building its context from the
    /// scan (file buffer, trigger subsig match counts). Returns the
    /// program's `setvirusname`, or `None` on no-detection / VM error.
    fn run_bytecode(
        &self,
        bc_idx: usize,
        counts: &[usize],
        ctx: &ScanContext<'_>,
    ) -> Option<String> {
        let bc = self.database.bytecode_programs.get(bc_idx)?;
        let mut bctx = crate::bytecode_vm::BcCtx::new(ctx.data);
        for (i, &c) in counts.iter().take(64).enumerate() {
            bctx.lsigcnt[i] = c as u32;
        }
        match bc.run(&mut bctx) {
            Ok(_) => bctx.virname,
            Err(_) => None,
        }
    }
}

/// The largest match length across a subsignature's pattern variants, or `None`
/// if any variant is unbounded (open gap) — in which case its scan can't be
/// window-restricted.
fn subsig_max_match_len(patterns: &[crate::pattern::Pattern]) -> Option<usize> {
    let mut m = 0usize;
    for p in patterns {
        m = m.max(p.max_match_len()?);
    }
    Some(m)
}

/// Restrict `base` ranges to windows `[h - max_len, h + max_len + 1)` around each
/// hint `h`, merged and intersected with `base`. A match containing an atom at `h`
/// starts in `[h - max_len, h]`, so scanning these windows (rather than the whole
/// buffer) finds every match while skipping the regions no atom touched. The
/// generous end keeps `h` itself a valid start position for `find_all`'s
/// `max_pos = end - min_len` bound.
fn restrict_ranges(
    base: &[(usize, usize)],
    hints: &[u32],
    max_len: usize,
    data_len: usize,
) -> Vec<(usize, usize)> {
    if hints.is_empty() {
        return Vec::new();
    }
    let mut wins: Vec<(usize, usize)> = hints
        .iter()
        .map(|&h| {
            let h = h as usize;
            (h.saturating_sub(max_len), (h + max_len + 1).min(data_len))
        })
        .collect();
    wins.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(wins.len());
    for (s, e) in wins {
        match merged.last_mut() {
            Some(last) if s <= last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => merged.push((s, e)),
        }
    }
    let mut out = Vec::new();
    for &(bs, be) in base {
        for &(ms, me) in &merged {
            let s = bs.max(ms);
            let e = be.min(me);
            if s < e {
                out.push((s, e));
            }
        }
    }
    out
}

fn body_matches(
    patterns: &[crate::pattern::Pattern],
    data: &[u8],
    ranges: &[(usize, usize)],
    limit: usize,
    hints: Option<&[u32]>,
) -> (usize, Option<usize>) {
    let mut count = 0usize;
    let mut last_end: Option<usize> = None;
    for pattern in patterns {
        let remaining = limit.saturating_sub(count);
        if remaining == 0 {
            break;
        }
        let hits = match hints {
            Some(h) => pattern.find_all_at(data, ranges, remaining, h),
            None => pattern.find_all(data, ranges, remaining),
        };
        count += hits.len();
        if let Some(m) = hits.last() {
            last_end = Some(m.end.max(last_end.unwrap_or(0)));
        }
    }
    (count, last_end)
}

/// ClamAV target codes worth running the ClamAV engine on at all: HTML(3),
/// Graphics(5), ELF(6), ASCII text(7), PDF(10), DEX(16), ZIP/APK(17). Anything
/// else — a confidently-typed desktop-only format or a type we can't classify
/// — never runs on Android, so `scan_object` skips the whole engine for it
/// rather than relying on `target_matches` to reject each candidate.
const CLAMAV_ALLOWED_TARGETS: [u32; 7] = [3, 5, 6, 7, 10, 16, 17];

fn clamav_target_allowed(target: Option<u32>) -> bool {
    matches!(target, Some(t) if CLAMAV_ALLOWED_TARGETS.contains(&t))
}

fn target_matches(target: Option<u32>, ctx: &ScanContext<'_>) -> bool {
    let want = target.unwrap_or(0);

    // Target 0 = generic: applies to every file type.
    if want == 0 {
        return true;
    }
    // Prefer the precise `.ftm`-derived type when available (strict typing).
    if let Some(detected) = ctx.detected_target {
        return want == detected;
    }
    // Concrete magic-based typing. ClamAV always types the file and only runs a
    // signature whose Target matches; without this, a type-specific signature
    // (e.g. a SWF `Target:11` exploit rule) fires on unrelated files (a PE DLL
    // that merely contains the same strings) — a real false positive. So if the
    // file is a KNOWN type different from the signature's target, reject it. This
    // gate applies even in non-strict mode; it only rejects clear cross-type
    // mismatches, never an indeterminate type (which stays permissive to avoid
    // false negatives).
    if let Some(detected) = detect_builtin_target(ctx) {
        return want == detected;
    }
    match want {
        3 => looks_like_html(ctx.data),
        7 => looks_like_ascii_text(ctx.data),
        _ => true,
    }
}

/// Best-effort concrete file-type detection by magic → ClamAV target number.
/// Returns `Some` only for confident detections (so callers reject clear
/// cross-type mismatches); `None` when indeterminate (callers stay permissive).
fn detect_builtin_target(ctx: &ScanContext<'_>) -> Option<u32> {
    let d = ctx.data;
    if d.starts_with(b"\x7fELF") {
        return Some(6); // CL_TYPE_ELF
    }
    if d.starts_with(b"%PDF") {
        return Some(10); // CL_TYPE_PDF
    }
    if d.starts_with(b"GIF8")
        || d.starts_with(&[0x89, b'P', b'N', b'G'])
        || d.starts_with(&[0xff, 0xd8, 0xff])
    {
        return Some(5); // CL_TYPE_GRAPHICS
    }
    if d.len() >= 4 && d[..4] == [0x64, 0x65, 0x78, 0x0a] {
        return Some(16); // CL_TYPE_DEX
    }
    if d.len() >= 4 && d[..2] == [0x50, 0x4b] && d[2] == 0x03 && d[3] == 0x04 {
        return Some(17); // CL_TYPE_ZIP_APK
    }
    None
}

fn clamav_type_to_target(clamav_type: &str) -> Option<u32> {
    Some(match clamav_type {
        "CL_TYPE_OLE2" | "CL_TYPE_MSOLE2" => 2,
        "CL_TYPE_HTML" => 3,
        "CL_TYPE_GRAPHICS" | "CL_TYPE_GIF" | "CL_TYPE_PNG" | "CL_TYPE_JPEG" => 5,
        "CL_TYPE_ELF" => 6,
        "CL_TYPE_TEXT_ASCII" => 7,
        "CL_TYPE_PDF" => 10,
        "CL_TYPE_SWF" => 11,
        "CL_TYPE_ZIP" | "CL_TYPE_APK" => 17,
        "CL_TYPE_DEX" => 16,
        _ => return None,
    })
}

fn looks_like_ascii_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(8192)];
    // Fail-fast: once the non-printable count exceeds 15% of the sample we
    // know the result without scanning the rest of the sample.
    let threshold = sample.len() * 15 / 100 + 1;
    let mut non_printable = 0usize;
    for &byte in sample {
        if !matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e) {
            non_printable += 1;
            if non_printable >= threshold {
                return false;
            }
        }
    }
    true
}

fn looks_like_html(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(4096)];
    // Scan for '<' first (fast byte search), then do case-insensitive prefix
    // comparison only at those positions. This avoids three full O(n) passes.
    for i in 0..sample.len() {
        if sample[i] != b'<' {
            continue;
        }
        let rest = &sample[i..];
        if rest.len() >= 5
            && rest[1..5].eq_ignore_ascii_case(b"html")
            && (rest.len() == 5 || !rest[5].is_ascii_alphanumeric())
        {
            return true; // <html
        }
        if rest.len() >= 14
            && rest[1..14].eq_ignore_ascii_case(b"!doctype html")
        {
            return true; // <!doctype html
        }
        if rest.len() >= 7
            && rest[1..7].eq_ignore_ascii_case(b"script")
            && (rest.len() == 7 || !rest[7].is_ascii_alphanumeric())
        {
            return true; // <script
        }
    }
    false
}

fn is_unsupported_archive(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] // RAR v5
    || data.len() >= 7 && data[..7] == [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] // RAR v1.5
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{
        ContainerSignature, ContainerType, ExtendedSignature, FileTypeMagic, NumSpec, OffsetSpec,
        SourceLocation,
    };
    use crate::logical::parse_logical_signature;
    use crate::pattern::{compile_pattern_variants, Modifiers};

    #[test]
    fn scans_extended_signature() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Signature"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap().into(),
                source: source.clone(),
            }],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled(), yara: Vec::new() };
        let found = engine.scan_bytes(b"xxABCyy", ScanOptions::default());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Test.Signature");
        assert_eq!(found[0].source, source);
        assert_eq!(found[0].object_path, "root");
        assert_eq!(found[0].view, ScanView::Raw);
    }

    #[test]
    fn prefilter_matches_exhaustive_scan() {
        // Same DB scanned with the real Aho-Corasick prefilter ("ABC" is the atom)
        // must give identical results: matches when the atom is present, skips
        // (no false negative, no false positive) when it isn't.
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Signature"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap().into(),
                source: source.clone(),
            }],
            name_arena,
            ..Default::default()
        };
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        let engine = Engine { database, prefilter, yara: Vec::new() };

        // Atom present → detected.
        let hit = engine.scan_bytes(b"xxABCyy", ScanOptions::default());
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].name, "Test.Signature");

        // Atom absent → correctly skipped, no match.
        let miss = engine.scan_bytes(b"xxxyyyzzz", ScanOptions::default());
        assert!(miss.is_empty());
    }

    #[test]
    fn scans_extracted_zip_child() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Zip.Child"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("4d414c57415245", Modifiers::default()).unwrap().into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled(), yara: Vec::new() };
        let found = engine.scan_bytes(&stored_zip("child.bin", b"MALWARE"), ScanOptions::default());
        assert!(found.iter().any(|hit| {
            hit.name == "Test.Zip.Child"
                && hit.object_path == "root#archive[0]"
                && hit.view == ScanView::Raw
        }));
    }

    #[test]
    fn scans_pcre_logical_signature() {
        let (sig, warnings) = crate::logical::parse_logical_signature(
            "Test.Pcre;Target:0;0&1;4141;0/world/",
            SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ldb")),
                line: 1,
            },
        )
        .unwrap();
        assert!(warnings.is_empty());
        let database = Database {
            logical: vec![sig],
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled(), yara: Vec::new() };
        // Body "AA" present and regex "world" present -> match.
        let found = engine.scan_bytes(b"AA hello world", ScanOptions::default());
        assert!(found.iter().any(|m| m.name == "Test.Pcre"));
        // Body trigger "AA" absent -> PCRE not evaluated -> no match.
        let none = engine.scan_bytes(b"hello world", ScanOptions::default());
        assert!(none.is_empty());
    }

    #[test]
    fn scans_byte_compare_logical_signature() {
        let (sig, warnings) = crate::logical::parse_logical_signature(
            "Test.Bc;Target:0;0&1;53495a45;0(>>4#il2#>0)",
            SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ldb")),
                line: 1,
            },
        )
        .unwrap();
        assert!(warnings.is_empty());
        let database = Database {
            logical: vec![sig],
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled(), yara: Vec::new() };
        // "SIZE" then 2 LE bytes = 5 (>0) -> match.
        let found = engine.scan_bytes(b"SIZE\x05\x00tail", ScanOptions::default());
        assert!(found.iter().any(|m| m.name == "Test.Bc"));
        // 2 LE bytes = 0 -> byte-compare fails.
        let none = engine.scan_bytes(b"SIZE\x00\x00tail", ScanOptions::default());
        assert!(none.is_empty());
    }

    #[test]
    fn scans_container_metadata_signature() {
        let container = ContainerSignature {
            name: "Test.Cdb".into(),
            container_type: ContainerType::Format("zip"),
            container_size: NumSpec::Any,
            has_filename: false,
            size_in_container: NumSpec::Any,
            size_real: NumSpec::Exact(7),
            encrypted: None,
            file_pos: NumSpec::Exact(1),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.cdb")),
                line: 1,
            },
        };
        let database = Database {
            container: vec![container],
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled(), yara: Vec::new() };
        // Member "MALWARE" is 7 bytes at position 1 inside a zip.
        let found =
            engine.scan_bytes(&stored_zip("child.bin", b"MALWARE"), ScanOptions::default());
        assert!(found
            .iter()
            .any(|m| m.name == "Test.Cdb" && m.kind == SignatureKind::Container));
    }

    #[test]
    fn ftm_strict_typing_filters_mismatched_target() {
        let magic = FileTypeMagic {
            offset: OffsetSpec {
                anchor: OffsetAnchor::Absolute(0),
                max_shift: None,
            },
            patterns: compile_pattern_variants("4d5a", Modifiers::default()).unwrap().into(),
            clamav_type: "CL_TYPE_MSEXE".into(),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ftm")),
                line: 1,
            },
        };
        let mut name_arena = String::new();
        let ext = ExtendedSignature {
            name: crate::database::intern_name(&mut name_arena, "Html.Sig"),
            target: Some(3),
            offset: OffsetSpec::any(),
            patterns: compile_pattern_variants("4142", Modifiers::default()).unwrap().into(),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ndb")),
                line: 1,
            },
        };
        let database = Database {
            extended: vec![ext],
            file_type_magic: vec![magic],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled(), yara: Vec::new() };
        // "MZAB": .ftm types it MSEXE (target 1); the sig's target 3 -> filtered by target_matches.
        assert!(engine.scan_bytes(b"MZAB", ScanOptions::default()).is_empty());
    }

    // --- Offset-threading equivalence: the built prefilter (threaded verify +
    // gating cutoff) must report EXACTLY the same signatures as a disabled
    // prefilter (full per-position scan, the ground truth). This is the core
    // "no detection regression" guarantee for offset-threading. ---

    fn match_keys(found: &[ScanMatch]) -> Vec<String> {
        let mut v: Vec<String> = found
            .iter()
            .map(|m| format!("{}@{}", m.name, m.object_path))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    fn assert_threading_equiv(build_db: impl Fn() -> Database, data: &[u8]) -> Vec<String> {
        let opts = ScanOptions::default();
        // Ground truth: prefilter disabled → Candidates::All → full scan, no gating.
        let engine_full = Engine {
            database: build_db(),
            prefilter: crate::prefilter::AtomPrefilter::disabled(),
            yara: Vec::new(),
        };
        let full = match_keys(&engine_full.scan_bytes(data, opts));
        // Threaded: real prefilter → candidate offsets + aligned gating cutoff.
        let db = build_db();
        let prefilter = crate::prefilter::AtomPrefilter::build(&db);
        let engine_thr = Engine {
            database: db,
            prefilter,
            yara: Vec::new(),
        };
        let threaded = match_keys(&engine_thr.scan_bytes(data, opts));
        assert_eq!(
            full, threaded,
            "offset-threading changed the match set on {:?}",
            String::from_utf8_lossy(data)
        );
        threaded
    }

    fn diverse_database() -> Database {
        let src = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("t.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let mut ext = |name: &str, target: u32, offset: OffsetSpec, body: &str, m: Modifiers| {
            ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, name),
                target: Some(target),
                offset,
                patterns: compile_pattern_variants(body, m).unwrap().into(),
                source: src.clone(),
            }
        };
        let nocase = Modifiers {
            nocase: true,
            ..Modifiers::default()
        };
        let extended = vec![
            // Anchored literal, fixed prefix 0.
            ext("E.Anchored", 0, OffsetSpec::any(), "4141414142424242", Modifiers::default()),
            // Masked first byte then literal → required_prefix = 1 (threaded at off-1).
            ext("E.MaskedPrefix", 0, OffsetSpec::any(), "??48495051", Modifiers::default()),
            // nocase → no required_literal → find_all_at falls back to full scan.
            ext("E.Nocase", 0, OffsetSpec::any(), "6d616c7761726e", nocase),
            // nocase atom made of DIGITS only ("012345") — must still match on a
            // letterless buffer (guards against an "is there a letter?" skip).
            ext("E.NocaseDigits", 0, OffsetSpec::any(), "303132333435", nocase),
            // Leading wildcard → required_prefix None → fallback path.
            ext("E.LeadingWild", 0, OffsetSpec::any(), "*5a5a5a5a", Modifiers::default()),
            // Absolute offset 0 only: a match elsewhere must be rejected by ranges.
            ext(
                "E.AbsZero",
                0,
                OffsetSpec { anchor: OffsetAnchor::Absolute(0), max_shift: None },
                "57575757",
                Modifiers::default(),
            ),
            // EOF-relative: only the tail occurrence is in range.
            ext(
                "E.EofTail",
                0,
                OffsetSpec { anchor: OffsetAnchor::EofMinus(8), max_shift: Some(8) },
                "59595959",
                Modifiers::default(),
            ),
        ];
        drop(ext); // release the &mut name_arena borrow so the arena can move below
        let logical: Vec<_> = [
            "L.And;Target:0;0&1;6b6b6b6b6b6b;6c6c6c6c6c6c", // "kkkkkk" & "llllll"
            "L.Or;Target:0;0|1;6d6d6d6d6d6d;6e6e6e6e6e6e",  // "mmmmmm" | "nnnnnn"
            "L.AndWild;Target:0;0&1;*6f6f6f6f6f6f;707070707070", // "*oooooo" & "pppppp"
        ]
        .iter()
        .map(|line| parse_logical_signature(line, src.clone()).unwrap().0)
        .collect();
        Database {
            extended,
            logical,
            name_arena,
            ..Default::default()
        }
    }

    #[test]
    fn threading_matches_full_scan_across_signature_shapes() {
        // Kitchen-sink buffer triggering a mix of shapes.
        let hits = assert_threading_equiv(
            diverse_database,
            b"00AAAABBBB00 zHIPQ MALWARN prefix-ZZZZ kkkkkk llllll oooooo pppppp",
        );
        // Not vacuous: confirm representative detections actually fired.
        assert!(hits.iter().any(|k| k.starts_with("E.Anchored@")));
        assert!(hits.iter().any(|k| k.starts_with("E.MaskedPrefix@")));
        assert!(hits.iter().any(|k| k.starts_with("E.Nocase@"))); // nocase MALWARN
        assert!(hits.iter().any(|k| k.starts_with("E.LeadingWild@")));
        assert!(hits.iter().any(|k| k.starts_with("L.And@")));
        assert!(hits.iter().any(|k| k.starts_with("L.AndWild@")));

        // Range-sensitive negatives: an out-of-range occurrence must NOT match,
        // identically for threaded and full scan (catches range-bypass bugs).
        // "WWWW" only away from offset 0 → E.AbsZero must not fire.
        let no_abs = assert_threading_equiv(diverse_database, b"....WWWW....");
        assert!(!no_abs.iter().any(|k| k.starts_with("E.AbsZero@")));
        // "WWWW" at offset 0 → E.AbsZero fires.
        let abs = assert_threading_equiv(diverse_database, b"WWWW........");
        assert!(abs.iter().any(|k| k.starts_with("E.AbsZero@")));

        // "YYYY" only at the start → outside the EOF-8 tail window → no match.
        let mut early = b"YYYY".to_vec();
        early.extend(std::iter::repeat(b'.').take(40));
        let no_eof = assert_threading_equiv(diverse_database, &early);
        assert!(!no_eof.iter().any(|k| k.starts_with("E.EofTail@")));
        // "YYYY" in the tail window → match.
        let mut late = vec![b'.'; 40];
        late.extend_from_slice(b"YYYY");
        let eof = assert_threading_equiv(diverse_database, &late);
        assert!(eof.iter().any(|k| k.starts_with("E.EofTail@")));

        // Logical AND with one operand missing → no match (both engines agree).
        let partial = assert_threading_equiv(diverse_database, b"kkkkkk but no ell");
        assert!(!partial.iter().any(|k| k.starts_with("L.And@")));

        // LETTERLESS buffer containing a digit-only nocase atom: the nocase pass
        // must NOT be skipped (regression guard for the alpha-byte fast-path).
        let digits = assert_threading_equiv(diverse_database, b"##!!##012345##!!##");
        assert!(digits.iter().any(|k| k.starts_with("E.NocaseDigits@")));

        // Empty-ish / no-trigger buffer.
        assert_threading_equiv(diverse_database, b"nothing to see here 12345");
    }

    // --- TDB (target description block) gating: a logical signature only fires
    // when its Container/FileSize/NumberOfSections context holds, and is skipped
    // entirely when gated by something we can't evaluate (IconGroup). This is the
    // fix for the mass false-positive where icon/container-gated heuristics fired
    // on every file. ---

    fn tdb_src() -> SourceLocation {
        SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("t.ldb")),
            line: 1,
        }
    }

    fn engine_with_logical(line: &str) -> (Engine, Vec<String>) {
        let (sig, warnings) = parse_logical_signature(line, tdb_src()).unwrap();
        let database = Database {
            logical: vec![sig],
            ..Default::default()
        };
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        (
            Engine {
                database,
                prefilter,
                yara: Vec::new(),
            },
            warnings,
        )
    }

    #[test]
    fn or_indexed_window_restriction_matches() {
        // `0|1` is OR-indexed (no required subsig) → every subsig is scanned only
        // in windows around the prefilter's union atom offsets. Exercises the
        // tricky case where the atom is NOT at the match start: subsig 0 is
        // `??powershell` (wildcard then the literal), so a real match starts one
        // byte BEFORE the "powershell" atom — the window must still cover it.
        let (engine, w) = engine_with_logical(
            "Test.Or;Target:0;0|1;??706f7765727368656c6c;636572747574696c",
        );
        assert!(w.is_empty());
        // "Xpowershell" (any byte then the literal) → subsig 0 matches.
        assert!(engine
            .scan_bytes(b"....Xpowershell....", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Or"));
        // "certutil" at the very end of the buffer → subsig 1 matches.
        assert!(engine
            .scan_bytes(b"junkjunkcertutil", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Or"));
        // Atom right at offset 0 (wildcard prefix consumes the byte before it does
        // not exist) — "Apowershell" at start still matches via subsig 0.
        assert!(engine
            .scan_bytes(b"Apowershell tail", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Or"));
        // Neither keyword present → no match (window restriction must not invent one).
        assert!(engine
            .scan_bytes(b"nothing to see here", ScanOptions::default())
            .is_empty());
    }

    #[test]
    fn compare_sibling_does_not_drop_logical_candidate() {
        // `(0=2)|1` matches if subsig 0 occurs exactly twice OR subsig 1 is
        // present. The prefilter's required-subsig probe must NOT wrongly gate this
        // on subsig 1: setting siblings to a huge count makes `0=2` falsely false,
        // which previously flagged subsig 1 as "required" and dropped the candidate
        // when the match came via `0=2` with subsig 1 absent. Regression for a
        // false negative found by adversarial audit.
        let (engine, w) = engine_with_logical("Test.Cmp;Target:0;(0=2)|1;4142;5859");
        assert!(w.is_empty());
        // subsig 0 ("AB") twice, subsig 1 ("XY") absent → `0=2` true → must match.
        let found = engine.scan_bytes(b"AB__AB__", ScanOptions::default());
        assert!(
            found.iter().any(|m| m.name == "Test.Cmp"),
            "false negative: (0=2) match dropped by prefilter gate selection"
        );
    }

    #[test]
    fn less_than_sibling_does_not_drop_logical_candidate() {
        // `(0|1)&(2<3)`: matches when (0 or 1 present) AND subsig 2 occurs < 3
        // times. A non-zero-but-small subsig-2 count satisfies `2<3`, which the
        // max-sibling probe (count = 1<<30) wrongly judges unsatisfiable.
        let (engine, w) =
            engine_with_logical("Test.Lt;Target:0;(0|1)&(2<3);4142;5859;4344");
        assert!(w.is_empty());
        // subsig 1 ("XY") present, subsig 0 absent, subsig 2 ("CD") twice (<3) → match.
        let found = engine.scan_bytes(b"XY__CD__CD", ScanOptions::default());
        assert!(
            found.iter().any(|m| m.name == "Test.Lt"),
            "false negative: (2<3) match dropped by prefilter gate selection"
        );
    }

    #[test]
    fn tdb_container_gates_match() {
        // Sig requires the object to live inside a ZIP container. Body = "MALWARE".
        let (engine, w) =
            engine_with_logical("Test.InZip;Engine:1-255,Container:CL_TYPE_ZIP,Target:0;0;4d414c57415245");
        assert!(w.is_empty());
        // Top-level "MALWARE" (no parent container) → must NOT fire.
        assert!(engine
            .scan_bytes(b"xxMALWAREyy", ScanOptions::default())
            .is_empty());
        // Same bytes inside a ZIP → child's parent container is CL_TYPE_ZIP → fires.
        let zip = stored_zip("c.bin", b"MALWARE");
        assert!(engine
            .scan_bytes(&zip, ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.InZip"));
    }

    #[test]
    fn swf_target_signature_matches_swf() {
        // A Target:11 (SWF) signature matches actual SWF content.
        let (engine, _) = engine_with_logical(
            "Test.Swf;Engine:81-255,Target:11;(0&1);5669727475616c50726f74656374::i;4b65726e656c3332::i",
        );
        // SWF with both strings present → match.
        let mut swf = b"FWS\x06\x00\x00\x00\x00".to_vec();
        swf.extend_from_slice(b"...VirtualProtect...Kernel32...");
        assert!(engine
            .scan_bytes(&swf, ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Swf"));
    }

    #[test]
    fn tdb_engine_flevel_gates_loading() {
        // Engine:1-5 excludes our ENGINE_FLEVEL (240) → signature never fires.
        let (engine, _) = engine_with_logical("Test.OldEngine;Engine:1-5,Target:0;0;4142");
        assert!(engine.scan_bytes(b"xxAByy", ScanOptions::default()).is_empty());
        // Engine:51-255 includes 240 → fires normally.
        let (engine2, _) = engine_with_logical("Test.NewEngine;Engine:51-255,Target:0;0;4142");
        assert!(engine2
            .scan_bytes(b"xxAByy", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.NewEngine"));
    }

    #[test]
    fn tdb_filesize_gates_match() {
        let (engine, _) =
            engine_with_logical("Test.Size;Engine:1-255,FileSize:5-10,Target:0;0;4142");
        // len 3, below FileSize:5-10 → no match.
        assert!(engine.scan_bytes(b"xAB", ScanOptions::default()).is_empty());
        // len 7, within range → match.
        assert!(engine
            .scan_bytes(b"xxABxxy", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Size"));
    }

    #[test]
    fn tdb_icongroup_never_matches_without_pe() {
        // IconGroup was PE-specific; without PE detection it never matches.
        // No unsupported-TDB warning is produced.
        let (engine, warnings) =
            engine_with_logical("Test.Icon;Engine:1-255,IconGroup1:BROWSER,Target:0;0;4142");
        assert!(
            warnings.is_empty(),
            "IconGroup parsed normally; no unsupported-TDB warning"
        );
        assert!(engine.scan_bytes(b"xxAByy", ScanOptions::default()).is_empty());
    }

    fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut out = Vec::new();
        let local_offset = 0u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        let central_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&local_offset.to_le_bytes());
        out.extend_from_slice(name_bytes);

        let central_size = out.len() as u32 - central_offset;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}
