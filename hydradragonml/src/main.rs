use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use hydradragonml::{features, Model, DEFAULT_CONFIDENCE_THRESHOLD};
use hydradragonxorfilter::XorFilter;
use walkdir::WalkDir;

struct Args {
    dataset: PathBuf,
    model: Option<PathBuf>,
    whitelist_xf: Option<PathBuf>,
    whitelist_packages_db: Option<PathBuf>,
    threshold: f32,
}

fn parse_args() -> Args {
    let mut dataset = None;
    let mut model = None;
    let mut whitelist_xf = None;
    let mut whitelist_packages_db = None;
    let mut threshold = DEFAULT_CONFIDENCE_THRESHOLD;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dataset" | "-d" => {
                dataset = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--dataset requires a path"),
                );
            }
            "--model" | "-m" => {
                model = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--model requires a path"),
                );
            }
            "--whitelist" | "-w" => {
                whitelist_xf = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--whitelist requires a path"),
                );
            }
            "--packages" | "-p" => {
                whitelist_packages_db = Some(
                    args.next()
                        .map(PathBuf::from)
                        .expect("--packages requires a path"),
                );
            }
            "--threshold" | "-t" => {
                threshold = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("--threshold requires a float");
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    Args {
        dataset: dataset.expect("--dataset is required"),
        model,
        whitelist_xf,
        whitelist_packages_db,
        threshold,
    }
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let digest = Md5::digest(data);
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn rd_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn rd_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn axml_strings(data: &[u8]) -> Option<Vec<String>> {
    if rd_u16(data, 0)? != 0x0003 {
        return None;
    }
    let _hdr_size = rd_u32(data, 4)? as usize;
    let pool_off = rd_u32(data, 8 + 4)? as usize;
    let _pool_size = rd_u32(data, 8 + 8)? as usize;
    let str_count = rd_u32(data, 8 + 16)? as usize;
    let str_indices_off = rd_u32(data, 8 + 28)? as usize;
    let str_data_off = rd_u32(data, 8 + 32)? as usize;
    let flags = rd_u32(data, 8 + 24)?;
    let is_utf8 = (flags & (1 << 8)) != 0;
    let mut strings = Vec::with_capacity(str_count);
    for i in 0..str_count {
        let off = pool_off + str_indices_off as usize + i * 4;
        let str_offset = rd_u32(data, off)? as usize;
        let str_start = pool_off + str_data_off as usize + str_offset;
        if is_utf8 {
            let len_byte = data.get(str_start)?;
            let skip = if *len_byte & 0x80 != 0 { 2 } else { 1 };
            let str_len = if skip == 1 { *len_byte as usize } else {
                u16::from_le_bytes([data[str_start], data[str_start + 1]]) as usize
            };
            let content_start = str_start + skip;
            let content_end = content_start + str_len;
            if content_end <= data.len() {
                if let Ok(s) = std::str::from_utf8(&data[content_start..content_end]) {
                    strings.push(s.to_string());
                } else {
                    strings.push(String::new());
                }
            } else {
                strings.push(String::new());
            }
        } else {
            let len_byte = rd_u16(data, str_start)?;
            let skip = if len_byte & 0x8000 != 0 { 4 } else { 2 };
            let str_len = if skip == 2 { len_byte as usize } else {
                rd_u32(data, str_start)? as usize
            };
            let content_start = str_start + skip;
            let content_end = content_start + str_len * 2;
            let mut s = Vec::with_capacity(str_len);
            for j in (content_start..content_end).step_by(2) {
                let lo = data.get(j).copied().unwrap_or(0);
                s.push(lo);
            }
            strings.push(String::from_utf8_lossy(&s).to_string());
        }
    }
    Some(strings)
}

fn axml_package(apk_bytes: &[u8]) -> Option<String> {
    let reader = std::io::Cursor::new(apk_bytes);
    let mut archive = zip::ZipArchive::new(reader).ok()?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).ok()?;
        let lname = entry.name().to_ascii_lowercase();
        if lname != "androidmanifest.xml" {
            continue;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).ok()?;
        return extract_package_from_axml(&buf);
    }
    None
}

fn extract_package_from_axml(data: &[u8]) -> Option<String> {
    if rd_u16(data, 0)? != 0x0003 {
        return None;
    }
    let strings = axml_strings(data)?;
    let pool_size = rd_u32(data, 8 + 4)? as usize;
    let mut off = 8 + pool_size;
    let mut guard = 0;
    while off + 8 <= data.len() && guard < 100_000 {
        guard += 1;
        let ctype = rd_u16(data, off)?;
        let csize = rd_u32(data, off + 4)? as usize;
        if csize == 0 {
            break;
        }
        if ctype == 0x0102 {
            let name_idx = rd_u32(data, off + 20)? as usize;
            if strings.get(name_idx).map(|s| s.as_str() == "manifest").unwrap_or(false) {
                let attr_start = rd_u16(data, off + 24)? as usize;
                let attr_count = rd_u16(data, off + 28)? as usize;
                let abase = off + 16 + attr_start;
                for i in 0..attr_count.min(256) {
                    let a = abase + i * 20;
                    let aname = rd_u32(data, a + 4)? as usize;
                    if strings.get(aname).map(|s| s.as_str() == "package").unwrap_or(false) {
                        let raw = rd_u32(data, a + 8)?;
                        let idx = if raw != 0xFFFF_FFFF {
                            raw as usize
                        } else {
                            rd_u32(data, a + 16)? as usize
                        };
                        return strings.get(idx).cloned();
                    }
                }
                return None;
            }
        }
        off = off.checked_add(csize)?;
    }
    None
}

fn load_package_whitelist(path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("WARN: could not read packages whitelist: {e}");
            return out;
        }
    };
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join("hydra_wl_pkg_cli.db");
    if std::fs::write(&tmp_path, &bytes).is_err() {
        eprintln!("WARN: could not write temp package DB");
        return out;
    }
    if let Ok(conn) =
        rusqlite::Connection::open_with_flags(&tmp_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    {
        if let Ok(mut stmt) =
            conn.prepare("SELECT key, md5 FROM whitelist_package WHERE md5 IS NOT NULL")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for row in rows.flatten() {
                    out.insert(row.0, row.1.to_lowercase());
                }
            }
        }
    }
    let _ = std::fs::remove_file(&tmp_path);
    out
}

struct ScanSignature {
    name: String,
}

fn find_apks(root: &Path) -> Vec<PathBuf> {
    let mut apks = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("apk"))
            .unwrap_or(false)
        {
            apks.push(path.to_path_buf());
        }
    }
    apks.sort();
    apks
}

fn main() {
    let args = parse_args();

    if !args.dataset.exists() {
        eprintln!("ERROR: dataset path does not exist: {}", args.dataset.display());
        std::process::exit(1);
    }

    let model = args.model.as_ref().and_then(|p| {
        if !p.exists() {
            eprintln!("WARN: model path does not exist: {}. ML disabled.", p.display());
            return None;
        }
        match Model::load_bin(p) {
            Ok(mut m) => {
                m.set_threshold(args.threshold);
                eprintln!("OK  model loaded: {} (threshold={})", p.display(), args.threshold);
                Some(m)
            }
            Err(e) => {
                eprintln!("WARN: failed to load model {p:?}: {e}. ML disabled.");
                None
            }
        }
    });

    let whitelist = args.whitelist_xf.as_ref().and_then(|p| {
        if !p.exists() {
            eprintln!("WARN: whitelist file not found: {}. NSRL hash whitelist disabled.", p.display());
            return None;
        }
        match XorFilter::load(p) {
            Some(wl) => {
                eprintln!("OK  NSRL hash whitelist loaded: {} entries", p.display());
                Some(wl)
            }
            None => {
                eprintln!("WARN: failed to load whitelist filter: {p:?}");
                None
            }
        }
    });

    let package_whitelist = args.whitelist_packages_db.as_ref().map(|p| {
        if !p.exists() {
            eprintln!("WARN: packages DB not found: {}. Package whitelist disabled.", p.display());
            HashMap::new()
        } else {
            let map = load_package_whitelist(p);
            eprintln!("OK  package whitelist loaded: {} entries from {}", map.len(), p.display());
            map
        }
    });

    if model.is_none() && whitelist.is_none() && package_whitelist.as_ref().map_or(true, |m| m.is_empty()) {
        eprintln!("WARNING: no model, no NSRL whitelist, no package whitelist loaded.");
        eprintln!("Only feature extraction will be performed.");
    }

    let apks = find_apks(&args.dataset);
    eprintln!("\nFound {} APK files. Scanning...\n", apks.len());

    if apks.is_empty() {
        return;
    }

    let mut tp = 0u64;
    let mut fp = 0u64;
    let mut tn = 0u64;
    let mut fn_ = 0u64;
    let mut unknown = 0u64;
    let mut errors = 0u64;
    let mut whitelisted_count = 0u64;
    let mut pkg_whitelisted_count = 0u64;
    let mut ml_benign_not_whitelisted = 0u64;
    let mut total_ms: u128 = 0;

    for apk_path in &apks {
        let expected = ground_truth(apk_path);

        let apk_bytes = match std::fs::read(apk_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ERROR   {} (read: {e})", apk_path.display());
                errors += 1;
                continue;
            }
        };

        let t0 = Instant::now();
        let mut signatures: Vec<ScanSignature> = Vec::new();
        let apk_md5 = md5_hex(&apk_bytes);

        // 1. NSRL hash whitelist — skip ML entirely
        let whitelisted = whitelist.as_ref().is_some_and(|wl| wl.contains(&apk_md5));
        if whitelisted {
            signatures.push(ScanSignature { name: "NSRL.Whitelist".to_string() });
        }

        // 2. Package whitelist — skip ML entirely (only if not already NSRL-whitelisted
        //    AND a package whitelist was actually loaded)
        let has_pkg_wl = package_whitelist.as_ref().is_some_and(|m| !m.is_empty());
        let package_name = if !whitelisted && has_pkg_wl { axml_package(&apk_bytes) } else { None };
        let pkg_whitelisted = !whitelisted && package_whitelist.as_ref().is_some_and(|pkg_map| {
            !pkg_map.is_empty()
                && package_name.as_ref().is_some_and(|pkg| {
                    pkg_map
                        .get(pkg)
                        .is_some_and(|known_md5| known_md5.eq_ignore_ascii_case(&apk_md5))
                })
        });
        if pkg_whitelisted {
            signatures.push(ScanSignature { name: "Package.Whitelist".to_string() });
        }

        // 3. ML model inference — only for non-whitelisted
        let (ml_malicious, ml_confidence, ml_skipped) = if whitelisted || pkg_whitelisted {
            (false, 0.0, true)
        } else {
            match &model {
                Some(m) => {
                    let feats = features::extract(&apk_bytes);
                    match feats {
                        Some(f) => {
                            let result = m.scan_features(&f);
                            (result.malicious, result.confidence, false)
                        }
                        None => (false, 0.0, true),
                    }
                }
                None => (false, 0.0, true),
            }
        };

        if whitelisted {
            whitelisted_count += 1;
        }
        if pkg_whitelisted {
            pkg_whitelisted_count += 1;
        }
        if !ml_skipped && !ml_malicious {
            ml_benign_not_whitelisted += 1;
        }

        if !ml_skipped {
            if ml_malicious {
                signatures.push(ScanSignature {
                    name: format!("ML.Malware/conf={:.4}", ml_confidence),
                });
            } else {
                signatures.push(ScanSignature {
                    name: format!("ML.Benign/conf={:.4}", ml_confidence),
                });
            }
        }

        let elapsed = t0.elapsed().as_millis();
        total_ms += elapsed;

        let relative = apk_path
            .strip_prefix(&args.dataset)
            .unwrap_or(apk_path)
            .display();

        let whitelisted_by_nsrl_or_pkg = whitelisted || pkg_whitelisted;
        let any_malicious = signatures.iter().any(|s| s.name.starts_with("ML.Malware"));

        let pkg_str = package_name
            .as_deref()
            .unwrap_or("(no-pkg)");
        let sigs: Vec<&str> = signatures.iter().map(|s| s.name.as_str()).collect();
        let sig_str = if sigs.is_empty() {
            "(no signatures)"
        } else {
            &sigs.join(", ")
        };

        let verdict = if whitelisted_by_nsrl_or_pkg {
            "WHITELIST"
        } else if any_malicious {
            "MALICIOUS"
        } else {
            "BENIGN"
        };

        println!(
            "  {:<12} {:<50} pkg={:<30} md5={}  [{:.3}s]  {}",
            verdict,
            relative.to_string().chars().take(48).collect::<String>(),
            pkg_str.chars().take(28).collect::<String>(),
            &apk_md5[..16],
            elapsed as f64 / 1000.0,
            sig_str,
        );

        let predicted_malicious = any_malicious;
        if let Some(exp) = expected {
            match (exp, predicted_malicious) {
                (true, true) => tp += 1,
                (true, false) => fn_ += 1,
                (false, true) => fp += 1,
                (false, false) => tn += 1,
            }
        } else {
            unknown += 1;
        }
    }

    println!();
    println!("=== SUMMARY ===");
    println!("Total APKs:       {}", apks.len());
    println!("Errors:           {}", errors);
    println!("Unknown label:    {}", unknown);
    println!("Total time:       {} ms", total_ms);
    if !apks.is_empty() {
        println!("Avg time/APK:     {} ms", total_ms / apks.len() as u128);
    }

    println!();
    println!("=== WHITELIST BREAKDOWN ===");
    println!("NSRL whitelist:   {} APKs skipped ML", whitelisted_count);
    println!("Package whitelist: {} APKs skipped ML", pkg_whitelisted_count);
    println!("Anti-FP candidates (ML.Benign, not whitelisted): {} APKs", ml_benign_not_whitelisted);

    println!();
    println!("=== CLASSIFICATION VS FOLDER LABEL ===");
    println!("True Positives:   {}", tp);
    println!("False Positives:  {}", fp);
    println!("True Negatives:   {}", tn);
    println!("False Negatives:  {}", fn_);
    let total_known = tp + fp + tn + fn_;
    println!("Labeled samples:  {}", total_known);

    if total_known > 0 {
        let accuracy = (tp + tn) as f64 / total_known as f64;
        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall = if tp + fn_ > 0 {
            tp as f64 / (tp + fn_) as f64
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        println!("Accuracy:         {:.4}", accuracy);
        println!("Precision:        {:.4}", precision);
        println!("Recall:           {:.4}", recall);
        println!("F1 Score:         {:.4}", f1);
    }
}

fn ground_truth(path: &Path) -> Option<bool> {
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.contains("benign") || path_str.contains("clean") || path_str.contains("f-droid") {
        Some(false)
    } else if path_str.contains("malware")
        || path_str.contains("malicious")
        || path_str.contains("malwarebazaar")
    {
        Some(true)
    } else {
        None
    }
}
