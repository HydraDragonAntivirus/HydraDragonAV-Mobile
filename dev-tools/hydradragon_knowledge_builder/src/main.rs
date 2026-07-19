use clap::Parser;
use rusqlite::Connection;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Parser)]
#[command(name = "hydradragon_knowledge_builder")]
struct Args {
    #[arg(long, required = true)]
    good: PathBuf,
    #[arg(long)]
    malicious: Option<PathBuf>,
    #[arg(long, default_value = ".")]
    output: PathBuf,
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let d = Md5::digest(data);
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn is_text_like(data: &[u8]) -> bool {
    let sample = if data.len() > 256 { &data[..256] } else { data };
    let mut text_bytes: usize = 0;
    let mut i = 0;
    while i < sample.len() {
        let b = sample[i];
        if b.is_ascii_graphic() || b.is_ascii_whitespace() {
            text_bytes += 1;
            i += 1;
        } else if b >= 0x80 {
            // Try to consume a valid UTF-8 multi-byte sequence
            let rem = sample.len() - i;
            if b & 0xE0 == 0xC0 && rem >= 2 && sample[i + 1] & 0xC0 == 0x80 {
                text_bytes += 2;
                i += 2;
            } else if b & 0xF0 == 0xE0 && rem >= 3 && sample[i + 1] & 0xC0 == 0x80 && sample[i + 2] & 0xC0 == 0x80 {
                text_bytes += 3;
                i += 3;
            } else if b & 0xF8 == 0xF0 && rem >= 4
                && sample[i + 1] & 0xC0 == 0x80
                && sample[i + 2] & 0xC0 == 0x80
                && sample[i + 3] & 0xC0 == 0x80
            {
                text_bytes += 4;
                i += 4;
            } else {
                // Invalid UTF-8 leader byte → not text
                i += 1;
            }
        } else {
            // Non-printable ASCII control char (e.g. null, escape) → not text
            i += 1;
        }
    }
    text_bytes > sample.len() * 9 / 10
}

fn is_resource_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("res/layout/")
        || lower.starts_with("res/values/")
        || lower.starts_with("res/menu/")
        || lower.starts_with("res/drawable/")
        || lower.starts_with("res/anim/")
        || lower.starts_with("res/color/")
        || lower.starts_with("res/raw/")
        || lower.starts_with("res/xml/")
}

fn is_obfuscated_xml(data: &[u8]) -> bool {
    let sample = if data.len() > 1024 { &data[..1024] } else { data };
    let non_ascii = sample.iter().filter(|&&b| !b.is_ascii()).count();
    non_ascii > sample.len() / 4
}

fn is_relevant_entry(name: &str, data: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    if (lower.contains("classes")
        && (lower.ends_with(".dex") || lower.ends_with(".vdex") || lower.ends_with(".odex")))
        || lower.ends_with(".so")
        || lower == "androidmanifest.xml"
    {
        return true;
    }
    if data.starts_with(b"dex\n") || data.starts_with(b"vdex") || data.starts_with(b"\x7fELF") {
        return true;
    }
    if is_resource_path(&lower) {
        let is_xml = data.starts_with(b"<?xml");
        if (is_xml && is_obfuscated_xml(data))
            || has_network_indicators(data)
            || has_base64(data)
            || has_embedded_data(data)
        {
            return true;
        }
        return false;
    }
    if data.starts_with(b"<?xml") || is_text_like(data) {
        return true;
    }
    has_network_indicators(data)
}

fn has_network_indicators(data: &[u8]) -> bool {
    let sample = if data.len() > 4096 { &data[..4096] } else { data };
    if let Ok(s) = std::str::from_utf8(sample) {
        if s.contains("http://") || s.contains("https://") || s.contains("www.") {
            return true;
        }
        // IPv4: at least 3 dots within 7 bytes, mostly digits
        if sample.windows(7).any(|w| {
            w.iter().filter(|&&b| b == b'.').count() >= 3
                && w.iter().filter(|&&b| b.is_ascii_digit() || b == b'.').count() >= 7
        }) {
            return true;
        }
        // Domain: word.XXX where XXX is a 2-6 letter TLD (com, org, io, xyz, online, etc.)
        if let Ok(text) = std::str::from_utf8(sample) {
            for part in text.split_whitespace() {
                let part = part.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
                if let Some(dot) = part.rfind('.') {
                    let tld = &part[dot + 1..];
                    if (2..=6).contains(&tld.len()) && tld.bytes().all(|b| b.is_ascii_alphabetic()) {
                        let domain = &part[..dot];
                        if domain.len() >= 2 && domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn has_base64(data: &[u8]) -> bool {
    let sample = if data.len() > 4096 { &data[..4096] } else { data };
    let mut run: usize = 0;
    for &b in sample {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            run += 1;
            if run >= 60 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_embedded_data(data: &[u8]) -> bool {
    let sample = if data.len() > 4096 { &data[..4096] } else { data };
    let printable = sample
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    printable > sample.len() / 4
}

fn process_apk(apk_path: &Path, compute_tlsh: bool) -> Vec<(String, String, String)> {
    let file = match fs::read(apk_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  SKIP {}: {}", apk_path.display(), e);
            return Vec::new();
        }
    };
    let mut archive = match ZipArchive::new(std::io::Cursor::new(&file)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("  SKIP {}: not a valid zip: {}", apk_path.display(), e);
            return Vec::new();
        }
    };
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.name().to_string();
        if entry.is_dir() || name.starts_with("META-INF/") {
            continue;
        }
        let entry_size = entry.size() as usize;
        let header_size = 4096.min(entry_size);
        let mut header = vec![0u8; header_size];
        let mut pos = 0;
        while pos < header_size {
            match entry.read(&mut header[pos..]) {
                Ok(0) => break,
                Ok(n) => pos += n,
                Err(_) => break,
            }
        }
        header.truncate(pos);
        if !is_relevant_entry(&name, &header) {
            continue;
        }
        let remaining = entry_size.saturating_sub(header.len());
        let mut full_data = header;
        if remaining > 0 {
            full_data.reserve(remaining);
            let mut tail = vec![0u8; remaining];
            pos = 0;
            while pos < remaining {
                match entry.read(&mut tail[pos..]) {
                    Ok(0) => break,
                    Ok(n) => pos += n,
                    Err(_) => break,
                }
            }
            tail.truncate(pos);
            full_data.extend_from_slice(&tail);
        }
        let md5 = md5_hex(&full_data);
        let tlsh = if compute_tlsh {
            tlsh_rs::hash_bytes(&full_data)
                .ok()
                .map(|d| d.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        entries.push((name, md5, tlsh));
    }
    entries
}

fn build_db(db_path: &Path, apk_dir: &Path, is_malicious: bool, fp_cache: Option<&Path>) {
    if !apk_dir.is_dir() {
        eprintln!("ERROR: {} is not a directory", apk_dir.display());
        return;
    }
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: failed to create database: {}", e);
            return;
        }
    };
    conn.execute_batch("PRAGMA cache_size=-2000; PRAGMA page_size=4096; PRAGMA synchronous=OFF")
        .ok();
    if is_malicious {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS malicious_entry_cache (
                md5 TEXT PRIMARY KEY,
                tlsh TEXT NOT NULL DEFAULT '',
                entry_name TEXT NOT NULL,
                detection_name TEXT NOT NULL DEFAULT '',
                added_at INTEGER NOT NULL
            );",
        )
        .ok();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_tlsh ON malicious_entry_cache(tlsh);",
        )
        .ok();
    } else {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entry_cache (
                md5 TEXT PRIMARY KEY,
                tlsh TEXT NOT NULL DEFAULT '',
                entry_name TEXT NOT NULL,
                source_apk_pkg TEXT NOT NULL DEFAULT '',
                added_at INTEGER NOT NULL
            );",
        )
        .ok();
        conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_tlsh ON entry_cache(tlsh);")
            .ok();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut total_entries = 0usize;
    let mut apk_count = 0usize;
    let mut dir_entries: Vec<PathBuf> = walkdir::WalkDir::new(apk_dir)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                .map(|s| s.eq_ignore_ascii_case("invalid"))
                .unwrap_or(false)
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|p| p.extension().map(|e| e == "apk").unwrap_or(false))
        .collect();
    dir_entries.sort();
    if is_malicious {
        let label = apk_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
        conn.execute_batch("BEGIN;").ok();
        let fp_conn = fp_cache.and_then(|p| Connection::open(p).ok());
        for apk_path in &dir_entries {
            print!("  {} ... ", apk_path.display());
            let data = match fs::read(apk_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("SKIP: {}", e);
                    continue;
                }
            };
            let mut inserted = 0;
            // 1. Full APK hash (exact-match detection)
            let apk_md5 = md5_hex(&data);
            let apk_tlsh = tlsh_rs::hash_bytes(&data)
                .ok()
                .map(|d| d.to_string())
                .unwrap_or_default();
            if conn.execute(
                "INSERT OR IGNORE INTO malicious_entry_cache(md5,tlsh,entry_name,detection_name,added_at) VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![&apk_md5, &apk_tlsh, "apk", &label, now],
            ).is_ok() { inserted += 1; }
            // 2. Individual entries unique to this malware (not in FP)
            let entries = process_apk(apk_path, true);
            for (name, md5, tlsh) in &entries {
                if let Some(ref fp) = fp_conn {
                    let in_fp: bool = fp
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM entry_cache WHERE md5 = ?1)",
                            rusqlite::params![md5],
                            |r| r.get(0),
                        )
                        .unwrap_or(false);
                    if in_fp {
                        continue;
                    }
                }
                if conn.execute(
                    "INSERT OR IGNORE INTO malicious_entry_cache(md5,tlsh,entry_name,detection_name,added_at) VALUES(?1,?2,?3,?4,?5)",
                    rusqlite::params![md5, tlsh, name, &label, now],
                ).is_ok() { inserted += 1; }
            }
            println!("{} entries ({} unique)", entries.len() + 1, inserted);
            total_entries += inserted;
            apk_count += 1;
        }
        conn.execute_batch("COMMIT;").ok();
    } else {
        conn.execute_batch("BEGIN;").ok();
        for apk_path in &dir_entries {
            print!("  {} ... ", apk_path.display());
            let source_pkg = apk_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let entries = process_apk(apk_path, false);
            if entries.is_empty() {
                println!("0 entries");
                continue;
            }
            for (name, md5, tlsh) in &entries {
                if let Err(e) = conn.execute(
                    "INSERT OR IGNORE INTO entry_cache(md5,tlsh,entry_name,source_apk_pkg,added_at) VALUES(?1,?2,?3,?4,?5)",
                    rusqlite::params![md5, tlsh, name, source_pkg, now],
                ) {
                    eprintln!("  DB insert error: {}", e);
                }
            }
            println!("{} entries", entries.len());
            total_entries += entries.len();
            apk_count += 1;
        }
        conn.execute_batch("COMMIT;").ok();
    }
    conn.execute_batch("VACUUM;").ok();
    let db_size = fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "  Done: {} APKs, {} entries, {} KB database",
        apk_count,
        total_entries,
        db_size / 1024
    );
}

fn main() {
    let args = Args::parse();
    fs::create_dir_all(&args.output).ok();
    println!("Building anti_fp_cache.db from good APKs...");
    let fp_path = args.output.join("anti_fp_cache.db");
    build_db(&fp_path, &args.good, false, None);
    if let Some(ref malicious_dir) = args.malicious {
        println!("\nBuilding anti_fn_cache.db from malicious APKs...");
        let fn_path = args.output.join("anti_fn_cache.db");
        build_db(&fn_path, malicious_dir, true, Some(&fp_path));
    }
    println!("\nDone.");
}
