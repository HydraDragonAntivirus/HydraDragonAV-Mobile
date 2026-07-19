use clap::Parser;
use rusqlite::Connection;
use std::fs;
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
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    text_bytes > sample.len() * 9 / 10
}

fn is_relevant_entry(name: &str, data: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    if (lower.contains("classes") && lower.ends_with(".dex"))
        || lower.ends_with(".so")
        || lower == "androidmanifest.xml"
        || lower.ends_with(".txt")
        || lower.ends_with(".html")
        || lower.ends_with(".htm")
        || lower.ends_with(".js")
        || lower.ends_with(".json")
        || lower.ends_with(".php")
        || lower.ends_with(".py")
        || lower.ends_with(".sh")
        || lower.ends_with(".xml")
    {
        return true;
    }
    if data.starts_with(b"dex\n") || data.starts_with(b"\x7fELF") || data.starts_with(b"<?xml") {
        return true;
    }
    is_text_like(data)
}

fn process_apk(apk_path: &Path) -> Vec<(String, String, String)> {
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
        let mut data = Vec::with_capacity(entry.size() as usize);
        if std::io::Read::read_to_end(&mut entry, &mut data).is_err() {
            continue;
        }
        if !is_relevant_entry(&name, &data) {
            continue;
        }
        let md5 = md5_hex(&data);
        let tlsh = tlsh_rs::hash_bytes(&data)
            .ok()
            .map(|d| d.to_string())
            .unwrap_or_default();
        entries.push((name, md5, tlsh));
    }
    entries
}

fn build_db(db_path: &Path, apk_dir: &Path, is_malicious: bool) {
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
    let mut dir_entries: Vec<PathBuf> = fs::read_dir(apk_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "apk").unwrap_or(false))
        .collect();
    dir_entries.sort();
    if is_malicious {
        let label = apk_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
        conn.execute_batch("BEGIN;").ok();
        for apk_path in &dir_entries {
            print!("  {} ... ", apk_path.display());
            let entries = process_apk(apk_path);
            if entries.is_empty() {
                println!("0 entries");
                continue;
            }
            for (name, md5, tlsh) in &entries {
                if let Err(e) = conn.execute(
                    "INSERT OR IGNORE INTO malicious_entry_cache(md5,tlsh,entry_name,detection_name,added_at) VALUES(?1,?2,?3,?4,?5)",
                    rusqlite::params![md5, tlsh, name, label, now],
                ) {
                    eprintln!("  DB insert error: {}", e);
                }
            }
            println!("{} entries", entries.len());
            total_entries += entries.len();
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
            let entries = process_apk(apk_path);
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
    build_db(&fp_path, &args.good, false);
    if let Some(ref malicious_dir) = args.malicious {
        println!("\nBuilding anti_fn_cache.db from malicious APKs...");
        let fn_path = args.output.join("anti_fn_cache.db");
        build_db(&fn_path, malicious_dir, true);
    }
    println!("\nDone.");
}
