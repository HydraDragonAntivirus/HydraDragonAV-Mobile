use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Cursor, Read};

const MAX_ENTRY_SCAN: usize = 16 * 1024 * 1024;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dump_features <apk_path>");
        std::process::exit(1);
    }
    let apk_path = &args[1];
    let bytes = fs::read(apk_path).expect("cannot read apk");

    // Debug: entry counting
    {
        let reader = Cursor::new(&bytes);
        match zip::ZipArchive::new(reader) {
            Ok(mut archive) => {
                let total_entries = archive.len();
                let mut names: HashSet<String> = HashSet::new();
                let mut scan_attempted = 0u32;
                let mut scan_ok = 0u32;
                let mut scan_failed = 0u32;

                for i in 0..archive.len() {
                    let name = match archive.by_index(i) {
                        Ok(e) => e.name().to_string(),
                        Err(_) => {
                            scan_failed += 1;
                            continue;
                        }
                    };
                    names.insert(name.to_ascii_lowercase());

                    let lname = name.to_ascii_lowercase();
                    let should_scan = lname == "androidmanifest.xml"
                        || lname == "resources.arsc"
                        || lname.ends_with(".dex")
                        || lname.starts_with("meta-inf/");
                    if !should_scan {
                        continue;
                    }
                    scan_attempted += 1;

                    let mut entry = match archive.by_index(i) {
                        Ok(e) => e,
                        Err(_) => {
                            scan_failed += 1;
                            continue;
                        }
                    };
                    let declared_size = entry.size();
                    let compressed_size = entry.compressed_size();
                    let mut buf = Vec::new();
                    match entry
                        .by_ref()
                        .take(MAX_ENTRY_SCAN as u64)
                        .read_to_end(&mut buf)
                    {
                        Ok(_) => {
                            scan_ok += 1;
                            println!(
                                "  ENTRY: {}  declared_size={}  compress_size={}  actual_read_len={}",
                                name, declared_size, compressed_size, buf.len()
                            );
                        }
                        Err(_) => scan_failed += 1,
                    }
                }

                println!("total_entries={}", total_entries);
                println!("unique_names={}", names.len());
                println!(
                    "scan_attempted={} scan_ok={} scan_failed={}",
                    scan_attempted, scan_ok, scan_failed
                );
            }
            Err(e) => {
                println!("ZIP error: {e}");
            }
        }
    }

    // Tokenize using a dummy vocabulary (all tokens map to UNK=0)
    let vocab = std::collections::HashMap::new();
    let tokenizer = hydradragonml::features::Tokenizer::new(vocab);
    let indices = match tokenizer.tokenize(&bytes) {
        Some(v) => v,
        None => {
            eprintln!("ERROR: tokenize returned None");
            std::process::exit(1);
        }
    };
    println!("token_count={}", indices.len());
    println!("first_20_tokens={:?}", &indices[..indices.len().min(20)]);
}
