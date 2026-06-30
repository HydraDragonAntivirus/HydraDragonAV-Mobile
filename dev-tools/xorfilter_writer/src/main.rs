//! Build a Binary-Fuse (xor) filter from a newline-delimited list and serialize
//! it to a tagged `.xf` file the native engine loads and queries.
//!
//! Replaces `qfilter_writer`: binary-fuse filters are smaller and faster to
//! query than quotient filters. Construction needs every key in memory at once
//! (binary fuse is not incremental), so we fold each line to a `u64` key, dedupe
//! and build in one shot. The width (BF8/BF16/BF32) is chosen from `fpp` by the
//! shared crate.
//!
//! Usage:
//!   xorfilter_writer <input.txt> <output.xf> <fpp>
//!   # whitelist (hashes):   xorfilter_writer all_sha256.txt whitelist.xf  0.0001
//!   # website (domain/url): xorfilter_writer malicious.txt  malicious.xf  0.000001
//!   xorfilter_writer --check <file.xf> <item>      # round-trip membership check
//!   xorfilter_writer --fp    <file.xf> <count> <hex|dom>   # empirical FP rate

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use hydradragonxorfilter::{build_from_keys, key, XorFilter};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // `--check <file.xf> <item>`: read + membership, verifies round-trip.
    if args.len() == 4 && args[1] == "--check" {
        let bytes = std::fs::read(&args[2]).expect("read xf");
        let f = XorFilter::from_bytes(&bytes).expect("deserialize");
        println!("contains({}) = {}", args[3], f.contains(&args[3]));
        return;
    }

    // `--fp <file.xf> <count> <hex|dom>`: empirical false-positive rate. Generate
    // <count> random items that are (with astronomically high probability) NOT in
    // the set, query each, and report hits/count. `hex` = 64-char sha256-style hex
    // (for the whitelist); `dom` = random "<hex>.com" (for the website filters).
    if args.len() == 5 && args[1] == "--fp" {
        let bytes = std::fs::read(&args[2]).expect("read xf");
        let f = XorFilter::from_bytes(&bytes).expect("deserialize");
        let n: u64 = args[3].parse().expect("count");
        let hex_kind = args[4] == "hex";
        let mut state: u64 = 0x9E3779B97F4A7C15; // fixed seed -> reproducible
        let mut next = || {
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        const HEXD: &[u8; 16] = b"0123456789abcdef";
        let mut hits: u64 = 0;
        let mut s = String::with_capacity(72);
        for _ in 0..n {
            s.clear();
            let len = if hex_kind { 64 } else { 16 };
            let mut produced = 0;
            while produced < len {
                let r = next();
                for k in 0..16 {
                    if produced == len {
                        break;
                    }
                    s.push(HEXD[((r >> (k * 4)) & 0xf) as usize] as char);
                    produced += 1;
                }
            }
            if !hex_kind {
                s.push_str(".com");
            }
            if f.contains(&s) {
                hits += 1;
            }
        }
        let rate = hits as f64 / n as f64;
        println!(
            "false positives: {hits}/{n} = {rate:.3e}  (1 in {:.0})",
            if rate > 0.0 { 1.0 / rate } else { f64::INFINITY }
        );
        return;
    }

    if args.len() != 4 {
        eprintln!("usage: xorfilter_writer <input.txt> <output.xf> <fpp>");
        eprintln!("       xorfilter_writer --fp    <file.xf> <count> <hex|dom>");
        eprintln!("       xorfilter_writer --check <file.xf> <item>");
        std::process::exit(2);
    }
    let input = &args[1];
    let output = &args[2];
    let fpp: f64 = args[3].parse().expect("fpp must be a float, e.g. 0.0001");

    // Fold every non-empty line to a u64 key. Binary fuse needs all keys at once,
    // so we hold them in a Vec (8 B each); the shared builder dedupes (distinct
    // keys are required) before constructing the filter.
    let mut keys: Vec<u64> = Vec::new();
    {
        let r = BufReader::with_capacity(1 << 20, File::open(input).expect("open input"));
        let mut n: u64 = 0;
        for line in r.lines() {
            let line = line.expect("read");
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            keys.push(key(t));
            n += 1;
            if n % 20_000_000 == 0 {
                eprintln!("  hashed {n}...");
            }
        }
    }
    eprintln!("items (lines): {}, fpp: {fpp}", keys.len());

    let bytes = match build_from_keys(keys, fpp) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FATAL: filter construction failed: {e}");
            std::process::exit(1);
        }
    };
    let mut out = File::create(output).expect("create output");
    out.write_all(&bytes).expect("write");
    eprintln!("wrote {output}: {} bytes", bytes.len());
}
