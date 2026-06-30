//! Build a `qfilter` (Rank-Select Quotient Filter) from a newline-delimited list
//! and serialize it (postcard) to a `.qf` file the native engine mmaps and
//! queries ZERO-COPY (`FilterRef<'static>`).
//!
//! Replaces the `fastbloom` writer: the device borrows the filter buffer from an
//! mmap, so the bytes stay in the OS page cache (reclaimable) instead of the
//! app's dirty heap — almost no resident RAM for a multi-hundred-MB whitelist.
//!
//! Usage:
//!   qfilter_writer <input.txt> <output.qf> <fpp>
//!   # whitelist (hashes):   qfilter_writer all_sha256.txt whitelist.qf   0.0001
//!   # website (domain/url): qfilter_writer malicious.txt  malicious.qf   0.000001
//!   qfilter_writer --check <file.qf> <item>     # round-trip membership check
//!   qfilter_writer --mem   <file.qf>            # mmap + hold, to measure RSS

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

/// Borrowed (zero-copy) view, matching what the device deserializes.
type FilterRef<'a> = qfilter::Filter<&'a [u8]>;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // `--check <file.qf> <item>`: mmap-free read + membership, verifies round-trip.
    if args.len() == 4 && args[1] == "--check" {
        let bytes = std::fs::read(&args[2]).expect("read qf");
        let f: FilterRef = postcard::from_bytes(&bytes).expect("deserialize");
        println!("contains({}) = {}", args[3], f.contains(args[3].as_str()));
        return;
    }
    // `--mem <file.qf>`: load + hold so an external tool can sanity-check it
    // round-trips. NOTE: the real zero-copy / small-RSS win is the DEVICE path,
    // which mmaps the file (qfilter `FilterRef` borrows page-cache bytes). On the
    // host this just reads the file, so don't read RSS here as representative.
    if args.len() == 3 && args[1] == "--mem" {
        let bytes = std::fs::read(&args[2]).expect("read qf");
        let f: FilterRef = postcard::from_bytes(&bytes).expect("deserialize");
        eprintln!("loaded (sanity contains check = {}); holding 40s", f.contains("x"));
        std::thread::sleep(std::time::Duration::from_secs(40));
        std::hint::black_box(&f);
        return;
    }
    // `--fp <file.qf> <count> <hex|dom>`: empirical false-positive rate. Generate
    // <count> random items that are (with astronomically high probability) NOT in
    // the set, query each, and report hits/count. `hex` = 64-char sha256-style hex
    // (for the whitelist); `dom` = random "<hex>.com" (for the website filters).
    if args.len() == 5 && args[1] == "--fp" {
        let bytes = std::fs::read(&args[2]).expect("read qf");
        let f: FilterRef = postcard::from_bytes(&bytes).expect("deserialize");
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
            // build `len` hex chars from rolling 64-bit randoms (16 nibbles each)
            let mut produced = 0;
            while produced < len {
                let r = next();
                for k in 0..16 {
                    if produced == len { break; }
                    s.push(HEXD[((r >> (k * 4)) & 0xf) as usize] as char);
                    produced += 1;
                }
            }
            if !hex_kind { s.push_str(".com"); }
            if f.contains(s.as_str()) { hits += 1; }
        }
        let rate = hits as f64 / n as f64;
        println!(
            "false positives: {hits}/{n} = {rate:.3e}  (1 in {:.0})",
            if rate > 0.0 { 1.0 / rate } else { f64::INFINITY }
        );
        return;
    }
    if args.len() != 4 {
        eprintln!("usage: qfilter_writer <input.txt> <output.qf> <fpp>");
        eprintln!("       qfilter_writer --fp    <file.qf> <count> <hex|dom>");
        eprintln!("       qfilter_writer --check <file.qf> <item>");
        eprintln!("       qfilter_writer --mem   <file.qf>");
        std::process::exit(2);
    }
    let input = &args[1];
    let output = &args[2];
    let fpp: f64 = args[3].parse().expect("fpp must be a float, e.g. 0.0001");

    // Pass 1: count non-empty lines to size the filter. Duplicates are fine —
    // qfilter is a set (re-inserting an existing item is Ok(false) and consumes
    // no capacity), and the line count is an upper bound on DISTINCT items, so a
    // filter sized for `count` can always hold every distinct entry (we never
    // deduplicate the input; we just let the filter absorb repeats).
    let mut count: u64 = 0;
    {
        let r = BufReader::with_capacity(1 << 20, File::open(input).expect("open input"));
        for line in r.lines() {
            if !line.expect("read").trim().is_empty() {
                count += 1;
            }
        }
    }
    eprintln!("items (lines): {count}, fpp: {fpp}");

    let mut filter = qfilter::Filter::new(count.max(1), fpp).expect("alloc qfilter");

    // Pass 2: stream-insert every line (trimmed). No giant in-memory Vec.
    {
        let r = BufReader::with_capacity(1 << 20, File::open(input).expect("open input"));
        let mut n: u64 = 0;
        for line in r.lines() {
            let line = line.expect("read");
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Err(e) = filter.insert(t) {
                // Should be impossible (capacity == line count >= distinct), but
                // fail loudly rather than ship a partial whitelist.
                eprintln!("FATAL: insert failed at item {n}: {e:?}");
                std::process::exit(1);
            }
            n += 1;
            if n % 20_000_000 == 0 {
                eprintln!("  inserted {n}...");
            }
        }
    }

    let bytes = postcard::to_allocvec(&filter).expect("serialize");
    let mut out = File::create(output).expect("create output");
    out.write_all(&bytes).expect("write");
    eprintln!("wrote {output}: {} bytes", bytes.len());
}
