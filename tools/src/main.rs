use std::time::Instant;

fn hex_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for ch in s.chars() {
        if let Some(d) = ch.to_digit(16) {
            match hi {
                None => hi = Some(d as u8),
                Some(h) => {
                    out.push(h << 4 | d as u8);
                    hi = None;
                }
            }
        }
    }
    out
}

fn decode_content(val: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(val.len());
    let mut in_hex = false;
    let mut hex_buf = String::new();
    for ch in val.chars() {
        if ch == '|' {
            if in_hex {
                if !hex_buf.is_empty() {
                    out.extend_from_slice(&hex_decode(&hex_buf));
                }
                hex_buf.clear();
                in_hex = false;
            } else {
                in_hex = true;
            }
        } else if in_hex {
            hex_buf.push(ch);
        } else {
            out.push(ch as u8);
        }
    }
    if in_hex && !hex_buf.is_empty() {
        out.extend_from_slice(&hex_decode(&hex_buf));
    }
    out
}

fn parse_pcre(raw: &str) -> Option<regex::Regex> {
    let raw = raw.trim();
    if !raw.starts_with('/') { return None; }
    let bs = raw.as_bytes();
    let mut i = 1;
    while i < bs.len() {
        if bs[i] == b'\\' { i += 2; continue; }
        if bs[i] == b'/' { break; }
        i += 1;
    }
    if i >= bs.len() { return None; }
    let pattern = &raw[1..i];
    let flags = &raw[i + 1..];
    let mut fp = String::from(pattern);
    if flags.contains('i') { fp.insert_str(0, "(?i)"); }
    if flags.contains('s') { fp.insert_str(0, "(?s)"); }
    if flags.contains('m') { fp.insert_str(0, "(?m)"); }
    regex::Regex::new(&fp).ok()
}

fn read_quoted<'a>(opts: &'a str, bs: &[u8], pos: &mut usize) -> Option<&'a str> {
    if *pos >= bs.len() || bs[*pos] != b'"' { return None; }
    *pos += 1;
    let val_start = *pos;
    while *pos < bs.len() {
        if bs[*pos] == b'\\' { *pos += 2; continue; }
        if bs[*pos] == b'"' { break; }
        *pos += 1;
    }
    let val = &opts[val_start..*pos];
    if *pos < bs.len() { *pos += 1; }
    Some(val)
}

fn read_unquoted<'a>(opts: &'a str, bs: &[u8], pos: &mut usize) -> &'a str {
    let val_start = *pos;
    while *pos < bs.len() && bs[*pos] != b';' && bs[*pos] != b' ' { *pos += 1; }
    &opts[val_start..*pos]
}

fn skip_value(bs: &[u8], pos: &mut usize) {
    while *pos < bs.len() {
        if bs[*pos] == b';' { break; }
        if bs[*pos] == b'"' {
            *pos += 1;
            while *pos < bs.len() && bs[*pos] != b'"' {
                if bs[*pos] == b'\\' { *pos += 1; }
                *pos += 1;
            }
            if *pos < bs.len() { *pos += 1; }
        } else {
            *pos += 1;
        }
    }
}

struct Rule {
    msg: String,
    sid: u32,
    classtype: String,
    n_patterns: usize,
    flow: Option<String>,
    has_pcre: bool,
    has_offset: bool,
    has_depth: bool,
    has_distance: bool,
    has_within: bool,
}

fn parse_rules(raw: &[u8]) -> (Vec<Rule>, Vec<(Vec<u8>, u32)>) {
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut rules_out: Vec<Rule> = Vec::new();
    let mut pat_dedup: std::collections::HashMap<Vec<u8>, u32> = std::collections::HashMap::new();
    let mut unique_pats: Vec<Vec<u8>> = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        let opt_start = match trimmed.find('(') { Some(p) => p, None => continue, };
        let opt_end = match trimmed.rfind(')') { Some(p) => p, None => continue, };
        if opt_end <= opt_start { continue; }

        let opts = &trimmed[opt_start + 1..opt_end];
        let mut sid = 0u32;
        let mut msg = String::new();
        let mut classtype = String::new();
        let mut flow: Option<String> = None;
        let mut has_pcre = false;
        let mut has_content = false;
        let mut n_patterns = 0;
        let mut has_offset = false;
        let mut has_depth = false;
        let mut has_distance = false;
        let mut has_within = false;
        let mut cur_offset: Option<u32> = None;
        let mut cur_depth: Option<u32> = None;
        let mut cur_distance: Option<u32> = None;
        let mut cur_within: Option<u32> = None;
        let mut pending_nocase = false;

        let mut pos = 0usize;
        let bs = opts.as_bytes();
        let olen = bs.len();

        while pos < olen {
            while pos < olen && (bs[pos] == b' ' || bs[pos] == b';' || bs[pos] == b'\t') { pos += 1; }
            if pos >= olen { break; }

            let key_start = pos;
            while pos < olen && bs[pos] != b':' && bs[pos] != b' ' && bs[pos] != b';' { pos += 1; }
            if pos >= olen || bs[pos] != b':' { continue; }
            let key = &opts[key_start..pos];
            pos += 1;
            while pos < olen && (bs[pos] == b' ' || bs[pos] == b'\t') { pos += 1; }

            match key {
                "msg" => { if let Some(v) = read_quoted(opts, bs, &mut pos) { msg = v.to_string(); } }
                "sid" => { sid = read_unquoted(opts, bs, &mut pos).parse().unwrap_or(0); }
                "classtype" => { classtype = read_unquoted(opts, bs, &mut pos).to_string(); }
                "content" | "uricontent" => {
                    has_content = true;
                    let val = match read_quoted(opts, bs, &mut pos) {
                        Some(v) => v,
                        None => { skip_value(bs, &mut pos); continue; }
                    };
                    let bytes = decode_content(val);
                    if bytes.is_empty() {
                        cur_offset = None; cur_depth = None;
                        cur_distance = None; cur_within = None;
                        continue;
                    }
                    n_patterns += 1;
                    if cur_offset.is_some() { has_offset = true; cur_offset = None; }
                    if cur_depth.is_some() { has_depth = true; cur_depth = None; }
                    if cur_distance.is_some() { has_distance = true; cur_distance = None; }
                    if cur_within.is_some() { has_within = true; cur_within = None; }

                    let len_u32 = unique_pats.len() as u32;
                    pat_dedup.entry(bytes.clone()).or_insert_with(|| {
                        unique_pats.push(bytes.clone());
                        len_u32
                    });

                    if pending_nocase {
                        if bytes.iter().any(|b| b.is_ascii_alphabetic()) {
                            let lower = bytes.to_ascii_lowercase();
                            if lower != bytes {
                                pat_dedup.entry(lower.clone()).or_insert_with(|| {
                                    unique_pats.push(lower);
                                    len_u32
                                });
                            }
                        }
                        pending_nocase = false;
                    }
                    cur_distance = None; cur_within = None;
                }
                "nocase" => { pending_nocase = true; skip_value(bs, &mut pos); }
                "offset" => { cur_offset = read_unquoted(opts, bs, &mut pos).parse().ok(); }
                "depth" => { cur_depth = read_unquoted(opts, bs, &mut pos).parse().ok(); }
                "distance" => { cur_distance = read_unquoted(opts, bs, &mut pos).parse().ok(); }
                "within" => { cur_within = read_unquoted(opts, bs, &mut pos).parse().ok(); }
                "flow" => { let v = read_unquoted(opts, bs, &mut pos).to_string(); if flow.is_none() { flow = Some(v); } }
                "pcre" => { has_pcre = true; skip_value(bs, &mut pos); }
                _ => { skip_value(bs, &mut pos); }
            }
        }

        if has_content && sid > 0 && n_patterns > 0 {
            rules_out.push(Rule { msg, sid, classtype, n_patterns, flow, has_pcre, has_offset, has_depth, has_distance, has_within });
        }
    }

    (rules_out, unique_pats.into_iter().enumerate().map(|(i, p)| (p, i as u32)).collect())
}

fn main() {
    let rules_path = std::env::args().nth(1).unwrap_or_else(|| {
        let base = if cfg!(target_os = "windows") {
            r"..\app\src\main\assets\scan\emerging-all.rules"
        } else {
            "../app/src/main/assets/scan/emerging-all.rules"
        };
        base.to_string()
    });

    println!("Reading {} ...", rules_path);
    let raw = match std::fs::read(&rules_path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Error: could not read '{}': {}", rules_path, e); std::process::exit(1); }
    };
    println!("  {} bytes", raw.len());

    let t0 = Instant::now();
    let (rules, pat_entries) = parse_rules(&raw);
    let t_parse = t0.elapsed();

    println!("  Parsed in {:?}", t_parse);
    println!("  Rules with content + sid: {}", rules.len());
    println!("  Unique patterns:          {}", pat_entries.len());

    let n_flow = rules.iter().filter(|r| r.flow.is_some()).count();
    let n_pcre = rules.iter().filter(|r| r.has_pcre).count();
    let n_offset = rules.iter().filter(|r| r.has_offset).count();
    let n_depth = rules.iter().filter(|r| r.has_depth).count();
    let n_distance = rules.iter().filter(|r| r.has_distance).count();
    let n_within = rules.iter().filter(|r| r.has_within).count();
    let total_pats: usize = rules.iter().map(|r| r.n_patterns).sum();

    println!("  Total content directives: {}", total_pats);
    println!("  Rules with flow:          {}", n_flow);
    println!("  Rules with pcre:          {}", n_pcre);
    println!("  Rules with offset:        {}", n_offset);
    println!("  Rules with depth:         {}", n_depth);
    println!("  Rules with distance:      {}", n_distance);
    println!("  Rules with within:        {}", n_within);
    println!();

    if pat_entries.is_empty() {
        println!("No patterns found.");
        return;
    }

    let t1 = Instant::now();
    let patvals: Vec<(&[u8], u32)> = pat_entries.iter().map(|(p, v)| (p.as_slice(), *v)).collect();
    let ac = daachorse::DoubleArrayAhoCorasick::with_values(patvals).unwrap();
    let t_build = t1.elapsed();
    println!("  daachorse build: {:?}", t_build);
    println!("  Automaton patterns: {}", pat_entries.len());

    if let Some((first_pat, _)) = pat_entries.first() {
        let t2 = Instant::now();
        let n_matches = ac.find_overlapping_iter(first_pat).count();
        let t_scan = t2.elapsed();
        println!("  Overlapping scan of first pattern ({} bytes): {:?} ({} matches)", first_pat.len(), t_scan, n_matches);
    }

    let serialized = ac.serialize();
    println!("  Serialized automaton size: {} bytes", serialized.len());
    println!();
    println!("SUCCESS: emerging-all.rules parsed and loaded successfully.");
}
