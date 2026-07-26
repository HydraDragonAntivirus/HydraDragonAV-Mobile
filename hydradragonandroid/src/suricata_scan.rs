use std::sync::OnceLock;
use daachorse::DoubleArrayAhoCorasick;
use crate::rust_timing_log;

static RULE_ENGINE: OnceLock<RuleEngine> = OnceLock::new();

#[derive(Clone, Copy, PartialEq)]
enum FlowDir {
    ToServer,
    FromServer,
}

struct FlowConstraints {
    to_server: bool,
    from_server: bool,
    established: bool,
    stateless: bool,
}

impl FlowConstraints {
    fn parse(s: &str) -> Self {
        let mut c = FlowConstraints { to_server: false, from_server: false, established: false, stateless: false };
        for part in s.split(',') {
            match part.trim() {
                "to_server" => c.to_server = true,
                "from_server" | "to_client" => c.from_server = true,
                "established" => c.established = true,
                "stateless" => c.stateless = true,
                _ => {}
            }
        }
        c
    }

    fn check(&self, flow_dir: FlowDir) -> bool {
        if self.to_server && flow_dir != FlowDir::ToServer { return false; }
        if self.from_server && flow_dir != FlowDir::FromServer { return false; }
        true
    }
}

struct PacketData {
    payload: Vec<u8>,
    protocol: Option<String>,
    src_port: u16,
    dst_port: u16,
    flow_dir: FlowDir,
}

struct ContentPattern {
    pat_id: u32,
    offset: Option<u32>,
    depth: Option<u32>,
    distance: Option<u32>,
    within: Option<u32>,
}

struct Rule {
    msg: String,
    sid: u32,
    classtype: String,
    patterns: Vec<ContentPattern>,
    flow_constraints: Option<FlowConstraints>,
    pcre: Option<regex::Regex>,
    protocol: Option<String>,
    src_port: Option<String>,
    dst_port: Option<String>,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    ac: DoubleArrayAhoCorasick<u32>,
    pattern_count: usize,
}

#[derive(serde::Serialize)]
pub struct MatchInfo {
    pub name: String,
    pub sid: u32,
    pub classtype: String,
    pub description: String,
}

#[derive(serde::Serialize)]
pub struct ScanResult {
    pub malicious: bool,
    pub matches: Vec<MatchInfo>,
}

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
    if !raw.starts_with('/') {
        return None;
    }
    let bs = raw.as_bytes();
    let mut i = 1;
    while i < bs.len() {
        if bs[i] == b'\\' {
            i += 2;
            continue;
        }
        if bs[i] == b'/' {
            break;
        }
        i += 1;
    }
    if i >= bs.len() {
        return None;
    }
    let pattern = &raw[1..i];
    let flags = &raw[i + 1..];
    let mut fp = String::from(pattern);
    if flags.contains('i') {
        fp.insert_str(0, "(?i)");
    }
    if flags.contains('s') {
        fp.insert_str(0, "(?s)");
    }
    if flags.contains('m') {
        fp.insert_str(0, "(?m)");
    }
    regex::Regex::new(&fp).ok()
}

fn read_quoted<'a>(opts: &'a str, bs: &[u8], pos: &mut usize) -> Option<&'a str> {
    if *pos >= bs.len() || bs[*pos] != b'"' {
        return None;
    }
    *pos += 1;
    let val_start = *pos;
    while *pos < bs.len() {
        if bs[*pos] == b'\\' {
            *pos += 2;
            continue;
        }
        if bs[*pos] == b'"' {
            break;
        }
        *pos += 1;
    }
    let val = &opts[val_start..*pos];
    if *pos < bs.len() {
        *pos += 1;
    }
    Some(val)
}

fn read_unquoted<'a>(opts: &'a str, bs: &[u8], pos: &mut usize) -> &'a str {
    let val_start = *pos;
    while *pos < bs.len() && bs[*pos] != b';' && bs[*pos] != b' ' {
        *pos += 1;
    }
    &opts[val_start..*pos]
}

fn skip_value(bs: &[u8], pos: &mut usize) {
    while *pos < bs.len() {
        if bs[*pos] == b';' {
            break;
        }
        if bs[*pos] == b'"' {
            *pos += 1;
            while *pos < bs.len() && bs[*pos] != b'"' {
                if bs[*pos] == b'\\' {
                    *pos += 1;
                }
                *pos += 1;
            }
            if *pos < bs.len() {
                *pos += 1;
            }
        } else {
            *pos += 1;
        }
    }
}

struct RawPattern {
    bytes: Vec<u8>,
    offset: Option<u32>,
    depth: Option<u32>,
    distance: Option<u32>,
    within: Option<u32>,
}

fn parse_header(header: &str) -> (Option<String>, Option<String>, Option<String>) {
    let arrow_pos = header.find("->").or_else(|| header.find("<>"));
    let Some(dp) = arrow_pos else { return (None, None, None) };
    let left = header[..dp].trim();
    let right = header[dp + 2..].trim();
    let lt: Vec<&str> = left.split_whitespace().collect();
    let rt: Vec<&str> = right.split_whitespace().collect();
    (lt.get(1).map(|s| s.to_string()), lt.get(3).map(|s| s.to_string()), rt.get(1).map(|s| s.to_string()))
}

fn check_port(rule_port: &Option<String>, pkt_port: u16) -> bool {
    let Some(s) = rule_port else { return true };
    if s == "any" { return true; }
    if pkt_port == 0 { return true; }
    if let Ok(n) = s.parse::<u16>() { return pkt_port == n; }
    if s.contains(',') {
        for part in s.split(',') {
            let part = part.trim();
            if let Ok(n) = part.parse::<u16>() { if pkt_port == n { return true; } }
            if part.contains(':') {
                if let Some((lo, hi)) = part.split_once(':') {
                    if let (Ok(l), Ok(h)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                        if pkt_port >= l && pkt_port <= h { return true; }
                    }
                }
            }
            if part.starts_with('$') { return true; }
        }
        return false;
    }
    if s.contains(':') {
        if let Some((lo, hi)) = s.split_once(':') {
            if let (Ok(l), Ok(h)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                return pkt_port >= l && pkt_port <= h;
            }
        }
        return true;
    }
    if s.starts_with('$') {
        if s.contains("HTTP") { return matches!(pkt_port, 80 | 443 | 8080 | 8443 | 8000 | 8008); }
        return true;
    }
    true
}

fn check_protocol(rule_proto: &Option<String>, pkt_proto: &Option<String>) -> bool {
    let Some(s) = rule_proto else { return true };
    if s == "ip" { return true; }
    let Some(p) = pkt_proto else { return true };
    p.eq_ignore_ascii_case(s)
}

fn parse_packets_json(json: &str) -> Vec<PacketData> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json) {
        let mut packets = Vec::new();
        for val in &arr {
            if let Some(obj) = val.as_object() {
                let payload_hex = obj.get("payload_hex").and_then(|v| v.as_str()).unwrap_or("");
                let protocol = obj.get("protocol").and_then(|v| v.as_str()).map(|s| s.to_string());
                let src_port = obj.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let dst_port = obj.get("dst_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let flow_dir = match obj.get("flow_dir").and_then(|v| v.as_str()) {
                    Some("from_server") => FlowDir::FromServer,
                    _ => FlowDir::ToServer,
                };
                let payload = hex_decode(payload_hex);
                if !payload.is_empty() {
                    packets.push(PacketData { payload, protocol, src_port, dst_port, flow_dir });
                }
            }
        }
        if !packets.is_empty() { return packets; }
    }
    if let Ok(hex_strings) = serde_json::from_str::<Vec<String>>(json) {
        return hex_strings.into_iter().map(|s| PacketData {
            payload: hex_decode(&s),
            protocol: None,
            src_port: 0,
            dst_port: 0,
            flow_dir: FlowDir::ToServer,
        }).filter(|p| !p.payload.is_empty()).collect();
    }
    Vec::new()
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
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let opt_start = match trimmed.find('(') {
            Some(p) => p,
            None => continue,
        };
        let opt_end = match trimmed.rfind(')') {
            Some(p) => p,
            None => continue,
        };
        if opt_end <= opt_start {
            continue;
        }

        let (protocol, src_port, dst_port) = parse_header(trimmed[..opt_start].trim());
        let opts = &trimmed[opt_start + 1..opt_end];
        let mut sid = 0u32;
        let mut msg = String::new();
        let mut classtype = String::new();
        let mut flow_constraints: Option<FlowConstraints> = None;
        let mut pcre_str: Option<String> = None;

        let mut raw_pats: Vec<RawPattern> = Vec::new();
        let mut cur_offset: Option<u32> = None;
        let mut cur_depth: Option<u32> = None;
        let mut cur_distance: Option<u32> = None;
        let mut cur_within: Option<u32> = None;
        let mut pending_nocase = false;
        let mut has_content = false;

        let mut pos = 0usize;
        let bs = opts.as_bytes();
        let olen = bs.len();

        while pos < olen {
            while pos < olen && (bs[pos] == b' ' || bs[pos] == b';' || bs[pos] == b'\t') {
                pos += 1;
            }
            if pos >= olen { break; }

            let key_start = pos;
            while pos < olen && bs[pos] != b':' && bs[pos] != b' ' && bs[pos] != b';' {
                pos += 1;
            }
            if pos >= olen || bs[pos] != b':' { continue; }
            let key = &opts[key_start..pos];
            pos += 1;

            while pos < olen && (bs[pos] == b' ' || bs[pos] == b'\t') {
                pos += 1;
            }

            match key {
                "msg" => {
                    if let Some(v) = read_quoted(opts, bs, &mut pos) {
                        msg = v.to_string();
                    }
                }
                "sid" => {
                    sid = read_unquoted(opts, bs, &mut pos).parse().unwrap_or(0);
                }
                "classtype" => {
                    classtype = read_unquoted(opts, bs, &mut pos).to_string();
                }
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
                    raw_pats.push(RawPattern {
                        bytes: bytes.clone(),
                        offset: cur_offset.take(),
                        depth: cur_depth.take(),
                        distance: cur_distance.take(),
                        within: cur_within.take(),
                    });
                    if pending_nocase {
                        if bytes.iter().any(|b| b.is_ascii_alphabetic()) {
                            let lower = bytes.to_ascii_lowercase();
                            if lower != bytes {
                                raw_pats.push(RawPattern {
                                    bytes: lower,
                                    offset: None, depth: None,
                                    distance: None, within: None,
                                });
                            }
                        }
                        pending_nocase = false;
                    }
                    cur_distance = None;
                    cur_within = None;
                }
                "nocase" => {
                    pending_nocase = true;
                    skip_value(bs, &mut pos);
                }
                "offset" => {
                    cur_offset = read_unquoted(opts, bs, &mut pos).parse().ok();
                }
                "depth" => {
                    cur_depth = read_unquoted(opts, bs, &mut pos).parse().ok();
                }
                "distance" => {
                    cur_distance = read_unquoted(opts, bs, &mut pos).parse().ok();
                }
                "within" => {
                    cur_within = read_unquoted(opts, bs, &mut pos).parse().ok();
                }
                "flow" => {
                    let v = read_unquoted(opts, bs, &mut pos).to_string();
                    if flow_constraints.is_none() {
                        flow_constraints = Some(FlowConstraints::parse(&v));
                    }
                }
                "pcre" => {
                    if let Some(v) = read_quoted(opts, bs, &mut pos) {
                        pcre_str = Some(v.to_string());
                    }
                }
                _ => {
                    skip_value(bs, &mut pos);
                }
            }
        }

        if !has_content || sid == 0 || raw_pats.is_empty() {
            continue;
        }

        for rp in &raw_pats {
            let len_u32 = unique_pats.len() as u32;
            pat_dedup.entry(rp.bytes.clone()).or_insert_with(|| {
                unique_pats.push(rp.bytes.clone());
                len_u32
            });
        }

        let pcre = match &pcre_str {
            Some(s) => parse_pcre(s),
            None => None,
        };

        let patterns: Vec<ContentPattern> = raw_pats.iter().map(|rp| {
            let &pid = pat_dedup.get(&rp.bytes).unwrap();
            ContentPattern {
                pat_id: pid,
                offset: rp.offset,
                depth: rp.depth,
                distance: rp.distance,
                within: rp.within,
            }
        }).collect();

        rules_out.push(Rule {
            msg,
            sid,
            classtype,
            patterns,
            flow_constraints,
            pcre,
            protocol,
            src_port,
            dst_port,
        });
    }

    (rules_out, unique_pats.into_iter().enumerate().map(|(i, p)| (p, i as u32)).collect())
}

impl RuleEngine {
    pub fn get() -> &'static RuleEngine {
        RULE_ENGINE.get_or_init(|| {
            rust_timing_log!("SuricataEngine: not yet initialised — call init(rules_bytes) first");
            RuleEngine { rules: Vec::new(), ac: DoubleArrayAhoCorasick::with_values(Vec::<(Vec<u8>, u32)>::new()).unwrap(), pattern_count: 0 }
        })
    }

    pub fn init(rules_bytes: &[u8]) {
        let (rules, pat_entries) = parse_rules(rules_bytes);
        if rules.is_empty() {
            rust_timing_log!("SuricataEngine: parse_rules returned 0 rules (maybe not loaded yet)");
            return;
        }
        let patvals: Vec<(&[u8], u32)> = pat_entries.iter().map(|(p, v)| (p.as_slice(), *v)).collect();
        let ac = DoubleArrayAhoCorasick::with_values(patvals)
            .expect("daachorse build failed");
        let pattern_count = pat_entries.len();
        let engine = RuleEngine { rules, ac, pattern_count };
        let _ = RULE_ENGINE.set(engine);
        rust_timing_log!("SuricataEngine: {} rules, {} patterns initialised",
            RULE_ENGINE.get().map(|e| e.rules.len()).unwrap_or(0),
            RULE_ENGINE.get().map(|e| e.pattern_count).unwrap_or(0));
    }

    fn check_rule(&self, rule: &Rule, matches_by_id: &[Vec<(usize, usize)>], combined: &[u8], pkt: &PacketData) -> bool {
        if !check_protocol(&rule.protocol, &pkt.protocol) { return false; }
        if !check_port(&rule.src_port, pkt.src_port) { return false; }
        if !check_port(&rule.dst_port, pkt.dst_port) { return false; }
        if let Some(ref fc) = rule.flow_constraints {
            if !fc.check(pkt.flow_dir) { return false; }
        }
        if rule.patterns.is_empty() {
            return false;
        }

        let mut prev_end: Option<usize> = None;

        for (i, cp) in rule.patterns.iter().enumerate() {
            let pid = cp.pat_id as usize;
            let pat_matches = match matches_by_id.get(pid) {
                Some(m) if !m.is_empty() => m,
                _ => return false,
            };

            let found = pat_matches.iter().any(|&(start, end)| {
                if i == 0 {
                    let meets_offset = cp.offset.map_or(true, |o| start >= o as usize);
                    let meets_depth = cp.depth.map_or(true, |d| end <= d as usize);
                    meets_offset && meets_depth
                } else {
                    let prev = prev_end.unwrap();
                    let meets_distance = cp.distance.map_or(true, |d| start >= prev + d as usize);
                    let meets_within = cp.within.map_or(true, |w| end <= prev + w as usize);
                    meets_distance && meets_within
                }
            });

            if found {
                if let Some(&(_, end)) = pat_matches.iter().find(|&&(start, end)| {
                    if i == 0 {
                        cp.offset.map_or(true, |o| start >= o as usize)
                            && cp.depth.map_or(true, |d| end <= d as usize)
                    } else {
                        let prev = prev_end.unwrap();
                        cp.distance.map_or(true, |d| start >= prev + d as usize)
                            && cp.within.map_or(true, |w| end <= prev + w as usize)
                    }
                }) {
                    prev_end = Some(end);
                }
            } else {
                return false;
            }
        }

        if let Some(ref re) = rule.pcre {
            let ok = std::str::from_utf8(combined)
                .map(|s| re.is_match(s))
                .unwrap_or(true);
            if !ok {
                return false;
            }
        }

        true
    }

    pub fn scan(&self, packets_json: &str) -> ScanResult {
        let packets = parse_packets_json(packets_json);
        if packets.is_empty() {
            return ScanResult { malicious: false, matches: Vec::new() };
        }

        let mut matches = Vec::new();

        for pkt in &packets {
            let combined = &pkt.payload;
            if combined.is_empty() { continue; }

            let mut matches_by_id: Vec<Vec<(usize, usize)>> = vec![Vec::new(); self.pattern_count];
            for mat in self.ac.find_overlapping_iter(combined) {
                let pid = mat.value() as usize;
                if pid < self.pattern_count {
                    matches_by_id[pid].push((mat.start(), mat.end()));
                }
            }

            for rule in &self.rules {
                if matches.iter().any(|m: &MatchInfo| m.sid == rule.sid) {
                    continue;
                }
                if self.check_rule(rule, &matches_by_id, combined, pkt) {
                    matches.push(MatchInfo {
                        name: rule.msg.clone(),
                        sid: rule.sid,
                        classtype: rule.classtype.clone(),
                        description: rule.msg.clone(),
                    });
                }
            }
        }

        ScanResult { malicious: !matches.is_empty(), matches }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode(""), vec![] as Vec<u8>);
        assert_eq!(hex_decode("FF"), vec![0xFF]);
        assert_eq!(hex_decode("FFD06668"), vec![0xFF, 0xD0, 0x66, 0x68]);
        assert_eq!(hex_decode("ff d0 66 68"), vec![0xFF, 0xD0, 0x66, 0x68]);
    }

    #[test]
    fn test_parse_single_rule() {
        let rules_text = b"alert udp any any -> any any (msg:\"ET TEST RULE\"; content:\"|FF D0 66 68|\"; classtype:bad-unknown; sid:2009001; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009001);
        assert_eq!(rules[0].msg, "ET TEST RULE");
        assert_eq!(rules[0].classtype, "bad-unknown");
        assert_eq!(rules[0].protocol.as_deref(), Some("udp"));
        assert_eq!(rules[0].src_port.as_deref(), Some("any"));
        assert_eq!(rules[0].dst_port.as_deref(), Some("any"));
        assert!(rules[0].flow_constraints.is_none());
        assert_eq!(pat_entries.len(), 1);
        assert_eq!(pat_entries[0].0, vec![0xFF, 0xD0, 0x66, 0x68]);
    }

    #[test]
    fn test_parse_multi_content_rule() {
        let rules_text = b"alert tcp any any -> any any (msg:\"ET MULTI PATTERN\"; content:\"|53 53 53|\"; content:\"|66 53 89|\"; distance:0; classtype:shellcode-detect; sid:2009002; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009002);
        assert_eq!(pat_entries.len(), 2);
        assert_eq!(pat_entries[0].0, vec![0x53, 0x53, 0x53]);
        assert_eq!(pat_entries[1].0, vec![0x66, 0x53, 0x89]);
    }

    #[test]
    fn test_skip_commented_rules() {
        let rules_text = b"#alert tcp any any -> any any (msg:\"COMMENTED\"; content:\"|FF|\"; sid:2009003; rev:1;)\nalert udp any any -> any any (msg:\"ACTIVE\"; content:\"|AA BB|\"; classtype:unknown; sid:2009004; rev:1;)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009004);
        assert_eq!(rules[0].msg, "ACTIVE");
    }

    #[test]
    fn test_skip_empty_lines() {
        let rules_text = b"\n\n  \nalert udp any any -> any any (msg:\"ET TEST\"; content:\"|FF|\"; classtype:unknown; sid:2009005; rev:1;)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009005);
    }

    #[test]
    fn test_text_content() {
        let rules_text = b"alert tcp any any -> any any (msg:\"TEXT CONTENT\"; content:\"GET\"; http_uri; classtype:unknown; sid:2009006; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009006);
        assert_eq!(pat_entries.len(), 1);
        assert_eq!(pat_entries[0].0, vec![0x47, 0x45, 0x54]);
    }

    #[test]
    fn test_no_sid_skipped() {
        let rules_text = b"alert udp any any -> any any (msg:\"NO SID\"; content:\"|FF|\";)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_parse_with_flow_and_reference() {
        let rules_text = b"alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:\"ET FULL RULE\"; flow:to_server,established; content:\"|DE AD BE EF|\"; http_uri; classtype:trojan-activity; sid:2009007; rev:1; reference:url,example.com;)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009007);
        assert_eq!(rules[0].msg, "ET FULL RULE");
        assert_eq!(rules[0].classtype, "trojan-activity");
        assert_eq!(rules[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(rules[0].src_port.as_deref(), Some("any"));
        assert_eq!(rules[0].dst_port.as_deref(), Some("$HTTP_PORTS"));
        let fc = rules[0].flow_constraints.as_ref().unwrap();
        assert!(fc.to_server);
        assert!(fc.established);
        assert!(!fc.from_server);
        assert!(!fc.stateless);
    }

    #[test]
    fn test_hex_decode_with_pipe_chars() {
        assert_eq!(hex_decode("|FF D0 66 68|"), vec![0xFF, 0xD0, 0x66, 0x68]);
        assert_eq!(hex_decode("|535353|"), vec![0x53, 0x53, 0x53]);
    }

    #[test]
    fn test_rule_engine_scan() {
        let rules_bytes = b"alert udp any any -> any any (msg:\"ET SCAN TEST\"; content:\"|DE AD|\"; classtype:unknown; sid:2009010; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_bytes);
        let patvals: Vec<(&[u8], u32)> = pat_entries.iter().map(|(p, v)| (p.as_slice(), *v)).collect();
        let ac = DoubleArrayAhoCorasick::with_values(patvals).unwrap();
        let pattern_count = pat_entries.len();
        let engine = RuleEngine { rules, ac, pattern_count };

        let result = engine.scan(r#"["deadbeef"]"#);
        assert!(result.malicious);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].sid, 2009010);
        assert_eq!(result.matches[0].name, "ET SCAN TEST");

        let result2 = engine.scan(r#"["ffeeddcc"]"#);
        assert!(!result2.malicious);
    }

    #[test]
    fn test_escaped_quote_in_msg() {
        let rules_text = b"alert udp any any -> any any (msg:\"ET \\\"QUOTED\\\" RULE\"; content:\"|FF|\"; classtype:unknown; sid:2009011; rev:1;)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].msg, "ET \\\"QUOTED\\\" RULE");
        assert_eq!(rules[0].sid, 2009011);
    }

    #[test]
    fn test_parse_multiple_rules() {
        let rules_text = b"alert udp any any -> any any (msg:\"RULE ONE\"; content:\"|AA|\"; classtype:one; sid:2009012; rev:1;)\nalert tcp any any -> any any (msg:\"RULE TWO\"; content:\"|BB BB|\"; classtype:two; sid:2009013; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].sid, 2009012);
        assert_eq!(rules[1].sid, 2009013);
        assert_eq!(pat_entries.len(), 2);
    }

    #[test]
    fn test_parse_rules_with_metadata() {
        let rules_text = b"alert udp any any -> any any (msg:\"ET META\"; content:\"|01 02|\"; classtype:unknown; sid:2009014; rev:1; metadata:created_at 2010_07_30, confidence High, signature_severity Major;)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009014);
    }

    #[test]
    fn test_empty_input() {
        let (rules, pat_entries) = parse_rules(b"");
        assert_eq!(rules.len(), 0);
        assert_eq!(pat_entries.len(), 0);
    }

    #[test]
    fn test_comments_only() {
        let (rules, _) = parse_rules(b"# just a comment\n# another one\n");
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_dedup_patterns() {
        let rules_text = b"alert udp any any -> any any (msg:\"RULE A\"; content:\"|AA BB|\"; classtype:one; sid:2009015; rev:1;)\nalert tcp any any -> any any (msg:\"RULE B\"; content:\"|AA BB|\"; classtype:two; sid:2009016; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 2);
        assert_eq!(pat_entries.len(), 1);
    }

    #[test]
    fn test_mixed_text_and_hex_content() {
        let rules_text = b"alert tcp any any -> any any (msg:\"MIXED\"; content:\"GET|20|HTTP\"; classtype:unknown; sid:2009017; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 2009017);
        assert_eq!(pat_entries.len(), 1);
        assert_eq!(pat_entries[0].0, vec![0x47, 0x45, 0x54, 0x20, 0x48, 0x54, 0x54, 0x50]);
    }

    #[test]
    fn test_nocase_duplicates_pattern() {
        let rules_text = b"alert udp any any -> any any (msg:\"NOCASE TEST\"; content:\"GET\"; nocase; classtype:unknown; sid:2009018; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(pat_entries.len(), 2);
        let pats: Vec<Vec<u8>> = pat_entries.into_iter().map(|(b, _)| b).collect();
        assert!(pats.contains(&vec![0x47, 0x45, 0x54]));
        assert!(pats.contains(&vec![0x67, 0x65, 0x74]));
    }

    #[test]
    fn test_uricontent_parsed_like_content() {
        let rules_text = b"alert tcp any any -> any any (msg:\"URICONTENT\"; uricontent:\"|DE AD|\"; classtype:unknown; sid:2009019; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 1);
        assert_eq!(pat_entries.len(), 1);
        assert_eq!(pat_entries[0].0, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_no_hex_in_content() {
        let rules_text = b"alert tcp any any -> any any (msg:\"ET TEXT\"; content:\"|text|\"; classtype:unknown; sid:2009017; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 0);
        assert_eq!(pat_entries.len(), 0);
    }

    #[test]
    fn test_flow_constraints_parse() {
        let fc = FlowConstraints::parse("to_server,established");
        assert!(fc.to_server);
        assert!(fc.established);
        assert!(!fc.from_server);
        assert!(!fc.stateless);

        let fc2 = FlowConstraints::parse("from_server");
        assert!(fc2.from_server);
        assert!(!fc2.to_server);

        let fc3 = FlowConstraints::parse("to_client");
        assert!(fc3.from_server);

        let fc4 = FlowConstraints::parse("stateless");
        assert!(fc4.stateless);
    }

    #[test]
    fn test_flow_constraints_check() {
        let to_srv = FlowConstraints::parse("to_server");
        assert!(to_srv.check(FlowDir::ToServer));
        assert!(!to_srv.check(FlowDir::FromServer));

        let from_srv = FlowConstraints::parse("from_server");
        assert!(from_srv.check(FlowDir::FromServer));
        assert!(!from_srv.check(FlowDir::ToServer));

        let both = FlowConstraints::parse("to_server,from_server");
        assert!(both.check(FlowDir::ToServer));
        assert!(both.check(FlowDir::FromServer));
    }

    #[test]
    fn test_check_port() {
        assert!(check_port(&Some("any".to_string()), 80));
        assert!(check_port(&Some("80".to_string()), 80));
        assert!(!check_port(&Some("80".to_string()), 443));
        assert!(check_port(&Some("80,443".to_string()), 80));
        assert!(check_port(&Some("80,443".to_string()), 443));
        assert!(!check_port(&Some("80,443".to_string()), 22));
        assert!(check_port(&Some("1024:65535".to_string()), 8080));
        assert!(check_port(&Some("1024:65535".to_string()), 1024));
        assert!(!check_port(&Some("1024:65535".to_string()), 80));
        assert!(check_port(&Some("$HTTP_PORTS".to_string()), 80));
        assert!(check_port(&Some("$HTTP_PORTS".to_string()), 443));
        assert!(check_port(&Some("$HTTP_PORTS".to_string()), 8080));
        assert!(!check_port(&Some("$HTTP_PORTS".to_string()), 22));
        assert!(check_port(&None, 80));
    }

    #[test]
    fn test_check_protocol() {
        assert!(check_protocol(&None, &None));
        assert!(check_protocol(&Some("ip".to_string()), &None));
        assert!(check_protocol(&Some("tcp".to_string()), &Some("TCP".to_string())));
        assert!(check_protocol(&Some("udp".to_string()), &Some("UDP".to_string())));
        assert!(!check_protocol(&Some("tcp".to_string()), &Some("UDP".to_string())));
        assert!(check_protocol(&Some("icmp".to_string()), &Some("ICMP".to_string())));
    }

    #[test]
    fn test_scan_with_packet_objects() {
        let rules_bytes = b"alert tcp any any -> any any (msg:\"ET TCP MATCH\"; content:\"|DE AD|\"; classtype:unknown; sid:2009020; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_bytes);
        let patvals: Vec<(&[u8], u32)> = pat_entries.iter().map(|(p, v)| (p.as_slice(), *v)).collect();
        let ac = DoubleArrayAhoCorasick::with_values(patvals).unwrap();
        let pattern_count = pat_entries.len();
        let engine = RuleEngine { rules, ac, pattern_count };

        let json = r#"[{"src_ip":"192.168.1.1","dst_ip":"1.2.3.4","src_port":12345,"dst_port":80,"protocol":"TCP","payload_hex":"deadbeef","flow_dir":"to_server"}]"#;
        let result = engine.scan(json);
        assert!(result.malicious);
        assert_eq!(result.matches[0].sid, 2009020);

        let json2 = r#"[{"src_ip":"1.2.3.4","dst_ip":"192.168.1.1","src_port":80,"dst_port":12345,"protocol":"UDP","payload_hex":"deadbeef","flow_dir":"from_server"}]"#;
        let result2 = engine.scan(json2);
        assert!(!result2.malicious);
    }

    #[test]
    fn test_scan_filters_by_protocol() {
        let rules_bytes = b"alert tcp any any -> any any (msg:\"TCP ONLY\"; content:\"|DE AD|\"; classtype:unknown; sid:2009021; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_bytes);
        let patvals: Vec<(&[u8], u32)> = pat_entries.iter().map(|(p, v)| (p.as_slice(), *v)).collect();
        let ac = DoubleArrayAhoCorasick::with_values(patvals).unwrap();
        let pattern_count = pat_entries.len();
        let engine = RuleEngine { rules, ac, pattern_count };

        let json_tcp = r#"[{"payload_hex":"deadbeef","protocol":"TCP","src_port":80,"dst_port":80,"flow_dir":"to_server"}]"#;
        assert!(engine.scan(json_tcp).malicious);

        let json_udp = r#"[{"payload_hex":"deadbeef","protocol":"UDP","src_port":80,"dst_port":80,"flow_dir":"to_server"}]"#;
        assert!(!engine.scan(json_udp).malicious);
    }

    #[test]
    fn test_scan_filters_by_flow() {
        let rules_bytes = b"alert tcp any any -> any any (msg:\"TO SERVER ONLY\"; flow:to_server; content:\"|DE AD|\"; classtype:unknown; sid:2009022; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_bytes);
        let patvals: Vec<(&[u8], u32)> = pat_entries.iter().map(|(p, v)| (p.as_slice(), *v)).collect();
        let ac = DoubleArrayAhoCorasick::with_values(patvals).unwrap();
        let pattern_count = pat_entries.len();
        let engine = RuleEngine { rules, ac, pattern_count };

        let json_to = r#"[{"payload_hex":"deadbeef","protocol":"TCP","src_port":80,"dst_port":80,"flow_dir":"to_server"}]"#;
        assert!(engine.scan(json_to).malicious);

        let json_from = r#"[{"payload_hex":"deadbeef","protocol":"TCP","src_port":80,"dst_port":80,"flow_dir":"from_server"}]"#;
        assert!(!engine.scan(json_from).malicious);
    }

    #[test]
    fn test_parse_header() {
        let (proto, srcp, dstp) = parse_header("alert tcp any any -> any any");
        assert_eq!(proto.as_deref(), Some("tcp"));
        assert_eq!(srcp.as_deref(), Some("any"));
        assert_eq!(dstp.as_deref(), Some("any"));

        let (proto2, srcp2, dstp2) = parse_header("alert udp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS");
        assert_eq!(proto2.as_deref(), Some("udp"));
        assert_eq!(srcp2.as_deref(), Some("any"));
        assert_eq!(dstp2.as_deref(), Some("$HTTP_PORTS"));

        let (proto3, _, _) = parse_header("alert ip any any <> any any");
        assert_eq!(proto3.as_deref(), Some("ip"));
    }
}
