use std::sync::OnceLock;
use daachorse::DoubleArrayAhoCorasick;

static RULE_ENGINE: OnceLock<RuleEngine> = OnceLock::new();

struct Rule {
    msg: String,
    sid: u32,
    classtype: String,
    /// Indices into the global daachorse automaton
    pattern_ids: Vec<u32>,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    ac: DoubleArrayAhoCorasick<u32>,
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

fn parse_rules(raw: &[u8]) -> (Vec<Rule>, Vec<(Vec<u8>, u32)>) {
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    struct RawPattern {
        rule_idx: usize,
        bytes: Vec<u8>,
    }

    let mut rules_raw: Vec<(String, u32, String, String)> = Vec::new();
    let mut raw_pats: Vec<RawPattern> = Vec::new();
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

        let opts = &trimmed[opt_start + 1..opt_end];
        let rule_idx = rules_raw.len();

        let mut sid = 0u32;
        let mut msg = String::new();
        let mut classtype = String::new();
        let mut has_content = false;

        let mut pos = 0usize;
        let bs = opts.as_bytes();
        let olen = bs.len();

        while pos < olen {
            while pos < olen && (bs[pos] == b' ' || bs[pos] == b';' || bs[pos] == b'\t') {
                pos += 1;
            }
            if pos >= olen {
                break;
            }

            let key_start = pos;
            while pos < olen && bs[pos] != b':' && bs[pos] != b' ' && bs[pos] != b';' {
                pos += 1;
            }
            if pos >= olen || bs[pos] != b':' {
                continue;
            }
            let key = &opts[key_start..pos];
            pos += 1;

            while pos < olen && (bs[pos] == b' ' || bs[pos] == b'\t') {
                pos += 1;
            }

            match key {
                "msg" => {
                    if pos < olen && bs[pos] == b'"' {
                        pos += 1;
                        let val_start = pos;
                        let mut escaped = false;
                        while pos < olen {
                            if escaped {
                                escaped = false;
                                pos += 1;
                                continue;
                            }
                            if bs[pos] == b'\\' {
                                escaped = true;
                                pos += 1;
                                continue;
                            }
                            if bs[pos] == b'"' {
                                break;
                            }
                            pos += 1;
                        }
                        msg = opts[val_start..pos].to_string();
                        if pos < olen {
                            pos += 1;
                        }
                    }
                }
                "sid" => {
                    let val_start = pos;
                    while pos < olen && bs[pos] != b';' && bs[pos] != b' ' {
                        pos += 1;
                    }
                    sid = opts[val_start..pos].parse().unwrap_or(0);
                }
                "classtype" => {
                    let val_start = pos;
                    while pos < olen && bs[pos] != b';' && bs[pos] != b' ' {
                        pos += 1;
                    }
                    classtype = opts[val_start..pos].to_string();
                }
                "content" => {
                    has_content = true;
                    if pos < olen && bs[pos] == b'"' {
                        pos += 1;
                    }
                    if pos < olen && bs[pos] == b'|' {
                        pos += 1;
                        let hex_start = pos;
                        while pos < olen && bs[pos] != b'|' {
                            pos += 1;
                        }
                        let hex_str = &opts[hex_start..pos];
                        if pos < olen {
                            pos += 1;
                        }
                        if pos < olen && bs[pos] == b'"' {
                            pos += 1;
                        }
                        let bytes = hex_decode(hex_str);
                        if !bytes.is_empty() {
                            raw_pats.push(RawPattern { rule_idx, bytes });
                        }
                    }
                }
                _ => {
                    while pos < olen {
                        if bs[pos] == b';' {
                            break;
                        }
                        if bs[pos] == b'"' {
                            pos += 1;
                            while pos < olen && bs[pos] != b'"' {
                                if bs[pos] == b'\\' {
                                    pos += 1;
                                }
                                pos += 1;
                            }
                            if pos < olen {
                                pos += 1;
                            }
                        } else {
                            pos += 1;
                        }
                    }
                }
            }
        }

        if has_content && sid > 0 {
            rules_raw.push((msg.clone(), sid, classtype.clone(), msg));
        }
    }

    for rp in &raw_pats {
        let len_u32 = unique_pats.len() as u32;
        pat_dedup.entry(rp.bytes.clone()).or_insert_with(|| {
            unique_pats.push(rp.bytes.clone());
            len_u32
        });
    }

    let mut rules = Vec::with_capacity(rules_raw.len());
    for (name, sid, description, _classtype_full) in &rules_raw {
        let mut pat_ids = Vec::new();
        for rp in &raw_pats {
            if rp.rule_idx == rules.len() {
                if let Some(&id) = pat_dedup.get(&rp.bytes) {
                    if !pat_ids.contains(&id) {
                        pat_ids.push(id);
                    }
                }
            }
        }
        if !pat_ids.is_empty() {
            rules.push(Rule {
                msg: name.clone(),
                sid: *sid,
                classtype: description.clone(),
                pattern_ids: pat_ids,
            });
        }
    }

    (rules, unique_pats.into_iter().enumerate().map(|(i, p)| (p, i as u32)).collect())
}

impl RuleEngine {
    pub fn get() -> &'static RuleEngine {
        RULE_ENGINE.get_or_init(|| {
            rust_timing_log!("SuricataEngine: not yet initialised — call init(rules_bytes) first");
            RuleEngine { rules: Vec::new(), ac: DoubleArrayAhoCorasick::new(Vec::<(Vec<u8>, u32)>::new()).unwrap() }
        })
    }

    pub fn init(rules_bytes: &[u8]) {
        let (rules, pat_entries) = parse_rules(rules_bytes);
        if rules.is_empty() {
            rust_timing_log!("SuricataEngine: parse_rules returned 0 rules (maybe not loaded yet)");
            return;
        }
        let patterns: Vec<&[u8]> = pat_entries.iter().map(|(p, _)| &p[..]).collect();
        let values: Vec<u32> = pat_entries.iter().map(|(_, id)| *id).collect();
        let ac = DoubleArrayAhoCorasick::new(patterns.into_iter().zip(values.into_iter()))
            .expect("daachorse build failed");
        let engine = RuleEngine { rules, ac };
        let _ = RULE_ENGINE.set(engine);
        rust_timing_log!("SuricataEngine: {} rules, {} patterns initialised",
            RULE_ENGINE.get().map(|e| e.rules.len()).unwrap_or(0),
            RULE_ENGINE.get().map(|e| e.ac.len()).unwrap_or(0));
    }

    pub fn scan(&self, packets_json: &str) -> ScanResult {
        let payloads: Vec<String> = match serde_json::from_str(packets_json) {
            Ok(v) => v,
            Err(_) => match serde_json::from_str::<serde_json::Value>(packets_json) {
                Ok(serde_json::Value::Array(arr)) => {
                    arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                }
                Ok(serde_json::Value::Object(obj)) => {
                    obj.get("packets").and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default()
                }
                _ => return ScanResult { malicious: false, matches: Vec::new() },
            },
        };

        let mut combined = Vec::new();
        for p in &payloads {
            combined.extend_from_slice(&hex_decode(p));
        }
        if combined.is_empty() {
            return ScanResult { malicious: false, matches: Vec::new() };
        }

        let mut found = vec![false; self.ac.len()];
        for mat in self.ac.find_overlapping(&combined) {
            let pid = mat.value() as usize;
            if pid < found.len() {
                found[pid] = true;
            }
        }

        let mut matches = Vec::new();
        for rule in &self.rules {
            if rule.pattern_ids.iter().all(|&pid| pid as usize < found.len() && found[pid as usize]) {
                matches.push(MatchInfo {
                    name: rule.msg.clone(),
                    sid: rule.sid,
                    classtype: rule.classtype.clone(),
                    description: rule.msg.clone(),
                });
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
    fn test_skip_rules_without_hex_content() {
        let rules_text = b"alert tcp any any -> any any (msg:\"NO HEX\"; content:\"GET\"; http_uri; classtype:unknown; sid:2009006; rev:1;)";
        let (rules, _) = parse_rules(rules_text);
        assert_eq!(rules.len(), 0);
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
        let patterns: Vec<&[u8]> = pat_entries.iter().map(|(p, _)| &p[..]).collect();
        let values: Vec<u32> = pat_entries.iter().map(|(_, id)| *id).collect();
        let ac = DoubleArrayAhoCorasick::new(patterns.into_iter().zip(values.into_iter())).unwrap();
        let engine = RuleEngine { rules, ac };

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
    fn test_no_hex_in_content() {
        let rules_text = b"alert tcp any any -> any any (msg:\"ET TEXT\"; content:\"|text|\"; classtype:unknown; sid:2009017; rev:1;)";
        let (rules, pat_entries) = parse_rules(rules_text);
        assert_eq!(rules.len(), 0);
        assert_eq!(pat_entries.len(), 0);
    }
}
