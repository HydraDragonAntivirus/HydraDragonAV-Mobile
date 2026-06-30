//! Native malicious-IP lookup: exact membership of a resolved IP against the
//! per-category xor blocklists (allips non-CIDR entries). No CIDR/subnet match.

use std::path::Path;

use hydradragonxorfilter::XorFilter;

struct CatFilter {
    category: &'static str,
    filter: XorFilter,
}

pub struct IpScanner {
    filters: Vec<CatFilter>,
}

/// (asset stem, category). Order = priority (most severe first).
const CATS: &[(&str, &str)] = &[
    ("ipmalware", "MALWARE_IP"),
    ("ipphishing", "PHISHING_IP"),
    ("ipbruteforce", "BRUTEFORCE_IP"),
    ("ipddos", "DDOS_IP"),
    ("ipspam", "SPAM_IP"),
];

impl IpScanner {
    /// Load every category `.xf` from `dir`. None if none loaded.
    pub fn load(dir: &Path) -> Option<IpScanner> {
        let mut filters = Vec::new();
        for &(stem, category) in CATS {
            let path = dir.join(format!("{stem}.xf"));
            if let Some(filter) = crate::load_xor_filter(&path) {
                filters.push(CatFilter { category, filter });
            }
        }
        if filters.is_empty() {
            return None;
        }
        Some(IpScanner { filters })
    }

    /// Category for a blocklisted IP, or None. Exact match on the trimmed
    /// canonical textual IP (no leading zeros; lowercase compact IPv6).
    pub fn scan(&self, ip: &str) -> Option<&'static str> {
        let ip = ip.trim();
        if ip.is_empty() {
            return None;
        }
        for f in &self.filters {
            if f.filter.contains(ip) {
                return Some(f.category);
            }
        }
        None
    }
}
