//! Native malicious-IP lookup: exact membership of a resolved IP against the
//! per-category xor blocklists (allips non-CIDR entries). No CIDR/subnet match.

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
    /// Load from pre-read files, PREFERRING a zero-copy view straight into the
    /// APK's stored (noCompress) asset data (`AAsset_getBuffer`) so the filter
    /// fingerprints are file-backed, not an anonymous heap copy. Falls back to
    /// the `files` map only when the asset is compressed/absent.
    pub fn from_bytes_map(
        asset_dir: &str,
        files: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Option<IpScanner> {
        let mut filters = Vec::new();
        for &(stem, category) in CATS {
            let xf_name = format!("{stem}.xf");
            let relative = format!("{asset_dir}/{xf_name}");
            let filter = match crate::asset_reader::open_asset_buffer(&relative) {
                // SAFETY: the AAsset handle stays open for the filter's whole
                // lifetime (it moves into the filter's backing).
                Some(buf) => unsafe {
                    XorFilter::from_asset_buffer(buf.ptr, buf.len, buf.asset)
                },
                None => files
                    .get(&xf_name)
                    .and_then(|b| XorFilter::from_owned(b.clone())),
            };
            if let Some(filter) = filter {
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
