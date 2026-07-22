//! Native URL/domain threat lookup — the Rust port of the Java
//! `UrlThreatScanner`. All membership is now Binary-Fuse (xor) filters loaded
//! from the `.xf` assets, by both the live DNS Web-Shield and the APK URL scan.
//! Mirrors the Java logic exactly:
//!
//!   * `http://domain` / `https://...`           -> domain scan (registrable
//!     main domain checked against the domain xor filters).
//!   * `http://domain/path` (has a real path)     -> URL scan (full scheme-less
//!     URL checked against the `*_URL` xor filters).
//!
//! Registrable (main) domain is derived with the public-suffix list
//! (`public_suffixes.txt`), identical to the Java `getMainDomain`.

use std::collections::HashSet;

/// One category filter: its label, whether it's a URL filter (full URL) vs a
/// domain filter (registrable domain), and the Binary-Fuse xor filter.
struct CatFilter {
    category: &'static str,
    is_url: bool,
    filter: hydradragonxorfilter::XorFilter,
}

pub struct UrlScanner {
    filters: Vec<CatFilter>,
    suffixes: HashSet<String>,
}

/// (asset stem, category, is_url_filter) — same order/labels as the Java XOR_FILTERS.
const CATS: &[(&str, &str, bool)] = &[
    ("malwareurl", "MALWARE_URL", true),
    ("phishingurl", "PHISHING_URL", true),
    ("phishing", "PHISHING", false),
    ("malicious", "MALICIOUS", false),
    ("malicious_mail", "MAIL", false),
    ("abuse", "ABUSE", false),
    ("spam", "SPAM", false),
    ("mining", "MINING", false),
];

impl UrlScanner {
    /// Load from a pre-read HashMap of filename → bytes (AAssetManager path).
    pub fn load_from_assets(files: &std::collections::HashMap<String, Vec<u8>>) -> Option<UrlScanner> {
        let mut filters = Vec::new();
        for &(stem, category, is_url) in CATS {
            let xf_name = format!("{stem}.xf");
            if let Some(bytes) = files.get(&xf_name) {
                if let Some(filter) = hydradragonxorfilter::XorFilter::from_bytes(bytes) {
                    filters.push(CatFilter { category, is_url, filter });
                }
            }
        }
        if filters.is_empty() {
            return None;
        }
        let mut suffixes = HashSet::new();
        if let Some(bytes) = files.get("public_suffixes.txt") {
            if let Ok(text) = std::str::from_utf8(bytes) {
                for line in text.lines() {
                    let l = line.trim().to_lowercase();
                    if !l.is_empty() && !l.starts_with("//") {
                        suffixes.insert(l);
                    }
                }
            }
        }
        Some(UrlScanner { filters, suffixes })
    }

    /// Registrable (main) domain via the public-suffix list. Falls back to the
    /// last two labels. `mc.yandex.ru` -> `yandex.ru`; `google.com.tk`
    /// (`com.tk` a listed suffix) -> `com.tk`.
    fn main_domain<'a>(&self, host: &'a str) -> String {
        if host.is_empty() {
            return String::new();
        }
        let p: Vec<&str> = host.split('.').collect();
        for i in 0..p.len() {
            let suf = p[i..].join(".");
            if self.suffixes.contains(&suf) {
                if i == 0 {
                    return host.to_string();
                }
                return p[i - 1..].join(".");
            }
        }
        if p.len() >= 2 {
            format!("{}.{}", p[p.len() - 2], p[p.len() - 1])
        } else {
            host.to_string()
        }
    }

    /// Look a single URL up against all filters (URL + domain). Used by JNI
    /// direct URL lookups (VPN DNS, SMS links, etc.).
    pub fn scan(&self, url: &str) -> Option<&'static str> {
        let lower = url.trim().to_lowercase();
        let scheme_http = lower.starts_with("http://");
        let scheme_https = lower.starts_with("https://");
        if !scheme_http && !scheme_https {
            return None;
        }
        let norm = if scheme_https {
            &lower["https://".len()..]
        } else {
            &lower["http://".len()..]
        };
        if norm.is_empty() {
            return None;
        }
        let slash = norm.find('/');
        let has_path = matches!(slash, Some(s) if s < norm.len() - 1);
        let mut host = match slash {
            Some(s) => &norm[..s],
            None => norm,
        };
        if let Some(colon) = host.find(':') {
            host = &host[..colon];
        }

        let url_scan = has_path;
        let main = if url_scan { String::new() } else { self.main_domain(host) };
        for f in &self.filters {
            if url_scan {
                if f.is_url && f.filter.contains(norm) {
                    return Some(f.category);
                }
            } else if !f.is_url && f.filter.contains(main.as_str()) {
                return Some(f.category);
            }
        }
        None
    }

    /// Same as [`scan`] but only checks URL-path filters (no domain/ip scan).
    /// Used during file scanning where only full URLs with paths are relevant.
    pub fn scan_url_only(&self, url: &str) -> Option<&'static str> {
        let lower = url.trim().to_lowercase();
        let scheme_http = lower.starts_with("http://");
        let scheme_https = lower.starts_with("https://");
        if !scheme_http && !scheme_https {
            return None;
        }
        let norm = if scheme_https {
            &lower["https://".len()..]
        } else {
            &lower["http://".len()..]
        };
        if norm.is_empty() {
            return None;
        }
        let slash = norm.find('/');
        // Skip bare domains (no path / no real path).
        let has_path = matches!(slash, Some(s) if s < norm.len() - 1);
        if !has_path {
            return None;
        }
        for f in &self.filters {
            if f.is_url && f.filter.contains(norm) {
                return Some(f.category);
            }
        }
        None
    }
}
