//! Native URL/domain threat lookup — the Rust port of the Java
//! `UrlThreatScanner`. All membership is now Binary-Fuse (xor) filters loaded
//! from the `.xf` assets, by both the live DNS Web-Shield and the APK URL scan.
//! Mirrors the Java logic exactly:
//!
//!   * `http://domain` / `https://...`           -> domain scan (registrable
//!     main domain checked against the domain blooms).
//!   * `http://domain/path` (has a real path)     -> URL scan (full scheme-less
//!     URL checked against the `*_URL` blooms).
//!
//! Registrable (main) domain is derived with the public-suffix list
//! (`public_suffixes.txt`), identical to the Java `getMainDomain`.

use std::collections::HashSet;
use std::path::Path;

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

/// (asset stem, category, is_url_filter) — same order/labels as the Java BLOOMS.
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
    /// Load every category `.xf` plus `public_suffixes.txt` from `dir`.
    /// Returns None if no filter loaded (URL scanning then disabled).
    pub fn load(dir: &Path) -> Option<UrlScanner> {
        let mut filters = Vec::new();
        for &(stem, category, is_url) in CATS {
            let path = dir.join(format!("{stem}.xf"));
            if let Some(filter) = crate::load_xor_filter(&path) {
                filters.push(CatFilter { category, is_url, filter });
            }
        }
        if filters.is_empty() {
            return None;
        }
        let mut suffixes = HashSet::new();
        if let Ok(text) = std::fs::read_to_string(dir.join("public_suffixes.txt")) {
            for line in text.lines() {
                let l = line.trim().to_lowercase();
                if !l.is_empty() && !l.starts_with("//") {
                    suffixes.insert(l);
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

    /// Look a single URL up. Returns the matching category, or None if clean /
    /// not an http(s) URL. Mirrors Java `scanUrl`.
    pub fn scan(&self, url: &str) -> Option<&'static str> {
        let lower = url.trim().to_lowercase();
        let scheme_http = lower.starts_with("http://");
        let scheme_https = lower.starts_with("https://");
        if !scheme_http && !scheme_https {
            return None;
        }
        // scheme-less host[:port]/path
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

        // http + path => URL scan (URL blooms, full URL); else domain scan
        // (registrable main domain against the domain blooms).
        let url_scan = scheme_http && has_path;
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
}
