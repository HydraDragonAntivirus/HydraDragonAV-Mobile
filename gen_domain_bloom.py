""" Extract per-category domain/URL lists from allblooms/ datasets into xf_build/.

Each xf_build/<stem>.txt is then turned into assets/scan/<stem>.xf by the Rust
`xorfilter_writer` (see build_xfilters.sh). No bloom/Guava code here — filter
construction lives entirely on the Rust side.

Usage:
    python gen_domain_bloom.py
"""

import csv
import json
import os
from pathlib import Path

BLOOMS_DIR = Path("allblooms")
ASSETS_DIR = Path("app/src/main/assets")
# Staging dir for the per-category entry lists. These .txt files are the INPUT to
# `xorfilter_writer` (see build_xfilters.sh), which builds one `<stem>.xf` per file
# into assets/scan/. The .txt themselves are NOT shipped. Stems match the Rust
# `CATS` table in hydradragonandroid/src/url_scan.rs.
STAGE_DIR = Path("xf_build")

def extract_domains_from_csv(filepath: str, column: int = 0) -> set:
    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if row and row[column].strip() and not row[column].startswith("#"):
                domains.add(row[column].strip().lower())
    return domains


def extract_hostnames_from_urls(filepath: str) -> set:
    # Keep the FULL scheme-less URL (host/path), NOT just the host. Malware is
    # often hosted on legit platforms (github.com, ...); reducing to the host
    # would flag the whole platform. The full URL goes into the URL bloom.
    urls = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            su = line.split("://", 1)[1] if "://" in line else line
            if su:
                urls.add(su.lower())
    return urls


def extract_urls_from_urlhaus_csv(filepath: str) -> set:
    # Full scheme-less URL (host/path), not the bare host — see above.
    urls = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or row[0] == "id" or len(row) <= 2:
                continue
            url = row[2].strip().lower()
            su = url.split("://", 1)[1] if "://" in url else url
            if su:
                urls.add(su)
    return urls


def extract_from_optimized(prefix: str, tag: str) -> set:
    path = BLOOMS_DIR / f"{prefix}.optimized.csv"
    if not path.exists():
        return set()
    domains = extract_domains_from_csv(str(path))
    print(f"  [{tag}] {path.name}: {len(domains):,} domains")
    return domains


def extract_domains_skip_zero(filepath: str) -> set:
    """Like extract_domains_from_csv but DROPS referenceless (,0) entries.
    Only for MalwareDomains/MalwareSubDomains: ,0 (no known reference) are
    overwhelmingly false positives — a tiny fraction are real."""
    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or not row[0].strip() or row[0].startswith("#"):
                continue
            if len(row) >= 2 and row[1].strip() == "0":
                continue
            domains.add(row[0].strip().lower())
    return domains


def main():
    os.chdir(Path(__file__).parent)
    STAGE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Blacklist ──────────────────────────────────────────────────
    black = set()
    print("=== Blacklist ===")
    black |= extract_from_optimized("PhishingDomains", "BLACK")
    black |= extract_from_optimized("PhishingSubDomains", "BLACK")
    black |= extract_from_optimized("MalwareSubDomains", "BLACK")
    black |= extract_from_optimized("AbuseDomains", "BLACK")
    black |= extract_from_optimized("AbuseSubDomains", "BLACK")
    black |= extract_from_optimized("MiningDomains", "BLACK")
    black |= extract_from_optimized("MiningSubDomains", "BLACK")
    black |= extract_from_optimized("SpamDomains", "BLACK")
    black |= extract_from_optimized("SpamSubDomains", "BLACK")
    black |= extract_from_optimized("MaliciousMailDomains", "BLACK")
    black |= extract_from_optimized("MaliciousMailSubDomains", "BLACK")

    # ── Per-category domain sets ─────────────────────────────────────
    categories = {
        "phishing": extract_from_optimized("PhishingDomains", "PHISH") | extract_from_optimized("PhishingSubDomains", "PHISH"),
    }

    # urlhaus + MaliciousLinks = malwareurl
    mal_urls = set()
    mal_txt = BLOOMS_DIR / "MaliciousLinks.txt"
    if mal_txt.exists():
        mal_urls |= extract_hostnames_from_urls(str(mal_txt))
    urlhaus = BLOOMS_DIR / "urlhaus.csv"
    if urlhaus.exists():
        mal_urls |= extract_urls_from_urlhaus_csv(str(urlhaus))
    if mal_urls:
        print(f"  [URLHS] urlhaus+MaliciousLinks: {len(mal_urls):,} domains")
    categories["malwareurl"] = mal_urls

    # MalwareDomains/MalwareSubDomains: drop referenceless (,0) entries — mostly FP.
    categories["malware"] = set()
    for prefix in ("MalwareDomains", "MalwareSubDomains"):
        p = BLOOMS_DIR / f"{prefix}.optimized.csv"
        if p.exists():
            d = extract_domains_skip_zero(str(p))
            print(f"  [MWDOM] {p.name}: {len(d):,} domains (,0 referenceless skipped)")
            categories["malware"] |= d
    categories["abuse"] = extract_from_optimized("AbuseDomains", "ABUSE") | extract_from_optimized("AbuseSubDomains", "ABUSE")
    categories["mining"] = extract_from_optimized("MiningDomains", "MINE") | extract_from_optimized("MiningSubDomains", "MINE")
    categories["spam"] = extract_from_optimized("SpamDomains", "SPAM") | extract_from_optimized("SpamSubDomains", "SPAM")
    categories["malicious_mail"] = extract_from_optimized("MaliciousMailDomains", "MAIL") | extract_from_optimized("MaliciousMailSubDomains", "MAIL")

    # phishing_links.json → phishingurl  (URLs live under the "data" key)
    phish_urls = set()
    phish_json = BLOOMS_DIR / "phishing_links.json"
    if phish_json.exists():
        try:
            with open(str(phish_json), "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, dict):
                entries = data.get("data", [])
            elif isinstance(data, list):
                entries = data
            else:
                entries = []
            for entry in entries:
                if isinstance(entry, str):
                    url = entry.strip().lower()
                    su = url.split("://", 1)[1] if "://" in url else url
                    if su:
                        phish_urls.add(su)   # full scheme-less URL, not bare host
            if phish_urls:
                print(f"  [PHURL] phishing_links.json: {len(phish_urls):,} urls")
        except Exception as e:
            print(f"  [SKIP] phishing_links.json: {e}")
    categories["phishingurl"] = phish_urls

    # Categories that feed the combined malicious set but get NO standalone
    # .bloom of their own. "malware" is huge (~8M) and fully covered by the
    # combined malicious.bloom, so we don't ship a separate malware.bloom.
    COMBINED_ONLY = {"malware"}

    # ── Write category text files (staging, stems match the Rust CATS) ──────
    print("\n=== Writing category text files (xf_build/) ===")
    for name, domains in sorted(categories.items()):
        if name in COMBINED_ONLY:
            continue
        txt_path = STAGE_DIR / f"{name}.txt"
        with open(str(txt_path), "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(d + "\n")
        size = os.path.getsize(str(txt_path))
        print(f"  {txt_path.name}: {len(domains):,} entries, {size:,} bytes")

    # ── Combined malicious set ──────────────────────────────────────
    combined = set()
    for d in categories.values():
        combined |= d
    combined_txt = STAGE_DIR / "malicious.txt"
    with open(str(combined_txt), "w", encoding="utf-8") as f:
        for d in sorted(combined):
            f.write(d + "\n")
    print(f"\n  malicious.txt: {len(combined):,} entries,"
          f" {os.path.getsize(str(combined_txt)):,} bytes")

    print("\n  Next: build_url_blooms.py (writes whitelist-FILTERED malwareurl.txt /")
    print("  phishingurl.txt into xf_build/), then ./build_xfilters.sh to turn every")
    print("  xf_build/<stem>.txt into assets/scan/<stem>.xf via xorfilter_writer (1e-6).")


if __name__ == "__main__":
    main()
