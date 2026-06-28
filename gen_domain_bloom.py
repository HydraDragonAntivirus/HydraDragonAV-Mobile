""" Extract domains from allblooms/ datasets and write text files for BloomFilter generation.

Usage:
    pip install mmh3        # optional — only if generating .bloom with Python
    python gen_domain_bloom.py
    python gen_domain_bloom.py --bloom   # also generate .bloom files (requires mmh3)
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path

BLOOMS_DIR = Path("allblooms")
ASSETS_DIR = Path("app/src/main/assets")

try:
    import mmh3
    from math import ceil, log

    HAVE_MMH3 = True
except ImportError:
    HAVE_MMH3 = False


def optimal_num_bits(n: int, p: float) -> int:
    if p == 0:
        p = 1e-300
    return int(ceil(-n * log(p) / (log(2) ** 2)))


def optimal_num_hash_functions(n: int, m: int) -> int:
    return max(1, round(m / n * log(2)))


class BloomFilter:
    """Guava MURMUR128_MITZ_64 compatible bloom filter."""

    LONG_MASK = 0xFFFFFFFFFFFFFFFF
    POSITIVE_MASK = 0x7FFFFFFFFFFFFFFF  # Long.MAX_VALUE

    def __init__(self, expected_insertions: int, fpp: float = 0.01):
        optimal = optimal_num_bits(expected_insertions, fpp)
        self.num_longs = int(ceil(optimal / 64))
        # Guava pads to next multiple of 64; bitSize = num_longs * 64
        self.num_bits = self.num_longs * 64
        self.num_hash_functions = optimal_num_hash_functions(expected_insertions, optimal)
        self.bits = [0] * self.num_longs

    def _mask_long(self, val: int) -> int:
        return val & self.LONG_MASK

    def put(self, key: str) -> bool:
        raw = mmh3.hash64(key.encode("utf-8"), seed=0)
        h1, h2 = raw if isinstance(raw, tuple) else (raw[0], raw[1])
        changed = False
        combined = self._mask_long(h1)
        for _ in range(self.num_hash_functions):
            idx = (combined & self.POSITIVE_MASK) % self.num_bits
            long_idx = idx // 64
            bit_idx = idx % 64
            mask = 1 << bit_idx
            if not (self.bits[long_idx] & mask):
                self.bits[long_idx] |= mask
                changed = True
            combined = self._mask_long(combined + h2)
        return changed

    def write_to(self, path: str):
        """Guava serialization: byte(strategy) + byte(numHash) + int(dataLen) + N*long(data)."""
        import struct
        with open(path, "wb") as f:
            f.write(struct.pack(">b", 1))       # strategy = MURMUR128_MITZ_64 (ordinal 1)
            f.write(struct.pack(">B", self.num_hash_functions))
            f.write(struct.pack(">I", self.num_longs))
            for val in self.bits:
                f.write(struct.pack(">Q", val))


def extract_domains_from_csv(filepath: str, column: int = 0) -> set:
    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if row and row[column].strip() and not row[column].startswith("#"):
                domains.add(row[column].strip().lower())
    return domains


def extract_hostnames_from_urls(filepath: str) -> set:
    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = line.split("://", 1)[1] if "://" in line else line
            host = url.split("/")[0].split(":")[0]
            if host:
                domains.add(host.lower())
    return domains


def extract_urls_from_urlhaus_csv(filepath: str) -> set:
    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or row[0] == "id" or len(row) <= 2:
                continue
            url = row[2].strip().lower()
            host = url.split("://", 1)[1].split("/")[0].split(":")[0] if "://" in url else url.split("/")[0].split(":")[0]
            if host:
                domains.add(host)
    return domains


def extract_from_optimized(prefix: str, tag: str) -> set:
    path = BLOOMS_DIR / f"{prefix}.optimized.csv"
    if not path.exists():
        return set()
    domains = extract_domains_from_csv(str(path))
    print(f"  [{tag}] {path.name}: {len(domains):,} domains")
    return domains


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bloom", action="store_true", help="Generate .bloom files (requires mmh3)")
    args = parser.parse_args()

    os.chdir(Path(__file__).parent)
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

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

    categories["malware"] = extract_from_optimized("MalwareSubDomains", "MWDOM")
    # MalwareDomains.csv is a plain (non-optimized) CSV: header "entry,reference"
    # with the domain in column 0.
    malware_csv = BLOOMS_DIR / "MalwareDomains.csv"
    if malware_csv.exists():
        mw_domains = extract_domains_from_csv(str(malware_csv))
        mw_domains.discard("entry")  # drop the CSV header value
        print(f"  [MWDOM] MalwareDomains.csv: {len(mw_domains):,} domains")
        categories["malware"] |= mw_domains
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
                    host = url.split("://", 1)[1] if "://" in url else url
                    host = host.split("/")[0].split(":")[0]
                    if host:
                        phish_urls.add(host)
            if phish_urls:
                print(f"  [PHURL] phishing_links.json: {len(phish_urls):,} domains")
        except Exception as e:
            print(f"  [SKIP] phishing_links.json: {e}")
    categories["phishingurl"] = phish_urls

    # Categories that feed the combined malicious set but get NO standalone
    # .bloom of their own. "malware" is huge (~8M) and fully covered by the
    # combined malicious.bloom, so we don't ship a separate malware.bloom.
    COMBINED_ONLY = {"malware"}

    # ── Write category text files ───────────────────────────────────
    print("\n=== Writing category text files ===")
    for name, domains in sorted(categories.items()):
        if name in COMBINED_ONLY:
            continue
        txt_path = ASSETS_DIR / f"{name}_domains.txt"
        with open(str(txt_path), "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(d + "\n")
        size = os.path.getsize(str(txt_path))
        print(f"  {txt_path.name}: {len(domains):,} entries, {size:,} bytes")

    # ── Combined malicious set ──────────────────────────────────────
    combined = set()
    for d in categories.values():
        combined |= d
    combined_txt = ASSETS_DIR / "malicious_domains.txt"
    with open(str(combined_txt), "w", encoding="utf-8") as f:
        for d in sorted(combined):
            f.write(d + "\n")
    print(f"\n  malicious_domains.txt: {len(combined):,} entries,"
          f" {os.path.getsize(str(combined_txt)):,} bytes")

    print("\n  Run dev-tools/bloom_writer/build_run.bat to generate one .bloom per")
    print("  category text file above (phishing.bloom, malwareurl.bloom, ...) plus")
    print("  the combined malicious.bloom, using BloomWriter.java (uses real Guava).")


if __name__ == "__main__":
    main()
