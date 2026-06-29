#!/usr/bin/env python3
"""
Build app/src/main/assets/scan/whitelist_domains.bloom from the whitelist/ CSVs.

UrlThreatScanner checks this FIRST: if a URL's host (or a parent domain) is in
the whitelist, it is treated as clean and the malware/phishing blooms are not
consulted — stopping bloom false-positives from flagging popular legit sites
(github.com, google.com, ...).

Entries are plain registrable domains + subdomains, lowercased.
"""
import csv
import os
from pathlib import Path

os.chdir(Path(__file__).parent)
from gen_domain_bloom import BloomFilter, HAVE_MMH3  # noqa: E402

WHITELIST_DIR = Path("whitelist")
OUT = Path("app/src/main/assets/scan/whitelist_domains.bloom")
FPP = 0.01
CSVS = [
    "DomainsPopularityWhiteList.optimized.csv",
    "WhiteListDomains.optimized.csv",
    "WhiteListSubDomains.optimized.csv",
]


def main():
    if not HAVE_MMH3:
        raise SystemExit("mmh3 required: pip install mmh3")
    hosts = set()
    for name in CSVS:
        p = WHITELIST_DIR / name
        if not p.exists():
            print(f"  (skip {name})")
            continue
        n = 0
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f):
                if not row:
                    continue
                h = row[0].strip().lower()
                if h and "." in h:
                    hosts.add(h)
                    n += 1
        print(f"  {name}: {n:,}")
    if not hosts:
        raise SystemExit("no whitelist hosts")
    print(f"total unique whitelist hosts: {len(hosts):,}")
    bf = BloomFilter(expected_insertions=len(hosts), fpp=FPP)
    for h in hosts:
        bf.put(h)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    bf.write_to(str(OUT))
    print(f"wrote {OUT} ({os.path.getsize(str(OUT)):,} bytes)")


if __name__ == "__main__":
    main()
