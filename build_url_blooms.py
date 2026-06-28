#!/usr/bin/env python3
"""
Build the URL blooms (scheme-less, WHITELIST-FILTERED) used by UrlThreatScanner:

  malwareurl.bloom  <- MaliciousLinks.txt + urlhaus.csv
  phishingurl.bloom <- phishing_links.json

Each entry has ONLY the leading scheme stripped (http:// / https:// removed,
host[:port]/path kept, lowercased). BOTH lists are then filtered against ALL the
whitelist/ CSVs: any entry whose host (or a parent domain) is whitelisted is
dropped, to avoid flagging legit/popular sites.

Memory-safe: we collect the (small) set of candidate hosts from the URL lists,
stream the huge whitelist CSVs once to mark which are whitelisted, then drop.
Reuses the Guava-compatible BloomFilter from gen_domain_bloom.py.
"""
import csv
import json
import os
from pathlib import Path

os.chdir(Path(__file__).parent)

from gen_domain_bloom import BloomFilter, HAVE_MMH3  # noqa: E402

BLOOMS_DIR = Path("allblooms")
WHITELIST_DIR = Path("whitelist")
ASSETS_DIR = Path("app/src/main/assets")
FPP = 0.01
WHITELIST_CSVS = [
    "DomainsPopularityWhiteList.optimized.csv",
    "SubDomainsPopularityWhiteList.optimized.csv",
    "WhiteListDomains.optimized.csv",
    "WhiteListSubDomains.optimized.csv",
]


def strip_scheme(u: str):
    if not u:
        return None
    u = u.strip().lower()
    if u.startswith("https://"):
        u = u[8:]
    elif u.startswith("http://"):
        u = u[7:]
    u = u.strip()
    return u or None


def host_candidates(entry: str):
    """host[:port]/path -> [full host, ... down to last two labels]."""
    host = entry.split("/", 1)[0].split(":", 1)[0]
    if not host:
        return []
    labels = host.split(".")
    out = []
    for i in range(0, max(1, len(labels) - 1)):
        out.append(".".join(labels[i:]))
    if len(labels) == 1:
        out.append(host)
    return out


def from_links_txt(path: Path):
    out = set()
    if path.exists():
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    v = strip_scheme(s)
                    if v:
                        out.add(v)
    return out


def from_urlhaus(path: Path):
    out = set()
    if path.exists():
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f):
                if not row or row[0] == "id" or len(row) <= 2:
                    continue
                v = strip_scheme(row[2])
                if v:
                    out.add(v)
    return out


def from_phishing_json(path: Path):
    out = set()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            entries = data.get("data", []) if isinstance(data, dict) else data
            for e in entries:
                if isinstance(e, str):
                    v = strip_scheme(e)
                    if v:
                        out.add(v)
        except Exception as ex:
            print(f"  [SKIP] {path.name}: {ex}")
    return out


def whitelist_filter(*entry_sets):
    """Drop entries whose host (or a parent domain) is in any whitelist CSV.
    Returns filtered copies of each input set, in order."""
    # 1) collect candidate hosts across ALL entry sets.
    all_cands = set()
    per_entry = []   # list of (entry, candidates) per set
    for s in entry_sets:
        ec = []
        for e in s:
            cs = host_candidates(e)
            ec.append((e, cs))
            all_cands.update(cs)
        per_entry.append(ec)
    print(f"  candidate hosts to check: {len(all_cands):,}")

    # 2) stream whitelist CSVs, mark whitelisted candidates.
    whitelisted = set()
    for name in WHITELIST_CSVS:
        path = WHITELIST_DIR / name
        if not path.exists():
            print(f"    (skip, not found: {name})")
            continue
        hits = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                host = line.split(",", 1)[0].strip().lower()
                if host and host in all_cands and host not in whitelisted:
                    whitelisted.add(host)
                    hits += 1
        print(f"    {name}: {hits:,} matches")
    print(f"  whitelisted hosts: {len(whitelisted):,}")

    # 3) drop entries whose any candidate is whitelisted.
    results = []
    for ec in per_entry:
        kept = {e for (e, cs) in ec if not any(c in whitelisted for c in cs)}
        results.append(kept)
    return results


def write_bloom(name: str, entries: set):
    if not entries:
        print(f"  [SKIP] {name}: no entries")
        return
    bf = BloomFilter(expected_insertions=len(entries), fpp=FPP)
    for e in entries:
        bf.put(e)
    out = ASSETS_DIR / name
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    bf.write_to(str(out))
    print(f"  {name}: {len(entries):,} entries -> {os.path.getsize(str(out)):,} bytes")


def main():
    if not HAVE_MMH3:
        raise SystemExit("mmh3 required: pip install mmh3")

    mal = from_links_txt(BLOOMS_DIR / "MaliciousLinks.txt") | from_urlhaus(BLOOMS_DIR / "urlhaus.csv")
    phish = from_phishing_json(BLOOMS_DIR / "phishing_links.json")
    print(f"raw: malwareurl={len(mal):,}, phishingurl={len(phish):,}")

    print("=== whitelist filtering (all CSVs) ===")
    mal_f, phish_f = whitelist_filter(mal, phish)
    print(f"filtered: malwareurl={len(mal_f):,} (-{len(mal) - len(mal_f):,}), "
          f"phishingurl={len(phish_f):,} (-{len(phish) - len(phish_f):,})")

    write_bloom("malwareurl.bloom", mal_f)
    write_bloom("phishingurl.bloom", phish_f)


if __name__ == "__main__":
    main()
