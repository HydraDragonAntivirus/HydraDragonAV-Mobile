#!/usr/bin/env python3
"""
Build the URL blooms (scheme-less) used by UrlThreatScanner:

  malwareurl.bloom  <- allblooms/MaliciousLinks.txt + allblooms/urlhaus.csv
  phishingurl.bloom <- allblooms/phishing_links.json

Each entry has ONLY the leading scheme removed: http:// / https:// is stripped
from the front, the rest (host[:port]/path) is kept and lowercased. This is
smaller than storing the scheme and matches UrlThreatScanner, which strips the
leading scheme of any http(s):// string it finds before lookup.

Reuses the Guava-compatible BloomFilter from gen_domain_bloom.py so the output
format is byte-identical to the other shipped .bloom files.
"""
import csv
import json
import os
from pathlib import Path

os.chdir(Path(__file__).parent)

from gen_domain_bloom import BloomFilter, HAVE_MMH3  # noqa: E402

BLOOMS_DIR = Path("allblooms")
ASSETS_DIR = Path("app/src/main/assets")
FPP = 0.01


def strip_scheme(u: str):
    """Lowercase + remove a leading http:// or https://. Empty -> None."""
    if not u:
        return None
    u = u.strip().lower()
    if u.startswith("https://"):
        u = u[8:]
    elif u.startswith("http://"):
        u = u[7:]
    u = u.strip()
    return u or None


def from_links_txt(path: Path):
    out = set()
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            v = strip_scheme(s)          # MaliciousLinks is already scheme-less
            if v:
                out.add(v)
    return out


def from_urlhaus(path: Path):
    out = set()
    if not path.exists():
        return out
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
    if not path.exists():
        return out
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

    mal = set()
    mal |= from_links_txt(BLOOMS_DIR / "MaliciousLinks.txt")
    print(f"  MaliciousLinks: {len(mal):,}")
    uh = from_urlhaus(BLOOMS_DIR / "urlhaus.csv")
    print(f"  urlhaus: {len(uh):,}")
    mal |= uh
    write_bloom("malwareurl.bloom", mal)

    phish = from_phishing_json(BLOOMS_DIR / "phishing_links.json")
    print(f"  phishing_links.json: {len(phish):,}")
    write_bloom("phishingurl.bloom", phish)


if __name__ == "__main__":
    main()
