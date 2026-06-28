#!/usr/bin/env python3
"""
Filter allblooms/MaliciousLinks.txt against the whitelist/ CSVs.

MaliciousLinks.txt holds scheme-less URLs (host[:port]/path). For each link we
take the host, derive its subdomain->registrable-domain candidates, and drop the
link if ANY candidate appears in the whitelist (popular/known-good domains &
subdomains). Output: allblooms/MaliciousLinks_filtered.txt.

Memory-safe: the whitelist CSVs are huge (~12M lines), so instead of loading
them we first collect the (small) set of candidate hosts from MaliciousLinks,
then stream the CSVs once and mark which candidates are whitelisted.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
LINKS = os.path.join(ROOT, "allblooms", "MaliciousLinks.txt")
OUT = os.path.join(ROOT, "allblooms", "MaliciousLinks_filtered.txt")
WHITELIST_DIR = os.path.join(ROOT, "whitelist")
WHITELIST_CSVS = [
    "DomainsPopularityWhiteList.optimized.csv",
    "SubDomainsPopularityWhiteList.optimized.csv",
    "WhiteListDomains.optimized.csv",
    "WhiteListSubDomains.optimized.csv",
]


def host_of(link: str) -> str:
    """Extract lowercase host from a scheme-less 'host[:port]/path' link."""
    h = link.strip()
    if not h:
        return ""
    h = h.split("/", 1)[0]      # drop path
    h = h.split(":", 1)[0]      # drop port
    return h.strip().lower()


def candidates(host: str):
    """Full host + each suffix down to the last two labels."""
    if not host:
        return []
    labels = host.split(".")
    out = []
    for i in range(0, max(1, len(labels) - 1)):
        out.append(".".join(labels[i:]))
    if len(labels) == 1:
        out.append(host)
    return out


def main():
    if not os.path.isfile(LINKS):
        print(f"missing {LINKS}")
        sys.exit(1)

    # Pass 1: read links, build per-line candidates + the global candidate set.
    line_cands = []          # (original_line, [candidates])
    all_cands = set()
    with open(LINKS, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.rstrip("\n")
            if not s.strip():
                continue
            cs = candidates(host_of(s))
            line_cands.append((s, cs))
            all_cands.update(cs)
    print(f"links: {len(line_cands)}, unique candidate hosts: {len(all_cands)}")

    # Pass 2: stream whitelist CSVs, mark candidates that are whitelisted.
    whitelisted = set()
    for name in WHITELIST_CSVS:
        path = os.path.join(WHITELIST_DIR, name)
        if not os.path.isfile(path):
            print(f"  (skip, not found: {name})")
            continue
        hits = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                host = line.split(",", 1)[0].strip().lower()
                if host and host in all_cands and host not in whitelisted:
                    whitelisted.add(host)
                    hits += 1
        print(f"  {name}: {hits} candidate matches")
    print(f"whitelisted candidate hosts: {len(whitelisted)}")

    # Pass 3: write links whose host has NO whitelisted candidate.
    kept = dropped = 0
    with open(OUT, "w", encoding="utf-8") as out:
        for s, cs in line_cands:
            if any(c in whitelisted for c in cs):
                dropped += 1
            else:
                out.write(s + "\n")
                kept += 1
    print(f"kept: {kept}, dropped (whitelisted): {dropped} -> {OUT}")


if __name__ == "__main__":
    main()
