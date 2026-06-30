"""Build the malware TLSH similarity database from the MalwareBazaar full dump,
keeping ONLY Android-relevant file types (apk, elf, so, dex) and their T1 TLSH
digests. Used by the native engine (tlsh-rs) for fuzzy-similarity detection:
a scanned APK/.so/.elf whose TLSH is close (small distance) to one of these is
flagged as similar to known malware.

Output: app/src/main/assets/scan/malware_tlsh.txt  (one T1 digest per line)

Usage:
    python gen_tlsh_db.py
"""

import csv
import os
from pathlib import Path

SRC = Path("malwarebazaarfull/full.csv")
OUT = Path("app/src/main/assets/scan/malware_tlsh.txt")
TYPES = {"apk", "elf", "so", "dex"}


def main():
    os.chdir(Path(__file__).parent)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    per_type = {t: 0 for t in TYPES}
    with open(SRC, "r", encoding="utf-8", errors="ignore") as f:
        rows = (line for line in f if not line.startswith("#"))
        for row in csv.reader(rows, skipinitialspace=True):
            if len(row) < 14:
                continue
            ftype = row[6].strip().lower()
            if ftype not in TYPES:
                continue
            tlsh = row[13].strip().upper()
            # Valid T1 digest: "T1" + 70 hex (128/1 default) — accept >=70 total.
            if not tlsh.startswith("T1") or len(tlsh) < 70:
                continue
            if all(c in "0123456789ABCDEF" for c in tlsh[2:]):
                if tlsh not in seen:
                    seen.add(tlsh)
                    per_type[ftype] += 1

    with open(OUT, "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(sorted(seen)))
        if seen:
            out.write("\n")

    print(f"  per-type kept: {per_type}")
    print(f"  {OUT}: {len(seen):,} unique T1 TLSH digests, "
          f"{os.path.getsize(OUT):,} bytes")


if __name__ == "__main__":
    main()
