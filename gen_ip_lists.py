"""Convert the referenced CIDR blacklist CSVs in allips/ to plain .txt lists.

Each allips/*.optimized.csv row is `CIDR,reference_count` — only the first
column (the CIDR) is kept; the second column is just a reference and is dropped.
Blank lines are removed. No bloom filter is produced: CIDR blacklists (sourced
from https://github.com/T145/black-mirror) are matched directly as prefix lists.

Output: app/src/main/assets/<name>.txt  (e.g. CIDRBlackListIPv4.txt)

Usage:
    python gen_ip_lists.py
"""

import csv
import os
from pathlib import Path

IPS_DIR = Path("allips")
ASSETS_DIR = Path("app/src/main/assets")


def main():
    os.chdir(Path(__file__).parent)
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    for src in sorted(IPS_DIR.glob("*.optimized.csv")):
        name = src.name.replace(".optimized.csv", "")
        out_path = ASSETS_DIR / f"{name}.txt"
        seen = set()
        cidrs = []
        with open(src, "r", encoding="utf-8", errors="ignore") as f:
            for row in csv.reader(f):
                if not row:
                    continue                      # drop blank lines
                cidr = row[0].strip()             # first column only
                if not cidr or cidr.startswith("#"):
                    continue
                if cidr in seen:
                    continue
                seen.add(cidr)
                cidrs.append(cidr)
        # Write with no trailing blank line.
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(cidrs))
            if cidrs:
                f.write("\n")
        print(f"  {src.name} -> {out_path.name}: {len(cidrs):,} CIDRs")


if __name__ == "__main__":
    main()
