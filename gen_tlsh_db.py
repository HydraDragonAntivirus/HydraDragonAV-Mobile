"""Build per-type malware TLSH similarity databases from the MalwareBazaar full
dump, keeping ONLY Android-relevant file types (apk, elf, so, dex) and their T1
TLSH digests. Each type gets its own file so the native engine (tlsh-rs) only
compares a scanned buffer against digests of the same type (ELF vs ELF, APK vs
APK, DEX vs DEX), avoiding cross-type false matches.

Outputs:
  app/src/main/assets/scan/malware_tlsh_elf.txt   (.so / ELF)
  app/src/main/assets/scan/malware_tlsh_apk.txt   (.apk / ZIP)
  app/src/main/assets/scan/malware_tlsh_dex.txt   (.dex)

Usage:
    python gen_tlsh_db.py
"""

import csv
import os
from pathlib import Path

SRC = Path("malwarebazaarfull/full.csv")
OUTDIR = Path("app/src/main/assets/scan")

# Output files keyed by type
TYPE_FILE = {
    "elf": "malware_tlsh_elf.txt",
    "so":  "malware_tlsh_elf.txt",   # Merge .so into ELF (same format)
    "apk": "malware_tlsh_apk.txt",
    "dex": "malware_tlsh_dex.txt",
}
TYPES = set(TYPE_FILE.keys())


def main():
    os.chdir(Path(__file__).parent)
    OUTDIR.mkdir(parents=True, exist_ok=True)

    # Per-output-file set to dedupe within each type
    per_file: dict[str, set[str]] = {}
    for fname in set(TYPE_FILE.values()):
        per_file[fname] = set()
    counts: dict[str, int] = {}

    with open(SRC, "r", encoding="utf-8", errors="ignore") as f:
        rows = (line for line in f if not line.startswith("#"))
        for row in csv.reader(rows, skipinitialspace=True):
            if len(row) < 14:
                continue
            ftype = row[6].strip().lower()
            target_file = TYPE_FILE.get(ftype)
            if target_file is None:
                continue
            tlsh = row[13].strip().upper()
            if not tlsh.startswith("T1") or len(tlsh) < 70:
                continue
            if all(c in "0123456789ABCDEF" for c in tlsh[2:]):
                if tlsh not in per_file[target_file]:
                    per_file[target_file].add(tlsh)
                    counts[target_file] = counts.get(target_file, 0) + 1

    total = 0
    for fname, digests in per_file.items():
        out_path = OUTDIR / fname
        with open(out_path, "w", encoding="utf-8", newline="\n") as out:
            out.write("\n".join(sorted(digests)))
            if digests:
                out.write("\n")
        n = len(digests)
        total += n
        print(f"  {fname}: {n:,} digests ({os.path.getsize(out_path):,} bytes)")

    print(f"  total: {total:,} unique T1 TLSH digests across {len(per_file)} files")


if __name__ == "__main__":
    main()
