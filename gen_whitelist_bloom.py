"""Build the NSRL SHA-256 whitelist bloom the SAME way as the domain/URL blooms:
extract every sha256 from the NSRL RDS Android database (.db) AND the monthly
delta (.sql), then compile a Guava bloom with BloomWriter at fpp 1e-6 (identical
to the malicious/domain blooms).

ONE hash type only: sha256. No deduplication is performed before the bloom — a
bloom is idempotent (duplicate inserts re-set the same bits), so DISTINCT is a
waste; we just stream every row. Both the full .db and the delta .sql are used.

Output: app/src/main/assets/whitelist.bloom

Usage:
    python gen_whitelist_bloom.py
"""

import os
import re
import subprocess
import sqlite3
from pathlib import Path

DB = "sql/RDS_2026.03.1_android.db"
DELTA = "sql/RDS_2026.06.1_android_delta.sql"
TXT = "whitelist_sha256.txt"            # working file (large; removed at end)
OUT = "app/src/main/assets/whitelist.bloom"
FPP = "0.000001"                        # same as the domain/malicious blooms
BW_DIR = "dev-tools/bloom_writer"
GUAVA = "guava-33.0.0-android.jar"

HEX64 = re.compile(rb"[0-9a-f]{64}'\);")


def extract():
    n = 0
    with open(TXT, "w", encoding="utf-8", newline="\n") as out:
        # 1) full .db — stream every sha256 (no DISTINCT).
        con = sqlite3.connect(DB)
        con.execute("PRAGMA cache_size=-1000000")
        for (h,) in con.execute(
            "SELECT lower(sha256) FROM METADATA "
            "WHERE sha256 IS NOT NULL AND length(sha256)=64"
        ):
            out.write(h)
            out.write("\n")
            n += 1
            if n % 20_000_000 == 0:
                print(f"  db {n:,}...", flush=True)
        con.close()
        # 2) delta .sql — sha256 is the last quoted value before ');' on each
        #    METADATA insert line. Pull it with a regex (case-insensitive hex).
        with open(DELTA, "rb") as f:
            for line in f:
                m = HEX64.search(line.lower())
                if m:
                    out.write(m.group(0)[:64].decode())
                    out.write("\n")
                    n += 1
    print(f"total sha256 rows written: {n:,}", flush=True)
    return n


def main():
    os.chdir(Path(__file__).parent)
    Path(OUT).parent.mkdir(parents=True, exist_ok=True)

    print("extracting sha256 from .db + delta .sql ...", flush=True)
    n = extract()

    # BloomWriter sizes by inserted-count; using the raw (non-deduped) row count
    # only ever over-provisions (slightly lower fpp), which is harmless.
    out_abs = str(Path(OUT).resolve())
    txt_abs = str(Path(TXT).resolve())
    print(f"building bloom (fpp={FPP}) ...", flush=True)
    subprocess.run(
        ["java", "-Xmx8g", "-cp", f".;{GUAVA}", "BloomWriter", txt_abs, out_abs, str(n), FPP],
        cwd=BW_DIR,
        check=True,
    )
    os.remove(TXT)
    print(f"{OUT}: {os.path.getsize(OUT):,} bytes", flush=True)


if __name__ == "__main__":
    main()
