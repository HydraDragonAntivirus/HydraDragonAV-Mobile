"""Build the NSRL MD5 whitelist bloom the SAME way as the domain/URL blooms:
extract every md5 from the NSRL RDS Android database (.db) AND the monthly
delta (.sql), then compile a Guava bloom with BloomWriter at fpp 1e-6 (identical
to the malicious/domain blooms).

ONE hash type only: md5. No deduplication is performed before the bloom — a
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
TXT = "whitelist_md5.txt"               # working file (large; removed at end)
OUT = "app/src/main/assets/whitelist.bloom"
FPP = "0.000001"                        # same as the domain/malicious blooms
BW_DIR = "dev-tools/bloom_writer"
GUAVA = "guava-33.0.0-android.jar"

# md5 is the 3rd-from-last quoted value on a METADATA insert: ...,md5,sha1,sha256).
MD5RE = re.compile(rb",'([0-9a-f]{32})','[0-9a-f]{40}','[0-9a-f]{64}'\);")


def extract():
    n = 0
    with open(TXT, "w", encoding="utf-8", newline="\n") as out:
        # 1) full .db — stream every md5 (no DISTINCT).
        con = sqlite3.connect(DB)
        con.execute("PRAGMA cache_size=-1000000")
        for (h,) in con.execute(
            "SELECT lower(md5) FROM METADATA "
            "WHERE md5 IS NOT NULL AND length(md5)=32"
        ):
            out.write(h)
            out.write("\n")
            n += 1
            if n % 20_000_000 == 0:
                print(f"  db {n:,}...", flush=True)
        con.close()
        # 2) delta .sql — pull md5 (3rd-from-last quoted value) per METADATA
        #    insert line with a regex (case-insensitive hex).
        with open(DELTA, "rb") as f:
            for line in f:
                m = MD5RE.search(line.lower())
                if m:
                    out.write(m.group(1).decode())
                    out.write("\n")
                    n += 1
    print(f"total md5 rows written: {n:,}", flush=True)
    return n


def main():
    os.chdir(Path(__file__).parent)
    Path(OUT).parent.mkdir(parents=True, exist_ok=True)

    print("extracting md5 from .db + delta .sql ...", flush=True)
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
