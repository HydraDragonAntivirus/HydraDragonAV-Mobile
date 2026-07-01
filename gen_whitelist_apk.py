"""Build the EXACT whole-APK MD5 whitelist from the NSRL RDS Android SQLite
database (sql/RDS_*_android.db).

Only `extension='apk'` rows are taken — these are whole APKs, whose MD5
matches what the on-device scanner computes for a whole APK/zip buffer. The full
per-file set (~105M hashes) is intentionally NOT used: it is ~3.4 GB exact /
~380 MB as a bloom (too big for a phone, and a bloom FP would be a whitelist
false-negative). Inner-file false positives are handled by per-detection APK
lineage suppression in the scanner, not a giant per-file hash DB.

The result is matched EXACTLY (HashSet, no bloom) on-device: the set is small
(~70k) so there are zero false positives — a malicious hash can never collide
into the whitelist.

Output: app/src/main/assets/whitelist_hashes.txt  (one lowercase md5/line)

Usage:
    python gen_whitelist_apk.py [path/to/RDS.db]
"""

import os
import sqlite3
import sys
from pathlib import Path

DB = sys.argv[1] if len(sys.argv) > 1 else "sql/RDS_2026.03.1_android.db"
OUT = Path("app/src/main/assets/whitelist_hashes.txt")


def main():
    os.chdir(Path(__file__).parent)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    rows = con.execute(
        "SELECT DISTINCT lower(md5) FROM METADATA "
        "WHERE lower(extension)='apk' AND md5 IS NOT NULL AND length(md5)=32"
    )
    n = 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for (h,) in rows:
            f.write(h + "\n")
            n += 1
    con.close()
    print(f"{OUT}: {n:,} distinct whole-APK MD5, {os.path.getsize(OUT):,} bytes")


if __name__ == "__main__":
    main()
