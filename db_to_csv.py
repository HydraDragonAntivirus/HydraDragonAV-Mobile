"""Convert an existing whitelist_packages.db (old SQLite format) into the
current CSV format (whitelist_packages.csv) without needing the NSRL RDS
source database.

Reads the whitelist_package table from the given .db and writes one
"key,md5" line per row with an md5 present. Useful for migrating a device /
build that already has the .db asset when the original RDS.db is not
available on this machine. New builds should use gen_whitelist_packages.py
directly from RDS instead.

Usage:
    python db_to_csv.py [path/to/whitelist_packages.db]
"""

import csv
import os
import sqlite3
import sys
from pathlib import Path

OUT = Path("app/src/main/assets/scan/whitelist_packages.csv")


def main():
    os.chdir(Path(__file__).parent)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    db_path = sys.argv[1] if len(sys.argv) > 1 else "app/src/main/assets/scan/whitelist_packages.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    if "whitelist_package" not in tables:
        sys.exit(f"{db_path}: no whitelist_package table (tables: {tables})")

    n = 0
    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        rows = cur.execute("SELECT key, md5 FROM whitelist_package WHERE md5 IS NOT NULL")
        for key, md5 in rows:
            writer.writerow((key, md5))
            n += 1
    conn.close()
    print(f"{OUT}: {n:,} rows, {os.path.getsize(OUT):,} bytes")


if __name__ == "__main__":
    main()
