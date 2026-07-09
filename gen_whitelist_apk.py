"""Build the compact whole-APK MD5 whitelist filter.

Only `extension='apk'` rows are taken - these are whole APKs, whose MD5
matches what the on-device scanner computes for a whole APK/zip buffer. The full
per-file set (~105M hashes) is intentionally NOT used: it is ~3.4 GB exact /
~380 MB as a bloom (too big for a phone, and a bloom FP would be a whitelist
false-negative). Inner-file false positives are handled by per-detection APK
lineage suppression in the scanner, not a giant per-file hash DB.

The result is a Binary-Fuse xor filter over 16-byte MD5 strings. It is generated
from app/src/main/assets/scan/whitelist_packages.db when that DB already exists,
or directly from the NSRL RDS Android SQLite database when a DB path is passed.

Outputs:
    xf_build/whitelist_md5.txt
    app/src/main/assets/scan/whitelist.xf

When reading NSRL RDS, applies every sql/RDS_*_android_delta.sql newer than the
base DB (not
just one hardcoded month) so a whole-APK hash only present in a later delta
isn't dropped.

Usage:
    python gen_whitelist_apk.py [path/to/RDS.db] [--fpp 0.0001]
"""

import argparse
import os
import sys
import sqlite3
import subprocess
from pathlib import Path

import nsrl_sql

SCAN_DIR = Path("app/src/main/assets/scan")
PACKAGE_DB = SCAN_DIR / "whitelist_packages.db"
HASHES_OUT = Path("xf_build/whitelist_md5.txt")
XF_OUT = SCAN_DIR / "whitelist.xf"
DEFAULT_FPP = "0.0001"


def _writer_path():
    exe = "xorfilter_writer.exe" if os.name == "nt" else "xorfilter_writer"
    return Path("dev-tools/xorfilter_writer/target/release") / exe


def _ensure_writer():
    writer = _writer_path()
    if writer.exists():
        return writer
    subprocess.run(["cargo", "build", "--release"], cwd="dev-tools/xorfilter_writer", check=True)
    return writer


def _valid_md5(value):
    if value is None:
        return None
    h = str(value).strip().lower()
    if len(h) != 32:
        return None
    if any(c not in "0123456789abcdef" for c in h):
        return None
    return h


def _md5_rows_from_package_db(path):
    con = sqlite3.connect(path)
    try:
        rows = con.execute(
            "SELECT DISTINCT lower(md5) FROM whitelist_package "
            "WHERE md5 IS NOT NULL AND length(md5)=32 "
            "ORDER BY 1"
        )
        for (h,) in rows:
            h = _valid_md5(h)
            if h:
                yield h
    finally:
        con.close()


def _md5_rows_from_rds(path):
    con = nsrl_sql.open_with_deltas(path)
    try:
        rows = con.execute(
            "SELECT DISTINCT lower(md5) FROM METADATA "
            "WHERE lower(extension)='apk' AND md5 IS NOT NULL AND length(md5)=32 "
            "ORDER BY 1"
        )
        for (h,) in rows:
            h = _valid_md5(h)
            if h:
                yield h
    finally:
        con.close()


def _write_hashes(rows, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for h in rows:
            f.write(h + "\n")
            n += 1
    return n


def main():
    os.chdir(Path(__file__).parent)
    parser = argparse.ArgumentParser()
    parser.add_argument("db", nargs="?", help="Optional NSRL RDS Android SQLite DB")
    parser.add_argument("--fpp", default=DEFAULT_FPP, help="Target false-positive rate")
    parser.add_argument("--hashes-out", default=str(HASHES_OUT))
    parser.add_argument("--xf-out", default=str(XF_OUT))
    parser.add_argument("--no-xf", action="store_true", help="Only write the md5 text list")
    args = parser.parse_args()

    hashes_out = Path(args.hashes_out)
    xf_out = Path(args.xf_out)

    if args.db:
        source = Path(args.db)
        rows = _md5_rows_from_rds(source)
    elif PACKAGE_DB.exists():
        source = PACKAGE_DB
        rows = _md5_rows_from_package_db(source)
    else:
        source = Path(nsrl_sql.find_main_db())
        rows = _md5_rows_from_rds(source)

    n = _write_hashes(rows, hashes_out)
    print(
        f"{hashes_out}: {n:,} distinct whole-APK MD5 from {source}, "
        f"{os.path.getsize(hashes_out):,} bytes"
    )
    if args.no_xf:
        return
    xf_out.parent.mkdir(parents=True, exist_ok=True)
    writer = _ensure_writer()
    subprocess.run([str(writer), str(hashes_out), str(xf_out), args.fpp], check=True)
    print(f"{xf_out}: {os.path.getsize(xf_out):,} bytes (fpp {args.fpp})")


if __name__ == "__main__":
    main()
