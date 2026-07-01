"""Shared NSRL RDS file discovery for the gen_whitelist_*.py build scripts.

The NSRL Android dump ships as a dated full DB (sql/RDS_2026.03.1_android.db)
plus periodic delta SQL dumps (sql/RDS_2026.06.1_android_delta.sql, and later
months as they arrive). The date/patch numbers in the filename are NOT fixed
to any one format, so callers must glob + sort rather than hardcode a path —
otherwise a newer delta (or a renamed full DB) silently gets skipped.
"""

import glob
import re
import sqlite3
from pathlib import Path

_RDS_RE = re.compile(r"RDS_(\d+)\.(\d+)\.(\d+)_android(?:_delta)?\.(db|sql)$", re.IGNORECASE)


def _sort_key(path):
    m = _RDS_RE.search(Path(path).name)
    return tuple(int(g) for g in m.groups()[:3]) if m else (0, 0, 0)


def find_main_db(sql_dir="sql"):
    """Newest sql/RDS_*_android.db (the full dump, not a delta)."""
    candidates = glob.glob(f"{sql_dir}/RDS_*_android.db")
    if not candidates:
        raise FileNotFoundError(f"no RDS_*_android.db under {sql_dir}/")
    return max(candidates, key=_sort_key)


def find_delta_sqls(sql_dir="sql"):
    """Every sql/RDS_*_android_delta.sql, oldest to newest."""
    return sorted(glob.glob(f"{sql_dir}/RDS_*_android_delta.sql"), key=_sort_key)


def open_with_deltas(db_path, sql_dir="sql"):
    """Open db_path and apply every delta .sql newer than it, in date order,
    so a package that only exists in a later delta (e.g. a "06.01" delta on
    top of a "03.01" base) is not missed."""
    con = sqlite3.connect(db_path)
    base_key = _sort_key(db_path)
    for delta in find_delta_sqls(sql_dir):
        if _sort_key(delta) > base_key:
            con.executescript(Path(delta).read_text(encoding="utf-8", errors="ignore"))
    return con
