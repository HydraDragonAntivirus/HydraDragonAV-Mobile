"""
F-Droid New APK Downloader
--------------------------
Downloads APKs from the official F-Droid repository that are NOT already
present locally. Compares by filename (apkName) so different versions of
the same package are considered "new".

Usage:
    pip install requests
    python fdroid-downloader.py

Config:
    Adjust the settings under CONFIG section below before running.
"""

import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ─────────────────────────── CONFIG ───────────────────────────

# Directory where existing APKs are stored (filenames here = "already have")
EXISTING_DIR = (
    r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile"
    r"\dataset\benign\F-Droid\16-07-2026-14.49"
)

# New APKs will be saved here
NEW_DIR = os.path.join(EXISTING_DIR, "new")

# F-Droid repository URLs
FDROID_INDEX_URL = "https://f-droid.org/repo/index-v1.json"
FDROID_REPO_BASE = "https://f-droid.org/repo/"

# Skip packages older than this many days. Set to 0 to disable age filter.
MAX_AGE_DAYS = 365 * 2  # 2 years

# Concurrent downloads
MAX_WORKERS = 6

# Download timeout (seconds)
TIMEOUT = 30

# ──────────────────────── FUNCTIONS ────────────────────────────


def get_existing_filenames(existing_dir: str) -> set:
    """Collect all .apk filenames under existing_dir (recursively)."""
    existing = set()
    if not os.path.isdir(existing_dir):
        print(f"[WARN] Existing directory not found: {existing_dir}")
        return existing
    for root, _, files in os.walk(existing_dir):
        for f in files:
            if f.lower().endswith(".apk"):
                existing.add(f)
    print(f"[INFO] Found {len(existing)} existing APK(s) in {existing_dir}")
    return existing


def download_fdroid_index(url: str) -> dict:
    """Fetch and parse the F-Droid repository index."""
    print("[INFO] Downloading F-Droid index (may be 50-100+ MB, please wait)...")
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    print("[INFO] Index downloaded, parsing JSON...")
    return resp.json()


def is_recent_enough(added_ms, last_updated_ms, max_age_days: int) -> bool:
    """Check whether the package is newer than max_age_days."""
    if max_age_days <= 0:
        return True
    cutoff = datetime.now(datetime.UTC) - timedelta(days=max_age_days)
    timestamps = [t for t in (added_ms, last_updated_ms) if t]
    if not timestamps:
        return True
    newest_dt = datetime.fromtimestamp(max(timestamps) / 1000, tz=datetime.UTC)
    return newest_dt >= cutoff


def build_download_list(index_data: dict, existing_filenames: set, max_age_days: int):
    """
    Build a list of (package_name, apk_name, url) for APKs that are:
      - not already present locally (by filename)
      - not too old (by added/lastUpdated timestamp)
    Picks the suggested version if available, otherwise the latest versionCode.
    """
    to_download = []

    packages = index_data.get("packages", {})
    apps = index_data.get("apps", [])
    apps_by_pkg = {a["packageName"]: a for a in apps}

    for pkg_name, versions in packages.items():
        if not versions:
            continue

        app_info = apps_by_pkg.get(pkg_name, {})
        suggested_code = app_info.get("suggestedVersionCode")

        chosen = None
        if suggested_code:
            for v in versions:
                if str(v.get("versionCode")) == str(suggested_code):
                    chosen = v
                    break
        if chosen is None:
            chosen = max(versions, key=lambda v: v.get("versionCode", 0))

        apk_name = chosen.get("apkName")
        if not apk_name:
            continue

        if apk_name in existing_filenames:
            continue

        added = chosen.get("added") or app_info.get("added")
        last_updated = app_info.get("lastUpdated") or chosen.get("added")
        if not is_recent_enough(added, last_updated, max_age_days):
            continue

        url = FDROID_REPO_BASE + apk_name
        to_download.append((pkg_name, apk_name, url))

    return to_download


def download_one(pkg_name: str, apk_name: str, url: str, dest_dir: str) -> str:
    """Download a single APK to dest_dir. Returns a status string."""
    dest_path = os.path.join(dest_dir, apk_name)
    if os.path.exists(dest_path):
        return f"[SKIP] {apk_name} already in new folder"

    tmp_path = dest_path + ".part"
    try:
        with requests.get(url, stream=True, timeout=TIMEOUT) as r:
            r.raise_for_status()
            with open(tmp_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=256 * 1024):
                    if chunk:
                        f.write(chunk)
        os.replace(tmp_path, dest_path)
        return f"[OK] {apk_name}"
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return f"[FAIL] {apk_name}: {e}"


# ─────────────────────────── MAIN ─────────────────────────────


def main():
    os.makedirs(NEW_DIR, exist_ok=True)

    existing_filenames = get_existing_filenames(EXISTING_DIR)
    index_data = download_fdroid_index(FDROID_INDEX_URL)

    to_download = build_download_list(index_data, existing_filenames, MAX_AGE_DAYS)
    print(
        f"[INFO] {len(to_download)} new APK(s) to download "
        f"(not in local dir and updated within {MAX_AGE_DAYS} days)."
    )

    if not to_download:
        print("[INFO] No new APKs to download.")
        return

    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(download_one, pkg, apk, url, NEW_DIR): apk
            for pkg, apk, url in to_download
        }
        for future in as_completed(futures):
            result = future.result()
            done += 1
            print(f"({done}/{len(to_download)}) {result}")

    print("[DONE] Download complete. Results saved in 'new' subfolder.")


if __name__ == "__main__":
    main()
