"""Build the known-good NSRL Android package whitelist as a SQLite database
(replaces the old flat whitelist_packages.txt).

For every package_id whose whole-APK METADATA row exists (extension='apk',
same selection rule as gen_whitelist_apk.py), joins in the associated
APPLICATION / MANUFACTURER / OPERATING_SYSTEM rows so the on-device DB carries
full provenance, not just a bare name.

`key` is METADATA.file_name verbatim (already an "id^^name" string in the
NSRL data itself) — the exact value the old txt whitelist held one per line.
On-device matching logic is unchanged, only the storage format and available
detail changed.

Output: app/src/main/assets/scan/whitelist_packages.db (under assets/scan/ so
NativeScanner.init() copies it alongside the .yrc/model files into the same
on-device directory the Rust engine reads at nativeInit — the same DB is then
usable from both Java and Rust).

Also applies every sql/RDS_*_android_delta.sql newer than the base DB (not
just one hardcoded month) so a package only present in a later delta isn't
dropped.

Usage:
    python gen_whitelist_packages.py [path/to/RDS.db]
"""

import os
import sys
from pathlib import Path

import nsrl_sql

OUT = Path("app/src/main/assets/scan/whitelist_packages.db")


def main():
    os.chdir(Path(__file__).parent)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.unlink(missing_ok=True)

    DB = sys.argv[1] if len(sys.argv) > 1 else nsrl_sql.find_main_db()
    src = nsrl_sql.open_with_deltas(DB)

    apk_by_object = {}
    for row in src.execute(
        "SELECT object_id, file_name, extension, bytes, md5, sha1, sha256, crc32 "
        "FROM METADATA WHERE lower(extension)='apk'"
    ):
        apk_by_object[row[0]] = row[1:]

    app_by_package = {}
    for app_id, package_id, name, version, poe, build in src.execute(
        "SELECT application_id, package_id, name, version, poe, build FROM APPLICATION"
    ):
        app_by_package.setdefault(package_id, (app_id, name, version, poe, build))

    manufacturer_by_app = {}
    for app_id, mf_name, mf_country in src.execute(
        "SELECT ma.application_id, mf.name, mf.country "
        "FROM MANUFACTURER_APPLICATION ma JOIN MANUFACTURER mf "
        "ON mf.manufacturer_id = ma.manufacturer_id"
    ):
        manufacturer_by_app.setdefault(app_id, (mf_name, mf_country))

    os_by_app = {}
    for app_id, os_name, os_version in src.execute(
        "SELECT oa.application_id, os.name, os.version "
        "FROM OPERATING_SYSTEM_APPLICATION oa JOIN OPERATING_SYSTEM os "
        "ON os.operating_system_id = oa.operating_system_id"
    ):
        os_by_app.setdefault(app_id, (os_name, os_version))

    out = sqlite3.connect(OUT)
    out.execute(
        """
        CREATE TABLE whitelist_package (
            package_id INTEGER,
            key TEXT PRIMARY KEY,
            file_name TEXT,
            extension TEXT,
            bytes INTEGER,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            crc32 TEXT,
            app_name TEXT,
            app_version TEXT,
            app_poe TEXT,
            app_build TEXT,
            manufacturer_name TEXT,
            manufacturer_country TEXT,
            os_name TEXT,
            os_version TEXT
        )
        """
    )

    n = 0
    for package_id, object_id in src.execute("SELECT package_id, object_id FROM PACKAGE_OBJECT"):
        apk = apk_by_object.get(object_id)
        if apk is None:
            continue
        file_name, extension, bytes_, md5, sha1, sha256, crc32 = apk

        app = app_by_package.get(package_id)
        app_id, app_name, app_version, app_poe, app_build = app if app else (None,) * 5

        manufacturer_name, manufacturer_country = manufacturer_by_app.get(app_id, (None, None))
        os_name, os_version = os_by_app.get(app_id, (None, None))

        key = file_name
        out.execute(
            "INSERT OR IGNORE INTO whitelist_package VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                package_id, key, file_name, extension, bytes_, md5, sha1, sha256, crc32,
                app_name, app_version, app_poe, app_build,
                manufacturer_name, manufacturer_country, os_name, os_version,
            ),
        )
        n += 1

    out.execute("CREATE INDEX idx_whitelist_package_md5 ON whitelist_package(md5)")
    out.commit()
    out.close()
    src.close()
    print(f"{OUT}: {n:,} rows, {os.path.getsize(OUT):,} bytes")


if __name__ == "__main__":
    main()
