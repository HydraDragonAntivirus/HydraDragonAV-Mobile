"""Bump the app version everywhere it's duplicated in the repo.

Updates in one pass:
  - app/build.gradle              (versionCode +1, versionName "X.Y.Z")
  - app/src/main/res/values*/strings.xml   (app_title "...vX.Y.Z", all 20 languages)
  - SettingsFragment.java's About screen text ("HydraDragon Antivirus vX.Y.Z")

Usage:
    python bump_version.py patch          # 1.0.1 -> 1.0.2 (default if no arg)
    python bump_version.py minor          # 1.0.1 -> 1.1.0
    python bump_version.py major          # 1.0.1 -> 2.0.0
    python bump_version.py 1.5.0          # set an explicit version
    python bump_version.py                # interactive prompt (asks patch/minor/major/explicit)
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD_GRADLE = os.path.join(ROOT, "app", "build.gradle")
SETTINGS_FRAGMENT = os.path.join(
    ROOT, "app", "src", "main", "java", "com", "hydradragon", "antivirus", "ui", "SettingsFragment.java"
)
STRINGS_GLOB = os.path.join(ROOT, "app", "src", "main", "res", "values*", "strings.xml")


def read_current_version():
    with open(BUILD_GRADLE, encoding="utf-8") as f:
        content = f.read()
    code_m = re.search(r'versionCode\s+(\d+)', content)
    name_m = re.search(r'versionName\s+"([\d.]+)"', content)
    if not code_m or not name_m:
        raise SystemExit("Could not find versionCode/versionName in app/build.gradle")
    return int(code_m.group(1)), name_m.group(1), content


def bump(version_str, kind):
    major, minor, patch = (int(x) for x in version_str.split("."))
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        return f"{major}.{minor + 1}.0"
    if kind == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(kind)


def resolve_new_version(current_version, arg):
    if arg is None:
        arg = input(
            f"Current version: {current_version}\n"
            "Enter bump type (patch/minor/major) or an explicit version (e.g. 1.5.0): "
        ).strip()
    if re.fullmatch(r"\d+\.\d+\.\d+", arg):
        return arg
    if arg in ("patch", "minor", "major"):
        return bump(current_version, arg)
    raise SystemExit(f"Unrecognized argument '{arg}' — expected patch/minor/major or X.Y.Z")


def update_build_gradle(content, old_code, new_version):
    new_code = old_code + 1
    content = re.sub(r'versionCode\s+\d+', f'versionCode {new_code}', content, count=1)
    content = re.sub(r'versionName\s+"[\d.]+"', f'versionName "{new_version}"', content, count=1)
    with open(BUILD_GRADLE, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    return new_code


def update_strings_xml(old_version, new_version):
    updated = []
    for path in glob.glob(STRINGS_GLOB):
        with open(path, encoding="utf-8") as f:
            content = f.read()
        new_content = re.sub(
            r'(<string name="app_title">[^<]*?)v' + re.escape(old_version) + r'(</string>)',
            r'\1v' + new_version + r'\2',
            content,
        )
        if new_content != content:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(new_content)
            updated.append(path)
    return updated


def update_settings_fragment(old_version, new_version):
    if not os.path.exists(SETTINGS_FRAGMENT):
        return False
    with open(SETTINGS_FRAGMENT, encoding="utf-8") as f:
        content = f.read()
    new_content = content.replace(
        f"HydraDragon Antivirus v{old_version}", f"HydraDragon Antivirus v{new_version}"
    )
    if new_content != content:
        with open(SETTINGS_FRAGMENT, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_content)
        return True
    return False


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    old_code, old_version, gradle_content = read_current_version()
    new_version = resolve_new_version(old_version, arg)

    new_code = update_build_gradle(gradle_content, old_code, new_version)
    changed_strings = update_strings_xml(old_version, new_version)
    changed_settings = update_settings_fragment(old_version, new_version)

    print(f"{old_version} (code {old_code})  ->  {new_version} (code {new_code})")
    print(f"app/build.gradle: updated")
    print(f"strings.xml: updated {len(changed_strings)} language file(s)")
    print(f"SettingsFragment.java: {'updated' if changed_settings else 'no match found — check manually'}")


if __name__ == "__main__":
    main()
