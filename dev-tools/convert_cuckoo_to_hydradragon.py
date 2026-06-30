#!/usr/bin/env python3
"""Convert YARA rules that use the `cuckoo` module to the Android-native
`hydradragon` module.

`hydradragon` exposes the exact same API as `cuckoo`
(network.{dns_lookup,http_request,http_get,http_post,http_user_agent,host,tcp,
udp}, registry.key_access, filesystem.file_access, sync.mutex) plus the extra
`hydradragon.url(...)`, so converting is a straight rename:

    import "cuckoo"   ->  import "hydradragon"
    cuckoo.<...>      ->  hydradragon.<...>

Usage:
    python convert_cuckoo_to_hydradragon.py <file_or_dir> [more...]
    python convert_cuckoo_to_hydradragon.py --check <path>   # report only, no write

Only whole-token `cuckoo` identifiers are replaced (so the word "cuckoo" inside
a string literal or comment author name is left alone — we only touch
`import "cuckoo"` and `cuckoo.` member accesses).
"""

import re
import sys
from pathlib import Path

IMPORT_RE = re.compile(r'(\bimport\s+)"cuckoo"')
MEMBER_RE = re.compile(r'\bcuckoo\.')


def convert_text(text: str) -> tuple[str, int]:
    n = 0
    text, c1 = IMPORT_RE.subn(r'\1"hydradragon"', text)
    text, c2 = MEMBER_RE.subn("hydradragon.", text)
    return text, c1 + c2


def iter_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from p.rglob("*.yar")
            yield from p.rglob("*.yara")
        elif p.is_file():
            yield p


def main(argv):
    check_only = "--check" in argv
    targets = [a for a in argv[1:] if not a.startswith("--")]
    if not targets:
        print(__doc__)
        return 1

    total_files = 0
    changed_files = 0
    for f in iter_files(targets):
        try:
            original = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"  [SKIP] {f}: {e}")
            continue
        total_files += 1
        converted, n = convert_text(original)
        if n == 0:
            continue
        changed_files += 1
        if check_only:
            print(f"  [WOULD CONVERT] {f}: {n} occurrence(s)")
        else:
            f.write_text(converted, encoding="utf-8")
            print(f"  [CONVERTED] {f}: {n} occurrence(s)")

    verb = "would change" if check_only else "changed"
    print(f"\n{changed_files}/{total_files} files {verb}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
