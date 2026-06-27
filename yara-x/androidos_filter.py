#!/usr/bin/env python3
"""
AndroidOS.yar filter.

AndroidOS.yar is already Android-specific, so it is NOT run through the general
yara_filter.py platform filtering. The ONLY thing dropped here is low-quality
rules — those whose metadata declares:

    strings_accuracy = "Low"

Everything else is kept verbatim.

Usage:
    python androidos_filter.py
    python androidos_filter.py --src AndroidOS.yar --dst AndroidOS_filtered.yar
"""

import argparse
import os
import re

# Matches a meta line:  strings_accuracy = "Low"   (case-insensitive value,
# quotes optional). Only this exact key/value pair triggers removal.
_LOW_ACCURACY_RE = re.compile(
    r'^\s*strings_accuracy\s*=\s*"?\s*low\s*"?\s*$', re.IGNORECASE
)


def split_blocks(lines):
    """Split a .yar file into (prelude, [rule_block, ...])."""
    prelude, blocks, current = [], [], None
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("rule ") or stripped.startswith("private rule "):
            if current is not None:
                blocks.append(current)
            current = [line]
            continue
        if current is None:
            prelude.append(line)
        else:
            current.append(line)
    if current is not None:
        blocks.append(current)
    return prelude, blocks


def is_low_accuracy(block):
    """Return True if the rule's meta has strings_accuracy = "Low"."""
    return any(_LOW_ACCURACY_RE.match(line) for line in block)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Drop only strings_accuracy = "Low" rules from AndroidOS.yar.'
    )
    parser.add_argument(
        "--src",
        default=None,
        help="Source .yar file (default: AndroidOS.yar next to this script)",
    )
    parser.add_argument(
        "--dst",
        default=None,
        help="Destination file (default: <src>_filtered.yar)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    src = args.src or os.path.join(script_dir, "AndroidOS.yar")
    src_base, src_ext = os.path.splitext(src)
    dst = args.dst or f"{src_base}_filtered{src_ext}"

    print(f"Reading {src}...")
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    prelude, blocks = split_blocks(lines)
    total = len(blocks)

    kept_blocks = [b for b in blocks if not is_low_accuracy(b)]
    kept = len(kept_blocks)

    print(f'Total rules: {total}, Kept: {kept}, '
          f'Removed: {total - kept} (strings_accuracy = "Low")')

    with open(dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in kept_blocks:
            f.writelines(b)

    print(f"Written to {dst}")


if __name__ == "__main__":
    main()
