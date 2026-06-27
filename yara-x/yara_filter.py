#!/usr/bin/env python3
import os
import sys

EXCLUDE_PREFIXES = {"win", "osx", "macho", "peid", "java"}


def prefix(name):
    """Return first underscore-delimited segment (lowercase)."""
    return name.split("_", 1)[0].lower()


def should_keep(name):
    return prefix(name) not in EXCLUDE_PREFIXES


def split_blocks(lines):
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


def rule_name(block):
    head = block[0].lstrip()
    rest = head[13:] if head.startswith("private rule ") else head[5:]
    name = []
    for ch in rest.strip():
        if ch.isalnum() or ch == "_":
            name.append(ch)
        else:
            break
    return "".join(name)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(script_dir, "clean_rules.yar")
    dst = os.path.join(script_dir, "clean_rules_filtered.yar")

    print(f"Reading {src}...")
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    total = 0
    kept_blocks = []
    prelude, blocks = split_blocks(lines)
    total = len(blocks)

    for b in blocks:
        name = rule_name(b)
        if should_keep(name):
            kept_blocks.append(b)

    kept = len(kept_blocks)
    print(f"Total rules: {total}, Kept: {kept}, Removed: {total - kept}")

    with open(dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in kept_blocks:
            f.writelines(b)

    print(f"Written to {dst}")


if __name__ == "__main__":
    main()
