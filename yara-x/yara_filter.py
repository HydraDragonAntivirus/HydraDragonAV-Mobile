#!/usr/bin/env python3
import argparse
import os
import re

DEFAULT_EXCLUDE_TERMS = {"win", "windows", "osx", "macho", "peid", "java", "mz", "pe",
                         "powershell", "susp", "suspicious"}

# Terms matched ONLY against the first underscore-segment of the rule name.
# Use for short/ambiguous terms that would cause false positives elsewhere.
DEFAULT_PREFIX_ONLY_TERMS = {"ttp", "cape", "devcpp"}

# Excluded terms allowed to match via startswith() even though they are shorter
# than the 5-char startswith guard. "susp" intentionally catches the whole
# suspicious-family (suspicious, and misspellings like suspicous/suspicoius).
PREFIX_MATCH_TERMS = {"susp"}

# Rule names CONTAINING any of these (case-insensitive, anywhere — start,
# middle or end) are dropped outright. Used for compiler/platform substrings
# that tokenisation does not otherwise catch, e.g. win32 / win64 (token
# "win32"/"win64", not "win") and borland_delphi (Windows-only Delphi binaries).
DEFAULT_EXCLUDE_NAME_SUBSTRINGS = {"borland_delphi", "win32", "win64", "windows", "exe"}

# Exact metadata values that cause a rule to be dropped, matched
# case-insensitively against the WHOLE meta value (not tokenised). Used for
# multi-word category tags whose individual words are otherwise harmless,
# e.g.  rule_category = "greyware_tool_keyword"  (greyware = legitimate tools
# that trip false positives on Android).
DEFAULT_EXCLUDE_META_VALUES = {"greyware_tool_keyword"}

# YARA modules whose usage makes a rule non-Android-compatible.
# hash / math / time / console are portable — not listed here.
# elf is included because native .so Android rules rarely use pe/macho/dotnet
# and elf-targeting rules are usually Linux-desktop focused; remove if needed.
NON_ANDROID_MODULES = {"pe", "macho", "dotnet"}

# Splits camelCase and acronyms:
#   OSXDropper    -> ['OSX', 'Dropper']  -> {'osx', 'dropper'}
#   WindowsShell  -> ['Windows', 'Shell'] -> {'windows', 'shell'}
#   WinExec       -> ['Win', 'Exec']     -> {'win', 'exec'}
_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+|[0-9]+")

# Matches:  import "pe"  /  import "macho"  etc.
_IMPORT_RE = re.compile(r'^\s*import\s+"(\w+)"')

# Matches module namespace usage in rule body: pe.  macho.  dotnet.  elf.
# Only triggers on word-boundary so "people." doesn't match "pe."
_MODULE_USAGE_RE = re.compile(r'\b(\w+)\.')

# Any identifier token (used to find rule references inside a condition).
_IDENT_RE = re.compile(r'[A-Za-z_]\w*')


def tokenise(text):
    """
    Lowercase tokens from text via camelCase + underscore splitting.
    Each underscore-part contributes both its camelCase sub-tokens AND
    its raw lowercased form, so 'PowerShell' yields both 'power'+'shell'
    and 'powershell'.
    Returns (tokens_set, raw_parts_list).
    """
    tokens = set()
    raw_parts = []
    for part in text.split("_"):
        if not part:
            continue
        for t in _CAMEL_RE.findall(part):
            tokens.add(t.lower())
        tokens.add(part.lower())
        raw_parts.append(part.lower())
    return tokens, raw_parts


def matches_exclude(tokens, raw_parts, exclude_terms):
    """
    Return True if any token exactly matches an excluded term, OR if any
    raw underscore-part starts with a long excluded term (>=5 chars).
    The length guard keeps short terms like 'pe'/'mz'/'win' from firing
    on unrelated prefixes via startswith.
    """
    if tokens & exclude_terms:
        return True
    for part in raw_parts:
        for term in exclude_terms:
            if part.startswith(term) and (len(term) >= 5 or term in PREFIX_MATCH_TERMS):
                return True
    return False


def imported_modules(lines):
    """
    Return the set of module names imported in the given lines.
    Handles both file-level prelude imports and any import lines
    inside individual rule blocks.
    """
    modules = set()
    for line in lines:
        m = _IMPORT_RE.match(line)
        if m:
            modules.add(m.group(1).lower())
    return modules


def uses_non_android_module(block, non_android_modules):
    """
    Return True if the rule block references any non-Android-compatible
    module via its namespace (e.g. pe.entry_point, macho.headers).

    Also catches import statements embedded inside the block itself.
    """
    for line in block:
        # embedded import inside block
        m = _IMPORT_RE.match(line)
        if m and m.group(1).lower() in non_android_modules:
            return True
        # namespace usage: pe.xxx  macho.xxx  dotnet.xxx  elf.xxx
        for mod in _MODULE_USAGE_RE.findall(line):
            if mod.lower() in non_android_modules:
                return True
    return False


def extract_comments(lines):
    """
    Return all comment text from the given lines as a single string,
    covering both ``// line comments`` and ``/* block comments */``.

    A small scanner tracks string-literal and block-comment state so that
    a ``//`` or ``/*`` appearing inside a quoted string (e.g. a URL like
    "http://...") is NOT mistaken for a comment.
    """
    out = []
    in_block = False
    for line in lines:
        i, n = 0, len(line)
        while i < n:
            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    out.append(line[i:])
                    i = n
                else:
                    out.append(line[i:end])
                    i, in_block = end + 2, False
                continue
            ch = line[i]
            if ch == '"':
                i += 1
                while i < n:
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if ch == "/" and i + 1 < n and line[i + 1] == "/":
                out.append(line[i + 2:])
                i = n
                continue
            if ch == "/" and i + 1 < n and line[i + 1] == "*":
                in_block = True
                i += 2
                continue
            i += 1
    return " ".join(out)


def extract_rule_name(header):
    """Return the rule identifier from a rule header line."""
    h = header.lstrip()
    rest = h[13:] if h.startswith("private rule ") else h[5:]
    name_chars = []
    for ch in rest.strip():
        if ch.isalnum() or ch == "_":
            name_chars.append(ch)
        else:
            break
    return "".join(name_chars)


def body_identifiers(block):
    """
    Return the set of bare identifiers appearing anywhere in the rule body
    (meta, strings, condition and comments) — excluding the rule's own name.

    A condition can reference other rules by name, but a removed rule may also
    be referenced indirectly elsewhere in the body; any rule that mentions a
    removed rule's name is treated as related and dropped too.
    """
    ids = set()
    for line in block[1:]:
        ids.update(_IDENT_RE.findall(line))
    ids.discard(extract_rule_name(block[0]))
    return ids


def should_keep(block, exclude_terms, prefix_only_terms, non_android_modules,
                exclude_meta_values=frozenset(), exclude_name_substrings=frozenset()):
    """
    Return False if any of these signals fires:

      0. Raw content strings — case-insensitive full-block scan for: "macos",
                               "microsoft". Catches these substrings anywhere in
                               the rule (strings, comments, meta, etc.).
      1. Rule name tokens    — camelCase + underscore split
         prefix_only_terms checked against first underscore-segment only
      2. Rule tags           — space-separated after colon on header line
      3. Metadata values     — strings inside the meta: section, plus exact
                               whole-value matches against exclude_meta_values
      4. Module usage        — pe. / macho. / dotnet. / elf. in rule body,
                               or import "pe" / import "macho" inside the block
      5. Comments            — excluded term in a // or /* */ comment, e.g.
                               a "//Windows" note above the rule body
      6. String contents     — name substring (win32/win64/...) appearing
                               anywhere in the strings: section
    """
    block_text = "".join(block).lower()
    # Raw full-block substring checks (catch strings in literals, comments, meta)
    for _raw_term in ("macos", "microsoft", ".exe", ".dll", ".sys"):
        if _raw_term in block_text:
            return False

    header = block[0].lstrip()

    # ── 1. Rule name ────────────────────────────────────────────────────────
    name = extract_rule_name(header)

    name_lower = name.lower()
    for sub in exclude_name_substrings:
        if sub in name_lower:
            return False

    name_tokens, name_parts = tokenise(name)
    if matches_exclude(name_tokens, name_parts, exclude_terms):
        return False

    first_segment = name.split("_")[0].lower() if name else ""
    if first_segment in prefix_only_terms:
        return False

    # ── 2. Tags (rule Foo : tag1 tag2 {) ────────────────────────────────────
    tag_match = re.search(r":\s*([^{]+)\{", header)
    if tag_match:
        for tag in tag_match.group(1).strip().split():
            tag_tokens, tag_parts = tokenise(tag)
            if matches_exclude(tag_tokens, tag_parts, exclude_terms):
                return False

    # ── 3. Metadata values ───────────────────────────────────────────────────
    in_meta = False
    for line in block[1:]:
        stripped = line.strip()
        if stripped in ("meta:", "strings:", "condition:"):
            in_meta = stripped == "meta:"
            continue
        if not in_meta:
            continue
        m = re.match(r'\w+\s*=\s*"?([^"]+)"?', stripped)
        if not m:
            continue
        value = m.group(1).strip()
        if value.lower() in exclude_meta_values:
            return False
        for word in re.split(r'[\s,;/\\|]+', value):
            word_tokens, word_parts = tokenise(word)
            if matches_exclude(word_tokens, word_parts, exclude_terms):
                return False

    # ── 4. Non-Android module usage ──────────────────────────────────────────
    if uses_non_android_module(block, non_android_modules):
        return False

    # ── 5. Comments (// ...  and  /* ... */) ─────────────────────────────────
    for word in re.split(r'[\s,;/\\|]+', extract_comments(block)):
        if not word:
            continue
        word_tokens, word_parts = tokenise(word)
        if matches_exclude(word_tokens, word_parts, exclude_terms):
            return False

    # ── 6. String contents (name substrings, e.g. win32 / win64) ─────────────
    if exclude_name_substrings:
        in_strings = False
        for line in block[1:]:
            stripped = line.strip()
            if stripped in ("meta:", "strings:", "condition:"):
                in_strings = stripped == "strings:"
                continue
            if not in_strings:
                continue
            low = line.lower()
            if any(sub in low for sub in exclude_name_substrings):
                return False

    return True


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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Filter YARA rules for Android compatibility.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Default excluded terms: {sorted(DEFAULT_EXCLUDE_TERMS)}
Default non-Android modules: {sorted(NON_ANDROID_MODULES)}

Seven signals are checked per rule — if any matches, the rule is dropped:
  1. Rule name          (camelCase/underscore tokens, e.g. OSXDropper -> osx;
                         plus name substrings anywhere, e.g. win32 / win64 /
                         borland_delphi)
  2. Rule tags          (e.g.  rule Foo : windows macho {{ ... }})
  3. Metadata values    (e.g.  os = "windows",  rule_category = "greyware_tool_keyword")
  4. Module usage       (e.g.  pe.entry_point,  macho.headers,  import "dotnet")
  5. Comments           (e.g.  //Windows  or  /* PE loader */ above the body)
  6. String contents    (name substrings win32/win64/... in the strings: section)
  7. Rule references    (body mentions any rule dropped by 1-6; cascades)

Portable modules (hash, math, time, console) are NOT filtered.

Examples:
  # Use defaults
  %(prog)s

  # Add extra name/tag/meta exclusion terms
  %(prog)s --exclude linux --exclude delphi

  # Keep elf rules (e.g. if you target Android native libs)
  %(prog)s --keep-module elf

  # Drop additional modules
  %(prog)s --drop-module hash

  # Custom src/dst
  %(prog)s --src /tmp/rules.yar --dst /tmp/out.yar
""",
    )
    parser.add_argument(
        "--src",
        default=None,
        help="Source .yar file (default: clean_rules.yar next to this script)",
    )
    parser.add_argument(
        "--dst",
        default=None,
        help="Destination file (default: <src>_filtered.yar)",
    )

    def min5_term(value):
        if len(value) < 5:
            raise argparse.ArgumentTypeError(
                f"{value!r} is too short ({len(value)} chars); "
                "minimum 5 characters required to avoid false positives."
            )
        return value

    parser.add_argument(
        "--exclude",
        metavar="TERM",
        type=min5_term,
        action="append",
        default=[],
        help=(
            "Add a term to the name/tag/metadata exclusion list (repeatable). "
            "Minimum 5 characters. "
            "Added on top of defaults unless --reset-defaults is given."
        ),
    )
    parser.add_argument(
        "--reset-defaults",
        action="store_true",
        help="Start from an empty exclusion list instead of the built-in defaults.",
    )
    parser.add_argument(
        "--exclude-meta-value",
        metavar="VALUE",
        action="append",
        default=[],
        help=(
            "Drop a rule when any meta value equals VALUE exactly "
            "(case-insensitive, repeatable). Added on top of defaults unless "
            "--reset-defaults is given. Default: "
            f"{sorted(DEFAULT_EXCLUDE_META_VALUES)}"
        ),
    )
    parser.add_argument(
        "--exclude-name-substring",
        metavar="SUB",
        action="append",
        default=[],
        help=(
            "Drop a rule when its name contains SUB anywhere (start, middle or "
            "end; case-insensitive, repeatable). Added on top of defaults "
            "unless --reset-defaults is given. Default: "
            f"{sorted(DEFAULT_EXCLUDE_NAME_SUBSTRINGS)}"
        ),
    )
    parser.add_argument(
        "--drop-module",
        metavar="MODULE",
        action="append",
        default=[],
        help="Add a module to the non-Android list (repeatable, e.g. --drop-module hash).",
    )
    parser.add_argument(
        "--keep-module",
        metavar="MODULE",
        action="append",
        default=[],
        help="Remove a module from the non-Android list (repeatable, e.g. --keep-module elf).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    src = args.src or os.path.join(script_dir, "clean_rules.yar")
    src_base, src_ext = os.path.splitext(src)
    dst = args.dst or f"{src_base}_filtered{src_ext}"

    if os.path.basename(src).startswith("AndroidOS"):
        print(f"Skipping '{src}': AndroidOS files are excluded from filtering.")
        return


    exclude_terms = set() if args.reset_defaults else set(DEFAULT_EXCLUDE_TERMS)
    prefix_only_terms = set() if args.reset_defaults else set(DEFAULT_PREFIX_ONLY_TERMS)
    for t in args.exclude:
        exclude_terms.add(t.lower())

    exclude_meta_values = (
        set() if args.reset_defaults else set(DEFAULT_EXCLUDE_META_VALUES)
    )
    for v in args.exclude_meta_value:
        exclude_meta_values.add(v.lower())

    exclude_name_substrings = (
        set() if args.reset_defaults else set(DEFAULT_EXCLUDE_NAME_SUBSTRINGS)
    )
    for p in args.exclude_name_substring:
        exclude_name_substrings.add(p.lower())

    non_android_modules = set(NON_ANDROID_MODULES)
    for m in args.drop_module:
        non_android_modules.add(m.lower())
    for m in args.keep_module:
        non_android_modules.discard(m.lower())

    print(f"Excluded terms:       {sorted(exclude_terms)}")
    print(f"Non-Android modules:  {sorted(non_android_modules)}")
    print(f"Excluded meta values: {sorted(exclude_meta_values)}")
    print(f"Excluded name subs:   {sorted(exclude_name_substrings)}")
    print(f"Reading {src}...")

    with open(src, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    prelude, blocks = split_blocks(lines)

    # Warn if the prelude itself imports non-Android modules — the filtered
    # output will still contain those import lines, which YARA will complain
    # about if no remaining rule uses that module. Informational only.
    prelude_imports = imported_modules(prelude)
    bad_prelude = prelude_imports & non_android_modules
    if bad_prelude:
        print(f"Note: prelude imports non-Android modules {sorted(bad_prelude)} — "
              "these import lines are kept as-is in the output.")

    total = len(blocks)
    names = [extract_rule_name(b[0]) for b in blocks]

    # Pass 1: direct signals (name, tags, meta, modules, comments).
    keep = [
        should_keep(b, exclude_terms, prefix_only_terms, non_android_modules,
                    exclude_meta_values, exclude_name_substrings)
        for b in blocks
    ]
    direct_removed = keep.count(False)

    # Pass 2: drop every rule related to a removed rule — i.e. any rule whose
    # body references a removed rule's name (condition, strings, meta or
    # comments). Cascades to a fixpoint: if C references B and B was dropped
    # for referencing excluded A, then C is dropped too.
    dropped_names = {names[i] for i in range(total) if not keep[i] and names[i]}
    changed = True
    while changed:
        changed = False
        for i, b in enumerate(blocks):
            if not keep[i]:
                continue
            if body_identifiers(b) & dropped_names:
                keep[i] = False
                if names[i]:
                    dropped_names.add(names[i])
                changed = True

    kept_blocks = [b for i, b in enumerate(blocks) if keep[i]]
    kept = len(kept_blocks)
    ref_removed = (total - kept) - direct_removed

    print(f"Total rules: {total}, Kept: {kept}, Removed: {total - kept} "
          f"({direct_removed} direct, {ref_removed} related via rule references)")

    with open(dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in kept_blocks:
            f.writelines(b)

    print(f"Written to {dst}")


if __name__ == "__main__":
    main()
