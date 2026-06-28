#!/usr/bin/env python3
import argparse
import os
import re

DEFAULT_EXCLUDE_TERMS = {"win", "windows", "osx", "macho", "peid", "java", "mz", "pe",
                         "powershell", "susp", "suspicious", "lnk", "packer", "nsis"}

# Terms matched ONLY against the first underscore-segment of the rule name.
# Use for short/ambiguous terms that would cause false positives elsewhere.
DEFAULT_PREFIX_ONLY_TERMS = {"ttp", "cape", "devcpp", "pptx"}

# Terms matched as an exact TOKEN in the rule NAME only (any camelCase or
# underscore segment), never in tags/meta/strings/comments. Use for short words
# that are meaningful in a rule name but common elsewhere, e.g. "net" (=dotnet)
# which should drop korna_net_korna / MyNetThing but not match "internet" in a
# comment or the word "net" in a string.
DEFAULT_NAME_ONLY_TERMS = {"net"}

# Excluded terms allowed to match via startswith() even though they are shorter
# than the 5-char startswith guard. "susp" intentionally catches the whole
# suspicious-family (suspicious, and misspellings like suspicous/suspicoius).
PREFIX_MATCH_TERMS = {"susp"}

# Rule names CONTAINING any of these (case-insensitive, anywhere — start,
# middle or end) are dropped outright. Used for compiler/platform substrings
# that tokenisation does not otherwise catch, e.g. win32 / win64 (token
# "win32"/"win64", not "win") and borland_delphi (Windows-only Delphi binaries).
DEFAULT_EXCLUDE_NAME_SUBSTRINGS = {"borland_delphi", "win32", "win64", "windows", "exe", "anti_debug"}

# Exact metadata values that cause a rule to be dropped, matched
# case-insensitively against the WHOLE meta value (not tokenised). Used for
# multi-word category tags whose individual words are otherwise harmless,
# e.g.  rule_category = "greyware_tool_keyword"  (greyware = legitimate tools
# that trip false positives on Android).
DEFAULT_EXCLUDE_META_VALUES = {"greyware_tool_keyword"}

# Terms that mark a KEPT rule as Android/Linux-related and therefore "verified"
# for the mobile target. Matched case-insensitively as whole words anywhere in
# the rule block (name, tags, meta, strings, condition, comments). Mirai is the
# canonical Linux/IoT/Android botnet family; Valhalla is the Nextron rule feed
# whose Linux/Android coverage we trust. Rules hitting any of these go to
# clean_rules_filtered_verified.yar; everything else kept goes to
# clean_rules_filtered_unverified.yar.
DEFAULT_VERIFY_TERMS = {"android", "linux", "mirai", "valhalla"}

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

# PE/DOS "MZ" magic-header check, e.g.  uint16(0) == 0x5A4D  (a Windows-PE
# indicator). Whitespace-insensitive (\s* matches newlines) so it still fires
# when the expression is split across multiple lines, and order-agnostic so
# 0x5A4D == uint16(0) is caught too. Matched against the lowercased block.
_MZ_MAGIC_RE = re.compile(
    r'uint16\s*\(\s*0\s*\)\s*==\s*0x5a4d|0x5a4d\s*==\s*uint16\s*\(\s*0\s*\)'
)

# ELF "\x7fELF" magic-header check via uint16(0), e.g. uint16(0) == 0x457f
# (little-endian read of the first two header bytes 0x7f 0x45). Order-agnostic
# and whitespace-insensitive. A hit marks the rule as native/Linux-related and
# therefore "verified" for the Android/Linux target. Matched on lowercased text.
_ELF_MAGIC_RE = re.compile(
    r'uint16\s*\(\s*0\s*\)\s*==\s*0x457f|0x457f\s*==\s*uint16\s*\(\s*0\s*\)'
)


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


def is_private_rule(header):
    """Return True if the rule header declares a private rule."""
    return header.lstrip().startswith("private rule ")


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
                exclude_meta_values=frozenset(), exclude_name_substrings=frozenset(),
                name_only_terms=frozenset()):
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
    for _raw_term in ("macos", "microsoft", ".exe", ".dll", ".sys", "hash.md5(0,", "c# ", "autoit", "mach-o", "mimikatz", "nullsoft", "c:\\", "c:/"):
        if _raw_term in block_text:
            return False

    # PE/DOS "MZ" magic header check (uint16(0) == 0x5A4D), even if split
    # across multiple lines or written in reverse order.
    if _MZ_MAGIC_RE.search(block_text):
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

    # Name-only token terms (e.g. "net" = dotnet): match any name segment but
    # never tags/meta/strings/comments.
    if name_tokens & name_only_terms:
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


def is_android_related(block, verify_terms):
    """
    Return True if the rule block contains any verify term (android / linux /
    mirai / valhalla, ...) as a substring anywhere in the block, case-
    insensitively. A bare substring match (not whole-word) is intentional: any
    rule mentioning these terms in any part — name, tags, meta, strings,
    condition or comments — is treated as Android/Linux-verified.
    """
    text = "".join(block).lower()
    if verify_terms and any(term in text for term in verify_terms):
        return True
    # ELF native/Linux signals: elf module usage (elf. namespace or import "elf")
    # and the ELF uint16 magic header pattern.
    if _ELF_MAGIC_RE.search(text):
        return True
    if uses_non_android_module(block, {"elf"}):
        return True
    return False


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
        "--verify-term",
        metavar="TERM",
        action="append",
        default=[],
        help=(
            "Add a whole-word term that marks a kept rule as Android/Linux-"
            "verified (repeatable, case-insensitive). Verified rules are written "
            "to <dst>_verified.yar, the rest to <dst>_unverified.yar. Added on "
            f"top of defaults unless --reset-defaults is given. Default: "
            f"{sorted(DEFAULT_VERIFY_TERMS)}"
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
    name_only_terms = set() if args.reset_defaults else set(DEFAULT_NAME_ONLY_TERMS)
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

    verify_terms = set() if args.reset_defaults else set(DEFAULT_VERIFY_TERMS)
    for t in args.verify_term:
        verify_terms.add(t.lower())

    non_android_modules = set(NON_ANDROID_MODULES)
    for m in args.drop_module:
        non_android_modules.add(m.lower())
    for m in args.keep_module:
        non_android_modules.discard(m.lower())

    print(f"Excluded terms:       {sorted(exclude_terms)}")
    print(f"Non-Android modules:  {sorted(non_android_modules)}")
    print(f"Excluded meta values: {sorted(exclude_meta_values)}")
    print(f"Excluded name subs:   {sorted(exclude_name_substrings)}")
    print(f"Name-only terms:      {sorted(name_only_terms)}")
    print(f"Verify terms:         {sorted(verify_terms)}")
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
                    exclude_meta_values, exclude_name_substrings, name_only_terms)
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

    removed_after_refs = total - keep.count(True)
    ref_removed = removed_after_refs - direct_removed

    # Pass 3: drop unused private rules — a private rule only exists to be
    # referenced by other rules, so if no kept rule references it, it is dead
    # code. Cascades to a fixpoint: removing one private rule can leave another
    # private rule (that only the first referenced) unused in turn.
    private_removed = 0
    changed = True
    while changed:
        changed = False
        # Names referenced by any currently-kept rule.
        referenced = set()
        for i, b in enumerate(blocks):
            if keep[i]:
                referenced |= body_identifiers(b)
        for i, b in enumerate(blocks):
            if keep[i] and is_private_rule(b[0]) and names[i] not in referenced:
                keep[i] = False
                private_removed += 1
                changed = True

    kept_blocks = [b for i, b in enumerate(blocks) if keep[i]]
    kept = len(kept_blocks)

    print(f"Total rules: {total}, Kept: {kept}, Removed: {total - kept} "
          f"({direct_removed} direct, {ref_removed} related via rule references, "
          f"{private_removed} unused private)")

    # Split kept rules: Android/Linux/Mirai/Valhalla-related -> verified,
    # everything else kept -> unverified. A verified rule's private dependencies
    # must travel with it, so private rules referenced (transitively) by any
    # verified rule are forced into the verified bucket too.
    verified_flags = [is_android_related(b, verify_terms) for b in kept_blocks]
    kept_names = [extract_rule_name(b[0]) for b in kept_blocks]

    changed = True
    while changed:
        changed = False
        verified_refs = set()
        for i, b in enumerate(kept_blocks):
            if verified_flags[i]:
                verified_refs |= body_identifiers(b)
        for i, b in enumerate(kept_blocks):
            if (not verified_flags[i] and is_private_rule(b[0])
                    and kept_names[i] in verified_refs):
                verified_flags[i] = True
                changed = True

    verified_blocks = [b for i, b in enumerate(kept_blocks) if verified_flags[i]]
    unverified_blocks = [b for i, b in enumerate(kept_blocks) if not verified_flags[i]]

    verified_dst = f"{src_base}_filtered_verified{src_ext}"
    unverified_dst = f"{src_base}_filtered_unverified{src_ext}"

    with open(verified_dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in verified_blocks:
            f.writelines(b)

    with open(unverified_dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in unverified_blocks:
            f.writelines(b)

    print(f"Verified (android/linux/mirai/valhalla): {len(verified_blocks)} "
          f"-> {verified_dst}")
    print(f"Unverified: {len(unverified_blocks)} -> {unverified_dst}")


if __name__ == "__main__":
    main()
