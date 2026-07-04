"""
Convert Suricata/Snort rules to YARA-X using hydradragon.network.payload_hex.

Every hex/string content pattern from the Suricata rule becomes a
hydradragon.network.payload_hex("...") >= 1 condition — no YARA
strings section, no other module dependency.
"""

import re
import sys
import os

SURICATA_RE = re.compile(
    r'^(alert|drop|pass|activate|dynamic)\s+'
    r'(\S+)\s+(\S+)\s+(\S+)\s+(?:->|<>)\s+(\S+)\s+(\S+)\s*'
    r'\((.*)\)\s*$',
    re.IGNORECASE
)

def parse_suricata_rule(line):
    m = SURICATA_RE.match(line)
    if not m:
        return None
    action, proto, src, sport, dst, dport, opts_str = m.groups()
    opts = {}
    i = 0
    n = len(opts_str)
    while i < n:
        while i < n and opts_str[i] in (' ', ';'):
            i += 1
        if i >= n:
            break
        m_kv = re.match(r'(\w+)\s*:\s*', opts_str[i:])
        if not m_kv:
            i += 1
            continue
        key = m_kv.group(1).lower()
        i += m_kv.end()
        in_quote = False
        quote_char = None
        depth = 0
        val_start = i
        while i < n:
            ch = opts_str[i]
            if in_quote:
                if ch == '\\':
                    i += 2
                    continue
                if ch == quote_char:
                    in_quote = False
                    quote_char = None
                    i += 1
                    continue
                i += 1
                continue
            if ch in ('"', "'"):
                in_quote = True
                quote_char = ch
                i += 1
                continue
            if ch == '(':
                depth += 1
                i += 1
                continue
            if ch == ')':
                depth -= 1
                i += 1
                continue
            if ch == ';' and depth == 0:
                break
            i += 1
        value = opts_str[val_start:i].strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if key == 'msg':
            value = value.replace('"', "'").replace('\\', '\\\\')
        if key == 'content':
            opts.setdefault('contents', []).append(value)
        else:
            opts[key] = value
        if i < n and opts_str[i] == ';':
            i += 1
    return {
        'action': action,
        'proto': proto.upper(),
        'opts': opts,
    }


def content_to_parts(content_str):
    parts = []
    i = 0
    n = len(content_str)
    while i < n:
        if content_str[i] == '|':
            j = i + 1
            while j < n and content_str[j] != '|':
                j += 1
            hex_part = content_str[i+1:j]
            hex_bytes = ''.join(hex_part.split())
            if hex_bytes:
                parts.append(('hex', hex_bytes))
            i = j + 1
        else:
            j = i
            while j < n and content_str[j] != '|':
                j += 1
            text_part = content_str[i:j]
            if text_part:
                parts.append(('text', text_part))
            i = j
    return parts


def parts_to_hex(parts):
    """Convert content parts to a single hex string for payload_hex."""
    result = []
    for ptype, pval in parts:
        if ptype == 'hex':
            result.append(pval)
        else:
            result.append(''.join(f'{ord(c):02x}' for c in pval))
    return ''.join(result)


def escape_yara(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


def simplify_name(msg):
    name = msg.strip()
    name = re.sub(r'[^a-zA-Z0-9]+', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')[:80]
    return name


def convert_rule(rule, idx):
    opts = rule['opts']
    msg = opts.get('msg', f'rule_{idx}')
    sid = opts.get('sid', str(idx))
    classtype = opts.get('classtype', 'unknown')
    rev = opts.get('rev', '1')

    rule_name = f"ET_{simplify_name(msg)}"
    if len(rule_name) > 120:
        rule_name = rule_name[:120]

    lines = []
    lines.append(f'rule {rule_name}')
    lines.append(f'{{')
    lines.append(f'  meta:')
    lines.append(f'    description = "{escape_yara(msg)}"')
    lines.append(f'    sid = "{sid}"')
    lines.append(f'    rev = "{rev}"')
    lines.append(f'    classtype = "{classtype}"')
    lines.append(f'    source = "EmergingThreats"')

    for k, v in opts.items():
        if k.startswith('reference'):
            r = escape_yara(v)
            if len(r) > 4:
                lines.append(f'    reference = "{r}"')

    contents = opts.get('contents', [])

    # Build hex patterns for each content field
    hex_patterns = []
    for c in contents:
        parts = content_to_parts(c)
        hex_str = parts_to_hex(parts)
        # Validate: must be even-length hex string
        if hex_str and len(hex_str) >= 2 and len(hex_str) % 2 == 0:
            if all(ch in '0123456789abcdefABCDEF' for ch in hex_str):
                hex_patterns.append(hex_str)

    lines.append('')
    lines.append('  condition:')

    if hex_patterns:
        conds = [f'hydradragon.network.payload_hex("{p}") >= 1' for p in hex_patterns]
        lines.append(f'    {" and ".join(conds)}')
    else:
        lines.append(f'    hydradragon.network_connections(/./) >= 1')
    lines.append('}')

    return '\n'.join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Convert Suricata/Snort rules to YARA-X (hydradragon.payload_hex)')
    parser.add_argument('input', help='Input .rules file')
    parser.add_argument('-o', '--output', default=None, help='Output .yar file (default: stdout)')
    args = parser.parse_args()

    out_file = None
    if args.output:
        out_file = open(args.output, 'w', encoding='utf-8')

    count = 0
    skipped = 0
    header_printed = False

    with open(args.input, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            rule = parse_suricata_rule(line)
            if not rule:
                skipped += 1
                continue
            count += 1
            yara_text = convert_rule(rule, count)
            if not header_printed:
                header = 'import "hydradragon"\n\n'
                if out_file:
                    out_file.write(header)
                else:
                    print(header, end='')
                header_printed = True
            if out_file:
                out_file.write(yara_text + '\n\n')
            else:
                print(yara_text)
                print()
            if count % 5000 == 0:
                print(f'  [{count} rules converted...]', file=sys.stderr)

    if out_file:
        out_file.close()
    print(f'Done: {count} rules converted, {skipped} skipped', file=sys.stderr)


if __name__ == '__main__':
    main()
