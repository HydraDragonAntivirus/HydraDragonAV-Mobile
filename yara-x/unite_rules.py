#!/usr/bin/env python3
import os
import argparse
import re

def main():
    parser = argparse.ArgumentParser(description="Unite YARA rules into a single file.")
    parser.add_argument(
        "--src",
        default=None,
        help="Source directory containing YARA files (default: AndroidOS next to this script)",
    )
    parser.add_argument(
        "--dst",
        default=None,
        help="Destination united YARA file (default: AndroidOS_united.yar next to this script)",
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = args.src or os.path.join(script_dir, "AndroidOS")
    dst_file = args.dst or os.path.join(script_dir, "AndroidOS_united.yar")

    if not os.path.exists(src_dir):
        print(f"Error: Source directory '{src_dir}' does not exist.")
        return

    print(f"Scanning for YARA rules in: {src_dir}")

    yara_files = []
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith((".yar", ".yara")):
                yara_files.append(os.path.join(root, file))

    print(f"Found {len(yara_files)} YARA files.")

    imports = set()
    rules_content = []

    import_pattern = re.compile(r'^\s*import\s+"(\w+)"')

    for file_path in sorted(yara_files):
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content_lines = []
                for line in f:
                    match = import_pattern.match(line)
                    if match:
                        imports.add(match.group(1))
                    else:
                        content_lines.append(line)
                
                # Clean up rule content
                file_content = "".join(content_lines).strip()
                if file_content:
                    rel_path = os.path.relpath(file_path, src_dir)
                    comment = f"// Source: {rel_path}"
                    rules_content.append(f"{comment}\n{file_content}\n")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    # Write to destination
    try:
        with open(dst_file, "w", encoding="utf-8") as f:
            if imports:
                for imp in sorted(imports):
                    f.write(f'import "{imp}"\n')
                f.write("\n")
            
            f.write("\n".join(rules_content))
            
        print(f"Successfully united rules into: {dst_file}")
    except Exception as e:
        print(f"Error writing destination file: {e}")

if __name__ == "__main__":
    main()
