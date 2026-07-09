"""Extract unique non-CIDR IPv4 addresses (first CSV column) from an
allips/<name>.optimized.csv into a newline-delimited xf_build/<stem>.txt.

Usage: python extract_ip_csv.py <csv_path> <out_path>
"""
import sys

def main():
    csv_path, out_path = sys.argv[1], sys.argv[2]
    ips = set()
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ip = line.split(",", 1)[0].strip()
            if ip and "/" not in ip:
                ips.add(ip)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(ips)))
        f.write("\n")
    print(f"  {out_path}: {len(ips):,} unique IPs")

if __name__ == "__main__":
    main()
