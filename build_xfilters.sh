#!/usr/bin/env bash
# Build every website Binary-Fuse (xor) filter (.xf) the native URL/domain
# scanner loads.
#
#   website (domain/url) filters -> fpp 1e-4   (these run on live DNS + APK URLs)
#   whitelist (md5 hashes)       -> fpp 1e-4   (built from all_md5.txt in step 4/4)
#
# The shared crate maps fpp to a binary-fuse width: fpp <= 1.5e-5 -> BinaryFuse32,
# fpp <= 3.9e-3 -> BinaryFuse16 (1e-4 lands here), else BinaryFuse8.
#
# Pipeline:
#   1. gen_domain_xfilter.py    -> xf_build/<stem>.txt  (phishing, abuse, spam,
#                                  mining, malicious_mail, malwareurl, phishingurl,
#                                  malicious[combined])
#   2. build_url_xfilters.py    -> overwrites xf_build/{malwareurl,phishingurl}.txt
#                                  with the whitelist-FILTERED versions
#   3. xorfilter_writer per stem -> app/src/main/assets/scan/<stem>.xf
set -euo pipefail
cd "$(dirname "$0")"

WRITER=dev-tools/xorfilter_writer/target/release/xorfilter_writer
SCAN=app/src/main/assets/scan
STAGE=xf_build
WEB_FPP=0.0001   # 1e-4 -> BinaryFuse16 for all filters

[ -x "$WRITER" ] || { echo "building xorfilter_writer..."; (cd dev-tools/xorfilter_writer && cargo build --release); }
mkdir -p "$SCAN"

echo "=== 1/3 extracting category lists ==="
python gen_domain_xfilter.py
echo "=== 2/3 whitelist-filtering URL lists ==="
python build_url_xfilters.py

echo "=== 3/3 building website .xf (fpp $WEB_FPP) ==="
# Stems MUST match the CATS table in hydradragonandroid/src/url_scan.rs.
for stem in malwareurl phishingurl phishing malicious malicious_mail abuse spam mining; do
    src="$STAGE/$stem.txt"
    if [ -s "$src" ]; then
        "$WRITER" "$src" "$SCAN/$stem.xf" "$WEB_FPP"
    else
        echo "  [SKIP] $stem: $src missing/empty"
    fi
done

echo "=== 3b/3 building malicious-IP .xf from allips (non-CIDR only) ==="
# Stems MUST match the CATS table in hydradragonandroid/src/ip_scan.rs.
declare -A IPMAP=( [ipmalware]=IPv4Malware [ipspam]=IPv4Spam \
                   [ipbruteforce]=IPv4BruteForce [ipddos]=IPv4DDoS \
                   [ipphishing]=IPv4PhishingActive )
for stem in ipmalware ipphishing ipbruteforce ipddos ipspam; do
    csv="allips/${IPMAP[$stem]}.optimized.csv"
    if [ -s "$csv" ]; then
        out="$STAGE/$stem.txt"
        awk -F, 'NF && $1!="" {print $1}' "$csv" | grep -v '/' | sort -u > "$out"
        "$WRITER" "$out" "$SCAN/$stem.xf" "$WEB_FPP"
    else
        echo "  [SKIP] $stem: $csv missing/empty"
    fi
done

echo "=== 4/4 building whitelist.xf from all_md5.txt (fpp $WEB_FPP) ==="
if [ -s all_md5.txt ]; then
    "$WRITER" all_md5.txt "$SCAN/whitelist.xf" "$WEB_FPP"
else
    echo "  [SKIP] whitelist: all_md5.txt missing/empty"
fi

echo
echo "Done. All .xf written to $SCAN/."
