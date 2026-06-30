#!/usr/bin/env bash
# Build every website qfilter (.qf) the native URL/domain scanner mmaps.
#
#   website (domain/url) filters -> fpp 1e-6   (these run on live DNS + APK URLs;
#                                               a false positive blocks a site)
#   whitelist (hashes)           -> fpp 1e-4   (built SEPARATELY from all_sha256.txt;
#                                               see the whitelist command at the end)
#
# Pipeline:
#   1. gen_domain_bloom.py      -> qf_build/<stem>.txt  (phishing, abuse, spam,
#                                  mining, malicious_mail, malwareurl, phishingurl,
#                                  malicious[combined])
#   2. build_url_blooms.py      -> overwrites qf_build/{malwareurl,phishingurl}.txt
#                                  with the whitelist-FILTERED versions
#   3. qfilter_writer per stem  -> app/src/main/assets/scan/<stem>.qf
set -euo pipefail
cd "$(dirname "$0")"

WRITER=dev-tools/qfilter_writer/target/release/qfilter_writer
SCAN=app/src/main/assets/scan
STAGE=qf_build
WEB_FPP=0.000001   # 1e-6 for website filters

[ -x "$WRITER" ] || { echo "building qfilter_writer..."; (cd dev-tools/qfilter_writer && cargo build --release); }
mkdir -p "$SCAN"

echo "=== 1/3 extracting category lists ==="
python gen_domain_bloom.py
echo "=== 2/3 whitelist-filtering URL lists ==="
python build_url_blooms.py

echo "=== 3/3 building website .qf (fpp $WEB_FPP) ==="
# Stems MUST match the CATS table in hydradragonandroid/src/url_scan.rs.
for stem in malwareurl phishingurl phishing malicious malicious_mail abuse spam mining; do
    src="$STAGE/$stem.txt"
    if [ -s "$src" ]; then
        "$WRITER" "$src" "$SCAN/$stem.qf" "$WEB_FPP"
    else
        echo "  [SKIP] $stem: $src missing/empty"
    fi
done

echo
echo "Done. Website .qf written to $SCAN/."
echo "Whitelist (run once, ~minutes, 7GB input):"
echo "  $WRITER all_sha256.txt $SCAN/whitelist.qf 0.0001"
