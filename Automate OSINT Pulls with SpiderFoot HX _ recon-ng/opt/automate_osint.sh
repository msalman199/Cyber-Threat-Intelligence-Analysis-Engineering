#!/bin/bash

echo "=== AUTOMATED OSINT COLLECTION PIPELINE ==="
echo "Starting at: $(date)"

TARGET_DOMAIN="$1"
if [ -z "$TARGET_DOMAIN" ]; then
    echo "Usage: $0 <target_domain>"
    exit 1
fi

echo "Target: $TARGET_DOMAIN"

# Start SpiderFoot scan
echo "Starting SpiderFoot scan..."
cd /opt/spiderfoot
python3 sf.py -s $TARGET_DOMAIN -t all -q &
SPIDERFOOT_PID=$!

# Run recon-ng scan
echo "Starting recon-ng reconnaissance..."
cd /opt/recon-ng
python3 recon-ng -w osint_automation -C "modules load recon/domains-hosts/hackertarget; options set SOURCE $TARGET_DOMAIN; run; exit" &
RECONNG_PID=$!

# Wait for both tools to complete
echo "Waiting for scans to complete..."
wait $SPIDERFOOT_PID
wait $RECONNG_PID

# Correlate findings
echo "Correlating findings..."
python3 /opt/correlate_osint.py

# Generate adversary profile
echo "Generating adversary profile..."
python3 /opt/adversary_profile.py

echo "=== AUTOMATION COMPLETE ==="
echo "Results available in:"
echo "  - /opt/correlated_findings.json"
echo "  - /opt/adversary_profile.json"
