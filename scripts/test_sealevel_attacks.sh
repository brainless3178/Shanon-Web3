#!/bin/bash
# Test script to run security analysis against sealevel-attacks programs

set -e

HACKATHON_DIR="/home/elliot/Music/hackathon"
TARGETS_DIR="${HACKATHON_DIR}/test_targets/sealevel-attacks/programs"
OUTPUT_DIR="${HACKATHON_DIR}/audit_reports"

mkdir -p "${OUTPUT_DIR}"

echo "=========================================="
echo "Solana Security Swarm - Bug Bounty Testing"
echo "=========================================="
echo ""
echo "Testing against: sealevel-attacks (Coral/Anchor)"
echo "This repo contains 11 intentionally vulnerable Solana programs"
echo ""

# List all vulnerability categories
echo "Vulnerability Categories to Test:"
echo "----------------------------------"
ls -1 "${TARGETS_DIR}"
echo ""

# Run the analyzer against each vulnerable program
for vuln_dir in "${TARGETS_DIR}"/*; do
    if [ -d "${vuln_dir}" ]; then
        vuln_name=$(basename "${vuln_dir}")
        echo ""
        echo "=============================================="
        echo "Testing: ${vuln_name}"
        echo "=============================================="
        
        # Each vulnerability has an insecure version
        insecure_src="${vuln_dir}/insecure/src"
        
        if [ -d "${insecure_src}" ]; then
            echo "Analyzing insecure implementation..."
            
            # Run the program analyzer directly on the source
            for rs_file in "${insecure_src}"/*.rs; do
                if [ -f "${rs_file}" ]; then
                    echo "  -> Processing: $(basename ${rs_file})"
                    
                    # Use the program-analyzer crate directly
                    cargo run -p program-analyzer --bin analyze_source -- "${rs_file}" 2>&1 || echo "  Analysis completed with findings"
                fi
            done
        else
            echo "  No insecure implementation found, skipping..."
        fi
    fi
done

echo ""
echo "=========================================="
echo "Testing Complete!"
echo "=========================================="
