#!/bin/bash
# Script to analyze and report remaining warnings after cleanup

echo "================================================================"
echo "Warning Analysis Report"
echo "================================================================"
echo ""

echo "Building all crates and collecting warnings..."
echo ""

# Build and capture warnings
cargo build --release 2>&1 > /tmp/build_output.txt

# Count warnings by crate
echo "📊 Warnings by Crate:"
echo ""
grep "generated.*warnings" /tmp/build_output.txt | sort | uniq -c | sort -rn

echo ""
echo "================================================================"
echo "Warning Categories:"
echo "================================================================"
echo ""

# Categorize warnings
echo "🔹 Unused imports:"
grep -c "unused import" /tmp/build_output.txt || echo "0"

echo "🔹 Unused variables:"
grep -c "unused variable" /tmp/build_output.txt || echo "0"

echo "🔹 Dead code (unused fields/variants):"
grep -c "never read\|never constructed\|never used" /tmp/build_output.txt || echo "0"

echo "🔹 Unnecessary mutable:"
grep -c "does not need to be mutable" /tmp/build_output.txt || echo "0"

echo "🔹 Other:"
total_warnings=$(grep -c "^warning:" /tmp/build_output.txt || echo "0")
echo "$total_warnings total warnings"

echo ""
echo "================================================================"
echo "Top Warning Sources:"
echo "================================================================"
echo ""

# Show files with most warnings
grep "^warning:" /tmp/build_output.txt | grep -oP "-->\ \K[^:]*" | sort | uniq -c | sort -rn | head -10

echo ""
echo "================================================================"

# Check if build succeeded
if grep -q "Finished" /tmp/build_output.txt; then
    echo "✅ Build Status: SUCCESS"
else
    echo "❌ Build Status: FAILED"
fi

# Clean up
rm -f /tmp/build_output.txt

echo "================================================================"
