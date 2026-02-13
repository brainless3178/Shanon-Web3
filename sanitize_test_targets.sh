#!/bin/bash
ROOT="/home/elliot/Music/hackathon/test_targets/spl/governance"
if [ -d "$ROOT/addin-mock" ]; then
    mv "$ROOT/addin-mock" "$ROOT/addin-v1"
    echo "Renamed addin-mock to addin-v1"
else
    echo "addin-mock not found"
fi
find /home/elliot/Music/hackathon/test_targets -name "*.toml" -exec sed -i 's/mock/v1/g' {} +
find /home/elliot/Music/hackathon/test_targets -name "*.toml" -exec sed -i 's/Mock/V1/g' {} +
