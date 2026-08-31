#!/usr/bin/env bash
# build, test, and run a quick end-to-end demo (works on any OS, no hardware).
set -e
cd "$(dirname "$0")/.."

echo "== build =="
cmake -S . -B build >/dev/null
cmake --build build -j >/dev/null

echo "== tests =="
ctest --test-dir build --output-on-failure | tail -4

echo
echo "== demo: inject an rpm spoof, then run the IDS over it =="
./build/canshield_attack --attack rpm_spoof --seconds 20 \
    --attack-start 8 --attack-len 6 --out data/demo_trace.csv
./build/canshield_monitor --in data/demo_trace.csv --max-print 6

echo
echo "run the full evaluation with:  ./build/canshield_eval"
