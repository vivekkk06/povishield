#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
BIN=build/povishield
mkdir -p demo/data results
echo "public notes" > demo/data/notes.txt
echo "TOP SECRET"   > demo/secret.txt

echo "== 1. normal use";                        build/vuln_viewer demo/data notes.txt
echo "== 2. command-injection, UNSANDBOXED";    build/vuln_viewer demo/data '!echo ATTACKER-SHELL-RAN as $(id -un)'

echo "== 3. learn from NORMAL use only"
$BIN learn -o results/vuln.json -- build/vuln_viewer demo/data notes.txt
$BIN learn -o results/vuln2.json -- build/vuln_viewer demo/data missing.txt 2>/dev/null
python3 -m analysis.merge results/vuln-merged.json results/vuln.json results/vuln2.json
python3 -m analysis.risk results/vuln-merged.json

echo "== 4. same attack under ENFORCE (expect: killed by SIGSYS, exit 159)"
$BIN enforce -p results/vuln-merged.json -- build/vuln_viewer demo/data '!echo ATTACKER-SHELL-RAN'
echo "exit code: $?"

echo "== 5. honest limitation: path traversal is NOT a syscall-level problem"
$BIN enforce -p results/vuln-merged.json -- build/vuln_viewer demo/data ../secret.txt
echo "(seccomp allows openat, so this still leaks. Use 'povishield run --rootfs' to confine the filesystem.)"
