#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

BIN=build/povishield
VIEWER=build/vuln_viewer
STATIC_VIEWER=build/vuln_viewer-static
ROOTFS=""

cleanup() {
    if [[ -n "${ROOTFS:-}" && "$ROOTFS" == /tmp/povishield-demo-rootfs.* ]]; then
        sudo rm -rf -- "$ROOTFS"
    fi
}
trap cleanup EXIT

if [[ ! -f demo/data/notes.txt || ! -f demo/secret.txt ]]; then
    echo "ERROR: demo input files are missing; refusing to recreate them." >&2
    exit 1
fi

if [[ ! -x "$BIN" || ! -x "$VIEWER" ]]; then
    echo "Building PoViShield..."
    make all || exit 1
fi

mkdir -p results

echo "== 1. Normal use"
"$VIEWER" demo/data notes.txt

echo
echo "== 2. Command injection in the UNSANDBOXED application"
"$VIEWER" demo/data '!echo ATTACKER-SHELL-RAN as $(id -un)'
echo "The application above is intentionally vulnerable."

echo
echo "== 3. Learn from benign use"
"$BIN" learn -o results/vuln.json -- "$VIEWER" demo/data notes.txt
"$BIN" learn -o results/vuln2.json -- "$VIEWER" demo/data missing.txt
if [[ ! -s results/vuln.json || ! -s results/vuln2.json ]]; then
    echo "ERROR: learning did not produce both profiles." >&2
    exit 1
fi
python3 -m analysis.merge results/vuln-merged.json results/vuln.json results/vuln2.json || exit 1
python3 -m analysis.risk results/vuln-merged.json || true

echo
echo "== 4. Enforce the learned seccomp policy against the attack"
"$BIN" enforce -p results/vuln-merged.json -- "$VIEWER" demo/data '!echo ATTACKER-SHELL-RAN'
enforce_rc=$?
echo "Enforcement command exit status: $enforce_rc"
if (( enforce_rc != 159 )); then
    echo "FAIL: expected SIGSYS status 159, got $enforce_rc" >&2
    exit 1
fi
echo "PASS: attack terminated by SIGSYS (159)"

echo
echo "== 5. Filesystem confinement with a rootfs"
if ! gcc -static -O2 -Wall -Wextra demo/vuln_viewer.c -o "$STATIC_VIEWER"; then
    echo "ERROR: static compilation failed (is glibc-static installed?)" >&2
    exit 1
fi

ROOTFS="$(mktemp -d /tmp/povishield-demo-rootfs.XXXXXX)"
mkdir -p "$ROOTFS/bin" "$ROOTFS/data" "$ROOTFS/proc" "$ROOTFS/tmp"
install -m 755 "$STATIC_VIEWER" "$ROOTFS/bin/vuln_viewer"
install -m 644 demo/data/notes.txt "$ROOTFS/data/notes.txt"
# Deliberately NOT copying demo/secret.txt into the rootfs.

echo "-- Public file inside the rootfs"
out_normal=$(sudo "$BIN" run --rootfs "$ROOTFS" -- /bin/vuln_viewer /data notes.txt 2>&1)
echo "$out_normal"
if [[ "$out_normal" != *"public notes"* ]]; then
    echo "FAIL: normal use inside the rootfs did not print the public notes" >&2
    exit 1
fi

echo
echo "-- Attempt traversal to a file absent from the rootfs"
out_trav=$(sudo "$BIN" run --rootfs "$ROOTFS" -- /bin/vuln_viewer /data ../secret.txt 2>&1)
echo "$out_trav"
if [[ "$out_trav" == *"TOP SECRET"* ]]; then
    echo "FAIL: rootfs did not confine the traversal (secret leaked)" >&2
    exit 1
fi
echo "PASS: traversal could not reach the host secret (rootfs confinement)"

echo
echo "== 6. Verify tracked demo inputs were not rewritten"
git diff --exit-code -- demo/data/notes.txt demo/secret.txt && echo "DEMO-INPUTS-UNCHANGED"
exit 0
