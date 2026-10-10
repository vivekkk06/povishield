#!/usr/bin/env bash
# Safe, non-root checks. Never runs escape tests.
set -u
cd "$(dirname "$0")/.."
BIN=./build/povishield; FAIL=0
ok()  { echo "  [PASS] $*"; }
bad() { echo "  [FAIL] $*"; FAIL=1; }
want() { local w=$1 l=$2; shift 2; "$@" >/dev/null 2>&1; local g=$?
         [ "$g" -eq "$w" ] && ok "$l (exit=$g)" || bad "$l (want $w, got $g)"; }

echo "== CLI validation =="
for v in 0 abc -1 ' 5' '' 99999999999999999999999; do
  want 2 "learn --max-event-bytes '$v'" $BIN learn --max-event-bytes "$v" -- /bin/true
done
want 2 "learn without command" $BIN learn
want 2 "run --mem abc"         $BIN run --mem abc -- /bin/true
want 2 "run --mem 0"           $BIN run --mem 0 -- /bin/true
want 2 "run --pids -5"         $BIN run --pids -5 -- /bin/true
want 2 "run --cpu 99999"       $BIN run --cpu 99999 -- /bin/true
want 2 "run --rootfs relative" $BIN run --rootfs relative/path -- /bin/true
want 0 "run --help"            $BIN run --help

echo "== learn + event log =="
T=$(mktemp -d)
want 0 "learn /bin/true" $BIN learn -o "$T/p.json" --events "$T/e.jsonl" --max-event-bytes 1048576 -- /bin/true
python3 -m json.tool "$T/p.json" >/dev/null 2>&1 && ok "profile JSON valid" || bad "profile JSON invalid"
python3 - "$T/e.jsonl" <<'PY' && ok "event JSONL valid" || bad "event JSONL invalid"
import json, sys
for i, l in enumerate(open(sys.argv[1]), 1):
    assert isinstance(json.loads(l), dict), i
PY
want 75 "byte cap stops tracing" $BIN learn -o "$T/p2.json" --events "$T/e2.jsonl" --max-event-bytes 200 -- /bin/true
$BIN learn -o /nonexistent-dir/p.json -- /bin/true >/dev/null 2>&1
[ $? -ne 0 ] && ok "unwritable profile fails" || bad "unwritable profile reported success"
rm -rf "$T"

[ "$FAIL" -eq 0 ] && echo "ALL SAFE CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
