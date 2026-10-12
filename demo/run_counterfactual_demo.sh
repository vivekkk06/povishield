#!/usr/bin/env bash
# PoViShield End-to-End Counterfactual Permission Verification Demo
# Demonstrates real code paths, actual seccomp enforcement, and proof ledger verification.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=build/povishield
TMP=$(mktemp -d /tmp/ps-cf-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT

echo "========================================================================"
echo "PoViShield: Counterfactual Permission Verification & Audit Ledger Demo"
echo "========================================================================"

if [[ ! -x "$BIN" ]]; then
    echo "Building PoViShield..."
    make all
fi

# Step 1: Learn an application's behavior
echo -e "\n[Step 1] Learning observed syscall behavior for 'grep' via ptrace tracer..."
"$BIN" learn -o "$TMP/grep_observed.json" -- grep -r root /etc/passwd
echo "Observed policy generated: $(python3 -c "import json; print(len(json.load(open('$TMP/grep_observed.json'))['syscalls']))") syscalls recorded."

# Step 2: Generate the baseline policy (with extraneous permissions to test minimization)
echo -e "\n[Step 2] Generating baseline policy (simulating extraneous permissions: ptrace, mount, socket, connect)..."
python3 -c "
import json
d = json.load(open('$TMP/grep_observed.json'))
d['syscalls'] = sorted(set(d['syscalls']) | {'ptrace', 'mount', 'socket', 'connect'})
d['count'] = len(d['syscalls'])
with open('$TMP/grep_baseline.json', 'w') as f:
    json.dump(d, f, indent=2)
"
echo "Baseline policy saved with $(python3 -c "import json; print(len(json.load(open('$TMP/grep_baseline.json'))['syscalls']))") syscalls."

# Step 3: Run a counterfactual permission test (ablation engine)
echo -e "\n[Step 3] Running counterfactual permission ablation against legitimate workloads..."
python3 -m analysis.ablate \
    --profile "$TMP/grep_baseline.json" \
    --workload "grep -r root /etc/passwd" \
    --workload "grep -c bin /etc/passwd" \
    --target "demo_grep" \
    -o "$TMP/grep_candidate.json"

# Step 4: Record the evidence into append-only JSONL ledger
LEDGER_PATH="results/ledgers/demo_grep.jsonl"
echo -e "\n[Step 4] Inspecting recorded evidence ledger ($LEDGER_PATH)..."
echo "Total trials recorded: $(wc -l < "$LEDGER_PATH")"
head -n 1 "$LEDGER_PATH" | python3 -m json.tool

# Step 5: Verify the evidence independently (fail-closed integrity audit)
echo -e "\n[Step 5] Performing independent ledger audit and consistency verification..."
python3 -m analysis.audit_ledger "$LEDGER_PATH" --candidate "$TMP/grep_candidate.json"

# Step 6: Generate and validate candidate policy
echo -e "\n[Step 6] Validating candidate policy (Schema 2) and permission tiers..."
python3 -c "
import json
d = json.load(open('$TMP/grep_candidate.json'))
print(f'Candidate Policy Schema: {d[\"schema\"]}')
print(f'Allowed Syscalls       : {d[\"count\"]}')
print(f'Removable Permissions  : {d[\"permission_tiers\"][\"removable_for_tested_tasks\"]}')
print(f'Required Permissions   : {len(d[\"permission_tiers\"][\"experimentally_necessary\"])} syscalls')
"

# Step 7: Compare baseline and candidate metrics
echo -e "\n[Step 7] Comparing baseline vs candidate security metrics..."
echo -n "Baseline  : "
python3 -m analysis.risk "$TMP/grep_baseline.json"
echo -n "Candidate : "
python3 -m analysis.risk "$TMP/grep_candidate.json"

# Step 8: Show a genuine failure / regression case when safely reproducible
echo -e "\n[Step 8] Demonstrating genuine failure when an essential permission ('read') is ablated..."
python3 -c "
import json
d = json.load(open('$TMP/grep_candidate.json'))
d['syscalls'] = [s for s in d['syscalls'] if s != 'read']
d['count'] = len(d['syscalls'])
with open('$TMP/grep_without_read.json', 'w') as f:
    json.dump(d, f, indent=2)
"
set +e
"$BIN" enforce -p "$TMP/grep_without_read.json" -- grep -r root /etc/passwd > "$TMP/fail_out.log" 2>&1
FAIL_RC=$?
set -e
echo "Application execution terminated with exit code: $FAIL_RC (159 = SIGSYS, seccomp kill)"
if [[ "$FAIL_RC" -eq 159 || "$FAIL_RC" -eq 128+31 ]]; then
    echo "SUCCESS: Empirical kernel-level proof that 'read' is indispensable."
else
    echo "Terminated with exit code $FAIL_RC."
fi

# Step 9: Demonstrate that invalid evidence cannot justify a removal
echo -e "\n[Step 9] Demonstrating fail-closed rejection of invalid / unbacked evidence..."

# 9A. Candidate claims removal without ledger proof
echo "  [9A] Candidate attempts unbacked removal ('write' marked removable without trial proof)..."
python3 -c "
import json
d = json.load(open('$TMP/grep_candidate.json'))
d['syscalls'] = [s for s in d['syscalls'] if s != 'write']
d['count'] = len(d['syscalls'])
d['permission_tiers']['removable_for_tested_tasks'].append('write')
with open('$TMP/unbacked_cand.json', 'w') as f:
    json.dump(d, f, indent=2)
"
if python3 -m analysis.audit_ledger "$LEDGER_PATH" --candidate "$TMP/unbacked_cand.json" 2>/dev/null; then
    echo "ERROR: Auditor accepted unbacked removal!"
    exit 1
else
    echo "  SUCCESS: Auditor rejected unbacked removal and failed closed."
fi

# 9B. Corrupted ledger file
echo "  [9B] Corrupted ledger detection..."
CORRUPT_LEDGER="$TMP/corrupt.jsonl"
cp "$LEDGER_PATH" "$CORRUPT_LEDGER"
echo '{"trial_id": "bad", MALFORMED_JSON' >> "$CORRUPT_LEDGER"
if python3 -m analysis.audit_ledger "$CORRUPT_LEDGER" 2>/dev/null; then
    echo "ERROR: Auditor accepted corrupted ledger!"
    exit 1
else
    echo "  SUCCESS: Auditor rejected corrupted ledger and failed closed."
fi

# Step 10: Pre-enforcement safety gate & approval
echo -e "\n[Step 10] Running pre-enforcement safety gate (regression + adversarial checks + approval)..."
python3 -m analysis.verify "$TMP/grep_candidate.json" \
    --active "$TMP/grep_observed.json" \
    --target "demo_grep" \
    --regression "grep -r root /etc/passwd" \
    --regression "grep -c bin /etc/passwd" \
    --adversarial "python3 -c 'import os; os.kill(os.getpid(), 0)'" \
    --approve

echo -e "\n========================================================================"
echo "DEMO COMPLETE: All 9 research criteria demonstrated on real code paths."
echo "========================================================================"
