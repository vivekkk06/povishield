#!/usr/bin/env bash
# API startup + endpoints on a temporary port, then frontend production build.
set -u
cd "$(dirname "$0")/.."
FAIL=0
[ -f results/results.json ] || { echo "results.json missing; running make eval..."; make eval >/dev/null 2>&1; }
PY=.venv/bin/python; [ -x "$PY" ] || PY=api/.venv/bin/python
"$PY" -c "import fastapi, uvicorn" 2>/dev/null || { echo "[FAIL] fastapi/uvicorn missing in venv"; exit 1; }
"$PY" -m py_compile api/main.py api/public_app.py && echo "[PASS] api/main.py & api/public_app.py compile" || FAIL=1
"$PY" -m uvicorn api.main:app --host 127.0.0.1 --port 8001 >/tmp/ps-api.log 2>&1 &
APIPID=$!
trap 'kill $APIPID ${PUBPID:-} 2>/dev/null' EXIT
sleep 3
for ep in health overview policies experiments events/profile ablation/results ablation/noisy ledgers approvals "events?limit=10" executions devices; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8001/api/$ep")
  [ "$code" = "200" ] && echo "[PASS] /api/$ep -> 200" || { echo "[FAIL] /api/$ep -> $code"; FAIL=1; }
done
inst_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8001/install.sh")
[ "$inst_code" = "200" ] && echo "[PASS] /install.sh -> 200" || { echo "[FAIL] /install.sh -> $inst_code"; FAIL=1; }

echo
echo "=== CLOUD ENTRYPOINT (api.public_app) VERIFICATION ==="
"$PY" -m uvicorn api.public_app:app --host 127.0.0.1 --port 8002 >/tmp/ps-pub.log 2>&1 &
PUBPID=$!
sleep 2
for pep in health devices executions; do
  pcode=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8002/api/$pep")
  [ "$pcode" = "200" ] && echo "[PASS] public_app /api/$pep -> 200" || { echo "[FAIL] public_app /api/$pep -> $pcode"; FAIL=1; }
done
peval_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:8002/api/executions/evaluate" -H "Content-Type: application/json" -d '{"command":["/usr/bin/echo","test"]}')
[ "$peval_code" = "200" ] && echo "[PASS] public_app /api/executions/evaluate -> 200" || { echo "[FAIL] public_app /api/executions/evaluate -> $peval_code"; FAIL=1; }
pinst_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8002/install.sh")
[ "$pinst_code" = "200" ] && echo "[PASS] public_app /install.sh -> 200" || { echo "[FAIL] public_app /install.sh -> $pinst_code"; FAIL=1; }
kill $PUBPID 2>/dev/null; wait $PUBPID 2>/dev/null

echo
echo "=== MULTI-DEVICE FLEET SECURITY TESTS ==="
"$PY" -m unittest tests/test_multi_device.py && echo "[PASS] multi-device fleet platform tests" || FAIL=1

echo
echo "=== LIVE MONITOR API INTEGRATION ==="
python3 tests/check_monitor_api.py && echo "[PASS] live monitor API integration" || FAIL=1
API=http://127.0.0.1:8001 python3 tests/check_monitor_security.py && echo "[PASS] monitor API security verification" || FAIL=1
echo
echo "NOTE: HTTP 200 does not prove live monitoring or enforcement is active."
kill $APIPID 2>/dev/null; wait $APIPID 2>/dev/null
( cd frontend && npm run build >/tmp/ps-fe.log 2>&1 ) && echo "[PASS] frontend build" || { echo "[FAIL] frontend build (see /tmp/ps-fe.log)"; FAIL=1; }
[ "$FAIL" -eq 0 ] && echo "WEB CHECKS PASSED" || { echo "WEB CHECKS FAILED"; exit 1; }
