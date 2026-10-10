#!/usr/bin/env python3
"""Mutation-fuzz the profile loader. Passes if it never crashes (SIGSEGV/SIGABRT/SIGBUS/ASan exit).
Usage: python3 tests/fuzz_profile.py [iterations]    (BIN=build/povishield-asan for sanitizers)"""
import os, random, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BIN = os.environ.get("BIN", str(ROOT / "build" / "povishield"))
N = int(sys.argv[1]) if len(sys.argv) > 1 else 500
CRASH = {-11, -6, -7, -4, -8, 99}   # SEGV ABRT BUS ILL FPE, ASAN_OPTIONS=exitcode=99
env = dict(os.environ, ASAN_OPTIONS="exitcode=99:detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1:exitcode=99")

d = Path(tempfile.mkdtemp())
seed_p = d / "seed.json"
subprocess.run([BIN, "learn", "-o", str(seed_p), "--", "/bin/true"], check=True, capture_output=True, env=env)
seed = seed_p.read_bytes()
rng = random.Random(1234)
junk = b'"[]{},:\\\x00 \n0aZ'
bad = 0
for i in range(N):
    b = bytearray(seed)
    for _ in range(rng.randint(1, 8)):
        op = rng.choice("flip ins del trunc dup".split())
        pos = rng.randrange(len(b)) if b else 0
        if op == "flip" and b: b[pos] = rng.randrange(256)
        elif op == "ins": b[pos:pos] = bytes(rng.choice(junk) for _ in range(rng.randint(1, 6)))
        elif op == "del" and b: del b[pos:pos + rng.randint(1, 10)]
        elif op == "trunc" and b: b = b[:pos]
        elif op == "dup" and b: b[pos:pos] = b[pos:pos + rng.randint(1, 40)]
    f = d / "m.json"
    f.write_bytes(bytes(b))
    r = subprocess.run([BIN, "enforce", "-p", str(f), "--", "/bin/true"], capture_output=True, env=env, timeout=20)
    if r.returncode in CRASH:
        bad += 1
        keep = ROOT / "results" / f"fuzz-crash-{i}.json"
        keep.parent.mkdir(exist_ok=True)
        keep.write_bytes(bytes(b))
        print(f"CRASH rc={r.returncode} iter={i} saved {keep}")
print(f"fuzz: {N} mutants, {bad} crashes")
sys.exit(1 if bad else 0)
