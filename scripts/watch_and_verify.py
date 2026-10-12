#!/usr/bin/env python3
"""PoViShield Automated Directory Watcher & Continuous Quality Gate.

Monitors project directories for modified or new feature files,
automatically verifies syntax, runs permission & security checks,
runs regression tests, and submits passing changes to the main branch.

Usage:
  python3 scripts/watch_and_verify.py --once
  python3 scripts/watch_and_verify.py --watch --auto-commit
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import py_compile
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WATCH_DIRS = ["src", "include", "analysis", "evaluation", "tests", "scripts", "demo", "docs"]
FILE_EXTENSIONS = {".py", ".c", ".h", ".json", ".md", ".sh"}


def get_git_branch() -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "branch", "--show-current"],
            capture_output=True,
            text=True,
            check=True,
        )
        return r.stdout.strip() or "master"
    except Exception:
        return "master"


def get_uncommitted_files() -> List[Path]:
    """Returns list of modified, staged, or untracked relevant files in git."""
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # format: XY filename or XY orig -> filename
            parts = line.split(maxsplit=1)
            if len(parts) >= 2:
                rel_path = parts[1]
                if " -> " in rel_path:
                    rel_path = rel_path.split(" -> ")[1]
                p = ROOT / rel_path
                if p.suffix in FILE_EXTENSIONS and p.exists() and not p.name.startswith("."):
                    files.append(p)
        return files
    except Exception:
        return []


def check_syntax(file_path: Path) -> Tuple[bool, str]:
    """Validates syntax for Python, C, or JSON files."""
    if file_path.suffix == ".py":
        try:
            py_compile.compile(str(file_path), doraise=True)
            return True, "OK"
        except py_compile.PyCompileError as e:
            return False, f"Python Syntax Error: {e.msg}"
    elif file_path.suffix in (".c", ".h"):
        r = subprocess.run(
            ["gcc", "-fsyntax-only", "-std=gnu11", "-Iinclude", str(file_path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            return False, f"C Syntax / Header Error:\n{r.stderr.strip()}"
        return True, "OK"
    elif file_path.suffix == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json.load(f)
            return True, "OK"
        except Exception as e:
            return False, f"JSON Syntax Error: {e}"
    return True, "OK"


def verify_permissions_and_ledgers() -> Tuple[bool, str]:
    """Runs independent verification of ledgers and profiles."""
    from analysis.audit_ledger import audit_ledger_file
    ledgers_dir = ROOT / "results" / "ledgers"
    if ledgers_dir.exists():
        for lpath in ledgers_dir.glob("*.jsonl"):
            ok, rep = audit_ledger_file(lpath)
            if not ok:
                return False, f"Ledger verification failed for {lpath.name}: {rep.get('errors')}"
    return True, "Permissions and evidence ledgers verified."


def run_tests() -> Tuple[bool, str]:
    """Executes project unit and regression test suite."""
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return False, f"Unit test regression failure:\n{r.stderr.strip()}"
    return True, "All tests passed."


def run_git_diff_check() -> Tuple[bool, str]:
    """Validates git whitespace and formatting rules."""
    r = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--check"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return False, f"Git diff check warnings:\n{r.stdout.strip()}"
    return True, "Diff check clean."


def process_changes(auto_commit: bool = False, dry_run: bool = False) -> bool:
    """Audits current changed files, runs checks, and commits if valid."""
    changed_files = get_uncommitted_files()
    if not changed_files:
        return True

    print(f"\n[Watcher] Detected {len(changed_files)} changed file(s):")
    for f in changed_files:
        print(f"  - {f.relative_to(ROOT)}")

    # 1. Syntax Check
    print("\n[Step 1/4] Verifying syntax across modified files...")
    syntax_ok = True
    for f in changed_files:
        ok, msg = check_syntax(f)
        if not ok:
            print(f"  [SYNTAX FAILED] {f.relative_to(ROOT)}:\n    {msg}")
            syntax_ok = False
        else:
            print(f"  [SYNTAX OK] {f.relative_to(ROOT)}")
    if not syntax_ok:
        print("[ABORT] Fix syntax errors before proceeding.")
        return False

    # 2. Git Diff Formatting Check
    print("\n[Step 2/4] Checking whitespace and formatting rules...")
    diff_ok, diff_msg = run_git_diff_check()
    if not diff_ok:
        print(f"  [FORMAT WARNING] {diff_msg}")
    else:
        print("  [FORMAT OK] Zero whitespace or EOF issues.")

    # 3. Permission & Ledger Security Check
    print("\n[Step 3/4] Verifying permissions and audit ledgers...")
    perm_ok, perm_msg = verify_permissions_and_ledgers()
    if not perm_ok:
        print(f"  [SECURITY FAILED] {perm_msg}")
        return False
    print(f"  [SECURITY OK] {perm_msg}")

    # 4. Regression Tests Check
    print("\n[Step 4/4] Running test regressions...")
    test_ok, test_msg = run_tests()
    if not test_ok:
        print(f"  [TESTS FAILED] {test_msg}")
        return False
    print("  [TESTS OK] Test suite passed cleanly.")

    # Auto-commit to main branch if requested
    if auto_commit and not dry_run:
        branch = get_git_branch()
        file_names = ", ".join(f.name for f in changed_files[:3])
        if len(changed_files) > 3:
            file_names += f" (+{len(changed_files) - 3} more)"
        commit_msg = f"feat: update {file_names} [verified permissions & syntax]"

        print(f"\n[Git Submission] Staging and submitting changes to branch '{branch}'...")
        rel_paths = [str(f.relative_to(ROOT)) for f in changed_files]
        subprocess.run(["git", "-C", str(ROOT), "add"] + rel_paths, check=True)
        subprocess.run(["git", "-C", str(ROOT), "commit", "-m", commit_msg], check=True)
        print(f"[SUCCESS] Changes committed cleanly to '{branch}': {commit_msg}")
    elif dry_run:
        print("\n[Dry Run] Verification passed. (Changes were not committed).")
    else:
        print("\n[Ready] All syntax, permission, and regression checks passed.")

    return True


def scan_snapshots() -> Dict[Path, float]:
    """Scans all monitored directories and records mtime timestamps."""
    snapshots: Dict[Path, float] = {}
    for dname in WATCH_DIRS:
        dp = ROOT / dname
        if not dp.exists():
            continue
        for p in dp.rglob("*"):
            if p.is_file() and p.suffix in FILE_EXTENSIONS and not p.name.startswith("."):
                snapshots[p] = p.stat().st_mtime
    return snapshots


def watch_loop(interval: float = 2.0, auto_commit: bool = True):
    print("========================================================================")
    print("PoViShield Project Watcher Active")
    print(f"Repository Root : {ROOT}")
    print(f"Branch Target   : {get_git_branch()}")
    print(f"Watching Dirs   : {', '.join(WATCH_DIRS)}")
    print(f"Poll Interval   : {interval}s")
    print(f"Auto-Commit     : {'Enabled' if auto_commit else 'Disabled'}")
    print("Press Ctrl+C to stop.")
    print("========================================================================")

    last_snapshot = scan_snapshots()
    try:
        while True:
            time.sleep(interval)
            current_snapshot = scan_snapshots()
            modified = []
            for path, mtime in current_snapshot.items():
                if path not in last_snapshot or last_snapshot[path] != mtime:
                    modified.append(path)
            if modified or get_uncommitted_files():
                process_changes(auto_commit=auto_commit)
                last_snapshot = scan_snapshots()
    except KeyboardInterrupt:
        print("\n[Watcher] Stopped by user.")


def main():
    parser = argparse.ArgumentParser(description="PoViShield Automated File Watcher and Quality Gate")
    parser.add_argument("--watch", action="store_true", help="Run continuous monitoring loop")
    parser.add_argument("--once", action="store_true", help="Run single verification pass on current changes")
    parser.add_argument("--auto-commit", action="store_true", help="Auto-commit passing changes to current branch")
    parser.add_argument("--dry-run", action="store_true", help="Perform checks without committing")
    parser.add_argument("--interval", type=float, default=2.0, help="Watcher polling interval in seconds")
    args = parser.parse_args()

    if args.watch:
        watch_loop(interval=args.interval, auto_commit=args.auto_commit)
    else:
        ok = process_changes(auto_commit=args.auto_commit, dry_run=args.dry_run)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
