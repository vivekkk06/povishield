# PoViShield Developer & Agent Instructions

This repository contains **PoViShield**, a Linux security research prototype and sandboxing platform.

When operating in this repository, follow these automated guidelines:

## Feature File Completion & Verification Workflow

Every time a new feature file or modification is completed:

1. **Verify Syntax & Static Analysis:**
   - **Python files (`*.py`):** Verify syntax using `python3 -m py_compile <file>`. Ensure clean formatting and zero trailing whitespace issues (`git diff --check`).
   - **C source & headers (`src/*.c`, `include/*.h`):** Verify compilation syntax with `gcc -fsyntax-only -std=gnu11 -Iinclude <file>` and run static analysis using `make lint` (`cppcheck`).

2. **Verify Security Policies & Permissions:**
   - Any profile changes or candidate permissions must be validated through the safety gate:
     ```bash
     python3 -m analysis.verify <candidate.json> --active <active.json> --regression "<cmd>"
     ```
   - Any permission ablation trials or ledgers must be verified fail-closed:
     ```bash
     python3 -m analysis.audit_ledger <ledger.jsonl> --candidate <candidate.json>
     ```
   - Never allow unbacked or unfamiliar syscalls into active policies.

3. **Run Regression Tests:**
   - Execute the test suite before submitting:
     ```bash
     make test
     ```

4. **Submit to the Main Branch:**
   - Verify `git diff --check` passes cleanly.
   - Stage the modified files and commit to the main branch (`master`):
     ```bash
     git add <modified_files>
     git commit -m "feat(<scope>): <description> [verified permissions & syntax]"
     ```

## Automated Watcher Service

To automatically watch this project directory, detect file changes, verify permissions, fix syntax errors, and commit passing changes to the main branch continuously, run:

```bash
make watch
# or
python3 scripts/watch_and_verify.py --watch --auto-commit
```
