# Continuous Feature Quality Gate & Commit Workflow

## Scope
This rule applies when implementing, modifying, or completing feature files in `povishield`.

## Directives
1. **Syntax Integrity:**
   - Every modified `.py` file must compile cleanly via `python3 -m py_compile <file>`.
   - Every modified `.c` and `.h` file must pass `gcc -fsyntax-only -std=gnu11 -Iinclude <file>` and `make lint`.

2. **Permission & Policy Security:**
   - Always run `python3 analysis/audit_ledger.py` on modified ledgers to fail closed on unbacked removals or corruptions.
   - Run `python3 analysis/verify.py` on candidate seccomp policies against regression workloads before proposing or approving activation.

3. **Regression Tests:**
   - Always run `make test` to verify unit and regression suite integrity.

4. **Main Branch Submission:**
   - Ensure clean formatting with `git diff --check`.
   - Submit passing changes to the main branch (`master`) using clear commit messages.
