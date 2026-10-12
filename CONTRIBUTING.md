# Contributing to PoViShield

Thank you for contributing to PoViShield. This document provides guidelines for development, testing, and contribution workflows.

## Development Setup

### System Prerequisites
PoViShield targets modern Linux environments with cgroup v2 and seccomp-bpf support (e.g., Fedora or Ubuntu on x86_64).

Required packages:
- **Fedora:** `sudo dnf install -y gcc libseccomp-devel python3 cppcheck nodejs npm`
- **Ubuntu/Debian:** `sudo apt-get install -y build-essential libseccomp-dev python3 cppcheck nodejs npm`

### Building the Project
```bash
make deps && make
```

---

## Testing & Quality Gates

Every code change must pass all verification gates prior to submission:

1. **Static Analysis & Syntax:**
   - C files: `make lint` (`cppcheck`)
   - Python files: `python3 -m py_compile <file>`
   - Whitespace: `git diff --check` (must pass cleanly with zero whitespace errors)

2. **Unprivileged Test Suite:**
   ```bash
   make test
   ```
   Runs unit tests, CLI tests, fail-closed validation, and security invariant tests.

3. **Privileged Isolation Tests (if modifying runtime/namespaces):**
   ```bash
   sudo make test-root
   ```
   Must be run in an isolated or disposable development environment.

4. **Web & Monitor Verification (if modifying api/ or frontend/):**
   ```bash
   bash tests/check_web.sh
   ```

5. **Counterfactual Evaluations (if modifying policy/ablation code):**
   ```bash
   make eval-ablate
   make eval-noisy
   ```

---

## Coding Standards

- **C Source (`src/`, `include/`):** Follow GNU C11 standard (`-std=gnu11`). All allocations must be checked; all file descriptors must be closed or flagged with `O_CLOEXEC`; initialization failures must fail closed.
- **Python (`analysis/`, `evaluation/`, `api/`):** Use clean, type-annotated Python 3.10+. Preserve fail-closed error handling and deterministic hashing.
- **Frontend (`frontend/`):** React 18+ with Vite. Keep state management clean and responsive.

## Commit Message Conventions

Commit messages must be concise, professional, and follow the Conventional Commits format:
```
feat(<scope>): <description> [verified permissions & syntax]
fix(<scope>): <description> [verified permissions & syntax]
docs(<scope>): <description>
test(<scope>): <description>
```
