# PoViShield Security Assurance & Formal Properties

## 1. Scope & Verification Methodology

This document formalizes the security invariants, state transitions, and empirical verification methods of PoViShield.

Security properties are categorized by their epistemic basis:
- **Deductive / Kernel-Guaranteed Properties:** Invariants that hold under the axiomatic assumptions of the Linux kernel's seccomp-bpf subsystem and POSIX capability model.
- **Fail-Closed State Invariants:** Deterministic runtime state-transition properties enforced by the PoViShield supervisor before invoking target code.
- **Empirical Minimization Properties:** Statistical and trial-backed properties verified over finite workload suites, accompanied by auditable evidence ledgers.

> **Important Scientific Distinction:** Testing, property assertions, and empirical evaluation do **not** constitute a formal mathematical proof of the entire Linux kernel. Properties proven under kernel assumptions are explicitly distinguished from empirical test results.

---

## 2. Formal Security Properties

### Property 1: Syscall Containment Invariant (Kernel-Enforced Allowlist)
* **Claim:** For any process $P$ running under an installed PoViShield seccomp filter with allowlist $\mathcal{A} \subset \mathcal{S}$, invoking any system call $s \notin \mathcal{A}$ results in immediate kernel-level termination of $P$ via signal `SIGSYS`, preventing the execution of $s$'s kernel routine.
* **Assumptions:** Linux kernel $\ge 5.8$, functioning seccomp-bpf subsystem, non-corrupted BPF filter compilation by `libseccomp`.
* **Implementation:** `src/policy/seccomp_gen.c` (`seccomp_init(SCMP_ACT_KILL_PROCESS)`, `seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)`).
* **Enforcement:** The Linux BPF seccomp engine intercepts system call entries in the arch entry vector prior to dispatch.
* **Verification Method:** Executable automated test `test_invariant_1_disallowed_syscall_terminates_with_sigsys` in `tests/test_security_properties.py`, asserting exit code `-31` or `159` on disallowed syscall.
* **What This Property Does NOT Establish:** It does not inspect pointer arguments of allowed system calls, nor prevent semantic misuse of permitted system calls.

---

### Property 2: Initialization Fail-Closed Invariant
* **Claim:** If any required isolation primitive (namespace creation, cgroup allocation, resource limit parsing, root filesystem mount, capability dropping, or profile compilation) fails during initialization, target execution ($execve$) is unreachable, and the supervisor terminates with a non-zero error code.
* **Assumptions:** Valid POSIX error reporting from kernel system calls.
* **Implementation:**
  - Argument validation: `src/runtime/validate.c` (`ps_validate_run_args`).
  - Child synchronization: `src/runtime/sandbox.c` (`child_main` reads synchronization pipe byte before proceeding; if parent aborts, child reads EOF and calls `_exit(125)`).
  - Parent cleanup: `src/runtime/sandbox.c` (`abort_child` sends `SIGKILL` to child and removes cgroup).
* **State Machine:**
  $$\text{Init} \xrightarrow{\text{Parse Limits OK}} \text{Clone} \xrightarrow{\text{Setup Cgroup OK}} \text{Notify Child} \xrightarrow{\text{PivotRoot \& DropCaps OK}} \text{Execve}$$
  $$\forall \text{ state } S \neq \text{Execve}: \text{Error} \implies \text{Abort} \implies \text{Kill Child} \implies \text{Exit } (rc \in \{1, 2, 125, 126\})$$
* **Verification Method:**
  - `tests/test_security_properties.py`: `test_invariant_2_unknown_syscall_aborts_before_execution`, `test_invariant_3_resource_limit_fail_closed`.
  - `tests/test_profile_validation.py`: 14 fail-closed unit tests asserting zero executions on malformed or empty profiles.

---

### Property 3: Capability Deprivation Invariant
* **Claim:** Upon reaching $execve$ in the sandboxed process, the bounding, ambient, effective, permitted, and inheritable Linux capability sets are strictly empty ($\emptyset$), and `PR_SET_NO_NEW_PRIVS` is set to $1$.
* **Assumptions:** Linux kernel capability subsystem adheres to POSIX 1003.1e draft.
* **Implementation:** `src/runtime/sandbox.c` (`drop_privileges` loops `PR_CAPBSET_DROP` for caps 0..63, calls `PR_CAP_AMBIENT_CLEAR_ALL`, and calls `capset` with zeroed data).
* **Consequence:** The process cannot execute SUID binaries to regain root capabilities, mount filesystems, create raw sockets, or bypass namespace boundaries.
* **Verification Method:** `tests/test_root_runtime.py` (`test_default_run_has_no_capabilities`, `test_mount_is_denied_by_default_and_allowed_with_keep_caps`).

---

### Property 4: Monotonic Non-Expansion of Active Policies
* **Claim:** Observing unlearned or unfamiliar system calls during runtime enforcement never silently adds permissions to the active seccomp policy. Active policies are immutable during runtime.
* **Assumptions:** Memory safety of the running process; read-only kernel BPF filter rules.
* **Implementation:** `src/policy/seccomp_gen.c` loads compiled BPF filters via `seccomp_load(ctx)`, which places the filter into kernel memory. In user space, profiles are parsed into immutable data structures.
* **Verification Method:** `tests/test_security_properties.py` and `tests/test_ablation.py`.

---

### Property 5: Evidence Ledger Audit Integrity
* **Claim:** An evidence ledger $\mathcal{L}$ passes independent audit if and only if every recorded removal decision is backed by a verified, non-timeout, non-error trial confirming output and exit code equivalence under candidate seccomp confinement.
* **Assumptions:** SHA-256 collision resistance.
* **Implementation:** `analysis/audit_ledger.py` (`audit_ledger_file`) recalculates trial checksums, cross-checks baseline hashes against candidate outputs, and asserts that no strictly required system call is omitted from candidate profiles.
* **Verification Method:** `tests/test_security_properties.py` (`test_invariant_4_ledger_audit_fails_on_tampered_trial`).

---

## 3. Scientific Taxonomy of Minimality Claims

To avoid misleading claims in research publications, PoViShield distinguishes four formal levels of syscall policy minimality:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Level 1: Minimality Relative to Observed Traces                        │
│ P_obs = ∪_{w ∈ W_train} traced(w)                                     │
│ (Granted by passive observation; may include dynamic loader noise)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Counterfactual Testing
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Level 2: Minimality Relative to a Finite Workload Suite (W_req)        │
│ ∀ s ∈ P_min : O(w, P_min \ {s}) ≠ O_nat(w) for some w ∈ W_req         │
│ (PROVEN BY POVI SHIELD FOR W_req; load-bearing for specified tasks)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Level 3: Minimality Relative to Workload & Compatibility Oracle        │
│ Accounting for acceptable exit codes, stdout tolerance, and signals.   │
│ (Formally tracked in PoViShield evidence ledgers)                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Level 4: Global Universal Minimality Across All Possible Executions    │
│ ∀ possible input x, ∀ possible code path in program                   │
│ ⚠️ EXPLICITLY NOT CLAIMED (Undecidable in general; Rice's Theorem)      │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Level 1 (Trace-Relative):** The baseline policy contains only syscalls observed during execution. *PoViShield proves that Level 1 policies can still contain unexercised extraneous permissions.*
2. **Level 2 (Suite-Relative):** For every syscall $s \in P_{min}$, withholding $s$ breaks at least one workload in $W_{req}$. **This is the exact property established by PoViShield's counterfactual minimizer.**
3. **Level 3 (Oracle-Relative):** The minimality guarantee depends on the strictness of the compatibility oracle (e.g. byte-for-byte stdout equality vs exit status preservation).
4. **Level 4 (Global Minimality):** Proving that a program will never, under any conceivable input, invoke syscall $s$ is reducible to the Halting Problem and undecidable in the general case. **PoViShield does NOT claim Level 4 minimality.**
