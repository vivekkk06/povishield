# PoViShield Threat Model and Security Architecture

## 1. Executive Summary & Purpose

PoViShield is a Linux security research prototype and sandboxing platform designed to investigate **least-privilege seccomp policy generation, counterfactual permission verification, and multi-layered defense-in-depth confinement**.

The primary objective is to **contain and minimize the damage of compromised or buggy application processes** by restricting the kernel and operating system interfaces exposed to them, verifying policy necessity against reproducible evidence, and failing closed under any security anomaly.

> **Status & Intended Use:** PoViShield is a research and benchmarking prototype. It is **not** a production multi-tenant container runtime (e.g., `runc`, `crun`, or `gVisor`). This document explicitly defines the prototype's trust boundaries, threat assumptions, and security limitations.

---

## 2. Assets and Security Objectives

| Asset | Protection Goal | Primary Enforcement Layer |
|:---|:---|:---|
| **Host Kernel Integrity** | Prevent privilege escalation, ring-0 exploitation, and unauthorized kernel subsystem manipulation (`bpf`, `kexec_load`, `reboot`). | Seccomp-BPF allowlist (`SCMP_ACT_KILL_PROCESS`) + Capability dropping (`PR_CAPBSET_DROP`, `capset`). |
| **Host Filesystem** | Prevent unauthorized reads, writes, path traversals, or filesystem tampering outside the designated sandbox. | Private root filesystem via `pivot_root`, `chdir("/")`, and `umount2(..., MNT_DETACH)`. |
| **Host Process Table** | Prevent inspection, signal transmission (`kill`), or process tampering (`ptrace`) directed against host tasks. | PID namespace (`CLONE_NEWPID`), UTS namespace (`CLONE_NEWUTS`), IPC namespace (`CLONE_NEWIPC`). |
| **Host Network Stack** | Prevent unauthorized network communication, C2 beaconing, raw socket crafting, or local interface listening. | Network namespace (`CLONE_NEWNET`, loopback only) + Seccomp socket filtering (`socket`, `connect`, `listen`). |
| **Host Resource Availability** | Prevent denial-of-service via memory exhaustion, CPU starvation, or fork bombs. | cgroup v2 controllers (`memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max`). |
| **Evidence & Policy Integrity** | Prevent undetected tampering with permission ledgers, candidate policies, or verification reports. | SHA-256 cryptographic hashing, append-only JSONL ledgers, and pre-enforcement safety gate. |

---

## 3. Attacker Capabilities & Threat Profiles

PoViShield models three distinct threat profiles:

### Threat Profile A: Compromised Workload (In-Scope Primary Threat)
- **Attacker State:** The target application has suffered a memory-corruption flaw (e.g., buffer overflow, ROP, use-after-free) or arbitrary code execution (ACE) vulnerability during runtime.
- **Capabilities:** The attacker can execute arbitrary machine code within the memory space of the target process and invoke arbitrary Linux system calls.
- **Assumed Objective:** The attacker attempts to establish reverse shells, read `/etc/shadow`, mount host filesystems, spawn child processes, or exploit kernel vulnerabilities.
- **Containment:** System calls outside the allowed set trigger immediate process termination via kernel `SIGSYS`. Capabilities are zeroed, and namespaces isolate filesystem and network views.

### Threat Profile B: Over-Privileged Baseline Policy (In-Scope Verification Target)
- **Attacker State:** Build scripts, upstream packages, or generic templates introduce extraneous high-risk permissions (e.g., `mount`, `ptrace`, `bpf`) that the isolated application workload never exercises.
- **Objective:** Exploit the excessive permissions if the application is subsequently compromised.
- **Mitigation:** PoViShield's counterfactual minimization engine challenges every permission via leave-one-out seccomp execution, pruning 100% of unexercised extraneous permissions while verifying that legitimate application tasks remain 100% functional.

### Threat Profile C: Malicious Training Code (Out-of-Scope Threat)
- **Attacker State:** Untrusted, malicious code supplied to `povishield learn`.
- **Constraint:** `povishield learn` uses `ptrace(2)` for passive observation. A malicious binary being traced could attempt to evade detection, manipulate registers, or trigger anti-tracing techniques.
- **Rule:** `povishield learn` must **only** be executed against trusted code during policy synthesis.

---

## 4. Trust Boundaries & Components

```
┌────────────────────────────────────────────────────────────────────────┐
│                        UNTRUSTED WORKLOAD                              │
│  Target binary (e.g., /usr/bin/cat, python script, server workload)    │
│  Dynamically loaded libraries (glibc, libm, etc.)                     │
│  Child processes spawned by workload                                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Invokes syscalls
════════════════════════════════════╪═════════════════════════════════════  [BOUNDARY 1]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     KERNEL SECCOMP-BPF ENGINE                          │
│  Strict Allowlist: SCMP_ACT_KILL_PROCESS on any unknown syscall        │
│  Enforced unconditionally by kernel before syscall handler execution    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Allowed syscalls only
════════════════════════════════════╪═════════════════════════════════════  [BOUNDARY 2]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     LINUX ISOLATION & CGROUP V2                        │
│  Namespaces: PID (pid 1), MNT (pivot_root), UTS, IPC, NET (loopback)   │
│  Capabilities: Effective=0, Permitted=0, Inheritable=0, Bounding=0     │
│  Resource Budgets: memory.max, memory.swap.max=0, pids.max, cpu.max    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
════════════════════════════════════╪═════════════════════════════════════  [BOUNDARY 3]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       TRUSTED HOST KERNEL & OS                         │
│  Linux Host Kernel (>= 5.8, x86_64), cgroup v2 hierarchy               │
│  Root Supervisor (povishield run) parent process                       │
└────────────────────────────────────────────────────────────────────────┘
```

### Trusted Computing Base (TCB)
1. **Linux Host Kernel:** Assumed to be non-compromised and executing bug-free implementations of seccomp, namespaces, and cgroups.
2. **`libseccomp` Library:** Assumed to correctly compile allowlist rules into BPF bytecode.
3. **Supervisor Process (`povishield run`):** Parent process running with root privileges responsible for configuring namespaces, cgroups, and mounting the private rootfs before dropping privileges.

### Untrusted Components
1. **The Sandboxed Target Binary and Libraries:** Treated as potentially hostile post-initialization.
2. **Policy Profile Files:** Treated as untrusted inputs by the seccomp loader; parsed with a strict fail-closed state machine rejecting invalid characters, overlong names, or unknown syscalls.

---

## 5. Security Invariants & Fail-Closed Behavior

PoViShield enforces a strict **fail-closed** paradigm across all subsystems:

1. **Seccomp Fail-Closed Invariant:**
   - Default filter action is `SCMP_ACT_KILL_PROCESS`. Any syscall not explicitly allowlisted results in kernel delivery of `SIGSYS` (exit code `-31` or `159`).
   - If the allowlist is empty, policy compilation fails immediately with an error (preventing accidental denial-of-service).
   - If an unknown system call name is encountered in the profile, policy compilation fails immediately.
   - `PR_SET_NO_NEW_PRIVS` is set prior to `seccomp_load`.

2. **Initialization Fail-Closed Invariant:**
   - If any configuration parameter (`--mem`, `--pids`, `--cpu`) cannot be parsed as a strictly positive integer within limits, the supervisor aborts with exit code `2` before creating the child process.
   - If cgroup controllers cannot be enabled, or the cgroup directory cannot be created, the supervisor aborts.
   - The child process blocks on a synchronization pipe until the parent has verified cgroup limits and namespace creation. If parent aborts, child reads EOF and calls `_exit(125)` before reaching `execve`.

3. **Capability Dropping Invariant:**
   - The bounding capability set is completely dropped (`PR_CAPBSET_DROP` for caps 0..63).
   - Ambient capabilities are cleared (`PR_CAP_AMBIENT_CLEAR_ALL`).
   - `capset(2)` is invoked to clear effective, permitted, and inheritable capability sets.
   - If capability dropping fails, the child calls `_exit(125)` and never invokes the target.

4. **File Descriptor Isolation:**
   - The profile file descriptor is opened with `O_CLOEXEC` prior to `pivot_root`.
   - The synchronization pipe write end is closed in the child, and read end is closed before execution.
   - Target inherits only standard I/O streams ($0, 1, 2$).

---

## 6. Prevention vs. Detection vs. Containment vs. Evidence

To maintain research honesty, PoViShield clearly separates security properties into four distinct categories:

| Category | Definition | PoViShield Mechanism | Examples |
|:---|:---|:---|:---|
| **Prevention** | Active blocking that makes an operation impossible before it can execute. | Seccomp allowlist filter (`KILL_PROCESS`) and dropped Linux capabilities. | Attempting `mount`, `socket`, or `ptrace` is stopped with `SIGSYS` or `EPERM`. |
| **Containment** | Confining the blast radius if an operation is permitted. | Namespaces (`PID`, `MNT`, `NET`) and cgroup v2 limits. | File operations are confined to private rootfs; memory allocation capped at 256 MiB. |
| **Detection** | Observing and alerting on behavior without terminating execution. | Seccomp audit mode (`SCMP_ACT_LOG`) and live ptrace event monitoring. | Emitting JSONL event records when unlearned syscalls are invoked. *(Detection is NOT claimed as prevention).* |
| **Post-Event Evidence** | Reproducible, immutable proof explaining decisions and trials. | Evidence ledgers (`analysis/ledger.py`) with SHA-256 hashes and reproduction CLI commands. | Cryptographic verification that ablated `write` broke `grep` via exit code `-31`. |

---

## 7. Explicit Non-Goals & Limitations (What We Do Not Protect Against)

1. **Syscall Argument Pointer Dereferencing:**
   - Classic seccomp-bpf inspects register values and syscall numbers. It **cannot** safely dereference userspace memory pointers (e.g., verifying whether `openat(..., path, ...)` refers to `/tmp` vs `/etc/passwd`). Path-based access control must be enforced via filesystem permissions and rootfs boundaries.
2. **Exploits within Permitted Syscalls:**
   - If an application is granted `write` and `poll`, an attacker exploiting an application flaw to send malicious application-level payloads over an open socket is outside the seccomp boundary.
3. **Kernel Zero-Day Vulnerabilities:**
   - If a permitted syscall contains an unpatched local privilege escalation vulnerability in the host Linux kernel, seccomp cannot prevent kernel exploitation through that specific syscall.
4. **Hardware and Microarchitectural Side Channels:**
   - Timing attacks, Spectre/Meltdown, and CPU cache side-channels are out of scope.
5. **Universal Policy Minimality:**
   - PoViShield minimizes policies relative to a finite workload suite $W_{req}$. It does **not** guarantee global minimality across all conceivable code paths or input flags.
