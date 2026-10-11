# PoViShield threat model

## Goal
Reduce the damage a *buggy or compromised, non-malicious-by-design* program can do, by giving it
the minimum kernel interface it was observed to need (least privilege).

## Layers and what each one actually does
| layer | mechanism | stops | does NOT stop |
|---|---|---|---|
| syscall policy | seccomp-bpf from a learned profile (default: kill) | any syscall never observed during learning | misuse of *allowed* syscalls; arguments are not inspected |
| privileges | no_new_privs, empty bounding/ambient sets, empty capset | operations needing a capability (mount, unshare, raw sockets, ptrace of protected tasks) | operations a plain uid-0 file owner may do |
| filesystem | `pivot_root` into a supplied rootfs | host path access / traversal | anything inside the rootfs |
| resources | cgroup v2 memory.max, pids.max, cpu.max | memory exhaustion, fork bombs, CPU hogging | I/O bandwidth, kernel memory side channels |
| views | PID, mount, UTS, IPC, network namespaces | seeing/signalling host processes, host network | nothing by themselves: root with caps escapes them (see escape matrix, `namespaces` column) |

## Assumptions
x86_64 Linux, cgroup v2, libseccomp >= 2.5, `run` executed as root, kernel is trusted and unpatched
bugs are out of scope.

## Out of scope (do not claim)
Kernel vulnerabilities; user namespaces (CLONE_NEWUSER is not used); argument-level syscall filtering;
TOCTOU on filenames; hardware side channels; a malicious profile author (profiles are trusted input,
but the loader fails closed on malformed ones); learn mode is not safe to run on hostile code.

## Known limitations
- A profile only covers behaviour seen during learning; rare paths (error handling, shutdown) may be killed.
  Mitigation: merge several workloads, use `--audit` first.
- Learner is x86_64 only and ptrace-based (slow).
- Escape results are evidence for the listed tests only, not a proof of security.

## Privileges and operational requirements
- `learn` and `enforce` need no privileges; `run` needs root (namespaces, mounts, cgroups).
- cgroup limits need a writable cgroup v2 hierarchy. A limit that is requested but cannot be applied must stop the run;
  `tests/test_root_runtime.py` checks the limits really bite (memory kill, process cap, CPU throttle) and that the cgroup is removed.
- `--rootfs` must contain everything the target needs. Static binaries are simplest. `tests/test_root_rootfs.py` checks that
  host paths, `..` traversal, `/proc/*/root` and a privileged chroot break-out do not reach the host.
- Capabilities are dropped by default. `--keep-caps` exists for baselines and tests only; never use it for untrusted programs.
- Run every privileged test in a disposable VM (`docs/VM_TESTING.md`).
