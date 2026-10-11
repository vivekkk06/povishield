# Escape matrix analysis

Run: `sudo make escape-full` (inside a disposable VM for final results, see `docs/VM_TESTING.md`).
The matrix is saved to `docs/escape-matrix.txt` and embedded in `docs/RESULTS.md`.

## Columns (what each configuration adds)
| column | configuration |
|---|---|
| bare | the test program, unconfined |
| seccomp | `povishield enforce` with a profile learned from a harmless program |
| namespaces | `povishield run --keep-caps` (namespaces only, root keeps all capabilities) |
| full | `run` with cgroup limits, seccomp profile and default capability dropping |
| full+rootfs | `full` plus `--rootfs` (static test binary inside a minimal root) |
| rootfs-only | `run --rootfs` with caps dropped but **no** seccomp profile |

## Statuses
`ESCAPED` means the attempted privileged action **succeeded** in that configuration (the program printed its marker).
It is a statement about that one action, not proof of a full host compromise.
`BLOCKED_SIGSYS`: killed by seccomp. `DENIED`: the call failed (for example `EPERM`, or the path does not exist).
`KILLED_BY_LIMIT`: stopped by a cgroup limit. A missing marker is **not** proof of a block; the runner validates each
configuration with a harmless control program, and every kill was cross-checked in the audit log
(`sudo ausearch -m SECCOMP -i`), which names the syscall that triggered it.

## Reading the cells
| test | what it attempts | unconfined | why the strongest column stops it |
|---|---|---|---|
| esc_mount | mount a tmpfs | ESCAPED | seccomp (`mount` never learned); also capabilities dropped |
| esc_chroot | `chroot()` | ESCAPED | seccomp; also capabilities dropped |
| esc_unshare | `unshare(CLONE_NEWNS)` | ESCAPED | seccomp; also capabilities dropped |
| esc_rawsock | `AF_PACKET` raw socket | ESCAPED | seccomp; also capabilities dropped |
| esc_ptrace | `PTRACE_ATTACH` to a non-dumpable sibling (needs `CAP_SYS_PTRACE`) | ESCAPED | seccomp; capabilities dropped (rootfs-only column shows `DENIED` without seccomp) |
| esc_hostfs | open `/proc/1/root/etc/hostname` | ESCAPED | **only a new root helps**: it stays ESCAPED in every column without `--rootfs` |
| limit_mem | touch 300 MB | ESCAPED | cgroup memory limit (KILLED_BY_LIMIT) |
| limit_pids | create 200 children | ESCAPED | seccomp kills `clone`; the pids cap itself shows in the rootfs-only column |

## Important lessons recorded here
- Namespaces without dropped capabilities blocked **nothing** (8/8 ESCAPED). A root process with capabilities is not contained by them.
- Seccomp from a learned profile does not stop filesystem access (`esc_hostfs`) or memory abuse; those need a root change and cgroups.
- Capability dropping and seccomp are independent layers. `rootfs-only` shows the capability layer working alone;
  `seccomp` shows the syscall layer alone. `tests/test_root_runtime.py` proves the capability layer with a control
  (`--keep-caps` flips the same attempt from denied to allowed).
- An early `full+rootfs` run reported SIGSYS for every test, including the resource-limit ones. The audit log showed the
  profile was too narrow and killed the static binaries at start-up (`openat`, `mmap`, `rt_sigprocmask`). The runner
  now builds a merged profile and the audit log confirms each kill is on the intended syscall.

## Not claimed
Kernel vulnerabilities, user namespaces, argument-level syscall filtering, side channels and the information
`/proc/self/mountinfo` may reveal inside the sandbox are out of scope (see `docs/THREAT_MODEL.md`).
