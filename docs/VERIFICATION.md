# Verification status (2026-10-10)
Environment: Linux 7.2.8-200.fc44.x86_64 x86_64, Fedora Linux 44 (Workstation Edition), cgroup fs: cgroup2fs

## Passed (this host, native)
- Build with -Wall -Wextra: no warnings. Unit tests: 6/6.
- CLI validation: invalid --max-event-bytes / --mem / --pids / --cpu / --rootfs rejected with exit 2.
- learn: valid profile + event log JSON; byte cap stops tracing (exit 75); unwritable output fails (exit 1).
- run: SIGINT -> 130 and SIGTERM -> 143 with child killed and cgroup removed; memory limit enforced (OOM kill, exit 137); pids limit enforced (fork EAGAIN); no leftover cgroups.

## Not yet verified
- rootfs isolation (needs disposable VM), escape suite with --rootfs,
  why the 'namespaces' escape column blocked nothing, seccomp overhead variance (31.6% vs 48.4% across runs).

## Known limitations
- Syscall filtering cannot stop path traversal (esc_hostfs); use run --rootfs.
- A learn run stopped by --max-event-bytes yields an incomplete profile.
