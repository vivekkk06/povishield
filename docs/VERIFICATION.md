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

## Escape matrix (Fedora 44 host, native, root; this host is not a disposable VM)
- rootfs-only: esc_hostfs DENIED, so --rootfs alone confines the host-path read; limit_mem KILLED_BY_LIMIT.
- full+rootfs: every test is a SIGSYS kill; it demonstrates the profile, not the rootfs.
- Capability bounding set is dropped by default (see rootfs-only column); --keep-caps restores the old baseline.
- limit_pids: test fixed to report ESCAPED when the limit does not hold; see matrix.
- Bug fixed: with --profile and no --rootfs the profile was opened after capabilities were dropped, so an absolute path under a 0700 home failed (EACCES). The profile is now opened before any privilege drop.
- esc_ptrace uses PTRACE_TRACEME (unprivileged), so it is a syscall-blocking test, not a containment test; it is excluded from the containment count.
- Containment (rootfs + limits + dropped caps, no seccomp): chroot, hostfs, mount, rawsock, unshare denied; memory limit kills the hog; pids limit stops the fork test.
- Root cause of the 'full' column failure: the sandboxed process is root with no capabilities, so it obeys file permissions and cannot exec binaries under a 0700 $HOME via absolute path. The harness now runs tests from /tmp/ps-escape-bin. Users who run `povishield run` on programs in private directories must use a readable path or --keep-caps.
- exec failure after seccomp load now reports via write(2) with exit 127 (perror's dup() would trigger SIGSYS).
