# Verification status (2026-10-11)

Environment: Fedora Linux 44 (Workstation), Linux 7.2.8-200.fc44.x86_64,
x86_64, cgroup v2 (cgroup2fs).

## Passed on this host

- `make -B all`: build completed successfully.
- `make lint`: cppcheck completed without errors.
- `make test`: 67 tests discovered; 29 passed and 38 root-required
  tests were skipped in the non-root run.
- `sudo make test-root`: all 38 root-required tests passed.
- `git diff --check`: passed.

These results describe the tests run on this host. They do not guarantee
that every attack, kernel configuration, or execution path is covered.

## Not yet established

- Security validation in a disposable VM or across different host kernels.
- Complete syscall coverage for every program execution path.
- A statistically conclusive performance improvement or regression.
- Protection against every possible sandbox escape.

## Known limitations

- Syscall filtering alone cannot prevent path traversal when permitted
  syscalls allow access to the target path. Use `run --rootfs` for
  filesystem confinement.
- A learning run stopped by `--max-event-bytes` produces an incomplete profile.
- Ptrace-based learning can miss rare or input-dependent execution paths.
- A missing escape marker alone does not prove that a security boundary held.
- Capabilities are dropped by default; `--keep-caps` is a less-restrictive
  option intended for baselines.

## Escape matrix (docs/escape-matrix.txt, 8 tests x 6 configurations)

Results from `sudo make escape-full` on this host:

- `bare` and `namespaces`: all 8 tests escaped.
- `seccomp` only: 2 of 8 escaped (`esc_hostfs`, `limit_mem`); the others
  were terminated by SIGSYS.
- `full`: 1 escape (`esc_hostfs`); `limit_mem` was killed by the memory limit.
- `rootfs-only` and `full+rootfs`: 0 escapes. `esc_hostfs` was denied by
  rootfs confinement; in `full+rootfs` the other syscall-based tests were
  terminated by seccomp, which shows policy enforcement, not rootfs isolation.
- A missing escape marker alone does not prove that a security boundary held.

## Implementation notes (confirmed in source)

- The seccomp profile is opened (`O_CLOEXEC`) before capabilities are
  dropped, so profiles under a private home directory still load.
- A failed `exec` reports the error with `dprintf` to stderr (no `dup()`)
  and exits with status 127.
- The escape harness copies test binaries to `/tmp/ps-escape-bin` (mode 755)
  to avoid unrelated failures caused by private directory permissions.
- Exit codes: 125 for rootfs, `/proc` mount, or privilege-drop failure;
  126 for profile open or seccomp failure; 127 for exec failure.
