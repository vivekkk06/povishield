# Security Policy

## Reporting Security Issues

PoViShield is a Linux security research prototype. We take security vulnerabilities seriously and welcome responsible disclosure of confirmed issues.

If you discover a security vulnerability, privilege escalation, sandbox escape, or defect within PoViShield's sandboxing runtime or policy engine, please report it via private disclosure rather than opening a public issue.

### Reporting Procedure
- Contact the project maintainers via email or private GitHub Security Advisory.
- Provide a detailed description of the vulnerability, including:
  - Affected component (`src/runtime/`, `src/policy/`, `src/tracer/`, or `api/`).
  - Target environment (kernel version, architecture, distribution).
  - Reproducible proof-of-concept (PoC) code or command sequence.
  - Expected vs. actual behavior.

### Scope of Security Evaluations
The following are considered **in-scope** security findings:
- Execution of target commands without intended seccomp filters or namespace confinement due to initialization flaws.
- Sandbox breakouts allowing an unprivileged child process to access host files outside `--rootfs`.
- Failure of resource limits or cgroups to be applied when requested.
- Untrusted input causing memory corruption or unauthorized execution in `povishield` supervisor binaries.
- Remote or cross-origin access to the local monitoring API outside loopback bounds.

The following are **out-of-scope** and explicitly documented research limitations:
- Exploits operating entirely within the permitted syscall allowlist without attempting withheld operations.
- Kernel zero-day vulnerabilities inside the host Linux kernel itself.
- Hardware side-channel attacks (e.g., Spectre, Meltdown, Rowhammer).
- Circumvention of seccomp argument inspection for pointer arguments (classic seccomp-bpf does not inspect memory pointers).
- Running `povishield learn` on hostile code (tracing is intended for trusted workloads during policy synthesis).

## Supported Versions

| Version | Supported |
|:---|:---:|
| Current Master (`master`) | :white_check_mark: |
