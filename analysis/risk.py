"""Attack-surface risk scoring.

Weights are a documented heuristic based on the man pages and on the syscalls that
Docker's default seccomp profile withholds from containers. They are NOT ground truth;
cite and justify any change in docs/ARCHITECTURE.md.
Score = sum(weight of allowed syscalls) / sum(weight of ALL syscalls) * 100
"""
import argparse
if __package__ is None or __package__ == "":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from analysis.common import load_profile, total_syscalls
else:
    from .common import load_profile, total_syscalls

CRITICAL = """ptrace mount umount2 unshare setns init_module finit_module delete_module bpf kexec_load
kexec_file_load pivot_root chroot reboot swapon swapoff iopl ioperm perf_event_open userfaultfd
process_vm_readv process_vm_writev open_by_handle_at keyctl add_key request_key acct settimeofday
clock_settime syslog""".split()
HIGH = """execve execveat clone clone3 fork vfork setuid setgid setreuid setregid setresuid setresgid
setgroups chmod fchmod fchmodat chown fchown lchown fchownat socket connect bind listen accept accept4
sendto sendmsg kill tkill tgkill prctl capset mknod mknodat symlink link personality""".split()
MEDIUM = "mprotect mremap shmget shmat shmctl unlink unlinkat rename renameat renameat2 truncate ftruncate".split()
LOW = """read write close brk fstat newfstatat lseek exit exit_group rt_sigaction rt_sigprocmask
rt_sigreturn getpid gettid getuid getgid geteuid getegid futex nanosleep clock_gettime clock_nanosleep
getrandom set_tid_address set_robust_list rseq arch_prctl uname""".split()

WEIGHTS = {}
for names, w in ((LOW, 1), (MEDIUM, 4), (HIGH, 7), (CRITICAL, 10)):
    for n in names:
        WEIGHTS[n] = w
DEFAULT = 2


def weight(name):
    return WEIGHTS.get(name, DEFAULT)


def risk_pct(allowed, total):
    """Normalised 0-100 risk of an allowed-syscall set; all-allowed == 100."""
    max_risk = sum(WEIGHTS.values()) + DEFAULT * max(total - len(WEIGHTS), 0)
    return 100.0 * sum(weight(s) for s in allowed) / max_risk


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("profile")
    ap.add_argument("--total", type=int, default=None)
    a = ap.parse_args()
    total = a.total or total_syscalls()
    s = load_profile(a.profile)
    print(f"allowed={len(s)}/{total}  attack-surface-reduction={(1-len(s)/total)*100:.1f}%  "
          f"risk: 100.0 -> {risk_pct(s, total):.1f}")
