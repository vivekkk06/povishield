import React, { useEffect, useState, useRef } from "react";

const AMBIENT_LOGS = [
  "[INIT] PoViShield security supervisor initializing...",
  "[KERNEL] Linux kernel 7.2.8-200.fc44.x86_64 (x86_64) verified",
  "[SUBSYS] PTRACE_SYSCALL dynamic tracer loaded (build/povishield)",
  "[SECCOMP] BPF filter engine active (action: SCMP_ACT_KILL_PROCESS)",
  "[PRIV] PR_SET_NO_NEW_PRIVS execution barrier enforced",
  "[PROFILE] 9 empirical system call profiles loaded from results/profiles/",
  "[GATE] Safety gate: fail-closed ledger audit active (approvals.jsonl)",
  "[LEDGER] Evidence ablation verification: counterfactual trials indexed",
  "[MONITOR] Local runtime event stream ready on loopback interface",
  "[AUDIT] Tamper detection active: SHA-256 integrity verifier armed",
  "[RULE] Non-expansion invariant: unobserved syscalls blocked fail-closed",
  "[TELEMETRY] Listening for sandboxed process execution vectors...",
  "[READY] PoViShield security operations console standing by",
];

export default function TerminalBackground() {
  const [lines, setLines] = useState(AMBIENT_LOGS.slice(0, 7));
  const [isPaused, setIsPaused] = useState(false);
  const logIndex = useRef(7);

  useEffect(() => {
    // Respect user's motion preferences
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) return;

    // Handle tab visibility to save CPU
    const handleVisibility = () => {
      setIsPaused(document.visibilityState === "hidden");
    };
    document.addEventListener("visibilitychange", handleVisibility);

    const interval = setInterval(() => {
      if (document.visibilityState === "hidden") return;

      const nextLog = AMBIENT_LOGS[logIndex.current % AMBIENT_LOGS.length];
      logIndex.current += 1;
      const ts = (performance.now() / 1000).toFixed(4);
      const formatted = `[+${ts}s] ${nextLog}`;

      setLines((prev) => [...prev.slice(-14), formatted]);
    }, 2800);

    return () => {
      clearInterval(interval);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, []);

  return (
    <div className="terminal-ambient-bg" aria-hidden="true">
      <div className="terminal-ambient-grid" />
      <div className="terminal-ambient-content">
        <div className="terminal-ambient-header">
          <span className="dot dot-green" />
          <span className="dot dot-amber" />
          <span className="dot dot-cyan" />
          <span className="terminal-ambient-title">POVISHIELD_KERNEL_TELEMETRY // LIVE RUNTIME SUPERVISOR</span>
        </div>
        <div className="terminal-ambient-logs">
          {lines.map((line, idx) => (
            <div key={idx} className="terminal-ambient-line">
              <span className="ambient-prefix">&gt;</span> {line}
            </div>
          ))}
          <div className="terminal-ambient-cursor">
            <span className="cursor-block">_</span>
          </div>
        </div>
      </div>
    </div>
  );
}
