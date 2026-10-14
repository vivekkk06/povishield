import React, { useState, useEffect } from "react";
import {
  FileText, GitCompare, ShieldCheck, ShieldAlert, CheckCircle2,
  AlertTriangle, Copy, Check, Download, Search, RefreshCw,
  Plus, Eye, Terminal, ArrowRight, X, Layers, Activity, Lock, Cpu
} from "lucide-react";

export function getSyscallCategory(name) {
  if ([
    "read", "write", "openat", "open", "close", "fstat", "newfstatat", "stat", "lstat",
    "statx", "ioctl", "lseek", "pread64", "pwrite64", "getdents64", "getdents",
    "access", "faccessat", "faccessat2", "dup", "dup2", "dup3", "pipe", "pipe2",
    "fcntl", "readlink", "readlinkat", "statfs", "fstatfs"
  ].includes(name)) return "File I/O";

  if (["mmap", "mprotect", "munmap", "brk", "madvise", "mremap", "msync", "mlock", "munlock"].includes(name)) {
    return "Memory";
  }

  if ([
    "execve", "execveat", "clone", "clone3", "fork", "vfork", "exit_group", "exit",
    "wait4", "waitid", "arch_prctl", "set_tid_address", "rseq", "getpid", "getppid",
    "gettid", "set_robust_list", "get_robust_list", "prlimit64", "getrlimit", "setrlimit"
  ].includes(name)) return "Process";

  if ([
    "socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom",
    "recvmsg", "sendmsg", "shutdown", "getsockname", "getpeername", "getsockopt", "setsockopt"
  ].includes(name)) return "Network";

  if ([
    "ptrace", "mount", "umount2", "bpf", "setns", "unshare", "capset", "capget",
    "prctl", "seccomp", "reboot", "sysfs", "iopl", "ioperm", "kexec_load"
  ].includes(name)) return "Privileged";

  return "System";
}

const COMMON_SYSCALL_PRESETS = [
  { name: "read", cat: "File I/O" },
  { name: "write", cat: "File I/O" },
  { name: "openat", cat: "File I/O" },
  { name: "close", cat: "File I/O" },
  { name: "fstat", cat: "File I/O" },
  { name: "newfstatat", cat: "File I/O" },
  { name: "lseek", cat: "File I/O" },
  { name: "ioctl", cat: "File I/O" },
  { name: "mmap", cat: "Memory" },
  { name: "mprotect", cat: "Memory" },
  { name: "munmap", cat: "Memory" },
  { name: "brk", cat: "Memory" },
  { name: "execve", cat: "Process" },
  { name: "exit_group", cat: "Process" },
  { name: "arch_prctl", cat: "Process" },
  { name: "set_tid_address", cat: "Process" },
  { name: "rseq", cat: "Process" },
  { name: "futex", cat: "System" },
  { name: "rt_sigaction", cat: "System" },
  { name: "rt_sigprocmask", cat: "System" },
  { name: "getrandom", cat: "System" },
  { name: "socket", cat: "Network" },
  { name: "connect", cat: "Network" },
  { name: "ptrace", cat: "Privileged" }
];

export default function PolicyExplorer({
  API,
  policies,
  onRefresh,
  compareBase,
  setCompareBase,
  compareCand,
  setCompareCand,
  compareResult,
  compareLoading,
  compareError,
  runCompare
}) {
  const [activeTab, setActiveTab] = useState("matrix"); // "matrix", "verify", "catalog", "builder"
  const [matrixSearch, setMatrixSearch] = useState("");
  const [matrixStatusFilter, setMatrixStatusFilter] = useState("all"); // "all", "removed", "added", "kept"
  const [matrixCategoryFilter, setMatrixCategoryFilter] = useState("all");

  // Selected policy deep inspector drawer
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [catalogSearch, setCatalogSearch] = useState("");
  const [drawerTab, setDrawerTab] = useState("pills"); // "pills", "table", "raw"
  const [drawerSyscallSearch, setDrawerSyscallSearch] = useState("");
  const [copiedPillText, setCopiedPillText] = useState(false);
  const [copiedJsonText, setCopiedJsonText] = useState(false);

  // Safety Gate Verification State
  const [verifyCand, setVerifyCand] = useState("");
  const [verifyActive, setVerifyActive] = useState("");
  const [verifyRegCmd, setVerifyRegCmd] = useState("grep --help");
  const [verifyAdvCmd, setVerifyAdvCmd] = useState("uname -a");
  const [verifyRunning, setVerifyRunning] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifyError, setVerifyError] = useState("");
  const [requestingApproval, setRequestingApproval] = useState(false);
  const [approvalFeedback, setApprovalFeedback] = useState("");

  // Policy Builder State
  const [builderName, setBuilderName] = useState("");
  const [builderCommand, setBuilderCommand] = useState("");
  const [builderSyscalls, setBuilderSyscalls] = useState(new Set(["read", "write", "openat", "close", "fstat", "mmap", "mprotect", "brk", "exit_group"]));
  const [builderCustomInput, setBuilderCustomInput] = useState("");
  const [builderSaving, setBuilderSaving] = useState(false);
  const [builderFeedback, setBuilderFeedback] = useState("");
  const [builderError, setBuilderError] = useState("");

  // Synchronize initial verification selectors
  useEffect(() => {
    if (policies?.items?.length) {
      if (!verifyCand) {
        const cand = policies.items.find(i => i.name.includes("counterfactual") || i.name.includes("candidate"));
        setVerifyCand(cand ? cand.name : policies.items[0].name);
      }
      if (!verifyActive) {
        const act = policies.items.find(i => i.name === "grep.json" || i.name.includes("baseline"));
        setVerifyActive(act ? act.name : policies.items[0].name);
      }
    }
  }, [policies]);

  const copyToClipboard = (text, type = "pill") => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      if (type === "pill") {
        setCopiedPillText(true);
        setTimeout(() => setCopiedPillText(false), 2000);
      } else {
        setCopiedJsonText(true);
        setTimeout(() => setCopiedJsonText(false), 2000);
      }
    }
  };

  const handleApplyPresetPair = (baseName, candName) => {
    setCompareBase(baseName);
    setCompareCand(candName);
    runCompare(baseName, candName);
  };

  // Run Safety Gate Verification endpoint
  const handleRunVerify = async () => {
    if (!verifyCand) {
      setVerifyError("Please choose a candidate policy to verify.");
      return;
    }
    setVerifyRunning(true);
    setVerifyError("");
    setVerifyResult(null);
    setApprovalFeedback("");
    try {
      const res = await fetch(`${API}/policies/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          candidate: verifyCand,
          active: verifyActive || undefined,
          regression_command: verifyRegCmd,
          adversarial_command: verifyAdvCmd,
          target_name: verifyCand.replace(/\.json$/, "").replace(/_counterfactual|_candidate/, "")
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Server returned ${res.status}`);
      setVerifyResult(data);
    } catch (err) {
      setVerifyError(err.message || "Failed to execute policy safety gate verification");
    } finally {
      setVerifyRunning(false);
    }
  };

  // Submit Verified Candidate for Operator Approval
  const handleSubmitApproval = async () => {
    if (!verifyResult || !verifyCand) return;
    setRequestingApproval(true);
    setApprovalFeedback("");
    try {
      const targetName = verifyResult.target || verifyCand.replace(/\.json$/, "");
      const res = await fetch(`${API}/approvals/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetName,
          candidate: verifyCand,
          command: verifyRegCmd ? verifyRegCmd.split(" ") : [targetName],
          mode: "approval-required",
          rationale: `Safety gate certified candidate (${verifyResult.allowed_count} syscalls, risk score ${verifyResult.risk_score}%, regression passed)`
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
      setApprovalFeedback(`✓ Approval request enqueued successfully (ID: ${data.id}). Check Safety Gate & Approvals tab.`);
      if (onRefresh) onRefresh();
    } catch (err) {
      setApprovalFeedback(`Failed: ${err.message}`);
    } finally {
      setRequestingApproval(false);
    }
  };

  // Handle saving new custom policy
  const handleSaveCustomPolicy = async () => {
    if (!builderName.trim()) {
      setBuilderError("Please provide a policy name.");
      return;
    }
    if (builderSyscalls.size === 0) {
      setBuilderError("Please select at least one permitted system call.");
      return;
    }
    setBuilderSaving(true);
    setBuilderError("");
    setBuilderFeedback("");
    try {
      const res = await fetch(`${API}/policies/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: builderName.trim(),
          command: builderCommand.trim() || undefined,
          syscalls: Array.from(builderSyscalls)
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Save failed (${res.status})`);
      setBuilderFeedback(`✓ Policy "${data.name}" successfully generated with ${data.count} allowed syscalls.`);
      if (onRefresh) onRefresh();
    } catch (err) {
      setBuilderError(err.message || "Failed to save policy profile");
    } finally {
      setBuilderSaving(false);
    }
  };

  const handleAddCustomSyscall = () => {
    if (!builderCustomInput.trim()) return;
    const parts = builderCustomInput.split(/[\s,]+/).filter(Boolean);
    setBuilderSyscalls(prev => {
      const next = new Set(prev);
      parts.forEach(p => next.add(p.toLowerCase().replace(/^sys_/, "")));
      return next;
    });
    setBuilderCustomInput("");
  };

  // Clone from existing policy into builder
  const handleClonePolicy = (item) => {
    if (!item?.data?.syscalls) return;
    setBuilderName(`${item.name.replace(/\.json$/, "")}_custom`);
    setBuilderCommand(item.data.command || "");
    setBuilderSyscalls(new Set(item.data.syscalls));
    setActiveTab("builder");
    setBuilderFeedback(`Cloned ${item.data.syscalls.length} syscalls from "${item.name}". Customize below and save.`);
  };

  // Build unified syscall comparison list for Comparator matrix
  const compareSyscallRows = React.useMemo(() => {
    if (!compareResult) return [];
    const baseSet = new Set(policies?.items?.find(i => i.name === compareBase)?.data?.syscalls || []);
    const candSet = new Set(policies?.items?.find(i => i.name === compareCand)?.data?.syscalls || []);

    const tiers = compareResult.permission_tiers || {};
    const necessarySet = new Set(tiers.experimentally_necessary || []);
    const removableSet = new Set(tiers.removable_for_tested_tasks || []);
    const unvalidatedSet = new Set(tiers.not_yet_validated || []);

    const allSyscalls = Array.from(new Set([...baseSet, ...candSet])).sort();

    return allSyscalls.map(name => {
      const inBase = baseSet.has(name);
      const inCand = candSet.has(name);
      const category = getSyscallCategory(name);

      let status = "kept";
      if (inBase && !inCand) status = "removed";
      if (!inBase && inCand) status = "added";

      let tier = "untiered";
      if (necessarySet.has(name)) tier = "Tier 1: Necessary";
      else if (removableSet.has(name)) tier = "Tier 2: Removable";
      else if (unvalidatedSet.has(name)) tier = "Tier 3: Unvalidated";

      return { name, category, inBase, inCand, status, tier };
    });
  }, [compareResult, policies, compareBase, compareCand]);

  const filteredMatrixRows = compareSyscallRows.filter(row => {
    if (matrixStatusFilter !== "all" && row.status !== matrixStatusFilter) return false;
    if (matrixCategoryFilter !== "all" && row.category !== matrixCategoryFilter) return false;
    if (matrixSearch && !row.name.toLowerCase().includes(matrixSearch.toLowerCase())) return false;
    return true;
  });

  // Calculate category stats for selected policy in deep inspection drawer
  const selectedPolicyCategoryStats = React.useMemo(() => {
    if (!selectedPolicy?.data?.syscalls) return [];
    const counts = {};
    selectedPolicy.data.syscalls.forEach(s => {
      const cat = getSyscallCategory(s);
      counts[cat] = (counts[cat] || 0) + 1;
    });
    const total = selectedPolicy.data.syscalls.length || 1;
    return Object.entries(counts).map(([cat, count]) => ({
      category: cat,
      count,
      pct: Math.round((count / total) * 100)
    })).sort((a, b) => b.count - a.count);
  }, [selectedPolicy]);

  return (
    <div className="policy-explorer-container" style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* Sub-navigation tabs */}
      <div className="policy-tabs-bar" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #1e293b", paddingBottom: 12, flexWrap: "wrap", gap: 10 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            className={`secondary-button ${activeTab === "matrix" ? "active-tab-btn" : ""}`}
            onClick={() => setActiveTab("matrix")}
            style={{
              padding: "7px 14px", fontSize: 12, display: "flex", alignItems: "center", gap: 6,
              background: activeTab === "matrix" ? "#0c2d48" : "transparent",
              borderColor: activeTab === "matrix" ? "#0284c7" : "#1e293b",
              color: activeTab === "matrix" ? "#38bdf8" : "#94a3b8"
            }}
          >
            <GitCompare size={14} /> Comparator & Diff Matrix
          </button>
          <button
            type="button"
            className={`secondary-button ${activeTab === "verify" ? "active-tab-btn" : ""}`}
            onClick={() => setActiveTab("verify")}
            style={{
              padding: "7px 14px", fontSize: 12, display: "flex", alignItems: "center", gap: 6,
              background: activeTab === "verify" ? "#064e3b" : "transparent",
              borderColor: activeTab === "verify" ? "#059669" : "#1e293b",
              color: activeTab === "verify" ? "#34d399" : "#94a3b8"
            }}
          >
            <ShieldCheck size={14} /> Safety Gate Policy Verifier
          </button>
          <button
            type="button"
            className={`secondary-button ${activeTab === "catalog" ? "active-tab-btn" : ""}`}
            onClick={() => setActiveTab("catalog")}
            style={{
              padding: "7px 14px", fontSize: 12, display: "flex", alignItems: "center", gap: 6,
              background: activeTab === "catalog" ? "#1e1b4b" : "transparent",
              borderColor: activeTab === "catalog" ? "#6366f1" : "#1e293b",
              color: activeTab === "catalog" ? "#a5b4fc" : "#94a3b8"
            }}
          >
            <Layers size={14} /> Policy Catalog ({policies?.items?.length || 0})
          </button>
          <button
            type="button"
            className={`secondary-button ${activeTab === "builder" ? "active-tab-btn" : ""}`}
            onClick={() => setActiveTab("builder")}
            style={{
              padding: "7px 14px", fontSize: 12, display: "flex", alignItems: "center", gap: 6,
              background: activeTab === "builder" ? "#2a1538" : "transparent",
              borderColor: activeTab === "builder" ? "#9333ea" : "#1e293b",
              color: activeTab === "builder" ? "#c084fc" : "#94a3b8"
            }}
          >
            <Plus size={14} /> Custom Policy Builder
          </button>
        </div>

        {onRefresh && (
          <button
            className="secondary-button"
            onClick={onRefresh}
            style={{ padding: "6px 12px", fontSize: 11, display: "flex", alignItems: "center", gap: 5 }}
          >
            <RefreshCw size={12} /> Refresh Policies
          </button>
        )}
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: Comparator & Syscall Diff Matrix */}
      {/* ========================================================================= */}
      {activeTab === "matrix" && (
        <>
          <section className="panel">
            <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 16 }}>Side-by-Side Policy Comparator</h3>
                <p style={{ margin: "4px 0 0", fontSize: 12, color: "#94a3b8" }}>
                  Empirically compare a baseline profile against an ablated candidate policy to measure attack surface reduction and permission tiers.
                </p>
              </div>
              <GitCompare size={20} className="muted-icon" />
            </div>

            {/* Quick Preset Selector Buttons */}
            <div style={{ margin: "14px 0 16px", display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: 11, color: "#64748b", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                QUICK BENCHMARK PAIRS:
              </span>
              {[
                { label: "grep (Coreutils)", base: "grep.json", cand: "grep_counterfactual.json" },
                { label: "sed (Stream Editor)", base: "sed.json", cand: "sed_counterfactual.json" },
                { label: "gzip (Compression)", base: "gzip.json", cand: "gzip_counterfactual.json" },
                { label: "curl (Network)", base: "curl.json", cand: "curl_counterfactual.json" },
                { label: "python (Runtime)", base: "python.json", cand: "python_counterfactual.json" },
                { label: "node (JS V8)", base: "node.json", cand: "node_counterfactual.json" },
              ].map((p, idx) => {
                const isSelected = compareBase === p.base && compareCand === p.cand;
                return (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleApplyPresetPair(p.base, p.cand)}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 5, cursor: "pointer",
                      background: isSelected ? "#0c2d48" : "#070d1a",
                      color: isSelected ? "#38bdf8" : "#94a3b8",
                      border: "1px solid",
                      borderColor: isSelected ? "#0284c7" : "#1e293b",
                      fontFamily: "var(--font-mono)"
                    }}
                  >
                    {p.label}
                  </button>
                );
              })}
            </div>

            {/* Dropdown Selectors */}
            <div className="comparator-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
              <div className="compare-select-card" style={{ background: "#050914", padding: "12px 14px", borderRadius: 8, border: "1px solid #1e293b" }}>
                <label style={{ fontSize: 11, fontWeight: 700, color: "#94a3b8", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                  Baseline Policy (Pre-Ablation Active Target)
                </label>
                <select
                  value={compareBase}
                  onChange={e => { setCompareBase(e.target.value); runCompare(e.target.value, compareCand); }}
                  style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12 }}
                >
                  {policies?.items?.map(item => (
                    <option key={`base-${item.name}`} value={item.name}>
                      {item.name} ({item.count} syscalls)
                    </option>
                  ))}
                </select>
              </div>

              <div className="compare-select-card" style={{ background: "#050914", padding: "12px 14px", borderRadius: 8, border: "1px solid #1e293b" }}>
                <label style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                  Candidate Policy (Evidence-Backed Minimization)
                </label>
                <select
                  value={compareCand}
                  onChange={e => { setCompareCand(e.target.value); runCompare(compareBase, e.target.value); }}
                  style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12 }}
                >
                  {policies?.items?.map(item => (
                    <option key={`cand-${item.name}`} value={item.name}>
                      {item.name} ({item.count} syscalls)
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {compareLoading && (
              <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "16px 0", color: "#38bdf8" }}>
                <RefreshCw size={16} className="spin" />
                <span style={{ fontSize: 12 }}>Computing differential seccomp attack surface and tripartite permission tiers...</span>
              </div>
            )}

            {compareError && (
              <div className="notice" style={{ margin: "12px 0" }}>
                <ShieldAlert size={16} />
                <div>{compareError}</div>
              </div>
            )}

            {compareResult && (
              <div className="diff-summary-card" style={{ marginTop: 12 }}>
                {/* 4 Stat Cards */}
                <div className="diff-stat-row" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginBottom: 18 }}>
                  <div className="diff-stat-item" style={{ background: "#060b17", padding: "12px 14px", borderRadius: 8, border: "1px solid #162238" }}>
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>Baseline Syscalls</span>
                    <strong style={{ fontSize: 20, color: "#f1f5f9", display: "block", marginTop: 4 }}>{compareResult.base_count}</strong>
                  </div>
                  <div className="diff-stat-item" style={{ background: "#060b17", padding: "12px 14px", borderRadius: 8, border: "1px solid #162238" }}>
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>Candidate Syscalls</span>
                    <strong style={{ fontSize: 20, color: "#38bdf8", display: "block", marginTop: 4 }}>{compareResult.cand_count}</strong>
                  </div>
                  <div className="diff-stat-item" style={{ background: "#060b17", padding: "12px 14px", borderRadius: 8, border: "1px solid #162238" }}>
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>Syscalls Pruned</span>
                    <strong style={{ fontSize: 20, color: "#34d399", display: "block", marginTop: 4 }}>
                      -{compareResult.removed_syscalls.length}
                    </strong>
                  </div>
                  <div className="diff-stat-item" style={{ background: "#060b17", padding: "12px 14px", borderRadius: 8, border: "1px solid #162238" }}>
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>Attack Surface Risk</span>
                    <strong style={{ fontSize: 18, color: "#34d399", display: "block", marginTop: 4 }}>
                      {compareResult.base_risk}% → {compareResult.cand_risk}%
                    </strong>
                  </div>
                </div>

                {/* Tripartite Permission Tiers Overview */}
                {compareResult.permission_tiers && (
                  <div style={{ marginBottom: 20, padding: "14px 16px", background: "#050914", borderRadius: 8, border: "1px solid #1e293b" }}>
                    <h4 style={{ margin: "0 0 10px", fontSize: 13, color: "#f1f5f9" }}>Tripartite Permission Tiers</h4>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
                      <div style={{ padding: "10px 12px", background: "#062319", border: "1px solid #059669", borderRadius: 6 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <strong style={{ fontSize: 12, color: "#34d399" }}>Tier 1: Indispensable</strong>
                          <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "#6ee7b7", fontWeight: 700 }}>
                            {compareResult.permission_tiers.experimentally_necessary?.length ?? 0}
                          </span>
                        </div>
                        <p style={{ margin: "4px 0 0", fontSize: 10, color: "#a7f3d0", lineHeight: 1.4 }}>
                          Proven indispensable by empirical execution failure (SIGSYS / exit code mismatch) when ablated.
                        </p>
                      </div>

                      <div style={{ padding: "10px 12px", background: "#261a06", border: "1px solid #d97706", borderRadius: 6 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <strong style={{ fontSize: 12, color: "#fbbf24" }}>Tier 2: Removable</strong>
                          <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "#fde68a", fontWeight: 700 }}>
                            {compareResult.permission_tiers.removable_for_tested_tasks?.length ?? 0}
                          </span>
                        </div>
                        <p style={{ margin: "4px 0 0", fontSize: 10, color: "#fef3c7", lineHeight: 1.4 }}>
                          Safely pruned for tested tasks with 0 regression impact; eliminated from candidate filter.
                        </p>
                      </div>

                      <div style={{ padding: "10px 12px", background: "#1b1429", border: "1px solid #7c3aed", borderRadius: 6 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <strong style={{ fontSize: 12, color: "#c084fc" }}>Tier 3: Unvalidated</strong>
                          <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "#e9d5ff", fontWeight: 700 }}>
                            {compareResult.permission_tiers.not_yet_validated?.length ?? 0}
                          </span>
                        </div>
                        <p style={{ margin: "4px 0 0", fontSize: 10, color: "#f3e8ff", lineHeight: 1.4 }}>
                          Retained in policy but untested or unconfirmed by positive ablation proof.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Interactive Syscall Matrix Table */}
                <div style={{ borderTop: "1px solid #1e293b", paddingTop: 16 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 10 }}>
                    <div>
                      <h4 style={{ margin: 0, fontSize: 14 }}>Side-by-Side Syscall Matrix ({filteredMatrixRows.length})</h4>
                      <p style={{ margin: "2px 0 0", fontSize: 11, color: "#64748b" }}>
                        Detailed per-syscall breakdown showing retention and policy delta.
                      </p>
                    </div>

                    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                      <div style={{ position: "relative" }}>
                        <input
                          type="text"
                          placeholder="Filter syscalls..."
                          value={matrixSearch}
                          onChange={e => setMatrixSearch(e.target.value)}
                          style={{
                            padding: "6px 26px 6px 10px", background: "#090d16",
                            border: "1px solid #1e293b", borderRadius: 6, color: "#f1f5f9", fontSize: 11, width: 140
                          }}
                        />
                        {matrixSearch && (
                          <button
                            onClick={() => setMatrixSearch("")}
                            style={{ position: "absolute", right: 6, top: 6, background: "none", border: "none", color: "#64748b", cursor: "pointer", padding: 0 }}
                          >
                            <X size={12} />
                          </button>
                        )}
                      </div>

                      <select
                        value={matrixCategoryFilter}
                        onChange={e => setMatrixCategoryFilter(e.target.value)}
                        style={{ padding: "6px 10px", background: "#090d16", border: "1px solid #1e293b", borderRadius: 6, color: "#f1f5f9", fontSize: 11 }}
                      >
                        <option value="all">All Categories</option>
                        <option value="File I/O">File I/O</option>
                        <option value="Process">Process</option>
                        <option value="Memory">Memory</option>
                        <option value="Network">Network</option>
                        <option value="Privileged">Privileged</option>
                        <option value="System">System</option>
                      </select>

                      <div style={{ display: "flex", gap: 4 }}>
                        <button
                          type="button"
                          onClick={() => setMatrixStatusFilter("all")}
                          style={{
                            padding: "4px 8px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                            background: matrixStatusFilter === "all" ? "#1e293b" : "transparent",
                            color: matrixStatusFilter === "all" ? "#f1f5f9" : "#64748b",
                            border: "1px solid #1e293b"
                          }}
                        >
                          All ({compareSyscallRows.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setMatrixStatusFilter("removed")}
                          style={{
                            padding: "4px 8px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                            background: matrixStatusFilter === "removed" ? "#381014" : "transparent",
                            color: matrixStatusFilter === "removed" ? "#f87171" : "#64748b",
                            border: "1px solid #7f1d1d"
                          }}
                        >
                          Pruned (-{compareResult.removed_syscalls.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setMatrixStatusFilter("kept")}
                          style={{
                            padding: "4px 8px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                            background: matrixStatusFilter === "kept" ? "#064e3b" : "transparent",
                            color: matrixStatusFilter === "kept" ? "#34d399" : "#64748b",
                            border: "1px solid #059669"
                          }}
                        >
                          Kept ({compareSyscallRows.filter(r => r.status === "kept").length})
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="table-wrap" style={{ maxHeight: 380, overflowY: "auto" }}>
                    <table>
                      <thead>
                        <tr>
                          <th>SYSCALL</th>
                          <th>CATEGORY</th>
                          <th>BASELINE ({compareBase})</th>
                          <th>CANDIDATE ({compareCand})</th>
                          <th>DELTA STATUS</th>
                          <th>PERMISSION TIER</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredMatrixRows.length === 0 ? (
                          <tr>
                            <td colSpan={6} style={{ textAlign: "center", padding: 20, color: "#64748b" }}>
                              No syscalls match the selected filter.
                            </td>
                          </tr>
                        ) : (
                          filteredMatrixRows.map(row => (
                            <tr key={row.name}>
                              <td className="process-cell">
                                <code style={{ fontWeight: 700, color: row.status === "removed" ? "#f87171" : "#f1f5f9" }}>
                                  sys_{row.name}
                                </code>
                              </td>
                              <td>
                                <span style={{
                                  fontSize: 10, padding: "2px 6px", borderRadius: 4,
                                  background: "#0c172a", border: "1px solid #1e293b",
                                  color: row.category === "Privileged" ? "#f87171" : row.category === "Network" ? "#a855f7" : "#38bdf8",
                                  fontFamily: "var(--font-mono)"
                                }}>
                                  {row.category}
                                </span>
                              </td>
                              <td>
                                {row.inBase ? (
                                  <span style={{ color: "#34d399", fontWeight: 700 }}>✓ Permitted</span>
                                ) : (
                                  <span style={{ color: "#64748b" }}>— Blocked</span>
                                )}
                              </td>
                              <td>
                                {row.inCand ? (
                                  <span style={{ color: "#38bdf8", fontWeight: 700 }}>✓ Permitted</span>
                                ) : (
                                  <span style={{ color: "#f87171", fontWeight: 700 }}>✗ Pruned (SIGSYS)</span>
                                )}
                              </td>
                              <td>
                                {row.status === "removed" ? (
                                  <span className="syscall-pill pill-removed" style={{ fontSize: 10, padding: "2px 6px" }}>
                                    - REMOVED
                                  </span>
                                ) : row.status === "added" ? (
                                  <span className="syscall-pill pill-added" style={{ fontSize: 10, padding: "2px 6px" }}>
                                    + ADDED (ALERT)
                                  </span>
                                ) : (
                                  <span className="syscall-pill pill-necessary" style={{ fontSize: 10, padding: "2px 6px" }}>
                                    = KEPT
                                  </span>
                                )}
                              </td>
                              <td>
                                <span style={{
                                  fontSize: 10, fontFamily: "var(--font-mono)",
                                  color: row.tier.includes("Tier 1") ? "#34d399" : row.tier.includes("Tier 2") ? "#fbbf24" : "#94a3b8"
                                }}>
                                  {row.tier}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </section>
        </>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: Safety Gate Policy Verifier */}
      {/* ========================================================================= */}
      {activeTab === "verify" && (
        <section className="panel">
          <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16 }}>Safety Gate Policy Candidate Verification</h3>
              <p style={{ margin: "4px 0 0", fontSize: 12, color: "#94a3b8" }}>
                Execute full kernel regression tests against a candidate policy to certify that legitimate tasks run unimpeded while adversarial actions are blocked.
              </p>
            </div>
            <ShieldCheck size={20} style={{ color: "#34d399" }} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, margin: "16px 0" }}>
            <div style={{ background: "#050914", padding: "14px 16px", borderRadius: 8, border: "1px solid #1e293b" }}>
              <label style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                1. Candidate Policy to Verify
              </label>
              <select
                value={verifyCand}
                onChange={e => setVerifyCand(e.target.value)}
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 12 }}
              >
                {policies?.items?.map(item => (
                  <option key={`v-cand-${item.name}`} value={item.name}>
                    {item.name} ({item.count} syscalls)
                  </option>
                ))}
              </select>

              <label style={{ fontSize: 11, fontWeight: 700, color: "#94a3b8", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                2. Active Baseline (Optional for Diff Audit)
              </label>
              <select
                value={verifyActive}
                onChange={e => setVerifyActive(e.target.value)}
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #1e293b", borderRadius: 6, color: "#cbd5e1", fontFamily: "var(--font-mono)", fontSize: 12 }}
              >
                <option value="">(None / Standalone Candidate)</option>
                {policies?.items?.map(item => (
                  <option key={`v-act-${item.name}`} value={item.name}>
                    {item.name} ({item.count} syscalls)
                  </option>
                ))}
              </select>
            </div>

            <div style={{ background: "#050914", padding: "14px 16px", borderRadius: 8, border: "1px solid #1e293b" }}>
              <label style={{ fontSize: 11, fontWeight: 700, color: "#34d399", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                3. Regression Workload Command (Must Succeed)
              </label>
              <input
                type="text"
                value={verifyRegCmd}
                onChange={e => setVerifyRegCmd(e.target.value)}
                placeholder="e.g. grep --help"
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 8 }}
              />
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                {["grep --help", "python3 --version", "cat /dev/null", "ls -la /"].map(c => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => setVerifyRegCmd(c)}
                    style={{ padding: "2px 6px", fontSize: 10, background: "#081d33", border: "1px solid #0284c7", borderRadius: 4, color: "#93c5fd", cursor: "pointer", fontFamily: "var(--font-mono)" }}
                  >
                    {c}
                  </button>
                ))}
              </div>

              <label style={{ fontSize: 11, fontWeight: 700, color: "#f87171", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                4. Adversarial Vector (Must be Blocked / SIGSYS)
              </label>
              <input
                type="text"
                value={verifyAdvCmd}
                onChange={e => setVerifyAdvCmd(e.target.value)}
                placeholder="e.g. uname -a"
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 8 }}
              />
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {["uname -a", "id", "whoami", "cat /etc/shadow"].map(c => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => setVerifyAdvCmd(c)}
                    style={{ padding: "2px 6px", fontSize: 10, background: "#260d10", border: "1px solid #7f1d1d", borderRadius: 4, color: "#fca5a5", cursor: "pointer", fontFamily: "var(--font-mono)" }}
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <span style={{ fontSize: 11, color: "#64748b" }}>
              Runs <code>build/povishield enforce</code> under native Linux seccomp to test exit codes and signal traps.
            </span>
            <button
              className="primary-button"
              onClick={handleRunVerify}
              disabled={verifyRunning}
              style={{ padding: "8px 16px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
            >
              {verifyRunning ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={14} />}
              {verifyRunning ? "Verifying Policy Against Kernel..." : "Verify Policy with Safety Gate"}
            </button>
          </div>

          {verifyError && (
            <div className="notice" style={{ marginBottom: 16 }}>
              <ShieldAlert size={16} />
              <div>{verifyError}</div>
            </div>
          )}

          {/* Verification Result Output */}
          {verifyResult && (
            <div style={{ background: "#050914", border: "1px solid #1e293b", borderRadius: 8, padding: 18, marginTop: 16 }}>
              {/* Top Verdict Banner */}
              <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "12px 16px", borderRadius: 8, marginBottom: 16,
                background: verifyResult.verdict === "READY_FOR_APPROVAL" ? "#062a1c" : "#2d0b10",
                border: verifyResult.verdict === "READY_FOR_APPROVAL" ? "1px solid #059669" : "1px solid #b91c1c"
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  {verifyResult.verdict === "READY_FOR_APPROVAL" ? (
                    <CheckCircle2 size={24} style={{ color: "#34d399" }} />
                  ) : (
                    <AlertTriangle size={24} style={{ color: "#f87171" }} />
                  )}
                  <div>
                    <strong style={{ fontSize: 14, color: verifyResult.verdict === "READY_FOR_APPROVAL" ? "#34d399" : "#f87171" }}>
                      VERDICT: {verifyResult.verdict}
                    </strong>
                    <p style={{ margin: "2px 0 0", fontSize: 11, color: "#cbd5e1" }}>
                      Target: <code>{verifyResult.target}</code> · Allowed Syscalls: {verifyResult.allowed_count} · Attack Surface Risk: {verifyResult.risk_score}%
                    </p>
                  </div>
                </div>

                {verifyResult.verdict === "READY_FOR_APPROVAL" && (
                  <button
                    className="primary-button"
                    onClick={handleSubmitApproval}
                    disabled={requestingApproval}
                    style={{ padding: "6px 12px", fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}
                  >
                    {requestingApproval ? <RefreshCw size={12} className="spin" /> : <CheckCircle2 size={12} />}
                    {requestingApproval ? "Submitting..." : "Submit for Operator Approval"}
                  </button>
                )}
              </div>

              {approvalFeedback && (
                <div style={{ padding: "8px 12px", background: "#062319", border: "1px solid #059669", borderRadius: 6, color: "#34d399", fontSize: 11, marginBottom: 14 }}>
                  {approvalFeedback}
                </div>
              )}

              {/* Workload checks table */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                {/* Regression workloads */}
                <div style={{ background: "#03060f", padding: "12px 14px", borderRadius: 6, border: "1px solid #162238" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <strong style={{ fontSize: 12, color: "#34d399" }}>Regression Test Validation</strong>
                    <span style={{ fontSize: 10, color: verifyResult.regression?.passed ? "#34d399" : "#f87171", fontWeight: 700 }}>
                      {verifyResult.regression?.passed ? "PASSED (0 REGRESSIONS)" : "FAILED"}
                    </span>
                  </div>
                  {verifyResult.regression?.details?.map((item, idx) => (
                    <div key={idx} style={{ padding: "6px 8px", background: "#080e1a", borderRadius: 4, fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 4 }}>
                      <div>CMD: <code>{Array.isArray(item.cmd) ? item.cmd.join(" ") : item.cmd}</code></div>
                      <div style={{ display: "flex", gap: 12, marginTop: 4, color: "#94a3b8", fontSize: 10 }}>
                        <span>Native RC: {item.native_rc}</span>
                        <span>Candidate RC: {item.candidate_rc}</span>
                        <span>SIGSYS: {item.sigsys ? "YES (FAILED)" : "NO (OK)"}</span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Adversarial Containment */}
                <div style={{ background: "#03060f", padding: "12px 14px", borderRadius: 6, border: "1px solid #162238" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <strong style={{ fontSize: 12, color: "#f87171" }}>Adversarial Containment Check</strong>
                    <span style={{ fontSize: 10, color: verifyResult.adversarial?.contained ? "#34d399" : "#f87171", fontWeight: 700 }}>
                      {verifyResult.adversarial?.contained ? "CONTAINED (BLOCKED)" : "LEAKED"}
                    </span>
                  </div>
                  {verifyResult.adversarial?.details?.map((item, idx) => (
                    <div key={idx} style={{ padding: "6px 8px", background: "#080e1a", borderRadius: 4, fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 4 }}>
                      <div>VECTOR: <code>{Array.isArray(item.cmd) ? item.cmd.join(" ") : item.cmd}</code></div>
                      <div style={{ display: "flex", gap: 12, marginTop: 4, color: "#94a3b8", fontSize: 10 }}>
                        <span>Return Code: {item.rc}</span>
                        <span>Blocked: {item.blocked ? "YES (SAFE)" : "NO"}</span>
                        <span>SIGSYS: {item.sigsys ? "SIGSYS KILL" : "NON-ZERO"}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Evidence Ledger backing */}
              <div style={{ marginTop: 14, padding: "10px 12px", background: "#040813", borderRadius: 6, border: "1px solid #162238" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11 }}>
                  <span style={{ color: "#cbd5e1" }}>
                    Evidence Ledger Backing: <strong>{verifyResult.evidence_audit?.evidence_backed_count}</strong> of {verifyResult.allowed_count} syscalls backed by empirical test proof.
                  </span>
                  <span style={{ color: verifyResult.evidence_audit?.unbacked_count > 0 ? "#fbbf24" : "#34d399", fontFamily: "var(--font-mono)" }}>
                    {verifyResult.evidence_audit?.unbacked_count} unbacked
                  </span>
                </div>
                {verifyResult.evidence_audit?.unbacked_syscalls?.length > 0 && (
                  <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {verifyResult.evidence_audit.unbacked_syscalls.map(s => (
                      <span key={s} style={{ fontSize: 9, padding: "1px 5px", background: "#1e1b2e", border: "1px solid #4338ca", borderRadius: 3, color: "#c7d2fe", fontFamily: "var(--font-mono)" }}>
                        {s}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: Policy Catalog & Deep Inspection */}
      {/* ========================================================================= */}
      {activeTab === "catalog" && (
        <section className="panel">
          <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16 }}>Policy Catalog</h3>
              <p style={{ margin: "2px 0 0", fontSize: 11, color: "#64748b" }}>
                All generated baseline and candidate JSON policies stored in <code>results/profiles/</code>
              </p>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                placeholder="Filter catalog..."
                value={catalogSearch}
                onChange={e => setCatalogSearch(e.target.value)}
                style={{ padding: "6px 10px", background: "#101a29", border: "1px solid #29364a", borderRadius: 6, color: "#d5deeb", fontSize: 11 }}
              />
              <button
                className="secondary-button"
                onClick={() => { setActiveTab("builder"); }}
                style={{ padding: "6px 10px", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
              >
                <Plus size={12} /> New Policy
              </button>
            </div>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>POLICY FILE</th>
                  <th>SCHEMA</th>
                  <th>ALLOWED SYSCALLS</th>
                  <th>SIZE</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {policies?.items
                  ?.filter(p => !catalogSearch || p.name.toLowerCase().includes(catalogSearch.toLowerCase()))
                  .map(item => (
                    <tr key={item.name}>
                      <td className="process-cell">
                        <code style={{ color: item.name.includes("counterfactual") ? "#34d399" : "#f1f5f9" }}>
                          {item.name}
                        </code>
                      </td>
                      <td>Schema {item.schema}</td>
                      <td>
                        <strong style={{ color: "#38bdf8" }}>{item.count}</strong>
                      </td>
                      <td>{item.size_bytes} bytes</td>
                      <td>
                        <div style={{ display: "flex", gap: 6 }}>
                          <button
                            className="secondary-button"
                            style={{ padding: "4px 8px", fontSize: 10 }}
                            onClick={() => { setSelectedPolicy(item); setDrawerTab("pills"); }}
                          >
                            <Eye size={11} style={{ marginRight: 3 }} /> Inspect
                          </button>
                          <button
                            className="secondary-button"
                            style={{ padding: "4px 8px", fontSize: 10, borderColor: "#0284c7", color: "#38bdf8" }}
                            onClick={() => {
                              setCompareBase(item.name);
                              setActiveTab("matrix");
                              runCompare(item.name, compareCand);
                            }}
                            title="Set as baseline in comparator"
                          >
                            Set Base
                          </button>
                          <button
                            className="secondary-button"
                            style={{ padding: "4px 8px", fontSize: 10, borderColor: "#059669", color: "#34d399" }}
                            onClick={() => {
                              setCompareCand(item.name);
                              setActiveTab("matrix");
                              runCompare(compareBase, item.name);
                            }}
                            title="Set as candidate in comparator"
                          >
                            Set Cand
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          {/* Policy Detail Deep Inspection Drawer */}
          {selectedPolicy && (
            <div className="trial-drawer" style={{ marginTop: 20 }}>
              <div className="trial-drawer-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                <div>
                  <h4 style={{ margin: 0, fontSize: 15, color: "#f1f5f9" }}>
                    Policy Specification: <code>{selectedPolicy.name}</code>
                  </h4>
                  <div style={{ display: "flex", gap: 12, marginTop: 4, fontSize: 11, color: "#94a3b8" }}>
                    <span>Schema: {selectedPolicy.schema}</span>
                    <span>Total Allowed: <strong>{selectedPolicy.count}</strong></span>
                    <span>Target: <code>{selectedPolicy.data?.command || selectedPolicy.name.replace(/\.json$/, "")}</code></span>
                  </div>
                </div>

                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    className="secondary-button"
                    style={{ padding: "4px 8px", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                    onClick={() => handleClonePolicy(selectedPolicy)}
                    title="Clone and edit in Policy Builder"
                  >
                    <Plus size={12} /> Clone & Edit
                  </button>
                  <a
                    href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(selectedPolicy.data, null, 2))}`}
                    download={selectedPolicy.name}
                    className="secondary-button"
                    style={{ padding: "4px 8px", fontSize: 11, display: "flex", alignItems: "center", gap: 4, textDecoration: "none" }}
                  >
                    <Download size={12} /> Download
                  </a>
                  <button
                    className="secondary-button"
                    style={{ padding: "4px 8px", fontSize: 11 }}
                    onClick={() => setSelectedPolicy(null)}
                  >
                    <X size={12} />
                  </button>
                </div>
              </div>

              {/* Category Breakdown Bar */}
              <div style={{ marginBottom: 16, padding: "12px 14px", background: "#050914", borderRadius: 8, border: "1px solid #1e293b" }}>
                <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 700, display: "block", marginBottom: 8, textTransform: "uppercase" }}>
                  System Call Distribution by Category:
                </span>
                <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", marginBottom: 10 }}>
                  {selectedPolicyCategoryStats.map(stat => {
                    let bg = "#38bdf8";
                    if (stat.category === "File I/O") bg = "#34d399";
                    if (stat.category === "Process") bg = "#a78bfa";
                    if (stat.category === "Memory") bg = "#fbbf24";
                    if (stat.category === "Privileged") bg = "#f87171";
                    if (stat.category === "Network") bg = "#ec4899";
                    return (
                      <div
                        key={stat.category}
                        style={{ width: `${stat.pct}%`, background: bg }}
                        title={`${stat.category}: ${stat.count} (${stat.pct}%)`}
                      />
                    );
                  })}
                </div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  {selectedPolicyCategoryStats.map(stat => (
                    <span key={stat.category} style={{ fontSize: 11, color: "#cbd5e1", fontFamily: "var(--font-mono)" }}>
                      <strong>{stat.count}</strong> {stat.category} ({stat.pct}%)
                    </span>
                  ))}
                </div>
              </div>

              {/* View toggle tabs */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, borderBottom: "1px solid #1e293b", paddingBottom: 8 }}>
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    type="button"
                    onClick={() => setDrawerTab("pills")}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 4, cursor: "pointer",
                      background: drawerTab === "pills" ? "#0c2d48" : "transparent",
                      color: drawerTab === "pills" ? "#38bdf8" : "#94a3b8",
                      border: "1px solid", borderColor: drawerTab === "pills" ? "#0284c7" : "transparent"
                    }}
                  >
                    Categorized Pills
                  </button>
                  <button
                    type="button"
                    onClick={() => setDrawerTab("table")}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 4, cursor: "pointer",
                      background: drawerTab === "table" ? "#0c2d48" : "transparent",
                      color: drawerTab === "table" ? "#38bdf8" : "#94a3b8",
                      border: "1px solid", borderColor: drawerTab === "table" ? "#0284c7" : "transparent"
                    }}
                  >
                    Detailed Table
                  </button>
                  <button
                    type="button"
                    onClick={() => setDrawerTab("raw")}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 4, cursor: "pointer",
                      background: drawerTab === "raw" ? "#0c2d48" : "transparent",
                      color: drawerTab === "raw" ? "#38bdf8" : "#94a3b8",
                      border: "1px solid", borderColor: drawerTab === "raw" ? "#0284c7" : "transparent"
                    }}
                  >
                    Raw JSON
                  </button>
                </div>

                <div style={{ display: "flex", gap: 6 }}>
                  {drawerTab === "raw" ? (
                    <button
                      className="secondary-button"
                      onClick={() => copyToClipboard(JSON.stringify(selectedPolicy.data, null, 2), "json")}
                      style={{ padding: "3px 8px", fontSize: 10, display: "flex", alignItems: "center", gap: 4 }}
                    >
                      {copiedJsonText ? <Check size={12} color="#34d399" /> : <Copy size={12} />}
                      {copiedJsonText ? "Copied" : "Copy JSON"}
                    </button>
                  ) : (
                    <button
                      className="secondary-button"
                      onClick={() => copyToClipboard((selectedPolicy.data?.syscalls || []).join("\n"), "pill")}
                      style={{ padding: "3px 8px", fontSize: 10, display: "flex", alignItems: "center", gap: 4 }}
                    >
                      {copiedPillText ? <Check size={12} color="#34d399" /> : <Copy size={12} />}
                      {copiedPillText ? "Copied" : "Copy Syscall Names"}
                    </button>
                  )}
                </div>
              </div>

              {/* View Tab Contents */}
              {drawerTab === "pills" && (
                <div className="syscall-pill-wrap" style={{ maxHeight: 260, overflowY: "auto" }}>
                  {(selectedPolicy.data?.syscalls ?? [])
                    .filter(s => !drawerSyscallSearch || s.includes(drawerSyscallSearch.toLowerCase()))
                    .map(s => {
                      const cat = getSyscallCategory(s);
                      return (
                        <span key={s} className="syscall-pill pill-necessary" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                          <span>{s}</span>
                          <span style={{ fontSize: 9, opacity: 0.6 }}>({cat})</span>
                        </span>
                      );
                    })}
                </div>
              )}

              {drawerTab === "table" && (
                <div className="table-wrap" style={{ maxHeight: 260, overflowY: "auto" }}>
                  <table>
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>SYSCALL</th>
                        <th>CATEGORY</th>
                        <th>ACTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedPolicy.data?.syscalls ?? []).map((s, idx) => (
                        <tr key={s}>
                          <td style={{ color: "#64748b", fontFamily: "var(--font-mono)" }}>{idx + 1}</td>
                          <td><code>sys_{s}</code></td>
                          <td>
                            <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 4, background: "#0c172a", border: "1px solid #1e293b", color: "#38bdf8" }}>
                              {getSyscallCategory(s)}
                            </span>
                          </td>
                          <td style={{ color: "#34d399", fontWeight: 700 }}>ALLOW</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {drawerTab === "raw" && (
                <pre style={{
                  margin: 0, padding: "12px 14px", background: "#02040a",
                  border: "1px solid #142034", borderRadius: 6, color: "#34d399",
                  fontSize: 11, fontFamily: "var(--font-mono)", maxHeight: 260, overflowY: "auto"
                }}>
                  {JSON.stringify(selectedPolicy.data, null, 2)}
                </pre>
              )}
            </div>
          )}
        </section>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: Custom Policy Builder */}
      {/* ========================================================================= */}
      {activeTab === "builder" && (
        <section className="panel">
          <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16 }}>Custom Policy Generator & Candidate Builder</h3>
              <p style={{ margin: "4px 0 0", fontSize: 12, color: "#94a3b8" }}>
                Craft an evidence-backed security profile, tailor permitted system calls, and save directly to <code>results/profiles/</code> for safety gate verification.
              </p>
            </div>
            <Plus size={20} style={{ color: "#c084fc" }} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, margin: "16px 0" }}>
            <div style={{ background: "#050914", padding: "14px 16px", borderRadius: 8, border: "1px solid #1e293b" }}>
              <label style={{ fontSize: 11, fontWeight: 700, color: "#c084fc", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                Policy File Identifier (*.json)
              </label>
              <input
                type="text"
                placeholder="e.g. webserver_candidate.json"
                value={builderName}
                onChange={e => setBuilderName(e.target.value)}
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 12 }}
              />

              <label style={{ fontSize: 11, fontWeight: 700, color: "#94a3b8", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                Target Executable / Command (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. /usr/bin/nginx -g 'daemon off;'"
                value={builderCommand}
                onChange={e => setBuilderCommand(e.target.value)}
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #1e293b", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 12 }}
              />

              <label style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                Clone Permissions from Existing Policy
              </label>
              <select
                onChange={e => {
                  const found = policies?.items?.find(i => i.name === e.target.value);
                  if (found) handleClonePolicy(found);
                }}
                defaultValue=""
                style={{ width: "100%", padding: "8px 10px", background: "#090d16", border: "1px solid #1e293b", borderRadius: 6, color: "#cbd5e1", fontFamily: "var(--font-mono)", fontSize: 12 }}
              >
                <option value="" disabled>-- Select a template profile to clone --</option>
                {policies?.items?.map(item => (
                  <option key={`clone-${item.name}`} value={item.name}>
                    {item.name} ({item.count} syscalls)
                  </option>
                ))}
              </select>
            </div>

            <div style={{ background: "#050914", padding: "14px 16px", borderRadius: 8, border: "1px solid #1e293b" }}>
              <label style={{ fontSize: 11, fontWeight: 700, color: "#34d399", display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                Add Custom Syscalls (Comma or Space Separated)
              </label>
              <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                <input
                  type="text"
                  placeholder="e.g. socket, connect, poll, epoll_wait"
                  value={builderCustomInput}
                  onChange={e => setBuilderCustomInput(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter") handleAddCustomSyscall(); }}
                  style={{ flex: 1, padding: "8px 10px", background: "#090d16", border: "1px solid #223854", borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12 }}
                />
                <button
                  type="button"
                  className="secondary-button"
                  onClick={handleAddCustomSyscall}
                  style={{ padding: "8px 12px", fontSize: 12 }}
                >
                  Add
                </button>
              </div>

              <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 700, display: "block", marginBottom: 6, textTransform: "uppercase" }}>
                Common Syscall Quick-Toggle Chips:
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, maxHeight: 110, overflowY: "auto" }}>
                {COMMON_SYSCALL_PRESETS.map(preset => {
                  const isChecked = builderSyscalls.has(preset.name);
                  return (
                    <button
                      key={preset.name}
                      type="button"
                      onClick={() => {
                        setBuilderSyscalls(prev => {
                          const next = new Set(prev);
                          if (next.has(preset.name)) next.delete(preset.name);
                          else next.add(preset.name);
                          return next;
                        });
                      }}
                      style={{
                        padding: "3px 7px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                        background: isChecked ? "#064e3b" : "#070d1a",
                        color: isChecked ? "#34d399" : "#64748b",
                        border: "1px solid", borderColor: isChecked ? "#059669" : "#1e293b",
                        fontFamily: "var(--font-mono)"
                      }}
                    >
                      {isChecked ? `✓ ${preset.name}` : `+ ${preset.name}`}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Builder Syscall Pool & Save Bar */}
          <div style={{ padding: "14px 16px", background: "#03060f", borderRadius: 8, border: "1px solid #1e293b", marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 12, color: "#f1f5f9", fontWeight: 700 }}>
                Selected Permitted Syscalls ({builderSyscalls.size}):
              </span>
              <button
                type="button"
                onClick={() => setBuilderSyscalls(new Set())}
                style={{ background: "none", border: "none", color: "#f87171", fontSize: 11, cursor: "pointer", textDecoration: "underline" }}
              >
                Clear All
              </button>
            </div>

            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, maxHeight: 180, overflowY: "auto" }}>
              {Array.from(builderSyscalls).sort().map(s => (
                <span
                  key={s}
                  onClick={() => {
                    setBuilderSyscalls(prev => {
                      const next = new Set(prev);
                      next.delete(s);
                      return next;
                    });
                  }}
                  title="Click to remove"
                  style={{
                    padding: "3px 8px", background: "#081d33", border: "1px solid #0284c7",
                    borderRadius: 4, color: "#38bdf8", fontSize: 11, fontFamily: "var(--font-mono)", cursor: "pointer"
                  }}
                >
                  sys_{s} <X size={10} style={{ marginLeft: 3, verticalAlign: "middle" }} />
                </span>
              ))}
            </div>
          </div>

          {builderError && (
            <div className="notice" style={{ marginBottom: 14 }}>
              <ShieldAlert size={16} />
              <div>{builderError}</div>
            </div>
          )}

          {builderFeedback && (
            <div style={{ padding: "10px 14px", background: "#062a1c", border: "1px solid #059669", borderRadius: 6, color: "#34d399", fontSize: 12, marginBottom: 14 }}>
              {builderFeedback}
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
            <button
              className="primary-button"
              onClick={handleSaveCustomPolicy}
              disabled={builderSaving}
              style={{ padding: "8px 18px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
            >
              {builderSaving ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={14} />}
              {builderSaving ? "Saving Policy..." : "Save Policy to Disk"}
            </button>
          </div>
        </section>
      )}

    </div>
  );
}
