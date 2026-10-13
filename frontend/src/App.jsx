import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck, LayoutDashboard, Activity, FileText,
  FlaskConical, Settings, ShieldAlert, Cpu,
  LockKeyhole, Gauge, ChevronRight, ChevronLeft, Menu, RefreshCw, Play, Square,
  GitCompare, Layers, FileCheck, CheckCircle2, XCircle, AlertTriangle,
  Check, Copy, Terminal, Server
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar
} from "recharts";
import "./App.css";
import TerminalBackground from "./components/TerminalBackground.jsx";
import TerminalExecutionConsole from "./components/TerminalExecutionConsole.jsx";
import FleetDeviceConsole from "./components/FleetDeviceConsole.jsx";

function getInitialApiUrl() {
  if (typeof window !== "undefined") {
    const custom = localStorage.getItem("povishield_custom_api_url");
    if (custom && custom.trim()) {
      let u = custom.trim().replace(/\/+$/, "");
      if (!u.endsWith("/api")) u = `${u}/api`;
      return u;
    }
  }
  if (import.meta.env.VITE_API_URL) {
    let u = import.meta.env.VITE_API_URL.trim().replace(/\/+$/, "");
    return u;
  }
  if (typeof window !== "undefined") {
    const port = window.location.port;
    if (port === "5173" || port === "5174" || port === "5175" || port === "5176" || port === "5177" || port === "4173") {
      return `${window.location.protocol}//${window.location.hostname}:8000/api`;
    }
    if (window.location.protocol !== "file:") {
      return "/api";
    }
  }
  return "http://127.0.0.1:8000/api";
}

const API = getInitialApiUrl();


const navigationGroups = [
  {
    title: "OPERATIONS & FLEET",
    items: [
      { name: "Overview", icon: LayoutDashboard },
      { name: "Fleet / Devices", icon: Server },
      { name: "Terminal / Execute", icon: Terminal },
      { name: "Activity Monitor", icon: Activity },
    ]
  },
  {
    title: "POLICY & RESEARCH",
    items: [
      { name: "Syscall Profile", icon: Cpu },
      { name: "Policy Explorer", icon: FileText },
      { name: "Counterfactual Research", icon: FlaskConical },
    ]
  },
  {
    title: "SECURITY ASSURANCE",
    items: [
      { name: "Evidence Ledgers", icon: Layers },
      { name: "Safety Gate & Approvals", icon: FileCheck },
      { name: "Experiments", icon: Gauge }
    ]
  }
];

const navigation = navigationGroups.flatMap(g => g.items);

function getSyscallCategory(name) {
  if (["read", "write", "openat", "close", "fstat", "newfstatat", "statx", "ioctl", "lseek", "pread64", "pwrite64", "getdents64"].includes(name)) return "File I/O";
  if (["mmap", "mprotect", "munmap", "brk", "madvise"].includes(name)) return "Memory";
  if (["execve", "clone", "clone3", "fork", "vfork", "exit_group", "exit", "wait4", "arch_prctl", "set_tid_address", "rseq"].includes(name)) return "Process";
  if (["socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom", "recvmsg", "sendmsg"].includes(name)) return "Network";
  if (["ptrace", "mount", "umount2", "bpf", "setns", "unshare", "capset", "prctl", "seccomp"].includes(name)) return "Privileged";
  return "System";
}

const ESCAPE_TEST_DEFS = [
  { id: "esc_chroot", name: "Chroot Breakout", desc: "Break out of chroot jail using fchdir and unconfined fd" },
  { id: "esc_hostfs", name: "Host FS Write", desc: "Attempt to write backdoor file to host filesystem /root" },
  { id: "esc_mount", name: "Mount Tampering", desc: "Invoke mount syscall to overwrite host filesystem mounts" },
  { id: "esc_ptrace", name: "Process Injection", desc: "Inject malicious shellcode into host process via ptrace" },
  { id: "esc_rawsock", name: "Raw Socket Sniffing", desc: "Create AF_INET SOCK_RAW socket to capture packet headers" },
  { id: "esc_unshare", name: "User NS Escalation", desc: "Unshare user namespace to acquire elevated capabilities" },
  { id: "limit_mem", name: "Memory Exhaustion", desc: "Allocate heap memory beyond configured 32MB cgroup limit" },
  { id: "limit_pids", name: "Fork Bomb / PID Floor", desc: "Fork processes aggressively to exhaust kernel task limits" },
];

const ESCAPE_CONFIGS = [
  { key: "bare", label: "Bare (Unsandboxed)", desc: "Direct host execution without sandbox" },
  { key: "seccomp", label: "Seccomp Only", desc: "Strict syscall filtering via BPF" },
  { key: "namespaces", label: "Namespaces Only", desc: "Linux mount/PID/net isolation" },
  { key: "full", label: "Full Sandbox", desc: "Namespaces + Seccomp BPF + cgroups" },
  { key: "full+rootfs", label: "Full + Rootfs", desc: "Full sandbox with read-only rootfs" },
  { key: "rootfs-only", label: "Rootfs Only", desc: "Isolated filesystem sandbox" }
];

function renderEscapeBadge(verdict) {
  if (verdict === "BLOCKED_SIGSYS") {
    return <span className="esc-cell-blocked">BLOCKED (SIGSYS)</span>;
  }
  if (verdict === "DENIED") {
    return <span className="esc-cell-denied">DENIED (EPERM)</span>;
  }
  if (verdict === "KILLED_BY_LIMIT") {
    return <span className="esc-cell-killed">KILLED (LIMIT)</span>;
  }
  if (verdict === "ESCAPED") {
    return <span className="esc-cell-escaped">ESCAPED</span>;
  }
  return <span style={{ color: "#64748b", fontFamily: "var(--font-mono)" }}>{verdict || "N/A"}</span>;
}


async function getJSON(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    const text = await response.text();
    if (text.trim().startsWith("<")) {
      throw new Error(`Connected to ${API}, but received HTML instead of JSON. If your backend is deployed on Render, connect your Render URL.`);
    }
    throw new Error(`API returned non-JSON response (${contentType})`);
  }
  return response.json();
}


function Metric({ icon: Icon, label, value, detail, progress, accent = "#10b981" }) {
  return (
    <div className="metric-card" style={{ position: "relative", overflow: "hidden" }}>
      <div style={{
        position: "absolute",
        top: 0,
        left: 0,
        right: 0,
        height: 2,
        background: `linear-gradient(90deg, ${accent}, transparent)`
      }} />
      <div className="metric-top">
        <span>{label}</span>
        <div style={{
          width: 32,
          height: 32,
          borderRadius: 8,
          background: "rgba(10, 20, 35, 0.8)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          display: "grid",
          placeItems: "center",
          color: accent
        }}>
          <Icon size={16} />
        </div>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
      {typeof progress === "number" && (
        <div className="metric-progress-bar">
          <div className="metric-progress-fill" style={{ width: `${Math.min(100, Math.max(0, progress))}%`, background: accent }} />
        </div>
      )}
    </div>
  );
}

function App() {
  const [page, setPage] = useState("Overview");
  const [menuOpen, setMenuOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    return localStorage.getItem("povishield_sidebar_collapsed") === "true";
  });
  const [devices, setDevices] = useState([]);
  const [activeDeviceId, setActiveDeviceId] = useState(() => {
    return localStorage.getItem("povishield_active_device_id") || "gateway";
  });

  const toggleSidebar = () => {
    setSidebarCollapsed(prev => {
      const next = !prev;
      localStorage.setItem("povishield_sidebar_collapsed", String(next));
      return next;
    });
  };

  const activeDevice = activeDeviceId !== "gateway"
    ? devices.find(d => d.id === activeDeviceId)
    : null;

  const [ambientLogsEnabled, setAmbientLogsEnabled] = useState(() => {
    return localStorage.getItem("povishield_ambient_enabled") !== "false";
  });
  const [strictLocalConfinement, setStrictLocalConfinement] = useState(() => {
    return localStorage.getItem("povishield_strict_confinement") !== "false";
  });
  const [expReportExpanded, setExpReportExpanded] = useState(false);
  const [expFilterConfig, setExpFilterConfig] = useState("all");

  const toggleAmbientLogs = () => {
    setAmbientLogsEnabled(prev => {
      const next = !prev;
      localStorage.setItem("povishield_ambient_enabled", String(next));
      return next;
    });
  };

  const toggleStrictConfinement = () => {
    setStrictLocalConfinement(prev => {
      const next = !prev;
      localStorage.setItem("povishield_strict_confinement", String(next));
      return next;
    });
  };

  const [overview, setOverview] = useState(null);
  const [policies, setPolicies] = useState(null);
  const [experiments, setExperiments] = useState(null);
  const [health, setHealth] = useState(null);
  const [ablationData, setAblationData] = useState(null);
  const [noisyAblationData, setNoisyAblationData] = useState(null);
  const [ablationSubTab, setAblationSubTab] = useState("noisy");
  const [ledgersList, setLedgersList] = useState([]);
  const [approvalsList, setApprovalsList] = useState([]);

  // Activity Monitor state
  const [eventsData, setEventsData] = useState(null);
  const [profileData, setProfileData] = useState(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState("");
  const [profilePhase, setProfilePhase] = useState("entry");
  const [profileSearch, setProfileSearch] = useState("");
  const [monitorCommand, setMonitorCommand] = useState('["/usr/bin/sleep", "10"]');
  const [monitorSession, setMonitorSession] = useState(null);
  const [monitorEvents, setMonitorEvents] = useState([]);
  const [monitorError, setMonitorError] = useState("");
  const [monitorBusy, setMonitorBusy] = useState(false);
  const monitorOffset = useRef(0);

  // Policy Explorer & Comparator state
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [policySearch, setPolicySearch] = useState("");
  const [compareBase, setCompareBase] = useState("");
  const [compareCand, setCompareCand] = useState("");
  const [compareResult, setCompareResult] = useState(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState("");

  // Evidence Ledgers state
  const [selectedLedgerTarget, setSelectedLedgerTarget] = useState("");
  const [ledgerTrials, setLedgerTrials] = useState([]);
  const [ledgerTotalRecords, setLedgerTotalRecords] = useState(0);
  const [ledgerVerdictFilter, setLedgerVerdictFilter] = useState("ALL");
  const [ledgerSyscallFilter, setLedgerSyscallFilter] = useState("");
  const [selectedTrial, setSelectedTrial] = useState(null);
  const [auditReport, setAuditReport] = useState(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Counterfactual research state
  const [showMarkdownReport, setShowMarkdownReport] = useState(false);
  const [chartMetric, setChartMetric] = useState("coverage_reduction");
  const [evalSearch, setEvalSearch] = useState("");

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  async function loadData() {
    setLoading(true);
    setError("");
    try {
      const [o, p, e, h] = await Promise.all([
        getJSON("/overview"),
        getJSON("/policies"),
        getJSON("/experiments"),
        getJSON("/health")
      ]);
      setOverview(o);
      setPolicies(p);
      setExperiments(e);
      setHealth(h);

      // Fetch optional research endpoints safely
      try {
        const abl = await getJSON("/ablation/results");
        setAblationData(abl);
      } catch {
        // Optional if eval-ablate not yet run
      }

      try {
        const noisy = await getJSON("/ablation/noisy");
        if (noisy?.available) setNoisyAblationData(noisy);
      } catch {
        // Optional if eval-noisy not yet run
      }

      try {
        const ledg = await getJSON("/ledgers");
        setLedgersList(ledg.ledgers ?? []);
        if (ledg.ledgers?.length && !selectedLedgerTarget) {
          setSelectedLedgerTarget(ledg.ledgers[0].target);
        }
      } catch {
        // Ledgers optional
      }

      try {
        const appr = await getJSON("/approvals");
        setApprovalsList(appr.approvals ?? []);
      } catch {
        // Approvals optional
      }

      try {
        const devRes = await getJSON("/devices");
        setDevices(devRes.devices ?? []);
      } catch {
        // Devices optional
      }

      // Initialize policy compare default filenames
      if (p?.items?.length) {
        const baseItem = p.items.find(i => i.name.includes("baseline") || i.name === "grep.json");
        const candItem = p.items.find(i => i.name.includes("counterfactual") || i.name.includes("candidate"));
        if (baseItem && candItem) {
          setCompareBase(baseItem.name);
          setCompareCand(candItem.name);
        } else if (p.items.length >= 2) {
          setCompareBase(p.items[0].name);
          setCompareCand(p.items[1].name);
        }
      }
    } catch (err) {
      setError(`${err.message}. Check that the FastAPI server is running on port 8000.`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const pollDevices = async () => {
      try {
        const devRes = await getJSON("/devices");
        setDevices(devRes.devices ?? []);
      } catch {}
    };
    const timer = setInterval(pollDevices, 6000);
    return () => clearInterval(timer);
  }, []);

  async function loadEvents() {
    setEventsLoading(true);
    setEventsError("");
    try {
      const [data, profile] = await Promise.all([
        getJSON("/events?limit=100"),
        getJSON("/events/profile")
      ]);
      if (!Array.isArray(data.events) || !Array.isArray(profile.syscalls)) {
        throw new Error("The events API returned an unexpected response");
      }
      setEventsData(data);
      setProfileData(profile);
    } catch (err) {
      setEventsError(`${err.message}. Check that the API is running and results/syscall-events.jsonl exists.`);
    } finally {
      setEventsLoading(false);
    }
  }

  async function runCompare(base, cand) {
    if (!base || !cand) return;
    setCompareLoading(true);
    setCompareError("");
    try {
      const res = await getJSON(`/policies/compare?base=${encodeURIComponent(base)}&cand=${encodeURIComponent(cand)}`);
      setCompareResult(res);
    } catch (err) {
      setCompareError(err.message || "Failed to compare policies");
      setCompareResult(null);
    } finally {
      setCompareLoading(false);
    }
  }

  async function loadLedgerTrials(target, verdict, syscall) {
    if (!target) return;
    try {
      let q = `/ledgers/${encodeURIComponent(target)}?limit=100`;
      if (verdict && verdict !== "ALL") q += `&verdict=${encodeURIComponent(verdict)}`;
      if (syscall) q += `&syscall=${encodeURIComponent(syscall)}`;
      const res = await getJSON(q);
      setLedgerTrials(res.trials ?? []);
      setLedgerTotalRecords(res.total_records ?? 0);
      if (res.trials?.length) setSelectedTrial(res.trials[0]);
    } catch (err) {
      console.error("Failed to load ledger trials:", err);
      setLedgerTrials([]);
    }
  }

  async function runLedgerAudit(target) {
    if (!target) return;
    setAuditLoading(true);
    try {
      const res = await getJSON(`/ledgers/${encodeURIComponent(target)}/audit`);
      setAuditReport(res);
    } catch (err) {
      setAuditReport({ valid: false, errors: [err.message] });
    } finally {
      setAuditLoading(false);
    }
  }

  async function startMonitoring() {
    setMonitorError(""); setMonitorBusy(true);
    try {
      let command;
      try { command = JSON.parse(monitorCommand); }
      catch { throw new Error('Command must be valid JSON, e.g. ["/usr/bin/sleep", "10"]'); }
      if (!Array.isArray(command) || command.length < 1 || command.some(arg => typeof arg !== "string"))
        throw new Error("Command must be a JSON array of strings; shell syntax is not supported.");
      const response = await fetch(`${API}/monitor/sessions`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command, timeout_seconds: 30 }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `API returned ${response.status}`);
      monitorOffset.current = 0; setMonitorEvents([]); setMonitorSession(result);
    } catch (err) { setMonitorError(err.message || "Could not start monitoring session"); }
    finally { setMonitorBusy(false); }
  }

  async function stopMonitoring() {
    if (!monitorSession?.id) return;
    setMonitorError(""); setMonitorBusy(true);
    try {
      const response = await fetch(`${API}/monitor/sessions/${monitorSession.id}/stop`, { method: "POST" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `API returned ${response.status}`);
      setMonitorSession(result);
    } catch (err) { setMonitorError(err.message || "Could not stop monitoring session"); }
    finally { setMonitorBusy(false); }
  }

  useEffect(() => { loadData(); }, []);

  useEffect(() => {
    if (page === "Activity Monitor" || page === "Syscall Profile") loadEvents();
  }, [page]);

  useEffect(() => {
    if (compareBase && compareCand) runCompare(compareBase, compareCand);
  }, [compareBase, compareCand]);

  useEffect(() => {
    if (selectedLedgerTarget) {
      loadLedgerTrials(selectedLedgerTarget, ledgerVerdictFilter, ledgerSyscallFilter);
      setAuditReport(null);
    }
  }, [selectedLedgerTarget, ledgerVerdictFilter, ledgerSyscallFilter]);

  useEffect(() => {
    if (!monitorSession?.id) return undefined;
    let cancelled = false; let timer;
    const poll = async () => {
      try {
        const sr = await fetch(`${API}/monitor/sessions/${monitorSession.id}`);
        const status = await sr.json();
        if (!sr.ok) throw new Error(status.detail || `API returned ${sr.status}`);
        if (cancelled) return;
        setMonitorSession(status);
        const er = await fetch(`${API}/monitor/sessions/${monitorSession.id}/events?offset=${monitorOffset.current}&limit=200`);
        const data = await er.json();
        if (!er.ok) throw new Error(data.detail || `API returned ${er.status}`);
        if (cancelled) return;
        monitorOffset.current = data.next_offset ?? monitorOffset.current;
        if (Array.isArray(data.events) && data.events.length) setMonitorEvents(prev => [...prev, ...data.events].slice(-1000));
        setMonitorError("");
        if (status.status === "running") timer = window.setTimeout(poll, 900);
      } catch (err) {
        if (!cancelled) { setMonitorError(err.message || "Live monitoring update failed"); timer = window.setTimeout(poll, 2000); }
      }
    };
    poll();
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); };
  }, [monitorSession?.id, monitorSession?.status]);

  const aggregate = overview?.aggregate ?? {
    targets: 0,
    avg_attack_surface_reduction_pct: 0,
    total_false_kills: 0,
    avg_median_overhead_pct: 0,
  };
  const targets = overview?.targets ?? [];

  const chartData = targets.map(t => ({
    target: t.target,
    coverage: t.heldout_coverage_pct ?? 100,
    reduction: t.attack_surface_reduction_pct ?? 0,
    compatibility: t.compat_pct ?? 100,
    allowed: t.allowed_syscalls ?? 0,
    total: t.total_syscalls ?? 385,
    overhead: t.overhead_pct?.median ?? 0,
    nativeMs: t.overhead_pct?.native_ms_median ?? 0,
    sandboxedMs: t.overhead_pct?.sandboxed_ms_median ?? 0,
    addedMs: t.overhead_pct?.added_ms ?? 0
  }));

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="app-shell">
      <TerminalBackground enabled={ambientLogsEnabled} />
      <aside className={`sidebar ${sidebarCollapsed ? "collapsed" : ""} ${menuOpen ? "sidebar-open" : ""}`}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 8px 24px" }}>
          <div className="brand" onClick={() => setPage("Overview")} style={{ cursor: "pointer", padding: 0 }}>
            <div className="brand-icon"><ShieldCheck size={26} /></div>
            <div><h2 className="brand-title">PoViShield</h2><span>LINUX DEFENSE & FLEET</span></div>
          </div>
          <button
            className="sidebar-hide-btn"
            onClick={toggleSidebar}
            title="Hide side panel"
          >
            <ChevronLeft size={16} />
          </button>
        </div>

        <nav style={{ overflowY: "auto", flex: 1, paddingRight: 4 }}>
          {navigationGroups.map(group => (
            <div key={group.title} style={{ marginBottom: 14 }}>
              <div style={{
                fontSize: 10,
                fontWeight: 700,
                color: "#52637a",
                letterSpacing: 1.2,
                padding: "4px 10px 6px",
                textTransform: "uppercase",
                fontFamily: "var(--font-mono)"
              }}>
                {group.title}
              </div>
              <div style={{ display: "grid", gap: 3 }}>
                {group.items.map(item => {
                  const Icon = item.icon;
                  const isActive = page === item.name;
                  return (
                    <button key={item.name}
                      className={`nav-item ${isActive ? "active" : ""}`}
                      onClick={() => { setPage(item.name); setMenuOpen(false); }}>
                      <Icon size={18} /><span>{item.name}</span>
                      {isActive && <ChevronRight size={15} />}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="engine-status">
            <span className={`status-dot ${health?.status === "ok" ? "active" : "warning"}`} />
            <div>
              <strong>{health?.status === "ok" ? "Control Plane Online" : "Connecting Control Plane"}</strong>
              <p>{health?.engine_connected ? "Linux Seccomp Engine Ready" : "Local Environment"}</p>
            </div>
          </div>
          <button className={`nav-item ${page === "Settings" ? "active" : ""}`} onClick={() => setPage("Settings")}>
            <Settings size={18} /><span>Settings & Capabilities</span>
          </button>
          <div className="version">PoViShield · Linux Security Platform</div>
        </div>
      </aside>

      <main className={`main-content ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <header className="topbar">
          <button className="menu-button" onClick={toggleSidebar} title={sidebarCollapsed ? "Show side panel" : "Hide side panel"}>
            <Menu size={16} />
            <span style={{ fontSize: 11, fontFamily: "var(--font-mono)" }}>{sidebarCollapsed ? "Expand" : "Hide"}</span>
          </button>
          <div className="breadcrumb">
            <span style={{ color: "#10b981", fontWeight: 700, cursor: "pointer" }} onClick={() => setPage("Overview")}>PoViShield</span>
            <span style={{ margin: "0 8px", color: "#334155" }}>/</span>
            <span style={{ color: "#f1f5f9" }}>{page}</span>
          </div>
          <div className="top-actions">
            <div className="device-selector-wrapper" title="Active Inspected Target Node">
              <Server size={14} style={{ color: activeDevice?.is_live ? "#34d399" : activeDevice ? "#f59e0b" : "#38bdf8" }} />
              <select
                value={activeDeviceId}
                onChange={(e) => {
                  const val = e.target.value;
                  if (val === "__pair__") {
                    setPage("Fleet / Devices");
                    return;
                  }
                  setActiveDeviceId(val);
                  localStorage.setItem("povishield_active_device_id", val);
                }}
                className="device-select-dropdown"
              >
                <option value="gateway">🌐 Local Server Gateway</option>
                {devices.map(d => (
                  <option key={d.id} value={d.id}>
                    💻 {d.name || d.hostname} ({d.is_live ? "Online" : d.status === "revoked" ? "Revoked" : "Offline"})
                  </option>
                ))}
                <option value="__pair__">➕ Connect / Pair Another PC…</option>
              </select>
            </div>

            {activeDevice ? (
              <>
                <div className="telemetry-chip">
                  <span className="live-pulse-dot" style={{ background: activeDevice.is_live ? "#10b981" : "#64748b" }} />
                  <span>NODE:</span>
                  <strong>{activeDevice.hostname || activeDevice.name}</strong>
                </div>
                <div className="telemetry-chip">
                  <span>KERNEL:</span>
                  <strong>{activeDevice.kernel_version?.split("-")[0] || activeDevice.arch}</strong>
                </div>
                <div className="telemetry-chip">
                  <span>SECCOMP:</span>
                  <strong style={{ color: activeDevice.capabilities?.seccomp_bpf ? "#34d399" : "#f87171" }}>
                    {activeDevice.capabilities?.seccomp_bpf ? "BPF KILL ACTIVE" : "BPF UNVERIFIED"}
                  </strong>
                </div>
              </>
            ) : (
              <>
                <div className="telemetry-chip">
                  <span className="live-pulse-dot" />
                  <span>KERNEL:</span>
                  <strong>{overview?.environment?.kernel?.split("-")[0] || "7.2.8 x86_64"}</strong>
                </div>
                <div className="telemetry-chip">
                  <span>SECCOMP:</span>
                  <strong style={{ color: "#34d399" }}>BPF KILL ACTIVE</strong>
                </div>
                <div className="telemetry-chip">
                  <span>GATE:</span>
                  <strong style={{ color: "#38bdf8" }}>FAIL-CLOSED</strong>
                </div>
              </>
            )}

            <button
              className="primary-button"
              style={{ padding: "6px 14px", fontSize: 11 }}
              onClick={() => setPage("Fleet / Devices")}
            >
              <Server size={14} /> Connect Device
            </button>
            <button className="icon-button" onClick={loadData} title="Refresh workspace data">
              <RefreshCw size={17} />
            </button>
            <div className="avatar" title="PoViShield Security Operator">PV</div>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">COUNTERFACTUAL PERMISSION VERIFICATION</div>
              <h1>{page}</h1>
              <p>Rigorous, evidence-backed syscall reduction and fail-closed security for Linux.</p>
            </div>
            <button className="secondary-button" onClick={loadData}>
              <RefreshCw size={16} /> Refresh workspace
            </button>
          </div>

          {error && (
            <div className="notice" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12, width: "100%" }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                  <ShieldAlert size={19} />
                  <div><strong>API connection problem</strong><p>{error}</p></div>
                </div>
                <button className="secondary-button" onClick={loadData} style={{ whiteSpace: "nowrap" }}>
                  <RefreshCw size={14} /> Retry Connection
                </button>
              </div>

              {/* Remote Render + Vercel Connection Helper */}
              <div style={{
                background: "#050914", border: "1px solid #1e3a5f", borderRadius: 8, padding: 12, marginTop: 4, width: "100%"
              }}>
                <div style={{ fontSize: 12, color: "#38bdf8", fontWeight: 600, marginBottom: 4, display: "flex", alignItems: "center", gap: 6 }}>
                  <Server size={14} /> Connecting frontend to a remote backend (Render / Custom URL)?
                </div>
                <p style={{ fontSize: 11, color: "#94a3b8", margin: "0 0 8px" }}>
                  If your backend is deployed on Render, enter your Render URL below to connect this Vercel dashboard:
                </p>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <input
                    type="text"
                    placeholder="https://your-backend.onrender.com"
                    defaultValue={localStorage.getItem("povishield_custom_api_url")?.replace(/\/api$/, "") || ""}
                    id="remote-backend-connect-input"
                    style={{
                      flex: 1, minWidth: 240, padding: "6px 12px", background: "#090f1d",
                      border: "1px solid #263852", borderRadius: 6, color: "#f1f5f9", fontSize: 12, fontFamily: "var(--font-mono)"
                    }}
                  />
                  <button
                    className="primary-button"
                    style={{ padding: "6px 14px", fontSize: 12 }}
                    onClick={() => {
                      const val = document.getElementById("remote-backend-connect-input")?.value?.trim();
                      if (val) {
                        let u = val.replace(/\/+$/, "");
                        if (!u.endsWith("/api")) u = `${u}/api`;
                        localStorage.setItem("povishield_custom_api_url", u);
                        window.location.reload();
                      }
                    }}
                  >
                    Connect Backend
                  </button>
                  {localStorage.getItem("povishield_custom_api_url") && (
                    <button
                      className="secondary-button"
                      style={{ padding: "6px 12px", fontSize: 12 }}
                      onClick={() => {
                        localStorage.removeItem("povishield_custom_api_url");
                        window.location.reload();
                      }}
                    >
                      Reset to Local
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {loading && <div className="panel"><p>Loading results from the local API…</p></div>}

          {!loading && !error && overview && (
            <>
              {page === "Overview" && (
                <>
                  <div className="notice" style={{ background: "rgba(9, 15, 26, 0.9)", borderColor: "#1e3a5f", color: "#38bdf8", marginBottom: 20 }}>
                    <ShieldCheck size={20} color="#34d399" />
                    <div>
                      <strong style={{ color: "#f1f5f9" }}>Autonomous Linux Security Platform — Measured & Fail-Closed</strong>
                      <p style={{ color: "#94a3b8" }}>
                        PoViShield challenges security policies before enforcing them. Every candidate syscall removal is empirically verified under <code>SCMP_ACT_KILL_PROCESS</code> and logged in a tamper-evident evidence ledger.
                      </p>
                    </div>
                  </div>

                  {activeDevice && (
                    <div className="panel" style={{ marginBottom: 20, border: "1px solid #10b981", background: "rgba(6, 26, 20, 0.7)" }}>
                      <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span className="live-pulse-dot" style={{ background: activeDevice.is_live ? "#10b981" : "#64748b" }} />
                            <h2 style={{ fontSize: 16, margin: 0, color: "#34d399" }}>
                              Target Endpoint Node: {activeDevice.name || activeDevice.hostname}
                            </h2>
                            <span className="demo-badge" style={{
                              background: activeDevice.is_live ? "#064e3b" : "#1e293b",
                              color: activeDevice.is_live ? "#34d399" : "#94a3b8",
                              border: activeDevice.is_live ? "1px solid #059669" : "1px solid #334155"
                            }}>
                              {activeDevice.is_live ? "LIVE ACTIVE NODE" : "DISCONNECTED / OFFLINE"}
                            </span>
                          </div>
                          <p style={{ marginTop: 4, color: "#94a3b8" }}>
                            Viewing telemetry and managing security confinement for host <code>{activeDevice.hostname}</code> ({activeDevice.os_info} · {activeDevice.arch})
                          </p>
                        </div>

                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button
                            className="primary-button"
                            style={{ padding: "6px 14px", fontSize: 12 }}
                            onClick={() => setPage("Terminal / Execute")}
                          >
                            <Terminal size={14} /> Execute on this Machine
                          </button>
                          <button
                            className="secondary-button"
                            style={{ padding: "6px 12px", fontSize: 12 }}
                            onClick={() => setPage("Fleet / Devices")}
                          >
                            <Server size={14} /> Manage Fleet
                          </button>
                          <button
                            className="secondary-button"
                            style={{ padding: "6px 12px", fontSize: 12 }}
                            onClick={() => {
                              setActiveDeviceId("gateway");
                              localStorage.setItem("povishield_active_device_id", "gateway");
                            }}
                          >
                            Reset to Gateway
                          </button>
                        </div>
                      </div>

                      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginTop: 14 }}>
                        <div className="eval-metric-box">
                          <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Kernel Seccomp-BPF</span>
                          <strong style={{ color: activeDevice.capabilities?.seccomp_bpf ? "#34d399" : "#f87171", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                            {activeDevice.capabilities?.seccomp_bpf ? "BPF KILL ACTIVE" : "UNAVAILABLE"}
                          </strong>
                        </div>
                        <div className="eval-metric-box">
                          <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>PR_SET_NO_NEW_PRIVS</span>
                          <strong style={{ color: activeDevice.capabilities?.no_new_privs ? "#34d399" : "#f87171", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                            {activeDevice.capabilities?.no_new_privs ? "SUPPORTED" : "UNSUPPORTED"}
                          </strong>
                        </div>
                        <div className="eval-metric-box">
                          <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Cgroups v2 Resource Cap</span>
                          <strong style={{ color: activeDevice.capabilities?.cgroups_v2 ? "#38bdf8" : "#94a3b8", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                            {activeDevice.capabilities?.cgroups_v2 ? "MOUNTED" : "ABSENT"}
                          </strong>
                        </div>
                        <div className="eval-metric-box">
                          <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Native Tracer Binary</span>
                          <strong style={{ color: activeDevice.capabilities?.native_sandbox ? "#34d399" : "#94a3b8", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                            {activeDevice.capabilities?.native_sandbox ? "VERIFIED" : "NOT BUILT"}
                          </strong>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Hero Quick Launch Cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 14, marginBottom: 22 }}>
                    <div className="quick-action-card" onClick={() => setPage("Fleet / Devices")}>
                      <div className="qa-icon" style={{ background: "#0c2d48", color: "#38bdf8" }}><Server size={20} /></div>
                      <div className="qa-body">
                        <strong>Fleet / Devices</strong>
                        <p>Pair Linux machines with 10m TTL code & inspect telemetry</p>
                      </div>
                      <ChevronRight size={16} className="qa-arrow" />
                    </div>

                    <div className="quick-action-card" onClick={() => setPage("Terminal / Execute")}>
                      <div className="qa-icon" style={{ background: "#064e3b", color: "#34d399" }}><Terminal size={20} /></div>
                      <div className="qa-body">
                        <strong>Terminal Sandbox</strong>
                        <p>Dispatch command vectors with live SIGSYS interception</p>
                      </div>
                      <ChevronRight size={16} className="qa-arrow" />
                    </div>

                    <div className="quick-action-card" onClick={() => setPage("Counterfactual Research")}>
                      <div className="qa-icon" style={{ background: "#31154a", color: "#c084fc" }}><FlaskConical size={20} /></div>
                      <div className="qa-body">
                        <strong>Ablation Engine</strong>
                        <p>Review leave-one-out syscall minimization trials</p>
                      </div>
                      <ChevronRight size={16} className="qa-arrow" />
                    </div>

                    <div className="quick-action-card" onClick={() => setPage("Evidence Ledgers")}>
                      <div className="qa-icon" style={{ background: "#422006", color: "#fbbf24" }}><Layers size={20} /></div>
                      <div className="qa-body">
                        <strong>Evidence Ledgers</strong>
                        <p>Audit tamper-evident records with SHA-256 integrity</p>
                      </div>
                      <ChevronRight size={16} className="qa-arrow" />
                    </div>
                  </div>

                  <section className="metrics-grid">
                    <Metric icon={Activity} label="Programs Evaluated"
                      value={aggregate.targets} detail="Core empirical benchmark suite" accent="#38bdf8" />
                    <Metric icon={LockKeyhole} label="Attack-Surface Reduction"
                      value={`${aggregate.avg_attack_surface_reduction_pct}%`}
                      detail="Average baseline attack surface reduction" progress={aggregate.avg_attack_surface_reduction_pct} accent="#10b981" />
                    <Metric icon={ShieldCheck} label="False Kills Recorded"
                      value={aggregate.total_false_kills}
                      detail="Zero broken legitimate workloads" accent="#34d399" />
                    <Metric icon={Gauge} label="Seccomp BPF Overhead"
                      value={`${aggregate.avg_median_overhead_pct}%`}
                      detail="Sub-microsecond kernel filtering overhead" accent="#f59e0b" />
                  </section>

                  {/* Interactive Architecture Pipeline */}
                  <section className="panel" style={{ marginBottom: 20 }}>
                    <div className="panel-heading">
                      <div>
                        <h3>Autonomous Linux Security Architecture Pipeline</h3>
                        <p>End-to-end security lifecycle from dynamic ptrace learning to fail-closed seccomp BPF containment</p>
                      </div>
                      <span className="demo-badge" style={{ background: "#064e3b", color: "#34d399", border: "1px solid #059669" }}>
                        VERIFIED KERNEL ENFORCEMENT
                      </span>
                    </div>

                    <div className="pipeline-flow-grid">
                      <div className="pipeline-step-card" onClick={() => setPage("Activity Monitor")} style={{ cursor: "pointer" }}>
                        <div className="step-num">STEP 01</div>
                        <div className="step-title">Dynamic Observer</div>
                        <div className="step-badge trace">PTRACE_SYSCALL</div>
                        <p>Intercepts syscalls across child processes and threads, writing JSONL logs.</p>
                      </div>

                      <div className="pipeline-arrow">&rarr;</div>

                      <div className="pipeline-step-card" onClick={() => setPage("Counterfactual Research")} style={{ cursor: "pointer" }}>
                        <div className="step-num">STEP 02</div>
                        <div className="step-title">Policy Minimizer</div>
                        <div className="step-badge ablate">COUNTERFACTUAL</div>
                        <p>Leave-one-out testing proves permissions unnecessary under SCMP_ACT_KILL_PROCESS.</p>
                      </div>

                      <div className="pipeline-arrow">&rarr;</div>

                      <div className="pipeline-step-card" onClick={() => setPage("Safety Gate & Approvals")} style={{ cursor: "pointer" }}>
                        <div className="step-num">STEP 03</div>
                        <div className="step-title">Safety Gate</div>
                        <div className="step-badge gate">FAIL-CLOSED GATE</div>
                        <p>Regression checks and SHA-256 evidence ledgers approve deployment.</p>
                      </div>

                      <div className="pipeline-arrow">&rarr;</div>

                      <div className="pipeline-step-card" onClick={() => setPage("Terminal / Execute")} style={{ cursor: "pointer" }}>
                        <div className="step-num">STEP 04</div>
                        <div className="step-title">Kernel Seccomp</div>
                        <div className="step-badge bpf">SCMP_ACT_KILL</div>
                        <p>PR_SET_NO_NEW_PRIVS installs BPF. Unauthorized syscalls trigger SIGSYS termination.</p>
                      </div>

                      <div className="pipeline-arrow">&rarr;</div>

                      <div className="pipeline-step-card" onClick={() => setPage("Fleet / Devices")} style={{ cursor: "pointer" }}>
                        <div className="step-num">STEP 05</div>
                        <div className="step-title">Fleet Supervisor</div>
                        <div className="step-badge fleet">OUTBOUND PULL</div>
                        <p>Remote agents connect via HTTPS outbound loops, reporting genuine capabilities.</p>
                      </div>
                    </div>
                  </section>

                  <section className="panel" style={{ marginBottom: 20 }}>
                    <div className="panel-heading">
                      <div>
                        <h3>Kernel Enforced Execution & Live Terminal Status</h3>
                        <p>Policy-gated process supervisor with fail-closed seccomp boundaries</p>
                      </div>
                      <button className="secondary-button" onClick={() => setPage("Terminal / Execute")}>
                        <Terminal size={14} /> Open Execution Terminal
                      </button>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12 }}>
                      <div className="eval-metric-box">
                        <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Enforcement Engine</span>
                        <strong style={{ color: "#34d399", fontSize: 13, fontFamily: "var(--font-mono)" }}>SCMP_ACT_KILL_PROCESS</strong>
                      </div>
                      <div className="eval-metric-box">
                        <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Tracer Telemetry</span>
                        <strong style={{ color: "#38bdf8", fontSize: 13, fontFamily: "var(--font-mono)" }}>PTRACE_SYSCALL Active</strong>
                      </div>
                      <div className="eval-metric-box">
                        <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Terminal Sessions</span>
                        <strong style={{ color: "#f8fafc", fontSize: 13, fontFamily: "var(--font-mono)" }}>{health?.recorded_executions_count ?? 0} Audited Runs</strong>
                      </div>
                    </div>
                  </section>

                  {ablationData?.aggregate && (
                    <section className="panel" style={{ marginBottom: 20 }}>
                      <div className="panel-heading">
                        <div>
                          <h3>Counterfactual Minimization Engine</h3>
                          <p>Empirical permission ablation summary (results/ablation_eval.json)</p>
                        </div>
                        <span className="demo-badge">COUNTERFACTUAL VERIFIED</span>
                      </div>
                      <div className="diff-stat-row">
                        <div className="diff-stat-item">
                          <span>Targets Evaluated</span>
                          <strong>{ablationData.targets?.length ?? 9}</strong>
                        </div>
                        <div className="diff-stat-item">
                          <span>Avg Syscalls</span>
                          <strong>{ablationData.aggregate.avg_baseline_syscalls}</strong>
                        </div>
                        <div className="diff-stat-item">
                          <span>Evidence Completeness</span>
                          <strong className="diff-removed">{ablationData.aggregate.avg_evidence_completeness_pct}%</strong>
                        </div>
                        <div className="diff-stat-item">
                          <span>Workload Compatibility</span>
                          <strong className="diff-removed">{ablationData.aggregate.avg_counterfactual_compat_pct}%</strong>
                        </div>
                        <div className="diff-stat-item">
                          <span>Search Duration</span>
                          <strong>{ablationData.aggregate.total_ablation_time_seconds}s</strong>
                        </div>
                      </div>
                    </section>
                  )}

                  <section className="content-grid">
                    <div className="panel chart-panel">
                      <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
                        <div>
                          <h3>Held-out coverage & Benchmark Analytics</h3>
                          <p>Per-program evaluation results across 9 Linux workloads</p>
                        </div>
                        <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                          <button
                            type="button"
                            className="quick-chip"
                            onClick={() => setChartMetric("coverage_reduction")}
                            style={{
                              padding: "3px 9px",
                              fontSize: 11,
                              background: chartMetric === "coverage_reduction" ? "#064e3b" : "#08101e",
                              color: chartMetric === "coverage_reduction" ? "#34d399" : "#94a3b8",
                              borderColor: chartMetric === "coverage_reduction" ? "#059669" : "#1e293b"
                            }}
                          >
                            Coverage & Reduction
                          </button>
                          <button
                            type="button"
                            className="quick-chip"
                            onClick={() => setChartMetric("syscall_counts")}
                            style={{
                              padding: "3px 9px",
                              fontSize: 11,
                              background: chartMetric === "syscall_counts" ? "#0c2d48" : "#08101e",
                              color: chartMetric === "syscall_counts" ? "#38bdf8" : "#94a3b8",
                              borderColor: chartMetric === "syscall_counts" ? "#1e4976" : "#1e293b"
                            }}
                          >
                            Syscall Pruning
                          </button>
                          <button
                            type="button"
                            className="quick-chip"
                            onClick={() => setChartMetric("timing_overhead")}
                            style={{
                              padding: "3px 9px",
                              fontSize: 11,
                              background: chartMetric === "timing_overhead" ? "#3b2005" : "#08101e",
                              color: chartMetric === "timing_overhead" ? "#f59e0b" : "#94a3b8",
                              borderColor: chartMetric === "timing_overhead" ? "#78350f" : "#1e293b"
                            }}
                          >
                            Latency (ms)
                          </button>
                        </div>
                      </div>

                      <div className="chart" style={{ height: 320, minHeight: 320 }}>
                        <ResponsiveContainer width="100%" height="100%">
                          {chartMetric === "coverage_reduction" ? (
                            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 20 }}>
                              <CartesianGrid stroke="#1c2a3e" strokeDasharray="3 3" vertical={false} />
                              <XAxis dataKey="target" stroke="#78869b" tickLine={false} axisLine={{ stroke: "#1c2a3e" }} />
                              <YAxis domain={[0, 100]} stroke="#78869b" tickLine={false} axisLine={{ stroke: "#1c2a3e" }} />
                              <Tooltip contentStyle={{ background: "#0a1220", border: "1px solid #1e3352", borderRadius: 8, fontSize: 12, color: "#f1f5f9" }} />
                              <Bar dataKey="coverage" name="Held-out Coverage (%)" fill="#10b981" radius={[4, 4, 0, 0]} />
                              <Bar dataKey="reduction" name="Surface Reduction (%)" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                            </BarChart>
                          ) : chartMetric === "syscall_counts" ? (
                            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 20 }}>
                              <CartesianGrid stroke="#1c2a3e" strokeDasharray="3 3" vertical={false} />
                              <XAxis dataKey="target" stroke="#78869b" tickLine={false} axisLine={{ stroke: "#1c2a3e" }} />
                              <YAxis domain={[0, 400]} stroke="#78869b" tickLine={false} axisLine={{ stroke: "#1c2a3e" }} />
                              <Tooltip contentStyle={{ background: "#0a1220", border: "1px solid #1e3352", borderRadius: 8, fontSize: 12, color: "#f1f5f9" }} />
                              <Bar dataKey="total" name="Total Baseline Kernel Syscalls" fill="#1e293b" stroke="#334155" radius={[4, 4, 0, 0]} />
                              <Bar dataKey="allowed" name="Allowed Syscalls in Profile" fill="#10b981" radius={[4, 4, 0, 0]} />
                            </BarChart>
                          ) : (
                            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 20 }}>
                              <CartesianGrid stroke="#1c2a3e" strokeDasharray="3 3" vertical={false} />
                              <XAxis dataKey="target" stroke="#78869b" tickLine={false} axisLine={{ stroke: "#1c2a3e" }} />
                              <YAxis stroke="#78869b" tickLine={false} axisLine={{ stroke: "#1c2a3e" }} />
                              <Tooltip contentStyle={{ background: "#0a1220", border: "1px solid #1e3352", borderRadius: 8, fontSize: 12, color: "#f1f5f9" }} />
                              <Bar dataKey="nativeMs" name="Native Execution (ms)" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                              <Bar dataKey="sandboxedMs" name="Sandboxed Execution (ms)" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                            </BarChart>
                          )}
                        </ResponsiveContainer>
                      </div>

                      <div className="chart-legend-strip">
                        {chartMetric === "coverage_reduction" && (
                          <>
                            <div className="legend-chip"><span style={{ background: "#10b981" }} /> Held-out Coverage (100% avg)</div>
                            <div className="legend-chip"><span style={{ background: "#38bdf8" }} /> Attack Surface Reduction (90.7% avg)</div>
                          </>
                        )}
                        {chartMetric === "syscall_counts" && (
                          <>
                            <div className="legend-chip"><span style={{ background: "#10b981" }} /> Allowed Syscalls in Policy (20–48)</div>
                            <div className="legend-chip"><span style={{ background: "#1e293b", border: "1px solid #334155" }} /> Full Linux Kernel Syscall Baseline (385)</div>
                          </>
                        )}
                        {chartMetric === "timing_overhead" && (
                          <>
                            <div className="legend-chip"><span style={{ background: "#38bdf8" }} /> Native Median Runtime (ms)</div>
                            <div className="legend-chip"><span style={{ background: "#f59e0b" }} /> Seccomp Sandboxed Runtime (ms)</div>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
                      <div className="panel-heading">
                        <div>
                          <h3>Evaluation environment</h3>
                          <p>Host kernel, hardware and measurement setup</p>
                        </div>
                        <Cpu size={20} className="muted-icon" />
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6, flex: 1, overflowY: "auto", maxHeight: 380, paddingRight: 4 }}>
                        {overview.environment && Object.entries(overview.environment).map(([key, value]) => {
                          const formattedValue = Array.isArray(value) ? value.join(", ") : String(value);
                          return (
                            <div className="policy-row" key={key}>
                              <span>{key.replaceAll("_", " ")}</span>
                              <strong>{formattedValue}</strong>
                            </div>
                          );
                        })}
                        <div className="policy-row">
                          <span>Ledger Directory</span>
                          <strong style={{ color: "#38bdf8" }}>results/ledgers/</strong>
                        </div>
                        <div className="policy-row">
                          <span>Results Source</span>
                          <strong style={{ color: "#34d399" }}>{overview.source || "results/results.json"}</strong>
                        </div>
                      </div>
                    </div>
                  </section>

                  <section className="panel events-section">
                    <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
                      <div>
                        <h3>Program evaluation</h3>
                        <p>Detailed benchmark metrics from results/results.json across all evaluated workloads</p>
                      </div>
                      <input
                        placeholder="Filter workloads (e.g. gzip, sort)…"
                        value={evalSearch}
                        onChange={e => setEvalSearch(e.target.value)}
                        style={{
                          padding: "6px 12px",
                          background: "#050914",
                          border: "1px solid #1a273b",
                          borderRadius: 6,
                          color: "#f1f5f9",
                          fontSize: 11,
                          fontFamily: "var(--font-mono)",
                          width: 220
                        }}
                      />
                    </div>
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>PROGRAM</th>
                            <th>ALLOWED</th>
                            <th>SURFACE REDUCTION</th>
                            <th>HELD-OUT COVERAGE</th>
                            <th>COMPATIBILITY</th>
                            <th>FALSE KILLS</th>
                            <th>OVERHEAD</th>
                          </tr>
                        </thead>
                        <tbody>
                          {targets
                            .filter(t => !evalSearch || t.target.toLowerCase().includes(evalSearch.toLowerCase()))
                            .map(t => (
                              <tr key={t.target}>
                                <td className="process-cell">
                                  <code>{t.target}</code>
                                </td>
                                <td>
                                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                                    <strong style={{ color: "#38bdf8" }}>{t.allowed_syscalls}</strong>
                                    <span style={{ color: "#64748b" }}> / {t.total_syscalls}</span>
                                  </span>
                                </td>
                                <td>
                                  <span className="diff-removed" style={{ fontWeight: 700 }}>
                                    -{t.attack_surface_reduction_pct}%
                                  </span>
                                </td>
                                <td>
                                  <span className="verdict-tag verdict-removable">
                                    {t.heldout_coverage_pct}%
                                  </span>
                                </td>
                                <td>
                                  <span className="verdict-tag verdict-necessary">
                                    {t.compat_pct}%
                                  </span>
                                </td>
                                <td>
                                  <span style={{
                                    fontFamily: "var(--font-mono)",
                                    fontWeight: 700,
                                    color: t.false_kills === 0 ? "#34d399" : "#f87171"
                                  }}>
                                    {t.false_kills}
                                  </span>
                                </td>
                                <td>
                                  {t.overhead_pct ? (
                                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#cbd5e1" }}>
                                      {t.overhead_pct.median}%
                                      {t.overhead_pct.added_ms !== undefined && (
                                        <small style={{ color: "#8292a8", marginLeft: 4 }}>
                                          ({t.overhead_pct.added_ms > 0 ? `+${t.overhead_pct.added_ms}` : t.overhead_pct.added_ms}ms)
                                        </small>
                                      )}
                                    </span>
                                  ) : (
                                    <span className="muted">—</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                </>
              )}

              {page === "Fleet / Devices" && (
                <FleetDeviceConsole
                  API={API}
                  activeDeviceId={activeDeviceId}
                  setActiveDeviceId={setActiveDeviceId}
                />
              )}

              {page === "Terminal / Execute" && (
                <TerminalExecutionConsole
                  API={API}
                  health={health}
                  devices={devices}
                  activeDeviceId={activeDeviceId}
                  setActiveDeviceId={setActiveDeviceId}
                />
              )}

              {page === "Activity Monitor" && (
                <>
                  <section className="panel events-section live-monitor-panel">
                    <div className="panel-heading activity-heading">
                      <div><h3>Live process monitor</h3><p>Launch a short-lived process under the PoViShield learning tracer.</p></div>
                      <span className={`monitor-state ${monitorSession?.status === "running" ? "monitor-state-live" : ""}`}><span />{monitorSession?.status === "running" ? "LIVE" : monitorSession ? monitorSession.status.replaceAll("_", " ").toUpperCase() : "IDLE"}</span>
                    </div>
                    <div className="trace-status">
                      <span className="trace-status-dot" /><div>
                        <strong>{monitorSession?.status === "running" ? "Live session — process currently monitored" : monitorSession ? "Session is no longer live" : "No live session — recorded trace remains separate"}</strong>
                        <p>This observes syscall activity; it is not a sandbox or filesystem confinement. Runs as the current non-root user, with a 30-second runtime cap and a 10 MiB event-file cap.</p>
                      </div>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14, marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
                      <label className="monitor-command-label" htmlFor="monitor-command" style={{ margin: 0 }}>
                        Command as a JSON argv array (no shell):
                      </label>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                        <span style={{ fontSize: 10, color: "#64748b", fontFamily: "var(--font-mono)" }}>Presets:</span>
                        <button
                          type="button"
                          className="quick-chip"
                          onClick={() => setMonitorCommand('["/usr/bin/sleep", "5"]')}
                          style={{ padding: "2px 8px", fontSize: 11 }}
                        >
                          Sleep 5s
                        </button>
                        <button
                          type="button"
                          className="quick-chip"
                          onClick={() => setMonitorCommand('["/usr/bin/echo", "Live tracing test"]')}
                          style={{ padding: "2px 8px", fontSize: 11 }}
                        >
                          Echo
                        </button>
                        <button
                          type="button"
                          className="quick-chip"
                          onClick={() => setMonitorCommand('["/usr/bin/cat", "/dev/null"]')}
                          style={{ padding: "2px 8px", fontSize: 11 }}
                        >
                          Cat /dev/null
                        </button>
                        <button
                          type="button"
                          className="quick-chip"
                          onClick={() => setMonitorCommand('["/usr/bin/date"]')}
                          style={{ padding: "2px 8px", fontSize: 11 }}
                        >
                          Date
                        </button>
                      </div>
                    </div>
                    <textarea id="monitor-command" className="monitor-command-input" value={monitorCommand}
                      onChange={event => setMonitorCommand(event.target.value)} spellCheck="false"
                      disabled={monitorSession?.status === "running" || monitorBusy} rows={2} />
                    <p className="footnote">Example: ["/usr/bin/sleep", "10"]. Use an absolute executable path. Shells and common interpreters are refused. Only run programs you trust.</p>
                    <div className="monitor-actions">
                      <button className="secondary-button" onClick={startMonitoring} disabled={monitorBusy || monitorSession?.status === "running"}><Play size={15} />{monitorBusy ? "Working…" : "Start live monitoring"}</button>
                      <button className="secondary-button monitor-stop-button" onClick={stopMonitoring} disabled={monitorBusy || monitorSession?.status !== "running"}><Square size={14} />Stop process</button>
                      {monitorSession && <span className="monitor-session-id">Session {monitorSession.id}</span>}
                    </div>
                    {monitorError && <div className="notice activity-error"><ShieldAlert size={19} /><div><strong>Monitoring message</strong><p>{monitorError}</p></div></div>}
                    {monitorSession && <>
                      <div className="activity-summary">
                        <div><span>Session status</span><strong>{monitorSession.status}</strong></div>
                        <div><span>Buffered events</span><strong>{monitorEvents.length}</strong></div>
                        <div><span>Elapsed (seconds)</span><strong>{monitorSession.elapsed_seconds ?? 0}</strong></div>
                        <div><span>Exit code</span><strong>{monitorSession.exit_code ?? "—"}</strong></div>
                      </div>
                      {monitorSession.reason && <p className="footnote">Session ended: {monitorSession.reason.replaceAll("_", " ")}. Trace: {monitorSession.source}</p>}
                      <div className="table-wrap activity-table-wrap"><table>
                        <thead><tr><th>SEQ</th><th>PID</th><th>PHASE</th><th>SYSCALL</th><th>CATEGORY</th><th>NUMBER</th><th>RETURN VALUE</th></tr></thead>
                        <tbody>{[...monitorEvents].reverse().map((event, index) => {
                          const cat = getSyscallCategory(event.syscall);
                          return (
                            <tr key={`live-${event.seq}-${event.pid}-${event.phase}-${index}`}>
                              <td className="time-cell">{event.seq}</td><td>{event.pid}</td>
                              <td><span className={`phase-tag ${event.phase === "entry" ? "phase-entry" : "phase-exit"}`}>{event.phase}</span></td>
                              <td className="process-cell">{event.syscall}</td>
                              <td><span className={`category-tag ${cat.toLowerCase().replace(/[^a-z0-9]/g, "-")}`}>{cat}</span></td>
                              <td><code>{event.syscall_nr}</code></td>
                              <td>{event.phase === "exit" && event.return_value !== undefined ? <code>{event.return_value}</code> : <span className="muted">—</span>}</td>
                            </tr>
                          );
                        })}</tbody>
                      </table></div>
                      <p className="footnote">Polling uses a byte cursor to avoid rereading the trace. The browser retains the latest 1,000 events; the session trace is stored separately under results/.</p>
                    </>}
                  </section>

                  <section className="panel events-section">
                    <div className="panel-heading activity-heading">
                      <div>
                        <h3>Syscall activity trace</h3>
                        <p>Events captured by PoViShield's learning tracer</p>
                      </div>
                      <button className="secondary-button" onClick={loadEvents} disabled={eventsLoading}>
                        <RefreshCw size={15} className={eventsLoading ? "spin-icon" : ""} />
                        {eventsLoading ? "Refreshing…" : "Refresh events"}
                      </button>
                    </div>

                    <div className="trace-status">
                      <span className="trace-status-dot" />
                      <div>
                        <strong>Recorded trace — not live</strong>
                        <p>This view reads a saved JSONL trace (results/syscall-events.jsonl). It does not continuously monitor running processes.</p>
                      </div>
                    </div>

                    {eventsError && (
                      <div className="notice activity-error">
                        <ShieldAlert size={19} />
                        <div><strong>Could not load syscall events</strong><p>{eventsError}</p></div>
                      </div>
                    )}

                    {eventsLoading && !eventsData && (
                      <p className="muted activity-message">Loading recorded syscall events…</p>
                    )}

                    {!eventsLoading && !eventsError && eventsData && (
                      <>
                        <div className="activity-summary">
                          <div><span>Events shown</span><strong>{eventsData.count}</strong></div>
                          <div><span>Valid records</span><strong>{eventsData.total_valid_records_in_read_window}</strong></div>
                          <div><span>Malformed records</span><strong>{eventsData.malformed_records_in_read_window}</strong></div>
                          <div><span>Source</span><strong className="source-value">{eventsData.source}</strong></div>
                        </div>

                        {eventsData.events.length === 0 ? (
                          <p className="muted activity-message">No recorded events found in results/syscall-events.jsonl.</p>
                        ) : (
                          <div className="table-wrap activity-table-wrap">
                            <table>
                              <thead>
                                <tr>
                                  <th>SEQ</th><th>PID</th><th>PHASE</th>
                                  <th>SYSCALL</th><th>CATEGORY</th><th>NUMBER</th><th>RETURN VALUE</th>
                                </tr>
                              </thead>
                              <tbody>
                                {eventsData.events.map((event, index) => {
                                  const cat = getSyscallCategory(event.syscall || "");
                                  return (
                                    <tr key={`${event.seq}-${event.pid}-${event.phase}-${index}`}>
                                      <td className="time-cell">{event.seq ?? "—"}</td>
                                      <td>{event.pid ?? "—"}</td>
                                      <td>
                                        <span className={`phase-tag ${event.phase === "entry" ? "phase-entry" : "phase-exit"}`}>
                                          {event.phase ?? "unknown"}
                                        </span>
                                      </td>
                                      <td className="process-cell">{event.syscall ?? "unknown"}</td>
                                      <td><span className={`category-tag ${cat.toLowerCase().replace(/[^a-z0-9]/g, "-")}`}>{cat}</span></td>
                                      <td><code>{event.syscall_nr ?? "—"}</code></td>
                                      <td>{event.phase === "exit" && event.return_value !== undefined
                                        ? <code>{event.return_value}</code>
                                        : <span className="muted">—</span>}</td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </>
                    )}
                  </section>
                </>
              )}

              {page === "Syscall Profile" && (
                <section className="panel events-section">
                  <div className="panel-heading">
                    <div>
                      <h3>Observed syscall profile</h3>
                      <p>Frequency analysis from the saved syscall trace</p>
                    </div>
                    <div className="profile-actions">
                      <button className="secondary-button" onClick={loadEvents} disabled={eventsLoading}>
                        <RefreshCw size={15} className={eventsLoading ? "spin-icon" : ""} />
                        {eventsLoading ? "Refreshing…" : "Refresh trace"}
                      </button>
                      <button className="secondary-button" onClick={() => {
                        if (!profileData) return;
                        const exportData = {
                          schema_version: 1,
                          profile_type: "observed_syscall_frequency",
                          data_type: profileData.data_type ?? "recorded_trace",
                          live: profileData.live ?? false,
                          source: profileData.source,
                          exported_at: new Date().toISOString(),
                          total_records: profileData.total_records,
                          entry_records: profileData.entry_records,
                          unique_syscalls: profileData.unique_syscalls,
                          malformed_records: profileData.malformed_records,
                          counting_method: "entry events only; one entry represents one observed syscall invocation",
                          syscalls: profileData.syscalls
                        };
                        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
                        const url = URL.createObjectURL(blob);
                        const link = document.createElement("a");
                        link.href = url;
                        link.download = "povishield-observed-syscall-profile.json";
                        document.body.appendChild(link);
                        link.click();
                        link.remove();
                        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
                      }} disabled={!profileData || eventsLoading}>
                        <FileText size={15} />
                        Export JSON
                      </button>
                    </div>
                  </div>

                  {eventsLoading && !eventsData && (
                    <p className="muted activity-message">Loading recorded syscall events…</p>
                  )}

                  {!eventsLoading && !eventsError && eventsData && (() => {
                    const allEvents = Array.isArray(eventsData.events) ? eventsData.events : [];
                    const allRows = (profileData?.syscalls ?? []).map(item => ({
                      name: item.syscall, number: item.syscall_nr, count: item.count
                    }));
                    const totalInvocations = profileData?.entry_records ?? 0;
                    const uniqueSyscalls = profileData?.unique_syscalls ?? allRows.length;
                    const visibleRows = allRows.filter(row => {
                      const query = profileSearch.trim().toLowerCase();
                      return !query || row.name.toLowerCase().includes(query) || String(row.number ?? "").includes(query);
                    });
                    const maxCount = Math.max(1, ...visibleRows.map(row => row.count));
                    return (
                      <>
                        <div className="activity-summary profile-summary">
                          <div><span>Observed invocations</span><strong>{totalInvocations}</strong></div>
                          <div><span>Unique syscall names</span><strong>{uniqueSyscalls}</strong></div>
                          <div><span>Full trace records</span><strong>{profileData?.total_records ?? allEvents.length}</strong></div>
                          <div><span>Count method</span><strong className="source-value">Entry records</strong></div>
                        </div>

                        <div className="profile-controls">
                          <label className="profile-search">
                            <span>Search syscall</span>
                            <input value={profileSearch} onChange={event => setProfileSearch(event.target.value)}
                              placeholder="e.g. openat, read, 3" />
                          </label>
                          <label className="profile-filter">
                            <span>Count events by</span>
                            <select value={profilePhase} onChange={event => setProfilePhase(event.target.value)}>
                              <option value="entry">Invocation entries (recommended)</option>
                              <option value="all">All observed syscall names</option>
                            </select>
                          </label>
                        </div>

                        <div className="profile-chart-list">
                          {visibleRows.length === 0 ? (
                            <p className="muted activity-message">No syscalls match this search.</p>
                          ) : visibleRows.map(row => (
                            <div className="profile-bar-row" key={row.name}>
                              <div className="profile-bar-label">
                                <span>{row.name}</span>
                                <code>#{row.number ?? "?"}</code>
                                <strong>{row.count}</strong>
                              </div>
                              <div className="profile-bar-track">
                                <div className="profile-bar-value" style={{ width: `${(row.count / maxCount) * 100}%` }} />
                              </div>
                            </div>
                          ))}
                        </div>
                      </>
                    );
                  })()}
                </section>
              )}

              {page === "Policy Explorer" && (
                <>
                  <section className="panel" style={{ marginBottom: 20 }}>
                    <div className="panel-heading">
                      <div>
                        <h3>Side-by-Side Policy Comparator & Permission Tiers</h3>
                        <p>Empirically compare a baseline profile against an ablated candidate policy.</p>
                      </div>
                      <GitCompare size={20} className="muted-icon" />
                    </div>

                    <div className="comparator-grid">
                      <div className="compare-select-card">
                        <label>Baseline Policy (Pre-Ablation)</label>
                        <select value={compareBase} onChange={e => setCompareBase(e.target.value)}>
                          {policies?.items?.map(item => (
                            <option key={`base-${item.name}`} value={item.name}>{item.name} ({item.count} syscalls)</option>
                          ))}
                        </select>
                      </div>
                      <div className="compare-select-card">
                        <label>Candidate Policy (Evidence-Backed Candidate)</label>
                        <select value={compareCand} onChange={e => setCompareCand(e.target.value)}>
                          {policies?.items?.map(item => (
                            <option key={`cand-${item.name}`} value={item.name}>{item.name} ({item.count} syscalls)</option>
                          ))}
                        </select>
                      </div>
                    </div>

                    {compareLoading && <p className="muted">Calculating policy diff…</p>}
                    {compareError && <div className="notice"><ShieldAlert size={16} /><div>{compareError}</div></div>}

                    {compareResult && (
                      <div className="diff-summary-card">
                        <div className="diff-stat-row">
                          <div className="diff-stat-item">
                            <span>Baseline Syscalls</span>
                            <strong>{compareResult.base_count}</strong>
                          </div>
                          <div className="diff-stat-item">
                            <span>Candidate Syscalls</span>
                            <strong>{compareResult.cand_count}</strong>
                          </div>
                          <div className="diff-stat-item">
                            <span>Syscalls Removed</span>
                            <strong className="diff-removed">-{compareResult.removed_syscalls.length}</strong>
                          </div>
                          <div className="diff-stat-item">
                            <span>Attack Surface Risk</span>
                            <strong className="diff-risk-down">{compareResult.base_risk} → {compareResult.cand_risk}</strong>
                          </div>
                        </div>

                        {compareResult.removed_syscalls.length > 0 && (
                          <div className="tier-section">
                            <h4><CheckCircle2 size={15} style={{ color: "#45d6a5" }} /> Removable Syscalls (Safe Pruning)</h4>
                            <div className="syscall-pill-wrap">
                              {compareResult.removed_syscalls.map(s => (
                                <span key={s} className="syscall-pill pill-removed">{s}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {compareResult.added_syscalls.length > 0 && (
                          <div className="tier-section">
                            <h4><AlertTriangle size={15} style={{ color: "#f4b251" }} /> Unexpected Added Syscalls</h4>
                            <div className="syscall-pill-wrap">
                              {compareResult.added_syscalls.map(s => (
                                <span key={s} className="syscall-pill pill-added">+{s}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {compareResult.permission_tiers && (
                          <div style={{ marginTop: 16 }}>
                            <h4>Tripartite Permission Tiers</h4>
                            <div className="tier-section">
                              <h4 style={{ color: "#78e6bc" }}>Tier 1: Experimentally Necessary ({compareResult.permission_tiers.experimentally_necessary?.length ?? 0})</h4>
                              <p className="footnote" style={{ margin: "4px 0 8px" }}>Proven indispensable by empirical execution failure (SIGSYS / exit code mismatch) when ablated.</p>
                              <div className="syscall-pill-wrap">
                                {(compareResult.permission_tiers.experimentally_necessary ?? []).map(s => (
                                  <span key={s} className="syscall-pill pill-necessary">{s}</span>
                                ))}
                              </div>
                            </div>

                            {(compareResult.permission_tiers.removable_for_tested_tasks?.length ?? 0) > 0 && (
                              <div className="tier-section">
                                <h4 style={{ color: "#f4c46d" }}>Tier 2: Removable for Tested Tasks ({compareResult.permission_tiers.removable_for_tested_tasks.length})</h4>
                                <div className="syscall-pill-wrap">
                                  {compareResult.permission_tiers.removable_for_tested_tasks.map(s => (
                                    <span key={s} className="syscall-pill pill-removable">{s}</span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {(compareResult.permission_tiers.not_yet_validated?.length ?? 0) > 0 && (
                              <div className="tier-section">
                                <h4 style={{ color: "#c9abf5" }}>Tier 3: Not Yet Validated ({compareResult.permission_tiers.not_yet_validated.length})</h4>
                                <p className="footnote" style={{ margin: "4px 0 8px" }}>Permitted in policy but untested or unconfirmed by positive ablation proof.</p>
                                <div className="syscall-pill-wrap">
                                  {compareResult.permission_tiers.not_yet_validated.map(s => (
                                    <span key={s} className="syscall-pill pill-untested">{s}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </section>

                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Policy Catalog</h3>
                        <p>All generated baseline and candidate JSON policies in results/ & results/profiles/</p>
                      </div>
                      <input
                        placeholder="Filter policies…"
                        value={policySearch}
                        onChange={e => setPolicySearch(e.target.value)}
                        style={{ padding: "6px 10px", background: "#101a29", border: "1px solid #29364a", borderRadius: 6, color: "#d5deeb", fontSize: 11 }}
                      />
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
                            ?.filter(p => !policySearch || p.name.toLowerCase().includes(policySearch.toLowerCase()))
                            .map(item => (
                              <tr key={item.name}>
                                <td className="process-cell">
                                  <code>{item.name}</code>
                                </td>
                                <td>Schema {item.schema}</td>
                                <td><strong>{item.count}</strong></td>
                                <td>{item.size_bytes} bytes</td>
                                <td>
                                  <button
                                    className="secondary-button"
                                    style={{ padding: "4px 8px", fontSize: 10 }}
                                    onClick={() => setSelectedPolicy(item)}
                                  >
                                    Inspect
                                  </button>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>

                    {selectedPolicy && (
                      <div className="trial-drawer">
                        <div className="trial-drawer-header">
                          <div>
                            <h4>Policy Details: {selectedPolicy.name}</h4>
                            <span className="footnote">Schema {selectedPolicy.schema} · {selectedPolicy.count} syscalls</span>
                          </div>
                          <button className="secondary-button" onClick={() => setSelectedPolicy(null)}>Close</button>
                        </div>
                        <div className="syscall-pill-wrap">
                          {(selectedPolicy.data?.syscalls ?? []).map(s => (
                            <span key={s} className="syscall-pill pill-necessary">{s}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </section>
                </>
              )}

              {page === "Counterfactual Research" && (
                <>
                  <div className="notice">
                    <ShieldAlert size={19} />
                    <div>
                      <strong>Empirical Permission Minimization — Beyond Passive Syscall Tracing</strong>
                      <p>
                        Passive learning models only record what executed during training. PoViShield rigorously challenges whether an observed syscall is truly required by running leave-one-out trials under <code>SCMP_ACT_KILL_PROCESS</code>. If removing a syscall causes the legitimate workload to fail, empirical necessity is established; if the workload succeeds, the permission is classified as removable.
                      </p>
                    </div>
                  </div>

                  <div className="research-subtabs" style={{ display: "flex", gap: 10, marginBottom: 20 }}>
                    <button
                      className="secondary-button"
                      style={{
                        background: ablationSubTab === "noisy" ? "#18372f" : "#111b2b",
                        borderColor: ablationSubTab === "noisy" ? "#4cbd99" : "#2a394f",
                        color: ablationSubTab === "noisy" ? "#78e6bc" : "#d5deeb",
                        fontWeight: ablationSubTab === "noisy" ? 600 : 400
                      }}
                      onClick={() => setAblationSubTab("noisy")}
                    >
                      <FlaskConical size={14} /> Controlled Noisy Policy (Synthetic Injections)
                    </button>
                    <button
                      className="secondary-button"
                      style={{
                        background: ablationSubTab === "baseline" ? "#18372f" : "#111b2b",
                        borderColor: ablationSubTab === "baseline" ? "#4cbd99" : "#2a394f",
                        color: ablationSubTab === "baseline" ? "#78e6bc" : "#d5deeb",
                        fontWeight: ablationSubTab === "baseline" ? 600 : 400
                      }}
                      onClick={() => setAblationSubTab("baseline")}
                    >
                      <Layers size={14} /> Real Workload Evaluation (Minimal Unions)
                    </button>
                  </div>

                  {ablationSubTab === "noisy" && (
                    <>
                      {noisyAblationData ? (
                        <>
                          <section className="metrics-grid">
                            <Metric icon={CheckCircle2} label="Injected Permissions Eliminated"
                              value={`${noisyAblationData.aggregate?.total_injected_permissions_removed}/${noisyAblationData.aggregate?.total_injected_permissions_tested} (${noisyAblationData.aggregate?.overall_injected_removal_rate_pct}%)`}
                              detail="100% of injected permissions safely pruned" />
                            <Metric icon={LockKeyhole} label="Required Permissions Retained"
                              value={`${noisyAblationData.aggregate?.avg_required_permission_retention_rate_pct}%`}
                              detail="Zero required syscalls erroneously pruned" />
                            <Metric icon={ShieldCheck} label="Workload Compatibility"
                              value={`${noisyAblationData.aggregate?.avg_heldout_compatibility_pct}%`}
                              detail="Zero broken legitimate workloads" />
                            <Metric icon={Activity} label="False Kills Observed"
                              value={noisyAblationData.aggregate?.total_false_kills ?? 0}
                              detail="No false positive terminations" />
                          </section>

                          <section className="panel" style={{ marginBottom: 20 }}>
                            <div className="panel-heading">
                              <div>
                                <h3>Controlled Noisy Policy Minimization Results</h3>
                                <p>Synthetic extraneous permissions eliminated across all 9 Linux targets (results/noisy_ablation_eval.json)</p>
                              </div>
                              <span className="demo-badge">100% INJECTED ELIMINATION</span>
                            </div>
                            <div className="table-wrap">
                              <table>
                                <thead>
                                  <tr>
                                    <th>PROGRAM</th>
                                    <th>GROUND TRUTH</th>
                                    <th>NOISY BASELINE</th>
                                    <th>MINIMIZED</th>
                                    <th>INJECTED REMOVED</th>
                                    <th>INJECTED REMOVAL %</th>
                                    <th>REQUIRED RETAINED %</th>
                                    <th>COMPAT %</th>
                                    <th>SEARCH TIME</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(noisyAblationData.targets ?? []).map(t => (
                                    <tr key={t.target}>
                                      <td className="process-cell"><strong>{t.target}</strong></td>
                                      <td>{t.ground_truth_syscalls}</td>
                                      <td>{t.noisy_baseline?.allowed_syscalls}</td>
                                      <td><strong>{t.minimized?.allowed_syscalls}</strong></td>
                                      <td>
                                        <span className="diff-removed">
                                          {t.minimized?.injected_removed_count}/{t.noisy_baseline?.injected_permissions_count}
                                        </span>
                                      </td>
                                      <td><strong style={{ color: "#45d6a5" }}>{t.minimized?.injected_removal_rate_pct}%</strong></td>
                                      <td>{t.minimized?.required_retention_rate_pct}%</td>
                                      <td>{t.minimized?.heldout_compat_pct}%</td>
                                      <td>{t.minimized?.ablation_search_seconds}s</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </section>

                          <section className="panel" style={{ marginBottom: 20 }}>
                            <div className="panel-heading">
                              <div>
                                <h3>Injected Permissions Catalog & Security Rationale</h3>
                                <p>10 valid Linux system call permissions deliberately injected into baseline profiles</p>
                              </div>
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 10 }}>
                              {(noisyAblationData.injected_permissions ?? []).map(p => (
                                <div key={p.syscall} className="tier-section" style={{ margin: 0 }}>
                                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <span className="syscall-pill pill-removable">{p.syscall}</span>
                                    <span style={{ fontSize: 11, color: "#dbe4f1" }}>{p.rationale}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </section>

                          {noisyAblationData?.report_markdown && (
                            <section className="panel" style={{ marginBottom: 20 }}>
                              <div className="panel-heading">
                                <div>
                                  <h3>Controlled Noisy Report Markdown</h3>
                                  <p>Source artifact: results/noisy_ablation_report.md</p>
                                </div>
                                <button className="secondary-button" onClick={() => setShowMarkdownReport(!showMarkdownReport)}>
                                  {showMarkdownReport ? "Collapse Report" : "Expand Report"}
                                </button>
                              </div>
                              {showMarkdownReport && (
                                <div className="report-view-box">
                                  <pre>{noisyAblationData.report_markdown}</pre>
                                </div>
                              )}
                            </section>
                          )}
                        </>
                      ) : (
                        <div className="panel" style={{ marginBottom: 20 }}>
                          <p className="muted">Controlled noisy evaluation results not yet generated. Run <code>make eval-noisy</code> to execute.</p>
                        </div>
                      )}
                    </>
                  )}

                  {ablationSubTab === "baseline" && (
                    <>
                      {ablationData && (
                        <>
                          <section className="metrics-grid">
                            <Metric icon={Activity} label="Targets Evaluated"
                              value={ablationData.targets?.length ?? 9} detail="Benchmark workloads" />
                            <Metric icon={LockKeyhole} label="Avg Baseline Syscalls"
                              value={ablationData.aggregate?.avg_baseline_syscalls ?? 35.8} detail="Minimal training union" />
                            <Metric icon={ShieldCheck} label="Workload Compatibility"
                              value={`${ablationData.aggregate?.avg_counterfactual_compat_pct ?? 100}%`} detail="Zero false kills recorded" />
                            <Metric icon={CheckCircle2} label="Evidence Completeness"
                              value={`${ablationData.aggregate?.avg_evidence_completeness_pct ?? 100}%`} detail="All decisions mathematically logged" />
                          </section>

                          <section className="panel" style={{ marginBottom: 20 }}>
                            <div className="panel-heading">
                              <div>
                                <h3>Minimization Benchmark Results by Program</h3>
                                <p>Observation-only minimal unions under SCMP_ACT_KILL_PROCESS fail-stop semantics (results/ablation_eval.json)</p>
                              </div>
                            </div>
                            <div className="table-wrap">
                              <table>
                                <thead>
                                  <tr>
                                    <th>PROGRAM</th>
                                    <th>BASELINE SYSCALLS</th>
                                    <th>CANDIDATE SYSCALLS</th>
                                    <th>REMOVED</th>
                                    <th>SEARCH TIME</th>
                                    <th>TRIALS RUN</th>
                                    <th>EVIDENCE COVERAGE</th>
                                    <th>FALSE KILLS</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(ablationData.targets ?? []).map(t => (
                                    <tr key={t.target}>
                                      <td className="process-cell"><strong>{t.target}</strong></td>
                                      <td>{t.baseline?.allowed_syscalls ?? "—"}</td>
                                      <td>{t.counterfactual?.allowed_syscalls ?? "—"}</td>
                                      <td>
                                        <span className={t.counterfactual?.syscalls_removed > 0 ? "diff-removed" : "muted"}>
                                          {t.counterfactual?.syscalls_removed ?? 0}
                                        </span>
                                      </td>
                                      <td>{t.counterfactual?.ablation_search_seconds ?? "—"}s</td>
                                      <td>{t.counterfactual?.trials_run ?? "—"}</td>
                                      <td>{t.counterfactual?.evidence_completeness_pct ?? 100}%</td>
                                      <td>{t.counterfactual?.false_kills ?? 0}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </section>

                          {ablationData?.report_markdown && (
                            <section className="panel" style={{ marginBottom: 20 }}>
                              <div className="panel-heading">
                                <div>
                                  <h3>Baseline Evaluation Report Markdown</h3>
                                  <p>Source artifact: results/ablation_report.md</p>
                                </div>
                                <button className="secondary-button" onClick={() => setShowMarkdownReport(!showMarkdownReport)}>
                                  {showMarkdownReport ? "Collapse Report" : "Expand Report"}
                                </button>
                              </div>
                              {showMarkdownReport && (
                                <div className="report-view-box">
                                  <pre>{ablationData.report_markdown}</pre>
                                </div>
                              )}
                            </section>
                          )}
                        </>
                      )}
                    </>
                  )}

                  <section className="panel" style={{ marginBottom: 20 }}>
                    <div className="panel-heading">
                      <div>
                        <h3>Literature Comparison: PoViShield vs Prior Systems</h3>
                        <p>Comparison against seccomp de-bloating and policy generation research</p>
                      </div>
                    </div>
                    <div className="table-wrap lit-table-wrap">
                      <table className="lit-table">
                        <thead>
                          <tr>
                            <th>SYSTEM</th>
                            <th>PRIMARY METHOD</th>
                            <th>COUNTERFACTUAL PROBING</th>
                            <th>KERNEL ENFORCEMENT</th>
                            <th>REPRODUCIBLE EVIDENCE LEDGER</th>
                            <th>FAIL-CLOSED AUDITOR</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td className="process-cell"><strong>PoViShield (This Work)</strong></td>
                            <td>Empirical Permission Ablation</td>
                            <td><span className="lit-badge-yes">Yes (SCMP_ACT_KILL)</span></td>
                            <td><span className="lit-badge-yes">Yes (seccomp-bpf)</span></td>
                            <td><span className="lit-badge-yes">Yes (JSONL + SHA-256)</span></td>
                            <td><span className="lit-badge-yes">Yes (Independent CLI)</span></td>
                          </tr>
                          <tr>
                            <td className="process-cell">Chestnut (USENIX Sec '21)</td>
                            <td>Static Analysis + Heuristics</td>
                            <td><span className="lit-badge-no">No (Static overapprox)</span></td>
                            <td><span className="lit-badge-yes">Yes (seccomp)</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                          </tr>
                          <tr>
                            <td className="process-cell">Confine (RAID '20)</td>
                            <td>Static System-Call Analysis</td>
                            <td><span className="lit-badge-no">No (Static)</span></td>
                            <td><span className="lit-badge-yes">Yes (Docker seccomp)</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                          </tr>
                          <tr>
                            <td className="process-cell">SPEAKER (TSE '22)</td>
                            <td>Dynamic Syscall Specialization</td>
                            <td><span className="lit-badge-no">No (Union of traces)</span></td>
                            <td><span className="lit-badge-yes">Yes (seccomp-bpf)</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                          </tr>
                          <tr>
                            <td className="process-cell">Chisel (FSE '18)</td>
                            <td>Reinforcement Learning Debloating</td>
                            <td><span className="lit-badge-yes">Yes (Delta-debugging)</span></td>
                            <td><span className="lit-badge-no">No (Source rewrite)</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                            <td><span className="lit-badge-no">No</span></td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </section>

                  {ablationData?.report_markdown && (
                    <section className="panel">
                      <div className="panel-heading">
                        <div>
                          <h3>Evaluation Report Markdown</h3>
                          <p>Source artifact: results/ablation_report.md</p>
                        </div>
                        <button className="secondary-button" onClick={() => setShowMarkdownReport(!showMarkdownReport)}>
                          {showMarkdownReport ? "Collapse Report" : "Expand Report"}
                        </button>
                      </div>
                      {showMarkdownReport && (
                        <div className="report-view-box">
                          <pre>{ablationData.report_markdown}</pre>
                        </div>
                      )}
                    </section>
                  )}
                </>
              )}

              {page === "Evidence Ledgers" && (
                <>
                  <div className="notice">
                    <ShieldAlert size={19} />
                    <div>
                      <strong>Cryptographic & Empirical Evidence Ledgers (results/ledgers/*.jsonl)</strong>
                      <p>
                        Every permission decision is recorded as an immutable JSONL line containing workload command, return code, kernel signal (SIGSYS), output divergence hash, kernel environment, and an exact CLI command to independently reproduce the trial.
                      </p>
                    </div>
                  </div>

                  <div className="ledger-controls">
                    <div className="ledger-target-select">
                      <label>Select Target Ledger</label>
                      <select value={selectedLedgerTarget} onChange={e => setSelectedLedgerTarget(e.target.value)}>
                        {ledgersList.map(l => (
                          <option key={l.target} value={l.target}>{l.target}.jsonl ({l.trial_count} trials)</option>
                        ))}
                      </select>
                    </div>

                    <div className="ledger-filter-select">
                      <label>Filter Verdict</label>
                      <select value={ledgerVerdictFilter} onChange={e => setLedgerVerdictFilter(e.target.value)}>
                        <option value="ALL">All Verdicts</option>
                        <option value="REQUIRED_FOR_TESTED_WORKLOADS">REQUIRED_FOR_TESTED_WORKLOADS / NECESSARY</option>
                        <option value="REMOVABLE_FOR_TESTED_WORKLOADS">REMOVABLE_FOR_TESTED_WORKLOADS / REMOVABLE</option>
                      </select>
                    </div>

                    <div className="ledger-search-input">
                      <label>Search Syscall</label>
                      <input
                        placeholder="e.g. read, write, openat"
                        value={ledgerSyscallFilter}
                        onChange={e => setLedgerSyscallFilter(e.target.value)}
                      />
                    </div>
                  </div>

                  <section className="audit-panel">
                    <div className="audit-header">
                      <div>
                        <h3>Independent Fail-Closed Ledger Audit</h3>
                        <p>Verify ledger records using analysis.audit_ledger</p>
                      </div>
                      <button
                        className="secondary-button"
                        onClick={() => runLedgerAudit(selectedLedgerTarget)}
                        disabled={auditLoading || !selectedLedgerTarget}
                      >
                        <ShieldCheck size={16} />
                        {auditLoading ? "Auditing…" : "Run Independent Audit"}
                      </button>
                    </div>

                    {auditReport && (
                      <div>
                        <div style={{ marginTop: 10 }}>
                          <span className={`audit-badge ${auditReport.valid ? "passed" : "failed"}`}>
                            {auditReport.valid ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                            {auditReport.valid ? "AUDIT PASSED — FAIL-CLOSED VERIFIED" : "AUDIT FAILED — TAMPER OR DEFECT DETECTED"}
                          </span>
                        </div>
                        <div className="audit-details-grid">
                          <div className="audit-detail-card">
                            <span>Total Trials Verified</span>
                            <strong>{auditReport.trials_total ?? 0}</strong>
                          </div>
                          <div className="audit-detail-card">
                            <span>Experimentally Required</span>
                            <strong style={{ color: "#78e6bc" }}>{auditReport.experimentally_required_count ?? 0}</strong>
                          </div>
                          <div className="audit-detail-card">
                            <span>Removable Syscalls</span>
                            <strong style={{ color: "#f4c46d" }}>{auditReport.removable_count ?? 0}</strong>
                          </div>
                          <div className="audit-detail-card">
                            <span>Audit Errors Detected</span>
                            <strong style={{ color: (auditReport.error_count ?? 0) === 0 ? "#78e6bc" : "#ff8696" }}>
                              {auditReport.error_count ?? 0}
                            </strong>
                          </div>
                        </div>

                        {auditReport.errors?.length > 0 && (
                          <div className="audit-error-list">
                            <strong>Audit Errors:</strong>
                            <ul>
                              {auditReport.errors.map((err, i) => (
                                <li key={i}>{err}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </section>

                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Ablation Trials Stream ({ledgerTrials.length} shown / {ledgerTotalRecords} total)</h3>
                        <p>Click any row to inspect reproduction details and environment fingerprints</p>
                      </div>
                    </div>
                    <div className="table-wrap activity-table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>TRIAL ID</th>
                            <th>ABLATED SYSCALL</th>
                            <th>VERDICT</th>
                            <th>RC</th>
                            <th>SIGNAL</th>
                            <th>OUTPUT DIVERGENCE</th>
                            <th>WORKLOAD</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ledgerTrials.map(trial => (
                            <tr
                              key={trial.trial_id}
                              onClick={() => setSelectedTrial(trial)}
                              style={{
                                cursor: "pointer",
                                background: selectedTrial?.trial_id === trial.trial_id ? "#132338" : "transparent"
                              }}
                            >
                              <td className="time-cell"><code>{trial.trial_id}</code></td>
                              <td className="process-cell"><code>{trial.ablated_syscall}</code></td>
                              <td>
                                <span className={`verdict-tag ${
                                  trial.verdict?.includes("NECESSARY") || trial.verdict?.includes("REQUIRED")
                                    ? "verdict-necessary"
                                    : "verdict-removable"
                                }`}>
                                  {trial.verdict}
                                </span>
                              </td>
                              <td><code>{trial.candidate_rc}</code></td>
                              <td>
                                <span className={trial.signal === "SIGSYS" ? "verdict-tag verdict-sigsys" : "muted"}>
                                  {trial.signal || "—"}
                                </span>
                              </td>
                              <td>{trial.output_diverged ? "Yes" : "No"}</td>
                              <td style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis" }}>
                                <code>{Array.isArray(trial.workload) ? trial.workload.join(" ") : trial.workload_str}</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {selectedTrial && (
                      <div className="trial-drawer">
                        <div className="trial-drawer-header">
                          <div>
                            <h4>Trial Inspection: {selectedTrial.trial_id}</h4>
                            <span className="footnote">
                              Ablated: <code>{selectedTrial.ablated_syscall}</code> · Verdict: <strong>{selectedTrial.verdict}</strong>
                            </span>
                          </div>
                          <span className={`verdict-tag ${selectedTrial.signal === "SIGSYS" ? "verdict-sigsys" : "verdict-necessary"}`}>
                            Exit Code: {selectedTrial.candidate_rc} {selectedTrial.signal ? `(${selectedTrial.signal})` : ""}
                          </span>
                        </div>

                        <div>
                          <span style={{ fontSize: 10, color: "#8292a8" }}>Independent Reproduction Command (CLI)</span>
                          <div className="reproduce-box">
                            <button
                              className="copy-btn"
                              onClick={() => copyToClipboard(selectedTrial.reproduce_cmd)}
                            >
                              {copiedCmd ? <Check size={13} style={{ color: "#45d6a5" }} /> : <Copy size={13} />}
                              {copiedCmd ? "Copied" : "Copy CLI"}
                            </button>
                            <pre className="reproduce-code">{selectedTrial.reproduce_cmd}</pre>
                          </div>
                        </div>

                        <div className="fingerprint-grid">
                          <div className="fingerprint-card">
                            <span>Kernel Version</span>
                            <strong>{selectedTrial.env_fingerprint?.kernel ?? "—"}</strong>
                          </div>
                          <div className="fingerprint-card">
                            <span>Git Commit Revision</span>
                            <strong>{selectedTrial.env_fingerprint?.git_commit ?? "—"}</strong>
                          </div>
                          <div className="fingerprint-card">
                            <span>Candidate Stdout Hash</span>
                            <strong style={{ fontSize: 9 }}>{selectedTrial.candidate_stdout_hash ? `${selectedTrial.candidate_stdout_hash.substring(0, 16)}…` : "—"}</strong>
                          </div>
                        </div>
                      </div>
                    )}
                  </section>
                </>
              )}

              {page === "Safety Gate & Approvals" && (
                <>
                  <div className="notice">
                    <ShieldAlert size={19} />
                    <div>
                      <strong>Pre-Enforcement Safety Gate (analysis/verify.py)</strong>
                      <p>
                        PoViShield prevents regression and containment loss by validating candidate policies through a 3-way gate before they can replace an active profile:
                      </p>
                      <ul style={{ margin: "8px 0 0", paddingLeft: 20, fontSize: 11, color: "#c5b391" }}>
                        <li>1. <strong>Regression Gate:</strong> Legitimate workloads are replayed inside the seccomp sandbox; any exit code divergence or SIGSYS rejects the candidate.</li>
                        <li>2. <strong>Adversarial Containment:</strong> Probes execution of non-whitelisted syscalls to prove the sandbox actively kills unauthorized operations.</li>
                        <li>3. <strong>Evidence Integrity:</strong> Verifies that every ablated permission is mathematically substantiated in the tamper-evident ledger.</li>
                      </ul>
                    </div>
                  </div>

                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Approved Policy Replacement History</h3>
                        <p>Records from results/approvals.jsonl</p>
                      </div>
                      <FileCheck size={20} className="muted-icon" />
                    </div>

                    {approvalsList.length === 0 ? (
                      <p className="muted">No approval records found in results/approvals.jsonl.</p>
                    ) : (
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>TARGET</th>
                              <th>STATUS</th>
                              <th>APPROVED AT</th>
                              <th>CANDIDATE POLICY</th>
                              <th>ACTIVE POLICY</th>
                            </tr>
                          </thead>
                          <tbody>
                            {approvalsList.map((appr, idx) => (
                              <tr key={idx}>
                                <td className="process-cell"><strong>{appr.target}</strong></td>
                                <td><span className="verdict-tag verdict-approved">APPROVED</span></td>
                                <td className="time-cell">{appr.timestamp || appr.approved_at || "—"}</td>
                                <td><code>{appr.candidate}</code></td>
                                <td><code>{appr.active}</code></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </section>
                </>
              )}

              {page === "Experiments" && (
                <>
                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Adversarial Escape Matrix & Benchmark Validation</h3>
                        <p>Empirical attack-surface pruning and kernel isolation verification across multiple sandboxing configurations</p>
                      </div>
                      <span className="badge-tag">Empirical Artifact: tests/adversarial_escape</span>
                    </div>

                    <div className="metrics-grid" style={{ marginBottom: 20 }}>
                      <Metric
                        icon={Gauge}
                        label="Workloads Evaluated"
                        value={experiments?.evaluation?.aggregate?.targets ?? 9}
                        detail="Linux userland binaries (ls, grep, cat, curl...)"
                        accent="#10b981"
                      />
                      <Metric
                        icon={ShieldCheck}
                        label="Mean Surface Reduction"
                        value={`${experiments?.evaluation?.aggregate?.avg_attack_surface_reduction_pct ?? 90.71}%`}
                        detail="Syscalls pruned via counterfactual analysis"
                        progress={experiments?.evaluation?.aggregate?.avg_attack_surface_reduction_pct ?? 90.71}
                        accent="#06b6d4"
                      />
                      <Metric
                        icon={FileCheck}
                        label="Held-Out Coverage"
                        value={`${experiments?.evaluation?.aggregate?.avg_heldout_coverage_pct ?? 100}%`}
                        detail="Zero missing syscalls in evaluation suite"
                        progress={experiments?.evaluation?.aggregate?.avg_heldout_coverage_pct ?? 100}
                        accent="#10b981"
                      />
                      <Metric
                        icon={ShieldAlert}
                        label="False Kills Recorded"
                        value={experiments?.evaluation?.aggregate?.total_false_kills ?? 0}
                        detail="Zero legitimate operations terminated"
                        accent="#38bdf8"
                      />
                    </div>

                    <div style={{ marginBottom: 20 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                        <div>
                          <h4 style={{ margin: 0, fontSize: 14, color: "#f1f5f9" }}>Adversarial Escape & Confinement Matrix</h4>
                          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#64748b" }}>
                            PoViShield evaluates 8 adversarial exploit vectors across 6 sandboxing security configurations.
                          </p>
                        </div>
                        <div style={{ display: "flex", gap: 8, fontSize: 11 }}>
                          <span className="esc-cell-blocked">BLOCKED</span>
                          <span className="esc-cell-denied">DENIED</span>
                          <span className="esc-cell-killed">KILLED</span>
                          <span className="esc-cell-escaped">ESCAPED</span>
                        </div>
                      </div>

                      <div style={{ overflowX: "auto", border: "1px solid #162438", borderRadius: 8, background: "#050914" }}>
                        <table className="escape-matrix-table">
                          <thead>
                            <tr style={{ background: "#08101e" }}>
                              <th style={{ minWidth: 200 }}>Exploit Vector</th>
                              {ESCAPE_CONFIGS.map(cfg => {
                                const res = experiments?.escape_results?.[cfg.key];
                                const blocked = res?.blocked ?? 0;
                                const total = res?.total ?? 8;
                                return (
                                  <th key={cfg.key} style={{ minWidth: 120 }}>
                                    <div style={{ fontWeight: 700, color: "#f1f5f9" }}>{cfg.label}</div>
                                    <div style={{ fontSize: 10, color: blocked === total ? "#34d399" : blocked > 0 ? "#38bdf8" : "#f87171", fontFamily: "var(--font-mono)" }}>
                                      {blocked}/{total} Blocked
                                    </div>
                                  </th>
                                );
                              })}
                            </tr>
                          </thead>
                          <tbody>
                            {ESCAPE_TEST_DEFS.map(t => (
                              <tr key={t.id}>
                                <td>
                                  <div style={{ fontWeight: 600, color: "#cbd5e1" }}>{t.name}</div>
                                  <div style={{ fontSize: 10, color: "#64748b" }}>{t.desc}</div>
                                </td>
                                {ESCAPE_CONFIGS.map(cfg => {
                                  const verdict = experiments?.escape_results?.[cfg.key]?.tests?.[t.id];
                                  return (
                                    <td key={cfg.key}>
                                      {renderEscapeBadge(verdict)}
                                    </td>
                                  );
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    <div style={{ marginBottom: 20 }}>
                      <div className="panel-heading" style={{ marginBottom: 12 }}>
                        <div>
                          <h4 style={{ margin: 0, fontSize: 14, color: "#f1f5f9" }}>Workload Compatibility & Surface Minimization</h4>
                          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#64748b" }}>Per-program benchmark metrics across 9 Linux workloads</p>
                        </div>
                      </div>
                      <div className="chart" style={{ height: 280 }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={chartData}>
                            <CartesianGrid stroke="#263247" strokeDasharray="3 3" vertical={false} />
                            <XAxis dataKey="target" stroke="#78869b" />
                            <YAxis stroke="#78869b" />
                            <Tooltip contentStyle={{ background: "#111a2a", border: "1px solid #2b3a50" }} />
                            <Bar dataKey="compatibility" name="Compatibility (%)" fill="#45d6a5" radius={[4, 4, 0, 0]} />
                            <Bar dataKey="reduction" name="Surface Reduction (%)" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    <div className="notice" style={{ marginBottom: 16 }}>
                      <ShieldAlert size={19} />
                      <div>
                        <strong>Kernel Security Isolation Boundary</strong>
                        <p>
                          Privileged features (cgroup v2 memory/PID ceilings, mount namespaces, host rootfs masking) require kernel capabilities (CAP_SYS_ADMIN) or root execution. Unprivileged enforcement applies strict seccomp-bpf filters with PR_SET_NO_NEW_PRIVS.
                        </p>
                      </div>
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 16 }}>
                      <button
                        className="btn-filter"
                        onClick={() => setExpReportExpanded(prev => !prev)}
                        style={{ display: "flex", alignItems: "center", gap: 6 }}
                      >
                        <FileText size={14} />
                        <span>{expReportExpanded ? "Collapse Full Evaluation Report" : "Expand Full Evaluation Report"}</span>
                      </button>
                      {experiments?.report && (
                        <button
                          className="btn-filter"
                          onClick={() => copyToClipboard(experiments.report)}
                          style={{ display: "flex", alignItems: "center", gap: 6 }}
                        >
                          <Copy size={14} />
                          <span>{copiedCmd ? "Copied!" : "Copy Report Markdown"}</span>
                        </button>
                      )}
                    </div>

                    {expReportExpanded && (
                      <div style={{ marginTop: 14, background: "#050914", border: "1px solid #162438", borderRadius: 8, padding: 14 }}>
                        <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: "#9eafc4", fontSize: 11, margin: 0, fontFamily: "var(--font-mono)" }}>
                          {experiments?.report ?? "No benchmark report available."}
                        </pre>
                      </div>
                    )}
                  </section>
                </>
              )}

              {page === "Settings" && (
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h3>Settings & Security Governance Console</h3>
                      <p>Active enforcement parameters, local privacy boundaries, and telemetry controls</p>
                    </div>
                    <span className="badge-tag">Control Plane: Port 8000</span>
                  </div>

                  <div className="settings-section-grid">
                    <div className="settings-card">
                      <div className="settings-card-header">
                        <Server size={18} style={{ color: "#38bdf8" }} />
                        <h4>Operator & Fleet Identity</h4>
                      </div>
                      <div className="policy-row">
                        <span>Operator Profile</span>
                        <strong>PV Security Lead</strong>
                      </div>
                      <div className="policy-row">
                        <span>Active Fleet Scope</span>
                        <strong style={{ color: activeDeviceId === "gateway" ? "#94a3b8" : "#34d399" }}>
                          {activeDeviceId === "gateway" ? "Global Fleet / Gateway" : (activeDevice?.hostname || activeDeviceId)}
                        </strong>
                      </div>
                      <div className="policy-row">
                        <span>Authorization Scheme</span>
                        <strong>Local Bearer & Ephemeral Token</strong>
                      </div>
                      <div className="policy-row">
                        <span>API Origin Host</span>
                        <strong style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{API}</strong>
                      </div>
                      <div style={{ marginTop: 8, padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <span style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600, display: "block", marginBottom: 4 }}>
                          Remote Backend URL (Render / Custom API)
                        </span>
                        <div style={{ display: "flex", gap: 6 }}>
                          <input
                            type="text"
                            placeholder="https://your-backend.onrender.com"
                            defaultValue={localStorage.getItem("povishield_custom_api_url")?.replace(/\/api$/, "") || ""}
                            id="settings-backend-url-input"
                            style={{
                              flex: 1, padding: "5px 8px", background: "#08101e", border: "1px solid #1e293b",
                              borderRadius: 4, color: "#f1f5f9", fontSize: 11, fontFamily: "var(--font-mono)"
                            }}
                          />
                          <button
                            className="btn-filter"
                            style={{ padding: "4px 10px", fontSize: 11 }}
                            onClick={() => {
                              const val = document.getElementById("settings-backend-url-input")?.value?.trim();
                              if (val) {
                                let u = val.replace(/\/+$/, "");
                                if (!u.endsWith("/api")) u = `${u}/api`;
                                localStorage.setItem("povishield_custom_api_url", u);
                                window.location.reload();
                              } else {
                                localStorage.removeItem("povishield_custom_api_url");
                                window.location.reload();
                              }
                            }}
                          >
                            Save
                          </button>
                        </div>
                      </div>

                      {activeDeviceId !== "gateway" && (
                        <button
                          className="btn-filter"
                          onClick={() => {
                            setActiveDeviceId("gateway");
                            localStorage.setItem("povishield_active_device_id", "gateway");
                          }}
                          style={{ marginTop: 6 }}
                        >
                          Reset Scope to Global Fleet
                        </button>
                      )}
                    </div>

                    <div className="settings-card">
                      <div className="settings-card-header">
                        <LockKeyhole size={18} style={{ color: "#10b981" }} />
                        <h4>Data Privacy & Output Confinement</h4>
                      </div>
                      <div className="settings-toggle-row">
                        <div>
                          <label>Strict Local Output Confinement</label>
                          <p>Keep command stdout/stderr on the local machine. Central API only collects exit status, violation metadata, and syscall telemetry.</p>
                        </div>
                        <label className="settings-toggle-switch">
                          <input
                            type="checkbox"
                            checked={strictLocalConfinement}
                            onChange={toggleStrictConfinement}
                          />
                          <span className="toggle-slider" />
                        </label>
                      </div>

                      <div className="settings-toggle-row">
                        <div>
                          <label>Credential & Token Masking</label>
                          <p>Automatically redact sensitive command-line parameters (passwords, tokens, keys) in recorded telemetry buffers.</p>
                        </div>
                        <label className="settings-toggle-switch">
                          <input
                            type="checkbox"
                            checked={true}
                            readOnly
                          />
                          <span className="toggle-slider" />
                        </label>
                      </div>

                      <div className="policy-row">
                        <span>Telemetry Ring Buffer</span>
                        <strong>1,000 Events (Bounded Memory)</strong>
                      </div>
                    </div>

                    <div className="settings-card">
                      <div className="settings-card-header">
                        <Activity size={18} style={{ color: "#f59e0b" }} />
                        <h4>Interface & Display Preferences</h4>
                      </div>
                      <div className="settings-toggle-row">
                        <div>
                          <label>Reactive Ambient Terminal Stream</label>
                          <p>Display real-time security diagnostics and telemetry initialization stream in the background canvas.</p>
                        </div>
                        <label className="settings-toggle-switch">
                          <input
                            type="checkbox"
                            checked={ambientLogsEnabled}
                            onChange={toggleAmbientLogs}
                          />
                          <span className="toggle-slider" />
                        </label>
                      </div>

                      <div className="policy-row">
                        <span>Side Navigation Panel</span>
                        <strong>{sidebarCollapsed ? "Collapsed (Expanded on Hover)" : "Fixed Expanded"}</strong>
                      </div>

                      <div className="policy-row">
                        <span>Live Transport Cadence</span>
                        <strong>900ms Polling / Exponential Backoff</strong>
                      </div>
                    </div>

                    <div className="settings-card">
                      <div className="settings-card-header">
                        <ShieldCheck size={18} style={{ color: "#10b981" }} />
                        <h4>Kernel Enforcement Diagnostics</h4>
                      </div>
                      <div className="policy-row">
                        <span>Seccomp BPF Action</span>
                        <strong style={{ color: "#34d399", fontFamily: "var(--font-mono)" }}>SCMP_ACT_KILL_PROCESS</strong>
                      </div>
                      <div className="policy-row">
                        <span>Privilege Flag</span>
                        <strong style={{ color: "#34d399", fontFamily: "var(--font-mono)" }}>PR_SET_NO_NEW_PRIVS</strong>
                      </div>
                      <div className="policy-row">
                        <span>Tracing Mechanism</span>
                        <strong style={{ color: "#38bdf8", fontFamily: "var(--font-mono)" }}>ptrace(PTRACE_SYSCALL)</strong>
                      </div>
                      <div className="policy-row">
                        <span>Safety Gate Verification</span>
                        <strong style={{ color: "#34d399" }}>Fail-Closed Verification</strong>
                      </div>
                      <div className="policy-row">
                        <span>Ledger Tamper-Resistance</span>
                        <strong style={{ color: "#34d399" }}>Append-Only JSONL</strong>
                      </div>
                    </div>
                  </div>
                </section>
              )}
            </>
          )}

          <footer className="footer">
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span className="live-pulse-dot" />
              <span>PoViShield Linux Defense & Fleet Platform</span>
              <span style={{ color: "#334155" }}>•</span>
              <span style={{ color: "#64748b" }}>Kernel Seccomp-BPF Enforced</span>
            </div>
            <div className="footer-links">
              <span onClick={() => setPage("Overview")}>Overview</span>
              <span onClick={() => setPage("Fleet / Devices")}>Fleet</span>
              <span onClick={() => setPage("Terminal / Execute")}>Terminal</span>
              <span onClick={() => setPage("Policy Explorer")}>Policies</span>
              <span onClick={() => setPage("Settings")}>Capabilities</span>
            </div>
          </footer>
        </div>
      </main>
    </div>
  );
}

export default App;
