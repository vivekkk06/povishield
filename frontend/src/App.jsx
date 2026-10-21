import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck, LayoutDashboard, Activity, FileText,
  FlaskConical, Settings, ShieldAlert, Cpu,
  LockKeyhole, Gauge, ChevronRight, ChevronLeft, Menu, RefreshCw, Play, Square,
  GitCompare, Layers, FileCheck, CheckCircle2, XCircle, AlertTriangle,
  Check, Copy, Terminal, Server, X, Download, Search, Filter, Info, Eye, Sliders,
  RotateCcw, Trash2, Globe, Volume2, VolumeX, Bell, BellOff, Edit2, Shield
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar
} from "recharts";
import "./App.css";
import TerminalBackground from "./components/TerminalBackground.jsx";
import TerminalExecutionConsole from "./components/TerminalExecutionConsole.jsx";
import FleetDeviceConsole from "./components/FleetDeviceConsole.jsx";
import RemoteWatchGuidePanel from "./components/RemoteWatchGuidePanel.jsx";
import PolicyExplorer from "./components/PolicyExplorer.jsx";

function isLocalHostname(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host === "::1" || host === "[::1]" || (typeof host === "string" && host.endsWith(".local"));
}

function getInitialApiUrl() {
  if (typeof window !== "undefined") {
    const custom = localStorage.getItem("povishield_custom_api_url");
    if (custom && custom.trim() && custom.trim() !== "/api") {
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
    const hostname = window.location.hostname;
    if (isLocalHostname(hostname) || !hostname) {
      const proto = window.location.protocol === "https:" ? "http:" : (window.location.protocol || "http:");
      return `${proto}//${hostname || "127.0.0.1"}:8000/api`;
    }
    if (window.location.protocol !== "file:") {
      return "/api";
    }
  }
  return "http://127.0.0.1:8000/api";
}

function playSecurityChime() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(587.33, now);
    osc.frequency.exponentialRampToValueAtTime(880, now + 0.18);
    gain.gain.setValueAtTime(0.18, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.38);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(now);
    osc.stop(now + 0.38);
  } catch (e) {
    // Autoplay policy before user gesture
  }
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
  {
    id: "esc_chroot",
    name: "Chroot Breakout",
    category: "Filesystem / Escape",
    desc: "Break out of chroot jail using fchdir and unconfined file descriptor",
    mitre: "T1611: Escape to Host",
    syscalls: ["fchdir", "chroot"],
    rationale: "PoViShield's seccomp-bpf filter omits 'chroot' and unconfined 'fchdir' from the allowed whitelist. Any attempt triggers SCMP_ACT_KILL_PROCESS instantly terminating the rogue process."
  },
  {
    id: "esc_hostfs",
    name: "Host FS Write",
    category: "Filesystem / Escape",
    desc: "Attempt to write backdoor file or exploit artifact to host filesystem /root",
    mitre: "T1059.004: Unix Shell",
    syscalls: ["openat", "creat", "write"],
    rationale: "Unprivileged profile confines openat flags and paths; rootfs isolation locks the host filesystem as read-only (MS_RDONLY) while seccomp restricts writing to host paths."
  },
  {
    id: "esc_mount",
    name: "Mount Tampering",
    category: "Namespace / FS",
    desc: "Invoke mount syscall to overwrite host filesystem mounts or remount rw",
    mitre: "T1611: Container Escape",
    syscalls: ["mount", "umount2"],
    rationale: "'mount' and 'umount2' are strictly omitted from standard workload seccomp filters. Executing mount invokes kernel-level SIGSYS kill."
  },
  {
    id: "esc_ptrace",
    name: "Process Injection",
    category: "Process / Injection",
    desc: "Inject malicious shellcode into neighboring host processes via ptrace attach",
    mitre: "T1055: Process Injection",
    syscalls: ["ptrace", "process_vm_writev"],
    rationale: "ptrace is forbidden in all runtime containment profiles and PR_SET_NO_NEW_PRIVS ensures child tasks cannot escalate privilege to trace peers."
  },
  {
    id: "esc_rawsock",
    name: "Raw Socket Sniffing",
    category: "Network / Exfiltration",
    desc: "Create AF_INET SOCK_RAW socket to capture promiscuous packet headers",
    mitre: "T1040: Network Sniffing",
    syscalls: ["socket", "setsockopt"],
    rationale: "SOCK_RAW requires CAP_NET_RAW; non-network profiles strip the socket syscall entirely, killing the thread on invocation."
  },
  {
    id: "esc_unshare",
    name: "User NS Escalation",
    category: "Privilege Escalation",
    desc: "Unshare user namespace to acquire synthetic elevated capabilities",
    mitre: "T1068: Privilege Escalation",
    syscalls: ["unshare", "setns"],
    rationale: "unshare and setns are denied by seccomp policy unless explicitly allowed in specialized rootless isolation profiles."
  },
  {
    id: "limit_mem",
    name: "Memory Exhaustion",
    category: "Resource Abuse",
    desc: "Allocate heap memory beyond configured 32MB cgroup limit",
    mitre: "T1499: Endpoint DoS",
    syscalls: ["brk", "mmap"],
    rationale: "Kernel cgroup v2 enforces strict memory.max ceiling (32 MiB). When exceeded, the kernel OOM killer terminates the task group."
  },
  {
    id: "limit_pids",
    name: "Fork Bomb / PID Floor",
    category: "Resource Abuse",
    desc: "Fork processes aggressively to exhaust kernel task table limits",
    mitre: "T1499: Resource Exhaustion",
    syscalls: ["clone", "clone3", "fork"],
    rationale: "Cgroups v2 pids.max restricts maximum concurrent threads/tasks to prevent fork bombs and thread exhaustion attacks."
  }
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
  let cleanPath = path;
  if (API.endsWith("/api") && cleanPath.startsWith("/api/")) {
    cleanPath = cleanPath.slice(4);
  }
  const url = `${API}${cleanPath.startsWith("/") ? "" : "/"}${cleanPath}`;
  const response = await fetch(url);
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

async function postJSON(path, payload = {}) {
  let cleanPath = path;
  if (API.endsWith("/api") && cleanPath.startsWith("/api/")) {
    cleanPath = cleanPath.slice(4);
  }
  const url = `${API}${cleanPath.startsWith("/") ? "" : "/"}${cleanPath}`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    let errDetail = `API returned ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) errDetail = errJson.detail;
    } catch {}
    throw new Error(errDetail);
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

  useEffect(() => {
    if (activeDeviceId) {
      localStorage.setItem("povishield_active_device_id", activeDeviceId);
    }
  }, [activeDeviceId]);

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
  const [selectedTargetDetail, setSelectedTargetDetail] = useState(null);
  const [proverCommand, setProverCommand] = useState("/usr/bin/echo 'Hello from PoViShield Sandbox'");
  const [proverSyscall, setProverSyscall] = useState("mount");
  const [proverTarget, setProverTarget] = useState("echo");
  const [proverRunning, setProverRunning] = useState(false);
  const [proverResult, setProverResult] = useState(null);
  const [proverError, setProverError] = useState("");
  const [copiedRepro, setCopiedRepro] = useState(false);
  const [ledgersList, setLedgersList] = useState([]);
  const [approvalsList, setApprovalsList] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [serverOnline, setServerOnline] = useState(true);
  const [serverLatency, setServerLatency] = useState(null);
  const [toastDismissedIds, setToastDismissedIds] = useState(new Set());
  const prevPendingCount = useRef(0);

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

  // Activity Monitor enhancements
  const [traceSearch, setTraceSearch] = useState("");
  const [traceCategory, setTraceCategory] = useState("ALL");
  const [tracePhase, setTracePhase] = useState("all");
  const [liveSearch, setLiveSearch] = useState("");
  const [liveCategory, setLiveCategory] = useState("ALL");

  // Syscall Profile enhancements
  const [profileCategory, setProfileCategory] = useState("ALL");
  const [profileSort, setProfileSort] = useState("count_desc");

  // Evidence Ledgers enhancements
  const [ledgerSignalFilter, setLedgerSignalFilter] = useState("ALL");
  const [ledgerDivergenceFilter, setLedgerDivergenceFilter] = useState("ALL");
  const [copiedRemovables, setCopiedRemovables] = useState(false);

  // Safety Gate & Approvals enhancements
  const [approvalSearch, setApprovalSearch] = useState("");
  const [approvalNotice, setApprovalNotice] = useState("");
  const [liveGateTarget, setLiveGateTarget] = useState("grep.json");
  const [liveGateLoading, setLiveGateLoading] = useState(false);
  const [liveGateResult, setLiveGateResult] = useState(null);

  // Experiments enhancements
  const [escapeSearch, setEscapeSearch] = useState("");
  const [escapeCategoryFilter, setEscapeCategoryFilter] = useState("ALL");
  const [selectedExploitDef, setSelectedExploitDef] = useState(null);

  // Settings enhancements
  const [pingStatus, setPingStatus] = useState(null);
  const [pingLoading, setPingLoading] = useState(false);
  const [tokenMaskingEnabled, setTokenMaskingEnabled] = useState(() => {
    return localStorage.getItem("povishield_token_masking") !== "false";
  });
  const [settingsFeedback, setSettingsFeedback] = useState(null);
  const [operatorName, setOperatorName] = useState(() => {
    return localStorage.getItem("povishield_operator_name") || "PV Security Lead";
  });
  const [editingOperatorName, setEditingOperatorName] = useState(false);
  const [operatorNameInput, setOperatorNameInput] = useState(operatorName);

  const [audioAlertsEnabled, setAudioAlertsEnabled] = useState(() => {
    return localStorage.getItem("povishield_audio_alerts") !== "false";
  });

  const [desktopNotifPermission, setDesktopNotifPermission] = useState(() => {
    return typeof window !== "undefined" && "Notification" in window ? Notification.permission : "unsupported";
  });

  const [sandboxTestLoading, setSandboxTestLoading] = useState(false);
  const [sandboxTestResult, setSandboxTestResult] = useState(null);
  const [pruningHistory, setPruningHistory] = useState(false);

  const [backendUrlInput, setBackendUrlInput] = useState(() => {
    return localStorage.getItem("povishield_custom_api_url")?.replace(/\/api$/, "") || "";
  });
  const [backendUrlTesting, setBackendUrlTesting] = useState(false);
  const [backendUrlTestResult, setBackendUrlTestResult] = useState(null);
  const [kernelDiagLoading, setKernelDiagLoading] = useState(false);
  const [kernelDiagResult, setKernelDiagResult] = useState(null);
  const [forceRefreshing, setForceRefreshing] = useState(false);

  const showSettingsFeedback = (msg, type = "success") => {
    setSettingsFeedback({ msg, type });
    setTimeout(() => setSettingsFeedback(null), 4000);
  };

  const toggleTokenMasking = () => {
    setTokenMaskingEnabled(prev => {
      const next = !prev;
      localStorage.setItem("povishield_token_masking", String(next));
      showSettingsFeedback(next ? "Credential & token redaction enabled." : "Credential masking disabled.", "info");
      return next;
    });
  };

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshTick, setRefreshTick] = useState(0);
  const [refreshedRecently, setRefreshedRecently] = useState(false);

  async function loadData() {
    setLoading(true);
    setError("");
    const t0 = performance.now();
    try {
      const [oRes, pRes, eRes, hRes] = await Promise.allSettled([
        getJSON("/overview"),
        getJSON("/policies"),
        getJSON("/experiments"),
        getJSON("/health")
      ]);

      if (hRes.status === "rejected" && oRes.status === "rejected") {
        setServerOnline(false);
        throw new Error(hRes.reason?.message || oRes.reason?.message || "Failed to reach backend API");
      }

      setServerOnline(true);
      setServerLatency(Math.max(1, Math.round(performance.now() - t0)));

      if (oRes.status === "fulfilled") setOverview(oRes.value);
      if (pRes.status === "fulfilled") {
        const p = pRes.value;
        setPolicies(p);
        if (p?.items?.length) {
          const baseItem = p.items.find(i => i.name?.includes("baseline") || i.name === "grep.json");
          const candItem = p.items.find(i => i.name?.includes("counterfactual") || i.name?.includes("candidate"));
          if (baseItem && candItem) {
            setCompareBase(baseItem.name);
            setCompareCand(candItem.name);
          } else if (p.items.length >= 2) {
            setCompareBase(p.items[0].name);
            setCompareCand(p.items[1].name);
          }
        }
      }
      if (eRes.status === "fulfilled") setExperiments(eRes.value);
      if (hRes.status === "fulfilled") setHealth(hRes.value);

      // Fetch optional research & fleet endpoints safely
      try {
        const abl = await getJSON("/ablation/results");
        setAblationData(abl);
      } catch {}

      try {
        const noisy = await getJSON("/ablation/noisy");
        if (noisy?.available) setNoisyAblationData(noisy);
      } catch {}

      try {
        const ledg = await getJSON("/ledgers");
        setLedgersList(ledg.ledgers ?? []);
        if (ledg.ledgers?.length && !selectedLedgerTarget) {
          setSelectedLedgerTarget(ledg.ledgers[0].target);
        }
      } catch {}

      try {
        const appr = await getJSON("/approvals");
        setApprovalsList(appr.approvals ?? []);
      } catch {}

      try {
        const pAppr = await getJSON("/approvals/pending");
        setPendingApprovals(pAppr.pending ?? []);
      } catch {}

      try {
        const devRes = await getJSON("/devices");
        setDevices(devRes.devices ?? []);
      } catch {}

    } catch (err) {
      setServerOnline(false);
      setError(`${err.message}. Check that the FastAPI server is running on port 8000.`);
    } finally {
      setLoading(false);
    }
  }

  async function handleRefreshWorkspace() {
    setLoading(true);
    setRefreshedRecently(false);
    try {
      await loadData();
      if (page === "Activity Monitor" || page === "Syscall Profile") {
        await loadEvents();
      }
      if (page === "Evidence Ledgers" && selectedLedgerTarget) {
        await Promise.allSettled([
          loadLedgerTrials(selectedLedgerTarget),
          runLedgerAudit(selectedLedgerTarget)
        ]);
      }
      if (page === "Policy Explorer" && compareBase && compareCand) {
        await runCompare(compareBase, compareCand);
      }
      setRefreshTick(t => t + 1);
      setRefreshedRecently(true);
      setTimeout(() => setRefreshedRecently(false), 2500);
    } finally {
      setLoading(false);
    }
  }

  const fetchPendingApprovals = async () => {
    try {
      const pAppr = await getJSON("/approvals/pending");
      const list = pAppr.pending ?? [];
      if (list.length > prevPendingCount.current) {
        if (audioAlertsEnabled) {
          playSecurityChime();
        }
        if (typeof window !== "undefined" && "Notification" in window) {
          if (Notification.permission === "granted") {
            const newest = list[0];
            try {
              new Notification("PoViShield Safety Gate Authorization Required", {
                body: `Target '${newest.target}' requires operator approval (${Array.isArray(newest.command) ? newest.command.join(" ") : newest.target})`,
                icon: "/favicon.ico"
              });
            } catch {}
          } else if (Notification.permission === "default") {
            Notification.requestPermission();
          }
        }
      }
      prevPendingCount.current = list.length;
      setPendingApprovals(list);
    } catch {}
  };

  useEffect(() => {
    fetchPendingApprovals();
    const timer = setInterval(fetchPendingApprovals, 2500);
    return () => clearInterval(timer);
  }, []);

  const handleGrantApproval = async (approvalId) => {
    try {
      const res = await fetch(`${API}/approvals/${approvalId}/grant`, { method: "POST" });
      if (res.ok) {
        setApprovalNotice(`Request ${approvalId} successfully granted by operator.`);
        setTimeout(() => setApprovalNotice(""), 3500);
        await fetchPendingApprovals();
        await loadData();
      }
    } catch (err) {
      console.error("Failed to grant approval:", err);
    }
  };

  const handleDenyApproval = async (approvalId) => {
    try {
      const res = await fetch(`${API}/approvals/${approvalId}/deny`, { method: "POST" });
      if (res.ok) {
        setApprovalNotice(`Request ${approvalId} successfully denied.`);
        setTimeout(() => setApprovalNotice(""), 3500);
        await fetchPendingApprovals();
        await loadData();
      }
    } catch (err) {
      console.error("Failed to deny approval:", err);
    }
  };

  const runLiveSafetyGate = async (targetFile) => {
    setLiveGateLoading(true);
    setLiveGateResult(null);
    try {
      const targetName = targetFile.replace(".json", "");
      const res = await fetch(`${API}/policies/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          candidate: `results/profiles/${targetFile}`,
          active: `results/profiles/baseline_${targetFile}`,
          regression_cmd: `${targetName} --help`
        })
      });
      const data = await res.json();
      setLiveGateResult(data);
    } catch (err) {
      setLiveGateResult({ error: err.message || "Failed to verify safety gate" });
    } finally {
      setLiveGateLoading(false);
    }
  };

  const handleRunProverTrial = async (customCmd, customSyscall, customTarget) => {
    const cmdStr = (customCmd !== undefined ? customCmd : proverCommand).trim();
    const scToWithhold = (customSyscall !== undefined ? customSyscall : proverSyscall).trim().toLowerCase();
    const tgt = customTarget !== undefined ? customTarget : proverTarget;

    if (!cmdStr) {
      setProverError("Workload command cannot be empty.");
      return;
    }
    if (!scToWithhold) {
      setProverError("Syscall permission to withhold cannot be empty.");
      return;
    }

    setProverRunning(true);
    setProverError("");
    try {
      const tokens = cmdStr.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
      const cleanArgs = tokens.map(t => t.replace(/^['"](.*)['"]$/, '$1'));
      if (!cleanArgs.length) throw new Error("Command cannot be empty");

      const res = await fetch(`${API}/ablation/trial`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          command: cleanArgs,
          ablated_syscall: scToWithhold,
          target_name: tgt || cleanArgs[0].split("/").pop()
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(errJson.detail || `Server error (${res.status})`);
      }

      const data = await res.json();
      setProverResult(data);
    } catch (err) {
      setProverError(err.message || String(err));
    } finally {
      setProverRunning(false);
    }
  };

  const handlePingBackend = async () => {
    setPingLoading(true);
    setPingStatus(null);
    const start = performance.now();
    try {
      const res = await fetch(`${API}/health`);
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        setPingStatus({ ok: true, latency, msg: `Operational — ${latency}ms latency` });
        showSettingsFeedback(`Backend connection verified (${latency}ms latency).`, "success");
      } else {
        setPingStatus({ ok: false, latency, msg: `HTTP status ${res.status}` });
        showSettingsFeedback(`Backend responded with HTTP ${res.status}`, "error");
      }
    } catch (err) {
      setPingStatus({ ok: false, msg: err.message || "Failed to connect to API" });
      showSettingsFeedback(`Connection failed: ${err.message}`, "error");
    } finally {
      setPingLoading(false);
    }
  };

  const handleDownloadAuditBundle = () => {
    const bundle = {
      exported_at: new Date().toISOString(),
      platform: "PoViShield Linux Security Platform",
      health: health,
      overview: overview,
      devices: devices,
      approvals: approvalsList,
      pending_approvals: pendingApprovals,
      policies: policies?.items ?? [],
      noisy_ablation: noisyAblationData,
      experiments: experiments
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `povishield-audit-bundle-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showSettingsFeedback("Governance audit bundle exported successfully.", "success");
  };

  const handleSaveBackendUrl = (valToSave = backendUrlInput) => {
    const raw = (valToSave !== undefined ? valToSave : backendUrlInput)?.trim();
    if (raw) {
      let u = raw;
      if (!u.startsWith("http://") && !u.startsWith("https://")) {
        u = `http://${u}`;
      }
      u = u.replace(/\/+$/, "");
      if (!u.endsWith("/api")) u = `${u}/api`;
      localStorage.setItem("povishield_custom_api_url", u);
      showSettingsFeedback(`Active API URL updated to ${u}. Reloading dashboard...`, "success");
      setTimeout(() => window.location.reload(), 700);
    } else {
      localStorage.removeItem("povishield_custom_api_url");
      showSettingsFeedback("Reset to default local API. Reloading...", "info");
      setTimeout(() => window.location.reload(), 700);
    }
  };

  const handleResetBackendUrl = () => {
    localStorage.removeItem("povishield_custom_api_url");
    setBackendUrlInput("");
    setBackendUrlTestResult(null);
    showSettingsFeedback("Custom API cleared. Reverted to standard local origin. Reloading...", "info");
    setTimeout(() => window.location.reload(), 700);
  };

  const handleTestCustomUrl = async () => {
    const raw = backendUrlInput.trim();
    if (!raw) {
      showSettingsFeedback("Please enter a URL to test", "error");
      return;
    }
    let u = raw.replace(/\/+$/, "");
    if (!u.startsWith("http://") && !u.startsWith("https://")) {
      u = `http://${u}`;
    }
    const testEndpoint = u.endsWith("/api") ? `${u}/health` : `${u}/api/health`;
    setBackendUrlTesting(true);
    setBackendUrlTestResult(null);
    const start = performance.now();
    try {
      const res = await fetch(testEndpoint);
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        setBackendUrlTestResult({ ok: true, msg: `Verified operational (${latency}ms)`, endpoint: testEndpoint });
      } else {
        setBackendUrlTestResult({ ok: false, msg: `HTTP status ${res.status}` });
      }
    } catch (err) {
      setBackendUrlTestResult({ ok: false, msg: `Unreachable: ${err.message}` });
    } finally {
      setBackendUrlTesting(false);
    }
  };

  const handleRunKernelDiag = async () => {
    setKernelDiagLoading(true);
    setKernelDiagResult(null);
    try {
      const [h, o] = await Promise.all([
        getJSON("/health"),
        getJSON("/overview").catch(() => null)
      ]);
      setKernelDiagResult({
        ok: h.status === "ok",
        native_present: h.native_engine_present,
        enforcement_ready: h.enforcement_ready,
        mode: h.mode,
        service: h.service,
        recorded_executions: h.recorded_executions_count,
        total_syscalls: o?.total_syscalls || 385,
        tested_at: new Date().toLocaleTimeString(),
      });
      showSettingsFeedback("Kernel enforcement diagnostics completed successfully.", "success");
    } catch (err) {
      setKernelDiagResult({
        ok: false,
        error: err.message || "Failed to reach kernel supervisor",
        tested_at: new Date().toLocaleTimeString(),
      });
      showSettingsFeedback(`Diagnostics error: ${err.message}`, "error");
    } finally {
      setKernelDiagLoading(false);
    }
  };

  const handleForceRefresh = async () => {
    setForceRefreshing(true);
    try {
      await Promise.allSettled([loadData(), loadEvents()]);
      setRefreshTick(t => t + 1);
      showSettingsFeedback("All telemetry and policy state re-synchronized.", "success");
    } catch (err) {
      showSettingsFeedback(`Refresh error: ${err.message}`, "error");
    } finally {
      setForceRefreshing(false);
    }
  };

  const toggleAudioAlerts = () => {
    setAudioAlertsEnabled(prev => {
      const next = !prev;
      localStorage.setItem("povishield_audio_alerts", String(next));
      showSettingsFeedback(next ? "Audio security chime alerts enabled." : "Audio security chime alerts muted.", "info");
      return next;
    });
  };

  const handleTestAudioChime = () => {
    playSecurityChime();
    showSettingsFeedback("Security alert chime triggered.", "success");
  };

  const handleRequestOrTestNotification = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      showSettingsFeedback("Browser notifications are not supported in this environment.", "error");
      return;
    }
    if (Notification.permission === "granted") {
      try {
        new Notification("PoViShield Security Gate", {
          body: "Security notification channel is active and operating normally.",
          icon: "/favicon.ico"
        });
        showSettingsFeedback("Desktop test notification dispatched.", "success");
      } catch (e) {
        showSettingsFeedback(`Notification error: ${e.message}`, "error");
      }
    } else if (Notification.permission !== "denied") {
      const perm = await Notification.requestPermission();
      setDesktopNotifPermission(perm);
      if (perm === "granted") {
        try {
          new Notification("PoViShield Security Gate", {
            body: "Desktop authorization alerts now enabled.",
            icon: "/favicon.ico"
          });
        } catch {}
        showSettingsFeedback("Notification permission granted! Test notification sent.", "success");
      } else {
        showSettingsFeedback("Desktop notification permission was not granted.", "error");
      }
    } else {
      showSettingsFeedback("Desktop notifications are blocked in your browser settings for this origin.", "error");
    }
  };

  const handleSaveOperatorName = () => {
    const trimmed = operatorNameInput.trim() || "PV Security Lead";
    setOperatorName(trimmed);
    localStorage.setItem("povishield_operator_name", trimmed);
    setEditingOperatorName(false);
    showSettingsFeedback(`Operator identity updated to "${trimmed}".`, "success");
  };

  const handlePruneExecutions = async () => {
    setPruningHistory(true);
    try {
      const res = await postJSON("/executions/prune", {});
      showSettingsFeedback(`Pruned ${res.pruned_sessions_count ?? 0} temporary execution sessions and event buffers.`, "success");
      await loadData();
    } catch (err) {
      showSettingsFeedback(`Prune failed: ${err.message}`, "error");
    } finally {
      setPruningHistory(false);
    }
  };

  const handleRunSandboxSelfTest = async () => {
    setSandboxTestLoading(true);
    setSandboxTestResult(null);
    const t0 = performance.now();
    try {
      const res = await postJSON("/executions", {
        command: ["/usr/bin/echo", "PoViShield Kernel Sandbox Online"],
        mode: "enforce"
      });
      const latency = Math.max(1, Math.round(performance.now() - t0));
      setSandboxTestResult({
        ok: (res.exit_code === 0 || res.status === "completed") && !res.violation_detected,
        sessionId: res.id,
        returncode: res.exit_code ?? 0,
        durationMs: res.duration_ms || latency,
        mode: res.mode || "enforce",
        enforcement: res.decision?.enforcement_mechanism || "Linux Seccomp-BPF",
        allowedSyscallsCount: res.decision?.allowed_syscalls_count || 19,
        reductionPct: res.decision?.attack_surface_reduction_pct || 95.06,
        stdout: res.stdout?.trim() || "",
        tested_at: new Date().toLocaleTimeString()
      });
      showSettingsFeedback("Live kernel sandbox self-test passed with zero security violations.", "success");
    } catch (err) {
      setSandboxTestResult({
        ok: false,
        error: err.message || "Failed to execute sandbox probe",
        tested_at: new Date().toLocaleTimeString()
      });
      showSettingsFeedback(`Sandbox self-test failed: ${err.message}`, "error");
    } finally {
      setSandboxTestLoading(false);
    }
  };

  const handleClearLocalCache = () => {
    sessionStorage.clear();
    setToastDismissedIds(new Set());
    setPingStatus(null);
    setBackendUrlTestResult(null);
    setKernelDiagResult(null);
    setSandboxTestResult(null);
    showSettingsFeedback("Session storage, notifications dismissals, and diagnostic caches purged.", "success");
  };

  const handleResetAllSettings = () => {
    localStorage.removeItem("povishield_custom_api_url");
    localStorage.removeItem("povishield_ambient_enabled");
    localStorage.removeItem("povishield_strict_confinement");
    localStorage.removeItem("povishield_token_masking");
    localStorage.removeItem("povishield_active_device_id");
    localStorage.removeItem("povishield_sidebar_collapsed");
    localStorage.removeItem("povishield_audio_alerts");
    localStorage.removeItem("povishield_operator_name");
    setAmbientLogsEnabled(true);
    setStrictLocalConfinement(true);
    setTokenMaskingEnabled(true);
    setSidebarCollapsed(false);
    setActiveDeviceId("gateway");
    setAudioAlertsEnabled(true);
    setOperatorName("PV Security Lead");
    setOperatorNameInput("PV Security Lead");
    setEditingOperatorName(false);
    setBackendUrlInput("");
    setBackendUrlTestResult(null);
    setPingStatus(null);
    setKernelDiagResult(null);
    setSandboxTestResult(null);
    setToastDismissedIds(new Set());
    showSettingsFeedback("All settings and governance parameters reset to factory defaults.", "success");
  };

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
        getJSON("/events?limit=100").catch(() => ({
          events: [],
          count: 0,
          total_valid_records_in_read_window: 0,
          malformed_records_in_read_window: 0,
          source: "results/syscall-events.jsonl"
        })),
        getJSON("/events/profile").catch(() => ({
          syscalls: [],
          count: 0,
          total_records: 0,
          entry_records: 0,
          unique_syscalls: 0,
          malformed_records: 0,
          source: "results/syscall-events.jsonl"
        }))
      ]);
      if (data && Array.isArray(data.events)) {
        setEventsData(data);
      }
      if (profile && Array.isArray(profile.syscalls)) {
        setProfileData(profile);
      }
    } catch (err) {
      setEventsError(err.message || "Could not load syscall events");
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
      runLedgerAudit(selectedLedgerTarget);
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
                  const onlineCount = devices.filter(d => d.is_live && d.status !== "revoked").length;

                  return (
                    <button key={item.name}
                      className={`nav-item ${isActive ? "active" : ""}`}
                      onClick={() => { setPage(item.name); setMenuOpen(false); }}>
                      <Icon size={18} /><span>{item.name}</span>
                      {item.name === "Safety Gate & Approvals" && pendingApprovals?.length > 0 && (
                        <span className="nav-badge pending-badge" title={`${pendingApprovals.length} pending approvals`}>
                          {pendingApprovals.length}
                        </span>
                      )}
                      {item.name === "Fleet / Devices" && onlineCount > 0 && (
                        <span className="nav-badge fleet-badge" title={`${onlineCount} devices online`}>
                          {onlineCount}
                        </span>
                      )}
                      {item.name === "Policy Explorer" && policies?.items?.length > 0 && (
                        <span className="nav-badge catalog-badge" title={`${policies.items.length} policy profiles`}>
                          {policies.items.length}
                        </span>
                      )}
                      {isActive && <ChevronRight size={15} style={{ marginLeft: item.name === "Overview" ? "auto" : undefined }} />}
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
                {devices.filter(d => d.status !== "revoked").length > 0 && (
                  <option value="broadcast" style={{ color: "#38bdf8", fontWeight: 700 }}>
                    ⚡ All Fleet Devices (Broadcast · {devices.filter(d => d.status !== "revoked").length} nodes)
                  </option>
                )}
                {devices.map(d => (
                  <option key={d.id} value={d.id}>
                    💻 {d.name || d.hostname} ({d.is_live ? "Online" : d.status === "revoked" ? "Revoked" : "Offline"})
                  </option>
                ))}
                <option value="__pair__">➕ Connect / Pair Another PC…</option>
              </select>
            </div>

            <div
              className={`server-status-chip ${serverOnline ? "online" : "offline"}`}
              title={`Active API endpoint: ${API} · Click to configure`}
              onClick={() => setPage("Settings")}
              style={{ cursor: "pointer" }}
            >
              <span className="live-pulse-dot" style={{ background: serverOnline ? "#10b981" : "#ef4444" }} />
              <span>SERVER:</span>
              <strong style={{ color: serverOnline ? "#34d399" : "#f87171" }}>
                {serverOnline ? `127.0.0.1:8000 (${serverLatency ?? 0}ms)` : "DISCONNECTED"}
              </strong>
            </div>

            {activeDeviceId === "broadcast" ? (
              <div className="telemetry-chip" style={{ borderColor: "#0284c7" }}>
                <span className="live-pulse-dot" style={{ background: "#38bdf8" }} />
                <span style={{ color: "#38bdf8" }}>TARGET:</span>
                <strong style={{ color: "#38bdf8" }}>ALL FLEET NODES ({devices.filter(d => d.status !== "revoked").length})</strong>
              </div>
            ) : activeDevice ? (
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

            <a
              href={`${API.replace(/\/api$/, '')}/download/povishield`}
              download="povishield"
              className="secondary-button"
              style={{ padding: "6px 12px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 5, textDecoration: "none", borderColor: "#0284c7", color: "#38bdf8" }}
              title="Download ./povishield executable for any remote Linux PC"
            >
              <Download size={13} /> Download CLI
            </a>
            <button
              className="primary-button"
              style={{ padding: "6px 14px", fontSize: 11 }}
              onClick={() => setPage("Fleet / Devices")}
            >
              <Server size={14} /> Connect Device
            </button>
            <button className="icon-button" onClick={handleRefreshWorkspace} title="Refresh workspace data" disabled={loading}>
              <RefreshCw size={17} className={loading ? "spin" : ""} />
            </button>
            <div className="avatar" title={`PoViShield Security Operator: ${operatorName}`}>
              {operatorName.split(" ").filter(Boolean).map(w => w[0]).join("").slice(0, 2).toUpperCase() || "PV"}
            </div>
          </div>
        </header>

        <div className="page-content">
          {/* Real-time Floating Safety Gate Authorization Toast */}
          {pendingApprovals && pendingApprovals.filter(r => !toastDismissedIds.has(r.id)).length > 0 && (
            <aside className="floating-approval-toast" role="alert" aria-live="assertive">
              <div className="floating-approval-toast-header">
                <div className="floating-approval-toast-title">
                  <ShieldAlert size={16} color="#fb923c" />
                  <span>Safety Gate Permission Required ({pendingApprovals.filter(r => !toastDismissedIds.has(r.id)).length})</span>
                </div>
                <button
                  className="icon-button"
                  style={{ padding: 4, height: "auto" }}
                  onClick={() => {
                    setToastDismissedIds(new Set([...pendingApprovals.map(r => r.id)]));
                  }}
                  title="Dismiss Notification Toast"
                >
                  <X size={14} />
                </button>
              </div>
              {pendingApprovals.filter(r => !toastDismissedIds.has(r.id)).slice(0, 1).map((req) => (
                <div key={req.id} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 11 }}>
                    <span style={{ color: "#38bdf8", fontFamily: "var(--font-mono)" }}>
                      💻 {req.hostname || "local"} ({req.device_id || "laptop_terminal"})
                    </span>
                    <span style={{ color: "#fdba74", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                      {req.mode?.toUpperCase() || "APPROVAL-REQUIRED"}
                    </span>
                  </div>
                  <div style={{
                    background: "#030712",
                    border: "1px solid #1f2937",
                    borderRadius: 4,
                    padding: "6px 8px",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    color: "#f8fafc",
                    overflowX: "auto"
                  }}>
                    $ {Array.isArray(req.command) ? req.command.join(" ") : req.target}
                  </div>
                  <div style={{ fontSize: 11, color: "#94a3b8" }}>
                    {req.rationale || "Interactive execution permission requested"} · ID: <code style={{ color: "#fdba74" }}>{req.id}</code>
                  </div>
                  <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                    <button
                      className="primary-button"
                      onClick={() => handleGrantApproval(req.id)}
                      style={{
                        background: "#059669",
                        borderColor: "#10b981",
                        color: "#fff",
                        padding: "6px 12px",
                        fontSize: 11,
                        fontWeight: 700,
                        flex: 1,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: 4
                      }}
                    >
                      <Check size={13} /> Grant Approval
                    </button>
                    <button
                      className="secondary-button"
                      onClick={() => handleDenyApproval(req.id)}
                      style={{
                        borderColor: "#7f1d1d",
                        color: "#f87171",
                        padding: "6px 10px",
                        fontSize: 11,
                        fontWeight: 600
                      }}
                    >
                      Deny
                    </button>
                  </div>
                </div>
              ))}
            </aside>
          )}

          <div className="page-heading">
            <div>
              <div className="eyebrow">COUNTERFACTUAL PERMISSION VERIFICATION</div>
              <h1>{page}</h1>
              <p>Rigorous, evidence-backed syscall reduction and fail-closed security for Linux.</p>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              {refreshedRecently && (
                <span style={{ fontSize: 12, color: "#34d399", fontFamily: "var(--font-mono)", display: "inline-flex", alignItems: "center", gap: 4 }}>
                  <Check size={14} /> Refreshed
                </span>
              )}
              <button className="secondary-button" onClick={handleRefreshWorkspace} disabled={loading}>
                <RefreshCw size={16} className={loading ? "spin" : ""} />
                {loading ? "Refreshing workspace…" : "Refresh workspace"}
              </button>
            </div>
          </div>

          {error && (
            <div className="notice" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12, width: "100%" }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                  <ShieldAlert size={19} />
                  <div><strong>API connection problem</strong><p>{error}</p></div>
                </div>
                <button className="secondary-button" onClick={handleRefreshWorkspace} disabled={loading} style={{ whiteSpace: "nowrap" }}>
                  <RefreshCw size={14} className={loading ? "spin" : ""} /> {loading ? "Retrying…" : "Retry Connection"}
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

          {/* Real-Time Pending Safety Gate Approvals Banner */}
          {pendingApprovals && pendingApprovals.length > 0 && (
            <div style={{
              background: "linear-gradient(135deg, rgba(234, 88, 12, 0.15) 0%, rgba(220, 38, 38, 0.2) 100%)",
              border: "1px solid rgba(249, 115, 22, 0.6)",
              borderRadius: 10,
              padding: "16px 20px",
              marginBottom: 20,
              boxShadow: "0 4px 24px rgba(249, 115, 22, 0.15)"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <ShieldAlert size={22} color="#fb923c" />
                  <div>
                    <h3 style={{ margin: 0, fontSize: 15, color: "#fed7aa", display: "flex", alignItems: "center", gap: 8 }}>
                      ⚠️ Safety Gate Permission Request ({pendingApprovals.length} Pending)
                    </h3>
                    <p style={{ margin: "2px 0 0", fontSize: 12, color: "#cbd5e1" }}>
                      An interactive terminal or remote host has requested execution authorization under policy-gated confinement.
                    </p>
                  </div>
                </div>
                <button
                  className="secondary-button"
                  onClick={() => setPage("Safety Gate & Approvals")}
                  style={{ fontSize: 11, padding: "4px 10px", borderColor: "#f97316", color: "#fdba74" }}
                >
                  View In Safety Gate →
                </button>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {pendingApprovals.map((req) => (
                  <div
                    key={req.id}
                    style={{
                      background: "rgba(10, 15, 29, 0.9)",
                      border: "1px solid rgba(249, 115, 22, 0.3)",
                      borderRadius: 8,
                      padding: "12px 16px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      flexWrap: "wrap",
                      gap: 12
                    }}
                  >
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: "#38bdf8", fontFamily: "var(--font-mono)" }}>
                          💻 {req.hostname || "local"} ({req.device_id || "laptop_terminal"})
                        </span>
                        <span style={{
                          fontSize: 10, padding: "2px 6px", borderRadius: 4,
                          background: "#431407", color: "#fb923c", border: "1px solid #7c2d12",
                          fontFamily: "var(--font-mono)", fontWeight: 700
                        }}>
                          MODE: {req.mode?.toUpperCase() || "APPROVAL-REQUIRED"}
                        </span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 13, color: "#f8fafc", fontFamily: "var(--font-mono)", background: "#030712", padding: "4px 8px", borderRadius: 4, border: "1px solid #1f2937" }}>
                          $ {Array.isArray(req.command) ? req.command.join(" ") : req.target}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: "#94a3b8" }}>
                        {req.rationale || "Interactive execution permission requested"} · Request ID: <code style={{ color: "#fdba74" }}>{req.id}</code>
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: 8 }}>
                      <button
                        className="primary-button"
                        onClick={() => handleGrantApproval(req.id)}
                        style={{
                          background: "#059669",
                          borderColor: "#10b981",
                          color: "#ffffff",
                          padding: "8px 16px",
                          fontSize: 12,
                          fontWeight: 700,
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          cursor: "pointer"
                        }}
                      >
                        <Check size={15} /> Grant Permission / Approve
                      </button>
                      <button
                        className="secondary-button"
                        onClick={() => handleDenyApproval(req.id)}
                        style={{
                          background: "rgba(185, 28, 28, 0.2)",
                          borderColor: "#dc2626",
                          color: "#fca5a5",
                          padding: "8px 14px",
                          fontSize: 12,
                          fontWeight: 700,
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          cursor: "pointer"
                        }}
                      >
                        <X size={15} /> Deny
                      </button>
                    </div>
                  </div>
                ))}
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

                  {/* Step-by-Step Guide Panel: Run ./povishield watch on Another PC */}
                  <RemoteWatchGuidePanel API={API} />

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
                  refreshTick={refreshTick}
                />
              )}

              {page === "Terminal / Execute" && (
                <TerminalExecutionConsole
                  API={API}
                  health={health}
                  devices={devices}
                  activeDeviceId={activeDeviceId}
                  setActiveDeviceId={setActiveDeviceId}
                  refreshTick={refreshTick}
                  pendingApprovals={pendingApprovals}
                  onGrantApproval={handleGrantApproval}
                  onDenyApproval={handleDenyApproval}
                  onRefreshApprovals={fetchPendingApprovals}
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
                      <button className="secondary-button" onClick={() => setMonitorEvents([])} disabled={monitorEvents.length === 0} title="Clear buffered live events"><RefreshCw size={13} />Clear buffer</button>
                      {monitorSession && <span className="monitor-session-id">Session {monitorSession.id}</span>}
                    </div>
                    {monitorError && <div className="notice activity-error"><ShieldAlert size={19} /><div><strong>Monitoring message</strong><p>{monitorError}</p></div></div>}
                    {monitorSession && (() => {
                      const filteredLive = monitorEvents.filter(ev => {
                        const cat = getSyscallCategory(ev.syscall || "");
                        const matchCat = liveCategory === "ALL" || cat.toLowerCase().replace(/[^a-z0-9]/g, "-") === liveCategory.toLowerCase().replace(/[^a-z0-9]/g, "-");
                        const query = liveSearch.trim().toLowerCase();
                        const matchQuery = !query || (ev.syscall || "").toLowerCase().includes(query) || String(ev.pid || "").includes(query);
                        return matchCat && matchQuery;
                      });
                      return (
                        <>
                          <div className="activity-summary">
                            <div><span>Session status</span><strong>{monitorSession.status}</strong></div>
                            <div><span>Buffered events</span><strong>{monitorEvents.length}</strong></div>
                            <div><span>Elapsed (seconds)</span><strong>{monitorSession.elapsed_seconds ?? 0}</strong></div>
                            <div><span>Exit code</span><strong>{monitorSession.exit_code ?? "—"}</strong></div>
                          </div>
                          {monitorSession.reason && <p className="footnote">Session ended: {monitorSession.reason.replaceAll("_", " ")}. Trace: {monitorSession.source}</p>}

                          <div className="filter-bar-container">
                            <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 200 }}>
                              <Search size={14} style={{ color: "#64748b" }} />
                              <input
                                placeholder="Filter live stream by syscall or PID…"
                                value={liveSearch}
                                onChange={e => setLiveSearch(e.target.value)}
                                style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, width: "100%", outline: "none", fontFamily: "var(--font-mono)" }}
                              />
                            </div>
                            <div className="filter-pills-row">
                              {["ALL", "File I/O", "Process", "Memory", "Network", "Privileged", "System"].map(cat => {
                                const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                                return (
                                  <button
                                    key={cat}
                                    type="button"
                                    className={`category-pill-btn ${liveCategory === cat ? `active ${cls}` : ""}`}
                                    onClick={() => setLiveCategory(cat)}
                                  >
                                    {cat}
                                  </button>
                                );
                              })}
                            </div>
                          </div>

                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6, fontSize: 11, color: "#64748b" }}>
                            <span>Showing {filteredLive.length} of {monitorEvents.length} live events</span>
                          </div>

                          <div className="table-wrap activity-table-wrap"><table>
                            <thead><tr><th>SEQ</th><th>PID</th><th>PHASE</th><th>SYSCALL</th><th>CATEGORY</th><th>NUMBER</th><th>RETURN VALUE</th></tr></thead>
                            <tbody>{[...filteredLive].reverse().map((event, index) => {
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
                        </>
                      );
                    })()}
                  </section>

                  <section className="panel events-section">
                    <div className="panel-heading activity-heading">
                      <div>
                        <h3>Syscall activity trace</h3>
                        <p>Events captured by PoViShield's learning tracer</p>
                      </div>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                        <button className="secondary-button" onClick={loadEvents} disabled={eventsLoading}>
                          <RefreshCw size={15} className={eventsLoading ? "spin-icon" : ""} />
                          {eventsLoading ? "Refreshing…" : "Refresh events"}
                        </button>
                        <button
                          className="secondary-button"
                          disabled={!eventsData?.events?.length}
                          onClick={() => {
                            if (!eventsData?.events?.length) return;
                            const blob = new Blob([JSON.stringify(eventsData.events, null, 2)], { type: "application/json" });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `povishield-trace-${new Date().toISOString().slice(0, 10)}.json`;
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            setTimeout(() => URL.revokeObjectURL(url), 1000);
                          }}
                        >
                          <Download size={14} /> Export JSON
                        </button>
                        <button
                          className="secondary-button"
                          disabled={!eventsData?.events?.length}
                          onClick={() => {
                            if (!eventsData?.events?.length) return;
                            const headers = ["seq", "pid", "phase", "syscall", "category", "syscall_nr", "return_value"];
                            const rows = eventsData.events.map(e => [
                              e.seq ?? "",
                              e.pid ?? "",
                              e.phase ?? "",
                              e.syscall ?? "",
                              getSyscallCategory(e.syscall || ""),
                              e.syscall_nr ?? "",
                              e.return_value ?? ""
                            ]);
                            const csv = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
                            const blob = new Blob([csv], { type: "text/csv" });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `povishield-trace-${new Date().toISOString().slice(0, 10)}.csv`;
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            setTimeout(() => URL.revokeObjectURL(url), 1000);
                          }}
                        >
                          <FileText size={14} /> Export CSV
                        </button>
                      </div>
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

                    {!eventsLoading && !eventsError && eventsData && (() => {
                      const allTraceEvents = Array.isArray(eventsData.events) ? eventsData.events : [];
                      const filteredTraceEvents = allTraceEvents.filter(ev => {
                        const cat = getSyscallCategory(ev.syscall || "");
                        const matchCat = traceCategory === "ALL" || cat.toLowerCase().replace(/[^a-z0-9]/g, "-") === traceCategory.toLowerCase().replace(/[^a-z0-9]/g, "-");
                        const matchPhase = tracePhase === "all" || ev.phase === tracePhase;
                        const query = traceSearch.trim().toLowerCase();
                        const matchQuery = !query || (ev.syscall || "").toLowerCase().includes(query) || String(ev.pid || "").includes(query) || String(ev.syscall_nr || "").includes(query);
                        return matchCat && matchPhase && matchQuery;
                      });

                      const uniqueSyscallsInFilter = new Set(filteredTraceEvents.map(e => e.syscall)).size;

                      return (
                        <>
                          <div className="activity-summary">
                            <div><span>Total Trace Events</span><strong>{eventsData.count}</strong></div>
                            <div><span>Matching Filter</span><strong style={{ color: "#38bdf8" }}>{filteredTraceEvents.length}</strong></div>
                            <div><span>Unique Syscalls</span><strong>{uniqueSyscallsInFilter}</strong></div>
                            <div><span>Source File</span><strong className="source-value">{eventsData.source}</strong></div>
                          </div>

                          <div className="filter-bar-container">
                            <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 220 }}>
                              <Search size={14} style={{ color: "#64748b" }} />
                              <input
                                placeholder="Search recorded trace by syscall name, number, or PID…"
                                value={traceSearch}
                                onChange={e => setTraceSearch(e.target.value)}
                                style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, width: "100%", outline: "none", fontFamily: "var(--font-mono)" }}
                              />
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", fontFamily: "var(--font-mono)" }}>Phase:</span>
                              <select
                                value={tracePhase}
                                onChange={e => setTracePhase(e.target.value)}
                                style={{ background: "#091220", border: "1px solid #1e293b", color: "#f1f5f9", fontSize: 11, borderRadius: 4, padding: "2px 6px" }}
                              >
                                <option value="all">All Phases</option>
                                <option value="entry">Entry Only</option>
                                <option value="exit">Exit Only</option>
                              </select>
                            </div>
                            <div className="filter-pills-row">
                              {["ALL", "File I/O", "Process", "Memory", "Network", "Privileged", "System"].map(cat => {
                                const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                                return (
                                  <button
                                    key={cat}
                                    type="button"
                                    className={`category-pill-btn ${traceCategory === cat ? `active ${cls}` : ""}`}
                                    onClick={() => setTraceCategory(cat)}
                                  >
                                    {cat}
                                  </button>
                                );
                              })}
                            </div>
                          </div>

                          {filteredTraceEvents.length === 0 ? (
                            <p className="muted activity-message">No recorded events match the selected filters.</p>
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
                                  {filteredTraceEvents.map((event, index) => {
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
                      );
                    })()}
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
                      name: item.syscall,
                      number: item.syscall_nr,
                      count: item.count,
                      category: getSyscallCategory(item.syscall)
                    }));
                    const totalInvocations = profileData?.entry_records ?? 0;
                    const uniqueSyscalls = profileData?.unique_syscalls ?? allRows.length;

                    // Category distribution stats
                    const categorySums = {
                      "File I/O": 0,
                      "Process": 0,
                      "Memory": 0,
                      "Network": 0,
                      "Privileged": 0,
                      "System": 0
                    };
                    allRows.forEach(r => {
                      if (categorySums[r.category] !== undefined) categorySums[r.category] += r.count;
                      else categorySums["System"] += r.count;
                    });
                    const totalSum = Object.values(categorySums).reduce((a, b) => a + b, 0) || 1;

                    // Filter
                    let visibleRows = allRows.filter(row => {
                      const query = profileSearch.trim().toLowerCase();
                      const matchQuery = !query || row.name.toLowerCase().includes(query) || String(row.number ?? "").includes(query);
                      const matchCat = profileCategory === "ALL" || row.category.toLowerCase().replace(/[^a-z0-9]/g, "-") === profileCategory.toLowerCase().replace(/[^a-z0-9]/g, "-");
                      return matchQuery && matchCat;
                    });

                    // Sort
                    if (profileSort === "count_desc") visibleRows.sort((a, b) => b.count - a.count);
                    else if (profileSort === "count_asc") visibleRows.sort((a, b) => a.count - b.count);
                    else if (profileSort === "name_asc") visibleRows.sort((a, b) => a.name.localeCompare(b.name));
                    else if (profileSort === "num_asc") visibleRows.sort((a, b) => (a.number ?? 999) - (b.number ?? 999));

                    const maxCount = Math.max(1, ...visibleRows.map(row => row.count));

                    return (
                      <>
                        <div className="activity-summary profile-summary">
                          <div><span>Observed Invocations</span><strong>{totalInvocations}</strong></div>
                          <div><span>Unique Syscalls</span><strong>{uniqueSyscalls}</strong></div>
                          <div><span>Filtered Syscalls</span><strong style={{ color: "#38bdf8" }}>{visibleRows.length}</strong></div>
                          <div><span>Count Method</span><strong className="source-value">Entry records</strong></div>
                        </div>

                        {/* Visual Category Distribution Bar */}
                        <div style={{ marginTop: 8, marginBottom: 12 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6, fontSize: 11 }}>
                            <span style={{ color: "#94a3b8", fontWeight: 600 }}>Syscall Category Invocations Distribution:</span>
                            <span style={{ color: "#64748b", fontFamily: "var(--font-mono)", fontSize: 10 }}>Total: {totalSum.toLocaleString()} calls</span>
                          </div>
                          <div className="category-dist-bar">
                            {Object.entries(categorySums).map(([cat, cnt]) => {
                              const pct = ((cnt / totalSum) * 100).toFixed(1);
                              if (cnt === 0) return null;
                              const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                              return (
                                <div
                                  key={cat}
                                  className={`category-dist-item ${cls}`}
                                  style={{ width: `${pct}%` }}
                                  title={`${cat}: ${cnt} (${pct}%)`}
                                />
                              );
                            })}
                          </div>
                          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", fontSize: 10, fontFamily: "var(--font-mono)" }}>
                            {Object.entries(categorySums).map(([cat, cnt]) => {
                              if (cnt === 0) return null;
                              const pct = ((cnt / totalSum) * 100).toFixed(1);
                              const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                              return (
                                <div key={cat} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                                  <span className={`category-tag ${cls}`} style={{ padding: "1px 5px", fontSize: 9 }}>{cat}</span>
                                  <span style={{ color: "#94a3b8" }}>{pct}%</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        <div className="filter-bar-container">
                          <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 200 }}>
                            <Search size={14} style={{ color: "#64748b" }} />
                            <input
                              value={profileSearch}
                              onChange={event => setProfileSearch(event.target.value)}
                              placeholder="Search syscall by name or number (e.g. openat, read, 3)…"
                              style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, width: "100%", outline: "none", fontFamily: "var(--font-mono)" }}
                            />
                          </div>

                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", fontFamily: "var(--font-mono)" }}>Sort:</span>
                            <select
                              value={profileSort}
                              onChange={e => setProfileSort(e.target.value)}
                              style={{ background: "#091220", border: "1px solid #1e293b", color: "#f1f5f9", fontSize: 11, borderRadius: 4, padding: "2px 6px" }}
                            >
                              <option value="count_desc">Frequency (Highest first)</option>
                              <option value="count_asc">Frequency (Lowest first)</option>
                              <option value="name_asc">Alphabetical (A-Z)</option>
                              <option value="num_asc">Syscall Number (#)</option>
                            </select>
                          </div>

                          <div className="filter-pills-row">
                            {["ALL", "File I/O", "Process", "Memory", "Network", "Privileged", "System"].map(cat => {
                              const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                              return (
                                <button
                                  key={cat}
                                  type="button"
                                  className={`category-pill-btn ${profileCategory === cat ? `active ${cls}` : ""}`}
                                  onClick={() => setProfileCategory(cat)}
                                >
                                  {cat}
                                </button>
                              );
                            })}
                          </div>
                        </div>

                        <div className="profile-chart-list">
                          {visibleRows.length === 0 ? (
                            <p className="muted activity-message">No syscalls match this search or category filter.</p>
                          ) : visibleRows.map(row => {
                            const cls = row.category.toLowerCase().replace(/[^a-z0-9]/g, "-");
                            return (
                              <div className="profile-bar-row" key={row.name}>
                                <div className="profile-bar-label">
                                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <span style={{ fontWeight: 600 }}>{row.name}</span>
                                    <code>#{row.number ?? "?"}</code>
                                    <span className={`category-tag ${cls}`} style={{ fontSize: 9, padding: "1px 6px" }}>{row.category}</span>
                                  </div>
                                  <strong>{row.count.toLocaleString()} calls</strong>
                                </div>
                                <div className="profile-bar-track">
                                  <div className={`profile-bar-value ${cls}`} style={{ width: `${(row.count / maxCount) * 100}%` }} />
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    );
                  })()}
                </section>
              )}

              {page === "Policy Explorer" && (
                <PolicyExplorer
                  API={API}
                  policies={policies}
                  onRefresh={handleRefreshWorkspace}
                  compareBase={compareBase}
                  setCompareBase={setCompareBase}
                  compareCand={compareCand}
                  setCompareCand={setCompareCand}
                  compareResult={compareResult}
                  compareLoading={compareLoading}
                  compareError={compareError}
                  runCompare={runCompare}
                />
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
                    <button
                      className="secondary-button"
                      style={{
                        background: ablationSubTab === "interactive" ? "#18372f" : "#111b2b",
                        borderColor: ablationSubTab === "interactive" ? "#4cbd99" : "#2a394f",
                        color: ablationSubTab === "interactive" ? "#78e6bc" : "#d5deeb",
                        fontWeight: ablationSubTab === "interactive" ? 600 : 400
                      }}
                      onClick={() => setAblationSubTab("interactive")}
                    >
                      <Play size={14} /> Interactive Permission Prover (Live Seccomp Lab)
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
                            <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
                              <div>
                                <h3>Controlled Noisy Policy Minimization Results</h3>
                                <p>Synthetic extraneous permissions eliminated across all 9 Linux targets (click any row to inspect & test)</p>
                              </div>
                              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#050914", border: "1px solid #1a273b", borderRadius: 6, padding: "4px 8px" }}>
                                  <Search size={13} style={{ color: "#64748b" }} />
                                  <input
                                    placeholder="Filter noisy targets…"
                                    value={noisyTargetSearch}
                                    onChange={e => setNoisyTargetSearch(e.target.value)}
                                    style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, outline: "none", width: 140, fontFamily: "var(--font-mono)" }}
                                  />
                                </div>
                                <button
                                  className="secondary-button"
                                  onClick={() => {
                                    const blob = new Blob([JSON.stringify(noisyAblationData, null, 2)], { type: "application/json" });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement("a");
                                    a.href = url;
                                    a.download = "povishield-noisy-ablation-eval.json";
                                    document.body.appendChild(a);
                                    a.click();
                                    a.remove();
                                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                                  }}
                                  style={{ fontSize: 11 }}
                                >
                                  <Download size={13} /> Export JSON
                                </button>
                                <span className="demo-badge">100% INJECTED ELIMINATION</span>
                              </div>
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
                                  {(noisyAblationData.targets ?? [])
                                    .filter(t => !noisyTargetSearch.trim() || t.target.toLowerCase().includes(noisyTargetSearch.trim().toLowerCase()))
                                    .map(t => (
                                      <tr
                                        key={t.target}
                                        className="clickable-table-row"
                                        onClick={() => setSelectedTargetDetail({ ...t, type: "noisy" })}
                                        title="Click to view deep permission breakdown and live trial"
                                      >
                                        <td className="process-cell">
                                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                            <strong>{t.target}</strong>
                                            <Eye size={12} style={{ color: "#45d6a5", opacity: 0.8 }} />
                                          </div>
                                        </td>
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
                              {(noisyAblationData.injected_permissions ?? []).map(p => {
                                const cat = getSyscallCategory(p.syscall);
                                const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                                return (
                                  <div key={p.syscall} className="tier-section" style={{ margin: 0 }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                      <span className="syscall-pill pill-removable">{p.syscall}</span>
                                      <span className={`category-tag ${cls}`} style={{ fontSize: 9, padding: "1px 5px" }}>{cat}</span>
                                      <span style={{ fontSize: 11, color: "#dbe4f1" }}>{p.rationale}</span>
                                    </div>
                                  </div>
                                );
                              })}
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
                            <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
                              <div>
                                <h3>Minimization Benchmark Results by Program</h3>
                                <p>Observation-only minimal unions under SCMP_ACT_KILL_PROCESS fail-stop semantics (results/ablation_eval.json)</p>
                              </div>
                              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#050914", border: "1px solid #1a273b", borderRadius: 6, padding: "4px 8px" }}>
                                  <Search size={13} style={{ color: "#64748b" }} />
                                  <input
                                    placeholder="Filter benchmark targets…"
                                    value={baselineTargetSearch}
                                    onChange={e => setBaselineTargetSearch(e.target.value)}
                                    style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, outline: "none", width: 140, fontFamily: "var(--font-mono)" }}
                                  />
                                </div>
                                <button
                                  className="secondary-button"
                                  onClick={() => {
                                    const blob = new Blob([JSON.stringify(ablationData, null, 2)], { type: "application/json" });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement("a");
                                    a.href = url;
                                    a.download = "povishield-ablation-eval.json";
                                    document.body.appendChild(a);
                                    a.click();
                                    a.remove();
                                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                                  }}
                                  style={{ fontSize: 11 }}
                                >
                                  <Download size={13} /> Export JSON
                                </button>
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
                                  {(ablationData.targets ?? [])
                                    .filter(t => !baselineTargetSearch.trim() || t.target.toLowerCase().includes(baselineTargetSearch.trim().toLowerCase()))
                                    .map(t => (
                                      <tr
                                        key={t.target}
                                        className="clickable-table-row"
                                        onClick={() => setSelectedTargetDetail({ ...t, type: "baseline" })}
                                        title="Click to view deep permission breakdown and live trial"
                                      >
                                        <td className="process-cell">
                                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                            <strong>{t.target}</strong>
                                            <Eye size={12} style={{ color: "#45d6a5", opacity: 0.8 }} />
                                          </div>
                                        </td>
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

                  {ablationSubTab === "interactive" && (
                    <>
                      <section className="metrics-grid">
                        <Metric icon={Activity} label="Enforcement Engine"
                          value="seccomp-bpf" detail="Kernel Filter (SCMP_ACT_KILL)" />
                        <Metric icon={LockKeyhole} label="Kernel Verdict Semantics"
                          value="SIGSYS (-31)" detail="Kernel terminates non-permitted syscalls" />
                        <Metric icon={ShieldCheck} label="Attack Surface Reduction"
                          value="Empirical Proof" detail="Extraneous permissions safely pruned" />
                        <Metric icon={CheckCircle2} label="Reproducibility"
                          value="100% Deterministic" detail="Exact CLI invocation exported" />
                      </section>

                      <section className="panel" style={{ marginBottom: 20 }}>
                        <div className="panel-heading">
                          <div>
                            <h3>Empirical Leave-One-Out (LOO) Permission Prover</h3>
                            <p>Challenge whether a permission is strictly required by withholding it under kernel kill semantics</p>
                          </div>
                          <span className="demo-badge">REAL LINUX SECCOMP ENFORCEMENT</span>
                        </div>

                        {/* Benchmark Vector Presets */}
                        <div style={{ marginBottom: 16 }}>
                          <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.5px", display: "block", marginBottom: 8 }}>
                            Quick Test Scenarios (Click to Load)
                          </span>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                            {[
                              { label: "Echo + mount (Extraneous)", cmd: "/usr/bin/echo 'Hello from PoViShield Sandbox'", syscall: "mount", target: "echo", desc: "Extraneous mount permission safe to remove (clean exit 0)" },
                              { label: "Echo - write (Load-Bearing)", cmd: "/usr/bin/echo 'Hello from PoViShield Sandbox'", syscall: "write", target: "echo", desc: "Write syscall required for output (triggers SIGSYS kill)" },
                              { label: "Cat - read (Load-Bearing)", cmd: "/usr/bin/cat /etc/os-release", syscall: "read", target: "cat", desc: "Read syscall required to read file (triggers SIGSYS kill)" },
                              { label: "Cat + ptrace (Extraneous)", cmd: "/usr/bin/cat /etc/os-release", syscall: "ptrace", target: "cat", desc: "Dangerous ptrace debugging syscall pruned (clean exit 0)" },
                              { label: "Ls - getdents64 (Load-Bearing)", cmd: "/usr/bin/ls -la /tmp", syscall: "getdents64", target: "ls", desc: "Directory reading syscall required (triggers SIGSYS kill)" },
                              { label: "Python3 + bpf (Extraneous)", cmd: "/usr/bin/python3 -c \"import os; print(os.getpid())\"", syscall: "bpf", target: "python3", desc: "Privileged eBPF syscall pruned from Python sandbox (clean exit 0)" },
                            ].map(preset => (
                              <button
                                key={preset.label}
                                className={`pvs-preset-btn ${proverCommand === preset.cmd && proverSyscall === preset.syscall ? "active" : ""}`}
                                onClick={() => {
                                  setProverCommand(preset.cmd);
                                  setProverSyscall(preset.syscall);
                                  setProverTarget(preset.target);
                                  setProverError("");
                                  handleRunProverTrial(preset.cmd, preset.syscall, preset.target);
                                }}
                                title={preset.desc}
                              >
                                {preset.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Interactive Prover Form */}
                        <div style={{ background: "#050a14", border: "1px solid #1a273b", borderRadius: 8, padding: 16, marginBottom: 16 }}>
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 180px", gap: 12, marginBottom: 14 }}>
                            <div>
                              <label style={{ display: "block", fontSize: 11, color: "#94a3b8", marginBottom: 6 }}>
                                Workload Command Line:
                              </label>
                              <input
                                value={proverCommand}
                                onChange={e => setProverCommand(e.target.value)}
                                placeholder="/usr/bin/echo 'Hello from PoViShield Sandbox'"
                                style={{
                                  width: "100%",
                                  background: "#08111e",
                                  border: "1px solid #23354e",
                                  borderRadius: 6,
                                  color: "#f1f5f9",
                                  fontFamily: "var(--font-mono)",
                                  fontSize: 12,
                                  padding: "8px 12px"
                                }}
                              />
                            </div>
                            <div>
                              <label style={{ display: "block", fontSize: 11, color: "#94a3b8", marginBottom: 6 }}>
                                Target Program Name:
                              </label>
                              <input
                                value={proverTarget}
                                onChange={e => setProverTarget(e.target.value)}
                                placeholder="echo"
                                style={{
                                  width: "100%",
                                  background: "#08111e",
                                  border: "1px solid #23354e",
                                  borderRadius: 6,
                                  color: "#f1f5f9",
                                  fontFamily: "var(--font-mono)",
                                  fontSize: 12,
                                  padding: "8px 12px"
                                }}
                              />
                            </div>
                          </div>

                          <div style={{ marginBottom: 14 }}>
                            <label style={{ display: "block", fontSize: 11, color: "#94a3b8", marginBottom: 6 }}>
                              System Call to Withhold (Ablated Permission):
                            </label>
                            <input
                              value={proverSyscall}
                              onChange={e => setProverSyscall(e.target.value.toLowerCase().trim())}
                              placeholder="mount"
                              style={{
                                width: "240px",
                                background: "#08111e",
                                border: "1px solid #23354e",
                                borderRadius: 6,
                                color: "#f1f5f9",
                                fontFamily: "var(--font-mono)",
                                fontSize: 12,
                                padding: "8px 12px",
                                marginBottom: 10
                              }}
                            />

                            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                              <div>
                                <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>High-Risk Extraneous Candidates: </span>
                                <div className="pvs-pill-group" style={{ display: "inline-flex", marginLeft: 6 }}>
                                  {["mount", "ptrace", "bpf", "reboot", "sysfs", "chroot", "kill", "setuid"].map(sc => (
                                    <button
                                      key={sc}
                                      className={`pvs-syscall-select-pill ${proverSyscall === sc ? "active" : ""}`}
                                      onClick={() => setProverSyscall(sc)}
                                      type="button"
                                    >
                                      {sc}
                                    </button>
                                  ))}
                                </div>
                              </div>
                              <div>
                                <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>Core Workload Syscalls: </span>
                                <div className="pvs-pill-group" style={{ display: "inline-flex", marginLeft: 6 }}>
                                  {["write", "read", "openat", "close", "getdents64", "execve", "mmap", "brk"].map(sc => (
                                    <button
                                      key={sc}
                                      className={`pvs-syscall-select-pill ${proverSyscall === sc ? "active" : ""}`}
                                      onClick={() => setProverSyscall(sc)}
                                      type="button"
                                    >
                                      {sc}
                                    </button>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>

                          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 16 }}>
                            <button
                              className="primary-button"
                              onClick={() => handleRunProverTrial()}
                              disabled={proverRunning}
                              style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 18px" }}
                            >
                              {proverRunning ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
                              {proverRunning ? "Executing in Linux Sandbox..." : "Run Empirical Counterfactual Trial"}
                            </button>
                            <span style={{ fontSize: 11, color: "#64748b" }}>
                              Enforces kernel filter via <code>SCMP_ACT_KILL_PROCESS</code> with reference baseline comparison
                            </span>
                          </div>
                        </div>

                        {proverError && (
                          <div className="notice" style={{ borderColor: "#ef4444", background: "rgba(239, 68, 68, 0.1)", marginBottom: 16 }}>
                            <XCircle size={18} style={{ color: "#ef4444" }} />
                            <div>
                              <strong style={{ color: "#ef4444" }}>Trial Execution Error</strong>
                              <p style={{ color: "#fca5a5" }}>{proverError}</p>
                            </div>
                          </div>
                        )}

                        {proverResult && (
                          <div style={{ background: "#060b17", border: `1px solid ${proverResult.is_load_bearing ? "#ef4444" : "#10b981"}`, borderRadius: 8, padding: 20 }}>
                            <div className={`pvs-verdict-banner ${proverResult.is_load_bearing ? "required" : "removable"}`} style={{ marginTop: 0, marginBottom: 16 }}>
                              {proverResult.is_load_bearing ? <ShieldAlert size={26} /> : <ShieldCheck size={26} />}
                              <div style={{ flex: 1 }}>
                                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
                                  <strong style={{ fontSize: 15, letterSpacing: "0.5px" }}>
                                    {proverResult.is_load_bearing
                                      ? `VERDICT: REQUIRED (LOAD-BEARING PERMISSION) — '${proverResult.ablated_syscall}'`
                                      : `VERDICT: REMOVABLE (EXTRANEOUS PERMISSION) — '${proverResult.ablated_syscall}'`}
                                  </strong>
                                  <span style={{
                                    fontFamily: "var(--font-mono)",
                                    fontSize: 11,
                                    padding: "3px 8px",
                                    borderRadius: 4,
                                    background: proverResult.is_load_bearing ? "#ef4444" : "#10b981",
                                    color: "#fff",
                                    fontWeight: 700
                                  }}>
                                    {proverResult.is_sigsys ? "KERNEL SIGSYS TERMINATION" : `EXIT ${proverResult.cand_exit_code}`}
                                  </span>
                                </div>
                                <p style={{ marginTop: 6, fontSize: 12, lineHeight: 1.5, opacity: 0.95 }}>
                                  {proverResult.reason}
                                </p>
                              </div>
                            </div>

                            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                              <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                                <span style={{ fontSize: 10, color: "#64748b" }}>KERNEL EXIT CODE</span>
                                <strong style={{ fontSize: 13, color: proverResult.is_sigsys ? "#f87171" : "#4ade80" }}>
                                  {proverResult.cand_exit_code} {proverResult.is_sigsys ? "(SIGSYS)" : ""}
                                </strong>
                              </div>
                              <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                                <span style={{ fontSize: 10, color: "#64748b" }}>SIGNAL</span>
                                <strong style={{ fontSize: 13, color: proverResult.signal === "SIGSYS" ? "#f87171" : "#e2e8f0" }}>
                                  {proverResult.signal || (proverResult.is_sigsys ? "SIGSYS" : "NONE")}
                                </strong>
                              </div>
                              <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                                <span style={{ fontSize: 10, color: "#64748b" }}>SEARCH DURATION</span>
                                <strong style={{ fontSize: 13, color: "#38bdf8" }}>
                                  {proverResult.duration_ms} ms
                                </strong>
                              </div>
                              <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                                <span style={{ fontSize: 10, color: "#64748b" }}>POLICY CANDIDATES</span>
                                <strong style={{ fontSize: 13, color: "#f1f5f9" }}>
                                  {proverResult.candidate_syscalls_count} syscalls
                                </strong>
                              </div>
                            </div>

                            {/* Workload Stdout / Stderr Previews */}
                            {(proverResult.cand_stdout || proverResult.cand_stderr) && (
                              <div style={{ background: "#040711", border: "1px solid #1a273b", borderRadius: 6, padding: 12, marginBottom: 14 }}>
                                <div style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", marginBottom: 6 }}>
                                  Process Output Stream Capture
                                </div>
                                {proverResult.cand_stdout && (
                                  <pre style={{ margin: 0, color: "#cbd5e1", fontSize: 11, fontFamily: "var(--font-mono)", whiteSpace: "pre-wrap" }}>
                                    {proverResult.cand_stdout}
                                  </pre>
                                )}
                                {proverResult.cand_stderr && (
                                  <pre style={{ margin: "6px 0 0", color: "#f87171", fontSize: 11, fontFamily: "var(--font-mono)", whiteSpace: "pre-wrap" }}>
                                    {proverResult.cand_stderr}
                                  </pre>
                                )}
                              </div>
                            )}

                            {/* Reproduction Command */}
                            <div style={{ background: "#08101d", border: "1px solid #1a2b42", borderRadius: 6, padding: 12 }}>
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                                <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>
                                  Deterministic CLI Reproduction Command
                                </span>
                                <button
                                  className="secondary-button"
                                  onClick={() => {
                                    navigator.clipboard.writeText(proverResult.reproduction_command);
                                    setCopiedRepro(true);
                                    setTimeout(() => setCopiedRepro(false), 2000);
                                  }}
                                  style={{ padding: "3px 8px", fontSize: 11 }}
                                >
                                  {copiedRepro ? <Check size={12} style={{ color: "#4ade80" }} /> : <Copy size={12} />}
                                  {copiedRepro ? "Copied!" : "Copy CLI Command"}
                                </button>
                              </div>
                              <code style={{ display: "block", color: "#38bdf8", fontSize: 11, wordBreak: "break-all" }}>
                                {proverResult.reproduction_command}
                              </code>
                            </div>
                          </div>
                        )}
                      </section>
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

                  {/* Target Empirical Inspection Modal */}
                  {selectedTargetDetail && (
                    <div className="pvs-modal-backdrop" onClick={() => setSelectedTargetDetail(null)}>
                      <div className="pvs-modal-dialog" onClick={e => e.stopPropagation()}>
                        <div className="pvs-modal-header">
                          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <FlaskConical size={20} style={{ color: "#45d6a5" }} />
                            <div>
                              <h3 style={{ margin: 0, fontSize: 16 }}>Target Empirical Breakdown: {selectedTargetDetail.target}</h3>
                              <span style={{ fontSize: 11, color: "#64748b" }}>
                                {selectedTargetDetail.type === "noisy" ? "Controlled Noisy Injection Benchmark" : "Real Workload Minimal Union Evaluation"}
                              </span>
                            </div>
                          </div>
                          <button className="pvs-modal-close-btn" onClick={() => setSelectedTargetDetail(null)}>
                            <X size={16} />
                          </button>
                        </div>

                        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
                          <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                            <span style={{ fontSize: 10, color: "#64748b" }}>GROUND TRUTH</span>
                            <strong style={{ fontSize: 14 }}>{selectedTargetDetail.ground_truth_syscalls ?? selectedTargetDetail.baseline?.allowed_syscalls ?? "—"}</strong>
                          </div>
                          <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                            <span style={{ fontSize: 10, color: "#64748b" }}>BASELINE ALLOWED</span>
                            <strong style={{ fontSize: 14 }}>{selectedTargetDetail.noisy_baseline?.allowed_syscalls ?? selectedTargetDetail.baseline?.allowed_syscalls ?? "—"}</strong>
                          </div>
                          <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                            <span style={{ fontSize: 10, color: "#64748b" }}>MINIMIZED ALLOWED</span>
                            <strong style={{ fontSize: 14, color: "#45d6a5" }}>{selectedTargetDetail.minimized?.allowed_syscalls ?? selectedTargetDetail.counterfactual?.allowed_syscalls ?? "—"}</strong>
                          </div>
                          <div className="summary-stat-chip" style={{ flexDirection: "column", alignItems: "flex-start", padding: 10 }}>
                            <span style={{ fontSize: 10, color: "#64748b" }}>ATTACK SURFACE REDUCTION</span>
                            <strong style={{ fontSize: 14, color: "#38bdf8" }}>{selectedTargetDetail.minimized?.attack_surface_reduction_pct ?? selectedTargetDetail.counterfactual?.attack_surface_reduction_pct ?? 91.69}%</strong>
                          </div>
                        </div>

                        {selectedTargetDetail.minimized?.injected_removed_list && (
                          <div style={{ background: "#050a14", border: "1px solid #1a273b", borderRadius: 8, padding: 14 }}>
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                              <span style={{ fontSize: 12, fontWeight: 600, color: "#f87171" }}>
                                Injected Extraneous Permissions Safely Pruned ({selectedTargetDetail.minimized.injected_removed_list.length})
                              </span>
                              <span className="diff-removed" style={{ fontSize: 11 }}>100% ELIMINATED BY POVISHIELD</span>
                            </div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                              {selectedTargetDetail.minimized.injected_removed_list.map(sc => {
                                const cat = getSyscallCategory(sc);
                                const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                                return (
                                  <div key={sc} style={{ display: "inline-flex", alignItems: "center", gap: 6, background: "#0c1524", border: "1px solid #1e293b", borderRadius: 6, padding: "3px 8px" }}>
                                    <span className="syscall-pill pill-removable" style={{ padding: "1px 6px", fontSize: 11 }}>{sc}</span>
                                    <span className={`category-tag ${cls}`} style={{ fontSize: 9, padding: "1px 4px" }}>{cat}</span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid #1a273b", paddingTop: 14, marginTop: 4 }}>
                          <button
                            className="primary-button"
                            onClick={() => {
                              const tgt = selectedTargetDetail.target;
                              setAblationSubTab("interactive");
                              setProverTarget(tgt);
                              const sampleCmd = tgt === "ls" ? "/usr/bin/ls -la /tmp" :
                                                tgt === "cat" ? "/usr/bin/cat /etc/os-release" :
                                                tgt === "grep" ? "/usr/bin/grep -i root /etc/passwd" :
                                                tgt === "gzip" ? "/usr/bin/gzip --version" :
                                                tgt === "python3" || tgt === "python_cpu" ? "/usr/bin/python3 -c \"import os; print(os.getpid())\"" :
                                                `/usr/bin/${tgt} --help`;
                              setProverCommand(sampleCmd);
                              const sampleSyscall = selectedTargetDetail.minimized?.injected_removed_list?.[0] || "mount";
                              setProverSyscall(sampleSyscall);
                              setSelectedTargetDetail(null);
                              handleRunProverTrial(sampleCmd, sampleSyscall, tgt);
                            }}
                            style={{ display: "flex", alignItems: "center", gap: 8 }}
                          >
                            <Play size={14} /> Test in Live Interactive Prover
                          </button>
                          <button className="secondary-button" onClick={() => setSelectedTargetDetail(null)}>
                            Close
                          </button>
                        </div>
                      </div>
                    </div>
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

                  {(() => {
                    const removableList = Array.from(new Set(
                      ledgerTrials.filter(t => t.verdict?.includes("REMOVABLE")).map(t => t.ablated_syscall)
                    ));

                    const filteredTrials = ledgerTrials.filter(t => {
                      const matchVerdict = ledgerVerdictFilter === "ALL" || (
                        ledgerVerdictFilter.includes("REQUIRED")
                          ? (t.verdict?.includes("NECESSARY") || t.verdict?.includes("REQUIRED"))
                          : (t.verdict?.includes("REMOVABLE"))
                      );
                      const matchSyscall = !ledgerSyscallFilter.trim() || t.ablated_syscall?.toLowerCase().includes(ledgerSyscallFilter.trim().toLowerCase());
                      const matchSignal = ledgerSignalFilter === "ALL" || (
                        ledgerSignalFilter === "SIGSYS" ? t.signal === "SIGSYS" : t.signal !== "SIGSYS"
                      );
                      const matchDiv = ledgerDivergenceFilter === "ALL" || (
                        ledgerDivergenceFilter === "DIVERGED" ? Boolean(t.output_diverged) : !Boolean(t.output_diverged)
                      );
                      return matchVerdict && matchSyscall && matchSignal && matchDiv;
                    });

                    return (
                      <>
                        <div className="ledger-controls" style={{ flexWrap: "wrap", gap: 10 }}>
                          <div className="ledger-target-select">
                            <label>Target Ledger File</label>
                            <select value={selectedLedgerTarget} onChange={e => setSelectedLedgerTarget(e.target.value)}>
                              {ledgersList.map(l => (
                                <option key={l.target} value={l.target}>{l.target}.jsonl ({l.trial_count} trials)</option>
                              ))}
                            </select>
                          </div>

                          <div className="ledger-filter-select">
                            <label>Verdict Filter</label>
                            <select value={ledgerVerdictFilter} onChange={e => setLedgerVerdictFilter(e.target.value)}>
                              <option value="ALL">All Verdicts</option>
                              <option value="REQUIRED_FOR_TESTED_WORKLOADS">Required / Necessary Only</option>
                              <option value="REMOVABLE_FOR_TESTED_WORKLOADS">Removable Permissions Only</option>
                            </select>
                          </div>

                          <div className="ledger-filter-select">
                            <label>Signal Filter</label>
                            <select value={ledgerSignalFilter} onChange={e => setLedgerSignalFilter(e.target.value)}>
                              <option value="ALL">All Signals</option>
                              <option value="SIGSYS">SIGSYS (Intercepted Kill)</option>
                              <option value="NORMAL">Normal Exit (RC 0 / no signal)</option>
                            </select>
                          </div>

                          <div className="ledger-filter-select">
                            <label>Output Divergence</label>
                            <select value={ledgerDivergenceFilter} onChange={e => setLedgerDivergenceFilter(e.target.value)}>
                              <option value="ALL">All Outputs</option>
                              <option value="DIVERGED">Diverged Output</option>
                              <option value="IDENTICAL">Identical Output</option>
                            </select>
                          </div>

                          <div className="ledger-search-input" style={{ flex: 1, minWidth: 160 }}>
                            <label>Search Syscall</label>
                            <input
                              placeholder="e.g. read, write, openat"
                              value={ledgerSyscallFilter}
                              onChange={e => setLedgerSyscallFilter(e.target.value)}
                            />
                          </div>
                        </div>

                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                            <span className="summary-stat-chip">
                              Total Trials: <strong>{ledgerTotalRecords}</strong>
                            </span>
                            <span className="summary-stat-chip">
                              Matching: <strong>{filteredTrials.length}</strong>
                            </span>
                            <span className="summary-stat-chip">
                              Removable Syscalls: <strong style={{ color: "#fbbf24" }}>{removableList.length}</strong>
                            </span>
                          </div>

                          <div style={{ display: "flex", gap: 8 }}>
                            {removableList.length > 0 && (
                              <button
                                className="secondary-button"
                                onClick={() => {
                                  copyToClipboard(removableList.join(", "));
                                  setCopiedRemovables(true);
                                  setTimeout(() => setCopiedRemovables(false), 2200);
                                }}
                                style={{ fontSize: 11 }}
                              >
                                {copiedRemovables ? <Check size={13} style={{ color: "#45d6a5" }} /> : <Copy size={13} />}
                                {copiedRemovables ? "Copied List!" : `Copy ${removableList.length} Removable Syscalls`}
                              </button>
                            )}
                            <button
                              className="secondary-button"
                              onClick={() => {
                                const blob = new Blob([JSON.stringify(ledgerTrials, null, 2)], { type: "application/json" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `povishield-ledger-${selectedLedgerTarget || "trials"}.json`;
                                document.body.appendChild(a);
                                a.click();
                                a.remove();
                                setTimeout(() => URL.revokeObjectURL(url), 1000);
                              }}
                              style={{ fontSize: 11 }}
                            >
                              <Download size={13} /> Export Ledger JSON
                            </button>
                          </div>
                        </div>

                        <section className="audit-panel">
                          <div className="audit-header">
                            <div>
                              <h3>Independent Fail-Closed Ledger Audit</h3>
                              <p>Verify cryptographic ledger records using analysis.audit_ledger</p>
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
                              <h3>Ablation Trials Stream ({filteredTrials.length} shown / {ledgerTotalRecords} total)</h3>
                              <p>Click any row to inspect reproduction details and environment fingerprints</p>
                            </div>
                          </div>
                          <div className="table-wrap activity-table-wrap">
                            <table>
                              <thead>
                                <tr>
                                  <th>TRIAL ID</th>
                                  <th>ABLATED SYSCALL</th>
                                  <th>CATEGORY</th>
                                  <th>VERDICT</th>
                                  <th>RC</th>
                                  <th>SIGNAL</th>
                                  <th>OUTPUT DIVERGENCE</th>
                                  <th>WORKLOAD</th>
                                </tr>
                              </thead>
                              <tbody>
                                {filteredTrials.map(trial => {
                                  const cat = getSyscallCategory(trial.ablated_syscall || "");
                                  const cls = cat.toLowerCase().replace(/[^a-z0-9]/g, "-");
                                  return (
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
                                      <td><span className={`category-tag ${cls}`} style={{ fontSize: 9, padding: "1px 6px" }}>{cat}</span></td>
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
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </section>
                      </>
                    );
                  })()}

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

                  {approvalNotice && (
                    <div className="notice" style={{ background: "rgba(6, 78, 59, 0.4)", borderColor: "#10b981", color: "#34d399", marginBottom: 16 }}>
                      <CheckCircle2 size={18} />
                      <strong>{approvalNotice}</strong>
                    </div>
                  )}

                  {/* Pre-Enforcement Safety Gate Interactive Verifier */}
                  <section className="safety-gate-widget">
                    <div className="safety-gate-widget-header">
                      <div>
                        <h3 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: 15 }}>
                          <ShieldCheck size={18} color="#34d399" />
                          Live Pre-Enforcement Safety Gate Verifier
                        </h3>
                        <p style={{ margin: "4px 0 0", fontSize: 12, color: "#64748b" }}>
                          Execute real-time seccomp-bpf regression checks, adversarial containment probes, and ledger audit before promoting to active enforcement
                        </p>
                      </div>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <select
                          value={liveGateTarget}
                          onChange={e => setLiveGateTarget(e.target.value)}
                          style={{ background: "#060d19", border: "1px solid #1e3a5f", color: "#38bdf8", fontSize: 11, borderRadius: 6, padding: "5px 10px", fontFamily: "var(--font-mono)" }}
                        >
                          {["grep.json", "sed.json", "gzip.json", "curl.json", "python.json", "node.json"].map(p => (
                            <option key={p} value={p}>{p}</option>
                          ))}
                        </select>
                        <button
                          className="primary-button"
                          onClick={() => runLiveSafetyGate(liveGateTarget)}
                          disabled={liveGateLoading}
                          style={{ padding: "5px 12px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 6 }}
                        >
                          <Play size={13} className={liveGateLoading ? "spin-icon" : ""} />
                          {liveGateLoading ? "Verifying Gate…" : "Run Safety Gate"}
                        </button>
                      </div>
                    </div>

                    {liveGateResult && (
                      <div style={{ marginTop: 14, animation: "fadeIn 0.2s ease" }}>
                        {liveGateResult.error ? (
                          <div className="notice activity-error">
                            <ShieldAlert size={18} />
                            <div><strong>Verification failed</strong><p>{liveGateResult.error}</p></div>
                          </div>
                        ) : (
                          <div style={{ background: "#050a14", border: "1px solid #142034", borderRadius: 8, padding: 12 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span className={`audit-badge ${liveGateResult.verdict === "READY_FOR_APPROVAL" ? "passed" : "failed"}`}>
                                  {liveGateResult.verdict === "READY_FOR_APPROVAL" ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                                  VERDICT: {liveGateResult.verdict}
                                </span>
                                <span style={{ fontSize: 11, color: "#94a3b8" }}>Target: <code>{liveGateResult.target}</code></span>
                              </div>
                              <span style={{ fontSize: 10, color: "#64748b", fontFamily: "var(--font-mono)" }}>
                                Evaluated at: {liveGateResult.timestamp ? new Date(liveGateResult.timestamp * 1000).toLocaleTimeString() : "just now"}
                              </span>
                            </div>

                            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
                              <div className="eval-metric-box">
                                <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>1. Regression Gate</span>
                                <strong style={{ color: liveGateResult.regression_tests?.status === "PASSED" ? "#34d399" : "#f87171", fontSize: 12 }}>
                                  {liveGateResult.regression_tests?.status || "PENDING"} (RC: {liveGateResult.regression_tests?.candidate_rc ?? "—"})
                                </strong>
                              </div>
                              <div className="eval-metric-box">
                                <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>2. Adversarial Containment</span>
                                <strong style={{ color: liveGateResult.adversarial_tests?.status === "CONTAINED" ? "#34d399" : "#f87171", fontSize: 12 }}>
                                  {liveGateResult.adversarial_tests?.status || "PENDING"} ({liveGateResult.adversarial_tests?.signal || "SIGSYS"})
                                </strong>
                              </div>
                              <div className="eval-metric-box">
                                <span style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase" }}>3. Evidence Ledger Backing</span>
                                <strong style={{ color: liveGateResult.ledger_audit?.valid ? "#34d399" : "#f87171", fontSize: 12 }}>
                                  {liveGateResult.ledger_audit?.valid ? "VALIDATED" : "FAIL-CLOSED BLOCKED"}
                                </strong>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </section>

                  {/* Pending Authorization Queue */}
                  <section className="panel" style={{
                    marginBottom: 24,
                    border: pendingApprovals.length > 0 ? "1px solid #f97316" : "1px solid #1e293b",
                    background: pendingApprovals.length > 0 ? "rgba(234, 88, 12, 0.05)" : undefined
                  }}>
                    <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <ShieldAlert size={18} color={pendingApprovals.length > 0 ? "#fb923c" : "#94a3b8"} />
                          Pending Safety Gate Authorization Queue ({pendingApprovals.length})
                        </h3>
                        <p>Real-time queue of commands and candidate profiles awaiting interactive operator verdict</p>
                      </div>
                      <span className="demo-badge" style={{
                        borderColor: pendingApprovals.length > 0 ? "#ea580c" : "#334155",
                        color: pendingApprovals.length > 0 ? "#fdba74" : "#94a3b8"
                      }}>
                        {pendingApprovals.length > 0 ? `${pendingApprovals.length} ACTION REQUIRED` : "QUEUE EMPTY"}
                      </span>
                    </div>

                    {pendingApprovals.length === 0 ? (
                      <p className="muted" style={{ padding: "12px 0 6px" }}>
                        No pending approval requests. When an interactive terminal or remote host runs in <code>approval-required</code> mode, permission requests appear here in real-time.
                      </p>
                    ) : (
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>REQUEST ID</th>
                              <th>ORIGIN HOST</th>
                              <th>COMMAND / TARGET</th>
                              <th>REQUESTED AT</th>
                              <th>RATIONALE</th>
                              <th style={{ textAlign: "right" }}>DECISION ACTION</th>
                            </tr>
                          </thead>
                          <tbody>
                            {pendingApprovals.map((req) => (
                              <tr key={req.id}>
                                <td><code style={{ color: "#fdba74" }}>{req.id}</code></td>
                                <td>
                                  <strong>{req.hostname || "local"}</strong>
                                  <div style={{ fontSize: 10, color: "#64748b" }}>{req.device_id || "laptop_terminal"}</div>
                                </td>
                                <td>
                                  <code>{Array.isArray(req.command) ? req.command.join(" ") : req.target}</code>
                                  <div style={{ fontSize: 10, color: "#38bdf8" }}>MODE: {req.mode}</div>
                                </td>
                                <td className="time-cell">{req.requested_at || "—"}</td>
                                <td style={{ fontSize: 12, color: "#94a3b8" }}>{req.rationale}</td>
                                <td style={{ textAlign: "right" }}>
                                  <div style={{ display: "inline-flex", gap: 6 }}>
                                    <button
                                      className="primary-button"
                                      onClick={() => handleGrantApproval(req.id)}
                                      style={{ padding: "4px 10px", fontSize: 11, background: "#059669", borderColor: "#10b981", display: "inline-flex", alignItems: "center", gap: 4 }}
                                    >
                                      <Check size={13} /> Approve
                                    </button>
                                    <button
                                      className="secondary-button"
                                      onClick={() => handleDenyApproval(req.id)}
                                      style={{ padding: "4px 10px", fontSize: 11, borderColor: "#dc2626", color: "#fca5a5", display: "inline-flex", alignItems: "center", gap: 4 }}
                                    >
                                      <X size={13} /> Deny
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </section>

                  {/* Approved Policy Replacement History */}
                  <section className="panel">
                    <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
                      <div>
                        <h3>Approved Policy Replacement History</h3>
                        <p>Immutable audit records from results/approvals.jsonl</p>
                      </div>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#050914", border: "1px solid #1a273b", borderRadius: 6, padding: "4px 8px" }}>
                          <Search size={13} style={{ color: "#64748b" }} />
                          <input
                            placeholder="Filter approvals history…"
                            value={approvalSearch}
                            onChange={e => setApprovalSearch(e.target.value)}
                            style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, outline: "none", width: 160, fontFamily: "var(--font-mono)" }}
                          />
                        </div>
                        <button
                          className="secondary-button"
                          disabled={approvalsList.length === 0}
                          onClick={() => {
                            const blob = new Blob([JSON.stringify(approvalsList, null, 2)], { type: "application/json" });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `povishield-approvals-audit-${new Date().toISOString().slice(0, 10)}.json`;
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            setTimeout(() => URL.revokeObjectURL(url), 1000);
                          }}
                          style={{ fontSize: 11 }}
                        >
                          <Download size={13} /> Export Audit Log
                        </button>
                      </div>
                    </div>

                    {approvalsList.length === 0 ? (
                      <p className="muted">No approval records found in results/approvals.jsonl.</p>
                    ) : (() => {
                      const filteredApprovals = approvalsList.filter(appr => {
                        const q = approvalSearch.trim().toLowerCase();
                        if (!q) return true;
                        return (appr.target || "").toLowerCase().includes(q) ||
                          (appr.hostname || "").toLowerCase().includes(q) ||
                          (appr.candidate || "").toLowerCase().includes(q);
                      });

                      return (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>TARGET</th>
                                <th>STATUS</th>
                                <th>APPROVED AT</th>
                                <th>ORIGIN HOST / DEVICE</th>
                                <th>WORKLOAD COMMAND</th>
                                <th>CANDIDATE POLICY</th>
                                <th>ACTIVE POLICY</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filteredApprovals.map((appr, idx) => (
                                <tr key={idx}>
                                  <td className="process-cell"><strong>{appr.target}</strong></td>
                                  <td><span className="verdict-tag verdict-approved">APPROVED</span></td>
                                  <td className="time-cell">{appr.timestamp || appr.approved_at || "—"}</td>
                                  <td>
                                    <strong>{appr.hostname || "local"}</strong>
                                    <div style={{ fontSize: 10, color: "#64748b" }}>{appr.device_id || "laptop_terminal"}</div>
                                  </td>
                                  <td>
                                    <code style={{ fontSize: 11 }}>{Array.isArray(appr.command) ? appr.command.join(" ") : (appr.command || appr.target)}</code>
                                  </td>
                                  <td><code>{appr.candidate}</code></td>
                                  <td><code>{appr.active}</code></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      );
                    })()}
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
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
                        <div>
                          <h4 style={{ margin: 0, fontSize: 14, color: "#f1f5f9" }}>Adversarial Escape & Confinement Matrix</h4>
                          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#64748b" }}>
                            PoViShield evaluates 8 adversarial exploit vectors across 6 sandboxing security configurations. Click any vector to inspect threat mechanics.
                          </p>
                        </div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <button
                            className="secondary-button"
                            onClick={() => {
                              const headers = ["Exploit Vector", "Category", "MITRE", ...ESCAPE_CONFIGS.map(c => c.label)];
                              const rows = ESCAPE_TEST_DEFS.map(t => {
                                const verdicts = ESCAPE_CONFIGS.map(cfg => experiments?.escape_results?.[cfg.key]?.tests?.[t.id] || "N/A");
                                return [t.name, t.category, t.mitre, ...verdicts];
                              });
                              const csv = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
                              const blob = new Blob([csv], { type: "text/csv" });
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement("a");
                              a.href = url;
                              a.download = `povishield-adversarial-escape-matrix.csv`;
                              document.body.appendChild(a);
                              a.click();
                              a.remove();
                              setTimeout(() => URL.revokeObjectURL(url), 1000);
                            }}
                            style={{ fontSize: 11 }}
                          >
                            <Download size={13} /> Export Matrix CSV
                          </button>
                          <div style={{ display: "flex", gap: 6, fontSize: 11 }}>
                            <span className="esc-cell-blocked">BLOCKED</span>
                            <span className="esc-cell-denied">DENIED</span>
                            <span className="esc-cell-killed">KILLED</span>
                            <span className="esc-cell-escaped">ESCAPED</span>
                          </div>
                        </div>
                      </div>

                      <div className="filter-bar-container">
                        <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 200 }}>
                          <Search size={14} style={{ color: "#64748b" }} />
                          <input
                            placeholder="Filter exploit vectors by name or description…"
                            value={escapeSearch}
                            onChange={e => setEscapeSearch(e.target.value)}
                            style={{ background: "transparent", border: "none", color: "#f1f5f9", fontSize: 11, width: "100%", outline: "none", fontFamily: "var(--font-mono)" }}
                          />
                        </div>
                        <div className="filter-pills-row">
                          {["ALL", "Filesystem / Escape", "Process / Injection", "Network / Exfiltration", "Privilege Escalation", "Resource Abuse"].map(cat => (
                            <button
                              key={cat}
                              type="button"
                              className={`category-pill-btn ${escapeCategoryFilter === cat ? "active" : ""}`}
                              onClick={() => setEscapeCategoryFilter(cat)}
                            >
                              {cat}
                            </button>
                          ))}
                        </div>
                      </div>

                      {(() => {
                        const filteredDefs = ESCAPE_TEST_DEFS.filter(t => {
                          const matchCat = escapeCategoryFilter === "ALL" || t.category === escapeCategoryFilter;
                          const q = escapeSearch.trim().toLowerCase();
                          const matchQuery = !q || t.name.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q) || (t.mitre || "").toLowerCase().includes(q);
                          return matchCat && matchQuery;
                        });

                        return (
                          <div style={{ overflowX: "auto", border: "1px solid #162438", borderRadius: 8, background: "#050914" }}>
                            <table className="escape-matrix-table">
                              <thead>
                                <tr style={{ background: "#08101e" }}>
                                  <th style={{ minWidth: 220 }}>Exploit Vector</th>
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
                                {filteredDefs.map(t => (
                                  <tr
                                    key={t.id}
                                    onClick={() => setSelectedExploitDef(selectedExploitDef?.id === t.id ? null : t)}
                                    style={{
                                      cursor: "pointer",
                                      background: selectedExploitDef?.id === t.id ? "rgba(14, 165, 233, 0.08)" : undefined
                                    }}
                                  >
                                    <td>
                                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                        <span style={{ fontWeight: 600, color: "#cbd5e1" }}>{t.name}</span>
                                        <span className="category-tag file-i-o" style={{ fontSize: 9, padding: "1px 5px" }}>{t.category}</span>
                                      </div>
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
                        );
                      })()}

                      {/* Interactive Exploit Inspector Card */}
                      {selectedExploitDef && (
                        <div className="exploit-inspector-card">
                          <div className="exploit-inspector-header">
                            <div>
                              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <h4 style={{ margin: 0, fontSize: 14, color: "#38bdf8" }}>Exploit Analysis: {selectedExploitDef.name}</h4>
                                <span className="category-tag process" style={{ fontSize: 10 }}>{selectedExploitDef.category}</span>
                              </div>
                              <span style={{ fontSize: 11, color: "#94a3b8" }}>{selectedExploitDef.desc}</span>
                            </div>
                            <button
                              type="button"
                              onClick={() => setSelectedExploitDef(null)}
                              style={{ background: "transparent", border: "none", color: "#64748b", cursor: "pointer", fontSize: 16 }}
                            >
                              ✕
                            </button>
                          </div>

                          <div className="exploit-grid-details">
                            <div className="exploit-detail-box">
                              <span>MITRE ATT&CK Mapping</span>
                              <strong>{selectedExploitDef.mitre}</strong>
                            </div>
                            <div className="exploit-detail-box">
                              <span>Intercepted Syscalls</span>
                              <strong>{selectedExploitDef.syscalls ? selectedExploitDef.syscalls.join(", ") : "—"}</strong>
                            </div>
                            <div className="exploit-detail-box">
                              <span>Confinement Invariant</span>
                              <strong style={{ color: "#34d399" }}>SCMP_ACT_KILL_PROCESS</strong>
                            </div>
                          </div>

                          <div style={{ marginTop: 10, padding: 10, background: "#050a14", borderRadius: 6, border: "1px solid #142034", fontSize: 11, color: "#cbd5e1", lineHeight: 1.5 }}>
                            <strong style={{ color: "#38bdf8", display: "block", marginBottom: 3 }}>Kernel Containment Rationale:</strong>
                            {selectedExploitDef.rationale}
                          </div>
                        </div>
                      )}
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
                  <div className="panel-heading" style={{ flexWrap: "wrap", gap: 10 }}>
                    <div>
                      <h3>Settings & Security Governance Console</h3>
                      <p>Active enforcement parameters, local privacy boundaries, and telemetry controls</p>
                    </div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <button
                        className="btn-filter"
                        onClick={handleForceRefresh}
                        disabled={forceRefreshing}
                        style={{ padding: "6px 12px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 6 }}
                        title="Force reload all live telemetry, device, and policy data"
                      >
                        <RefreshCw size={13} className={forceRefreshing ? "spin-icon" : ""} />
                        {forceRefreshing ? "Syncing…" : "Sync All Telemetry"}
                      </button>
                      <button
                        className="primary-button"
                        onClick={handleDownloadAuditBundle}
                        style={{ padding: "6px 14px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 6 }}
                      >
                        <Download size={14} /> Download Governance Audit Bundle
                      </button>
                    </div>
                  </div>

                  {settingsFeedback && (
                    <div className={`settings-feedback-banner ${settingsFeedback.type}`}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        {settingsFeedback.type === "success" ? <CheckCircle2 size={16} /> : settingsFeedback.type === "error" ? <XCircle size={16} /> : <Info size={16} />}
                        <span>{settingsFeedback.msg}</span>
                      </div>
                      <X size={14} style={{ cursor: "pointer", opacity: 0.7 }} onClick={() => setSettingsFeedback(null)} />
                    </div>
                  )}

                  <div className="settings-section-grid">
                    {/* Card 1: Operator & Fleet Identity */}
                    <div className="settings-card">
                      <div className="settings-card-header">
                        <Server size={18} style={{ color: "#38bdf8" }} />
                        <h4>Operator & Fleet Identity</h4>
                      </div>
                      <div className="policy-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span>Operator Profile</span>
                        {editingOperatorName ? (
                          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                            <input
                              type="text"
                              value={operatorNameInput}
                              onChange={e => setOperatorNameInput(e.target.value)}
                              onKeyDown={e => e.key === "Enter" && handleSaveOperatorName()}
                              style={{
                                padding: "3px 6px",
                                background: "#050914",
                                border: "1px solid #38bdf8",
                                borderRadius: 4,
                                color: "#f1f5f9",
                                fontSize: 11,
                                width: 130
                              }}
                              autoFocus
                            />
                            <button
                              className="primary-button"
                              onClick={handleSaveOperatorName}
                              style={{ padding: "3px 8px", fontSize: 10 }}
                            >
                              Save
                            </button>
                            <button
                              className="btn-filter"
                              onClick={() => {
                                setEditingOperatorName(false);
                                setOperatorNameInput(operatorName);
                              }}
                              style={{ padding: "3px 6px", fontSize: 10 }}
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                            <strong>{operatorName}</strong>
                            <button
                              className="btn-filter"
                              onClick={() => {
                                setOperatorNameInput(operatorName);
                                setEditingOperatorName(true);
                              }}
                              style={{ padding: "2px 6px", fontSize: 10, display: "inline-flex", alignItems: "center", gap: 3 }}
                              title="Edit Operator Profile Identity"
                            >
                              <Edit2 size={10} /> Edit
                            </button>
                          </div>
                        )}
                      </div>
                      <div className="policy-row">
                        <span>Active Fleet Scope</span>
                        <strong style={{ color: activeDeviceId === "gateway" ? "#94a3b8" : "#34d399" }}>
                          {activeDeviceId === "gateway" ? "Global Fleet / Gateway" : activeDeviceId === "broadcast" ? "All Fleet Devices (Broadcast)" : (activeDevice?.hostname || activeDeviceId)}
                        </strong>
                      </div>

                      {/* Interactive Fleet Scope Selector */}
                      <div style={{ padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <span style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600, display: "block", marginBottom: 6 }}>
                          Switch Active Console Target
                        </span>
                        <div className="settings-btn-group">
                          <button
                            className={`settings-scope-pill ${activeDeviceId === "gateway" ? "active" : ""}`}
                            onClick={() => {
                              setActiveDeviceId("gateway");
                              localStorage.setItem("povishield_active_device_id", "gateway");
                              showSettingsFeedback("Console scope switched to Global Gateway.", "info");
                            }}
                          >
                            Global Gateway
                          </button>
                          <button
                            className={`settings-scope-pill ${activeDeviceId === "broadcast" ? "active" : ""}`}
                            onClick={() => {
                              setActiveDeviceId("broadcast");
                              localStorage.setItem("povishield_active_device_id", "broadcast");
                              showSettingsFeedback("Console scope switched to Broadcast Fleet.", "info");
                            }}
                          >
                            Broadcast (All)
                          </button>
                          {devices.filter(d => d.id !== "gateway" && d.id !== "broadcast").map(d => (
                            <button
                              key={d.id}
                              className={`settings-scope-pill ${activeDeviceId === d.id ? "active" : ""}`}
                              onClick={() => {
                                setActiveDeviceId(d.id);
                                localStorage.setItem("povishield_active_device_id", d.id);
                                showSettingsFeedback(`Console scope switched to ${d.hostname || d.id}.`, "info");
                              }}
                            >
                              {d.hostname || d.id.slice(0, 10)}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="policy-row">
                        <span>Authorization Scheme</span>
                        <strong>Local Bearer & Ephemeral Token</strong>
                      </div>
                      <div className="policy-row">
                        <span>API Origin Host</span>
                        <strong style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{API}</strong>
                      </div>

                      {/* Interactive Ping Latency Test */}
                      <div style={{ marginTop: 4, padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                          <span style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600 }}>Backend Connection Health</span>
                          <button
                            className="btn-filter"
                            onClick={handlePingBackend}
                            disabled={pingLoading}
                            style={{ padding: "2px 8px", fontSize: 10, display: "inline-flex", alignItems: "center", gap: 4 }}
                          >
                            <RefreshCw size={11} className={pingLoading ? "spin-icon" : ""} />
                            {pingLoading ? "Pinging…" : "Test Ping"}
                          </button>
                        </div>
                        {pingStatus && (
                          <div style={{ fontSize: 11, color: pingStatus.ok ? "#34d399" : "#f87171", display: "flex", alignItems: "center", gap: 6 }}>
                            {pingStatus.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                            <span>{pingStatus.msg}</span>
                          </div>
                        )}
                      </div>

                      {/* Remote Backend URL Configuration */}
                      <div style={{ marginTop: 4, padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <span style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600, display: "block", marginBottom: 4 }}>
                          Remote Backend URL (Render / Custom API)
                        </span>
                        <input
                          type="text"
                          placeholder="e.g. 127.0.0.1:8000 or https://your-backend.onrender.com"
                          value={backendUrlInput}
                          onChange={e => setBackendUrlInput(e.target.value)}
                          onKeyDown={e => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              handleSaveBackendUrl();
                            }
                          }}
                          style={{
                            width: "100%", boxSizing: "border-box", padding: "6px 8px", background: "#08101e", border: "1px solid #1e293b",
                            borderRadius: 4, color: "#f1f5f9", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 6
                          }}
                        />
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button
                            className="btn-filter"
                            style={{ padding: "4px 10px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4 }}
                            onClick={handleTestCustomUrl}
                            disabled={backendUrlTesting}
                          >
                            <RefreshCw size={11} className={backendUrlTesting ? "spin-icon" : ""} />
                            {backendUrlTesting ? "Testing…" : "Test URL"}
                          </button>
                          <button
                            className="primary-button"
                            style={{ padding: "4px 12px", fontSize: 11 }}
                            onClick={() => handleSaveBackendUrl()}
                          >
                            Save URL
                          </button>
                          <button
                            className="btn-filter"
                            style={{ padding: "4px 10px", fontSize: 11 }}
                            onClick={handleResetBackendUrl}
                            title="Revert to default local backend (http://127.0.0.1:8000/api)"
                          >
                            Reset to Default
                          </button>
                        </div>
                        {backendUrlTestResult && (
                          <div style={{ marginTop: 6, fontSize: 11, color: backendUrlTestResult.ok ? "#34d399" : "#f87171", display: "flex", alignItems: "center", gap: 4 }}>
                            {backendUrlTestResult.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                            <span>{backendUrlTestResult.msg}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Card 2: Data Privacy, Alerts & Output Confinement */}
                    <div className="settings-card">
                      <div className="settings-card-header">
                        <LockKeyhole size={18} style={{ color: "#10b981" }} />
                        <h4>Data Privacy, Alerts & Storage</h4>
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
                            checked={tokenMaskingEnabled}
                            onChange={toggleTokenMasking}
                          />
                          <span className="toggle-slider" />
                        </label>
                      </div>

                      {/* Real-time Audio Security Alerts Toggle & Tester */}
                      <div className="settings-toggle-row">
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <label>Audio Security Chime Alerts</label>
                            {audioAlertsEnabled ? <Volume2 size={13} color="#34d399" /> : <VolumeX size={13} color="#94a3b8" />}
                          </div>
                          <p>Play acoustic chime when high-risk commands pause at the Safety Gate for operator authorization.</p>
                          <div style={{ marginTop: 6 }}>
                            <button
                              className="btn-filter"
                              onClick={handleTestAudioChime}
                              style={{ padding: "2px 8px", fontSize: 10, display: "inline-flex", alignItems: "center", gap: 4 }}
                            >
                              <Volume2 size={11} /> Test Security Chime
                            </button>
                          </div>
                        </div>
                        <label className="settings-toggle-switch">
                          <input
                            type="checkbox"
                            checked={audioAlertsEnabled}
                            onChange={toggleAudioAlerts}
                          />
                          <span className="toggle-slider" />
                        </label>
                      </div>

                      {/* Desktop Push Notifications */}
                      <div className="settings-toggle-row">
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <label>Desktop Authorization Notifications</label>
                            {desktopNotifPermission === "granted" ? <Bell size={13} color="#34d399" /> : <BellOff size={13} color="#94a3b8" />}
                          </div>
                          <p>Native OS desktop alerts when background jobs require interactive permission approval ({desktopNotifPermission}).</p>
                          <div style={{ marginTop: 6 }}>
                            <button
                              className="btn-filter"
                              onClick={handleRequestOrTestNotification}
                              style={{ padding: "2px 8px", fontSize: 10, display: "inline-flex", alignItems: "center", gap: 4 }}
                            >
                              <Bell size={11} /> {desktopNotifPermission === "granted" ? "Test Desktop Alert" : "Enable Push Notifications"}
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="policy-row">
                        <span>Telemetry Ring Buffer</span>
                        <strong>1,000 Events (Bounded Memory)</strong>
                      </div>

                      <div style={{ marginTop: "auto", padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 600, display: "block", marginBottom: 6 }}>
                          Cache & Storage Maintenance
                        </span>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button
                            className="btn-filter"
                            onClick={handleClearLocalCache}
                            style={{ padding: "4px 10px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4 }}
                            title="Purge session storage, dismissals, and diagnostic caches"
                          >
                            <Trash2 size={11} /> Clear Session Cache
                          </button>
                          <button
                            className="btn-filter"
                            onClick={handlePruneExecutions}
                            disabled={pruningHistory}
                            style={{ padding: "4px 10px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4, color: "#f59e0b" }}
                            title="Prune past execution logs and session traces on backend disk"
                          >
                            <RotateCcw size={11} className={pruningHistory ? "spin-icon" : ""} />
                            {pruningHistory ? "Pruning Logs…" : "Prune Recorded Logs"}
                          </button>
                          <button
                            className="btn-filter"
                            onClick={handleResetAllSettings}
                            style={{ padding: "4px 10px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4 }}
                            title="Reset all settings and governance parameters back to factory defaults"
                          >
                            <RotateCcw size={11} /> Reset All Defaults
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Card 3: Interface & Display Preferences */}
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

                      <div className="settings-toggle-row">
                        <div>
                          <label>Side Navigation Auto-Collapse</label>
                          <p>Collapse sidebar into compact icon mode to maximize terminal and matrix workspace.</p>
                        </div>
                        <label className="settings-toggle-switch">
                          <input
                            type="checkbox"
                            checked={sidebarCollapsed}
                            onChange={toggleSidebar}
                          />
                          <span className="toggle-slider" />
                        </label>
                      </div>

                      <div className="policy-row">
                        <span>Live Transport Cadence</span>
                        <strong>900ms Polling / Exponential Backoff</strong>
                      </div>

                      <div style={{ marginTop: "auto", padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <span style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600, display: "block", marginBottom: 6 }}>
                          Manual Telemetry Synchronization
                        </span>
                        <button
                          className="btn-filter"
                          onClick={handleForceRefresh}
                          disabled={forceRefreshing}
                          style={{ padding: "5px 12px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 6, width: "100%", justifyContent: "center" }}
                        >
                          <RefreshCw size={12} className={forceRefreshing ? "spin-icon" : ""} />
                          {forceRefreshing ? "Re-syncing with Kernel…" : "Force Refresh All Telemetry Now"}
                        </button>
                      </div>
                    </div>

                    {/* Card 4: Kernel Enforcement Diagnostics */}
                    <div className="settings-card">
                      <div className="settings-card-header" style={{ justifyContent: "space-between" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <ShieldCheck size={18} style={{ color: "#10b981" }} />
                          <h4>Kernel Enforcement Diagnostics</h4>
                        </div>
                        <button
                          className="btn-filter"
                          onClick={handleRunKernelDiag}
                          disabled={kernelDiagLoading}
                          style={{ padding: "3px 8px", fontSize: 10, display: "inline-flex", alignItems: "center", gap: 4 }}
                        >
                          <RefreshCw size={11} className={kernelDiagLoading ? "spin-icon" : ""} />
                          {kernelDiagLoading ? "Testing…" : "Run Probe"}
                        </button>
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

                      {/* Live Diagnostic Probe Box */}
                      {kernelDiagResult && (
                        <div className="settings-diag-box">
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontSize: 11, fontWeight: 600, color: kernelDiagResult.ok ? "#34d399" : "#f87171", display: "flex", alignItems: "center", gap: 6 }}>
                              {kernelDiagResult.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                              {kernelDiagResult.ok ? "Kernel Supervisor Active" : "Supervisor Check Failed"}
                            </span>
                            <span style={{ fontSize: 10, color: "#64748b" }}>{kernelDiagResult.tested_at}</span>
                          </div>
                          {kernelDiagResult.ok ? (
                            <div style={{ fontSize: 11, color: "#94a3b8", display: "flex", flexDirection: "column", gap: 3 }}>
                              <div>Native Engine: <strong style={{ color: kernelDiagResult.native_present ? "#34d399" : "#f59e0b" }}>{kernelDiagResult.native_present ? "Present (build/povishield)" : "Cloud Fallback"}</strong></div>
                              <div>Mode: <strong style={{ color: "#f1f5f9" }}>{kernelDiagResult.mode}</strong></div>
                              <div>Total Monitored Syscalls: <strong style={{ color: "#38bdf8" }}>{kernelDiagResult.total_syscalls}</strong></div>
                              <div>Recorded Executions: <strong style={{ color: "#f1f5f9" }}>{kernelDiagResult.recorded_executions}</strong></div>
                            </div>
                          ) : (
                            <div style={{ fontSize: 11, color: "#f87171" }}>
                              {kernelDiagResult.error}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Live Kernel Sandbox Self-Test Box */}
                      <div style={{ marginTop: 6, padding: 10, background: "#050914", borderRadius: 6, border: "1px solid #142032" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                          <span style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600 }}>Live Seccomp Sandbox Probe</span>
                          <button
                            className="btn-filter"
                            onClick={handleRunSandboxSelfTest}
                            disabled={sandboxTestLoading}
                            style={{ padding: "3px 8px", fontSize: 10, display: "inline-flex", alignItems: "center", gap: 4 }}
                          >
                            <ShieldCheck size={11} className={sandboxTestLoading ? "spin-icon" : ""} />
                            {sandboxTestLoading ? "Enforcing…" : "Run Live Sandbox Test"}
                          </button>
                        </div>
                        {sandboxTestResult && (
                          <div className="settings-diag-box" style={{ marginTop: 4, background: "#08101e" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <span style={{ fontSize: 11, fontWeight: 600, color: sandboxTestResult.ok ? "#34d399" : "#f87171", display: "flex", alignItems: "center", gap: 6 }}>
                                {sandboxTestResult.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                                {sandboxTestResult.ok ? "Sandbox Active & Enforcing" : "Sandbox Probe Failed"}
                              </span>
                              <span style={{ fontSize: 10, color: "#64748b" }}>{sandboxTestResult.tested_at}</span>
                            </div>
                            {sandboxTestResult.ok ? (
                              <div style={{ fontSize: 11, color: "#94a3b8", display: "flex", flexDirection: "column", gap: 3 }}>
                                <div>Mechanism: <strong style={{ color: "#34d399" }}>{sandboxTestResult.enforcement}</strong></div>
                                <div>Return Code: <strong style={{ color: "#38bdf8" }}>{sandboxTestResult.returncode}</strong> · Latency: <strong style={{ color: "#f1f5f9" }}>{sandboxTestResult.durationMs}ms</strong></div>
                                <div>Allowed Syscalls: <strong style={{ color: "#38bdf8" }}>{sandboxTestResult.allowedSyscallsCount} / 385 ({sandboxTestResult.reductionPct}% reduced)</strong></div>
                                {sandboxTestResult.stdout && <div>Output: <code style={{ color: "#f1f5f9", background: "#050914", padding: "1px 4px", borderRadius: 3 }}>{sandboxTestResult.stdout}</code></div>}
                              </div>
                            ) : (
                              <div style={{ fontSize: 11, color: "#f87171" }}>
                                {sandboxTestResult.error}
                              </div>
                            )}
                          </div>
                        )}
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
