import React, { useState, useEffect, useRef } from "react";
import {
  Server, ShieldCheck, ShieldAlert, Terminal, Plus, RefreshCw,
  Copy, Check, Trash2, Lock, AlertTriangle, Cpu, Activity,
  Clock, CheckCircle2, XCircle, ArrowRight, X, ExternalLink
} from "lucide-react";

export default function FleetDeviceConsole({ API }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedDevice, setSelectedDevice] = useState(null);

  // Pairing Wizard Modal State
  const [showPairModal, setShowPairModal] = useState(false);
  const [wizardStep, setWizardStep] = useState(1); // 1: Privacy & Perms, 2: Code & Install
  const [pairingName, setPairingName] = useState("");
  const [pairingData, setPairingData] = useState(null);
  const [generatingCode, setGeneratingCode] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [waitingForPair, setWaitingForPair] = useState(false);

  // Remote Execution State
  const [commandInput, setCommandInput] = useState("/usr/bin/echo 'Fleet Policy Execution'");
  const [execMode, setExecMode] = useState("enforce");
  const [dispatchingTask, setDispatchingTask] = useState(false);
  const [activeTaskResult, setActiveTaskResult] = useState(null);
  const [deviceTasks, setDeviceTasks] = useState([]);
  const [deviceEvents, setDeviceEvents] = useState([]);
  const [detailsLoading, setDetailsLoading] = useState(false);

  const fetchDevices = async () => {
    try {
      const res = await fetch(`${API}/devices`);
      if (res.ok) {
        const data = await res.json();
        setDevices(data.devices || []);
        if (data.devices?.length && !selectedDevice) {
          setSelectedDevice(data.devices[0]);
        } else if (selectedDevice) {
          const updated = data.devices.find(d => d.id === selectedDevice.id);
          if (updated) setSelectedDevice(updated);
        }
      }
    } catch (err) {
      setError(err.message || "Failed to load device fleet");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 4000);
    return () => clearInterval(interval);
  }, []);

  const loadDeviceDetails = async (devId) => {
    if (!devId) return;
    setDetailsLoading(true);
    try {
      const res = await fetch(`${API}/devices/${devId}`);
      if (res.ok) {
        const data = await res.json();
        setDeviceTasks(data.tasks || []);
        setDeviceEvents(data.events || []);
      }
    } catch (err) {
      console.warn("Could not load device details:", err);
    } finally {
      setDetailsLoading(false);
    }
  };

  useEffect(() => {
    if (selectedDevice?.id) {
      loadDeviceDetails(selectedDevice.id);
    }
  }, [selectedDevice?.id]);

  // Generate Pairing Code
  const handleGeneratePairing = async () => {
    setGeneratingCode(true);
    setError("");
    try {
      const res = await fetch(`${API}/pairing/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_name_hint: pairingName || undefined })
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setPairingData(data);
      setWizardStep(2);
      setWaitingForPair(true);
    } catch (err) {
      setError(err.message || "Could not generate pairing code");
    } finally {
      setGeneratingCode(false);
    }
  };

  // Poll while in wizard step 2 to detect when newly paired device connects
  useEffect(() => {
    if (!waitingForPair || !pairingData) return;
    const timer = setInterval(async () => {
      try {
        const res = await fetch(`${API}/devices`);
        if (res.ok) {
          const data = await res.json();
          const devList = data.devices || [];
          if (devList.length > devices.length) {
            setDevices(devList);
            setSelectedDevice(devList[0]);
            setWaitingForPair(false);
            setShowPairModal(false);
            setWizardStep(1);
          }
        }
      } catch {}
    }, 2000);
    return () => clearInterval(timer);
  }, [waitingForPair, pairingData, devices.length]);

  // Dispatch Remote Task
  const handleDispatchTask = async () => {
    if (!selectedDevice || selectedDevice.status === "revoked") return;
    const tokens = commandInput.trim().match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    const args = tokens.map(t => (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t);
    if (!args.length) return;

    setDispatchingTask(true);
    setActiveTaskResult(null);
    try {
      const res = await fetch(`${API}/devices/${selectedDevice.id}/tasks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: args, mode: execMode })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Dispatch failed (${res.status})`);

      // Poll task result
      const taskId = data.id;
      let polls = 0;
      const pollTask = setInterval(async () => {
        polls++;
        try {
          const tr = await fetch(`${API}/devices/${selectedDevice.id}/tasks/${taskId}`);
          if (tr.ok) {
            const tData = await tr.json();
            if (tData.status === "completed" || tData.status === "failed") {
              clearInterval(pollTask);
              setActiveTaskResult(tData.result);
              loadDeviceDetails(selectedDevice.id);
              setDispatchingTask(false);
            }
          }
        } catch {}
        if (polls > 15) {
          clearInterval(pollTask);
          setDispatchingTask(false);
        }
      }, 1000);
    } catch (err) {
      setError(err.message || "Failed to dispatch task");
      setDispatchingTask(false);
    }
  };

  // Revoke Device
  const handleRevokeDevice = async (devId) => {
    if (!window.confirm("Are you sure you want to revoke this device? The agent credentials will be permanently invalidated and all sessions halted.")) return;
    try {
      const res = await fetch(`${API}/devices/${devId}/revoke`, { method: "POST" });
      if (res.ok) {
        fetchDevices();
        if (selectedDevice?.id === devId) {
          setSelectedDevice(prev => ({ ...prev, status: "revoked" }));
        }
      }
    } catch (err) {
      setError(err.message || "Failed to revoke device");
    }
  };

  const copyText = (txt) => {
    navigator.clipboard.writeText(txt);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const onlineDevicesCount = devices.filter(d => d.is_live).length;
  const verifiedEnforceCount = devices.filter(d => d.capabilities?.enforcement_verified).length;

  return (
    <div className="fleet-view">
      {/* Top Fleet Summary Metrics */}
      <div className="metrics-grid" style={{ marginBottom: 20 }}>
        <div className="metric-card">
          <div className="metric-top"><span>Paired Endpoints</span><Server size={19} /></div>
          <div className="metric-value">{devices.length}</div>
          <div className="metric-detail">{devices.length === 1 ? "1 connected computer" : `${devices.length} registered hosts`}</div>
        </div>
        <div className="metric-card">
          <div className="metric-top"><span>Active & Online</span><Activity size={19} /></div>
          <div className="metric-value" style={{ color: onlineDevicesCount > 0 ? "#34d399" : "#94a3b8" }}>
            {onlineDevicesCount}
          </div>
          <div className="metric-detail">Heartbeat received &lt; 25s ago</div>
        </div>
        <div className="metric-card">
          <div className="metric-top"><span>Kernel Seccomp Verified</span><ShieldCheck size={19} /></div>
          <div className="metric-value" style={{ color: "#38bdf8" }}>{verifiedEnforceCount}</div>
          <div className="metric-detail">BPF & PR_SET_NO_NEW_PRIVS verified</div>
        </div>
        <div className="metric-card">
          <div className="metric-top"><span>Security Model</span><Lock size={19} /></div>
          <div className="metric-value" style={{ fontSize: 18, color: "#a78bfa" }}>OUTBOUND PULL</div>
          <div className="metric-detail">Zero open listening ports on agent</div>
        </div>
      </div>

      {error && (
        <div className="notice" style={{ marginBottom: 16 }}>
          <ShieldAlert size={19} />
          <div><strong>Fleet Console Alert</strong><p>{error}</p></div>
        </div>
      )}

      {/* Main Layout: Device List + Device Detail Drawer */}
      <div className="fleet-layout" style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: 20 }}>

        {/* Left Column: Device List & Pairing Wizard CTA */}
        <div className="panel fleet-list-panel">
          <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h3>Connected Fleet</h3>
              <p>Linux endpoints reporting telemetry</p>
            </div>
            <button
              className="primary-button"
              onClick={() => { setWizardStep(1); setShowPairModal(true); }}
              style={{ padding: "6px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
            >
              <Plus size={14} /> Pair Device
            </button>
          </div>

          <div className="device-cards-container" style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 12 }}>
            {devices.length === 0 ? (
              <div style={{ textAlign: "center", padding: "32px 16px", color: "#64748b" }}>
                <Server size={32} style={{ margin: "0 auto 12px", opacity: 0.4 }} />
                <p style={{ fontWeight: 600, color: "#94a3b8" }}>No devices paired yet</p>
                <p style={{ fontSize: 12, marginTop: 4 }}>Pair any Linux computer or virtual machine to inspect kernel telemetry and policy enforcement.</p>
                <button
                  className="secondary-button"
                  onClick={() => { setWizardStep(1); setShowPairModal(true); }}
                  style={{ marginTop: 16, marginInline: "auto" }}
                >
                  <Plus size={14} /> Launch Pairing Wizard
                </button>
              </div>
            ) : (
              devices.map(dev => {
                const isSelected = selectedDevice?.id === dev.id;
                const isOnline = dev.is_live;
                const isRevoked = dev.status === "revoked";

                return (
                  <div
                    key={dev.id}
                    onClick={() => setSelectedDevice(dev)}
                    className={`device-card ${isSelected ? "selected" : ""}`}
                    style={{
                      padding: "14px 16px",
                      borderRadius: 8,
                      border: isSelected ? "1px solid #10b981" : "1px solid #1e293b",
                      background: isSelected ? "#0a1f18" : "#0a0f1d",
                      cursor: "pointer",
                      transition: "all 0.2s ease"
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <strong style={{ fontSize: 14, color: isSelected ? "#34d399" : "#f1f5f9" }}>
                        {dev.name || dev.hostname}
                      </strong>
                      <span className={`status-pill ${isRevoked ? "revoked" : isOnline ? "online" : "offline"}`} style={{
                        fontSize: 10,
                        padding: "2px 8px",
                        borderRadius: 999,
                        fontFamily: "var(--font-mono)",
                        fontWeight: 700,
                        background: isRevoked ? "#381014" : isOnline ? "#064e3b" : "#1e293b",
                        color: isRevoked ? "#f87171" : isOnline ? "#34d399" : "#94a3b8",
                        border: isRevoked ? "1px solid #7f1d1d" : isOnline ? "1px solid #059669" : "1px solid #334155"
                      }}>
                        {isRevoked ? "REVOKED" : isOnline ? "ONLINE" : "OFFLINE"}
                      </span>
                    </div>

                    <div style={{ fontSize: 11, color: "#64748b", fontFamily: "var(--font-mono)", display: "flex", flexDirection: "column", gap: 3 }}>
                      <span>HOST: {dev.hostname} ({dev.arch})</span>
                      <span>KERNEL: {dev.kernel_version?.slice(0, 22)}</span>
                    </div>

                    <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
                      {dev.capabilities?.enforcement_verified && (
                        <span style={{ fontSize: 9, background: "#064e3b", color: "#34d399", padding: "1px 5px", borderRadius: 4, fontFamily: "var(--font-mono)" }}>
                          SECCOMP BPF
                        </span>
                      )}
                      {dev.capabilities?.cgroups_v2 && (
                        <span style={{ fontSize: 9, background: "#0c2d48", color: "#38bdf8", padding: "1px 5px", borderRadius: 4, fontFamily: "var(--font-mono)" }}>
                          CGROUPS V2
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Detailed Device Console & Remote Supervisor */}
        {selectedDevice ? (
          <div className="panel fleet-detail-panel">
            <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <h2>{selectedDevice.name}</h2>
                  <span style={{
                    fontSize: 11,
                    fontFamily: "var(--font-mono)",
                    color: selectedDevice.status === "revoked" ? "#f87171" : selectedDevice.is_live ? "#34d399" : "#94a3b8",
                    display: "flex",
                    alignItems: "center",
                    gap: 5
                  }}>
                    <span style={{
                      width: 7, height: 7, borderRadius: "50%",
                      background: selectedDevice.status === "revoked" ? "#ef4444" : selectedDevice.is_live ? "#10b981" : "#64748b"
                    }} />
                    {selectedDevice.status === "revoked" ? "AUTHORIZATION REVOKED" : selectedDevice.is_live ? "LIVE HEARTBEAT ACTIVE" : "OFFLINE / DISCONNECTED"}
                  </span>
                </div>
                <p style={{ marginTop: 4 }}>ID: <code>{selectedDevice.id}</code> · Host: <code>{selectedDevice.hostname}</code> · OS: {selectedDevice.os_info}</p>
              </div>

              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="secondary-button"
                  onClick={() => loadDeviceDetails(selectedDevice.id)}
                  title="Refresh device telemetry"
                >
                  <RefreshCw size={14} /> Refresh
                </button>
                {selectedDevice.status !== "revoked" && (
                  <button
                    className="secondary-button"
                    onClick={() => handleRevokeDevice(selectedDevice.id)}
                    style={{ color: "#f87171", borderColor: "#7f1d1d" }}
                  >
                    <Trash2 size={14} /> Revoke Authorization
                  </button>
                )}
              </div>
            </div>

            {/* Capability Diagnostics Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, margin: "16px 0 24px" }}>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Kernel Seccomp-BPF</span>
                <strong style={{ color: selectedDevice.capabilities?.seccomp_bpf ? "#34d399" : "#f87171", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                  {selectedDevice.capabilities?.seccomp_bpf ? "ACTIVE" : "UNAVAILABLE"}
                </strong>
              </div>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>PR_SET_NO_NEW_PRIVS</span>
                <strong style={{ color: selectedDevice.capabilities?.no_new_privs ? "#34d399" : "#f87171", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                  {selectedDevice.capabilities?.no_new_privs ? "SUPPORTED" : "UNSUPPORTED"}
                </strong>
              </div>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Cgroups v2 Resource Cap</span>
                <strong style={{ color: selectedDevice.capabilities?.cgroups_v2 ? "#38bdf8" : "#94a3b8", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                  {selectedDevice.capabilities?.cgroups_v2 ? "MOUNTED" : "ABSENT"}
                </strong>
              </div>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Native Tracer Binary</span>
                <strong style={{ color: selectedDevice.capabilities?.native_sandbox ? "#34d399" : "#94a3b8", fontSize: 13, fontFamily: "var(--font-mono)" }}>
                  {selectedDevice.capabilities?.native_sandbox ? "VERIFIED" : "NOT BUILT"}
                </strong>
              </div>
            </div>

            {/* Remote Command Execution Console */}
            <div style={{ borderTop: "1px solid #1e293b", paddingTop: 18 }}>
              <h3 style={{ fontSize: 15, marginBottom: 4 }}>Remote Policy-Gated Execution</h3>
              <p style={{ fontSize: 12, color: "#64748b", marginBottom: 12 }}>
                Dispatch commands to execute under kernel seccomp confinement on this specific computer.
              </p>

              {/* Preset Chips */}
              <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
                <button
                  className="quick-chip"
                  onClick={() => { setCommandInput("/usr/bin/echo 'Remote Echo Passed'"); setExecMode("enforce"); }}
                >
                  Echo (Permitted)
                </button>
                <button
                  className="quick-chip"
                  onClick={() => { setCommandInput("/usr/bin/cat /dev/null"); setExecMode("enforce"); }}
                >
                  Cat /dev/null (Permitted)
                </button>
                <button
                  className="quick-chip"
                  onClick={() => { setCommandInput("/usr/bin/uname -a"); setExecMode("enforce"); }}
                >
                  Uname (Trigger Kernel SIGSYS Kill)
                </button>
              </div>

              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <div style={{ flex: 1, position: "relative" }}>
                  <input
                    type="text"
                    value={commandInput}
                    onChange={(e) => setCommandInput(e.target.value)}
                    placeholder="Enter command vector e.g. /usr/bin/echo test"
                    style={{
                      width: "100%",
                      padding: "10px 14px",
                      background: "#050914",
                      border: "1px solid #1e293b",
                      borderRadius: 6,
                      color: "#f1f5f9",
                      fontFamily: "var(--font-mono)",
                      fontSize: 13
                    }}
                  />
                </div>
                <select
                  value={execMode}
                  onChange={(e) => setExecMode(e.target.value)}
                  style={{
                    padding: "10px 12px",
                    background: "#091220",
                    border: "1px solid #1e293b",
                    borderRadius: 6,
                    color: "#38bdf8",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12
                  }}
                >
                  <option value="enforce">MODE: ENFORCE (SECCOMP BPF)</option>
                  <option value="inspect">MODE: INSPECT (PTRACE AUDIT)</option>
                  <option value="approval-required">MODE: APPROVAL-REQUIRED</option>
                </select>
                <button
                  className="primary-button"
                  onClick={handleDispatchTask}
                  disabled={dispatchingTask || selectedDevice.status === "revoked"}
                  style={{ minWidth: 140, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
                >
                  {dispatchingTask ? <RefreshCw size={14} className="spin" /> : <Terminal size={14} />}
                  {dispatchingTask ? "Executing..." : "Dispatch Task"}
                </button>
              </div>

              {/* Task Result Viewport */}
              {activeTaskResult && (
                <div className="terminal-viewport" style={{ marginTop: 16 }}>
                  <div className="terminal-top-bar">
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>REMOTE_EXECUTION_RESULT // {selectedDevice.hostname}</span>
                    <span style={{
                      color: activeTaskResult.exit_code === 0 ? "#34d399" : "#f87171",
                      fontFamily: "var(--font-mono)", fontSize: 11
                    }}>
                      EXIT CODE: {activeTaskResult.exit_code} ({activeTaskResult.status?.toUpperCase()})
                    </span>
                  </div>
                  <div className="terminal-screen" style={{ maxHeight: 220, overflowY: "auto" }}>
                    <div className="terminal-line init">
                      [TARGET] Command: {commandInput} | Host: {selectedDevice.hostname}
                    </div>
                    {activeTaskResult.stdout && (
                      <pre className="terminal-line stdout" style={{ margin: "4px 0", whiteSpace: "pre-wrap" }}>
                        {activeTaskResult.stdout}
                      </pre>
                    )}
                    {activeTaskResult.stderr && (
                      <pre className="terminal-line stderr" style={{ margin: "4px 0", whiteSpace: "pre-wrap" }}>
                        {activeTaskResult.stderr}
                      </pre>
                    )}
                    {activeTaskResult.status === "killed_by_seccomp" && (
                      <div className="terminal-line violation">
                        [ALERT: KERNEL SIGSYS TERMINATION] Unauthorized system call outside policy blocked. Kernel immediately terminated process with SIGSYS (returncode {activeTaskResult.exit_code}).
                      </div>
                    )}
                    <div className="terminal-line success">
                      [RESULT] Status: {activeTaskResult.status} | Duration: {activeTaskResult.duration_ms}ms
                    </div>
                  </div>
                </div>
              )}

              {/* Recent Tasks List */}
              <div style={{ marginTop: 24 }}>
                <h4 style={{ fontSize: 13, color: "#94a3b8", marginBottom: 8 }}>Recent Endpoint Tasks</h4>
                {deviceTasks.length === 0 ? (
                  <p style={{ fontSize: 12, color: "#64748b" }}>No execution tasks recorded on this host yet.</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {deviceTasks.slice(0, 5).map(t => (
                      <div key={t.id} style={{
                        padding: "8px 12px",
                        background: "#070c18",
                        border: "1px solid #162032",
                        borderRadius: 6,
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        fontSize: 11,
                        fontFamily: "var(--font-mono)"
                      }}>
                        <span>{t.command?.join(" ")}</span>
                        <span style={{ color: t.result?.exit_code === 0 ? "#34d399" : t.status === "completed" ? "#f87171" : "#38bdf8" }}>
                          {t.status.toUpperCase()} (EXIT: {t.result?.exit_code ?? "-"})
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="panel" style={{ display: "grid", placeItems: "center", padding: 60, color: "#64748b" }}>
            <Server size={40} style={{ opacity: 0.3, marginBottom: 12 }} />
            <p>Select a paired device on the left to inspect telemetry, review capabilities, and dispatch policy-gated tasks.</p>
          </div>
        )}
      </div>

      {/* --- DEVICE PAIRING WIZARD MODAL --- */}
      {showPairModal && (
        <div className="modal-backdrop" style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)",
          backdropFilter: "blur(6px)", zIndex: 9999, display: "grid", placeItems: "center", padding: 20
        }}>
          <div className="modal-card" style={{
            background: "#090d16", border: "1px solid #1e293b", borderRadius: 12,
            maxWidth: 640, width: "100%", padding: 28, boxShadow: "0 20px 40px rgba(0,0,0,0.6)"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Server size={20} style={{ color: "#10b981" }} />
                <h3 style={{ fontSize: 18, color: "#f1f5f9" }}>Pair New Linux Security Endpoint</h3>
              </div>
              <button
                className="icon-button"
                onClick={() => { setShowPairModal(false); setWaitingForPair(false); }}
              >
                <X size={18} />
              </button>
            </div>

            {wizardStep === 1 && (
              <div>
                <p style={{ fontSize: 13, color: "#94a3b8", lineHeight: 1.5, marginBottom: 16 }}>
                  Connect any Linux workstation, server, or VM to the central PoViShield console. Before pairing, review the data collection and permission boundaries:
                </p>

                <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 20 }}>
                  <div style={{ padding: "10px 14px", background: "#050914", borderRadius: 8, border: "1px solid #1e293b" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#34d399", fontWeight: 600, fontSize: 12 }}>
                      <CheckCircle2 size={14} /> Telemetry & System-Call Events
                    </div>
                    <p style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
                      Shares observed system calls, exit codes, and process durations with the dashboard for security evaluation.
                    </p>
                  </div>

                  <div style={{ padding: "10px 14px", background: "#050914", borderRadius: 8, border: "1px solid #1e293b" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#38bdf8", fontWeight: 600, fontSize: 12 }}>
                      <CheckCircle2 size={14} /> Least Privilege (Unprivileged Seccomp)
                    </div>
                    <p style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
                      Root privileges are NOT required for standard seccomp enforcement. Linux <code>PR_SET_NO_NEW_PRIVS</code> allows unprivileged users to install BPF filters.
                    </p>
                  </div>

                  <div style={{ padding: "10px 14px", background: "#050914", borderRadius: 8, border: "1px solid #1e293b" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#a78bfa", fontWeight: 600, fontSize: 12 }}>
                      <Lock size={14} /> Outbound Security Tunnel
                    </div>
                    <p style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
                      The agent connects outbound to the server over HTTPS. It never opens inbound listening ports on your computer.
                    </p>
                  </div>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ fontSize: 12, color: "#94a3b8", display: "block", marginBottom: 6 }}>
                    Optional Device Nickname:
                  </label>
                  <input
                    type="text"
                    value={pairingName}
                    onChange={(e) => setPairingName(e.target.value)}
                    placeholder="e.g. Production-Ubuntu-01 or Fedora-Laptop"
                    style={{
                      width: "100%", padding: "8px 12px", background: "#050914",
                      border: "1px solid #1e293b", borderRadius: 6, color: "#f1f5f9"
                    }}
                  />
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
                  <button className="secondary-button" onClick={() => setShowPairModal(false)}>
                    Cancel
                  </button>
                  <button
                    className="primary-button"
                    onClick={handleGeneratePairing}
                    disabled={generatingCode}
                    style={{ display: "flex", alignItems: "center", gap: 6 }}
                  >
                    {generatingCode ? "Generating..." : "Generate Pairing Code"} <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            )}

            {wizardStep === 2 && pairingData && (
              <div>
                <div style={{ textAlign: "center", padding: "16px 0 20px" }}>
                  <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: 1 }}>
                    Single-Use Pairing Code (Valid for 10 minutes)
                  </span>
                  <div style={{
                    fontSize: 32, fontWeight: 800, fontFamily: "var(--font-mono)",
                    color: "#10b981", margin: "8px 0", letterSpacing: 2
                  }}>
                    {pairingData.code}
                  </div>
                </div>

                <div style={{ marginBottom: 18 }}>
                  <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 600, display: "block", marginBottom: 6 }}>
                    Option A: Run this on the target Linux terminal (One-liner install):
                  </span>
                  <div style={{
                    position: "relative", background: "#050811", border: "1px solid #1e293b",
                    borderRadius: 6, padding: "10px 42px 10px 12px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#34d399"
                  }}>
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {pairingData.install_command}
                    </pre>
                    <button
                      className="icon-button"
                      onClick={() => copyText(pairingData.install_command)}
                      style={{ position: "absolute", right: 8, top: 8 }}
                      title="Copy install command"
                    >
                      {copiedCmd ? <Check size={16} color="#34d399" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 600, display: "block", marginBottom: 6 }}>
                    Option B: If you already have the repository cloned:
                  </span>
                  <div style={{
                    position: "relative", background: "#050811", border: "1px solid #1e293b",
                    borderRadius: 6, padding: "10px 42px 10px 12px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#38bdf8"
                  }}>
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {pairingData.cli_command}
                    </pre>
                    <button
                      className="icon-button"
                      onClick={() => copyText(pairingData.cli_command)}
                      style={{ position: "absolute", right: 8, top: 8 }}
                      title="Copy CLI command"
                    >
                      {copiedCmd ? <Check size={16} color="#38bdf8" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                {waitingForPair && (
                  <div style={{
                    display: "flex", alignItems: "center", justifyContent: "center", gap: 10,
                    padding: "12px", background: "#071224", borderRadius: 8, border: "1px dashed #1e3a5f"
                  }}>
                    <RefreshCw size={16} className="spin" color="#38bdf8" />
                    <span style={{ fontSize: 12, color: "#93c5fd" }}>
                      Waiting for endpoint connection... (this window will close automatically when paired)
                    </span>
                  </div>
                )}

                <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 20 }}>
                  <button
                    className="secondary-button"
                    onClick={() => { setShowPairModal(false); setWaitingForPair(false); }}
                  >
                    Done / Close
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
