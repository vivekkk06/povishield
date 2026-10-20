import React, { useState, useEffect, useRef } from "react";
import {
  Server, ShieldCheck, ShieldAlert, Terminal, Plus, RefreshCw,
  Copy, Check, Trash2, Lock, AlertTriangle, Cpu, Activity,
  Clock, CheckCircle2, XCircle, ArrowRight, X, ExternalLink, Download,
  Radio, Play, Eye
} from "lucide-react";
import RemoteWatchGuidePanel from "./RemoteWatchGuidePanel.jsx";

function getEffectiveBackendUrl(api) {
  if (api && (api.startsWith("http://") || api.startsWith("https://"))) {
    return api.replace(/\/api$/, "").replace(/\/+$/, "");
  }
  if (typeof window !== "undefined") {
    const custom = localStorage.getItem("povishield_custom_api_url");
    if (custom && (custom.startsWith("http://") || custom.startsWith("https://"))) {
      return custom.replace(/\/api$/, "").replace(/\/+$/, "");
    }
    if (window.location.hostname && !window.location.hostname.includes("vercel")) {
      return window.location.origin.replace(/\/+$/, "");
    }
  }
  return "http://localhost:8000";
}

export default function FleetDeviceConsole({ API, activeDeviceId, setActiveDeviceId, refreshTick }) {
  const effectiveBackend = getEffectiveBackendUrl(API);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState(new Set());

  // Pairing Wizard & Download Modal State
  const [showPairModal, setShowPairModal] = useState(false);
  const [showDownloadModal, setShowDownloadModal] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [pairingName, setPairingName] = useState("");
  const [enrollmentMode, setEnrollmentMode] = useState("multi"); // "multi" or "single"
  const [enrolledDevicesThisSession, setEnrolledDevicesThisSession] = useState([]);
  const [pairingData, setPairingData] = useState(null);
  const [generatingCode, setGeneratingCode] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [waitingForPair, setWaitingForPair] = useState(false);

  // Fleet Filter & Broadcast State
  const [fleetFilter, setFleetFilter] = useState("all");
  const [broadcastRunning, setBroadcastRunning] = useState(false);
  const [broadcastResult, setBroadcastResult] = useState(null);

  // Remote Execution State
  const [commandInput, setCommandInput] = useState("/usr/bin/echo 'Fleet Policy Execution'");
  const [execMode, setExecMode] = useState("enforce");
  const [dispatchingTask, setDispatchingTask] = useState(false);
  const [dispatchedTaskId, setDispatchedTaskId] = useState(null);
  const [activeTaskResult, setActiveTaskResult] = useState(null);
  const [deviceTasks, setDeviceTasks] = useState([]);
  const [deviceEvents, setDeviceEvents] = useState([]);
  const [detailsLoading, setDetailsLoading] = useState(false);

  const fetchDevices = async () => {
    try {
      const res = await fetch(`${API}/devices`);
      if (res.ok) {
        const data = await res.json();
        const devList = data.devices || [];
        setDevices(devList);
        const activeDevs = devList.filter(d => d.status !== "revoked");

        // Maintain selection
        setSelectedDeviceIds(prevIds => {
          if (prevIds.size === 0) {
            return new Set(activeDevs.map(d => d.id));
          }
          const valid = new Set([...prevIds].filter(id => devList.some(d => d.id === id && d.status !== "revoked")));
          return valid.size > 0 ? valid : new Set(activeDevs.map(d => d.id));
        });

        if (devList.length > 0) {
          setSelectedDevice(prev => {
            if (!prev) {
              if (activeDeviceId && activeDeviceId !== "gateway" && activeDeviceId !== "broadcast") {
                const found = devList.find(d => d.id === activeDeviceId);
                if (found) return found;
              }
              return { id: "all", name: "All Fleet Devices", isAll: true };
            }
            if (prev.id === "all") {
              return prev;
            }
            const updated = devList.find(d => d.id === prev.id);
            return updated || { id: "all", name: "All Fleet Devices", isAll: true };
          });
        } else {
          setSelectedDevice(null);
          setSelectedDeviceIds(new Set());
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

  useEffect(() => {
    if (!devices.length) return;
    const activeDevs = devices.filter(d => d.status !== "revoked");
    if (activeDeviceId === "broadcast") {
      setSelectedDevice({ id: "all", name: "All Fleet Devices", isAll: true });
      setSelectedDeviceIds(new Set(activeDevs.map(d => d.id)));
    } else if (activeDeviceId && activeDeviceId !== "gateway") {
      const found = devices.find(d => d.id === activeDeviceId);
      if (found) {
        setSelectedDevice(found);
      }
    }
  }, [activeDeviceId]);

  // Master Select/Deselect All Checkboxes
  const handleToggleSelectAll = (e) => {
    if (e) e.stopPropagation();
    const activeDevs = devices.filter(d => d.status !== "revoked");
    if (selectedDeviceIds.size === activeDevs.length && selectedDeviceIds.size > 0) {
      setSelectedDeviceIds(new Set());
    } else {
      setSelectedDeviceIds(new Set(activeDevs.map(d => d.id)));
    }
  };

  // Toggle individual device checkbox
  const handleToggleDeviceCheckbox = (e, dev) => {
    e.stopPropagation();
    setSelectedDeviceIds(prev => {
      const next = new Set(prev);
      if (next.has(dev.id)) {
        next.delete(dev.id);
      } else {
        next.add(dev.id);
      }
      return next;
    });
  };

  // Click on a device card to inspect its details
  const handleInspectDevice = (dev) => {
    setSelectedDevice(dev);
    setActiveTaskResult(null);
    setDispatchedTaskId(null);
  };

  // Switch right pane to broadcast supervisor
  const handleSwitchToBroadcast = () => {
    const activeDevs = devices.filter(d => d.status !== "revoked");
    setSelectedDevice({ id: "all", name: "All Fleet Devices", isAll: true });
    if (selectedDeviceIds.size === 0) {
      setSelectedDeviceIds(new Set(activeDevs.map(d => d.id)));
    }
  };

  const loadDeviceDetails = async (devId) => {
    if (!devId || devId === "all") return;
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
    if (selectedDevice?.id && selectedDevice.id !== "all") {
      loadDeviceDetails(selectedDevice.id);
    }
  }, [selectedDevice?.id]);

  const handleRefreshFleet = async () => {
    setRefreshing(true);
    try {
      await fetchDevices();
      if (selectedDevice?.id && selectedDevice.id !== "all") {
        await loadDeviceDetails(selectedDevice.id);
      }
    } finally {
      setTimeout(() => setRefreshing(false), 400);
    }
  };

  useEffect(() => {
    if (refreshTick) {
      handleRefreshFleet();
    }
  }, [refreshTick]);

  // Generate Pairing Code
  const handleGeneratePairing = async () => {
    setGeneratingCode(true);
    setError("");
    setEnrolledDevicesThisSession([]);
    try {
      const res = await fetch(`${API}/pairing/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_name_hint: pairingName || undefined,
          max_uses: enrollmentMode === "multi" ? 0 : 1
        })
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

  // Poll pairing code endpoint to live-detect all newly paired endpoints
  useEffect(() => {
    if (!waitingForPair || !pairingData) return;
    const timer = setInterval(async () => {
      try {
        const res = await fetch(`${API}/pairing/${pairingData.code}/devices`);
        if (res.ok) {
          const data = await res.json();
          const enrolled = data.devices || [];
          if (enrolled.length > 0) {
            setEnrolledDevicesThisSession(enrolled);
            fetchDevices();
          }
        }
      } catch {}
    }, 2000);
    return () => clearInterval(timer);
  }, [waitingForPair, pairingData]);

  // Broadcast task to multiple / all endpoints
  const handleBroadcastTask = async (overrideCmd, overrideMode) => {
    const effectiveCmd = (typeof overrideCmd === "string" ? overrideCmd : null) || commandInput;
    const effectiveMode = (typeof overrideMode === "string" ? overrideMode : null) || execMode;
    const tokens = effectiveCmd.trim().match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    const args = tokens.map(t => (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t);
    if (!args.length) {
      setError("Please specify a command to broadcast.");
      return;
    }

    if (selectedDeviceIds.size === 0) {
      setError("Please select at least one fleet endpoint to broadcast the command.");
      return;
    }

    setBroadcastRunning(true);
    setBroadcastResult(null);
    setError("");

    try {
      const payload = {
        command: args,
        mode: effectiveMode,
        target_device_ids: Array.from(selectedDeviceIds)
      };
      const res = await fetch(`${API}/devices/broadcast`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Broadcast failed (${res.status})`);

      setBroadcastResult(data);

      let currentDispatched = data.dispatched || [];
      let polls = 0;
      const pollBroadcast = setInterval(async () => {
        polls++;
        let allDone = true;
        currentDispatched = await Promise.all(currentDispatched.map(async (item) => {
          if (item.status === "completed" || item.status === "failed") return item;
          try {
            const tr = await fetch(`${API}/devices/${item.device_id}/tasks/${item.task_id}`);
            if (tr.ok) {
              const tData = await tr.json();
              if (tData.status === "completed" || tData.status === "failed") {
                return { ...item, status: tData.status, result: tData.result };
              }
            }
          } catch {}
          allDone = false;
          return item;
        }));

        setBroadcastResult(prev => ({ ...(prev || data), dispatched: currentDispatched }));
        if (allDone || polls > 25) {
          clearInterval(pollBroadcast);
          setBroadcastRunning(false);
          fetchDevices();
        }
      }, 1000);
    } catch (err) {
      setError(err.message || "Failed to broadcast task");
      setBroadcastRunning(false);
    }
  };

  // Dispatch Remote Task to Single Device
  const handleDispatchTask = async (overrideCmd, overrideMode) => {
    if (selectedDevice?.id === "all") {
      return handleBroadcastTask(overrideCmd, overrideMode);
    }
    if (!selectedDevice || selectedDevice.status === "revoked") return;
    const effectiveCmd = (typeof overrideCmd === "string" ? overrideCmd : null) || commandInput;
    const effectiveMode = (typeof overrideMode === "string" ? overrideMode : null) || execMode;
    const tokens = effectiveCmd.trim().match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    const args = tokens.map(t => (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t);
    if (!args.length) {
      setError("Please specify a command to dispatch.");
      return;
    }

    setDispatchingTask(true);
    setActiveTaskResult(null);
    setDispatchedTaskId(null);
    setError("");

    try {
      const res = await fetch(`${API}/devices/${selectedDevice.id}/tasks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: args, mode: effectiveMode })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Dispatch failed (${res.status})`);

      const taskId = data.id;
      setDispatchedTaskId(taskId);

      // If device is offline, show queued notice
      if (!selectedDevice.is_live) {
        setActiveTaskResult({
          status: "queued",
          task_id: taskId,
          command: args,
          mode: effectiveMode,
          queued_notice: true
        });
      }

      // Poll task result
      let polls = 0;
      const pollTask = setInterval(async () => {
        polls++;
        try {
          const tr = await fetch(`${API}/devices/${selectedDevice.id}/tasks/${taskId}`);
          if (tr.ok) {
            const tData = await tr.json();
            if (tData.status === "completed" || tData.status === "failed") {
              clearInterval(pollTask);
              setActiveTaskResult({
                ...(tData.result || {}),
                status: tData.status,
                task_id: taskId,
                command: args,
                mode: effectiveMode,
                error: tData.error || tData.result?.error
              });
              loadDeviceDetails(selectedDevice.id);
              setDispatchingTask(false);
              return;
            }
          }
        } catch {}
        if (polls > 20) {
          clearInterval(pollTask);
          setDispatchingTask(false);
          loadDeviceDetails(selectedDevice.id);
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
        await fetchDevices();
        if (selectedDevice?.id === devId) {
          setSelectedDevice(prev => ({ ...prev, status: "revoked" }));
        }
      }
    } catch (err) {
      setError(err.message || "Failed to revoke device");
    }
  };

  // Delete Device
  const handleDeleteDevice = async (devId) => {
    if (!window.confirm("Are you sure you want to remove this device from the fleet? Its record will be erased.")) return;
    try {
      const res = await fetch(`${API}/devices/${devId}`, { method: "DELETE" });
      if (res.ok) {
        setSelectedDeviceIds(prev => {
          const next = new Set(prev);
          next.delete(devId);
          return next;
        });
        if (selectedDevice?.id === devId) {
          setSelectedDevice({ id: "all", name: "All Fleet Devices", isAll: true });
        }
        await fetchDevices();
      }
    } catch (err) {
      setError(err.message || "Failed to delete device");
    }
  };

  // Run Security Audit on Device
  const handleRunSecurityAudit = async () => {
    if (!selectedDevice || selectedDevice.status === "revoked") return;
    setCommandInput("/usr/bin/id");
    setExecMode("inspect");
    await handleDispatchTask("/usr/bin/id", "inspect");
  };

  const copyText = (txt) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(txt);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  const activeDevsCount = devices.filter(d => d.status !== "revoked").length;
  const onlineDevicesCount = devices.filter(d => d.is_live && d.status !== "revoked").length;
  const verifiedEnforceCount = devices.filter(d => d.capabilities?.enforcement_verified && d.status !== "revoked").length;

  const filteredDevices = devices.filter(d => {
    if (fleetFilter === "online") return d.is_live && d.status !== "revoked";
    if (fleetFilter === "seccomp") return d.capabilities?.enforcement_verified && d.status !== "revoked";
    return true;
  });

  return (
    <div className="fleet-view">
      {/* Top Fleet Summary Metrics */}
      <div className="metrics-grid" style={{ marginBottom: 20 }}>
        <div className="metric-card">
          <div className="metric-top"><span>Registered Endpoints</span><Server size={19} /></div>
          <div className="metric-value">{activeDevsCount}</div>
          <div className="metric-detail">{activeDevsCount === 1 ? "1 connected machine" : `${activeDevsCount} registered hosts`}</div>
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
          <div style={{ flex: 1 }}>
            <strong>Fleet Console Alert</strong>
            <p>{error}</p>
          </div>
          <button className="icon-button" onClick={() => setError("")}><X size={14} /></button>
        </div>
      )}

      {/* Step-by-Step Guide Panel: Run ./povishield watch on Another PC */}
      <RemoteWatchGuidePanel API={API} onDevicePaired={fetchDevices} />

      {/* Main Layout: Device List + Device Detail Drawer */}
      <div className="fleet-layout">

        {/* Left Column: Device List & Pairing Wizard CTA */}
        <div className="panel fleet-list-panel">
          <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 15 }}>Connected Fleet</h3>
              <p style={{ margin: "3px 0 0", fontSize: 11 }}>Linux endpoints reporting telemetry</p>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <button
                className="secondary-button"
                onClick={() => setShowDownloadModal(true)}
                title="Download ./povishield CLI & Agent"
                style={{ padding: "5px 9px", fontSize: 11, display: "flex", alignItems: "center", gap: 4, borderColor: "#0284c7", color: "#38bdf8" }}
              >
                <Download size={13} /> Download CLI
              </button>
              <button
                className="secondary-button"
                onClick={handleRefreshFleet}
                disabled={refreshing}
                title="Refresh connected device fleet"
                style={{ padding: "5px 9px", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
              >
                <RefreshCw size={13} className={refreshing ? "spin" : ""} />
              </button>
              <button
                className="primary-button"
                onClick={() => { setWizardStep(1); setShowPairModal(true); }}
                style={{ padding: "5px 10px", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
              >
                <Plus size={13} /> Pair Device
              </button>
            </div>
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
              <>
                {/* Filter Tabs */}
                <div style={{ display: "flex", gap: 6, marginBottom: 4 }}>
                  <button
                    type="button"
                    onClick={() => setFleetFilter("all")}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 5, cursor: "pointer",
                      background: fleetFilter === "all" ? "#1e293b" : "transparent",
                      color: fleetFilter === "all" ? "#f1f5f9" : "#64748b",
                      border: "1px solid",
                      borderColor: fleetFilter === "all" ? "#334155" : "#1e293b",
                      fontFamily: "var(--font-mono)"
                    }}
                  >
                    All ({devices.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFleetFilter("online")}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 5, cursor: "pointer",
                      background: fleetFilter === "online" ? "#064e3b" : "transparent",
                      color: fleetFilter === "online" ? "#34d399" : "#64748b",
                      border: "1px solid",
                      borderColor: fleetFilter === "online" ? "#059669" : "#1e293b",
                      fontFamily: "var(--font-mono)"
                    }}
                  >
                    Online ({onlineDevicesCount})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFleetFilter("seccomp")}
                    style={{
                      padding: "4px 8px", fontSize: 11, borderRadius: 5, cursor: "pointer",
                      background: fleetFilter === "seccomp" ? "#0c2d48" : "transparent",
                      color: fleetFilter === "seccomp" ? "#38bdf8" : "#64748b",
                      border: "1px solid",
                      borderColor: fleetFilter === "seccomp" ? "#0284c7" : "#1e293b",
                      fontFamily: "var(--font-mono)"
                    }}
                  >
                    Seccomp ({verifiedEnforceCount})
                  </button>
                </div>

                {/* ⚡ All Fleet Devices (Broadcast Supervisor) Card */}
                <div
                  onClick={handleSwitchToBroadcast}
                  className={`device-card ${selectedDevice?.id === "all" ? "selected-broadcast" : ""}`}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <input
                        type="checkbox"
                        checked={activeDevsCount > 0 && selectedDeviceIds.size === activeDevsCount}
                        onChange={handleToggleSelectAll}
                        onClick={(e) => e.stopPropagation()}
                        style={{ cursor: "pointer", accentColor: "#38bdf8" }}
                        title="Select/Deselect all endpoints for broadcast"
                      />
                      <strong style={{ fontSize: 13, color: selectedDevice?.id === "all" ? "#38bdf8" : "#f1f5f9" }}>
                        ⚡ Fleet Broadcast Supervisor
                      </strong>
                    </div>
                    <span style={{
                      fontSize: 10,
                      padding: "2px 7px",
                      borderRadius: 999,
                      fontFamily: "var(--font-mono)",
                      fontWeight: 700,
                      background: "#0c2d48",
                      color: "#38bdf8",
                      border: "1px solid #0284c7"
                    }}>
                      {selectedDeviceIds.size} / {activeDevsCount} TARGETED
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: "#94a3b8", paddingLeft: 22 }}>
                    Simultaneously dispatch tasks and stream live telemetry across targeted nodes.
                  </div>
                </div>

                {/* Section header: Individual Endpoints with Select All toggle */}
                <div style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  margin: "6px 0 2px", padding: "0 4px"
                }}>
                  <span style={{ fontSize: 10, color: "#64748b", fontFamily: "var(--font-mono)", fontWeight: 700, textTransform: "uppercase" }}>
                    INDIVIDUAL ENDPOINTS ({filteredDevices.length})
                  </span>
                  <button
                    type="button"
                    onClick={handleToggleSelectAll}
                    style={{
                      background: "none", border: "none", color: "#38bdf8",
                      fontSize: 10, fontFamily: "var(--font-mono)", cursor: "pointer", textDecoration: "underline"
                    }}
                  >
                    {selectedDeviceIds.size === activeDevsCount ? "Deselect All" : "Select All"}
                  </button>
                </div>

                {filteredDevices.map(dev => {
                  const isInspecting = selectedDevice?.id === dev.id;
                  const isChecked = selectedDeviceIds.has(dev.id);
                  const isOnline = dev.is_live;
                  const isRevoked = dev.status === "revoked";
                  const isGloballyActive = activeDeviceId === dev.id;

                  return (
                    <div
                      key={dev.id}
                      onClick={() => handleInspectDevice(dev)}
                      className={`device-card ${isInspecting ? "selected" : isChecked ? "checked-target" : ""}`}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={(e) => handleToggleDeviceCheckbox(e, dev)}
                            onClick={(e) => e.stopPropagation()}
                            style={{ cursor: "pointer", accentColor: "#10b981" }}
                            title="Toggle inclusion in multi-device broadcast pool"
                          />
                          <strong style={{ fontSize: 13, color: isInspecting ? "#34d399" : isGloballyActive ? "#38bdf8" : "#f1f5f9" }}>
                            {dev.name || dev.hostname}
                          </strong>
                          {isGloballyActive && (
                            <span style={{ fontSize: 9, background: "#0c2d48", color: "#38bdf8", padding: "1px 4px", borderRadius: 3, fontWeight: 700 }}>
                              SCOPED
                            </span>
                          )}
                        </div>
                        <span className={`status-pill ${isRevoked ? "revoked" : isOnline ? "online" : "offline"}`}>
                          {isOnline && !isRevoked && <span className="live-pulse-dot" style={{ width: 5, height: 5 }} />}
                          {isRevoked ? "REVOKED" : isOnline ? "ONLINE" : "OFFLINE"}
                        </span>
                      </div>

                      <div style={{ fontSize: 11, color: "#64748b", fontFamily: "var(--font-mono)", display: "flex", flexDirection: "column", gap: 2, paddingLeft: 22 }}>
                        <span>HOST: {dev.hostname} ({dev.arch})</span>
                        <span>KERNEL: {dev.kernel_version?.slice(0, 24) || "Linux"}</span>
                      </div>

                      <div style={{ display: "flex", gap: 6, marginTop: 8, paddingLeft: 22, flexWrap: "wrap", alignItems: "center" }}>
                        {dev.capabilities?.seccomp_bpf && (
                          <span style={{ fontSize: 9, background: "#064e3b", color: "#34d399", padding: "1px 5px", borderRadius: 4, fontFamily: "var(--font-mono)" }}>
                            SECCOMP BPF
                          </span>
                        )}
                        {dev.capabilities?.cgroups_v2 && (
                          <span style={{ fontSize: 9, background: "#0c2d48", color: "#38bdf8", padding: "1px 5px", borderRadius: 4, fontFamily: "var(--font-mono)" }}>
                            CGROUPS V2
                          </span>
                        )}
                        {dev.capabilities?.no_new_privs && (
                          <span style={{ fontSize: 9, background: "#1e1b4b", color: "#a5b4fc", padding: "1px 5px", borderRadius: 4, fontFamily: "var(--font-mono)" }}>
                            NO_NEW_PRIVS
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>

        {/* Right Column: Detailed Device Console & Remote Supervisor */}
        {selectedDevice?.id === "all" ? (
          /* Multi-Device Broadcast Supervisor Pane */
          <div className="panel fleet-detail-panel">
            <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: 18 }}>
                    ⚡ Fleet Multi-Node Supervisor
                  </h2>
                  <span style={{
                    fontSize: 11,
                    fontFamily: "var(--font-mono)",
                    color: "#38bdf8",
                    display: "flex",
                    alignItems: "center",
                    gap: 5
                  }}>
                    <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#0ea5e9" }} />
                    BROADCAST READY
                  </span>
                </div>
                <p style={{ marginTop: 4, color: "#94a3b8", fontSize: 12 }}>
                  Targeting <strong>{selectedDeviceIds.size}</strong> of {activeDevsCount} registered endpoint(s) · Simultaneous policy dispatch & real-time kernel observability
                </p>
              </div>

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  className="secondary-button"
                  onClick={handleRefreshFleet}
                  disabled={refreshing}
                  title="Refresh all fleet telemetry"
                  style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}
                >
                  <RefreshCw size={13} className={refreshing ? "spin" : ""} />
                  {refreshing ? "Refreshing..." : "Refresh"}
                </button>

                <button
                  className="secondary-button"
                  onClick={handleToggleSelectAll}
                  style={{ borderColor: "#1e3a5f", color: "#38bdf8", padding: "6px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
                >
                  <CheckCircle2 size={13} />
                  {selectedDeviceIds.size === activeDevsCount ? "Deselect All" : "Select All Nodes"}
                </button>

                {setActiveDeviceId && (
                  activeDeviceId === "broadcast" ? (
                    <span className="demo-badge" style={{ borderColor: "#0284c7", color: "#38bdf8", padding: "6px 12px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 5 }}>
                      <span className="live-pulse-dot" style={{ width: 6, height: 6, background: "#38bdf8" }} /> SCOPED: ALL NODES
                    </span>
                  ) : (
                    <button
                      className="secondary-button"
                      onClick={() => setActiveDeviceId("broadcast")}
                      title="Scope entire dashboard to broadcast mode across all fleet nodes"
                      style={{ borderColor: "#1e3a5f", color: "#38bdf8", padding: "6px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
                    >
                      <Activity size={13} /> Scope Dashboard
                    </button>
                  )
                )}

                <button
                  className="primary-button"
                  onClick={() => handleBroadcastTask("/usr/bin/uname -a", "enforce")}
                  disabled={broadcastRunning || selectedDeviceIds.size === 0}
                  style={{ padding: "6px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
                  title="Dispatch kernel probe across all selected nodes"
                >
                  <ShieldCheck size={13} /> Probe All Nodes
                </button>
              </div>
            </div>

            {/* Capability Diagnostics Grid across targeted nodes */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10, margin: "16px 0 20px" }}>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Target Nodes Selected</span>
                <strong style={{ color: selectedDeviceIds.size > 0 ? "#38bdf8" : "#f87171", fontSize: 14, fontFamily: "var(--font-mono)" }}>
                  {selectedDeviceIds.size} / {activeDevsCount}
                </strong>
              </div>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Live Heartbeats</span>
                <strong style={{ color: "#34d399", fontSize: 14, fontFamily: "var(--font-mono)" }}>
                  {devices.filter(d => selectedDeviceIds.has(d.id) && d.is_live).length} ONLINE
                </strong>
              </div>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Kernel Seccomp-BPF</span>
                <strong style={{ color: "#34d399", fontSize: 14, fontFamily: "var(--font-mono)" }}>
                  {devices.filter(d => selectedDeviceIds.has(d.id) && d.capabilities?.seccomp_bpf).length} NODES
                </strong>
              </div>
              <div className="eval-metric-box">
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Cgroups v2 Resource Cap</span>
                <strong style={{ color: "#38bdf8", fontSize: 14, fontFamily: "var(--font-mono)" }}>
                  {devices.filter(d => selectedDeviceIds.has(d.id) && d.capabilities?.cgroups_v2).length} NODES
                </strong>
              </div>
            </div>

            {/* Target Endpoints Chip Bar */}
            <div style={{ marginBottom: 20, padding: "12px 14px", background: "#050914", border: "1px solid #142034", borderRadius: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 6 }}>
                <span style={{ fontSize: 11, color: "#94a3b8", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                  ACTIVE BROADCAST TARGET POOL ({selectedDeviceIds.size} nodes):
                </span>
                <span style={{ fontSize: 10, color: "#64748b" }}>Click an endpoint to inspect individual telemetry</span>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {devices.filter(d => d.status !== "revoked").map(dev => {
                  const isChecked = selectedDeviceIds.has(dev.id);
                  return (
                    <div
                      key={dev.id}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        padding: "4px 10px",
                        borderRadius: 6,
                        background: isChecked ? "#08243b" : "#080e1a",
                        border: isChecked ? "1px solid #0284c7" : "1px solid #1e293b",
                        fontSize: 11,
                        fontFamily: "var(--font-mono)",
                        color: isChecked ? "#38bdf8" : "#64748b"
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => handleToggleDeviceCheckbox(e, dev)}
                        style={{ cursor: "pointer", accentColor: "#38bdf8" }}
                      />
                      <span
                        onClick={() => handleInspectDevice(dev)}
                        style={{ cursor: "pointer", textDecoration: "underline" }}
                        title="Click to inspect this device individually"
                      >
                        💻 {dev.name || dev.hostname}
                      </span>
                      <span style={{
                        width: 6, height: 6, borderRadius: "50%",
                        background: dev.is_live ? "#10b981" : "#64748b"
                      }} />
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Fleet-Wide Command Dispatch Section */}
            <div style={{ marginBottom: 24, padding: "16px 18px", background: "#070c1a", border: "1px solid #1e293b", borderRadius: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", display: "flex", alignItems: "center", gap: 8 }}>
                  <Terminal size={15} color="#38bdf8" /> Multi-Node Command Dispatch
                </span>
                <span style={{ fontSize: 11, color: "#64748b", fontFamily: "var(--font-mono)" }}>
                  Broadcasts to {selectedDeviceIds.size} selected nodes simultaneously
                </span>
              </div>

              {/* Quick Presets */}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                {[
                  { label: "Echo Hello", cmd: "/usr/bin/echo 'PoViShield Fleet Broadcast Active'", mode: "enforce" },
                  { label: "Probe Kernel Release", cmd: "/usr/bin/uname -a", mode: "enforce" },
                  { label: "Inspect Distro Matrix", cmd: "/usr/bin/cat /etc/os-release", mode: "enforce" },
                  { label: "Check System Uptime", cmd: "/usr/bin/uptime", mode: "enforce" },
                  { label: "SIGSYS Curl Block Test", cmd: "/usr/bin/curl -s https://example.com", mode: "enforce" },
                ].map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setCommandInput(preset.cmd);
                      setExecMode(preset.mode);
                    }}
                    style={{
                      padding: "4px 8px", fontSize: 11, background: "#0b1528",
                      border: "1px solid #1e3a5f", color: "#93c5fd", borderRadius: 4,
                      cursor: "pointer", fontFamily: "var(--font-mono)"
                    }}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              {/* Dispatch Form */}
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                <div style={{ flex: 1, minWidth: 260, display: "flex", alignItems: "center", background: "#03060f", border: "1px solid #1e293b", borderRadius: 6, padding: "0 10px" }}>
                  <span style={{ fontSize: 11, color: "#38bdf8", fontFamily: "var(--font-mono)", marginRight: 6 }}>[fleet]$</span>
                  <input
                    type="text"
                    value={commandInput}
                    onChange={(e) => setCommandInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !broadcastRunning) handleBroadcastTask(); }}
                    placeholder="/usr/bin/uname -a"
                    style={{ flex: 1, background: "transparent", border: "none", color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 12, padding: "8px 0", outline: "none" }}
                  />
                </div>

                <select
                  value={execMode}
                  onChange={(e) => setExecMode(e.target.value)}
                  style={{
                    padding: "8px 12px", background: "#050914", border: "1px solid #1e293b",
                    borderRadius: 6, color: "#f1f5f9", fontFamily: "var(--font-mono)", fontSize: 11
                  }}
                >
                  <option value="enforce">Mode: ENFORCE (Seccomp-BPF Kill)</option>
                  <option value="inspect">Mode: INSPECT (Ptrace Trace Audit)</option>
                  <option value="approval-required">Mode: APPROVAL (Safety Ledger)</option>
                </select>

                <button
                  className="primary-button"
                  onClick={() => handleBroadcastTask()}
                  disabled={broadcastRunning || selectedDeviceIds.size === 0}
                  style={{ padding: "8px 16px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
                >
                  {broadcastRunning ? <RefreshCw size={14} className="spin" /> : <Terminal size={14} />}
                  {broadcastRunning ? "Broadcasting..." : `Dispatch to ${selectedDeviceIds.size} Node(s)`}
                </button>
              </div>
            </div>

            {/* Broadcast Results Section */}
            {broadcastRunning && (
              <div style={{
                marginBottom: 24, padding: "16px 20px", background: "#081d33",
                border: "1px solid #0284c7", borderRadius: 8, display: "flex", alignItems: "center", gap: 14
              }}>
                <RefreshCw size={20} className="spin" color="#38bdf8" />
                <div>
                  <strong style={{ fontSize: 13, color: "#38bdf8" }}>Broadcasting task across active endpoints...</strong>
                  <p style={{ margin: "3px 0 0", fontSize: 11, color: "#93c5fd" }}>
                    Dispatching policy-gated seccomp workload and awaiting kernel verdict confirmation from each endpoint.
                  </p>
                </div>
              </div>
            )}

            {broadcastResult && (
              <div style={{ marginBottom: 24 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <h3 style={{ fontSize: 13, margin: 0, color: "#f1f5f9", display: "flex", alignItems: "center", gap: 8 }}>
                    <Activity size={15} color="#34d399" /> Fleet Execution Results ({broadcastResult.dispatched?.length || 0} Endpoints)
                  </h3>
                  <span style={{ fontSize: 11, color: "#64748b", fontFamily: "var(--font-mono)" }}>
                    Command: <code>{Array.isArray(broadcastResult.command) ? broadcastResult.command.join(" ") : broadcastResult.command}</code>
                  </span>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {(broadcastResult.dispatched || []).map((item, idx) => {
                    const res = item.result;
                    const isDone = item.status === "completed";
                    const isFailed = item.status === "failed";
                    const exitZero = res?.exit_code === 0;

                    return (
                      <div
                        key={idx}
                        style={{
                          background: "#050914",
                          border: isDone ? (exitZero ? "1px solid #059669" : "1px solid #b91c1c") : "1px solid #1e3a5f",
                          borderRadius: 8,
                          padding: "12px 16px"
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <strong style={{ fontSize: 13, color: "#f1f5f9" }}>
                              💻 {item.device_name || item.hostname || item.device_id}
                            </strong>
                            <span style={{ fontSize: 10, color: "#64748b", fontFamily: "var(--font-mono)" }}>
                              ({item.device_id})
                            </span>
                          </div>

                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            {res?.syscalls && res.syscalls.length > 0 && (
                              <span style={{ fontSize: 10, background: "#0c2d48", color: "#38bdf8", padding: "2px 6px", borderRadius: 4, fontFamily: "var(--font-mono)" }}>
                                {res.syscalls.length} syscalls observed
                              </span>
                            )}
                            <span style={{
                              fontSize: 10,
                              padding: "2px 8px",
                              borderRadius: 999,
                              fontFamily: "var(--font-mono)",
                              fontWeight: 700,
                              background: isDone ? (exitZero ? "#064e3b" : "#381014") : "#0c2d48",
                              color: isDone ? (exitZero ? "#34d399" : "#f87171") : "#38bdf8",
                              border: isDone ? (exitZero ? "1px solid #059669" : "1px solid #7f1d1d") : "1px solid #0284c7"
                            }}>
                              {item.status.toUpperCase()} {res?.exit_code !== undefined ? `(EXIT: ${res.exit_code})` : ""}
                            </span>
                          </div>
                        </div>

                        {res ? (
                          <div style={{
                            background: "#02040a",
                            border: "1px solid #142034",
                            borderRadius: 6,
                            padding: "8px 12px",
                            fontFamily: "var(--font-mono)",
                            fontSize: 11,
                            color: res.exit_code === 0 ? "#34d399" : "#f87171",
                            whiteSpace: "pre-wrap",
                            maxHeight: 160,
                            overflowY: "auto",
                            wordBreak: "break-all"
                          }}>
                            {res.stdout || res.stderr || "(No terminal output captured)"}
                          </div>
                        ) : (
                          <div style={{
                            background: "#030814",
                            border: "1px dashed #1e3a5f",
                            borderRadius: 6,
                            padding: "8px 12px",
                            fontSize: 11,
                            color: "#93c5fd",
                            fontFamily: "var(--font-mono)",
                            display: "flex",
                            alignItems: "center",
                            gap: 8
                          }}>
                            <RefreshCw size={12} className="spin" color="#38bdf8" />
                            <span>Task queued on server. Awaiting endpoint agent heartbeat to execute... (run <code>./povishield watch</code> on host)</span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Fleet Overview Guidance */}
            {!broadcastResult && !broadcastRunning && (
              <div style={{
                padding: "24px 20px", background: "#050914", border: "1px dashed #1e293b",
                borderRadius: 8, textAlign: "center", color: "#64748b"
              }}>
                <Server size={32} style={{ opacity: 0.4, marginBottom: 8 }} />
                <h4 style={{ margin: "0 0 6px", color: "#cbd5e1", fontSize: 13 }}>Multi-Device Fleet Dispatch Ready</h4>
                <p style={{ margin: 0, fontSize: 11, maxWidth: 540, marginLeft: "auto", marginRight: "auto" }}>
                  Enter any Linux command above or pick a preset to execute across all {selectedDeviceIds.size} selected nodes simultaneously.
                  Each endpoint enforces local seccomp BPF filters and streams observed syscall events back to this supervisor console.
                </p>
              </div>
            )}
          </div>
        ) : selectedDevice ? (
          /* Single Device Deep-Dive Inspector Pane */
          <div className="panel fleet-detail-panel">
            {/* Top Multi-Device Switch Banner if user has checkboxes selected */}
            {selectedDeviceIds.size > 1 && (
              <div style={{
                marginBottom: 16, padding: "8px 14px", background: "#071a2e",
                border: "1px solid #0284c7", borderRadius: 8, display: "flex",
                justifyContent: "space-between", alignItems: "center"
              }}>
                <span style={{ fontSize: 11, color: "#38bdf8", display: "flex", alignItems: "center", gap: 6 }}>
                  <Terminal size={14} /> You have <strong>{selectedDeviceIds.size}</strong> endpoints selected for multi-device broadcast.
                </span>
                <button
                  className="secondary-button"
                  onClick={handleSwitchToBroadcast}
                  style={{ padding: "3px 8px", fontSize: 11, borderColor: "#0284c7", color: "#38bdf8" }}
                >
                  Open Broadcast Supervisor
                </button>
              </div>
            )}

            <div className="panel-heading" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <h2 style={{ margin: 0, fontSize: 18 }}>{selectedDevice.name}</h2>
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
                <p style={{ marginTop: 4, fontSize: 12 }}>ID: <code>{selectedDevice.id}</code> · Host: <code>{selectedDevice.hostname}</code> · OS: {selectedDevice.os_info}</p>
              </div>

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  className="secondary-button"
                  onClick={handleRefreshFleet}
                  disabled={refreshing}
                  title="Refresh device telemetry and fleet"
                  style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}
                >
                  <RefreshCw size={13} className={refreshing ? "spin" : ""} />
                  {refreshing ? "Refreshing..." : "Refresh"}
                </button>

                {setActiveDeviceId && (
                  activeDeviceId === selectedDevice.id ? (
                    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                      <span className="demo-badge" style={{ borderColor: "#10b981", color: "#34d399", padding: "6px 10px", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 5 }}>
                        <span className="live-pulse-dot" style={{ width: 6, height: 6 }} /> SCOPED ACTIVE TARGET
                      </span>
                      <button
                        className="secondary-button"
                        onClick={() => setActiveDeviceId("gateway")}
                        style={{ padding: "6px 10px", fontSize: 11 }}
                        title="Reset global scope back to Gateway"
                      >
                        Reset Scope
                      </button>
                    </div>
                  ) : (
                    <button
                      className="secondary-button"
                      onClick={() => setActiveDeviceId(selectedDevice.id)}
                      title="Scope entire dashboard and execution to this computer"
                      style={{ borderColor: "#1e3a5f", color: "#38bdf8", padding: "6px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
                    >
                      <Activity size={13} /> Scope Dashboard to this PC
                    </button>
                  )
                )}

                <button
                  className="primary-button"
                  onClick={handleRunSecurityAudit}
                  disabled={dispatchingTask || selectedDevice.status === "revoked"}
                  style={{ padding: "6px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
                  title="Run immediate kernel diagnostic audit on this PC"
                >
                  <ShieldCheck size={13} /> Run Security Audit
                </button>

                {selectedDevice.status !== "revoked" ? (
                  <button
                    className="secondary-button"
                    onClick={() => handleRevokeDevice(selectedDevice.id)}
                    style={{ color: "#f87171", borderColor: "#7f1d1d", fontSize: 12 }}
                    title="Permanently invalidate agent credentials"
                  >
                    <Lock size={13} /> Revoke
                  </button>
                ) : (
                  <button
                    className="secondary-button"
                    onClick={() => handleDeleteDevice(selectedDevice.id)}
                    style={{ color: "#f87171", borderColor: "#7f1d1d", fontSize: 12 }}
                    title="Delete device record"
                  >
                    <Trash2 size={13} /> Delete Record
                  </button>
                )}

                <button
                  className="secondary-button"
                  onClick={() => handleDeleteDevice(selectedDevice.id)}
                  style={{ color: "#94a3b8", fontSize: 12 }}
                  title="Remove device from fleet"
                >
                  <Trash2 size={13} /> Remove
                </button>
              </div>
            </div>

            {/* Capability Diagnostics Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10, margin: "16px 0 24px" }}>
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
                <span style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>Cgroups v2 Cap</span>
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
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <h3 style={{ fontSize: 15, margin: 0 }}>Remote Policy-Gated Execution</h3>
                {!selectedDevice.is_live && (
                  <span style={{ fontSize: 11, color: "#f59e0b", fontFamily: "var(--font-mono)" }}>
                    ⚠️ Endpoint is offline (tasks will queue until agent connects)
                  </span>
                )}
              </div>
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

              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 260, position: "relative" }}>
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
                  onClick={() => handleDispatchTask()}
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
                  <div className="terminal-top-bar" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 11, color: "#94a3b8" }}>
                        REMOTE_EXECUTION_RESULT // {selectedDevice.hostname} {activeTaskResult.task_id ? `[${activeTaskResult.task_id}]` : ""}
                      </span>
                      {activeTaskResult.mode && (
                        <span style={{ fontSize: 9, padding: "1px 5px", background: "#0c2d48", color: "#38bdf8", borderRadius: 3, fontFamily: "var(--font-mono)" }}>
                          MODE: {activeTaskResult.mode.toUpperCase()}
                        </span>
                      )}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{
                        color: activeTaskResult.exit_code === 0 ? "#34d399" : activeTaskResult.status === "queued" ? "#fbbf24" : "#f87171",
                        fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700
                      }}>
                        STATUS: {activeTaskResult.status?.toUpperCase()} {activeTaskResult.exit_code !== undefined ? `(EXIT: ${activeTaskResult.exit_code})` : ""}
                      </span>
                      <button
                        className="icon-button"
                        onClick={() => setActiveTaskResult(null)}
                        title="Dismiss execution result viewport"
                        style={{ padding: 2, background: "transparent", border: "none", color: "#94a3b8", cursor: "pointer" }}
                      >
                        <X size={14} />
                      </button>
                    </div>
                  </div>
                  <div className="terminal-screen" style={{ maxHeight: 240, overflowY: "auto" }}>
                    <div className="terminal-line init">
                      [TARGET] Command: {Array.isArray(activeTaskResult.command) ? activeTaskResult.command.join(" ") : String(activeTaskResult.command || commandInput)} | Host: {selectedDevice.hostname}
                    </div>

                    {activeTaskResult.queued_notice && (
                      <div style={{ margin: "8px 0", padding: "10px", background: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)", borderRadius: 6, color: "#fbbf24" }}>
                        <strong>Task Queued on Server (ID: {activeTaskResult.task_id})</strong>
                        <p style={{ margin: "4px 0 0", fontSize: 11, color: "#fef3c7" }}>
                          This endpoint is currently offline. The command has been saved to the queue and will execute automatically the moment <code>./povishield watch</code> or the background agent connects from <strong>{selectedDevice.hostname}</strong>.
                        </p>
                      </div>
                    )}

                    {activeTaskResult.error && (
                      <div className="terminal-line error" style={{ margin: "6px 0", padding: "8px 10px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: 5, color: "#f87171" }}>
                        [ALERT: EXECUTION ERROR] {activeTaskResult.error}
                      </div>
                    )}

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
                    {activeTaskResult.syscalls?.length > 0 && (
                      <div style={{ margin: "8px 0", padding: "6px 10px", background: "rgba(14, 165, 233, 0.08)", border: "1px solid rgba(14, 165, 233, 0.25)", borderRadius: 6 }}>
                        <div style={{ fontSize: 10, color: "#38bdf8", fontWeight: 700, marginBottom: 4, display: "flex", justifyContent: "space-between" }}>
                          <span>[OS INTERACTION] {activeTaskResult.syscalls.length} Observed System Calls Talking to Remote Linux Kernel:</span>
                          <span style={{ color: "#34d399" }}>Boundary Enforced</span>
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {activeTaskResult.syscalls.map((sc, i) => (
                            <span key={i} style={{ fontSize: 10, padding: "2px 6px", background: "#0e1a2d", border: "1px solid #1e3a5f", borderRadius: 4, color: "#93c5fd", fontFamily: "var(--font-mono)" }}>
                              sys_{sc}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {activeTaskResult.duration_ms !== undefined && (
                      <div className="terminal-line success">
                        [RESULT] Status: {activeTaskResult.status} | Duration: {activeTaskResult.duration_ms}ms
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Two Column Section: Recent Tasks & Device Audit Events */}
              <div className="fleet-two-col">
                {/* Recent Tasks List */}
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <h4 style={{ fontSize: 13, color: "#94a3b8", margin: 0 }}>Recent Tasks (Click to Inspect)</h4>
                    <span style={{ fontSize: 10, color: "#64748b" }}>{deviceTasks.length} recorded</span>
                  </div>
                  {deviceTasks.length === 0 ? (
                    <p style={{ fontSize: 12, color: "#64748b" }}>No execution tasks recorded on this host yet.</p>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 240, overflowY: "auto" }}>
                      {deviceTasks.slice(0, 10).map(t => {
                        const cmdText = Array.isArray(t.command) ? t.command.join(" ") : String(t.command || "");
                        const isSelectedTask = activeTaskResult?.task_id === t.id || activeTaskResult?.id === t.id;

                        return (
                          <div
                            key={t.id}
                            className={`fleet-task-row ${isSelectedTask ? "active" : ""}`}
                            onClick={() => {
                              setActiveTaskResult(t.result ? {
                                ...t.result,
                                status: t.status,
                                task_id: t.id,
                                command: t.command,
                                mode: t.mode,
                                error: t.error
                              } : {
                                status: t.status,
                                task_id: t.id,
                                command: t.command,
                                mode: t.mode,
                                error: t.error
                              });
                            }}
                            title="Click to view execution stdout and syscall details in viewport"
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: 8, overflow: "hidden" }}>
                              <Eye size={12} style={{ opacity: isSelectedTask ? 1 : 0.4 }} />
                              <span style={{ textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>{cmdText}</span>
                              {t.result?.syscalls?.length > 0 && (
                                <span style={{ fontSize: 9, padding: "1px 5px", background: "#0e1a2d", border: "1px solid #1e3a5f", borderRadius: 3, color: "#38bdf8", flexShrink: 0 }}>
                                  {t.result.syscalls.length} syscalls
                                </span>
                              )}
                            </div>
                            <span style={{
                              color: t.result?.exit_code === 0 ? "#34d399" : t.status === "completed" ? "#f87171" : "#fbbf24",
                              flexShrink: 0,
                              fontWeight: 600
                            }}>
                              {t.status.toUpperCase()} {t.result?.exit_code !== undefined ? `(${t.result.exit_code})` : ""}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Device Audit Events Timeline */}
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <h4 style={{ fontSize: 13, color: "#94a3b8", margin: 0 }}>Endpoint Telemetry Events</h4>
                    <span style={{ fontSize: 10, color: "#64748b" }}>{deviceEvents.length} events</span>
                  </div>
                  {deviceEvents.length === 0 ? (
                    <p style={{ fontSize: 12, color: "#64748b" }}>No audit events logged for this device yet.</p>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 240, overflowY: "auto" }}>
                      {deviceEvents.slice(0, 10).map((ev, i) => {
                        const payloadSummary = ev.payload ? (
                          ev.payload.command ? (Array.isArray(ev.payload.command) ? ev.payload.command.join(" ") : String(ev.payload.command)) :
                          ev.payload.target ? `target: ${ev.payload.target}` :
                          ev.payload.task_id ? `task: ${ev.payload.task_id}` :
                          ev.payload.reason ? `reason: ${ev.payload.reason}` :
                          null
                        ) : null;

                        return (
                          <div key={i} className="fleet-event-row" style={{ display: "flex", flexDirection: "column", alignItems: "stretch", gap: 3 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{
                                  width: 6, height: 6, borderRadius: "50%",
                                  background: ev.event_type.includes("completed") ? "#10b981" : ev.event_type.includes("queued") ? "#38bdf8" : ev.event_type.includes("revoked") ? "#ef4444" : "#a855f7"
                                }} />
                                <strong style={{ color: "#cbd5e1", fontSize: 11 }}>{ev.event_type}</strong>
                              </div>
                              <span style={{ color: "#64748b", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                                {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "—"}
                              </span>
                            </div>
                            {payloadSummary && (
                              <div style={{ fontSize: 10, color: "#94a3b8", fontFamily: "var(--font-mono)", paddingLeft: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {payloadSummary}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
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

                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 12, color: "#94a3b8", display: "block", marginBottom: 6 }}>
                    Enrollment Key Type:
                  </label>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    <div
                      onClick={() => setEnrollmentMode("multi")}
                      style={{
                        padding: "10px 12px",
                        borderRadius: 8,
                        cursor: "pointer",
                        border: enrollmentMode === "multi" ? "1px solid #10b981" : "1px solid #1e293b",
                        background: enrollmentMode === "multi" ? "#06281e" : "#050914",
                        transition: "all 0.2s ease"
                      }}
                    >
                      <div style={{ fontWeight: 600, fontSize: 12, color: enrollmentMode === "multi" ? "#34d399" : "#cbd5e1" }}>
                        ⚡ Multi-Device Fleet (Recommended)
                      </div>
                      <p style={{ fontSize: 10, color: "#64748b", marginTop: 4 }}>
                        Enroll any number of Linux endpoints, VMs, and servers with one command.
                      </p>
                    </div>
                    <div
                      onClick={() => setEnrollmentMode("single")}
                      style={{
                        padding: "10px 12px",
                        borderRadius: 8,
                        cursor: "pointer",
                        border: enrollmentMode === "single" ? "1px solid #38bdf8" : "1px solid #1e293b",
                        background: enrollmentMode === "single" ? "#08243b" : "#050914",
                        transition: "all 0.2s ease"
                      }}
                    >
                      <div style={{ fontWeight: 600, fontSize: 12, color: enrollmentMode === "single" ? "#38bdf8" : "#cbd5e1" }}>
                        🔒 Single-Use Device
                      </div>
                      <p style={{ fontSize: 10, color: "#64748b", marginTop: 4 }}>
                        Restricted to exactly 1 machine; code self-expires upon first connection.
                      </p>
                    </div>
                  </div>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ fontSize: 12, color: "#94a3b8", display: "block", marginBottom: 6 }}>
                    Optional Fleet / Cluster Nickname:
                  </label>
                  <input
                    type="text"
                    value={pairingName}
                    onChange={(e) => setPairingName(e.target.value)}
                    placeholder="e.g. Production-Cluster, AWS-Nodes, or Lab-VMs"
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
                    {generatingCode ? "Generating..." : "Generate Fleet Enrollment Code"} <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            )}

            {wizardStep === 2 && pairingData && (
              <div>
                <div style={{ textAlign: "center", padding: "16px 0 20px" }}>
                  <span style={{ fontSize: 11, color: "#38bdf8", textTransform: "uppercase", letterSpacing: 1, fontWeight: 700 }}>
                    {enrollmentMode === "multi" ? "⚡ Multi-Device Fleet Enrollment Key (Unlimited Endpoints)" : "🔒 Single-Use Device Key"} · Valid 10 Minutes
                  </span>
                  <div style={{
                    fontSize: 32, fontWeight: 800, fontFamily: "var(--font-mono)",
                    color: "#10b981", margin: "8px 0", letterSpacing: 2
                  }}>
                    {pairingData.code}
                  </div>
                  <p style={{ fontSize: 11, color: "#94a3b8", maxWidth: 500, margin: "0 auto", lineHeight: 1.4 }}>
                    {enrollmentMode === "multi"
                      ? "Run the install command on ANY number of Linux workstations, servers, or cloud nodes. Every machine will link automatically to your fleet."
                      : "Run the install command on your target Linux machine."}
                  </p>
                </div>

                {/* Live Enrolled Devices Indicator */}
                {enrolledDevicesThisSession.length > 0 && (
                  <div style={{
                    marginBottom: 16, padding: "12px 14px", background: "#051f15",
                    border: "1px solid #059669", borderRadius: 8
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                      <strong style={{ fontSize: 12, color: "#34d399", display: "flex", alignItems: "center", gap: 6 }}>
                        <span className="live-pulse-dot" style={{ width: 7, height: 7, background: "#10b981" }} />
                        {enrolledDevicesThisSession.length} Endpoint(s) Successfully Enrolled in Fleet:
                      </strong>
                      <span style={{ fontSize: 10, color: "#6ee7b7", fontFamily: "var(--font-mono)" }}>LIVE FLEET SYNC</span>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 120, overflowY: "auto" }}>
                      {enrolledDevicesThisSession.map(dev => (
                        <div key={dev.id} style={{
                          display: "flex", justifyContent: "space-between", alignItems: "center",
                          background: "#082e21", padding: "6px 10px", borderRadius: 6, fontSize: 11, fontFamily: "var(--font-mono)"
                        }}>
                          <span style={{ color: "#f1f5f9", fontWeight: 600 }}>💻 {dev.name || dev.hostname}</span>
                          <span style={{ color: "#6ee7b7" }}>{dev.arch} · {dev.kernel_version?.slice(0, 18)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {typeof window !== "undefined" && window.location.hostname.includes("vercel") && !localStorage.getItem("povishield_custom_api_url") && (
                  <div style={{
                    background: "rgba(245, 158, 11, 0.12)", border: "1px solid rgba(245, 158, 11, 0.35)",
                    borderRadius: 6, padding: "8px 12px", marginBottom: 14, fontSize: 11, color: "#fde68a"
                  }}>
                    <strong>Notice:</strong> This web dashboard is running on Vercel. Connect your machine to your local backend at <strong style={{ color: "#38bdf8" }}>http://localhost:8000</strong>, or open <a href="http://localhost:8000" target="_blank" rel="noopener noreferrer" style={{ color: "#38bdf8", fontWeight: 700 }}>http://localhost:8000</a> directly.
                  </div>
                )}

                <div style={{ marginBottom: 18 }}>
                  <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 600, display: "block", marginBottom: 6 }}>
                    Option A: Run this on target Linux machines (One-liner install):
                  </span>
                  <div style={{
                    position: "relative", background: "#050811", border: "1px solid #1e293b",
                    borderRadius: 6, padding: "10px 42px 10px 12px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#34d399"
                  }}>
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {`curl -sSL ${(pairingData.server_url && !pairingData.server_url.includes("vercel")) ? pairingData.server_url : effectiveBackend}/install.sh | bash -s -- --code ${pairingData.code} --server ${(pairingData.server_url && !pairingData.server_url.includes("vercel")) ? pairingData.server_url : effectiveBackend} --start`}
                    </pre>
                    <button
                      className="icon-button"
                      onClick={() => copyText(`curl -sSL ${(pairingData.server_url && !pairingData.server_url.includes("vercel")) ? pairingData.server_url : effectiveBackend}/install.sh | bash -s -- --code ${pairingData.code} --server ${(pairingData.server_url && !pairingData.server_url.includes("vercel")) ? pairingData.server_url : effectiveBackend} --start`)}
                      style={{ position: "absolute", right: 8, top: 8 }}
                      title="Copy install command"
                    >
                      {copiedCmd ? <Check size={16} color="#34d399" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 600, display: "block", marginBottom: 6 }}>
                    Option B: If you already downloaded <code>./povishield</code>:
                  </span>
                  <div style={{
                    position: "relative", background: "#050811", border: "1px solid #1e293b",
                    borderRadius: 6, padding: "10px 42px 10px 12px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#38bdf8"
                  }}>
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {`./povishield connect ${(pairingData.server_url && !pairingData.server_url.includes("vercel")) ? pairingData.server_url : effectiveBackend} --code ${pairingData.code}`}
                    </pre>
                    <button
                      className="icon-button"
                      onClick={() => copyText(`./povishield connect ${(pairingData.server_url && !pairingData.server_url.includes("vercel")) ? pairingData.server_url : effectiveBackend} --code ${pairingData.code}`)}
                      style={{ position: "absolute", right: 8, top: 8 }}
                      title="Copy CLI command"
                    >
                      {copiedCmd ? <Check size={16} color="#38bdf8" /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                {waitingForPair && (
                  <div style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "12px 16px", background: "#071224", borderRadius: 8, border: "1px dashed #1e3a5f"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <RefreshCw size={16} className="spin" color="#38bdf8" />
                      <span style={{ fontSize: 12, color: "#93c5fd" }}>
                        {enrollmentMode === "multi"
                          ? `Listening for endpoint connections... (${enrolledDevicesThisSession.length} joined so far)`
                          : "Waiting for endpoint connection..."}
                      </span>
                    </div>
                    {enrolledDevicesThisSession.length > 0 && (
                      <span style={{ fontSize: 11, color: "#34d399", fontWeight: 700 }}>
                        ✓ {enrolledDevicesThisSession.length} NODE(S) ACTIVE
                      </span>
                    )}
                  </div>
                )}

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 20 }}>
                  <span style={{ fontSize: 11, color: "#64748b" }}>
                    {enrollmentMode === "multi" ? "Keep this window open to paste into additional machines." : ""}
                  </span>
                  <div style={{ display: "flex", gap: 10 }}>
                    <button
                      className="primary-button"
                      onClick={() => { setShowPairModal(false); setWaitingForPair(false); fetchDevices(); }}
                    >
                      Done & Manage Fleet ({devices.length})
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- STANDALONE DOWNLOAD & WATCH MODAL --- */}
      {showDownloadModal && (
        <div className="modal-backdrop" style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)",
          backdropFilter: "blur(6px)", zIndex: 9999, display: "grid", placeItems: "center", padding: 20
        }}>
          <div className="modal-card" style={{
            background: "#090d16", border: "1px solid #1e293b", borderRadius: 12,
            maxWidth: 620, width: "100%", padding: 28, boxShadow: "0 20px 40px rgba(0,0,0,0.6)"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Download size={20} style={{ color: "#38bdf8" }} />
                <h3 style={{ fontSize: 18, color: "#f1f5f9" }}>Download PoViShield CLI & Remote Watch Tool</h3>
              </div>
              <button
                className="icon-button"
                onClick={() => setShowDownloadModal(false)}
              >
                <X size={18} />
              </button>
            </div>

            <p style={{ fontSize: 13, color: "#94a3b8", lineHeight: 1.5, marginBottom: 18 }}>
              Execute <code>./povishield watch</code> on any other computer, laptop, or server to live stream executions, security approvals, and kernel syscalls.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
              <a
                href={`${API.replace(/\/api$/, '')}/download/povishield`}
                download="povishield"
                className="primary-button"
                style={{
                  textDecoration: "none", display: "flex", alignItems: "center", justifyContent: "center",
                  gap: 8, padding: "12px 16px", fontSize: 13, textAlign: "center"
                }}
              >
                <Download size={16} /> Download ./povishield
              </a>
              <a
                href={`${API.replace(/\/api$/, '')}/download/povishield-agent.tar.gz`}
                download="povishield-agent.tar.gz"
                className="secondary-button"
                style={{
                  textDecoration: "none", display: "flex", alignItems: "center", justifyContent: "center",
                  gap: 8, padding: "12px 16px", fontSize: 13, textAlign: "center", borderColor: "#334155"
                }}
              >
                <Download size={16} /> Full Bundle (.tar.gz)
              </a>
            </div>

            <div style={{
              background: "#050811", border: "1px solid #1e293b", borderRadius: 8, padding: 16, marginBottom: 20
            }}>
              <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 600, display: "block", marginBottom: 10 }}>
                Step-by-Step Setup on the Other PC:
              </span>
              <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 12, fontFamily: "var(--font-mono)" }}>
                <div>
                  <div style={{ color: "#64748b", marginBottom: 4 }}>1. Download via Terminal:</div>
                  <div style={{ position: "relative", background: "#090d16", padding: "8px 36px 8px 10px", borderRadius: 6, color: "#38bdf8", wordBreak: "break-all" }}>
                    if [ -d "povishield" ]; then cd povishield; else curl -sSL {effectiveBackend}/download/povishield -o povishield && chmod +x povishield; fi
                    <button className="icon-button" onClick={() => copyText(`if [ -d "povishield" ]; then cd povishield; else curl -sSL ${effectiveBackend}/download/povishield -o povishield && chmod +x povishield; fi`)} style={{ position: "absolute", right: 6, top: 6 }}><Copy size={13} /></button>
                  </div>
                </div>
                <div>
                  <div style={{ color: "#64748b", marginBottom: 4 }}>2. Connect & enroll this machine:</div>
                  <div style={{ position: "relative", background: "#090d16", padding: "8px 36px 8px 10px", borderRadius: 6, color: "#cbd5e1", wordBreak: "break-all" }}>
                    ./povishield connect {effectiveBackend}
                    <button className="icon-button" onClick={() => copyText(`./povishield connect ${effectiveBackend}`)} style={{ position: "absolute", right: 6, top: 6 }}><Copy size={13} /></button>
                  </div>
                </div>
                <div>
                  <div style={{ color: "#64748b", marginBottom: 4 }}>3. Launch live cybersecurity watch stream:</div>
                  <div style={{ position: "relative", background: "#090d16", padding: "8px 36px 8px 10px", borderRadius: 6, color: "#34d399", fontWeight: 700 }}>
                    ./povishield watch
                    <button className="icon-button" onClick={() => copyText("./povishield watch")} style={{ position: "absolute", right: 6, top: 6 }}><Copy size={13} /></button>
                  </div>
                </div>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button
                className="secondary-button"
                onClick={() => { setShowDownloadModal(false); setWizardStep(1); setShowPairModal(true); }}
                style={{ display: "flex", alignItems: "center", gap: 6 }}
              >
                <Plus size={14} /> Get Pairing Code
              </button>
              <button
                className="primary-button"
                onClick={() => setShowDownloadModal(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
