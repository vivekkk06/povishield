import React, { useState, useEffect } from "react";
import {
  Download, Terminal, Server, ShieldCheck, ShieldAlert,
  Copy, Check, RefreshCw, Key, ChevronDown, ChevronUp,
  ExternalLink, Play, CheckCircle2, Activity, Cpu, Layers
} from "lucide-react";

export default function RemoteWatchGuidePanel({
  API = "/api",
  defaultServerUrl = "",
  onDevicePaired = null,
  embedded = false
}) {
  const [serverUrl, setServerUrl] = useState(() => {
    if (defaultServerUrl) return defaultServerUrl.replace(/\/$/, "");
    if (typeof window !== "undefined" && window.location) {
      return window.location.origin.replace(/\/$/, "");
    }
    return "http://localhost:8000";
  });

  const [customUrlInput, setCustomUrlInput] = useState(serverUrl);
  const [editingUrl, setEditingUrl] = useState(false);

  const [pairingCode, setPairingCode] = useState("");
  const [pairingExpiresAt, setPairingExpiresAt] = useState(null);
  const [generatingCode, setGeneratingCode] = useState(false);
  const [pairingError, setPairingError] = useState("");
  const [copiedStep, setCopiedStep] = useState(null);
  const [expanded, setExpanded] = useState(true);

  // Sync serverUrl when prop changes
  useEffect(() => {
    if (defaultServerUrl) {
      const clean = defaultServerUrl.replace(/\/$/, "");
      setServerUrl(clean);
      setCustomUrlInput(clean);
    }
  }, [defaultServerUrl]);

  const copyToClipboard = (text, stepKey) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedStep(stepKey);
      setTimeout(() => setCopiedStep(null), 2200);
    }
  };

  const handleGeneratePairingCode = async () => {
    setGeneratingCode(true);
    setPairingError("");
    try {
      const res = await fetch(`${API}/pairing/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_name_hint: "remote_linux_node",
          expires_in_seconds: 600
        })
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      if (data.code) {
        setPairingCode(data.code);
        setPairingExpiresAt(new Date(Date.now() + 600 * 1000));
        if (data.server_url && (!customUrlInput || customUrlInput.includes("localhost") || customUrlInput.includes("127.0.0.1"))) {
          setServerUrl(data.server_url.replace(/\/$/, ""));
          setCustomUrlInput(data.server_url.replace(/\/$/, ""));
        }
      }
    } catch (err) {
      console.error("Pairing code error:", err);
      setPairingError("Could not generate pairing code. Check server connection.");
    } finally {
      setGeneratingCode(false);
    }
  };

  const step1Curl = `curl -sSL ${serverUrl}/download/povishield -o povishield`;
  const step2Chmod = `chmod +x povishield`;
  const codeParam = pairingCode || "<PAIRING_CODE>";
  const step3Connect = `./povishield connect ${serverUrl} --code ${codeParam}`;
  const step3Sudo = `sudo ./povishield connect ${serverUrl} --code ${codeParam}`;
  const step4Watch = `./povishield watch`;
  const step4Monitor = `./povishield monitor`;

  const allInOneScript = `${step1Curl} && ${step2Chmod} && ${step3Connect} && ${step4Watch}`;

  return (
    <div className="remote-watch-guide-card" style={{
      background: "linear-gradient(135deg, rgba(8, 17, 32, 0.95) 0%, rgba(5, 12, 22, 0.98) 100%)",
      border: "1px solid rgba(16, 185, 129, 0.35)",
      borderRadius: "12px",
      boxShadow: "0 12px 36px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(16, 185, 129, 0.2)",
      marginBottom: "24px",
      overflow: "hidden",
      position: "relative"
    }}>
      {/* Top Banner & Header */}
      <div style={{
        padding: "16px 20px",
        background: "rgba(16, 185, 129, 0.08)",
        borderBottom: "1px solid rgba(16, 185, 129, 0.2)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: "12px"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            width: "38px",
            height: "38px",
            borderRadius: "8px",
            background: "rgba(16, 185, 129, 0.15)",
            border: "1px solid #10b981",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#10b981"
          }}>
            <Terminal size={22} />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.01em" }}>
                Step-by-Step: How to Run <code style={{ color: "#34d399", background: "rgba(16, 185, 129, 0.15)", padding: "2px 6px", borderRadius: "4px" }}>./povishield watch</code> on Another PC
              </h3>
              <span className="demo-badge" style={{
                background: "rgba(16, 185, 129, 0.2)",
                color: "#34d399",
                border: "1px solid #10b981",
                fontSize: "10px",
                padding: "2px 8px"
              }}>
                REMOTE FLEET WATCH
              </span>
            </div>
            <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#94a3b8" }}>
              Follow these 4 simple steps on any remote Linux machine to stream live kernel syscall verdicts, dispatched tasks, and interactive approvals.
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <button
            className="secondary-button"
            onClick={() => copyToClipboard(allInOneScript, "all")}
            style={{
              fontSize: "12px",
              padding: "6px 12px",
              background: copiedStep === "all" ? "rgba(16, 185, 129, 0.25)" : "rgba(15, 23, 42, 0.8)",
              borderColor: copiedStep === "all" ? "#10b981" : "#334155",
              color: copiedStep === "all" ? "#34d399" : "#e2e8f0"
            }}
            title="Copy all steps as a single combined shell command"
          >
            {copiedStep === "all" ? <Check size={14} style={{ color: "#34d399" }} /> : <Copy size={14} />}
            <span>{copiedStep === "all" ? "All Steps Copied!" : "Copy Full 1-Liner"}</span>
          </button>

          <button
            className="secondary-button"
            onClick={() => setExpanded(!expanded)}
            style={{ padding: "6px 10px", fontSize: "12px" }}
            aria-label="Toggle Guide Panel"
          >
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        </div>
      </div>

      {expanded && (
        <div style={{ padding: "20px" }}>
          {/* Server URL Customizer / Bar */}
          <div style={{
            background: "rgba(15, 23, 42, 0.6)",
            border: "1px solid #1e293b",
            borderRadius: "8px",
            padding: "10px 14px",
            marginBottom: "20px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "10px"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1, minWidth: "260px" }}>
              <Server size={15} color="#38bdf8" />
              <span style={{ fontSize: "12px", color: "#94a3b8" }}>Server Endpoint URL:</span>
              {editingUrl ? (
                <div style={{ display: "flex", alignItems: "center", gap: "6px", flex: 1 }}>
                  <input
                    type="text"
                    value={customUrlInput}
                    onChange={(e) => setCustomUrlInput(e.target.value)}
                    placeholder="http://<YOUR_SERVER_IP>:8000"
                    style={{
                      background: "#030712",
                      border: "1px solid #38bdf8",
                      borderRadius: "4px",
                      padding: "4px 8px",
                      fontSize: "12px",
                      color: "#38bdf8",
                      fontFamily: "var(--font-mono)",
                      flex: 1
                    }}
                  />
                  <button
                    className="primary-button"
                    style={{ padding: "4px 10px", fontSize: "11px" }}
                    onClick={() => {
                      setServerUrl(customUrlInput.trim().replace(/\/$/, ""));
                      setEditingUrl(false);
                    }}
                  >
                    Save
                  </button>
                  <button
                    className="secondary-button"
                    style={{ padding: "4px 8px", fontSize: "11px" }}
                    onClick={() => {
                      setCustomUrlInput(serverUrl);
                      setEditingUrl(false);
                    }}
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <code style={{ color: "#38bdf8", fontSize: "12px" }}>{serverUrl}</code>
                  <button
                    className="secondary-button"
                    style={{ padding: "2px 8px", fontSize: "10px", height: "auto" }}
                    onClick={() => setEditingUrl(true)}
                  >
                    Change IP/URL
                  </button>
                </div>
              )}
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "11px", color: "#64748b" }}>Quick Download Options:</span>
              <a
                href={`${serverUrl}/download/povishield`}
                download="povishield"
                className="secondary-button"
                style={{
                  fontSize: "11px",
                  padding: "4px 10px",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "5px",
                  color: "#34d399",
                  borderColor: "rgba(16, 185, 129, 0.4)",
                  background: "rgba(16, 185, 129, 0.1)"
                }}
              >
                <Download size={13} /> Download CLI (povishield)
              </a>
              <a
                href={`${serverUrl}/download/povishield-agent.tar.gz`}
                download="povishield-agent.tar.gz"
                className="secondary-button"
                style={{
                  fontSize: "11px",
                  padding: "4px 10px",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "5px",
                  color: "#94a3b8"
                }}
              >
                <Download size={13} /> Full Bundle (.tar.gz)
              </a>
            </div>
          </div>

          {/* 4 Steps Container */}
          <div style={{ display: "grid", gap: "16px" }}>

            {/* STEP 1 */}
            <div style={{
              background: "rgba(11, 19, 34, 0.75)",
              border: "1px solid #162236",
              borderRadius: "8px",
              padding: "16px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{
                      background: "rgba(56, 189, 248, 0.15)",
                      color: "#38bdf8",
                      fontSize: "11px",
                      fontWeight: 700,
                      padding: "2px 8px",
                      borderRadius: "4px",
                      border: "1px solid rgba(56, 189, 248, 0.3)"
                    }}>
                      STEP 1
                    </span>
                    <strong style={{ fontSize: "14px", color: "#f1f5f9" }}>Download povishield</strong>
                  </div>
                  <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#94a3b8" }}>
                    You can either click <strong>Download CLI</strong> on the website dashboard or run in your terminal:
                  </p>
                </div>

                <div style={{ display: "flex", gap: "6px" }}>
                  <a
                    href={`${serverUrl}/download/povishield`}
                    download="povishield"
                    className="primary-button"
                    style={{ padding: "4px 10px", fontSize: "11px", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "4px" }}
                  >
                    <Download size={13} /> Download CLI
                  </a>
                  <button
                    className="secondary-button"
                    onClick={() => copyToClipboard(step1Curl, "step1")}
                    style={{ padding: "4px 8px", fontSize: "11px" }}
                  >
                    {copiedStep === "step1" ? <Check size={13} style={{ color: "#34d399" }} /> : <Copy size={13} />}
                    {copiedStep === "step1" ? "Copied" : "Copy Command"}
                  </button>
                </div>
              </div>

              <div style={{
                background: "#030712",
                border: "1px solid #1e293b",
                borderRadius: "6px",
                padding: "8px 12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "#e2e8f0"
              }}>
                <span style={{ overflowX: "auto", whiteSpace: "nowrap" }}>
                  <span style={{ color: "#10b981" }}>$ </span>{step1Curl}
                </span>
              </div>
            </div>

            {/* STEP 2 */}
            <div style={{
              background: "rgba(11, 19, 34, 0.75)",
              border: "1px solid #162236",
              borderRadius: "8px",
              padding: "16px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{
                      background: "rgba(245, 158, 11, 0.15)",
                      color: "#fbbf24",
                      fontSize: "11px",
                      fontWeight: 700,
                      padding: "2px 8px",
                      borderRadius: "4px",
                      border: "1px solid rgba(245, 158, 11, 0.3)"
                    }}>
                      STEP 2
                    </span>
                    <strong style={{ fontSize: "14px", color: "#f1f5f9" }}>Make It Executable</strong>
                  </div>
                  <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#94a3b8" }}>
                    Grant execute permissions to the downloaded script:
                  </p>
                </div>

                <button
                  className="secondary-button"
                  onClick={() => copyToClipboard(step2Chmod, "step2")}
                  style={{ padding: "4px 8px", fontSize: "11px" }}
                >
                  {copiedStep === "step2" ? <Check size={13} style={{ color: "#34d399" }} /> : <Copy size={13} />}
                  {copiedStep === "step2" ? "Copied" : "Copy Command"}
                </button>
              </div>

              <div style={{
                background: "#030712",
                border: "1px solid #1e293b",
                borderRadius: "6px",
                padding: "8px 12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "#e2e8f0"
              }}>
                <span style={{ overflowX: "auto", whiteSpace: "nowrap" }}>
                  <span style={{ color: "#10b981" }}>$ </span>{step2Chmod}
                </span>
              </div>
            </div>

            {/* STEP 3 */}
            <div style={{
              background: "rgba(11, 19, 34, 0.75)",
              border: "1px solid rgba(16, 185, 129, 0.25)",
              borderRadius: "8px",
              padding: "16px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{
                      background: "rgba(16, 185, 129, 0.15)",
                      color: "#34d399",
                      fontSize: "11px",
                      fontWeight: 700,
                      padding: "2px 8px",
                      borderRadius: "4px",
                      border: "1px solid rgba(16, 185, 129, 0.3)"
                    }}>
                      STEP 3
                    </span>
                    <strong style={{ fontSize: "14px", color: "#f1f5f9" }}>Link / Connect to the PoViShield Server</strong>
                  </div>
                  <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#94a3b8" }}>
                    Generate a pairing code on the website (Fleet / Devices -&gt; Pair Device) and run:
                  </p>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <button
                    className="primary-button"
                    onClick={handleGeneratePairingCode}
                    disabled={generatingCode}
                    style={{
                      padding: "4px 12px",
                      fontSize: "11px",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "5px",
                      background: pairingCode ? "rgba(16, 185, 129, 0.2)" : undefined,
                      borderColor: "#10b981",
                      color: "#34d399"
                    }}
                  >
                    <Key size={13} className={generatingCode ? "spin-icon" : ""} />
                    {generatingCode ? "Generating…" : pairingCode ? `Code: ${pairingCode} (Re-generate)` : "Generate Pairing Code"}
                  </button>

                  <button
                    className="secondary-button"
                    onClick={() => copyToClipboard(step3Connect, "step3")}
                    style={{ padding: "4px 8px", fontSize: "11px" }}
                  >
                    {copiedStep === "step3" ? <Check size={13} style={{ color: "#34d399" }} /> : <Copy size={13} />}
                    {copiedStep === "step3" ? "Copied" : "Copy Command"}
                  </button>
                </div>
              </div>

              {pairingError && (
                <div style={{ fontSize: "11px", color: "#f87171", marginBottom: "8px" }}>
                  {pairingError}
                </div>
              )}

              <div style={{
                background: "#030712",
                border: "1px solid #1e293b",
                borderRadius: "6px",
                padding: "8px 12px",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "#e2e8f0",
                marginBottom: "8px"
              }}>
                <span style={{ overflowX: "auto", whiteSpace: "nowrap" }}>
                  <span style={{ color: "#10b981" }}>$ </span>
                  ./povishield connect {serverUrl} --code <span style={{ color: pairingCode ? "#34d399" : "#fbbf24", fontWeight: 700 }}>{codeParam}</span>
                </span>
              </div>

              <div style={{
                fontSize: "11px",
                color: "#38bdf8",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "rgba(56, 189, 248, 0.08)",
                padding: "6px 10px",
                borderRadius: "4px"
              }}>
                <span>💡</span>
                <span>
                  (On first execution, it will automatically download <code>povishield_agent.py</code> to <code>~/.povishield/</code> and store your server configuration).
                </span>
              </div>

              <div style={{ marginTop: "6px", fontSize: "11px", color: "#64748b" }}>
                <span>Root / Sudo variation: </span>
                <code
                  onClick={() => copyToClipboard(step3Sudo, "step3sudo")}
                  style={{ cursor: "pointer", color: "#94a3b8" }}
                  title="Click to copy sudo command"
                >
                  {step3Sudo}
                </code>
              </div>
            </div>

            {/* STEP 4 */}
            <div style={{
              background: "rgba(11, 19, 34, 0.75)",
              border: "1px solid rgba(56, 189, 248, 0.3)",
              borderRadius: "8px",
              padding: "16px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{
                      background: "rgba(168, 85, 247, 0.15)",
                      color: "#c084fc",
                      fontSize: "11px",
                      fontWeight: 700,
                      padding: "2px 8px",
                      borderRadius: "4px",
                      border: "1px solid rgba(168, 85, 247, 0.3)"
                    }}>
                      STEP 4
                    </span>
                    <strong style={{ fontSize: "14px", color: "#f1f5f9" }}>Run ./povishield watch</strong>
                  </div>
                  <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#94a3b8" }}>
                    Run <code>./povishield watch</code> (You can also run <code>./povishield monitor</code>)
                  </p>
                </div>

                <div style={{ display: "flex", gap: "6px" }}>
                  <button
                    className="primary-button"
                    onClick={() => copyToClipboard(step4Watch, "step4watch")}
                    style={{ padding: "4px 10px", fontSize: "11px", background: "#065f46", borderColor: "#10b981", color: "#34d399" }}
                  >
                    {copiedStep === "step4watch" ? <Check size={13} /> : <Copy size={13} />}
                    {copiedStep === "step4watch" ? "Copied" : "Copy ./povishield watch"}
                  </button>
                  <button
                    className="secondary-button"
                    onClick={() => copyToClipboard(step4Monitor, "step4mon")}
                    style={{ padding: "4px 8px", fontSize: "11px" }}
                  >
                    {copiedStep === "step4mon" ? <Check size={13} /> : <Copy size={13} />}
                    {copiedStep === "step4mon" ? "Copied" : "./povishield monitor"}
                  </button>
                </div>
              </div>

              <div style={{
                background: "#030712",
                border: "1px solid #1e293b",
                borderRadius: "6px",
                padding: "8px 12px",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "#e2e8f0",
                marginBottom: "12px"
              }}>
                <span style={{ overflowX: "auto", whiteSpace: "nowrap" }}>
                  <span style={{ color: "#10b981" }}>$ </span>./povishield watch
                </span>
              </div>

              {/* Live Streaming Outputs Panel */}
              <div>
                <div style={{ fontSize: "12px", fontWeight: 600, color: "#e2e8f0", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Activity size={14} color="#34d399" />
                  <span>This terminal will now display live streaming output with:</span>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "10px" }}>
                  {/* Feature 1 */}
                  <div style={{
                    background: "rgba(15, 23, 42, 0.7)",
                    border: "1px solid #1e293b",
                    borderRadius: "6px",
                    padding: "10px 12px"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#34d399", fontWeight: 600, fontSize: "12px" }}>
                      <ShieldCheck size={16} />
                      <span>Device Identity & Seccomp Sandbox status</span>
                    </div>
                    <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#94a3b8" }}>
                      Hardware UUID, hostname, OS kernel probe, and active seccomp-bpf kill enforcement verification.
                    </p>
                  </div>

                  {/* Feature 2 */}
                  <div style={{
                    background: "rgba(15, 23, 42, 0.7)",
                    border: "1px solid #1e293b",
                    borderRadius: "6px",
                    padding: "10px 12px"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#38bdf8", fontWeight: 600, fontSize: "12px" }}>
                      <Server size={16} />
                      <span>Live Dispatched Tasks & Remote Broadcasts</span>
                    </div>
                    <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#94a3b8" }}>
                      Instant execution notifications, remote workload dispatches, and multi-node fleet synchronization.
                    </p>
                  </div>

                  {/* Feature 3 */}
                  <div style={{
                    background: "rgba(15, 23, 42, 0.7)",
                    border: "1px solid #1e293b",
                    borderRadius: "6px",
                    padding: "10px 12px"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#fbbf24", fontWeight: 600, fontSize: "12px" }}>
                      <Cpu size={16} />
                      <span>Kernel Syscalls Observed & Security Verdicts</span>
                    </div>
                    <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#94a3b8" }}>
                      Dynamic ptrace/seccomp trace stream, SIGSYS trap containment, and divergence integrity checking.
                    </p>
                  </div>

                  {/* Feature 4 */}
                  <div style={{
                    background: "rgba(15, 23, 42, 0.7)",
                    border: "1px solid #1e293b",
                    borderRadius: "6px",
                    padding: "10px 12px"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#f472b6", fontWeight: 600, fontSize: "12px" }}>
                      <ShieldAlert size={16} />
                      <span>Interactive Security Approval Prompts</span>
                    </div>
                    <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#94a3b8" }}>
                      Direct interactive prompts for approval-required workflows with live operator verdicts in real-time.
                    </p>
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>
      )}
    </div>
  );
}
