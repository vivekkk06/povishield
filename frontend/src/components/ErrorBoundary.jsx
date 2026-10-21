import React from 'react';
import { ShieldAlert, RefreshCw, Home, Terminal } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("PoViShield Uncaught Component Error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (window.location.hash) {
      window.location.hash = "#overview";
    }
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      const errorMessage = this.state.error?.message || String(this.state.error);
      const componentStack = this.state.errorInfo?.componentStack || "";

      return (
        <div style={{
          minHeight: "60vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "24px",
          color: "#e2e8f0",
          fontFamily: "var(--font-sans, system-ui, -apple-system, sans-serif)"
        }}>
          <div style={{
            maxWidth: "680px",
            width: "100%",
            background: "linear-gradient(180deg, #0e1726 0%, #080d1a 100%)",
            border: "1px solid #334155",
            borderRadius: "12px",
            padding: "28px",
            boxShadow: "0 20px 40px rgba(0,0,0,0.6), 0 0 0 1px rgba(239, 68, 68, 0.2)"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "14px", marginBottom: "16px" }}>
              <div style={{
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                borderRadius: "10px",
                padding: "10px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center"
              }}>
                <ShieldAlert size={28} color="#f87171" />
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: "18px", fontWeight: "700", color: "#f87171", letterSpacing: "-0.01em" }}>
                  Dashboard Exception Isolated
                </h2>
                <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#94a3b8" }}>
                  A component runtime error was safely intercepted by PoViShield fail-closed defense.
                </p>
              </div>
            </div>

            <div style={{
              background: "#050914",
              border: "1px solid #1e293b",
              borderRadius: "8px",
              padding: "12px 16px",
              marginBottom: "20px"
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
                <Terminal size={13} color="#f59e0b" />
                <span style={{ fontSize: "11px", fontWeight: "600", color: "#f59e0b", letterSpacing: "0.5px" }}>
                  ERROR DIAGNOSTIC
                </span>
              </div>
              <pre style={{
                margin: 0,
                fontSize: "12px",
                color: "#cbd5e1",
                fontFamily: "var(--font-mono, monospace)",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all"
              }}>
                {errorMessage}
              </pre>
              {componentStack && (
                <details style={{ marginTop: "10px" }}>
                  <summary style={{ fontSize: "11px", color: "#64748b", cursor: "pointer" }}>
                    View Component Stack
                  </summary>
                  <pre style={{
                    marginTop: "6px",
                    fontSize: "10px",
                    color: "#64748b",
                    fontFamily: "var(--font-mono, monospace)",
                    whiteSpace: "pre-wrap",
                    maxHeight: "120px",
                    overflowY: "auto"
                  }}>
                    {componentStack}
                  </pre>
                </details>
              )}
            </div>

            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", justifyContent: "flex-end" }}>
              <button
                onClick={this.handleReset}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "8px 16px",
                  background: "#1e293b",
                  border: "1px solid #334155",
                  borderRadius: "6px",
                  color: "#e2e8f0",
                  fontSize: "12px",
                  fontWeight: "600",
                  cursor: "pointer"
                }}
              >
                <Home size={14} /> Return to Overview
              </button>
              <button
                onClick={this.handleReload}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "8px 16px",
                  background: "#0284c7",
                  border: "1px solid #38bdf8",
                  borderRadius: "6px",
                  color: "#ffffff",
                  fontSize: "12px",
                  fontWeight: "600",
                  cursor: "pointer"
                }}
              >
                <RefreshCw size={14} /> Reload Page
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
