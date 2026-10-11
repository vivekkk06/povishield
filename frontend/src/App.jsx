import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck, LayoutDashboard, Activity, FileText,
  FlaskConical, Settings, ShieldAlert, Cpu,
  LockKeyhole, Gauge, ChevronRight, Menu, RefreshCw, Play, Square
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar
} from "recharts";
import "./App.css";

const API = "http://127.0.0.1:8000/api";

const navigation = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Activity Monitor", icon: Activity },
  { name: "Syscall Profile", icon: Cpu },
  { name: "Policy Explorer", icon: FileText },
  { name: "Experiments", icon: FlaskConical }
];

async function getJSON(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}

function Metric({ icon: Icon, label, value, detail }) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span>{label}</span><Icon size={19} />
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

function App() {
  const [page, setPage] = useState("Overview");
  const [menuOpen, setMenuOpen] = useState(false);
  const [overview, setOverview] = useState(null);
  const [policies, setPolicies] = useState(null);
  const [experiments, setExperiments] = useState(null);
  const [health, setHealth] = useState(null);
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
    } catch (err) {
      setError(`${err.message}. Check that the FastAPI server is running on port 8000.`);
    } finally {
      setLoading(false);
    }
  }

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

  const aggregate = overview?.aggregate;
  const targets = overview?.targets ?? [];

  const chartData = targets.map(t => ({
    target: t.target,
    coverage: t.heldout_coverage_pct,
    compatibility: t.compat_pct,
    overhead: t.overhead_pct?.median ?? 0
  }));

  return (
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={25} /></div>
          <div><h2>PoViShield</h2><span>APPLICATION SECURITY</span></div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav>
          {navigation.map(item => {
            const Icon = item.icon;
            return (
              <button key={item.name}
                className={`nav-item ${page === item.name ? "active" : ""}`}
                onClick={() => { setPage(item.name); setMenuOpen(false); }}>
                <Icon size={19} /><span>{item.name}</span>
                {page === item.name && <ChevronRight size={16} />}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="engine-status">
            <span className="status-dot" />
            <div>
              <strong>{health?.status === "ok" ? "API connected" : "Checking API"}</strong>
              <p>{health?.engine_connected ? "Engine connected" : "Engine integration pending"}</p>
            </div>
          </div>
          <button className="nav-item" onClick={() => setPage("Settings")}>
            <Settings size={19} /><span>Settings</span>
          </button>
          <div className="version">PoViShield · Research Prototype</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <button className="menu-button" onClick={() => setMenuOpen(!menuOpen)}>
            <Menu size={22} />
          </button>
          <div className="breadcrumb">Workspace <span>/</span> {page}</div>
          <div className="top-actions">
            <span className="demo-badge">LOCAL RESULTS</span>
            <button className="icon-button" onClick={loadData} title="Refresh data">
              <RefreshCw size={17} />
            </button>
            <div className="avatar">VB</div>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">LINUX SECURITY RESEARCH</div>
              <h1>{page}</h1>
              <p>Explore PoViShield's measured local evaluation results.</p>
            </div>
            <button className="secondary-button" onClick={loadData}>
              <RefreshCw size={16} /> Refresh results
            </button>
          </div>

          {error && (
            <div className="notice">
              <ShieldAlert size={19} />
              <div><strong>API connection problem</strong><p>{error}</p></div>
            </div>
          )}

          {loading && <div className="panel"><p>Loading results from the local API…</p></div>}

          {!loading && !error && overview && (
            <>
              <div className="notice">
                <ShieldAlert size={19} />
                <div>
                  <strong>Measured local results — not live monitoring</strong>
                  <p>
                    Data source: {overview.source}. These are existing benchmark
                    artifacts. No live syscall events are connected, and these
                    results do not prove that the sandbox is secure.
                  </p>
                </div>
              </div>

              {page === "Overview" && (
                <>
                  <section className="metrics-grid">
                    <Metric icon={Activity} label="Programs evaluated"
                      value={aggregate.targets} detail="Local benchmark targets" />
                    <Metric icon={LockKeyhole} label="Attack-surface reduction"
                      value={`${aggregate.avg_attack_surface_reduction_pct}%`}
                      detail="Reported average" />
                    <Metric icon={ShieldAlert} label="False kills"
                      value={aggregate.total_false_kills}
                      detail="Reported compatibility failures" />
                    <Metric icon={Gauge} label="Median overhead"
                      value={`${aggregate.avg_median_overhead_pct}%`}
                      detail="Reported average of target medians" />
                  </section>

                  <section className="content-grid">
                    <div className="panel chart-panel">
                      <div className="panel-heading">
                        <div><h3>Held-out coverage</h3>
                          <p>Per-program evaluation results</p></div>
                      </div>
                      <div className="chart">
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={chartData}>
                            <CartesianGrid stroke="#263247" strokeDasharray="3 3" vertical={false} />
                            <XAxis dataKey="target" stroke="#78869b" tickLine={false} axisLine={false} />
                            <YAxis domain={[0, 100]} stroke="#78869b" tickLine={false} axisLine={false} />
                            <Tooltip contentStyle={{ background: "#111a2a", border: "1px solid #2b3a50", borderRadius: 10 }} />
                            <Area type="monotone" dataKey="coverage" name="Held-out coverage (%)"
                              stroke="#45d6a5" fill="#45d6a5" fillOpacity={0.12} />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                    <div className="panel">
                      <div className="panel-heading">
                        <div><h3>Evaluation environment</h3>
                          <p>Read from results.json</p></div>
                        <Cpu size={20} className="muted-icon" />
                      </div>
                      {Object.entries(overview.environment).map(([key, value]) => (
                        <div className="policy-row" key={key}>
                          <span>{key.replaceAll("_", " ")}</span>
                          <strong>{String(value)}</strong>
                        </div>
                      ))}
                      <div className="policy-row">
                        <span>Live monitoring</span>
                        <strong className={health?.live_events_connected ? "" : "warning-text"}>
                          {error ? "API unavailable" : health?.live_events_connected ? "Active session" : "No active session"}
                        </strong>
                      </div>
                    </div>
                  </section>

                  <section className="panel events-section">
                    <div className="panel-heading">
                      <div><h3>Program evaluation</h3>
                        <p>Actual records from the local evaluation JSON</p></div>
                    </div>
                    <div className="table-wrap">
                      <table>
                        <thead><tr>
                          <th>PROGRAM</th><th>ALLOWED</th><th>SURFACE REDUCTION</th>
                          <th>COVERAGE</th><th>COMPATIBILITY</th><th>FALSE KILLS</th>
                        </tr></thead>
                        <tbody>{targets.map(t => (
                          <tr key={t.target}>
                            <td className="process-cell">{t.target}</td>
                            <td>{t.allowed_syscalls}/{t.total_syscalls}</td>
                            <td>{t.attack_surface_reduction_pct}%</td>
                            <td>{t.heldout_coverage_pct}%</td>
                            <td>{t.compat_pct}%</td>
                            <td>{t.false_kills}</td>
                          </tr>
                        ))}</tbody>
                      </table>
                    </div>
                  </section>
                </>
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
                  <label className="monitor-command-label" htmlFor="monitor-command">Command as a JSON argv array (no shell)</label>
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
                      <thead><tr><th>SEQ</th><th>PID</th><th>PHASE</th><th>SYSCALL</th><th>NUMBER</th><th>RETURN VALUE</th></tr></thead>
                      <tbody>{[...monitorEvents].reverse().map((event, index) => <tr key={`live-${event.seq}-${event.pid}-${event.phase}-${index}`}>
                        <td className="time-cell">{event.seq}</td><td>{event.pid}</td>
                        <td><span className={`phase-tag ${event.phase === "entry" ? "phase-entry" : "phase-exit"}`}>{event.phase}</span></td>
                        <td className="process-cell">{event.syscall}</td><td><code>{event.syscall_nr}</code></td>
                        <td>{event.phase === "exit" && event.return_value !== undefined ? <code>{event.return_value}</code> : <span className="muted">—</span>}</td>
                      </tr>)}</tbody>
                    </table></div>
                    <p className="footnote">Polling uses a byte cursor to avoid rereading the trace. The browser retains the latest 1,000 events; the session trace is stored separately under results/.</p>
                  </>}
                </section>
                <section className="panel events-section">
                  <div className="panel-heading activity-heading">
                    <div>
                      <h3>Syscall activity</h3>
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
                      <p>This view reads a saved JSONL trace. It does not continuously monitor running processes.</p>
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
                        <div><span>Valid records in read window</span><strong>{eventsData.total_valid_records_in_read_window}</strong></div>
                        <div><span>Malformed records</span><strong>{eventsData.malformed_records_in_read_window}</strong></div>
                        <div><span>Source</span><strong className="source-value">{eventsData.source}</strong></div>
                      </div>

                      {eventsData.events.length === 0 ? (
                        <p className="muted activity-message">No recorded events found. Run the learning tracer with its --events option, then copy the resulting JSONL file to results/syscall-events.jsonl.</p>
                      ) : (
                        <div className="table-wrap activity-table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>SEQ</th><th>PID</th><th>PHASE</th>
                                <th>SYSCALL</th><th>NUMBER</th><th>RETURN VALUE</th>
                              </tr>
                            </thead>
                            <tbody>
                              {eventsData.events.map((event, index) => (
                                <tr key={`${event.seq}-${event.pid}-${event.phase}-${index}`}>
                                  <td className="time-cell">{event.seq ?? "—"}</td>
                                  <td>{event.pid ?? "—"}</td>
                                  <td>
                                    <span className={`phase-tag ${event.phase === "entry" ? "phase-entry" : "phase-exit"}`}>
                                      {event.phase ?? "unknown"}
                                    </span>
                                  </td>
                                  <td className="process-cell">{event.syscall ?? "unknown"}</td>
                                  <td><code>{event.syscall_nr ?? "—"}</code></td>
                                  <td>{event.phase === "exit" && event.return_value !== undefined
                                    ? <code>{event.return_value}</code>
                                    : <span className="muted">—</span>}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                      <p className="footnote">Newest events are listed first. Entry records show syscall attempts; exit records include the return value when available. This is trace data, not a policy enforcement verdict.</p>
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

                  <div className="trace-status">
                    <span className="trace-status-dot" />
                    <div>
                      <strong>Recorded trace — not live</strong>
                      <p>Invocation counts use entry records only, so an entry/exit pair counts as one observed invocation. This is not a complete profile guarantee.</p>
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
                    const allEvents = Array.isArray(eventsData.events) ? eventsData.events : [];
                    const allRows = (profileData?.syscalls ?? []).map(item => ({
                      name: item.syscall, number: item.syscall_nr, count: item.count
                    }));
                    const totalInvocations = profileData?.entry_records ?? 0;
                    const uniqueSyscalls = profileData?.unique_syscalls ?? allRows.length;
                    const visibleRows = allRows.filter(row => {
                      const query = profileSearch.trim().toLowerCase();
                      const matchesSearch = !query || row.name.toLowerCase().includes(query) || String(row.number ?? "").includes(query);
                      if (profilePhase === "entry") return matchesSearch;
                      return matchesSearch;
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

                        <div className="table-wrap activity-table-wrap profile-table-wrap">
                          <table>
                            <thead><tr><th>SYSCALL</th><th>NUMBER</th><th>INVOCATIONS</th><th>SHARE OF ENTRIES</th></tr></thead>
                            <tbody>
                              {visibleRows.map(row => (
                                <tr key={`table-${row.name}`}>
                                  <td className="process-cell">{row.name}</td>
                                  <td><code>{row.number ?? "—"}</code></td>
                                  <td>{row.count}</td>
                                  <td>{totalInvocations ? `${((row.count / totalInvocations) * 100).toFixed(1)}%` : "0.0%"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        <p className="footnote">Frequency counts are aggregated by the API across the complete saved JSONL trace, not just the newest 100 events. The event table elsewhere still displays a limited recent window. Counts describe this trace only and should not be used alone to generate a production security policy.</p>
                      </>
                    );
                  })()}
                </section>
              )}

              {page === "Policy Explorer" && (
                <section className="panel">
                  <div className="panel-heading">
                    <div><h3>Generated policy artifacts</h3>
                      <p>Read-only listing from results/*.json</p></div>
                  </div>
                  {policies?.items?.length ? policies.items.map(item => (
                    <div className="policy-row" key={item.name}>
                      <span>{item.name}</span>
                      <strong>{item.size_bytes ?? 0} bytes</strong>
                    </div>
                  )) : <p className="muted">No policy artifacts returned.</p>}
                  <p className="footnote">{policies?.note}</p>
                  <p className="footnote">File presence does not prove a policy is safe or currently enforced.</p>
                </section>
              )}

              {page === "Experiments" && (
                <section className="panel">
                  <div className="panel-heading">
                    <div><h3>Benchmark results</h3><p>Local evaluation artifacts</p></div>
                  </div>
                  <div className="chart" style={{ height: 300 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={chartData}>
                        <CartesianGrid stroke="#263247" strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="target" stroke="#78869b" />
                        <YAxis stroke="#78869b" />
                        <Tooltip contentStyle={{ background: "#111a2a", border: "1px solid #2b3a50" }} />
                        <Bar dataKey="compatibility" name="Compatibility (%)" fill="#45d6a5" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="notice">
                    <ShieldAlert size={19} />
                    <div><strong>Known limitations</strong>
                      <p>Previous tests reported a host-filesystem escape and path-traversal weakness. Namespace results also require investigation. Do not interpret these metrics as proof of sandbox security.</p>
                    </div>
                  </div>
                  <h3>Evaluation report</h3>
                  <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: "#9eafc4", fontSize: 11 }}>
                    {experiments?.report ?? "No report available."}
                  </pre>
                </section>
              )}

              {page === "Settings" && (
                <section className="panel">
                  <h3>Project configuration</h3>
                  <div className="policy-row"><span>API</span><strong>Connected</strong></div>
                  <div className="policy-row"><span>Data source</span><strong>{overview.source}</strong></div>
                  <div className="policy-row"><span>Engine connected</span><strong>No</strong></div>
                  <div className="policy-row"><span>Live events</span><strong>No</strong></div>
                </section>
              )}
            </>
          )}

          <footer className="footer">
            <span><span className="status-dot" /> Local research workspace</span>
            <span>PoViShield · Prototype UI</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

export default App;
