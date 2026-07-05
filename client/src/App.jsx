import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, ArcElement, Title, Tooltip, Legend, Filler,
} from "chart.js";
import { Bar, Doughnut, Line } from "react-chartjs-2";
import {
  fetchStats,
  fetchLogs,
  clearLogs,
  checkHealth,
  fetchHistory,
  fetchDemoStatus,
  startDemo,
  stopDemo,
} from "./utils/api.js";

ChartJS.register(
  CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, ArcElement, Title, Tooltip, Legend, Filler
);

// ── Constants ─────────────────────────────────────────────────────────────────
const POLL_INTERVAL = 3000;
const CRITICAL_CATEGORIES = new Set(["dos", "u2r"]);

const CATEGORY_COLORS = {
  dos:     "#ff3366",
  probe:   "#ff8c00",
  r2l:     "#ffd700",
  u2r:     "#9d4edd",
  anomaly: "#00d4ff",
  normal:  "#00ff88",
  unknown: "#607080",
};

const SEVERITY_MAP = {
  dos:     "CRITICAL",
  probe:   "HIGH",
  r2l:     "HIGH",
  u2r:     "CRITICAL",
  anomaly: "MEDIUM",
  normal:  "INFO",
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (str === undefined || str === null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

function fmt(n) {
  if (n === undefined || n === null) return "—";
  return Number(n).toLocaleString();
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function triggerCsvDownload(filename, content) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildCsv(logs) {
  const header = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "prediction", "attack_category", "is_attack", "confidence", "model_used",
  ];
  const rows = logs.map((log) => header.map((key) => {
    const value = log[key] ?? "";
    return `"${String(value).replaceAll('"', '""')}"`;
  }).join(","));
  return [header.join(","), ...rows].join("\n");
}

function openPrintableReport({ stats, logs, history, demoStatus }) {
  const popup = window.open("", "_blank", "noopener,noreferrer,width=1100,height=800");
  if (!popup) throw new Error("Pop-up blocked");

  const rows = logs.map((log) => `
    <tr>
      <td>${escapeHtml(new Date(log.timestamp || Date.now()).toLocaleString())}</td>
      <td>${escapeHtml(log.src_ip || "—")}</td>
      <td>${escapeHtml(log.dst_ip || "—")}</td>
      <td>${escapeHtml(log.protocol || "—")}</td>
      <td>${escapeHtml(log.prediction || "—")}</td>
      <td>${escapeHtml((log.attack_category || "normal").toUpperCase())}</td>
      <td>${log.confidence != null ? Number(log.confidence).toFixed(1) : "—"}</td>
      <td>${escapeHtml(log.model_used || "—")}</td>
    </tr>
  `).join("");

  const historyRows = history.slice(-10).map((point) => `
    <tr>
      <td>${escapeHtml(new Date(point.time).toLocaleTimeString())}</td>
      <td>${point.total_cumulative || 0}</td>
      <td>${point.attacks_cumulative || 0}</td>
    </tr>
  `).join("");

  const html = `
    <html>
      <head>
        <title>Threat-IQ Report</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 24px; color: #111827; }
          h1, h2 { margin: 0 0 12px; }
          .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
          .card { border: 1px solid #d1d5db; border-radius: 6px; padding: 12px; }
          .label { font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 1px; }
          .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
          table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
          th, td { border: 1px solid #d1d5db; padding: 8px; text-align: left; }
          th { background: #f3f4f6; }
          .meta { margin-top: 8px; color: #4b5563; font-size: 13px; }
          .toolbar { position: sticky; top: 0; background: #ffffff; padding: 0 0 16px; margin-bottom: 16px; border-bottom: 1px solid #e5e7eb; }
          .button { appearance: none; border: 1px solid #111827; background: #111827; color: #ffffff; padding: 10px 14px; border-radius: 6px; font-size: 14px; cursor: pointer; }
          .button.secondary { background: #ffffff; color: #111827; margin-left: 8px; }
          @media print {
            .toolbar { display: none; }
            body { padding: 0; }
          }
        </style>
      </head>
      <body>
        <div class="toolbar">
          <button class="button" onclick="window.print()">Save as PDF</button>
          <button class="button secondary" onclick="window.close()">Close</button>
        </div>
        <h1>Threat-IQ Security Analysis Report</h1>
        <div class="meta">Generated: ${escapeHtml(new Date().toLocaleString())}</div>
        <div class="meta">Storage: ${escapeHtml((stats?.storage || "unknown").toUpperCase())} | Demo mode: ${escapeHtml(demoStatus?.running ? "RUNNING" : "IDLE")}</div>
        <div class="grid">
          <div class="card"><div class="label">Total Packets</div><div class="value">${stats?.total_packets || 0}</div></div>
          <div class="card"><div class="label">Attack Packets</div><div class="value">${stats?.attack_packets || 0}</div></div>
          <div class="card"><div class="label">Normal Packets</div><div class="value">${stats?.normal_packets || 0}</div></div>
          <div class="card"><div class="label">Attack Rate</div><div class="value">${stats?.attack_rate || 0}%</div></div>
        </div>
        <h2>Recent Logs</h2>
        <table>
          <thead>
            <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Prediction</th><th>Category</th><th>Confidence</th><th>Model</th></tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="8">No logs available</td></tr>'}</tbody>
        </table>
        <h2 style="margin-top:24px;">Traffic History</h2>
        <table>
          <thead><tr><th>Time</th><th>Total Cumulative</th><th>Attack Cumulative</th></tr></thead>
          <tbody>${historyRows || '<tr><td colspan="3">No history available</td></tr>'}</tbody>
        </table>
        <script>
          window.addEventListener("load", function () {
            setTimeout(function () {
              try { window.focus(); } catch (e) {}
            }, 50);
          });
        </script>
      </body>
    </html>
  `;
  popup.document.open();
  popup.document.write(html);
  popup.document.close();
  popup.focus();
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StatusBar({ connected }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8,
      fontSize: 12, color: "var(--text-2)", fontFamily: "var(--mono)",
    }}>
      <span className={`dot ${connected ? "dot-green dot-pulse" : "dot-red"}`} />
      {connected ? "BACKEND ONLINE" : "BACKEND OFFLINE"}
    </div>
  );
}

function StatCard({ label, value, sub, color = "var(--accent)", big = false }) {
  return (
    <div className="card" style={{ padding: "16px 20px", flex: 1, minWidth: 130 }}>
      <div style={{ fontSize: 11, letterSpacing: 2, color: "var(--text-2)", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{
        fontSize: big ? 36 : 28,
        fontWeight: 700,
        fontFamily: "var(--mono)",
        color,
        lineHeight: 1,
      }}>
        {value}
      </div>
      {sub && (
        <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-3)" }}>{sub}</div>
      )}
    </div>
  );
}

function CategoryBadge({ cat }) {
  const c = CATEGORY_COLORS[cat] || CATEGORY_COLORS.unknown;
  const sev = SEVERITY_MAP[cat] || "INFO";
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: 2,
      border: `1px solid ${c}`,
      color: c,
      fontSize: 11,
      fontFamily: "var(--mono)",
      letterSpacing: 1,
    }}>
      {sev}
    </span>
  );
}

function LogTable({ logs }) {
  if (!logs.length) {
    return (
      <div style={{
        padding: "40px 0", textAlign: "center",
        color: "var(--text-3)", fontFamily: "var(--mono)", fontSize: 13,
      }}>
        NO PACKETS LOGGED — start capture.py to begin monitoring
      </div>
    );
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{
            background: "var(--bg-panel)",
            color: "var(--text-3)",
            fontFamily: "var(--mono)",
            fontSize: 11,
            letterSpacing: 1,
          }}>
            {["TIME","SRC IP","DST IP","PROTO","PREDICTION","CATEGORY","CONF %","MODEL"].map(h => (
              <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 400 }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {logs.map((log, i) => {
            const isAtk = log.is_attack;
            const cat   = log.attack_category || "normal";
            const color = CATEGORY_COLORS[cat];
            return (
              <tr
                key={log.id || i}
                className={i === 0 ? "new-row" : ""}
                style={{
                  borderBottom: "1px solid var(--border)",
                  borderLeft: isAtk ? `2px solid ${color}` : "2px solid transparent",
                  background: isAtk
                    ? `rgba(${cat === "dos" || cat === "u2r" ? "255,51,102" : "255,140,0"},0.04)`
                    : "transparent",
                }}
              >
                <td style={{ padding: "7px 12px", fontFamily: "var(--mono)", color: "var(--text-3)", whiteSpace:"nowrap" }}>
                  {log.timestamp ? timeAgo(log.timestamp) : "—"}
                </td>
                <td style={{ padding: "7px 12px", fontFamily: "var(--mono)", color: "var(--text-2)" }}>
                  {log.src_ip || "—"}
                </td>
                <td style={{ padding: "7px 12px", fontFamily: "var(--mono)", color: "var(--text-2)" }}>
                  {log.dst_ip || "—"}
                </td>
                <td style={{ padding: "7px 12px", fontFamily: "var(--mono)", color: "var(--accent)" }}>
                  {log.protocol || "—"}
                </td>
                <td style={{ padding: "7px 12px", fontFamily: "var(--mono)", color, fontWeight: 600 }}>
                  {log.prediction || "—"}
                </td>
                <td style={{ padding: "7px 12px" }}>
                  <CategoryBadge cat={cat} />
                </td>
                <td style={{
                  padding: "7px 12px",
                  fontFamily: "var(--mono)",
                  color: (log.confidence || 0) > 90
                    ? "var(--green)"
                    : (log.confidence || 0) > 70
                    ? "var(--yellow)"
                    : "var(--orange)",
                }}>
                  {log.confidence != null ? log.confidence.toFixed(1) : "—"}
                </td>
                <td style={{ padding: "7px 12px", color: "var(--text-3)", fontSize: 11 }}>
                  {log.model_used || "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Charts ────────────────────────────────────────────────────────────────────
const chartDefaults = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { labels: { color: "#7090a8", font: { family: "Share Tech Mono", size: 11 } } },
    tooltip: { backgroundColor: "#0c1622", titleColor: "#00d4ff", bodyColor: "#e0f0ff" },
  },
};

function AttackPieChart({ byCategory }) {
  const cats  = Object.keys(byCategory).filter(k => byCategory[k] > 0);
  const data  = {
    labels:   cats.map(c => c.toUpperCase()),
    datasets: [{
      data:            cats.map(c => byCategory[c]),
      backgroundColor: cats.map(c => CATEGORY_COLORS[c] + "cc"),
      borderColor:     cats.map(c => CATEGORY_COLORS[c]),
      borderWidth:     1,
    }],
  };

  if (!cats.length) {
    return (
      <div style={{
        height: 200, display:"flex", alignItems:"center",
        justifyContent:"center", color:"var(--text-3)",
        fontFamily:"var(--mono)", fontSize:12,
      }}>
        NO ATTACKS DETECTED
      </div>
    );
  }

  return (
    <div style={{ height: 200 }}>
      <Doughnut
        data={data}
        options={{
          ...chartDefaults,
          cutout: "65%",
          plugins: {
            ...chartDefaults.plugins,
            legend: { ...chartDefaults.plugins.legend, position: "right" },
          },
        }}
      />
    </div>
  );
}

function ThreatBarChart({ byCategory }) {
  const cats = ["dos","probe","r2l","u2r","anomaly"];
  const data = {
    labels:   cats.map(c => c.toUpperCase()),
    datasets: [{
      label:           "Packets",
      data:            cats.map(c => byCategory[c] || 0),
      backgroundColor: cats.map(c => CATEGORY_COLORS[c] + "99"),
      borderColor:     cats.map(c => CATEGORY_COLORS[c]),
      borderWidth:     1,
      borderRadius:    2,
    }],
  };
  return (
    <div style={{ height: 200 }}>
      <Bar data={data} options={{
        ...chartDefaults,
        scales: {
          x: { ticks: { color: "#7090a8", font: { family: "Share Tech Mono", size: 11 } },
               grid: { color: "#0f2236" } },
          y: { ticks: { color: "#7090a8", font: { family: "Share Tech Mono" } },
               grid: { color: "#0f2236" } },
        },
      }} />
    </div>
  );
}

function TrafficLineChart({ history, total, attacks }) {
  // Build rolling 10-point snapshot from history or fake it from stats
  const points = history.length > 0 ? history.slice(-10) : [];

  // Generate placeholder labels
  const labels = points.length > 0
    ? points.map((_, i) => `T-${points.length - i}m`)
    : Array.from({ length: 10 }, (_, i) => `T-${10 - i}m`);

  const totalArr   = points.length > 0 ? points.map(p => p.total_cumulative || 0)  : Array(10).fill(0);
  const attackArr  = points.length > 0 ? points.map(p => p.attacks_cumulative || 0) : Array(10).fill(0);

  const data = {
    labels,
    datasets: [
      {
        label: "Total",
        data: totalArr,
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,0.08)",
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: "#00d4ff",
      },
      {
        label: "Attacks",
        data: attackArr,
        borderColor: "#ff3366",
        backgroundColor: "rgba(255,51,102,0.08)",
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: "#ff3366",
      },
    ],
  };

  return (
    <div style={{ height: 200 }}>
      <Line data={data} options={{
        ...chartDefaults,
        scales: {
          x: { ticks: { color: "#7090a8", font: { family: "Share Tech Mono", size: 10 } },
               grid: { color: "#0f2236" } },
          y: { ticks: { color: "#7090a8", font: { family: "Share Tech Mono" } },
               grid: { color: "#0f2236" } },
        },
      }} />
    </div>
  );
}

// ── Alert ticker ──────────────────────────────────────────────────────────────
function AlertTicker({ logs }) {
  const attacks = logs.filter(l => l.is_attack).slice(0, 5);
  if (!attacks.length) return null;

  return (
    <div style={{
      background: "rgba(255,51,102,0.06)",
      border: "1px solid rgba(255,51,102,0.3)",
      borderRadius: 4,
      padding: "8px 16px",
      display: "flex",
      alignItems: "center",
      gap: 12,
      overflow: "hidden",
    }}>
      <span style={{
        fontFamily: "var(--mono)", fontSize: 11,
        color: "var(--red)", letterSpacing: 2,
        whiteSpace: "nowrap",
      }}>
        ⚠ THREAT DETECTED
      </span>
      <div style={{ flex: 1, overflow: "hidden" }}>
        <div style={{
          display: "flex", gap: 20,
          fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-2)",
        }}>
          {attacks.map((a, i) => (
            <span key={i} style={{ whiteSpace: "nowrap" }}>
              <span style={{ color: CATEGORY_COLORS[a.attack_category] }}>
                {a.prediction}
              </span>
              {" "}from {a.src_ip}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function NotificationStack({ alerts, onDismiss }) {
  if (!alerts.length) return null;

  return (
    <div className="notification-stack">
      {alerts.map((alert) => (
        <div key={alert.id} className={`notification-card ${alert.severity}`}>
          <div>
            <div className="notification-title">{alert.title}</div>
            <div className="notification-body">{alert.body}</div>
          </div>
          <button className="notification-close" onClick={() => onDismiss(alert.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

function DemoPanel({ demoStatus, busy, onStart, onStop }) {
  return (
    <div className="card" style={{ padding: 16, marginBottom: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: 2, color: "var(--text-3)", fontFamily: "var(--mono)" }}>
            DEMO MODE
          </div>
          <div style={{ marginTop: 8, color: "var(--text-2)", fontSize: 14 }}>
            Simulate live network traffic to evaluate model accuracy, latency, and threat detection alerts.
          </div>
          <div style={{ marginTop: 8, color: demoStatus?.running ? "var(--green)" : "var(--text-3)", fontFamily: "var(--mono)", fontSize: 12 }}>
            {demoStatus?.running
              ? `RUNNING · ${demoStatus?.config?.duration || 0}s · ${demoStatus?.config?.attacks || 0} attack ratio`
              : "IDLE"}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button className="action-button accent" disabled={busy || demoStatus?.running} onClick={onStart}>
            {busy && !demoStatus?.running ? "STARTING…" : "START DEMO"}
          </button>
          <button className="action-button" disabled={busy || !demoStatus?.running} onClick={onStop}>
            {busy && demoStatus?.running ? "STOPPING…" : "STOP DEMO"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [stats,     setStats]     = useState(null);
  const [logs,      setLogs]      = useState([]);
  const [history,   setHistory]   = useState([]);
  const [connected, setConnected] = useState(false);
  const [loading,   setLoading]   = useState(true);
  const [attackOnly,setAttackOnly] = useState(false);
  const [demoStatus,setDemoStatus] = useState({ running: false });
  const [demoBusy,  setDemoBusy]  = useState(false);
  const [alerts,    setAlerts]    = useState([]);
  const timerRef = useRef(null);
  const seenAlertIdsRef = useRef(new Set());

  const poll = useCallback(async () => {
    try {
      const ok = await checkHealth();
      setConnected(ok);
      if (!ok) return;

      const [s, l, h, d] = await Promise.all([
        fetchStats(),
        fetchLogs(100, attackOnly),
        fetchHistory(),
        fetchDemoStatus(),
      ]);
      setStats(s);
      setLogs(l.logs || []);
      setHistory(h.history || []);
      setDemoStatus(d);
    } catch {
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, [attackOnly]);

  useEffect(() => {
    poll();
    timerRef.current = setInterval(poll, POLL_INTERVAL);
    return () => clearInterval(timerRef.current);
  }, [poll]);

  const handleClear = async () => {
    await clearLogs();
    setLogs([]);
    await poll();
  };

  const pushAlert = useCallback((title, body, severity = "critical") => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setAlerts((current) => [...current.slice(-2), { id, title, body, severity }]);
    window.setTimeout(() => {
      setAlerts((current) => current.filter((item) => item.id !== id));
    }, 6000);
  }, []);

  useEffect(() => {
    for (const log of logs) {
      if (!log.id || seenAlertIdsRef.current.has(log.id)) continue;
      seenAlertIdsRef.current.add(log.id);
      if (!log.is_attack || !CRITICAL_CATEGORIES.has(log.attack_category)) continue;

      const title = `${(log.attack_category || "attack").toUpperCase()} attack detected`;
      const body = `${log.prediction || "Threat"} from ${log.src_ip || "unknown source"} to ${log.dst_ip || "unknown destination"}`;
      pushAlert(title, body, "critical");

      if (typeof window !== "undefined" && "Notification" in window) {
        if (Notification.permission === "granted") {
          new Notification(title, { body });
        }
      }
    }
  }, [logs, pushAlert]);

  const ensureNotificationPermission = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) return;
    if (Notification.permission === "default") {
      try {
        await Notification.requestPermission();
      } catch {
        return;
      }
    }
  };

  const handleExportCsv = () => {
    const filename = `nids-report-${new Date().toISOString().replaceAll(":", "-")}.csv`;
    triggerCsvDownload(filename, buildCsv(logs));
  };

  const handleExportPdf = () => {
    openPrintableReport({ stats, logs, history, demoStatus });
  };

  const handleDemoStart = async () => {
    setDemoBusy(true);
    try {
      await ensureNotificationPermission();
      const response = await startDemo({ duration: 90, rate: 2, attacks: 0.2, clear_existing: true });
      setDemoStatus(response.status || { running: true });
      pushAlert("Demo mode started", "Controlled attack simulation is now feeding the dashboard.", "info");
      await poll();
    } catch (err) {
      pushAlert("Demo start failed", err.message, "critical");
    } finally {
      setDemoBusy(false);
    }
  };

  const handleDemoStop = async () => {
    setDemoBusy(true);
    try {
      const response = await stopDemo();
      setDemoStatus(response.status || { running: false });
      pushAlert("Demo mode stopped", "Simulator process stopped.", "info");
      await poll();
    } catch (err) {
      pushAlert("Demo stop failed", err.message, "critical");
    } finally {
      setDemoBusy(false);
    }
  };

  const byCategory = stats?.by_category || { dos:0, probe:0, r2l:0, u2r:0, anomaly:0 };
  const uptime = stats
    ? `${Math.floor(stats.uptime_seconds / 60)}m ${stats.uptime_seconds % 60}s`
    : "—";

  return (
    <div style={{
      minHeight: "100vh",
      background: "var(--bg-base)",
      fontFamily: "var(--sans)",
    }}>
      <NotificationStack alerts={alerts} onDismiss={(id) => setAlerts((current) => current.filter((item) => item.id !== id))} />
      {/* ── Header ── */}
      <header style={{
        background: "var(--bg-panel)",
        borderBottom: "1px solid var(--border-glow)",
        padding: "0 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        height: 56,
        position: "sticky",
        top: 0,
        zIndex: 100,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {/* Shield icon */}
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 6V12C3 16.97 7.02 21.57 12 23C16.98 21.57 21 16.97 21 12V6L12 2Z"
              stroke="#00d4ff" strokeWidth="1.5" fill="rgba(0,212,255,0.08)" />
            <path d="M9 12L11 14L15 10" stroke="#00ff88" strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round" />
          </svg>

          <div>
            <div style={{
              fontFamily: "var(--sans)", fontSize: 20, fontWeight: 700,
              color: "var(--accent)", letterSpacing: 2, textTransform: "uppercase",
              lineHeight: 1.1
            }}>
              Threat-IQ
            </div>
            <div style={{ fontSize: 10, color: "var(--text-3)", letterSpacing: 1.5 }}>
              NETWORK INTRUSION DETECTION SYSTEM
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <div style={{
            fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-3)",
          }}>
            UPTIME: <span style={{ color: "var(--text-2)" }}>{uptime}</span>
          </div>
          <div style={{
            fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-3)",
          }}>
            STORAGE: <span style={{ color: "var(--text-2)" }}>
              {stats?.storage?.toUpperCase() || "—"}
            </span>
          </div>
          <StatusBar connected={connected} />
        </div>
      </header>

      <div style={{ padding: "20px 24px", maxWidth: 1600 }}>
        <DemoPanel demoStatus={demoStatus} busy={demoBusy} onStart={handleDemoStart} onStop={handleDemoStop} />

        {/* ── Alert ticker ── */}
        {logs.some(l => l.is_attack) && (
          <div style={{ marginBottom: 16 }}>
            <AlertTicker logs={logs} />
          </div>
        )}

        {/* ── Stat cards ── */}
        <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
          <StatCard
            label="TOTAL PACKETS"
            value={fmt(stats?.total_packets)}
            sub="since startup"
            color="var(--accent)"
          />
          <StatCard
            label="ATTACKS"
            value={fmt(stats?.attack_packets)}
            sub={`${stats?.attack_rate ?? 0}% of traffic`}
            color="var(--red)"
          />
          <StatCard
            label="NORMAL"
            value={fmt(stats?.normal_packets)}
            color="var(--green)"
          />
          <StatCard
            label="DoS"
            value={fmt(byCategory.dos)}
            color={CATEGORY_COLORS.dos}
          />
          <StatCard
            label="PROBE"
            value={fmt(byCategory.probe)}
            color={CATEGORY_COLORS.probe}
          />
          <StatCard
            label="R2L"
            value={fmt(byCategory.r2l)}
            color={CATEGORY_COLORS.r2l}
          />
          <StatCard
            label="U2R"
            value={fmt(byCategory.u2r)}
            color={CATEGORY_COLORS.u2r}
          />
        </div>

        {/* ── Charts row ── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 12,
          marginBottom: 20,
        }}>
          <div className="card" style={{ padding: 16 }}>
            <div style={{
              fontSize: 11, letterSpacing: 2,
              color: "var(--text-3)", marginBottom: 12,
              fontFamily: "var(--mono)",
            }}>
              ATTACK DISTRIBUTION
            </div>
            <AttackPieChart byCategory={byCategory} />
          </div>

          <div className="card" style={{ padding: 16 }}>
            <div style={{
              fontSize: 11, letterSpacing: 2,
              color: "var(--text-3)", marginBottom: 12,
              fontFamily: "var(--mono)",
            }}>
              THREATS BY CATEGORY
            </div>
            <ThreatBarChart byCategory={byCategory} />
          </div>

          <div className="card" style={{ padding: 16 }}>
            <div style={{
              fontSize: 11, letterSpacing: 2,
              color: "var(--text-3)", marginBottom: 12,
              fontFamily: "var(--mono)",
            }}>
              TRAFFIC OVER TIME
            </div>
            <TrafficLineChart
              history={history}
              total={stats?.total_packets || 0}
              attacks={stats?.attack_packets || 0}
            />
          </div>
        </div>

        {/* ── Log table ── */}
        <div className="card">
          {/* Table header */}
          <div className="log-toolbar">
            <div style={{
              fontFamily: "var(--mono)", fontSize: 12,
              color: "var(--text-2)", letterSpacing: 2,
            }}>
              LIVE TRAFFIC LOG
              <span style={{
                marginLeft: 12, padding: "2px 8px",
                background: "rgba(0,212,255,0.1)",
                border: "1px solid var(--accent-dim)",
                borderRadius: 2,
                fontSize: 10, color: "var(--accent)",
              }}>
                {logs.length} entries
              </span>
            </div>

            <div className="log-toolbar-actions">
              <button className="action-button" onClick={handleExportCsv}>
                EXPORT CSV
              </button>

              <button className="action-button" onClick={handleExportPdf}>
                EXPORT PDF
              </button>

              {/* Attack-only toggle */}
              <button
                onClick={() => setAttackOnly(v => !v)}
                className={`action-button ${attackOnly ? "danger" : ""}`}
              >
                {attackOnly ? "⬛ ATTACKS ONLY" : "ATTACKS ONLY"}
              </button>

              {/* Clear */}
              <button
                onClick={handleClear}
                className="action-button"
              >
                CLEAR
              </button>

              {/* Auto-refresh indicator */}
              <div style={{
                display: "flex", alignItems: "center", gap: 6,
                fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-3)",
              }}>
                <span className="dot dot-cyan dot-pulse" />
                LIVE
              </div>
            </div>
          </div>

          {loading ? (
            <div style={{
              padding: "40px 0", textAlign: "center",
              fontFamily: "var(--mono)", color: "var(--text-3)", fontSize: 12,
            }}>
              INITIALIZING…
            </div>
          ) : !connected ? (
            <div style={{
              padding: "40px 0", textAlign: "center",
              fontFamily: "var(--mono)", color: "var(--red)", fontSize: 12,
            }}>
              ⚠️ CONNECTION OFFLINE — UNABLE TO REACH DETECTION SERVICE
            </div>
          ) : (
            <LogTable logs={logs} />
          )}
        </div>

        {/* ── Footer ── */}
        <div style={{
          marginTop: 20, paddingBottom: 20,
          display: "flex", justifyContent: "space-between",
          fontFamily: "var(--mono)", fontSize: 10,
          color: "var(--text-3)",
        }}>
          <span>Threat-IQ v1.0 · XGBoost + Isolation Forest · NSL-KDD</span>
          <span>POLL INTERVAL: {POLL_INTERVAL / 1000}s · EDUCATIONAL USE ONLY</span>
        </div>
      </div>
    </div>
  );
}
