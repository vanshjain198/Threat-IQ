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
  dos:     "#ff2d55",
  probe:   "#ff9500",
  r2l:     "#ffd60a",
  u2r:     "#bf5fff",
  anomaly: "#00d4ff",
  normal:  "#00e676",
  unknown: "#304a60",
};

const CATEGORY_GLOW = {
  dos:     "rgba(255,45,85,0.3)",
  probe:   "rgba(255,149,0,0.3)",
  r2l:     "rgba(255,214,10,0.3)",
  u2r:     "rgba(191,95,255,0.3)",
  anomaly: "rgba(0,212,255,0.3)",
  normal:  "rgba(0,230,118,0.3)",
  unknown: "rgba(48,74,96,0.3)",
};

const SEVERITY_MAP = {
  dos:     { label: "CRITICAL", color: "#ff2d55" },
  probe:   { label: "HIGH",     color: "#ff9500" },
  r2l:     { label: "HIGH",     color: "#ffd60a" },
  u2r:     { label: "CRITICAL", color: "#bf5fff" },
  anomaly: { label: "MEDIUM",   color: "#00d4ff" },
  normal:  { label: "INFO",     color: "#00e676" },
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
  if (s < 5)    return "just now";
  if (s < 60)   return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function useAnimatedValue(target, duration = 600) {
  const [display, setDisplay] = useState(target);
  const prevRef = useRef(target);
  const rafRef  = useRef(null);

  useEffect(() => {
    const from = prevRef.current;
    const to   = typeof target === "number" ? target : 0;
    if (from === to) return;
    const start = performance.now();
    const tick  = (now) => {
      const elapsed = now - start;
      const t       = Math.min(elapsed / duration, 1);
      const ease    = 1 - Math.pow(1 - t, 3); // cubic ease-out
      setDisplay(Math.round(from + (to - from) * ease));
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
      else { setDisplay(to); prevRef.current = to; }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  return display;
}

function triggerCsvDownload(filename, content) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  a.click();
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
  // Bypasses browser pop-up blocker by rendering in a hidden iframe and printing
  const iframe = document.createElement("iframe");
  iframe.style.position = "fixed";
  iframe.style.width = "0px";
  iframe.style.height = "0px";
  iframe.style.border = "none";
  document.body.appendChild(iframe);

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
        <title>Threat Lens Report</title>
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
        </style>
      </head>
      <body>
        <h1>Threat Lens Security Analysis Report</h1>
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
      </body>
    </html>
  `;

  const doc = iframe.contentDocument || iframe.contentWindow.document;
  doc.open();
  doc.write(html);
  doc.close();

  // Wait briefly for content to load, trigger print dialog, then remove the iframe
  setTimeout(() => {
    iframe.contentWindow.focus();
    iframe.contentWindow.print();
    document.body.removeChild(iframe);
  }, 300);
}

// ── LiveClock ────────────────────────────────────────────────────────────────
function LiveClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-2)", letterSpacing: 1 }}>
      {time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
    </span>
  );
}

// ── ThreatLevelGauge ──────────────────────────────────────────────────────────
function ThreatLevelGauge({ attackRate }) {
  const rate     = Math.min(100, attackRate || 0);
  const color    = rate > 60 ? "var(--red)" : rate > 30 ? "var(--orange)" : rate > 10 ? "var(--yellow)" : "var(--green)";
  const label    = rate > 60 ? "CRITICAL" : rate > 30 ? "HIGH" : rate > 10 ? "ELEVATED" : "LOW";

  return (
    <div className="threat-gauge" title={`Threat Level: ${label} (${rate.toFixed(1)}%)`}>
      <span style={{ fontFamily: "var(--mono)", fontSize: 10, color, letterSpacing: 1 }}>
        {label}
      </span>
      <div className="threat-gauge-bar">
        <div
          className="threat-gauge-fill"
          style={{ width: `${rate}%`, background: color, boxShadow: `0 0 6px ${color}` }}
        />
      </div>
      <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)", minWidth: 32, textAlign: "right" }}>
        {rate.toFixed(0)}%
      </span>
    </div>
  );
}

// ── StatusBar ─────────────────────────────────────────────────────────────────
function StatusBar({ connected }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--text-2)", fontFamily: "var(--mono)" }}>
      <span className={`dot ${connected ? "dot-green dot-pulse" : "dot-red dot-pulse"}`} />
      {connected ? "ONLINE" : "OFFLINE"}
    </div>
  );
}

// ── StatCard ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color = "var(--accent)", icon }) {
  const numVal     = typeof value === "string" ? parseInt(value.replace(/,/g, ""), 10) || 0 : (value || 0);
  const animated   = useAnimatedValue(numVal);
  const displayVal = numVal > 0 ? animated.toLocaleString() : (value === "—" ? "—" : "0");

  return (
    <div className="card stat-card card-accent-top" style={{ "--card-accent": color }}>
      <div className="stat-card-label">{label}</div>
      <div className="stat-card-value" style={{ color, textShadow: `0 0 20px ${color}40` }}>
        {displayVal}
      </div>
      {sub && <div className="stat-card-sub">{sub}</div>}
    </div>
  );
}

// ── CategoryBadge ─────────────────────────────────────────────────────────────
function CategoryBadge({ cat }) {
  const c   = CATEGORY_COLORS[cat] || CATEGORY_COLORS.unknown;
  const sev = SEVERITY_MAP[cat] || { label: "INFO", color: c };
  return (
    <span className="badge" style={{ borderColor: c + "55", color: c, background: c + "12" }}>
      {sev.label}
    </span>
  );
}

// ── ExpandedRow ───────────────────────────────────────────────────────────────
function ExpandedRow({ log, colSpan }) {
  const fields = [
    ["Source",     `${log.src_ip || "—"}:${log.src_port || 0}`],
    ["Destination",`${log.dst_ip || "—"}:${log.dst_port || 0}`],
    ["Protocol",    log.protocol || "—"],
    ["Prediction",  log.prediction || "—"],
    ["Category",   (log.attack_category || "normal").toUpperCase()],
    ["Confidence",  log.confidence != null ? `${log.confidence.toFixed(1)}%` : "—"],
    ["Model",       log.model_used || "—"],
    ["Timestamp",   log.timestamp ? new Date(log.timestamp).toLocaleString() : "—"],
  ];
  return (
    <tr className="expand-row">
      <td colSpan={colSpan} style={{ padding: "0 14px" }}>
        <div className="expand-content" style={{ padding: "12px 0", display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 }}>
          {fields.map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 6 }}>
              <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)", letterSpacing: 1, minWidth: 80 }}>
                {k.toUpperCase()}
              </span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-2)" }}>{v}</span>
            </div>
          ))}
        </div>
      </td>
    </tr>
  );
}

// ── LogTable ──────────────────────────────────────────────────────────────────
function LogTable({ logs }) {
  const [expandedId, setExpandedId] = useState(null);
  const [sortCol,    setSortCol]    = useState("timestamp");
  const [sortDir,    setSortDir]    = useState("desc");

  const handleSort = (col) => {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("desc"); }
  };

  const sorted = [...logs].sort((a, b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (sortCol === "timestamp") { va = new Date(va).getTime(); vb = new Date(vb).getTime(); }
    if (sortCol === "confidence") { va = va || 0; vb = vb || 0; }
    if (va < vb) return sortDir === "asc" ? -1 : 1;
    if (va > vb) return sortDir === "asc" ? 1  : -1;
    return 0;
  });

  if (!logs.length) {
    return (
      <div style={{ padding: "60px 0", textAlign: "center", color: "var(--text-3)", fontFamily: "var(--mono)", fontSize: 12 }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>📡</div>
        NO PACKETS LOGGED — start capture.py or demo mode to begin monitoring
      </div>
    );
  }

  const cols = [
    { key: "timestamp",       label: "TIME",       sortable: true  },
    { key: "src_ip",          label: "SRC IP",     sortable: true  },
    { key: "dst_ip",          label: "DST IP",     sortable: false },
    { key: "protocol",        label: "PROTO",      sortable: true  },
    { key: "prediction",      label: "PREDICTION", sortable: true  },
    { key: "attack_category", label: "SEVERITY",   sortable: true  },
    { key: "confidence",      label: "CONF %",     sortable: true  },
    { key: "model_used",      label: "MODEL",      sortable: false },
  ];

  return (
    <div style={{ overflowX: "auto" }}>
      <table className="data-table">
        <thead>
          <tr>
            {cols.map(col => (
              <th
                key={col.key}
                className={col.sortable ? "sortable" : ""}
                onClick={() => col.sortable && handleSort(col.key)}
              >
                {col.label}
                {sortCol === col.key && (
                  <span style={{ marginLeft: 4, color: "var(--accent)" }}>
                    {sortDir === "asc" ? "↑" : "↓"}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((log, i) => {
            const isAtk   = log.is_attack;
            const cat     = log.attack_category || "normal";
            const color   = CATEGORY_COLORS[cat];
            const isOpen  = expandedId === (log.id || i);

            return (
              <React.Fragment key={log.id || i}>
                <tr
                  className={i === 0 && isAtk ? "new-row" : ""}
                  onClick={() => setExpandedId(isOpen ? null : (log.id || i))}
                  style={{
                    borderLeft: isAtk ? `2px solid ${color}` : "2px solid transparent",
                    background: isAtk
                      ? `${color}08`
                      : "transparent",
                    cursor: "pointer",
                  }}
                >
                  <td style={{ fontFamily: "var(--mono)", color: "var(--text-3)", whiteSpace: "nowrap", fontSize: 11 }}>
                    {log.timestamp ? timeAgo(log.timestamp) : "—"}
                  </td>
                  <td style={{ fontFamily: "var(--mono)", color: "var(--text-2)", fontSize: 11 }}>
                    {log.src_ip || "—"}
                  </td>
                  <td style={{ fontFamily: "var(--mono)", color: "var(--text-2)", fontSize: 11 }}>
                    {log.dst_ip || "—"}
                  </td>
                  <td style={{ fontFamily: "var(--mono)", color: "var(--accent)", fontSize: 11 }}>
                    {log.protocol || "—"}
                  </td>
                  <td style={{ fontFamily: "var(--mono)", color, fontWeight: 600, fontSize: 12, textShadow: isAtk ? `0 0 8px ${color}60` : "none" }}>
                    {log.prediction || "—"}
                  </td>
                  <td>
                    <CategoryBadge cat={cat} />
                  </td>
                  <td style={{
                    fontFamily: "var(--mono)",
                    fontSize: 12,
                    color: (log.confidence || 0) > 90
                      ? "var(--green)"
                      : (log.confidence || 0) > 70
                      ? "var(--yellow)"
                      : "var(--orange)",
                  }}>
                    {log.confidence != null ? log.confidence.toFixed(1) : "—"}
                  </td>
                  <td style={{ color: "var(--text-3)", fontSize: 10, fontFamily: "var(--mono)" }}>
                    {log.model_used || "—"}
                  </td>
                </tr>
                {isOpen && <ExpandedRow log={log} colSpan={cols.length} />}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Chart defaults ────────────────────────────────────────────────────────────
const chartDefaults = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 400 },
  plugins: {
    legend: {
      labels: {
        color: "#6b90ab",
        font: { family: "JetBrains Mono, monospace", size: 11 },
        boxWidth: 10,
        padding: 12,
      },
    },
    tooltip: {
      backgroundColor: "#060d18",
      titleColor: "#00d4ff",
      bodyColor: "#e8f4ff",
      borderColor: "#1a3a5c",
      borderWidth: 1,
      padding: 10,
    },
  },
};

// ── AttackPieChart ────────────────────────────────────────────────────────────
function AttackPieChart({ byCategory }) {
  const cats = Object.keys(byCategory).filter(k => byCategory[k] > 0);
  const data = {
    labels:   cats.map(c => c.toUpperCase()),
    datasets: [{
      data:            cats.map(c => byCategory[c]),
      backgroundColor: cats.map(c => CATEGORY_COLORS[c] + "bb"),
      borderColor:     cats.map(c => CATEGORY_COLORS[c]),
      borderWidth:     1,
      hoverOffset:     6,
    }],
  };

  if (!cats.length) {
    return (
      <div style={{ height: 200, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8 }}>
        <div style={{ fontSize: 28 }}>🛡️</div>
        <div style={{ color: "var(--text-3)", fontFamily: "var(--mono)", fontSize: 11, letterSpacing: 2 }}>
          NO ATTACKS DETECTED
        </div>
      </div>
    );
  }

  return (
    <div style={{ height: 200 }}>
      <Doughnut
        data={data}
        options={{
          ...chartDefaults,
          cutout: "68%",
          plugins: {
            ...chartDefaults.plugins,
            legend: { ...chartDefaults.plugins.legend, position: "right" },
          },
        }}
      />
    </div>
  );
}

// ── ThreatBarChart ────────────────────────────────────────────────────────────
function ThreatBarChart({ byCategory }) {
  const cats = ["dos", "probe", "r2l", "u2r", "anomaly"];
  const data = {
    labels:   cats.map(c => c.toUpperCase()),
    datasets: [{
      label:           "Packets",
      data:            cats.map(c => byCategory[c] || 0),
      backgroundColor: cats.map(c => CATEGORY_COLORS[c] + "80"),
      borderColor:     cats.map(c => CATEGORY_COLORS[c]),
      borderWidth:     1,
      borderRadius:    4,
      borderSkipped:   false,
    }],
  };
  const scaleStyle = {
    ticks: { color: "#6b90ab", font: { family: "JetBrains Mono, monospace", size: 11 } },
    grid:  { color: "rgba(14,32,56,0.8)", drawBorder: false },
  };
  return (
    <div style={{ height: 200 }}>
      <Bar data={data} options={{ ...chartDefaults, scales: { x: scaleStyle, y: scaleStyle } }} />
    </div>
  );
}

// ── TrafficLineChart ──────────────────────────────────────────────────────────
function TrafficLineChart({ history }) {
  const points  = history.length > 0 ? history.slice(-12) : [];
  const labels  = points.length > 0
    ? points.map((_, i) => `T-${points.length - i}m`)
    : Array.from({ length: 12 }, (_, i) => `T-${12 - i}m`);

  const totalArr  = points.length > 0 ? points.map(p => p.total_cumulative  || 0) : Array(12).fill(0);
  const attackArr = points.length > 0 ? points.map(p => p.attacks_cumulative || 0) : Array(12).fill(0);

  const data = {
    labels,
    datasets: [
      {
        label: "Total",
        data: totalArr,
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,0.06)",
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: "#00d4ff",
        pointBorderColor: "#060d18",
        pointBorderWidth: 2,
      },
      {
        label: "Attacks",
        data: attackArr,
        borderColor: "#ff2d55",
        backgroundColor: "rgba(255,45,85,0.06)",
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: "#ff2d55",
        pointBorderColor: "#060d18",
        pointBorderWidth: 2,
      },
    ],
  };

  const scaleStyle = {
    ticks: { color: "#6b90ab", font: { family: "JetBrains Mono, monospace", size: 10 } },
    grid:  { color: "rgba(14,32,56,0.8)", drawBorder: false },
  };

  return (
    <div style={{ height: 200 }}>
      <Line data={data} options={{ ...chartDefaults, scales: { x: scaleStyle, y: scaleStyle } }} />
    </div>
  );
}

// ── AlertTicker ───────────────────────────────────────────────────────────────
function AlertTicker({ logs }) {
  const attacks = logs.filter(l => l.is_attack).slice(0, 6);
  if (!attacks.length) return null;

  return (
    <div className="alert-ticker" style={{ marginBottom: 16 }}>
      <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--red)", letterSpacing: 2, whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 6 }}>
        <span className="dot dot-red dot-pulse" />
        THREAT DETECTED
      </span>
      <div style={{ flex: 1, overflow: "hidden", display: "flex", gap: 16, flexWrap: "nowrap" }}>
        {attacks.map((a, i) => (
          <span key={i} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-2)", whiteSpace: "nowrap" }}>
            <span style={{ color: CATEGORY_COLORS[a.attack_category], fontWeight: 600 }}>
              {a.prediction}
            </span>
            {" "}from {a.src_ip}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── NotificationStack ─────────────────────────────────────────────────────────
function NotificationStack({ alerts, onDismiss }) {
  if (!alerts.length) return null;
  const icons = { critical: "🚨", info: "ℹ️", warning: "⚠️" };

  return (
    <div className="notification-stack">
      {alerts.map((alert) => (
        <div key={alert.id} className={`notification-card ${alert.severity}`}>
          <span className="notification-icon">{icons[alert.severity] || "🔔"}</span>
          <div className="notification-content">
            <div className="notification-title">{alert.title}</div>
            <div className="notification-body">{alert.body}</div>
          </div>
          <button className="notification-close" onClick={() => onDismiss(alert.id)}>×</button>
        </div>
      ))}
    </div>
  );
}

// ── DemoPanel ─────────────────────────────────────────────────────────────────
function DemoPanel({ demoStatus, busy, onStart, onStop }) {
  const [elapsed, setElapsed] = useState(0);
  const duration = demoStatus?.config?.duration || 90;

  useEffect(() => {
    if (!demoStatus?.running || !demoStatus?.started_at) { setElapsed(0); return; }
    const tick = () => {
      const e = Math.floor((Date.now() - new Date(demoStatus.started_at).getTime()) / 1000);
      setElapsed(Math.min(e, duration));
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [demoStatus?.running, demoStatus?.started_at, duration]);

  const progress = demoStatus?.running ? Math.min((elapsed / duration) * 100, 100) : 0;

  return (
    <div className="card demo-panel card-accent-top">
      <div style={{ display: "flex", justifyContent: "space-between", gap: 16, alignItems: "flex-start", flexWrap: "wrap" }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span className={`dot ${demoStatus?.running ? "dot-green dot-pulse" : "dot-red"}`} />
            <span style={{ fontFamily: "var(--mono)", fontSize: 10, letterSpacing: 2, color: "var(--text-3)" }}>
              DEMO SIMULATION
            </span>
            {demoStatus?.running && (
              <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--green)", marginLeft: 4 }}>
                RUNNING
              </span>
            )}
          </div>
          <div style={{ color: "var(--text-2)", fontSize: 13, marginBottom: demoStatus?.running ? 10 : 0 }}>
            {demoStatus?.running
              ? `Simulating ${Math.round((demoStatus?.config?.attacks || 0.2) * 100)}% attack traffic · ${elapsed}s / ${duration}s elapsed`
              : "Simulate mixed normal + attack network traffic for live dashboard testing"}
          </div>

          {demoStatus?.running && (
            <div>
              <div className="progress-bar-track">
                <div className="progress-bar-fill animated" style={{ width: `${progress}%` }} />
              </div>
              <div style={{ marginTop: 4, fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)" }}>
                {Math.max(0, duration - elapsed)}s remaining
              </div>
            </div>
          )}
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button className="action-button accent" disabled={busy || demoStatus?.running} onClick={onStart}>
            {busy && !demoStatus?.running ? "STARTING…" : "▶ START DEMO"}
          </button>
          <button className="action-button danger" disabled={busy || !demoStatus?.running} onClick={onStop}>
            {busy && demoStatus?.running ? "STOPPING…" : "■ STOP"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── AlertHistory ──────────────────────────────────────────────────────────────
function AlertHistory({ history }) {
  if (!history.length) {
    return (
      <div style={{ padding: "24px", textAlign: "center", color: "var(--text-3)", fontFamily: "var(--mono)", fontSize: 11 }}>
        NO ALERTS IN THIS SESSION
      </div>
    );
  }
  return (
    <div style={{ maxHeight: 280, overflowY: "auto" }}>
      {history.map(a => (
        <div key={a.id} style={{
          padding: "10px 16px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          gap: 12,
          alignItems: "flex-start",
        }}>
          <span style={{ fontSize: 14, flexShrink: 0 }}>{a.severity === "critical" ? "🚨" : "ℹ️"}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: a.severity === "critical" ? "var(--red)" : "var(--accent)", letterSpacing: 1 }}>
              {a.title}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-2)", marginTop: 2 }}>{a.body}</div>
          </div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)", whiteSpace: "nowrap" }}>
            {new Date(a.timestamp).toLocaleTimeString()}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [stats,      setStats]      = useState(null);
  const [logs,       setLogs]       = useState([]);
  const [history,    setHistory]    = useState([]);
  const [connected,  setConnected]  = useState(false);
  const [loading,    setLoading]    = useState(true);
  const [attackOnly, setAttackOnly] = useState(false);
  const [demoStatus, setDemoStatus] = useState({ running: false });
  const [demoBusy,   setDemoBusy]   = useState(false);
  const [alerts,     setAlerts]     = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [activeTab,  setActiveTab]  = useState("dashboard"); // dashboard | logs | alerts

  const timerRef        = useRef(null);
  const seenAlertIdsRef = useRef(new Set());

  // ── Polling ────────────────────────────────────────────────────────────────
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

  // ── Handlers ──────────────────────────────────────────────────────────────
  const handleClear = async () => {
    await clearLogs();
    setLogs([]);
    await poll();
  };

  const pushAlert = useCallback((title, body, severity = "critical") => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const entry = { id, title, body, severity, timestamp: Date.now() };
    setAlerts(cur => [...cur.slice(-2), entry]);
    setAlertHistory(cur => [entry, ...cur].slice(0, 50));
    window.setTimeout(() => {
      setAlerts(cur => cur.filter(item => item.id !== id));
    }, 6000);
  }, []);

  // ── Critical alert watcher ────────────────────────────────────────────────
  useEffect(() => {
    for (const log of logs) {
      if (!log.id || seenAlertIdsRef.current.has(log.id)) continue;
      seenAlertIdsRef.current.add(log.id);
      if (!log.is_attack || !CRITICAL_CATEGORIES.has(log.attack_category)) continue;

      const title = `${(log.attack_category || "attack").toUpperCase()} ATTACK DETECTED`;
      const body  = `${log.prediction || "Threat"} from ${log.src_ip || "unknown"} → ${log.dst_ip || "unknown"}`;
      pushAlert(title, body, "critical");

      if (typeof window !== "undefined" && "Notification" in window && Notification.permission === "granted") {
        new Notification(title, { body });
      }
    }
  }, [logs, pushAlert]);

  const ensureNotifPermission = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) return;
    if (Notification.permission === "default") {
      try { await Notification.requestPermission(); } catch { return; }
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
      await ensureNotifPermission();
      const resp = await startDemo({ duration: 90, rate: 2, attacks: 0.2, clear_existing: true });
      setDemoStatus(resp.status || { running: true });
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
      const resp = await stopDemo();
      setDemoStatus(resp.status || { running: false });
      pushAlert("Demo mode stopped", "Simulator stopped.", "info");
      await poll();
    } catch (err) {
      pushAlert("Demo stop failed", err.message, "critical");
    } finally {
      setDemoBusy(false);
    }
  };

  // ── Derived ────────────────────────────────────────────────────────────────
  const byCategory = stats?.by_category || { dos: 0, probe: 0, r2l: 0, u2r: 0, anomaly: 0 };
  const uptime     = stats
    ? `${Math.floor(stats.uptime_seconds / 60)}m ${stats.uptime_seconds % 60}s`
    : "—";
  const avgConf    = logs.length
    ? (logs.reduce((acc, l) => acc + (l.confidence || 0), 0) / logs.length).toFixed(1)
    : null;

  // ── Tabs ───────────────────────────────────────────────────────────────────
  const tabs = [
    { id: "dashboard", label: "DASHBOARD" },
    { id: "logs",      label: `LIVE LOGS ${logs.length > 0 ? `(${logs.length})` : ""}` },
    { id: "alerts",    label: `ALERTS (${alertHistory.length})` },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-base)", fontFamily: "var(--sans)", position: "relative", zIndex: 1 }}>
      <NotificationStack alerts={alerts} onDismiss={(id) => setAlerts(cur => cur.filter(item => item.id !== id))} />

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header className="app-header">
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {/* Shield icon */}
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 6V12C3 16.97 7.02 21.57 12 23C16.98 21.57 21 16.97 21 12V6L12 2Z"
              stroke="#00d4ff" strokeWidth="1.5" fill="rgba(0,212,255,0.08)" />
            <path d="M9 12L11 14L15 10" stroke="#00e676" strokeWidth="1.8"
              strokeLinecap="round" strokeLinejoin="round" />
          </svg>

          <div>
            <div style={{
              fontFamily: "var(--head)", fontSize: 22, fontWeight: 700,
              color: "var(--accent)", letterSpacing: 3, textTransform: "uppercase",
              lineHeight: 1, textShadow: "0 0 20px rgba(0,212,255,0.4)",
            }}>
              Threat Lens
            </div>
            <div style={{ fontSize: 9, color: "var(--text-3)", letterSpacing: 2 }}>
              NETWORK INTRUSION DETECTION SYSTEM · AI-POWERED
            </div>
          </div>
        </div>

        {/* Header right */}
        <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)" }}>
            UPTIME: <span style={{ color: "var(--text-2)" }}>{uptime}</span>
          </div>

          {avgConf && (
            <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)" }}>
              AVG CONF: <span style={{ color: "var(--yellow)" }}>{avgConf}%</span>
            </div>
          )}

          <ThreatLevelGauge attackRate={stats?.attack_rate} />
          <LiveClock />
          <StatusBar connected={connected} />
        </div>
      </header>

      {/* ── Tab nav ────────────────────────────────────────────────────────── */}
      <div style={{
        background: "var(--bg-panel)",
        borderBottom: "1px solid var(--border)",
        padding: "0 24px",
        display: "flex",
        gap: 0,
      }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: "10px 18px",
              background: "transparent",
              border: "none",
              borderBottom: activeTab === tab.id ? `2px solid var(--accent)` : "2px solid transparent",
              color: activeTab === tab.id ? "var(--accent)" : "var(--text-3)",
              fontFamily: "var(--mono)",
              fontSize: 10,
              letterSpacing: 2,
              cursor: "pointer",
              transition: "all 0.2s",
              marginBottom: -1,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Main content ───────────────────────────────────────────────────── */}
      <div style={{ padding: "20px 24px", maxWidth: 1600 }}>

        {/* ── DASHBOARD tab ─────────────────────────────────────────────── */}
        {activeTab === "dashboard" && (
          <>
            <DemoPanel demoStatus={demoStatus} busy={demoBusy} onStart={handleDemoStart} onStop={handleDemoStop} />

            {logs.some(l => l.is_attack) && <AlertTicker logs={logs} />}

            {/* Stat cards */}
            <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
              <StatCard label="TOTAL PACKETS"   value={stats?.total_packets ?? "—"} sub="since startup"                     color="var(--accent)" />
              <StatCard label="ATTACK PACKETS"  value={stats?.attack_packets ?? "—"} sub={`${stats?.attack_rate ?? 0}% of traffic`} color="var(--red)"    />
              <StatCard label="NORMAL TRAFFIC"  value={stats?.normal_packets ?? "—"} color="var(--green)"  />
              <StatCard label="DoS"    value={byCategory.dos}    color={CATEGORY_COLORS.dos}   />
              <StatCard label="PROBE"  value={byCategory.probe}  color={CATEGORY_COLORS.probe} />
              <StatCard label="R2L"    value={byCategory.r2l}    color={CATEGORY_COLORS.r2l}   />
              <StatCard label="U2R"    value={byCategory.u2r}    color={CATEGORY_COLORS.u2r}   />
            </div>

            {/* Charts row */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
              <div className="card" style={{ padding: 16 }}>
                <div className="section-title">ATTACK DISTRIBUTION</div>
                <AttackPieChart byCategory={byCategory} />
              </div>

              <div className="card" style={{ padding: 16 }}>
                <div className="section-title">THREATS BY CATEGORY</div>
                <ThreatBarChart byCategory={byCategory} />
              </div>

              <div className="card" style={{ padding: 16 }}>
                <div className="section-title">TRAFFIC OVER TIME</div>
                <TrafficLineChart history={history} />
              </div>
            </div>

            {/* Quick log preview on dashboard */}
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="log-toolbar">
                <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-2)", letterSpacing: 2, display: "flex", alignItems: "center", gap: 10 }}>
                  RECENT ACTIVITY
                  <span style={{ padding: "2px 8px", background: "rgba(0,212,255,0.08)", border: "1px solid var(--border-accent)", borderRadius: 3, fontSize: 10, color: "var(--accent)" }}>
                    {logs.length} entries
                  </span>
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <span className="dot dot-cyan dot-pulse" />
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)" }}>AUTO-REFRESH 3s</span>
                  <button className="action-button" style={{ marginLeft: 8 }} onClick={() => setActiveTab("logs")}>VIEW ALL →</button>
                </div>
              </div>
              {loading ? (
                <div style={{ padding: "40px 16px", textAlign: "center", fontFamily: "var(--mono)" }}>
                  <div className="dot dot-cyan dot-pulse" style={{ width: 14, height: 14, marginBottom: 12 }} />
                  <div style={{ color: "var(--text-1)", fontSize: 13, fontWeight: 500, letterSpacing: 1 }}>
                    INITIALIZING SYSTEM SERVICES…
                  </div>
                  <div style={{ color: "var(--text-3)", fontSize: 11, marginTop: 6, maxWidth: 420, margin: "6px auto 0" }}>
                    The backend services are hosted on a free cloud tier and may take 30–60 seconds to spin up from idle sleep. Thank you for your patience!
                  </div>
                </div>
              ) : !connected ? (
                <div style={{ padding: "40px 16px", textAlign: "center", fontFamily: "var(--mono)", borderLeft: "2px solid var(--red)" }}>
                  <div style={{ color: "var(--red)", fontSize: 13, fontWeight: 600, letterSpacing: 1 }}>
                    ⚠️ DETECTION SERVICE CONNECTION OFFLINE
                  </div>
                  <div style={{ color: "var(--text-3)", fontSize: 11, marginTop: 6, maxWidth: 420, margin: "6px auto 0" }}>
                    Waking up containers on free hosting. If loading takes a long time, the server might be performing a cold boot. Please refresh in a moment.
                  </div>
                </div>
              ) : (
                <LogTable logs={logs.slice(0, 10)} />
              )}
            </div>
          </>
        )}

        {/* ── LOGS tab ──────────────────────────────────────────────────── */}
        {activeTab === "logs" && (
          <div className="card">
            <div className="log-toolbar">
              <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-2)", letterSpacing: 2, display: "flex", alignItems: "center", gap: 10 }}>
                LIVE TRAFFIC LOG
                <span style={{ padding: "2px 8px", background: "rgba(0,212,255,0.08)", border: "1px solid var(--border-accent)", borderRadius: 3, fontSize: 10, color: "var(--accent)" }}>
                  {logs.length} entries
                </span>
              </div>

              <div className="log-toolbar-actions">
                <button className="action-button" onClick={handleExportCsv}>↓ EXPORT CSV</button>
                <button className="action-button" onClick={handleExportPdf}>↓ EXPORT PDF</button>
                <button
                  onClick={() => setAttackOnly(v => !v)}
                  className={`action-button ${attackOnly ? "danger" : ""}`}
                >
                  {attackOnly ? "⬛ ATTACKS ONLY" : "ATTACKS ONLY"}
                </button>
                <button onClick={handleClear} className="action-button">CLEAR</button>
                <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-3)" }}>
                  <span className="dot dot-cyan dot-pulse" />
                  LIVE
                </div>
              </div>
            </div>

            {loading ? (
              <div style={{ padding: "40px 16px", textAlign: "center", fontFamily: "var(--mono)" }}>
                <div className="dot dot-cyan dot-pulse" style={{ width: 14, height: 14, marginBottom: 12 }} />
                <div style={{ color: "var(--text-1)", fontSize: 12, letterSpacing: 1 }}>
                  WAKING BACKEND MODULES…
                </div>
              </div>
            ) : !connected ? (
              <div style={{ padding: "40px 16px", textAlign: "center", fontFamily: "var(--mono)", borderLeft: "2px solid var(--red)" }}>
                <div style={{ color: "var(--red)", fontSize: 12, fontWeight: 600 }}>
                  ⚠️ SERVICE OFFLINE (COLD BOOT ACTIVE)
                </div>
              </div>
            ) : (
              <LogTable logs={logs} />
            )}
          </div>
        )}

        {/* ── ALERTS tab ────────────────────────────────────────────────── */}
        {activeTab === "alerts" && (
          <div className="card">
            <div className="log-toolbar">
              <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-2)", letterSpacing: 2, display: "flex", alignItems: "center", gap: 10 }}>
                ALERT HISTORY
                <span style={{ padding: "2px 8px", background: "rgba(255,45,85,0.08)", border: "1px solid rgba(255,45,85,0.3)", borderRadius: 3, fontSize: 10, color: "var(--red)" }}>
                  {alertHistory.length} alerts
                </span>
              </div>
              <button className="action-button danger" onClick={() => setAlertHistory([])}>CLEAR HISTORY</button>
            </div>
            <AlertHistory history={alertHistory} />
          </div>
        )}

        {/* ── Footer ────────────────────────────────────────────────────── */}
        <div style={{
          marginTop: 24, paddingBottom: 24,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-4)",
          borderTop: "1px solid var(--border)", paddingTop: 16,
          flexWrap: "wrap", gap: 8,
        }}>
          <span>
            Threat Lens v1.1 · XGBoost + Isolation Forest · NSL-KDD Dataset
          </span>
          <span style={{ display: "flex", gap: 16, alignItems: "center" }}>
            <span>STORAGE: {stats?.storage?.toUpperCase() || "—"}</span>
            <span>POLL: {POLL_INTERVAL / 1000}s</span>
            <span style={{ color: "var(--text-3)" }}>EDUCATIONAL USE ONLY</span>
          </span>
        </div>
      </div>
    </div>
  );
}
