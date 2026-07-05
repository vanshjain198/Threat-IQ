/**
 * index.js — NIDS Node.js/Express Backend
 *
 * Receives packet feature data, forwards to ML service,
 * stores results (MongoDB or in-memory), serves dashboard API.
 */

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const morgan   = require("morgan");
const axios    = require("axios");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

// ── Config ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT           || 3001;
const ML_URL     = process.env.ML_SERVICE_URL || "http://localhost:8000";
const MONGO_URI  = process.env.MONGODB_URI    || "mongodb://localhost:27017/nids";
const ALERT_CATEGORIES = (process.env.ALERT_CRITICAL_CATEGORIES || "dos,u2r")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);
const ALERT_COOLDOWN_MS = Math.max(0, Number(process.env.ALERT_COOLDOWN_MS) || 5 * 60 * 1000);
const EMAIL_ALERTS_ENABLED = String(process.env.EMAIL_ALERTS_ENABLED || "").toLowerCase() === "true";
const API_KEY = process.env.API_KEY || "";
const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

const app = express();
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    const cleanedOrigin = origin.trim().replace(/\/$/, "");
    if (allowedOrigins.includes(cleanedOrigin)) return callback(null, true);
    console.warn(`[CORS Blocked] Browser origin "${origin}" is not allowed. Configured CORS_ALLOWED_ORIGINS: [${allowedOrigins.join(", ")}]`);
    return callback(new Error("Origin not allowed by CORS"));
  },
}));
app.use(express.json({ limit: "5mb" }));
app.use(morgan("tiny"));

function hasValidApiKey(req) {
  const provided = req.get("x-api-key") || "";
  if (!API_KEY || provided.length !== API_KEY.length) return false;
  return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(API_KEY));
}

function requireApiKey(req, res, next) {
  if (!API_KEY) {
    return res.status(503).json({ error: "API_KEY is not configured" });
  }
  if (!hasValidApiKey(req)) {
    return res.status(401).json({ error: "Invalid or missing API key" });
  }
  next();
}

// ── Alert integrations ───────────────────────────────────────────────────────
const alertCooldowns = new Map();
const mailTransport = EMAIL_ALERTS_ENABLED
  && process.env.SMTP_HOST
  && process.env.SMTP_USER
  && process.env.SMTP_PASS
  && process.env.EMAIL_FROM
  && process.env.EMAIL_TO
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: String(process.env.SMTP_SECURE || "").toLowerCase() === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    })
  : null;

function getAlertTargets() {
  return {
    email: !!mailTransport,
    slack: !!process.env.SLACK_WEBHOOK_URL,
    discord: !!process.env.DISCORD_WEBHOOK_URL,
    telegram: !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID),
  };
}

function getAlertStatus() {
  const targets = getAlertTargets();
  const activeChannels = Object.entries(targets)
    .filter(([, enabled]) => enabled)
    .map(([name]) => name);

  return {
    enabled: activeChannels.length > 0,
    active_channels: activeChannels,
    targets,
    cooldown_ms: ALERT_COOLDOWN_MS,
    critical_categories: ALERT_CATEGORIES,
  };
}

function isCriticalAlert(result) {
  return !!(result && result.is_attack && ALERT_CATEGORIES.includes(String(result.attack_category || "").toLowerCase()));
}

function buildAlertSignature(log) {
  return [
    String(log.attack_category || "unknown").toLowerCase(),
    log.prediction || "unknown",
    log.protocol || "unknown",
  ].join("|");
}

function shouldDispatchAlert(log) {
  const signature = buildAlertSignature(log);
  const now = Date.now();
  const lastSentAt = alertCooldowns.get(signature) || 0;

  if (now - lastSentAt < ALERT_COOLDOWN_MS) {
    return false;
  }

  alertCooldowns.set(signature, now);

  if (alertCooldowns.size > 2000) {
    const expiry = now - ALERT_COOLDOWN_MS * 2;
    for (const [key, timestamp] of alertCooldowns.entries()) {
      if (timestamp < expiry) alertCooldowns.delete(key);
    }
  }

  return true;
}

function buildAlertPayload(log) {
  const category = String(log.attack_category || "unknown").toUpperCase();
  const confidence = typeof log.confidence === "number" ? `${log.confidence.toFixed(1)}%` : "n/a";
  const title = `[NIDS] ${category} threat detected`;
  const lines = [
    `Prediction: ${log.prediction || "unknown"}`,
    `Category: ${category}`,
    `Confidence: ${confidence}`,
    `Source: ${log.src_ip || "unknown"}:${log.src_port || 0}`,
    `Destination: ${log.dst_ip || "unknown"}:${log.dst_port || 0}`,
    `Protocol: ${log.protocol || "unknown"}`,
    `Packet Length: ${log.packet_length || 0}`,
    `Model: ${log.model_used || "unknown"}`,
    `Time: ${new Date(log.timestamp).toISOString()}`,
  ];

  return {
    title,
    text: lines.join("\n"),
    html: `
      <h2>${title}</h2>
      <ul>
        ${lines.map((line) => `<li>${line}</li>`).join("")}
      </ul>
    `,
    lines,
  };
}

async function sendEmailAlert(payload) {
  if (!mailTransport) return;

  await mailTransport.sendMail({
    from: process.env.EMAIL_FROM,
    to: process.env.EMAIL_TO,
    subject: payload.title,
    text: payload.text,
    html: payload.html,
  });
}

async function sendSlackAlert(payload) {
  if (!process.env.SLACK_WEBHOOK_URL) return;

  await axios.post(process.env.SLACK_WEBHOOK_URL, {
    text: `${payload.title}\n${payload.text}`,
  }, { timeout: 5000 });
}

async function sendDiscordAlert(payload) {
  if (!process.env.DISCORD_WEBHOOK_URL) return;

  await axios.post(process.env.DISCORD_WEBHOOK_URL, {
    content: `${payload.title}\n${payload.text}`,
  }, { timeout: 5000 });
}

async function sendTelegramAlert(payload) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
    chat_id: chatId,
    text: `${payload.title}\n${payload.text}`,
  }, { timeout: 5000 });
}

async function dispatchAlerts(log) {
  const alertStatus = getAlertStatus();
  if (!alertStatus.enabled || !isCriticalAlert(log) || !shouldDispatchAlert(log)) return;

  const payload = buildAlertPayload(log);
  const operations = [
    ["email", sendEmailAlert(payload)],
    ["slack", sendSlackAlert(payload)],
    ["discord", sendDiscordAlert(payload)],
    ["telegram", sendTelegramAlert(payload)],
  ];

  const results = await Promise.allSettled(operations.map(([, promise]) => promise));
  results.forEach((result, index) => {
    if (result.status === "rejected") {
      console.error(`alert delivery failed (${operations[index][0]}):`, result.reason?.message || result.reason);
    }
  });
}

// ── Demo simulator process (Pure JS In-Memory Simulator) ─────────────────────
const demoState = {
  running: false,
  startedAt: null,
  config: null,
  lastExitCode: null,
  lastError: null,
};

let demoInterval = null;

const ATTACK_TEMPLATES_JS = {
  neptune: {
    attack_category: "dos",
    prediction: "Neptune",
    serror_rate: 0.99, srv_serror_rate: 0.99,
    count: 511, same_srv_rate: 1.0, src_bytes: 0,
    dst_bytes: 0, protocol_type: "tcp", logged_in: 0,
    dst_ports: [80, 443],
  },
  smurf: {
    attack_category: "dos",
    prediction: "Smurf",
    serror_rate: 0.0, count: 511, src_bytes: 936,
    dst_bytes: 0, protocol_type: "icmp",
    same_srv_rate: 1.0, diff_srv_rate: 0.0,
    dst_ports: [0],
  },
  portsweep: {
    attack_category: "probe",
    prediction: "Portsweep",
    diff_srv_rate: 0.81, same_srv_rate: 0.07,
    count: 200, src_bytes: 0, dst_bytes: 0,
    protocol_type: "tcp", serror_rate: 0.0,
    srv_diff_host_rate: 0.78,
    dst_ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389],
  },
  ipsweep: {
    attack_category: "probe",
    prediction: "IPsweep",
    diff_srv_rate: 0.0, same_srv_rate: 1.0,
    count: 200, src_bytes: 0, dst_bytes: 0,
    srv_diff_host_rate: 0.95, protocol_type: "icmp",
    dst_ports: [0],
  },
  guess_passwd: {
    attack_category: "r2l",
    prediction: "GuestPasswd",
    num_failed_logins: 5, is_guest_login: 1,
    logged_in: 0, count: 5, src_bytes: 200,
    dst_bytes: 40, protocol_type: "tcp",
    service: "ftp", same_srv_rate: 1.0, diff_srv_rate: 0.0,
    dst_ports: [21, 22, 23],
  },
  buffer_overflow: {
    attack_category: "u2r",
    prediction: "BufferOverflow",
    root_shell: 1, su_attempted: 1,
    num_root: 1, src_bytes: 1408, dst_bytes: 120,
    protocol_type: "tcp", hot: 2,
    num_compromised: 1, num_shells: 1,
    service: "telnet", dst_ports: [22, 23],
  },
};

function randPrivateIp() {
  const prefixes = ["192.168.1.", "10.0.0.", "172.16.0."];
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  return prefix + Math.floor(Math.random() * 254 + 1);
}

function generateNormalPacket() {
  const protocol = Math.random() < 0.7 ? "tcp" : (Math.random() < 0.7 ? "udp" : "icmp");
  const services = {
    tcp: ["http", "http_443", "ssh", "ftp", "smtp"],
    udp: ["domain_u", "ntp_u", "other"],
    icmp: ["eco_i", "ecr_i"]
  };
  const service = services[protocol][Math.floor(Math.random() * services[protocol].length)];
  const flags = {
    tcp: ["SF", "SF", "S0", "REJ"],
    udp: ["SF"],
    icmp: ["SF"]
  };
  const flag = flags[protocol][Math.floor(Math.random() * flags[protocol].length)];

  return {
    duration: Math.floor(Math.random() * 3),
    protocol_type: protocol,
    service: service,
    flag: flag,
    src_bytes: Math.floor(Math.random() * 1000 + 40),
    dst_bytes: Math.floor(Math.random() * 5000 + 40),
    land: 0,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    logged_in: protocol === "tcp" && Math.random() < 0.8 ? 1 : 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    count: Math.floor(Math.random() * 10 + 1),
    srv_count: Math.floor(Math.random() * 10 + 1),
    serror_rate: 0.0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_count: Math.floor(Math.random() * 50 + 10),
    dst_host_srv_count: Math.floor(Math.random() * 50 + 10),
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.05,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0,
    
    // network metadata
    src_ip: randPrivateIp(),
    dst_ip: randPrivateIp(),
    src_port: protocol === "icmp" ? 0 : Math.floor(Math.random() * 64511 + 1024),
    dst_port: protocol === "icmp" ? 0 : (service === "http" ? 80 : (service === "http_443" ? 443 : (service === "ssh" ? 22 : 80))),
    packet_length: Math.floor(Math.random() * 1000 + 60),
    protocol: protocol.toUpperCase(),
  };
}

function generateAttackPacket(templateName) {
  const template = ATTACK_TEMPLATES_JS[templateName];
  const base = generateNormalPacket();
  
  const packet = {
    ...base,
    ...template,
    protocol_type: template.protocol_type,
    protocol: template.protocol_type.toUpperCase(),
    src_ip: randPrivateIp(),
    dst_ip: randPrivateIp(),
  };
  
  packet.src_port = packet.protocol === "ICMP" ? 0 : Math.floor(Math.random() * 64511 + 1024);
  packet.dst_port = packet.protocol === "ICMP" ? 0 : template.dst_ports[Math.floor(Math.random() * template.dst_ports.length)];
  delete packet.dst_ports;
  
  return packet;
}

function getDemoStatus() {
  return {
    running: demoState.running,
    started_at: demoState.startedAt,
    config: demoState.config,
    last_exit_code: demoState.lastExitCode,
    last_error: demoState.lastError,
  };
}

function stopDemo() {
  if (!demoInterval) return false;
  clearInterval(demoInterval);
  demoInterval = null;
  demoState.running = false;
  demoState.startedAt = null;
  demoState.lastExitCode = 0;
  return true;
}

function startDemo({ duration = 90, rate = 2, attacks = 0.2, clearExisting = true } = {}) {
  if (demoInterval) {
    const err = new Error("Demo is already running");
    err.status = 409;
    throw err;
  }

  if (clearExisting) {
    memStore.clear();
    Object.assign(stats, {
      total: 0, attacks: 0, normal: 0,
      byCategory: { dos:0, probe:0, r2l:0, u2r:0, anomaly:0 },
      history: [],
    });
    if (usingMongo && TrafficLog) {
      TrafficLog.deleteMany({}).catch(() => {});
    }
  }

  demoState.startedAt = new Date().toISOString();
  demoState.config = { duration, rate, attacks, clearExisting };
  demoState.lastExitCode = null;
  demoState.lastError = null;
  demoState.running = true;

  const intervalMs = 1000 / rate;
  const endTime = Date.now() + duration * 1000;
  
  const attackTemplates = Object.keys(ATTACK_TEMPLATES_JS);
  let attackCount = 0;

  demoInterval = setInterval(async () => {
    if (Date.now() >= endTime) {
      stopDemo();
      return;
    }

    try {
      let packet;
      if (Math.random() < attacks) {
        const tmpl = attackTemplates[attackCount % attackTemplates.length];
        packet = generateAttackPacket(tmpl);
        attackCount++;
      } else {
        packet = generateNormalPacket();
      }

      // Call ML classification
      const result = await callML(packet);

      // Update stats
      stats.total++;
      if (result.is_attack) {
        stats.attacks++;
        const cat = result.attack_category;
        if (cat in stats.byCategory) stats.byCategory[cat]++;
      } else {
        stats.normal++;
      }

      const log = {
        id:              uuidv4(),
        timestamp:       new Date(),
        src_ip:          packet.src_ip,
        dst_ip:          packet.dst_ip,
        src_port:        packet.src_port,
        dst_port:        packet.dst_port,
        protocol:        packet.protocol,
        packet_length:   packet.packet_length,
        prediction:      result.prediction,
        is_attack:       result.is_attack,
        confidence:      result.confidence,
        attack_category: result.attack_category,
        model_used:      result.model_used,
        features:        packet,
      };

      await storeLog(log);
      dispatchAlerts(log).catch((err) => {
        console.error("alert dispatch error:", err.message);
      });
    } catch (err) {
      console.error("Demo packet generation/processing error:", err.message);
    }
  }, intervalMs);
}

// ── MongoDB ───────────────────────────────────────────────────────────────────
let usingMongo = false;

const TrafficLogSchema = new mongoose.Schema({
  id:              { type: String, default: () => uuidv4() },
  timestamp:       { type: Date,   default: Date.now, index: true },
  src_ip:          String,
  dst_ip:          String,
  src_port:        Number,
  dst_port:        Number,
  protocol:        String,
  packet_length:   Number,
  prediction:      String,
  is_attack:       Boolean,
  confidence:      Number,
  attack_category: String,
  model_used:      String,
  features:        mongoose.Schema.Types.Mixed,
});

let TrafficLog;

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 3000 })
  .then(() => {
    usingMongo = true;
    TrafficLog = mongoose.model("TrafficLog", TrafficLogSchema);
    console.log("✓ MongoDB connected");
  })
  .catch(() => {
    console.log("⚠  MongoDB unavailable — using in-memory store");
  });

// ── In-memory fallback ────────────────────────────────────────────────────────
const memStore = {
  logs:    [],
  maxSize: 5000,
  push(doc) {
    this.logs.unshift(doc);
    if (this.logs.length > this.maxSize) this.logs.pop();
  },
  find({ limit = 100, attackOnly = false } = {}) {
    let result = this.logs;
    if (attackOnly) result = result.filter(l => l.is_attack);
    return result.slice(0, limit);
  },
  count()       { return this.logs.length; },
  attackCount() { return this.logs.filter(l => l.is_attack).length; },
  clear()       { this.logs = []; },
};

// ── Stats tracking ────────────────────────────────────────────────────────────
const stats = {
  total:          0,
  attacks:        0,
  normal:         0,
  startTime:      Date.now(),
  byCategory:     { dos: 0, probe: 0, r2l: 0, u2r: 0, anomaly: 0 },
  history:        [],   // {time, total, attacks} every 60s
  lastMinuteTotal: 0,
  lastMinuteAttacks: 0,
};

// Sample history every 60 seconds
setInterval(() => {
  stats.history.push({
    time:    new Date().toISOString(),
    total:   stats.total - (stats.history.length > 0 ? stats.history.reduce((a,b) => a + b.total, 0) : 0),
    attacks: stats.attacks - (stats.history.length > 0 ? stats.history.reduce((a,b) => a + b.attacks, 0) : 0),
    total_cumulative: stats.total,
    attacks_cumulative: stats.attacks,
  });
  if (stats.history.length > 30) stats.history.shift();
}, 60_000);

// ── Helper: store log ─────────────────────────────────────────────────────────
async function storeLog(doc) {
  if (usingMongo && TrafficLog) {
    try {
      await new TrafficLog(doc).save();
      return;
    } catch { /* fall through */ }
  }
  memStore.push(doc);
}

// ── ML Service proxy ──────────────────────────────────────────────────────────
async function callML(features) {
  try {
    const res = await axios.post(`${ML_URL}/predict`, features, { timeout: 5000 });
    return res.data;
  } catch (err) {
    // ML service unavailable — use simple rule fallback
    const { serror_rate = 0, srv_serror_rate = 0,
            diff_srv_rate = 0, same_srv_rate = 1,
            num_failed_logins = 0, is_guest_login = 0,
            root_shell = 0 } = features;

    let category = "normal";
    if (serror_rate > 0.8 || srv_serror_rate > 0.8)            category = "dos";
    else if (diff_srv_rate > 0.6 && same_srv_rate < 0.4)        category = "probe";
    else if (num_failed_logins > 3 || is_guest_login === 1)     category = "r2l";
    else if (root_shell === 1)                                   category = "u2r";

    const labels = { dos:"Neptune", probe:"Portsweep", r2l:"GuestPasswd", u2r:"BufferOverflow" };
    return {
      prediction:      labels[category] || "Normal",
      is_attack:       category !== "normal",
      confidence:      70,
      attack_category: category,
      model_used:      "Rule-Based (ML service offline)",
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Routes
// ══════════════════════════════════════════════════════════════════════════════

// Health
app.get("/health", (_req, res) => res.json({ status: "ok", mongo: usingMongo }));

app.get("/api/alerts/status", (_req, res) => {
  res.json(getAlertStatus());
});

// ── POST /api/analyze — receive packet + classify ─────────────────────────────
app.post("/api/analyze", requireApiKey, async (req, res) => {
  try {
    const packet = req.body;

    // Call ML service
    const result = await callML(packet);

    // Update stats
    stats.total++;
    if (result.is_attack) {
      stats.attacks++;
      const cat = result.attack_category;
      if (cat in stats.byCategory) stats.byCategory[cat]++;
    } else {
      stats.normal++;
    }

    // Build log document
    const log = {
      id:              uuidv4(),
      timestamp:       new Date(),
      src_ip:          packet.src_ip    || "0.0.0.0",
      dst_ip:          packet.dst_ip    || "0.0.0.0",
      src_port:        packet.src_port  || 0,
      dst_port:        packet.dst_port  || 0,
      protocol:        packet.protocol  || (packet.protocol_type === 0 ? "ICMP"
                                          : packet.protocol_type === 2 ? "UDP"
                                          : "TCP"),
      packet_length:   packet.packet_length || 0,
      prediction:      result.prediction,
      is_attack:       result.is_attack,
      confidence:      result.confidence,
      attack_category: result.attack_category,
      model_used:      result.model_used,
      features:        packet,
    };

    await storeLog(log);
    dispatchAlerts(log).catch((err) => {
      console.error("alert dispatch error:", err.message);
    });

    res.json({ success: true, result, log_id: log.id });
  } catch (err) {
    console.error("analyze error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/logs ─────────────────────────────────────────────────────────────
app.get("/api/logs", async (req, res) => {
  try {
    const limit      = Math.min(parseInt(req.query.limit) || 100, 500);
    const attackOnly = req.query.attack_only === "true";

    if (usingMongo && TrafficLog) {
      const query = attackOnly ? { is_attack: true } : {};
      const docs  = await TrafficLog.find(query)
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();
      return res.json({ logs: docs, total: docs.length, source: "mongodb" });
    }

    res.json({
      logs:   memStore.find({ limit, attackOnly }),
      total:  memStore.count(),
      source: "memory",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/logs ──────────────────────────────────────────────────────────
app.delete("/api/logs", requireApiKey, async (req, res) => {
  try {
    if (usingMongo && TrafficLog) {
      await TrafficLog.deleteMany({});
    }
    memStore.clear();
    Object.assign(stats, {
      total: 0, attacks: 0, normal: 0,
      byCategory: { dos:0, probe:0, r2l:0, u2r:0, anomaly:0 },
      history: [],
    });
    res.json({ success: true, message: "All logs cleared" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/stats ────────────────────────────────────────────────────────────
app.get("/api/stats", (_req, res) => {
  const uptimeMs  = Date.now() - stats.startTime;
  const uptimeSec = Math.floor(uptimeMs / 1000);
  res.json({
    total_packets:  stats.total,
    attack_packets: stats.attacks,
    normal_packets: stats.normal,
    attack_rate:    stats.total > 0 ? +((stats.attacks / stats.total) * 100).toFixed(2) : 0,
    by_category:    stats.byCategory,
    uptime_seconds: uptimeSec,
    storage:        usingMongo ? "mongodb" : "memory",
  });
});

// ── GET /api/stats/history ────────────────────────────────────────────────────
app.get("/api/stats/history", (_req, res) => {
  res.json({ history: stats.history });
});

// ── Demo controls ────────────────────────────────────────────────────────────
app.get("/api/demo/status", (_req, res) => {
  res.json(getDemoStatus());
});

app.post("/api/demo/start", requireApiKey, (req, res) => {
  try {
    const duration = Math.max(15, Math.min(Number(req.body.duration) || 90, 900));
    const rate = Math.max(0.5, Math.min(Number(req.body.rate) || 2, 20));
    const attacks = Math.max(0, Math.min(Number(req.body.attacks) || 0.2, 1));
    const clearExisting = req.body.clear_existing !== false;

    startDemo({ duration, rate, attacks, clearExisting });
    res.json({ success: true, status: getDemoStatus() });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post("/api/demo/stop", requireApiKey, (_req, res) => {
  const stopped = stopDemo();
  res.json({ success: stopped, status: getDemoStatus() });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  NIDS Backend running on http://localhost:${PORT}`);
  console.log(`   ML Service : ${ML_URL}`);
  console.log(`   Storage    : ${usingMongo ? "MongoDB" : "in-memory"}\n`);
  const alertStatus = getAlertStatus();
  console.log(`   Alerts     : ${alertStatus.enabled ? alertStatus.active_channels.join(", ") : "disabled"}\n`);
});
