const BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:3001";
const API_KEY = import.meta.env.VITE_API_KEY || "";

const authenticatedHeaders = {
  "Content-Type": "application/json",
  "X-API-Key": API_KEY,
};

async function asJson(response, message) {
  if (!response.ok) throw new Error(message);
  return response.json();
}

export async function fetchStats() {
  const r = await fetch(`${BASE}/api/stats`);
  return asJson(r, "stats fetch failed");
}

export async function fetchLogs(limit = 100, attackOnly = false) {
  const url = `${BASE}/api/logs?limit=${limit}&attack_only=${attackOnly}`;
  const r = await fetch(url);
  return asJson(r, "logs fetch failed");
}

export async function clearLogs() {
  const r = await fetch(`${BASE}/api/logs`, {
    method: "DELETE",
    headers: authenticatedHeaders,
  });
  return asJson(r, "clear failed");
}

export async function checkHealth() {
  const r = await fetch(`${BASE}/health`);
  return r.ok;
}

export async function fetchHistory() {
  const r = await fetch(`${BASE}/api/stats/history`);
  return asJson(r, "history fetch failed");
}

export async function fetchDemoStatus() {
  const r = await fetch(`${BASE}/api/demo/status`);
  return asJson(r, "demo status fetch failed");
}

export async function startDemo(payload) {
  const r = await fetch(`${BASE}/api/demo/start`, {
    method: "POST",
    headers: authenticatedHeaders,
    body: JSON.stringify(payload),
  });
  return asJson(r, "demo start failed");
}

export async function stopDemo() {
  const r = await fetch(`${BASE}/api/demo/stop`, {
    method: "POST",
    headers: authenticatedHeaders,
  });
  return asJson(r, "demo stop failed");
}
