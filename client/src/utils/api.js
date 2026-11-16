/**
 * api.js — NIDS frontend API helpers
 *
 * Wraps all backend requests with:
 *  - Consistent base URL / API key config
 *  - Typed error handling (network vs. HTTP errors)
 *  - Exponential backoff retry for transient failures
 */

const BASE    = import.meta.env.VITE_BACKEND_URL || "http://localhost:3001";
const API_KEY = import.meta.env.VITE_API_KEY     || "";

const authenticatedHeaders = {
  "Content-Type": "application/json",
  "X-API-Key": API_KEY,
};

// ── Error types ────────────────────────────────────────────────────────────────
class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name   = "ApiError";
    this.status = status;
  }
}

// ── Core fetch helper with retry ───────────────────────────────────────────────
async function apiFetch(url, options = {}, { retries = 2, retryDelay = 500 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) {
        let detail = "";
        try {
          const body = await res.clone().json();
          detail = body?.error || body?.message || "";
        } catch { /* ignore */ }
        throw new ApiError(
          `HTTP ${res.status}: ${detail || res.statusText}`,
          res.status,
        );
      }
      return res.json();
    } catch (err) {
      lastErr = err;
      // Don't retry on auth/validation errors
      if (err instanceof ApiError && err.status >= 400 && err.status < 500) throw err;
      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
      }
    }
  }
  throw lastErr;
}

// ── Public API ────────────────────────────────────────────────────────────────
export async function fetchStats() {
  return apiFetch(`${BASE}/api/stats`);
}

export async function fetchLogs(limit = 100, attackOnly = false) {
  return apiFetch(`${BASE}/api/logs?limit=${limit}&attack_only=${attackOnly}`);
}

export async function clearLogs() {
  return apiFetch(`${BASE}/api/logs`, {
    method: "DELETE",
    headers: authenticatedHeaders,
  });
}

export async function checkHealth() {
  try {
    const data = await apiFetch(`${BASE}/health`, {}, { retries: 1, retryDelay: 300 });
    return !!(data?.status === "ok" || data?.status);
  } catch {
    return false;
  }
}

export async function fetchHistory() {
  return apiFetch(`${BASE}/api/stats/history`);
}

export async function fetchDemoStatus() {
  return apiFetch(`${BASE}/api/demo/status`);
}

export async function startDemo(payload) {
  return apiFetch(`${BASE}/api/demo/start`, {
    method: "POST",
    headers: authenticatedHeaders,
    body: JSON.stringify(payload),
  });
}

export async function stopDemo() {
  return apiFetch(`${BASE}/api/demo/stop`, {
    method: "POST",
    headers: authenticatedHeaders,
  });
}

export async function fetchAlertStatus() {
  return apiFetch(`${BASE}/api/alerts/status`);
}
