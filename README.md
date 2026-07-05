# Threat-IQ

AI-Based Network Intrusion Detection System (NIDS)

A production-ready NIDS that captures live network packets, classifies traffic
using ML models (XGBoost, Random Forest, Isolation Forest), and displays
real-time results on a dark-themed React dashboard.

---

## 🌐 Live Demo

Experience the React Dashboard interface in action:
👉 **[Threat-IQ Live Demo](https://threat-lens-lovat.vercel.app/)**

> [!NOTE]
> * **Backend Wake-Up Time**: Please wait 1 to 2 minutes when first loading the demo. The backend services are hosted on a free Render tier and may take a moment to spin up if they have gone idle.
> * **Local Installation vs. Web Demo**: The live web demo allows you to inspect the dashboard interface and traffic history. To experience the full capabilities of the system—such as capturing live network packets from your own machine and running simulated traffic scripts—please install and run the application locally on your PC by following the [Setup & Installation](#-setup--installation) instructions below.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         NIDS Architecture                            │
│                                                                      │
│  ┌─────────────────┐     features     ┌────────────────────────┐    │
│  │  Packet Capture │ ──────────────▶  │    Node.js Backend     │    │
│  │  (Python/Scapy) │                  │  Express + MongoDB     │    │
│  └─────────────────┘                  │  :3001                 │    │
│       ↕ Live Network                  └───────────┬────────────┘    │
│  (or --simulate flag)                             │                 │
│                                                   │ /predict        │
│                                         ┌─────────▼──────────┐     │
│                                         │    ML Service       │     │
│                                         │  FastAPI + sklearn  │     │
│                                         │  XGBoost + IsoForest│     │
│                                         │  :8000              │     │
│                                         └─────────────────────┘     │
│                                                   │                 │
│                                      ┌────────────▼────────────┐    │
│                                      │   React Dashboard        │    │
│                                      │   Chart.js + Tailwind    │    │
│                                      │   :5173                  │    │
│                                      └─────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

**Data Flow:**
```
Live Packet → Scapy Capture → Feature Extraction → POST /api/analyze
→ Node Backend → POST /predict (ML Service) → XGBoost Prediction
→ Store in MongoDB → React Dashboard (polling every 3s) → Live Display
```

---

## 🗂️ Project Structure

```
nids/
├── client/                     # React Frontend
│   ├── src/
│   │   ├── App.jsx             # Main dashboard component
│   │   ├── index.css           # Dark cyberpunk theme
│   │   └── utils/api.js        # API helpers
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
│
├── server/                     # Node.js Backend
│   ├── index.js                # Express server
│   ├── package.json
│   └── .env
│
├── ml-service/                 # Python ML Service
│   ├── main.py                 # FastAPI app
│   ├── train.py                # Training script
│   ├── requirements.txt
│   ├── models/                 # Saved .pkl files (after training)
│   └── data/                   # NSL-KDD dataset (auto-downloaded)
│
├── packet-capture/             # Live capture module
│   ├── capture.py              # Scapy capture + simulator
│   └── requirements.txt
│
└── README.md
```

---

## ⚙️ Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.9+ | For ML service and packet capture |
| Node.js | 18+ | For backend and frontend |
| MongoDB | 6+ | **Optional** — system works in-memory without it |
| Root/Admin | — | Only needed for live packet capture |

---

## 🚀 Setup & Installation

### Environment configuration

Copy the example files before running locally:

```bash
cp server/.env.example server/.env
cp client/.env.example client/.env
```

Set the same long random value for `API_KEY` in `server/.env`,
`VITE_API_KEY` in `client/.env`, and `NIDS_API_KEY` when running packet capture.
The backend accepts browser requests only from `CORS_ALLOWED_ORIGINS`, which can
contain a comma-separated list of frontend URLs.

### Step 1 — ML Service (train models FIRST)

```bash
cd ml-service
pip install -r requirements.txt

# Downloads NSL-KDD and trains all models (~5-10 min)
python train.py
```

This will:
- Auto-download NSL-KDD dataset from GitHub
- Train Random Forest, XGBoost, and Isolation Forest
- Print accuracy scores and classification report
- Save models to `ml-service/models/`

```bash
# Start the ML API
python -m uvicorn main:app --reload --port 8000
```

Verify: http://localhost:8000 → `{"status":"NIDS ML Service running"}`

---

### Step 2 — Node.js Backend

```bash
cd server
npm install
npm start
```

Verify: http://localhost:3001/health → `{"status":"ok"}`

---

### Step 3 — React Frontend

```bash
cd client
npm install
npm run dev
```

Open: **http://localhost:5173**

---

### Step 4 — Start Packet Capture

**Option A — Simulate traffic (no root needed, great for testing):**
```bash
cd packet-capture
pip install -r requirements.txt

# Simulate 120 seconds of mixed normal + attack traffic at 2 pkt/s
python capture.py --simulate --duration 120

# Higher intensity demo
python capture.py --simulate --duration 300 --rate 5 --attacks 0.5
```

**Option B — Live capture (requires root/admin):**
```bash
# Linux / macOS
sudo python capture.py

# Specific interface
sudo python capture.py --interface eth0

# List available interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

**Windows (Run Command Prompt as Administrator):**
```cmd
python capture.py
```

---

## 🧠 ML Models

| Model | Purpose | Notes |
|-------|---------|-------|
| **XGBoost** | Primary multi-class classifier | Tuned & calibrated test set accuracy (**81.31%**) |
| **Random Forest** | Fallback classifier | Used if XGBoost unavailable |
| **Isolation Forest** | Anomaly/zero-day detection | Catches unknown attack patterns |

### Attack Categories Detected

| Category | Examples | Severity |
|----------|---------|----------|
| **DoS** | Neptune, Smurf, Back, Teardrop, Pod | CRITICAL |
| **Probe** | Portsweep, IPSweep, NMAP, Satan | HIGH |
| **R2L** | Guess Password, FTP Write, IMAP | HIGH |
| **U2R** | Buffer Overflow, Rootkit, LoadModule | CRITICAL |
| **Anomaly** | Unknown / zero-day patterns | MEDIUM |

### Rule-Based Fallback

If models haven't been trained yet, the system uses heuristic rules:
- High `serror_rate` → DoS/Neptune
- High `diff_srv_rate` + low `same_srv_rate` → Probe/Portsweep
- Multiple failed logins → R2L/GuestPasswd
- `root_shell = 1` → U2R/BufferOverflow

### Model Performance Metrics (NSL-KDD Test Set)

The models are evaluated against the realistic, imbalanced `KDDTest+.txt` test set (which contains several novel attack types not present in the training set). 

Using **ColumnTransformer One-Hot Encoding** and **inference threshold calibration** (scaling class probabilities to handle extreme imbalance), we achieve the following verified results:

#### Overall Comparison
| Model | Accuracy | Weighted Precision | Weighted Recall | Weighted F1-Score | Macro F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **XGBoost (Tuned)** | **81.31%** | **83.90%** | **81.31%** | **0.7961** | **0.6908** |
| **Random Forest (Tuned)** | 78.89% | 81.54% | 78.89% | 0.7793 | 0.6715 |

#### Per-Class Recall (XGBoost vs. Random Forest)
- **DoS**: XGBoost **83%** | Random Forest **74%**
- **Normal**: XGBoost **97%** | Random Forest **96%**
- **Probe**: XGBoost **78%** | Random Forest **76%**
- **R2L (Remote-to-Local)**: XGBoost **28%** | Random Forest **37%** *(Calibrated threshold scaling raised this from 1%-7% baseline)*
- **U2R (User-to-Root)**: XGBoost **55%** | Random Forest **78%** *(Calibrated threshold scaling raised this from 7%-28% baseline)*

---

## 📊 Dataset

**NSL-KDD** — An improved version of the KDD Cup 1999 dataset.

- 41 features per connection record
- ~125,000 training samples
- ~22,000 test samples
- 5 classes: normal, dos, probe, r2l, u2r

Manual download (if auto-download fails):
1. Visit: https://github.com/defcom17/NSL_KDD
2. Download `KDDTrain+.txt` and `KDDTest+.txt`
3. Place both files in `ml-service/data/`

---

## 🔌 API Reference

### ML Service (port 8000)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health + model status |
| `/health` | GET | Simple health check |
| `/predict` | POST | Classify single packet |
| `/predict/batch` | POST | Classify multiple packets |
| `/reload-models` | POST | Reload trained models from disk |

---

## ☁️ Free Deployment

This repository includes `render.yaml` for the Node and Python services and
`vercel.json` for the React dashboard.

### 1. MongoDB Atlas

1. Create a free Atlas cluster and database user.
2. Add `0.0.0.0/0` to the Atlas network access list because Render does not use
   a fixed outbound IP on its free service. Use a strong database password.
3. Copy the connection string for the `MONGODB_URI` Render variable.

### 2. Render

1. Push this repository to GitHub, then create a Render Blueprint from it.
2. Render creates `nids-ml-service` and `nids-backend` from `render.yaml`.
3. Set these backend variables when prompted:
   - `ML_SERVICE_URL`: the complete public ML URL, such as
     `https://nids-ml-service.onrender.com`
   - `MONGODB_URI`: the Atlas connection string
   - `CORS_ALLOWED_ORIGINS`: the final Vercel URL
4. Render generates `API_KEY`. Copy its value for the next step.

Free Render services sleep when idle, so the first request can be slow. The two
services also share the workspace's free usage allowance.

### 3. Vercel

1. Import the same GitHub repository into Vercel.
2. Keep the repository root as the project root; `vercel.json` builds `client`.
3. Add `VITE_BACKEND_URL` with the complete Render backend URL.
4. Add `VITE_API_KEY` with the same value as the backend `API_KEY`.
5. Deploy, then update `CORS_ALLOWED_ORIGINS` on Render with the Vercel URL.

`VITE_API_KEY` is included in the browser bundle, so it prevents casual or
accidental writes but is not a true secret. For a public production application,
replace it with user authentication and keep privileged operations server-side.

### 4. Run packet capture locally

Cloud services cannot capture traffic from your computer. Run the agent on the
computer or network being monitored:

```bash
export NIDS_API_KEY="the-same-api-key"
python packet-capture/capture.py \
  --backend https://nids-backend.onrender.com/api/analyze
```

Live capture still requires administrator/root privileges. Simulation mode does
not:

```bash
python packet-capture/capture.py --simulate \
  --backend https://nids-backend.onrender.com/api/analyze
```

### Protected backend routes

The following routes require an `X-API-Key` header:

- `POST /api/analyze`
- `DELETE /api/logs`
- `POST /api/demo/start`
- `POST /api/demo/stop`

Dashboard reads and health checks remain public.

**POST /predict body:**
```json
{
  "protocol_type": 1,
  "src_bytes": 1500,
  "dst_bytes": 0,
  "serror_rate": 0.99,
  "same_srv_rate": 1.0,
  "count": 511
}
```

**Response:**
```json
{
  "prediction": "neptune",
  "is_attack": true,
  "confidence": 97.3,
  "attack_category": "dos",
  "model_used": "XGBoost + IsolationForest",
  "features_received": 40,
  "latency_ms": 2.1
}
```

### Backend (port 3001)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/analyze` | POST | Receive + classify packet |
| `/api/logs` | GET | Fetch traffic logs |
| `/api/stats` | GET | Current counters |
| `/api/stats/history` | GET | 30-min time series |
| `/api/logs` | DELETE | Clear all logs |
| `/api/alerts/status` | GET | Alert integration status |

---

## 🔔 Alert Integrations

The backend can send **critical detections** to external channels when
`attack_category` matches `ALERT_CRITICAL_CATEGORIES` (defaults to `dos,u2r`).
Duplicate alerts are rate-limited using `ALERT_COOLDOWN_MS` (defaults to 5 min).

Configure any combination of these in `server/.env`:

```env
# Critical categories and dedupe cooldown
ALERT_CRITICAL_CATEGORIES=dos,u2r
ALERT_COOLDOWN_MS=300000

# Email via SMTP
EMAIL_ALERTS_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@example.com
SMTP_PASS=your-app-password
EMAIL_FROM=your-email@example.com
EMAIL_TO=security-team@example.com

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Telegram
TELEGRAM_BOT_TOKEN=123456789:bot_token_here
TELEGRAM_CHAT_ID=123456789
```

Notes:
- Email requires SMTP credentials. For Gmail, use an app password rather than your main password.
- Slack and Discord use incoming webhook URLs.
- Telegram requires a bot token and a target chat ID.
- Alert delivery runs in the backend after `/api/analyze`, so the dashboard still works even if a channel is misconfigured.

Quick check:

```bash
curl http://localhost:3001/api/alerts/status
```

---

## 🧪 Testing

### Test ML API directly:
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"serror_rate": 0.99, "count": 511, "src_bytes": 0, "protocol_type": 1}'
```

### Test Backend:
```bash
curl http://localhost:3001/api/stats
curl http://localhost:3001/api/logs?limit=10
curl http://localhost:3001/api/alerts/status
```

### Simulate a Neptune (DoS) attack:
```python
import requests

requests.post("http://localhost:3001/api/analyze", json={
    "protocol_type": 1,
    "src_bytes": 0,
    "dst_bytes": 0,
    "serror_rate": 0.99,
    "srv_serror_rate": 0.99,
    "count": 511,
    "same_srv_rate": 1.0,
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.5",
    "src_port": 45231,
    "dst_port": 80,
    "packet_length": 60
})
```

---

## capture.py Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--simulate` | false | Use traffic simulator |
| `--duration` | 60 | Simulation time in seconds |
| `--rate` | 2.0 | Packets per second |
| `--attacks` | 0.3 | Attack ratio (0–1) |
| `--interface` | auto | Network interface for live capture |
| `--count` | 0 | Max live packets (0 = unlimited) |
| `--backend` | localhost:3001 | Backend URL |

---

## ⚠️ Permissions

Live packet capture requires elevated privileges:

- **Linux/macOS:** Run capture.py with `sudo`
- **Windows:** Run terminal as Administrator
- **No-root option:** Use `--simulate` flag

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| ML models not loading | Run `python train.py` in `ml-service/` first |
| MongoDB connection refused | System auto-switches to in-memory mode |
| Scapy permission error | Use `sudo` or `--simulate` |
| XGBoost not found | `pip install xgboost` — falls back to Random Forest |
| Port in use | Change in `.env` (backend) or `--port` (ML service) |
| Can't reach backend | Check http://localhost:3001/health |

---

## 🔒 Security Notes

- This system is for **educational and defensive purposes only**
- Packet capture may be illegal without authorization on networks you don't own
- Trained models detect known attack patterns; zero-day attacks may be missed
- Use Isolation Forest (`anomaly` category) for unknown threat detection

---

## 📦 Dependencies Summary

### Python (ml-service/)
- `fastapi` + `uvicorn` — ML API server
- `scikit-learn` — Random Forest + Isolation Forest
- `xgboost` — Primary classifier
- `pandas` + `numpy` — Data processing
- `joblib` — Model serialization

### Python (packet-capture/)
- `scapy` — Live packet capture
- `requests` — HTTP to backend

### Node.js (server/)
- `express` — HTTP server
- `mongoose` — MongoDB ODM
- `axios` — HTTP to ML service
- `cors`, `morgan`, `dotenv`, `uuid`

### JavaScript (client/)
- `react` + `react-dom` — UI framework
- `chart.js` + `react-chartjs-2` — Data visualization
- `vite` — Build tool
wert

## License

This project is licensed under the MIT License.
