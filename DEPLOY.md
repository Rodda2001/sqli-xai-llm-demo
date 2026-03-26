# QueryGuard — Deployment Guide

## Local Development

### Prerequisites
- Python 3.10+ with venv
- Go 1.21+
- Node.js 18+
- Ollama (for LLM analysis)

### Quick Start

```bash
# 1. Build everything
chmod +x build.sh start.sh
./build.sh

# 2. Start all services
./start.sh

# 3. With simulation
./start.sh simulate
```

### Manual Start (each in separate terminal)

```bash
# Terminal 1 — Ollama
ollama serve

# Terminal 2 — Detection server
cd detection
source venv/bin/activate
python3 server.py

# Terminal 3 — Gateway
cd gateway
go run main.go

# Terminal 4 — Dashboard (dev mode)
cd dashboard
npm run dev

# Terminal 5 — Simulation (optional)
python3 tests/generate_log.py --speed fast
cd agent && go run main.go -file /tmp/mysql_general.log
```

Dashboard: http://localhost:5173 (dev) or http://localhost:9000 (production build)

---

## Production Deployment on Render

QueryGuard has 2 deployable services: the Python detection server and the Go gateway (which serves the React dashboard).

### Option 1: Deploy Detection Server (Render Web Service)

1. Create a new **Web Service** on Render
2. Connect your GitHub repo
3. Settings:
   - **Name**: `queryguard-detection`
   - **Runtime**: Python 3
   - **Build Command**: `cd detection && pip install -r requirements.txt`
   - **Start Command**: `cd detection && uvicorn server:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free or Starter
4. Environment Variables:
   - None required (Ollama won't be available on free tier — LLM falls back to template)

### Option 2: Deploy Gateway + Dashboard (Render Web Service)

1. Create another **Web Service** on Render
2. Settings:
   - **Name**: `queryguard-gateway`
   - **Runtime**: Docker (or Native with Go + Node build)
   - **Build Command**: `cd dashboard && npm install && npm run build && cd ../gateway && CGO_ENABLED=1 go build -o gateway main.go`
   - **Start Command**: `cd gateway && ./gateway`
   - **Plan**: Free or Starter
3. Environment Variables:
   - `DETECTION_URL`: `https://queryguard-detection.onrender.com`
   - `PORT`: `10000` (Render assigns this automatically)
   - `DB_PATH`: `/tmp/filesense.db`

### Important Notes for Render

- **SQLite**: Use `/tmp/filesense.db` — Render's filesystem is ephemeral
- **Ollama**: Not available on free tier. LLM analysis will use the fallback template
- **WebSocket**: Works automatically — the frontend auto-detects `wss://` in production
- **Simulate**: Won't work on Render (no agent/generator). Use the Scan tab for manual testing
- **Free tier**: Services spin down after 15 min of inactivity, first request takes ~30s

---

## For Viva Demo (Recommended)

Run everything locally on your laptop. This gives you:
- Full Ollama LLM analysis
- Real-time simulation with live attacks
- WebSocket live feed
- Email alerts

```bash
./build.sh
./start.sh simulate
# Open http://localhost:9000
```

The simulate button on the Monitor page triggers `generate_log.py` + `agent` automatically.

---

## Project Structure

```
SQLI+XAI+LLM/
├── detection/          Python ML + SHAP + LLM server
│   ├── server.py       FastAPI server (:8000)
│   ├── detect.py       Detection engine
│   ├── config.py       Configuration
│   └── models/         Trained ML models (.joblib)
├── gateway/            Go API gateway
│   └── main.go         Fiber server (:9000)
├── agent/              Go log agent
│   └── main.go         Tails MySQL log → POSTs to gateway
├── dashboard/          React frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── api.js
│   │   ├── pages/      Monitor, Scan, Settings, About, Feedback
│   │   ├── components/ AlertQueue, DetailPanel, ShapChart, etc
│   │   └── hooks/      useGateway (WebSocket + polling)
│   └── dist/           Production build (after npm run build)
├── tests/
│   └── generate_log.py MySQL log traffic simulator
├── build.sh            Build all components
├── start.sh            Start all services
└── DEPLOY.md           This file
```
