const BASE = ''

export async function getStatus() { const r = await fetch(`${BASE}/api/status`); return r.json() }
export async function getHistory(limit=500) { const r = await fetch(`${BASE}/api/history?limit=${limit}`); return r.json() }
export async function getStats() { const r = await fetch(`${BASE}/api/stats`); return r.json() }
export async function getConfig() { const r = await fetch(`${BASE}/api/config`); return r.json() }
export async function saveConfig(data) { const r = await fetch(`${BASE}/api/config`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}); return r.json() }

// Analyze with 60s timeout (LLM can be slow)
export async function analyze(query) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 60000)
  try {
    const r = await fetch(`${BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query }),
      signal: controller.signal
    })
    return r.json()
  } finally {
    clearTimeout(timeout)
  }
}

// Simulate
export async function startSimulate() { const r = await fetch(`${BASE}/api/simulate/start`,{method:'POST'}); return r.json() }
export async function stopSimulate() { const r = await fetch(`${BASE}/api/simulate/stop`,{method:'POST'}); return r.json() }
export async function getSimulateStatus() { const r = await fetch(`${BASE}/api/simulate/status`); return r.json() }

// Feedback
export async function sendFeedback(data) {
  const r = await fetch(`${BASE}/api/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  return r.json()
}

// WebSocket — auto-detect protocol and host for production
export function createWebSocket(onMessage) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const ws = new WebSocket(`${proto}//${host}/api/ws`)
  ws.onmessage = e => {
    const data = JSON.parse(e.data)
    if (data.type !== 'connected') onMessage(data)
  }
  return ws
}
