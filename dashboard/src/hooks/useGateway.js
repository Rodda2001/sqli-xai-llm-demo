import { useState, useEffect, useRef } from 'react'
import { getStats, getHistory, createWebSocket } from '../api'
export function useGateway() {
  const [detections, setDetections] = useState([])
  const [stats, setStats]           = useState({ total: 0, sqli_detected: 0, normal: 0 })
  const [connected, setConnected]   = useState(false)
  const wsRef = useRef(null)
  useEffect(() => {
    loadHistory(); loadStats(); connect()
    const interval = setInterval(loadStats, 5000)
    return () => { clearInterval(interval); if (wsRef.current) wsRef.current.close() }
  }, [])
  function connect() {
    const ws = createWebSocket((data) => { setDetections(prev => [data, ...prev].slice(0, 500)); loadStats() })
    ws.onopen  = () => setConnected(true)
    ws.onclose = () => { setConnected(false); setTimeout(connect, 3000) }
    wsRef.current = ws
  }
  async function loadHistory() { try { const data = await getHistory(500); if (data.items) setDetections(data.items) } catch(e) {} }
  async function loadStats()   { try { const data = await getStats(); setStats(data) } catch(e) {} }
  return { detections, stats, connected }
}