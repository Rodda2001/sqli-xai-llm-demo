import { useState, useEffect } from 'react'
import { startSimulate, stopSimulate, getSimulateStatus } from '../api'
import AlertQueue from '../components/AlertQueue'
import DetailPanel from '../components/DetailPanel'
import AnalyticsPanel from '../components/AnalyticsPanel'

export default function MonitorPage({ detections }) {
  const [selected, setSelected] = useState(-1)
  const [detail, setDetail]     = useState(null)
  const [simRunning, setSimRunning] = useState(false)
  const [simLoading, setSimLoading] = useState(false)
  const [simError, setSimError]     = useState('')

  // Check simulation status on mount and poll every 5s
  useEffect(() => {
    checkStatus()
    const interval = setInterval(checkStatus, 5000)
    return () => clearInterval(interval)
  }, [])

  async function checkStatus() {
    try {
      const data = await getSimulateStatus()
      setSimRunning(data.running)
    } catch(e) {}
  }

  async function toggleSimulate() {
    setSimLoading(true)
    setSimError('')
    try {
      if (simRunning) {
        await stopSimulate()
        setSimRunning(false)
      } else {
        const res = await startSimulate()
        if (res.error) {
          setSimError(res.error)
        } else {
          setSimRunning(true)
        }
      }
    } catch(e) {
      setSimError('Failed to connect to gateway')
    }
    setSimLoading(false)
  }

  function handleSelect(i, d) {
    setSelected(i)
    setDetail(d)
  }

  return (
    <div className="monitor-layout">
      <div style={{display:'flex', flexDirection:'column', overflow:'hidden'}}>
        {/* Simulate control bar */}
        <div style={{
          display:'flex', alignItems:'center', gap:'10px',
          padding:'10px 14px', borderBottom:'1px solid #1e2d40',
          background:'#111820', flexShrink:0
        }}>
          <button
            onClick={toggleSimulate}
            disabled={simLoading}
            style={{
              display:'flex', alignItems:'center', gap:'6px',
              background: simRunning ? 'rgba(255,71,87,0.12)' : 'rgba(46,213,115,0.12)',
              border: `1px solid ${simRunning ? 'rgba(255,71,87,0.3)' : 'rgba(46,213,115,0.3)'}`,
              color: simRunning ? '#ff4757' : '#2ed573',
              borderRadius:'6px', padding:'7px 14px',
              fontFamily:'IBM Plex Mono, monospace', fontSize:'11px',
              fontWeight:600, cursor: simLoading ? 'not-allowed' : 'pointer',
              opacity: simLoading ? 0.5 : 1, transition:'all 0.15s',
              letterSpacing:'0.5px'
            }}
          >
            {simRunning && <span style={{
              width:'6px', height:'6px', borderRadius:'50%',
              background:'#ff4757', animation:'blink 1s infinite'
            }}></span>}
            {simLoading ? 'WORKING...' : simRunning ? 'STOP SIMULATION' : '▶ START SIMULATION'}
          </button>
          {simRunning && (
            <span style={{fontSize:'10px', color:'#526b85'}}>
              Log generator + agent running — queries flowing live
            </span>
          )}
          {simError && (
            <span style={{fontSize:'10px', color:'#ff4757'}}>{simError}</span>
          )}
        </div>
        <AlertQueue detections={detections} onSelect={handleSelect} selected={selected} />
      </div>
      <DetailPanel detection={detail} />
      <AnalyticsPanel detections={detections} />
    </div>
  )
}
