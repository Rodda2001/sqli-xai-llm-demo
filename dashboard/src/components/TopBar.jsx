import { useEffect, useState } from 'react'

export default function TopBar({ connected, activeTab, setActiveTab }) {
  const [time, setTime] = useState('')
  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toTimeString().slice(0,8)), 1000)
    return () => clearInterval(t)
  }, [])
  return (
    <div className="topbar">
      <div className="brand">
        <div className="brand-icon">🛡</div>
        <div className="brand-name">Query<span className="brand-accent">Guard</span></div>
      </div>
      <nav className="tabs">
        {['monitor','scan','settings','about','feedback'].map(tab => (
          <button key={tab} className={`tab ${activeTab===tab?'active':''}`} onClick={() => setActiveTab(tab)}>
            {tab==='monitor' && <span className="tab-dot"></span>}
            {tab.toUpperCase()}
          </button>
        ))}
      </nav>
      <div className="topbar-right">
        <div className={`live-pill ${connected?'online':'offline'}`}>
          <div className="live-dot"></div>
          {connected ? 'LIVE' : 'RECONNECTING'}
        </div>
        <div className="clock">{time}</div>
      </div>
    </div>
  )
}
