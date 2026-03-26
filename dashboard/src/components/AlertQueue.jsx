import { useState } from 'react'

function sevColor(sev) {
  return {critical:'#ff4757', high:'#ff7e30', medium:'#ffc300', normal:'#2ed573'}[sev] || '#dce8f4'
}

export default function AlertQueue({ detections, onSelect, selected }) {
  const [filter, setFilter] = useState('all')

  const filtered = detections.filter(d => {
    if (filter === 'critical') return d.severity === 'critical'
    if (filter === 'high')     return d.severity === 'high'
    if (filter === 'normal')   return !d.is_sqli
    return true
  })

  return (
    <div className="queue-panel">
      <div className="panel-header">
        <span className="panel-label">Alert Queue</span>
        <span className="panel-count">{filtered.length} alerts</span>
      </div>
      <div className="filter-row">
        {['all','critical','high','normal'].map(f => (
          <button key={f} className={`chip ${f==='critical'?'crit':''} ${filter===f?'on':''}`} onClick={() => setFilter(f)}>
            {f.toUpperCase()}
          </button>
        ))}
      </div>
      <div className="queue-list">
        {filtered.length === 0 && (
          <div style={{padding:'36px 14px', textAlign:'center', color:'#526b85', fontSize:'12px'}}>
            Waiting for queries...
          </div>
        )}
        {filtered.map((d, i) => {
          const sev   = d.is_sqli ? (d.severity || 'high') : 'normal'
          const type  = d.is_sqli ? (d.attack_type || 'sqli').replace(/_/g,' ') : 'normal query'
          const time  = (d.timestamp || '').split(' ')[1] || ''
          const query = (d.query || '').substring(0, 40)
          const color = sevColor(sev)
          return (
            <div key={i} className={`alert-row sev-${sev} ${selected===i?'picked':''}`} onClick={() => onSelect(i, d)}>
              <div className="row-top">
                <span className="sev-tag" style={{background:`${color}22`, color, border:`1px solid ${color}44`}}>{sev.toUpperCase()}</span>
                <span className="row-type">{type}</span>
                <span className="row-time">{time}</span>
              </div>
              <div className="row-bottom">
                <span className="row-ip">{d.source_ip || '?'}</span>
                <span className="row-query">{query}{d.query?.length > 40 ? '…' : ''}</span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
