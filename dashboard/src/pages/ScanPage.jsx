import { useState } from 'react'
import { analyze } from '../api'
import ShapChart from '../components/ShapChart'

function sevColor(sev) {
  return {critical:'#ff4757', high:'#ff7e30', medium:'#ffc300', normal:'#2ed573'}[sev] || '#dce8f4'
}

export default function ScanPage() {
  const [query,   setQuery]   = useState('')
  const [loading, setLoading] = useState(false)
  const [result,  setResult]  = useState(null)
  const [error,   setError]   = useState('')

  async function runScan() {
    if (!query.trim()) return
    setLoading(true)
    setResult(null)
    setError('')
    try {
      const data = await analyze(query)
      setResult(data)
    } catch(e) {
      setError('Cannot connect to gateway. Make sure it is running.')
    }
    setLoading(false)
  }

  const sev   = result ? (result.is_sqli ? (result.severity || 'high') : 'normal') : null
  const color = sev ? sevColor(sev) : null

  return (
    <div className="page-wrap">
      <div className="page-title">Manual Query Scanner</div>
      <div className="page-sub">Enter any SQL query to run it through the ML + SHAP + LLM detection pipeline.</div>

      <div className="scan-row">
        <input
          className="scan-input"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && runScan()}
          placeholder="e.g. ' OR '1'='1  or  1 UNION SELECT user,pass FROM admin--"
        />
        <button className="btn-primary" onClick={runScan} disabled={loading}>
          {loading ? 'Analyzing...' : 'Analyze →'}
        </button>
      </div>

      {error && <div style={{color:'#ff4757', fontSize:'13px', marginBottom:'16px'}}>{error}</div>}

      {result && (
        <div className="scan-result" style={{borderLeft:`3px solid ${color}`}}>
          <div className="scan-result-header">
            <span className="sev-tag tag-${sev}" style={{background:`${color}22`, color, border:`1px solid ${color}44`, padding:'3px 8px', borderRadius:'3px', fontSize:'10px', fontWeight:700}}>{sev?.toUpperCase()}</span>
            <span className="scan-conf" style={{color}}>{result.confidence?.toFixed(1)}%</span>
            <span style={{fontSize:'12px', color:'#526b85'}}>confidence</span>
            {result.mitre && <span className="mitre-tag" style={{marginLeft:'auto'}}>{result.mitre.technique} — {result.mitre.name}</span>}
          </div>

          <div className="sec-head">SHAP Feature Importance</div>
          <ShapChart tokens={result.xai_tokens} />

          <div className="sec-head" style={{marginTop:'16px'}}>LLM Security Analysis</div>
          <div className="llm-block">{result.llm_explanation || 'No LLM analysis — Ollama not running.'}</div>
        </div>
      )}

      {!result && !loading && !error && (
        <div style={{color:'#526b85', fontSize:'13px'}}>
          <div style={{marginBottom:'8px'}}>Try these examples:</div>
          {["SELECT * FROM users WHERE id = 1", "' OR '1'='1", "1 UNION SELECT username, password FROM admin--", "' AND SLEEP(5)--"].map(q => (
            <div key={q} style={{fontFamily:'IBM Plex Mono, monospace', fontSize:'12px', color:'#3d8ef5', cursor:'pointer', marginBottom:'6px'}} onClick={() => setQuery(q)}>
              → {q}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
