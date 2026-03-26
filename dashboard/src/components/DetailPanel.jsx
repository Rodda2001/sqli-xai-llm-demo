import ShapChart from './ShapChart'

function sevColor(sev) {
  return {critical:'#ff4757', high:'#ff7e30', medium:'#ffc300', normal:'#2ed573'}[sev] || '#dce8f4'
}

export default function DetailPanel({ detection }) {
  if (!detection) {
    return (
      <div className="detail-panel">
        <div className="panel-header"><span className="panel-label">Detection Detail</span></div>
        <div className="detail-body">
          <div className="empty-state">
            <div className="empty-icon">⚡</div>
            <div className="empty-title">No alert selected</div>
            <div className="empty-sub">Click any item in the alert queue to view full ML + SHAP + LLM analysis</div>
          </div>
        </div>
      </div>
    )
  }

  const d = detection
  const sev = d.is_sqli ? (d.severity || 'high') : 'normal'
  const color = sevColor(sev)

  return (
    <div className="detail-panel">
      <div className="panel-header">
        <span className="panel-label">Detection Detail</span>
        <span className="sev-tag" style={{background:`${color}22`, color, border:`1px solid ${color}44`, padding:'2px 8px', borderRadius:'3px', fontSize:'10px', fontWeight:700}}>{sev.toUpperCase()}</span>
      </div>
      <div className="detail-body">
        <div className="detail-view">

          {/* Verdict */}
          <div className="dv-header">
            <div className="dv-result-label">Detection Result</div>
            <div className="dv-result-title" style={{color}}>
              {d.is_sqli ? `⚠ ${(d.attack_type||'SQLi').replace(/_/g,' ').toUpperCase()}` : '✓ NORMAL QUERY'}
            </div>
            <div className="conf-row">
              <div className="conf-bar"><div className="conf-fill" style={{width:`${d.confidence}%`, background: d.is_sqli ? undefined : '#2ed573'}}></div></div>
              <span className="conf-pct" style={{color}}>{d.confidence?.toFixed(1)}%</span>
              <span className="conf-text">{d.is_sqli ? 'threat confidence' : 'safe confidence'}</span>
            </div>
          </div>

          {/* Info grid */}
          <div className="dv-grid">
            {d.is_sqli ? (
              <div className="dv-card">
                <div className="dv-card-title">Threat Intel</div>
                <div className="dv-row"><span className="dk">Severity</span><span className="dv-val" style={{color}}>{sev.toUpperCase()}</span></div>
                <div className="dv-row"><span className="dk">Type</span><span className="dv-val">{(d.attack_type||'normal').replace(/_/g,' ')}</span></div>
                {d.mitre && <div className="dv-row"><span className="dk">MITRE</span><span className="dv-val" style={{color:'#a78bfa'}}>{d.mitre.technique}</span></div>}
              </div>
            ) : (
              <div className="dv-card">
                <div className="dv-card-title">Analysis</div>
                <div className="dv-row"><span className="dk">Status</span><span className="dv-val" style={{color:'#2ed573'}}>SAFE</span></div>
                <div className="dv-row"><span className="dk">Type</span><span className="dv-val">legitimate query</span></div>
                <div className="dv-row"><span className="dk">Threat Level</span><span className="dv-val" style={{color:'#2ed573'}}>NONE</span></div>
              </div>
            )}
            <div className="dv-card">
              <div className="dv-card-title">Source</div>
              <div className="dv-row"><span className="dk">IP</span><span className="dv-val" style={{color:'#3d8ef5'}}>{d.source_ip||'unknown'}</span></div>
              <div className="dv-row"><span className="dk">Host</span><span className="dv-val">{d.source_host||'unknown'}</span></div>
              <div className="dv-row"><span className="dk">Time</span><span className="dv-val">{d.timestamp}</span></div>
            </div>
          </div>

          {/* Query */}
          <div className="sec-head">{d.is_sqli ? 'Detected Query' : 'Query'}</div>
          <div className={`qblock ${d.is_sqli ? '' : 'safe'}`}>{d.query}</div>

          {/* SQLi-only sections */}
          {d.is_sqli && (
            <>
              {/* MITRE */}
              {d.mitre && (
                <>
                  <div className="sec-head">MITRE ATT&CK</div>
                  <div className="mitre-row">
                    <span className="mitre-tag">🗡 {d.mitre.technique}</span>
                    <span className="mitre-tag">📋 {d.mitre.name}</span>
                    <span className="mitre-tag">🎯 {d.mitre.tactic}</span>
                  </div>
                </>
              )}

              {/* SHAP */}
              {d.xai_tokens && d.xai_tokens.length > 0 && (
                <>
                  <div className="sec-head">SHAP Explainability</div>
                  <ShapChart tokens={d.xai_tokens} />
                </>
              )}

              {/* LLM */}
              {d.llm_explanation && (
                <>
                  <div className="sec-head" style={{marginTop:'18px'}}>LLM Security Analysis</div>
                  <div className="llm-block">{d.llm_explanation}</div>
                </>
              )}
            </>
          )}

          {/* Normal query summary */}
          {!d.is_sqli && (
            <div style={{
              marginTop: '16px',
              padding: '14px 16px',
              background: 'rgba(46,213,115,0.06)',
              border: '1px solid rgba(46,213,115,0.15)',
              borderRadius: '6px',
              fontSize: '12px',
              color: '#8fa8c4',
              lineHeight: '1.6'
            }}>
              This query was classified as a <span style={{color:'#2ed573', fontWeight:600}}>legitimate SQL statement</span> with {(100 - (d.confidence || 0)).toFixed(1)}% safe confidence. No malicious patterns, injection attempts, or suspicious syntax were detected by the ML model.
            </div>
          )}

        </div>
      </div>
    </div>
  )
}
