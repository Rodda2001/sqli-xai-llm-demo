export default function ShapChart({ tokens }) {
  if (!tokens || tokens.length === 0) return <div style={{color:'#526b85',fontSize:'12px'}}>No XAI data available</div>
  // Filter noise tokens (less than 2 meaningful chars)
  const clean = tokens.filter(t => t.token.trim().length >= 2).slice(0, 8)
  const max = Math.max(...clean.map(t => Math.abs(t.shap))) || 1
  return (
    <div>
      <div className="shap-legend">
        <span style={{color:'#ff4757'}}>■ Toward SQLi</span>
        <span style={{color:'#2ed573'}}>■ Toward Normal</span>
      </div>
      <div className="shap-list">
        {clean.map((t, i) => {
          const pct = (Math.abs(t.shap) / max * 100).toFixed(0)
          const pos = t.direction === 'sqli'
          return (
            <div className="shap-item" key={i}>
              <span className="shap-token">'{t.token}'</span>
              <div className="shap-track">
                <div className={`shap-fill ${pos ? 'shap-pos' : 'shap-neg'}`} style={{width:`${pct}%`}}></div>
              </div>
              <span className="shap-score" style={{color: pos ? '#ff4757' : '#2ed573'}}>
                {pos ? '+' : ''}{t.shap.toFixed(3)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
