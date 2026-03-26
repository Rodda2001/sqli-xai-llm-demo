import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

const COLORS = {
  auth_bypass:     '#ff4757',
  union_based:     '#ff7e30',
  blind_time:      '#ffc300',
  blind_boolean:   '#a78bfa',
  error_based:     '#3d8ef5',
  evasion:         '#2ed573',
  stacked_queries: '#ff6b9d',
  other:           '#526b85',
}

export default function AnalyticsPanel({ detections }) {
  const sqli = detections.filter(d => d.is_sqli)

  // Count attack types
  const counts = {}
  sqli.forEach(d => { const t = d.attack_type || 'other'; counts[t] = (counts[t]||0)+1 })
  const chartData = Object.entries(counts).map(([name, value]) => ({ name, value }))

  // Count IPs
  const ipCounts = {}
  sqli.forEach(d => { const ip = d.source_ip || 'unknown'; ipCounts[ip] = (ipCounts[ip]||0)+1 })
  const topIPs = Object.entries(ipCounts).sort((a,b) => b[1]-a[1]).slice(0,6)

  const max = Math.max(...Object.values(counts), 1)

  return (
    <div className="analytics-panel">
      <div className="r-block">
        <div className="panel-label" style={{marginBottom:'12px'}}>Attack Distribution</div>
        {chartData.length > 0 ? (
          <div className="chart-box">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={chartData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={2} dataKey="value">
                  {chartData.map((entry, i) => (
                    <Cell key={i} fill={COLORS[entry.name] || '#526b85'} stroke="none" fillOpacity={0.85} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{background:'#151e28', border:'1px solid #1e2d40', borderRadius:'6px', fontSize:'11px'}}
                  labelStyle={{color:'#dce8f4'}}
                  itemStyle={{color:'#90afc8'}}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div style={{color:'#526b85', fontSize:'12px', padding:'20px 0', textAlign:'center'}}>No threat data yet</div>
        )}
      </div>

      <div className="r-block">
        <div className="panel-label" style={{marginBottom:'10px'}}>By Type</div>
        {Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([type, cnt]) => (
          <div className="atk-item" key={type}>
            <div className="atk-dot" style={{background: COLORS[type]||'#526b85'}}></div>
            <span className="atk-name">{type.replace(/_/g,' ')}</span>
            <div className="atk-bar"><div className="atk-fill" style={{width:`${(cnt/max*100).toFixed(0)}%`, background: COLORS[type]||'#526b85'}}></div></div>
            <span className="atk-cnt">{cnt}</span>
          </div>
        ))}
        {chartData.length === 0 && <div style={{color:'#526b85', fontSize:'12px'}}>No data</div>}
      </div>

      <div className="r-block">
        <div className="panel-label" style={{marginBottom:'10px'}}>Top Attacker IPs</div>
        {topIPs.length === 0 && <div style={{color:'#526b85', fontSize:'12px'}}>No threat IPs yet</div>}
        {topIPs.map(([ip, cnt]) => (
          <div className="ip-item" key={ip}>
            <span className="ip-addr">{ip}</span>
            <span className="ip-cnt">{cnt} hits</span>
          </div>
        ))}
      </div>
    </div>
  )
}
