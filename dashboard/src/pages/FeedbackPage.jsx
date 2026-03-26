import { useState } from 'react'
import { sendFeedback } from '../api'

const CATEGORIES = [
  { key: 'detection_accuracy', label: 'Detection Accuracy' },
  { key: 'shap_explanations',  label: 'SHAP Explanations' },
  { key: 'llm_analysis',       label: 'LLM Analysis Quality' },
  { key: 'dashboard_ui',       label: 'Dashboard & UI' },
  { key: 'overall_system',     label: 'Overall System' },
]

function StarRating({ value, onChange }) {
  const [hover, setHover] = useState(0)
  return (
    <div style={{display:'flex', gap:'4px'}}>
      {[1,2,3,4,5].map(i => (
        <span
          key={i}
          onClick={() => onChange(i)}
          onMouseEnter={() => setHover(i)}
          onMouseLeave={() => setHover(0)}
          style={{
            fontSize:'20px',
            cursor:'pointer',
            color: (hover || value) >= i ? '#ffc300' : '#1e2d40',
            transition:'color 0.12s',
          }}
        >★</span>
      ))}
    </div>
  )
}

export default function FeedbackPage() {
  const [name, setName]             = useState('')
  const [email, setEmail]           = useState('')
  const [role, setRole]             = useState('')
  const [positive, setPositive]     = useState('')
  const [negative, setNegative]     = useState('')
  const [suggestions, setSuggestions] = useState('')
  const [ratings, setRatings]       = useState({})
  const [sending, setSending]       = useState(false)
  const [sent, setSent]             = useState(false)
  const [error, setError]           = useState('')

  function setRating(key, val) {
    setRatings(prev => ({...prev, [key]: val}))
  }

  async function handleSubmit() {
    if (!name.trim() || !email.trim()) {
      setError('Name and email are required')
      return
    }
    setSending(true)
    setError('')
    try {
      const res = await sendFeedback({
        name, email, role, positive, negative, suggestions, ratings
      })
      if (res.error) {
        setError(res.error)
      } else {
        setSent(true)
      }
    } catch(e) {
      setError('Failed to send feedback. Make sure the gateway is running.')
    }
    setSending(false)
  }

  if (sent) {
    return (
      <div style={{flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:'16px', padding:'40px'}}>
        <div style={{fontSize:'48px', opacity:0.3}}>✓</div>
        <div style={{fontSize:'18px', fontWeight:700, color:'#2ed573'}}>Feedback Submitted</div>
        <div style={{fontSize:'13px', color:'#526b85', textAlign:'center', maxWidth:'320px'}}>
          Thank you for your feedback. It has been sent to the project supervisor for review.
        </div>
        <button className="btn-primary" onClick={() => {
          setSent(false); setName(''); setEmail(''); setRole('');
          setPositive(''); setNegative(''); setSuggestions(''); setRatings({});
        }} style={{marginTop:'12px'}}>
          Submit Another
        </button>
      </div>
    )
  }

  return (
    <div className="page-wrap" style={{maxWidth:'640px'}}>
      <div className="page-title">System Feedback</div>
      <div className="page-sub" style={{marginBottom:'24px'}}>
        Your feedback helps evaluate and improve QueryGuard. All responses are sent directly to the project developer.
      </div>

      {/* Identity */}
      <div style={{
        background:'#151e28', border:'1px solid #1e2d40', borderRadius:'8px',
        padding:'18px 20px', marginBottom:'16px'
      }}>
        <div className="sec-head" style={{marginBottom:'14px'}}>Your Information</div>
        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px', marginBottom:'10px'}}>
          <div>
            <label className="form-label">Name *</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="Full name" />
          </div>
          <div>
            <label className="form-label">Email *</label>
            <input className="form-input" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="your@email.com" />
          </div>
        </div>
        <div>
          <label className="form-label">Role / Title</label>
          <input className="form-input" value={role} onChange={e => setRole(e.target.value)} placeholder="e.g. Senior Lecturer, Security Analyst, Student" />
        </div>
      </div>

      {/* Ratings */}
      <div style={{
        background:'#151e28', border:'1px solid #1e2d40', borderRadius:'8px',
        padding:'18px 20px', marginBottom:'16px'
      }}>
        <div className="sec-head" style={{marginBottom:'14px'}}>Rate Each Component</div>
        {CATEGORIES.map(cat => (
          <div key={cat.key} style={{
            display:'flex', alignItems:'center', justifyContent:'space-between',
            padding:'8px 0', borderBottom:'1px solid rgba(30,45,64,0.5)'
          }}>
            <span style={{fontSize:'13px', color:'#90afc8'}}>{cat.label}</span>
            <div style={{display:'flex', alignItems:'center', gap:'10px'}}>
              <StarRating value={ratings[cat.key] || 0} onChange={v => setRating(cat.key, v)} />
              <span style={{
                fontFamily:'IBM Plex Mono, monospace', fontSize:'11px',
                color: (ratings[cat.key] || 0) > 0 ? '#dce8f4' : '#526b85',
                width:'28px', textAlign:'right'
              }}>
                {ratings[cat.key] || '—'}/5
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Positive */}
      <div style={{
        background:'#151e28', border:'1px solid #1e2d40', borderRadius:'8px',
        padding:'18px 20px', marginBottom:'16px', borderLeft:'3px solid #2ed573'
      }}>
        <div style={{fontSize:'10px', fontWeight:600, letterSpacing:'1.2px', textTransform:'uppercase', color:'#2ed573', marginBottom:'10px'}}>
          What Worked Well
        </div>
        <textarea
          className="form-input"
          rows={4}
          value={positive}
          onChange={e => setPositive(e.target.value)}
          placeholder="What aspects of the system impressed you? Which features are most useful?"
          style={{resize:'vertical', minHeight:'80px'}}
        />
      </div>

      {/* Negative */}
      <div style={{
        background:'#151e28', border:'1px solid #1e2d40', borderRadius:'8px',
        padding:'18px 20px', marginBottom:'16px', borderLeft:'3px solid #ff4757'
      }}>
        <div style={{fontSize:'10px', fontWeight:600, letterSpacing:'1.2px', textTransform:'uppercase', color:'#ff4757', marginBottom:'10px'}}>
          Areas for Improvement
        </div>
        <textarea
          className="form-input"
          rows={4}
          value={negative}
          onChange={e => setNegative(e.target.value)}
          placeholder="What could be improved? Did you encounter any issues or limitations?"
          style={{resize:'vertical', minHeight:'80px'}}
        />
      </div>

      {/* Suggestions */}
      <div style={{
        background:'#151e28', border:'1px solid #1e2d40', borderRadius:'8px',
        padding:'18px 20px', marginBottom:'20px', borderLeft:'3px solid #3d8ef5'
      }}>
        <div style={{fontSize:'10px', fontWeight:600, letterSpacing:'1.2px', textTransform:'uppercase', color:'#3d8ef5', marginBottom:'10px'}}>
          Suggestions & Additional Comments
        </div>
        <textarea
          className="form-input"
          rows={3}
          value={suggestions}
          onChange={e => setSuggestions(e.target.value)}
          placeholder="Any additional thoughts, feature requests, or suggestions for future work?"
          style={{resize:'vertical', minHeight:'60px'}}
        />
      </div>

      {error && <div style={{color:'#ff4757', fontSize:'13px', marginBottom:'14px'}}>{error}</div>}

      <div className="save-row">
        <button className="btn-primary" onClick={handleSubmit} disabled={sending}>
          {sending ? 'Sending...' : 'Submit Feedback →'}
        </button>
        <span style={{fontSize:'11px', color:'#526b85'}}>
          Feedback will be emailed to the project developer
        </span>
      </div>
    </div>
  )
}
