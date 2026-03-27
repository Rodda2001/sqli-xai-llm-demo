import { useState, useEffect } from 'react'
import { getConfig, saveConfig } from '../api'

export default function SettingsPage() {
  const [emails, setEmails] = useState([])
  const [emailInput, setEmailInput] = useState('')
  const [saved, setSaved] = useState(false)

  // Load saved emails on page load
  useEffect(() => {
    loadConfig()
  }, [])

  async function loadConfig() {
    try {
      const c = await getConfig()

      if (!c || !c.alert_email) {
        setEmails([])
        return
      }

      // Support both string and array formats
      if (Array.isArray(c.alert_email)) {
        setEmails(c.alert_email)
      } else {
        setEmails(
          c.alert_email
            .split(',')
            .map(e => e.trim())
            .filter(Boolean)
        )
      }
    } catch (err) {
      console.error('Failed to load config:', err)
      setEmails([])
    }
  }

  function addEmail() {
    const email = emailInput.trim()
    if (!email) return
    if (emails.includes(email)) return

    setEmails(prev => [...prev, email])
    setEmailInput('')
  }

  function removeEmail(index) {
    setEmails(prev => prev.filter((_, i) => i !== index))
  }

  async function save() {
    try {
      await saveConfig({
        alert_email: emails.join(',')
      })

      // Reload from backend to sync UI
      await loadConfig()

      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      alert('Save failed: ' + e.message)
    }
  }

  return (
    <div className="page-wrap">
      <div className="page-title">Alert Recipients</div>
      <div className="page-sub">
        Add emails that should receive SQL injection alerts.
      </div>

      {/* Email input */}
      <div className="form-group">
        <label className="form-label">Recipients (Email alert functionality is implemented, but delivery is disabled for demo purposes.)</label>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
          <input
            className="form-input"
            type="email"
            value={emailInput}
            onChange={e => setEmailInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') addEmail()
            }}
            placeholder="analyst@company.com — press Enter"
          />

          <button
            onClick={addEmail}
            style={{
              background: '#1e2d40',
              border: '1px solid #2d4a6e',
              color: '#3d8ef5',
              borderRadius: '6px',
              padding: '0 16px',
              cursor: 'pointer',
              fontSize: '13px',
              whiteSpace: 'nowrap',
              fontFamily: 'inherit'
            }}
          >
            + Add
          </button>
        </div>

        {/* Email tags */}
        {emails.length > 0 ? (
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {emails.map((email, i) => (
              <span
                key={i}
                style={{
                  background: '#1e2d40',
                  border: '1px solid #2d4a6e',
                  padding: '5px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  color: '#3d8ef5',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
              >
                {email}
                <span
                  onClick={() => removeEmail(i)}
                  style={{
                    cursor: 'pointer',
                    color: '#526b85',
                    fontWeight: 700,
                    fontSize: '14px'
                  }}
                >
                  ×
                </span>
              </span>
            ))}
          </div>
        ) : (
          <div style={{ color: '#526b85', fontSize: '12px' }}>
            No recipients added yet
          </div>
        )}

        <div className="form-hint">
          Multiple users can be added. All will receive alerts.
        </div>
      </div>

      {/* Save */}
      <div className="save-row">
        <button className="btn-primary" onClick={save}>
          Save
        </button>
        <span className={`save-ok ${saved ? 'show' : ''}`}>
          ✓ Saved
        </span>
      </div>
    </div>
  )
}
