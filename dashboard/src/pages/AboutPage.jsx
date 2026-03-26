export default function AboutPage() {
  const S = {
    wrap:   { flex:1, overflowY:'auto', padding:'28px 36px', maxWidth:'820px' },
    sec:    { background:'#151e28', border:'1px solid #1e2d40', borderRadius:'8px', padding:'18px 20px', marginBottom:'16px' },
    h:      { fontSize:'10px', fontWeight:600, letterSpacing:'1.2px', textTransform:'uppercase', color:'#526b85', marginBottom:'12px', display:'flex', alignItems:'center', gap:'10px' },
    line:   { content:'', flex:1, height:'1px', background:'#1e2d40' },
    p:      { fontSize:'13px', color:'#90afc8', lineHeight:'1.7', marginBottom:'10px' },
    tag:    { display:'inline-block', background:'rgba(61,142,245,0.1)', border:'1px solid rgba(61,142,245,0.2)', color:'#3d8ef5', padding:'3px 10px', borderRadius:'4px', fontFamily:'IBM Plex Mono, monospace', fontSize:'11px', marginRight:'6px', marginBottom:'6px' },
    tagP:   { display:'inline-block', background:'rgba(167,139,250,0.1)', border:'1px solid rgba(167,139,250,0.25)', color:'#a78bfa', padding:'3px 10px', borderRadius:'4px', fontFamily:'IBM Plex Mono, monospace', fontSize:'11px', marginRight:'6px', marginBottom:'6px' },
    tagG:   { display:'inline-block', background:'rgba(46,213,115,0.1)', border:'1px solid rgba(46,213,115,0.2)', color:'#2ed573', padding:'3px 10px', borderRadius:'4px', fontFamily:'IBM Plex Mono, monospace', fontSize:'11px', marginRight:'6px', marginBottom:'6px' },
    tagR:   { display:'inline-block', background:'rgba(255,71,87,0.1)', border:'1px solid rgba(255,71,87,0.2)', color:'#ff4757', padding:'3px 10px', borderRadius:'4px', fontFamily:'IBM Plex Mono, monospace', fontSize:'11px', marginRight:'6px', marginBottom:'6px' },
    mono:   { fontFamily:'IBM Plex Mono, monospace', fontSize:'12px', color:'#f0c060', background:'#0d1117', border:'1px solid #1e2d40', borderRadius:'6px', padding:'14px', lineHeight:'1.8', marginBottom:'10px', whiteSpace:'pre-wrap' },
  }

  return (
    <div style={S.wrap}>
      <div className="page-title">About QueryGuard</div>
      <div className="page-sub" style={{marginBottom:'24px'}}>
        Real-time SQL Injection Detection System using Machine Learning, Explainable AI, and Large Language Models
      </div>

      {/* Overview */}
      <div style={S.sec}>
        <div style={S.h}>Overview<span style={S.line}></span></div>
        <p style={S.p}>
          QueryGuard is a zero-day SQL injection prediction and detection system designed to monitor database traffic in real-time. Unlike traditional WAF/IDS solutions that rely on static signatures, QueryGuard uses a multi-layered ML pipeline combined with SHAP explainability and LLM-powered analysis to detect novel attack patterns — including obfuscated and evasion-based injections.
        </p>
        <p style={S.p}>
          The system processes every SQL query passing through a monitored database server, classifies it as safe or malicious, identifies the specific attack type, maps it to MITRE ATT&CK techniques, generates SHAP feature explanations, and produces a natural language security analysis via a local LLM — all in real-time.
        </p>
      </div>

      {/* Detection Pipeline */}
      <div style={S.sec}>
        <div style={S.h}>Detection Pipeline<span style={S.line}></span></div>
        <div style={S.mono}>{`Step 1 → Binary Classification (ML Model 1)
         TF-IDF char n-gram vectorizer → Logistic Regression
         Output: is_sqli (true/false) + confidence score

Step 2 → Attack Type Classification (ML Model 2)
         TF-IDF char n-gram vectorizer → Logistic Regression
         Labels: auth_bypass, union_based, blind_time,
                 blind_boolean, error_based, stacked_queries,
                 evasion, other

Step 3 → SHAP Explainability (XAI)
         SHAP LinearExplainer on Model 1
         SQL-aware pattern grouping (regex → human-readable labels)
         Per-token SHAP values with direction (toward SQLi / normal)

Step 4 → MITRE ATT&CK Mapping
         Attack type → MITRE technique ID + tactic + name

Step 5 → LLM Security Analysis (Ollama)
         Structured XAI report → tinyllama → SOC analyst narrative
         3-line format: THREAT / RISK / ACTION`}</div>
      </div>

      {/* Architecture */}
      <div style={S.sec}>
        <div style={S.h}>System Architecture<span style={S.line}></span></div>
        <div style={S.mono}>{`┌──────────────────────┐
│   MySQL Server       │    Server A
│   general.log        │
│        ↓             │
│   Go Log Agent       │─── Tails log, parses SQL queries
└──────────┬───────────┘    Extracts source IP, resolves hostname
           │
           │  HTTP POST /api/ingest
           ▼
┌──────────────────────────────────────────┐
│         Go Gateway  :9000                │    Server B
│                                          │
│  ┌─ Routes ────────────────────────┐     │
│  │  /api/ingest    → detection     │     │
│  │  /api/analyze   → manual scan   │     │
│  │  /api/ws        → WebSocket     │     │
│  │  /api/history   → SQLite        │     │
│  │  /api/simulate  → start/stop    │     │
│  │  /api/feedback  → email         │     │
│  └─────────────────────────────────┘     │
│         │                                │
│         ▼                                │
│  ┌─ Python Detection Server :8000 ─┐    │
│  │  Model 1 → Binary (SQLi/Normal) │    │
│  │  Model 2 → Attack Type          │    │
│  │  SHAP    → Explainability        │    │
│  │  Ollama  → LLM Analysis          │    │
│  └──────────────────────────────────┘    │
│         │                                │
│         ├──→ WebSocket broadcast         │
│         ├──→ SQLite storage              │
│         └──→ Email alerts (Gmail SMTP)   │
└──────────────────────────────────────────┘
           │
           ▼
┌──────────────────────┐
│   React Dashboard    │    Browser
│   Monitor / Scan     │
│   Settings / About   │
│   Feedback           │
└──────────────────────┘`}</div>
      </div>

      {/* MITRE Coverage */}
      <div style={S.sec}>
        <div style={S.h}>MITRE ATT&CK Coverage<span style={S.line}></span></div>
        <div style={{display:'flex', flexWrap:'wrap', gap:'4px', marginBottom:'12px'}}>
          <span style={S.tagR}>T1190 — Exploit Public-Facing Application</span>
          <span style={S.tagR}>T1005 — Data from Local System</span>
          <span style={S.tagR}>T1082 — System Information Discovery</span>
          <span style={S.tagR}>T1059 — Command and Scripting Interpreter</span>
          <span style={S.tagR}>T1027 — Obfuscated Files or Information</span>
        </div>
        <p style={{...S.p, fontSize:'11px'}}>
          Each detected attack is automatically mapped to the relevant MITRE ATT&CK technique, providing SOC teams with standardized threat intelligence context.
        </p>
      </div>

      {/* Tech Stack */}
      <div style={S.sec}>
        <div style={S.h}>Technology Stack<span style={S.line}></span></div>
        <div style={{marginBottom:'12px'}}>
          <div style={{fontSize:'10px', color:'#526b85', fontWeight:600, letterSpacing:'0.8px', marginBottom:'6px'}}>ML & DETECTION</div>
          <span style={S.tagP}>Python 3</span>
          <span style={S.tagP}>scikit-learn</span>
          <span style={S.tagP}>SHAP</span>
          <span style={S.tagP}>FastAPI</span>
          <span style={S.tagP}>Ollama + TinyLlama</span>
        </div>
        <div style={{marginBottom:'12px'}}>
          <div style={{fontSize:'10px', color:'#526b85', fontWeight:600, letterSpacing:'0.8px', marginBottom:'6px'}}>BACKEND</div>
          <span style={S.tag}>Go (Fiber)</span>
          <span style={S.tag}>SQLite</span>
          <span style={S.tag}>WebSocket</span>
          <span style={S.tag}>SMTP</span>
        </div>
        <div style={{marginBottom:'12px'}}>
          <div style={{fontSize:'10px', color:'#526b85', fontWeight:600, letterSpacing:'0.8px', marginBottom:'6px'}}>FRONTEND</div>
          <span style={S.tagG}>React 19</span>
          <span style={S.tagG}>Vite</span>
          <span style={S.tagG}>Recharts</span>
        </div>
        <div>
          <div style={{fontSize:'10px', color:'#526b85', fontWeight:600, letterSpacing:'0.8px', marginBottom:'6px'}}>AGENT</div>
          <span style={S.tag}>Go</span>
          <span style={S.tag}>fsnotify</span>
          <span style={S.tag}>Reverse DNS</span>
          <span style={S.tag}>GeoIP enrichment</span>
        </div>
      </div>

      {/* Project Info */}
      <div style={S.sec}>
        <div style={S.h}>Project Information<span style={S.line}></span></div>
        <div style={{display:'grid', gridTemplateColumns:'140px 1fr', gap:'8px', fontSize:'13px'}}>
          <span style={{color:'#526b85'}}>Project</span>
          <span style={{color:'#dce8f4'}}>Zero-day SQL Injection Prediction System</span>
          <span style={{color:'#526b85'}}>Module</span>
          <span style={{color:'#dce8f4'}}>6COSC019W — Final Year Project</span>
          <span style={{color:'#526b85'}}>University</span>
          <span style={{color:'#dce8f4'}}>University of Westminster (IIT Sri Lanka)</span>
          <span style={{color:'#526b85'}}>Student</span>
          <span style={{color:'#dce8f4'}}>Ravindu Imesh Herath — 20200642</span>
          <span style={{color:'#526b85'}}>Supervisor</span>
          <span style={{color:'#dce8f4'}}>Ms. Ganguli Ranawaka</span>
          <span style={{color:'#526b85'}}>Version</span>
          <span style={{color:'#3d8ef5', fontFamily:'IBM Plex Mono, monospace'}}>3.0</span>
        </div>
      </div>
    </div>
  )
}
