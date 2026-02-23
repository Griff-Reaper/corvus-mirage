import { useState, useEffect, useRef } from 'react'

const ARIA_API = 'http://localhost:8001'
const ARIA_WS  = 'ws://localhost:8001/soc/ws'
const GATEWAY_API = 'http://localhost:8002'
const DASH_API = 'http://localhost:8080'
const DASH_WS  = 'ws://localhost:8080/ws/events'

const LEVEL_COLOR = {
  MONITORING: '#64748b', SUSPICIOUS: '#f59e0b',
  ELEVATED: '#f97316', HIGH: '#ef4444', CRITICAL: '#dc2626',
}
const LEVEL_BG = {
  MONITORING: 'rgba(100,116,139,0.12)', SUSPICIOUS: 'rgba(245,158,11,0.12)',
  ELEVATED: 'rgba(249,115,22,0.12)', HIGH: 'rgba(239,68,68,0.12)', CRITICAL: 'rgba(220,38,38,0.15)',
}

function fmtTime(iso) { if (!iso) return '--'; return new Date(iso).toLocaleTimeString('en-US', { hour12: false }) }
function fmtDur(sec) { if (!sec || sec < 60) return `${sec||0}s`; return `${Math.floor(sec/60)}m ${sec%60}s` }
function scoreColor(s) {
  if (s >= 80) return '#dc2626'; if (s >= 60) return '#ef4444';
  if (s >= 36) return '#f97316'; if (s >= 16) return '#f59e0b'; return '#64748b';
}

const css = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=DM+Sans:wght@300;400;500;600&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0d1117;--bg2:#161b22;--bg3:#1c2333;--bg4:#21262d;
    --border:#30363d;--border2:#3d444d;
    --text:#e6edf3;--text2:#8b949e;--text3:#484f58;
    --orange:#f97316;--orange-dim:rgba(249,115,22,0.15);
    --red:#ef4444;--amber:#f59e0b;--green:#3fb950;--blue:#58a6ff;
    --purple:#a371f7;--pink:#f472b6;
    --aria:#a371f7;--aria-dim:rgba(163,113,247,0.15);
    --gateway:#f97316;--gateway-dim:rgba(249,115,22,0.15);
    --font:'DM Sans',sans-serif;--mono:'JetBrains Mono',monospace;
  }
  html,body,#root{height:100%;width:100%;background:var(--bg);color:var(--text);font-family:var(--font);overflow:hidden}
  .soc{display:grid;grid-template-rows:52px 1fr;grid-template-columns:300px 1fr 360px;height:100vh;gap:1px;background:var(--border)}
  .soc-header{grid-column:1/-1;background:var(--bg2);display:flex;align-items:center;justify-content:space-between;padding:0 20px;border-bottom:1px solid var(--border)}
  .soc-logo{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--orange);letter-spacing:2px}
  .soc-sub{font-size:11px;color:var(--text2);font-family:var(--mono);letter-spacing:1px;margin-left:8px}
  .soc-meta{display:flex;align-items:center;gap:20px;font-family:var(--mono);font-size:11px;color:var(--text2)}
  .live-badge{display:flex;align-items:center;gap:6px;font-size:11px}
  .live-dot{width:6px;height:6px;border-radius:50%;animation:pulse 1.5s ease-in-out infinite}
  @keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(63,185,80,0.4)}50%{box-shadow:0 0 0 4px rgba(63,185,80,0)}}
  .panel{background:var(--bg2);display:flex;flex-direction:column;overflow:hidden}
  .panel-hdr{padding:10px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
  .panel-title{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:2px;color:var(--text2);text-transform:uppercase}
  .panel-count{font-family:var(--mono);font-size:10px;color:var(--text3)}
  .stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border);flex-shrink:0}
  .stat{background:var(--bg2);padding:10px 12px}
  .stat-val{font-family:var(--mono);font-size:20px;font-weight:600;line-height:1;margin-bottom:2px}
  .stat-lbl{font-size:9px;color:var(--text3);font-family:var(--mono);letter-spacing:0.5px;text-transform:uppercase}
  .session-list{flex:1;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
  .sitem{padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer;transition:background 0.15s;position:relative}
  .sitem:hover{background:var(--bg3)}
  .sitem.sel{background:var(--bg3);border-left:3px solid var(--orange);padding-left:11px}
  .sitem-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px}
  .sid{font-family:var(--mono);font-size:10px;color:var(--blue)}
  .lvl-badge{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1px;padding:2px 6px;border-radius:3px}
  .score-row{display:flex;align-items:center;gap:8px;margin-bottom:4px}
  .score-track{flex:1;height:3px;background:var(--bg4);border-radius:2px;overflow:hidden}
  .score-fill{height:100%;border-radius:2px;transition:width 0.6s ease}
  .score-num{font-family:var(--mono);font-size:11px;font-weight:600;min-width:24px;text-align:right}
  .stags{display:flex;flex-wrap:wrap;gap:3px;margin-bottom:3px}
  .tag{font-family:var(--mono);font-size:9px;padding:1px 5px;border-radius:2px;background:var(--bg4);color:var(--text2);border:1px solid var(--border2)}
  .smeta{font-family:var(--mono);font-size:10px;color:var(--text3)}
  .honey-indicator{display:flex;align-items:center;gap:4px;font-family:var(--mono);font-size:9px;color:var(--purple);margin-top:2px}
  .corr-indicator{display:flex;align-items:center;gap:4px;font-family:var(--mono);font-size:9px;color:var(--amber);margin-top:2px}

  /* Filter bar */
  .filter-bar{display:flex;gap:6px;padding:8px 14px;border-bottom:1px solid var(--border);flex-shrink:0}
  .filter-btn{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1px;padding:3px 10px;border-radius:3px;border:1px solid var(--border2);background:transparent;color:var(--text3);cursor:pointer;transition:all 0.15s;text-transform:uppercase}
  .filter-btn:hover{border-color:var(--text2);color:var(--text2)}
  .filter-btn.active-all{background:rgba(88,166,255,0.12);border-color:var(--blue);color:var(--blue)}
  .filter-btn.active-aria{background:var(--aria-dim);border-color:var(--aria);color:var(--aria)}
  .filter-btn.active-gateway{background:var(--gateway-dim);border-color:var(--gateway);color:var(--gateway)}

  /* Center feed */
  .center-panel{background:var(--bg2);display:flex;flex-direction:column;overflow:hidden}
  .feed{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:6px;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
  .fitem{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:10px 12px;animation:slide 0.25s ease;border-left-width:3px}
  @keyframes slide{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
  .fhdr{display:flex;align-items:center;gap:8px;margin-bottom:5px}
  .ftype{font-family:var(--mono);font-size:10px;font-weight:600}
  .fsource{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1px;padding:1px 6px;border-radius:2px}
  .fsource.aria{background:var(--aria-dim);color:var(--aria);border:1px solid rgba(163,113,247,0.3)}
  .fsource.gateway{background:var(--gateway-dim);color:var(--gateway);border:1px solid rgba(249,115,22,0.3)}
  .fsid{font-family:var(--mono);font-size:10px;color:var(--blue)}
  .ftime{font-family:var(--mono);font-size:10px;color:var(--text3);margin-left:auto}
  .fmsg{font-size:11px;color:var(--text2);margin-bottom:5px;font-family:var(--mono);line-height:1.5}
  .ftags{display:flex;flex-wrap:wrap;gap:3px}
  .honey-event{background:rgba(163,113,247,0.08);border-color:rgba(163,113,247,0.3)!important}
  .corr-event{background:rgba(245,158,11,0.08);border-color:rgba(245,158,11,0.3)!important}
  .cross-vector-event{background:rgba(244,114,182,0.06);border-color:rgba(244,114,182,0.35)!important}
  .feed-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:6px;color:var(--text3);font-family:var(--mono);font-size:11px;text-align:center}

  /* Detail */
  .detail{flex:1;overflow-y:auto;padding:14px;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
  .detail-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:6px;color:var(--text3);font-family:var(--mono);font-size:11px}
  .dsec{margin-bottom:18px}
  .dsec-title{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:2px;color:var(--text3);text-transform:uppercase;margin-bottom:6px;padding-bottom:3px;border-bottom:1px solid var(--border)}
  .drow{display:flex;justify-content:space-between;align-items:flex-start;padding:4px 0;border-bottom:1px solid var(--border);gap:10px}
  .dkey{font-family:var(--mono);font-size:10px;color:var(--text3);min-width:90px;flex-shrink:0}
  .dval{font-family:var(--mono);font-size:10px;color:var(--text);text-align:right;word-break:break-all}
  .score-ring{width:72px;height:72px;margin:0 auto 10px;position:relative}
  .score-ring svg{transform:rotate(-90deg)}
  .score-number{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:var(--mono);font-size:20px;font-weight:600}
  .convo{padding:7px 9px;border-radius:4px;margin-bottom:5px;font-family:var(--mono);font-size:10px;line-height:1.5}
  .convo.user{background:rgba(88,166,255,0.08);border:1px solid rgba(88,166,255,0.15);color:var(--text2)}
  .convo.aria{background:var(--bg4);border:1px solid var(--border);color:var(--text3)}
  .convo.gateway{background:rgba(249,115,22,0.06);border:1px solid rgba(249,115,22,0.2);color:var(--text2)}
  .convo-role{font-weight:600;margin-bottom:2px;font-size:9px;letter-spacing:1px;text-transform:uppercase}
  .convo.user .convo-role{color:var(--blue)}
  .convo.aria .convo-role{color:var(--aria)}
  .convo.gateway .convo-role{color:var(--gateway)}
  .honey-item{background:rgba(163,113,247,0.08);border:1px solid rgba(163,113,247,0.2);border-radius:4px;padding:8px 10px;margin-bottom:6px;font-family:var(--mono);font-size:10px}
  .honey-val{color:var(--purple);font-weight:600;margin-top:3px;font-size:11px}
  .corr-box{background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.25);border-radius:4px;padding:8px 10px;font-family:var(--mono);font-size:10px;color:var(--amber);line-height:1.6;margin-bottom:6px}
  .cross-vector-box{background:rgba(244,114,182,0.06);border:1px solid rgba(244,114,182,0.3);border-radius:4px;padding:10px;font-family:var(--mono);font-size:10px;line-height:1.6;margin-bottom:6px}
  .vector-split{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px}
  .vector-col{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:8px;font-family:var(--mono);font-size:9px}
  .vector-col-title{font-size:9px;font-weight:600;letter-spacing:1px;margin-bottom:6px;padding-bottom:3px;border-bottom:1px solid var(--border);text-transform:uppercase}
  .action-btns{display:flex;flex-direction:column;gap:8px}
  .btn{width:100%;padding:9px;font-family:var(--mono);font-size:11px;letter-spacing:1px;border-radius:4px;cursor:pointer;transition:background 0.2s;text-transform:uppercase;border:1px solid}
  .btn-nexus{background:var(--orange-dim);border-color:var(--orange);color:var(--orange)}
  .btn-nexus:hover{background:rgba(249,115,22,0.25)}
  .btn-export{background:rgba(88,166,255,0.08);border-color:rgba(88,166,255,0.4);color:var(--blue)}
  .btn-export:hover{background:rgba(88,166,255,0.15)}
  .push-result{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:var(--mono);font-size:9px;color:var(--text2);margin-top:6px;line-height:1.6;max-height:120px;overflow-y:auto}
  ::-webkit-scrollbar{width:4px;height:4px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
`

export default function SOCDashboard() {
  const [sessions, setSessions]       = useState([])
  const [selected, setSelected]       = useState(null)
  const [feed, setFeed]               = useState([])
  const [feedFilter, setFeedFilter]   = useState('all')
  const [unifiedStats, setUnifiedStats] = useState({
    total_sessions: 0, critical: 0, honeytokens_deployed: 0,
    high_threat: 0, total_messages: 0, correlated_groups: 0,
    aria_events: 0, gateway_events: 0, cross_vector_hits: 0,
  })
  const [ariaConnected, setAriaConnected]       = useState(false)
  const [dashConnected, setDashConnected]       = useState(false)
  const [clock, setClock]             = useState(new Date().toLocaleTimeString('en-US', { hour12: false }))
  const [pushResult, setPushResult]   = useState(null)

  // Track gateway events keyed by session_id for cross-vector detection
  const gatewayEventsBySession = useRef({})

  const ariaWsRef = useRef(null)
  const dashWsRef = useRef(null)

  // Clock
  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString('en-US', { hour12: false })), 1000)
    return () => clearInterval(t)
  }, [])

  // ARIA WebSocket
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(ARIA_WS)
      ariaWsRef.current = ws
      ws.onopen  = () => setAriaConnected(true)
      ws.onclose = () => { setAriaConnected(false); setTimeout(connect, 3000) }
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data)
        if (msg.type === 'init') {
          setSessions(msg.sessions || [])
          if (msg.recent_events?.length) {
            const events = msg.recent_events.slice().reverse().slice(0, 50).map(ev => ({ ...ev, _source: 'aria' }))
            setFeed(prev => [...events, ...prev].slice(0, 100))
          }
        } else if (msg.type === 'new_session') {
          setSessions(prev => [{ session_id: msg.session_id, started_at: msg.timestamp, threat_score: 0, threat_level: 'MONITORING', message_count: 0, detected_categories: [], honeytokens: [], correlation: {} }, ...prev])
          setFeed(prev => [{ ...msg, feed_type: 'new_session', _source: 'aria' }, ...prev].slice(0, 100))
          setUnifiedStats(prev => ({ ...prev, total_sessions: prev.total_sessions + 1 }))
        } else if (msg.type === 'message_event') {
          setSessions(prev => prev.map(s => s.session_id === msg.session_id ? { ...s, ...msg.session } : s))
          setFeed(prev => [{ ...msg, _source: 'aria' }, ...prev].slice(0, 100))
          setUnifiedStats(prev => ({
            ...prev,
            total_messages: prev.total_messages + 1,
            honeytokens_deployed: prev.honeytokens_deployed + (msg.honeytoken_deployed ? 1 : 0),
          }))
          setSelected(prev => prev?.session_id === msg.session_id ? { ...prev, ...msg.session } : prev)
        }
      }
    }
    connect()
    return () => ariaWsRef.current?.close()
  }, [])

  // Dashboard (shared event bus) WebSocket — Gateway events + unified stats
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(DASH_WS)
      dashWsRef.current = ws
      ws.onopen  = () => {
        setDashConnected(true)
        // Load unified stats on connect
        fetch(`${DASH_API}/api/stats`).then(r => r.json()).then(data => {
          setUnifiedStats(prev => ({ ...prev, ...data }))
        }).catch(() => {})
      }
      ws.onclose = () => { setDashConnected(false); setTimeout(connect, 3000) }
      ws.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data)
          const ev = payload.data
          if (!ev) return

          const component = (ev.component || ev.source || 'unknown').toLowerCase()

          // Only pipe Gateway events in — ARIA already comes through ARIA WS
          if (component !== 'gateway') return

          // Track by session for cross-vector detection
          if (ev.session_id) {
            if (!gatewayEventsBySession.current[ev.session_id]) {
              gatewayEventsBySession.current[ev.session_id] = []
            }
            gatewayEventsBySession.current[ev.session_id].push(ev)
          }

          // Check if this session also exists in ARIA sessions (cross-vector hit)
          const isCrossVector = ev.session_id && sessions.some(s => s.session_id === ev.session_id)

          const feedItem = {
            ...ev,
            _source: 'gateway',
            component: 'gateway',
            _cross_vector: isCrossVector,
            timestamp: ev.timestamp || new Date().toISOString(),
          }

          setFeed(prev => [feedItem, ...prev].slice(0, 100))
          setUnifiedStats(prev => ({
            ...prev,
            gateway_events: (prev.gateway_events || 0) + 1,
            cross_vector_hits: isCrossVector ? (prev.cross_vector_hits || 0) + 1 : (prev.cross_vector_hits || 0),
          }))
        } catch (err) {
          console.warn('Dash WS parse error', err)
        }
      }
    }
    connect()
    return () => dashWsRef.current?.close()
  }, [sessions])

  // Periodic unified stats refresh
  useEffect(() => {
    const t = setInterval(() => {
      fetch(`${DASH_API}/api/stats`).then(r => r.json()).then(data => {
        setUnifiedStats(prev => ({ ...prev, ...data }))
      }).catch(() => {})
    }, 15000)
    return () => clearInterval(t)
  }, [])

  const selectSession = async (s) => {
    setPushResult(null)
    try {
      const res = await fetch(`${ARIA_API}/soc/sessions/${s.session_id}`)
      const data = await res.json()
      // Attach any gateway events for this session
      data._gateway_events = gatewayEventsBySession.current[s.session_id] || []
      setSelected(data)
    } catch { setSelected(s) }
  }

  const exportSession = async () => {
    if (!selected) return
    const res = await fetch(`${ARIA_API}/soc/export/${selected.session_id}`)
    const data = await res.json()
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url
    a.download = `corvus-session-${selected.session_id.slice(0, 8)}.json`
    a.click()
  }

  const pushToNexus = async () => {
    if (!selected) return
    setPushResult({ status: 'pushing', message: 'Pushing to Nexus-Sec...' })
    try {
      const res = await fetch(`${ARIA_API}/soc/push-to-nexus`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: selected.session_id }),
      })
      setPushResult(await res.json())
    } catch (e) {
      setPushResult({ status: 'error', message: String(e) })
    }
  }

  // Filtered feed
  const filteredFeed = feed.filter(ev => {
    if (feedFilter === 'all') return true
    return (ev._source || ev.component || '').toLowerCase() === feedFilter
  })

  const circ = 2 * Math.PI * 32
  const selScore = selected?.threat_score || 0
  const selColor = scoreColor(selScore)

  const connected = ariaConnected || dashConnected

  return (
    <>
      <style>{css}</style>
      <div className="soc">

        {/* HEADER */}
        <header className="soc-header">
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <span style={{ fontSize: '18px', marginRight: '10px' }}>🪶</span>
            <span className="soc-logo">CORVUS MIRAGE</span>
            <span style={{ color: 'var(--text3)', margin: '0 6px', fontFamily: 'var(--mono)' }}>/</span>
            <span className="soc-sub">SOC COMMAND CENTER</span>
          </div>
          <div className="soc-meta">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div className="live-badge">
                <div className="live-dot" style={{ background: ariaConnected ? 'var(--aria)' : 'var(--text3)' }} />
                <span style={{ color: ariaConnected ? 'var(--aria)' : 'var(--text3)', fontSize: '10px' }}>ARIA</span>
              </div>
              <div className="live-badge">
                <div className="live-dot" style={{ background: dashConnected ? 'var(--gateway)' : 'var(--text3)' }} />
                <span style={{ color: dashConnected ? 'var(--gateway)' : 'var(--text3)', fontSize: '10px' }}>GATEWAY</span>
              </div>
            </div>
            <span>{clock}</span>
            <span style={{ color: 'var(--text3)' }}>CORVUS MIRAGE v1.0</span>
          </div>
        </header>

        {/* LEFT — SESSIONS */}
        <div className="panel">
          <div className="stats-row">
            <div className="stat"><div className="stat-val" style={{ color: 'var(--orange)' }}>{unifiedStats.total_sessions}</div><div className="stat-lbl">SESSIONS</div></div>
            <div className="stat"><div className="stat-val" style={{ color: 'var(--red)' }}>{unifiedStats.critical || unifiedStats.high_threat_count || 0}</div><div className="stat-lbl">CRITICAL</div></div>
            <div className="stat"><div className="stat-val" style={{ color: 'var(--purple)' }}>{unifiedStats.honeytokens_deployed}</div><div className="stat-lbl">HONEYTOKENS</div></div>
            <div className="stat"><div className="stat-val" style={{ color: 'var(--aria)' }}>{unifiedStats.aria_events || unifiedStats.total_messages || 0}</div><div className="stat-lbl">ARIA EVENTS</div></div>
            <div className="stat"><div className="stat-val" style={{ color: 'var(--gateway)' }}>{unifiedStats.gateway_events || 0}</div><div className="stat-lbl">GW EVENTS</div></div>
            <div className="stat"><div className="stat-val" style={{ color: 'var(--pink)' }}>{unifiedStats.cross_vector_hits || 0}</div><div className="stat-lbl">CROSS-VECTOR</div></div>
          </div>

          <div className="panel-hdr">
            <span className="panel-title">Active Sessions</span>
            <span className="panel-count">{sessions.length} total</span>
          </div>

          <div className="session-list">
            {sessions.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text3)' }}>
                Waiting for connections...<br />
                <span style={{ fontSize: '10px', marginTop: '6px', display: 'block' }}>Open the ARIA portal to begin</span>
              </div>
            ) : sessions.map(s => {
              const hasGateway = !!gatewayEventsBySession.current[s.session_id]?.length
              return (
                <div key={s.session_id} className={`sitem ${selected?.session_id === s.session_id ? 'sel' : ''}`} onClick={() => selectSession(s)}>
                  <div className="sitem-top">
                    <span className="sid">{s.session_id?.slice(0, 12)}...</span>
                    <span className="lvl-badge" style={{ background: LEVEL_BG[s.threat_level] || LEVEL_BG.MONITORING, color: LEVEL_COLOR[s.threat_level] || LEVEL_COLOR.MONITORING }}>
                      {s.threat_level || 'MONITORING'}
                    </span>
                  </div>
                  <div className="score-row">
                    <div className="score-track"><div className="score-fill" style={{ width: `${s.threat_score || 0}%`, background: scoreColor(s.threat_score || 0) }} /></div>
                    <span className="score-num" style={{ color: scoreColor(s.threat_score || 0) }}>{s.threat_score || 0}</span>
                  </div>
                  <div className="stags">
                    {(s.detected_categories || []).slice(0, 3).map(t => (
                      <span key={t} className="tag">{t.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                  {(s.honeytokens || []).length > 0 && (
                    <div className="honey-indicator">🍯 {s.honeytokens.length} honeytoken{s.honeytokens.length > 1 ? 's' : ''} deployed</div>
                  )}
                  {hasGateway && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--pink)', marginTop: '2px' }}>
                      ⚡ CROSS-VECTOR ACTOR
                    </div>
                  )}
                  {s.correlation?.group_id && (
                    <div className="corr-indicator">⚠️ {s.correlation.group_id}</div>
                  )}
                  <div className="smeta">{s.message_count || 0} msgs · {fmtTime(s.last_activity || s.started_at)}</div>
                </div>
              )
            })}
          </div>
        </div>

        {/* CENTER — LIVE FEED */}
        <div className="center-panel">
          <div className="panel-hdr">
            <span className="panel-title">Live Event Feed</span>
            <span className="panel-count">{filteredFeed.length} events</span>
          </div>

          {/* Filter bar */}
          <div className="filter-bar">
            <button className={`filter-btn ${feedFilter === 'all' ? 'active-all' : ''}`} onClick={() => setFeedFilter('all')}>ALL</button>
            <button className={`filter-btn ${feedFilter === 'aria' ? 'active-aria' : ''}`} onClick={() => setFeedFilter('aria')}>ARIA</button>
            <button className={`filter-btn ${feedFilter === 'gateway' ? 'active-gateway' : ''}`} onClick={() => setFeedFilter('gateway')}>GATEWAY</button>
          </div>

          <div className="feed">
            {filteredFeed.length === 0 ? (
              <div className="feed-empty">
                <div style={{ fontSize: '22px', opacity: 0.3 }}>◎</div>
                <div>NO EVENTS YET</div>
                <div style={{ fontSize: '10px', marginTop: '4px' }}>Events appear here in real time</div>
              </div>
            ) : filteredFeed.map((ev, i) => {
              const source       = (ev._source || ev.component || 'aria').toLowerCase()
              const isHoney      = ev.honeytoken_deployed
              const isCorr       = ev.correlation?.matches?.length > 0
              const isCrossVec   = ev._cross_vector
              const isNew        = ev.feed_type === 'new_session' || ev.type === 'new_session'
              const isGateway    = source === 'gateway'

              const borderColor = isCrossVec ? 'var(--pink)'
                : isHoney      ? 'var(--purple)'
                : isCorr       ? 'var(--amber)'
                : isNew        ? 'var(--blue)'
                : isGateway    ? 'var(--gateway)'
                : scoreColor(ev.threat_score || 0)

              const eventLabel = isCrossVec ? '🔗 CROSS-VECTOR'
                : isHoney      ? '🍯 HONEYTOKEN'
                : isCorr       ? '⚠️ CORRELATED'
                : isNew        ? '⊕ NEW SESSION'
                : isGateway    ? '🛡 PROMPT BLOCK'
                : '⚡ MESSAGE'

              const content = ev.raw_content || ev.message || ev.primary_objective || (ev.categories || [])[0] || ''

              return (
                <div key={i} className={`fitem ${isHoney ? 'honey-event' : ''} ${isCorr ? 'corr-event' : ''} ${isCrossVec ? 'cross-vector-event' : ''}`} style={{ borderLeftColor: borderColor }}>
                  <div className="fhdr">
                    <span className="ftype" style={{ color: borderColor }}>{eventLabel}</span>
                    <span className={`fsource ${source}`}>{source.toUpperCase()}</span>
                    <span className="fsid">{(ev.session_id || '').slice(0, 10)}{ev.session_id ? '...' : ''}</span>
                    <span className="ftime">{fmtTime(ev.timestamp)}</span>
                  </div>
                  {content && (
                    <div className="fmsg">
                      <span style={{ color: 'var(--text3)' }}>{isGateway ? 'Prompt: ' : 'User: '}</span>
                      {content.slice(0, 130)}{content.length > 130 ? '...' : ''}
                    </div>
                  )}
                  {isNew && <div className="fmsg" style={{ color: 'var(--text3)' }}>New attacker session initiated</div>}
                  {isHoney && <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--purple)', marginBottom: '4px' }}>Deployed: {ev.honeytoken?.type} — {ev.honeytoken?.system}</div>}
                  {isCorr && <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--amber)', marginBottom: '4px' }}>{ev.correlation.assessment?.slice(0, 80)}</div>}
                  {isCrossVec && <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--pink)', marginBottom: '4px' }}>Same actor detected across ARIA + Gateway vectors</div>}
                  <div className="ftags">
                    {(ev.classification?.tags || ev.categories || []).map(t => (
                      <span key={t} className="tag" style={{ color: 'var(--amber)', borderColor: 'rgba(245,158,11,0.3)' }}>{t.replace(/_/g, ' ')}</span>
                    ))}
                    {(ev.threat_level || ev.threat_score) && (
                      <span className="tag" style={{ color: borderColor, borderColor: borderColor + '44' }}>
                        {ev.threat_level} {ev.threat_score ? `· ${Number(ev.threat_score).toFixed(1)}` : ''}
                      </span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* RIGHT — DETAIL */}
        <div className="panel">
          <div className="panel-hdr">
            <span className="panel-title">Session Detail</span>
            {selected?._gateway_events?.length > 0 && (
              <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--pink)', background: 'rgba(244,114,182,0.1)', border: '1px solid rgba(244,114,182,0.3)', padding: '2px 6px', borderRadius: '3px' }}>
                CROSS-VECTOR
              </span>
            )}
          </div>
          {!selected ? (
            <div className="detail-empty"><div style={{ fontSize: '22px', opacity: 0.3 }}>⬡</div><div>SELECT A SESSION</div></div>
          ) : (
            <div className="detail">

              {/* Score ring */}
              <div className="dsec" style={{ textAlign: 'center' }}>
                <div className="score-ring">
                  <svg width="72" height="72" viewBox="0 0 72 72">
                    <circle cx="36" cy="36" r="32" fill="none" stroke="var(--bg4)" strokeWidth="5" />
                    <circle cx="36" cy="36" r="32" fill="none" stroke={selColor} strokeWidth="5" strokeLinecap="round"
                      strokeDasharray={circ} strokeDashoffset={circ - (selScore / 100) * circ}
                      style={{ transition: 'stroke-dashoffset 0.8s ease', filter: `drop-shadow(0 0 4px ${selColor})` }} />
                  </svg>
                  <div className="score-number" style={{ color: selColor }}>
                    {selScore}
                    <span style={{ fontSize: '9px', color: 'var(--text3)', fontWeight: 400 }}>{selected.threat_level}</span>
                  </div>
                </div>
              </div>

              {/* Session info */}
              <div className="dsec">
                <div className="dsec-title">Session Info</div>
                {[
                  ['ID', selected.session_id?.slice(0, 14) + '...'],
                  ['Started', fmtTime(selected.started_at)],
                  ['Messages', selected.message_count || 0],
                  ['Duration', fmtDur(selected.profile?.engagement_duration_sec)],
                  ['Sophistication', selected.profile?.sophistication_level || 'unknown'],
                ].map(([k, v]) => (
                  <div key={k} className="drow"><span className="dkey">{k}</span><span className="dval">{v}</span></div>
                ))}
              </div>

              {/* Cross-vector alert */}
              {selected._gateway_events?.length > 0 && (
                <div className="dsec">
                  <div className="dsec-title" style={{ color: 'var(--pink)' }}>🔗 Cross-Vector Actor</div>
                  <div className="cross-vector-box">
                    <span style={{ color: 'var(--pink)', fontWeight: 600 }}>HIGH CONFIDENCE</span> — Same actor operating across voice and prompt vectors.<br />
                    <span style={{ color: 'var(--text3)', fontSize: '9px' }}>{selected._gateway_events.length} Gateway event{selected._gateway_events.length > 1 ? 's' : ''} correlated to this session.</span>
                    <div className="vector-split">
                      <div className="vector-col">
                        <div className="vector-col-title" style={{ color: 'var(--aria)' }}>ARIA — Voice</div>
                        {(selected.detected_categories || []).slice(0, 4).map(t => (
                          <div key={t} style={{ color: 'var(--text2)', marginBottom: '2px' }}>→ {t.replace(/_/g, ' ')}</div>
                        ))}
                      </div>
                      <div className="vector-col">
                        <div className="vector-col-title" style={{ color: 'var(--gateway)' }}>GATEWAY — Prompt</div>
                        {selected._gateway_events.slice(0, 4).map((ev, i) => (
                          <div key={i} style={{ color: 'var(--text2)', marginBottom: '2px' }}>→ {(ev.categories?.[0] || ev.threat_level || 'detected').replace(/_/g, ' ')}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Techniques */}
              {(selected.detected_categories || []).length > 0 && (
                <div className="dsec">
                  <div className="dsec-title">Detected Techniques</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '5px' }}>
                    {selected.detected_categories.map(t => (
                      <span key={t} className="tag" style={{ color: 'var(--amber)', borderColor: 'rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)' }}>{t.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Honeytokens */}
              {(selected.honeytokens || []).length > 0 && (
                <div className="dsec">
                  <div className="dsec-title">🍯 Honeytokens Deployed</div>
                  {selected.honeytokens.map((h, i) => (
                    <div key={i} className="honey-item">
                      <div style={{ color: 'var(--text3)', fontSize: '9px', textTransform: 'uppercase', letterSpacing: '1px' }}>{h.type} — {h.system}</div>
                      <div className="honey-val">{h.value}</div>
                      <div style={{ color: 'var(--text3)', fontSize: '9px', marginTop: '3px' }}>{fmtTime(h.deployed_at)}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* Correlation */}
              {selected.correlation?.group_id && (
                <div className="dsec">
                  <div className="dsec-title">⚠️ Correlation: {selected.correlation.group_id}</div>
                  <div className="corr-box">
                    {selected.correlation.assessment}<br />
                    <span style={{ color: 'var(--text3)', fontSize: '9px' }}>
                      Matched: {selected.correlation.matches?.length || 0} other session(s)
                    </span>
                  </div>
                </div>
              )}

              {/* Attacker profile */}
              {selected.profile?.summary && (
                <div className="dsec">
                  <div className="dsec-title">Attacker Profile</div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text2)', lineHeight: 1.6, padding: '7px', background: 'var(--bg3)', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    {selected.profile.summary}
                  </div>
                  {(selected.profile.likely_objectives || []).length > 0 && (
                    <div style={{ marginTop: '7px' }}>
                      {selected.profile.likely_objectives.map((o, i) => (
                        <div key={i} style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text2)', padding: '3px 0', borderBottom: '1px solid var(--border)' }}>→ {o.slice(0, 80)}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* MITRE */}
              {(selected.mitre_tags || []).length > 0 && (
                <div className="dsec">
                  <div className="dsec-title">MITRE Tags</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '5px' }}>
                    {selected.mitre_tags.map(t => (
                      <span key={t} className="tag" style={{ color: 'var(--blue)', borderColor: 'rgba(88,166,255,0.3)' }}>{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Gateway events for this session */}
              {selected._gateway_events?.length > 0 && (
                <div className="dsec">
                  <div className="dsec-title" style={{ color: 'var(--gateway)' }}>Gateway — Prompt Attempts</div>
                  {selected._gateway_events.map((ev, i) => (
                    <div key={i} className="convo gateway">
                      <div className="convo-role">🛡 GATEWAY BLOCK · {fmtTime(ev.timestamp)}</div>
                      {ev.raw_content?.slice(0, 150)}{ev.raw_content?.length > 150 ? '...' : ''}
                      {ev.categories?.length > 0 && (
                        <div style={{ marginTop: '4px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {ev.categories.map(c => <span key={c} className="tag" style={{ color: 'var(--gateway)' }}>{c.replace(/_/g, ' ')}</span>)}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Conversation log */}
              {(selected.history || []).length > 0 && (
                <div className="dsec">
                  <div className="dsec-title">Conversation Log</div>
                  {selected.history.slice(-8).map((h, i) => (
                    <div key={i} className={`convo ${h.role}`}>
                      <div className="convo-role">{h.role === 'aria' ? '🪶 ARIA' : '⚠️ ATTACKER'}</div>
                      {h.content?.slice(0, 200)}{h.content?.length > 200 ? '...' : ''}
                      {h.honeytoken_deployed && <div style={{ color: 'var(--purple)', fontSize: '9px', marginTop: '3px' }}>🍯 Honeytoken deployed in this response</div>}
                    </div>
                  ))}
                </div>
              )}

              {/* Actions */}
              <div className="dsec">
                <div className="dsec-title">Actions</div>
                <div className="action-btns">
                  <button className="btn btn-nexus" onClick={pushToNexus}>⬆ Push to Nexus-Sec</button>
                  <button className="btn btn-export" onClick={exportSession}>⬇ Export JSON</button>
                </div>
                {pushResult && (
                  <div className="push-result">
                    <span style={{ color: pushResult.status === 'pushed' ? 'var(--green)' : pushResult.status === 'nexus_offline' ? 'var(--amber)' : 'var(--red)' }}>
                      [{pushResult.status?.toUpperCase()}]
                    </span>{' '}
                    {pushResult.message || ''}
                  </div>
                )}
              </div>

            </div>
          )}
        </div>

      </div>
    </>
  )
}