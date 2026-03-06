import { useState, useEffect, useRef } from 'react'
import { Crosshair, RefreshCw, AlertTriangle, Shield, ChevronDown, ChevronUp, Globe, Clock, Server, Download, FileText } from 'lucide-react'

const API = '/api/v1/aggressive-scan'

const RISK_COLORS = {
  critical: { bg: 'rgba(239,68,68,0.12)',  border: '#ef4444', text: '#ef4444'  },
  high:     { bg: 'rgba(249,115,22,0.12)', border: '#f97316', text: '#f97316'  },
  medium:   { bg: 'rgba(234,179,8,0.12)',  border: '#eab308', text: '#eab308'  },
  low:      { bg: 'rgba(34,197,94,0.12)',  border: '#22c55e', text: '#22c55e'  },
}

const MUTATION_LABELS = {
  character_omission:             'Char omission',
  character_insertion:            'Char insertion',
  character_substitution:         'Char substitution',
  keyboard_substitution:          'Keyboard typo',
  transposition:                  'Transposition',
  tld_substitution:               'TLD swap',
  hyphenation_attack:             'Hyphen attack',
  unicode_homoglyph:              'Homoglyph',
  unicode_homoglyph_mixed_script: 'Mixed script',
  multi_character_edit:           'Multi-edit',
  pattern_match:                  'Pattern match',
}

function RiskBadge({ level }) {
  const c = RISK_COLORS[level] || RISK_COLORS.low
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
      padding: '2px 8px', borderRadius: 4,
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
    }}>
      {level}
    </span>
  )
}

function ScoreBar({ score, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'var(--surface2)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 2, transition: 'width .4s' }} />
      </div>
      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text)', minWidth: 28 }}>{score}</span>
    </div>
  )
}

function ResultRow({ r }) {
  const [open, setOpen] = useState(false)
  const riskColor = RISK_COLORS[r.risk_level] || RISK_COLORS.low

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, marginBottom: 6, overflow: 'hidden' }}>
      {/* Summary row */}
      <div
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 150px 100px 110px 90px 28px',
          alignItems: 'center',
          gap: 12,
          padding: '10px 14px',
          cursor: 'pointer',
          background: open ? 'rgba(0,229,255,0.03)' : 'var(--surface)',
          transition: 'background .15s',
        }}
      >
        <div>
          <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{r.candidate}</div>
          <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>
            ↳ {r.base_domain} · {MUTATION_LABELS[r.mutation_type] || r.mutation_type}
          </div>
        </div>
        <div>
          <ScoreBar score={r.enriched_score} color={riskColor.border} />
          <div style={{ fontSize: 9, color: 'var(--muted)', marginTop: 2 }}>sim: {r.similarity_score}</div>
        </div>
        <RiskBadge level={r.risk_level} />
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>
          {r.is_registered
            ? <span style={{ color: '#ef4444' }}>● Registered</span>
            : <span style={{ color: 'var(--muted)' }}>○ Unresolved</span>}
        </div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {r.dns?.has_mx  && <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'rgba(239,68,68,0.15)', color: '#ef4444', fontWeight: 700 }}>MX</span>}
          {r.dns?.has_a   && <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'rgba(0,229,255,0.1)', color: 'var(--accent)' }}>A</span>}
          {r.certs?.length > 0 && <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'rgba(139,164,190,0.15)', color: 'var(--muted)' }}>CT</span>}
          {r.takeover_risk && <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'rgba(249,115,22,0.15)', color: '#f97316', fontWeight: 700 }}>⚠ TKO</span>}
        </div>
        <div style={{ color: 'var(--muted)' }}>{open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</div>
      </div>

      {/* Expanded detail */}
      {open && (
        <div style={{ padding: '12px 14px', borderTop: '1px solid var(--border)', background: 'var(--surface2)', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          {/* Reasons */}
          <div>
            <div style={{ fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 6 }}>Detection Reasons</div>
            {r.reasons.map((reason, i) => (
              <div key={i} style={{ fontSize: 12, color: 'var(--text)', marginBottom: 3 }}>• {reason}</div>
            ))}
          </div>

          {/* DNS */}
          <div>
            <div style={{ fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 6 }}>DNS Records</div>
            {r.dns ? (
              <>
                {r.dns.a_records?.length    > 0 && <div style={{ fontSize: 11, color: 'var(--text)', marginBottom: 2 }}><b>A:</b> {r.dns.a_records.join(', ')}</div>}
                {r.dns.aaaa_records?.length > 0 && <div style={{ fontSize: 11, color: 'var(--text)', marginBottom: 2 }}><b>AAAA:</b> {r.dns.aaaa_records.join(', ')}</div>}
                {r.dns.mx_records?.length   > 0 && <div style={{ fontSize: 11, color: '#ef4444', marginBottom: 2 }}><b>MX:</b> {r.dns.mx_records.join(', ')}</div>}
                {r.dns.ns_records?.length   > 0 && <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 2 }}><b>NS:</b> {r.dns.ns_records.slice(0,2).join(', ')}</div>}
                {r.dns.txt_records?.length  > 0 && <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 2 }}><b>TXT:</b> {r.dns.txt_records[0]?.slice(0, 60)}</div>}
                {!r.is_registered           && <div style={{ fontSize: 11, color: 'var(--muted)', fontStyle: 'italic' }}>No active DNS records — may be pre-registered</div>}
              </>
            ) : <div style={{ fontSize: 11, color: 'var(--muted)' }}>No DNS data</div>}
          </div>

          {/* WHOIS + CT + Takeover */}
          <div>
            {r.whois && (
              <>
                <div style={{ fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 6 }}>WHOIS / RDAP</div>
                {r.whois.age_days != null && (
                  <div style={{ fontSize: 11, color: r.whois.age_days < 90 ? '#ef4444' : 'var(--text)', marginBottom: 2 }}>
                    <b>Age:</b> {r.whois.age_days} days {r.whois.age_days < 90 ? '⚠ FRESH' : ''}
                  </div>
                )}
                {r.whois.registrar     && <div style={{ fontSize: 11, color: 'var(--text)', marginBottom: 2 }}><b>Registrar:</b> {r.whois.registrar}</div>}
                {r.whois.registrant_org && <div style={{ fontSize: 11, color: 'var(--text)', marginBottom: 2 }}><b>Registrant:</b> {r.whois.registrant_org}</div>}
                {r.whois.registered_date && <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 2 }}><b>Registered:</b> {r.whois.registered_date?.slice(0,10)}</div>}
              </>
            )}
            {r.certs?.length > 0 && (
              <>
                <div style={{ fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--muted)', marginTop: 10, marginBottom: 6 }}>CT Certificates ({r.certs.length})</div>
                {r.certs.slice(0, 2).map((c, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--text)', marginBottom: 2 }}>
                    {c.domain} · {c.not_before?.slice(0,10)} → {c.not_after?.slice(0,10)}
                  </div>
                ))}
              </>
            )}
            {r.takeover_risk && (
              <div style={{ marginTop: 10, padding: '6px 10px', background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)', borderRadius: 6 }}>
                <div style={{ fontSize: 11, color: '#f97316', fontWeight: 600 }}>⚠ Takeover Risk: {r.takeover_risk}</div>
                <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>Domain points to cloud infra that may be claimable</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default function LookalikeScan({ token }) {
  const [scanId,   setScanId]   = useState(null)
  const [status,   setStatus]   = useState(null)   // pending|running|completed|failed
  const [results,  setResults]  = useState(null)
  const [domains,  setDomains]  = useState([])
  const [error,    setError]    = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [filter,   setFilter]   = useState('all')
  const [sortKey,  setSortKey]  = useState('risk_level')
  const [sortDir,  setSortDir]  = useState('asc')
  const [hideNoSignals, setHideNoSignals] = useState(false)
  const pollRef = useRef(null)

  const headers = { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }

  const stopPolling = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null } }

  const pollStatus = async (id) => {
    try {
      const r = await fetch(`${API}/status/${id}`, { headers })
      const data = await r.json()
      setStatus(data.status)
      setDomains(data.domains || [])
      if (data.status === 'completed' || data.status === 'failed') {
        stopPolling()
        setLoading(false)
        if (data.status === 'completed') {
          const res = await fetch(`${API}/result/${id}`, { headers })
          const full = await res.json()
          setResults(full.results || [])
        } else {
          setError(data.error || 'Scan failed.')
        }
      }
    } catch (e) {
      stopPolling()
      setLoading(false)
      setError('Lost connection during scan.')
    }
  }

  const handleTrigger = async () => {
    setLoading(true)
    setError(null)
    setResults(null)
    setScanId(null)
    setStatus('pending')
    stopPolling()
    try {
      const r = await fetch(`${API}/trigger`, { method: 'POST', headers })
      if (!r.ok) {
        let msg = `Server error ${r.status}`
        try { const e = await r.json(); msg = e.detail || msg } catch (_) {}
        throw new Error(msg)
      }
      const data = await r.json()
      setScanId(data.id)
      setStatus(data.status)
      pollRef.current = setInterval(() => pollStatus(data.id), 3000)
    } catch (e) {
      setLoading(false)
      setStatus(null)
      setError(e.message)
    }
  }

  useEffect(() => () => stopPolling(), [])

  const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

  const handleSort = (key) => {
    if (sortKey === key) { setSortDir(d => d === 'desc' ? 'asc' : 'desc') }
    else { setSortKey(key); setSortDir('desc') }
  }

  const SortIcon = ({ col }) => {
    if (sortKey !== col) return <span style={{ color:'var(--muted)', fontSize:9, marginLeft:3 }}>↕</span>
    return <span style={{ color:'var(--accent)', fontSize:9, marginLeft:3 }}>{sortDir === 'desc' ? '↓' : '↑'}</span>
  }

  const hasSignals = (r) => r.is_registered || r.dns?.has_mx || r.dns?.has_a || (r.certs?.length > 0) || r.takeover_risk

  const filtered = (results || [])
    .filter(r => {
      if (hideNoSignals && !r.is_registered && !hasSignals(r)) return false
      if (filter === 'all')        return true
      if (filter === 'registered') return r.is_registered
      return r.risk_level === filter
    })
    .sort((a, b) => {
      const dir = sortDir === 'desc' ? 1 : -1
      if (sortKey === 'enriched_score') {
        const diff = b.enriched_score - a.enriched_score
        return diff !== 0 ? diff * dir : a.candidate.localeCompare(b.candidate)
      }
      if (sortKey === 'risk_level') {
        const diff = (RISK_ORDER[a.risk_level] ?? 4) - (RISK_ORDER[b.risk_level] ?? 4)
        return diff !== 0 ? diff * dir : a.candidate.localeCompare(b.candidate)
      }
      if (sortKey === 'candidate') {
        return a.candidate.localeCompare(b.candidate) * dir
      }
      if (sortKey === 'signals') {
        const diff = b.similarity_score - a.similarity_score
        return diff !== 0 ? diff * dir : a.candidate.localeCompare(b.candidate)
      }
      if (sortKey === 'status') {
        const aR = a.is_registered ? 0 : 1
        const bR = b.is_registered ? 0 : 1
        return aR !== bR ? (aR - bR) * dir : a.candidate.localeCompare(b.candidate)
      }
      return 0
    })

  const counts = (results || []).reduce((acc, r) => {
    acc[r.risk_level] = (acc[r.risk_level] || 0) + 1
    acc.registered = (acc.registered || 0) + (r.is_registered ? 1 : 0)
    return acc
  }, {})

  const exportCSV = () => {
    const hdrs = [
      'Candidate','Base Domain','Risk Level','Enriched Score','Similarity Score',
      'Mutation Type','Registered','Has MX','Has A','Takeover Risk',
      'Domain Age (days)','Registrar','Registered Date','CT Certs','Reasons'
    ]
    const rows = (results || []).map(r => [
      r.candidate, r.base_domain, r.risk_level, r.enriched_score, r.similarity_score,
      r.mutation_type, r.is_registered ? 'Yes' : 'No',
      r.dns?.has_mx ? 'Yes' : 'No', r.dns?.has_a ? 'Yes' : 'No',
      r.takeover_risk || '', r.whois?.age_days ?? '', r.whois?.registrar || '',
      r.whois?.registered_date?.slice(0,10) || '', r.certs?.length || 0,
      (r.reasons || []).join(' | '),
    ])
    const csv = [hdrs, ...rows]
      .map(row => row.map(v => `"${String(v).replace(/"/g,'""')}"`).join(','))
      .join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `lookalike-scan-${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const exportPDF = () => {
    const win = window.open('', '_blank')
    const rc = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e' }
    const trs = (results || []).map(r => `<tr style="border-bottom:1px solid #e5e7eb">
      <td style="padding:6px 8px;font-family:monospace;font-size:12px">${r.candidate}</td>
      <td style="padding:6px 8px;font-size:12px">${r.base_domain}</td>
      <td style="padding:6px 8px"><span style="background:${rc[r.risk_level]}22;color:${rc[r.risk_level]};border:1px solid ${rc[r.risk_level]};padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase">${r.risk_level}</span></td>
      <td style="padding:6px 8px;text-align:center;font-weight:600">${r.enriched_score}</td>
      <td style="padding:6px 8px;font-size:11px">${(r.mutation_type||'').replace(/_/g,' ')}</td>
      <td style="padding:6px 8px;font-size:11px;color:${r.is_registered?'#ef4444':'#6b7280'}">${r.is_registered?'● Registered':'○ Unresolved'}</td>
      <td style="padding:6px 8px;font-size:11px">${r.dns?.has_mx?'<b style="color:#ef4444">MX</b>':''}${r.dns?.has_a?' A':''}</td>
      <td style="padding:6px 8px;font-size:11px">${r.whois?.age_days!=null?r.whois.age_days+'d':'—'}</td>
      <td style="padding:6px 8px;font-size:11px;max-width:200px">${(r.reasons||[]).slice(0,2).join('; ')}</td>
    </tr>`).join('')
    win.document.write(`<!DOCTYPE html><html><head>
      <title>MailGuard Lookalike Scan</title>
      <style>body{font-family:-apple-system,sans-serif;margin:32px;color:#111}
      h1{font-size:20px;margin-bottom:4px}.meta{font-size:12px;color:#6b7280;margin-bottom:24px}
      table{width:100%;border-collapse:collapse;font-size:12px}
      th{background:#f3f4f6;padding:8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e5e7eb}
      @media print{@page{margin:16mm}}</style>
    </head><body>
      <h1>MailGuard — Lookalike Scanner (Aggressive)</h1>
      <div class="meta">Domains: ${(domains||[]).join(', ')} · ${(results||[]).length} candidates · ${new Date().toLocaleString()}</div>
      <table><thead><tr>
        <th>Candidate</th><th>Base</th><th>Risk</th><th>Score</th>
        <th>Mutation</th><th>Status</th><th>DNS</th><th>Age</th><th>Reasons</th>
      </tr></thead><tbody>${trs}</tbody></table>
    </body></html>`)
    win.document.close()
    win.focus()
    setTimeout(() => win.print(), 400)
  }

  return (
    <div style={{ padding: '28px 32px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <Crosshair size={20} color="var(--accent)" />
            <h1 style={{ fontSize: 20, fontWeight: 600, margin: 0 }}>Lookalike Scanner</h1>
            <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(239,68,68,0.12)', color: '#ef4444', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: '1px solid rgba(239,68,68,0.3)' }}>
              Aggressive
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--muted)', margin: 0 }}>
            Deep typosquatting scan across all connected tenant domains — includes DNS, WHOIS, CT and takeover detection.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {results && results.length > 0 && (
            <>
              <button onClick={exportCSV} style={{
                display:'flex',alignItems:'center',gap:6,padding:'8px 14px',
                borderRadius:8,border:'1px solid var(--border)',background:'transparent',
                color:'var(--text)',cursor:'pointer',fontSize:12,fontFamily:'var(--font-body)',transition:'all .15s'
              }}>
                <Download size={13} /> CSV
              </button>
              <button onClick={exportPDF} style={{
                display:'flex',alignItems:'center',gap:6,padding:'8px 14px',
                borderRadius:8,border:'1px solid var(--border)',background:'transparent',
                color:'var(--text)',cursor:'pointer',fontSize:12,fontFamily:'var(--font-body)',transition:'all .15s'
              }}>
                <FileText size={13} /> PDF
              </button>
            </>
          )}
          <button
            onClick={handleTrigger}
            disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '10px 20px', borderRadius: 8,
            background: loading ? 'var(--surface2)' : 'var(--accent)',
            color: loading ? 'var(--muted)' : '#000',
            border: 'none', cursor: loading ? 'not-allowed' : 'pointer',
            fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-body)',
            transition: 'all .15s',
          }}
        >
          {loading
            ? <><RefreshCw size={14} style={{ animation: 'spin 1s linear infinite' }} /> Scanning…</>
            : <><Crosshair size={14} /> Run Aggressive Scan</>}
        </button>
        </div>
      </div>

      {/* Status bar */}
      {status && status !== 'completed' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, marginBottom: 20 }}>
          {status === 'running'
            ? <RefreshCw size={14} color="var(--accent)" style={{ animation: 'spin 1s linear infinite' }} />
            : <Clock size={14} color="var(--muted)" />}
          <span style={{ fontSize: 13, color: 'var(--text)', textTransform: 'capitalize' }}>{status}</span>
          {domains.length > 0 && (
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>— scanning {domains.length} domain{domains.length !== 1 ? 's' : ''}: {domains.join(', ')}</span>
          )}
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ display: 'flex', gap: 10, padding: '12px 16px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, marginBottom: 20 }}>
          <AlertTriangle size={15} color="#ef4444" style={{ flexShrink: 0, marginTop: 1 }} />
          <span style={{ fontSize: 13, color: '#ef4444' }}>{error}</span>
        </div>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10, marginBottom: 20 }}>
            {[
              { label: 'Total',      value: results.length,          color: 'var(--text)',   filter: 'all' },
              { label: 'Critical',   value: counts.critical  || 0,   color: '#ef4444',       filter: 'critical' },
              { label: 'High',       value: counts.high      || 0,   color: '#f97316',       filter: 'high' },
              { label: 'Medium',     value: counts.medium    || 0,   color: '#eab308',       filter: 'medium' },
              { label: 'Registered', value: counts.registered || 0,  color: 'var(--accent)', filter: 'registered' },
            ].map(({ label, value, color, filter: f }) => (
              <div
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  background: filter === f ? 'rgba(0,229,255,0.06)' : 'var(--surface)',
                  border: `1px solid ${filter === f ? 'rgba(0,229,255,0.3)' : 'var(--border)'}`,
                  borderRadius: 8, padding: '12px 16px', cursor: 'pointer', transition: 'all .15s',
                }}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 700, color }}>{value}</div>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Filters toolbar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 12 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer', userSelect: 'none' }}>
              <input
                type="checkbox"
                checked={hideNoSignals}
                onChange={e => setHideNoSignals(e.target.checked)}
                style={{ width: 14, height: 14, accentColor: 'var(--accent)', cursor: 'pointer' }}
              />
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>Hide unresolved / no-signal domains</span>
            </label>
          </div>

          {/* Column headers — clickable to sort */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 150px 100px 110px 90px 28px',
            gap: 12, padding: '6px 14px', marginBottom: 4,
          }}>
            {[
              { label: 'Domain / Base', key: 'candidate' },
              { label: 'Proximity Score', key: 'enriched_score' },
              { label: 'Risk',          key: 'risk_level' },
              { label: 'Status',        key: 'status' },
              { label: 'Signals',       key: 'signals' },
              { label: '',              key: null },
            ].map(({ label, key }) => (
              <div
                key={label}
                onClick={() => key && handleSort(key)}
                style={{
                  fontSize: 10, letterSpacing: 1, textTransform: 'uppercase',
                  color: sortKey === key ? 'var(--accent)' : 'var(--muted)',
                  cursor: key ? 'pointer' : 'default',
                  userSelect: 'none',
                  display: 'flex', alignItems: 'center',
                  transition: 'color .15s',
                }}
              >
                {label}{key && <SortIcon col={key} />}
              </div>
            ))}
          </div>

          {/* Rows */}
          {filtered.length === 0
            ? <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontSize: 13 }}>No results for this filter.</div>
            : filtered.map((r, i) => <ResultRow key={`${r.candidate}-${r.base_domain}-${i}`} r={r} />)
          }

          {/* Scan meta */}
          <div style={{ marginTop: 16, fontSize: 11, color: 'var(--muted)', textAlign: 'right' }}>
            Scanned {domains.length} domain{domains.length !== 1 ? 's' : ''} · {results.length} candidates scored · Sorted by enriched risk score
          </div>
        </>
      )}

      {/* Empty state */}
      {!results && !loading && !error && (
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Crosshair size={40} color="var(--muted)" style={{ marginBottom: 16, opacity: 0.4 }} />
          <div style={{ fontSize: 14, color: 'var(--muted)', marginBottom: 8 }}>No scan run yet</div>
          <div style={{ fontSize: 12, color: 'var(--muted)', opacity: 0.7 }}>Click "Run Aggressive Scan" to start a deep lookalike analysis across all your tenants.</div>
        </div>
      )}

      <style>{`@keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}
