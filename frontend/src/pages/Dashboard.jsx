/**
 * Dashboard.jsx  —  MailGuard Exposure & Risk Dashboard
 *
 * Product: Email Exposure Management (ESPM)
 *
 * Layout:
 *   1. Top nav bar  (MailGuard brand, page title, tenant context, action buttons)
 *   2. Header strip (Risk Score pill | Security Score pill | Benchmarks cluster)
 *   3. Risk panel   (inline expandable, pushes table down — no modal/sidebar)
 *   4. Filter bar   (All Findings / Fail / Warning / Pass + Sort controls)
 *   5. Findings table
 */

import React, { useState, useEffect, useRef } from 'react'
import { RefreshCw, Download, Globe, Plus, Shield } from 'lucide-react'
import CheckRow from '../components/CheckRow'
import DetailPanel from '../components/DetailPanel'
import RiskPanel from '../components/RiskPanel'
import { api } from '../utils/api'
import { attachFindingBenchmarks, buildFindingBenchmarkMap } from '../utils/benchmarkDisplay'
import { ACTION_LABELS, BENCHMARK_LABELS, DASHBOARD_TITLE, EXPOSURE_LABELS, PRODUCT_LABEL, STATUS_LABELS, formatTenantContextLine, riskLevelFromScore, riskStateFromScore } from '../utils/uiLabels'

// ── Scan step labels (unchanged) ─────────────────────────────────────────────
const SCAN_STEPS = [
  'Connecting to Exchange Online...', 'Authenticating via Graph API...',
  'Fetching accepted domains...', 'Checking SPF records...',
  'Validating DKIM selectors...', 'Inspecting DMARC policies...',
  'Scanning anti-phishing policies...', 'Reviewing anti-spam configuration...',
  'Checking Safe Links policies...', 'Auditing Safe Attachments...',
  'Reviewing MFA enrollment...', 'Checking Conditional Access policies...',
  'Inspecting legacy auth settings...', 'Auditing direct send configuration...',
  'Compiling results...',
]

// ── Risk score derivation ─────────────────────────────────────────────────────
// Temporary heuristic until the backend exposes a real risk score.
// exposure_lift = weighted sum of fail/warn counts capped at 60.
function deriveRiskScores(findings, postureBase) {
  const critCount = findings.filter(f => f.status === 'fail').length
  const warnCount = findings.filter(f => f.status === 'warn').length
  const raw = Math.round(critCount * 4 + warnCount * 1.5)
  const exposureLift = Math.min(raw, 60)
  const riskScore = Math.min(100, Math.round((postureBase ?? 0) + exposureLift))
  return { riskScore, exposureLift }
}

function gradeFromScore(s) {
  if (s == null) return '—'
  if (s >= 90) return 'A'
  if (s >= 75) return 'B'
  if (s >= 60) return 'C'
  if (s >= 45) return 'D'
  return 'F'
}

function gradeColor(g) {
  if (g === 'A' || g === 'B') return '#00e676'
  if (g === 'C') return '#ffd740'
  return '#ff4f5e'
}

function securityToneColor(score) {
  if (score == null) return '#5a7290'
  return score >= 75 ? '#378add' : '#ba7517'
}

// ── Small arc SVG for Security Score pill ────────────────────────────────────
function SecArc({ score }) {
  const r = 14
  const circ = 2 * Math.PI * r
  const filled = score != null ? circ * (1 - score / 100) : circ
  return (
    <svg width="38" height="38" viewBox="0 0 38 38">
      <circle cx="19" cy="19" r={r} fill="none" stroke="rgba(14,68,124,.5)" strokeWidth="4" />
      <circle cx="19" cy="19" r={r} fill="none" stroke="#378add" strokeWidth="4"
        strokeDasharray={`${circ} ${circ}`} strokeDashoffset={filled}
        strokeLinecap="round" transform="rotate(-210 19 19)"
        style={{ transition: 'stroke-dashoffset .6s ease' }} />
      <text x="19" y="17" textAnchor="middle" fill="#378add" fontSize="9" fontWeight="700" fontFamily="monospace">
        {score ?? '—'}
      </text>
      <text x="19" y="26" textAnchor="middle" fill="#5a7290" fontSize="6" fontFamily="sans-serif">/100</text>
    </svg>
  )
}

// ── Larger benchmark arc for readability ─────────────────────────────────────
function BenchArc({ score, color }) {
  const r = 16
  const circ = 2 * Math.PI * r
  const filled = score != null ? circ * (1 - score / 100) : circ
  return (
    <svg width="42" height="42" viewBox="0 0 42 42">
      <circle cx="21" cy="21" r={r} fill="none" stroke="rgba(255,255,255,.06)" strokeWidth="5" />
      <circle cx="21" cy="21" r={r} fill="none" stroke={color} strokeWidth="5"
        strokeDasharray={`${circ} ${circ}`} strokeDashoffset={filled}
        strokeLinecap="round" transform="rotate(-210 21 21)"
        style={{ transition: 'stroke-dashoffset .6s ease' }} />
      <text x="21" y="18" textAnchor="middle" fill={color} fontSize="10" fontWeight="700" fontFamily="monospace">
        {score ?? '—'}
      </text>
      <text x="21" y="28" textAnchor="middle" fill="#5a7290" fontSize="6" fontFamily="sans-serif">/100</text>
    </svg>
  )
}

function benchmarkRank(benchmark) {
  const b = String(benchmark || '')
  if (/CIS/i.test(b)) return 0
  if (/SCuBA/i.test(b)) return 1
  if (/Secure Score/i.test(b)) return 2
  if (/Baseline/i.test(b)) return 3
  return 4
}

const BENCHMARK_CARD_ORDER = [
  { key: 'cis', label: BENCHMARK_LABELS.cis },
  { key: 'scuba', label: BENCHMARK_LABELS.scuba },
  { key: 'microsoft_secure_score', label: BENCHMARK_LABELS.microsoftSecureScore },
  { key: 'microsoft_baseline', label: BENCHMARK_LABELS.microsoftBaseline },
]

function benchmarkExecutionLabel(result) {
  if (!result) return 'Unavailable'
  if (result.execution_status === 'completed') return result.grade || gradeFromScore(result.score)
  if (result.execution_status === 'not_implemented') return 'Pending'
  if (result.execution_status === 'skipped') return 'Skipped'
  if (result.execution_status === 'failed') return 'Error'
  return 'Unavailable'
}

function benchmarkExecutionColor(result) {
  if (!result) return '#5a7290'
  if (result.execution_status === 'completed') {
    return gradeColor(result.grade || gradeFromScore(result.score))
  }
  if (result.execution_status === 'failed') return '#ff4f5e'
  return '#6f8196'
}

// ── Main component ────────────────────────────────────────────────────────────
export default function Dashboard({ tenant, scan, scanning, onScan, onAddTenant, token, selectableDomains }) {
  const [syncing, setSyncing] = useState(false)
  const [syncMsg, setSyncMsg] = useState(null)
  const [selectedCheck, setSelectedCheck] = useState(null)
  const [activeTab, setActiveTab] = useState('all')
  const [sortMode, setSortMode] = useState('severity')
  const [riskOpen, setRiskOpen] = useState(false)
  const [highlightId, setHighlightId] = useState(null)
  const [scanStep, setScanStep] = useState(0)
  const [benchmarkFilter, setBenchmarkFilter] = useState(null)
  const highlightTimer = useRef(null)

  useEffect(() => {
    const p = new URLSearchParams(window.location.search)
    if (p.get('gws_connected') === '1') { window.history.replaceState({}, '', '/'); window.location.reload() }
    if (p.get('gws_error')) { alert('Google Workspace connection failed: ' + p.get('gws_error')); window.history.replaceState({}, '', '/') }
  }, [])

  const isGws = tenant?.has_gws && !tenant?.has_m365
  const findings = scan?.findings || []
  const postureBase = scan?.score ?? 0
  const { riskScore, exposureLift } = deriveRiskScores(findings, postureBase)
  const riskState = riskStateFromScore(riskScore)
  const securityGrade = gradeFromScore(postureBase)
  const securityTone = securityToneColor(postureBase)

  const benchmarkResults = Array.isArray(scan?.benchmark_results) ? scan.benchmark_results : []
  const benchmarkResultMap = benchmarkResults.reduce((acc, result) => {
    if (result?.benchmark_key) acc[result.benchmark_key] = result
    return acc
  }, {})
  const benchmarkFindings = scan?.benchmark_findings || {}
  const findingBenchmarkMap = buildFindingBenchmarkMap(benchmarkFindings)
  const benchmarkCards = BENCHMARK_CARD_ORDER.map(({ key, label }) => {
    const result = benchmarkResultMap[key] || null
    const resultFindings = Array.isArray(benchmarkFindings[key])
      ? benchmarkFindings[key]
      : Array.isArray(result?.findings)
        ? result.findings
        : []

    return {
      key,
      label,
      result,
      score: typeof result?.score === 'number' ? result.score : null,
      findings: resultFindings,
    }
  })
  const benchmarkCardMap = benchmarkCards.reduce((acc, card) => {
    acc[card.key] = card
    return acc
  }, {})
  const BENCH_LABEL = benchmarkCards.reduce((acc, card) => {
    acc[card.key] = card.label
    return acc
  }, {})

  const benchFiltered = benchmarkFilter
    ? (benchmarkCardMap[benchmarkFilter]?.findings || [])
    : findings

  const tabFiltered = activeTab === 'all' ? benchFiltered
    : benchFiltered.filter(f =>
        activeTab === 'fail' ? f.status === 'fail'
      : activeTab === 'warn' ? f.status === 'warn'
      : f.status === 'pass'
      )

  const benchCritical = benchFiltered.filter(f => f.status === 'fail').length
  const benchWarnings = benchFiltered.filter(f => f.status === 'warn').length
  const benchPassing = benchFiltered.filter(f => f.status === 'pass').length

  const severityRank = { fail: 0, warn: 1, pass: 2 }
  const sorted = [...tabFiltered].sort((a, b) => {
    if (sortMode === 'benchmark') {
      const benchDelta = benchmarkRank(a.benchmark) - benchmarkRank(b.benchmark)
      if (benchDelta !== 0) return benchDelta
      const benchmarkText = String(a.benchmark || '').localeCompare(String(b.benchmark || ''))
      if (benchmarkText !== 0) return benchmarkText
    }

    const statusDelta = (severityRank[a.status] ?? 3) - (severityRank[b.status] ?? 3)
    if (statusDelta !== 0) return statusDelta
    return String(a.name || '').localeCompare(String(b.name || ''))
  })

  const displayFindings = sorted.map((finding) => attachFindingBenchmarks(finding, findingBenchmarkMap))

  const tabs = [
    { key: 'all', label: `All ${EXPOSURE_LABELS.findingPlural} (${benchFiltered.length})` },
    { key: 'fail', label: `${STATUS_LABELS.fail} (${benchCritical})` },
    { key: 'warn', label: `${STATUS_LABELS.warn} (${benchWarnings})` },
    { key: 'pass', label: `${STATUS_LABELS.pass} (${benchPassing})` },
  ]

  const syncDomains = async () => {
    if (!tenant) return
    setSyncing(true); setSyncMsg(null)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`/api/v1/tenants/${tenant.id}/sync-domains`, { method: 'POST', headers })
      const data = await res.json()
      if (res.ok) {
        const n = (data.extra_domains || []).length
        setSyncMsg(`Found ${n + 1} domain${n ? 's' : ''} (${[data.domain, ...(data.extra_domains || [])].join(', ')})`)
        setTimeout(() => window.location.reload(), 1500)
      } else {
        setSyncMsg(data.detail || 'Sync failed')
      }
    } catch {
      setSyncMsg('Sync failed')
    } finally {
      setSyncing(false)
    }
  }

  const startScan = () => {
    setScanStep(0); onScan()
    let i = 0
    const iv = setInterval(() => {
      i++; setScanStep(i)
      if (i >= SCAN_STEPS.length - 1) clearInterval(iv)
    }, 900)
  }

  const handleDriverClick = (checkId) => {
    setActiveTab('all')
    setRiskOpen(false)
    if (highlightTimer.current) clearTimeout(highlightTimer.current)
    setHighlightId(checkId)
    setTimeout(() => {
      const el = document.getElementById(`check-${checkId}`)
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
      highlightTimer.current = setTimeout(() => setHighlightId(null), 2800)
    }, 80)
  }

  const contextLine = formatTenantContextLine(tenant)
  const riskLevel = riskLevelFromScore(riskScore)

  return (
    <div>
      <div style={{
        padding: '10px 20px', borderBottom: '1px solid var(--border)',
        background: 'rgba(8,12,18,.9)', backdropFilter: 'blur(10px)',
        position: 'sticky', top: 0, zIndex: 10,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)', letterSpacing: '-.2px' }}>MailGuard</div>
          <div style={{ fontSize: 8, color: 'var(--accent)', letterSpacing: '1.2px', fontWeight: 700 }}>{PRODUCT_LABEL}</div>
        </div>

        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>{DASHBOARD_TITLE}</div>
          {contextLine && <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 1 }}>{contextLine}</div>}
          {syncMsg && <div style={{ fontSize: 10, color: 'var(--accent)', marginTop: 1 }}>{syncMsg}</div>}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {scan && (
            <button onClick={async () => {
              try {
                const res = await fetch(api.reportPdfUrl(scan.id), { headers: api.authHeaders() })
                if (!res.ok) throw new Error(`Server error ${res.status}`)
                const blob = await res.blob()
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                const cd = res.headers.get('content-disposition') || ''
                const m = cd.match(/filename="([^"]+)"/)
                const dt = new Date().toISOString().slice(0, 16).replace('T', '-').replace(/:/g, '')
                a.download = m ? m[1] : `mailguard-report-${dt}.pdf`
                a.href = url; document.body.appendChild(a); a.click()
                setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url) }, 100)
              } catch (e) { alert('Failed to download report: ' + e.message) }
            }} style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 10px', borderRadius: 5, fontSize: 11,
              border: '1px solid var(--border)', background: 'transparent',
              color: 'var(--muted)', cursor: 'pointer',
            }}>
              <Download size={11} /> {ACTION_LABELS.exportReport}
            </button>
          )}
          {!tenant ? (
            <button onClick={onAddTenant} style={{
              display: 'flex', alignItems: 'center', gap: 5, padding: '5px 10px',
              borderRadius: 5, fontSize: 11, border: '1px solid var(--border)',
              background: 'transparent', color: 'var(--muted)', cursor: 'pointer',
            }}>
              <Plus size={11} /> Connect Tenant
            </button>
          ) : (<>
            {!tenant.has_gws && (
              <button onClick={() => window.location.href = '/api/v1/google/connect'} style={{
                display: 'flex', alignItems: 'center', gap: 5, padding: '5px 10px',
                borderRadius: 5, fontSize: 11, border: '1px solid var(--border)',
                background: 'transparent', color: 'var(--muted)', cursor: 'pointer',
              }}>
                <svg width="11" height="11" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
                + Google Workspace
              </button>
            )}
            {(tenant.has_m365 || tenant.has_gws) && (
              <button onClick={syncDomains} disabled={syncing} style={{
                display: 'flex', alignItems: 'center', gap: 5, padding: '5px 10px',
                borderRadius: 5, fontSize: 11, border: '1px solid var(--border)',
                background: 'transparent', color: 'var(--muted)', cursor: syncing ? 'wait' : 'pointer',
                opacity: syncing ? .7 : 1,
              }}>
                <Globe size={11} style={{ animation: syncing ? 'spin 1s linear infinite' : '' }} />
                {syncing ? 'Syncing...' : ACTION_LABELS.syncData}
              </button>
            )}
            <button onClick={startScan} disabled={scanning} style={{
              display: 'flex', alignItems: 'center', gap: 5, padding: '5px 12px',
              borderRadius: 5, fontSize: 11, fontWeight: 700,
              background: 'var(--accent)', color: '#000', border: 'none',
              cursor: scanning ? 'wait' : 'pointer', opacity: scanning ? .7 : 1,
            }}>
              <RefreshCw size={11} style={{ animation: scanning ? 'spin 1s linear infinite' : '' }} />
              {scanning ? 'Scanning...' : ACTION_LABELS.runScan}
            </button>
          </>)}
        </div>
      </div>

      {tenant && (
        <div style={{
          display: 'flex', alignItems: 'stretch', borderBottom: '1px solid var(--border)',
          background: 'rgba(8,12,18,.6)',
        }}>
          <div
            onClick={() => scan && setRiskOpen(o => !o)}
            title={scan ? (riskOpen ? ACTION_LABELS.collapseRiskBreakdown : ACTION_LABELS.viewRiskBreakdown) : 'Run a scan first'}
            style={{
              display: 'flex', flexDirection: 'column', justifyContent: 'center',
              padding: '10px 16px', borderRight: '1px solid var(--border)',
              background: riskOpen ? 'rgba(255,79,94,.07)' : 'rgba(255,79,94,.03)',
              cursor: scan ? 'pointer' : 'default', minWidth: 172,
              transition: 'background .15s', gap: 1,
            }}
            onMouseOver={e => { if (scan) e.currentTarget.style.background = 'rgba(255,79,94,.09)' }}
            onMouseOut={e => { e.currentTarget.style.background = riskOpen ? 'rgba(255,79,94,.07)' : 'rgba(255,79,94,.03)' }}
          >
            <div style={{ fontSize: 8, color: '#8b4a42', letterSpacing: '.7px', fontWeight: 700 }}>RISK SCORE</div>
            <div style={{ fontSize: 32, fontWeight: 700, color: '#ff4f5e', fontFamily: 'var(--font-mono)', lineHeight: 1, marginBottom: 1 }}>
              {scan ? Math.round(riskScore) : '—'}
            </div>
            <div style={{ fontSize: 8, color: '#8b4a42', letterSpacing: '.7px', fontWeight: 700, marginTop: 2 }}>RISK LEVEL</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#ff4f5e', lineHeight: 1 }}>
              {scan ? riskLevel : 'No scan'}
            </div>
            <div style={{ fontSize: 10, color: '#c0543a', lineHeight: 1, marginTop: 2 }}>
              {scan ? `Risk State • ${riskState}` : 'Risk State • —'}
            </div>
            {scan && (
              <div style={{ fontSize: 8, color: '#484f58', marginTop: 4 }}>
                {riskOpen ? `▲ ${ACTION_LABELS.collapseRiskBreakdown}` : `▼ ${ACTION_LABELS.viewRiskBreakdown}`}
              </div>
            )}
          </div>

          <div style={{ width: 1, background: 'var(--border)' }} />

          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '10px 14px', borderRight: '1px solid var(--border)', minWidth: 158,
          }}>
            <SecArc score={scan ? Math.round(postureBase) : null} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <div style={{ fontSize: 8, color: '#185fa5', letterSpacing: '.7px', fontWeight: 700 }}>SECURITY SCORE</div>
              {scan ? (
                <>
                  <div style={{ fontSize: 13, fontWeight: 700, color: securityTone, lineHeight: 1 }}>
                    Grade {securityGrade}
                  </div>
                  <div style={{ fontSize: 9, color: '#5a7290' }}>Posture only</div>
                </>
              ) : (
                <div style={{ fontSize: 10, color: '#5a7290' }}>run a scan</div>
              )}
            </div>
          </div>

          <div style={{ width: 1, background: 'var(--border)' }} />

          <div style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '8px 14px', flex: 1,
          }}>
            <div style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.6px', fontWeight: 700, whiteSpace: 'nowrap' }}>
              BENCHMARKS
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {benchmarkCards.map(b => {
                const isActive = benchmarkFilter === b.key
                const valueLabel = scan ? benchmarkExecutionLabel(b.result) : '—'
                const color = isActive ? 'var(--accent)' : benchmarkExecutionColor(b.result)
                return (
                  <div
                    key={b.key}
                    onClick={() => {
                      if (!scan) return
                      setBenchmarkFilter(isActive ? null : b.key)
                      setActiveTab('all')
                    }}
                    title={isActive ? `Clear ${b.label} filter` : `Filter findings by ${b.label}`}
                    style={{
                      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                      background: isActive ? 'rgba(0,229,255,.05)' : 'rgba(255,255,255,.02)',
                      border: `1px solid ${isActive ? 'rgba(0,229,255,.35)' : 'rgba(255,255,255,.07)'}`,
                      borderRadius: 7, padding: '4px 7px', minWidth: 64,
                      cursor: scan ? 'pointer' : 'default', transition: 'all .15s',
                    }}
                    onMouseOver={e => { if (!isActive && scan) e.currentTarget.style.borderColor = 'rgba(0,229,255,.22)' }}
                    onMouseOut={e => { if (!isActive) e.currentTarget.style.borderColor = 'rgba(255,255,255,.07)' }}
                  >
                    <BenchArc score={b.score} color={color} />
                    <div style={{
                      fontSize: 9, marginTop: 1, textAlign: 'center', maxWidth: 72,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      color: isActive ? 'var(--accent)' : '#6f8196',
                    }}>
                      {b.label}
                    </div>
                    <div style={{ fontSize: 9, fontWeight: 700, color }}>
                      {valueLabel}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {tenant && riskOpen && scan && (
        <RiskPanel
          riskScore={riskScore}
          postureBase={postureBase}
          exposureLift={exposureLift}
          riskState={riskState}
          findings={findings}
          lastScan={scan.finished_at}
          onDriverClick={handleDriverClick}
        />
      )}

      {scanning && (
        <div style={{
          margin: '16px 20px 0',
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: '14px 18px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>
            <span>Scanning tenant configuration...</span>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{Math.round(((scanStep + 1) / SCAN_STEPS.length) * 100)}%</span>
          </div>
          <div style={{ height: 4, background: 'var(--surface2)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              height: '100%', background: 'linear-gradient(90deg, var(--accent), #7b61ff)',
              borderRadius: 2, width: `${Math.round(((scanStep + 1) / SCAN_STEPS.length) * 100)}%`,
              transition: 'width .4s ease',
            }} />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', marginTop: 5 }}>
            {SCAN_STEPS[scanStep]}
          </div>
        </div>
      )}

      {!tenant && (
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Shield size={48} color="var(--muted)" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>No tenant connected</h2>
          <p style={{ color: 'var(--muted)', marginBottom: 24 }}>
            Connect your Microsoft 365 or Google Workspace tenant to start scanning.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button onClick={() => window.location.href = '/connect'} style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '10px 24px',
              borderRadius: 6, fontSize: 14, fontWeight: 700, cursor: 'pointer',
              background: 'var(--accent)', color: '#000', border: 'none',
            }}>
              Connect Microsoft 365
            </button>
            <button onClick={() => window.location.href = '/api/v1/google/connect'} style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '10px 24px',
              borderRadius: 6, fontSize: 14, fontWeight: 700, cursor: 'pointer',
              background: '#fff', color: '#333', border: '1px solid var(--border)',
            }}>
              Connect Google Workspace
            </button>
          </div>
        </div>
      )}

      {tenant && (
        <div>
          {benchmarkFilter && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '4px 20px',
              background: 'rgba(0,229,255,.04)',
              borderLeft: '3px solid var(--accent)',
              borderBottom: '1px solid var(--border)',
              fontSize: 10,
            }}>
              <span style={{ fontWeight: 700, color: 'var(--accent)' }}>
                {BENCH_LABEL[benchmarkFilter]}
              </span>
              <span style={{ color: '#5a7290' }}>
                · {benchFiltered.length} findings · sorted by {sortMode === 'severity' ? 'status' : 'benchmark'}
              </span>
              <button
                onClick={() => setBenchmarkFilter(null)}
                style={{
                  marginLeft: 'auto', background: 'transparent', border: 'none',
                  color: '#5a7290', fontSize: 10, cursor: 'pointer', padding: '1px 4px',
                }}
              >
                ✕ clear filter
              </button>
            </div>
          )}

          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '0 20px', borderBottom: '1px solid var(--border)',
            background: 'rgba(8,12,18,.4)',
          }}>
            <div style={{ display: 'flex', alignItems: 'stretch' }}>
              {tabs.map(t => (
                <button key={t.key} onClick={() => setActiveTab(t.key)} style={{
                  padding: '9px 14px', fontSize: 11, fontWeight: activeTab === t.key ? 700 : 600,
                  background: 'transparent', border: 'none',
                  borderBottom: `2px solid ${activeTab === t.key ? 'var(--accent)' : 'transparent'}`,
                  color: activeTab === t.key ? 'var(--accent)' : 'var(--muted)',
                  cursor: 'pointer', marginBottom: -1,
                  transition: 'color .15s, border-color .15s',
                }}>
                  {t.label}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, color: 'var(--muted)' }}>
              <span>Sort:</span>
              <button onClick={() => setSortMode('severity')} style={{
                fontSize: 9, padding: '3px 7px', borderRadius: 4, cursor: 'pointer',
                background: 'transparent', border: `1px solid ${sortMode === 'severity' ? 'var(--accent)' : 'var(--border)'}`,
                color: sortMode === 'severity' ? 'var(--accent)' : 'var(--muted)',
              }}>Status ↓</button>
              <button onClick={() => setSortMode('benchmark')} style={{
                fontSize: 9, padding: '3px 7px', borderRadius: 4, cursor: 'pointer',
                background: 'transparent', border: `1px solid ${sortMode === 'benchmark' ? 'var(--accent)' : 'var(--border)'}`,
                color: sortMode === 'benchmark' ? 'var(--accent)' : 'var(--muted)',
              }}>By Benchmark</button>
            </div>
          </div>

          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 144px 110px 64px',
            gap: 10, padding: '6px 20px 6px 24px',
            fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase',
            color: 'var(--muted)', opacity: .5,
          }}>
            <div>{EXPOSURE_LABELS.finding}</div><div>{EXPOSURE_LABELS.domain}</div><div>Current Value</div><div>Status</div>
          </div>

          <div style={{ padding: '4px 20px 28px' }}>
            {findings.length === 0 && !scanning && (
              <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--muted)', fontSize: 13 }}>
                Run a scan to populate exposure findings.
              </div>
            )}
            {displayFindings.map(f => (
              <CheckRow
                key={f.check_id}
                finding={f}
                highlighted={highlightId === f.check_id}
                onClick={() => setSelectedCheck(attachFindingBenchmarks(f, findingBenchmarkMap))}
              />
            ))}
          </div>
        </div>
      )}

      {selectedCheck && (
        <DetailPanel finding={selectedCheck} onClose={() => setSelectedCheck(null)} />
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0) } to { transform: rotate(360deg) } }
        @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
      `}</style>
    </div>
  )
}
