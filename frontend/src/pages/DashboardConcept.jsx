import React, { useMemo, useState } from 'react'
import { AlertTriangle, ChevronRight, Download, RefreshCw, Shield, Sparkles, Target } from 'lucide-react'
import CheckRow from '../components/CheckRow'
import DetailPanel from '../components/DetailPanel'
import { api } from '../utils/api'
import { attachFindingBenchmarks, buildFindingBenchmarkMap } from '../utils/benchmarkDisplay'
import { ACTION_LABELS, BENCHMARK_LABELS, DASHBOARD_TITLE, EXPOSURE_LABELS, PRODUCT_LABEL, STATUS_LABELS, formatTenantContextLine, riskLevelFromScore } from '../utils/uiLabels'

function deriveRiskScores(findings, postureBase) {
  const critCount = findings.filter((f) => f.status === 'fail').length
  const warnCount = findings.filter((f) => f.status === 'warn').length
  const raw = Math.round(critCount * 4 + warnCount * 1.5)
  const exposureLift = Math.min(raw, 60)
  const riskScore = Math.min(100, Math.round((postureBase ?? 0) + exposureLift))
  return { riskScore, exposureLift }
}

function gradeFromScore(score) {
  if (score == null) return '—'
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 45) return 'D'
  return 'F'
}

function gradeColor(grade) {
  if (grade === 'A' || grade === 'B') return '#2dd4bf'
  if (grade === 'C') return '#f59e0b'
  return '#f87171'
}

function benchmarkExecutionLabel(result) {
  if (!result) return 'Unavailable'
  if (result.execution_status === 'completed') return result.grade || gradeFromScore(result.score)
  if (result.execution_status === 'not_implemented') return 'Pending'
  if (result.execution_status === 'skipped') return 'Skipped'
  if (result.execution_status === 'failed') return 'Error'
  return 'Unavailable'
}

function benchmarkExecutionColor(result) {
  if (!result) return '#64748b'
  if (result.execution_status === 'completed') return gradeColor(result.grade || gradeFromScore(result.score))
  if (result.execution_status === 'failed') return '#f87171'
  return '#94a3b8'
}

const BENCHMARK_CARD_ORDER = [
  { key: 'cis', label: BENCHMARK_LABELS.cis },
  { key: 'scuba', label: BENCHMARK_LABELS.scuba },
  { key: 'microsoft_secure_score', label: BENCHMARK_LABELS.microsoftSecureScore },
  { key: 'microsoft_baseline', label: BENCHMARK_LABELS.microsoftBaseline },
]

const STATUS_TONE = {
  fail: { color: '#f87171', bg: 'rgba(248,113,113,.12)' },
  warn: { color: '#fbbf24', bg: 'rgba(251,191,36,.12)' },
  pass: { color: '#34d399', bg: 'rgba(52,211,153,.12)' },
}

function Frame({ children, style }) {
  return (
    <div
      style={{
        background: 'linear-gradient(180deg, rgba(11,18,30,.92), rgba(8,12,20,.96))',
        border: '1px solid rgba(111,139,184,.16)',
        borderRadius: 18,
        boxShadow: '0 24px 60px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.03)',
        ...style,
      }}
    >
      {children}
    </div>
  )
}

function ScoreDial({ score, tone, label, sublabel }) {
  const radius = 48
  const circumference = 2 * Math.PI * radius
  const safeScore = typeof score === 'number' ? Math.max(0, Math.min(100, score)) : null
  const dashOffset = safeScore == null ? circumference : circumference * (1 - safeScore / 100)

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
      <svg width="132" height="132" viewBox="0 0 132 132">
        <defs>
          <linearGradient id={`dial-${tone.replace('#', '')}`} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={tone} stopOpacity="1" />
            <stop offset="100%" stopColor={tone} stopOpacity=".58" />
          </linearGradient>
        </defs>
        <circle cx="66" cy="66" r={radius} fill="none" stroke="rgba(148,163,184,.1)" strokeWidth="10" />
        <circle
          cx="66"
          cy="66"
          r={radius}
          fill="none"
          stroke={`url(#dial-${tone.replace('#', '')})`}
          strokeWidth="10"
          strokeDasharray={`${circumference} ${circumference}`}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          transform="rotate(-210 66 66)"
        />
        <text x="66" y="60" textAnchor="middle" fill={tone} fontSize="34" fontWeight="700" fontFamily="var(--font-mono)">
          {safeScore ?? '—'}
        </text>
        <text x="66" y="81" textAnchor="middle" fill="#7b8ba7" fontSize="11">/100</text>
      </svg>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 11, letterSpacing: '1.6px', textTransform: 'uppercase', color: '#7b8ba7', marginBottom: 6 }}>{label}</div>
        <div style={{ fontSize: 28, fontWeight: 700, color: '#f8fafc', lineHeight: 1.05 }}>{sublabel}</div>
      </div>
    </div>
  )
}

export default function DashboardConcept({ tenant, scan, scanning, onScan, onAddTenant, token }) {
  const [selectedCheck, setSelectedCheck] = useState(null)
  const [activeTab, setActiveTab] = useState('all')

  const findings = scan?.findings || []
  const postureBase = scan?.score ?? 0
  const { riskScore } = deriveRiskScores(findings, postureBase)
  const riskLevel = riskLevelFromScore(riskScore)
  const securityGrade = gradeFromScore(postureBase)
  const contextLine = formatTenantContextLine(tenant)

  const benchmarkResults = Array.isArray(scan?.benchmark_results) ? scan.benchmark_results : []
  const benchmarkResultMap = benchmarkResults.reduce((acc, result) => {
    if (result?.benchmark_key) acc[result.benchmark_key] = result
    return acc
  }, {})
  const benchmarkFindings = scan?.benchmark_findings || {}
  const findingBenchmarkMap = buildFindingBenchmarkMap(benchmarkFindings)
  const benchmarkCards = BENCHMARK_CARD_ORDER.map(({ key, label }) => ({
    key,
    label,
    result: benchmarkResultMap[key] || null,
  }))

  const enrichedFindings = findings.map((finding) => attachFindingBenchmarks(finding, findingBenchmarkMap))
  const failCount = enrichedFindings.filter((f) => f.status === 'fail').length
  const warnCount = enrichedFindings.filter((f) => f.status === 'warn').length
  const passCount = enrichedFindings.filter((f) => f.status === 'pass').length

  const filteredFindings = activeTab === 'all'
    ? enrichedFindings
    : enrichedFindings.filter((finding) => finding.status === activeTab)

  const severityRank = { fail: 0, warn: 1, pass: 2 }
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    const statusDelta = (severityRank[a.status] ?? 3) - (severityRank[b.status] ?? 3)
    if (statusDelta !== 0) return statusDelta
    return String(a.name || '').localeCompare(String(b.name || ''))
  })

  const findingByCheck = useMemo(() => {
    const map = {}
    enrichedFindings.forEach((finding) => {
      if (!map[finding.check_id]) map[finding.check_id] = finding
    })
    return map
  }, [enrichedFindings])

  const actionQueue = useMemo(() => {
    return (scan?.penalty_breakdown || [])
      .filter((item) => item.status !== 'pass')
      .sort((a, b) => (b.max_points || 0) - (a.max_points || 0))
      .slice(0, 5)
      .map((item) => ({
        ...item,
        finding: findingByCheck[item.check_id],
      }))
  }, [scan?.penalty_breakdown, findingByCheck])

  const topDrivers = useMemo(() => {
    return enrichedFindings
      .filter((finding) => finding.status !== 'pass')
      .slice(0, 4)
  }, [enrichedFindings])

  const startScan = () => {
    if (!scanning) onScan()
  }

  const exportReport = async () => {
    if (!scan) return
    try {
      const res = await fetch(api.reportPdfUrl(scan.id), { headers: api.authHeaders() })
      if (!res.ok) throw new Error(`Server error ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      const dt = new Date().toISOString().slice(0, 16).replace('T', '-').replace(/:/g, '')
      a.download = `mailguard-report-${dt}.pdf`
      a.href = url
      document.body.appendChild(a)
      a.click()
      setTimeout(() => {
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      }, 100)
    } catch (e) {
      alert(`Failed to download report: ${e.message}`)
    }
  }

  if (!tenant) {
    return (
      <div style={{ padding: 36 }}>
        <Frame style={{ padding: 32, textAlign: 'center' }}>
          <Shield size={42} color="#7b8ba7" style={{ margin: '0 auto 14px' }} />
          <div style={{ fontSize: 28, fontWeight: 700, color: '#f8fafc', marginBottom: 8 }}>Concept Dashboard</div>
          <div style={{ color: '#93a4bf', marginBottom: 22 }}>Connect a tenant to preview the alternate landing page with real scan data.</div>
          <button onClick={onAddTenant} style={{ padding: '10px 16px', borderRadius: 10, border: 'none', background: 'linear-gradient(135deg, #38bdf8, #2563eb)', color: '#06111f', fontWeight: 700, cursor: 'pointer' }}>
            Connect Tenant
          </button>
        </Frame>
      </div>
    )
  }

  const tabs = [
    { key: 'all', label: `All Findings ${enrichedFindings.length}` },
    { key: 'fail', label: `Critical ${failCount}` },
    { key: 'warn', label: `Warnings ${warnCount}` },
    { key: 'pass', label: `Passing ${passCount}` },
  ]

  return (
    <div style={{ minHeight: '100vh', background: 'radial-gradient(circle at top left, rgba(37,99,235,.16), transparent 34%), radial-gradient(circle at top right, rgba(16,185,129,.08), transparent 26%), linear-gradient(180deg, #060b13 0%, #0a1220 100%)' }}>
      <div style={{ padding: '26px 26px 32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 22 }}>
          <div>
            <div style={{ fontSize: 13, letterSpacing: '1.7px', textTransform: 'uppercase', color: '#38bdf8', fontWeight: 700, marginBottom: 8 }}>{PRODUCT_LABEL}</div>
            <div style={{ fontSize: 34, fontWeight: 700, color: '#f8fafc', letterSpacing: '-.03em', marginBottom: 6 }}>{DASHBOARD_TITLE} Concept</div>
            <div style={{ color: '#93a4bf', fontSize: 14 }}>{contextLine}</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {scan && (
              <button onClick={exportReport} style={{ padding: '10px 14px', borderRadius: 10, border: '1px solid rgba(148,163,184,.18)', background: 'rgba(15,23,42,.65)', color: '#d7e3f4', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Download size={14} /> {ACTION_LABELS.exportReport}
              </button>
            )}
            <button onClick={startScan} disabled={scanning} style={{ padding: '10px 16px', borderRadius: 10, border: 'none', background: 'linear-gradient(135deg, #38bdf8, #2563eb)', color: '#06111f', fontWeight: 800, cursor: scanning ? 'wait' : 'pointer', display: 'flex', alignItems: 'center', gap: 8, opacity: scanning ? .8 : 1 }}>
              <RefreshCw size={14} style={{ animation: scanning ? 'spin 1s linear infinite' : '' }} />
              {scanning ? 'Scanning...' : ACTION_LABELS.runScan}
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr .8fr .95fr', gap: 18, marginBottom: 18 }}>
          <Frame style={{ padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 18, alignItems: 'flex-start' }}>
              <ScoreDial score={riskScore} tone="#f97373" label="Risk Score" sublabel={riskLevel} />
              <div style={{ minWidth: 220 }}>
                <div style={{ fontSize: 11, letterSpacing: '1.6px', textTransform: 'uppercase', color: '#7b8ba7', marginBottom: 10 }}>What the CISO sees</div>
                <div style={{ display: 'grid', gap: 10 }}>
                  <div style={{ color: '#f8fafc', fontSize: 15, fontWeight: 600 }}>{failCount} active fail states are driving exposure.</div>
                  <div style={{ color: '#93a4bf', fontSize: 13, lineHeight: 1.55 }}>This version makes risk the headline, keeps posture separate, and puts the operational work queue directly underneath.</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
                    <Pill tone="#f87171" text={`${failCount} fail`} />
                    <Pill tone="#fbbf24" text={`${warnCount} warning`} />
                    <Pill tone="#34d399" text={`${passCount} pass`} />
                  </div>
                </div>
              </div>
            </div>
          </Frame>

          <Frame style={{ padding: 24 }}>
            <div style={{ fontSize: 11, letterSpacing: '1.6px', textTransform: 'uppercase', color: '#7b8ba7', marginBottom: 14 }}>Security Score</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 18, marginBottom: 16 }}>
              <ScoreDial score={postureBase} tone="#38bdf8" label="Posture only" sublabel={`Grade ${securityGrade}`} />
            </div>
            <div style={{ color: '#93a4bf', fontSize: 13, lineHeight: 1.55 }}>Security Score stays posture-only here so it cannot be confused with external exposure or risk severity.</div>
          </Frame>

          <Frame style={{ padding: 24 }}>
            <div style={{ fontSize: 11, letterSpacing: '1.6px', textTransform: 'uppercase', color: '#7b8ba7', marginBottom: 14 }}>Top Risk Drivers</div>
            <div style={{ display: 'grid', gap: 10 }}>
              {topDrivers.map((driver) => (
                <button key={`${driver.check_id}-${driver.domain || 'tenant'}`} onClick={() => setSelectedCheck(driver)} style={{ background: 'rgba(15,23,42,.72)', border: '1px solid rgba(148,163,184,.12)', borderRadius: 12, color: '#f8fafc', padding: '12px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}>
                  <div style={{ minWidth: 0, textAlign: 'left' }}>
                    <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{driver.name}</div>
                    <div style={{ color: '#93a4bf', fontSize: 12 }}>{driver.category}</div>
                  </div>
                  <ChevronRight size={16} color="#64748b" />
                </button>
              ))}
            </div>
          </Frame>
        </div>

        <Frame style={{ padding: 18, marginBottom: 18 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ fontSize: 12, letterSpacing: '1.6px', textTransform: 'uppercase', color: '#7b8ba7' }}>Benchmark Coverage</div>
            <div style={{ color: '#93a4bf', fontSize: 13 }}>Quieter than risk, but still scan-backed and clickable in the main dashboard.</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
            {benchmarkCards.map((card) => (
              <div key={card.key} style={{ background: 'rgba(15,23,42,.55)', border: '1px solid rgba(148,163,184,.12)', borderRadius: 14, padding: '16px 16px 14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, marginBottom: 10 }}>
                  <div style={{ color: '#f8fafc', fontSize: 15, fontWeight: 600 }}>{card.label}</div>
                  <div style={{ color: benchmarkExecutionColor(card.result), fontWeight: 700, fontSize: 13 }}>{benchmarkExecutionLabel(card.result)}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 8 }}>
                  <div style={{ fontSize: 26, lineHeight: 1, color: '#f8fafc', fontWeight: 700 }}>{card.result?.score ?? '—'}</div>
                  <div style={{ color: '#7b8ba7', fontSize: 12 }}>/100</div>
                </div>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', color: '#93a4bf', fontSize: 12 }}>
                  <span>{card.result?.summary?.failed || 0} fail</span>
                  <span>{card.result?.summary?.warning || 0} warning</span>
                  <span>{card.result?.summary?.passed || 0} pass</span>
                </div>
              </div>
            ))}
          </div>
        </Frame>

        <div style={{ display: 'grid', gridTemplateColumns: '1.45fr .82fr', gap: 18 }}>
          <Frame style={{ padding: '0 0 16px' }}>
            <div style={{ padding: '18px 18px 10px', borderBottom: '1px solid rgba(148,163,184,.12)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 16, marginBottom: 12 }}>
                <div>
                  <div style={{ fontSize: 24, fontWeight: 700, color: '#f8fafc', marginBottom: 4 }}>Operational Findings Queue</div>
                  <div style={{ color: '#93a4bf', fontSize: 13 }}>The table stays dominant so operators can scan, filter, and act fast.</div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {tabs.map((tab) => (
                    <button key={tab.key} onClick={() => setActiveTab(tab.key)} style={{ padding: '8px 12px', borderRadius: 999, border: activeTab === tab.key ? '1px solid rgba(56,189,248,.55)' : '1px solid rgba(148,163,184,.14)', background: activeTab === tab.key ? 'rgba(56,189,248,.12)' : 'rgba(15,23,42,.45)', color: activeTab === tab.key ? '#e0f2fe' : '#93a4bf', fontWeight: 700, cursor: 'pointer' }}>
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 144px 110px 64px', gap: 10, padding: '10px 20px 6px 24px', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', color: '#6b7a91' }}>
              <div>{EXPOSURE_LABELS.finding}</div>
              <div>{EXPOSURE_LABELS.domain}</div>
              <div>Current Value</div>
              <div>Status</div>
            </div>
            <div style={{ padding: '0 18px' }}>
              {sortedFindings.slice(0, 8).map((finding) => (
                <CheckRow key={`${finding.check_id}-${finding.domain || 'tenant'}`} finding={finding} onClick={() => setSelectedCheck(finding)} />
              ))}
            </div>
          </Frame>

          <div style={{ display: 'grid', gap: 18, alignContent: 'start' }}>
            <Frame style={{ padding: 22 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                <Target size={16} color="#38bdf8" />
                <div style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>Next Best Actions</div>
              </div>
              <div style={{ display: 'grid', gap: 10 }}>
                {actionQueue.map((action, index) => {
                  const tone = STATUS_TONE[action.status] || STATUS_TONE.warn
                  return (
                    <button key={`${action.check_id}-${index}`} onClick={() => action.finding && setSelectedCheck(action.finding)} style={{ background: 'rgba(15,23,42,.65)', border: '1px solid rgba(148,163,184,.12)', borderRadius: 14, padding: '14px 14px 12px', cursor: action.finding ? 'pointer' : 'default', textAlign: 'left' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                          <div style={{ width: 24, height: 24, borderRadius: 999, background: 'rgba(56,189,248,.12)', color: '#7dd3fc', fontSize: 12, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{index + 1}</div>
                          <div style={{ color: '#f8fafc', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{action.finding?.name || action.name}</div>
                        </div>
                        <span style={{ padding: '3px 8px', borderRadius: 999, background: tone.bg, color: tone.color, fontSize: 11, fontWeight: 700 }}>{STATUS_LABELS[action.status] || action.status}</span>
                      </div>
                      <div style={{ color: '#93a4bf', fontSize: 12, lineHeight: 1.55 }}>
                        Reduce exposure by up to <span style={{ color: '#f8fafc', fontWeight: 700 }}>{action.max_points || 0} points</span> when this remediation is completed.
                      </div>
                    </button>
                  )
                })}
              </div>
            </Frame>

            <Frame style={{ padding: 22 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <Sparkles size={16} color="#2dd4bf" />
                <div style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>Design Intent</div>
              </div>
              <div style={{ display: 'grid', gap: 10, color: '#93a4bf', fontSize: 13, lineHeight: 1.6 }}>
                <div>Risk is the hero. Posture stays separate. Benchmarks stay visible but quieter.</div>
                <div>The table keeps most of the page because that is where the operations team spends time.</div>
                <div>Color is limited so the dashboard feels more trustworthy and less noisy for executive reviews.</div>
              </div>
            </Frame>
          </div>
        </div>
      </div>

      {selectedCheck && <DetailPanel finding={selectedCheck} onClose={() => setSelectedCheck(null)} />}

      <style>{`@keyframes spin { from { transform: rotate(0) } to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}

function Pill({ tone, text }) {
  return (
    <span style={{ padding: '6px 10px', borderRadius: 999, background: `${tone}1f`, color: tone, border: `1px solid ${tone}30`, fontSize: 12, fontWeight: 700 }}>
      {text}
    </span>
  )
}
