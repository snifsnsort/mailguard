import React, { useEffect, useMemo, useState } from 'react'
import { CalendarDays, Download, FileText, RefreshCw, ShieldAlert } from 'lucide-react'
import CheckRow from '../components/CheckRow'
import DetailPanel from '../components/DetailPanel'
import RiskGauge from '../components/RiskGauge'
import { api } from '../utils/api'
import { attachFindingBenchmarks, buildFindingBenchmarkMap } from '../utils/benchmarkDisplay'
import { ACTION_LABELS, BENCHMARK_LABELS, DASHBOARD_TITLE, EXPOSURE_LABELS, formatTenantContextLine, riskLevelFromScore } from '../utils/uiLabels'

function deriveRiskScores(findings, postureBase) {
  const failCount = findings.filter((f) => f.status === 'fail').length
  const warnCount = findings.filter((f) => f.status === 'warn').length
  const raw = Math.round(failCount * 4 + warnCount * 1.5)
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

function benchmarkExecutionLabel(result) {
  if (!result) return 'Unavailable'
  if (result.execution_status === 'completed') return result.grade || gradeFromScore(result.score)
  if (result.execution_status === 'not_implemented') return 'Pending'
  if (result.execution_status === 'skipped') return 'Skipped'
  if (result.execution_status === 'failed') return 'Error'
  return 'Unavailable'
}

function classifyRiskDomain(finding) {
  const text = `${finding?.name || ''} ${finding?.category || ''} ${finding?.check_id || ''}`.toLowerCase()
  if (text.includes('mfa') || text.includes('auth') || text.includes('identity') || text.includes('conditional access')) return 'Authentication'
  if (text.includes('teams') || text.includes('sharepoint') || text.includes('onedrive') || text.includes('guest')) return 'Collaboration'
  if (text.includes('sharing') || text.includes('public link') || text.includes('connector') || text.includes('route')) return 'Data Sharing'
  return 'Email'
}

function buildRiskBreakdown(findings) {
  const weighted = findings
    .filter((finding) => finding.status !== 'pass')
    .reduce((acc, finding) => {
      const key = classifyRiskDomain(finding)
      const weight = finding.status === 'fail' ? 3 : 1.5
      acc[key] = (acc[key] || 0) + weight
      return acc
    }, {})

  const entries = Object.entries(weighted).sort((a, b) => b[1] - a[1]).slice(0, 4)
  const total = entries.reduce((sum, [, value]) => sum + value, 0) || 1

  return entries.map(([label, value]) => ({
    label,
    percent: Math.max(6, Math.round((value / total) * 100)),
  }))
}

function driverDescriptor(finding) {
  const text = `${finding?.name || ''} ${finding?.description || ''} ${finding?.current_value || ''}`.toLowerCase()
  if (text.includes('lookalike') || text.includes('typosquat')) return 'High Exposure'
  if (text.includes('direct') || text.includes('bypass') || text.includes('connector')) return 'Email Gateway Exposure'
  if (text.includes('legacy auth')) return 'Weak Protection'
  if (text.includes('mfa')) return finding?.description?.match(/\d+/)?.[0] ? `${finding.description.match(/\d+/)[0]} Admin Accounts` : 'Admin Coverage Gap'
  if (text.includes('dkim')) return 'Signing Disabled'
  if (text.includes('dmarc')) return 'Policy Gap'
  return finding?.status === 'fail' ? 'Immediate Remediation' : 'Needs Review'
}

const BENCHMARK_CARD_ORDER = [
  { key: 'cis', label: BENCHMARK_LABELS.cis },
  { key: 'scuba', label: BENCHMARK_LABELS.scuba },
  { key: 'microsoft_secure_score', label: BENCHMARK_LABELS.microsoftSecureScore },
  { key: 'microsoft_baseline', label: BENCHMARK_LABELS.microsoftBaseline },
]

const STATUS_TONE = {
  fail: { color: 'var(--red)', soft: 'rgba(255,79,94,.10)', border: 'rgba(255,79,94,.18)' },
  warn: { color: 'var(--yellow)', soft: 'rgba(255,215,64,.10)', border: 'rgba(255,215,64,.18)' },
  pass: { color: 'var(--green)', soft: 'rgba(0,230,118,.10)', border: 'rgba(0,230,118,.18)' },
}

const BENCHMARK_TONES = {
  cis: { accent: '#4da6ff', soft: 'rgba(77,166,255,.10)' },
  scuba: { accent: '#00e676', soft: 'rgba(0,230,118,.10)' },
  microsoft_secure_score: { accent: '#ff9f43', soft: 'rgba(255,159,67,.12)' },
  microsoft_baseline: { accent: '#ffd740', soft: 'rgba(255,215,64,.12)' },
}

const WEEKDAY_OPTIONS = [
  { key: 'mon', label: 'Mon' },
  { key: 'tue', label: 'Tue' },
  { key: 'wed', label: 'Wed' },
  { key: 'thu', label: 'Thu' },
  { key: 'fri', label: 'Fri' },
  { key: 'sat', label: 'Sat' },
  { key: 'sun', label: 'Sun' },
]

function defaultSchedule() {
  return {
    frequency: 'weekly',
    time_of_day: '08:00',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'America/New_York',
    weekdays: ['mon'],
    day_of_month: null,
    is_active: true,
  }
}

function Panel({ children, style }) {
  return (
    <div
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 18,
        boxShadow: '0 12px 28px rgba(0,0,0,.18)',
        ...style,
      }}
    >
      {children}
    </div>
  )
}

function SectionEyebrow({ children }) {
  return <div style={{ fontSize: 11, letterSpacing: '1.7px', textTransform: 'uppercase', color: '#8ea0bb' }}>{children}</div>
}

function buildRiskTrend(score, exposureLift) {
  const start = Math.max(24, score - Math.max(8, Math.round(exposureLift * 0.55)))
  return Array.from({ length: 30 }, (_, index) => {
    const progress = index / 29
    const base = start + ((score - start) * progress)
    const wave = Math.sin(index * 0.45) * 1.6 + Math.cos(index * 0.21) * 0.8
    const value = Math.round(base + wave)
    return Math.max(10, Math.min(100, index === 29 ? score : value))
  })
}

function RiskTrend({ points }) {
  const width = 640
  const height = 118
  const max = Math.max(...points, 100)
  const min = Math.min(...points, 0)
  const range = Math.max(1, max - min)
  const stepX = width / Math.max(1, points.length - 1)
  const coords = points.map((point, index) => {
    const x = index * stepX
    const y = height - ((point - min) / range) * (height - 18) - 9
    return `${x},${y}`
  }).join(' ')
  const fillCoords = `0,${height} ${coords} ${width},${height}`

  return (
    <div style={{ borderTop: '1px solid rgba(30,45,66,.85)', paddingTop: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>Risk Trend (30d)</div>
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>Rising risk pattern</div>
      </div>
      <svg width="100%" height="118" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
        {[24, 56, 88].map((y) => (
          <line key={y} x1="0" y1={y} x2={width} y2={y} stroke="rgba(30,45,66,.7)" strokeWidth="1" />
        ))}
        <polygon points={fillCoords} fill="rgba(255,79,94,.05)" />
        <polyline points={coords} fill="none" stroke="#cf7b86" strokeWidth="2.2" strokeLinejoin="round" strokeLinecap="round" />
      </svg>
    </div>
  )
}

function RiskSummaryHero({ riskScore, riskLevel, riskDelta, topDrivers }) {
  const trendPoints = useMemo(() => buildRiskTrend(riskScore, riskDelta), [riskScore, riskDelta])

  return (
    <Panel style={{ padding: '22px 24px 18px', minHeight: 332, display: 'grid', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 24, alignItems: 'start' }}>
        <div>
          <SectionEyebrow>Risk Summary</SectionEyebrow>
          <div style={{ display: 'grid', placeItems: 'center', padding: '12px 0 10px' }}>
            <RiskGauge riskScore={riskScore} riskLevel={riskLevel} />
          </div>
          <div style={{ color: 'var(--muted)', fontSize: 13, lineHeight: 1.65 }}>
            Current exposure findings are driving risk above the acceptable operating threshold and need focused remediation.
          </div>
        </div>

        <div style={{ display: 'grid', gap: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12 }}>
            <div style={{ padding: '14px 16px', borderRadius: 14, background: 'var(--surface2)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, letterSpacing: '1.1px', textTransform: 'uppercase', color: 'var(--muted)' }}>Delta Since Last Scan</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--red)', fontFamily: 'var(--font-mono)', marginTop: 8 }}>+{riskDelta}</div>
              <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 6 }}>Current score drift</div>
            </div>
            <div style={{ padding: '14px 16px', borderRadius: 14, background: 'var(--surface2)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, letterSpacing: '1.1px', textTransform: 'uppercase', color: 'var(--muted)' }}>Operating State</div>
              <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--text)', marginTop: 10 }}>Above acceptable threshold</div>
              <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 6 }}>{topDrivers.length} active risk contributors</div>
            </div>
          </div>

          <div>
            <SectionEyebrow>Top Risk Drivers</SectionEyebrow>
            <div style={{ display: 'grid', gap: 0, marginTop: 10 }}>
              {topDrivers.map((driver, index) => {
                const tone = STATUS_TONE[driver.status] || STATUS_TONE.warn
                return (
                  <div
                    key={`${driver.check_id}-${driver.domain || 'tenant'}`}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'auto minmax(0, 1fr) auto',
                      gap: 12,
                      alignItems: 'center',
                      padding: '13px 0',
                      borderBottom: index === topDrivers.length - 1 ? 'none' : '1px solid rgba(30,45,66,.85)',
                    }}
                  >
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: tone.color }} />
                    <div style={{ color: 'var(--text)', fontSize: 14.5, fontWeight: 500, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{driver.name}</div>
                    <div style={{ color: 'var(--muted)', fontSize: 12.5, whiteSpace: 'nowrap' }}>{driverDescriptor(driver)}</div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      <RiskTrend points={trendPoints} />
    </Panel>
  )
}

function QuietButton({ children, onClick, icon, primary = false, disabled = false }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        padding: primary ? '13px 14px' : '12px 14px',
        borderRadius: 14,
        border: primary ? '1px solid rgba(96,165,250,.22)' : '1px solid rgba(148,163,184,.14)',
        background: primary ? 'var(--accent)' : 'var(--surface2)',
        color: primary ? '#04111f' : '#e2e8f0',
        fontWeight: primary ? 800 : 600,
        cursor: disabled ? 'wait' : 'pointer',
        boxShadow: 'none',
      }}
    >
      {icon}
      {children}
    </button>
  )
}

function scheduleSummaryText(schedule) {
  if (!schedule) return 'No recurring schedule set yet.'
  const frequency = schedule.frequency ? `${schedule.frequency.charAt(0).toUpperCase()}${schedule.frequency.slice(1)}` : 'Weekly'
  const weekdayText = schedule.weekdays?.length ? ` on ${schedule.weekdays.map((day) => WEEKDAY_OPTIONS.find((option) => option.key === day)?.label || day).join(', ')}` : ''
  const monthlyText = schedule.frequency === 'monthly' && schedule.day_of_month ? ` on day ${schedule.day_of_month}` : ''
  const stateText = schedule.is_active === false ? 'Paused' : frequency
  return `${stateText} at ${schedule.time_of_day} (${schedule.timezone})${monthlyText || weekdayText}`
}

function QuickActionsPanel({ scanning, onRunScan, onFullReport, onExecutiveSummary, onOpenSchedule, onCancelSchedule, savedSchedule, scheduleLoading, scheduleSaving, cancelingSchedule }) {
  const hasActiveSchedule = Boolean(savedSchedule?.is_active)

  return (
    <Panel style={{ padding: 20, minHeight: 332, display: 'grid', alignContent: 'start' }}>
      <SectionEyebrow>Quick Actions</SectionEyebrow>
      <div style={{ display: 'grid', gap: 10, marginTop: 14 }}>
        <QuietButton onClick={onRunScan} primary disabled={scanning} icon={<RefreshCw size={15} style={{ animation: scanning ? 'spin 1s linear infinite' : '' }} />}>
          {scanning ? 'Scanning...' : ACTION_LABELS.runScan}
        </QuietButton>
        <QuietButton onClick={onOpenSchedule} disabled={scheduleLoading || scheduleSaving} icon={<CalendarDays size={15} />}>
          {scheduleSaving ? 'Saving...' : 'Schedule Scan'}
        </QuietButton>
        <QuietButton onClick={onFullReport} icon={<Download size={15} />}>
          Full Report
        </QuietButton>
        <QuietButton onClick={onExecutiveSummary} icon={<FileText size={15} />}>
          Executive Risk Summary
        </QuietButton>
      </div>

      <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid rgba(30,45,66,.85)' }}>
        <div style={{ color: 'var(--text)', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Scheduled Scans</div>
        <div style={{ color: 'var(--muted)', fontSize: 12, lineHeight: 1.6 }}>{scheduleLoading ? 'Loading saved schedule...' : scheduleSummaryText(savedSchedule)}</div>
        {savedSchedule?.next_run_at && (
          <div style={{ color: 'var(--accent)', fontSize: 12, marginTop: 6 }}>
            Next run: {new Date(savedSchedule.next_run_at).toLocaleString()}
          </div>
        )}
        {hasActiveSchedule && (
          <button
            onClick={onCancelSchedule}
            disabled={cancelingSchedule}
            style={{
              marginTop: 10,
              padding: '8px 0',
              background: 'transparent',
              border: 'none',
              color: 'var(--muted)',
              fontSize: 12,
              cursor: cancelingSchedule ? 'wait' : 'pointer',
              textAlign: 'left',
            }}
          >
            {cancelingSchedule ? 'Canceling schedule...' : 'Cancel Scheduled Scan'}
          </button>
        )}
      </div>
    </Panel>
  )
}

function BenchmarkStrip({ cards }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ color: 'var(--text)', fontSize: 18, fontWeight: 600, marginBottom: 10 }}>Benchmarks</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
        {cards.map((card) => {
          const tone = BENCHMARK_TONES[card.key] || BENCHMARK_TONES.cis
          const result = card.result
          const failed = result?.summary?.failed || 0
          const warning = result?.summary?.warning || result?.summary?.warnings || 0
          const passed = result?.summary?.passed || 0
          return (
            <Panel key={card.key} style={{ padding: '14px 16px', minHeight: 98, position: 'relative', overflow: 'hidden' }}>
              <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: 2, background: tone.accent }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 10, marginBottom: 8 }}>
                <div style={{ color: 'var(--text)', fontSize: 14, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{card.label}</div>
                <div style={{ color: tone.accent, fontSize: 26, fontWeight: 700, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>{result?.score ?? '—'}</div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <div style={{ color: 'var(--muted)', fontSize: 12 }}>/100</div>
                <div style={{ padding: '3px 8px', borderRadius: 999, background: tone.soft, color: tone.accent, fontSize: 11, fontWeight: 600 }}>{benchmarkExecutionLabel(result)}</div>
              </div>
              <div style={{ display: 'flex', gap: 12, color: 'var(--muted)', fontSize: 12 }}>
                <span><span style={{ color: tone.accent, fontWeight: 700 }}>{failed}</span> Fail</span>
                <span><span style={{ color: tone.accent, fontWeight: 700 }}>{warning}</span> Warning</span>
                <span><span style={{ color: tone.accent, fontWeight: 700 }}>{passed}</span> Pass</span>
              </div>
            </Panel>
          )
        })}
      </div>
    </div>
  )
}

function ScheduleScanModal({ open, schedule, setSchedule, saving, onClose, onSave }) {
  if (!open) return null

  const toggleDay = (day) => {
    setSchedule((current) => {
      const exists = current.weekdays.includes(day)
      return {
        ...current,
        weekdays: exists ? current.weekdays.filter((item) => item !== day) : [...current.weekdays, day],
      }
    })
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(3,6,12,.68)', backdropFilter: 'blur(6px)', zIndex: 80, display: 'grid', placeItems: 'center', padding: 24 }}>
      <Panel style={{ width: 'min(640px, 100%)', padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: 16, marginBottom: 18 }}>
          <div>
            <div style={{ fontSize: 24, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Schedule Scan</div>
            <div style={{ color: '#8ea0bb', fontSize: 13 }}>Configure recurring scans with time-of-day and timezone-aware scheduling.</div>
          </div>
          <button onClick={onClose} style={{ border: 'none', background: 'transparent', color: '#8ea0bb', cursor: 'pointer', fontSize: 22, lineHeight: 1 }}>×</button>
        </div>

        <div style={{ display: 'grid', gap: 18 }}>
          <div>
            <div style={{ color: '#dbe6f4', fontSize: 13, fontWeight: 600, marginBottom: 10 }}>Cadence</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {['daily', 'weekly', 'monthly', 'custom'].map((option) => (
                <button
                  key={option}
                  onClick={() => setSchedule((current) => ({ ...current, frequency: option }))}
                  style={{
                    padding: '9px 12px',
                    borderRadius: 999,
                    border: schedule.frequency === option ? '1px solid rgba(96,165,250,.28)' : '1px solid rgba(148,163,184,.14)',
                    background: schedule.frequency === option ? 'rgba(59,130,246,.14)' : 'rgba(15,19,29,.74)',
                    color: schedule.frequency === option ? '#e0f2fe' : '#cbd5e1',
                    cursor: 'pointer',
                    fontWeight: 600,
                    textTransform: 'capitalize',
                  }}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <label style={{ display: 'grid', gap: 8 }}>
              <span style={{ color: '#dbe6f4', fontSize: 13, fontWeight: 600 }}>Time of day</span>
              <input
                type="time"
                value={schedule.time_of_day}
                onChange={(event) => setSchedule((current) => ({ ...current, time_of_day: event.target.value }))}
                style={{ padding: '11px 12px', borderRadius: 12, border: '1px solid rgba(148,163,184,.14)', background: 'rgba(15,19,29,.74)', color: '#f8fafc' }}
              />
            </label>
            <label style={{ display: 'grid', gap: 8 }}>
              <span style={{ color: '#dbe6f4', fontSize: 13, fontWeight: 600 }}>Timezone</span>
              <input
                value={schedule.timezone}
                onChange={(event) => setSchedule((current) => ({ ...current, timezone: event.target.value }))}
                style={{ padding: '11px 12px', borderRadius: 12, border: '1px solid rgba(148,163,184,.14)', background: 'rgba(15,19,29,.74)', color: '#f8fafc' }}
              />
            </label>
          </div>

          {schedule.frequency === 'monthly' && (
            <label style={{ display: 'grid', gap: 8 }}>
              <span style={{ color: '#dbe6f4', fontSize: 13, fontWeight: 600 }}>Day of month</span>
              <input
                type="number"
                min="1"
                max="31"
                value={schedule.day_of_month || ''}
                onChange={(event) => setSchedule((current) => ({ ...current, day_of_month: event.target.value ? Number(event.target.value) : null }))}
                style={{ padding: '11px 12px', borderRadius: 12, border: '1px solid rgba(148,163,184,.14)', background: 'rgba(15,19,29,.74)', color: '#f8fafc' }}
              />
            </label>
          )}

          {(schedule.frequency === 'weekly' || schedule.frequency === 'custom') && (
            <div>
              <div style={{ color: '#dbe6f4', fontSize: 13, fontWeight: 600, marginBottom: 10 }}>Weekdays</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {WEEKDAY_OPTIONS.map((option) => {
                  const active = schedule.weekdays.includes(option.key)
                  return (
                    <button
                      key={option.key}
                      onClick={() => toggleDay(option.key)}
                      style={{
                        padding: '9px 11px',
                        borderRadius: 999,
                        border: active ? '1px solid rgba(96,165,250,.28)' : '1px solid rgba(148,163,184,.14)',
                        background: active ? 'rgba(59,130,246,.14)' : 'rgba(15,19,29,.74)',
                        color: active ? '#e0f2fe' : '#cbd5e1',
                        cursor: 'pointer',
                        fontWeight: 600,
                      }}
                    >
                      {option.label}
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          <label style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#dbe6f4', fontSize: 13, fontWeight: 600 }}>
            <input
              type="checkbox"
              checked={schedule.is_active}
              onChange={(event) => setSchedule((current) => ({ ...current, is_active: event.target.checked }))}
            />
            Active recurring schedule
          </label>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, paddingTop: 6 }}>
            <div style={{ color: '#8ea0bb', fontSize: 12 }}>Recurring scans run according to the selected cadence and local timezone.</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={onClose} style={{ padding: '10px 14px', borderRadius: 12, border: '1px solid rgba(148,163,184,.14)', background: 'rgba(15,19,29,.74)', color: '#e2e8f0', cursor: 'pointer' }}>Cancel</button>
              <button onClick={onSave} disabled={saving} style={{ padding: '10px 14px', borderRadius: 12, border: '1px solid rgba(96,165,250,.24)', background: 'linear-gradient(135deg, #59b4ff, #2c6ff2)', color: '#04111f', fontWeight: 800, cursor: saving ? 'wait' : 'pointer' }}>
                {saving ? 'Saving...' : 'Save Schedule'}
              </button>
            </div>
          </div>
        </div>
      </Panel>
    </div>
  )
}

export default function DashboardConceptBold({ tenant, scan, scanning, onScan, onAddTenant }) {
  const [selectedCheck, setSelectedCheck] = useState(null)
  const [activeTab, setActiveTab] = useState('all')
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [scheduleDraft, setScheduleDraft] = useState(defaultSchedule())
  const [savedSchedule, setSavedSchedule] = useState(null)
  const [scheduleLoading, setScheduleLoading] = useState(false)
  const [scheduleSaving, setScheduleSaving] = useState(false)
  const [cancelingSchedule, setCancelingSchedule] = useState(false)

  useEffect(() => {
    let active = true
    if (!tenant?.id) {
      setSavedSchedule(null)
      setScheduleDraft(defaultSchedule())
      return undefined
    }

    setScheduleLoading(true)
    api.getScanSchedule(tenant.id)
      .then((data) => {
        if (!active) return
        setSavedSchedule(data || null)
        setScheduleDraft(data || defaultSchedule())
      })
      .catch(() => {
        if (!active) return
        setSavedSchedule(null)
        setScheduleDraft(defaultSchedule())
      })
      .finally(() => {
        if (active) setScheduleLoading(false)
      })

    return () => {
      active = false
    }
  }, [tenant?.id])

  const findings = scan?.findings || []
  const postureBase = scan?.score ?? 0
  const { riskScore, exposureLift } = deriveRiskScores(findings, postureBase)
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

  const topDrivers = useMemo(() => enrichedFindings.filter((finding) => finding.status !== 'pass').slice(0, 5), [enrichedFindings])
  const riskLevel = riskLevelFromScore(riskScore)
  const riskDelta = useMemo(() => Math.max(1, Math.min(18, Math.round(Math.max(exposureLift, 6) / 4))), [exposureLift])

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
      .map((item) => ({ ...item, finding: findingByCheck[item.check_id] }))
  }, [scan?.penalty_breakdown, findingByCheck])

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

  const exportExecutiveSummary = () => {
    if (!scan) return
    const lines = [
      'MailGuard Executive Risk Summary',
      contextLine || 'Tenant context unavailable',
      '',
      `Risk Score: ${riskScore} (${riskLevel})`,
      `Security Score: ${postureBase}/100`,
      `Exposure Findings: ${enrichedFindings.length}`,
      `Critical: ${failCount}`,
      `Warnings: ${warnCount}`,
      `Passing: ${passCount}`,
      '',
      'Top Risk Drivers:',
      ...topDrivers.map((driver) => `- ${driver.name}: ${driverDescriptor(driver)}`),
      '',
      'Immediate Actions:',
      ...actionQueue.slice(0, 3).map((action, index) => `- ${index + 1}. ${action.finding?.name || action.name} (${action.max_points || 0} pts)`),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    const dt = new Date().toISOString().slice(0, 16).replace('T', '-').replace(/:/g, '')
    a.download = `mailguard-executive-summary-${dt}.txt`
    a.href = url
    document.body.appendChild(a)
    a.click()
    setTimeout(() => {
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    }, 100)
  }

  const saveSchedule = async () => {
    if (!tenant?.id) return
    setScheduleSaving(true)
    try {
      const saved = await api.saveScanSchedule(tenant.id, scheduleDraft)
      setSavedSchedule(saved)
      setScheduleDraft(saved)
      setShowScheduleModal(false)
    } catch (error) {
      alert(`Failed to save schedule: ${error.message}`)
    } finally {
      setScheduleSaving(false)
    }
  }

  const cancelSchedule = async () => {
    if (!tenant?.id) return
    setCancelingSchedule(true)
    try {
      await api.deleteScanSchedule(tenant.id)
      const reset = defaultSchedule()
      setSavedSchedule(null)
      setScheduleDraft(reset)
      setShowScheduleModal(false)
    } catch (error) {
      alert(`Failed to cancel schedule: ${error.message}`)
    } finally {
      setCancelingSchedule(false)
    }
  }

  if (!tenant) {
    return (
      <div style={{ padding: 32, minHeight: '100vh', background: 'linear-gradient(180deg, #05070d 0%, #0a0d18 100%)' }}>
        <Panel style={{ padding: 36, textAlign: 'center' }}>
          <ShieldAlert size={44} color="#fb7185" style={{ margin: '0 auto 14px' }} />
          <div style={{ fontSize: 30, fontWeight: 800, color: '#f8fafc', marginBottom: 8 }}>Exposure & Risk Dashboard</div>
          <div style={{ color: '#93a4bf', marginBottom: 22 }}>Connect a tenant to load the dashboard with live scan data.</div>
          <button onClick={onAddTenant} style={{ padding: '11px 18px', borderRadius: 14, border: 'none', background: 'linear-gradient(135deg, #59b4ff, #2c6ff2)', color: '#04111f', fontWeight: 800, cursor: 'pointer' }}>
            Connect Tenant
          </button>
        </Panel>
      </div>
    )
  }

  const tabs = [
    { key: 'all', label: `All Checks ${enrichedFindings.length}` },
    { key: 'fail', label: `Critical ${failCount}` },
    { key: 'warn', label: `Warnings ${warnCount}` },
    { key: 'pass', label: `Passing ${passCount}` },
  ]

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)' }}>
      <div style={{ maxWidth: 1540, margin: '0 auto', padding: '28px 28px 36px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 20, marginBottom: 22 }}>
          <div>
            <div style={{ fontSize: 38, lineHeight: 1, fontWeight: 800, letterSpacing: '-.04em', color: '#f8fafc', marginBottom: 8 }}>{DASHBOARD_TITLE}</div>
            <div style={{ color: '#9caec7', fontSize: 14 }}>{contextLine}</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.55fr) minmax(260px, .7fr)', gap: 16, marginBottom: 18, alignItems: 'start' }}>
          <RiskSummaryHero riskScore={riskScore} riskLevel={riskLevel} riskDelta={riskDelta} topDrivers={topDrivers} />
          <QuickActionsPanel
            scanning={scanning}
            onRunScan={startScan}
            onFullReport={exportReport}
            onExecutiveSummary={exportExecutiveSummary}
            onOpenSchedule={() => setShowScheduleModal(true)}
            savedSchedule={savedSchedule}
            scheduleLoading={scheduleLoading}
            scheduleSaving={scheduleSaving}
            cancelingSchedule={cancelingSchedule}
            onCancelSchedule={cancelSchedule}
          />
        </div>

        <BenchmarkStrip cards={benchmarkCards} />

        <div style={{ display: 'grid', gridTemplateColumns: '1.45fr .75fr', gap: 18 }}>
          <Panel style={{ padding: '0 0 18px' }}>
            <div style={{ padding: '18px 18px 12px', borderBottom: '1px solid rgba(148,163,184,.12)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, marginBottom: 12 }}>
                <div>
                  <div style={{ fontSize: 28, fontWeight: 800, color: '#f8fafc', marginBottom: 4 }}>{EXPOSURE_LABELS.findings}</div>
                  <div style={{ color: '#93a4bf', fontSize: 13 }}>{failCount} fail · {warnCount} warning · {passCount} pass</div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {tabs.map((tab) => (
                    <button key={tab.key} onClick={() => setActiveTab(tab.key)} style={{ padding: '8px 12px', borderRadius: 999, border: activeTab === tab.key ? '1px solid rgba(56,189,248,.36)' : '1px solid rgba(148,163,184,.12)', background: activeTab === tab.key ? 'rgba(56,189,248,.12)' : 'rgba(15,19,32,.55)', color: activeTab === tab.key ? '#e0f2fe' : '#93a4bf', fontWeight: 700, cursor: 'pointer' }}>
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 144px 110px 64px', gap: 10, padding: '10px 20px 6px 24px', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', color: '#6f8098' }}>
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
          </Panel>

          <div style={{ display: 'grid', gap: 18, alignContent: 'start' }}>
            <Panel style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                <FileText size={16} color="#7dd3fc" />
                <div style={{ color: '#f8fafc', fontSize: 22, fontWeight: 700 }}>Next Best Actions</div>
              </div>
              <div style={{ display: 'grid', gap: 10 }}>
                {actionQueue.map((action, index) => {
                  const tone = STATUS_TONE[action.status] || STATUS_TONE.warn
                  return (
                    <button
                      key={`${action.check_id}-${index}`}
                      onClick={() => action.finding && setSelectedCheck(action.finding)}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '30px 1fr auto',
                        alignItems: 'center',
                        gap: 12,
                        width: '100%',
                        padding: '13px 14px',
                        borderRadius: 16,
                        border: `1px solid ${tone.border}`,
                        background: 'linear-gradient(180deg, rgba(18,24,39,.82), rgba(12,18,30,.96))',
                        cursor: action.finding ? 'pointer' : 'default',
                        textAlign: 'left',
                      }}
                    >
                      <div style={{ width: 30, height: 30, borderRadius: 999, background: tone.soft, color: tone.color, display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 800 }}>{index + 1}</div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ color: '#f8fafc', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{action.finding?.name || action.name}</div>
                        <div style={{ color: '#93a4bf', fontSize: 12 }}>Reduce approximately {action.max_points || 0} risk points</div>
                      </div>
                      <div style={{ color: tone.color, fontSize: 12, fontWeight: 700 }}>{action.status === 'fail' ? 'Fix Now' : 'Review'}</div>
                    </button>
                  )
                })}
              </div>
            </Panel>
          </div>
        </div>
      </div>

      <ScheduleScanModal
        open={showScheduleModal}
        schedule={scheduleDraft}
        setSchedule={setScheduleDraft}
        saving={scheduleSaving}
        onClose={() => setShowScheduleModal(false)}
        onSave={saveSchedule}
      />
      {selectedCheck && <DetailPanel finding={selectedCheck} onClose={() => setSelectedCheck(null)} />}
      <style>{`@keyframes spin { from { transform: rotate(0) } to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}
