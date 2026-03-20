/**
 * RiskPanel.jsx
 *
 * Inline expandable risk breakdown panel.
 * Renders below the header strip, pushing the findings table down.
 * NOT a modal. NOT a sidebar.
 */

import { Shield } from 'lucide-react'
import { ACTION_LABELS, EXPOSURE_LABELS, riskLevelFromScore } from '../utils/uiLabels'

function severityOf(f) {
  if (f.status === 'fail') return 'Critical Risk'
  if (f.status === 'warn') return 'High Risk'
  return 'Moderate Risk'
}

function severityRank(s) {
  if (s === 'Critical Risk') return 0
  if (s === 'High Risk') return 1
  return 2
}

function riskStateColor(state) {
  if (state === 'Critical Risk') return '#ff4f5e'
  if (state === 'High Risk') return '#ff7a45'
  if (state === 'Moderate Risk') return '#ffd740'
  return '#8ba4be'
}

function buildDrivers(findings) {
  return findings
    .filter(f => f.status !== 'pass')
    .map(f => ({ id: f.check_id, name: f.name, severity: severityOf(f) }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 7)
}

function buildExposureBullets(findings) {
  const bullets = []
  if (findings.some(f => f.status === 'fail' && f.name?.toLowerCase().includes('dkim')))
    bullets.push('DKIM signing is not configured on the primary domain')
  if (findings.some(f => f.status === 'fail' && f.name?.toLowerCase().includes('dmarc')))
    bullets.push('DMARC enforcement is not enabled for spoofing protection')
  if (findings.some(f => (f.status === 'fail' || f.status === 'warn') && f.name?.toLowerCase().includes('lookalike')))
    bullets.push('Lookalike domains are creating external exposure')
  if (findings.some(f => f.status === 'fail' && f.name?.toLowerCase().includes('seg')))
    bullets.push('Direct-to-EOP routing is bypassing secure mail inspection')
  if (findings.some(f => f.status === 'fail' && f.name?.toLowerCase().includes('mfa')))
    bullets.push('Admin authentication is missing stronger access protection')
  if (bullets.length === 0 && findings.filter(f => f.status === 'fail').length > 0)
    bullets.push('Multiple exposure signals are increasing the current risk score')
  return bullets.slice(0, 4)
}

const SEV_COLOR = {
  'Critical Risk': '#ff4f5e',
  'High Risk': '#ff7a45',
  'Moderate Risk': '#4da6ff',
}

const SEV_RAIL = {
  'Critical Risk': '#ff4f5e',
  'High Risk': '#ff7a45',
  'Moderate Risk': '#4da6ff',
}

function DriverRow({ driver, onClick }) {
  const color = SEV_COLOR[driver.severity]
  const rail = SEV_RAIL[driver.severity]

  return (
    <div
      onClick={() => onClick(driver.id)}
      title={`Jump to ${EXPOSURE_LABELS.finding.toLowerCase()}: ${driver.name}`}
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 8,
        background: '#0e1520', border: '1px solid #1e2d42',
        borderLeft: `3px solid ${rail}`,
        borderRadius: '0 6px 6px 0',
        padding: '7px 10px', cursor: 'pointer',
        transition: 'background .12s',
      }}
      onMouseOver={e => { e.currentTarget.style.background = '#141c2b' }}
      onMouseOut={e => { e.currentTarget.style.background = '#0e1520' }}
    >
      <span style={{ fontSize: 9, fontWeight: 700, color, letterSpacing: '.3px', flexShrink: 0, minWidth: 74, marginTop: 1 }}>
        {driver.severity.toUpperCase()}
      </span>
      <span style={{ fontSize: 10, color: '#8ba4be', flex: 1, lineHeight: 1.35, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
        {driver.name}
      </span>
      <span style={{ fontSize: 10, color: '#5a7290', flexShrink: 0 }}>↗</span>
    </div>
  )
}

function EqBlock({ label, value, hint, valueColor }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '10px 0', flex: 1 }}>
      <div style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.5px', fontWeight: 700, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', color: valueColor, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 8, color: '#5a7290', marginTop: 2 }}>{hint}</div>
    </div>
  )
}

export default function RiskPanel({ riskScore, postureBase, exposureLift, riskState, findings, lastScan, onDriverClick }) {
  const drivers = buildDrivers(findings)
  const exposureBullets = buildExposureBullets(findings)
  const riskLevel = riskLevelFromScore(riskScore)
  const stateColor = riskStateColor(riskState)
  const criticalDriverCount = drivers.filter(d => d.severity === 'Critical Risk').length
  const lastScanStr = lastScan
    ? new Date(lastScan).toLocaleString('en-CA', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '—'

  const postureWidth = `${Math.round(postureBase)}%`
  const exposureWidth = `${Math.round(Math.min(exposureLift, 100 - postureBase))}%`
  const markerLeft = `${Math.round(riskScore)}%`

  return (
    <div style={{ background: '#080c12', borderBottom: '2px solid #1e2d42' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '4px 16px',
        background: 'rgba(255,79,94,.04)',
        borderBottom: '1px solid rgba(255,79,94,.12)',
      }}>
        <span style={{ fontSize: 8, color: '#8b4a42', letterSpacing: '.6px', fontWeight: 700 }}>
          ▲ RISK CALCULATION — EXPANDED
        </span>
        <span style={{ fontSize: 9, color: '#5a7290', marginLeft: 'auto' }}>
          {`click "${ACTION_LABELS.viewRiskBreakdown}" to collapse ▲`}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '152px 1fr 216px', gap: 0 }}>
        <div style={{
          padding: '16px 14px', borderRight: '1px solid #1e2d42',
          display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 3,
        }}>
          <div style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.6px', fontWeight: 700 }}>RISK SCORE</div>
          <div style={{ fontSize: 46, fontWeight: 700, color: '#ff4f5e', fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
            {Math.round(riskScore)}
          </div>
          <div style={{ fontSize: 8, color: '#8b4a42', letterSpacing: '.6px', fontWeight: 700, marginTop: 2 }}>RISK LEVEL</div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#ff4f5e' }}>{riskLevel}</div>
          <div style={{ fontSize: 8, color: '#8b4a42', letterSpacing: '.6px', fontWeight: 700, marginTop: 2 }}>RISK STATE</div>
          <div style={{ fontSize: 10, fontWeight: 700, color: stateColor, marginTop: 1 }}>{riskState}</div>
          <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid #1e2d42' }}>
            <div style={{ fontSize: 9, color: '#5a7290', lineHeight: 1.5 }}>Last scan<br />{lastScanStr}</div>
            {criticalDriverCount > 0 && (
              <div style={{ fontSize: 9, color: '#ff4f5e', marginTop: 4, fontWeight: 700 }}>
                {criticalDriverCount} critical risk driver{criticalDriverCount !== 1 ? 's' : ''} active
              </div>
            )}
          </div>
        </div>

        <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <div style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.5px', fontWeight: 700, marginBottom: 5 }}>
              RISK CALCULATION
            </div>
            <div style={{
              display: 'flex', alignItems: 'stretch',
              background: '#0e1520', border: '1px solid #1e2d42', borderRadius: 7, overflow: 'hidden',
            }}>
              <EqBlock label="SECURITY SCORE" value={Math.round(postureBase)} hint="Posture only" valueColor="#4da6ff" />
              <div style={{ fontSize: 16, color: '#5a7290', fontWeight: 700, padding: '0 6px', alignSelf: 'center', flexShrink: 0 }}>+</div>
              <EqBlock label={EXPOSURE_LABELS.signals.toUpperCase()} value={`+${Math.round(exposureLift)}`} hint={EXPOSURE_LABELS.external} valueColor="#ff4f5e" />
              <div style={{ fontSize: 16, color: '#5a7290', fontWeight: 700, padding: '0 6px', alignSelf: 'center', flexShrink: 0 }}>=</div>
              <div style={{
                background: '#100808', borderLeft: '1px solid #1e2d42',
                padding: '10px 14px', display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <div style={{ fontSize: 8, color: '#8b4a42', letterSpacing: '.5px', fontWeight: 700, marginBottom: 3 }}>RISK SCORE</div>
                <div style={{ fontSize: 24, fontWeight: 700, color: '#ff4f5e', fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
                  {Math.round(riskScore)}
                </div>
                <div style={{ fontSize: 8, color: '#8b4a42', marginTop: 1 }}>/100</div>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.5px', fontWeight: 700 }}>RISK CALCULATION</span>
              <span style={{ fontSize: 8, color: '#5a7290' }}>LOW ——————————————— CRITICAL</span>
            </div>
            <div style={{ display: 'flex', height: 9, borderRadius: 5, overflow: 'hidden', background: '#0e1520', gap: 2 }}>
              <div style={{ width: postureWidth, background: '#185fa5', borderRadius: '5px 0 0 5px', flexShrink: 0 }} />
              <div style={{ width: exposureWidth, background: '#ff4f5e', flexShrink: 0 }} />
              <div style={{ flex: 1, background: '#141c2b' }} />
            </div>
            <div style={{ position: 'relative', height: 14 }}>
              <div style={{ position: 'absolute', left: markerLeft, transform: 'translateX(-50%)', fontSize: 8, color: '#ff4f5e', fontWeight: 700, top: 0 }}>
                {Math.round(riskScore)}
              </div>
              <div style={{ position: 'absolute', left: markerLeft, transform: 'translateX(-50%)', width: 1, height: 6, background: '#ff4f5e', top: 8 }} />
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              {[
                { color: '#185fa5', label: 'Security Score' },
                { color: '#ff4f5e', label: EXPOSURE_LABELS.signals },
              ].map(l => (
                <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: '#8ba4be' }}>
                  <div style={{ width: 8, height: 3, borderRadius: 2, background: l.color, flexShrink: 0 }} />
                  {l.label}
                </div>
              ))}
            </div>
          </div>

          <div style={{
            background: '#100d0d', border: '1px solid rgba(255,79,94,.2)',
            borderRadius: 6, padding: '9px 11px', display: 'flex', gap: 9,
          }}>
            <div style={{
              width: 26, height: 26, borderRadius: '50%',
              background: 'rgba(255,79,94,.1)', border: '1px solid rgba(255,79,94,.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1,
            }}>
              <Shield size={12} color="#ff4f5e" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.5px', fontWeight: 700 }}>{EXPOSURE_LABELS.external.toUpperCase()}</span>
                <span style={{
                  fontSize: 8, fontWeight: 700, color: '#ba7517',
                  background: 'rgba(186,117,23,.1)', border: '1px solid rgba(186,117,23,.25)',
                  padding: '1px 5px', borderRadius: 3,
                }}>ACTIVE</span>
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#ff4f5e' }}>{EXPOSURE_LABELS.signals}</div>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                {exposureBullets.map((b, i) => (
                  <li key={i} style={{ fontSize: 10, color: '#8b7060', display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#ff4f5e', opacity: .6, flexShrink: 0 }} />
                    {b}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        <div style={{
          padding: '14px 14px', borderLeft: '1px solid #1e2d42',
          display: 'flex', flexDirection: 'column', gap: 6,
        }}>
          <div style={{ fontSize: 8, color: '#5a7290', letterSpacing: '.5px', fontWeight: 700, marginBottom: 2 }}>
            TOP RISK DRIVERS
          </div>
          {drivers.length === 0 && (
            <div style={{ fontSize: 11, color: '#5a7290', padding: '12px 0' }}>No active risk drivers</div>
          )}
          {drivers.map(d => (
            <DriverRow key={d.id} driver={d} onClick={onDriverClick} />
          ))}
        </div>
      </div>
    </div>
  )
}


