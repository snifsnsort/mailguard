/**
 * DnsPostureLayout.tsx
 *
 * Wraps all /v2/dns-posture/* routes.
 * Renders a shared batch status bar above the page content (Outlet).
 */

import { Outlet } from 'react-router-dom'
import { useDnsPosture } from '../context/DnsPostureContext'
import { useScope } from '../context/ScopeContext'
import { ACTION_LABELS, EXPOSURE_LABELS } from '../../utils/uiLabels'

const statusColor = (s: string) => {
  if (s === 'completed') return '#22c55e'
  if (s === 'failed') return '#ef4444'
  if (s === 'running') return '#0ee'
  if (s === 'queued') return '#94a3b8'
  return '#64748b'
}

const statusLabel = (s: string) => {
  if (s === 'completed') return 'Done'
  if (s === 'failed') return 'Failed'
  if (s === 'running') return 'Running'
  if (s === 'queued') return 'Queued'
  return s
}

function TaskPill({ label, status, deferred = false }: { label: string; status?: string; deferred?: boolean }) {
  const color = deferred ? '#64748b' : statusColor(status ?? 'queued')
  const text = deferred ? 'Coming soon' : statusLabel(status ?? 'queued')
  const isSpinning = !deferred && status === 'running'

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '4px 10px', borderRadius: 20,
      border: `1px solid ${color}33`,
      background: `${color}0d`,
      fontSize: 11,
    }}>
      {isSpinning ? (
        <span style={{
          display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
          border: `1.5px solid ${color}`, borderTopColor: 'transparent',
          animation: 'spin 0.8s linear infinite',
        }} />
      ) : (
        <span style={{
          width: 7, height: 7, borderRadius: '50%',
          background: deferred ? 'transparent' : color,
          border: deferred ? `1.5px dashed ${color}` : 'none',
          display: 'inline-block', flexShrink: 0,
        }} />
      )}
      <span style={{ color: 'var(--text)', opacity: deferred ? 0.5 : 0.9 }}>{label}</span>
      <span style={{ color, fontWeight: 600, opacity: deferred ? 0.6 : 1 }}>{text}</span>
    </div>
  )
}

export default function DnsPostureLayout() {
  const { activeDomain } = useScope()
  const { jobStatus, taskStatuses, jobError, jobDomain, triggerRefresh } = useDnsPosture()

  const isRunning = jobStatus === 'queued' || jobStatus === 'running'
  const isFailed = jobStatus === 'failed'
  const domainDisplay = jobDomain || activeDomain || '—'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <div style={{
        position: 'sticky', top: 0, zIndex: 10,
        background: 'rgba(8,12,18,0.92)', backdropFilter: 'blur(10px)',
        borderBottom: '1px solid var(--border)',
        padding: '10px 28px',
        display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>
            {domainDisplay}
          </span>
          <span style={{
            padding: '2px 8px', borderRadius: 10,
            fontSize: 10, letterSpacing: 0.5, textTransform: 'uppercase',
            background: 'rgba(0,229,255,0.06)', border: '1px solid rgba(0,229,255,0.15)',
            color: 'var(--muted)',
          }}>
            {EXPOSURE_LABELS.surface}
          </span>
        </div>

        <div style={{ width: 1, height: 18, background: 'var(--border)', flexShrink: 0 }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, flexShrink: 0 }}>
          {isRunning && (
            <span style={{
              display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
              border: '1.5px solid var(--accent)', borderTopColor: 'transparent',
              animation: 'spin 0.8s linear infinite',
            }} />
          )}
          <span style={{ color: statusColor(jobStatus === 'idle' ? 'queued' : jobStatus), fontWeight: 600 }}>
            {jobStatus === 'idle' ? 'Waiting' : statusLabel(jobStatus)}
          </span>
          {isFailed && jobError && (
            <span style={{ color: '#ef4444', fontSize: 10, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              — {jobError}
            </span>
          )}
        </div>

        <div style={{ width: 1, height: 18, background: 'var(--border)', flexShrink: 0 }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', flex: 1 }}>
          <TaskPill label="MX Health" status={taskStatuses['mx_health']} />
          <TaskPill label="Authentication" status={taskStatuses['authentication_status']} />
          <TaskPill label="Lookalike Domains" deferred={true} />
        </div>

        <button
          onClick={triggerRefresh}
          disabled={isRunning}
          style={{
            padding: '5px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
            border: '1px solid rgba(0,229,255,0.25)',
            background: isRunning ? 'transparent' : 'rgba(0,229,255,0.06)',
            color: isRunning ? 'var(--muted)' : 'var(--accent)',
            cursor: isRunning ? 'not-allowed' : 'pointer',
            fontFamily: 'var(--font-body)', flexShrink: 0,
            transition: 'all .15s',
          }}
        >
          ↺ {ACTION_LABELS.runScan}
        </button>
      </div>

      <div style={{ flex: 1 }}>
        <Outlet />
      </div>

      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}
