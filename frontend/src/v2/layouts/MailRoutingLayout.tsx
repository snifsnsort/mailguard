/**
 * MailRoutingLayout.tsx
 *
 * Wraps all /v2/mail-routing/* routes.
 * Renders a shared status bar showing both family batch statuses.
 */

import { Outlet } from 'react-router-dom'
import { useMailRouting } from '../context/MailRoutingContext'
import { useScope } from '../context/ScopeContext'
import { ACTION_LABELS } from '../../utils/uiLabels'

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
  if (s === 'idle') return 'Waiting'
  return s
}

function TaskPill({ label, status, deferred = false }: { label: string; status?: string; deferred?: boolean }) {
  const color = deferred ? '#64748b' : statusColor(status ?? 'queued')
  const text = deferred ? 'Deferred' : statusLabel(status ?? 'queued')
  const spin = !deferred && status === 'running'

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '3px 9px', borderRadius: 20, border: `1px solid ${color}33`, background: `${color}0d`, fontSize: 10 }}>
      {spin
        ? <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', border: `1.5px solid ${color}`, borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
        : <span style={{ width: 6, height: 6, borderRadius: '50%', background: deferred ? 'transparent' : color, border: deferred ? `1.5px dashed ${color}` : 'none', display: 'inline-block', flexShrink: 0 }} />
      }
      <span style={{ color: 'var(--text)', opacity: deferred ? 0.45 : 0.9 }}>{label}</span>
      <span style={{ color, fontWeight: 600, opacity: deferred ? 0.5 : 1 }}>{text}</span>
    </div>
  )
}

function FamilyBar({ label, state }: { label: string; state: { jobStatus: string; taskStatuses: Record<string, string> } }) {
  const isRunning = state.jobStatus === 'queued' || state.jobStatus === 'running'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <span style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.8, flexShrink: 0 }}>{label}</span>
      {isRunning && <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', border: `1.5px solid ${statusColor(state.jobStatus)}`, borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />}
      <span style={{ fontSize: 10, color: statusColor(state.jobStatus), fontWeight: 600 }}>{statusLabel(state.jobStatus)}</span>
    </div>
  )
}

export default function MailRoutingLayout() {
  const { activeDomain } = useScope()
  const { routing, tls, jobDomain, triggerRefresh } = useMailRouting()

  const isRunning = ['queued','running'].includes(routing.jobStatus) || ['queued','running'].includes(tls.jobStatus)
  const domainDisplay = jobDomain || activeDomain || '—'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <div style={{ position: 'sticky', top: 0, zIndex: 10, background: 'rgba(8,12,18,0.92)', backdropFilter: 'blur(10px)', borderBottom: '1px solid var(--border)', padding: '10px 28px', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>{domainDisplay}</span>
          <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, letterSpacing: 0.5, textTransform: 'uppercase', background: 'rgba(0,229,255,0.06)', border: '1px solid rgba(0,229,255,0.15)', color: 'var(--muted)' }}>Change & Drift</span>
        </div>

        <div style={{ width: 1, height: 18, background: 'var(--border)', flexShrink: 0 }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <FamilyBar label="Routing Topology" state={routing} />
          <TaskPill label="Inbound Path" status={routing.taskStatuses['inbound_path_mapping']} />
          <TaskPill label="Connectors" status={routing.taskStatuses['connector_posture']} />
          <TaskPill label="Direct Send" status={routing.taskStatuses['direct_send_check']} />
        </div>

        <div style={{ width: 1, height: 18, background: 'var(--border)', flexShrink: 0 }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <FamilyBar label="TLS Security" state={tls} />
          <TaskPill label="MTA-STS" status={tls.taskStatuses['mta_sts_check']} />
          <TaskPill label="TLSRPT" status={tls.taskStatuses['tlsrpt_check']} />
          <TaskPill label="STARTTLS" status={tls.taskStatuses['starttls_probe']} />
          <TaskPill label="Conflicts" status={tls.taskStatuses['tls_conflict_analysis']} />
          <TaskPill label="DANE" status={tls.taskStatuses['dane_tlsa_check']} />
        </div>

        <button onClick={triggerRefresh} disabled={isRunning} style={{ marginLeft: 'auto', padding: '5px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600, border: '1px solid rgba(0,229,255,0.25)', background: isRunning ? 'transparent' : 'rgba(0,229,255,0.06)', color: isRunning ? 'var(--muted)' : 'var(--accent)', cursor: isRunning ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-body)', flexShrink: 0 }}>
          ↺ {ACTION_LABELS.runScan}
        </button>
      </div>

      <div style={{ flex: 1 }}><Outlet /></div>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}
