/**
 * MXAnalysisPage.tsx — MailGuard V2
 *
 * Pure result viewer. Reads mx_health task result from DnsPostureContext.
 * No fetch calls, no scan logic, no job ownership.
 */

import { useState } from 'react'
import { useDnsPosture } from '../../context/DnsPostureContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface MxRecord {
  priority: number
  host: string
  provider: string
  ips: string[]
  resolved: boolean
  multi_ip: boolean
  resolve_error?: string
}

interface Finding {
  id: string
  category: string
  severity: string
  title: string
  description: string
  recommended_action: string
  evidence: Record<string, unknown>
}

// ── Style helpers ─────────────────────────────────────────────────────────────

const SEV: Record<string, { bg: string; border: string; color: string }> = {
  critical: { bg: 'rgba(239,68,68,0.10)',   border: 'rgba(239,68,68,0.35)',   color: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.10)',  border: 'rgba(249,115,22,0.35)',  color: '#f97316' },
  medium:   { bg: 'rgba(234,179,8,0.10)',   border: 'rgba(234,179,8,0.35)',   color: '#eab308' },
  low:      { bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.3)', color: '#94a3b8' },
  info:     { bg: 'rgba(148,163,184,0.06)', border: 'rgba(148,163,184,0.2)', color: '#64748b' },
}

// ── Sub-components ────────────────────────────────────────────────────────────

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false)
  const s = SEV[f.severity] ?? SEV.info
  return (
    <div style={{ border: `1px solid ${s.border}`, borderRadius: 8, marginBottom: 6, overflow: 'hidden' }}>
      <div onClick={() => setOpen(v => !v)}
        style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 14px', cursor: 'pointer', background: s.bg }}>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase', color: s.color, flexShrink: 0, marginTop: 1, minWidth: 58 }}>{f.severity}</span>
        <span style={{ fontSize: 12, color: 'var(--text)', flex: 1, lineHeight: 1.5 }}>{f.title}</span>
        <span style={{ fontSize: 11, color: 'var(--muted)', flexShrink: 0 }}>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.01)', borderTop: `1px solid ${s.border}` }}>
          <p style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.65, margin: '0 0 10px' }}>{f.description}</p>
          {f.recommended_action && (
            <div style={{ padding: '8px 12px', borderRadius: 6, fontSize: 12, background: 'rgba(0,229,255,0.04)', border: '1px solid rgba(0,229,255,0.12)', color: 'var(--text)', lineHeight: 1.5 }}>
              <strong style={{ color: 'var(--accent)' }}>Action: </strong>{f.recommended_action}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Collapsible({ title, icon, children, defaultOpen = false }: {
  title: string; icon: string; children: React.ReactNode; defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 10, marginBottom: 12, overflow: 'hidden' }}>
      <button onClick={() => setOpen(v => !v)} style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 18px', background: 'var(--surface)', border: 'none', cursor: 'pointer', color: 'var(--text)', fontFamily: 'var(--font-body)' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600 }}>{icon} {title}</span>
        <span style={{ fontSize: 11, color: 'var(--muted)' }}>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div style={{ padding: '14px 18px', borderTop: '1px solid var(--border)', background: 'rgba(255,255,255,0.01)' }}>
          {children}
        </div>
      )}
    </div>
  )
}

function KV({ label, value, valueColor }: { label: string; value: string | number; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
      <span style={{ color: 'var(--muted)' }}>{label}</span>
      <span style={{ color: valueColor ?? 'var(--text)', fontFamily: 'var(--font-mono)' }}>{value}</span>
    </div>
  )
}

const routingColor = (t?: string) => {
  if (!t) return 'var(--muted)'
  if (t === 'seg_present')  return '#22c55e'
  if (t === 'direct_m365') return '#eab308'
  if (t === 'mixed')        return '#f97316'
  return 'var(--muted)'
}

// ── Main page — pure consumer ─────────────────────────────────────────────────

export default function MXAnalysisPage() {
  const { jobStatus, taskResults, jobError } = useDnsPosture()

  const taskResult = taskResults['mx_health']
  const ev         = taskResult?.evidence as Record<string, unknown> | undefined
  const findings   = (taskResult?.findings ?? []) as Finding[]

  const isLoading = jobStatus === 'queued' || jobStatus === 'running'
  const isFailed  = jobStatus === 'failed' && !taskResult

  const mxRecords  = (ev?.mx_records  ?? []) as MxRecord[]
  const providers  = (ev?.providers   ?? []) as string[]
  const routingType = ev?.routing_type as string | undefined
  const healthScore = ev?.health_score as number | undefined

  return (
    <div>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 32px', borderBottom: '1px solid var(--border)', background: 'rgba(8,12,18,0.85)', backdropFilter: 'blur(10px)', position: 'sticky', top: 44, zIndex: 5 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 20, fontWeight: 600 }}>MX Routing Analysis</h1>
            <span style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 500, background: 'rgba(0,229,255,0.08)', color: 'var(--accent)', border: '1px solid rgba(0,229,255,0.2)' }}>
              Exposure
            </span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
            MX record resolution, routing posture, and gateway exposure
          </p>
        </div>
      </div>

      <div style={{ padding: '28px 32px', maxWidth: 860 }}>

        {/* Loading */}
        {isLoading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '24px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10, marginBottom: 20 }}>
            <span style={{ display: 'inline-block', width: 16, height: 16, borderRadius: '50%', border: '2px solid var(--accent)', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
            <span style={{ fontSize: 13, color: 'var(--muted)' }}>
              {jobStatus === 'queued' ? 'Scan queued…' : 'Resolving MX records…'}
            </span>
          </div>
        )}

        {/* Error */}
        {isFailed && (
          <div style={{ display: 'flex', gap: 10, padding: '12px 16px', marginBottom: 20, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8 }}>
            <span style={{ fontSize: 13, color: '#ef4444' }}>⚠ {jobError ?? 'Scan failed'}</span>
          </div>
        )}

        {/* Results */}
        {ev && (
          <>
            {/* Routing summary */}
            <div style={{ display: 'flex', gap: 16, alignItems: 'stretch', marginBottom: 20, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: '18px 22px' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8 }}>{ev.domain as string}</div>
                <div style={{ fontSize: 20, fontWeight: 700, color: routingColor(routingType), marginBottom: 4 }}>
                  {routingType?.replace(/_/g, ' ') ?? 'Unknown routing'}
                </div>
                {providers.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
                    <span style={{ fontSize: 11, color: 'var(--muted)' }}>Providers:</span>
                    {providers.map(p => (
                      <span key={p} style={{ padding: '2px 10px', borderRadius: 12, fontSize: 11, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--text)' }}>{p}</span>
                    ))}
                  </div>
                )}
              </div>
              {healthScore !== undefined && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minWidth: 70 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 28, fontWeight: 700, color: healthScore >= 70 ? '#22c55e' : healthScore >= 40 ? '#eab308' : '#ef4444' }}>{healthScore}</div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>Health</div>
                </div>
              )}
            </div>

            {findings.length > 0 && (
              <Collapsible title={`Findings (${findings.length})`} icon="🔍" defaultOpen>
                {findings.map(f => <FindingRow key={f.id} f={f} />)}
              </Collapsible>
            )}

            {mxRecords.length > 0 && (
              <Collapsible title={`MX Records (${mxRecords.length})`} icon="📡" defaultOpen>
                {mxRecords.map((r, i) => (
                  <div key={i} style={{ marginBottom: 10, padding: '10px 14px', background: 'rgba(0,229,255,0.03)', border: '1px solid var(--border)', borderRadius: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', minWidth: 28 }}>{r.priority}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent)' }}>{r.host}</span>
                      {r.provider && r.provider !== 'Unknown' && (
                        <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--muted)' }}>{r.provider}</span>
                      )}
                      {!r.resolved && (
                        <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>unresolvable</span>
                      )}
                    </div>
                    {r.ips && r.ips.length > 0 && (
                      <div style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--font-mono)', marginLeft: 38 }}>
                        {r.ips.slice(0, 3).join(', ')}{r.ips.length > 3 ? ` +${r.ips.length - 3}` : ''}
                      </div>
                    )}
                  </div>
                ))}
              </Collapsible>
            )}

            <Collapsible title="Raw Evidence" icon="🗂">
              <KV label="Domain"       value={ev.domain as string} />
              <KV label="Routing type" value={routingType ?? '—'} />
              <KV label="Providers"    value={providers.join(', ') || '—'} />
            </Collapsible>
          </>
        )}

        {/* Empty state */}
        {!ev && !isLoading && !isFailed && (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <div style={{ fontSize: 44, marginBottom: 16, opacity: 0.35 }}>📡</div>
            <div style={{ fontSize: 14, color: 'var(--muted)', marginBottom: 8 }}>Select a domain to analyse MX routing</div>
            <div style={{ fontSize: 12, color: 'var(--muted)', opacity: 0.7 }}>
              Resolves MX records, classifies routing posture, and detects gateway exposure risks.
            </div>
          </div>
        )}
      </div>

      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}
