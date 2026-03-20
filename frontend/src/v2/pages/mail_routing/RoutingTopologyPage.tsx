/**
 * RoutingTopologyPage.tsx — MailGuard V2
 * Pure result viewer for mail_routing_topology family.
 * Reads inbound_path_mapping, connector_posture, direct_send_check from context.
 */

import { useState } from 'react'
import { useMailRouting } from '../../context/MailRoutingContext'

// ── Shared sub-components ─────────────────────────────────────────────────────

const SEV: Record<string, { bg: string; border: string; color: string }> = {
  critical: { bg: 'rgba(239,68,68,0.10)',   border: 'rgba(239,68,68,0.35)',   color: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.10)',  border: 'rgba(249,115,22,0.35)',  color: '#f97316' },
  medium:   { bg: 'rgba(234,179,8,0.10)',   border: 'rgba(234,179,8,0.35)',   color: '#eab308' },
  low:      { bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.3)', color: '#94a3b8' },
  info:     { bg: 'rgba(148,163,184,0.06)', border: 'rgba(148,163,184,0.2)', color: '#64748b' },
}

function FindingRow({ f }: { f: any }) {
  const [open, setOpen] = useState(false)
  const s = SEV[f.severity] ?? SEV.info
  const impact = f.evidence?.impact as string | undefined
  return (
    <div style={{ border: `1px solid ${s.border}`, borderRadius: 8, marginBottom: 6, overflow: 'hidden' }}>
      <div onClick={() => setOpen(v => !v)} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 14px', cursor: 'pointer', background: s.bg }}>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase', color: s.color, flexShrink: 0, marginTop: 1, minWidth: 58 }}>{f.severity}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.5 }}>{f.title}</div>
          {impact && !open && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 3 }}>{impact}</div>}
        </div>
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

function Section({ title, icon, children, defaultOpen = true }: { title: string; icon: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 10, marginBottom: 16, overflow: 'hidden' }}>
      <button onClick={() => setOpen(v => !v)} style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '13px 18px', background: 'var(--surface)', border: 'none', cursor: 'pointer', color: 'var(--text)', fontFamily: 'var(--font-body)' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600 }}>{icon} {title}</span>
        <span style={{ fontSize: 11, color: 'var(--muted)' }}>{open ? '▲' : '▼'}</span>
      </button>
      {open && <div style={{ padding: '16px 18px', borderTop: '1px solid var(--border)', background: 'rgba(255,255,255,0.01)' }}>{children}</div>}
    </div>
  )
}

function LoadingCard({ label }: { label: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 18px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, marginBottom: 12 }}>
      <span style={{ display: 'inline-block', width: 14, height: 14, borderRadius: '50%', border: '2px solid var(--accent)', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
      <span style={{ fontSize: 13, color: 'var(--muted)' }}>{label}</span>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}

function InfoCard({ label, tone = 'var(--muted)' }: { label: string; tone?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 18px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, marginBottom: 12 }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: tone, flexShrink: 0 }} />
      <span style={{ fontSize: 13, color: 'var(--muted)' }}>{label}</span>
    </div>
  )
}

// ── Routing type colour ───────────────────────────────────────────────────────

const routingColor = (t?: string) => {
  if (t === 'seg_gateway') return '#22c55e'
  if (t === 'direct_to_platform') return '#eab308'
  if (t === 'seg_only') return '#94a3b8'
  return 'var(--muted)'
}

const routingLabel = (t?: string) => {
  if (t === 'seg_gateway') return 'Email Gateway / SEG'
  if (t === 'direct_to_platform') return 'Direct to Platform'
  if (t === 'seg_only') return 'Email Gateway Only'
  return t?.replace(/_/g, ' ') ?? 'Unknown'
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function RoutingTopologyPage() {
  const { routing } = useMailRouting()
  const { jobStatus, taskResults, taskStatuses } = routing

  const pathStatus = taskStatuses['inbound_path_mapping']
  const connectorStatus = taskStatuses['connector_posture']
  const directStatus = taskStatuses['direct_send_check']

  const isTaskLoading = (status?: string) => status === 'queued' || status === 'running'

  const pathResult      = taskResults['inbound_path_mapping']
  const connResult      = taskResults['connector_posture']
  const directResult    = taskResults['direct_send_check']

  const pathEv   = pathResult?.evidence  as Record<string, any> | undefined
  const connEv   = connResult?.evidence  as Record<string, any> | undefined
  const directEv = directResult?.evidence as Record<string, any> | undefined

  const pathFindings   = (pathResult?.findings   ?? []) as any[]
  const connFindings   = (connResult?.findings   ?? []) as any[]
  const directFindings = (directResult?.findings ?? []) as any[]

  const allFindings = [...pathFindings, ...connFindings, ...directFindings]
  const critCount   = allFindings.filter(f => f.severity === 'critical').length
  const highCount   = allFindings.filter(f => f.severity === 'high').length

  const showPathLoading = isTaskLoading(pathStatus)
  const showConnectorLoading = isTaskLoading(connectorStatus)
  const showDirectLoading = isTaskLoading(directStatus)

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 32px', borderBottom: '1px solid var(--border)', background: 'rgba(8,12,18,0.85)', backdropFilter: 'blur(10px)', position: 'sticky', top: 44, zIndex: 5 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 20, fontWeight: 600 }}>Mail Routing Topology</h1>
            <span style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 500, background: 'rgba(0,229,255,0.08)', color: 'var(--accent)', border: '1px solid rgba(0,229,255,0.2)' }}>Routing · Email Gateway / SEG · Direct Send</span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>Inbound mail routing, Email Gateway / SEG connectors, and direct send posture</p>
        </div>
        {allFindings.length > 0 && (
          <div style={{ display: 'flex', gap: 8 }}>
            {critCount > 0 && <span style={{ fontSize: 12, color: '#ef4444', fontWeight: 600 }}>{critCount} Critical</span>}
            {highCount > 0 && <span style={{ fontSize: 12, color: '#f97316', fontWeight: 600 }}>{highCount} High</span>}
          </div>
        )}
      </div>

      <div style={{ padding: '24px 32px', maxWidth: 920 }}>

        {/* ── Inbound Path Mapping ─────────────────────────────────────── */}
        {showPathLoading && !pathEv && <LoadingCard label="Analyzing inbound mail routing…" />}
        {!showPathLoading && !pathEv && pathStatus === 'completed' && <InfoCard label="Inbound mail routing completed with no evidence returned." />}

        {pathEv && (
          <Section title={`Inbound Path — ${routingLabel(pathEv.routing_type)}`} icon="🗺">
            <div style={{ marginBottom: 14, padding: '14px 18px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: routingColor(pathEv.routing_type), marginBottom: 6 }}>
                {routingLabel(pathEv.routing_type)}
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.6, marginBottom: 10 }}>{pathEv.routing_description}</div>
              {(pathEv.providers as string[] | undefined)?.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--muted)' }}>Detected:</span>
                  {(pathEv.providers as string[]).map(p => (
                    <span key={p} style={{ padding: '2px 10px', borderRadius: 12, fontSize: 11, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--text)' }}>{p}</span>
                  ))}
                </div>
              )}
            </div>
            {(pathEv.mx_hops as any[] | undefined)?.length > 0 && (
              <div>
                {(pathEv.mx_hops as any[]).map((hop: any, i: number) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', marginBottom: 4, background: 'rgba(0,229,255,0.03)', border: '1px solid var(--border)', borderRadius: 6 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', minWidth: 24 }}>{hop.priority}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)', flex: 1 }}>{hop.host}</span>
                    {hop.provider !== 'Unknown' && <span style={{ fontSize: 10, padding: '1px 8px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--muted)' }}>{hop.provider}</span>}
                    {!hop.resolved && <span style={{ fontSize: 10, padding: '1px 8px', borderRadius: 10, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>unresolvable</span>}
                  </div>
                ))}
              </div>
            )}
            {pathFindings.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 8 }}>Routing Findings</div>
                {pathFindings.map(f => <FindingRow key={f.id} f={f} />)}
              </div>
            )}
          </Section>
        )}

        {/* ── Connector Posture ────────────────────────────────────────── */}
        {showConnectorLoading && !connEv && <LoadingCard label="Analyzing Email Gateway / connector posture…" />}
        {!showConnectorLoading && !connEv && connectorStatus === 'completed' && <InfoCard label="Email Gateway / connector posture completed with no evidence returned." />}
        {connectorStatus === 'failed' && !connEv && <InfoCard label="Email Gateway / connector posture failed to complete." tone="#ef4444" />}

        {connEv && (
          <Section title="Email Gateway / Connector Posture" icon="🔌">
            {connEv.not_applicable ? (
              <div style={{ fontSize: 13, color: 'var(--muted)' }}>Not applicable — {connEv.reason}</div>
            ) : (
              <>
                <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
                  {[
                    { label: 'Inbound Connectors',  value: connEv.inbound_connector_count  },
                    { label: 'Outbound Connectors', value: connEv.outbound_connector_count },
                    { label: 'Transport Rules',     value: connEv.transport_rule_count     },
                  ].map(({ label, value }) => (
                    <div key={label} style={{ padding: '10px 16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, textAlign: 'center' }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, fontWeight: 700, color: 'var(--text)' }}>{value ?? '—'}</div>
                      <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>{label}</div>
                    </div>
                  ))}
                </div>
                {connFindings.length > 0
                  ? connFindings.map(f => <FindingRow key={f.id} f={f} />)
                  : <div style={{ fontSize: 13, color: '#22c55e' }}>✓ No Email Gateway / connector issues detected</div>
                }
              </>
            )}
          </Section>
        )}

        {/* ── Direct Send ──────────────────────────────────────────────── */}
        {showDirectLoading && !directEv && <LoadingCard label="Checking direct send posture…" />}
        {!showDirectLoading && !directEv && directStatus === 'completed' && <InfoCard label="Direct send posture completed with no evidence returned." />}
        {directStatus === 'failed' && !directEv && <InfoCard label="Direct send posture failed to complete." tone="#ef4444" />}

        {directEv && (
          <Section title="Direct Send / SMTP AUTH" icon="📨">
            {directEv.not_applicable ? (
              <div style={{ fontSize: 13, color: 'var(--muted)' }}>Not applicable — {directEv.reason}</div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, padding: '12px 16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--muted)' }}>Global SMTP AUTH:</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: directEv.smtp_auth_disabled ? '#22c55e' : '#ef4444' }}>
                    {directEv.smtp_auth_disabled ? '✓ Disabled (secure)' : '✗ Enabled (risk)'}
                  </span>
                </div>
                {directFindings.length > 0
                  ? directFindings.map(f => <FindingRow key={f.id} f={f} />)
                  : <div style={{ fontSize: 13, color: '#22c55e' }}>✓ No direct send misconfiguration detected</div>
                }
              </>
            )}
          </Section>
        )}

        {/* Empty state */}
        {!showPathLoading && !showConnectorLoading && !showDirectLoading && !pathEv && !connEv && !directEv && (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <div style={{ fontSize: 44, marginBottom: 16, opacity: 0.35 }}>🗺</div>
            <div style={{ fontSize: 14, color: 'var(--muted)' }}>Select a domain to analyse mail routing</div>
          </div>
        )}
      </div>
    </div>
  )
}
