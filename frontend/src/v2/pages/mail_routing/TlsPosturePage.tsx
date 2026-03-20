/**
 * TlsPosturePage.tsx — MailGuard V2
 * Pure result viewer for tls_posture family.
 * Reads mta_sts_check, tlsrpt_check, starttls_probe, tls_conflict_analysis,
 * dane_tlsa_check from context.
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

function StatusChip({ ok, label }: { ok: boolean | null; label: string }) {
  const color = ok === null ? '#64748b' : ok ? '#22c55e' : '#ef4444'
  const icon  = ok === null ? '?' : ok ? '✓' : '✗'
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 10px', borderRadius: 12, fontSize: 11, background: `${color}12`, border: `1px solid ${color}40`, color }}>
      {icon} {label}
    </span>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TlsPosturePage() {
  const { tls } = useMailRouting()
  const { jobStatus, taskResults } = tls

  const isLoading = jobStatus === 'queued' || jobStatus === 'running'

  const mtaResult      = taskResults['mta_sts_check']
  const tlsrptResult   = taskResults['tlsrpt_check']
  const starttlsResult = taskResults['starttls_probe']
  const conflictResult = taskResults['tls_conflict_analysis']
  const daneResult     = taskResults['dane_tlsa_check']

  const mtaEv      = mtaResult?.evidence      as Record<string, any> | undefined
  const tlsrptEv   = tlsrptResult?.evidence   as Record<string, any> | undefined
  const starttlsEv = starttlsResult?.evidence as Record<string, any> | undefined
  const conflictEv = conflictResult?.evidence as Record<string, any> | undefined
  const daneEv     = daneResult?.evidence     as Record<string, any> | undefined

  const mtaFindings      = (mtaResult?.findings      ?? []) as any[]
  const tlsrptFindings   = (tlsrptResult?.findings   ?? []) as any[]
  const starttlsFindings = (starttlsResult?.findings ?? []) as any[]
  const conflictFindings = (conflictResult?.findings ?? []) as any[]
  const daneFindings     = (daneResult?.findings     ?? []) as any[]

  const allFindings = [...mtaFindings, ...tlsrptFindings, ...starttlsFindings, ...conflictFindings]
  const critCount   = allFindings.filter(f => f.severity === 'critical').length
  const highCount   = allFindings.filter(f => f.severity === 'high').length

  const mtaMode    = mtaEv?.policy?.mode as string | undefined
  const mtaPresent = !!mtaEv?.mta_sts_record
  const tlsrptPresent = !!tlsrptEv?.tlsrpt_record

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 32px', borderBottom: '1px solid var(--border)', background: 'rgba(8,12,18,0.85)', backdropFilter: 'blur(10px)', position: 'sticky', top: 44, zIndex: 5 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 20, fontWeight: 600 }}>TLS Posture</h1>
            <span style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 500, background: 'rgba(0,229,255,0.08)', color: 'var(--accent)', border: '1px solid rgba(0,229,255,0.2)' }}>MTA-STS · STARTTLS · DANE</span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>Transport layer security enforcement, policy verification, and conflict detection</p>
        </div>
        {allFindings.length > 0 && (
          <div style={{ display: 'flex', gap: 8 }}>
            {critCount > 0 && <span style={{ fontSize: 12, color: '#ef4444', fontWeight: 600 }}>{critCount} critical</span>}
            {highCount > 0 && <span style={{ fontSize: 12, color: '#f97316', fontWeight: 600 }}>{highCount} high</span>}
          </div>
        )}
      </div>

      <div style={{ padding: '24px 32px', maxWidth: 920 }}>

        {/* ── TLS Policy Summary ─────────────────────────────────────────── */}
        {(mtaEv || tlsrptEv) && (
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 20 }}>
            <StatusChip ok={mtaPresent} label={`MTA-STS${mtaMode ? ` (${mtaMode})` : ''}`} />
            <StatusChip ok={tlsrptPresent} label="TLSRPT" />
            {starttlsEv && (
              <StatusChip
                ok={(starttlsEv.probe_results as any[] ?? []).every(p => p.tls_offered)}
                label="STARTTLS on all MX"
              />
            )}
            <StatusChip ok={daneEv?.dane_present ?? null} label="DANE" />
          </div>
        )}

        {/* ── MTA-STS ────────────────────────────────────────────────────── */}
        {isLoading && !mtaEv && <LoadingCard label="Checking MTA-STS policy…" />}

        {mtaEv && (
          <Section title="MTA-STS" icon="🔒">
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>TXT Record</div>
              {mtaEv.mta_sts_record
                ? <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', background: 'rgba(0,229,255,0.04)', border: '1px solid rgba(0,229,255,0.1)', borderRadius: 6, padding: '8px 12px', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{mtaEv.mta_sts_record as string}</pre>
                : <span style={{ fontSize: 12, color: '#ef4444' }}>Not found</span>
              }
            </div>
            {mtaEv.policy && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>Policy</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {['mode','max_age'].map(k => (
                    <div key={k} style={{ padding: '6px 12px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 9, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{k}</div>
                      <div style={{ fontSize: 12, color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>
                        {(mtaEv.policy as any)[k] ?? '—'}
                        {k === 'max_age' && (mtaEv.policy as any)[k] ? `s (${Math.round((mtaEv.policy as any)[k]/86400)}d)` : ''}
                      </div>
                    </div>
                  ))}
                </div>
                {(mtaEv.policy as any).mx?.length > 0 && (
                  <div style={{ marginTop: 10 }}>
                    <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 6 }}>Whitelisted MX</div>
                    {(mtaEv.policy as any).mx.map((m: string, i: number) => (
                      <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', marginBottom: 2 }}>{m}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {mtaFindings.length > 0
              ? mtaFindings.map(f => <FindingRow key={f.id} f={f} />)
              : mtaEv.mta_sts_record && <div style={{ fontSize: 13, color: '#22c55e' }}>✓ MTA-STS policy looks good</div>
            }
          </Section>
        )}

        {/* ── TLSRPT ─────────────────────────────────────────────────────── */}
        {isLoading && !tlsrptEv && <LoadingCard label="Checking TLSRPT record…" />}

        {tlsrptEv && (
          <Section title="TLSRPT Reporting" icon="📊">
            {tlsrptEv.tlsrpt_record
              ? <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', background: 'rgba(0,229,255,0.04)', border: '1px solid rgba(0,229,255,0.1)', borderRadius: 6, padding: '8px 12px', margin: '0 0 12px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{tlsrptEv.tlsrpt_record as string}</pre>
              : <div style={{ fontSize: 12, color: '#ef4444', marginBottom: 12 }}>No TLSRPT record found at _smtp._tls.{tlsrptEv.domain}</div>
            }
            {tlsrptFindings.length > 0
              ? tlsrptFindings.map(f => <FindingRow key={f.id} f={f} />)
              : tlsrptEv.tlsrpt_record && <div style={{ fontSize: 13, color: '#22c55e' }}>✓ TLSRPT reporting configured</div>
            }
          </Section>
        )}

        {/* ── STARTTLS Probe ─────────────────────────────────────────────── */}
        {isLoading && !starttlsEv && <LoadingCard label="Probing STARTTLS on MX hosts…" />}

        {starttlsEv && (
          <Section title={`STARTTLS Probe — ${(starttlsEv.mx_hosts_probed as string[] ?? []).length} MX hosts`} icon="🔐">
            <div style={{ marginBottom: 12 }}>
              {(starttlsEv.probe_results as any[] ?? []).map((probe: any, i: number) => (
                <div key={i} style={{ marginBottom: 8, padding: '10px 14px', background: 'rgba(0,229,255,0.03)', border: '1px solid var(--border)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: probe.tls_offered ? 6 : 0 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)', flex: 1 }}>{probe.host}</span>
                    {probe.error && !probe.connectable
                      ? <span style={{ fontSize: 10, color: '#ef4444' }}>✗ unreachable</span>
                      : probe.tls_offered
                        ? <span style={{ fontSize: 10, color: '#22c55e' }}>✓ STARTTLS</span>
                        : <span style={{ fontSize: 10, color: '#ef4444' }}>✗ no STARTTLS</span>
                    }
                  </div>
                  {probe.tls_offered && (
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {probe.tls_version && <span style={{ fontSize: 10, padding: '1px 8px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--muted)' }}>{probe.tls_version}</span>}
                      {probe.cert_cn    && <span style={{ fontSize: 10, padding: '1px 8px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--muted)' }}>CN: {probe.cert_cn}</span>}
                      {probe.cert_expiry && <span style={{ fontSize: 10, padding: '1px 8px', borderRadius: 10, background: probe.cert_expired ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)', border: `1px solid ${probe.cert_expired ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`, color: probe.cert_expired ? '#ef4444' : '#22c55e' }}>
                        {probe.cert_expired ? '✗ expired' : `✓ valid to ${probe.cert_expiry?.slice(0,10)}`}
                      </span>}
                      {probe.hostname_match !== null && <span style={{ fontSize: 10, padding: '1px 8px', borderRadius: 10, background: probe.hostname_match ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${probe.hostname_match ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`, color: probe.hostname_match ? '#22c55e' : '#ef4444' }}>
                        {probe.hostname_match ? '✓ hostname match' : '✗ hostname mismatch'}
                      </span>}
                    </div>
                  )}
                </div>
              ))}
            </div>
            {starttlsFindings.length > 0
              ? starttlsFindings.map(f => <FindingRow key={f.id} f={f} />)
              : <div style={{ fontSize: 13, color: '#22c55e' }}>✓ STARTTLS operational on all probed MX hosts</div>
            }
          </Section>
        )}

        {/* ── TLS Conflicts ──────────────────────────────────────────────── */}
        {isLoading && !conflictEv && <LoadingCard label="Checking for TLS policy conflicts…" />}

        {conflictEv && conflictFindings.length > 0 && (
          <Section title={`TLS Policy Conflicts (${conflictFindings.length})`} icon="⚡">
            {conflictFindings.map(f => <FindingRow key={f.id} f={f} />)}
          </Section>
        )}

        {/* ── DANE / TLSA ────────────────────────────────────────────────── */}
        {isLoading && !daneEv && <LoadingCard label="Checking DANE/TLSA records…" />}

        {daneEv && (
          <Section title="DANE / TLSA" icon="🔑" defaultOpen={false}>
            <div style={{ marginBottom: 12, padding: '10px 14px', background: 'rgba(148,163,184,0.06)', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 8 }}>
              <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>
                Full DANE validation deferred — DNSSEC resolver required
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>
                TLSA record presence check only. Certificate chain validation against TLSA records
                will be enabled in a future release.
              </div>
            </div>
            {(daneEv.tlsa_results as any[] ?? []).map((r: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', marginBottom: 4, background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: 6 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', flex: 1 }}>{r.host}</span>
                <span style={{ fontSize: 10, color: r.tlsa_present ? '#22c55e' : 'var(--muted)' }}>
                  {r.tlsa_present ? `✓ TLSA present (${r.record_count} record${r.record_count !== 1 ? 's' : ''})` : '○ No TLSA'}
                </span>
              </div>
            ))}
            {daneFindings.map(f => <FindingRow key={f.id} f={f} />)}
          </Section>
        )}

        {/* Empty state */}
        {!isLoading && !mtaEv && !starttlsEv && (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <div style={{ fontSize: 44, marginBottom: 16, opacity: 0.35 }}>🔐</div>
            <div style={{ fontSize: 14, color: 'var(--muted)' }}>Select a domain to analyse TLS posture</div>
          </div>
        )}
      </div>
    </div>
  )
}
