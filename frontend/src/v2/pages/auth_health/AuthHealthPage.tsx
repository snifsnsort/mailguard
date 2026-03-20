/**
 * AuthHealthPage.tsx — MailGuard V2
 *
 * Pure result viewer. Reads authentication_status task result from
 * DnsPostureContext. No fetch calls, no scan logic, no job ownership.
 *
 * Job lifecycle is owned by DnsPostureContext (app-level).
 * Batch status is shown in DnsPostureLayout (layout-level).
 * This page renders results only.
 */

import { useState } from 'react'
import { useDnsPosture } from '../../context/DnsPostureContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface DkimSelector {
  selector: string
  fqdn: string
  key_type?: string
  key_bits?: number
  platform?: string
  valid: boolean
  error?: string
}

interface SpfEvidence {
  present: boolean
  record?: string
  policy?: string
  multiple: boolean
  lookup_count: number
  includes: string[]
  providers: string[]
}

interface DmarcEvidence {
  present: boolean
  record?: string
  policy?: string
  subdomain_policy?: string
  pct: number
  rua: string[]
  ruf: string[]
  aspf: string
  adkim: string
  multiple: boolean
}

interface DkimEvidence {
  selectors_found: DkimSelector[]
  selectors_checked: number
  providers: string[]
}

interface ScoreBreakdown {
  spf: number
  dmarc: number
  dkim: number
  cross: number
  health_total: number
  exposure: number
}

interface ScanMetadata {
  scan_type: string
  module_version: string
  scan_duration_ms: number
  selectors_checked: number
}

interface Evidence {
  domain: string
  health_score: number
  grade: string
  spf: SpfEvidence
  dmarc: DmarcEvidence
  dkim: DkimEvidence
  detected_providers: string[]
  score_breakdown: ScoreBreakdown
  scan_metadata: ScanMetadata
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

const POLICY_COLOR: Record<string, string> = {
  reject: '#22c55e', quarantine: '#eab308', none: '#f97316',
  '-all': '#22c55e', '~all': '#eab308', '?all': '#f97316', '+all': '#ef4444', missing: '#ef4444',
}

const POLICY_LABEL: Record<string, string> = {
  reject: 'reject', quarantine: 'quarantine', none: 'none (monitoring)',
  '-all': 'hard fail (-all)', '~all': 'soft fail (~all)',
  '?all': 'neutral (?all)', '+all': 'pass all (+all) ⚠', missing: 'missing',
}

function healthColor(score: number): string {
  if (score >= 80) return '#22c55e'
  if (score >= 60) return '#eab308'
  if (score >= 40) return '#f97316'
  return '#ef4444'
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const size = 108; const r = 42; const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ; const color = healthColor(score)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--surface2)" strokeWidth={7} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={7}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          transform={`rotate(-90 ${size/2} ${size/2})`}
          style={{ transition: 'stroke-dashoffset .5s ease' }} />
        <text x={size/2} y={size/2-6} textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize={26} fontWeight={700} fontFamily="var(--font-mono)">{score}</text>
        <text x={size/2} y={size/2+16} textAnchor="middle" dominantBaseline="middle"
          fill="var(--muted)" fontSize={12} fontFamily="var(--font-body)">Grade {grade}</text>
      </svg>
      <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: 1, textTransform: 'uppercase' }}>
        Health Score
      </div>
    </div>
  )
}

function ProtoBadge({ label, present, policy, selectors }: {
  label: string; present: boolean; policy?: string; selectors?: number
}) {
  const ok   = present && policy !== 'none' && policy !== '+all' && policy !== 'missing' && (selectors === undefined || selectors > 0)
  const warn = present && (policy === 'none' || policy === '~all' || policy === '?all')
  const color = ok ? '#22c55e' : warn ? '#eab308' : '#ef4444'
  const bg    = ok ? 'rgba(34,197,94,0.08)' : warn ? 'rgba(234,179,8,0.08)' : 'rgba(239,68,68,0.08)'
  const statusText = !present ? 'Not configured'
    : policy !== undefined ? (POLICY_LABEL[policy] ?? policy)
    : selectors !== undefined ? `${selectors} selector${selectors !== 1 ? 's' : ''}`
    : 'Configured'
  return (
    <div style={{ flex: 1, minWidth: 140, padding: '14px 18px', borderRadius: 10, background: bg, border: `1px solid ${color}33` }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{label}</span>
        <span style={{ fontSize: 16 }}>{ok ? '✓' : warn ? '⚠' : '✗'}</span>
      </div>
      <div style={{ fontSize: 11, color }}>{statusText}</div>
    </div>
  )
}

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

function RecordBlock({ label, value }: { label: string; value?: string }) {
  if (!value) return null
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 6 }}>{label}</div>
      <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', background: 'rgba(0,229,255,0.04)', border: '1px solid rgba(0,229,255,0.1)', borderRadius: 6, padding: '10px 14px', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, lineHeight: 1.6 }}>{value}</pre>
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

// ── Main page — pure consumer ─────────────────────────────────────────────────

export default function AuthHealthPage() {
  const { jobStatus, taskResults, jobError } = useDnsPosture()

  const taskResult = taskResults['authentication_status']
  const ev         = taskResult?.evidence as Evidence | undefined
  const findings   = (taskResult?.findings ?? []) as Finding[]

  const isLoading = jobStatus === 'queued' || jobStatus === 'running'
  const isFailed  = jobStatus === 'failed' && !taskResult

  const critical      = findings.filter(f => f.severity === 'critical').length
  const high          = findings.filter(f => f.severity === 'high').length
  const medium        = findings.filter(f => f.severity === 'medium').length
  const detailFindings = findings.filter(f => !f.id.startsWith('auth-summary-'))

  return (
    <div>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 32px', borderBottom: '1px solid var(--border)', background: 'rgba(8,12,18,0.85)', backdropFilter: 'blur(10px)', position: 'sticky', top: 44, zIndex: 5 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 20, fontWeight: 600 }}>Authentication Health</h1>
            <span style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 500, background: 'rgba(0,229,255,0.08)', color: 'var(--accent)', border: '1px solid rgba(0,229,255,0.2)' }}>
              SPF · DKIM · DMARC
            </span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
            Email authentication posture — spoofing risk and alignment
          </p>
        </div>
      </div>

      <div style={{ padding: '28px 32px', maxWidth: 860 }}>

        {/* Loading state */}
        {isLoading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '24px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10, marginBottom: 20 }}>
            <span style={{ display: 'inline-block', width: 16, height: 16, borderRadius: '50%', border: '2px solid var(--accent)', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
            <span style={{ fontSize: 13, color: 'var(--muted)' }}>
              {jobStatus === 'queued' ? 'Scan queued…' : 'Scanning authentication records…'}
            </span>
          </div>
        )}

        {/* Error state */}
        {isFailed && (
          <div style={{ display: 'flex', gap: 10, padding: '12px 16px', marginBottom: 20, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8 }}>
            <span style={{ fontSize: 13, color: '#ef4444' }}>⚠ {jobError ?? 'Scan failed'}</span>
          </div>
        )}

        {/* Results */}
        {ev && (
          <>
            {/* Score + protocol summary card */}
            <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', marginBottom: 24, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: '20px 24px' }}>
              <ScoreRing score={ev.health_score} grade={ev.grade} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 12 }}>
                  {ev.domain}
                  {critical > 0 && <span style={{ color: '#ef4444', marginLeft: 8 }}>· {critical} critical</span>}
                  {high     > 0 && <span style={{ color: '#f97316', marginLeft: 8 }}>· {high} high</span>}
                  {medium   > 0 && <span style={{ color: '#eab308', marginLeft: 8 }}>· {medium} medium</span>}
                  {critical === 0 && high === 0 && <span style={{ color: '#22c55e', marginLeft: 8 }}>· no critical or high issues</span>}
                </div>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 14 }}>
                  <ProtoBadge label="SPF"   present={ev.spf.present}   policy={ev.spf.policy ?? undefined} />
                  <ProtoBadge label="DMARC" present={ev.dmarc.present} policy={ev.dmarc.policy ?? undefined} />
                  <ProtoBadge label="DKIM"  present={ev.dkim.selectors_found.length > 0} selectors={ev.dkim.selectors_found.length} />
                </div>
                {ev.detected_providers.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                    <span style={{ fontSize: 11, color: 'var(--muted)' }}>Detected senders:</span>
                    {ev.detected_providers.map(p => (
                      <span key={p} style={{ padding: '2px 10px', borderRadius: 12, fontSize: 11, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--text)' }}>{p}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {detailFindings.length > 0 && (
              <Collapsible title={`Security Findings (${detailFindings.length})`} icon="🔍" defaultOpen>
                {detailFindings.map(f => <FindingRow key={f.id} f={f} />)}
              </Collapsible>
            )}

            <Collapsible title="SPF" icon="📋" defaultOpen={ev.spf.present}>
              {ev.spf.present ? (
                <>
                  <RecordBlock label="SPF Record" value={ev.spf.record} />
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px' }}>
                    <KV label="Policy" value={POLICY_LABEL[ev.spf.policy ?? ''] ?? ev.spf.policy ?? '—'} valueColor={POLICY_COLOR[ev.spf.policy ?? '']} />
                    <KV label="DNS Lookups" value={`${ev.spf.lookup_count} / 10`} valueColor={ev.spf.lookup_count > 10 ? '#ef4444' : ev.spf.lookup_count >= 9 ? '#f97316' : '#22c55e'} />
                    <KV label="Multiple records" value={ev.spf.multiple ? 'Yes ⚠' : 'No'} valueColor={ev.spf.multiple ? '#ef4444' : '#22c55e'} />
                    <KV label="Includes" value={ev.spf.includes.length} />
                  </div>
                  {ev.spf.providers.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <div style={{ fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 6 }}>Authorised senders</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {ev.spf.providers.map(p => (
                          <span key={p} style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--text)' }}>{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div style={{ color: '#ef4444', fontSize: 13 }}>No SPF record found for {ev.domain}</div>
              )}
            </Collapsible>

            <Collapsible title="DMARC" icon="🛡" defaultOpen={ev.dmarc.present}>
              {ev.dmarc.present ? (
                <>
                  <RecordBlock label="DMARC Record" value={ev.dmarc.record} />
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px' }}>
                    <KV label="Policy (p=)" value={ev.dmarc.policy ?? '—'} valueColor={POLICY_COLOR[ev.dmarc.policy ?? '']} />
                    <KV label="Subdomain (sp=)" value={ev.dmarc.subdomain_policy ?? 'inherits p='} valueColor={POLICY_COLOR[ev.dmarc.subdomain_policy ?? '']} />
                    <KV label="Enforcement pct" value={`${ev.dmarc.pct}%`} valueColor={ev.dmarc.pct === 100 ? '#22c55e' : '#f97316'} />
                    <KV label="SPF alignment (aspf=)" value={ev.dmarc.aspf === 's' ? 'strict' : 'relaxed'} />
                    <KV label="DKIM alignment (adkim=)" value={ev.dmarc.adkim === 's' ? 'strict' : 'relaxed'} />
                    <KV label="Multiple records" value={ev.dmarc.multiple ? 'Yes ⚠' : 'No'} valueColor={ev.dmarc.multiple ? '#ef4444' : '#22c55e'} />
                  </div>
                  {(ev.dmarc.rua.length > 0 || ev.dmarc.ruf.length > 0) && (
                    <div style={{ marginTop: 10 }}>
                      {ev.dmarc.rua.length > 0 && <KV label="Aggregate reports (rua)" value={ev.dmarc.rua.join(', ')} />}
                      {ev.dmarc.ruf.length > 0 && <KV label="Forensic reports (ruf)"  value={ev.dmarc.ruf.join(', ')} />}
                    </div>
                  )}
                </>
              ) : (
                <div style={{ color: '#ef4444', fontSize: 13 }}>No DMARC record found at _dmarc.{ev.domain}</div>
              )}
            </Collapsible>

            <Collapsible title={`DKIM (${ev.dkim.selectors_found.length} selector${ev.dkim.selectors_found.length !== 1 ? 's' : ''} found)`} icon="🔑" defaultOpen={ev.dkim.selectors_found.length > 0}>
              {ev.dkim.selectors_found.length > 0 ? (
                <>
                  {ev.dkim.selectors_found.map((s: DkimSelector) => (
                    <div key={s.selector} style={{ marginBottom: 10, padding: '10px 14px', background: 'rgba(0,229,255,0.03)', border: '1px solid var(--border)', borderRadius: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent)' }}>{s.selector}</span>
                        {s.platform && <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', color: 'var(--muted)' }}>{s.platform}</span>}
                        {s.key_bits !== undefined && (
                          <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, background: s.key_bits >= 2048 ? 'rgba(34,197,94,0.08)' : 'rgba(234,179,8,0.08)', border: `1px solid ${s.key_bits >= 2048 ? 'rgba(34,197,94,0.3)' : 'rgba(234,179,8,0.3)'}`, color: s.key_bits >= 2048 ? '#22c55e' : '#eab308' }}>~{s.key_bits} bits</span>
                        )}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--muted)' }}>{s.fqdn}</div>
                    </div>
                  ))}
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>Checked {ev.dkim.selectors_checked} common selectors</div>
                </>
              ) : (
                <div style={{ color: 'var(--muted)', fontSize: 13 }}>
                  No DKIM selectors found after checking {ev.dkim.selectors_checked} common names. DKIM may use a non-standard selector — verify manually.
                </div>
              )}
            </Collapsible>

            <Collapsible title="Raw DNS Evidence" icon="🗂">
              <RecordBlock label="SPF (TXT)"   value={ev.spf.record} />
              <RecordBlock label="DMARC (TXT)" value={ev.dmarc.record} />
              <div style={{ marginTop: 8, fontSize: 11, color: 'var(--muted)' }}>
                Scan completed in {ev.scan_metadata.scan_duration_ms}ms · Module {ev.scan_metadata.module_version} · {ev.scan_metadata.selectors_checked} DKIM selectors checked
              </div>
            </Collapsible>
          </>
        )}

        {/* Empty state */}
        {!ev && !isLoading && !isFailed && (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <div style={{ fontSize: 44, marginBottom: 16, opacity: 0.35 }}>🛡</div>
            <div style={{ fontSize: 14, color: 'var(--muted)', marginBottom: 8 }}>Select a domain to start scanning</div>
            <div style={{ fontSize: 12, color: 'var(--muted)', opacity: 0.7 }}>
              Analysing SPF, DKIM, and DMARC to detect spoofing risks and authentication gaps.
            </div>
          </div>
        )}
      </div>

      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}
