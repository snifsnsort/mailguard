/**
 * PublicIntelPage.tsx — MailGuard V2
 *
 * Displays public tenant intelligence for a domain.
 * Defaults to the shared activeDomain from ScopeContext.
 * Supports local override and explicit promotion to global scope.
 *
 * API: GET /api/v2/public-intel/{domain}?platform=microsoft365
 */

import { useState, useEffect, useRef } from 'react'
import { useScope } from '../../context/ScopeContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Finding {
  id: string
  category: string
  severity: string
  title: string
  description: string
  recommended_action: string
  evidence: Record<string, unknown>
}

interface ScanResult {
  scan_id: string
  tenant_id: string
  family: string
  findings: Finding[]
  score: number
  status: string
  timestamp: string
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
      <div
        onClick={() => setOpen(v => !v)}
        style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 14px', cursor: 'pointer', background: s.bg }}
      >
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase', color: s.color, flexShrink: 0, marginTop: 1, minWidth: 58 }}>
          {f.severity}
        </span>
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

function KV({ label, value, valueColor }: { label: string; value: string | number | boolean; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
      <span style={{ color: 'var(--muted)' }}>{label}</span>
      <span style={{ color: valueColor ?? 'var(--text)', fontFamily: 'var(--font-mono)' }}>{String(value)}</span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PublicIntelPage() {
  const { activeDomain, setActiveDomain, selectableDomains, addToSelectableDomains } = useScope()

  const [domain,   setDomain]   = useState('')
  const [platform, setPlatform] = useState('microsoft365')
  const [loading,  setLoading]  = useState(false)
  const [result,   setResult]   = useState<ScanResult | null>(null)
  const [error,    setError]    = useState<string | null>(null)

  // Track whether the user has manually typed something different from global scope
  const userHasOverridden = useRef(false)

  // Follow sidebar scope changes unless user has locally overridden
  useEffect(() => {
    if (!userHasOverridden.current) {
      setDomain(activeDomain)
    }
  }, [activeDomain])

  const handleDomainChange = (value: string) => {
    setDomain(value)
    userHasOverridden.current = value.trim().toLowerCase() !== activeDomain.toLowerCase()
  }

  const isOverride = domain.trim().toLowerCase() !== activeDomain.toLowerCase() && domain.trim() !== ''

  const handleScan = async () => {
    const d = domain.trim().toLowerCase()
    if (!d) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const token = localStorage.getItem('mg_token')
      const headers: Record<string, string> = {}
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`/api/v2/public-intel/${encodeURIComponent(d)}?platform=${platform}`, { headers })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error((body as { detail?: string }).detail ?? `HTTP ${res.status}`)
      }
      setResult(await res.json() as ScanResult)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  const ev = result?.evidence as Record<string, unknown> | undefined
  const findings = result?.findings ?? []

  return (
    <div>
      {/* Sticky header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 32px', borderBottom: '1px solid var(--border)', background: 'rgba(8,12,18,0.85)', backdropFilter: 'blur(10px)', position: 'sticky', top: 0, zIndex: 5 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 20, fontWeight: 600 }}>Public Tenant Intelligence</h1>
            <span style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 500, background: 'rgba(0,229,255,0.08)', color: 'var(--accent)', border: '1px solid rgba(0,229,255,0.2)' }}>
              Public Intel
            </span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
            Discover publicly observable tenant signals for a domain
          </p>
        </div>
      </div>

      <div style={{ padding: '28px 32px', maxWidth: 860 }}>

        {/* Domain input row */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 8 }}>
          <input
            value={domain}
            onChange={e => handleDomainChange(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="example.com"
            style={{ flex: 1, padding: '10px 16px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: 14, fontFamily: 'var(--font-mono)', outline: 'none' }}
          />
          {/* Platform selector */}
          <select
            value={platform}
            onChange={e => setPlatform(e.target.value)}
            style={{ padding: '10px 12px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', fontSize: 13, fontFamily: 'var(--font-body)', cursor: 'pointer', outline: 'none' }}
          >
            <option value="microsoft365">Microsoft 365</option>
            <option value="google_workspace">Google Workspace</option>
          </select>
          <button
            onClick={handleScan}
            disabled={loading || !domain.trim()}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 22px', borderRadius: 8, background: loading || !domain.trim() ? 'var(--surface2)' : 'var(--accent)', color: loading || !domain.trim() ? 'var(--muted)' : '#000', border: 'none', cursor: loading || !domain.trim() ? 'not-allowed' : 'pointer', fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-body)', transition: 'all .15s' }}
          >
            {loading ? '⟳ Scanning…' : '🔍 Scan'}
          </button>
        </div>

        {/* Scope indicator */}
        <div style={{ marginBottom: 20, fontSize: 11, color: 'var(--muted)', display: 'flex', alignItems: 'center', gap: 10, minHeight: 18 }}>
          {!isOverride && activeDomain && (
            <span style={{ color: 'rgba(0,229,255,0.6)' }}>🔵 Active scope: {activeDomain}</span>
          )}
          {isOverride && (
            <>
              <span style={{ color: 'rgba(249,115,22,0.8)' }}>↩ Override — not updating global scope</span>
              <button
                onClick={() => {
                  const d = domain.trim().toLowerCase()
                  addToSelectableDomains(d)
                  setActiveDomain(d)
                  userHasOverridden.current = false
                }}
                style={{ background: 'none', border: '1px solid rgba(0,229,255,0.25)', borderRadius: 4, color: 'var(--accent)', cursor: 'pointer', fontSize: 10, padding: '2px 8px', fontFamily: 'var(--font-body)' }}
              >
                Set as active scope
              </button>
            </>
          )}
        </div>

        {/* Error */}
        {error && (
          <div style={{ display: 'flex', gap: 10, padding: '12px 16px', marginBottom: 20, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8 }}>
            <span style={{ fontSize: 13, color: '#ef4444' }}>⚠ {error}</span>
          </div>
        )}

        {/* Results */}
        {result && ev && (
          <>
            {/* Summary card */}
            <div style={{ marginBottom: 20, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: '18px 22px' }}>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 10 }}>{ev.domain as string} · {platform}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                {ev.tenant_id && (
                  <div style={{ padding: '8px 14px', borderRadius: 8, background: 'rgba(0,120,212,0.08)', border: '1px solid rgba(0,120,212,0.2)' }}>
                    <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 2 }}>Tenant ID</div>
                    <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{ev.tenant_id as string}</div>
                  </div>
                )}
                {ev.tenant_name && (
                  <div style={{ padding: '8px 14px', borderRadius: 8, background: 'rgba(0,120,212,0.08)', border: '1px solid rgba(0,120,212,0.2)' }}>
                    <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 2 }}>Tenant Name</div>
                    <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{ev.tenant_name as string}</div>
                  </div>
                )}
                {ev.region && (
                  <div style={{ padding: '8px 14px', borderRadius: 8, background: 'rgba(0,120,212,0.08)', border: '1px solid rgba(0,120,212,0.2)' }}>
                    <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 2 }}>Region</div>
                    <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{ev.region as string}</div>
                  </div>
                )}
              </div>
            </div>

            {/* Findings */}
            {findings.length > 0 && (
              <Collapsible title={`Intelligence Findings (${findings.length})`} icon="🔍" defaultOpen>
                {findings.map(f => <FindingRow key={f.id} f={f} />)}
              </Collapsible>
            )}

            {/* Raw evidence */}
            <Collapsible title="Raw Evidence" icon="🗂">
              {Object.entries(ev)
                .filter(([k]) => !['domain'].includes(k))
                .map(([k, v]) => (
                  <KV key={k} label={k.replace(/_/g, ' ')} value={typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—')} />
                ))}
              <div style={{ marginTop: 8, fontSize: 11, color: 'var(--muted)' }}>
                Scan completed at {new Date(result.timestamp).toLocaleString()}
              </div>
            </Collapsible>
          </>
        )}

        {/* Empty state */}
        {!result && !loading && !error && (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <div style={{ fontSize: 44, marginBottom: 16, opacity: 0.35 }}>🔎</div>
            <div style={{ fontSize: 14, color: 'var(--muted)', marginBottom: 8 }}>Enter a domain to discover public tenant signals</div>
            <div style={{ fontSize: 12, color: 'var(--muted)', opacity: 0.7 }}>
              Identifies publicly observable Microsoft 365 or Google Workspace tenant information.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
