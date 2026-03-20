/**
 * LookalikePage.tsx — MailGuard V2
 *
 * Lookalike scan is part of the dns_posture target-state task set
 * (mx_health + authentication_status + lookalike_scan) but is operationally
 * deferred in the first executable implementation.
 *
 * This page holds the nav slot and will render real results when
 * lookalike_scan is registered in task_registry.py.
 */

import { useDnsPosture } from '../../context/DnsPostureContext'

export default function LookalikePage() {
  const { jobDomain } = useDnsPosture()

  return (
    <div style={{ padding: '48px 32px', maxWidth: 600 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600 }}>Lookalike Scanner</h1>
        <span style={{
          padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 500,
          background: 'rgba(148,163,184,0.08)', color: '#94a3b8',
          border: '1px solid rgba(148,163,184,0.2)',
        }}>
          Coming Soon
        </span>
      </div>

      <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.7, marginBottom: 24 }}>
        Lookalike domain detection is part of the <strong style={{ color: 'var(--text)' }}>dns_posture</strong> scan
        family and will run automatically alongside MX Health and Authentication Status.
      </p>

      <div style={{
        padding: '20px 24px', borderRadius: 10,
        background: 'var(--surface)', border: '1px solid var(--border)',
      }}>
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
          What's coming
        </div>
        {[
          'Typosquat and homoglyph domain detection',
          'Active MX record verification on discovered domains',
          'Risk scoring per lookalike candidate',
          'Integration with the dns_posture batch — no separate trigger needed',
        ].map((item, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: 10,
            padding: '8px 0', borderBottom: i < 3 ? '1px solid var(--border)' : 'none',
            fontSize: 13, color: 'var(--text)',
          }}>
            <span style={{ color: '#94a3b8', flexShrink: 0 }}>○</span>
            {item}
          </div>
        ))}
      </div>

      {jobDomain && (
        <div style={{ marginTop: 20, fontSize: 11, color: 'var(--muted)' }}>
          Will scan: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{jobDomain}</span>
        </div>
      )}
    </div>
  )
}
