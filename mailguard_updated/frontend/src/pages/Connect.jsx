import { useEffect, useState } from 'react'

export default function Connect() {
  const [showManual, setShowManual] = useState(false)

  useEffect(() => {
    document.title = 'MailGuard — Connect Tenant'
  }, [])

  return (
    <div style={{
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      background: '#0a0a0f', color: '#e8eaf0', minHeight: '100vh',
      display: 'flex', flexDirection: 'column',
      marginLeft: '-220px', width: '100vw',
      position: 'fixed', top: 0, left: 0, zIndex: 1000, overflowY: 'auto',
    }}>
      <div style={{
        position: 'fixed', width: 800, height: 800,
        background: 'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%)',
        top: '30%', left: '50%', transform: 'translate(-50%, -50%)', pointerEvents: 'none',
      }} />

      <section style={{
        flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', padding: '60px 24px', textAlign: 'center', position: 'relative',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 48 }}>
          <div style={{ width: 52, height: 52, background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 26 }}>🛡️</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>Mail<span style={{ color: '#6366f1' }}>Guard</span></div>
        </div>

        <h1 style={{ fontSize: 'clamp(28px, 5vw, 52px)', fontWeight: 800, lineHeight: 1.1, letterSpacing: -1.5, maxWidth: 700, marginBottom: 16 }}>
          Connect your email environment
        </h1>
        <p style={{ fontSize: 18, color: '#9ca3af', maxWidth: 520, lineHeight: 1.6, marginBottom: 52 }}>
          Choose your platform. You can connect both Microsoft 365 and Google Workspace to the same organization for a unified security score.
        </p>

        <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', justifyContent: 'center', marginBottom: 36 }}>
          <PlatformCard
            href="/api/auth/start"
            logo={<MsLogo size={44} />}
            name="Microsoft 365"
            desc="Exchange Online, Defender, Teams, SharePoint, Entra ID"
            btnLogo={<MsLogo size={16} />}
            btnText="Connect M365"
            hoverColor="rgba(99,102,241,0.6)"
            hoverBg="rgba(99,102,241,0.08)"
            note="OAuth · Read-only · Admin consent required"
          />
          <PlatformCard
            href="/api/v1/google/connect"
            logo={<GoogleLogo size={44} />}
            name="Google Workspace"
            desc="Gmail, Admin Console, Drive, 2SV enforcement, Alert Center"
            btnLogo={<GoogleLogo size={16} />}
            btnText="Connect Google"
            hoverColor="rgba(52,168,83,0.6)"
            hoverBg="rgba(52,168,83,0.06)"
            note="OAuth · Read-only · Super Admin required"
          />
        </div>

        <button onClick={() => setShowManual(v => !v)} style={{ background: 'transparent', border: 'none', color: '#4b5563', fontSize: 13, cursor: 'pointer', textDecoration: 'underline', marginBottom: showManual ? 24 : 0 }}>
          {showManual ? '▲ Hide manual setup' : '▼ Connect manually (enter credentials yourself)'}
        </button>

        {showManual && (
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24, maxWidth: 480, width: '100%', textAlign: 'left' }}>
            <p style={{ fontSize: 13, color: '#6b7280', marginBottom: 16 }}>Use this if OAuth onboarding isn't available. You'll need your Azure AD tenant ID, app client ID and secret.</p>
            <ManualForm />
          </div>
        )}
      </section>

      <div style={{ maxWidth: 900, margin: '0 auto', padding: '0 24px 64px' }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 24, textAlign: 'center' }}>What MailGuard checks</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
          {[
            { icon: '📧', name: 'SPF / DKIM / DMARC', desc: 'Email authentication controls' },
            { icon: '🔐', name: 'MFA Enforcement', desc: 'Admin & user account protection' },
            { icon: '🚦', name: 'MX Gateway', desc: 'Mail routing & SEG bypass risk' },
            { icon: '🔍', name: 'Lookalike Domains', desc: 'Typosquat threat detection' },
            { icon: '🛑', name: 'Legacy Auth', desc: 'Old protocols that bypass MFA' },
            { icon: '🔗', name: 'Safe Links & ATP', desc: 'Defender URL & attachment scanning' },
            { icon: '👥', name: 'Teams / External', desc: 'Collaboration access controls' },
            { icon: '📁', name: 'SharePoint Sharing', desc: 'External data exposure risks' },
          ].map(c => (
            <div key={c.name} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, padding: 16 }}>
              <div style={{ fontSize: 20, marginBottom: 8 }}>{c.icon}</div>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 3 }}>{c.name}</div>
              <div style={{ fontSize: 12, color: '#6b7280' }}>{c.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <footer style={{ textAlign: 'center', padding: 24, color: '#374151', fontSize: 12, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        MailGuard · Read-only access · No changes made to your environment
      </footer>
    </div>
  )
}

function PlatformCard({ href, logo, name, desc, btnLogo, btnText, hoverColor, hoverBg, note }) {
  const [hovered, setHovered] = useState(false)
  return (
    <a href={href} style={{ textDecoration: 'none' }}>
      <div
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          width: 280, background: hovered ? hoverBg : 'rgba(255,255,255,0.04)',
          border: `1px solid ${hovered ? hoverColor : 'rgba(255,255,255,0.12)'}`,
          borderRadius: 16, padding: '32px 28px', cursor: 'pointer',
          transition: 'all .2s', textAlign: 'center',
        }}
      >
        <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'center' }}>{logo}</div>
        <div style={{ fontSize: 18, fontWeight: 700, color: '#e8eaf0', marginBottom: 8 }}>{name}</div>
        <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.5, marginBottom: 20 }}>{desc}</div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: '#ffffff', color: '#1a1a2e', fontSize: 14, fontWeight: 600, padding: '10px 20px', borderRadius: 8 }}>
          {btnLogo}{btnText}
        </div>
        <div style={{ fontSize: 11, color: '#4b5563', marginTop: 10 }}>{note}</div>
      </div>
    </a>
  )
}

function ManualForm() {
  const [form, setForm] = useState({ display_name: '', tenant_id: '', domain: '', client_id: '', client_secret: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const submit = async () => {
    setLoading(true); setError(null)
    try {
      const token = localStorage.getItem('mg_token')
      const res = await fetch('/api/v1/tenants/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(form),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed')
      window.location.href = '/'
    } catch (e) { setError(e.message); setLoading(false) }
  }

  const inp = (field, placeholder) => (
    <input placeholder={placeholder} value={form[field]} onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
      style={{ width: '100%', padding: '9px 12px', borderRadius: 7, fontSize: 13, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)', color: '#e8eaf0', outline: 'none', boxSizing: 'border-box', marginBottom: 10 }} />
  )

  return (
    <div>
      {inp('display_name', 'Organization name')}
      {inp('domain', 'Primary domain (e.g. contoso.com)')}
      {inp('tenant_id', 'Azure AD Tenant ID')}
      {inp('client_id', 'App Client ID')}
      {inp('client_secret', 'Client Secret')}
      {error && <p style={{ color: '#f87171', fontSize: 12, marginBottom: 8 }}>{error}</p>}
      <button onClick={submit} disabled={loading} style={{ width: '100%', padding: '10px', borderRadius: 7, fontSize: 14, fontWeight: 600, background: '#6366f1', color: '#fff', border: 'none', cursor: 'pointer' }}>
        {loading ? 'Connecting...' : 'Connect Manually'}
      </button>
    </div>
  )
}

function MsLogo({ size = 22 }) {
  return (
    <div style={{ width: size, height: size, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: size > 24 ? 3 : 2 }}>
      <div style={{ background: '#f25022', borderRadius: '2px 0 0 0' }} />
      <div style={{ background: '#7fba00', borderRadius: '0 2px 0 0' }} />
      <div style={{ background: '#00a4ef', borderRadius: '0 0 0 2px' }} />
      <div style={{ background: '#ffb900', borderRadius: '0 0 2px 0' }} />
    </div>
  )
}

function GoogleLogo({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  )
}
