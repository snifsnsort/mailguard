import { useState } from 'react'
import { api } from '../utils/api'

export default function LoginPage({ onLogin }) {
  const [username, setUsername]       = useState('')
  const [password, setPassword]       = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm]         = useState('')
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [step, setStep]               = useState('login') // 'login' | 'change'
  const [pendingToken, setPendingToken] = useState('')

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.login(username, password)
      if (res.must_change_password) {
        setPendingToken(res.token)
        setStep('change')
      } else {
        onLogin(res.token, false)
      }
    } catch (err) {
      setError(err.message || 'Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  const handleChangePassword = async (e) => {
    e.preventDefault()
    setError('')
    if (newPassword !== confirm) { setError('Passwords do not match'); return }
    if (newPassword.length < 8)  { setError('Password must be at least 8 characters'); return }
    setLoading(true)
    try {
      await api.changePassword(pendingToken, newPassword)
      onLogin(pendingToken, false)
    } catch (err) {
      setError(err.message || 'Failed to change password')
    } finally {
      setLoading(false)
    }
  }

  const S = {
    page:     { minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'var(--bg)' },
    card:     { width:360, background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:32 },
    logo:     { textAlign:'center', marginBottom:28 },
    logoMark: { fontFamily:'var(--font-mono)', fontSize:22, fontWeight:700, color:'var(--accent)' },
    logoSub:  { fontSize:10, color:'var(--muted)', letterSpacing:2, textTransform:'uppercase', marginTop:4 },
    label:    { display:'block', fontSize:12, color:'var(--muted)', marginBottom:6 },
    input:    { width:'100%', padding:'10px 12px', background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:6, color:'var(--text)', fontSize:13, fontFamily:'var(--font-body)', boxSizing:'border-box', outline:'none' },
    btn:      { width:'100%', padding:'11px', borderRadius:6, border:'none', background:'var(--accent)', color:'#000', fontSize:13, fontWeight:700, cursor:'pointer', fontFamily:'var(--font-body)', marginTop:8 },
    error:    { background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)', borderRadius:6, padding:'10px 12px', fontSize:12, color:'#ef4444', marginBottom:16 },
    field:    { marginBottom:16 },
    title:    { fontSize:16, fontWeight:600, marginBottom:4 },
    subtitle: { fontSize:12, color:'var(--muted)', marginBottom:20 },
  }

  return (
    <div style={S.page}>
      <div style={S.card}>
        <div style={S.logo}>
          <div style={S.logoMark}>MailGuard</div>
          <div style={S.logoSub}>Email Security Posture</div>
        </div>

        {step === 'login' && (
          <form onSubmit={handleLogin}>
            <div style={S.title}>Sign in</div>
            <div style={S.subtitle}>Enter your credentials to continue</div>
            {error && <div style={S.error}>{error}</div>}
            <div style={S.field}>
              <label style={S.label}>Username</label>
              <input style={S.input} value={username} onChange={e => setUsername(e.target.value)} autoFocus required />
            </div>
            <div style={S.field}>
              <label style={S.label}>Password</label>
              <input style={S.input} type="password" value={password} onChange={e => setPassword(e.target.value)} required />
            </div>
            <button style={S.btn} disabled={loading}>{loading ? 'Signing in...' : 'Sign In'}</button>
          </form>
        )}

        {step === 'change' && (
          <form onSubmit={handleChangePassword}>
            <div style={S.title}>Set new password</div>
            <div style={S.subtitle}>You must change your password before continuing.</div>
            {error && <div style={S.error}>{error}</div>}
            <div style={S.field}>
              <label style={S.label}>New password</label>
              <input style={S.input} type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} autoFocus required />
            </div>
            <div style={S.field}>
              <label style={S.label}>Confirm password</label>
              <input style={S.input} type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required />
            </div>
            <button style={S.btn} disabled={loading}>{loading ? 'Saving...' : 'Set Password'}</button>
          </form>
        )}
      </div>
    </div>
  )
}
