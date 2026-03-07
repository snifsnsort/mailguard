import { Routes, Route, useNavigate } from 'react-router-dom'
import { useState, useEffect, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Checks from './pages/Checks'
import History from './pages/History'
import Connect from './pages/Connect'
import LookalikeScan from './pages/LookalikeScan'
import ConnectModal from './components/ConnectModal'
import LoginPage from './pages/LoginPage'
import { api } from './utils/api'

export default function App() {
  const [tenants, setTenants] = useState([])
  const [activeTenant, setActiveTenant] = useState(null)
  const [lastScan, setLastScan] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [showConnect, setShowConnect] = useState(false)
  const [authToken, setAuthToken] = useState(() => localStorage.getItem('mg_token'))
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [loadingScan, setLoadingScan] = useState(false)
  const [notification, setNotification] = useState(null)
  const navigate = useNavigate()

  // Handle OAuth redirect results (M365 and Google)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const onboardError   = params.get('onboard_error')
    const onboardSuccess = params.get('onboard_success')
    const gwsError       = params.get('gws_error')
    const gwsConnected   = params.get('gws_connected')

    if (onboardError === 'config_error') {
      setNotification({ type: 'error', msg: 'M365 OAuth not configured on this server. Use the manual form or set MAILGUARD_CLIENT_ID in your .env.' })
    } else if (onboardError) {
      setNotification({ type: 'error', msg: 'M365 connection failed: ' + (params.get('detail') || onboardError) })
    } else if (onboardSuccess) {
      setNotification({ type: 'success', msg: 'Microsoft 365 tenant connected: ' + (params.get('domain') || '') })
    } else if (gwsError === 'not_configured') {
      setNotification({ type: 'error', msg: 'Google OAuth not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI in your .env.' })
    } else if (gwsError) {
      setNotification({ type: 'error', msg: 'Google Workspace connection failed: ' + gwsError })
    } else if (gwsConnected) {
      setNotification({ type: 'success', msg: 'Google Workspace connected successfully.' })
    }

    if (onboardError || onboardSuccess || gwsError || gwsConnected) {
      // Clean the query string from the URL without reloading
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [])

  // Load tenants on auth
  useEffect(() => {
    if (!authToken) return
    api.listTenants().then(ts => {
      setTenants(ts)
      if (ts.length > 0) setActiveTenant(ts[0])
    }).catch(() => {})
  }, [authToken])

  // Reload last scan whenever active tenant changes
  useEffect(() => {
    if (!activeTenant) { setLastScan(null); return }
    setLastScan(null)
    setLoadingScan(true)
    api.scanHistory(activeTenant.id)
      .then(async history => {
        const completed = (history || []).filter(s => s.status === 'completed')
        if (completed.length > 0) {
          const full = await api.scanResult(completed[0].id)
          setLastScan(full)
        }
      })
      .catch(() => {})
      .finally(() => setLoadingScan(false))
  }, [activeTenant?.id])

  const handleLogin = (token, passwordChangeRequired) => {
    localStorage.setItem('mg_token', token)
    setAuthToken(token)
    setMustChangePassword(passwordChangeRequired)
  }

  const handleLogout = () => {
    localStorage.removeItem('mg_token')
    setAuthToken(null)
    setTenants([])
    setActiveTenant(null)
    setLastScan(null)
  }

  const handleTenantAdded = (tenant) => {
    setTenants(prev => [...prev, tenant])
    setActiveTenant(tenant)
    setShowConnect(false)
  }

  const handleTenantDeleted = (deletedId) => {
    const remaining = tenants.filter(t => t.id !== deletedId)
    setTenants(remaining)
    setActiveTenant(remaining.length > 0 ? remaining[0] : null)
    setLastScan(null)
    navigate('/')
  }

  const handleScan = async () => {
    if (!activeTenant || scanning) return
    setScanning(true)
    try {
      const { id: scanId } = await api.triggerScan(activeTenant.id)
      const poll = setInterval(async () => {
        const status = await api.scanStatus(scanId)
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(poll)
          if (status.status === 'completed') setLastScan(await api.scanResult(scanId))
          setScanning(false)
        }
      }, 2000)
    } catch (e) {
      setScanning(false)
    }
  }

  // /connect routes render fullscreen with no sidebar
  const path = window.location.pathname
  if (path === '/connect' || path === '/onboard' || path === '/start')
    return <Connect />

  if (!authToken) {
    return <LoginPage onLogin={handleLogin} />
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', position: 'relative', zIndex: 1 }}>
      <Sidebar
        tenants={tenants}
        activeTenant={activeTenant}
        setActiveTenant={setActiveTenant}
        onAddTenant={() => setShowConnect(true)}
        onTenantDeleted={handleTenantDeleted}
        onLogout={handleLogout}
        mustChangePassword={mustChangePassword}
        onPasswordChanged={() => setMustChangePassword(false)}
      />
      <main style={{ marginLeft: 220, flex: 1, minHeight: '100vh' }}>
        <Routes>
          <Route path="/" element={
            <Dashboard
              tenant={activeTenant}
              scan={lastScan}
              scanning={scanning || loadingScan}
              onScan={handleScan}
              onAddTenant={() => setShowConnect(true)}
              token={authToken}
            />
          } />
          <Route path="/checks"        element={<Checks scan={lastScan} token={authToken} />} />
          <Route path="/history"       element={<History tenant={activeTenant} token={authToken} />} />
          <Route path="/lookalike-scan" element={<LookalikeScan token={authToken} />} />
          <Route path="/connect"       element={<Connect />} />
          <Route path="/onboard"       element={<Connect />} />
          <Route path="/start"         element={<Connect />} />
        </Routes>
      </main>

      {showConnect && (
        <ConnectModal onClose={() => setShowConnect(false)} onAdded={handleTenantAdded} />
      )}

      {/* OAuth result notification banner */}
      {notification && (
        <div style={{
          position: 'fixed',
          top: 20,
          right: 20,
          zIndex: 9999,
          background: notification.type === 'error' ? '#450a0a' : '#052e16',
          border: `1px solid ${notification.type === 'error' ? '#ef4444' : '#22c55e'}`,
          color: '#f1f5f9',
          padding: '14px 18px',
          borderRadius: 10,
          maxWidth: 440,
          fontSize: 14,
          lineHeight: 1.5,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 12,
          boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
        }}>
          <span style={{ flex: 1 }}>{notification.msg}</span>
          <button
            onClick={() => setNotification(null)}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              fontSize: 18,
              lineHeight: 1,
              padding: 0,
              flexShrink: 0,
            }}
          >×</button>
        </div>
      )}
    </div>
  )
}
