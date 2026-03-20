import { Routes, Route, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import DashboardConcept from './pages/DashboardConcept'
import DashboardConceptBold from './pages/DashboardConceptBold'
import Checks from './pages/Checks'
import History from './pages/History'
import Connect from './pages/Connect'
import LookalikeScan from './pages/LookalikeScan'

// ── V2 pages ──────────────────────────────────────────────────────────────────
import PublicIntelPage  from './v2/pages/public_intel/PublicIntelPage'
import MXAnalysisPage   from './v2/pages/exposure/MXAnalysisPage'
import AuthHealthPage   from './v2/pages/auth_health/AuthHealthPage'
import LookalikePage    from './v2/pages/dns_posture/LookalikePage'
import DnsPostureLayout from './v2/layouts/DnsPostureLayout'
import { DnsPostureProvider } from './v2/context/DnsPostureContext'
import { MailRoutingProvider } from './v2/context/MailRoutingContext'
import MailRoutingLayout from './v2/layouts/MailRoutingLayout'
import RoutingTopologyPage from './v2/pages/mail_routing/RoutingTopologyPage'
import TlsPosturePage from './v2/pages/mail_routing/TlsPosturePage'
import MailSecurityPage from './v2/pages/mail_flow/MailFlowSecurityPage'
import DomainExposurePage from './v2/pages/domain_exposure/DomainExposurePage'
import ConnectModal from './components/ConnectModal'
import LoginPage from './pages/LoginPage'
import { api } from './utils/api'
import { ScopeContext } from './v2/context/ScopeContext'

export default function App() {
  const [tenants, setTenants] = useState([])
  const [activeTenant, setActiveTenant] = useState(null)
  const [lastScan, setLastScan] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [showConnect, setShowConnect] = useState(false)
  const [authToken, setAuthToken] = useState(() => localStorage.getItem('mg_token'))
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [loadingScan, setLoadingScan] = useState(false)
  const navigate = useNavigate()

  // ── Active domain scope ───────────────────────────────────────────────────
  // activeDomain: the single domain selected for v2 module navigation (one at a time)
  // selectableDomains: full cached inventory from last sync (tenant.all_domains)
  const [activeDomain, setActiveDomainRaw] = useState('')
  const [selectableDomains, setSelectableDomains] = useState([])

  // Persist active domain selection in sessionStorage, keyed by tenant ID
  const setActiveDomain = (domain) => {
    const normalized = (domain || '').trim().toLowerCase()
    setActiveDomainRaw(normalized)
    if (activeTenant?.id) {
      sessionStorage.setItem(`scope_${activeTenant.id}`, normalized)
    }
  }

  // Load tenants on auth
  useEffect(() => {
    if (!authToken) return
    api.listTenants().then(ts => {
      setTenants(ts)
      if (ts.length > 0) setActiveTenant(ts[0])
    }).catch(() => {})
  }, [authToken])

  // When active tenant changes: restore persisted domain scope and update selectable list
  useEffect(() => {
    if (!activeTenant) {
      setSelectableDomains([])
      setActiveDomainRaw('')
      return
    }
    // Prefer all_domains property if present, fallback to manual construction
    const raw = activeTenant.all_domains && activeTenant.all_domains.length > 0
      ? activeTenant.all_domains
      : [activeTenant.domain, ...(activeTenant.extra_domains || [])]
    // Normalize: trim, lowercase, remove empties, deduplicate
    const seen = new Set()
    const allDomains = raw
      .map(d => (d || '').trim().toLowerCase())
      .filter(d => d && !seen.has(d) && seen.add(d))
    setSelectableDomains(allDomains)
    // Restore persisted domain selection for this tenant, or default to primary domain
    const persisted = (sessionStorage.getItem(`scope_${activeTenant.id}`) || '').trim().toLowerCase()
    if (persisted && allDomains.includes(persisted)) {
      setActiveDomainRaw(persisted)
    } else {
      setActiveDomainRaw(allDomains[0] || '')
    }
  }, [activeTenant?.id])

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

  // Not logged in — show login page
  if (!authToken) {
    return <LoginPage onLogin={handleLogin} />
  }

  return (
    <ScopeContext.Provider value={{
        activeDomain,
        setActiveDomain,
        selectableDomains,
        addToSelectableDomains: (domain) => {
          const normalized = (domain || '').trim().toLowerCase()
          if (normalized && !selectableDomains.includes(normalized)) {
            setSelectableDomains(prev => [...prev, normalized])
          }
        },
      }}>
    <MailRoutingProvider
      tenantId={activeTenant?.id ?? null}
      tenantPlatform={activeTenant?.has_m365 ? 'microsoft365' : activeTenant?.has_gws ? 'google_workspace' : 'global'}
    >
    <DnsPostureProvider>
    <div style={{display:'flex',minHeight:'100vh',position:'relative',zIndex:1}}>
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
      <main style={{marginLeft:220,flex:1,minHeight:'100vh'}}>
        <Routes>
          <Route path="/" element={
            <DashboardConceptBold
              tenant={activeTenant}
              scan={lastScan}
              scanning={scanning || loadingScan}
              onScan={handleScan}
              onAddTenant={() => setShowConnect(true)}
            />
          } />
          <Route path="/old/dashboard" element={
            <Dashboard
              tenant={activeTenant}
              scan={lastScan}
              scanning={scanning || loadingScan}
              onScan={handleScan}
              onAddTenant={() => setShowConnect(true)}
              token={authToken}
              selectableDomains={selectableDomains}
            />
          } />
          <Route path="/concept/dashboard" element={
            <DashboardConcept
              tenant={activeTenant}
              scan={lastScan}
              scanning={scanning || loadingScan}
              onScan={handleScan}
              onAddTenant={() => setShowConnect(true)}
              token={authToken}
            />
          } />
          <Route path="/concept/dashboard-bold" element={
            <DashboardConceptBold
              tenant={activeTenant}
              scan={lastScan}
              scanning={scanning || loadingScan}
              onScan={handleScan}
              onAddTenant={() => setShowConnect(true)}
            />
          } />
          <Route path="/checks"         element={<Checks scan={lastScan} token={authToken} />} />
          <Route path="/history"        element={<History tenant={activeTenant} token={authToken} />} />
          <Route path="/lookalike-scan" element={<LookalikeScan token={authToken} />} />
          <Route path="/connect"        element={<Connect />} />
          <Route path="/onboard"        element={<Connect />} />
          <Route path="/start"          element={<Connect />} />

          {/* V2 public intel — transitional direct-fetch */}
          <Route path="/v2/public-intel" element={<PublicIntelPage />} />
          <Route path="/v2/domain-exposure" element={<DomainExposurePage tenant={activeTenant} token={authToken} />} />
          <Route path="/v2/mail-security" element={<MailSecurityPage tenant={activeTenant} />} />
          <Route path="/v2/mail-flow-security" element={<MailSecurityPage tenant={activeTenant} />} />

          {/* V2 Mail Routing Status — nested under shared layout */}
          <Route path="/v2/mail-routing" element={<MailRoutingLayout />}>
            <Route path="routing" element={<RoutingTopologyPage />} />
            <Route path="tls"     element={<TlsPosturePage />} />
          </Route>

          {/* V2 DNS Posture — nested under shared layout */}
          <Route path="/v2" element={<DnsPostureLayout />}>
            <Route path="auth-health"  element={<AuthHealthPage />} />
            <Route path="exposure/mx"  element={<MXAnalysisPage />} />
            <Route path="lookalike"    element={<LookalikePage />} />
          </Route>
        </Routes>
      </main>
      {showConnect && <ConnectModal onClose={() => setShowConnect(false)} onAdded={handleTenantAdded} />}
    </div>
    </DnsPostureProvider>
    </MailRoutingProvider>
    </ScopeContext.Provider>
  )
}

