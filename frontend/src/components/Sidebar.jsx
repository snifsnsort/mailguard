import { NavLink, useLocation } from 'react-router-dom'
import { useScope } from '../v2/context/ScopeContext'
import { LayoutDashboard, ShieldCheck, Clock, Plus, ChevronDown, LogOut, Globe, ScanSearch, Network, Activity } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../utils/api'
import { EXPOSURE_LABELS, PRODUCT_LABEL } from '../utils/uiLabels'

const S = {
  sidebar: { position:'fixed',left:0,top:0,bottom:0,width:220,background:'var(--surface)',borderRight:'1px solid var(--border)',display:'flex',flexDirection:'column',zIndex:10,padding:'0 0 24px' },
  logo: { padding:'24px 20px 20px',borderBottom:'1px solid var(--border)',marginBottom:16 },
  logoMark: { fontFamily:'var(--font-mono)',fontSize:18,fontWeight:700,color:'var(--accent)' },
  logoSub: { fontSize:10,color:'var(--muted)',letterSpacing:2,textTransform:'uppercase',marginTop:2 },
  section: { padding:'0 12px',marginBottom:8 },
  navItem: { display:'flex',alignItems:'center',gap:10,padding:'9px 10px',borderRadius:8,cursor:'pointer',fontSize:13.5,color:'var(--text)',transition:'all .15s ease',textDecoration:'none',border:'1px solid transparent',background:'transparent' },
  parentItem: { fontWeight:600 },
  childWrap: { display:'flex',flexDirection:'column',gap:2,paddingLeft:14,marginTop:4 },
  footer: { marginTop:'auto',padding:'0 12px' },
  tenantChip: { display:'flex',alignItems:'center',gap:8,padding:'10px 12px',background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:8,cursor:'pointer' },
  dot: { width:8,height:8,background:'var(--green)',borderRadius:'50%',boxShadow:'0 0 6px var(--green)',flexShrink:0 },
}

const flatHoverStyle = {
  color:'var(--text)',
  background:'rgba(0,229,255,0.035)',
  boxShadow:'inset 2px 0 0 rgba(0,229,255,0.22)',
}

const activeChildStyle = {
  color:'var(--accent)',
  background:'rgba(0,229,255,0.06)',
  boxShadow:'inset 2px 0 0 var(--accent)',
}

function groupForPath(pathname) {
  if (!pathname || pathname === '/') return null

  if (
    pathname.startsWith('/v2/mail-security') ||
    pathname.startsWith('/v2/mail-flow-security') ||
    pathname.startsWith('/v2/domain-exposure') ||
    pathname.startsWith('/v2/lookalike')
  ) {
    return 'surface'
  }

  if (
    pathname.startsWith('/old/dashboard') ||
    pathname.startsWith('/v2/exposure/mx') ||
    pathname.startsWith('/lookalike-scan') ||
    pathname.startsWith('/v2/mail-routing/routing') ||
    pathname.startsWith('/v2/mail-routing/tls')
  ) {
    return 'oldui'
  }

  if (pathname.startsWith('/configuration-drift')) {
    return 'drift'
  }

  if (pathname.startsWith('/checks') || pathname.startsWith('/history')) {
    return 'operations'
  }

  return null
}

function SidebarLink({ to, end = false, children, child = false }) {
  const [hovered, setHovered] = useState(false)

  return (
    <NavLink
      to={to}
      end={end}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={({ isActive }) => ({
        ...S.navItem,
        ...(child ? { paddingLeft: 14, fontSize: 13, marginLeft: 8 } : null),
        ...(hovered && !isActive ? flatHoverStyle : null),
        ...(isActive ? activeChildStyle : null),
      })}
    >
      {children}
    </NavLink>
  )
}

function ParentRow({ icon, label, expanded, onClick }) {
  const [hovered, setHovered] = useState(false)

  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        ...S.navItem,
        ...S.parentItem,
        width:'100%',
        border:'none',
        outline:'none',
        fontFamily:'var(--font-body)',
        ...(hovered ? flatHoverStyle : null),
        ...(expanded ? { color:'var(--accent)', background:'rgba(0,229,255,0.04)' } : null),
      }}
    >
      {icon}
      <span style={{ flex: 1, textAlign: 'left' }}>{label}</span>
      <ChevronDown size={13} style={{ transform: expanded ? 'rotate(0deg)' : 'rotate(-90deg)', transition:'transform .15s ease', flexShrink:0 }} />
    </button>
  )
}

function PlaceholderChild({ icon, label }) {
  const [hovered, setHovered] = useState(false)

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        ...S.navItem,
        paddingLeft: 22,
        fontSize: 13,
        marginLeft: 8,
        opacity: 0.72,
        cursor: 'default',
        ...(hovered ? flatHoverStyle : null),
      }}
    >
      {icon}
      <span style={{ flex: 1 }}>{label}</span>
      <span style={{ fontSize: 9, color: 'var(--muted)' }}>Soon</span>
    </div>
  )
}

function NavGroup({ groupId, icon, label, expandedGroup, setExpandedGroup, children }) {
  const expanded = expandedGroup === groupId

  return (
    <div style={S.section}>
      <ParentRow
        icon={icon}
        label={label}
        expanded={expanded}
        onClick={() => setExpandedGroup(current => current === groupId ? null : groupId)}
      />
      {expanded && <div style={S.childWrap}>{children}</div>}
    </div>
  )
}

export default function Sidebar({ tenants, activeTenant, setActiveTenant, onTenantDeleted, onLogout }) {
  const location = useLocation()
  const { activeDomain, setActiveDomain, selectableDomains } = useScope()
  const [showDomainPicker, setShowDomainPicker] = useState(false)
  const [showTenants, setShowTenants] = useState(false)
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)
  const [expandedGroup, setExpandedGroup] = useState(() => groupForPath(window.location.pathname))

  useEffect(() => {
    setExpandedGroup(groupForPath(location.pathname))
  }, [location.pathname])

  const handleDisconnect = async () => {
    if (!activeTenant) return
    setDisconnecting(true)
    try {
      await api.deleteTenant(activeTenant.id)
      setConfirmDisconnect(false)
      onTenantDeleted(activeTenant.id)
    } catch {
      alert('Failed to disconnect tenant')
    } finally {
      setDisconnecting(false)
    }
  }

  return (
    <aside style={S.sidebar}>
      <div style={S.logo}>
        <div style={S.logoMark}>MailGuard</div>
        <div style={S.logoSub}>{PRODUCT_LABEL}</div>
      </div>

      <div style={S.section}>
        <SidebarLink to="/" end>
          <LayoutDashboard size={15} /> Dashboard
        </SidebarLink>
      </div>

      {activeTenant && (
        <NavGroup
          groupId="surface"
          icon={<Globe size={15} />}
          label={EXPOSURE_LABELS.surface}
          expandedGroup={expandedGroup}
          setExpandedGroup={setExpandedGroup}
        >
          <SidebarLink to="/v2/mail-security" child>
            <Network size={14} /> Email Controls
          </SidebarLink>
          <SidebarLink to="/v2/domain-exposure" child>
            <ScanSearch size={14} /> Domain Exposure
          </SidebarLink>
        </NavGroup>
      )}

      {activeTenant && (
        <NavGroup
          groupId="oldui"
          icon={<Globe size={15} />}
          label="OLD UI"
          expandedGroup={expandedGroup}
          setExpandedGroup={setExpandedGroup}
        >
          <SidebarLink to="/old/dashboard" child>
            <LayoutDashboard size={14} /> Legacy Dashboard
          </SidebarLink>
          <SidebarLink to="/v2/exposure/mx" child>
            <Network size={14} /> MX Health
          </SidebarLink>
          <SidebarLink to="/lookalike-scan" child>
            <ScanSearch size={14} /> Lookalike Scanner
          </SidebarLink>
          <SidebarLink to="/v2/mail-routing/routing" child>
            <Network size={14} /> Mail Routing
          </SidebarLink>
          <SidebarLink to="/v2/mail-routing/tls" child>
            <Network size={14} /> TLS Security
          </SidebarLink>
        </NavGroup>
      )}

      {activeTenant && (
        <NavGroup
          groupId="drift"
          icon={<Activity size={15} />}
          label="Change & Drift"
          expandedGroup={expandedGroup}
          setExpandedGroup={setExpandedGroup}
        >
          <PlaceholderChild icon={<Activity size={14} />} label="Configuration Drift" />
        </NavGroup>
      )}

      <NavGroup
        groupId="operations"
        icon={<ShieldCheck size={15} />}
        label="Operations"
        expandedGroup={expandedGroup}
        setExpandedGroup={setExpandedGroup}
      >
        <SidebarLink to="/checks" child>
          <ShieldCheck size={14} /> {EXPOSURE_LABELS.findings}
        </SidebarLink>
        <SidebarLink to="/history" child>
          <Clock size={14} /> Scan History
        </SidebarLink>
      </NavGroup>

      {selectableDomains.length > 0 && (
        <div style={{ padding: '0 12px', marginBottom: 8 }}>
          <div style={{ ...S.navItem, cursor: 'default', paddingLeft: 10, fontSize: 11, color: 'var(--muted)', fontWeight: 600 }}>
            <Globe size={12} /> Active Domain
          </div>
          {selectableDomains.length === 1 ? (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '7px 10px', borderRadius: 8, fontSize: 12,
              background: 'rgba(0,229,255,0.05)',
              color: 'var(--accent)', fontFamily: 'var(--font-mono)',
              marginLeft: 8,
            }}>
              <Globe size={11} />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {activeDomain}
              </span>
            </div>
          ) : (
            <div style={{ position: 'relative', marginLeft: 8 }}>
              <button
                onClick={() => setShowDomainPicker(v => !v)}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  width: '100%', padding: '7px 10px', borderRadius: 8, fontSize: 12,
                  background: 'rgba(0,229,255,0.05)', border: '1px solid rgba(0,229,255,0.15)',
                  color: 'var(--accent)', cursor: 'pointer', fontFamily: 'var(--font-mono)',
                  gap: 6,
                }}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
                  <Globe size={11} style={{ flexShrink: 0 }} />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {activeDomain || 'Select domain'}
                  </span>
                </span>
                <ChevronDown size={11} style={{ flexShrink: 0, transform: showDomainPicker ? 'rotate(180deg)' : 'none', transition: 'transform .15s' }} />
              </button>
              {showDomainPicker && (
                <div style={{
                  position: 'absolute', bottom: '100%', left: 0, right: 0, marginBottom: 4,
                  background: 'var(--surface)', border: '1px solid var(--border)',
                  borderRadius: 6, overflow: 'hidden', zIndex: 20,
                  boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
                }}>
                  {selectableDomains.map(d => (
                    <div
                      key={d}
                      onClick={() => { setActiveDomain(d); setShowDomainPicker(false) }}
                      style={{
                        padding: '8px 12px', fontSize: 12, cursor: 'pointer',
                        fontFamily: 'var(--font-mono)',
                        color: d === activeDomain ? 'var(--accent)' : 'var(--text)',
                        background: d === activeDomain ? 'rgba(0,229,255,0.06)' : 'transparent',
                        display: 'flex', alignItems: 'center', gap: 6,
                        transition: 'background .15s ease, color .15s ease, box-shadow .15s ease',
                        boxShadow: d === activeDomain ? 'inset 2px 0 0 var(--accent)' : 'none',
                      }}
                      onMouseEnter={e => {
                        if (d !== activeDomain) e.currentTarget.style.background = 'rgba(0,229,255,0.035)'
                      }}
                      onMouseLeave={e => {
                        if (d !== activeDomain) e.currentTarget.style.background = 'transparent'
                      }}
                    >
                      {d === activeDomain && <span style={{ fontSize: 8 }}>•</span>}
                      {d}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div style={S.footer}>
        {tenants.length > 1 && (
          <div style={{marginBottom:8}}>
            <button
              onClick={() => setShowTenants(v => !v)}
              style={{...S.tenantChip, width:'100%', justifyContent:'space-between', background:'transparent'}}
            >
              <span style={{fontSize:11,color:'var(--text)'}}>Switch tenant</span>
              <ChevronDown size={12} color="var(--muted)" />
            </button>
            {showTenants && (
              <div style={{background:'var(--bg)',border:'1px solid var(--border)',borderRadius:6,marginTop:4}}>
                {tenants.map(t => (
                  <div key={t.id} onClick={() => { setActiveTenant(t); setShowTenants(false) }} style={{...S.navItem, borderRadius:0, ...(activeTenant?.id === t.id ? {color:'var(--accent)'} : {})}}>
                    {t.display_name}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div style={S.tenantChip} onClick={activeTenant ? undefined : () => window.location.href = '/connect'}>
          {activeTenant ? (
            <>
              <div style={S.dot} />
              <div style={{flex:1, minWidth:0}}>
                <div style={{fontSize:12,fontWeight:500,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{activeTenant.display_name}</div>
                <div style={{fontSize:10,color:'var(--muted)'}}>{activeTenant.domain}</div>
              </div>
              <button onClick={(e) => { e.stopPropagation(); setConfirmDisconnect(true) }} title="Disconnect tenant" style={{background:'none',border:'none',cursor:'pointer',padding:2,display:'flex',alignItems:'center',color:'var(--muted)',flexShrink:0}}>
                <LogOut size={13} />
              </button>
            </>
          ) : (
            <>
              <Plus size={14} color="var(--accent)" />
              <div style={{fontSize:12,color:'var(--accent)'}}>Connect Tenant</div>
            </>
          )}
        </div>

        {activeTenant && (
          <button onClick={() => window.location.href = '/connect'} style={{ display:'flex',alignItems:'center',gap:8,padding:'8px 12px',borderRadius:6,cursor:'pointer',fontSize:12,width:'100%',marginTop:6,justifyContent:'center',background:'transparent',border:'1px solid var(--accent)',color:'var(--accent)',fontFamily:'var(--font-body)',transition:'all .15s' }} onMouseEnter={e => { e.currentTarget.style.background='rgba(0,229,255,0.08)' }} onMouseLeave={e => { e.currentTarget.style.background='transparent' }}>
            <Plus size={13} /> Add Tenant
          </button>
        )}

        {onLogout && (
          <button onClick={onLogout} style={{ display:'flex',alignItems:'center',gap:8,padding:'8px 12px',borderRadius:6,cursor:'pointer',fontSize:12,width:'100%',marginTop:4,justifyContent:'center',background:'transparent',border:'1px solid var(--border)',color:'var(--muted)',fontFamily:'var(--font-body)',transition:'all .15s' }} onMouseEnter={e => { e.currentTarget.style.borderColor='var(--red)'; e.currentTarget.style.color='var(--red)' }} onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.color='var(--muted)' }}>
            <LogOut size={13} /> Sign Out
          </button>
        )}
      </div>

      {confirmDisconnect && (
        <div style={{ position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',zIndex:1000,display:'flex',alignItems:'center',justifyContent:'center' }}>
          <div style={{ background:'var(--surface)',border:'1px solid var(--border)',borderRadius:12,padding:24,maxWidth:320,width:'90%' }}>
            <div style={{fontSize:15,fontWeight:600,marginBottom:8}}>Disconnect tenant?</div>
            <div style={{fontSize:13,color:'var(--muted)',marginBottom:20}}>
              This will remove <strong>{activeTenant?.display_name}</strong> from MailGuard.
              You can reconnect anytime via /connect.
            </div>
            <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
              <button onClick={() => setConfirmDisconnect(false)} style={{padding:'8px 16px',borderRadius:6,border:'1px solid var(--border)',background:'none',color:'var(--text)',cursor:'pointer',fontSize:13}}>
                Cancel
              </button>
              <button onClick={handleDisconnect} disabled={disconnecting} style={{padding:'8px 16px',borderRadius:6,border:'none',background:'#ef4444',color:'#fff',cursor:'pointer',fontSize:13,fontWeight:600}}>
                {disconnecting ? 'Disconnecting…' : 'Disconnect'}
              </button>
            </div>
          </div>
        </div>
      )}
    </aside>
  )
}
