import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ShieldCheck, Clock, Plus, ChevronDown, LogOut } from 'lucide-react'
import { useState } from 'react'
import { api } from '../utils/api'

const S = {
  sidebar: { position:'fixed',left:0,top:0,bottom:0,width:220,background:'var(--surface)',borderRight:'1px solid var(--border)',display:'flex',flexDirection:'column',zIndex:10,padding:'0 0 24px' },
  logo: { padding:'24px 20px 20px',borderBottom:'1px solid var(--border)',marginBottom:16 },
  logoMark: { fontFamily:'var(--font-mono)',fontSize:18,fontWeight:700,color:'var(--accent)' },
  logoSub: { fontSize:10,color:'var(--muted)',letterSpacing:2,textTransform:'uppercase',marginTop:2 },
  section: { padding:'0 12px',marginBottom:8 },
  label: { fontSize:9,letterSpacing:2,textTransform:'uppercase',color:'var(--muted)',padding:'0 8px',marginBottom:6,display:'block' },
  navItem: { display:'flex',alignItems:'center',gap:10,padding:'9px 10px',borderRadius:6,cursor:'pointer',fontSize:13.5,color:'var(--text)',transition:'all .15s',border:'1px solid transparent',textDecoration:'none' },
  footer: { marginTop:'auto',padding:'0 12px' },
  tenantChip: { display:'flex',alignItems:'center',gap:8,padding:'10px 12px',background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:8,cursor:'pointer' },
  dot: { width:8,height:8,background:'var(--green)',borderRadius:'50%',boxShadow:'0 0 6px var(--green)',flexShrink:0 },
}

const activeStyle = { color:'var(--accent)',background:'rgba(0,229,255,0.06)',borderColor:'rgba(0,229,255,0.15)' }

export default function Sidebar({ tenants, activeTenant, setActiveTenant, onAddTenant, onTenantDeleted, onLogout }) {
  const [showTenants, setShowTenants] = useState(false)
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)

  const handleDisconnect = async () => {
    if (!activeTenant) return
    setDisconnecting(true)
    try {
      await api.deleteTenant(activeTenant.id)
      setConfirmDisconnect(false)
      onTenantDeleted(activeTenant.id)
    } catch (e) {
      alert('Failed to disconnect tenant')
    } finally {
      setDisconnecting(false)
    }
  }

  return (
    <aside style={S.sidebar}>
      <div style={S.logo}>
        <div style={S.logoMark}>MailGuard</div>
        <div style={S.logoSub}>Posture Management</div>
      </div>

      <div style={S.section}>
        <span style={S.label}>Navigate</span>
        <NavLink to="/" end style={({isActive}) => ({...S.navItem, ...(isActive ? activeStyle : {})})}>
          <LayoutDashboard size={15} /> Dashboard
        </NavLink>
        <NavLink to="/checks" style={({isActive}) => ({...S.navItem, ...(isActive ? activeStyle : {})})}>
          <ShieldCheck size={15} /> Security Checks
        </NavLink>
        <NavLink to="/history" style={({isActive}) => ({...S.navItem, ...(isActive ? activeStyle : {})})}>
          <Clock size={15} /> Scan History
        </NavLink>
      </div>

      <div style={S.footer}>
        {/* Tenant switcher */}
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
                  <div key={t.id} onClick={() => { setActiveTenant(t); setShowTenants(false) }}
                    style={{...S.navItem, borderRadius:0, ...(activeTenant?.id === t.id ? {color:'var(--accent)'} : {})}}>
                    {t.display_name}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tenant chip */}
        <div style={S.tenantChip} onClick={activeTenant ? undefined : () => window.location.href = '/connect'}>
          {activeTenant ? (
            <>
              <div style={S.dot} />
              <div style={{flex:1, minWidth:0}}>
                <div style={{fontSize:12,fontWeight:500,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{activeTenant.display_name}</div>
                <div style={{fontSize:10,color:'var(--muted)'}}>{activeTenant.domain}</div>
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); setConfirmDisconnect(true) }}
                title="Disconnect tenant"
                style={{background:'none',border:'none',cursor:'pointer',padding:2,display:'flex',alignItems:'center',color:'var(--muted)',flexShrink:0}}
              >
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

        {/* Add tenant button — only shown when a tenant is already active */}
        {activeTenant && (
          <button onClick={() => window.location.href = '/connect'} style={{...S.navItem, width:'100%', marginTop:6, justifyContent:'center', fontSize:12}}>
            <Plus size={13} /> Add Tenant
          </button>
        )}

        {/* Sign out */}
        {onLogout && (
          <button onClick={onLogout} style={{...S.navItem, width:'100%', marginTop:4, justifyContent:'center', fontSize:12, color:'var(--muted)'}}>
            <LogOut size={13} /> Sign Out
          </button>
        )}
      </div>

      {/* Disconnect confirmation modal */}
      {confirmDisconnect && (
        <div style={{
          position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',zIndex:1000,
          display:'flex',alignItems:'center',justifyContent:'center'
        }}>
          <div style={{
            background:'var(--surface)',border:'1px solid var(--border)',borderRadius:12,
            padding:24,maxWidth:320,width:'90%'
          }}>
            <div style={{fontSize:15,fontWeight:600,marginBottom:8}}>Disconnect tenant?</div>
            <div style={{fontSize:13,color:'var(--muted)',marginBottom:20}}>
              This will remove <strong>{activeTenant?.display_name}</strong> from MailGuard.
              You can reconnect anytime via /connect.
            </div>
            <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
              <button
                onClick={() => setConfirmDisconnect(false)}
                style={{padding:'8px 16px',borderRadius:6,border:'1px solid var(--border)',background:'none',color:'var(--text)',cursor:'pointer',fontSize:13}}
              >
                Cancel
              </button>
              <button
                onClick={handleDisconnect}
                disabled={disconnecting}
                style={{padding:'8px 16px',borderRadius:6,border:'none',background:'#ef4444',color:'#fff',cursor:'pointer',fontSize:13,fontWeight:600}}
              >
                {disconnecting ? 'Disconnecting…' : 'Disconnect'}
              </button>
            </div>
          </div>
        </div>
      )}
    </aside>
  )
}
