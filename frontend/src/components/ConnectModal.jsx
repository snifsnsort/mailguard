import { useState } from 'react'
import { X, ExternalLink } from 'lucide-react'
import { api } from '../utils/api'

const PERMISSIONS = ['Policy.Read.All','Directory.Read.All','SecurityEvents.Read.All','ReportingWebService.Read.All','Exchange.ManageAsApp']

export default function ConnectModal({ onClose, onAdded }) {
  const [form, setForm]   = useState({ display_name:'', tenant_id:'', domain:'', client_id:'', client_secret:'' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const update = k => e => setForm(f => ({...f, [k]: e.target.value}))

  const submit = async () => {
    setError('')
    for (const [k,v] of Object.entries(form)) {
      if (!v.trim()) { setError(`${k.replace('_',' ')} is required.`); return }
    }
    setLoading(true)
    try {
      const tenant = await api.createTenant(form)
      onAdded(tenant)
    } catch(e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.75)',backdropFilter:'blur(4px)',zIndex:200,display:'flex',alignItems:'center',justifyContent:'center'}} onClick={e => e.target===e.currentTarget && onClose()}>
      <div style={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:14,width:500,overflow:'hidden',animation:'slideUp .25s ease'}}>

        {/* Header */}
        <div style={{padding:'24px',borderBottom:'1px solid var(--border)',position:'relative'}}>
          <button onClick={onClose} style={{position:'absolute',top:18,right:18,background:'var(--surface2)',border:'1px solid var(--border)',color:'var(--muted)',width:28,height:28,borderRadius:6,cursor:'pointer',display:'flex',alignItems:'center',justifyContent:'center'}}>
            <X size={14}/>
          </button>
          <h2 style={{fontSize:17,fontWeight:600}}>Connect Microsoft 365 Tenant</h2>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:4}}>App-only OAuth 2.0 — read-only permissions, no user login required</p>
        </div>

        {/* Body */}
        <div style={{padding:24}}>
          {/* Provider toggle */}
          <div style={{display:'flex',gap:8,marginBottom:20}}>
            <button style={{flex:1,padding:10,borderRadius:8,border:'1px solid var(--accent)',background:'rgba(0,229,255,0.06)',color:'var(--accent)',cursor:'pointer',fontFamily:'var(--font-body)',fontSize:12}}>
              ☁ Microsoft 365
            </button>
            <button style={{flex:1,padding:10,borderRadius:8,border:'1px solid var(--border)',background:'transparent',color:'var(--muted)',cursor:'not-allowed',fontFamily:'var(--font-body)',fontSize:12,opacity:.5}} title="Coming in Phase 2">
              Google Workspace (Phase 2)
            </button>
          </div>

          {[
            { key:'display_name',  label:'Display Name',             placeholder:'Contoso Ltd' },
            { key:'tenant_id',     label:'Tenant ID (Azure AD GUID)', placeholder:'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
            { key:'domain',        label:'Primary Domain',            placeholder:'contoso.onmicrosoft.com' },
            { key:'client_id',     label:'Client ID (App Registration)', placeholder:'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' },
            { key:'client_secret', label:'Client Secret',             placeholder:'••••••••••••••••', type:'password' },
          ].map(f => (
            <div key={f.key} style={{marginBottom:14}}>
              <label style={{fontSize:10,letterSpacing:'1.5px',textTransform:'uppercase',color:'var(--muted)',display:'block',marginBottom:5}}>{f.label}</label>
              <input
                type={f.type || 'text'}
                value={form[f.key]}
                onChange={update(f.key)}
                placeholder={f.placeholder}
                style={{width:'100%',background:'var(--bg)',border:'1px solid var(--border)',color:'var(--text)',padding:'9px 12px',borderRadius:6,fontFamily:'var(--font-mono)',fontSize:11,outline:'none'}}
                onFocus={e=>e.target.style.borderColor='var(--accent)'}
                onBlur={e=>e.target.style.borderColor='var(--border)'}
              />
            </div>
          ))}

          <div style={{marginBottom:16}}>
            <label style={{fontSize:10,letterSpacing:'1.5px',textTransform:'uppercase',color:'var(--muted)',display:'block',marginBottom:6}}>Required API Permissions (Application)</label>
            <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
              {PERMISSIONS.map(p => (
                <span key={p} style={{fontSize:10,fontFamily:'var(--font-mono)',padding:'3px 8px',background:'rgba(123,97,255,0.1)',border:'1px solid rgba(123,97,255,0.3)',borderRadius:4,color:'var(--accent2)'}}>{p}</span>
              ))}
            </div>
          </div>

          <a href="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app" target="_blank" rel="noopener noreferrer"
            style={{display:'inline-flex',alignItems:'center',gap:6,fontSize:11,color:'var(--accent)',textDecoration:'none'}}>
            <ExternalLink size={12}/> How to register an Azure AD app
          </a>

          {error && <div style={{marginTop:12,padding:'10px 14px',background:'rgba(255,79,94,0.1)',border:'1px solid rgba(255,79,94,0.3)',borderRadius:6,fontSize:12,color:'var(--red)'}}>{error}</div>}
        </div>

        {/* Footer */}
        <div style={{padding:'14px 24px',borderTop:'1px solid var(--border)',display:'flex',justifyContent:'flex-end',gap:10}}>
          <button onClick={onClose} style={{padding:'8px 18px',borderRadius:6,fontSize:13,cursor:'pointer',border:'1px solid var(--border)',background:'transparent',color:'var(--muted)',fontFamily:'var(--font-body)'}}>Cancel</button>
          <button onClick={submit} disabled={loading} style={{padding:'8px 20px',borderRadius:6,fontSize:13,fontWeight:700,cursor:loading?'wait':'pointer',background:'var(--accent)',color:'#000',border:'none',fontFamily:'var(--font-body)',opacity:loading?.7:1}}>
            {loading ? 'Connecting...' : 'Connect Tenant'}
          </button>
        </div>
      </div>
      <style>{`@keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}`}</style>
    </div>
  )
}
