import React, { useState, useEffect } from 'react'
import { RadialBarChart, RadialBar, ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts'
import { RefreshCw, Plus, Download, Shield, AlertTriangle, CheckCircle, Info , Globe} from 'lucide-react'
import CheckRow from '../components/CheckRow'
import DetailPanel from '../components/DetailPanel'
import { api } from '../utils/api'

const SCAN_STEPS = [
  'Connecting to Exchange Online...','Authenticating via Graph API...',
  'Fetching accepted domains...','Checking SPF records...',
  'Validating DKIM selectors...','Inspecting DMARC policies...',
  'Scanning anti-phishing policies...','Reviewing anti-spam configuration...',
  'Checking Safe Links policies...','Auditing Safe Attachments...',
  'Reviewing MFA enrollment...','Checking Conditional Access policies...',
  'Inspecting legacy auth settings...','Auditing direct send configuration...',
  'Compiling results...'
]

function gradeColor(g) {
  if (!g) return 'var(--muted)'
  if (g === 'A') return 'var(--green)'
  if (g === 'B') return 'var(--accent)'
  if (g === 'C') return 'var(--yellow)'
  return 'var(--red)'
}

export default function Dashboard({ tenant, scan, scanning, onScan, onAddTenant, token }) {
  const [syncing, setSyncing] = React.useState(false)
  const [syncMsg, setSyncMsg] = React.useState(null)

  const syncDomains = async () => {
    if (!tenant) return
    setSyncing(true); setSyncMsg(null)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`/api/v1/tenants/${tenant.id}/sync-domains`, { method: 'POST', headers })
      const data = await res.json()
      if (res.ok) {
        const n = (data.extra_domains || []).length
        setSyncMsg(`Found ${n + 1} domain${n ? 's' : ''} (${[data.domain, ...(data.extra_domains||[])].join(', ')})`)
        // Reload page so new tenant data is reflected
        setTimeout(() => window.location.reload(), 1500)
      } else {
        setSyncMsg(data.detail || 'Sync failed')
      }
    } catch (e) { setSyncMsg('Sync failed') }
    finally { setSyncing(false) }
  }
  const [selectedCheck, setSelectedCheck] = useState(null)
  const [activeTab, setActiveTab]         = useState('all')
  const [scanStep, setScanStep]           = useState(0)

  // Handle redirect back from Google OAuth
  useEffect(() => {
    const p = new URLSearchParams(window.location.search)
    if (p.get('gws_connected') === '1') {
      window.history.replaceState({}, '', '/')
      window.location.reload()
    }
    if (p.get('gws_error')) {
      alert('Google Workspace connection failed: ' + p.get('gws_error'))
      window.history.replaceState({}, '', '/')
    }
  }, [])

  // isGws: GWS-only tenant (no M365). Dual-platform tenants run M365 checks so sync domains is still useful.
  const isGws = tenant?.has_gws && !tenant?.has_m365

  const findings         = scan?.findings || []
  const critical  = findings.filter(f => f.status === 'fail').length
  const warnings  = findings.filter(f => f.status === 'warn').length
  const passing   = findings.filter(f => f.status === 'pass').length
  const score     = scan?.score ?? null
  const grade     = scan?.grade ?? null

  const filtered = activeTab === 'all' ? findings
    : findings.filter(f => f.status === activeTab)

  // Scan animation
  const startScan = () => {
    setScanStep(0)
    onScan()
    let i = 0
    const iv = setInterval(() => {
      i++
      setScanStep(i)
      if (i >= SCAN_STEPS.length - 1) clearInterval(iv)
    }, 900)
  }

  const tabs = [
    { key:'all',  label:'All Checks', count: findings.length },
    { key:'fail', label:'Critical',   count: critical },
    { key:'warn', label:'Warnings',   count: warnings },
    { key:'pass', label:'Passing',    count: passing },
  ]

  return (
    <div>
      {/* Topbar */}
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'18px 32px',borderBottom:'1px solid var(--border)',background:'rgba(8,12,18,0.85)',backdropFilter:'blur(10px)',position:'sticky',top:0,zIndex:5}}>
        <div>
          <h1 style={{fontSize:20,fontWeight:600}}>Security Posture Dashboard</h1>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:2}}>
            {tenant ? `${tenant.display_name} · ${(tenant.extra_domains||[]).length > 0 ? `${1+(tenant.extra_domains||[]).length} domains` : tenant.domain}` : 'No tenant connected'}
            {tenant && (
              <span style={{marginLeft:8}}>
                {tenant.has_m365 && <span style={{fontSize:10,padding:'1px 6px',borderRadius:4,background:'rgba(0,120,212,0.15)',color:'#4fc3f7',marginRight:4}}>M365</span>}
                {tenant.has_gws && <span style={{fontSize:10,padding:'1px 6px',borderRadius:4,background:'rgba(52,168,83,0.15)',color:'#81c784'}}>GWS</span>}
              </span>
            )}
          </p>
          {syncMsg && <p style={{fontSize:11,color:'var(--accent)',marginTop:2}}>{syncMsg}</p>}
        </div>
        <div style={{display:'flex',alignItems:'center',gap:12}}>
          {scan && (
            <button onClick={async()=>{
                try{
                  const res=await fetch(api.reportPdfUrl(scan.id),{headers:api.authHeaders()});
                  if(!res.ok){
                    const txt=await res.text().catch(()=>res.statusText);
                    throw new Error(`Server error ${res.status}: ${txt}`);
                  }
                  const blob=await res.blob();
                  if(blob.size===0)throw new Error('Empty response from server');
                  const url=URL.createObjectURL(blob);
                  const a=document.createElement('a');
                  const cd=res.headers.get('content-disposition')||'';
                  const m=cd.match(/filename="([^"]+)"/);
                  const dt=new Date().toISOString().slice(0,16).replace('T','-').replace(/:/g,'');
                  a.download=m?m[1]:`mailguard-report-${dt}.pdf`;
                  a.href=url;document.body.appendChild(a);a.click();
                  setTimeout(()=>{document.body.removeChild(a);URL.revokeObjectURL(url);},100);
                }catch(e){alert('Failed to download report: '+e.message);}
              }} style={{display:'flex',alignItems:'center',gap:6,padding:'8px 14px',borderRadius:6,fontSize:13,border:'1px solid var(--border)',background:'transparent',color:'var(--text)',cursor:'pointer',transition:'all .15s'}}
              onMouseOver={e=>{e.currentTarget.style.borderColor='var(--accent)';e.currentTarget.style.color='var(--accent)'}}
              onMouseOut={e=>{e.currentTarget.style.borderColor='var(--border)';e.currentTarget.style.color='var(--text)'}}>
              <Download size={13}/> Export PDF
            </button>
          )}
          {!tenant ? (
            <button onClick={onAddTenant} style={{display:'flex',alignItems:'center',gap:6,padding:'8px 18px',borderRadius:6,fontSize:13,fontWeight:700,cursor:'pointer',background:'transparent',color:'var(--muted)',border:'1px solid var(--border)',fontFamily:'var(--font-body)'}}>
              <Plus size={13}/> Connect Manually
            </button>
          ) : (<>
            {tenant && !tenant.has_gws && (
              <button onClick={() => window.location.href = '/api/v1/google/connect'} title="Add Google Workspace to this tenant" style={{display:'flex',alignItems:'center',gap:6,padding:'8px 12px',borderRadius:6,fontSize:12,cursor:'pointer',background:'transparent',color:'var(--muted)',border:'1px solid var(--border)',fontFamily:'var(--font-body)'}}>
                <svg width="12" height="12" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
                + Google Workspace
              </button>
            )}
            {tenant && tenant.has_m365 && !isGws && <button onClick={syncDomains} disabled={syncing} title="Auto-discover all verified domains from Microsoft 365" style={{display:'flex',alignItems:'center',gap:6,padding:'8px 14px',borderRadius:6,fontSize:12,cursor:syncing?'wait':'pointer',background:'transparent',color:'var(--muted)',border:'1px solid var(--border)',fontFamily:'var(--font-body)',opacity:syncing?.7:1}}>
              <Globe size={12} style={{animation:syncing?'spin 1s linear infinite':''}}/> {syncing ? 'Syncing...' : 'Sync Domains'}
            </button>}
            <button onClick={startScan} disabled={scanning} style={{display:'flex',alignItems:'center',gap:6,padding:'8px 18px',borderRadius:6,fontSize:13,fontWeight:700,cursor:scanning?'wait':'pointer',background:'var(--accent)',color:'#000',border:'none',fontFamily:'var(--font-body)',opacity:scanning?.7:1}}>
              <RefreshCw size={13} style={{animation:scanning?'spin 1s linear infinite':''}}/> {scanning ? 'Scanning...' : 'Run Scan'}
            </button>
          </>)}
        </div>
      </div>

      <div style={{padding:'28px 32px'}}>

        {/* Scan progress */}
        {scanning && (
          <div style={{marginBottom:20,background:'var(--surface)',border:'1px solid var(--border)',borderRadius:10,padding:'16px 20px',animation:'fadeIn .3s ease'}}>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:12,color:'var(--muted)',marginBottom:8}}>
              <span>Scanning tenant configuration...</span>
              <span style={{fontFamily:'var(--font-mono)'}}>{Math.round(((scanStep+1)/SCAN_STEPS.length)*100)}%</span>
            </div>
            <div style={{height:4,background:'var(--surface2)',borderRadius:2,overflow:'hidden'}}>
              <div style={{height:'100%',background:'linear-gradient(90deg,var(--accent),var(--accent2))',borderRadius:2,width:`${Math.round(((scanStep+1)/SCAN_STEPS.length)*100)}%`,transition:'width .4s ease'}}/>
            </div>
            <div style={{fontFamily:'var(--font-mono)',fontSize:11,color:'var(--accent)',marginTop:6}}>{SCAN_STEPS[scanStep]}</div>
          </div>
        )}

        {/* No tenant state */}
        {!tenant && (
          <div style={{textAlign:'center',padding:'80px 0'}}>
            <Shield size={48} color="var(--muted)" style={{margin:'0 auto 16px'}}/>
            <h2 style={{fontSize:18,fontWeight:600,marginBottom:8}}>No tenant connected</h2>
            <p style={{color:'var(--muted)',marginBottom:24}}>Connect your Microsoft 365 or Google Workspace tenant to start scanning.</p>
            <div style={{display:'flex',gap:12,justifyContent:'center',flexWrap:'wrap'}}>
              <button onClick={() => window.location.href = '/connect'} style={{display:'flex',alignItems:'center',gap:8,padding:'10px 24px',borderRadius:6,fontSize:14,fontWeight:700,cursor:'pointer',background:'var(--accent)',color:'#000',border:'none',fontFamily:'var(--font-body)'}}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M21 3H3a2 2 0 00-2 2v14a2 2 0 002 2h18a2 2 0 002-2V5a2 2 0 00-2-2zm-9 3c1.93 0 3.5 1.57 3.5 3.5S13.93 13 12 13s-3.5-1.57-3.5-3.5S10.07 6 12 6zm7 13H5v-.23c0-.62.28-1.2.76-1.58C7.47 15.82 9.64 15 12 15s4.53.82 6.24 2.19c.48.38.76.97.76 1.58V19z"/></svg>
                Connect Microsoft 365
              </button>
              <button onClick={() => window.location.href = '/api/v1/google/connect'} style={{display:'flex',alignItems:'center',gap:8,padding:'10px 24px',borderRadius:6,fontSize:14,fontWeight:700,cursor:'pointer',background:'#fff',color:'#333',border:'1px solid var(--border)',fontFamily:'var(--font-body)'}}>
                <svg width="16" height="16" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
                Connect Google Workspace
              </button>
            </div>
          </div>
        )}

        {/* Score hero */}
        {tenant && (
          <>
            <div style={{display:'grid',gridTemplateColumns:'240px 1fr',gap:16,marginBottom:24}}>
              {/* Score card */}
              <div style={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:12,padding:24,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'}}>
                <div style={{position:'relative',width:120,height:120,marginBottom:12}}>
                  <svg width="120" height="120" viewBox="0 0 100 100" style={{transform:'rotate(-90deg)'}}>
                    <circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface2)" strokeWidth="8"/>
                    <circle cx="50" cy="50" r="42" fill="none"
                      stroke={gradeColor(grade)}
                      strokeWidth="8" strokeLinecap="round"
                      strokeDasharray="263.9"
                      strokeDashoffset={score != null ? 263.9 * (1 - score/100) : 263.9}
                      style={{transition:'stroke-dashoffset .8s ease'}}
                    />
                  </svg>
                  <div style={{position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'}}>
                    <div style={{fontFamily:'var(--font-mono)',fontSize:28,fontWeight:700,color:gradeColor(grade),lineHeight:1}}>{score ?? '—'}</div>
                    <div style={{fontSize:10,color:'var(--muted)'}}>/100</div>
                  </div>
                </div>
                <div style={{fontSize:12,color:'var(--muted)'}}>Security Score</div>
                {grade && <div style={{fontFamily:'var(--font-mono)',fontSize:24,fontWeight:700,color:gradeColor(grade),padding:'4px 14px',borderRadius:6,background:`${gradeColor(grade)}18`,border:`1px solid ${gradeColor(grade)}44`,marginTop:8}}>{grade}</div>}
                {scan?.finished_at && <div style={{fontSize:10,color:'var(--muted)',marginTop:8}}>Last scan: {new Date(scan.finished_at).toLocaleString('en-CA',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}</div>}
                {!scan && !scanning && <div style={{fontSize:12,color:'var(--muted)',marginTop:8}}>Run a scan to see score</div>}
              </div>

              {/* Stat grid */}
              <div style={{display:'grid',gridTemplateColumns:'repeat(2,1fr)',gap:10,alignContent:'start'}}>
                {[
                  { num: critical, label:'Critical Findings', color:'var(--red)' },
                  { num: warnings, label:'Warnings',          color:'var(--yellow)' },
                  { num: passing,  label:'Passing Checks',    color:'var(--green)' },
                  { num: findings.length, label:'Total Checks', color:'var(--accent)' },
                ].map(s => (
                  <div key={s.label} style={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:10,padding:16}}>
                    <div style={{fontFamily:'var(--font-mono)',fontSize:26,fontWeight:700,lineHeight:1,marginBottom:4,color:s.color}}>{s.num}</div>
                    <div style={{fontSize:12,color:'var(--text)',opacity:0.75}}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Tabs */}
            <div style={{display:'flex',gap:4,marginBottom:20,borderBottom:'1px solid var(--border)'}}>
              {tabs.map(t => (
                <button key={t.key} onClick={() => setActiveTab(t.key)}
                  style={{padding:'10px 18px',fontSize:13,background:'transparent',border:'none',borderBottom:`2px solid ${activeTab===t.key?'var(--accent)':'transparent'}`,color:activeTab===t.key?'var(--accent)':'var(--text)',cursor:'pointer',display:'flex',alignItems:'center',gap:6,fontFamily:'var(--font-body)',marginBottom:-1}}>
                  {t.label}
                  <span style={{fontSize:10,fontFamily:'var(--font-mono)',padding:'1px 6px',borderRadius:10,background:activeTab===t.key?'rgba(0,229,255,0.15)':'var(--surface2)',color:activeTab===t.key?'var(--accent)':'var(--text)'}}>{t.count}</span>
                </button>
              ))}
            </div>

            {/* Check header */}
            <div style={{display:'grid',gridTemplateColumns:'20px 1fr 140px 110px 80px',gap:12,padding:'8px 16px',fontSize:10,letterSpacing:'1.5px',textTransform:'uppercase',color:'var(--text)',opacity:0.5,marginBottom:4}}>
              <div/><div>Check</div><div>Category</div><div>Current Value</div><div>Status</div>
            </div>

            {/* Checks */}
            {findings.length === 0 && !scanning && (
              <div style={{textAlign:'center',padding:'40px 0',color:'var(--muted)',fontSize:14}}>
                Run a scan to populate security checks.
              </div>
            )}
            {filtered.map(f => (
              <CheckRow key={f.check_id} finding={f} onClick={() => setSelectedCheck(f)} />
            ))}
          </>
        )}
      </div>

      {selectedCheck && <DetailPanel finding={selectedCheck} onClose={() => setSelectedCheck(null)} />}
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}@keyframes fadeIn{from{opacity:0}to{opacity:1}}`}</style>
    </div>
  )
}
