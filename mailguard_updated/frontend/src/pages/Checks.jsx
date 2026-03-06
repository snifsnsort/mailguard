import { useState, useRef } from 'react'
import CheckRow from '../components/CheckRow'
import DetailPanel from '../components/DetailPanel'

const CATEGORIES = [
  'All','SPF/DKIM/DMARC','Anti-Phishing','MFA & Admin',
  'Safe Links / Attachments','Direct Send','Google Workspace',
]

const PLATFORM_STYLE = {
  'Microsoft 365':    { bg:'rgba(0,120,212,0.12)', color:'#4da6ff', label:'Microsoft 365' },
  'Google Workspace': { bg:'rgba(52,168,83,0.12)',  color:'#5cb85c', label:'Google Workspace' },
}

function VendorPdfPanel({ token }) {
  const [open,      setOpen]      = useState(false)
  const [uploading, setUploading] = useState(false)
  const [result,    setResult]    = useState(null)
  const [dragOver,  setDragOver]  = useState(false)
  const fileRef = useRef(null)

  const handleFile = async (file) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.pdf')) {
      setResult({ type:'error', msg:'Only PDF files are supported.' }); return
    }
    setUploading(true); setResult(null)
    try {
      const fd = new FormData(); fd.append('file', file)
      const headers = token ? { Authorization:`Bearer ${token}` } : {}
      const res = await fetch('/api/v1/vendor-pdfs/upload', { method:'POST', body:fd, headers })
      const data = await res.json()
      setResult({ type:'success', msg: data.message || 'Received — analysis coming soon.' })
    } catch {
      setResult({ type:'error', msg:'Upload failed. Please try again.' })
    } finally { setUploading(false) }
  }

  const VENDORS = ['Mimecast','Barracuda','Proofpoint','Cisco Secure Email',
    'Sophos','Broadcom','Trellix','Trend Micro','Forcepoint','Check Point','Hornetsecurity']

  return (
    <div style={{marginBottom:24}}>
      <button onClick={() => setOpen(o=>!o)} style={{
        display:'flex',alignItems:'center',justifyContent:'space-between',
        gap:8,padding:'8px 16px',borderRadius:8,fontSize:12,cursor:'pointer',
        border:'1px dashed var(--border)',background:'transparent',color:'var(--muted)',
        fontFamily:'var(--font-body)',transition:'all .15s',width:'100%'
      }}>
        <span style={{display:'flex',alignItems:'center',gap:8}}>
          <span style={{fontSize:16}}>📄</span>
          <span>Upload vendor best-practices PDF{' '}
            <span style={{marginLeft:6,padding:'2px 8px',borderRadius:10,fontSize:10,
              background:'rgba(0,229,255,0.08)',color:'var(--accent)',border:'1px solid rgba(0,229,255,0.2)'}}>
              Coming soon</span></span>
        </span>
        <span style={{fontSize:10}}>{open?'▲':'▼'}</span>
      </button>

      {open && (
        <div style={{marginTop:8,padding:20,borderRadius:8,border:'1px solid var(--border)',background:'rgba(255,255,255,0.02)'}}>
          <p style={{fontSize:12,color:'var(--muted)',marginBottom:12,lineHeight:1.6}}>
            Upload your email security vendor's best-practices guide and MailGuard will
            automatically evaluate your configuration against it.
          </p>
          <div style={{display:'flex',flexWrap:'wrap',gap:6,marginBottom:16}}>
            {VENDORS.map(v=>(
              <span key={v} style={{padding:'3px 10px',borderRadius:12,fontSize:11,
                background:'rgba(255,255,255,0.04)',border:'1px solid var(--border)',color:'var(--muted)'}}>
                {v}</span>
            ))}
          </div>
          <div
            onDragOver={e=>{e.preventDefault();setDragOver(true)}}
            onDragLeave={()=>setDragOver(false)}
            onDrop={e=>{e.preventDefault();setDragOver(false);handleFile(e.dataTransfer.files?.[0])}}
            onClick={()=>fileRef.current?.click()}
            style={{padding:'32px 20px',borderRadius:8,cursor:'pointer',textAlign:'center',
              border:`2px dashed ${dragOver?'var(--accent)':'var(--border)'}`,
              background:dragOver?'rgba(0,229,255,0.04)':'rgba(255,255,255,0.01)',
              transition:'all .15s',marginBottom:12}}>
            <div style={{fontSize:24,marginBottom:8}}>☁️</div>
            <div style={{fontSize:12,color:'var(--muted)'}}>
              {uploading?'Uploading…':'Drop PDF here or click to browse'}
            </div>
            <div style={{fontSize:11,color:'rgba(255,255,255,0.3)',marginTop:4}}>Max 50 MB · PDF only</div>
            <input ref={fileRef} type="file" accept=".pdf" style={{display:'none'}}
              onChange={e=>handleFile(e.target.files?.[0])} />
          </div>
          {result && (
            <div style={{padding:'10px 14px',borderRadius:6,fontSize:12,
              background:result.type==='success'?'rgba(52,168,83,0.1)':'rgba(220,50,50,0.1)',
              border:`1px solid ${result.type==='success'?'rgba(52,168,83,0.3)':'rgba(220,50,50,0.3)'}`,
              color:result.type==='success'?'#5cb85c':'#e06c75'}}>
              {result.msg}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Checks({ scan, tenantId, token }) {
  const [selected,   setSelected]   = useState(null)
  const [cat,        setCat]        = useState('All')
  const [domainFilter, setDomainFilter] = useState('All')

  const findings        = scan?.findings || []
  const platform        = scan?.platform || null
  const domainsScanned  = scan?.domains_scanned || []
  const hasGws          = findings.some(f => f.category === 'Google Workspace')
  const hasMultiDomain  = domainsScanned.length > 1

  // Build domain-aware findings list
  const domainFiltered = domainFilter === 'All' || domainFilter === 'Tenant-wide'
    ? domainFilter === 'Tenant-wide'
      ? findings.filter(f => !f.domain)
      : findings
    : findings.filter(f => f.domain === domainFilter)

  const categories = hasGws ? CATEGORIES : CATEGORIES.filter(c=>c!=='Google Workspace')
  const filtered   = cat === 'All' ? domainFiltered : domainFiltered.filter(f => f.category === cat)
  const pStyle     = platform ? PLATFORM_STYLE[platform] : null

  return (
    <div>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',
        padding:'18px 32px',borderBottom:'1px solid var(--border)',
        background:'rgba(8,12,18,0.85)',backdropFilter:'blur(10px)',position:'sticky',top:0,zIndex:5}}>
        <div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            <h1 style={{fontSize:20,fontWeight:600}}>Security Checks</h1>
            {pStyle && (
              <span style={{padding:'3px 10px',borderRadius:12,fontSize:11,fontWeight:500,
                background:pStyle.bg,color:pStyle.color,border:`1px solid ${pStyle.color}33`}}>
                {pStyle.label}</span>
            )}
          </div>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:2}}>
            {findings.length} checks · {findings.filter(f=>f.status==='fail').length} critical
            {hasMultiDomain && ` · ${domainsScanned.length} domains scanned`}
          </p>
        </div>
      </div>

      <div style={{padding:'28px 32px'}}>
        <VendorPdfPanel token={token} />

        {/* Domain filter — only shown when multiple domains were scanned */}
        {hasMultiDomain && (
          <div style={{marginBottom:16}}>
            <div style={{fontSize:10,letterSpacing:'1.5px',textTransform:'uppercase',
              color:'var(--muted)',marginBottom:8}}>Filter by domain</div>
            <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
              {['All','Tenant-wide',...domainsScanned].map(d => {
                const isActive = domainFilter === d
                return (
                  <button key={d} onClick={() => setDomainFilter(d)} style={{
                    padding:'5px 12px',borderRadius:16,fontSize:11,cursor:'pointer',
                    fontFamily:'var(--font-body)',transition:'all .15s',
                    border:isActive?'1px solid var(--accent)':'1px solid var(--border)',
                    background:isActive?'rgba(0,229,255,0.08)':'transparent',
                    color:isActive?'var(--accent)':'var(--muted)',
                  }}>
                    {d === 'Tenant-wide' ? '🏢 Tenant-wide' : d === 'All' ? 'All domains' : `🌐 ${d}`}
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {/* Category filter */}
        <div style={{display:'flex',gap:8,flexWrap:'wrap',marginBottom:24}}>
          {categories.map(c => {
            const isGws = c==='Google Workspace', isActive = cat===c
            return (
              <button key={c} onClick={()=>setCat(c)} style={{
                padding:'6px 14px',borderRadius:20,fontSize:12,cursor:'pointer',
                fontFamily:'var(--font-body)',transition:'all .15s',
                border:isActive?`1px solid ${isGws?'#5cb85c':'var(--accent)'}`
                               :`1px solid ${isGws?'rgba(52,168,83,0.35)':'var(--border)'}`,
                background:isActive?(isGws?'rgba(52,168,83,0.08)':'rgba(0,229,255,0.08)'):'transparent',
                color:isActive?(isGws?'#5cb85c':'var(--accent)'):(isGws?'rgba(92,184,92,0.7)':'var(--muted)'),
              }}>
                {isGws?'🔵 Google Workspace':c}
              </button>
            )
          })}
        </div>

        <div style={{display:'grid',gridTemplateColumns:'20px 1fr 140px 110px 80px',
          gap:12,padding:'8px 16px',fontSize:10,letterSpacing:'1.5px',
          textTransform:'uppercase',color:'var(--muted)',marginBottom:4}}>
          <div/><div>Check</div><div>Category</div><div>Current Value</div><div>Status</div>
        </div>

        {findings.length===0 && (
          <div style={{textAlign:'center',padding:'60px 0',color:'var(--muted)'}}>
            No scan data — run a scan from the Dashboard.
          </div>
        )}
        {filtered.map(f => (
          <CheckRow
            key={`${f.check_id}-${f.domain || 'tenant'}`}
            finding={f}
            showDomain={hasMultiDomain && domainFilter === 'All'}
            onClick={() => setSelected(f)}
          />
        ))}
      </div>

      {selected && <DetailPanel finding={selected} onClose={()=>setSelected(null)} />}
    </div>
  )
}
