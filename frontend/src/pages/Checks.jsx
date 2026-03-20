import { useState } from 'react'
import CheckRow from '../components/CheckRow'
import DetailPanel from '../components/DetailPanel'
import { EXPOSURE_LABELS } from '../utils/uiLabels'

const DOMAINS = [
  'All','SPF/DKIM/DMARC','Anti-Phishing','MFA & Admin',
  'Safe Links / Attachments','Direct Send','Google Workspace',
]

const PLATFORM_STYLE = {
  'Microsoft 365':    { bg:'rgba(0,120,212,0.12)', color:'#4da6ff', label:'Microsoft 365' },
  'Google Workspace': { bg:'rgba(52,168,83,0.12)',  color:'#5cb85c', label:'Google Workspace' },
}

export default function Checks({ scan, token }) {
  const [selected, setSelected] = useState(null)
  const [domainTag, setDomainTag] = useState('All')
  const [tenantDomainFilter, setTenantDomainFilter] = useState('All')

  const findings = scan?.findings || []
  const platform = scan?.platform || null
  const domainsScanned = scan?.domains_scanned || []
  const hasGws = findings.some(f => f.category === 'Google Workspace')
  const hasMultiDomain = domainsScanned.length > 1

  const domainFiltered = tenantDomainFilter === 'All' || tenantDomainFilter === 'Tenant-wide'
    ? tenantDomainFilter === 'Tenant-wide'
      ? findings.filter(f => !f.domain)
      : findings
    : findings.filter(f => f.domain === tenantDomainFilter)

  const domains = hasGws ? DOMAINS : DOMAINS.filter(c => c !== 'Google Workspace')
  const filtered = domainTag === 'All' ? domainFiltered : domainFiltered.filter(f => f.category === domainTag)
  const pStyle = platform ? PLATFORM_STYLE[platform] : null

  return (
    <div>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',
        padding:'18px 32px',borderBottom:'1px solid var(--border)',
        background:'rgba(8,12,18,0.85)',backdropFilter:'blur(10px)',position:'sticky',top:0,zIndex:5}}>
        <div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            <h1 style={{fontSize:20,fontWeight:600}}>{EXPOSURE_LABELS.findings}</h1>
            {pStyle && (
              <span style={{padding:'3px 10px',borderRadius:12,fontSize:11,fontWeight:500,
                background:pStyle.bg,color:pStyle.color,border:`1px solid ${pStyle.color}33`}}>
                {pStyle.label}</span>
            )}
          </div>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:2}}>
            {findings.length} findings · {findings.filter(f=>f.status==='fail').length} fail
            {hasMultiDomain && ` · ${domainsScanned.length} domains scanned`}
          </p>
        </div>
      </div>

      <div style={{padding:'28px 32px'}}>

        {hasMultiDomain && (
          <div style={{marginBottom:16}}>
            <div style={{fontSize:10,letterSpacing:'1.5px',textTransform:'uppercase',color:'var(--muted)',marginBottom:8}}>Filter by {EXPOSURE_LABELS.tenantDomain.toLowerCase()}</div>
            <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
              {['All','Tenant-wide',...domainsScanned].map(d => {
                const isActive = tenantDomainFilter === d
                return (
                  <button key={d} onClick={() => setTenantDomainFilter(d)} style={{
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

        <div style={{display:'flex',gap:8,flexWrap:'wrap',marginBottom:24}}>
          {domains.map(c => {
            const isGws = c==='Google Workspace'
            const isActive = domainTag===c
            return (
              <button key={c} onClick={()=>setDomainTag(c)} style={{
                padding:'6px 14px',borderRadius:20,fontSize:12,cursor:'pointer',
                fontFamily:'var(--font-body)',transition:'all .15s',
                border:isActive?`1px solid ${isGws?'#5cb85c':'var(--accent)'}`:`1px solid ${isGws?'rgba(52,168,83,0.35)':'var(--border)'}`,
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
          <div/><div>{EXPOSURE_LABELS.finding}</div><div>{EXPOSURE_LABELS.domain}</div><div>Current Value</div><div>Status</div>
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
            showDomain={hasMultiDomain && tenantDomainFilter === 'All'}
            onClick={() => setSelected(f)}
          />
        ))}
      </div>

      {selected && <DetailPanel finding={selected} onClose={()=>setSelected(null)} />}
    </div>
  )
}
