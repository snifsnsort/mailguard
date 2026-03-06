import { X, ExternalLink } from 'lucide-react'

const STATUS_COLOR = { fail:'var(--red)', warn:'var(--yellow)', pass:'var(--green)' }

export default function DetailPanel({ finding: f, onClose }) {
  const color = STATUS_COLOR[f.status]

  return (
    <>
      <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.3)',zIndex:90}} onClick={onClose}/>
      <div style={{position:'fixed',right:0,top:0,bottom:0,width:500,background:'var(--surface)',borderLeft:'1px solid var(--border)',zIndex:100,overflowY:'auto',animation:'slideIn .3s cubic-bezier(.4,0,.2,1)',display:'flex',flexDirection:'column'}}>
        {/* Header */}
        <div style={{padding:24,borderBottom:'1px solid var(--border)',position:'sticky',top:0,background:'var(--surface)',zIndex:1}}>
          <button onClick={onClose} style={{position:'absolute',top:18,right:18,background:'var(--surface2)',border:'1px solid var(--border)',color:'var(--muted)',width:28,height:28,borderRadius:6,cursor:'pointer',display:'flex',alignItems:'center',justifyContent:'center'}}>
            <X size={13}/>
          </button>
          <div style={{fontSize:11,fontFamily:'var(--font-mono)',color,textTransform:'uppercase',letterSpacing:'1.5px',marginBottom:6}}>{f.severity}</div>
          <div style={{fontSize:18,fontWeight:600}}>{f.name}</div>
          <div style={{fontSize:12,color:'var(--muted)',marginTop:4}}>{f.category}</div>
        </div>

        {/* Body */}
        <div style={{padding:24,flex:1}}>
          <Block label="Description"><p style={{fontSize:13,lineHeight:1.6}}>{f.description}</p></Block>
          <Block label="Benchmark Reference"><p style={{fontSize:13,lineHeight:1.6}}>{f.benchmark}</p></Block>
          <Block label="Current Configuration">
            <code style={{display:'block',background:'var(--bg)',border:'1px solid var(--border)',borderRadius:6,padding:'12px 14px',fontFamily:'var(--font-mono)',fontSize:11.5,color:'var(--accent)',lineHeight:1.7,whiteSpace:'pre-wrap'}}>
              {typeof f.current_value === 'object' ? JSON.stringify(f.current_value, null, 2) : String(f.current_value)}
            </code>
          </Block>
          <Block label="Recommended Configuration">
            <code style={{display:'block',background:'var(--bg)',border:'1px solid var(--border)',borderRadius:6,padding:'12px 14px',fontFamily:'var(--font-mono)',fontSize:11.5,color:'var(--green)',lineHeight:1.7,whiteSpace:'pre-wrap'}}>
              {typeof f.expected_value === 'object' ? JSON.stringify(f.expected_value, null, 2) : String(f.expected_value)}
            </code>
          </Block>
          {f.remediation?.length > 0 && (
            <Block label="Remediation Steps">
              <ol style={{listStyle:'none',counterReset:'step'}}>
                {f.remediation.map((s,i) => (
                  <li key={i} style={{display:'flex',gap:10,marginBottom:10,fontSize:13,lineHeight:1.5}}>
                    <span style={{fontFamily:'var(--font-mono)',fontSize:10,fontWeight:700,background:'var(--accent)',color:'#000',width:20,height:20,borderRadius:'50%',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0,marginTop:1}}>{i+1}</span>
                    {s}
                  </li>
                ))}
              </ol>
            </Block>
          )}
          {f.reference_url && f.reference_url !== '#' && (
            <Block label="Microsoft Documentation">
              <a href={f.reference_url} target="_blank" rel="noopener noreferrer"
                style={{display:'inline-flex',alignItems:'center',gap:6,fontSize:12,color:'var(--accent)',textDecoration:'none',padding:'7px 14px',border:'1px solid rgba(0,229,255,0.2)',borderRadius:6,background:'rgba(0,229,255,0.05)'}}>
                <ExternalLink size={12}/> Open Microsoft Learn
              </a>
            </Block>
          )}
        </div>
        <style>{`@keyframes slideIn{from{transform:translateX(100%)}to{transform:translateX(0)}}`}</style>
      </div>
    </>
  )
}

function Block({ label, children }) {
  return (
    <div style={{marginBottom:24}}>
      <div style={{fontSize:10,letterSpacing:2,textTransform:'uppercase',color:'var(--muted)',marginBottom:8}}>{label}</div>
      {children}
    </div>
  )
}
