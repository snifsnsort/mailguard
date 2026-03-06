const STATUS = { fail:'var(--red)', warn:'var(--yellow)', pass:'var(--green)' }
const LABEL  = { fail:'FAIL', warn:'WARN', pass:'PASS' }

export default function CheckRow({ finding: f, onClick, showDomain = false }) {
  const color = STATUS[f.status]
  return (
    <div onClick={onClick}
      style={{display:'grid',gridTemplateColumns:'20px 1fr 140px 110px 80px',gap:12,alignItems:'center',padding:'13px 16px',background:'var(--surface)',border:'1px solid var(--border)',borderRadius:8,marginBottom:6,cursor:'pointer',transition:'all .15s',position:'relative',overflow:'hidden'}}
      onMouseOver={e=>{e.currentTarget.style.borderColor='var(--accent)';e.currentTarget.style.transform='translateX(2px)'}}
      onMouseOut={e=>{e.currentTarget.style.borderColor='var(--border)';e.currentTarget.style.transform='translateX(0)'}}>
      {/* Left accent bar */}
      <div style={{position:'absolute',left:0,top:0,bottom:0,width:3,background:color}}/>
      <div style={{width:10,height:10,borderRadius:'50%',background:color,boxShadow:`0 0 6px ${color}`}}/>
      <div>
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          <span style={{fontSize:14,fontWeight:500}}>{f.name}</span>
          {showDomain && f.domain && (
            <span style={{
              fontSize:10,padding:'2px 7px',borderRadius:10,
              background:'rgba(0,229,255,0.06)',color:'var(--accent)',
              border:'1px solid rgba(0,229,255,0.2)',fontFamily:'var(--font-mono)',
              whiteSpace:'nowrap',flexShrink:0,
            }}>
              {f.domain}
            </span>
          )}
        </div>
        <div style={{fontSize:11,color:'var(--muted)',marginTop:2}}>{f.description}</div>
      </div>
      <div style={{fontSize:11,fontFamily:'var(--font-mono)',padding:'3px 10px',borderRadius:20,background:'var(--surface2)',color:'var(--muted)',border:'1px solid var(--border)',textAlign:'center'}}>{f.category}</div>
      <div style={{fontFamily:'var(--font-mono)',fontSize:11,color:'var(--muted)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{String(typeof f.current_value === 'object' ? JSON.stringify(f.current_value) : f.current_value).slice(0,30)}</div>
      <div style={{fontSize:11,fontFamily:'var(--font-mono)',fontWeight:700,padding:'3px 10px',borderRadius:4,textAlign:'center',background:`${color}22`,color,border:`1px solid ${color}55`}}>{LABEL[f.status]}</div>
    </div>
  )
}
