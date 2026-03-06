import { useEffect, useState } from 'react'
import { api } from '../utils/api'
import { Download, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react'

function gradeColor(g) {
  if (g === 'A') return 'var(--green)'
  if (g === 'B') return 'var(--accent)'
  if (g === 'C') return 'var(--yellow)'
  return 'var(--red)'
}

export default function History({ tenant }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!tenant) return
    setLoading(true)
    api.scanHistory(tenant.id).then(setHistory).finally(() => setLoading(false))
  }, [tenant?.id])

  return (
    <div>
      <div style={{display:'flex',alignItems:'center',padding:'18px 32px',borderBottom:'1px solid var(--border)',background:'rgba(8,12,18,0.85)',backdropFilter:'blur(10px)',position:'sticky',top:0,zIndex:5}}>
        <div>
          <h1 style={{fontSize:20,fontWeight:600}}>Scan History</h1>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:2}}>{tenant ? tenant.display_name : 'No tenant selected'}</p>
        </div>
      </div>
      <div style={{padding:'28px 32px'}}>
        {!tenant && <div style={{textAlign:'center',padding:60,color:'var(--muted)'}}>Connect a tenant to view history.</div>}
        {loading && <div style={{textAlign:'center',padding:60,color:'var(--muted)'}}>Loading...</div>}
        {!loading && tenant && history.length === 0 && <div style={{textAlign:'center',padding:60,color:'var(--muted)'}}>No scans yet. Run your first scan from the Dashboard.</div>}
        {history.map(s => (
          <div key={s.id} style={{display:'grid',gridTemplateColumns:'32px 1fr auto',gap:16,alignItems:'center',padding:'16px 20px',background:'var(--surface)',border:'1px solid var(--border)',borderRadius:10,marginBottom:8}}>
            <div>
              {s.status === 'completed' && <CheckCircle size={20} color="var(--green)"/>}
              {s.status === 'failed'    && <XCircle     size={20} color="var(--red)"/>}
              {s.status === 'running'   && <Clock       size={20} color="var(--yellow)"/>}
              {s.status === 'pending'   && <Clock       size={20} color="var(--muted)"/>}
            </div>
            <div>
              <div style={{display:'flex',alignItems:'center',gap:10}}>
                <span style={{fontSize:14,fontWeight:500}}>{new Date(s.started_at).toLocaleString()}</span>
                {s.grade && <span style={{fontFamily:'var(--font-mono)',fontSize:12,fontWeight:700,color:gradeColor(s.grade),padding:'2px 8px',borderRadius:4,background:`${gradeColor(s.grade)}18`}}>{s.grade}</span>}
              </div>
              <div style={{fontSize:12,color:'var(--muted)',marginTop:3}}>
                {s.status === 'completed' ? `Score: ${s.score}/100 · ${s.critical} critical · ${s.warnings} warnings · ${s.passing} passing` : s.status}
              </div>
            </div>
            <div style={{display:'flex',gap:8}}>
              {s.status === 'completed' && (
                <a href={api.reportPdfUrl(s.id)} download={`mailguard-report-${s.id.slice(0,8)}.pdf`} style={{display:'flex',alignItems:'center',gap:6,fontSize:12,color:'var(--accent)',textDecoration:'none',padding:'6px 12px',border:'1px solid rgba(0,229,255,0.2)',borderRadius:6,background:'rgba(0,229,255,0.05)'}}>
                  <Download size={12}/> PDF
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
