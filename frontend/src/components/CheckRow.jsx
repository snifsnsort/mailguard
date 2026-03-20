/**
 * CheckRow.jsx
 *
 * Renders a clickable dashboard row with support for multiple benchmark tags.
 */

import { parseBenchmarkDisplay } from '../utils/benchmarkDisplay'
import { STATUS_LABELS } from '../utils/uiLabels'

const STATUS = { fail: 'var(--red)', warn: 'var(--yellow)', pass: 'var(--green)' }

function BenchmarkTag({ tag }) {
  return (
    <span style={{
      fontSize: 8,
      padding: '1px 5px',
      borderRadius: 3,
      fontFamily: 'var(--font-mono)',
      whiteSpace: 'nowrap',
      flexShrink: 0,
      background: tag.bg,
      color: tag.color,
      border: `1px solid ${tag.color}33`,
    }}>
      {tag.shortLabel}
    </span>
  )
}

export default function CheckRow({ finding: f, onClick, showDomain = false, highlighted = false }) {
  const color = STATUS[f.status]
  const benchmarkTags = f.benchmarks?.length ? f.benchmarks : (() => {
    const fallback = parseBenchmarkDisplay(f.benchmark)
    return fallback ? [fallback] : []
  })()

  return (
    <div
      id={`check-${f.check_id}`}
      onClick={onClick}
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 144px 110px 64px',
        gap: 10,
        alignItems: 'center',
        padding: '13px 14px 13px 18px',
        background: highlighted ? 'rgba(0,229,255,.04)' : 'var(--surface)',
        border: `1px solid ${highlighted ? 'rgba(0,229,255,.42)' : 'var(--border)'}`,
        borderLeft: `4px solid ${color}`,
        borderRadius: 8,
        marginBottom: 6,
        cursor: 'pointer',
        transition: 'all .15s ease',
        position: 'relative',
        boxShadow: highlighted ? '0 0 0 1px rgba(0,229,255,.12)' : 'none',
      }}
      onMouseOver={e => {
        e.currentTarget.style.borderColor = highlighted ? 'rgba(0,229,255,.58)' : 'rgba(0,229,255,.46)'
        e.currentTarget.style.borderLeftColor = color
        e.currentTarget.style.background = highlighted ? 'rgba(0,229,255,.05)' : 'var(--surface)'
        e.currentTarget.style.transform = 'translateX(0)'
        e.currentTarget.style.boxShadow = highlighted
          ? '0 0 0 1px rgba(0,229,255,.18)'
          : '0 0 0 1px rgba(0,229,255,.16)'
      }}
      onMouseOut={e => {
        e.currentTarget.style.borderColor = highlighted ? 'rgba(0,229,255,.42)' : 'var(--border)'
        e.currentTarget.style.borderLeftColor = color
        e.currentTarget.style.background = highlighted ? 'rgba(0,229,255,.04)' : 'var(--surface)'
        e.currentTarget.style.transform = 'translateX(0)'
        e.currentTarget.style.boxShadow = highlighted
          ? '0 0 0 1px rgba(0,229,255,.12)'
          : 'none'
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap', marginBottom: 3 }}>
          <span style={{ fontSize: 13, fontWeight: 500, whiteSpace: 'nowrap' }}>{f.name}</span>
          {benchmarkTags.map((tag) => (
            <BenchmarkTag key={`${f.check_id}-${tag.fullLabel}`} tag={tag} />
          ))}
          {showDomain && f.domain && (
            <span style={{
              fontSize: 9,
              padding: '1px 6px',
              borderRadius: 10,
              background: 'rgba(0,229,255,.06)',
              color: 'var(--accent)',
              border: '1px solid rgba(0,229,255,.2)',
              fontFamily: 'var(--font-mono)',
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}>
              {f.domain}
            </span>
          )}
        </div>
        <div style={{ fontSize: 11, color: 'var(--muted)', lineHeight: 1.4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {f.description}
        </div>
      </div>

      <div
        title={f.category}
        style={{
          fontSize: 10,
          fontFamily: 'var(--font-mono)',
          padding: '4px 12px',
          borderRadius: 20,
          background: 'var(--surface2)',
          color: 'var(--muted)',
          border: '1px solid var(--border)',
          textAlign: 'center',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          maxWidth: '100%',
          lineHeight: 1.1,
        }}
      >
        {f.category}
      </div>

      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        color: 'var(--muted)',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}>
        {String(typeof f.current_value === 'object' ? JSON.stringify(f.current_value) : f.current_value).slice(0, 24)}
      </div>

      <div style={{
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        fontWeight: 700,
        padding: '3px 8px',
        borderRadius: 4,
        textAlign: 'center',
        background: `${color}22`,
        color,
        border: `1px solid ${color}55`,
      }}>
        {STATUS_LABELS[f.status]}
      </div>
    </div>
  )
}
