import React, { useMemo, useState } from 'react'
import { AlertTriangle, Filter, Globe, Lock, Network, RefreshCw, Shield } from 'lucide-react'
import { useDnsPosture } from '../../context/DnsPostureContext'
import { useMailRouting } from '../../context/MailRoutingContext'
import { useScope } from '../../context/ScopeContext'
import { PRODUCT_LABEL } from '../../../utils/uiLabels'

const SECTION_ORDER = { auth: 0, routing: 1, tls: 2, mx: 3 }
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'auth', label: 'Authentication' },
  { key: 'routing', label: 'Routing' },
  { key: 'tls', label: 'TLS' },
  { key: 'mx', label: 'MX' },
]

const SECTION_META = {
  auth: { label: 'Authentication', icon: Shield },
  routing: { label: 'Routing', icon: Network },
  tls: { label: 'TLS', icon: Lock },
  mx: { label: 'MX', icon: Globe },
}

const SEVERITY_GROUPS = [
  { key: 'critical', label: 'Critical', color: 'var(--red)' },
  { key: 'high', label: 'High', color: '#f97316' },
  { key: 'medium', label: 'Medium', color: 'var(--yellow)' },
]

function statusFromSeverity(severity) {
  if (severity === 'critical' || severity === 'high') return 'fail'
  if (severity === 'medium' || severity === 'low' || severity === 'info') return 'warn'
  return 'pass'
}

function scoreTone(score) {
  if (score == null) return { color: 'var(--muted)', bg: 'rgba(255,255,255,.04)', border: 'rgba(255,255,255,.12)' }
  if (score >= 80) return { color: 'var(--green)', bg: 'rgba(0,230,118,.08)', border: 'rgba(0,230,118,.20)' }
  if (score >= 60) return { color: 'var(--yellow)', bg: 'rgba(255,215,64,.08)', border: 'rgba(255,215,64,.20)' }
  return { color: 'var(--red)', bg: 'rgba(255,79,94,.08)', border: 'rgba(255,79,94,.20)' }
}

function chipStyle(kind = 'neutral') {
  if (kind === 'red') return { color: 'var(--red)', background: 'rgba(255,79,94,.08)', border: 'rgba(255,79,94,.22)' }
  if (kind === 'yellow') return { color: 'var(--yellow)', background: 'rgba(255,215,64,.08)', border: 'rgba(255,215,64,.22)' }
  if (kind === 'green') return { color: 'var(--green)', background: 'rgba(0,230,118,.08)', border: 'rgba(0,230,118,.20)' }
  if (kind === 'orange') return { color: '#f97316', background: 'rgba(249,115,22,.08)', border: 'rgba(249,115,22,.22)' }
  return { color: 'var(--text)', background: 'rgba(255,255,255,.04)', border: 'var(--border)' }
}

function compactLabel(value, limit = 34) {
  const text = String(value || '').replace(/\s+/g, ' ').trim()
  if (!text) return ''
  return text.length > limit ? `${text.slice(0, limit - 3)}...` : text
}

function providerLabel(provider) {
  if (!provider) return ''
  if (provider === 'Microsoft EOP') return 'Microsoft 365'
  if (provider === 'Google Workspace') return 'Google Workspace'
  return provider
}

function exploitabilityFromFinding(sectionKey, title, severity) {
  const lower = String(title || '').toLowerCase()
  const direct = [
    'direct send',
    'smtp auth',
    'smtp authentication',
    'dmarc none',
    'mta-sts missing',
    'mta sts missing',
    'bypass',
    'open relay',
  ]
  if (direct.some(token => lower.includes(token))) return 'Critical'
  if (severity === 'critical') return 'Critical'
  if (severity === 'high') return 'High'
  if (severity === 'medium') return 'Medium'
  if (sectionKey === 'routing' && lower.includes('connector')) return 'High'
  if (sectionKey === 'tls' && lower.includes('starttls')) return 'Medium'
  return 'Low'
}

function fixHintForFinding(sectionKey, title, recommendedAction) {
  const lower = String(title || '').toLowerCase()
  if (sectionKey === 'auth') {
    if (lower.includes('spf')) return 'Publish SPF'
    if (lower.includes('dkim')) return 'Fix DKIM'
    if (lower.includes('dmarc')) return 'Tighten DMARC'
    return 'Harden auth'
  }
  if (sectionKey === 'routing') {
    if (lower.includes('direct')) return 'Block direct send'
    if (lower.includes('smtp')) return 'Disable SMTP AUTH'
    if (lower.includes('connector')) return 'Lock connector scope'
    return 'Restrict routing'
  }
  if (sectionKey === 'tls') {
    if (lower.includes('mta-sts')) return 'Publish MTA-STS'
    if (lower.includes('tlsrpt')) return 'Enable TLSRPT'
    if (lower.includes('starttls')) return 'Require STARTTLS'
    if (lower.includes('dane')) return 'Fix DANE'
    if (lower.includes('conflict')) return 'Remove conflicts'
    return 'Tighten TLS'
  }
  if (sectionKey === 'mx') {
    if (lower.includes('mx')) return 'Normalize MX'
    if (lower.includes('a record')) return 'Remove A fallback'
    if (lower.includes('mail')) return 'Seal ingress'
    return 'Review ingress'
  }
  return compactLabel(recommendedAction || 'Review')
}

function normalizeFinding(sectionKey, sectionLabel, finding, activeDomain) {
  const title = String(finding.title || 'Untitled issue')
  const severity = String(finding.severity || 'low')
  return {
    check_id: `${sectionKey}-${finding.id}`,
    name: title,
    category: sectionLabel,
    sectionKey,
    risk_level: severity,
    status: statusFromSeverity(severity),
    exploitability: exploitabilityFromFinding(sectionKey, title, severity),
    fix_hint: fixHintForFinding(sectionKey, title, finding.recommended_action),
    domain: activeDomain || '',
    rawFinding: finding,
  }
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const severityDelta = (SEVERITY_ORDER[a.risk_level] ?? 9) - (SEVERITY_ORDER[b.risk_level] ?? 9)
    if (severityDelta !== 0) return severityDelta
    const sectionDelta = (SECTION_ORDER[a.sectionKey] ?? 9) - (SECTION_ORDER[b.sectionKey] ?? 9)
    if (sectionDelta !== 0) return sectionDelta
    return String(a.name || '').localeCompare(String(b.name || ''))
  })
}

function sectionTone(findings) {
  if (findings.some(f => f.risk_level === 'critical' || f.risk_level === 'high')) {
    return { color: 'var(--red)', bg: 'rgba(255,79,94,.08)', border: 'rgba(255,79,94,.22)' }
  }
  if (findings.some(f => f.risk_level === 'medium')) {
    return { color: 'var(--yellow)', bg: 'rgba(255,215,64,.08)', border: 'rgba(255,215,64,.20)' }
  }
  return { color: 'var(--green)', bg: 'rgba(0,230,118,.08)', border: 'rgba(0,230,118,.20)' }
}

function sectionCounts(findings) {
  return {
    fail: findings.filter(f => f.status === 'fail').length,
    warn: findings.filter(f => f.status === 'warn').length,
  }
}

function sectionIssues(findings) {
  const seen = new Set()
  return sortFindings(findings)
    .map(finding => compactLabel(finding.name))
    .filter(label => label && !seen.has(label) && seen.add(label))
    .slice(0, 3)
}

function authScoreFromEvidence(evidence) {
  if (typeof evidence?.health_score === 'number') return Math.round(evidence.health_score)
  return null
}

function toneForState(kind = 'neutral') {
  if (kind === 'good') return { color: 'var(--green)', bg: 'rgba(0,230,118,.08)', border: 'rgba(0,230,118,.20)' }
  if (kind === 'warn') return { color: 'var(--yellow)', bg: 'rgba(255,215,64,.08)', border: 'rgba(255,215,64,.20)' }
  if (kind === 'high') return { color: '#f97316', bg: 'rgba(249,115,22,.08)', border: 'rgba(249,115,22,.22)' }
  if (kind === 'bad') return { color: 'var(--red)', bg: 'rgba(255,79,94,.08)', border: 'rgba(255,79,94,.20)' }
  return { color: 'var(--text)', bg: 'rgba(255,255,255,.04)', border: 'var(--border)' }
}

function InlineBadge({ label, tone = 'neutral', mono = false }) {
  const colors = toneForState(tone)
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '3px 8px',
      borderRadius: 999,
      border: `1px solid ${colors.border}`,
      background: colors.bg,
      color: colors.color,
      fontSize: 10.5,
      fontWeight: 700,
      fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)',
      whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

function OverviewMetaCard({ label, value, subvalue, tone = 'neutral', mono = false }) {
  return (
    <div style={{ padding: '10px 12px', borderRadius: 10, border: '1px solid var(--border)', background: 'rgba(255,255,255,.02)' }}>
      <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '1px', textTransform: 'uppercase', fontWeight: 700 }}>{label}</div>
      <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)' }}>{value}</div>
        {subvalue ? <InlineBadge label={subvalue} tone={tone} /> : null}
      </div>
    </div>
  )
}

function PathNode({ label, tone = 'neutral' }) {
  const colors = toneForState(tone)
  return (
    <div style={{ padding: '8px 10px', borderRadius: 10, border: `1px solid ${colors.border}`, background: colors.bg, color: colors.color, fontSize: 11.5, fontWeight: 700, whiteSpace: 'nowrap' }}>
      {label}
    </div>
  )
}

function PathFlow({ nodes, tone = 'neutral', dashed = false }) {
  const colors = toneForState(tone)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      {nodes.map((node, index) => (
        <React.Fragment key={`${node}-${index}`}>
          <PathNode label={node} tone={tone} />
          {index < nodes.length - 1 && (
            <div style={{ width: 28, borderTop: `2px ${dashed ? 'dashed' : 'solid'} ${colors.color}`, opacity: 0.95 }} />
          )}
        </React.Fragment>
      ))}
    </div>
  )
}

function ControlRow({ label, note, presence, effectiveness, coverage }) {
  return (
    <div style={{ padding: '10px 12px', border: '1px solid var(--border)', borderRadius: 10, background: 'rgba(255,255,255,.02)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'start', flexWrap: 'wrap' }}>
        <div style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text)' }}>{label}</div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'end' }}>
          <InlineBadge label={`Presence: ${presence.label}`} tone={presence.tone} />
          <InlineBadge label={`Effectiveness: ${effectiveness.label}`} tone={effectiveness.tone} />
          <InlineBadge label={`Coverage: ${coverage.label}`} tone={coverage.tone} />
        </div>
      </div>
      <div style={{ marginTop: 5, fontSize: 11, color: 'var(--muted)', lineHeight: 1.45 }}>{note}</div>
    </div>
  )
}

function PathPanel({ title, tone, badge, children }) {
  const colors = toneForState(tone)
  return (
    <div style={{ padding: '12px', borderRadius: 12, border: `1px solid ${colors.border}`, background: colors.bg }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'start', marginBottom: 10, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '1px', textTransform: 'uppercase', fontWeight: 700 }}>{title}</div>
        {badge ? <InlineBadge label={badge} tone={tone} /> : null}
      </div>
      <div style={{ display: 'grid', gap: 8 }}>
        {children}
      </div>
    </div>
  )
}

function MailFlowOverviewPanel({ mxResult, routingResult, connectorResult, directResult, authScore }) {
  const routingEvidence = routingResult?.evidence || {}
  const mxEvidence = mxResult?.evidence || {}
  const connectorEvidence = connectorResult?.evidence || {}
  const directEvidence = directResult?.evidence || {}
  const connectorFindings = connectorResult?.findings ?? []
  const directFindings = directResult?.findings ?? []

  const routingType = routingEvidence.routing_type || 'unknown'
  const routingDescription = routingEvidence.routing_description || routingEvidence.description || ''
  const mxRoutingType = mxEvidence.routing_type || mxEvidence.architecture || routingType
  const rawProviders = mxEvidence.providers || routingEvidence.providers || []
  const mxHealth = typeof mxEvidence.health_score === 'number' ? Math.round(mxEvidence.health_score) : null
  const mxRecords = mxEvidence.mx_records || routingEvidence.mx_hops || []

  const inboundCount = connectorEvidence.inbound_connector_count ?? 0
  const outboundCount = connectorEvidence.outbound_connector_count ?? 0
  const transportCount = connectorEvidence.transport_rule_count ?? directEvidence.transport_rule_count ?? 0
  const smtpDisabled = directEvidence.smtp_auth_disabled
  const outboundConnectors = connectorEvidence.outbound_connectors || []

  const inboundWeak = connectorFindings.some(finding => /inbound connector|enhanced filtering|require tls/i.test(String(finding.name || '')))
  const outboundWeak = connectorFindings.some(finding => /outbound connector/i.test(String(finding.name || '')))
  const transportWeak = connectorFindings.some(finding => /transport rule/i.test(String(finding.name || '')))
    || directFindings.some(finding => /transport rule/i.test(String(finding.name || '')))
  const anonymousConnectorOpen = directFindings.some(finding => /anonymous .*connector|no ip restriction/i.test(String(finding.title || finding.name || '')))
  const connectorRuleGap = directFindings.some(finding => /no blocking transport rule/i.test(String(finding.title || finding.name || '')))

  const segProviders = rawProviders.filter(provider => provider !== 'Microsoft EOP' && provider !== 'Google Workspace')
  const platformProviders = rawProviders.filter(provider => provider === 'Microsoft EOP' || provider === 'Google Workspace')
  const gatewayLabel = segProviders[0] ? `${providerLabel(segProviders[0])} SEG` : 'SEG'
  const platformLabel = platformProviders.includes('Microsoft EOP')
    ? 'Microsoft 365'
    : providerLabel(platformProviders[0]) || 'Mail platform'
  const providerSummary = rawProviders.length > 0
    ? rawProviders.map(providerLabel).join(', ')
    : 'No provider fingerprint'

  const mxIncludesPlatform = mxRoutingType === 'mixed' || mxRoutingType === 'direct_m365' || routingType === 'direct_to_platform'
  const directReachable = mxIncludesPlatform
    || smtpDisabled === false
    || anonymousConnectorOpen
    || connectorRuleGap
    || directFindings.some(finding => /globally enabled|direct send/i.test(String(finding.title || finding.name || '')))

  const bypassPossible = directReachable || inboundWeak || transportWeak || smtpDisabled === false

  const mxSummary = mxRoutingType === 'mixed'
    ? 'Mixed provider routing'
    : mxRoutingType === 'direct_m365' || routingType === 'direct_to_platform'
      ? 'Direct platform MX'
      : segProviders.length > 0
        ? 'Gateway-fronted MX'
        : 'Unclassified MX'
  const mxConfigSummary = mxRoutingType === 'mixed'
    ? 'MX splits between SEG and platform targets.'
    : mxRoutingType === 'direct_m365' || routingType === 'direct_to_platform'
      ? 'MX resolves straight to the platform edge.'
      : segProviders.length > 0
        ? 'MX resolves to the external security gateway first.'
        : 'MX topology could not be clearly classified.'

  const mxPointsTo = mxRecords.length > 0
    ? mxRecords.slice(0, 4).map(record => record.provider ? `${providerLabel(record.provider)}: ${record.host}` : record.host)
    : []

  const outboundRoutedThroughSeg = outboundConnectors.some(connector => {
    const smartHosts = Array.isArray(connector.smartHosts) ? connector.smartHosts : []
    return smartHosts.length > 0 || connector.useMxRecord === false
  })
  const directOutboundAllowed = outboundConnectors.some(connector => connector.useMxRecord === true)

  const expectedPathBadge = hasSegPath(segProviders, routingType)
    ? 'Expected ingress defined'
    : 'Gateway path incomplete'

  function hasSegPath(segList, routeType) {
    return segList.length > 0 || routeType === 'seg_gateway' || routeType === 'seg_only'
  }

  const inboundPresence = inboundCount > 0
    ? { label: 'Present', tone: 'good' }
    : { label: 'Missing', tone: 'bad' }
  const inboundEffectiveness = inboundCount === 0
    ? { label: 'No restriction', tone: 'bad' }
    : inboundWeak
      ? { label: 'Not restrictive', tone: 'high' }
      : { label: 'Expected path only', tone: 'good' }
  const inboundCoverage = inboundCount === 0
    ? { label: 'None', tone: 'bad' }
    : directReachable
      ? { label: 'Not full coverage', tone: 'high' }
      : { label: 'No direct gap seen', tone: 'good' }

  const transportPresence = transportCount > 0
    ? { label: 'Present', tone: 'good' }
    : { label: 'Missing', tone: 'bad' }
  const transportEffectiveness = transportCount === 0
    ? { label: 'No enforcement', tone: 'bad' }
    : transportWeak
      ? { label: 'Not sufficient', tone: 'high' }
      : { label: 'Expected path only', tone: 'good' }
  const transportCoverage = transportCount === 0
    ? { label: 'None', tone: 'bad' }
    : directReachable
      ? { label: 'Not global', tone: 'high' }
      : { label: 'Tenant-wide not disproven', tone: 'good' }

  const outboundPresence = outboundCount > 0
    ? { label: 'Present', tone: 'good' }
    : { label: 'Missing', tone: 'bad' }
  const outboundEffectiveness = outboundCount === 0
    ? { label: 'No routed control', tone: 'bad' }
    : outboundWeak
      ? { label: 'Not enforced', tone: 'high' }
      : outboundRoutedThroughSeg
        ? { label: 'Routed through connector', tone: 'good' }
        : { label: 'Present only', tone: 'warn' }
  const outboundCoverage = outboundCount === 0
    ? { label: 'Direct outbound possible', tone: 'bad' }
    : outboundRoutedThroughSeg && !directOutboundAllowed
      ? { label: 'Controlled', tone: 'good' }
      : outboundRoutedThroughSeg
        ? { label: 'Partial', tone: 'warn' }
        : { label: 'Not forced via SEG', tone: 'high' }
  const outboundRouteText = outboundRoutedThroughSeg ? 'Yes' : 'No'
  const directOutboundText = outboundCount === 0 ? 'Unknown' : directOutboundAllowed ? 'Yes' : 'No'

  const directPathState = directReachable
    ? { label: 'Bypass reachable', tone: 'bad' }
    : { label: 'No direct path seen', tone: 'good' }
  const smtpState = smtpDisabled === true
    ? { label: 'Disabled', tone: 'good' }
    : smtpDisabled === false
      ? { label: 'Enabled', tone: 'bad' }
      : { label: 'Unknown', tone: 'warn' }

  const causalBullets = []
  if (mxRoutingType === 'direct_m365') {
    causalBullets.push('MX points directly to Microsoft 365 with no external SEG in front.')
  }
  if (mxRoutingType === 'mixed') {
    causalBullets.push('MX includes both the SEG and Microsoft 365 endpoints.')
  }
  if (directReachable) {
    causalBullets.push('Direct-to-M365 delivery is reachable.')
  }
  if (inboundCount === 0) {
    causalBullets.push('No inbound connector fully restricts accepted source paths.')
  } else if (inboundWeak || directReachable) {
    causalBullets.push('Inbound connector does not fully restrict accepted source paths.')
  }
  if (transportCount === 0) {
    causalBullets.push('No transport rule enforces SEG-only ingress globally.')
  } else if (transportWeak || directReachable || connectorRuleGap) {
    causalBullets.push('Transport rules do not enforce SEG-only ingress globally.')
  }
  if (smtpDisabled === false) {
    causalBullets.push('SMTP AUTH is enabled.')
  }
  if (anonymousConnectorOpen) {
    causalBullets.push('Anonymous receive connector exposure keeps a direct delivery path open.')
  }
  if (causalBullets.length === 0) {
    causalBullets.push('No direct bypass cause was confirmed from the current evidence set.')
  }

  const authTone = authScore != null && authScore >= 80 ? 'good' : authScore != null && authScore >= 60 ? 'warn' : 'bad'

  return (
    <section style={{ margin: '0 18px 12px', padding: 14, border: '1px solid var(--border)', borderRadius: 14, background: 'linear-gradient(180deg, rgba(255,255,255,.025), rgba(255,255,255,.015))' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'start', flexWrap: 'wrap', marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '1px', textTransform: 'uppercase', fontWeight: 700 }}>Mail Flow Overview</div>
          <div style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {authScore != null && <InlineBadge label={`Auth score ${authScore}`} tone={authTone} />}
            <InlineBadge label={bypassPossible ? 'Bypass reachable' : 'No direct bypass confirmed'} tone={bypassPossible ? 'bad' : 'good'} />
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10, marginBottom: 12 }}>
        <OverviewMetaCard
          label="Providers detected"
          value={providerSummary}
          subvalue={mxSummary}
          tone={mxRoutingType === 'mixed' ? 'high' : mxRoutingType === 'direct_m365' ? 'warn' : 'good'}
        />
        <OverviewMetaCard
          label="MX health"
          value={mxHealth != null ? String(mxHealth) : 'Unavailable'}
          subvalue={mxHealth != null ? (mxHealth >= 70 ? 'Healthy' : mxHealth >= 40 ? 'Needs review' : 'Elevated risk') : null}
          tone={mxHealth != null ? (mxHealth >= 70 ? 'good' : mxHealth >= 40 ? 'warn' : 'bad') : 'neutral'}
          mono={mxHealth != null}
        />
        <OverviewMetaCard
          label="MX configuration"
          value={mxConfigSummary}
          subvalue={mxRoutingType === 'mixed' ? 'Mixed provider routing' : mxRoutingType === 'direct_m365' ? 'Direct platform routing' : 'Gateway-first routing'}
          tone={mxRoutingType === 'mixed' ? 'high' : mxRoutingType === 'direct_m365' ? 'warn' : 'good'}
        />
        <OverviewMetaCard
          label="MX points to"
          value={mxPointsTo.length > 0 ? mxPointsTo.slice(0, 2).join(' | ') : 'No MX evidence'}
          subvalue={routingDescription || null}
          tone={mxRoutingType === 'mixed' ? 'high' : directReachable ? 'warn' : 'neutral'}
          mono={mxPointsTo.length > 0}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
        <PathPanel title="Expected Path" tone="good" badge={expectedPathBadge}>
          <PathFlow nodes={['Internet', gatewayLabel, platformLabel]} tone="good" />
          <ControlRow
            label="Inbound connector status"
            presence={inboundPresence}
            effectiveness={inboundEffectiveness}
            coverage={inboundCoverage}
            note={inboundCount > 0
              ? `${inboundCount} inbound connector${inboundCount === 1 ? '' : 's'} configured. ${inboundWeak ? 'Current findings show weak source restriction or filtering scope.' : 'Current findings support the expected gateway path.'}`
              : 'No inbound connector evidence was found.'}
          />
          <ControlRow
            label="Outbound connector status"
            presence={outboundPresence}
            effectiveness={outboundEffectiveness}
            coverage={outboundCoverage}
            note={outboundCount > 0
              ? `${outboundCount} outbound connector${outboundCount === 1 ? '' : 's'} configured. Routed through SEG: ${outboundRouteText}. Direct outbound allowed: ${directOutboundText}. ${outboundRoutedThroughSeg ? 'At least one connector routes through smart hosts or a non-MX path.' : 'Connectors do not clearly force outbound mail through the SEG.'}`
              : 'No outbound connector evidence was found.'}
          />
          <ControlRow
            label="Transport rules status"
            presence={transportPresence}
            effectiveness={transportEffectiveness}
            coverage={transportCoverage}
            note={transportCount > 0
              ? `${transportCount} transport rule${transportCount === 1 ? '' : 's'} detected. ${transportWeak ? 'Findings indicate rule scope is not sufficient to close all ingress gaps.' : 'Rules support the expected path, but that is not the same as full tenant enforcement.'}`
              : 'No transport rules were returned in evidence.'}
          />
        </PathPanel>

        <PathPanel title="Bypass Path" tone="bad" badge={directPathState.label}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--red)', fontSize: 11.5, fontWeight: 700 }}>
            <AlertTriangle size={14} />
            <span>Unprotected ingress</span>
          </div>
          <PathFlow nodes={['Internet', platformLabel]} tone="bad" dashed />
          <ControlRow
            label="Direct-to-M365 reachability"
            presence={{ label: 'Observed', tone: directReachable ? 'bad' : 'good' }}
            effectiveness={{ label: directReachable ? 'Reachable' : 'Not observed', tone: directReachable ? 'bad' : 'good' }}
            coverage={{ label: directReachable ? 'Bypass open' : 'No direct path seen', tone: directReachable ? 'bad' : 'good' }}
            note={directReachable ? 'Direct delivery remains reachable outside the expected gateway path.' : 'No direct internet-to-platform ingress was confirmed from current evidence.'}
          />
          <ControlRow
            label="SMTP AUTH"
            presence={{ label: 'Checked', tone: 'neutral' }}
            effectiveness={smtpState}
            coverage={{ label: smtpDisabled === false ? 'Credential-based bypass' : smtpDisabled === true ? 'Legacy auth path reduced' : 'Coverage unknown', tone: smtpDisabled === false ? 'bad' : smtpDisabled === true ? 'good' : 'warn' }}
            note={smtpDisabled === false ? 'Legacy authenticated SMTP remains available and can bypass the expected ingress model.' : smtpDisabled === true ? 'SMTP AUTH is disabled globally in current evidence.' : 'SMTP AUTH state was not conclusively returned.'}
          />
          <ControlRow
            label="Connector coverage gap"
            presence={inboundPresence}
            effectiveness={{ label: inboundCount === 0 ? 'No connector control' : inboundWeak ? 'Weak restriction' : 'Expected-path restrictive', tone: inboundCount === 0 ? 'bad' : inboundWeak ? 'high' : 'good' }}
            coverage={{ label: directReachable ? 'Gap remains' : inboundWeak ? 'Partial' : 'No direct gap seen', tone: directReachable ? 'bad' : inboundWeak ? 'warn' : 'good' }}
            note={inboundCount === 0 ? 'No inbound connector exists to constrain accepted source paths.' : directReachable ? 'Connectors support the intended path but do not fully block alternate ingress.' : 'Current connector evidence does not show an obvious direct coverage gap.'}
          />
          <ControlRow
            label="Transport rule coverage gap"
            presence={transportPresence}
            effectiveness={{ label: transportCount === 0 ? 'No rule control' : transportWeak ? 'Rule scope weak' : 'Rules present', tone: transportCount === 0 ? 'bad' : transportWeak ? 'high' : 'good' }}
            coverage={{ label: transportCount === 0 || transportWeak || directReachable ? 'Not global' : 'No direct gap seen', tone: transportCount === 0 || transportWeak || directReachable ? 'bad' : 'good' }}
            note={transportCount === 0 ? 'No transport rule evidence was returned for direct-path containment.' : transportWeak || connectorRuleGap ? 'Rules exist, but findings show they do not fully restrict or audit bypass delivery.' : 'Rules support the expected path, but they should not be treated as proof of full tenant protection.'}
          />
        </PathPanel>
      </div>

      <div style={{ padding: '12px', borderRadius: 12, border: `1px solid ${toneForState(bypassPossible ? 'bad' : 'neutral').border}`, background: bypassPossible ? 'rgba(255,79,94,.06)' : 'rgba(255,255,255,.02)' }}>
        <div style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '1px', textTransform: 'uppercase', fontWeight: 700, marginBottom: 8 }}>Why Bypass Is Possible</div>
        <div style={{ display: 'grid', gap: 6 }}>
          {causalBullets.map((bullet, index) => (
            <div key={`${bullet}-${index}`} style={{ display: 'flex', gap: 8, alignItems: 'start' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: bypassPossible ? 'var(--red)' : 'var(--muted)', marginTop: 6, flexShrink: 0 }} />
              <span style={{ fontSize: 11.5, color: 'var(--text)', lineHeight: 1.45 }}>{bullet}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function SectionCard({ section, selected, onSelect }) {
  const Icon = SECTION_META[section.key]?.icon || Shield
  const tone = sectionTone(section.findings)
  const counts = sectionCounts(section.findings)
  const issues = sectionIssues(section.findings)
  const score = section.score
  const scoreBadge = scoreTone(score)
  const neutralChip = chipStyle()

  return (
    <button
      onClick={onSelect}
      style={{
        width: '100%',
        textAlign: 'left',
        color: 'inherit',
        cursor: 'pointer',
        background: selected ? 'rgba(255,255,255,.04)' : 'var(--surface)',
        border: `1px solid ${selected ? tone.border : 'var(--border)'}`,
        borderLeft: `4px solid ${tone.color}`,
        borderRadius: 12,
        padding: 14,
        display: 'grid',
        gap: 10,
        transition: 'transform .12s ease, border-color .12s ease, background .12s ease',
      }}
      onMouseOver={e => { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.borderColor = tone.border }}
      onMouseOut={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.borderColor = selected ? tone.border : 'var(--border)' }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: 12 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', minWidth: 0 }}>
          <div style={{ width: 28, height: 28, borderRadius: 8, display: 'grid', placeItems: 'center', border: `1px solid ${tone.border}`, background: tone.bg, flexShrink: 0 }}>
            <Icon size={14} color={tone.color} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 10, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--muted)', fontWeight: 700 }}>{section.label}</div>
            {score != null && (
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 6, padding: '3px 8px', borderRadius: 999, border: `1px solid ${scoreBadge.border}`, background: scoreBadge.bg, color: scoreBadge.color, fontSize: 11, fontWeight: 700 }}>
                Score {score}
              </div>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'end' }}>
          <span style={{ ...neutralChip, display: 'inline-flex', alignItems: 'center', padding: '3px 8px', borderRadius: 999, border: `1px solid ${neutralChip.border}`, fontSize: 11, fontWeight: 700 }}>
            {counts.fail} fail
          </span>
          <span style={{ ...neutralChip, display: 'inline-flex', alignItems: 'center', padding: '3px 8px', borderRadius: 999, border: `1px solid ${neutralChip.border}`, fontSize: 11, fontWeight: 700 }}>
            {counts.warn} warn
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gap: 6 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {issues.length > 0 ? issues.map(issue => (
            <span key={issue} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 8px', borderRadius: 999, fontSize: 11, color: 'var(--text)', background: 'rgba(255,255,255,.03)', border: '1px solid var(--border)', minWidth: 0 }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: tone.color, flexShrink: 0 }} />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{issue}</span>
            </span>
          )) : (
            <span style={{ color: 'var(--muted)', fontSize: 11 }}>None</span>
          )}
        </div>
      </div>
    </button>
  )
}

function SeverityGroup({ group }) {
  const borderColor = group.color === 'var(--red)'
    ? 'rgba(255,79,94,.18)'
    : group.color === 'var(--yellow)'
      ? 'rgba(255,215,64,.18)'
      : 'rgba(249,115,22,.18)'
  const neutralChip = chipStyle()

  return (
    <section style={{ border: `1px solid ${borderColor}`, borderRadius: 12, background: 'var(--surface)', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '10px 12px', borderBottom: '1px solid var(--border)', background: 'rgba(255,255,255,.02)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: group.color, boxShadow: `0 0 0 4px ${group.color === 'var(--red)' ? 'rgba(255,79,94,.08)' : group.color === 'var(--yellow)' ? 'rgba(255,215,64,.08)' : 'rgba(249,115,22,.08)'}` }} />
          <div style={{ fontSize: 12, fontWeight: 700 }}>{group.label}</div>
        </div>
        <span style={{ ...neutralChip, display: 'inline-flex', alignItems: 'center', padding: '3px 8px', borderRadius: 999, border: `1px solid ${neutralChip.border}`, fontSize: 11, fontWeight: 700 }}>
          {group.findings.length}
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ color: 'var(--muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.8px' }}>
              <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid var(--border)', width: '34%' }}>Finding</th>
              <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid var(--border)', width: '14%' }}>Area</th>
              <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid var(--border)', width: '16%' }}>Exploitability</th>
              <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>Fix</th>
            </tr>
          </thead>
          <tbody>
            {group.findings.map((finding, index) => {
              const exploitTone = finding.exploitability === 'Critical'
                ? 'red'
                : finding.exploitability === 'High'
                  ? 'orange'
                  : finding.exploitability === 'Medium'
                    ? 'yellow'
                    : 'neutral'
              return (
                <tr key={finding.check_id} style={{ borderBottom: index === group.findings.length - 1 ? 'none' : '1px solid rgba(255,255,255,.04)' }}>
                  <td style={{ padding: '11px 12px', verticalAlign: 'top' }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{finding.name}</div>
                  </td>
                  <td style={{ padding: '11px 12px', verticalAlign: 'top' }}>
                    <span style={{ ...chipStyle(), display: 'inline-flex', alignItems: 'center', padding: '3px 8px', borderRadius: 999, border: '1px solid', fontSize: 11, fontWeight: 700 }}>
                      {finding.category}
                    </span>
                  </td>
                  <td style={{ padding: '11px 12px', verticalAlign: 'top' }}>
                    <span style={{ ...chipStyle(exploitTone), display: 'inline-flex', alignItems: 'center', padding: '3px 8px', borderRadius: 999, border: '1px solid', fontSize: 11, fontWeight: 700 }}>
                      {finding.exploitability}
                    </span>
                  </td>
                  <td style={{ padding: '11px 12px', verticalAlign: 'top' }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', padding: '3px 8px', borderRadius: 999, border: '1px solid var(--border)', background: 'var(--surface2)', color: 'var(--text)', fontSize: 11, fontWeight: 700 }}>
                      {finding.fix_hint}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default function MailSecurityPage({ tenant }) {
  const { activeDomain } = useScope()
  const dns = useDnsPosture()
  const mail = useMailRouting()
  const [selectedFilter, setSelectedFilter] = useState('all')

  const authResult = dns.taskResults['authentication_status']
  const mxResult = dns.taskResults['mx_health']
  const pathResult = mail.routing.taskResults['inbound_path_mapping']
  const connResult = mail.routing.taskResults['connector_posture']
  const directResult = mail.routing.taskResults['direct_send_check']
  const mtaResult = mail.tls.taskResults['mta_sts_check']
  const tlsrptResult = mail.tls.taskResults['tlsrpt_check']
  const starttlsResult = mail.tls.taskResults['starttls_probe']
  const conflictResult = mail.tls.taskResults['tls_conflict_analysis']
  const daneResult = mail.tls.taskResults['dane_tlsa_check']

  const authFindings = sortFindings(
    (authResult?.findings ?? [])
      .filter(finding => !String(finding.id).startsWith('auth-summary-'))
      .map(finding => normalizeFinding('auth', 'Authentication', finding, activeDomain))
  )
  const mxFindings = sortFindings(
    (mxResult?.findings ?? []).map(finding => normalizeFinding('mx', 'MX', finding, activeDomain))
  )
  const routingFindings = sortFindings([
    ...(pathResult?.findings ?? []).map(finding => normalizeFinding('routing', 'Routing', finding, activeDomain)),
    ...(connResult?.findings ?? []).map(finding => normalizeFinding('routing', 'Routing', finding, activeDomain)),
    ...(directResult?.findings ?? []).map(finding => normalizeFinding('routing', 'Routing', finding, activeDomain)),
  ])
  const tlsFindings = sortFindings([
    ...(mtaResult?.findings ?? []).map(finding => normalizeFinding('tls', 'TLS', finding, activeDomain)),
    ...(tlsrptResult?.findings ?? []).map(finding => normalizeFinding('tls', 'TLS', finding, activeDomain)),
    ...(starttlsResult?.findings ?? []).map(finding => normalizeFinding('tls', 'TLS', finding, activeDomain)),
    ...(conflictResult?.findings ?? []).map(finding => normalizeFinding('tls', 'TLS', finding, activeDomain)),
    ...(daneResult?.findings ?? []).map(finding => normalizeFinding('tls', 'TLS', finding, activeDomain)),
  ])

  const authScore = authScoreFromEvidence(authResult?.evidence)

  const sections = [
    { key: 'auth', label: SECTION_META.auth.label, icon: SECTION_META.auth.icon, score: authScore, findings: authFindings },
    { key: 'routing', label: SECTION_META.routing.label, icon: SECTION_META.routing.icon, findings: routingFindings },
    { key: 'tls', label: SECTION_META.tls.label, icon: SECTION_META.tls.icon, findings: tlsFindings },
    { key: 'mx', label: SECTION_META.mx.label, icon: SECTION_META.mx.icon, findings: mxFindings },
  ]

  const allFindings = sections.flatMap(section => section.findings)
  const visibleFindings = useMemo(() => {
    const scoped = selectedFilter === 'all'
      ? allFindings
      : allFindings.filter(finding => finding.sectionKey === selectedFilter)
    return scoped.filter(finding => finding.risk_level === 'critical' || finding.risk_level === 'high' || finding.risk_level === 'medium')
  }, [allFindings, selectedFilter])

  const sectionCountsMap = useMemo(() => {
    return sections.reduce((acc, section) => {
      acc[section.key] = section.findings.length
      return acc
    }, { all: allFindings.length })
  }, [allFindings, sections])

  const severityBuckets = useMemo(() => {
    return SEVERITY_GROUPS
      .map(group => ({
        ...group,
        findings: visibleFindings.filter(finding => finding.risk_level === group.key),
      }))
      .filter(group => group.findings.length > 0)
  }, [visibleFindings])

  const counts = visibleFindings.reduce((acc, finding) => {
    acc[finding.risk_level] = (acc[finding.risk_level] || 0) + 1
    return acc
  }, {})

  const tenantChip = tenant?.display_name || ''
  const activeChip = activeDomain || ''

  return (
    <div style={{
      minHeight: '100vh',
      background: 'radial-gradient(circle at top left, rgba(255,79,94,.06), transparent 28%), radial-gradient(circle at top right, rgba(255,215,64,.05), transparent 24%), var(--bg)',
      color: 'var(--text)',
    }}>
      <div style={{
        padding: '14px 18px',
        borderBottom: '1px solid var(--border)',
        background: 'rgba(8,12,18,.94)',
        backdropFilter: 'blur(10px)',
        position: 'sticky',
        top: 0,
        zIndex: 10,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        flexWrap: 'wrap',
      }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: '-.2px' }}>MailGuard</div>
          <div style={{ fontSize: 10, color: 'var(--accent)', letterSpacing: '1.2px', fontWeight: 700, marginTop: 2 }}>{PRODUCT_LABEL}</div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', justifyContent: 'end' }}>
          {tenantChip && (
            <span style={{ ...chipStyle(), display: 'inline-flex', alignItems: 'center', padding: '4px 8px', borderRadius: 999, border: `1px solid ${chipStyle().border}`, fontSize: 11, fontWeight: 700 }}>
              {tenantChip}
            </span>
          )}
          {activeChip && (
            <span style={{ ...chipStyle(), display: 'inline-flex', alignItems: 'center', padding: '4px 8px', borderRadius: 999, border: `1px solid ${chipStyle().border}`, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              {activeChip}
            </span>
          )}
          <span style={{ ...chipStyle('red'), display: 'inline-flex', alignItems: 'center', padding: '4px 8px', borderRadius: 999, border: `1px solid ${chipStyle('red').border}`, fontSize: 11, fontWeight: 700 }}>
            {allFindings.filter(finding => finding.risk_level === 'critical').length} critical
          </span>
          <span style={{ ...chipStyle('orange'), display: 'inline-flex', alignItems: 'center', padding: '4px 8px', borderRadius: 999, border: `1px solid ${chipStyle('orange').border}`, fontSize: 11, fontWeight: 700 }}>
            {allFindings.filter(finding => finding.risk_level === 'high').length} high
          </span>
          <span style={{ ...chipStyle('yellow'), display: 'inline-flex', alignItems: 'center', padding: '4px 8px', borderRadius: 999, border: `1px solid ${chipStyle('yellow').border}`, fontSize: 11, fontWeight: 700 }}>
            {allFindings.filter(finding => finding.risk_level === 'medium').length} medium
          </span>
          <button
            onClick={() => { dns.triggerRefresh(); mail.triggerRefresh() }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '7px 12px',
              borderRadius: 8,
              fontSize: 11,
              fontWeight: 700,
              background: 'var(--accent)',
              color: '#000',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      <MailFlowOverviewPanel
        mxResult={mxResult}
        routingResult={pathResult}
        connectorResult={connResult}
        directResult={directResult}
        authScore={authScore}
      />

      <div style={{ padding: '12px 18px 0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <Filter size={12} color="var(--muted)" />
          {FILTERS.map(filter => (
            <button
              key={filter.key}
              onClick={() => setSelectedFilter(filter.key)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 10px',
                borderRadius: 999,
                border: `1px solid ${selectedFilter === filter.key ? 'rgba(255,255,255,.22)' : 'var(--border)'}`,
                background: selectedFilter === filter.key ? 'rgba(255,255,255,.05)' : 'var(--surface2)',
                color: selectedFilter === filter.key ? 'var(--text)' : 'var(--muted)',
                cursor: 'pointer',
                fontSize: 11,
                fontWeight: 700,
              }}
            >
              {filter.label}
              <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>{filter.key === 'all' ? allFindings.length : sectionCountsMap[filter.key] || 0}</span>
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding: '14px 18px 12px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 10 }}>
          {sections.map(section => (
            <SectionCard
              key={section.key}
              section={section}
              selected={selectedFilter === section.key}
              onSelect={() => setSelectedFilter(section.key)}
            />
          ))}
        </div>
      </div>

      <div style={{ padding: '0 18px 18px' }}>
        <div style={{ display: 'grid', gap: 10 }}>
          {severityBuckets.length > 0 ? severityBuckets.map(group => (
            <SeverityGroup
              key={group.key}
              group={group}
            />
          )) : (
            <div style={{ padding: '12px 14px', border: '1px solid var(--border)', borderRadius: 12, background: 'var(--surface)', color: 'var(--muted)', fontSize: 12 }}>
              No findings.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
