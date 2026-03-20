import { useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, ChevronUp, ChevronDown, Crosshair, Download, RefreshCw } from 'lucide-react'
import RiskGauge from '../../../components/RiskGauge'
import { riskLevelFromScore } from '../../../utils/uiLabels'

const API = '/api/v1/aggressive-scan'

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const RISK_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

const WORKFLOW_STATUS_ORDER = {
  new: 0,
  investigating: 1,
  resolved: 2,
  ignored: 3,
}

const MUTATION_LABELS = {
  character_omission: 'character omission',
  character_insertion: 'character insertion',
  character_substitution: 'character substitution',
  keyboard_substitution: 'keyboard typo',
  transposition: 'transposition',
  tld_substitution: 'TLD swap',
  hyphenation_attack: 'hyphenation',
  unicode_homoglyph: 'homoglyph',
  unicode_homoglyph_mixed_script: 'mixed script',
  multi_character_edit: 'multi-edit',
  pattern_match: 'pattern match',
}

function toneForRisk(level = 'low') {
  if (level === 'critical') return { color: 'var(--red)', background: 'rgba(255,79,94,.08)', border: 'rgba(255,79,94,.22)' }
  if (level === 'high') return { color: '#f97316', background: 'rgba(249,115,22,.08)', border: 'rgba(249,115,22,.22)' }
  if (level === 'medium') return { color: 'var(--yellow)', background: 'rgba(255,215,64,.08)', border: 'rgba(255,215,64,.22)' }
  return { color: 'var(--muted)', background: 'rgba(255,255,255,.03)', border: 'var(--border)' }
}

function toneForStatus(tone = 'neutral') {
  if (tone === 'info') return { color: 'var(--accent)', background: 'rgba(0,229,255,.08)', border: 'rgba(0,229,255,.20)' }
  if (tone === 'bad') return { color: 'var(--red)', background: 'rgba(255,79,94,.08)', border: 'rgba(255,79,94,.22)' }
  if (tone === 'warn') return { color: 'var(--yellow)', background: 'rgba(255,215,64,.08)', border: 'rgba(255,215,64,.22)' }
  if (tone === 'good') return { color: 'var(--green)', background: 'rgba(0,230,118,.08)', border: 'rgba(0,230,118,.20)' }
  return { color: 'var(--muted)', background: 'rgba(255,255,255,.03)', border: 'var(--border)' }
}

function buttonStyle(primary = false, disabled = false) {
  if (primary) {
    return {
      display: 'inline-flex',
      alignItems: 'center',
      gap: 8,
      padding: '8px 14px',
      borderRadius: 8,
      border: 'none',
      background: disabled ? 'var(--surface2)' : 'var(--accent)',
      color: disabled ? 'var(--muted)' : '#000',
      cursor: disabled ? 'not-allowed' : 'pointer',
      fontSize: 12,
      fontWeight: 700,
      fontFamily: 'var(--font-body)',
    }
  }

  return {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 8,
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid var(--border)',
    background: 'var(--surface)',
    color: disabled ? 'var(--muted)' : 'var(--text)',
    cursor: disabled ? 'not-allowed' : 'pointer',
    fontSize: 12,
    fontWeight: 600,
    fontFamily: 'var(--font-body)',
  }
}

function riskBadge(level) {
  const tone = toneForRisk(level)
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '3px 8px',
      borderRadius: 999,
      border: `1px solid ${tone.border}`,
      background: tone.background,
      color: tone.color,
      fontSize: 10.5,
      fontWeight: 700,
      letterSpacing: '.3px',
      textTransform: 'uppercase',
      whiteSpace: 'nowrap',
    }}>
      {RISK_LABELS[level] || RISK_LABELS.low} (Exposure)
    </span>
  )
}

function statusBadge(label, tone = 'neutral') {
  const colors = toneForStatus(tone)
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '3px 8px',
      borderRadius: 999,
      border: `1px solid ${colors.border}`,
      background: colors.background,
      color: colors.color,
      fontSize: 10.5,
      fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

function signalChip(label, tone = 'neutral') {
  const colors = toneForStatus(tone)
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '2px 6px',
      borderRadius: 999,
      border: `1px solid ${colors.border}`,
      background: colors.background,
      color: colors.color,
      fontSize: 9.5,
      fontWeight: 700,
      letterSpacing: '.2px',
      whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

function scoreBar(score, color) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, minWidth: 60, height: 4, borderRadius: 999, overflow: 'hidden', background: 'var(--surface2)' }}>
        <div style={{ width: `${Math.max(0, Math.min(100, score || 0))}%`, height: '100%', background: color }} />
      </div>
      <span style={{ minWidth: 26, textAlign: 'right', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
        {score ?? 0}
      </span>
    </div>
  )
}

function hasDnsSignals(result) {
  return Boolean(result?.dns?.has_mx || result?.dns?.has_a || result?.dns?.has_aaaa || result?.dns?.has_ns || result?.dns?.has_txt || result?.takeover_risk)
}

function hasMeaningfulSignals(result, surfaceMetrics) {
  return Boolean(
    result?.dns?.has_mx ||
    result?.dns?.has_a ||
    result?.dns?.has_aaaa ||
    result?.dns?.has_ns ||
    result?.dns?.has_txt ||
    isMailRelated(result)
  )
}

function isDormant(result) {
  return Boolean(
    result?.is_registered &&
    !result?.dns?.has_mx &&
    !result?.dns?.has_a &&
    !result?.dns?.has_aaaa &&
    !result?.takeover_risk &&
    (result?.certs?.length || 0) === 0
  )
}

function hasExploitableDns(result) {
  const reasons = (result?.reasons || []).join(' ').toLowerCase()
  return Boolean(result?.takeover_risk || /takeover|dangling|broken|vendor|wildcard|exploit/i.test(reasons))
}

function needsInsightReview(result) {
  return Boolean(
    result?.takeover_risk ||
    result?.has_homoglyphs ||
    result?.mixed_script ||
    (result?.certs?.length > 0) ||
    (result?.whois?.age_days != null && result.whois.age_days <= 90)
  )
}

function dedupe(values) {
  return Array.from(new Set(values.filter(Boolean)))
}

function rootDomainOptions(domains) {
  const normalized = dedupe(
    (domains || []).map((domain) => String(domain || '').trim().toLowerCase())
  )

  return normalized.filter((domain) => (
    !normalized.some((candidate) => candidate !== domain && domain.endsWith(`.${candidate}`))
  ))
}

function averageScore(rows) {
  if (!rows.length) return 0
  return Math.round(rows.reduce((sum, row) => sum + (row.enriched_score || 0), 0) / rows.length)
}

function resultStatus(result) {
  if (result.takeover_risk) return { label: 'Investigate', tone: 'bad' }
  if (result.is_registered && (result.dns?.has_mx || result.dns?.has_a || result.dns?.has_aaaa || (result.certs?.length > 0))) {
    return { label: 'Active', tone: 'warn' }
  }
  if (isDormant(result)) return { label: 'Dormant', tone: 'warn' }
  if (result.is_registered) return { label: 'Registered', tone: 'warn' }
  return { label: 'Unresolved', tone: 'neutral' }
}

function hasOperationalDns(result) {
  return Boolean(result?.dns?.has_a || result?.dns?.has_aaaa || result?.dns?.has_ns)
}

function hasExternalMailHosting(result) {
  if (!result?.dns?.has_mx) return false
  const base = String(result?.base_domain || '').toLowerCase()
  const mxRecords = result?.dns?.mx_records || []
  if (!base || mxRecords.length === 0) return false
  return mxRecords.some((host) => !String(host || '').toLowerCase().endsWith(base))
}

function recommendedNextStep(result) {
  if (result.takeover_risk) return 'Disable unused DNS records or secure the mapped service immediately.'
  if (result.dns?.has_mx && hasExternalMailHosting(result)) return 'Block or monitor this domain at your email gateway and investigate external mail routing.'
  if (result.dns?.has_mx) return 'Review and block the domain at the email gateway, then monitor for phishing activity.'
  if (result.is_registered && hasOperationalDns(result)) return 'Verify domain ownership and disable unused DNS records.'
  if ((result?.dns?.has_a || result?.dns?.has_ns) && !result?.dns?.has_mx) return 'Monitor for unexpected web activity and verify the DNS records are intentional.'
  if (result.is_registered) return 'Verify domain ownership and keep the domain under monitoring.'
  return 'Keep the candidate in watchlist scope and rescan if new DNS signals appear.'
}

function reputationIndicator(summary) {
  if (!summary) return null
  const abusiveIpFound = (summary?.ips || []).some((item) => (item?.abuseConfidenceScore || 0) > 10)
  if (abusiveIpFound) return { label: 'ABUSE-IP', tone: 'warn' }
  return null
}

function rootFlaggedIpCount(summary) {
  return Number(summary?.flaggedIpCount || 0)
}

function titleCaseLabel(value) {
  return String(value || 'unknown')
    .split(' ')
    .map((part) => part ? `${part.charAt(0).toUpperCase()}${part.slice(1)}` : part)
    .join(' ')
}

function formatLookupTimestamp(value) {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString()
}

function formatDomainAge(ageDays) {
  if (ageDays == null || Number.isNaN(Number(ageDays))) return null
  const days = Math.max(0, Math.round(Number(ageDays)))
  const classification = days > 90 ? 'ESTABLISHED' : 'RECENT'
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} (${classification})`
  if (days < 365) {
    const months = Math.round(days / 30)
    return `${months} month${months === 1 ? '' : 's'} (${days}d) (${classification})`
  }
  const years = (days / 365).toFixed(days % 365 === 0 ? 0 : 1)
  return `${years} year${years === '1' ? '' : 's'} (${days}d) (${classification})`
}

function emailAbuseReadiness(result) {
  const txtRecords = Array.isArray(result?.dns?.txt_records) ? result.dns.txt_records : []
  const hasSpf = txtRecords.some((record) => String(record || '').trim().toLowerCase().startsWith('v=spf1'))

  if (hasSpf) {
    return {
      label: 'High',
      why: 'SPF present',
    }
  }

  const activeDomain = Boolean(
    result?.is_registered ||
    result?.dns?.has_mx ||
    result?.dns?.has_a ||
    result?.dns?.has_aaaa ||
    result?.dns?.has_ns ||
    result?.dns?.has_txt
  )

  if (activeDomain) {
    return {
      label: 'Medium',
      why: 'active domain; no SPF evidence',
    }
  }

  return {
    label: 'Low',
    why: 'no infrastructure',
  }
}

function hasSpfSignal(result) {
  const txtRecords = Array.isArray(result?.dns?.txt_records) ? result.dns.txt_records : []
  return txtRecords.some((record) => String(record || '').trim().toLowerCase().startsWith('v=spf1'))
}

function riskExplanation(result) {
  const lines = []

  if (result?.dns?.has_mx) {
    lines.push('Domain is hosted on infrastructure with prior abuse reports and can be used for phishing or impersonation.')
    if (hasExternalMailHosting(result)) {
      lines.push('Mail is hosted externally, increasing abuse risk.')
    }
  }

  if (result?.takeover_risk) {
    lines.push('Potential subdomain takeover risk detected.')
  }

  if (result?.is_registered && hasOperationalDns(result)) {
    lines.push('Domain is active and operational.')
  } else if ((result?.dns?.has_a || result?.dns?.has_ns) && !result?.dns?.has_mx) {
    lines.push('Domain is active but not mail-capable.')
  } else if (result?.is_registered && lines.length === 0) {
    lines.push('The candidate is registered and available for active external use.')
  }

  if (lines.length === 0) {
    lines.push('The candidate is unresolved now but remains relevant as a high-proximity lookalike.')
  }

  return lines.slice(0, 2).join(' ')
}

function buildSignalChips(result) {
  const chips = []
  if (result.dns?.has_mx) chips.push({ label: 'MX', tone: 'bad' })
  if (result.dns?.has_a) chips.push({ label: 'A', tone: 'neutral' })
  if (result.dns?.has_aaaa) chips.push({ label: 'AAAA', tone: 'neutral' })
  if (result.dns?.has_ns) chips.push({ label: 'NS', tone: 'neutral' })
  if (result.dns?.has_txt) chips.push({ label: 'TXT', tone: 'neutral' })
  if (result.certs?.length > 0) chips.push({ label: 'CT', tone: 'neutral' })
  if (result.has_homoglyphs) chips.push({ label: 'HOMOGLYPH', tone: 'warn' })
  if (result.mixed_script) chips.push({ label: 'MIXED', tone: 'warn' })
  if (result.takeover_risk) chips.push({ label: 'TAKEOVER', tone: 'bad' })
  return chips
}

function scoreTone(level) {
  return toneForRisk(level).color
}

function rowStatusKey(result) {
  return `${result?.base_domain || 'unknown'}::${result?.candidate || 'unknown'}`
}

function workflowBadge(status) {
  if (status === 'investigating') return statusBadge('INVESTIGATING', 'info')
  if (status === 'resolved') return statusBadge('RESOLVED', 'good')
  if (status === 'ignored') return statusBadge('IGNORED', 'neutral')
  return null
}

function defaultPriorityRank(result) {
  if ((result?.risk_level === 'critical' || result?.risk_level === 'high') && result?.dns?.has_mx) return 0
  if (Boolean(result?.takeover_risk)) return 1
  if (result?.dns?.has_a || result?.dns?.has_aaaa || result?.dns?.has_ns) return 2
  return 3
}

function compareRowsByDefaultPriority(a, b) {
  const priorityDelta = defaultPriorityRank(a) - defaultPriorityRank(b)
  if (priorityDelta !== 0) return priorityDelta

  const scoreDelta = (b.enriched_score || 0) - (a.enriched_score || 0)
  if (scoreDelta !== 0) return scoreDelta

  return a.candidate.localeCompare(b.candidate)
}

function compareRowsByExposurePriority(a, b, abuseLinkedCandidates) {
  const rank = (result) => {
    const abuseLinked = isAbuseDetectedCandidate(result, abuseLinkedCandidates)
    if (isExploitable(result) && abuseLinked) return 0
    if (isExploitable(result)) return 1
    if (abuseLinked) return 2
    return 3
  }

  const rankDelta = rank(a) - rank(b)
  if (rankDelta !== 0) return rankDelta

  const scoreDelta = exposureScoreValue(b) - exposureScoreValue(a)
  if (scoreDelta !== 0) return scoreDelta

  return a.candidate.localeCompare(b.candidate)
}

function compareRowsByLookalikePriority(a, b) {
  const similarityDelta = similarityScoreValue(b) - similarityScoreValue(a)
  if (similarityDelta !== 0) return similarityDelta

  const registeredDelta = Number(Boolean(b?.is_registered)) - Number(Boolean(a?.is_registered))
  if (registeredDelta !== 0) return registeredDelta

  const mailDelta = Number(Boolean((b?.dns?.has_mx || isMailRelated(b)))) - Number(Boolean((a?.dns?.has_mx || isMailRelated(a))))
  if (mailDelta !== 0) return mailDelta

  const exposureDelta = exposureScoreValue(b) - exposureScoreValue(a)
  if (exposureDelta !== 0) return exposureDelta

  return a.candidate.localeCompare(b.candidate)
}

function compareRowsBySurfacePriority(a, b, surfaceMetrics) {
  const ageValue = (result) => {
    const value = Number(result?.whois?.age_days)
    return Number.isFinite(value) ? value : Number.POSITIVE_INFINITY
  }

  const providerDelta = providersForResult(b).length - providersForResult(a).length
  if (providerDelta !== 0) return providerDelta

  const nsDelta = Number(Boolean(b?.dns?.has_ns)) - Number(Boolean(a?.dns?.has_ns))
  if (nsDelta !== 0) return nsDelta

  const aDelta = Number(Boolean(b?.dns?.has_a)) - Number(Boolean(a?.dns?.has_a))
  if (aDelta !== 0) return aDelta

  const ageDelta = ageValue(a) - ageValue(b)
  if (ageDelta !== 0) return ageDelta

  return a.candidate.localeCompare(b.candidate)
}

function compareRowsByMailDnsPriority(a, b, abuseLinkedCandidates) {
  const rank = (result) => {
    const abuseDetected = isAbuseDetectedCandidate(result, abuseLinkedCandidates || new Set())
    return [
      result?.dns?.has_mx ? 0 : 1,
      hasSpfSignal(result) ? 0 : 1,
      abuseDetected ? 0 : 1,
      -exposureScoreValue(result),
      String(result?.candidate || '').toLowerCase(),
    ]
  }

  const rankA = rank(a)
  const rankB = rank(b)
  for (let i = 0; i < rankA.length; i += 1) {
    if (rankA[i] < rankB[i]) return -1
    if (rankA[i] > rankB[i]) return 1
  }

  return 0
}

const PROVIDER_PATTERNS = [
  { name: 'Microsoft 365', patterns: ['protection.outlook.com', 'outlook.com'] },
  { name: 'Proofpoint', patterns: ['pphosted.com', 'proofpoint.com'] },
  { name: 'Google Workspace', patterns: ['google.com', 'googlemail.com', 'aspmx.l.google.com'] },
  { name: 'Cloudflare', patterns: ['cloudflare.com'] },
  { name: 'AWS', patterns: ['amazonaws.com', 'awsdns'] },
  { name: 'Azure', patterns: ['azurewebsites.net'] },
  { name: 'GoDaddy', patterns: ['secureserver.net', 'domaincontrol.com'] },
  { name: 'Wix', patterns: ['wixdns.net', 'wixsite.com'] },
  { name: 'Squarespace', patterns: ['squarespace.com', 'squarespacedns.com'] },
  { name: 'Shopify', patterns: ['myshopify.com', 'shops.myshopify.com'] },
  { name: 'HubSpot', patterns: ['hubspot', 'hubspotemail.net'] },
  { name: 'Mailgun', patterns: ['mailgun.org'] },
  { name: 'SendGrid', patterns: ['sendgrid.net'] },
  { name: 'Fastmail', patterns: ['messagingengine.com'] },
]

function inferProvidersFromHost(host) {
  const value = String(host || '').toLowerCase()
  if (!value) return []
  return PROVIDER_PATTERNS
    .filter((provider) => provider.patterns.some((pattern) => value.includes(pattern)))
    .map((provider) => provider.name)
}

function providersForResult(result) {
  const providers = []
  ;(result?.dns?.mx_records || []).forEach((host) => providers.push(...inferProvidersFromHost(host)))
  ;(result?.dns?.ns_records || []).forEach((host) => providers.push(...inferProvidersFromHost(host)))
  if (result?.takeover_risk) providers.push(String(result.takeover_risk))
  return dedupe(providers)
}

function mappingSignature(result) {
  const parts = dedupe([
    ...(result?.dns?.mx_records || []).map((value) => `mx:${String(value).toLowerCase()}`),
    ...(result?.dns?.a_records || []).map((value) => `a:${String(value).toLowerCase()}`),
    ...(result?.dns?.aaaa_records || []).map((value) => `aaaa:${String(value).toLowerCase()}`),
    ...(result?.dns?.ns_records || []).map((value) => `ns:${String(value).toLowerCase()}`),
  ])
  return parts.length ? parts.sort().join('|') : ''
}

function isMailRelated(result) {
  const label = String(result?.candidate || '').split('.')[0]?.toLowerCase() || ''
  return Boolean(
    result?.dns?.has_mx ||
    (/^(mail|mx|smtp|owa|webmail|autodiscover|email|exchange|securemail)/.test(label) && (
      result?.dns?.has_a ||
      result?.dns?.has_aaaa ||
      result?.dns?.has_txt
    ))
  )
}

function isSubdomainCandidate(result) {
  return String(result?.candidate || '').split('.').length > 2
}

function buildSurfaceMetrics(rows) {
  const signatureCounts = new Map()
  const providerSet = new Set()

  rows.forEach((result) => {
    const signature = mappingSignature(result)
    if (signature) {
      signatureCounts.set(signature, (signatureCounts.get(signature) || 0) + 1)
    }
    providersForResult(result).forEach((provider) => providerSet.add(provider))
  })

  const reusedCandidates = new Set()
  const wildcardCandidates = new Set()

  rows.forEach((result) => {
    const signature = mappingSignature(result)
    if (!signature) return
    const count = signatureCounts.get(signature) || 0
    if (count >= 2) reusedCandidates.add(result.candidate)
    if (count >= 3) wildcardCandidates.add(result.candidate)
  })

  return {
    providers: Array.from(providerSet),
    providerCount: providerSet.size,
    reusedMappings: reusedCandidates.size,
    wildcardLinked: wildcardCandidates.size,
    subdomains: rows.filter(isSubdomainCandidate).length,
    mailRelated: rows.filter(isMailRelated).length,
    takeoverVectors: rows.filter((result) => Boolean(result?.takeover_risk)).length,
    reusedCandidates,
    wildcardCandidates,
  }
}

function buildRowDescription(result, surfaceMetrics) {
  const mutation = MUTATION_LABELS[result.mutation_type] || String(result.mutation_type || 'similarity match').replace(/_/g, ' ')
  const headline = `${mutation.charAt(0).toUpperCase()}${mutation.slice(1)} of ${result.base_domain || 'unknown base'}`
  const similarity = Number.isFinite(result.similarity_score)
    ? `${result.similarity_score >= 80 ? 'Very high' : result.similarity_score >= 65 ? 'High' : 'Moderate'} similarity (${(result.similarity_score / 100).toFixed(2)})`
    : 'Similarity match'

  const details = [similarity]

  if (result.is_registered) details.push('Registered domain')
  else details.push('Unresolved candidate')

  const readiness = emailAbuseReadiness(result)
  details.push(`EMAIL ABUSE READINESS: ${readiness.label}`)
  details.push(`Why: ${readiness.why}`)

  if (result.takeover_risk) details.push('Potential takeover vector')
  else if (surfaceMetrics?.wildcardCandidates?.has(result.candidate)) details.push('Wildcard-like DNS pattern')
  else if (surfaceMetrics?.reusedCandidates?.has(result.candidate)) details.push('Shared DNS pattern')

  return {
    line1: headline,
    line2: details.join(' · '),
  }
}

function isActiveOrExploitable(result) {
  return Boolean(
    result?.takeover_risk ||
    result?.dns?.has_mx ||
    result?.dns?.has_a ||
    result?.dns?.has_aaaa ||
    result?.dns?.has_ns ||
    result?.dns?.has_txt ||
    isMailRelated(result)
  )
}

function isExploitable(result) {
  return Boolean(
    (result?.risk_level === 'high' || result?.risk_level === 'critical') &&
    (result?.dns?.has_mx || result?.dns?.has_a || Boolean(result?.takeover_risk))
  )
}

function isRegisteredHighRisk(result) {
  return Boolean(result?.is_registered && !isActiveOrExploitable(result))
}

function reputationDomainKey(summary) {
  return String(summary?.domain || summary?.candidate || summary?.name || '').trim().toLowerCase()
}

function exposureScoreValue(result) {
  const score = Number(result?.exposure_score ?? result?.enriched_score ?? 0)
  return Number.isFinite(score) ? score : 0
}

function similarityScoreValue(result) {
  const score = Number(result?.similarity_score ?? 0)
  return Number.isFinite(score) ? score : 0
}

function isAbuseDetectedCandidate(result, abuseLinkedCandidates) {
  const candidateKey = String(result?.candidate || '').trim().toLowerCase()
  return Boolean(candidateKey && abuseLinkedCandidates.has(candidateKey))
}

function isExposureRiskResult(result, abuseLinkedCandidates) {
  return Boolean(
    exposureScoreValue(result) >= 60 ||
    result?.risk_level === 'high' ||
    result?.risk_level === 'critical' ||
    isExploitable(result) ||
    isAbuseDetectedCandidate(result, abuseLinkedCandidates)
  )
}

function isSurfaceLinkedResult(result, surfaceMetrics) {
  return Boolean(
    isSubdomainCandidate(result) ||
    surfaceMetrics?.reusedCandidates?.has(result.candidate) ||
    surfaceMetrics?.wildcardCandidates?.has(result.candidate) ||
    providersForResult(result).length > 0 ||
    Boolean(result?.dns?.has_ns) ||
    Boolean(result?.dns?.has_a)
  )
}

function isMailDnsSignalResult(result) {
  return Boolean(
    result?.dns?.has_mx ||
    result?.dns?.has_a ||
    result?.dns?.has_aaaa ||
    result?.dns?.has_ns ||
    result?.dns?.has_txt ||
    hasSpfSignal(result)
  )
}

function isLookalikeCandidate(result) {
  return result?.similarity_score != null
}

function GroupHeader({ label, count }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '8px 14px', borderTop: '1px solid rgba(255,255,255,.06)', background: 'rgba(255,255,255,.012)' }}>
      <div style={{ fontSize: 10.5, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.9px', fontWeight: 700 }}>
        {label}
      </div>
      <div style={{ fontSize: 10.5, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
        {count}
      </div>
    </div>
  )
}

function MetricCard({ title, primaryLabel, value, metrics, highlightedMetric = null, detailLines = null, tone = 'neutral', active = false, featured = false, onClick }) {
  const colors = toneForStatus(tone)
  const visibleMetrics = (metrics || []).filter((metric) => metric.value > 0)

  return (
    <button
      type="button"
      className={`domain-exposure-summary-card${active ? ' is-active' : ''}`}
      aria-pressed={active}
      onClick={onClick}
      style={{
        minHeight: featured ? 196 : 104,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: 12,
        position: 'relative',
        padding: featured ? '16px 18px' : '11px 13px',
        borderRadius: 8,
        border: `1px solid ${active ? 'rgba(255,255,255,.18)' : 'var(--border)'}`,
        background: active ? 'rgba(10,16,26,.98)' : 'rgba(14,21,32,.96)',
        boxShadow: featured
          ? '0 10px 20px rgba(0,0,0,.16)'
          : active
          ? '0 8px 16px rgba(0,0,0,.16)'
          : '0 4px 10px rgba(0,0,0,.10)',
        cursor: 'pointer',
        textAlign: 'left',
        fontFamily: 'var(--font-body)',
        gridColumn: featured ? 'span 2' : 'span 1',
        opacity: featured ? 1 : 0.92,
      }}
    >
      {active && (
        <span style={{
          position: 'absolute',
          top: -1,
          left: 14,
          right: 14,
          height: 2,
          borderRadius: 999,
          background: colors.color,
          opacity: 0.9,
        }} />
      )}
      {featured ? (
        <div style={{ width: '100%', display: 'grid', gridTemplateColumns: '176px minmax(0, 1fr)', gap: 12, alignItems: 'center' }}>
          <div style={{ display: 'grid', justifyItems: 'center', alignContent: 'start' }}>
            <RiskGauge
              riskScore={Math.max(0, Math.min(100, Number(value) || 0))}
              riskLevel={riskLevelFromScore(Math.max(0, Math.min(100, Number(value) || 0)))}
              centerLabel="Exposure Risk"
            />
            <div style={{ marginTop: 2, fontSize: 13.5, color: 'var(--text)', fontWeight: 700, letterSpacing: '-.1px' }}>
              {title}
            </div>
          </div>
          <div style={{ minWidth: 0, display: 'grid', gap: 6, alignContent: 'center' }}>
            {highlightedMetric && highlightedMetric.value > 0 ? (
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.4 }}>
                <span style={{ color: colors.color, fontFamily: 'var(--font-mono)', fontWeight: 700, marginRight: 6 }}>
                  {highlightedMetric.value}
                </span>
                {highlightedMetric.label}
              </div>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.4 }}>
                {primaryLabel}
              </div>
            )}
            {(detailLines || []).slice(0, 2).map((line) => (
              <div key={`${title}-${line}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.4 }}>
                {line}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12.5, color: 'var(--text)', fontWeight: 600, letterSpacing: '-.1px' }}>
              {title}
            </div>
            <div style={{ marginTop: 10, display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap' }}>
              <div style={{ fontSize: 24, lineHeight: 1, fontWeight: 700, fontFamily: 'var(--font-mono)', color: active ? colors.color : 'var(--text)' }}>
                {value}
              </div>
              <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.8px', fontWeight: 700 }}>
                {primaryLabel}
              </div>
            </div>
            {highlightedMetric && highlightedMetric.value > 0 && (
              <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '5px 10px',
                  borderRadius: 999,
                  border: '1px solid rgba(255,79,94,.22)',
                  background: 'rgba(255,79,94,.08)',
                  color: 'var(--red)',
                  fontSize: 12,
                  fontWeight: 700,
                  lineHeight: 1,
                  letterSpacing: '.2px',
                  textTransform: 'uppercase',
                  whiteSpace: 'nowrap',
                }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{highlightedMetric.value}</span>
                  <span>{highlightedMetric.label}</span>
                </span>
              </div>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(108px, 1fr))', gap: 8, width: '100%' }}>
            {visibleMetrics.map((metric) => (
              <div key={`${title}-${metric.label}`} style={{ minWidth: 0 }}>
                <div style={{ fontSize: 11, color: metric.tone === 'bad' ? 'var(--red)' : metric.tone === 'warn' ? 'var(--yellow)' : 'var(--text)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                  {metric.value}
                </div>
                <div style={{ marginTop: 3, fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {metric.label}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </button>
  )
}

function DetailBlock({ label, children }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.8px', fontWeight: 700, marginBottom: 6 }}>
        {label}
      </div>
      {children}
    </div>
  )
}

function ResultRow({ result, surfaceMetrics, rowStatus = 'new', onRowStatusChange, reputationSummary, reputationLoading = false, providerAvailability = {}, detailMode = null }) {
  const [open, setOpen] = useState(false)
  const status = resultStatus(result)
  const workflowStateBadge = workflowBadge(rowStatus)
  const exploitableBadge = isExploitable(result) ? statusBadge('EXPLOITABLE', 'bad') : null
  const reputationFlag = reputationIndicator(reputationSummary)
  const signals = buildSignalChips(result)
  const visibleSignalItems = [
    ...(reputationFlag ? [{ label: reputationFlag.label, tone: reputationFlag.tone }] : []),
    ...signals,
  ]
  const visibleSignals = visibleSignalItems.slice(0, 4)
  const hiddenSignals = visibleSignalItems.length - visibleSignals.length
  const scoreColor = scoreTone(result.risk_level)
  const description = buildRowDescription(result, surfaceMetrics)
  const txtRecords = Array.isArray(result?.dns?.txt_records) ? result.dns.txt_records : []
  const spfRecord = txtRecords.find((record) => String(record || '').trim().toLowerCase().startsWith('v=spf1'))
  const signalDetails = [
    result.dns?.mx_records?.length ? `MX: ${result.dns.mx_records.slice(0, 2).join(', ')}` : null,
    result.dns?.a_records?.length ? `A: ${result.dns.a_records.slice(0, 2).join(', ')}` : null,
    result.dns?.aaaa_records?.length ? `AAAA: ${result.dns.aaaa_records.slice(0, 2).join(', ')}` : null,
    result.dns?.ns_records?.length ? `NS: ${result.dns.ns_records.slice(0, 2).join(', ')}` : null,
    result.dns?.has_txt && txtRecords.length ? `TXT: ${txtRecords.slice(0, 2).join(', ')}` : null,
    hasSpfSignal(result) ? `SPF: ${String(spfRecord || 'present').trim()}` : null,
    providersForResult(result).length ? `Providers: ${providersForResult(result).join(', ')}` : null,
    result.certs?.length ? `Certificates: ${result.certs.length}` : null,
    result.whois?.age_days != null ? `Domain age: ${formatDomainAge(result.whois.age_days)}` : null,
    result.whois?.registrar ? `Registrar: ${result.whois.registrar}` : null,
  ].filter(Boolean)
  const abuseConfigured = providerAvailability?.AbuseIPDB === 'configured'
  const spamhausConfigured = providerAvailability?.Spamhaus === 'configured'
  const ipFindings = reputationSummary?.ips || []
  const abuseIpFindings = ipFindings.filter((item) => item?.lookupStatus === 'ok')
  const abuseDetected = Boolean(reputationSummary?.abuseDetected)
  const spamhausSummary = reputationSummary?.spamhaus || null
  const spamhausListedIps = (spamhausSummary?.ips || []).filter((item) => item?.listed === true)
  const abuseAvailable = Boolean(
    abuseConfigured &&
    reputationSummary?.lookupStatus === 'ok' &&
    abuseIpFindings.length > 0
  )
  const spamhausAvailable = Boolean(
    spamhausConfigured &&
    spamhausSummary?.lookupStatus === 'ok' &&
    (
      spamhausSummary?.domain?.listed != null ||
      (spamhausSummary?.ips || []).some((item) => item?.listed != null)
    )
  )
  const hasAnyReputationData = abuseAvailable || spamhausAvailable
  const readiness = emailAbuseReadiness(result)
  let detailSections = detailMode === 'exposure-risk'
    ? [
        {
          label: 'Risk and next step',
          content: (
            <div style={{ display: 'grid', gap: 6 }}>
              <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                {riskExplanation(result)}
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>Recommended action: </span>
                {recommendedNextStep(result)}
              </div>
            </div>
          ),
        },
        {
          label: 'REPUTATION (Abuse Intelligence)',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              {reputationLoading && !reputationSummary ? (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading reputation intelligence...</div>
              ) : !hasAnyReputationData ? (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
              ) : reputationSummary ? (
                <>
                  {abuseAvailable ? (
                    <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Reputation: {titleCaseLabel(reputationSummary.label)}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Blacklisted: {reputationSummary.blacklisted ? 'Yes' : 'No'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Abuse detected: {abuseDetected ? 'Yes' : 'No'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Worst abuse score: {reputationSummary.worstScore != null ? reputationSummary.worstScore : 'Unknown'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Flagged IPs: {reputationSummary.flaggedIpCount}
                      </div>
                      {abuseDetected ? (
                        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                          Risk interpretation: Resolved IPs show repeated abuse reports {'->'} increases likelihood of malicious hosting.
                        </div>
                      ) : null}
                      {abuseIpFindings.slice(0, 3).map((item) => (
                        <div key={`${result.candidate}-${item.ip}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                          {item.ip} - {item.abuseConfidenceScore != null ? `score ${item.abuseConfidenceScore}` : titleCaseLabel(item.label)}
                          {item.totalReports != null ? `, reports ${item.totalReports}` : ''}
                          {item.lastReportedAt ? `, last reported ${formatLookupTimestamp(item.lastReportedAt)}` : ''}
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {spamhausAvailable ? (
                    <div style={{ marginTop: abuseAvailable ? 8 : 0, paddingTop: abuseAvailable ? 8 : 0, borderTop: abuseAvailable ? '1px solid rgba(255,255,255,.05)' : 'none', display: 'grid', gap: 4 }}>
                      <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                        Spamhaus
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Domain listed: {spamhausSummary?.domain?.listed == null ? 'Unknown' : spamhausSummary.domain.listed ? 'Yes' : 'No'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Listed IPs: {spamhausListedIps.length}
                      </div>
                      {spamhausSummary?.domain?.listed && spamhausSummary.domain.evidence ? (
                        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                          Domain evidence: {spamhausSummary.domain.evidence}
                        </div>
                      ) : null}
                      {spamhausListedIps.length > 0 && (
                        <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                          <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                            IPs
                          </div>
                          {spamhausListedIps.slice(0, 3).map((item) => (
                            <div key={`${result.candidate}-spamhaus-${item.entity}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                              {item.entity} - listed ({item.source}){item.evidence ? `, ${item.evidence}` : ''}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : null}
                  {abuseAvailable && !spamhausConfigured ? (
                    <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,.05)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                      Spamhaus: Not configured
                    </div>
                  ) : null}
                </>
              ) : (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
              )}
            </div>
          ),
        },
        {
          label: 'EMAIL ABUSE READINESS',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                {readiness.label}
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                Why: {readiness.why}
              </div>
            </div>
          ),
        },
        {
          label: 'Detection Factors',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              {(result.reasons || []).slice(0, 4).map((reason, index) => (
                <div key={`${result.candidate}-reason-${index}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {reason}
                </div>
              ))}
              {(result.reasons || []).length === 0 && (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>No flagging detail returned.</div>
              )}
            </div>
          ),
        },
        {
          label: 'Observed signals',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              {signalDetails.map((detail) => (
                <div key={`${result.candidate}-${detail}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {detail}
                </div>
              ))}
              {signalDetails.length === 0 && (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>No active DNS or certificate signals observed.</div>
              )}
            </div>
          ),
        },
      ]
    : detailMode === 'mail-dns'
      ? [
          {
            label: 'OBSERVED SIGNALS',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {signalDetails
                  .filter((detail) => !detail.startsWith('Domain age:') && !detail.startsWith('Registrar:'))
                  .map((detail) => (
                    <div key={`${result.candidate}-${detail}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      {detail}
                    </div>
                  ))}
                {signalDetails.filter((detail) => !detail.startsWith('Domain age:') && !detail.startsWith('Registrar:')).length === 0 && (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>No active DNS or certificate signals observed.</div>
                )}
              </div>
            ),
          },
          {
            label: 'EMAIL ABUSE READINESS',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {readiness.label}
                </div>
                <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                  Why: {readiness.why}
                </div>
              </div>
            ),
          },
          {
            label: 'REPUTATION (Abuse Intelligence)',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {reputationLoading && !reputationSummary ? (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading reputation intelligence...</div>
                ) : !hasAnyReputationData ? (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
                ) : reputationSummary ? (
                  <>
                    {abuseAvailable ? (
                      <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Reputation: {titleCaseLabel(reputationSummary.label)}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Blacklisted: {reputationSummary.blacklisted ? 'Yes' : 'No'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Abuse detected: {abuseDetected ? 'Yes' : 'No'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Worst abuse score: {reputationSummary.worstScore != null ? reputationSummary.worstScore : 'Unknown'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Flagged IPs: {reputationSummary.flaggedIpCount}
                        </div>
                        {abuseDetected ? (
                          <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            Risk interpretation: Resolved IPs show repeated abuse reports {'->'} increases likelihood of malicious hosting.
                          </div>
                        ) : null}
                        {abuseIpFindings.slice(0, 3).map((item) => (
                          <div key={`${result.candidate}-${item.ip}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            {item.ip} - {item.abuseConfidenceScore != null ? `score ${item.abuseConfidenceScore}` : titleCaseLabel(item.label)}
                            {item.totalReports != null ? `, reports ${item.totalReports}` : ''}
                            {item.lastReportedAt ? `, last reported ${formatLookupTimestamp(item.lastReportedAt)}` : ''}
                          </div>
                        ))}
                      </div>
                    ) : null}
                    {spamhausAvailable ? (
                      <div style={{ marginTop: abuseAvailable ? 8 : 0, paddingTop: abuseAvailable ? 8 : 0, borderTop: abuseAvailable ? '1px solid rgba(255,255,255,.05)' : 'none', display: 'grid', gap: 4 }}>
                        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                          Spamhaus
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Domain listed: {spamhausSummary?.domain?.listed == null ? 'Unknown' : spamhausSummary.domain.listed ? 'Yes' : 'No'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Listed IPs: {spamhausListedIps.length}
                        </div>
                        {spamhausSummary?.domain?.listed && spamhausSummary.domain.evidence ? (
                          <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            Domain evidence: {spamhausSummary.domain.evidence}
                          </div>
                        ) : null}
                        {spamhausListedIps.length > 0 && (
                          <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                            <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                              IPs
                            </div>
                            {spamhausListedIps.slice(0, 3).map((item) => (
                              <div key={`${result.candidate}-spamhaus-${item.entity}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                                {item.entity} - listed ({item.source}){item.evidence ? `, ${item.evidence}` : ''}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : null}
                    {abuseAvailable && !spamhausConfigured ? (
                      <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,.05)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                        Spamhaus: Not configured
                      </div>
                    ) : null}
                  </>
                ) : (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
                )}
              </div>
            ),
          },
          {
            label: 'RISK AND NEXT STEP',
            content: (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {riskExplanation(result)}
                </div>
                <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                  <span style={{ color: 'var(--text)', fontWeight: 600 }}>Recommended action: </span>
                  {recommendedNextStep(result)}
                </div>
              </div>
            ),
          },
          {
            label: 'DETECTION FACTORS',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {(result.reasons || []).slice(0, 4).map((reason, index) => (
                  <div key={`${result.candidate}-reason-${index}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                    {reason}
                  </div>
                ))}
                {(result.reasons || []).length === 0 && (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>No flagging detail returned.</div>
                )}
              </div>
            ),
          },
          {
            label: 'DOMAIN AGE / REGISTRAR',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {result.whois?.age_days != null ? (
                  <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                    Domain age: {formatDomainAge(result.whois.age_days)}
                  </div>
                ) : null}
                {result.whois?.registrar ? (
                  <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                    Registrar: {result.whois.registrar}
                  </div>
                ) : null}
                {!result.whois?.age_days && !result.whois?.registrar && (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>No WHOIS age or registrar data returned.</div>
                )}
              </div>
            ),
          },
        ]
    : detailMode === 'surface'
      ? [
          {
            label: 'OBSERVED SIGNALS',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {signalDetails
                  .filter((detail) => !detail.startsWith('Domain age:') && !detail.startsWith('Registrar:'))
                  .map((detail) => (
                    <div key={`${result.candidate}-${detail}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      {detail}
                    </div>
                  ))}
                {signalDetails.filter((detail) => !detail.startsWith('Domain age:') && !detail.startsWith('Registrar:')).length === 0 && (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>No active DNS or certificate signals observed.</div>
                )}
              </div>
            ),
          },
          {
            label: 'DOMAIN AGE / REGISTRAR',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {result.whois?.age_days != null ? (
                  <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                    Domain age: {formatDomainAge(result.whois.age_days)}
                  </div>
                ) : null}
                {result.whois?.registrar ? (
                  <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                    Registrar: {result.whois.registrar}
                  </div>
                ) : null}
                {!result.whois?.age_days && !result.whois?.registrar && (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>No WHOIS age or registrar data returned.</div>
                )}
              </div>
            ),
          },
          {
            label: 'REPUTATION (Abuse Intelligence)',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {reputationLoading && !reputationSummary ? (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading reputation intelligence...</div>
                ) : !hasAnyReputationData ? (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
                ) : reputationSummary ? (
                  <>
                    {abuseAvailable ? (
                      <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Reputation: {titleCaseLabel(reputationSummary.label)}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Blacklisted: {reputationSummary.blacklisted ? 'Yes' : 'No'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Abuse detected: {abuseDetected ? 'Yes' : 'No'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Worst abuse score: {reputationSummary.worstScore != null ? reputationSummary.worstScore : 'Unknown'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Flagged IPs: {reputationSummary.flaggedIpCount}
                        </div>
                        {abuseDetected ? (
                          <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            Risk interpretation: Resolved IPs show repeated abuse reports {'->'} increases likelihood of malicious hosting.
                          </div>
                        ) : null}
                        {abuseIpFindings.slice(0, 3).map((item) => (
                          <div key={`${result.candidate}-${item.ip}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            {item.ip} - {item.abuseConfidenceScore != null ? `score ${item.abuseConfidenceScore}` : titleCaseLabel(item.label)}
                            {item.totalReports != null ? `, reports ${item.totalReports}` : ''}
                            {item.lastReportedAt ? `, last reported ${formatLookupTimestamp(item.lastReportedAt)}` : ''}
                          </div>
                        ))}
                      </div>
                    ) : null}
                    {spamhausAvailable ? (
                      <div style={{ marginTop: abuseAvailable ? 8 : 0, paddingTop: abuseAvailable ? 8 : 0, borderTop: abuseAvailable ? '1px solid rgba(255,255,255,.05)' : 'none', display: 'grid', gap: 4 }}>
                        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                          Spamhaus
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Domain listed: {spamhausSummary?.domain?.listed == null ? 'Unknown' : spamhausSummary.domain.listed ? 'Yes' : 'No'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                          Listed IPs: {spamhausListedIps.length}
                        </div>
                        {spamhausSummary?.domain?.listed && spamhausSummary.domain.evidence ? (
                          <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            Domain evidence: {spamhausSummary.domain.evidence}
                          </div>
                        ) : null}
                        {spamhausListedIps.length > 0 && (
                          <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                            <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                              IPs
                            </div>
                            {spamhausListedIps.slice(0, 3).map((item) => (
                              <div key={`${result.candidate}-spamhaus-${item.entity}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                                {item.entity} - listed ({item.source}){item.evidence ? `, ${item.evidence}` : ''}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : null}
                    {abuseAvailable && !spamhausConfigured ? (
                      <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,.05)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                        Spamhaus: Not configured
                      </div>
                    ) : null}
                  </>
                ) : (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
                )}
              </div>
            ),
          },
          {
            label: 'DETECTION FACTORS',
            content: (
              <div style={{ display: 'grid', gap: 4 }}>
                {(result.reasons || []).slice(0, 4).map((reason, index) => (
                  <div key={`${result.candidate}-reason-${index}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                    {reason}
                  </div>
                ))}
                {(result.reasons || []).length === 0 && (
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>No flagging detail returned.</div>
                )}
              </div>
            ),
          },
          {
            label: 'RISK AND NEXT STEP',
            content: (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {riskExplanation(result)}
                </div>
                <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                  <span style={{ color: 'var(--text)', fontWeight: 600 }}>Recommended action: </span>
                  {recommendedNextStep(result)}
                </div>
              </div>
            ),
          },
        ]
    : [
        {
          label: 'Detection Factors',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              {(result.reasons || []).slice(0, 4).map((reason, index) => (
                <div key={`${result.candidate}-reason-${index}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {reason}
                </div>
              ))}
              {(result.reasons || []).length === 0 && (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>No flagging detail returned.</div>
              )}
            </div>
          ),
        },
        {
          label: 'Observed signals',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              {signalDetails.map((detail) => (
                <div key={`${result.candidate}-${detail}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {detail}
                </div>
              ))}
              {signalDetails.length === 0 && (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>No active DNS or certificate signals observed.</div>
              )}
            </div>
          ),
        },
        {
          label: 'Risk and next step',
          content: (
            <div style={{ display: 'grid', gap: 6 }}>
              <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                {riskExplanation(result)}
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>Recommended action: </span>
                {recommendedNextStep(result)}
              </div>
            </div>
          ),
        },
        {
          label: 'REPUTATION (Abuse Intelligence)',
          content: (
            <div style={{ display: 'grid', gap: 4 }}>
              {reputationLoading && !reputationSummary ? (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading reputation intelligence...</div>
              ) : !hasAnyReputationData ? (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
              ) : reputationSummary ? (
                <>
                  {abuseAvailable ? (
                    <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Reputation: {titleCaseLabel(reputationSummary.label)}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Blacklisted: {reputationSummary.blacklisted ? 'Yes' : 'No'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Abuse detected: {abuseDetected ? 'Yes' : 'No'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Worst abuse score: {reputationSummary.worstScore != null ? reputationSummary.worstScore : 'Unknown'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Flagged IPs: {reputationSummary.flaggedIpCount}
                      </div>
                      {abuseDetected ? (
                        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                          Risk interpretation: Resolved IPs show repeated abuse reports {'->'} increases likelihood of malicious hosting.
                        </div>
                      ) : null}
                      {abuseIpFindings.slice(0, 3).map((item) => (
                        <div key={`${result.candidate}-${item.ip}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                          {item.ip} - {item.abuseConfidenceScore != null ? `score ${item.abuseConfidenceScore}` : titleCaseLabel(item.label)}
                          {item.totalReports != null ? `, reports ${item.totalReports}` : ''}
                          {item.lastReportedAt ? `, last reported ${formatLookupTimestamp(item.lastReportedAt)}` : ''}
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {spamhausAvailable ? (
                    <div style={{ marginTop: abuseAvailable ? 8 : 0, paddingTop: abuseAvailable ? 8 : 0, borderTop: abuseAvailable ? '1px solid rgba(255,255,255,.05)' : 'none', display: 'grid', gap: 4 }}>
                      <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                        Spamhaus
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Domain listed: {spamhausSummary?.domain?.listed == null ? 'Unknown' : spamhausSummary.domain.listed ? 'Yes' : 'No'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                        Listed IPs: {spamhausListedIps.length}
                      </div>
                      {spamhausSummary?.domain?.listed && spamhausSummary.domain.evidence ? (
                        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                          Domain evidence: {spamhausSummary.domain.evidence}
                        </div>
                      ) : null}
                      {spamhausListedIps.length > 0 && (
                        <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                          <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                            IPs
                          </div>
                          {spamhausListedIps.slice(0, 3).map((item) => (
                            <div key={`${result.candidate}-spamhaus-${item.entity}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                              {item.entity} - listed ({item.source}){item.evidence ? `, ${item.evidence}` : ''}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : null}
                  {abuseAvailable && !spamhausConfigured ? (
                    <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,.05)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                      Spamhaus: Not configured
                    </div>
                  ) : null}
                </>
              ) : (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
              )}
            </div>
          ),
        },
      ]

  if (detailMode === 'lookalike') {
    detailSections = [
      {
        label: 'Detection Factors',
        content: (
          <div style={{ display: 'grid', gap: 4 }}>
            {(result.reasons || []).slice(0, 4).map((reason, index) => (
              <div key={`${result.candidate}-reason-${index}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                {reason}
              </div>
            ))}
            {(result.reasons || []).length === 0 && (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>No flagging detail returned.</div>
            )}
          </div>
        ),
      },
      {
        label: 'DOMAIN AGE / REGISTRAR',
        content: (
          <div style={{ display: 'grid', gap: 4 }}>
            {result.whois?.age_days != null ? (
              <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                Domain age: {formatDomainAge(result.whois.age_days)}
              </div>
            ) : null}
            {result.whois?.registrar ? (
              <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                Registrar: {result.whois.registrar}
              </div>
            ) : null}
            {!result.whois?.age_days && !result.whois?.registrar && (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>No WHOIS age or registrar data returned.</div>
            )}
          </div>
        ),
      },
      {
        label: 'REPUTATION (Abuse Intelligence)',
        content: (
          <div style={{ display: 'grid', gap: 4 }}>
            {reputationLoading && !reputationSummary ? (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading reputation intelligence...</div>
            ) : !hasAnyReputationData ? (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
            ) : reputationSummary ? (
              <>
                {abuseAvailable ? (
                  <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Reputation: {titleCaseLabel(reputationSummary.label)}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Blacklisted: {reputationSummary.blacklisted ? 'Yes' : 'No'}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Abuse detected: {abuseDetected ? 'Yes' : 'No'}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Worst abuse score: {reputationSummary.worstScore != null ? reputationSummary.worstScore : 'Unknown'}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Flagged IPs: {reputationSummary.flaggedIpCount}
                    </div>
                    {abuseDetected ? (
                      <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                        Risk interpretation: Resolved IPs show repeated abuse reports {'->'} increases likelihood of malicious hosting.
                      </div>
                    ) : null}
                    {abuseIpFindings.slice(0, 3).map((item) => (
                      <div key={`${result.candidate}-${item.ip}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                        {item.ip} - {item.abuseConfidenceScore != null ? `score ${item.abuseConfidenceScore}` : titleCaseLabel(item.label)}
                        {item.totalReports != null ? `, reports ${item.totalReports}` : ''}
                        {item.lastReportedAt ? `, last reported ${formatLookupTimestamp(item.lastReportedAt)}` : ''}
                      </div>
                    ))}
                  </div>
                ) : null}
                {spamhausAvailable ? (
                  <div style={{ marginTop: abuseAvailable ? 8 : 0, paddingTop: abuseAvailable ? 8 : 0, borderTop: abuseAvailable ? '1px solid rgba(255,255,255,.05)' : 'none', display: 'grid', gap: 4 }}>
                    <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                      Spamhaus
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Domain listed: {spamhausSummary?.domain?.listed == null ? 'Unknown' : spamhausSummary.domain.listed ? 'Yes' : 'No'}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                      Listed IPs: {spamhausListedIps.length}
                    </div>
                    {spamhausSummary?.domain?.listed && spamhausSummary.domain.evidence ? (
                      <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                        Domain evidence: {spamhausSummary.domain.evidence}
                      </div>
                    ) : null}
                    {spamhausListedIps.length > 0 && (
                      <div style={{ display: 'grid', gap: 3, marginTop: 4 }}>
                        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.7px', fontWeight: 700 }}>
                          IPs
                        </div>
                        {spamhausListedIps.slice(0, 3).map((item) => (
                          <div key={`${result.candidate}-spamhaus-${item.entity}`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                            {item.entity} - listed ({item.source}){item.evidence ? `, ${item.evidence}` : ''}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : null}
                {abuseAvailable && !spamhausConfigured ? (
                  <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,.05)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                    Spamhaus: Not configured
                  </div>
                ) : null}
              </>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>Reputation unavailable.</div>
            )}
          </div>
        ),
      },
      {
        label: 'EMAIL ABUSE READINESS',
        content: (
          <div style={{ display: 'grid', gap: 4 }}>
            <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
              {readiness.label}
            </div>
            <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
              Why: {readiness.why}
            </div>
          </div>
        ),
      },
      {
        label: 'Risk and next step',
        content: (
          <div style={{ display: 'grid', gap: 6 }}>
            <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
              {riskExplanation(result)}
            </div>
            <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
              <span style={{ color: 'var(--text)', fontWeight: 600 }}>Recommended action: </span>
              {recommendedNextStep(result)}
            </div>
          </div>
        ),
      },
      {
        label: 'Observed signals',
        content: (
          <div style={{ display: 'grid', gap: 4 }}>
            {signalDetails
              .filter((detail) => !detail.startsWith('Domain age:') && !detail.startsWith('Registrar:'))
              .map((detail) => (
                <div key={`${result.candidate}-${detail}`} style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                  {detail}
                </div>
              ))}
            {signalDetails.filter((detail) => !detail.startsWith('Domain age:') && !detail.startsWith('Registrar:')).length === 0 && (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>No active DNS or certificate signals observed.</div>
            )}
          </div>
        ),
      },
    ]
  }

  return (
    <div style={{ borderTop: '1px solid var(--border)' }}>
      <div
        onClick={() => setOpen(value => !value)}
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1.7fr) 150px 100px 120px 120px minmax(150px, 1fr) 34px',
          gap: 12,
          alignItems: 'center',
          padding: '10px 14px',
          cursor: 'pointer',
          background: open ? 'rgba(255,255,255,.025)' : 'transparent',
          transition: 'background .14s ease',
        }}
        onMouseOver={e => {
          e.currentTarget.style.background = open ? 'rgba(255,255,255,.035)' : 'rgba(255,255,255,.018)'
        }}
        onMouseOut={e => {
          e.currentTarget.style.background = open ? 'rgba(255,255,255,.025)' : 'transparent'
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: 'var(--text)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {result.candidate}
          </div>
          <div style={{ marginTop: 4, fontSize: 10.5, color: 'var(--text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {description.line1}
          </div>
          <div style={{ marginTop: 2, fontSize: 10.5, color: 'var(--muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {description.line2}
          </div>
        </div>

        <div>
          {scoreBar(result.enriched_score, scoreColor)}
        </div>

        <div>
          {riskBadge(result.risk_level)}
        </div>

        <div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {statusBadge(status.label, status.tone)}
            {exploitableBadge}
          </div>
        </div>

        <div
          onClick={(event) => event.stopPropagation()}
          style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}
        >
          <select
            value={rowStatus}
            aria-label={`Set workflow status for ${result.candidate}`}
            onChange={(event) => onRowStatusChange?.(event.target.value)}
            style={{
              width: 104,
              padding: '4px 8px',
              borderRadius: 6,
              border: '1px solid var(--border)',
              background: 'var(--surface)',
              color: 'var(--text)',
              fontSize: 11,
              fontFamily: 'var(--font-body)',
              cursor: 'pointer',
              outline: 'none',
            }}
          >
            <option value="new" style={{ background: 'var(--surface)', color: 'var(--text)' }}>New</option>
            <option value="investigating" style={{ background: 'var(--surface)', color: 'var(--text)' }}>Investigating</option>
            <option value="resolved" style={{ background: 'var(--surface)', color: 'var(--text)' }}>Resolved</option>
            <option value="ignored" style={{ background: 'var(--surface)', color: 'var(--text)' }}>Ignored</option>
          </select>
          {workflowStateBadge}
        </div>

        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', minWidth: 0 }}>
          {visibleSignals.length > 0 ? visibleSignals.map((signal, index) => (
            <span
              key={`${result.candidate}-${signal.label}`}
              style={{ marginRight: index === 0 && signal.label === 'ABUSE-IP' ? 8 : 0 }}
            >
              {signalChip(signal.label, signal.tone)}
            </span>
          )) : (
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>None</span>
          )}
          {hiddenSignals > 0 ? signalChip(`+${hiddenSignals}`, 'neutral') : null}
        </div>

        <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--muted)' }}>
          {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </div>
      </div>

      {open && (
        <div style={{ padding: '12px 14px 14px', background: 'rgba(255,255,255,.018)', borderTop: '1px solid rgba(255,255,255,.04)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
            {detailSections.map((section) => (
              <DetailBlock key={section.label} label={section.label}>
                {section.content}
              </DetailBlock>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function SortHeader({ label, sortKey, activeKey, sortDir, onClick }) {
  const active = sortKey === activeKey
  return (
    <button
      onClick={() => onClick(sortKey)}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 4,
        padding: 0,
        background: 'transparent',
        border: 'none',
        color: active ? 'var(--text)' : 'var(--muted)',
        cursor: 'pointer',
        fontSize: 10,
        letterSpacing: '.9px',
        textTransform: 'uppercase',
        fontWeight: 700,
        fontFamily: 'var(--font-body)',
      }}
    >
      <span>{label}</span>
      <span style={{ color: active ? 'var(--accent)' : 'var(--muted)', fontSize: 9 }}>
        {active ? (sortDir === 'desc' ? '↓' : '↑') : '↕'}
      </span>
    </button>
  )
}

export default function DomainExposurePage({ tenant, token }) {
  const [status, setStatus] = useState(null)
  const [results, setResults] = useState(null)
  const [domains, setDomains] = useState([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [sortKey, setSortKey] = useState('priority')
  const [sortDir, setSortDir] = useState('desc')
  const [hideNoSignals, setHideNoSignals] = useState(true)
  const [activeCard, setActiveCard] = useState(null)
  const [rowStatuses, setRowStatuses] = useState({})
  const [reputationEntities, setReputationEntities] = useState({})
  const [rootReputation, setRootReputation] = useState(null)
  const [reputationProviderAvailability, setReputationProviderAvailability] = useState({})
  const [reputationLoading, setReputationLoading] = useState(false)
  const pollRef = useRef(null)

  const headers = useMemo(() => ({
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }), [token])

  const ownedDomains = useMemo(() => {
    if (!tenant) return []
    const raw = tenant.all_domains?.length ? tenant.all_domains : [tenant.domain, ...(tenant.extra_domains || [])]
    return dedupe(raw.map((domain) => String(domain || '').trim().toLowerCase()))
  }, [tenant])

  useEffect(() => {
    const loadLatest = async () => {
      try {
        const response = await fetch(`${API}/latest`, { headers })
        if (!response.ok) return
        const data = await response.json()
        if (data.status === 'completed' && data.results) {
          setResults(data.results)
          setDomains(data.domains || [])
          setStatus('completed')
        }
      } catch (_) {}
    }

    loadLatest()
  }, [])

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  const pollStatus = async (scanId) => {
    try {
      const response = await fetch(`${API}/status/${scanId}`, { headers })
      const data = await response.json()
      setStatus(data.status)
      setDomains(data.domains || [])

      if (data.status === 'completed' || data.status === 'failed') {
        stopPolling()
        setLoading(false)

        if (data.status === 'completed') {
          const resultResponse = await fetch(`${API}/result/${scanId}`, { headers })
          const full = await resultResponse.json()
          setResults(full.results || [])
        } else {
          setError(data.error || 'Scan failed.')
        }
      }
    } catch (_) {
      stopPolling()
      setLoading(false)
      setError('Lost connection during scan.')
    }
  }

  const handleTrigger = async () => {
    setLoading(true)
    setError(null)
    setResults(null)
    setStatus('pending')
    stopPolling()

    try {
      const response = await fetch(`${API}/trigger`, { method: 'POST', headers })
      if (!response.ok) {
        let message = `Server error ${response.status}`
        try {
          const payload = await response.json()
          message = payload.detail || message
        } catch (_) {}
        throw new Error(message)
      }

      const data = await response.json()
      setStatus(data.status)
      pollRef.current = setInterval(() => pollStatus(data.id), 3000)
    } catch (e) {
      setLoading(false)
      setStatus(null)
      setError(e.message)
    }
  }

  useEffect(() => () => stopPolling(), [])

  const domainOptions = useMemo(() => rootDomainOptions(ownedDomains), [ownedDomains])

  useEffect(() => {
    if (!domainOptions.length) {
      setSelectedDomain('')
      return
    }

    if (!selectedDomain || !domainOptions.includes(selectedDomain)) {
      setSelectedDomain(domainOptions[0])
    }
  }, [domainOptions, selectedDomain])

  const scopedResults = useMemo(() => {
    const rows = results || []
    return selectedDomain ? rows.filter((result) => result.base_domain === selectedDomain) : rows
  }, [results, selectedDomain])

  useEffect(() => {
    let cancelled = false

    const loadReputation = async () => {
      if (!selectedDomain) {
        setReputationEntities({})
        setRootReputation(null)
        return
      }

      const domainsPayload = {}
      scopedResults.forEach((result) => {
        domainsPayload[result.candidate] = [
          ...(result?.dns?.a_records || []),
          ...(result?.dns?.aaaa_records || []),
        ]
      })

      setReputationLoading(true)
      try {
        const response = await fetch(`${API}/reputation`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            root_domain: selectedDomain,
            domains: domainsPayload,
          }),
        })

        if (!response.ok) throw new Error('Failed to load reputation intelligence.')
        const payload = await response.json()
        if (cancelled) return

        setReputationEntities(payload.entities || {})
        setRootReputation(payload.rootDomain || null)
        setReputationProviderAvailability(payload.providerAvailability || {})
      } catch (_) {
        if (cancelled) return
        setReputationEntities({})
        setRootReputation(null)
        setReputationProviderAvailability({})
      } finally {
        if (!cancelled) setReputationLoading(false)
      }
    }

    loadReputation()
    return () => {
      cancelled = true
    }
  }, [headers, scopedResults, selectedDomain])

  const reputationAbuseIntel = useMemo(() => {
    const candidates = new Set()
    const summaries = [
      ...(Object.values(reputationEntities) || []),
      rootReputation,
    ].filter(Boolean)

    summaries.forEach((summary) => {
      if (!summary?.abuseDetected) return
      const key = reputationDomainKey(summary)
      if (key) candidates.add(key)
    })

    return {
      abuseLinkedCandidates: candidates,
      abusiveInfrastructureCount: candidates.size,
    }
  }, [reputationEntities, rootReputation])

  const surfaceMetrics = useMemo(() => buildSurfaceMetrics(scopedResults), [scopedResults])
  const lookalikeRows = scopedResults.filter(isLookalikeCandidate)
  const highRiskLookalikeRows = scopedResults.filter((result) => result.risk_level === 'high' || result.risk_level === 'critical')
  const highRiskLookalikeCount = highRiskLookalikeRows.length
  const exposureRiskRows = scopedResults.filter((result) => isExposureRiskResult(result, reputationAbuseIntel.abuseLinkedCandidates))
  const surfaceRows = scopedResults.filter((result) => isSurfaceLinkedResult(result, surfaceMetrics))
  const mailDnsSignalRows = scopedResults.filter(isMailDnsSignalResult)
  const cardFilteredRows = useMemo(() => {
    if (activeCard === 'exposure-risk') {
      return exposureRiskRows
    }

    if (activeCard === 'lookalike') {
      return lookalikeRows
    }

    if (activeCard === 'surface') {
      return surfaceRows
    }

    if (activeCard === 'mail-dns') {
      return mailDnsSignalRows
    }

    return scopedResults
  }, [activeCard, exposureRiskRows, lookalikeRows, mailDnsSignalRows, scopedResults, surfaceRows])

  const filteredRows = useMemo(() => {
    const rows = hideNoSignals
      ? cardFilteredRows.filter((result) => (
          activeCard === 'mail-dns'
            ? isMailDnsSignalResult(result)
            : hasMeaningfulSignals(result, surfaceMetrics)
        ))
      : cardFilteredRows
    return [...rows].sort((a, b) => {
      if (sortKey === 'priority') {
        if (activeCard === 'exposure-risk') {
          return compareRowsByExposurePriority(a, b, reputationAbuseIntel.abuseLinkedCandidates)
        }

        if (activeCard === 'lookalike') {
          return compareRowsByLookalikePriority(a, b)
        }

        if (activeCard === 'surface') {
          return compareRowsBySurfacePriority(a, b, surfaceMetrics)
        }

        if (activeCard === 'mail-dns') {
          return compareRowsByMailDnsPriority(a, b, reputationAbuseIntel.abuseLinkedCandidates)
        }

        const delta = compareRowsByDefaultPriority(a, b)
        return sortDir === 'desc' ? delta : -delta
      }

      if (sortKey === 'candidate') {
        return sortDir === 'desc'
          ? b.candidate.localeCompare(a.candidate)
          : a.candidate.localeCompare(b.candidate)
      }

      if (sortKey === 'enriched_score') {
        const delta = sortDir === 'desc'
          ? (b.enriched_score || 0) - (a.enriched_score || 0)
          : (a.enriched_score || 0) - (b.enriched_score || 0)
        return delta !== 0 ? delta : a.candidate.localeCompare(b.candidate)
      }

      if (sortKey === 'risk_level') {
        const delta = sortDir === 'desc'
          ? (RISK_ORDER[b.risk_level] ?? 9) - (RISK_ORDER[a.risk_level] ?? 9)
          : (RISK_ORDER[a.risk_level] ?? 9) - (RISK_ORDER[b.risk_level] ?? 9)
        return delta !== 0 ? delta : a.candidate.localeCompare(b.candidate)
      }

      if (sortKey === 'status') {
        return sortDir === 'desc'
          ? resultStatus(b).label.localeCompare(resultStatus(a).label)
          : resultStatus(a).label.localeCompare(resultStatus(b).label)
      }

      if (sortKey === 'workflow_status') {
        const workflowA = rowStatuses[rowStatusKey(a)] || 'new'
        const workflowB = rowStatuses[rowStatusKey(b)] || 'new'
        const workflowDelta = sortDir === 'desc'
          ? (WORKFLOW_STATUS_ORDER[workflowB] ?? 99) - (WORKFLOW_STATUS_ORDER[workflowA] ?? 99)
          : (WORKFLOW_STATUS_ORDER[workflowA] ?? 99) - (WORKFLOW_STATUS_ORDER[workflowB] ?? 99)

        if (workflowDelta !== 0) return workflowDelta

        return a.candidate.localeCompare(b.candidate)
      }

      if (sortKey === 'signals') {
        const delta = sortDir === 'desc'
          ? buildSignalChips(b).length - buildSignalChips(a).length
          : buildSignalChips(a).length - buildSignalChips(b).length
        return delta !== 0 ? delta : a.candidate.localeCompare(b.candidate)
      }

      return 0
    })
  }, [activeCard, cardFilteredRows, hideNoSignals, reputationAbuseIntel.abuseLinkedCandidates, rowStatuses, sortDir, sortKey, surfaceMetrics])

  const selectedCounts = useMemo(() => {
    return scopedResults.reduce((acc, result) => {
      acc.critical += result.risk_level === 'critical' ? 1 : 0
      acc.high += result.risk_level === 'high' ? 1 : 0
      acc.medium += result.risk_level === 'medium' ? 1 : 0
      acc.registered += result.is_registered ? 1 : 0
      acc.signalRich += hasMeaningfulSignals(result, surfaceMetrics) ? 1 : 0
      acc.mailEnabled += result.dns?.has_mx ? 1 : 0
      acc.dormant += isDormant(result) ? 1 : 0
      acc.exploitable += hasExploitableDns(result) ? 1 : 0
      acc.fresh += result.whois?.age_days != null && result.whois.age_days <= 90 ? 1 : 0
      acc.mixed += result.has_homoglyphs || result.mixed_script ? 1 : 0
      acc.certs += (result.certs?.length || 0) > 0 ? 1 : 0
      return acc
    }, {
      critical: 0,
      high: 0,
      medium: 0,
      registered: 0,
      signalRich: 0,
      mailEnabled: 0,
      dormant: 0,
      exploitable: 0,
      fresh: 0,
      mixed: 0,
      certs: 0,
    })
  }, [scopedResults, surfaceMetrics])

  const riskScore = averageScore(exposureRiskRows)
  const mailDnsSignalCount = mailDnsSignalRows.length
  const abusiveInfrastructureCount = reputationAbuseIntel.abusiveInfrastructureCount
  const exposureRiskDetailLines = useMemo(() => {
    const lines = []
    if (abusiveInfrastructureCount > 0 && highRiskLookalikeCount > 0) {
      lines.push(`${abusiveInfrastructureCount} of ${highRiskLookalikeCount} high-risk lookalike domains are linked to abusive infrastructure.`)
    }
    return lines
  }, [abusiveInfrastructureCount, highRiskLookalikeCount])
  const groupedRows = useMemo(() => {
    if (activeCard === 'exposure-risk') {
      const abuseLinked = (result) => isAbuseDetectedCandidate(result, reputationAbuseIntel.abuseLinkedCandidates)
      const exploitableAbuse = filteredRows.filter((result) => isExploitable(result) && abuseLinked(result))
      const exploitableOnly = filteredRows.filter((result) => isExploitable(result) && !abuseLinked(result))
      const abuseOnly = filteredRows.filter((result) => !isExploitable(result) && abuseLinked(result))
      const remaining = filteredRows.filter((result) => !isExploitable(result) && !abuseLinked(result))

      return [
        { key: 'exploitable-abuse', label: `EXPLOITABLE + ABUSE (${exploitableAbuse.length})`, rows: exploitableAbuse },
        { key: 'exploitable', label: `EXPLOITABLE (${exploitableOnly.length})`, rows: exploitableOnly },
        { key: 'abuse', label: `ABUSE ONLY (${abuseOnly.length})`, rows: abuseOnly },
        { key: 'remaining', label: `REMAINING (${remaining.length})`, rows: remaining },
      ].filter((group) => group.rows.length > 0)
    }

    if (activeCard === 'surface') {
      const surfaceType = (result) => {
        if (surfaceMetrics.wildcardCandidates.has(result.candidate) || surfaceMetrics.reusedCandidates.has(result.candidate)) return 'wildcard'
        if (isSubdomainCandidate(result)) return 'subdomain'
        if (providersForResult(result).length > 0) return 'provider'
        if (result?.dns?.has_ns || result?.dns?.has_a) return 'dns'
        return 'other'
      }

      const wildcardOrReused = filteredRows.filter((result) => surfaceType(result) === 'wildcard')
      const subdomains = filteredRows.filter((result) => surfaceType(result) === 'subdomain')
      const providerLinked = filteredRows.filter((result) => surfaceType(result) === 'provider')
      const dnsFootprint = filteredRows.filter((result) => surfaceType(result) === 'dns')
      const other = filteredRows.filter((result) => surfaceType(result) === 'other')

      return [
        { key: 'wildcard-reused', label: `WILDCARD / REUSED (${wildcardOrReused.length})`, rows: wildcardOrReused },
        { key: 'subdomains', label: `SUBDOMAINS (${subdomains.length})`, rows: subdomains },
        { key: 'providers', label: `PROVIDER-LINKED (${providerLinked.length})`, rows: providerLinked },
        { key: 'dns-footprint', label: `DNS FOOTPRINT (${dnsFootprint.length})`, rows: dnsFootprint },
        { key: 'other', label: `OTHER SURFACE (${other.length})`, rows: other },
      ].filter((group) => group.rows.length > 0)
    }

    const exploitable = filteredRows.filter(isExploitable)
    const activeNonExploitable = filteredRows.filter((result) => isActiveOrExploitable(result) && !isExploitable(result))
    const registered = filteredRows.filter((result) => !isActiveOrExploitable(result) && isRegisteredHighRisk(result))
    const low = filteredRows.filter((result) => !isActiveOrExploitable(result) && !isRegisteredHighRisk(result))
    return [
      { key: 'exploitable', label: `EXPLOITABLE (${exploitable.length})`, rows: exploitable },
      { key: 'active', label: `ACTIVE - NON-EXPLOITABLE (${activeNonExploitable.length})`, rows: activeNonExploitable },
      { key: 'registered', label: 'REGISTERED', rows: registered },
      { key: 'low', label: 'LOW / NO SIGNAL', rows: low },
    ].filter((group) => group.rows.length > 0)
  }, [activeCard, filteredRows, reputationAbuseIntel.abuseLinkedCandidates])

  const severeCount = selectedCounts.critical + selectedCounts.high
  const bannerState = severeCount > 0
    ? {
        title: 'Critical risk detected',
        body: 'Urgent lookalike and DNS risks identified across selected domains.',
        color: 'var(--red)',
        background: 'rgba(255,79,94,.08)',
        border: 'rgba(255,79,94,.20)',
      }
    : loading || status === 'pending' || status === 'running'
      ? {
          title: 'Scan in progress',
          body: 'Domain discovery and enrichment are running for the selected tenant domains.',
          color: 'var(--yellow)',
          background: 'rgba(255,215,64,.08)',
          border: 'rgba(255,215,64,.20)',
        }
      : {
          title: 'Exposure review active',
          body: 'Lookalike and DNS findings are available for operator review.',
          color: 'var(--muted)',
          background: 'rgba(255,255,255,.03)',
          border: 'var(--border)',
        }

  const cardLabel = activeCard === 'exposure-risk'
    ? 'Exposure Risk'
    : activeCard === 'surface'
      ? 'Domain Surface'
      : activeCard === 'mail-dns'
        ? 'Mail & DNS Signals'
        : activeCard === 'lookalike'
          ? 'Lookalike Domains'
          : 'All candidates'
  const viewLabel = `Filter: ${hideNoSignals ? 'Signal-bearing only' : 'All rows'} · Results: ${filteredRows.length}`

  const emptyStateMessage = useMemo(() => {
    if (cardFilteredRows.length === 0) {
      if (activeCard === 'exposure-risk') return 'No exposure-driven domains matched the current scope.'
      if (activeCard === 'lookalike') return 'No lookalike domains matched the current scope.'
      if (activeCard === 'mail-dns') return 'No mail and DNS signal-bearing domains matched the current scope.'
      if (activeCard === 'surface') return 'No domain surface or footprint findings for current scope.'
      return 'No candidates matched the current scope.'
    }

    if (filteredRows.length === 0 && hideNoSignals) {
      if (activeCard === 'exposure-risk') return 'No exposure-driven domains matched the current signal filter.'
      if (activeCard === 'lookalike') return 'No lookalike domains matched the current signal filter.'
      if (activeCard === 'mail-dns') return 'No mail and DNS signal-bearing domains matched the current signal filter.'
      if (activeCard === 'surface') return 'No domain surface or footprint findings for current scope.'
      return 'No candidates matched the current signal filter.'
    }

    return 'No candidates matched the current scope.'
  }, [activeCard, cardFilteredRows.length, filteredRows.length, hideNoSignals])

  const cardMetrics = useMemo(() => ([
    {
      key: 'exposure-risk',
      title: 'Exposure Risk',
      primaryLabel: 'Risk score',
      value: riskScore,
      tone: 'bad',
      highlightedMetric: { label: 'high-risk lookalikes', value: highRiskLookalikeCount },
      detailLines: exposureRiskDetailLines,
      metrics: [
        { label: 'High-risk lookalikes', value: highRiskLookalikeCount, tone: 'bad' },
        { label: 'Dormant domains', value: scopedResults.filter(isDormant).length, tone: 'warn' },
        { label: 'Takeover risk', value: scopedResults.filter((result) => Boolean(result.takeover_risk)).length, tone: 'bad' },
      ],
    },
    {
      key: 'lookalike',
      title: 'Lookalike Domains',
      primaryLabel: 'Lookalike domains',
      value: lookalikeRows.length,
      highlightedMetric: { label: 'High-risk', value: highRiskLookalikeCount },
      metrics: [
        { label: 'Registered', value: scopedResults.filter((result) => result.is_registered).length, tone: 'warn' },
        { label: 'Mail-capable', value: scopedResults.filter(isMailRelated).length, tone: 'warn' },
      ],
    },
    {
      key: 'surface',
      title: 'Domain Surface',
      primaryLabel: surfaceMetrics.subdomains > 0 ? 'Discovered domains' : 'Active surface',
      value: surfaceRows.length,
      metrics: [
        { label: 'Subdomains', value: surfaceMetrics.subdomains, tone: 'neutral' },
        { label: 'Providers', value: surfaceMetrics.providerCount, tone: 'neutral' },
        { label: 'Dormant domains', value: surfaceRows.filter(isDormant).length, tone: 'warn' },
      ],
    },
    {
      key: 'mail-dns',
      title: 'Mail & DNS Signals',
      primaryLabel: 'Signal-bearing domains',
      value: mailDnsSignalCount,
      metrics: [
        { label: 'MX present', value: scopedResults.filter((result) => Boolean(result?.dns?.has_mx)).length, tone: 'bad' },
        { label: 'NS present', value: scopedResults.filter((result) => Boolean(result?.dns?.has_ns)).length, tone: 'neutral' },
        { label: 'TXT present', value: scopedResults.filter((result) => Boolean(result?.dns?.has_txt)).length, tone: 'neutral' },
      ],
    },
  ]), [abusiveInfrastructureCount, exposureRiskDetailLines, highRiskLookalikeCount, lookalikeRows.length, mailDnsSignalCount, riskScore, scopedResults, surfaceMetrics, surfaceRows]).sort((a, b) => {
    const order = {
      'exposure-risk': 0,
      lookalike: 1,
      'mail-dns': 2,
      surface: 3,
    }
    return order[a.key] - order[b.key]
  })

  const toggleSort = (key, nextDefault) => {
    if (sortKey === key) {
      setSortDir((value) => value === 'desc' ? 'asc' : 'desc')
      return
    }
    setSortKey(key)
    setSortDir(nextDefault)
  }

  const exportCSV = () => {
    const headersRow = ['Candidate', 'Base Domain', 'Proximity Score', 'Risk', 'Status', 'Signals', 'Mutation Type', 'Reasons']
    const csvRows = filteredRows.map((result) => [
      result.candidate,
      result.base_domain,
      result.enriched_score,
      RISK_LABELS[result.risk_level] || RISK_LABELS.low,
      resultStatus(result).label,
      buildSignalChips(result).map((signal) => signal.label).join(' | '),
      MUTATION_LABELS[result.mutation_type] || result.mutation_type,
      (result.reasons || []).join(' | '),
    ])
    const csv = [headersRow, ...csvRows]
      .map((row) => row.map((value) => `"${String(value ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `domain-exposure-${selectedDomain || 'all'}-${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(link.href)
  }

  const updateRowStatus = (result, nextStatus) => {
    const key = rowStatusKey(result)
    setRowStatuses((current) => {
      if (nextStatus === 'new') {
        const { [key]: _removed, ...rest } = current
        return rest
      }
      return { ...current, [key]: nextStatus }
    })
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)' }}>
      <div style={{ width: '100%', maxWidth: 'none', margin: 0, padding: '16px 20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', minWidth: 0 }}>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 500, color: 'var(--text)', letterSpacing: '-.2px' }}>Domain Exposure</h1>
            <select
              value={selectedDomain}
              onChange={(event) => {
                setSelectedDomain(event.target.value)
                setActiveCard(null)
              }}
              disabled={domainOptions.length <= 1}
              style={{
                minWidth: 210,
                maxWidth: 300,
                padding: '6px 10px',
                borderRadius: 8,
                border: '1px solid var(--border)',
                background: 'rgba(255,255,255,.02)',
                color: domainOptions.length ? 'var(--text)' : 'var(--muted)',
                fontSize: 12,
                fontFamily: 'var(--font-body)',
              }}
            >
              {domainOptions.length === 0 ? (
                <option value="">No domains</option>
              ) : domainOptions.map((domain) => (
                <option key={domain} value={domain}>
                  {domain}
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button onClick={handleTrigger} disabled={loading} style={buttonStyle(true, loading)}>
              {loading ? <RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Crosshair size={13} />}
              {loading ? 'Scanning...' : 'Run Scan'}
            </button>
            <button onClick={exportCSV} disabled={!filteredRows.length} style={buttonStyle(false, !filteredRows.length)}>
              <Download size={13} />
              Export CSV
            </button>
          </div>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '8px 12px',
          marginBottom: 12,
          borderRadius: 8,
          border: `1px solid ${bannerState.border}`,
          background: bannerState.background,
          boxShadow: '0 8px 18px rgba(0,0,0,.12)',
        }}>
          <AlertTriangle size={14} color={bannerState.color} style={{ flexShrink: 0 }} />
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap', minWidth: 0 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: bannerState.color, letterSpacing: '.4px', textTransform: 'uppercase' }}>
              {bannerState.title}
            </span>
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>
              {bannerState.body}
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.25fr 1.25fr 1fr 1fr 1fr', gap: 10, marginBottom: 12 }}>
          {cardMetrics.map((card) => (
            <MetricCard
              key={card.key}
              title={card.title}
              primaryLabel={card.primaryLabel}
              value={card.value}
              metrics={card.metrics}
              highlightedMetric={card.highlightedMetric}
              tone={card.tone}
              active={activeCard === card.key}
              featured={card.key === 'exposure-risk'}
              onClick={() => setActiveCard((value) => value === card.key ? null : card.key)}
            />
          ))}
        </div>

        <section style={{ border: '1px solid var(--border)', borderRadius: 10, background: 'rgba(14,21,32,.96)', overflow: 'hidden', boxShadow: '0 10px 22px rgba(0,0,0,.16)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '10px 14px', borderBottom: '1px solid rgba(255,255,255,.06)', background: 'rgba(255,255,255,.015)', flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500, letterSpacing: '-.1px' }}>
                {cardLabel}
              </div>
              <div style={{ marginTop: 4, fontSize: 12, color: 'var(--muted)' }}>
                {viewLabel}
              </div>
            </div>

            {(status === 'pending' || status === 'running') && (
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--muted)' }}>
                <RefreshCw size={12} color="var(--accent)" style={{ animation: 'spin 1s linear infinite' }} />
                <span>Scanning {domains.length || ownedDomains.length} domains</span>
              </div>
            )}
          </div>

          <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(255,255,255,.06)', background: 'rgba(255,255,255,.01)' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
              <input
                type="checkbox"
                checked={hideNoSignals}
                onChange={(event) => setHideNoSignals(event.target.checked)}
                style={{ width: 14, height: 14, accentColor: 'var(--accent)', cursor: 'pointer' }}
              />
              <span style={{ fontSize: 12, color: 'var(--text)' }}>Hide unresolved / no-signal domains</span>
            </label>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.7fr) 150px 100px 120px 120px minmax(150px, 1fr) 34px', gap: 12, alignItems: 'center', padding: '9px 14px', borderBottom: '1px solid rgba(255,255,255,.06)', background: 'rgba(255,255,255,.01)' }}>
            <SortHeader label="Domain / Base" sortKey="candidate" activeKey={sortKey} sortDir={sortDir} onClick={(key) => toggleSort(key, 'asc')} />
            <SortHeader label="Proximity Score" sortKey="enriched_score" activeKey={sortKey} sortDir={sortDir} onClick={(key) => toggleSort(key, 'desc')} />
            <SortHeader label="Risk" sortKey="risk_level" activeKey={sortKey} sortDir={sortDir} onClick={(key) => toggleSort(key, 'asc')} />
            <SortHeader label="Status" sortKey="status" activeKey={sortKey} sortDir={sortDir} onClick={(key) => toggleSort(key, 'asc')} />
            <SortHeader label="Workflow" sortKey="workflow_status" activeKey={sortKey} sortDir={sortDir} onClick={(key) => toggleSort(key, 'asc')} />
            <SortHeader label="Signals" sortKey="signals" activeKey={sortKey} sortDir={sortDir} onClick={(key) => toggleSort(key, 'desc')} />
            <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '.9px', fontWeight: 700, textAlign: 'center' }}>
              Expand
            </div>
          </div>

          {error && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '10px 14px', borderBottom: '1px solid var(--border)', background: 'rgba(255,79,94,.06)' }}>
              <AlertTriangle size={14} color="var(--red)" />
              <span style={{ fontSize: 12, color: 'var(--red)' }}>{error}</span>
            </div>
          )}

          {!results && !loading && !error && (
            <div style={{ padding: '28px 14px', fontSize: 13, color: 'var(--muted)' }}>
              No exposure scan has been run yet for the selected tenant domains.
            </div>
          )}

          {loading && !results && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '18px 14px', fontSize: 12, color: 'var(--muted)' }}>
              <RefreshCw size={13} color="var(--accent)" style={{ animation: 'spin 1s linear infinite' }} />
              <span>Running domain exposure scan...</span>
            </div>
          )}

          {results && filteredRows.length === 0 && (
            <div style={{ padding: '24px 14px', fontSize: 12.5, color: 'var(--muted)' }}>
              {emptyStateMessage}
            </div>
          )}

          {results && filteredRows.length > 0 && groupedRows.map((group) => (
            <div key={group.key}>
              <GroupHeader label={group.label} count={group.rows.length} />
              {group.rows.map((result, index) => (
                <ResultRow
                  key={`${group.key}-${result.base_domain}-${result.candidate}-${index}`}
                  result={result}
                  surfaceMetrics={surfaceMetrics}
                  detailMode={activeCard}
                  rowStatus={rowStatuses[rowStatusKey(result)] || 'new'}
                  onRowStatusChange={(nextStatus) => updateRowStatus(result, nextStatus)}
                  reputationSummary={reputationEntities[result.candidate] || null}
                  reputationLoading={reputationLoading}
                  providerAvailability={reputationProviderAvailability}
                />
              ))}
            </div>
          ))}
        </section>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }
        .domain-exposure-summary-card {
          transition: background .14s ease, border-color .14s ease, box-shadow .14s ease, opacity .14s ease;
        }
        .domain-exposure-summary-card:hover {
          border-color: rgba(255,255,255,.12);
          box-shadow: 0 6px 12px rgba(0,0,0,.12);
          opacity: 1;
        }
        .domain-exposure-summary-card.is-active {
          border-color: rgba(255,255,255,.18);
          background: rgba(10,16,26,.98);
          box-shadow: 0 8px 16px rgba(0,0,0,.16);
          opacity: 1;
        }
        .domain-exposure-summary-card.is-active:hover {
          border-color: rgba(255,255,255,.22);
        }
      `}</style>
    </div>
  )
}
