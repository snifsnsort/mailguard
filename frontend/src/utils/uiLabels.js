export const PRODUCT_LABEL = 'EMAIL EXPOSURE MANAGEMENT'
export const DASHBOARD_TITLE = 'Exposure & Risk Dashboard'

export const EXPOSURE_LABELS = {
  surface: 'Exposure Surface',
  findings: 'Exposure Findings',
  finding: 'Finding',
  findingPlural: 'Findings',
  signals: 'Exposure Signals',
  external: 'External Exposure',
  domain: 'Domain',
  tenantDomain: 'Tenant Domain',
}

export const ACTION_LABELS = {
  exportReport: 'Export Report',
  runScan: 'Run Scan',
  syncData: 'Sync Data',
  viewDetails: 'View Details',
  viewRiskBreakdown: 'View Risk Breakdown',
  collapseRiskBreakdown: 'Collapse Risk Breakdown',
}

export const STATUS_LABELS = {
  fail: 'Fail',
  warn: 'Warning',
  pass: 'Pass',
}

export const BENCHMARK_LABELS = {
  cis: 'CIS',
  scuba: 'SCuBA',
  microsoftSecureScore: 'Microsoft Secure Score',
  microsoftBaseline: 'Microsoft Baseline',
}

export function formatTenantContextLine(tenant) {
  if (!tenant) return null

  const platforms = []
  if (tenant.has_m365) platforms.push('Microsoft 365')
  if (tenant.has_gws) platforms.push('Google Workspace')

  return [tenant.domain, ...platforms].join(' • ')
}

export function riskStateFromScore(score) {
  if (score >= 80) return 'Critical Risk'
  if (score >= 60) return 'High Risk'
  if (score >= 40) return 'Moderate Risk'
  return 'Low Risk'
}

export const riskLevelFromScore = riskStateFromScore
