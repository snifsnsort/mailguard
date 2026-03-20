import { BENCHMARK_LABELS } from './uiLabels'

export function findingBenchmarkKey(finding) {
  return `${finding?.check_id || ''}::${finding?.domain || ''}`
}

function makeDisplay(fullLabel, shortLabel, color, bg) {
  return { fullLabel, shortLabel, color, bg }
}

export function parseBenchmarkDisplay(benchmarkLabel, benchmarkKey = null) {
  if (!benchmarkLabel && !benchmarkKey) return null

  const label = String(benchmarkLabel || '')

  if (/CIS/i.test(label) || benchmarkKey === 'cis') {
    const controlMatch = label.match(/Control(?:s)?\s*([\d.,\s]+)/i)
    const shortLabel = controlMatch ? `CIS ${controlMatch[1].replace(/\s+/g, '')}` : BENCHMARK_LABELS.cis
    return makeDisplay(label || BENCHMARK_LABELS.cis, shortLabel, '#4da6ff', 'rgba(77,166,255,.1)')
  }

  if (/SCuBA/i.test(label) || benchmarkKey === 'scuba') {
    const controlMatch = label.match(/(MS\.[A-Z]+(?:\.[\dA-Z]+)+)/i)
    const shortLabel = controlMatch ? `SCuBA ${controlMatch[1]}` : BENCHMARK_LABELS.scuba
    return makeDisplay(label || BENCHMARK_LABELS.scuba, shortLabel, '#00e676', 'rgba(0,230,118,.1)')
  }

  if (/Secure Score/i.test(label) || benchmarkKey === 'microsoft_secure_score') {
    return makeDisplay(
      label || BENCHMARK_LABELS.microsoftSecureScore,
      'MS Secure Score',
      '#ff9f43',
      'rgba(255,159,67,.12)',
    )
  }

  if (/Baseline/i.test(label) || benchmarkKey === 'microsoft_baseline') {
    return makeDisplay(
      label || BENCHMARK_LABELS.microsoftBaseline,
      'MS Baseline',
      '#ffd740',
      'rgba(255,215,64,.1)',
    )
  }

  return null
}

export function buildFindingBenchmarkMap(benchmarkFindings = {}) {
  const map = {}

  Object.entries(benchmarkFindings || {}).forEach(([benchmarkKey, findingList]) => {
    ;(findingList || []).forEach((finding) => {
      const parsed = parseBenchmarkDisplay(finding?.benchmark, benchmarkKey)
      if (!parsed) return

      const key = findingBenchmarkKey(finding)
      const existing = map[key] || []
      if (!existing.some((entry) => entry.fullLabel === parsed.fullLabel)) {
        existing.push(parsed)
      }
      map[key] = existing
    })
  })

  return map
}

export function attachFindingBenchmarks(finding, benchmarkMap) {
  const key = findingBenchmarkKey(finding)
  const mapped = benchmarkMap[key]
  if (mapped?.length) {
    return { ...finding, benchmarks: mapped }
  }

  const fallback = parseBenchmarkDisplay(finding?.benchmark)
  return { ...finding, benchmarks: fallback ? [fallback] : [] }
}
