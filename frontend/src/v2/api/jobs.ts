/**
 * jobs.ts — V2 Jobs API client
 *
 * All fetch calls go through here. Auth headers are attached automatically
 * from localStorage. No scan logic lives here — only HTTP.
 */

const BASE = '/api/v2'

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('mg_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...opts.headers },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error((body as { detail?: string }).detail ?? `HTTP ${res.status}`)
  }
  return res.json()
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed'

export interface TaskResult {
  task_type:    string
  family:       string
  job_id:       string
  domain:       string
  tenant_id:    string | null
  completed_at: string
  status:       string
  score:        number | null
  findings:     unknown[]
  evidence:     Record<string, unknown>
}

export interface JobTask {
  id:           string
  task_type:    string
  platform:     string
  status:       JobStatus
  started_at:   string | null
  completed_at: string | null
  error:        string | null
  result:       TaskResult | null
}

export interface Job {
  id:            string
  tenant_id:     string | null
  domain:        string
  scan_family:   string
  status:        JobStatus
  triggered_by:  string
  started_at:    string | null
  completed_at:  string | null
  error_summary: string | null
  tasks:         JobTask[]
}

// ── API calls ─────────────────────────────────────────────────────────────────

export async function createJob(
  domain: string,
  scanFamily: string,
  triggeredBy: 'scope_change' | 'manual' | 'api' = 'api',
  tenantId?: string,
  platform: 'global' | 'microsoft365' | 'google_workspace' = 'global',
): Promise<Job> {
  return request<Job>('/jobs', {
    method: 'POST',
    body: JSON.stringify({
      domain,
      scan_family: scanFamily,
      triggered_by: triggeredBy,
      tenant_id: tenantId ?? null,
      platform,
    }),
  })
}

export async function getJob(jobId: string): Promise<Job> {
  return request<Job>(`/jobs/${jobId}`)
}

export async function getLatestJob(domain: string, family: string): Promise<Job | null> {
  try {
    return await request<Job>(`/jobs/latest?domain=${encodeURIComponent(domain)}&family=${encodeURIComponent(family)}`)
  } catch (e: unknown) {
    // 404 = no job exists yet — not an error
    if (e instanceof Error && e.message.includes('404')) return null
    throw e
  }
}

