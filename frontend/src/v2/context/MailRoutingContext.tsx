/**
 * MailRoutingContext.tsx
 *
 * Owns the job lifecycle for both mail_routing_topology and tls_posture
 * at the app level. Fires both family jobs immediately when activeDomain
 * changes — before any page mounts.
 *
 * Disciplined behaviour:
 * - Does nothing when activeDomain is empty
 * - Stops polling immediately when jobs reach terminal state
 * - Does not create duplicate jobs (scope_change applies TTL reuse)
 * - triggerRefresh() always creates fresh jobs (manual policy)
 *
 * ScopeContext is NOT modified.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react'
import { useScope } from './ScopeContext'
import { createJob, getJob } from '../api/jobs'
import type { Job, JobStatus, TaskResult } from '../api/jobs'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface FamilyJobState {
  jobId:        string | null
  jobStatus:    'idle' | JobStatus
  taskResults:  Record<string, TaskResult>
  taskStatuses: Record<string, JobStatus>
  jobError:     string | null
}

export interface MailRoutingContextValue {
  routing:         FamilyJobState   // mail_routing_topology
  tls:             FamilyJobState   // tls_posture
  jobDomain:       string
  triggerRefresh:  () => void
}

const IDLE_STATE: FamilyJobState = {
  jobId: null, jobStatus: 'idle', taskResults: {}, taskStatuses: {}, jobError: null,
}

export const MailRoutingContext = createContext<MailRoutingContextValue>({
  routing:        IDLE_STATE,
  tls:            IDLE_STATE,
  jobDomain:      '',
  triggerRefresh: () => {},
})

export function useMailRouting(): MailRoutingContextValue {
  return useContext(MailRoutingContext)
}

// ── Constants ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS   = 2000
const TERMINAL: JobStatus[] = ['completed', 'failed']

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractResults(job: Job): Record<string, TaskResult> {
  const out: Record<string, TaskResult> = {}
  for (const t of job.tasks) { if (t.result) out[t.task_type] = t.result }
  return out
}

function extractStatuses(job: Job): Record<string, JobStatus> {
  const out: Record<string, JobStatus> = {}
  for (const t of job.tasks) { out[t.task_type] = t.status }
  return out
}

function jobToState(job: Job): FamilyJobState {
  return {
    jobId:        job.id,
    jobStatus:    job.status,
    taskResults:  extractResults(job),
    taskStatuses: extractStatuses(job),
    jobError:     job.error_summary ?? null,
  }
}

// ── Single-family lifecycle hook ──────────────────────────────────────────────

function useFamilyJob(
  family: string,
  tenantId: string | null,
  tenantPlatform: 'global' | 'microsoft365' | 'google_workspace',
) {
  const [state, setState] = useState<FamilyJobState>(IDLE_STATE)
  const pollRef  = useRef<ReturnType<typeof setInterval> | null>(null)
  const jobIdRef = useRef<string | null>(null)
  const mounted  = useRef(true)

  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  const startPolling = useCallback((jobId: string) => {
    stopPolling()
    pollRef.current = setInterval(async () => {
      if (jobIdRef.current !== jobId) { stopPolling(); return }
      try {
        const job = await getJob(jobId)
        if (!mounted.current) return
        setState(jobToState(job))
        if (TERMINAL.includes(job.status)) stopPolling()
      } catch { /* network hiccup — keep polling */ }
    }, POLL_INTERVAL_MS)
  }, [stopPolling])

  const startJob = useCallback(async (domain: string, triggeredBy: 'scope_change' | 'manual') => {
    if (!domain) return
    stopPolling()
    setState({ ...IDLE_STATE, jobStatus: 'queued' })
    try {
      const job = await createJob(domain, family, triggeredBy, tenantId ?? undefined, tenantPlatform)
      if (!mounted.current) return
      jobIdRef.current = job.id
      setState(jobToState(job))
      if (!TERMINAL.includes(job.status)) startPolling(job.id)
    } catch (e: unknown) {
      if (!mounted.current) return
      setState({ ...IDLE_STATE, jobStatus: 'failed', jobError: e instanceof Error ? e.message : 'Job creation failed' })
    }
  }, [family, stopPolling, startPolling, tenantId, tenantPlatform])

  useEffect(() => () => stopPolling(), [stopPolling])

  return { state, startJob }
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function MailRoutingProvider({
  children,
  tenantId,
  tenantPlatform,
}: {
  children: React.ReactNode
  tenantId: string | null
  tenantPlatform: 'global' | 'microsoft365' | 'google_workspace'
}) {
  const { activeDomain } = useScope()
  const [jobDomain, setJobDomain] = useState('')

  const { state: routingState, startJob: startRouting } = useFamilyJob('mail_routing_topology', tenantId, tenantPlatform)
  const { state: tlsState,     startJob: startTls     } = useFamilyJob('tls_posture', tenantId, tenantPlatform)

  const prevScopeRef = useRef('')

  useEffect(() => {
    if (!activeDomain) return
    const scopeKey = `${activeDomain}:${tenantId ?? 'none'}:${tenantPlatform}`
    if (scopeKey === prevScopeRef.current) return
    prevScopeRef.current = scopeKey
    setJobDomain(activeDomain)
    startRouting(activeDomain, 'scope_change')
    startTls(activeDomain, 'scope_change')
  }, [activeDomain, startRouting, startTls, tenantId, tenantPlatform])

  const triggerRefresh = useCallback(() => {
    if (!activeDomain) return
    setJobDomain(activeDomain)
    startRouting(activeDomain, 'manual')
    startTls(activeDomain, 'manual')
  }, [activeDomain, startRouting, startTls])

  return (
    <MailRoutingContext.Provider value={{
      routing:        routingState,
      tls:            tlsState,
      jobDomain,
      triggerRefresh,
    }}>
      {children}
    </MailRoutingContext.Provider>
  )
}

