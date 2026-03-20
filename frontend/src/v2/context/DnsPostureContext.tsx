/**
 * DnsPostureContext.tsx
 *
 * Owns the full dns_posture job lifecycle at the app level.
 *
 * Design rules:
 * - Watches activeDomain from ScopeContext
 * - Creates a job immediately when activeDomain changes (scope_change policy)
 * - Polls only while the job is queued or running — stops immediately on terminal state
 * - Does nothing when activeDomain is empty or when no job exists
 * - triggerRefresh() creates a fresh job regardless of existing state (manual policy)
 * - Pages consume this context and render results — they own no scan logic
 *
 * ScopeContext is NOT modified by this file.
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

export interface DnsPostureContextValue {
  /** Current job ID for the active domain, or null if none exists yet */
  currentJobId:  string | null
  /** Derived from the active job's status */
  jobStatus:     'idle' | JobStatus
  /** Task results keyed by task_type, e.g. taskResults['authentication_status'] */
  taskResults:   Record<string, TaskResult>
  /** Task statuses keyed by task_type — for the status bar */
  taskStatuses:  Record<string, JobStatus>
  /** Error message if the job failed */
  jobError:      string | null
  /** The domain this job is for — may differ briefly from activeDomain during transition */
  jobDomain:     string
  /** Force a fresh job regardless of TTL or existing state */
  triggerRefresh: () => void
}

export const DnsPostureContext = createContext<DnsPostureContextValue>({
  currentJobId:   null,
  jobStatus:      'idle',
  taskResults:    {},
  taskStatuses:   {},
  jobError:       null,
  jobDomain:      '',
  triggerRefresh: () => {},
})

export function useDnsPosture(): DnsPostureContextValue {
  return useContext(DnsPostureContext)
}

// ── Constants ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 2000
const TERMINAL_STATUSES: JobStatus[] = ['completed', 'failed']

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractTaskResults(job: Job): Record<string, TaskResult> {
  const results: Record<string, TaskResult> = {}
  for (const task of job.tasks) {
    if (task.result) results[task.task_type] = task.result
  }
  return results
}

function extractTaskStatuses(job: Job): Record<string, JobStatus> {
  const statuses: Record<string, JobStatus> = {}
  for (const task of job.tasks) {
    statuses[task.task_type] = task.status
  }
  return statuses
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function DnsPostureProvider({ children }: { children: React.ReactNode }) {
  const { activeDomain } = useScope()

  const [currentJobId,  setCurrentJobId]  = useState<string | null>(null)
  const [jobStatus,     setJobStatus]     = useState<'idle' | JobStatus>('idle')
  const [taskResults,   setTaskResults]   = useState<Record<string, TaskResult>>({})
  const [taskStatuses,  setTaskStatuses]  = useState<Record<string, JobStatus>>({})
  const [jobError,      setJobError]      = useState<string | null>(null)
  const [jobDomain,     setJobDomain]     = useState<string>('')

  // Refs used inside polling interval — avoids stale closures
  const pollRef      = useRef<ReturnType<typeof setInterval> | null>(null)
  const jobIdRef     = useRef<string | null>(null)
  const isMounted    = useRef(true)

  useEffect(() => {
    isMounted.current = true
    return () => { isMounted.current = false }
  }, [])

  // ── Polling ────────────────────────────────────────────────────────────────

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  const startPolling = useCallback((jobId: string) => {
    stopPolling()
    pollRef.current = setInterval(async () => {
      // Only poll if this is still the current job
      if (jobIdRef.current !== jobId) { stopPolling(); return }
      try {
        const job = await getJob(jobId)
        if (!isMounted.current) return
        setJobStatus(job.status)
        setTaskResults(extractTaskResults(job))
        setTaskStatuses(extractTaskStatuses(job))
        if (job.error_summary) setJobError(job.error_summary)
        if (TERMINAL_STATUSES.includes(job.status)) {
          stopPolling()
        }
      } catch {
        // Network error — keep polling; do not flip to failed
      }
    }, POLL_INTERVAL_MS)
  }, [stopPolling])

  // ── Job creation ───────────────────────────────────────────────────────────

  const startJob = useCallback(async (
    domain: string,
    triggeredBy: 'scope_change' | 'manual',
  ) => {
    if (!domain) return
    stopPolling()
    setJobStatus('queued')
    setTaskResults({})
    setTaskStatuses({})
    setJobError(null)
    setJobDomain(domain)

    try {
      const job = await createJob(domain, 'dns_posture', triggeredBy)
      if (!isMounted.current) return

      jobIdRef.current = job.id
      setCurrentJobId(job.id)
      setJobStatus(job.status)
      setTaskResults(extractTaskResults(job))
      setTaskStatuses(extractTaskStatuses(job))

      // Only poll if not already terminal (scope_change may return completed job)
      if (!TERMINAL_STATUSES.includes(job.status)) {
        startPolling(job.id)
      }
    } catch (e: unknown) {
      if (!isMounted.current) return
      setJobStatus('failed')
      setJobError(e instanceof Error ? e.message : 'Job creation failed')
    }
  }, [stopPolling, startPolling])

  // ── React to activeDomain changes ──────────────────────────────────────────
  // Fires immediately when sidebar domain selector changes — before any page mounts.
  // Guards:
  //   - skip if domain is empty
  //   - skip if domain is unchanged (prevents double-fire on re-renders)

  const prevDomainRef = useRef<string>('')

  useEffect(() => {
    if (!activeDomain) return
    if (activeDomain === prevDomainRef.current) return
    prevDomainRef.current = activeDomain
    startJob(activeDomain, 'scope_change')
  }, [activeDomain, startJob])

  // ── Cleanup on unmount ─────────────────────────────────────────────────────

  useEffect(() => {
    return () => { stopPolling() }
  }, [stopPolling])

  // ── Manual refresh ─────────────────────────────────────────────────────────

  const triggerRefresh = useCallback(() => {
    if (!activeDomain) return
    startJob(activeDomain, 'manual')
  }, [activeDomain, startJob])

  return (
    <DnsPostureContext.Provider value={{
      currentJobId,
      jobStatus,
      taskResults,
      taskStatuses,
      jobError,
      jobDomain,
      triggerRefresh,
    }}>
      {children}
    </DnsPostureContext.Provider>
  )
}
