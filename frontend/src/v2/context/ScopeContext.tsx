/**
 * ScopeContext.tsx
 *
 * App-level shared state for active domain scope.
 * Provided at the App root so both v1 and v2 pages can consume it.
 *
 * activeDomain     — the single domain currently selected for module navigation
 * setActiveDomain  — update active domain (sidebar selector or page-level promotion)
 * selectableDomains — full cached domain inventory from the last sync
 *                     (tenant.domain + tenant.extra_domains)
 *
 * Persistence: activeDomain is stored in sessionStorage keyed by tenant ID
 * so navigation between pages within a session preserves the selection,
 * but a new session starts fresh from the tenant's primary domain.
 */

import { createContext, useContext } from 'react'

export interface ScopeContextValue {
  activeDomain: string
  setActiveDomain: (domain: string) => void
  selectableDomains: string[]
  /** Add a manually-typed domain to the selectable list for this session */
  addToSelectableDomains: (domain: string) => void
}

export const ScopeContext = createContext<ScopeContextValue>({
  activeDomain: '',
  setActiveDomain: () => {},
  selectableDomains: [],
  addToSelectableDomains: () => {},
})

export function useScope(): ScopeContextValue {
  return useContext(ScopeContext)
}
