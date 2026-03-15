// client.ts
//
// Central API client for MailGuard V2 frontend.

import { PublicIntelScanResult } from "../types/PublicIntelResult";

const API_BASE = "/api/v2";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    let detail = `Request failed: ${response.status}`;
    try {
      const err = await response.json();
      detail = err.detail ?? detail;
    } catch { /* ignore */ }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export const apiClient = {
  /**
   * Discover public Microsoft 365 tenant intelligence for a domain.
   * GET /api/v2/public-intel/{domain}
   */
  getPublicTenantIntel: (domain: string): Promise<PublicIntelScanResult> =>
    get<PublicIntelScanResult>(`/public-intel/${encodeURIComponent(domain)}`),

  /**
   * Resolve and classify MX records for a domain.
   * GET /api/v2/exposure/mx/{domain}
   */
  getMXExposure: (domain: string): Promise<PublicIntelScanResult> =>
    get<PublicIntelScanResult>(`/exposure/mx/${encodeURIComponent(domain)}`),
};