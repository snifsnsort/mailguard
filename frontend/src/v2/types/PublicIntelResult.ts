// PublicIntelResult.ts
//
// Type for the executive summary block returned by the public intel endpoint.
// This maps to the `evidence` field on ScanResult for public_intel scans.

export interface PublicIntelSummary {
  discovered: boolean;
  domain: string;
  tenant_id: string | null;
  namespace_type: string | null;
  cloud_instance_name: string | null;
  tenant_region_scope: string | null;
  oidc_issuer: string | null;
  is_m365_detected: boolean;
}

// Full scan result shape for a public intel scan.
// Extends the base ScanResult with a typed evidence block.
export interface PublicIntelScanResult {
  scan_id: string;
  tenant_id: string;
  family: string;
  findings: Array<{
    id: string;
    category: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    description: string;
    evidence: Record<string, unknown>;
    references: string[];
  }>;
  score: number;
  status: "pending" | "running" | "complete" | "failed";
  timestamp: string;
  evidence: PublicIntelSummary;
}