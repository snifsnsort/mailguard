// Tenant.ts — MailGuard V2
// Represents an onboarded tenant in the UI.
// Mirrors the backend tenant model.

export interface Tenant {
  tenant_id: string;
  domain: string;
  platform: "microsoft365" | "google_workspace";
  display_name?: string;
}

// ---------------------------------------------------------------------------
// Mock tenant list — used until tenant persistence is implemented
// Replace with an API call to GET /api/v1/tenants once wired.
// ---------------------------------------------------------------------------

export const MOCK_TENANTS: Tenant[] = [
  {
    tenant_id: "pfptdev",
    domain: "pfptdev.com",
    display_name: "PfptDev (Proofpoint)",
    platform: "microsoft365",
  },
  {
    tenant_id: "cloud4you",
    domain: "cloud4you.ca",
    display_name: "Cloud4You",
    platform: "google_workspace",
  },
];
