// ScanResult.ts
// Mirrors backend models/v2/scan_result.py

import { Finding } from "./Finding";

export interface ScanResult {
  scan_id: string;
  tenant_id: string;
  family: string;
  findings: Finding[];
  score: number;
  status: "pending" | "running" | "complete" | "failed";
  timestamp: string;
}
