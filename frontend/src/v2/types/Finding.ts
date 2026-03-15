// Finding.ts
// Mirrors backend models/v2/finding.py

export interface Finding {
  id: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  references: string[];
}
