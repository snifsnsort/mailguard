// PublicIntelPage.tsx — MailGuard V2
// Public Tenant Intelligence — dark security terminal aesthetic

import React, { useState, useEffect } from "react";
import { apiClient } from "../../api/client";
import { PublicIntelScanResult, PublicIntelSummary } from "../../types/PublicIntelResult";
import { colors, fonts, radius, injectFonts, cardStyle } from "../../theme";
import { DomainSelector } from "../../components/DomainSelector";
import { Tenant, MOCK_TENANTS } from "../../types/Tenant";

type PageState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; result: PublicIntelScanResult }
  | { status: "error"; message: string };

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "2px 8px",
      borderRadius: radius.sm,
      fontSize: 10,
      fontWeight: 600,
      letterSpacing: "0.08em",
      fontFamily: fonts.mono,
      backgroundColor: colors.severityBg[severity as keyof typeof colors.severityBg] ?? colors.bgElevated,
      color: colors.severityText[severity as keyof typeof colors.severityText] ?? colors.textSecondary,
      border: `1px solid ${colors.severityText[severity as keyof typeof colors.severityText] ?? colors.borderSubtle}22`,
    }}>
      {severity.toUpperCase()}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Summary row component
// ---------------------------------------------------------------------------

function SummaryRow({
  label,
  value,
  mono = false,
  highlight = false,
}: {
  label: string;
  value: string | null | boolean;
  mono?: boolean;
  highlight?: boolean;
}) {
  const displayValue = value === null || value === undefined
    ? <span style={{ color: colors.textMuted }}>—</span>
    : typeof value === "boolean"
    ? (
      <span style={{
        color: value ? colors.green : colors.textSecondary,
        fontFamily: fonts.mono,
        fontSize: 13,
      }}>
        {value ? "● YES" : "○ NO"}
      </span>
    )
    : (
      <span style={{
        fontFamily: mono ? fonts.mono : fonts.ui,
        fontSize: mono ? 12 : 13,
        color: highlight ? colors.cyan : colors.textPrimary,
        wordBreak: "break-all",
      }}>
        {String(value)}
      </span>
    );

  return (
    <tr>
      <td style={{
        padding: "10px 0",
        color: colors.textSecondary,
        fontSize: 12,
        fontWeight: 500,
        letterSpacing: "0.04em",
        textTransform: "uppercase",
        width: 200,
        verticalAlign: "top",
        borderBottom: `1px solid ${colors.borderFaint}`,
      }}>
        {label}
      </td>
      <td style={{
        padding: "10px 0 10px 16px",
        verticalAlign: "top",
        borderBottom: `1px solid ${colors.borderFaint}`,
      }}>
        {displayValue}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Summary card
// ---------------------------------------------------------------------------

function SummaryCard({ summary }: { summary: PublicIntelSummary }) {
  return (
    <div style={cardStyle}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
        <span style={{
          width: 3,
          height: 18,
          backgroundColor: colors.cyan,
          borderRadius: 2,
          display: "inline-block",
        }} />
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: colors.textPrimary, letterSpacing: "0.04em" }}>
          TENANT INTELLIGENCE SUMMARY
        </h3>
        {summary.is_m365_detected && (
          <span style={{
            marginLeft: "auto",
            padding: "2px 10px",
            borderRadius: 12,
            fontSize: 11,
            fontWeight: 600,
            backgroundColor: colors.greenDim,
            color: colors.green,
            border: `1px solid ${colors.green}33`,
            fontFamily: fonts.mono,
          }}>
            M365 DETECTED
          </span>
        )}
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <tbody>
          <SummaryRow label="Domain"           value={summary.domain} />
          <SummaryRow label="Tenant ID"        value={summary.tenant_id}          mono highlight />
          <SummaryRow label="Namespace Type"   value={summary.namespace_type} />
          <SummaryRow label="Cloud Instance"   value={summary.cloud_instance_name} mono />
          <SummaryRow label="Tenant Region"    value={summary.tenant_region_scope} />
          <SummaryRow label="OIDC Issuer"      value={summary.oidc_issuer}         mono />
          <SummaryRow label="M365 Detected"    value={summary.is_m365_detected} />
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Finding row
// ---------------------------------------------------------------------------

function FindingRow({ finding }: { finding: PublicIntelScanResult["findings"][number] }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      style={{
        borderBottom: `1px solid ${colors.borderFaint}`,
        transition: "background 0.15s",
      }}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "12px 4px",
          cursor: "pointer",
        }}
        onMouseEnter={e => (e.currentTarget.style.backgroundColor = colors.bgElevated)}
        onMouseLeave={e => (e.currentTarget.style.backgroundColor = "transparent")}
      >
        <SeverityBadge severity={finding.severity} />
        <span style={{ flex: 1, fontSize: 13, color: colors.textPrimary, fontWeight: 500 }}>
          {finding.title}
        </span>
        <span style={{
          fontSize: 10,
          color: colors.textMuted,
          fontFamily: fonts.mono,
          transform: expanded ? "rotate(180deg)" : "none",
          transition: "transform 0.2s",
        }}>
          ▼
        </span>
      </div>

      {expanded && (
        <div style={{ padding: "0 4px 16px 4px" }}>
          <p style={{
            margin: "0 0 12px",
            fontSize: 13,
            color: colors.textSecondary,
            lineHeight: 1.6,
          }}>
            {finding.description}
          </p>
          {Object.keys(finding.evidence).length > 0 && (
            <pre style={{
              backgroundColor: colors.bgInset,
              border: `1px solid ${colors.borderSubtle}`,
              borderRadius: radius.sm,
              padding: "12px 14px",
              fontSize: 11,
              fontFamily: fonts.mono,
              color: colors.textCode,
              overflowX: "auto",
              margin: 0,
              lineHeight: 1.6,
            }}>
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function PublicIntelPage() {
  const [domain, setDomain]               = useState("");
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [page, setPage]                   = useState<PageState>({ status: "idle" });

  useEffect(() => { injectFonts(); }, []);

  const handleScan = async () => {
    const trimmed = domain.trim().toLowerCase();
    if (!trimmed) return;
    setPage({ status: "loading" });
    try {
      const result = await apiClient.getPublicTenantIntel(trimmed);
      setPage({ status: "success", result });
    } catch (err: unknown) {
      setPage({ status: "error", message: err instanceof Error ? err.message : "Unknown error" });
    }
  };

  return (
    <div style={{
      minHeight: "100vh",
      backgroundColor: colors.bgBase,
      fontFamily: fonts.ui,
      color: colors.textPrimary,
      padding: "40px 32px",
    }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <div style={{
          fontSize: 11,
          fontFamily: fonts.mono,
          color: colors.cyan,
          letterSpacing: "0.12em",
          marginBottom: 8,
          opacity: 0.8,
        }}>
          PUBLIC TENANT INTELLIGENCE
        </div>
        <h1 style={{ margin: 0, fontSize: 26, fontWeight: 600, color: colors.textPrimary }}>
          M365 Tenant Discovery
        </h1>
        <p style={{ margin: "8px 0 0", color: colors.textSecondary, fontSize: 14 }}>
          Discover publicly visible Microsoft 365 tenant signals using only unauthenticated sources.
        </p>
      </div>

      {/* Input */}
      <DomainSelector
        tenantList={MOCK_TENANTS}
        selectedTenant={selectedTenant}
        domain={domain}
        onTenantChange={setSelectedTenant}
        onDomainChange={setDomain}
        onScan={handleScan}
        loading={page.status === "loading"}
        accentColor={colors.cyan}
      />

      {/* Loading */}
      {page.status === "loading" && (
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          color: colors.textSecondary,
          fontSize: 13,
          fontFamily: fonts.mono,
        }}>
          <span style={{ color: colors.cyan, animation: "pulse 1.2s infinite" }}>▋</span>
          Querying public Microsoft endpoints…
        </div>
      )}

      {/* Error */}
      {page.status === "error" && (
        <div style={{
          padding: "14px 18px",
          backgroundColor: colors.redSubtle,
          border: `1px solid ${colors.redDim}`,
          borderRadius: radius.md,
          color: colors.red,
          fontSize: 13,
          fontFamily: fonts.mono,
          maxWidth: 640,
        }}>
          <span style={{ opacity: 0.6 }}>ERROR: </span>{page.message}
        </div>
      )}

      {/* Results */}
      {page.status === "success" && (
        <div style={{ maxWidth: 800 }}>
          {/* Meta bar */}
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            marginBottom: 20,
            padding: "10px 16px",
            backgroundColor: colors.bgSurface,
            border: `1px solid ${colors.borderFaint}`,
            borderRadius: radius.md,
            flexWrap: "wrap",
          }}>
            <span style={{
              padding: "2px 10px",
              borderRadius: 12,
              fontSize: 10,
              fontWeight: 700,
              fontFamily: fonts.mono,
              letterSpacing: "0.06em",
              backgroundColor: colors.greenDim,
              color: colors.green,
            }}>
              {page.result.status.toUpperCase()}
            </span>
            <span style={{ fontSize: 11, fontFamily: fonts.mono, color: colors.textMuted }}>
              SCAN {page.result.scan_id.split("-")[0].toUpperCase()}
            </span>
            <span style={{ marginLeft: "auto", fontSize: 11, fontFamily: fonts.mono, color: colors.textMuted }}>
              {page.result.timestamp}
            </span>
          </div>

          <SummaryCard summary={page.result.evidence} />

          {/* Findings */}
          <div style={cardStyle}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              <span style={{ width: 3, height: 18, backgroundColor: colors.amber, borderRadius: 2, display: "inline-block" }} />
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600, letterSpacing: "0.04em" }}>
                FINDINGS
              </h3>
              <span style={{
                marginLeft: 4,
                padding: "1px 8px",
                borderRadius: 10,
                fontSize: 11,
                fontFamily: fonts.mono,
                backgroundColor: colors.bgElevated,
                color: colors.textSecondary,
                border: `1px solid ${colors.borderSubtle}`,
              }}>
                {page.result.findings.length}
              </span>
            </div>
            {page.result.findings.length === 0
              ? <p style={{ color: colors.textMuted, fontSize: 13 }}>No findings returned.</p>
              : page.result.findings.map(f => <FindingRow key={f.id} finding={f} />)
            }
          </div>
        </div>
      )}

      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.2 } }
        input::placeholder { color: ${colors.textMuted}; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${colors.bgBase}; }
        ::-webkit-scrollbar-thumb { background: ${colors.borderActive}; border-radius: 3px; }
      `}</style>
    </div>
  );
}
