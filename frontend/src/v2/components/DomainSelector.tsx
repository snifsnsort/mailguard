// DomainSelector.tsx — MailGuard V2
//
// Reusable domain input component used on all V2 scan pages.
//
// Behaviour:
//   - Tenant dropdown (optional): selecting auto-populates the domain field
//   - Domain field is always the actual scan input; user can edit after tenant select
//   - Inline validation on submit attempt

import React, { useState } from "react";
import { Tenant } from "../types/Tenant";
import { colors, fonts, radius } from "../theme";

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function validateDomain(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return "Domain is required.";
  if (!DOMAIN_RE.test(trimmed)) return "Enter a valid domain (e.g. contoso.com).";
  return null; // valid
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface DomainSelectorProps {
  /** List of onboarded tenants to populate the dropdown */
  tenantList: Tenant[];
  /** Currently selected tenant (controlled) */
  selectedTenant: Tenant | null;
  /** Current domain field value (controlled) */
  domain: string;
  /** Called when user picks a tenant from the dropdown */
  onTenantChange: (tenant: Tenant | null) => void;
  /** Called whenever the domain field changes */
  onDomainChange: (domain: string) => void;
  /** Called when the user submits (Enter or Scan button) */
  onScan: () => void;
  /** Disables inputs and button while a scan is running */
  loading?: boolean;
  /** Accent colour for the scan button and focus ring — matches page theme */
  accentColor?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function DomainSelector({
  tenantList,
  selectedTenant,
  domain,
  onTenantChange,
  onDomainChange,
  onScan,
  loading = false,
  accentColor = colors.cyan,
}: DomainSelectorProps) {
  const [validationError, setValidationError] = useState<string | null>(null);

  // When a tenant is selected from the dropdown, auto-fill the domain field.
  const handleTenantSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const id = e.target.value;
    if (!id) {
      onTenantChange(null);
      return;
    }
    const tenant = tenantList.find(t => t.tenant_id === id) ?? null;
    onTenantChange(tenant);
    if (tenant) {
      onDomainChange(tenant.domain);
      setValidationError(null);
    }
  };

  // Tenant selection is only a convenience for filling the domain field.
  // The domain input is always the authoritative scan target.
  // If the domain is edited manually, the tenant association is cleared.
  const handleDomainChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    onDomainChange(val);
    if (validationError) setValidationError(null);
    // If the typed value no longer matches the selected tenant's domain, deselect it
    if (selectedTenant && val.trim().toLowerCase() !== selectedTenant.domain.toLowerCase()) {
      onTenantChange(null);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") handleScan();
  };

  const handleScan = () => {
    const err = validateDomain(domain);
    if (err) {
      setValidationError(err);
      return;
    }
    setValidationError(null);
    onScan();
  };

  const hasTenantsToShow = tenantList.length > 0;
  const dropdownValue    = selectedTenant?.tenant_id ?? "";
  const accentBg         = accentColor + "1a"; // 10% opacity tint

  return (
    <div style={{ marginBottom: 32, maxWidth: 640 }}>

      {/* Tenant dropdown — only rendered if there are onboarded tenants */}
      {hasTenantsToShow && (
        <div style={{ marginBottom: 12 }}>
          <label style={labelStyle}>
            Select onboarded tenant
          </label>
          <select
            value={dropdownValue}
            onChange={handleTenantSelect}
            disabled={loading}
            style={{
              width: "100%",
              padding: "11px 14px",
              fontSize: 13,
              fontFamily: fonts.mono,
              backgroundColor: colors.bgSurface,
              border: `1px solid ${colors.borderSubtle}`,
              borderRadius: radius.md,
              color: dropdownValue ? colors.textPrimary : colors.textMuted,
              outline: "none",
              cursor: loading ? "not-allowed" : "pointer",
              appearance: "none" as const,
              backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath fill='%2364748b' d='M0 0l5 6 5-6z'/%3E%3C/svg%3E")`,
              backgroundRepeat: "no-repeat",
              backgroundPosition: "right 14px center",
            }}
          >
            <option value="">— select tenant —</option>
            {tenantList.map(t => (
              <option key={t.tenant_id} value={t.tenant_id}>
                {t.display_name ?? t.domain}
                {t.display_name ? ` (${t.domain})` : ""}
                {" · "}
                {t.platform === "microsoft365" ? "M365" : "GWS"}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Divider label */}
      <label style={labelStyle}>
        {hasTenantsToShow ? "Or enter domain manually" : "Enter domain"}
      </label>

      {/* Domain input + Scan button */}
      <div style={{ display: "flex", gap: 8 }}>
        <div style={{ flex: 1, position: "relative" }}>
          <input
            type="text"
            value={domain}
            onChange={handleDomainChange}
            onKeyDown={handleKeyDown}
            placeholder="target-domain.com"
            disabled={loading}
            autoComplete="off"
            spellCheck={false}
            style={{
              width: "100%",
              padding: "12px 14px",
              fontSize: 14,
              fontFamily: fonts.mono,
              backgroundColor: colors.bgSurface,
              border: `1px solid ${validationError ? colors.red : colors.borderSubtle}`,
              borderRadius: radius.md,
              color: colors.textPrimary,
              outline: "none",
              boxSizing: "border-box" as const,
              caretColor: accentColor,
              transition: "border-color 0.15s",
            }}
          />
        </div>

        <button
          onClick={handleScan}
          disabled={loading || !domain.trim()}
          style={{
            padding: "12px 24px",
            fontSize: 13,
            fontWeight: 600,
            fontFamily: fonts.ui,
            letterSpacing: "0.05em",
            backgroundColor: loading ? colors.bgElevated : accentColor,
            color: loading ? colors.textSecondary : colors.bgBase,
            border: "none",
            borderRadius: radius.md,
            cursor: loading || !domain.trim() ? "not-allowed" : "pointer",
            flexShrink: 0,
            transition: "background-color 0.15s",
          }}
        >
          {loading ? "SCANNING…" : "SCAN"}
        </button>
      </div>

      {/* Selected tenant context pill — shown when a tenant is active */}
      {selectedTenant && (
        <div style={{
          marginTop: 8,
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          padding: "4px 10px",
          borderRadius: 12,
          backgroundColor: accentBg,
          border: `1px solid ${accentColor}33`,
        }}>
          <span style={{ fontSize: 10, fontFamily: fonts.mono, color: accentColor, letterSpacing: "0.06em" }}>
            TENANT
          </span>
          <span style={{ fontSize: 12, color: colors.textPrimary }}>
            {selectedTenant.display_name ?? selectedTenant.domain}
          </span>
          <span style={{ fontSize: 10, color: colors.textMuted, fontFamily: fonts.mono }}>
            {selectedTenant.platform === "microsoft365" ? "M365" : "GWS"}
          </span>
          {/* Clear selection */}
          <button
            onClick={() => { onTenantChange(null); }}
            style={{
              background: "none",
              border: "none",
              color: colors.textMuted,
              cursor: "pointer",
              padding: "0 0 0 4px",
              fontSize: 12,
              lineHeight: 1,
            }}
            title="Clear tenant selection"
          >
            ×
          </button>
        </div>
      )}

      {/* Validation error */}
      {validationError && (
        <div style={{
          marginTop: 8,
          fontSize: 12,
          color: colors.red,
          fontFamily: fonts.mono,
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}>
          <span>⚠</span> {validationError}
        </div>
      )}

      {/* Focus ring injection */}
      <style>{`
        input[type="text"]:focus {
          border-color: ${accentColor} !important;
          box-shadow: 0 0 0 3px ${accentColor}22;
        }
        select:focus {
          border-color: ${accentColor} !important;
          box-shadow: 0 0 0 3px ${accentColor}22;
          outline: none;
        }
        input[type="text"]::placeholder { color: ${colors.textMuted}; }
      `}</style>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared label style
// ---------------------------------------------------------------------------

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: 11,
  fontFamily: fonts.mono,
  color: colors.textMuted,
  letterSpacing: "0.08em",
  marginBottom: 6,
  textTransform: "uppercase",
};
