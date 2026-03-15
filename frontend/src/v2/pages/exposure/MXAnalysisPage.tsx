// MXAnalysisPage.tsx — MailGuard V2
// SOC-grade MX Routing Health analysis page.
//
// Sections:
//   1. Posture Overview  — arc gauge + metrics grid (no inline styles where avoidable)
//   2. Findings          — compact expandable list, severity-grouped
//   3. Mail Routing Map  — RoutingTopology component (responsive SVG)
//   4. Evidence          — MX records table with conservative path roles
//   5. Scan Details      — collapsed by default

import React, { useState, useEffect } from "react";
import { apiClient } from "../../api/client";
import { PublicIntelScanResult } from "../../types/PublicIntelResult";
import { colors, fonts, injectFonts } from "../../theme";
import { DomainSelector } from "../../components/DomainSelector";
import { Tenant, MOCK_TENANTS } from "../../types/Tenant";
import { RoutingTopology } from "../../components/RoutingTopology";

type MXScanResult = PublicIntelScanResult;

type EnrichedMXRecord = {
  priority:      number;
  host:          string;
  provider:      string;
  ips:           string[];
  resolved:      boolean;
  multi_ip:      boolean;
  resolve_error: string | null;
};

type MXEvidence = {
  domain:             string;
  mx_records:         EnrichedMXRecord[];
  providers:          string[];
  routing_type:       string;
  provider_count:     number;
  unresolvable_hosts: string[];
  health_score:       number;
  health_deductions:  string[];
  scan_metadata?:     Record<string, unknown>;
  routing_analysis?:  Record<string, unknown>;
};

type PageState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; result: MXScanResult; evidence: MXEvidence }
  | { status: "error"; message: string };

// ---------------------------------------------------------------------------
// CSS injection — tokens + component classes
// All static layout/color comes from CSS classes. Inline styles only for
// computed dynamic values (score fill %, per-record colors).
// ---------------------------------------------------------------------------

function injectPageStyles() {
  if (document.getElementById("mg-mx-styles")) return;
  const s = document.createElement("style");
  s.id = "mg-mx-styles";
  s.textContent = `
    /* ── Tokens (fallback if tokens.css not imported at app level) ── */
    :root {
      --bg-primary:          #080d16;
      --bg-surface:          #0f1724;
      --bg-elevated:         #162032;
      --bg-inset:            #0a1020;
      --border-faint:        #1a2840;
      --border-subtle:       #1e3152;
      --border-active:       #2a4a7f;
      --accent-cyan:         #00d4ff;
      --accent-amber:        #f59e0b;
      --accent-green:        #00e57a;
      --accent-red:          #ff3d5a;
      --status-critical:     #ff3d5a;
      --status-critical-dim: #3d0d14;
      --status-warning:      #f59e0b;
      --status-warning-dim:  #3d2800;
      --status-success:      #00e57a;
      --status-success-dim:  #0a3d24;
      --status-info:         #64748b;
      --status-info-dim:     #111827;
      --sev-critical:        #ff3d5a;
      --sev-high:            #ff6b2b;
      --sev-medium:          #f59e0b;
      --sev-low:             #00d4ff;
      --sev-info:            #64748b;
      --sev-bg-critical:     #3d0d14;
      --sev-bg-high:         #3d1a00;
      --sev-bg-medium:       #3d2800;
      --sev-bg-low:          #0e2a3d;
      --sev-bg-info:         #111827;
      --text-primary:        #e2e8f0;
      --text-secondary:      #64748b;
      --text-muted:          #3d5068;
      --text-code:           #94a3b8;
      --font-ui:             'DM Sans', 'Segoe UI', sans-serif;
      --font-mono:           'JetBrains Mono', 'Fira Code', monospace;
      --radius-sm:           3px;
      --radius-md:           5px;
      --radius-lg:           8px;
    }

    /* ── Page ── */
    .mg-page {
      min-height: 100vh;
      background-color: var(--bg-primary);
      font-family: var(--font-ui);
      color: var(--text-primary);
      padding: 36px 32px;
    }
    .mg-results { max-width: 860px; }

    /* ── Card ── */
    .mg-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-faint);
      border-radius: var(--radius-lg);
      padding: 12px 16px;
      margin-bottom: 14px;
    }

    /* ── Section header ── */
    .mg-sh {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 12px;
    }
    .mg-sh-bar {
      width: 3px;
      height: 15px;
      border-radius: 2px;
      display: inline-block;
      flex-shrink: 0;
    }
    .mg-sh-title {
      margin: 0;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.07em;
      color: var(--text-primary);
    }
    .mg-sh-right { margin-left: auto; }

    /* ── Posture overview ── */
    .mg-posture {
      display: flex;
      gap: 20px;
      align-items: flex-start;
      flex-wrap: wrap;
    }
    .mg-posture-gauge {
      flex-shrink: 0;
      width: 110px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
    }
    .mg-posture-right {
      flex: 1;
      min-width: 200px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .mg-deductions {
      font-size: 9px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      text-align: center;
      line-height: 1.4;
      max-width: 110px;
    }
    .mg-deductions span {
      color: var(--text-secondary);
    }

    /* ── Metrics grid ── */
    .mg-metrics-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
    }
    .mg-metric {
      padding: 8px 10px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-faint);
      border-radius: var(--radius-md);
      border-left-width: 3px;
    }
    .mg-metric-val {
      font-size: 20px;
      font-weight: 700;
      font-family: var(--font-mono);
      line-height: 1;
      margin-bottom: 3px;
    }
    .mg-metric-lbl {
      font-size: 9px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      letter-spacing: 0.08em;
      font-weight: 600;
    }

    /* ── Routing status row ── */
    .mg-status-row {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      padding-top: 6px;
      border-top: 1px solid var(--border-faint);
    }
    .mg-status-meta {
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--text-secondary);
    }

    /* ── Attack surface indicator ── */
    .mg-paths {
      flex-shrink: 0;
      text-align: center;
      padding: 8px 14px;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      background: var(--bg-elevated);
    }
    .mg-paths.multi {
      border-color: #f59e0b55;
      background: #3d2800;
    }
    .mg-paths-val {
      font-size: 22px;
      font-weight: 700;
      font-family: var(--font-mono);
      line-height: 1;
      margin-bottom: 3px;
      color: var(--text-secondary);
    }
    .mg-paths.multi .mg-paths-val { color: var(--accent-amber); }
    .mg-paths-lbl {
      font-size: 8px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      letter-spacing: 0.08em;
      line-height: 1.4;
    }

    /* ── Routing badge ── */
    .mg-routing-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 10px;
      border-radius: 10px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-mono);
      letter-spacing: 0.03em;
      border: 1px solid transparent;
    }
    .mg-routing-badge.direct-m365  { color: var(--accent-amber);  background: #3d2800; border-color: #f59e0b44; }
    .mg-routing-badge.seg-present  { color: var(--accent-green);  background: #0a3d24; border-color: #00e57a44; }
    .mg-routing-badge.mixed        { color: var(--accent-amber);  background: #3d2800; border-color: #f59e0b44; }
    .mg-routing-badge.unknown      { color: var(--text-secondary); background: var(--bg-elevated); border-color: var(--border-subtle); }
    .mg-routing-badge.no-mx        { color: var(--accent-red);    background: #3d0d14; border-color: #ff3d5a44; }

    /* ── Severity distribution in findings header ── */
    .mg-sev-dist {
      display: flex;
      gap: 10px;
      font-size: 11px;
      font-family: var(--font-mono);
    }
    .mg-sev-dist .sev-critical { color: var(--sev-critical); }
    .mg-sev-dist .sev-high     { color: var(--sev-high); }
    .mg-sev-dist .sev-medium   { color: var(--sev-medium); }
    .mg-sev-dist .sev-low      { color: var(--sev-low); }
    .mg-sev-dist .sev-info     { color: var(--sev-info); }

    /* ── Severity group separator ── */
    .mg-sev-sep {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 5px 4px;
    }
    .mg-sev-sep-line {
      height: 1px;
      opacity: 0.4;
    }
    .mg-sev-sep-lbl {
      font-size: 9px;
      font-family: var(--font-mono);
      font-weight: 700;
      letter-spacing: 0.1em;
      white-space: nowrap;
    }
    .mg-sev-sep-fill { flex: 1; height: 1px; opacity: 0.12; }

    /* ── Finding row ── */
    .mg-finding { border-bottom: 1px solid var(--border-faint); }
    .mg-finding:last-child { border-bottom: none; }
    .mg-finding-hd {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 9px 4px;
      border-radius: var(--radius-sm);
      cursor: pointer;
      transition: background 0.1s;
    }
    .mg-finding-hd:hover { background: var(--bg-elevated); }
    .mg-finding-hd.no-expand { cursor: default; }
    .mg-finding-hd.no-expand:hover { background: transparent; }
    .mg-finding-title {
      flex: 1;
      font-size: 12px;
      color: var(--text-primary);
      font-weight: 500;
    }
    .mg-finding-chev {
      font-size: 10px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      transition: transform 0.2s;
      flex-shrink: 0;
    }
    .mg-finding-chev.open { transform: rotate(180deg); }
    .mg-finding-body {
      padding: 2px 4px 12px;
    }
    .mg-finding-section-lbl {
      font-size: 9px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      letter-spacing: 0.08em;
      margin-bottom: 5px;
    }
    .mg-finding-desc {
      margin: 0 0 10px;
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.65;
    }
    .mg-fix-panel {
      margin-top: 10px;
      padding: 8px 12px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-left: 3px solid var(--accent-amber);
      border-radius: var(--radius-sm);
    }
    .mg-fix-lbl {
      font-size: 9px;
      font-family: var(--font-mono);
      color: var(--accent-amber);
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }
    .mg-fix-text {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.65;
    }

    /* ── Severity badge ── */
    .mg-badge {
      display: inline-flex;
      align-items: center;
      padding: 1px 7px;
      border-radius: var(--radius-sm);
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.08em;
      font-family: var(--font-mono);
      border: 1px solid transparent;
      white-space: nowrap;
    }
    .mg-badge.sev-critical { background: var(--sev-bg-critical); color: var(--sev-critical); border-color: #ff3d5a22; }
    .mg-badge.sev-high     { background: var(--sev-bg-high);     color: var(--sev-high);     border-color: #ff6b2b22; }
    .mg-badge.sev-medium   { background: var(--sev-bg-medium);   color: var(--sev-medium);   border-color: #f59e0b22; }
    .mg-badge.sev-low      { background: var(--sev-bg-low);      color: var(--sev-low);      border-color: #00d4ff22; }
    .mg-badge.sev-info     { background: var(--sev-bg-info);     color: var(--sev-info);     border-color: #64748b22; }

    /* ── Evidence table ── */
    .mg-tbl-wrap {
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
      background: var(--bg-inset);
    }
    .mg-tbl {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-mono);
    }
    .mg-tbl th {
      text-align: left;
      padding: 7px 10px;
      font-size: 9px;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-subtle);
      font-weight: 700;
    }
    .mg-tbl td {
      padding: 8px 10px;
      font-size: 11px;
      border-bottom: 1px solid var(--border-faint);
      vertical-align: middle;
    }
    .mg-tbl tr:last-child td { border-bottom: none; }
    .mg-tbl tr.err { background: #200508; }
    .mg-tbl tr.alt { background: var(--bg-elevated); }
    .mg-host-broken { color: var(--accent-red); }
    .mg-host-ok     { color: var(--text-primary); }
    .mg-gslb {
      margin-left: 7px;
      font-size: 8px;
      color: var(--text-muted);
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 2px;
      padding: 0 4px;
      letter-spacing: 0.05em;
    }
    .mg-resolve-ok  { color: var(--status-success); font-size: 13px; }
    .mg-resolve-err { color: var(--accent-red); font-size: 11px; }
    .mg-resolve-err-detail { font-weight: 400; color: #ff3d5acc; }

    /* Path role badges */
    .mg-role {
      display: inline-block;
      font-size: 9px;
      font-weight: 700;
      font-family: var(--font-mono);
      padding: 1px 7px;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
    }
    .mg-role.primary   { color: var(--status-success); background: #0a3d2433; border-color: #00e57a22; }
    .mg-role.secondary { color: var(--text-secondary); background: var(--bg-elevated); border-color: var(--border-subtle); }
    .mg-role.broken    { color: var(--accent-red);     background: #3d0d1433; border-color: #ff3d5a22; }
    .mg-role.direct    { color: var(--accent-amber);   background: #3d280033; border-color: #f59e0b22; }
    .mg-role.protected { color: var(--accent-cyan);    background: #0e3a4f33; border-color: #00d4ff22; }

    /* Provider badge */
    .mg-provider {
      display: inline-block;
      font-size: 10px;
      font-weight: 600;
      padding: 1px 7px;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
    }

    /* ── Scan details ── */
    .mg-scan-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-faint);
      border-radius: var(--radius-lg);
      overflow: hidden;
      margin-bottom: 14px;
    }
    .mg-scan-toggle {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 11px 16px;
      background: none;
      border: none;
      cursor: pointer;
      text-align: left;
      color: var(--text-primary);
      font-family: var(--font-ui);
    }
    .mg-scan-toggle:hover { background: var(--bg-elevated); }
    .mg-scan-toggle-title {
      flex: 1;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.07em;
    }
    .mg-scan-body {
      padding: 0 16px 14px;
      border-top: 1px solid var(--border-faint);
    }
    .mg-scan-ts {
      font-size: 10px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      margin: 10px 0 10px;
    }
    .mg-meta-grid {
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .mg-meta-key {
      font-size: 8px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      letter-spacing: 0.08em;
      margin-bottom: 2px;
    }
    .mg-meta-val {
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--text-secondary);
    }
    .mg-raw-btn {
      background: none;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.06em;
      padding: 5px 12px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 7px;
    }
    .mg-raw-btn:hover { background: var(--bg-elevated); }
    .mg-raw-pre {
      margin-top: 8px;
      background: var(--bg-inset);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 12px 14px;
      font-size: 10px;
      font-family: var(--font-mono);
      color: var(--text-code);
      overflow: auto;
      line-height: 1.55;
      max-height: 360px;
    }

    /* ── Loading/error ── */
    .mg-loading {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text-secondary);
      font-size: 13px;
      font-family: var(--font-mono);
    }
    .mg-loading-cursor {
      color: var(--accent-amber);
      animation: mg-pulse 1.2s infinite;
    }
    .mg-error {
      padding: 12px 16px;
      background: #200508;
      border: 1px solid #3d0d14;
      border-radius: var(--radius-md);
      color: var(--accent-red);
      font-size: 12px;
      font-family: var(--font-mono);
      max-width: 640px;
    }
    .mg-error-pfx { opacity: 0.6; }

    /* ── Divider ── */
    .mg-divider-v {
      width: 1px;
      background: var(--border-faint);
      align-self: stretch;
      flex-shrink: 0;
    }

    /* ── Animations ── */
    @keyframes mg-pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.15; }
    }

    input::placeholder { color: var(--text-muted); }
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: var(--bg-primary); }
    ::-webkit-scrollbar-thumb { background: var(--border-active); border-radius: 3px; }
  `;
  document.head.appendChild(s);
}

// ---------------------------------------------------------------------------
// Routing config for badge
// ---------------------------------------------------------------------------

const ROUTING_CFG: Record<string, { cls: string; icon: string; label: string }> = {
  direct_m365: { cls: "direct-m365", icon: "⚠", label: "Direct to M365 — No SEG" },
  seg_present: { cls: "seg-present",  icon: "✓", label: "Healthy — Mail Routed via SEG" },
  mixed:       { cls: "mixed",        icon: "⚡", label: "Mixed Routing — Bypass Risk" },
  unknown:     { cls: "unknown",      icon: "?", label: "Unknown — Provider Unclassified" },
  no_mx:       { cls: "no-mx",        icon: "✗", label: "No MX Records" },
};

function RoutingBadge({ routing }: { routing: string }) {
  const cfg = ROUTING_CFG[routing] ?? ROUTING_CFG.unknown;
  return (
    <span className={`mg-routing-badge ${cfg.cls}`}>
      <span>{cfg.icon}</span>
      {cfg.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Score arc gauge
// ---------------------------------------------------------------------------

function ScoreGauge({ score, color }: { score: number; color: string }) {
  // Semi-circle gauge: left (270° → 0°=top,CW) through top to right (450°=90°)
  // viewBox 0 0 120 72, center (60,60), radius 46, stroke 10
  const CX = 60, CY = 60, R = 46, SW = 10;

  const polar = (deg: number) => {
    const r = (deg - 90) * Math.PI / 180;
    return { x: +(CX + R * Math.cos(r)).toFixed(2), y: +(CY + R * Math.sin(r)).toFixed(2) };
  };

  const arc = (startDeg: number, sweepDeg: number): string => {
    if (sweepDeg <= 0) return "";
    const s  = polar(startDeg);
    const e  = polar(startDeg + Math.min(sweepDeg, 179.99));
    const lg = sweepDeg >= 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${R} ${R} 0 ${lg} 1 ${e.x} ${e.y}`;
  };

  const fillSweep = (score / 100) * 180;

  return (
    <svg viewBox="0 0 120 72" width="100%" style={{ display: "block", maxWidth: 112 }}>
      {/* Track */}
      <path d={arc(270, 179.99)} fill="none"
            stroke="#162032" strokeWidth={SW} strokeLinecap="round" />
      {/* Fill */}
      {fillSweep > 1 && (
        <path d={arc(270, fillSweep)} fill="none"
              stroke={color} strokeWidth={SW} strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 5px ${color}55)` }} />
      )}
      {/* Score numeral */}
      <text x={CX} y={52} textAnchor="middle"
            fontSize={28} fontWeight={700}
            fontFamily="'JetBrains Mono', monospace"
            fill={color}>{score}</text>
      {/* /100 */}
      <text x={CX} y={67} textAnchor="middle"
            fontSize={9} fontFamily="'JetBrains Mono', monospace"
            fill="#3d5068" letterSpacing={0.5}>HEALTH SCORE</text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Posture overview
// ---------------------------------------------------------------------------

function PostureOverview({
  evidence, findings,
}: {
  evidence: MXEvidence;
  findings: MXScanResult["findings"];
}) {
  const healthScore = evidence.health_score ?? 0;
  const healthColor = healthScore >= 70 ? colors.green
                    : healthScore >= 40 ? colors.amber
                    : colors.red;

  const deductions = evidence.health_deductions ?? [];
  const deductionLine = deductions
    .map(d => d.replace(/\s*\(-\d+\)$/, ""))
    .join(" · ");

  // Metrics — correction #1: no "passing", use Critical/Warnings/Informational/Total
  const criticalCount = findings.filter(f => f.severity === "critical" || f.severity === "high").length;
  const warningCount  = findings.filter(f => f.severity === "medium").length;
  const infoCount     = findings.filter(f => f.severity === "info" || f.severity === "low").length;
  const totalCount    = findings.length;

  const metrics: Array<{ label: string; value: number; color: string }> = [
    { label: "CRITICAL",      value: criticalCount, color: criticalCount > 0 ? colors.red   : colors.textMuted },
    { label: "WARNINGS",      value: warningCount,  color: warningCount  > 0 ? colors.amber : colors.textMuted },
    { label: "INFORMATIONAL", value: infoCount,      color: colors.textSecondary },
    { label: "TOTAL",         value: totalCount,     color: colors.textPrimary },
  ];

  // Attack surface: distinct inbound paths
  const allRecords = evidence.mx_records ?? [];
  const inboundPaths = evidence.routing_type === "no_mx" ? 0
    : evidence.routing_type === "direct_m365" ? 1
    : Math.max(1, allRecords.length);

  return (
    <div className="mg-card">
      <div className="mg-sh">
        <span className="mg-sh-bar" style={{ backgroundColor: healthColor }} />
        <h2 className="mg-sh-title">MX ROUTING HEALTH</h2>
      </div>

      <div className="mg-posture">
        {/* Gauge column */}
        <div className="mg-posture-gauge">
          <ScoreGauge score={healthScore} color={healthColor} />
          {deductionLine && (
            <div className="mg-deductions">
              <span>Deductions: </span>{deductionLine}
            </div>
          )}
        </div>

        <div className="mg-divider-v" />

        {/* Right column: metrics + status */}
        <div className="mg-posture-right">
          {/* Metrics grid */}
          <div className="mg-metrics-grid">
            {metrics.map(m => (
              <div key={m.label} className="mg-metric"
                   style={{ borderLeftColor: m.color }}>
                <div className="mg-metric-val" style={{ color: m.color }}>
                  {m.value}
                </div>
                <div className="mg-metric-lbl">{m.label}</div>
              </div>
            ))}
          </div>

          {/* Routing status row */}
          <div className="mg-status-row">
            <RoutingBadge routing={evidence.routing_type} />
            <span className="mg-status-meta">
              {evidence.providers?.join(", ") || "—"}
              {" · "}
              {allRecords.length} MX record{allRecords.length !== 1 ? "s" : ""}
            </span>
          </div>
        </div>

        {/* Attack surface indicator */}
        {inboundPaths > 0 && (
          <div className={`mg-paths${inboundPaths > 1 ? " multi" : ""}`}>
            <div className="mg-paths-val">{inboundPaths}</div>
            <div className="mg-paths-lbl">INBOUND<br/>PATHS</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Findings — compact expandable list (correction #2: not a data table)
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_GROUP_LABEL: Record<string, string> = {
  critical: "CRITICAL RISK",
  high:     "HIGH RISK",
  medium:   "MEDIUM RISK",
  low:      "LOW RISK",
  info:     "INFORMATIONAL",
};

function SevBadge({ severity }: { severity: string }) {
  return (
    <span className={`mg-badge sev-${severity}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function FindingRow({ finding }: { finding: MXScanResult["findings"][number] }) {
  const [open, setOpen] = useState(false);
  const recommendedAction = (finding as any).recommended_action as string | undefined;
  const hasContent = !!(finding.description || recommendedAction);

  return (
    <div className="mg-finding">
      <div
        className={`mg-finding-hd${hasContent ? "" : " no-expand"}`}
        onClick={() => hasContent && setOpen(o => !o)}
        role={hasContent ? "button" : undefined}
      >
        <SevBadge severity={finding.severity} />
        <span className="mg-finding-title">{finding.title}</span>
        {hasContent && (
          <span className={`mg-finding-chev${open ? " open" : ""}`}>▼</span>
        )}
      </div>

      {open && hasContent && (
        <div className="mg-finding-body">
          {finding.description && (
            <>
              <div className="mg-finding-section-lbl">EXPLANATION</div>
              <p className="mg-finding-desc">{finding.description}</p>
            </>
          )}
          {recommendedAction && (
            <div className="mg-fix-panel">
              <div className="mg-fix-lbl">RECOMMENDED FIX</div>
              <div className="mg-fix-text">{recommendedAction}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FindingsSection({ findings }: { findings: MXScanResult["findings"] }) {
  if (!findings.length) {
    return <p style={{ color: colors.textMuted, fontSize: 13, margin: 0 }}>No findings returned.</p>;
  }

  const groups: Array<{ sev: string; items: typeof findings }> = [];
  const seen = new Set<string>();
  SEVERITY_ORDER.forEach(sev => {
    const items = findings.filter(f => f.severity === sev);
    if (items.length) { groups.push({ sev, items }); seen.add(sev); }
  });
  findings.forEach(f => {
    if (!seen.has(f.severity)) {
      groups.push({ sev: f.severity, items: findings.filter(x => x.severity === f.severity) });
      seen.add(f.severity);
    }
  });

  // Color for group separator line
  const sevLineColor: Record<string, string> = {
    critical: colors.red, high: colors.red, medium: colors.amber,
    low: colors.cyan, info: colors.textMuted,
  };

  return (
    <>
      {groups.map(({ sev, items }, gi) => (
        <div key={sev} style={{ marginTop: gi === 0 ? 0 : 10 }}>
          <div className="mg-sev-sep">
            <div className="mg-sev-sep-line"
                 style={{ width: 18, backgroundColor: sevLineColor[sev] ?? colors.borderSubtle }} />
            <span className="mg-sev-sep-lbl"
                  style={{ color: sevLineColor[sev] ?? colors.textMuted }}>
              {SEV_GROUP_LABEL[sev] ?? sev.toUpperCase()}
            </span>
            <div className="mg-sev-sep-fill"
                 style={{ backgroundColor: sevLineColor[sev] ?? colors.borderSubtle }} />
          </div>
          {items.map(f => <FindingRow key={f.id} finding={f} />)}
        </div>
      ))}
    </>
  );
}

// ---------------------------------------------------------------------------
// Evidence table — conservative path roles (correction #5)
// ---------------------------------------------------------------------------

const SEG_PROVIDERS_ROLE = new Set([
  "Proofpoint", "Mimecast", "Symantec/Broadcom",
  "Barracuda", "Sophos", "Hornetsecurity", "SpamHero",
]);

const PROVIDER_COLORS: Record<string, string> = {
  "Microsoft EOP": colors.cyan,
  "Proofpoint":    colors.amber,
  "Mimecast":      "#a78bfa",
  "Symantec/Broadcom": "#fb923c",
  "Barracuda":     "#34d399",
  "Unknown":       colors.textSecondary,
};

function computePathRole(
  record: EnrichedMXRecord,
  index: number,
  allRecords: EnrichedMXRecord[],
): { role: string; cls: string } {
  if (!record.resolved) return { role: "Broken", cls: "broken" };

  const isEOP = record.provider === "Microsoft EOP";

  // Primary = first record (lowest priority number)
  if (index === 0) return { role: "Primary", cls: "primary" };

  if (isEOP) {
    // Protected = a resolved SEG provider appears before this EOP record
    const hasSEGBefore = allRecords
      .slice(0, index)
      .some(r => r.resolved && SEG_PROVIDERS_ROLE.has(r.provider));
    return hasSEGBefore
      ? { role: "Protected", cls: "protected" }
      : { role: "Direct",    cls: "direct"    };
  }

  return { role: "Secondary", cls: "secondary" };
}

function EvidenceTable({ records }: { records: EnrichedMXRecord[] }) {
  if (!records.length) return null;
  return (
    <div className="mg-tbl-wrap">
      <table className="mg-tbl">
        <thead>
          <tr>
            {["PRI", "HOST", "PROVIDER", "RESOLVES", "PATH ROLE"].map(h => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => {
            const isError  = !r.resolved;
            const role     = computePathRole(r, i, records);
            const pColor   = PROVIDER_COLORS[r.provider] ?? colors.textSecondary;
            const rowClass = isError ? "err" : i % 2 !== 0 ? "alt" : "";
            return (
              <tr key={i} className={rowClass}>
                <td style={{ color: colors.textMuted, width: 40 }}>{r.priority}</td>
                <td className={isError ? "mg-host-broken" : "mg-host-ok"}
                    style={{ wordBreak: "break-all" }}>
                  {r.host}
                  {r.multi_ip && <span className="mg-gslb">GSLB</span>}
                </td>
                <td style={{ width: 140 }}>
                  <span className="mg-provider"
                        style={{ color: pColor, backgroundColor: pColor + "1a", borderColor: pColor + "33" }}>
                    {r.provider}
                  </span>
                </td>
                <td style={{ width: 70, textAlign: "center" }}>
                  {isError ? (
                    <span className="mg-resolve-err">
                      ✗ <span className="mg-resolve-err-detail">{r.resolve_error ?? "No A/AAAA"}</span>
                    </span>
                  ) : (
                    <span className="mg-resolve-ok">✓</span>
                  )}
                </td>
                <td style={{ width: 110 }}>
                  <span className={`mg-role ${role.cls}`}>{role.role}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan details — collapsed by default
// ---------------------------------------------------------------------------

function ScanDetails({ evidence, timestamp }: { evidence: MXEvidence; timestamp: string }) {
  const [open,    setOpen]    = useState(false);
  const [rawOpen, setRawOpen] = useState(false);
  const meta = evidence.scan_metadata;

  const fmt = (ts: string) => {
    try { return new Date(ts).toISOString().replace("T", " ").slice(0, 16) + " UTC"; }
    catch { return ts; }
  };

  return (
    <div className="mg-scan-card">
      <button className="mg-scan-toggle" onClick={() => setOpen(o => !o)}>
        <span className="mg-sh-bar" style={{ backgroundColor: colors.borderSubtle }} />
        <span className="mg-scan-toggle-title">SCAN DETAILS</span>
        <span className={`mg-finding-chev${open ? " open" : ""}`}>▼</span>
      </button>

      {open && (
        <div className="mg-scan-body">
          <div className="mg-scan-ts">Last scan: {fmt(timestamp)}</div>
          {meta && (
            <div className="mg-meta-grid">
              {Object.entries(meta).map(([k, v]) => (
                <div key={k}>
                  <div className="mg-meta-key">{k.replace(/_/g, " ").toUpperCase()}</div>
                  <div className="mg-meta-val">{String(v)}</div>
                </div>
              ))}
            </div>
          )}
          <button className="mg-raw-btn" onClick={() => setRawOpen(o => !o)}>
            <span className={`mg-finding-chev${rawOpen ? " open" : ""}`} style={{ fontSize: 9 }}>▼</span>
            {rawOpen ? "HIDE RAW SCAN DATA" : "SHOW RAW SCAN DATA"}
          </button>
          {rawOpen && (
            <pre className="mg-raw-pre">{JSON.stringify(evidence, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function MXAnalysisPage() {
  const [domain,         setDomain]         = useState("");
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [page,           setPage]           = useState<PageState>({ status: "idle" });

  useEffect(() => {
    injectFonts();
    injectPageStyles();
  }, []);

  const handleScan = async () => {
    const trimmed = domain.trim().toLowerCase();
    if (!trimmed) return;
    setPage({ status: "loading" });
    try {
      const result   = await apiClient.getMXExposure(trimmed);
      const evidence = result.evidence as unknown as MXEvidence;
      setPage({ status: "success", result, evidence });
    } catch (err: unknown) {
      setPage({ status: "error", message: err instanceof Error ? err.message : "Unknown error" });
    }
  };

  return (
    <div className="mg-page">

      {/* Page header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{
          fontSize: 10, fontFamily: fonts.mono, color: colors.amber,
          letterSpacing: "0.12em", marginBottom: 6, opacity: 0.75,
        }}>
          EMAIL SECURITY / MX ROUTING
        </div>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 600, color: colors.textPrimary }}>
          MX Routing Health
        </h1>
        <p style={{ margin: "6px 0 0", color: colors.textSecondary, fontSize: 13 }}>
          Assess MX routing health and identify potential bypass paths.
        </p>
      </div>

      {/* Domain selector */}
      <DomainSelector
        tenantList={MOCK_TENANTS}
        selectedTenant={selectedTenant}
        domain={domain}
        onTenantChange={setSelectedTenant}
        onDomainChange={setDomain}
        onScan={handleScan}
        loading={page.status === "loading"}
        accentColor={colors.amber}
      />

      {/* Loading */}
      {page.status === "loading" && (
        <div className="mg-loading">
          <span className="mg-loading-cursor">▋</span>
          Resolving MX records…
        </div>
      )}

      {/* Error */}
      {page.status === "error" && (
        <div className="mg-error">
          <span className="mg-error-pfx">ERROR: </span>{page.message}
        </div>
      )}

      {/* Results */}
      {page.status === "success" && (
        <div className="mg-results">

          {/* ① Posture overview */}
          <PostureOverview
            evidence={page.evidence}
            findings={page.result.findings}
          />

          {/* ② Findings — compact expandable list */}
          <div className="mg-card">
            <div className="mg-sh">
              <span className="mg-sh-bar" style={{ backgroundColor: colors.red }} />
              <h3 className="mg-sh-title">FINDINGS</h3>
              {/* Severity distribution — compact, right-aligned */}
              {page.result.findings.length > 0 && (() => {
                const counts: Record<string, number> = {};
                page.result.findings.forEach(f => {
                  counts[f.severity] = (counts[f.severity] ?? 0) + 1;
                });
                return (
                  <div className="mg-sev-dist mg-sh-right">
                    {SEVERITY_ORDER.filter(s => counts[s]).map(s => (
                      <span key={s} className={`sev-${s}`}>
                        {counts[s]}&nbsp;{s.charAt(0).toUpperCase() + s.slice(1)}
                      </span>
                    ))}
                  </div>
                );
              })()}
            </div>
            <FindingsSection findings={page.result.findings} />
          </div>

          {/* ③ Mail routing map */}
          <RoutingTopology
            records={page.evidence.mx_records ?? []}
            routingType={page.evidence.routing_type}
          />

          {/* ④ Evidence — MX records table */}
          {page.evidence.mx_records?.length > 0 && (
            <div className="mg-card">
              <div className="mg-sh">
                <span className="mg-sh-bar" style={{ backgroundColor: colors.cyan }} />
                <h3 className="mg-sh-title">EVIDENCE</h3>
              </div>
              <EvidenceTable records={page.evidence.mx_records} />
            </div>
          )}

          {/* ⑤ Scan details — collapsed */}
          <ScanDetails
            evidence={page.evidence}
            timestamp={page.result.timestamp}
          />

        </div>
      )}

    </div>
  );
}
