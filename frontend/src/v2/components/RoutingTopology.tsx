// RoutingTopology.tsx — MailGuard V2
//
// Compact 3-column orthogonal topology widget.
// Reusable for: MX routing, SEG bypass detection, multi-provider analysis.
//
// Layout (left → right):
//   Col 1  INTERNET source node
//   Col 2  MX endpoint nodes   (one per record, stacked)
//   Col 3  EXCHANGE ONLINE     (only when ≥1 record resolves)
//
// Connectors (orthogonal only — no curves):
//   Internet → vertical trunk → colored horizontal branch → MX node
//   Resolved MX → L-path (or straight) → Exchange Online
//   Broken MX  → terminates (no right-side connector)
//
// Responsive: SVG uses viewBox internal coordinates rendered at width="100%".
// Wrapper maxWidth caps natural size so height never exceeds ~120px.

import React from "react";
import { colors, fonts, cardStyle } from "../theme";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type TopologyRecord = {
  priority:      number;
  host:          string;
  provider:      string;
  resolved:      boolean;
  multi_ip?:     boolean;
  resolve_error: string | null;
};

export interface RoutingTopologyProps {
  records:     TopologyRecord[];
  routingType: string;
}

// ---------------------------------------------------------------------------
// Path classification
// ---------------------------------------------------------------------------

type PathClass = "healthy_seg" | "direct_eop" | "broken";

const SEG_PROVIDERS = new Set([
  "Proofpoint", "Mimecast", "Symantec/Broadcom",
  "Barracuda", "Sophos", "Hornetsecurity", "SpamHero",
]);

function classify(r: TopologyRecord, routingType: string): PathClass {
  if (!r.resolved)                    return "broken";
  if (r.provider === "Microsoft EOP") return routingType === "seg_present" ? "healthy_seg" : "direct_eop";
  if (SEG_PROVIDERS.has(r.provider))  return "healthy_seg";
  return "direct_eop";
}

const CLS_COLOR: Record<PathClass, string> = {
  healthy_seg: colors.green,
  direct_eop:  colors.amber,
  broken:      colors.red,
};

// ---------------------------------------------------------------------------
// SVG layout constants (internal coordinate system)
// ---------------------------------------------------------------------------

const N_W    = 130;  // node width
const N_H    = 38;   // node height
const N_GAP  = 12;   // vertical gap between MX nodes
const PAD_V  = 14;   // top/bottom SVG padding
const PAD_L  = 10;   // left SVG padding

const COL1_X  = PAD_L;              // Internet node left  = 10
const TRUNK_X = COL1_X + N_W + 28;  // trunk line X        = 168
const COL2_X  = TRUNK_X + 22;       // MX node left        = 190
const CONV_X  = COL2_X + N_W + 26;  // convergence X       = 346
const COL3_X  = CONV_X + 20;        // Exchange Online left = 366
const SVG_W   = COL3_X + N_W + PAD_L; // total viewport W  = 506

// ---------------------------------------------------------------------------
// SVG helpers
// ---------------------------------------------------------------------------

const mid = (s: string) => `arr-${s.replace(/[^a-zA-Z0-9]/g, "")}`;

function NodeBox(
  x: number, y: number,
  title: string, sub: string,
  stroke: string, bg: string,
  dashed = false,
): JSX.Element {
  return (
    <g>
      <rect
        x={x} y={y} width={N_W} height={N_H} rx={4}
        fill={bg} stroke={stroke} strokeWidth={1.5}
        strokeDasharray={dashed ? "5 3" : undefined}
      />
      <text
        x={x + N_W / 2} y={y + 15}
        textAnchor="middle" fontFamily="monospace"
        fontSize={10} fontWeight={700} fill={stroke} letterSpacing={0.5}
      >{title}</text>
      {sub && (
        <text
          x={x + N_W / 2} y={y + 29}
          textAnchor="middle" fontFamily="monospace"
          fontSize={9} fill={stroke} opacity={0.6}
        >{sub}</text>
      )}
    </g>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RoutingTopology({ records, routingType }: RoutingTopologyProps) {
  if (!records.length) return null;

  const sorted = [...records].sort((a, b) => a.priority - b.priority);
  const n = sorted.length;

  const nodes = sorted.map(r => {
    const cls   = classify(r, routingType);
    const color = CLS_COLOR[cls];
    const label = r.provider === "Microsoft EOP"
      ? "Microsoft 365 MX"
      : (`${r.provider} MX`).length > 20
        ? `${r.provider.slice(0, 16)}\u2026 MX`
        : `${r.provider} MX`;
    const sub = cls === "broken"
      ? (r.resolve_error?.includes("NXDOMAIN") ? "NXDOMAIN" : "Unresolvable")
      : cls === "healthy_seg"
        ? "Protected route"
        : "Direct path";
    return { r, cls, color, label, sub };
  });

  // Vertical geometry
  const totalMXH = n * N_H + (n - 1) * N_GAP;
  const svgH     = totalMXH + 2 * PAD_V;
  const mxY      = (i: number) => PAD_V + i * (N_H + N_GAP);
  const mxCY     = (i: number) => mxY(i) + N_H / 2;
  const inetCY   = PAD_V + totalMXH / 2;
  const inetY    = inetCY - N_H / 2;

  // Exchange Online: centered on resolved nodes
  const resolvedIdx = nodes.map((nd, i) => nd.r.resolved ? i : -1).filter(i => i >= 0);
  const hasEOP = resolvedIdx.length > 0;
  const eopCY  = hasEOP
    ? resolvedIdx.reduce((s, i) => s + mxCY(i), 0) / resolvedIdx.length
    : inetCY;
  const eopY = eopCY - N_H / 2;

  // Arrowhead marker IDs per unique color
  const arrowColors = [...new Set([
    ...nodes.map(nd => nd.color),
    ...(hasEOP ? [colors.green, colors.amber] : []),
  ])];

  const configuredCount = sorted.length;
  const activeCount     = resolvedIdx.length;

  return (
    <div style={{ ...cardStyle, padding: "12px 16px", marginBottom: 16 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <span style={{
          width: 3, height: 16, backgroundColor: colors.cyan,
          borderRadius: 2, display: "inline-block", flexShrink: 0,
        }} />
        <span style={{
          fontSize: 12, fontWeight: 600, letterSpacing: "0.06em",
          color: colors.textPrimary, fontFamily: fonts.ui,
        }}>MAIL ROUTING MAP</span>
        <span style={{ marginLeft: "auto", fontSize: 10, fontFamily: fonts.mono, color: colors.textMuted }}>
          {"Configured: "}
          <span style={{ color: colors.textCode, fontWeight: 600 }}>{configuredCount}</span>
          {"  ·  Active: "}
          <span style={{ color: activeCount > 0 ? colors.green : colors.red, fontWeight: 600 }}>
            {activeCount}
          </span>
        </span>
      </div>

      {/* Topology — responsive: viewBox internal coords, width=100%, capped by maxWidth */}
      <div style={{ width: "100%", maxWidth: SVG_W, overflow: "visible" }}>
        <svg
          viewBox={`0 0 ${SVG_W} ${svgH}`}
          width="100%"
          style={{ display: "block" }}
          aria-label="Mail routing topology diagram"
        >
          <defs>
            {arrowColors.map(c => (
              <marker key={c} id={mid(c)}
                markerWidth="7" markerHeight="5"
                refX="7" refY="2.5" orient="auto">
                <polygon points="0 0, 7 2.5, 0 5" fill={c} opacity={0.85} />
              </marker>
            ))}
          </defs>

          {/* Col 1: Internet */}
          {NodeBox(COL1_X, inetY, "INTERNET", "", colors.textMuted, colors.bgElevated)}

          {/* Internet → MX: trunk + branches (n>1) or direct line (n=1) */}
          {n === 1 ? (
            <line
              x1={COL1_X + N_W} y1={inetCY}
              x2={COL2_X}        y2={mxCY(0)}
              stroke={nodes[0].color} strokeWidth={1.5}
              markerEnd={`url(#${mid(nodes[0].color)})`}
            />
          ) : (
            <>
              {/* Horizontal spur from Internet to trunk */}
              <line
                x1={COL1_X + N_W} y1={inetCY}
                x2={TRUNK_X}       y2={inetCY}
                stroke={colors.borderActive} strokeWidth={1.5} opacity={0.6}
              />
              {/* Vertical trunk spanning all MX nodes */}
              <line
                x1={TRUNK_X} y1={mxCY(0)}
                x2={TRUNK_X} y2={mxCY(n - 1)}
                stroke={colors.borderActive} strokeWidth={1.5} opacity={0.6}
              />
              {/* Colored horizontal branch per MX node */}
              {nodes.map((nd, i) => (
                <line
                  key={`br-${i}`}
                  x1={TRUNK_X} y1={mxCY(i)}
                  x2={COL2_X}  y2={mxCY(i)}
                  stroke={nd.color} strokeWidth={1.5}
                  markerEnd={`url(#${mid(nd.color)})`}
                />
              ))}
            </>
          )}

          {/* Col 2: MX endpoint nodes */}
          {nodes.map((nd, i) => (
            <g key={`mx-${i}`}>
              {NodeBox(
                COL2_X, mxY(i),
                nd.label, nd.sub,
                nd.color, nd.color + "18",
                nd.cls === "broken",
              )}
              {nd.r.multi_ip && (
                <text
                  x={COL2_X + N_W - 4} y={mxY(i) + 11}
                  textAnchor="end" fontSize={8}
                  fontFamily="monospace" fill={colors.textMuted} opacity={0.7}
                >GSLB</text>
              )}
            </g>
          ))}

          {/* Col 3: Exchange Online + connectors from resolved nodes */}
          {hasEOP && (
            <>
              {NodeBox(COL3_X, eopY, "EXCHANGE ONLINE", "", colors.cyan, colors.bgInset)}
              {resolvedIdx.map(i => {
                const x0 = COL2_X + N_W;
                const y0 = mxCY(i);
                const lc = nodes[i].cls === "healthy_seg" ? colors.green : colors.amber;
                // Straight line when Y aligns; orthogonal L-path otherwise
                const d  = Math.abs(y0 - eopCY) < 1
                  ? `M ${x0} ${y0} L ${COL3_X} ${eopCY}`
                  : `M ${x0} ${y0} L ${CONV_X} ${y0} L ${CONV_X} ${eopCY} L ${COL3_X} ${eopCY}`;
                return (
                  <path key={`ec-${i}`}
                    d={d} fill="none"
                    stroke={lc} strokeWidth={1.5} opacity={0.85}
                    markerEnd={`url(#${mid(lc)})`}
                  />
                );
              })}
            </>
          )}
        </svg>
      </div>
    </div>
  );
}
