// theme.ts
//
// MailGuard V2 design system — dark security terminal aesthetic.
// All V2 pages and components should import from here.

export const colors = {
  // Backgrounds
  bgBase:      "#080d16",   // Page background
  bgSurface:   "#0f1724",   // Card / panel background
  bgElevated:  "#162032",   // Slightly elevated surface (table rows, hover)
  bgInset:     "#0a1020",   // Code blocks, evidence panels

  // Borders
  borderFaint:  "#1a2840",
  borderSubtle: "#1e3152",
  borderActive: "#2a4a7f",

  // Text
  textPrimary:   "#e2e8f0",
  textSecondary: "#64748b",
  textMuted:     "#3d5068",
  textCode:      "#94a3b8",

  // Accent — cyan (discoveries, info, links)
  cyan:       "#00d4ff",
  cyanDim:    "#0e3a4f",
  cyanSubtle: "#062030",

  // Accent — green (secure, positive findings)
  green:       "#00e57a",
  greenDim:    "#0a3d24",
  greenSubtle: "#061e14",

  // Accent — amber (warnings, medium severity)
  amber:       "#f59e0b",
  amberDim:    "#3d2800",
  amberSubtle: "#1e1400",

  // Accent — red (critical, high severity)
  red:       "#ff3d5a",
  redDim:    "#3d0d14",
  redSubtle: "#200508",

  // Severity scale
  severityBg: {
    critical: "#3d0d14",
    high:     "#3d1a00",
    medium:   "#3d2800",
    low:      "#0e2a3d",
    info:     "#111827",
  },
  severityText: {
    critical: "#ff3d5a",
    high:     "#ff6b2b",
    medium:   "#f59e0b",
    low:      "#00d4ff",
    info:     "#64748b",
  },
};

export const fonts = {
  ui:   "'DM Sans', 'Segoe UI', sans-serif",
  mono: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
};

export const radius = {
  sm: "4px",
  md: "6px",
  lg: "10px",
};

// Injects Google Fonts — call once at app level or per-page
export function injectFonts() {
  if (document.getElementById("mg-v2-fonts")) return;
  const link = document.createElement("link");
  link.id = "mg-v2-fonts";
  link.rel = "stylesheet";
  link.href =
    "https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap";
  document.head.appendChild(link);
}

// Shared card style
export const cardStyle: React.CSSProperties = {
  backgroundColor: colors.bgSurface,
  border: `1px solid ${colors.borderFaint}`,
  borderRadius: radius.lg,
  padding: "20px 24px",
  marginBottom: 16,
};
