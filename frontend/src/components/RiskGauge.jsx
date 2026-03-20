export default function RiskGauge({ riskScore, riskLevel, centerLabel = riskLevel }) {
  const radius = 60
  const circumference = 2 * Math.PI * radius
  const progress = circumference * (1 - riskScore / 100)

  return (
    <svg width="164" height="164" viewBox="0 0 164 164" aria-hidden>
      <circle cx="82" cy="82" r={radius} fill="none" stroke="rgba(30,45,66,.9)" strokeWidth="12" />
      <circle
        cx="82"
        cy="82"
        r={radius}
        fill="none"
        stroke="var(--red)"
        strokeOpacity="0.9"
        strokeWidth="12"
        strokeDasharray={`${circumference} ${circumference}`}
        strokeDashoffset={progress}
        strokeLinecap="round"
        transform="rotate(-210 82 82)"
      />
      <text x="82" y="76" textAnchor="middle" fill="var(--text)" fontSize="42" fontWeight="700" fontFamily="var(--font-mono)">{riskScore}</text>
      <text x="82" y="98" textAnchor="middle" fill="var(--muted)" fontSize="14" fontWeight="600">{centerLabel}</text>
      <text x="82" y="116" textAnchor="middle" fill="var(--muted-dim)" fontSize="10">/100</text>
    </svg>
  )
}
