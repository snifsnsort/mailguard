with open('backend/app/services/report_generator.py', 'r', encoding='utf-8') as f:
    content = f.read()

start = content.find('# ── Penalty breakdown table')
end = content.find('\n    t = Table(rows, colWidths=[10.5*cm, 2.5*cm, 2*cm])', start) + len('\n    t = Table(rows, colWidths=[10.5*cm, 2.5*cm, 2*cm])')

new_block = (
    '# ── Score breakdown table ─────────────────────────────────────────────────────\n'
    'def _penalty_table(breakdown) -> Table:\n'
    '    if not breakdown:\n'
    '        return Table([["All checks passed."]])\n'
    '    header = ["Check", "Status", "Points"]\n'
    '    rows   = [header]\n'
    '    for b in sorted(breakdown, key=lambda x: -(x.get("max_points", x.get("max_penalty", 0)))):\n'
    '        status  = b.get("status", "").upper()\n'
    '        earned  = b.get("points_earned", 0)\n'
    '        max_pts = b.get("max_points", b.get("max_penalty", 0))\n'
    '        rows.append([\n'
    '            b.get("name", b.get("check_id", "")),\n'
    '            status,\n'
    '            f"{earned}/{max_pts}",\n'
    '        ])\n'
    '    t = Table(rows, colWidths=[10.5*cm, 2.5*cm, 2*cm])'
)

content = content[:start] + new_block + content[end:]
content = content.replace(
    '    deducted = sum(b.get("penalty_applied", 0) for b in penalty_breakdown)',
    '    deducted = sum(b.get("points_earned", 0) for b in penalty_breakdown)\n    total_possible = sum(b.get("max_points", b.get("max_penalty", 0)) for b in penalty_breakdown)'
)
content = content.replace(
    '        ["Points Deducted", f"\u2212{deducted} pts  (of 100)"],',
    '        ["Points Earned", f"{round(deducted)} / {total_possible} pts"],'
)
content = content.replace('<b>Score Penalty Breakdown</b>', '<b>Score Breakdown</b>')

with open('backend/app/services/report_generator.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Done')
