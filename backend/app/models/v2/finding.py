# finding.py
#
# Defines a single security finding produced by any scan family.
# All scan family modules must return findings in this format.

from dataclasses import dataclass, field

# Valid severity values. Use these constants — do not use raw strings.
SEVERITIES = ["critical", "high", "medium", "low", "info"]

@dataclass
class Finding:
    id: str
    category: str          # e.g. "posture", "exposure", "lookalike"
    severity: str          # must be one of SEVERITIES
    title: str
    description: str
    evidence: dict = field(default_factory=dict)
    references: list = field(default_factory=list)
    recommended_action: str = ""  # Short operator guidance (1-2 sentences). Empty string = no recommendation.
