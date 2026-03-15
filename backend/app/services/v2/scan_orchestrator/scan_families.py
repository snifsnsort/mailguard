# scan_families.py
#
# Scan family name constants.
# All orchestrator logic and scan modules should reference these
# constants rather than raw strings to prevent naming drift.
POSTURE         = "posture"
PUBLIC_INTEL    = "public_intel"
EXPOSURE        = "exposure"
SIMULATION      = "simulation"
LOOKALIKE       = "lookalike"
AUTHENTICATION  = "authentication"

ALL_FAMILIES = [POSTURE, PUBLIC_INTEL, EXPOSURE, SIMULATION, LOOKALIKE, AUTHENTICATION]
