# scan_families.py
#
# Scan family name constants.
# All orchestrator logic and scan modules should reference these
# constants rather than raw strings to prevent naming drift.
POSTURE               = "posture"
PUBLIC_INTEL          = "public_intel"
EXPOSURE              = "exposure"
SIMULATION            = "simulation"
LOOKALIKE             = "lookalike"
AUTHENTICATION        = "authentication"
DNS_POSTURE           = "dns_posture"          # mx_health + authentication_status
MAIL_ROUTING_TOPOLOGY = "mail_routing_topology" # inbound_path_mapping + connector_posture + direct_send_check
TLS_POSTURE           = "tls_posture"           # mta_sts_check + tlsrpt_check + starttls_probe + tls_conflict_analysis + dane_tlsa_check

ALL_FAMILIES = [
    POSTURE, PUBLIC_INTEL, EXPOSURE, SIMULATION, LOOKALIKE, AUTHENTICATION,
    DNS_POSTURE, MAIL_ROUTING_TOPOLOGY, TLS_POSTURE,
]
