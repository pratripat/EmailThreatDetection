from .parser import RelayHop, parse_received_header, extract_ip_candidates
from .domain_utils import (
    DomainRelation,
    domain_relationship,
    normalize_domain,
    registrable_domain,
    load_brand_list,
    HOMOGLYPH_MAP,
)
from .auth_trust import parse_auth_context, check_auth_results
from .anomalies import detect_anomalies, evaluate_brand_impersonation
from .scoring import compute_risk_score, POSITIVE_INDICATORS
from .report import ForensicReport, generate_forensic_summary
