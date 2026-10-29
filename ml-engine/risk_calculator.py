"""
Risk Calculator Engine for computing 0-100 Risk Scores and Risk Tiers.
"""

from typing import Dict, Any, Tuple

def compute_security_penalty(sample: Dict[str, Any]) -> float:
    """Calculates security penalty score (0-100) based on critical security event counters."""
    auth_mac_fail = sample.get('authMacFailures', 0)
    auth_sqn_fail = sample.get('authSqnFailures', 0)
    intrusions = sample.get('intrusionEvents', 0)
    rate_limits = sample.get('rateLimitEvents', 0)
    unknown_gnb = sample.get('unknownGnbEvents', 0)
    blocked_ips = sample.get('blockedIpCount', 0)

    score = 0.0
    score += min(50.0, auth_mac_fail * 25.0)
    score += min(30.0, auth_sqn_fail * 15.0)
    score += min(40.0, intrusions * 20.0)
    score += min(30.0, unknown_gnb * 15.0)
    score += min(20.0, rate_limits * 5.0)
    score += min(20.0, blocked_ips * 10.0)

    return min(100.0, score)

def compute_qos_penalty(sample: Dict[str, Any]) -> float:
    """Calculates QoS/System load penalty score (0-100)."""
    loss_rate = sample.get('packetLossRate', 0.0)
    ul_drop = sample.get('ulDropped', 0)
    dl_drop = sample.get('dlDropped', 0)
    nf_load = sample.get('nfLoadLevel', 0)  # 0=low, 1=medium, 2=high
    qos_status = sample.get('qosStatus', 0)  # 0=sustainable, 1=at_risk, 2=degraded

    score = 0.0
    score += min(40.0, loss_rate * 100.0)
    score += min(30.0, (ul_drop + dl_drop) * 2.0)
    score += nf_load * 15.0
    score += qos_status * 20.0

    return min(100.0, score)

def calculate_risk_score(
    macro_anomaly_prob: float,
    macro_attack_category: str,
    micro_anomaly_prob: float,
    sample_data: Dict[str, Any]
) -> Tuple[float, str, str]:
    """
    Computes a continuous Risk Score (0 - 100), Risk Tier, and Recommended Policy Action.
    
    Returns:
        (risk_score, risk_tier, policy_action)
    """
    # ML Anomaly Score (0-100)
    ml_score = max(macro_anomaly_prob, micro_anomaly_prob) * 100.0

    # Security Event Penalty (0-100)
    sec_penalty = compute_security_penalty(sample_data)

    # QoS & Load Penalty (0-100)
    qos_penalty = compute_qos_penalty(sample_data)

    # Weighted Base Score
    raw_risk = (0.50 * ml_score) + (0.35 * sec_penalty) + (0.15 * qos_penalty)

    # Critical Overrule Protection
    if macro_anomaly_prob >= 0.85 or micro_anomaly_prob >= 0.85 or sec_penalty >= 50.0 or macro_attack_category == 'AUTH_MAC_FAILURE':
        risk_score = max(raw_risk, 90.0)
    else:
        risk_score = raw_risk

    risk_score = round(min(100.0, max(0.0, risk_score)), 2)

    # Assign Risk Tier and Policy Action
    if risk_score < 30.0:
        tier = "LOW"
        policy = "ROUTINE_MONITORING"
    elif risk_score < 60.0:
        tier = "MEDIUM"
        policy = "ENHANCED_SURVEILLANCE"
    elif risk_score < 85.0:
        tier = "HIGH"
        policy = "THROTTLING_AND_RATE_LIMIT"
    else:
        tier = "CRITICAL"
        policy = "EMERGENCY_SLICE_ISOLATION_AND_BLOCK"

    return risk_score, tier, policy
