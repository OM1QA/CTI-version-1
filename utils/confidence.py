"""Confidence scoring utilities"""

# Source confidence scoring (0.0 - 1.0)
SOURCE_CONFIDENCE = {
    "CISA KEV": 0.95,
    "CISA Advisories": 0.95,
    "NVD": 0.90,
    "OTX": 0.75,
    "Abuse.ch ThreatFox": 0.85,
    "Abuse.ch URLhaus": 0.85,
    "CISA Alerts": 0.95,
    "UK NCSC News": 0.92,
    "ENISA News": 0.90,
    "The Hacker News": 0.70,
    "BleepingComputer": 0.75,
    "Cisco Talos": 0.85,
    "Microsoft Security Blog": 0.85,
    "Palo Alto Unit 42": 0.85
}

def calculate_confidence_score(source, base_confidence=None, days_old=0, corroboration_count=0):
    """Calculate overall confidence score based on source, age, and corroboration"""
    if base_confidence is None:
        base_confidence = SOURCE_CONFIDENCE.get(source, 0.70)
    
    # Age factor: newer data gets higher confidence
    if days_old <= 1:
        age_factor = 1.0
    elif days_old <= 7:
        age_factor = 0.95
    elif days_old <= 30:
        age_factor = 0.90
    elif days_old <= 90:
        age_factor = 0.85
    else:
        age_factor = 0.80
    
    # Corroboration factor: multiple sources increase confidence
    corroboration_factor = min(1.0 + (corroboration_count * 0.05), 1.20)
    
    final_confidence = base_confidence * age_factor * corroboration_factor
    return min(final_confidence, 1.0)

def get_severity_color(severity):
    """Get color code for severity levels"""
    colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
    }
    return colors.get(severity, '#6c757d')
