"""
Utility functions for the threat intelligence platform
"""
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import hashlib
import re
import logging

logger = logging.getLogger(__name__)

def format_date(date_input) -> str:
    """Format datetime for display"""
    if pd.isna(date_input):
        return "Unknown"
    
    if isinstance(date_input, str):
        try:
            date_input = pd.to_datetime(date_input)
        except:
            return date_input
    
    if isinstance(date_input, datetime):
        return date_input.strftime("%Y-%m-%d")
    
    return str(date_input)

def format_datetime(date_input) -> str:
    """Format datetime with time for display"""
    if pd.isna(date_input):
        return "Unknown"
    
    if isinstance(date_input, str):
        try:
            date_input = pd.to_datetime(date_input)
        except:
            return date_input
    
    if isinstance(date_input, datetime):
        return date_input.strftime("%Y-%m-%d %H:%M:%S")
    
    return str(date_input)

def get_severity_color(severity: str) -> str:
    """Get color code for severity levels"""
    color_map = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745',
        'Info': '#17a2b8'
    }
    return color_map.get(severity, '#6c757d')

def get_risk_color(risk_score: float) -> str:
    """Get color code for risk scores"""
    if risk_score >= 90:
        return '#dc3545'  # Critical - Red
    elif risk_score >= 70:
        return '#fd7e14'  # High - Orange
    elif risk_score >= 40:
        return '#ffc107'  # Medium - Yellow
    else:
        return '#28a745'  # Low - Green

def clean_indicator(indicator: str) -> str:
    """Clean and normalize indicators"""
    if not indicator:
        return ""
    
    # Remove common prefixes/suffixes
    indicator = indicator.strip()
    indicator = re.sub(r'^https?://', '', indicator)
    indicator = re.sub(r'^www\.', '', indicator)
    
    return indicator.lower()

def validate_ip(ip: str) -> bool:
    """Validate if string is a valid IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    """Validate if string is a valid domain"""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(pattern.match(domain)) and len(domain) <= 253

def validate_hash(hash_value: str, hash_type: str = None) -> bool:
    """Validate if string is a valid hash"""
    if not hash_value:
        return False
    
    hash_patterns = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$'
    }
    
    if hash_type and hash_type.lower() in hash_patterns:
        return bool(re.match(hash_patterns[hash_type.lower()], hash_value))
    
    # Check all hash types if not specified
    for pattern in hash_patterns.values():
        if re.match(pattern, hash_value):
            return True
    
    return False

def deduplicate_indicators(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate indicators while preserving highest risk score"""
    if df.empty or 'indicator' not in df.columns:
        return df
    
    try:
        # Sort by risk score (highest first) and drop duplicates keeping first
        df_sorted = df.sort_values('risk_score', ascending=False)
        df_deduped = df_sorted.drop_duplicates(subset=['indicator'], keep='first')
        
        logger.info(f"Deduplicated {len(df) - len(df_deduped)} indicators")
        return df_deduped
    
    except Exception as e:
        logger.error(f"Error deduplicating indicators: {str(e)}")
        return df

def age_indicators(df: pd.DataFrame, max_age_days: int = 90) -> pd.DataFrame:
    """Remove indicators older than specified age"""
    if df.empty or 'first_seen' not in df.columns:
        return df
    
    try:
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        
        # Convert to datetime if needed
        df['first_seen'] = pd.to_datetime(df['first_seen'], errors='coerce')
        
        # Filter out old indicators
        df_filtered = df[df['first_seen'] >= cutoff_date]
        
        aged_out = len(df) - len(df_filtered)
        if aged_out > 0:
            logger.info(f"Aged out {aged_out} old indicators")
        
        return df_filtered
    
    except Exception as e:
        logger.error(f"Error aging indicators: {str(e)}")
        return df

def normalize_ioc_type(ioc_type: str) -> str:
    """Normalize IOC types to standard format"""
    if not ioc_type:
        return "Unknown"
    
    type_mapping = {
        'ipv4': 'IP',
        'ipv6': 'IP',
        'ip': 'IP',
        'domain': 'Domain',
        'hostname': 'Domain',
        'url': 'URL',
        'uri': 'URL',
        'md5': 'Hash',
        'sha1': 'Hash',
        'sha256': 'Hash',
        'hash': 'Hash',
        'file': 'Hash',
        'email': 'Email',
        'email-addr': 'Email'
    }
    
    normalized = type_mapping.get(ioc_type.lower(), ioc_type.upper())
    return normalized

def calculate_confidence_score(sources: List[str], base_confidence: float = 50.0) -> float:
    """Calculate confidence score based on multiple sources"""
    if not sources:
        return base_confidence
    
    # Source reliability weights
    source_weights = {
        'CISA KEV': 1.0,
        'Abuse.ch': 0.9,
        'OTX': 0.7,
        'Manual': 0.95,
        'Unknown': 0.5
    }
    
    # Calculate weighted average
    total_weight = 0
    weighted_sum = 0
    
    for source in sources:
        weight = source_weights.get(source, 0.5)
        total_weight += weight
        weighted_sum += base_confidence * weight
    
    if total_weight == 0:
        return base_confidence
    
    # Boost confidence for multiple sources
    multi_source_bonus = min(len(sources) * 5, 20)  # Max 20% bonus
    
    final_confidence = (weighted_sum / total_weight) + multi_source_bonus
    return min(final_confidence, 100.0)

def generate_indicator_hash(indicator: str, ioc_type: str) -> str:
    """Generate unique hash for an indicator"""
    combined = f"{clean_indicator(indicator)}|{normalize_ioc_type(ioc_type)}"
    return hashlib.md5(combined.encode()).hexdigest()

def filter_by_confidence(df: pd.DataFrame, min_confidence: float = 70.0) -> pd.DataFrame:
    """Filter dataframe by minimum confidence threshold"""
    if df.empty or 'confidence' not in df.columns:
        return df
    
    try:
        filtered_df = df[df['confidence'] >= min_confidence]
        filtered_count = len(df) - len(filtered_df)
        
        if filtered_count > 0:
            logger.info(f"Filtered out {filtered_count} low-confidence indicators")
        
        return filtered_df
    
    except Exception as e:
        logger.error(f"Error filtering by confidence: {str(e)}")
        return df

def get_time_buckets(df: pd.DataFrame, date_column: str, bucket_size: str = 'D') -> pd.DataFrame:
    """Group dataframe by time buckets for trending analysis"""
    if df.empty or date_column not in df.columns:
        return pd.DataFrame()
    
    try:
        # Ensure datetime column
        df[date_column] = pd.to_datetime(df[date_column], errors='coerce')
        
        # Group by time bucket
        df['time_bucket'] = df[date_column].dt.floor(bucket_size)
        
        # Count by bucket
        bucket_counts = df.groupby('time_bucket').size().reset_index(name='count')
        bucket_counts['date'] = bucket_counts['time_bucket'].dt.date
        
        return bucket_counts
    
    except Exception as e:
        logger.error(f"Error creating time buckets: {str(e)}")
        return pd.DataFrame()

def create_summary_stats(vuln_df: pd.DataFrame, ioc_df: pd.DataFrame) -> Dict[str, Any]:
    """Create summary statistics for dashboards"""
    stats = {
        'vulnerabilities': {
            'total': len(vuln_df) if not vuln_df.empty else 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'indicators': {
            'total': len(ioc_df) if not ioc_df.empty else 0,
            'high_confidence': 0,
            'recent': 0,
            'by_type': {}
        },
        'risk_summary': {
            'overall_risk': 'Low',
            'critical_actions': 0,
            'trending': 'stable'
        }
    }
    
    try:
        # Vulnerability stats
        if not vuln_df.empty and 'severity' in vuln_df.columns:
            severity_counts = vuln_df['severity'].value_counts()
            stats['vulnerabilities'].update({
                'critical': severity_counts.get('Critical', 0),
                'high': severity_counts.get('High', 0),
                'medium': severity_counts.get('Medium', 0),
                'low': severity_counts.get('Low', 0)
            })
        
        # Indicator stats  
        if not ioc_df.empty:
            if 'confidence' in ioc_df.columns:
                stats['indicators']['high_confidence'] = len(ioc_df[ioc_df['confidence'] >= 80])
            
            if 'first_seen' in ioc_df.columns:
                recent_cutoff = datetime.now() - timedelta(days=7)
                ioc_df['first_seen'] = pd.to_datetime(ioc_df['first_seen'], errors='coerce')
                stats['indicators']['recent'] = len(ioc_df[ioc_df['first_seen'] >= recent_cutoff])
            
            if 'type' in ioc_df.columns:
                stats['indicators']['by_type'] = ioc_df['type'].value_counts().to_dict()
        
        # Overall risk assessment
        critical_vulns = stats['vulnerabilities']['critical']
        high_vulns = stats['vulnerabilities']['high']
        
        if critical_vulns > 5 or high_vulns > 10:
            stats['risk_summary']['overall_risk'] = 'High'
        elif critical_vulns > 0 or high_vulns > 5:
            stats['risk_summary']['overall_risk'] = 'Medium'
        
        stats['risk_summary']['critical_actions'] = critical_vulns + (high_vulns // 2)
        
    except Exception as e:
        logger.error(f"Error creating summary stats: {str(e)}")
    
    return stats

def export_to_csv(df: pd.DataFrame, filename: str) -> bool:
    """Export dataframe to CSV file"""
    try:
        df.to_csv(filename, index=False)
        logger.info(f"Exported {len(df)} records to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error exporting to CSV: {str(e)}")
        return False

def create_ioc_blocklist(ioc_df: pd.DataFrame, min_risk_score: float = 70.0) -> Dict[str, List[str]]:
    """Create blocklists organized by IOC type"""
    blocklist = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': []
    }
    
    if ioc_df.empty:
        return blocklist
    
    try:
        # Filter by minimum risk score
        high_risk_iocs = ioc_df[ioc_df['risk_score'] >= min_risk_score]
        
        # Group by type
        for _, row in high_risk_iocs.iterrows():
            ioc_type = normalize_ioc_type(row.get('type', ''))
            indicator = clean_indicator(str(row.get('indicator', '')))
            
            if ioc_type == 'IP' and validate_ip(indicator):
                blocklist['ips'].append(indicator)
            elif ioc_type == 'Domain' and validate_domain(indicator):
                blocklist['domains'].append(indicator)
            elif ioc_type == 'URL':
                blocklist['urls'].append(indicator)
            elif ioc_type == 'Hash':
                blocklist['hashes'].append(indicator)
        
        # Remove duplicates
        for key in blocklist:
            blocklist[key] = list(set(blocklist[key]))
        
        logger.info(f"Created blocklist with {sum(len(v) for v in blocklist.values())} indicators")
        
    except Exception as e:
        logger.error(f"Error creating blocklist: {str(e)}")
    
    return blocklist
