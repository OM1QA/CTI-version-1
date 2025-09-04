"""
Risk scoring engine for threat intelligence data
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class RiskScorer:
    """Risk scoring engine that calculates risk scores based on multiple factors"""
    
    def __init__(self):
        self.vulnerability_weights = {
            'cvss_base': 0.4,      # Base CVSS score weight
            'exploitability': 0.3,  # Known exploitation weight
            'age': 0.2,            # Age of vulnerability weight
            'asset_exposure': 0.1   # Asset exposure weight
        }
        
        self.indicator_weights = {
            'confidence': 0.4,      # Source confidence weight
            'threat_severity': 0.3, # Threat type severity weight
            'freshness': 0.2,      # How recent the indicator is
            'source_reliability': 0.1  # Source reliability weight
        }
        
        # Threat type severity mapping
        self.threat_severity_map = {
            'Ransomware': 100,
            'Malware C2': 90,
            'Phishing': 85,
            'Credential Theft': 85,
            'Malware': 80,
            'Botnet': 75,
            'Suspicious': 60,
            'Unknown': 50
        }
        
        # Source reliability mapping
        self.source_reliability_map = {
            'CISA KEV': 100,
            'Abuse.ch': 90,
            'OTX': 75,
            'Manual': 95
        }
    
    def score_vulnerabilities(self, vuln_df: pd.DataFrame) -> pd.DataFrame:
        """Score vulnerabilities based on multiple risk factors"""
        if vuln_df.empty:
            return vuln_df
        
        df = vuln_df.copy()
        
        try:
            # Ensure required columns exist with defaults
            if 'cvss_score' not in df.columns:
                df['cvss_score'] = self._estimate_cvss_from_severity(df.get('severity', 'Medium'))
            
            if 'date_added' not in df.columns:
                df['date_added'] = datetime.now()
            
            # Calculate individual risk components
            df['cvss_risk'] = self._calculate_cvss_risk(df['cvss_score'])
            df['exploit_risk'] = self._calculate_exploit_risk(df)
            df['age_risk'] = self._calculate_age_risk(df['date_added'])
            df['exposure_risk'] = self._calculate_exposure_risk(df)
            
            # Calculate weighted risk score
            df['risk_score'] = (
                df['cvss_risk'] * self.vulnerability_weights['cvss_base'] +
                df['exploit_risk'] * self.vulnerability_weights['exploitability'] +
                df['age_risk'] * self.vulnerability_weights['age'] +
                df['exposure_risk'] * self.vulnerability_weights['asset_exposure']
            )
            
            # Ensure risk score is between 0-100
            df['risk_score'] = np.clip(df['risk_score'], 0, 100)
            df['risk_score'] = df['risk_score'].round(0).astype(int)
            
            # Add risk category
            df['risk_category'] = df['risk_score'].apply(self._get_risk_category)
            
            logger.info(f"Scored {len(df)} vulnerabilities")
            return df
            
        except Exception as e:
            logger.error(f"Error scoring vulnerabilities: {str(e)}")
            # Return original dataframe with default risk scores
            df['risk_score'] = 50
            df['risk_category'] = 'Medium'
            return df
    
    def score_indicators(self, ioc_df: pd.DataFrame) -> pd.DataFrame:
        """Score indicators of compromise based on multiple risk factors"""
        if ioc_df.empty:
            return ioc_df
        
        df = ioc_df.copy()
        
        try:
            # Ensure required columns exist with defaults
            if 'confidence' not in df.columns:
                df['confidence'] = 75
            
            if 'threat_type' not in df.columns:
                df['threat_type'] = 'Unknown'
            
            if 'first_seen' not in df.columns:
                df['first_seen'] = datetime.now()
            
            if 'source' not in df.columns:
                df['source'] = 'Unknown'
            
            # Calculate individual risk components
            df['confidence_risk'] = self._calculate_confidence_risk(df['confidence'])
            df['threat_risk'] = self._calculate_threat_severity_risk(df['threat_type'])
            df['freshness_risk'] = self._calculate_freshness_risk(df['first_seen'])
            df['source_risk'] = self._calculate_source_reliability_risk(df['source'])
            
            # Calculate weighted risk score
            df['risk_score'] = (
                df['confidence_risk'] * self.indicator_weights['confidence'] +
                df['threat_risk'] * self.indicator_weights['threat_severity'] +
                df['freshness_risk'] * self.indicator_weights['freshness'] +
                df['source_risk'] * self.indicator_weights['source_reliability']
            )
            
            # Ensure risk score is between 0-100
            df['risk_score'] = np.clip(df['risk_score'], 0, 100)
            df['risk_score'] = df['risk_score'].round(0).astype(int)
            
            # Add risk category
            df['risk_category'] = df['risk_score'].apply(self._get_risk_category)
            
            logger.info(f"Scored {len(df)} indicators")
            return df
            
        except Exception as e:
            logger.error(f"Error scoring indicators: {str(e)}")
            # Return original dataframe with default risk scores
            df['risk_score'] = 50
            df['risk_category'] = 'Medium'
            return df
    
    def _calculate_cvss_risk(self, cvss_scores: pd.Series) -> pd.Series:
        """Convert CVSS scores to 0-100 risk scale"""
        # CVSS is 0-10, normalize to 0-100
        return (cvss_scores / 10.0) * 100
    
    def _calculate_exploit_risk(self, df: pd.DataFrame) -> pd.Series:
        """Calculate exploitation risk based on known exploitation"""
        # CISA KEV entries are known to be exploited
        exploit_risk = pd.Series(50, index=df.index)  # Default medium risk
        
        if 'source' in df.columns:
            exploit_risk[df['source'] == 'CISA KEV'] = 100  # Maximum risk for KEV
        
        # Check for exploitation indicators in description
        if 'description' in df.columns:
            exploit_indicators = ['exploit', 'in the wild', 'active', 'weaponized']
            desc_lower = df['description'].fillna('').str.lower()
            
            for indicator in exploit_indicators:
                exploit_risk[desc_lower.str.contains(indicator)] = 90
        
        return exploit_risk
    
    def _calculate_age_risk(self, dates: pd.Series) -> pd.Series:
        """Calculate risk based on vulnerability age (newer = higher risk)"""
        now = datetime.now()
        
        # Convert to datetime if needed
        if dates.dtype == 'object':
            dates = pd.to_datetime(dates, errors='coerce')
        
        # Calculate days since disclosure
        days_old = (now - dates).dt.days.fillna(30)  # Default to 30 days if missing
        
        # Risk decreases over time but starts high
        # 0-7 days: 100 risk, 8-30 days: 80 risk, 31-90 days: 60 risk, >90 days: 40 risk
        risk = pd.Series(40, index=dates.index)  # Default for old vulns
        risk[days_old <= 90] = 60
        risk[days_old <= 30] = 80
        risk[days_old <= 7] = 100
        
        return risk
    
    def _calculate_exposure_risk(self, df: pd.DataFrame) -> pd.Series:
        """Calculate risk based on asset exposure (simplified for MVP)"""
        # For MVP, we'll use a simple heuristic based on product type
        exposure_risk = pd.Series(50, index=df.index)  # Default medium exposure
        
        if 'product' in df.columns:
            # High exposure products
            high_exposure = ['exchange', 'outlook', 'iis', 'apache', 'nginx', 'vpn']
            product_lower = df['product'].fillna('').str.lower()
            
            for product in high_exposure:
                exposure_risk[product_lower.str.contains(product)] = 90
            
            # Medium exposure products
            medium_exposure = ['windows', 'office', 'browser']
            for product in medium_exposure:
                exposure_risk[product_lower.str.contains(product)] = 70
        
        return exposure_risk
    
    def _calculate_confidence_risk(self, confidence: pd.Series) -> pd.Series:
        """Convert confidence scores to risk scores"""
        # Higher confidence = higher risk score
        return confidence.fillna(50)
    
    def _calculate_threat_severity_risk(self, threat_types: pd.Series) -> pd.Series:
        """Calculate risk based on threat type severity"""
        risk_scores = threat_types.map(self.threat_severity_map)
        return risk_scores.fillna(50)  # Default medium risk for unknown threats
    
    def _calculate_freshness_risk(self, dates: pd.Series) -> pd.Series:
        """Calculate risk based on how fresh the indicator is"""
        now = datetime.now()
        
        # Convert to datetime if needed
        if dates.dtype == 'object':
            dates = pd.to_datetime(dates, errors='coerce')
        
        # Calculate hours since first seen
        hours_old = (now - dates).dt.total_seconds() / 3600
        hours_old = hours_old.fillna(48)  # Default to 48 hours if missing
        
        # Fresher indicators are riskier
        # 0-6 hours: 100 risk, 6-24 hours: 90 risk, 1-7 days: 70 risk, >7 days: 50 risk
        risk = pd.Series(50, index=dates.index)  # Default for old indicators
        risk[hours_old <= (7 * 24)] = 70  # 7 days
        risk[hours_old <= 24] = 90        # 24 hours
        risk[hours_old <= 6] = 100        # 6 hours
        
        return risk
    
    def _calculate_source_reliability_risk(self, sources: pd.Series) -> pd.Series:
        """Calculate risk based on source reliability"""
        risk_scores = sources.map(self.source_reliability_map)
        return risk_scores.fillna(75)  # Default medium-high reliability
    
    def _estimate_cvss_from_severity(self, severity: pd.Series) -> pd.Series:
        """Estimate CVSS scores from severity ratings"""
        severity_map = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.5,
            'Low': 2.5
        }
        
        if isinstance(severity, pd.Series):
            return severity.map(severity_map).fillna(5.5)
        else:
            # Single value
            return pd.Series([severity_map.get(severity, 5.5)])
    
    def _get_risk_category(self, risk_score: float) -> str:
        """Convert numeric risk score to category"""
        if risk_score >= 90:
            return 'Critical'
        elif risk_score >= 70:
            return 'High'
        elif risk_score >= 40:
            return 'Medium'
        else:
            return 'Low'
    
    def get_priority_actions(self, vuln_df: pd.DataFrame, ioc_df: pd.DataFrame, 
                           limit: int = 10) -> Dict[str, Any]:
        """Get prioritized actions based on risk scores"""
        actions = {
            'critical_patches': [],
            'high_risk_iocs': [],
            'immediate_actions': [],
            'summary': {}
        }
        
        try:
            # Critical vulnerabilities requiring immediate patching
            if not vuln_df.empty:
                critical_vulns = vuln_df[vuln_df['risk_score'] >= 90].nlargest(limit, 'risk_score')
                actions['critical_patches'] = critical_vulns.to_dict('records')
            
            # High-risk IOCs to block
            if not ioc_df.empty:
                high_risk_iocs = ioc_df[ioc_df['risk_score'] >= 80].nlargest(limit, 'risk_score')
                actions['high_risk_iocs'] = high_risk_iocs.to_dict('records')
            
            # Generate immediate action items
            actions['immediate_actions'] = self._generate_action_items(vuln_df, ioc_df)
            
            # Summary statistics
            actions['summary'] = {
                'total_critical_vulns': len(vuln_df[vuln_df['risk_score'] >= 90]) if not vuln_df.empty else 0,
                'total_high_risk_iocs': len(ioc_df[ioc_df['risk_score'] >= 80]) if not ioc_df.empty else 0,
                'avg_vuln_risk': vuln_df['risk_score'].mean() if not vuln_df.empty else 0,
                'avg_ioc_risk': ioc_df['risk_score'].mean() if not ioc_df.empty else 0
            }
            
        except Exception as e:
            logger.error(f"Error generating priority actions: {str(e)}")
        
        return actions
    
    def _generate_action_items(self, vuln_df: pd.DataFrame, ioc_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Generate immediate action items"""
        actions = []
        
        try:
            # Critical vulnerability actions
            if not vuln_df.empty:
                critical_count = len(vuln_df[vuln_df['risk_score'] >= 90])
                if critical_count > 0:
                    actions.append({
                        'priority': 'Critical',
                        'action': f'Patch {critical_count} critical vulnerabilities immediately',
                        'timeline': '24 hours',
                        'type': 'vulnerability'
                    })
            
            # High-risk IOC actions
            if not ioc_df.empty:
                high_risk_count = len(ioc_df[ioc_df['risk_score'] >= 80])
                if high_risk_count > 0:
                    actions.append({
                        'priority': 'High',
                        'action': f'Block {high_risk_count} high-risk indicators',
                        'timeline': '4 hours',
                        'type': 'indicator'
                    })
            
            # Monitoring actions
            if not vuln_df.empty or not ioc_df.empty:
                actions.append({
                    'priority': 'Medium',
                    'action': 'Review and update security monitoring rules',
                    'timeline': '1 week',
                    'type': 'monitoring'
                })
        
        except Exception as e:
            logger.error(f"Error generating action items: {str(e)}")
        
        return actions
