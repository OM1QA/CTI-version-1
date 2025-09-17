import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import time

# Page config
st.set_page_config(
    page_title="SME Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.critical-card {
    border-left-color: #dc3545;
}
.high-card {
    border-left-color: #fd7e14;
}
.medium-card {
    border-left-color: #ffc107;
}
.low-card {
    border-left-color: #28a745;
}
</style>
""", unsafe_allow_html=True)

# Utility Functions
def format_date(date_obj):
    """Format date object to readable string"""
    if isinstance(date_obj, str):
        return date_obj
    return date_obj.strftime('%Y-%m-%d') if date_obj else 'Unknown'

def get_severity_color(severity):
    """Get color code for severity levels"""
    colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
    }
    return colors.get(severity, '#6c757d')

# Data Ingestion Classes
class BaseIngester:
    """Base class for threat intelligence ingesters"""
    def __init__(self):
        self.source_name = "Base"
        
    def fetch_data(self):
        """Override this method in child classes"""
        return []

class CISAKEVIngester(BaseIngester):
    """Ingest CISA Known Exploited Vulnerabilities"""
    def __init__(self):
        super().__init__()
        self.source_name = "CISA KEV"
        self.api_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def fetch_data(self):
        """Fetch CISA KEV data"""
        try:
            response = requests.get(self.api_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Convert to DataFrame
            vulns = []
            for vuln in data.get('vulnerabilities', [])[:50]:  # Limit for demo
                vulns.append({
                    'cve_id': vuln.get('cveID', 'N/A'),
                    'product': vuln.get('product', 'Unknown'),
                    'vendor': vuln.get('vendorProject', 'Unknown'),
                    'severity': 'Critical',  # CISA KEV are all critical
                    'cvss_score': 9.0,  # Default high score for KEV
                    'date_added': datetime.strptime(vuln.get('dateAdded', '2024-01-01'), '%Y-%m-%d'),
                    'description': vuln.get('shortDescription', 'No description available'),
                    'source': 'CISA KEV'
                })
            
            return pd.DataFrame(vulns)
            
        except Exception as e:
            st.warning(f"Failed to fetch CISA KEV data: {str(e)}. Using sample data.")
            return self.get_sample_vulns()
    
    def get_sample_vulns(self):
        """Fallback sample vulnerability data"""
        return pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],
            'product': ['Microsoft Exchange', 'Apache Struts', 'WordPress Plugin'],
            'vendor': ['Microsoft', 'Apache', 'WordPress'],
            'severity': ['Critical', 'High', 'High'],
            'cvss_score': [9.8, 8.1, 7.5],
            'date_added': [datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=2), datetime.now() - timedelta(days=3)],
            'description': ['Remote code execution in Exchange Server', 'SQL injection in Struts framework', 'XSS vulnerability in popular plugin'],
            'source': ['CISA KEV', 'CISA KEV', 'CISA KEV']
        })

class OTXIngester(BaseIngester):
    """Ingest AlienVault OTX threat intelligence"""
    def __init__(self):
        super().__init__()
        self.source_name = "OTX"
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.api_key = st.secrets.get("OTX_API_KEY", "")
    
    def fetch_data(self):
        """Fetch OTX indicators"""
        if not self.api_key:
            st.warning("OTX API key not found. Using sample data.")
            return self.get_sample_iocs()
        
        try:
            headers = {
                'X-OTX-API-KEY': self.api_key,
                'User-Agent': 'SME-TIP/1.0'
            }
            
            # Fetch recent pulses (threat intelligence reports)
            pulses_url = f"{self.base_url}/pulses/subscribed"
            params = {
                'limit': 20,
                'page': 1
            }
            
            response = requests.get(pulses_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            pulses_data = response.json()
            
            # Extract indicators from pulses
            indicators = []
            for pulse in pulses_data.get('results', [])[:10]:  # Limit for demo
                for indicator in pulse.get('indicators', [])[:5]:  # 5 per pulse
                    indicators.append({
                        'indicator': indicator.get('indicator', 'N/A'),
                        'type': indicator.get('type', 'Unknown'),
                        'threat_type': self.classify_threat_type(pulse.get('name', '')),
                        'confidence': min(85 + len(pulse.get('references', [])) * 5, 100),  # Score based on references
                        'first_seen': self.parse_date(indicator.get('created', pulse.get('created', ''))),
                        'source': 'OTX',
                        'pulse_name': pulse.get('name', 'Unknown Pulse')
                    })
            
            return pd.DataFrame(indicators[:30])  # Limit total indicators
            
        except Exception as e:
            st.warning(f"Failed to fetch OTX data: {str(e)}. Using sample data.")
            return self.get_sample_iocs()
    
    def classify_threat_type(self, pulse_name):
        """Classify threat type based on pulse name"""
        pulse_lower = pulse_name.lower()
        if any(word in pulse_lower for word in ['ransomware', 'ransom']):
            return 'Ransomware'
        elif any(word in pulse_lower for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in pulse_lower for word in ['malware', 'trojan', 'backdoor']):
            return 'Malware C2'
        elif any(word in pulse_lower for word in ['botnet', 'bot']):
            return 'Botnet'
        elif any(word in pulse_lower for word in ['apt', 'advanced']):
            return 'APT Activity'
        else:
            return 'Suspicious Activity'
    
    def parse_date(self, date_string):
        """Parse various date formats"""
        try:
            if 'T' in date_string:
                return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            else:
                return datetime.strptime(date_string, '%Y-%m-%d')
        except:
            return datetime.now() - timedelta(days=1)
    
    def get_sample_iocs(self):
        """Fallback sample IOC data"""
        return pd.DataFrame({
            'indicator': ['192.168.1.100', 'malware.example.com', 'bad-hash-123'],
            'type': ['IPv4', 'hostname', 'FileHash-SHA256'],
            'threat_type': ['Malware C2', 'Phishing', 'Ransomware'],
            'confidence': [85, 92, 78],
            'first_seen': [datetime.now() - timedelta(days=2), datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=4)],
            'source': ['OTX', 'OTX', 'OTX'],
            'pulse_name': ['Sample Malware Campaign', 'Phishing Infrastructure', 'Ransomware IOCs']
        })

class AbuseCHIngester(BaseIngester):
    """Ingest Abuse.ch threat intelligence"""
    def __init__(self):
        super().__init__()
        self.source_name = "Abuse.ch"
        self.apis = {
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/',
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1/',
            'malwarebazaar': 'https://mb-api.abuse.ch/api/v1/'
        }
    
    def fetch_data(self):
        """Fetch real Abuse.ch indicators from multiple sources"""
        try:
            all_indicators = []
            
            # Fetch from URLhaus (malicious URLs)
            urlhaus_data = self.fetch_urlhaus()
            all_indicators.extend(urlhaus_data)
            
            # Fetch from ThreatFox (IOCs)
            threatfox_data = self.fetch_threatfox()
            all_indicators.extend(threatfox_data)
            
            # Return combined data
            if all_indicators:
                return pd.DataFrame(all_indicators[:25])  # Limit total indicators
            else:
                return self.get_sample_data()
            
        except Exception as e:
            st.warning(f"Failed to fetch Abuse.ch data: {str(e)}. Using sample data.")
            return self.get_sample_data()
    
    def fetch_urlhaus(self):
        """Fetch malicious URLs from URLhaus"""
        try:
            # URLhaus recent URLs endpoint (no authentication needed)
            response = requests.get(self.apis['urlhaus'], timeout=15)
            response.raise_for_status()
            
            result = response.json()
            indicators = []
            
            for url_entry in result.get('urls', [])[:12]:  # Limit to 12
                # Extract domain from URL
                url = url_entry.get('url', '')
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.netloc if parsed.netloc else url
                except:
                    domain = url.split('/')[0] if '/' in url else url
                
                # Skip empty domains
                if not domain or domain == '':
                    continue
                
                indicators.append({
                    'indicator': domain,
                    'type': 'hostname',
                    'threat_type': self.classify_urlhaus_threat(url_entry.get('tags', [])),
                    'confidence': self.calculate_urlhaus_confidence(url_entry),
                    'first_seen': self.parse_abuse_date(url_entry.get('date_added', '')),
                    'source': 'Abuse.ch URLhaus',
                    'campaign': url_entry.get('threat', 'Malicious URL'),
                    'url_status': url_entry.get('url_status', 'unknown')
                })
            
            return indicators
            
        except Exception as e:
            st.warning(f"URLhaus API error: {str(e)}")
            return []
    
    def fetch_threatfox(self):
        """Fetch IOCs from ThreatFox"""
        try:
            # ThreatFox get_iocs endpoint
            payload = {
                'query': 'get_iocs',
                'days': 7  # Get IOCs from last 7 days
            }
            
            response = requests.post(
                self.apis['threatfox'], 
                json=payload,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'SME-TIP/1.0'
                },
                timeout=15
            )
            response.raise_for_status()
            
            result = response.json()
            indicators = []
            
            if result.get('query_status') == 'ok':
                for ioc_entry in result.get('data', [])[:12]:  # Limit to 12
                    ioc_value = ioc_entry.get('ioc', '').strip()
                    if not ioc_value:
                        continue
                        
                    indicators.append({
                        'indicator': ioc_value,
                        'type': self.normalize_ioc_type(ioc_entry.get('ioc_type', '')),
                        'threat_type': self.classify_threatfox_threat(ioc_entry.get('malware', '')),
                        'confidence': self.calculate_threatfox_confidence(ioc_entry),
                        'first_seen': self.parse_abuse_date(ioc_entry.get('first_seen', '')),
                        'source': 'Abuse.ch ThreatFox',
                        'campaign': ioc_entry.get('malware', 'Unknown Malware'),
                        'confidence_level': ioc_entry.get('confidence_level', 50)
                    })
            else:
                st.info(f"ThreatFox query status: {result.get('query_status', 'unknown')}")
            
            return indicators
            
        except Exception as e:
            st.warning(f"ThreatFox API error: {str(e)}")
            return []
    
    def classify_urlhaus_threat(self, tags):
        """Classify threat type based on URLhaus tags"""
        tags_str = ' '.join(tags).lower()
        if any(word in tags_str for word in ['emotet', 'trickbot', 'qakbot']):
            return 'Banking Trojan'
        elif any(word in tags_str for word in ['ransomware', 'lockbit', 'ryuk']):
            return 'Ransomware'
        elif any(word in tags_str for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in tags_str for word in ['malware', 'trojan']):
            return 'Malware C2'
        else:
            return 'Malicious Infrastructure'
    
    def classify_threatfox_threat(self, malware_name):
        """Classify threat type based on malware family"""
        malware_lower = malware_name.lower()
        if any(word in malware_lower for word in ['emotet', 'trickbot', 'qakbot', 'banking']):
            return 'Banking Trojan'
        elif any(word in malware_lower for word in ['lockbit', 'conti', 'ryuk', 'ransom']):
            return 'Ransomware'
        elif any(word in malware_lower for word in ['cobalt', 'beacon']):
            return 'APT Activity'
        elif any(word in malware_lower for word in ['stealer', 'info']):
            return 'Credential Theft'
        else:
            return 'Malware C2'
    
    def calculate_urlhaus_confidence(self, url_entry):
        """Calculate confidence score for URLhaus entries"""
        base_confidence = 75
        
        # Boost confidence based on threat status
        if url_entry.get('url_status') == 'online':
            base_confidence += 15
        
        # Boost based on number of tags
        tags_count = len(url_entry.get('tags', []))
        base_confidence += min(tags_count * 2, 10)
        
        return min(base_confidence, 95)
    
    def calculate_threatfox_confidence(self, ioc_entry):
        """Calculate confidence score for ThreatFox entries"""
        base_confidence = 80
        
        # Boost based on confidence rating from ThreatFox
        confidence_rating = ioc_entry.get('confidence_level', 50)
        base_confidence = max(base_confidence, confidence_rating)
        
        # Boost based on number of tags
        tags_count = len(ioc_entry.get('tags', []))
        base_confidence += min(tags_count, 10)
        
        return min(base_confidence, 98)
    
    def normalize_ioc_type(self, ioc_type):
        """Normalize IOC types to standard format"""
        type_mapping = {
            'ip:port': 'IPv4',
            'domain': 'hostname',
            'url': 'URL',
            'md5_hash': 'FileHash-MD5',
            'sha1_hash': 'FileHash-SHA1',
            'sha256_hash': 'FileHash-SHA256'
        }
        return type_mapping.get(ioc_type.lower(), ioc_type)
    
    def parse_abuse_date(self, date_string):
        """Parse Abuse.ch date format"""
        try:
            if not date_string:
                return datetime.now() - timedelta(days=1)
            
            # Handle different date formats from Abuse.ch
            if 'T' in date_string:
                return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            else:
                return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        except:
            return datetime.now() - timedelta(days=1)
    
    def get_sample_data(self):
        """Fallback sample data"""
        return pd.DataFrame({
            'indicator': ['10.0.0.50', 'phishing.test.com', 'botnet.example.org'],
            'type': ['IPv4', 'hostname', 'hostname'],
            'threat_type': ['Botnet', 'Phishing', 'Botnet'],
            'confidence': [68, 95, 73],
            'first_seen': [datetime.now() - timedelta(days=6), datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=3)],
            'source': ['Abuse.ch', 'Abuse.ch', 'Abuse.ch'],
            'campaign': ['Emotet', 'Generic Phishing', 'Qakbot']
        })

# Risk Scoring Engine
class RiskScorer:
    """Calculate risk scores for threats"""
    def __init__(self):
        self.threat_severity_map = {
            'Ransomware': 100,
            'APT Activity': 95,
            'Malware C2': 90,
            'Credential Theft': 85,
            'Phishing': 80,
            'Botnet': 75,
            'Suspicious Activity': 60
        }
    
    def score_vulnerabilities(self, vuln_df):
        """Score vulnerabilities based on CVSS and other factors"""
        if vuln_df.empty:
            return vuln_df
        
        # Calculate risk score
        def calculate_vuln_risk(row):
            base_score = row.get('cvss_score', 5.0) * 10  # Scale to 100
            
            # CISA KEV gets automatic high score
            if row.get('source') == 'CISA KEV':
                base_score = max(base_score, 95)
            
            # Age factor (newer = higher risk)
            days_old = (datetime.now() - row.get('date_added', datetime.now())).days
            age_factor = max(1.0 - (days_old / 365), 0.5)  # Reduce over time
            
            return min(int(base_score * age_factor), 100)
        
        vuln_df = vuln_df.copy()
        vuln_df['risk_score'] = vuln_df.apply(calculate_vuln_risk, axis=1)
        return vuln_df
    
    def score_indicators(self, ioc_df):
        """Score IOCs based on confidence and threat type"""
        if ioc_df.empty:
            return ioc_df
        
        def calculate_ioc_risk(row):
            confidence = row.get('confidence', 50)
            threat_type = row.get('threat_type', 'Suspicious Activity')
            
            # Get threat type severity
            threat_severity = self.threat_severity_map.get(threat_type, 50)
            
            # Calculate composite risk score
            risk_score = (confidence * 0.6) + (threat_severity * 0.4)
            
            # Freshness factor (newer = higher risk)
            days_old = (datetime.now() - row.get('first_seen', datetime.now())).days
            if days_old <= 7:
                risk_score *= 1.1  # 10% boost for recent
            elif days_old <= 30:
                risk_score *= 1.05  # 5% boost for recent
            
            return min(int(risk_score), 100)
        
        ioc_df = ioc_df.copy()
        ioc_df['risk_score'] = ioc_df.apply(calculate_ioc_risk, axis=1)
        return ioc_df

@st.cache_data(ttl=3600)  # Cache for 1 hour
def load_threat_data():
    """Load and process threat intelligence data"""
    with st.spinner("Loading threat intelligence data..."):
        try:
            # Initialize ingesters
            cisa_ingester = CISAKEVIngester()
            otx_ingester = OTXIngester()
            abuse_ingester = AbuseCHIngester()
            
            # Ingest data
            cisa_data = cisa_ingester.fetch_data()
            otx_data = otx_ingester.fetch_data()
            abuse_data = abuse_ingester.fetch_data()
            
            # Initialize risk scorer
            scorer = RiskScorer()
            
            # Process and score data
            processed_data = {
                'vulnerabilities': scorer.score_vulnerabilities(cisa_data),
                'indicators': scorer.score_indicators(pd.concat([otx_data, abuse_data], ignore_index=True) if not otx_data.empty or not abuse_data.empty else pd.DataFrame()),
                'last_updated': datetime.now()
            }
            
            return processed_data
        
        except Exception as e:
            st.error(f"Error loading threat data: {str(e)}")
            # Return empty data structure
            return {
                'vulnerabilities': pd.DataFrame(),
                'indicators': pd.DataFrame(),
                'last_updated': datetime.now()
            }

def main():
    st.title("🛡️ SME Threat Intelligence Platform")
    st.markdown("**Enterprise-grade threat intelligence without enterprise costs**")
    
    # Load data
    data = load_threat_data()
    
    # Check if we have data
    if data['vulnerabilities'].empty and data['indicators'].empty:
        st.error("Unable to load threat intelligence data. Please check your API configuration.")
        st.stop()
    
    # Sidebar filters
    st.sidebar.header("🔍 Filters")
    
    # Severity filter for vulnerabilities
    severity_filter = st.sidebar.multiselect(
        "Vulnerability Severity",
        ['Critical', 'High', 'Medium', 'Low'],
        default=['Critical', 'High']
    )
    
    # Confidence filter for IOCs
    confidence_filter = st.sidebar.slider(
        "IOC Confidence Threshold",
        min_value=0,
        max_value=100,
        value=70,
        help="Only show indicators with confidence above this threshold"
    )
    
    # Date filter
    days_back = st.sidebar.selectbox(
        "Show threats from last:",
        [7, 14, 30, 90],
        index=1
    )
    
    # Filter data based on selections
    filtered_vulns = data['vulnerabilities'][
        (data['vulnerabilities']['severity'].isin(severity_filter)) &
        (data['vulnerabilities']['date_added'] >= datetime.now() - timedelta(days=days_back))
    ] if not data['vulnerabilities'].empty else pd.DataFrame()
    
    filtered_iocs = data['indicators'][
        (data['indicators']['confidence'] >= confidence_filter) &
        (data['indicators']['first_seen'] >= datetime.now() - timedelta(days=days_back))
    ] if not data['indicators'].empty else pd.DataFrame()
    
    # Executive Summary Section
    st.header("📊 Executive Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        critical_vulns = len(filtered_vulns[filtered_vulns['severity'] == 'Critical']) if not filtered_vulns.empty else 0
        st.markdown(f"""
        <div class="metric-card critical-card">
            <h3 style="margin:0; color:#dc3545;">🚨 {critical_vulns}</h3>
            <p style="margin:0;">Critical Vulnerabilities</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        high_risk_iocs = len(filtered_iocs[filtered_iocs['risk_score'] >= 80]) if not filtered_iocs.empty else 0
        st.markdown(f"""
        <div class="metric-card high-card">
            <h3 style="margin:0; color:#fd7e14;">⚠️ {high_risk_iocs}</h3>
            <p style="margin:0;">High-Risk IOCs</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        total_threats = len(filtered_vulns) + len(filtered_iocs)
        st.markdown(f"""
        <div class="metric-card medium-card">
            <h3 style="margin:0; color:#ffc107;">📈 {total_threats}</h3>
            <p style="margin:0;">Total Active Threats</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        # Calculate risk posture (simplified)
        if critical_vulns > 5:
            posture = "🔴 HIGH"
            posture_color = "#dc3545"
        elif critical_vulns > 2:
            posture = "🟡 MEDIUM" 
            posture_color = "#ffc107"
        else:
            posture = "🟢 LOW"
            posture_color = "#28a745"
            
        st.markdown(f"""
        <div class="metric-card">
            <h3 style="margin:0; color:{posture_color};">{posture}</h3>
            <p style="margin:0;">Risk Posture</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Last updated info
    st.caption(f"Last updated: {data['last_updated'].strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Data source status
    with st.expander("🔗 Data Source Status"):
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("CISA KEV", f"{len(data['vulnerabilities'])} vulnerabilities")
        with col2:
            otx_count = len(data['indicators'][data['indicators']['source'] == 'OTX']) if not data['indicators'].empty else 0
            st.metric("AlienVault OTX", f"{otx_count} indicators")
        with col3:
            abuse_count = len(data['indicators'][data['indicators']['source'] == 'Abuse.ch']) if not data['indicators'].empty else 0
            st.metric("Abuse.ch", f"{abuse_count} indicators")
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Priority Actions", "🦠 Vulnerabilities", "🚩 Indicators", "📊 Analytics"])
    
    with tab1:
        st.subheader("🎯 Priority Actions for Your Team")
        
        # Top critical vulnerabilities
        if not filtered_vulns.empty:
            st.markdown("### 🚨 Immediate Patching Required")
            top_vulns = filtered_vulns.nlargest(5, 'risk_score')
            
            for _, vuln in top_vulns.iterrows():
                with st.expander(f"🔥 {vuln['cve_id']} - {vuln['product']} (Risk: {vuln['risk_score']}/100)"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Description:** {vuln['description']}")
                        st.write(f"**Vendor:** {vuln['vendor']}")
                        st.write(f"**CVSS Score:** {vuln['cvss_score']}")
                    with col2:
                        st.write(f"**Severity:** {vuln['severity']}")
                        st.write(f"**Date Added:** {format_date(vuln['date_added'])}")
                        if st.button(f"Track Patching", key=f"patch_{vuln['cve_id']}"):
                            st.success("Added to patch management queue (Demo)")
        
        # Top IOCs to block
        if not filtered_iocs.empty:
            st.markdown("### 🛡️ IOCs to Block Immediately")
            top_iocs = filtered_iocs.nlargest(5, 'risk_score')
            
            ioc_df = top_iocs[['indicator', 'type', 'threat_type', 'confidence', 'risk_score']]
            st.dataframe(ioc_df, use_container_width=True)
            
            if st.button("🚫 Block Selected IOCs"):
                st.success(f"Would block {len(top_iocs)} high-risk indicators across your security stack (Demo)")
    
    with tab2:
        st.subheader("🦠 Vulnerability Management")
        
        if not filtered_vulns.empty:
            # Vulnerability distribution chart
            severity_counts = filtered_vulns['severity'].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Distribution by Severity",
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14', 
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
            )
            st.plotly_chart(fig_severity, use_container_width=True)
            
            # Risk score distribution
            fig_risk = px.histogram(
                filtered_vulns,
                x='risk_score',
                nbins=20,
                title='Vulnerability Risk Score Distribution'
            )
            st.plotly_chart(fig_risk, use_container_width=True)
            
            # Detailed vulnerability table
            st.markdown("### 📋 Detailed Vulnerability List")
            vuln_display = filtered_vulns[['cve_id', 'product', 'vendor', 'severity', 'cvss_score', 'risk_score', 'date_added']]
            st.dataframe(vuln_display, use_container_width=True)
            
        else:
            st.info("No vulnerabilities match your current filters.")
    
    with tab3:
        st.subheader("🚩 Threat Indicators")
        
        if not filtered_iocs.empty:
            # IOC type distribution
            type_counts = filtered_iocs['type'].value_counts()
            fig_types = px.bar(
                x=type_counts.index,
                y=type_counts.values,
                title="IOC Distribution by Type",
                labels={'x': 'IOC Type', 'y': 'Count'}
            )
            st.plotly_chart(fig_types, use_container_width=True)
            
            # Threat type distribution
            threat_counts = filtered_iocs['threat_type'].value_counts()
            fig_threats = px.pie(
                values=threat_counts.values,
                names=threat_counts.index,
                title="Threat Type Distribution"
            )
            st.plotly_chart(fig_threats, use_container_width=True)
            
            # IOC timeline
            if 'first_seen' in filtered_iocs.columns:
                ioc_timeline = filtered_iocs.groupby(filtered_iocs['first_seen'].dt.date).size().reset_index()
                ioc_timeline.columns = ['Date', 'Count']
                
                fig_timeline = px.line(
                    ioc_timeline,
                    x='Date',
                    y='Count',
                    title='New IOCs Over Time'
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
            
            # Detailed IOC table
            st.markdown("### 📋 Detailed IOC List")
            st.dataframe(filtered_iocs, use_container_width=True)
            
        else:
            st.info("No indicators match your current filters.")
    
    with tab4:
        st.subheader("📊 Threat Intelligence Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk score distribution for vulnerabilities
            if not filtered_vulns.empty:
                fig_vuln_risk = px.histogram(
                    filtered_vulns,
                    x='risk_score',
                    nbins=20,
                    title='Vulnerability Risk Score Distribution',
                    color_discrete_sequence=['#dc3545']
                )
                st.plotly_chart(fig_vuln_risk, use_container_width=True)
        
        with col2:
            # Source reliability
            if not filtered_iocs.empty:
                source_confidence = filtered_iocs.groupby('source')['confidence'].mean().reset_index()
                fig_source = px.bar(
                    source_confidence,
                    x='source',
                    y='confidence',
                    title='Average Confidence by Source',
                    color='confidence',
                    color_continuous_scale='Viridis'
                )
                st.plotly_chart(fig_source, use_container_width=True)
        
        # Threat landscape overview
        st.markdown("### 🌍 Threat Landscape Overview")
        
        threat_summary = {
            'Total Vulnerabilities': len(data['vulnerabilities']) if not data['vulnerabilities'].empty else 0,
            'Critical/High Severity': len(data['vulnerabilities'][data['vulnerabilities']['severity'].isin(['Critical', 'High'])]) if not data['vulnerabilities'].empty else 0,
            'Total IOCs': len(data['indicators']) if not data['indicators'].empty else 0,
            'High Confidence IOCs': len(data['indicators'][data['indicators']['confidence'] >= 80]) if not data['indicators'].empty else 0,
            'Unique Threat Types': data['indicators']['threat_type'].nunique() if not data['indicators'].empty else 0,
            'Data Sources Active': len(set(data['indicators']['source'])) if not data['indicators'].empty else 0
        }
        
        summary_df = pd.DataFrame(list(threat_summary.items()), columns=['Metric', 'Value'])
        st.dataframe(summary_df, use_container_width=True, hide_index=True)
        
        # Risk posture over time (placeholder for future enhancement)
        st.markdown("### 📈 Risk Posture Trend (Coming Soon)")
        st.info("Historical risk tracking will be available in the next update.")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ SME Threat Intelligence Platform MVP | Built with ❤️ for small businesses</p>
        <p>Data sources: CISA KEV (Live), AlienVault OTX (Live), Abuse.ch (Sample) | Auto-refresh: Every hour</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
