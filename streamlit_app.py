import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import sys
import os

# Add the src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from ingest import CISAKEVIngester, OTXIngester, AbuseCHIngester
    from scoring import RiskScorer
    from utils import format_date, get_severity_color
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()

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

@st.cache_data(ttl=3600)  # Cache for 1 hour
def load_threat_data():
    """Load and process threat intelligence data"""
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
            'indicators': scorer.score_indicators(otx_data + abuse_data),
            'last_updated': datetime.now()
        }
        
        return processed_data
    
    except Exception as e:
        st.error(f"Error loading threat data: {str(e)}")
        # Return sample data for demo
        return get_sample_data()

def get_sample_data():
    """Generate sample data for demo purposes"""
    sample_vulns = pd.DataFrame({
        'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0004', 'CVE-2024-0005'],
        'product': ['Microsoft Exchange', 'Apache Struts', 'WordPress Plugin', 'Cisco IOS', 'VMware vCenter'],
        'vendor': ['Microsoft', 'Apache', 'WordPress', 'Cisco', 'VMware'],
        'severity': ['Critical', 'High', 'High', 'Medium', 'Critical'],
        'cvss_score': [9.8, 8.1, 7.5, 6.5, 9.1],
        'date_added': [datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=2), 
                      datetime.now() - timedelta(days=3), datetime.now() - timedelta(days=5),
                      datetime.now() - timedelta(days=7)],
        'description': [
            'Remote code execution in Exchange Server',
            'SQL injection in Struts framework',
            'XSS vulnerability in popular plugin',
            'Buffer overflow in IOS software',
            'Authentication bypass in vCenter'
        ],
        'risk_score': [95, 82, 75, 45, 91]
    })
    
    sample_iocs = pd.DataFrame({
        'indicator': ['192.168.1.100', 'malware.example.com', 'bad-hash-123', '10.0.0.50', 'phishing.test.com'],
        'type': ['IP', 'Domain', 'Hash', 'IP', 'Domain'],
        'threat_type': ['Malware C2', 'Phishing', 'Ransomware', 'Botnet', 'Credential Theft'],
        'confidence': [85, 92, 78, 68, 95],
        'first_seen': [datetime.now() - timedelta(days=2), datetime.now() - timedelta(days=1),
                      datetime.now() - timedelta(days=4), datetime.now() - timedelta(days=6),
                      datetime.now() - timedelta(days=1)],
        'source': ['OTX', 'Abuse.ch', 'OTX', 'Abuse.ch', 'OTX'],
        'risk_score': [85, 92, 78, 68, 95]
    })
    
    return {
        'vulnerabilities': sample_vulns,
        'indicators': sample_iocs,
        'last_updated': datetime.now()
    }

def main():
    st.title("🛡️ SME Threat Intelligence Platform")
    st.markdown("**Enterprise-grade threat intelligence without enterprise costs**")
    
    # Load data
    data = load_threat_data()
    
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
    ]
    
    filtered_iocs = data['indicators'][
        (data['indicators']['confidence'] >= confidence_filter) &
        (data['indicators']['first_seen'] >= datetime.now() - timedelta(days=days_back))
    ]
    
    # Executive Summary Section
    st.header("📊 Executive Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        critical_vulns = len(filtered_vulns[filtered_vulns['severity'] == 'Critical'])
        st.markdown(f"""
        <div class="metric-card critical-card">
            <h3 style="margin:0; color:#dc3545;">🚨 {critical_vulns}</h3>
            <p style="margin:0;">Critical Vulnerabilities</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        high_risk_iocs = len(filtered_iocs[filtered_iocs['risk_score'] >= 80])
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
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Priority Actions", "🦠 Vulnerabilities", "🚩 Indicators", "📊 Analytics"])
    
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
                        if st.button(f"Block IOCs for {vuln['cve_id']}", key=f"block_{vuln['cve_id']}"):
                            st.success("IOCs would be pushed to security tools (Demo)")
        
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
            
            # IOC timeline
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
            # Risk score distribution
            if not filtered_vulns.empty:
                fig_risk_dist = px.histogram(
                    filtered_vulns,
                    x='risk_score',
                    nbins=20,
                    title='Vulnerability Risk Score Distribution'
                )
                st.plotly_chart(fig_risk_dist, use_container_width=True)
        
        with col2:
            # Source reliability
            if not filtered_iocs.empty:
                source_confidence = filtered_iocs.groupby('source')['confidence'].mean().reset_index()
                fig_source = px.bar(
                    source_confidence,
                    x='source',
                    y='confidence',
                    title='Average Confidence by Source'
                )
                st.plotly_chart(fig_source, use_container_width=True)
        
        # Threat landscape overview
        st.markdown("### 🌍 Threat Landscape Overview")
        
        threat_summary = {
            'Total Vulnerabilities': len(data['vulnerabilities']),
            'Critical/High Severity': len(data['vulnerabilities'][data['vulnerabilities']['severity'].isin(['Critical', 'High'])]),
            'Total IOCs': len(data['indicators']),
            'High Confidence IOCs': len(data['indicators'][data['indicators']['confidence'] >= 80]),
            'Unique Threat Types': data['indicators']['threat_type'].nunique() if not data['indicators'].empty else 0,
            'Data Sources': len(set(data['indicators']['source'])) if not data['indicators'].empty else 0
        }
        
        summary_df = pd.DataFrame(list(threat_summary.items()), columns=['Metric', 'Value'])
        st.dataframe(summary_df, use_container_width=True, hide_index=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ SME Threat Intelligence Platform MVP | Built with ❤️ for small businesses</p>
        <p>Data sources: CISA KEV, AlienVault OTX, Abuse.ch | Auto-refresh: Every hour</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
