import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import time
import feedparser
from bs4 import BeautifulSoup
import hashlib
import re

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

# News-related helper functions
import re
from collections import defaultdict
from datetime import timezone

# Configuration constants
TOTAL_ITEMS_IN_FEED = 40
MIN_PER_SOURCE_IN_FEED = 2
MAX_PER_SOURCE_IN_FEED = 8
MAX_EXTRACT_SIZE = 150 * 1024  # 150KB limit for extracted text

# Enhanced tagging data
ACTORS = {"ALPHV", "BlackCat", "Scattered Spider", "Lapsus$", "FIN7", "Wizard Spider", "TA505", "APT29", "APT28"}
PRIORITY_TOPICS = {
    "ransomware": "topic:ransomware",
    "0-day": "topic:0day", "zero-day": "topic:0day",
    "phishing": "topic:phishing",
    "data breach": "topic:breach", "breach": "topic:breach",
    "credentials": "topic:credentials",
    "mfa": "topic:mfa",
    "supply chain": "topic:supply-chain",
}
VENDOR_KEYWORDS = ["microsoft", "office 365", "microsoft 365", "fortinet", "citrix", "atlassian", "progress",
                   "vpn", "rdp", "exchange", "cisco", "vmware", "palo alto", "linux", "windows", "macos", 
                   "quickbooks", "invoice"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Whitelisted sources for full content extraction
EXTRACT_WHITELIST = {
    "The Hacker News", "BleepingComputer", "Palo Alto Unit 42", 
    "Microsoft Security Blog", "Cisco Talos", "CISA Alerts", "UK NCSC News", "ENISA News"
}

def stable_id(title, link):
    """Generate stable ID for news items"""
    return hashlib.sha256(f"{title}|{link}".encode()).hexdigest()[:16]

def parse_rss_date(date_string):
    """Parse various RSS date formats with timezone awareness"""
    try:
        import feedparser
        parsed_date = feedparser._parse_date(date_string)
        if parsed_date:
            dt = datetime(*parsed_date[:6])
            # Make timezone-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    except:
        pass
    
    # Fallback to current time with UTC timezone
    return datetime.now(timezone.utc)

def extract_full_content(url, source_name):
    """Extract full article content for whitelisted sources"""
    if source_name not in EXTRACT_WHITELIST:
        return ""
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        if len(response.content) > MAX_EXTRACT_SIZE:
            return ""
        
        soup = BeautifulSoup(response.content, 'lxml')
        
        # Remove scripts and style elements
        for script in soup(["script", "style", "nav", "footer", "header", "aside"]):
            script.decompose()
        
        # Try to find main content
        content = soup.find('article') or soup.find('main') or soup.find('div', class_='content')
        if not content:
            content = soup.find('body')
        
        if content:
            text = content.get_text()
            return text[:MAX_EXTRACT_SIZE] if len(text) > MAX_EXTRACT_SIZE else text
        
        return ""
    except:
        return ""

def tag_item(text: str) -> list[str]:
    """Enhanced tagging with comprehensive detection"""
    tags = set()
    
    # CVE detection
    for match in CVE_RE.findall(text):
        tags.add(f"cve:{match.upper()}")
    
    text_lower = text.lower()
    
    # Threat actor detection
    for actor in ACTORS:
        if actor.lower() in text_lower:
            tags.add(f"actor:{actor}")
    
    # Priority topic detection
    for keyword, tag in PRIORITY_TOPICS.items():
        if keyword in text_lower:
            tags.add(tag)
    
    # Vendor keyword detection
    for vendor in VENDOR_KEYWORDS:
        if vendor in text_lower:
            tags.add(f"vendor:{vendor}")
    
    return sorted(tags)

def time_decay(published_dt: datetime) -> float:
    """Calculate time decay factor for relevance scoring"""
    if not published_dt:
        return 0.8
    
    try:
        # Ensure both timestamps are timezone-aware
        now = datetime.now(timezone.utc)
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        
        days = (now - published_dt).days
        
        if days <= 2:
            return 1.25
        elif days <= 7:
            return 1.0
        elif days <= 14:
            return 0.8
        else:
            return 0.6
    except:
        return 0.8

def compute_relevance(item: dict) -> int:
    """Compute relevance score based on tags and time"""
    tags = item.get("tags", [])
    
    cves = [t for t in tags if t.startswith("cve:")]
    actors = [t for t in tags if t.startswith("actor:")]
    topics = [t for t in tags if t.startswith("topic:")]
    vendors = [t for t in tags if t.startswith("vendor:")]
    
    score = 0
    
    # CVE points (max 12)
    score += min(len(set(cves)) * 4, 12)
    
    # Actor points (max 9)
    score += min(len(set(actors)) * 3, 9)
    
    # Priority topic points (max 6)
    priority_topics = {"topic:ransomware", "topic:0day", "topic:breach"}
    score += min(sum(1 for t in topics if t in priority_topics) * 2, 6)
    
    # Vendor points (max 3)
    score += min(len(set(vendors)), 3)
    
    # SME relevance bump
    sme_vendors = ["vendor:microsoft", "vendor:microsoft 365", "vendor:office 365", "vendor:vpn", 
                   "vendor:rdp", "vendor:quickbooks"]
    sme_topics = ["topic:phishing", "topic:credentials"]
    
    if any(v in vendors for v in sme_vendors) or any(t in topics for t in sme_topics):
        score += 2
    
    # Apply time decay
    score = int(round(score * time_decay(item.get("published_dt"))))
    
    return max(score, 0)

def mix_items_scored(items: list[dict]) -> list[dict]:
    """Mix items across sources for balanced representation"""
    by_src = defaultdict(list)
    
    # Group by source and sort by relevance/date
    for item in items:
        by_src[item["source"]].append(item)
    
    for source in by_src:
        by_src[source].sort(
            key=lambda x: (x["relevance_score"], x["published_dt"] or datetime.min.replace(tzinfo=timezone.utc)), 
            reverse=True
        )
    
    picked = []
    
    # First pass: ensure minimum per source
    for _ in range(MIN_PER_SOURCE_IN_FEED):
        for source in list(by_src.keys()):
            if by_src[source] and sum(1 for x in picked if x["source"] == source) < MAX_PER_SOURCE_IN_FEED:
                picked.append(by_src[source].pop(0))
                if len(picked) >= TOTAL_ITEMS_IN_FEED:
                    return picked
    
    # Second pass: fill remaining slots
    while len(picked) < TOTAL_ITEMS_IN_FEED:
        progressed = False
        for source in list(by_src.keys()):
            if by_src[source] and sum(1 for x in picked if x["source"] == source) < MAX_PER_SOURCE_IN_FEED:
                picked.append(by_src[source].pop(0))
                progressed = True
                if len(picked) >= TOTAL_ITEMS_IN_FEED:
                    break
        if not progressed:
            break
    
    return picked

@st.cache_data(ttl=7200, show_spinner=False)  # Cache for 2 hours
def load_news():
    """Load cybersecurity news from RSS feeds with enhanced processing"""
    sources = [
        ("CISA Alerts", "https://www.cisa.gov/news-events/alerts/all.xml"),
        ("UK NCSC News", "https://www.ncsc.gov.uk/api/1/services/v1/news.rss"),
        ("ENISA News", "https://www.enisa.europa.eu/news/rss"),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
        ("Cisco Talos", "https://blog.talosintelligence.com/feed/"),
        ("Microsoft Security Blog", "https://www.microsoft.com/security/blog/feed/"),
        ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/")
    ]
    
    all_news = []
    
    for source_name, url in sources:
        try:
            # Parse RSS feed
            feed = feedparser.parse(url)
            
            # Check if feed parsed successfully
            if hasattr(feed, 'entries') and feed.entries:
                for entry in feed.entries[:30]:  # Increased from 10 to 30
                    try:
                        title = entry.get('title', 'No title')
                        link = entry.get('link', '')
                        summary = entry.get('summary', entry.get('description', ''))
                        
                        # Clean summary HTML
                        if summary:
                            soup = BeautifulSoup(summary, 'html.parser')
                            summary = soup.get_text().strip()
                        
                        # Parse publication date with timezone awareness
                        pub_date = entry.get('published', entry.get('pubDate', ''))
                        parsed_date = parse_rss_date(pub_date) if pub_date else datetime.now(timezone.utc)
                        
                        # Combine text for tagging
                        full_text = f"{title} {summary}"
                        
                        # Extract full content for whitelisted sources
                        if source_name in EXTRACT_WHITELIST and link:
                            full_content = extract_full_content(link, source_name)
                            if full_content:
                                full_text += f" {full_content}"
                        
                        # Extract tags
                        tags = tag_item(full_text)
                        
                        news_item = {
                            'id': stable_id(title, link),
                            'source': source_name,
                            'title': title,
                            'link': link,
                            'published_dt': parsed_date,
                            'summary_raw': summary,
                            'tags': tags,
                            'pub_date_str': pub_date
                        }
                        
                        # Compute relevance score
                        news_item['relevance_score'] = compute_relevance(news_item)
                        
                        all_news.append(news_item)
                        
                    except Exception as e:
                        continue  # Skip problematic entries
                        
        except Exception as e:
            # Silent failure as specified
            continue
    
    # Mix items for balanced representation
    mixed_news = mix_items_scored(all_news)
    
    return mixed_news

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
            response = requests.get(self.api_url, timeout=15)
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
            
            response = requests.get(pulses_url, headers=headers, params=params, timeout=15)
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
                        'confidence': min(85 + len(pulse.get('references', [])) * 5, 100),
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
    """Ingest Abuse.ch threat intelligence using authenticated APIs"""
    def __init__(self):
        super().__init__()
        self.source_name = "Abuse.ch"
        self.api_key = st.secrets.get("ABUSE_CH_API_KEY", "")
        self.apis = {
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1/',
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1/'
        }
    
    def fetch_data(self):
        """Fetch real Abuse.ch indicators using authenticated APIs"""
        if not self.api_key:
            st.warning("Abuse.ch API key not found. Using sample data.")
            return self.get_sample_data()
        
        try:
            all_indicators = []
            
            # Fetch from ThreatFox (IOCs) with timeout protection
            try:
                threatfox_data = self.fetch_threatfox()
                all_indicators.extend(threatfox_data)
            except Exception as e:
                st.warning(f"ThreatFox failed: {str(e)}")
            
            # Fetch from URLhaus (malicious URLs) with timeout protection
            try:
                urlhaus_data = self.fetch_urlhaus()
                all_indicators.extend(urlhaus_data)
            except Exception as e:
                st.warning(f"URLhaus failed: {str(e)}")
            
            # Return combined data
            if all_indicators:
                return pd.DataFrame(all_indicators[:30])
            else:
                return self.get_sample_data()
            
        except Exception as e:
            st.warning(f"Failed to fetch Abuse.ch data: {str(e)}. Using sample data.")
            return self.get_sample_data()
    
    def fetch_threatfox(self):
        """Fetch IOCs from ThreatFox using authenticated API"""
        try:
            payload = {
                'query': 'get_iocs',
                'days': 7
            }
            
            headers = {
                'Auth-Key': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'SME-TIP/1.0'
            }
            
            response = requests.post(
                self.apis['threatfox'], 
                json=payload,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()
            
            result = response.json()
            indicators = []
            
            if result.get('query_status') == 'ok':
                for ioc_entry in result.get('data', [])[:15]:
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
            
            return indicators
            
        except Exception as e:
            st.warning(f"ThreatFox API error: {str(e)}")
            return []
    
    def fetch_urlhaus(self):
        """Fetch malicious URLs from URLhaus using authenticated API"""
        try:
            payload = {
                'query': 'get_urls',
                'days': 3
            }
            
            headers = {
                'Auth-Key': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'SME-TIP/1.0'
            }
            
            response = requests.post(
                self.apis['urlhaus'],
                json=payload,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()
            
            result = response.json()
            indicators = []
            
            if result.get('query_status') == 'ok':
                for url_entry in result.get('urls', [])[:15]:
                    url = url_entry.get('url', '')
                    if not url:
                        continue
                    
                    # Extract domain from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        domain = parsed.netloc if parsed.netloc else url.split('/')[0]
                    except:
                        domain = url.split('/')[0] if '/' in url else url
                    
                    if not domain:
                        continue
                    
                    indicators.append({
                        'indicator': domain,
                        'type': 'hostname',
                        'threat_type': self.classify_urlhaus_threat(url_entry.get('tags', [])),
                        'confidence': self.calculate_urlhaus_confidence(url_entry),
                        'first_seen': self.parse_abuse_date(url_entry.get('date_added', '')),
                        'source': 'Abuse.ch URLhaus',
                        'campaign': url_entry.get('threat', 'Malicious URL'),
                        'url_status': url_entry.get('url_status', 'unknown'),
                        'full_url': url
                    })
            
            return indicators
            
        except Exception as e:
            st.warning(f"URLhaus API error: {str(e)}")
            return []
    
    def classify_threatfox_threat(self, malware_name):
        """Classify threat type based on malware family"""
        malware_lower = str(malware_name).lower()
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
    
    def classify_urlhaus_threat(self, tags):
        """Classify threat type based on URLhaus tags"""
        if not tags:
            return 'Malware C2'
        
        tags_str = ' '.join(tags).lower()
        if any(word in tags_str for word in ['emotet', 'trickbot', 'qakbot']):
            return 'Banking Trojan'
        elif any(word in tags_str for word in ['ransomware', 'lockbit', 'ryuk', 'sodinokibi']):
            return 'Ransomware'
        elif any(word in tags_str for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in tags_str for word in ['cobalt', 'beacon']):
            return 'APT Activity'
        elif any(word in tags_str for word in ['stealer', 'redline', 'vidar']):
            return 'Credential Theft'
        elif any(word in tags_str for word in ['malware', 'trojan']):
            return 'Malware C2'
        else:
            return 'Malicious Infrastructure'
    
    def calculate_threatfox_confidence(self, ioc_entry):
        """Calculate confidence score for ThreatFox entries"""
        base_confidence = 80
        confidence_rating = ioc_entry.get('confidence_level', 50)
        base_confidence = max(base_confidence, confidence_rating)
        return min(base_confidence, 98)
    
    def calculate_urlhaus_confidence(self, url_entry):
        """Calculate confidence score for URLhaus entries"""
        base_confidence = 80
        
        if url_entry.get('url_status') == 'online':
            base_confidence += 10
        
        tags_count = len(url_entry.get('tags', []))
        base_confidence += min(tags_count * 2, 10)
        
        threat = str(url_entry.get('threat', '')).lower()
        if any(family in threat for family in ['emotet', 'trickbot', 'cobalt', 'ransomware']):
            base_confidence += 5
        
        return min(base_confidence, 98)
    
    def normalize_ioc_type(self, ioc_type):
        """Normalize IOC types to standard format"""
        type_mapping = {
            'ip:port': 'IPv4',
            'domain': 'hostname',
            'url': 'URL',
            'md5_hash': 'FileHash-MD5',
            'sha1_hash': 'FileHash-SHA1',
            'sha256_hash': 'FileHash-SHA256',
            'email': 'email-addr'
        }
        return type_mapping.get(ioc_type.lower(), ioc_type)
    
    def parse_abuse_date(self, date_string):
        """Parse Abuse.ch date format"""
        try:
            if not date_string:
                return datetime.now() - timedelta(days=1)
            
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
        
        def calculate_vuln_risk(row):
            base_score = row.get('cvss_score', 5.0) * 10
            
            if row.get('source') == 'CISA KEV':
                base_score = max(base_score, 95)
            
            days_old = (datetime.now() - row.get('date_added', datetime.now())).days
            age_factor = max(1.0 - (days_old / 365), 0.5)
            
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
            
            threat_severity = self.threat_severity_map.get(threat_type, 50)
            risk_score = (confidence * 0.6) + (threat_severity * 0.4)
            
            days_old = (datetime.now() - row.get('first_seen', datetime.now())).days
            if days_old <= 7:
                risk_score *= 1.1
            elif days_old <= 30:
                risk_score *= 1.05
            
            return min(int(risk_score), 100)
        
        ioc_df = ioc_df.copy()
        ioc_df['risk_score'] = ioc_df.apply(calculate_ioc_risk, axis=1)
        return ioc_df

@st.cache_data(ttl=3600, show_spinner=False)
def load_threat_data():
    """Load and process threat intelligence data"""
    try:
        cisa_ingester = CISAKEVIngester()
        otx_ingester = OTXIngester()
        abuse_ingester = AbuseCHIngester()
        
        scorer = RiskScorer()
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Loading CISA KEV vulnerabilities...")
        progress_bar.progress(10)
        cisa_data = cisa_ingester.fetch_data()
        
        status_text.text("Loading OTX threat intelligence...")
        progress_bar.progress(40)
        otx_data = otx_ingester.fetch_data()
        
        status_text.text("Loading Abuse.ch indicators...")
        progress_bar.progress(70)
        abuse_data = abuse_ingester.fetch_data()
        
        status_text.text("Processing and scoring threats...")
        progress_bar.progress(90)
        
        combined_iocs = pd.DataFrame()
        if not otx_data.empty and not abuse_data.empty:
            combined_iocs = pd.concat([otx_data, abuse_data], ignore_index=True)
        elif not otx_data.empty:
            combined_iocs = otx_data
        elif not abuse_data.empty:
            combined_iocs = abuse_data
        
        processed_data = {
            'vulnerabilities': scorer.score_vulnerabilities(cisa_data),
            'indicators': scorer.score_indicators(combined_iocs),
            'last_updated': datetime.now()
        }
        
        progress_bar.progress(100)
        status_text.text("✅ Threat data loaded successfully!")
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        return processed_data
    
    except Exception as e:
        st.error(f"Error loading threat data: {str(e)}")
        return {
            'vulnerabilities': pd.DataFrame(),
            'indicators': pd.DataFrame(),
            'last_updated': datetime.now()
        }

@st.cache_data(ttl=1800, show_spinner=False)
def load_threat_data_quick():
    """Load only CISA KEV data for quick startup"""
    try:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Loading CISA KEV vulnerabilities (Quick Mode)...")
        progress_bar.progress(50)
        
        cisa_ingester = CISAKEVIngester()
        cisa_data = cisa_ingester.fetch_data()
        
        scorer = RiskScorer()
        
        status_text.text("Processing vulnerabilities...")
        progress_bar.progress(90)
        
        processed_data = {
            'vulnerabilities': scorer.score_vulnerabilities(cisa_data),
            'indicators': pd.DataFrame(),
            'last_updated': datetime.now()
        }
        
        progress_bar.progress(100)
        status_text.text("✅ Quick mode loaded!")
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        return processed_data
        
    except Exception as e:
        st.error(f"Error in quick mode: {str(e)}")
        return {
            'vulnerabilities': pd.DataFrame(),
            'indicators': pd.DataFrame(),
            'last_updated': datetime.now()
        }

def main():
    st.title("🛡️ SME Threat Intelligence Platform")
    st.markdown("**Enterprise-grade threat intelligence without enterprise costs**")
    
    # Add a quick mode toggle
    with st.sidebar:
        st.header("⚙️ Settings")
        quick_mode = st.checkbox("Quick Mode (Skip slow APIs)", value=False, help="Skip OTX and Abuse.ch if they're slow")
    
    # Load data with optional quick mode
    if quick_mode:
        data = load_threat_data_quick()
    else:
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
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("CISA KEV", f"{len(data['vulnerabilities'])} vulnerabilities")
        with col2:
            otx_count = len(data['indicators'][data['indicators']['source'] == 'OTX']) if not data['indicators'].empty else 0
            st.metric("AlienVault OTX", f"{otx_count} indicators")
        with col3:
            threatfox_count = len(data['indicators'][data['indicators']['source'] == 'Abuse.ch ThreatFox']) if not data['indicators'].empty else 0
            st.metric("ThreatFox", f"{threatfox_count} IOCs")
        with col4:
            urlhaus_count = len(data['indicators'][data['indicators']['source'] == 'Abuse.ch URLhaus']) if not data['indicators'].empty else 0
            st.metric("URLhaus", f"{urlhaus_count} URLs")
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 Priority Actions", "🦠 Vulnerabilities", "🚩 Indicators", "📊 Analytics", "📰 News"])
    
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
        st.markdown("### 🌐 Threat Landscape Overview")
        
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
    
    with tab5:
        st.subheader("📰 Latest Cybersecurity News & Intelligence")
        
        # Enhanced sidebar filters for news
        with st.sidebar:
            st.markdown("---")
            st.markdown("**📰 News Filters**")
            
            # Freshness slider
            freshness_days = st.slider(
                "Freshness (days)",
                min_value=1,
                max_value=30,
                value=7,
                help="Show news from the last N days"
            )
            
            # Topics multiselect
            available_topics = [
                "All Topics",
                "CVE/Vulnerability", 
                "Ransomware",
                "Phishing", 
                "Data Breach",
                "APT/Nation-State",
                "Zero-Day",
                "Supply Chain",
                "Microsoft/Office 365",
                "VPN/Remote Access"
            ]
            
            selected_topics = st.multiselect(
                "Filter by Topics",
                available_topics[1:],  # Exclude "All Topics" from multiselect
                default=[],
                help="Select specific topics to focus on"
            )
        
        # Load news data
        try:
            with st.spinner("Loading latest cybersecurity intelligence..."):
                news_items = load_news()
            
            if not news_items:
                st.warning("No news items could be loaded. Please check your internet connection.")
            else:
                # Apply freshness filter
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=freshness_days)
                filtered_news = [
                    item for item in news_items 
                    if item.get('published_dt', datetime.min.replace(tzinfo=timezone.utc)) >= cutoff_date
                ]
                
                # Apply topic filters
                if selected_topics:
                    topic_map = {
                        "CVE/Vulnerability": ["cve:", "topic:vulnerability", "topic:0day"],
                        "Ransomware": ["topic:ransomware"],
                        "Phishing": ["topic:phishing"],
                        "Data Breach": ["topic:breach"],
                        "APT/Nation-State": ["actor:", "topic:apt"],
                        "Zero-Day": ["topic:0day"],
                        "Supply Chain": ["topic:supply-chain"],
                        "Microsoft/Office 365": ["vendor:microsoft", "vendor:office 365", "vendor:microsoft 365"],
                        "VPN/Remote Access": ["vendor:vpn", "vendor:rdp"]
                    }
                    
                    topic_filtered = []
                    for item in filtered_news:
                        item_tags = item.get('tags', [])
                        for selected_topic in selected_topics:
                            target_tags = topic_map.get(selected_topic, [])
                            if any(any(tag.startswith(target) for target in target_tags) for tag in item_tags):
                                topic_filtered.append(item)
                                break
                    filtered_news = topic_filtered
                
                # Display summary metrics (simplified)
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📰 Articles", len(filtered_news))
                with col2:
                    cve_count = len([item for item in filtered_news if any('cve:' in tag for tag in item.get('tags', []))])
                    st.metric("🔍 CVE Mentions", cve_count)
                with col3:
                    high_relevance = len([item for item in filtered_news if item.get('relevance_score', 0) >= 5])
                    st.metric("⚠️ High Relevance", high_relevance)
                
                st.markdown("---")
                
                # Display news items with enhanced formatting
                if filtered_news:
                    for i, item in enumerate(filtered_news):
                        with st.container():
                            # Title (bold headline)
                            st.markdown(f"**{item['title']}**")
                            
                            # Tags as chips (if any)
                            if item.get('tags'):
                                # Prioritize important tags for display
                                important_tags = []
                                other_tags = []
                                
                                for tag in item['tags'][:6]:  # Limit to 6 tags max
                                    if any(tag.startswith(prefix) for prefix in ['cve:', 'actor:', 'topic:ransomware', 'topic:0day', 'topic:breach']):
                                        important_tags.append(tag)
                                    else:
                                        other_tags.append(tag)
                                
                                display_tags = important_tags + other_tags[:6-len(important_tags)]
                                if display_tags:
                                    tag_display = " ".join([f"`{tag}`" for tag in display_tags])
                                    st.markdown(tag_display)
                            
                            # Summary (always visible, 2-3 lines) - preserving our earlier change
                            if item.get('summary_raw'):
                                summary_text = item['summary_raw'][:300] + "..." if len(item['summary_raw']) > 300 else item['summary_raw']
                                st.write(summary_text)
                            
                            # Read more link (source attribution only here)
                            if item.get('link'):
                                st.markdown(f"[🔗 Read full article]({item['link']})")
                            
                            # Date only (muted, at bottom) - preserving our earlier change
                            if item.get('published_dt'):
                                st.caption(f"📅 {item['published_dt'].strftime('%Y-%m-%d %H:%M UTC')}")
                            
                            # Relevance score for debugging (remove in production)
                            if item.get('relevance_score', 0) > 0:
                                st.caption(f"Relevance: {item['relevance_score']}")
                            
                            st.markdown("---")
                else:
                    st.info("No recent items matched your filters. Try adjusting the freshness slider or removing topic filters.")
                    
        except Exception as e:
            st.error(f"Error loading news: {str(e)}")
            st.info("Please check your internet connection and try refreshing the page.")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ SME Threat Intelligence Platform MVP | Built with ❤️ for small businesses</p>
        <p>Data sources: CISA KEV (Live), AlienVault OTX (Live), Abuse.ch ThreatFox (Live), Abuse.ch URLhaus (Live), 8 News Sources (Live) | Auto-refresh: Every hour</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
