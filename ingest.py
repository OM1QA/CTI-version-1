"""
Data ingestion module for threat intelligence feeds
"""
import requests
import pandas as pd
from datetime import datetime, timedelta
import json
import time
import logging
from typing import List, Dict, Any
import feedparser
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseIngester:
    """Base class for all data ingesters"""
    
    def __init__(self, name: str):
        self.name = name
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SME-ThreatIntel-Platform/1.0'
        })
    
    def fetch_data(self) -> pd.DataFrame:
        """Fetch and return processed data"""
        raise NotImplementedError
    
    def _make_request(self, url: str, timeout: int = 30) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.error(f"{self.name} - Request failed for {url}: {str(e)}")
            raise

class CISAKEVIngester(BaseIngester):
    """CISA Known Exploited Vulnerabilities ingester"""
    
    def __init__(self):
        super().__init__("CISA KEV")
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def fetch_data(self) -> pd.DataFrame:
        """Fetch CISA KEV data"""
        try:
            logger.info(f"{self.name} - Fetching data from {self.url}")
            response = self._make_request(self.url)
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            # Convert to DataFrame
            df = pd.DataFrame(vulnerabilities)
            
            if df.empty:
                logger.warning(f"{self.name} - No vulnerabilities found")
                return pd.DataFrame()
            
            # Standardize column names and add metadata
            df['source'] = 'CISA KEV'
            df['ingested_at'] = datetime.now()
            df['severity'] = 'Critical'  # CISA KEV are all critical
            
            # Parse dates
            if 'dateAdded' in df.columns:
                df['date_added'] = pd.to_datetime(df['dateAdded'])
            if 'dueDate' in df.columns:
                df['due_date'] = pd.to_datetime(df['dueDate'])
            
            # Rename columns for consistency
            column_mapping = {
                'cveID': 'cve_id',
                'vendorProject': 'vendor',
                'product': 'product',
                'vulnerabilityName': 'description',
                'shortDescription': 'short_description'
            }
            
            df = df.rename(columns=column_mapping)
            
            logger.info(f"{self.name} - Successfully fetched {len(df)} vulnerabilities")
            return df
            
        except Exception as e:
            logger.error(f"{self.name} - Error fetching data: {str(e)}")
            return pd.DataFrame()

class OTXIngester(BaseIngester):
    """AlienVault OTX (Open Threat Exchange) ingester"""
    
    def __init__(self, api_key: str = None):
        super().__init__("AlienVault OTX")
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        
        if api_key:
            self.session.headers.update({'X-OTX-API-KEY': api_key})
    
    def fetch_data(self) -> pd.DataFrame:
        """Fetch OTX indicators"""
        try:
            # For demo purposes, we'll use the public pulses endpoint
            # In production, you'd want to use authenticated endpoints with more data
            url = f"{self.base_url}/pulses/subscribed"
            
            logger.info(f"{self.name} - Fetching recent pulses")
            
            # If no API key, return sample data for demo
            if not self.api_key:
                logger.info(f"{self.name} - No API key provided, returning sample data")
                return self._get_sample_otx_data()
            
            response = self._make_request(url)
            data = response.json()
            
            indicators = []
            for pulse in data.get('results', [])[:10]:  # Limit to recent pulses
                pulse_indicators = pulse.get('indicators', [])
                for indicator in pulse_indicators:
                    indicators.append({
                        'indicator': indicator.get('indicator', ''),
                        'type': indicator.get('type', '').upper(),
                        'description': indicator.get('description', ''),
                        'pulse_name': pulse.get('name', ''),
                        'created': indicator.get('created', ''),
                        'source': 'OTX',
                        'confidence': 75,  # Default confidence for OTX
                        'threat_type': self._classify_threat_type(pulse.get('tags', []))
                    })
            
            df = pd.DataFrame(indicators)
            
            if not df.empty:
                df['first_seen'] = pd.to_datetime(df['created'])
                df['ingested_at'] = datetime.now()
            
            logger.info(f"{self.name} - Successfully fetched {len(df)} indicators")
            return df
            
        except Exception as e:
            logger.error(f"{self.name} - Error fetching data: {str(e)}")
            return self._get_sample_otx_data()
    
    def _get_sample_otx_data(self) -> pd.DataFrame:
        """Return sample OTX data for demo"""
        sample_data = [
            {
                'indicator': '192.168.100.1',
                'type': 'IPv4',
                'description': 'Malicious IP associated with botnet activity',
                'pulse_name': 'Sample Botnet Campaign',
                'created': (datetime.now() - timedelta(days=1)).isoformat(),
                'source': 'OTX',
                'confidence': 85,
                'threat_type': 'Malware C2'
            },
            {
                'indicator': 'evil.example.com',
                'type': 'domain',
                'description': 'Domain hosting phishing content',
                'pulse_name': 'Phishing Campaign Analysis',
                'created': (datetime.now() - timedelta(days=2)).isoformat(),
                'source': 'OTX',
                'confidence': 90,
                'threat_type': 'Phishing'
            }
        ]
        
        df = pd.DataFrame(sample_data)
        df['first_seen'] = pd.to_datetime(df['created'])
        df['ingested_at'] = datetime.now()
        
        return df
    
    def _classify_threat_type(self, tags: List[str]) -> str:
        """Classify threat type based on tags"""
        tags_lower = [tag.lower() for tag in tags]
        
        if any(word in tags_lower for word in ['phish', 'credential', 'login']):
            return 'Phishing'
        elif any(word in tags_lower for word in ['malware', 'trojan', 'rat']):
            return 'Malware'
        elif any(word in tags_lower for word in ['ransomware', 'crypto', 'locker']):
            return 'Ransomware'
        elif any(word in tags_lower for word in ['botnet', 'c2', 'command']):
            return 'Malware C2'
        else:
            return 'Unknown'

class AbuseCHIngester(BaseIngester):
    """Abuse.ch threat intelligence ingester"""
    
    def __init__(self):
        super().__init__("Abuse.ch")
        self.threatfox_url = "https://threatfox.abuse.ch/api/"
        self.urlhaus_url = "https://urlhaus-api.abuse.ch/v1/"
    
    def fetch_data(self) -> pd.DataFrame:
        """Fetch data from Abuse.ch feeds"""
        try:
            indicators = []
            
            # Fetch recent IOCs from ThreatFox
            threatfox_data = self._fetch_threatfox_data()
            indicators.extend(threatfox_data)
            
            # Fetch recent URLs from URLhaus
            urlhaus_data = self._fetch_urlhaus_data()
            indicators.extend(urlhaus_data)
            
            df = pd.DataFrame(indicators)
            
            if not df.empty:
                df['source'] = 'Abuse.ch'
                df['ingested_at'] = datetime.now()
                df['first_seen'] = pd.to_datetime(df['first_seen'])
            
            logger.info(f"{self.name} - Successfully fetched {len(df)} indicators")
            return df
            
        except Exception as e:
            logger.error(f"{self.name} - Error fetching data: {str(e)}")
            return self._get_sample_abuse_data()
    
    def _fetch_threatfox_data(self) -> List[Dict]:
        """Fetch data from ThreatFox API"""
        try:
            # Get recent IOCs
            payload = {
                "query": "get_iocs",
                "days": 7
            }
            
            response = requests.post(self.threatfox_url, json=payload, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            indicators = []
            
            for ioc in data.get('data', [])[:50]:  # Limit to 50 recent IOCs
                indicators.append({
                    'indicator': ioc.get('ioc', ''),
                    'type': self._normalize_ioc_type(ioc.get('ioc_type', '')),
                    'threat_type': ioc.get('malware_printable', 'Unknown'),
                    'confidence': ioc.get('confidence_level', 50),
                    'first_seen': ioc.get('first_seen', ''),
                    'description': f"Associated with {ioc.get('malware_printable', 'malware')}"
                })
            
            return indicators
            
        except Exception as e:
            logger.error(f"{self.name} - Error fetching ThreatFox data: {str(e)}")
            return []
    
    def _fetch_urlhaus_data(self) -> List[Dict]:
        """Fetch data from URLhaus API"""
        try:
            # Get recent URLs
            payload = {"query": "get_payloads", "days": 7}
            
            response = requests.post(f"{self.urlhaus_url}payloads/recent/", 
                                   json=payload, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            indicators = []
            
            for item in data.get('query_status') == 'ok' and data.get('payloads', [])[:25]:
                indicators.append({
                    'indicator': item.get('sha256_hash', ''),
                    'type': 'Hash',
                    'threat_type': 'Malware',
                    'confidence': 80,
                    'first_seen': item.get('firstseen', ''),
                    'description': f"Malware payload: {item.get('file_type', 'unknown')}"
                })
            
            return indicators
            
        except Exception as e:
            logger.error(f"{self.name} - Error fetching URLhaus data: {str(e)}")
            return []
    
    def _get_sample_abuse_data(self) -> pd.DataFrame:
        """Return sample Abuse.ch data for demo"""
        sample_data = [
            {
                'indicator': 'bad-domain.example.com',
                'type': 'Domain',
                'threat_type': 'Malware',
                'confidence': 95,
                'first_seen': (datetime.now() - timedelta(days=1)).isoformat(),
                'description': 'Domain hosting malware payload',
                'source': 'Abuse.ch'
            },
            {
                'indicator': 'a1b2c3d4e5f6789',
                'type': 'Hash',
                'threat_type': 'Ransomware',
                'confidence': 88,
                'first_seen': (datetime.now() - timedelta(days=3)).isoformat(),
                'description': 'Ransomware payload hash',
                'source': 'Abuse.ch'
            }
        ]
        
        df = pd.DataFrame(sample_data)
        df['first_seen'] = pd.to_datetime(df['first_seen'])
        df['ingested_at'] = datetime.now()
        
        return df
    
    def _normalize_ioc_type(self, ioc_type: str) -> str:
        """Normalize IOC types to standard format"""
        type_mapping = {
            'ip:port': 'IP',
            'domain': 'Domain',
            'url': 'URL',
            'md5_hash': 'Hash',
            'sha1_hash': 'Hash',
            'sha256_hash': 'Hash'
        }
        
        return type_mapping.get(ioc_type.lower(), ioc_type.upper())
