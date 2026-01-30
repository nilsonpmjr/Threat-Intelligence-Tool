import os
import requests
import logging
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatIntelClient:
    """
    Client for querying multiple Threat Intelligence APIs.
    Handles authentication, request formatting, and graceful degradation.
    """

    def __init__(self):
        self.services = {
            'virustotal': False,
            'abuseipdb': False,
            'shodan': False,
            'alienvault': False,
            'greynoise': False,
            'urlscan': False
        }
        self.api_keys = {}
        self._load_keys()

    def _load_keys(self):
        """Loads API keys from environment variables and updates service status."""
        keys_map = {
            'virustotal': 'VT_API_KEY',
            'abuseipdb': 'ABUSEIPDB_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'alienvault': 'OTX_API_KEY',
            'greynoise': 'GREYNOISE_API_KEY',
            'urlscan': 'URLSCAN_API_KEY'
        }

        for service, env_var in keys_map.items():
            key = os.environ.get(env_var)
            if key:
                self.api_keys[service] = key
                self.services[service] = True
                logger.debug(f"{service} enabled.")
            else:
                self.services[service] = False
                logger.debug(f"{service} disabled (missing {env_var}).")

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        try:
            response = requests.request(method, url, timeout=10, **kwargs)
            
            if response.status_code == 404:
                return {"_meta_error": "not_found", "_meta_msg": "Not found in database"}
            if response.status_code == 403:
                return {"_meta_error": "forbidden", "_meta_msg": "Access Denied (Check Quota/Key)"}
            if response.status_code == 401:
                return {"_meta_error": "unauthorized", "_meta_msg": "Invalid API Key"}
                
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying {url}")
            return {"_meta_error": "timeout", "_meta_msg": "Request Timed Out"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying {url}: {e}")
            return {"_meta_error": "generic", "_meta_msg": str(e)}
        except Exception as e:
             logger.error(f"Unexpected error {url}: {e}")
             return {"_meta_error": "generic", "_meta_msg": str(e)}

    def query_virustotal(self, target: str, type_hint: str) -> Optional[Dict[str, Any]]:
        """
        Query VirusTotal API.
        :param target: IP, Domain, or Hash
        :param type_hint: 'ip', 'domain', 'file'
        """
        if not self.services['virustotal']:
            return None

        endpoint_map = {
            'ip': 'ip_addresses',
            'domain': 'domains',
            'file': 'files'
        }
        
        endpoint = endpoint_map.get(type_hint)
        if not endpoint:
            logger.error(f"Invalid type_hint '{type_hint}' for VirusTotal")
            return None

        url = f"https://www.virustotal.com/api/v3/{endpoint}/{target}"
        headers = {"x-apikey": self.api_keys['virustotal']}
        
        return self._safe_request("GET", url, headers=headers)

    def query_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API for IP reputation."""
        if not self.services['abuseipdb']:
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': self.api_keys['abuseipdb'],
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        
        return self._safe_request("GET", url, headers=headers, params=params)

    def query_shodan(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query Shodan API for IP host info."""
        if not self.services['shodan']:
            return None

        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.api_keys['shodan']}
        
        return self._safe_request("GET", url, params=params)

    def query_alienvault(self, target: str, type_hint: str) -> Optional[Dict[str, Any]]:
        """
        Query AlienVault OTX API.
        :param type_hint: 'IPv4', 'domain', 'file'
        """
        if not self.services['alienvault']:
            return None

        # Map generic hints to OTX specific types if necessary
        otx_type = type_hint
        if type_hint == 'ip': otx_type = 'IPv4'
        
        valid_types = ['IPv4', 'domain', 'file']
        if otx_type not in valid_types:
             # Fallback or strict check
             return None

        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{target}/general"
        headers = {"X-OTX-API-KEY": self.api_keys['alienvault']}
        
        return self._safe_request("GET", url, headers=headers)

    def query_greynoise(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query GreyNoise Community API."""
        if not self.services['greynoise']:
            return None

        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": self.api_keys['greynoise']}
        
        return self._safe_request("GET", url, headers=headers)

    def query_urlscan(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query UrlScan.io for domain scans."""
        if not self.services['urlscan']:
            return None

        url = "https://urlscan.io/api/v1/search/"
        headers = {"API-Key": self.api_keys['urlscan']}
        params = {"q": f"domain:{domain}"}
        
        return self._safe_request("GET", url, headers=headers, params=params)
