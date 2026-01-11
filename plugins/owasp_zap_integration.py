# plugins/owasp_zap_integration.py
"""
OWASP ZAP integration for ZeroTrustDjango Scanner
"""

import requests
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

class OWASPZAPIntegration:
    """Integration with OWASP ZAP for automated security testing"""
    
    def __init__(self, zap_host: str = "http://localhost:8080", api_key: str = None):
        self.zap_host = zap_host
        self.api_key = api_key
        self.session = requests.Session()
        
    def start_scan(self, target_url: str, scan_policy: str = "Default Policy") -> str:
        """Start an active scan on target URL"""
        
        # Start the scan
        params = {
            "url": target_url,
            "recurse": True,
            "inScopeOnly": True,
            "scanPolicyName": scan_policy,
            "method": "GET",
            "postData": ""
        }
        
        if self.api_key:
            params["apikey"] = self.api_key
            
        response = self.session.get(
            urljoin(self.zap_host, "/JSON/ascan/action/scan/"),
            params=params
        )
        
        if response.status_code == 200:
            scan_id = response.json().get("scan")
            return scan_id
        else:
            raise Exception(f"Failed to start scan: {response.text}")
            
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get status of a running scan"""
        params = {"scanId": scan_id}
        if self.api_key:
            params["apikey"] = self.api_key
            
        response = self.session.get(
            urljoin(self.zap_host, "/JSON/ascan/view/status/"),
            params=params
        )
        
        return response.json()
        
    def get_alerts(self, base_url: str = None, risk_level: str = None) -> List[Dict[str, Any]]:
        """Get alerts from ZAP"""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        if risk_level:
            params["riskId"] = self._risk_level_to_id(risk_level)
        if self.api_key:
            params["apikey"] = self.api_key
            
        response = self.session.get(
            urljoin(self.zap_host, "/JSON/core/view/alerts/"),
            params=params
        )
        
        if response.status_code == 200:
            return response.json().get("alerts", [])
        else:
            return []
            
    def generate_report(self, report_format: str = "html") -> str:
        """Generate a report from ZAP"""
        params = {"title": "ZeroTrustDjango Security Scan"}
        if self.api_key:
            params["apikey"] = self.api_key
            
        endpoint = f"/OTHER/core/other/{report_format}report/"
        
        response = self.session.get(
            urljoin(self.zap_host, endpoint),
            params=params
        )
        
        return response.text
        
    def _risk_level_to_id(self, risk_level: str) -> str:
        """Convert risk level string to ZAP risk ID"""
        risk_map = {
            "high": "3",
            "medium": "2",
            "low": "1",
            "info": "0"
        }
        return risk_map.get(risk_level.lower(), "0")
        
    def integrate_with_scanner(self, scanner_issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Integrate ZAP findings with scanner issues"""
        
        # Get high and medium risk alerts from ZAP
        zap_alerts = self.get_alerts(risk_level="high") + self.get_alerts(risk_level="medium")
        
        # Convert ZAP alerts to scanner issue format
        zap_issues = []
        for alert in zap_alerts:
            zap_issues.append({
                "severity": self._zap_risk_to_severity(alert.get("risk")),
                "category": "OWASP ZAP Finding",
                "title": alert.get("alert"),
                "description": alert.get("description", ""),
                "location": alert.get("url", ""),
                "recommendation": alert.get("solution", ""),
                "cwe_id": alert.get("cweid", ""),
                "source": "OWASP ZAP"
            })
            
        # Merge with scanner issues
        all_issues = scanner_issues + zap_issues
        
        return all_issues
        
    def _zap_risk_to_severity(self, risk: str) -> str:
        """Convert ZAP risk level to scanner severity"""
        risk_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO"
        }
        return risk_map.get(risk, "INFO")
