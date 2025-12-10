import requests
import json
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any
from playwright.sync_api import Request as PlaywrightRequest

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\" onmouseover=\"alert('XSS')",
    "'>\"><img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')"
]

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()

    def _prepare_session_from_playwright(self, playwright_request: PlaywrightRequest):
        """Kopiuje nagłówki i ciasteczka z Playwright."""
        headers = playwright_request.headers
        headers_to_skip = ['content-length', 'content-type', 'accept-encoding']
        clean_headers = {k: v for k, v in headers.items() if k.lower() not in headers_to_skip}
        self.session.headers.update(clean_headers)

    def scan_request(self, playwright_request: PlaywrightRequest) -> List[Dict]:
        """Główna metoda skanująca."""
        if playwright_request.resource_type in ['image', 'stylesheet', 'font', 'script', 'media']:
            return []

        print(f"\n[XSS] Analiza zapytania: {playwright_request.url}")
        
        self._prepare_session_from_playwright(playwright_request)
        
        url = playwright_request.url
        method = playwright_request.method
        post_data = playwright_request.post_data
        findings = []

        if (post_data and post_data.strip().startswith("{")):
            try:
                json_data = json.loads(post_data)
                findings.extend(self._test_json_xss(url, method, json_data))
            except json.JSONDecodeError:
                pass
        
        elif method in ["POST", "PUT"] and post_data:
            if "=" in post_data and not post_data.strip().startswith("{"):
                findings.extend(self._test_form_data_xss(url, method, post_data))

        if "?" in url:
            findings.extend(self._test_query_param_xss(url))

        return findings

    def _test_json_xss(self, url: str, method: str, base_json: Dict) -> List[Dict]:
        """Wstrzykuje XSS do kluczy JSON."""
        findings = []
        for key, value in base_json.items():
            if not isinstance(value, str): continue
            
            print(f"  > [XSS] Test pola JSON: '{key}'")
            for payload in XSS_PAYLOADS:
                test_json = base_json.copy()
                test_json[key] = payload 
                
                try:
                    if method == "POST":
                        r = self.session.post(url, json=test_json, timeout=5)
                    elif method == "PUT":
                        r = self.session.put(url, json=test_json, timeout=5)
                    else:
                        continue

                    if self._check_reflection(r.text, payload):
                        findings.append(self._create_finding(url, key, payload, "JSON Body"))
                        print(f"    [!!!] Znaleziono XSS w polu JSON '{key}'!")
                        break
                except Exception: pass
        return findings

    def _test_form_data_xss(self, url: str, method: str, post_data_str: str) -> List[Dict]:
        """
        NOWOŚĆ: Parsuje standardowe dane formularza (a=1&b=2) i wstrzykuje XSS.
        """
        findings = []
        params = parse_qs(post_data_str)
        
        if not params:
            return []

        for param_name, values in params.items():
            print(f"  > [XSS] Test pola Formularza (POST): '{param_name}'")
            
            for payload in XSS_PAYLOADS:
                test_params = params.copy()

                test_params[param_name] = payload

                try:
                    # Używamy parametru 'data' (nie 'json') dla formularzy!
                    if method == "POST":
                        r = self.session.post(url, data=test_params, timeout=5)
                    elif method == "PUT":
                        r = self.session.put(url, data=test_params, timeout=5)
                    else:
                        continue

                    if self._check_reflection(r.text, payload):
                        findings.append(self._create_finding(url, param_name, payload, "Form Data (POST)"))
                        print(f"    [!!!] Znaleziono XSS w polu formularza '{param_name}'!")
                        break
                except Exception: pass
        
        return findings

    def _test_query_param_xss(self, full_url: str) -> List[Dict]:
        """Wstrzykuje XSS do parametrów URL (GET)."""
        findings = []
        parsed_url = urlparse(full_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)

        if not params: return []

        for param_name, values in params.items():
            print(f"  > [XSS] Test parametru URL: '{param_name}'")
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    r = self.session.get(base_url, params=test_params, timeout=5)
                    if self._check_reflection(r.text, payload):
                        findings.append(self._create_finding(base_url, param_name, payload, "URL Parameter"))
                        print(f"    [!!!] Znaleziono XSS w URL '{param_name}'!")
                        break
                except Exception: pass
        return findings

    def _check_reflection(self, response_text: str, payload: str) -> bool:
        if not response_text: return False
        return payload in response_text

    def _create_finding(self, url, param, payload, location):
        return {
            "type": "Cross-Site Scripting (XSS)",
            "subtype": "Reflected",
            "location": location,
            "url": url,
            "parameter": param,
            "payload": payload
        }

xss_scanner = XSSScanner()