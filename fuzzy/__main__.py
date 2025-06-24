"""
fuzzy cli - by æ’’
educational penetration testing tool for authorized environments only
"""
from .core import fuzzyRequester, fuzzyPayloads, fuzzyFuzzer
import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(
        description='fuzzy - penetration testing request library cli',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m fuzzy --url http://example.com --method GET
  python -m fuzzy --url http://example.com/login --method POST --data "username=admin&password=123"
  python -m fuzzy --url http://example.com/api --method POST --json '{"key": "value"}'
  python -m fuzzy --url http://example.com --fuzz-param id --payloads sqli
  
disclaimer: this tool is for educational and authorized testing purposes only
        """
    )
    
    parser.add_argument('--url', required=True, help='target url')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                       help='http method (default: GET)')
    parser.add_argument('--data', help='post data (form-encoded)')
    parser.add_argument('--json', help='json data for request body')
    parser.add_argument('--headers', help='custom headers (json format)')
    parser.add_argument('--cookies', help='custom cookies (json format)')
    parser.add_argument('--proxy', help='proxy url (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=30, help='request timeout in seconds')
    parser.add_argument('--no-verify', action='store_true', help='disable ssl verification')
    parser.add_argument('--verbose', action='store_true', help='enable verbose output')
    parser.add_argument('--output', help='save response to file')
    
    parser.add_argument('--auth-basic', help='basic auth (username:password)')
    parser.add_argument('--auth-bearer', help='bearer token')
    parser.add_argument('--auto-csrf', action='store_true', help='auto-extract csrf token')
    
    parser.add_argument('--fuzz-param', help='parameter name to fuzz')
    parser.add_argument('--payloads', choices=['sqli', 'xss', 'traversal'], 
                       help='payload type for fuzzing')
    parser.add_argument('--custom-payloads', help='file containing custom payloads (one per line)')
    
    parser.add_argument('--pretty', action='store_true', help='pretty print json/html response')
    parser.add_argument('--extract-forms', action='store_true', help='extract forms from html response')
    
    args = parser.parse_args()
    
    headers = {}
    cookies = {}
    proxies = {}
    
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print("error: invalid json format for headers")
            sys.exit(1)
    
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print("error: invalid json format for cookies")
            sys.exit(1)
    
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
    
    if args.auth_basic:
        import base64
        username, password = args.auth_basic.split(':', 1)
        auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers['Authorization'] = f'Basic {auth_string}'
    
    if args.auth_bearer:
        headers['Authorization'] = f'Bearer {args.auth_bearer}'
    
    requester = fuzzyRequester(
        headers=headers,
        cookies=cookies,
        proxies=proxies,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        verbose=args.verbose
    )
    
    try:
        if args.fuzz_param and args.payloads:
            payloads = []
            
            if args.payloads == 'sqli':
                payloads = fuzzyPayloads.sql_injection_basic()
            elif args.payloads == 'xss':
                payloads = fuzzyPayloads.xss_basic()
            elif args.payloads == 'traversal':
                payloads = fuzzyPayloads.directory_traversal()
            
            if args.custom_payloads:
                try:
                    with open(args.custom_payloads, 'r') as f:
                        payloads.extend([line.strip() for line in f if line.strip()])
                except FileNotFoundError:
                    print(f"error: payload file '{args.custom_payloads}' not found")
                    sys.exit(1)
            
            fuzzer = fuzzyFuzzer(requester)
            results = fuzzer.fuzz_parameters(args.url, args.fuzz_param, payloads, args.method)
            
            print(f"\nfuzzing results for parameter '{args.fuzz_param}':")
            print("-" * 60)
            
            for result in results:
                print(f"payload: {result['payload'][:50]}")
                print(f"status: {result['status_code']} | "
                      f"length: {result['response_length']} | "
                      f"time: {result['response_time']:.3f}s")
                print("-" * 40)
            
            return
        
        response = None
        
        if args.method == 'GET':
            response = requester.get(args.url)
        elif args.method == 'POST':
            post_data = None
            json_data = None
            
            if args.data:
                post_data = {}
                for pair in args.data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        post_data[key] = value
            
            if args.json:
                try:
                    json_data = json.loads(args.json)
                except json.JSONDecodeError:
                    print("error: invalid json format for data")
                    sys.exit(1)
            
            response = requester.post(args.url, data=post_data, json=json_data, 
                                    auto_token=args.auto_csrf)
        
        elif args.method == 'PUT':
            put_data = None
            json_data = None
            
            if args.data:
                put_data = {}
                for pair in args.data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        put_data[key] = value
            
            if args.json:
                try:
                    json_data = json.loads(args.json)
                except json.JSONDecodeError:
                    print("error: invalid json format for data")
                    sys.exit(1)
            
            response = requester.put(args.url, data=put_data, json=json_data)
        
        elif args.method == 'DELETE':
            response = requester.delete(args.url)
        
        elif args.method == 'PATCH':
            patch_data = None
            json_data = None
            
            if args.data:
                patch_data = {}
                for pair in args.data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        patch_data[key] = value
            
            if args.json:
                try:
                    json_data = json.loads(args.json)
                except json.JSONDecodeError:
                    print("error: invalid json format for data")
                    sys.exit(1)
            
            response = requester.patch(args.url, data=patch_data, json=json_data)
        
        if response:
            print(f"\nresponse status: {response.status_code}")
            print(f"response headers:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")
            
            print(f"\nresponse body:")
            if args.pretty:
                if 'application/json' in response.headers.get('content-type', ''):
                    print(response.pretty_json())
                elif 'text/html' in response.headers.get('content-type', ''):
                    print(response.pretty_html())
                else:
                    print(response.text)
            else:
                print(response.text)
            
            if args.extract_forms:
                forms = response.extract_forms()
                if forms:
                    print(f"\nextracted forms ({len(forms)}):")
                    for i, form in enumerate(forms, 1):
                        print(f"form {i}:")
                        print(f"  action: {form['action']}")
                        print(f"  method: {form['method']}")
                        print(f"  inputs: {len(form['inputs'])}")
                        for inp in form['inputs']:
                            print(f"    - {inp['name']} ({inp['type']})")
            
            if args.output:
                requester.save_response(response, args.output)
    
    except KeyboardInterrupt:
        print("\noperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()