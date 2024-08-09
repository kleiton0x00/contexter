# main.py

import argparse
from utils import print_msg, disable_warnings
from scanner import Scanner
from color_codes import banner

def parse_proxies(proxy_str):
    """Convert proxy string to a dictionary format."""
    if proxy_str:
        return {
            "http": f"http://{proxy_str}",
            "https": f"https://{proxy_str}",
        }
    return None

def main():
    disable_warnings()
    
    print(banner)

    parser = argparse.ArgumentParser(description='Contexter - A server-side parameter pollution testing tool')
    parser.add_argument('-f', '--file', action='store', required=True, help='The location of the raw HTTP request file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-x', '--exit_early', action='store_true', help='Exit scan on first finding')
    parser.add_argument('--proxy', action='store', help='Use proxy (e.g "127.0.0.1:8080")')
    parser.add_argument('-p', '--param', action='store', help='Test only a specific parameter')
    parser.add_argument('-t', '--timeout', type=float, help='Request timeout in seconds')  # Specify type
    parser.add_argument('-s', '--ignore_ssl', action='store_true', help='Do not verify SSL when sending requests.')
    args = parser.parse_args()

    # Convert proxy to a dictionary format
    if args.proxy:
        proxies = parse_proxies(args.proxy)
    else:
        proxies=None

    # Configure scanner parameters
    scanner = Scanner(
        verbose=args.verbose,
        exit_early=args.exit_early,
        specific_param=args.param,
        scan_specific_param=bool(args.param),
        proxies=proxies,
        ignore_ssl=not args.ignore_ssl,
        timeout=args.timeout,  # Pass as float
        param=args.param
    )

    # Read the file
    with open(args.file, 'r') as file:
        raw_request = file.read()

    scanner.parse_and_modify_http_request(raw_request, proxies)

if __name__ == '__main__':
    main()
