import argparse
import subprocess
from colorama import Fore, Style, init
import time
import socket
import os
import sys
import requests
from host_header_injection import scan_host_header_injection 
#from host_header_new import scan_host_header_injection   
from stem import Signal
from stem.control import Controller
from ssti_scanner import scan_ssti
from http_request_smuggling import scan_http_request_smuggling
from os_command_injection_scanner import scan_os_command_injection
from open_redirect import check_open_redirect
from cors import scan_cors
from sql_injection import scan_sql_injection

# Initialize Colorama for colored output
init(autoreset=True)

def log(message, level="info"):
    """
    Log messages with levels and color-coded output.
    """
    levels = {
        "info": Fore.CYAN + "[*]",
        "success": Fore.GREEN + "[✓]",
        "warning": Fore.YELLOW + "[!]",
        "error": Fore.RED + "[!]",
    }
    print(levels.get(level, "[*]") + " " + message + Style.RESET_ALL)


# Function to check if Tor is running
def check_tor_proxy():
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=5):
            log("Tor is running on 127.0.0.1:9050", "success")
            return True
    except (socket.timeout, socket.error):
        log("Tor is not running or proxy is not correctly set up.", "error")
        return False

# Function to check if script is running with sudo
def check_sudo():
    return os.geteuid() == 0

# Proxy setup function
def configure_proxy():
    if not check_sudo():
        print(Fore.RED + "[!] You must run this script with sudo to modify proxychains configuration.")
        choice = input(Fore.YELLOW + "[?] Do you want to continue without configuring proxychains? (y/n): ")
        if choice.lower() != 'y':
            print(Fore.RED + "[!] Exiting the script.")
            exit(1)
        else:
            print(Fore.GREEN + "[✓] Continuing without modifying proxychains...\n")
            return
'''
    proxy_config = """
[ProxyList]
# Add proxy here ...
# Meanwhile, defaults set to "tor"
socks4 127.0.0.1 9050
socks5 127.0.0.1 9050
"""
    config_path = "/etc/proxychains4.conf"
    with open(config_path, "w") as config_file:
        config_file.write(proxy_config)
    print(Fore.GREEN + "[✓] Proxychains configuration updated.\n")

'''


def run_with_proxy(command):
    result = subprocess.run(['proxychains', command], capture_output=True, text=True)
    return result.stdout

def find_endpoints_gau(target):
    try:
        print(Fore.CYAN + "[*] Using gau to find endpoints...")
        result = subprocess.run(['gau', target], capture_output=True, text=True, timeout=30)
        urls = set(result.stdout.splitlines())
        with open("urls.txt", "w") as f:
            f.write("\n".join(urls))
        return list(urls)
    except Exception as e:
        print(Fore.RED + f"[!] Error using gau: {e}")
        return []

def find_endpoints_waybackurls(target):
    try:
        print(Fore.CYAN + "[*] Using waybackurls to find endpoints...")
        result = subprocess.run(['waybackurls', target], capture_output=True, text=True, timeout=30)
        urls = set(result.stdout.splitlines())
        with open("urls.txt", "w") as f:
            f.write("\n".join(urls))
        return list(urls)
    except Exception as e:
        print(Fore.RED + f"[!] Error using waybackurls: {e}")
        return []


def scan_sql_injection_advanced(urls):
    print(Fore.CYAN + "[*] Starting advanced SQL Injection scan with sqlmap...")
    time.sleep(1)
    vulnerable_urls = []
    for url in urls:
        result = subprocess.run(['sqlmap', '-u', url, '--batch', '--crawl=1'], capture_output=True, text=True)
        if "parameter" in result.stdout:
            print(Fore.RED + f"[!] Advanced SQL Injection vulnerability detected: {url}")
            vulnerable_urls.append(f"Advanced SQL Injection: {url}")
    print(Fore.GREEN + "[✓] Advanced SQL Injection scan completed.\n")
    return vulnerable_urls

def scan_xss(urls):
    print(Fore.CYAN + "[*] Starting XSS scan...")
    time.sleep(1)
    vulnerable_urls = []
    for url in urls:
        if "alert" in url:
            print(Fore.RED + f"[!] XSS vulnerability detected: {url}")
            vulnerable_urls.append(f"XSS: {url}")
    print(Fore.GREEN + "[✓] XSS scan completed.\n")
    return vulnerable_urls

def scan_with_xsstrik(urls):
    print(Fore.CYAN + "[*] Starting advanced XSS scan with xsstrik...")
    time.sleep(1)
    vulnerable_urls = []
    for url in urls:
        result = subprocess.run(['xsstrik', '-h', url], capture_output=True, text=True)
        if "XSS" in result.stdout:
            print(Fore.RED + f"[!] Advanced XSS vulnerability detected (xsstrik): {url}")
            vulnerable_urls.append(f"Advanced XSS (xsstrik): {url}")
    print(Fore.GREEN + "[✓] Advanced XSS scan completed.\n")
    return vulnerable_urls

def scan_open_redirect(urls):
    print(Fore.CYAN + "[*] Starting Open Redirect scan...")
    time.sleep(1)
    vulnerable_urls = check_open_redirect(urls)  # Use the check_open_redirect function from redirect.py
    print(Fore.GREEN + "[✓] Open Redirect scan completed.\n")
    return vulnerable_urls
'''
def scan_cors(urls):
    """
    Scan URLs for CORS vulnerabilities.
    """
    print(Fore.CYAN + "[*] Starting CORS scan...")
    vulnerable_urls = []
    malicious_origins = [
        "http://evil.com",
        "http://attacker.com",
        "http://localhost",  # Localhost abuse
        "http://127.0.0.1",  # Loopback address
        f"http://{socket.gethostname()}.attacker.com"  # Subdomain
    ]

    for url in urls:
        try:
            for origin in malicious_origins:
                headers = {'Origin': origin}
                response = requests.get(url, headers=headers, timeout=10)

                # Check CORS-related headers
                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                allow_credentials = response.headers.get("Access-Control-Allow-Credentials")

                if allow_origin:
                    # Check if the Origin is echoed back or wildcard used
                    if allow_origin == origin or allow_origin == "*":
                        if allow_credentials == "true":
                            # Allowing credentials with wildcard or any origin is a critical issue
                            print(Fore.RED + f"[!] Critical CORS vulnerability detected at {url} with Origin {origin}")
                            vulnerable_urls.append(f"CORS: {url} (Critical: Credentials with {allow_origin})")
                        else:
                            # Echoing back the origin without credentials
                            print(Fore.YELLOW + f"[!] CORS misconfiguration detected at {url} with Origin {origin}")
                            vulnerable_urls.append(f"CORS: {url} (Misconfigured: {allow_origin})")

        except requests.RequestException as e:
            print(Fore.RED + f"[!] Failed to connect to {url}: {e}")
            continue

    print(Fore.GREEN + "[✓] CORS scan completed.")
    return vulnerable_urls
'''


def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("-t", "--target", help="Target domain (required if --url is not provided)")
    parser.add_argument("-o", "--output", default="output.txt", help="Output file (default: output.txt)")
    parser.add_argument("--sql", action="store_true", help="Check for SQL Injection")
    parser.add_argument("--xss", action="store_true", help="Check for XSS")
    parser.add_argument("--redirect", action="store_true", help="Check for Open Redirect")
    parser.add_argument("--xss-advance", action="store_true", help="Use advanced XSS scanner (xsstrik)")
    parser.add_argument("--cors", action="store_true", help="Check for CORS vulnerabilities")
    parser.add_argument("--host-header", action="store_true", help="Check for Host Header Injection")
    parser.add_argument("--ssti", action="store_true", help="Check for SSTI vulnerabilities")
    parser.add_argument("-u", help="Specific URL (required if --target or --url is not provided)")
    parser.add_argument("--url", help="File containing specific URLs")
    parser.add_argument("--method", choices=["gau", "wayback"], default="gau", help="Method to find endpoints (default: gau)")
    parser.add_argument("--sql-advanced", action="store_true", help="Use advanced SQL Injection scanner (sqlmap)")
    parser.add_argument("--proxy", action="store_true", help="Use proxychains for all requests")
    parser.add_argument("--http-smuggling", action="store_true", help="Check for HTTP Request Smuggling vulnerabilities")
    parser.add_argument("--command-injection", action="store_true", help="Check for OS Command Injection vulnerabilities")

    # Parse arguments
    args = parser.parse_args()

    # Exit immediately if -h is requested
    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        parser.print_help()
        sys.exit(0)

    # Validate required arguments
    if not (args.target or args.u or args.url):
    #if not args.target and not args.url:
        print(Fore.RED + "[!] You must provide either a target domain (-t) or a file containing URLs (--url).")
        parser.print_help()
        sys.exit(1)

    try:
        # Check for proxy and configure if needed
        if args.proxy:
            if not check_tor_proxy():
                choice = input(Fore.RED + "[!] Tor is not running. Do you want to continue without using proxy? (y/n): ")
                if choice.lower() != 'y':
                    print(Fore.RED + "[!] Exiting the script.")
                    sys.exit(1)
                else:
                    print(Fore.GREEN + "[✓] Continuing without proxy...\n")
            else:
                configure_proxy()

        # Prepare URLs from file or using methods
        if args.url:
            with open(args.url, "r") as f:
                urls = [line.strip() for line in f]
        elif args.u:
        	urls = [args.u]
        else:
            print(Fore.GREEN + f"[*] Finding endpoints for {args.target} using {args.method}...")
            urls = find_endpoints_gau(args.target) if args.method == "gau" else find_endpoints_waybackurls(args.target)
            print(Fore.GREEN + f"[*] Found {len(urls)} endpoints. Saved to urls.txt\n")

        # Default to running all scans if no specific scan is selected
        if not any([args.sql, args.xss, args.redirect, args.sql_advanced, args.xss_advance, args.cors, args.host_header, args.ssti, args.http_smuggling, args.command_injection]):
            print(Fore.MAGENTA + "[*] No specific scan selected. Running all scans...\n")
            args.sql = args.xss = args.redirect = args.cors = True
            args.sql_advanced = args.xss_advance = args.http_smuggling = args.command_injection = args.host_header = args.ssti = False

        results = []

        # Call scan functions based on selected options
        if args.sql:
            results.extend(scan_sql_injection(urls))

        if args.sql_advanced:
            results.extend(scan_sql_injection_advanced(urls))

        if args.xss:
            results.extend(scan_xss(urls))

        if args.xss_advance:
            results.extend(scan_with_xsstrik(urls))

        if args.redirect:
            results.extend(scan_open_redirect(urls))

        if args.cors:
            results.extend(scan_cors(urls))

        if args.host_header:
            results.extend(scan_host_header_injection(urls))

        if args.ssti:
            print(Fore.CYAN + "[*] Checking for SSTI vulnerabilities...")
            results.extend(scan_ssti(urls))

        if args.http_smuggling:
            results.extend(scan_http_request_smuggling(urls))

        if args.command_injection:
            headers = {"Authorization": "Bearer YOUR_TOKEN"}  # Add if authentication is needed
            results.extend(scan_os_command_injection(urls, headers))

        # Save results to output file
        # Assuming `args` contains the arguments passed to the script, including 'sql', 'xss', etc.
        try:
    # Handle dynamic output file naming based on the argument
            vuln_type = args.vuln_type  # Replace with actual argument name if different
            if vuln_type:
        # Construct output file name dynamically based on the vulnerability type
                output_filename = f"{vuln_type}_vuln.txt"
                if results:
                    with open(output_filename, "w") as f:
                        f.write("\n".join(results))
                    print(Fore.GREEN + f"[✓] Results saved to {output_filename}\n")
                else:
                    print(Fore.YELLOW + "[!] No vulnerabilities found. No output saved.\n")

        except Exception as e:
            print(Fore.RED + f"[!] An error occurred: {e}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

    except Exception as e:
        print(Fore.RED + f"[!] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
