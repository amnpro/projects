import requests
import time
from colorama import Fore
import urllib3
from tqdm import tqdm

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_host_header_injection(urls):
    print(Fore.CYAN + "[*] Starting Host Header Injection scan...")
    time.sleep(1)
    vulnerable_urls = []

    for url in tqdm(urls, desc="Scanning URLs", unit="url"):
        try:
            bad_url = 'evil.com'
            
            # 1. Check Host header only
            headers_host = {
                'Host': bad_url
            }
            response_host = requests.get(url, headers=headers_host, timeout=5, verify=False)
            if response_host.status_code in {200, 301, 302} and (
                bad_url in response_host.text or
                bad_url in response_host.headers.get('Location', '') or
                bad_url in response_host.headers.get('Content-Location', '')
            ):
                print(Fore.RED + f"[!] Vulnerable to Host Header Injection (Host only): {url}")
                vulnerable_urls.append((url, 'Host Only'))

            # 2. Check X-Forwarded-Host header only
            headers_x_forwarded_host = {
                'X-Forwarded-Host': bad_url
            }
            response_x_forwarded_host = requests.get(url, headers=headers_x_forwarded_host, timeout=5, verify=False)
            if response_x_forwarded_host.status_code in {200, 301, 302} and (
                bad_url in response_x_forwarded_host.text or
                bad_url in response_x_forwarded_host.headers.get('Location', '') or
                bad_url in response_x_forwarded_host.headers.get('Content-Location', '')
            ):
                print(Fore.RED + f"[!] Vulnerable to Host Header Injection (X-Forwarded-Host only): {url}")
                vulnerable_urls.append((url, 'X-Forwarded-Host Only'))

            # 3. Check both headers together
            headers_both = {
                'Host': bad_url,
                'X-Forwarded-Host': bad_url
            }
            response_both = requests.get(url, headers=headers_both, timeout=5, verify=False)
            if response_both.status_code in {200, 301, 302} and (
                bad_url in response_both.text or
                bad_url in response_both.headers.get('Location', '') or
                bad_url in response_both.headers.get('Content-Location', '')
            ):
                print(Fore.RED + f"[!] Vulnerable to Host Header Injection (Both headers): {url}")
                vulnerable_urls.append((url, 'Both Headers'))

            # 4. Check Location header explicitly
            headers_location = {
                'Host': bad_url,
                'Location': bad_url
            }
            response_location = requests.get(url, headers=headers_location, timeout=5, verify=False)
            if response_location.status_code in {200, 301, 302} and (
                bad_url in response_location.text or
                bad_url in response_location.headers.get('Location', '') or
                bad_url in response_location.headers.get('Content-Location', '')
            ):
                print(Fore.RED + f"[!] Vulnerable to Host Header Injection (Location header): {url}")
                vulnerable_urls.append((url, 'Location Header'))

        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"[!] Error scanning {url}: {e}")
            continue

    print(Fore.GREEN + "[✓] Host Header Injection scan completed.\n")
    return vulnerable_urls

