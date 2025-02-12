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

    # Customized TQDM progress bar with arrows
    with tqdm(
        urls,
        desc="🚀 Scanning URLs",
        unit="url",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
        ascii=" >="  # Custom characters for the progress bar
    ) as progress:
        for url in progress:
            try:
                bad_url = 'evil.com'
                vulnerabilities = []

                # 1. Check X-Forwarded-Host header only
                headers_x_forwarded_host = {'X-Forwarded-Host': bad_url}
                response_x_forwarded_host = requests.get(url, headers=headers_x_forwarded_host, timeout=5, verify=False)
                if response_x_forwarded_host.status_code in {200, 301, 302} and (
                    bad_url in response_x_forwarded_host.text or
                    bad_url in response_x_forwarded_host.headers.get('Location', '') or
                    bad_url in response_x_forwarded_host.headers.get('Content-Location', '')
                ):
                    vulnerabilities.append("X-Forwarded-Host")

                # 2. Check Host header only
                headers_host = {'Host': bad_url}
                response_host = requests.get(url, headers=headers_host, timeout=5, verify=False)
                if response_host.status_code in {200, 301, 302} and (
                    bad_url in response_host.text or
                    bad_url in response_host.headers.get('Location', '') or
                    bad_url in response_host.headers.get('Content-Location', '')
                ):
                    vulnerabilities.append("Host")

                # If any vulnerabilities are found, append them to the results
                if vulnerabilities:
                    vulnerable_urls.append(f"{url} ({', '.join(vulnerabilities)})")
                    print(Fore.RED + f"[!] Vulnerable ({', '.join(vulnerabilities)}): {url}")

            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[!] Error scanning {url}: {e}")
                continue

    print(Fore.GREEN + "[✓] Host Header Injection scan completed.\n")
    return vulnerable_urls
