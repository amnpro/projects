import requests
from colorama import Fore, Style
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from tqdm import tqdm  # Import tqdm for progress bar

# Updated payloads for SSTI detection (more varied payloads)
PAYLOADS = [
    "{{777*777}}",
    "[[777*777]]",
    "{{777*777}}",
    "{{777*'777'}}",
    "<%= 777 * 777 %>",
    "${777*777}",
    "${{777*777}}",
    "@(777+777)",
    "#{777*777}",
    "#{ 777 * 777 }",
]

#EXPECTED_RESULTS = ["603729", "1554", "777777"]
EXPECTED_RESULTS = ["603729", "777777"]
def inject_payload_into_url(url, param_name, payload):
    """
    Inject a payload into a specific query parameter in the URL.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param_name] = payload
    modified_query = urlencode(query_params, doseq=True)
    modified_url = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", modified_query, parsed_url.fragment)
    )
    return modified_url

def send_ssti_payload_get(url):
    """
    Send an SSTI payload using a GET request and analyze the response.
    """
    try:
        response = requests.get(url, timeout=10, verify=False)
        if any(result in response.text for result in EXPECTED_RESULTS):
            return True, response.text
        if response.status_code in {500, 400} and "template" in response.text.lower():
            return True, response.text
    except requests.RequestException as e:
        return False, str(e)
    return False, None

def scan_ssti_in_url(url):
    """
    Scan all query parameters in a URL for SSTI vulnerabilities.
    """
    vulnerable = []
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query).keys()  # Get query parameter names

    for param in params:
        for payload in PAYLOADS:
            modified_url = inject_payload_into_url(url, param, payload)
            # Inject the payload and check if vulnerable
            is_vulnerable, response = send_ssti_payload_get(modified_url)
            if is_vulnerable:
                # Print only when a vulnerability is found
                print(Fore.RED + f"[!] Vulnerable to SSTI: {modified_url}")
                print(Fore.YELLOW + f"    Parameter: {param}, Payload: {payload}")
                vulnerable.append((url, param, payload))
                break  # Stop checking further payloads once a vulnerability is found
    return vulnerable

def scan_ssti(urls):
    """
    Scan a list of URLs for SSTI vulnerabilities with a progress bar.
    """
    print(Fore.CYAN + "[*] Starting SSTI scan...")
    time.sleep(1)

    vulnerable_urls = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_ssti_in_url, url): url for url in urls}
        # Use tqdm to show progress
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning URLs"):
            result = future.result()
            if result:
                vulnerable_urls.extend(result)

    print(Fore.GREEN + "[✓] SSTI scan completed.\n")

    # Print summary of vulnerable URLs
    print(Fore.CYAN + "\n[*] Vulnerable URLs found:")
    for vuln in vulnerable_urls:
        print(Fore.RED + f"Vulnerable URL: {vuln[0]}")
        print(Fore.YELLOW + f"Location: {vuln[1]}, Payload: {vuln[2]}")

    return vulnerable_urls
