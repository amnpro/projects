from tqdm import tqdm
from colorama import Fore
import requests
import socket

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

    # Add a progress bar for the URLs
    with tqdm(total=len(urls), desc="Scanning URLs", unit="url") as progress_bar:
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

            # Update the progress bar
            progress_bar.update(1)

    print(Fore.GREEN + "[\u2713] CORS scan completed.")
    return vulnerable_urls
