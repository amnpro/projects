import subprocess

def find_endpoints_gau(target):
    try:
        result = subprocess.run(['gau', target], capture_output=True, text=True, timeout=30)
        urls = set(result.stdout.splitlines())
        with open("urls.txt", "w") as f:
            f.write("\n".join(urls))
        return list(urls)
    except Exception as e:
        print(f"Error using gau: {e}")
        return []

def find_endpoints_waybackurls(target):
    try:
        result = subprocess.run(['waybackurls', target], capture_output=True, text=True, timeout=30)
        urls = set(result.stdout.splitlines())
        with open("urls.txt", "w") as f:
            f.write("\n".join(urls))
        return list(urls)
    except Exception as e:
        print(f"Error using waybackurls: {e}")
        return []
