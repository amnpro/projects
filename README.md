# Web Vulnerability Find
**Find vulnerability** :- SSTI, cors, Host-Header-Injection, Command-Injection, xss, sql .

**Setup Tool**
> $ bash setup.sh

**Help Command**

```
$  python3 main.py -h
usage: main.py [-h] [-t TARGET] [-o OUTPUT] [--sql] [--xss] [--redirect]
               [--xss-advance] [--cors] [--host-header] [--ssti] [-u U]
               [--url URL] [--method {gau,wayback}] [--sql-advanced]
               [--proxy] [--http-smuggling] [--command-injection]

Web Application Vulnerability Scanner

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target domain (required if --url is not provided)
  -o OUTPUT, --output OUTPUT
                        Output file (default: output.txt)
  --sql                 Check for SQL Injection
  --xss                 Check for XSS
  --redirect            Check for Open Redirect
  --xss-advance         Use advanced XSS scanner (xsstrik)
  --cors                Check for CORS vulnerabilities
  --host-header         Check for Host Header Injection
  --ssti                Check for SSTI vulnerabilities
  -u U                  Specific URL (required if --target or --url is not
                        provided)
  --url URL             File containing specific URLs
  --method {gau,wayback}
                        Method to find endpoints (default: gau)
  --sql-advanced        Use advanced SQL Injection scanner (sqlmap)
  --proxy               Use proxychains for all requests
  --http-smuggling      Check for HTTP Request Smuggling vulnerabilities
  --command-injection   Check for OS Command Injection vulnerabilities
```

**SSTI Find**
> $ python3 main.py --url url-file.txt --ssti

![ssti](https://github.com/user-attachments/assets/3865737e-314e-44f8-a098-140fd179a45e)


**Host Header Injection**
> $ python3 main.py --url url-file.txt --host-header

![host-headr](https://github.com/user-attachments/assets/a867a51f-d818-4cc1-8397-ffd7998594cc)


**Command Injection**
> $ python3 main.py --url url-file.txt --command-injection

![command-injection](https://github.com/user-attachments/assets/f7468c20-995f-42ed-ab26-fb9be98f3ac5)


