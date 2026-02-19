# WebScanner v2.2

Differential vulnerability scanner. Sends a **baseline** (clean) request, injects payloads, and **compares** responses to detect real vulnerabilities.

## Supported Checks

| Module | Key | Detection |
|--------|-----|-----------|
| **SQLi** | `sqli` | Error-based (diff regex) + Time-based (diff elapsed) |
| **SSTI** | `ssti` | Canary + math eval (diff) |
| **XSS** | `xss` | Canary reflection unescaped (diff) |
| **CMDi** | `cmdi` | Echo canary (diff) + Time-based (diff elapsed) |
| **LFI** | `lfi` | File content patterns (diff) + Path traversal errors |
| **SSRF** | `ssrf` | Internal content patterns (diff) + Size anomaly |
| **Open Redirect** | `redirect` | External Location header (diff) + Status flip |
| **CRLF** | `crlf` | Injected response headers (diff) |

## Usage

### From URL (auto-detect params)
```bash
python scan.py --url "http://example.com/page?id=1&name=test"
python scan.py --url "http://example.com/?q=search" --checks sqli,xss
```

### Crawl mode (discover forms + links)
```bash
python scan.py --url "http://example.com/" --crawl
python scan.py --url "http://example.com/" --crawl --crawl-depth 3
python scan.py --url "http://example.com/" --crawl --checks sqli -vv
```

### From raw request file (FUZZ mode)
```bash
python scan.py --request example.req --request-proto https
python scan.py --request example.req --checks sqli,xss --proxy http://127.0.0.1:8080
```

### Options
```
--request FILE     Raw request file with FUZZ marker
--url URL          Target URL (mutually exclusive with --request)
--crawl            BFS crawl to discover forms and links
--crawl-depth N    Max crawl depth (default: 2)
--checks LIST      sqli,xss,ssti,lfi,cmdi,ssrf,redirect,crlf or 'all' (default: all)
--proxy URL        HTTP proxy
--timeout N        Timeout in seconds (default: 15)
-v / -vv           Verbosity
```

## VulnLab (Test Server)

Start the vulnerable lab server:
```bash
pip install -r vuln_lab/requirements.txt
python vuln_lab/app.py
```

Then scan it:
```bash
python scan.py --url "http://127.0.0.1:5000/" --crawl -v
```

## Request File Format

```
POST /path?param=FUZZ HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&input=FUZZ
```

## Install

```bash
pip install -r requirements.txt
```
