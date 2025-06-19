# ReconMapper - Advanced Reconnaissance Data Mapper

## Overview
ReconMapper is a powerful tool for consolidating and organizing reconnaissance findings from various sources. It helps security professionals and penetration testers map discovered assets, categorize them, and generate comprehensive reports.

## Features
- Loads data from multiple file types (subdomains, content discovery, endpoints, parameters)
- URL normalization and validation
- Smart categorization of assets (subdomains, directories, files, endpoints, JS, APIs)
- Parallelized URL probing with detailed response analysis
- Technology detection (headers, content, known patterns)
- DNS record resolution
- Basic vulnerability pattern detection
- Multiple report formats (JSON, text, Markdown, HTML, Excel)

## Installation
1. Clone this repository or download the `reconmap.py` script
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```
Usage
```bash
python reconmap.py -d example.com [options]
```

Required arguments:
  -d, --domain       Base domain to map (e.g., example.com)

Optional arguments:
  -s, --subdomains   File containing subdomains (one per line)
  -c, --content      File containing content discovery results (URLs)
  -e, --endpoints    File containing API/endpoint URLs
  -p, --parameters   File containing parameterized URLs
  --probe            Enable URL probing (HTTP requests)
  --max-workers      Max concurrent threads for probing (default: 10)
  --rate-limit       Seconds between requests (default: 0.1)
  --timeout          Request timeout in seconds (default: 15)
  --no-ssl-verify    Disable SSL certificate verification
  --format           Report format (json, text, markdown, html, xls) (default: json)
  --output-dir       Output directory for reports (default: ./reports)
  --debug            Enable debug logging
Examples
Basic mapping with subdomains and content discovery:

```bash
python reconmap.py -d example.com -s subdomains.txt -c content.txt
```
Full scan with probing and Markdown report:

```bash
python reconmap.py -d example.com -s subdomains.txt -c content.txt -e endpoints.txt --probe --format markdown
```
Scan with custom settings:

```bash
python reconmap.py -d example.com --max-workers 20 --rate-limit 0.2 --timeout 30 --no-ssl-verify
```
Output
Reports are saved in the specified output directory (default: ./reports) with a timestamp in the filename.

Notes
For large-scale scans, adjust the rate limit and timeout values appropriately

Disabling SSL verification (--no-ssl-verify) should only be used in controlled environments

The tool includes basic rate limiting to avoid overwhelming target servers

License
This project is open-source and available for use under the MIT License.

text

These files provide:
1. A minimal `requirements.txt` with only the essential external dependencies
2. A comprehensive `README.md` that includes:
   - Project description
   - Features list
   - Installation instructions
   - Usage examples
   - Command-line options
   - Important notes about usage

The requirements are kept minimal since many of the imports (like `argparse`, `json`, etc.) are part of Python's standard library. The README provides clear instructions for both basic and advanced usage scenarios.
