## Overview

AI generated project using anti-bot tools to analyse malicous redirects.

This project:

✅ Bypasses bot detection (Cloudflare, CAPTCHA)  
✅ Captures JavaScript network requests (hidden payloads)  
✅ Extracts full redirection chains dynamically  
✅ Checks URL reputation (VirusTotal, URLScan.io)  
✅ Processes multiple URLs in parallel  

## Installation
1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   
2. Download Chromedriver: https://chromedriver.chromium.org/downloads

3. Replace API keys in scripts/config.py

## Usage

Scan a single URL:
	python scripts/url_scanner.py https://suspicious-site.com

Bulk scan URLs from file:
	python scripts/url_scanner.py



