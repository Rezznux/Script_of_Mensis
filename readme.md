
![som_banner](https://github.com/user-attachments/assets/a8ff84b6-ec9a-4b2f-b96f-562805b76272)

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
1. Scan a single URL:
	
   ```sh
   python scripts/url_scanner.py https://suspicious-site.com

2. Bulk scan URLs from file:

   ```sh
   python scripts/url_scanner.py



