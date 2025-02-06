import json
import time
import concurrent.futures
import undetected_chromedriver.v2 as uc
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from utils import check_virustotal, check_urlscan, capture_network_requests
from config import VIRUSTOTAL_API_KEY, URLSCAN_API_KEY

# Configure logging to capture network requests
def configure_chrome():
    chrome_options = Options()
    chrome_options.headless = True
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")

    # Enable DevTools Protocol (captures network requests)
    capabilities = DesiredCapabilities.CHROME
    capabilities["goog:loggingPrefs"] = {"performance": "ALL"}

    driver = uc.Chrome(options=chrome_options, desired_capabilities=capabilities)
    return driver

# Analyse a single URL
def analyse_url(url):
    print(f"[*] Analysing: {url}")

    driver = configure_chrome()
    try:
        driver.get(url)
        time.sleep(5)  # Wait for JavaScript execution

        final_url = driver.current_url
        network_requests = capture_network_requests(driver)

        driver.quit()
    except Exception as e:
        driver.quit()
        return {"error": str(e)}

    # Check URL reputation
    print(f"[*] Checking VirusTotal for {final_url}...")
    vt_results = check_virustotal(final_url, VIRUSTOTAL_API_KEY)

    print(f"[*] Checking URLScan.io for {final_url}...")
    urlscan_results = check_urlscan(final_url, URLSCAN_API_KEY)

    return {
        "original_url": url,
        "final_url": final_url,
        "network_requests": network_requests,
        "virustotal": vt_results,
        "urlscan": urlscan_results
    }

# Process multiple URLs in parallel
def analyse_bulk_urls(file_path, output_file, max_threads=5):
    with open(file_path, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
        future_to_url = {executor.submit(analyse_url, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({"url": url, "error": str(e)})

    # Save results to JSON file
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[*] Scan complete. Results saved to {output_file}")

# Example usage
if __name__ == "__main__":
    input_file = "../data/malicious_urls.txt"
    output_file = "../data/scan_results.json"
    analyse_bulk_urls(input_file, output_file)

