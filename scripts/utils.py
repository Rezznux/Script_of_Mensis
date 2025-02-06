import requests
import json

# Capture network requests made by the page
def capture_network_requests(driver):
    logs = driver.get_log("performance")
    requests_list = []

    for entry in logs:
        log_entry = json.loads(entry["message"])["message"]
        if log_entry["method"] == "Network.requestWillBeSent":
            request_url = log_entry["params"]["request"]["url"]
            requests_list.append(request_url)

    return requests_list

# Check URL reputation using VirusTotal
def check_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        return result.json()
    return {"error": "Failed to fetch VirusTotal results"}

# Check URL reputation using URLScan.io
def check_urlscan(url, api_key):
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "private"}
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch URLScan results"}

