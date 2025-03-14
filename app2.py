import os   
import subprocess
import time
import concurrent.futures
import aiohttp
import asyncio
import shodan  # Import Shodan library
from flask import Flask, render_template, request, jsonify
import nmap
import requests
from urllib.parse import urlparse, parse_qs

# Initialize Flask app
app = Flask(__name__)

# Shodan API Key (replace with your actual key)
SHODAN_API_KEY = 'AjeVRyUneMq8hLumqbo6YFJX2HziKJZo'
api = shodan.Shodan(SHODAN_API_KEY)

# Retry mechanism for requests
def retry_request(func, retries=3, delay=2, *args, **kwargs):
    last_exception = None
    for _ in range(retries):
        try:
            return func(*args, **kwargs)
        except requests.RequestException as e:
            last_exception = e
            time.sleep(delay)
    raise last_exception  # Raise the last exception if all retries fail

# Function to scan open ports and find service versions using nmap
def scan_ports_and_versions(target):
    nm = nmap.PortScanner()
    try:
        # Perform version detection scan using -sV for service version info
        nm.scan(target, '1-1024', arguments='-sV')
        open_ports = []
        services = {}

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    open_ports.append(port)
                    service = nm[host][proto][port]
                    service_name = service.get('name', 'Unknown')
                    service_version = service.get('version', 'Unknown')
                    services[port] = {
                        'name': service_name,
                        'version': service_version
                    }
        return open_ports, services
    except Exception as e:
        print(f"Error scanning ports: {e}")
        return [], {}

# Function to check for Cross-Site Scripting (XSS) vulnerability
async def test_xss_async(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>"
    ]
    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            try:
                async with session.get(url, params={'input': payload}, timeout=10) as response:
                    if payload in await response.text():
                        return True
            except Exception as e:
                print(f"Error testing XSS: {e}")
    return False

# Function to check for common security headers
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        headers = response.headers
        missing_headers = []

        security_headers = [
            'Strict-Transport-Security', 'X-Content-Type-Options', 'Content-Security-Policy',
            'X-Frame-Options', 'X-XSS-Protection', 'Referrer-Policy', 'Feature-Policy'
        ]

        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)

        if missing_headers:
            return f"Missing security headers: {', '.join(missing_headers)}"
        else:
            return "All critical security headers are present."
    except requests.exceptions.Timeout:
        return "The request to check security headers timed out."
    except requests.exceptions.RequestException as e:
        return f"Error checking security headers: {e}"

# Function to get Shodan info for a given IP
def get_shodan_info(target_ip):
    try:
        # Lookup the target IP using Shodan
        result = api.host(target_ip)
        info = {
            "ip": target_ip,
            "hostname": result.get('hostnames', []),
            "ports": result.get('ports', []),
            "vulns": result.get('vulns', {}),
            "org": result.get('org', 'Unknown')
        }
        return info
    except shodan.APIError as e:
        return f"Error with Shodan API: {e}"

# Semaphore for limiting concurrent requests during directory fuzzing
semaphore = asyncio.Semaphore(10)  # Limit to 10 concurrent requests

# Directory fuzzing task with retry logic and concurrency control
async def fetch_with_retry(session, url, retries=3, delay=2):
    last_exception = None
    for _ in range(retries):
        try:
            async with session.get(url, timeout=10) as response:
                return response
        except Exception as e:
            last_exception = e
            await asyncio.sleep(delay)
    raise last_exception

# Directory fuzzing task with retry logic and concurrency control
async def fuzz_directory_task(session, full_url):
    async with semaphore:
        try:
            response = await fetch_with_retry(session, full_url)
            if response.status == 200 or response.status == 301:
                return full_url
        except Exception as e:
            print(f"Error during directory fuzzing for {full_url}: {e}")
        return None

# Directory fuzzing using wordlist
async def fuzz_directories_async(url, wordlist_path):
    found = {'200_OK': [], '301_Redirect': [], 'Other': []}
    async with aiohttp.ClientSession() as session:
        try:
            with open(wordlist_path, 'r') as wordlist_file:
                tasks = []
                for line in wordlist_file:
                    word = line.strip()
                    full_url = f"{url}/{word}"
                    tasks.append(fuzz_directory_task(session, full_url))

                results = await asyncio.gather(*tasks)
                for res in results:
                    if res:
                        if '200 OK' in res:
                            found['200_OK'].append(res)
                        elif '301 Moved Permanently' in res:
                            found['301_Redirect'].append(res)
                        else:
                            found['Other'].append(res)
        except Exception as e:
            print(f"Error during directory fuzzing: {e}")
    return found

# Function to run searchsploit command to find exploits for a given service and version
def search_exploit(query):
    try:
        result = subprocess.check_output(['searchsploit', query], stderr=subprocess.STDOUT, text=True)
        return result if result else f"No exploits found for {query}."
    except subprocess.CalledProcessError as e:
        return f"Error running searchsploit: {e.output}"

# Route for the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    exploit_results = None
    shodan_results = None

    if request.method == 'POST':
        if 'exploit_query' in request.form:  # If the exploit search form was submitted
            exploit_query = request.form['exploit_query']
            exploit_results = search_exploit(exploit_query)

        else:  # Handle the other forms for vulnerabilities
            target_ip = request.form['target_ip']
            web_url = request.form['web_url']
            wordlist_selection = request.form['wordlist']  # Get selected wordlist path

            # Run scans
            open_ports, service_versions = scan_ports_and_versions(target_ip)

            # Get Shodan info for the target IP
            shodan_results = get_shodan_info(target_ip)

            # Automatically find exploits based on extracted versions
            exploit_query = []
            for port, service in service_versions.items():
                service_name = service['name']
                service_version = service['version']
                if service_version and service_name:
                    query = f"{service_name} {service_version}"
                    exploit_query.append(query)

            # Run searchsploit based on extracted services and versions
            exploit_results = ""
            for query in exploit_query:
                result = search_exploit(query)
                if result:
                    exploit_results += f"Results for {query}:\n{result}\n\n"

            # Test for XSS vulnerability
            xss_result = asyncio.run(test_xss_async(web_url))

            # Perform directory fuzzing using the selected wordlist
            discovered_files = asyncio.run(fuzz_directories_async(web_url, wordlist_selection))

            # Collect the results
            results = {
                'open_ports': open_ports,
                'service_versions': service_versions,
                'xss': xss_result,
                'security_headers': check_security_headers(web_url),
                'discovered_files': discovered_files,
            }

    return render_template('index.html', results=results, exploit_results=exploit_results, shodan_results=shodan_results)

# AJAX request handler for external exploit search
@app.route('/search_exploit', methods=['POST'])
def search_exploit_ajax():
    exploit_query = request.json.get('query')
    exploit_results = search_exploit(exploit_query)
    return jsonify({'exploit_results': exploit_results})

if __name__ == '__main__':
    app.run(debug=True)
