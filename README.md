# Misconfiguration Detection Tool

This project is a web-based security scanner tool built using Flask that aims to detect common security misconfigurations and vulnerabilities on web applications. It combines a range of security tools to help identify open ports, check for Cross-Site Scripting (XSS) vulnerabilities, assess missing security headers, perform directory fuzzing, and find potential exploits based on service versions. Additionally, it leverages Shodan to gather information on the target host for further vulnerability insights.

## Features

- **Port Scanning & Service Version Detection**: Identifies open ports and associated service versions using Nmap.
- **Cross-Site Scripting (XSS) Vulnerability Detection**: Tests the target website for potential XSS vulnerabilities.
- **Security Header Analysis**: Checks if essential security headers (e.g., `X-Content-Type-Options`, `Strict-Transport-Security`) are present on the target website.
- **Directory Fuzzing**: Performs directory and file discovery using a customizable wordlist.
- **Exploit Search**: Allows you to search for known exploits related to specific services and versions using SearchSploit.
- **Shodan Integration**: Fetches information from Shodan to identify potential vulnerabilities or exposures based on the target IP.
  
## Requirements

To run this project, you will need the following:

- Python 3.x
- Flask
- Nmap
- Shodan
- A Shodan API key
- SearchSploit (for exploit search functionality)
- Aiohttp
- Requests

### Install the dependencies:

You can install the required libraries by running the following command:

```bash
pip install -r requirements.txt
```

Ensure that Nmap and SearchSploit are installed and accessible on your system:

```bash
sudo apt-get install nmap
sudo apt-get install exploitdb
```

## Setup

1. **Clone the repository**:

```bash
git clone https://github.com/ganaak/WebServerMisconfig.git
cd WebServerMisconfig
```

2. **Set up your Shodan API key**:  
   Replace the `SHODAN_API_KEY` variable in the code with your actual Shodan API key.

   ```python
   SHODAN_API_KEY = 'your_shodan_api_key_here'
   ```

3. **Run the Flask App**:

To start the Flask server, use the following command:

```bash
python appplicaion.py
```

By default, the application will run at `http://127.0.0.1:5000/`.

## Usage

### Web Interface

1. **Scan Target**:  
   - Input the target IP address and website URL.
   - Select a wordlist for directory fuzzing.
   - Hit "Run Scan" to initiate the security scan.

2. **Exploit Search**:  
   - Navigate to the "Exploit Search Tool" tab.
   - Enter the service name and version (e.g., `Apache 2.4`).
   - Hit "Search Exploits" to fetch known exploits for the specified service/version.

### Scanning Results

The results from the scan will be displayed on the same page under the following sections:

- **Open Ports & Services**: Displays open ports along with the detected service and version information.
- **Cross-Site Scripting (XSS)**: Shows whether the target is vulnerable to XSS attacks.
- **Security Headers**: Lists any missing security headers.
- **Discovered Files**: Lists directories or files discovered via fuzzing.
- **Target Exploit Suggestions**: Displays potential exploit results based on detected service versions.
- **Shodan Results**: Displays information about the target IP from Shodan, such as open ports, vulnerabilities, and associated organization.

## Example Output

- **Open Ports and Services**:

| Port | Service        | Version       |
|------|----------------|---------------|
| 80   | HTTP           | 2.4.49        |
| 443  | HTTPS          | 2.4.49        |

- **XSS Vulnerability**: Not Vulnerable
- **Missing Security Headers**: `Strict-Transport-Security`, `X-Frame-Options`
- **Discovered Files**:
  - 200 OK: `/admin`
  - 301 Redirect: `/login`
- **Exploit Suggestions**:  
  Results for `Apache 2.4.49`:
  ```
  [Exploit Information]
  ```
- **Shodan Results**:  
  Information about the target IP from Shodan.

## Contributing

Contributions are welcome! If you find any issues or would like to improve the project, please feel free to open a pull request or create an issue.

### Steps to Contribute:
1. Fork the repository.
2. Create a new branch for your changes.
3. Make the necessary changes or additions.
4. Submit a pull request with a description of your changes.
