# Custom-Python-tools-for-Cyber

A collection of Python scripts built for cybersecurity practice, networking fundamentals, and hands-on lab exploration.

This project started as a way to learn Python scripting through practical cyber tasks instead of only watching tutorials and using built-in tools. The tools are designed for use in controlled lab environments such as Kali Linux, Metasploitable, Windows VMs, and other systems I own or have permission to test.

## Current Tools

### Multi-Target Port Scanner

A Python-based multithreaded port scanner that reads target IP addresses from a file and scans selected ports on each host.

Features:

- Reads multiple target IPs from a file
- Supports quick scan and full scan modes
- Uses Python sockets for TCP connection checks
- Uses multithreading with `ThreadPoolExecutor` for faster scanning
- Identifies open ports across multiple hosts
- Designed for lab environments and cybersecurity practice

Example output:

```text
Scanning: 192.168.227.129
21 is open
22 is open
23 is open
25 is open
53 is open
80 is open
139 is open
445 is open
3306 is open
Scan done
```

### Banner Grabber

`banner-grabber.py` is currently in progress.

This tool is planned as the next step after the multithreaded port scanner. While the port scanner identifies which ports are open, the banner grabber will attempt to identify what services are running on those ports by collecting service banners and basic response information.

Planned features:

- Read target IPs from a file
- Connect to common open ports
- Attempt to collect service banners
- Support common services such as FTP, SSH, SMTP, and HTTP
- Handle timeouts and closed ports gracefully
- Eventually integrate with the port scanner for basic service fingerprinting

## Project Goals

The goal of this repository is to build practical Python scripting skills for cybersecurity by creating tools that help with:

- Network scanning
- Service discovery
- Banner grabbing
- Recon automation
- Log parsing
- IOC extraction
- Report generation

This project is also meant to document my learning process as I move from basic Python scripts toward more useful security automation tools.

## Usage

Clone the repository:

```bash
git clone https://github.com/DolgormaaS/Custom-Python-tools-for-Cyber.git
cd Custom-Python-tools-for-Cyber
```

Edit the target addresses file:

```bash
vim targetips.txt
```

Example `targetips.txt`:

```text
192.168.227.129
192.168.0.32
```
## Running the scripts: 
### Scanner:

```bash
python3 multi-target-port-scanner.py targetips.txt
```

Choose scan mode:

```text
Choose 1 for full scan, 2 for quick scan:
```

Quick Scan:

Scans a smaller set of commonly exposed ports, such as:

```text
21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443
```

Full Scan:

Scans a broader list of common service ports including FTP, SSH, Telnet, SMTP, DNS, HTTP, SMB, databases, VNC, WinRM, Elasticsearch, MongoDB, and other frequently exposed services.

## Requirements

- Python 3
- A Linux or Windows machine with Python installed
- A lab target or authorized system to scan

No external Python libraries are required for the current port scanner.

## Planned Features

Future improvements may include:

- Complete `banner-grabber.py`
- Service name detection
- Banner grabbing for FTP, SSH, SMTP, and HTTP
- HTTP header grabbing
- Saving scan results to a file
- JSON or CSV report output
- Better error handling
- Optional timeout configuration
- Integration with a basic recon report generator
- Comparison notes against tools like `nmap`

## Learning Notes

Some key concepts practiced in this project:

- Python socket programming
- File input handling
- TCP connection checks
- Command-line arguments with `sys.argv`
- Multithreading with `ThreadPoolExecutor`
- Handling timeouts and unreachable hosts
- Designing quick vs. full scan modes
- Writing tools for practical cybersecurity workflows

## Ethical Use

These tools are intended only for:

- Personal lab environments
- CTFs
- Authorized testing
- Educational use
- Systems I own or have explicit permission to scan

Do not use these scripts to scan networks or systems without authorization.

## Disclaimer

This repository is for educational purposes only. Unauthorized scanning or testing of systems may violate laws, policies, or terms of service. Use responsibly.

## Author

Created by Dolgormaa Sansarsaikhan as part of my cybersecurity scripting practice and hands-on learning journey.
