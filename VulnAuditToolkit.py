import subprocess
import os
import platform
import socket
import psutil
import requests
from datetime import datetime

# Function to detect the current platform
def get_platform():
    return platform.system()

# Function for Open Port Scanning
def scan_open_ports(ip):
    print("[*] Scanning for open ports on IP:", ip)
    open_ports = []
    for port in range(20, 1024):  # Common low ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to check for Outdated Software (example with pip and system package managers)
def check_outdated_software():
    outdated = []
    system_platform = get_platform()
    
    if system_platform == "Linux":
        # Check for outdated packages on Linux (Debian-based example)
        result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
        outdated = result.stdout.splitlines()
    
    elif system_platform == "Darwin":
        # Check for outdated packages on macOS using brew
        result = subprocess.run(['brew', 'outdated'], capture_output=True, text=True)
        outdated = result.stdout.splitlines()

    elif system_platform == "Windows":
        # Check for outdated software in Windows using winget
        result = subprocess.run(['winget', 'upgrade'], capture_output=True, text=True)
        outdated = result.stdout.splitlines()
    
    return outdated

# Function to check Weak Password Policies
def check_password_policy():
    print("[*] Checking system password policy")
    system_platform = get_platform()
    password_policy = None
    
    if system_platform == "Linux":
        # Check password policy for Linux (checking /etc/login.defs for example)
        with open('/etc/login.defs') as f:
            lines = f.readlines()
            for line in lines:
                if "PASS_MIN_LEN" in line or "PASS_MAX_DAYS" in line:
                    password_policy = line.strip()
    
    elif system_platform == "Darwin":
        # macOS checks for password policies would go here (typically needs to be run via sysadmin commands)
        pass
    
    elif system_platform == "Windows":
        # Use Windows command for password policy check
        result = subprocess.run(['net', 'accounts'], capture_output=True, text=True)
        password_policy = result.stdout
    
    return password_policy

# Function to detect Configuration Misconfigurations (Example: Checking for unused services)
def check_configuration_misconfigurations():
    print("[*] Checking for configuration misconfigurations")
    misconfigurations = []
    system_platform = get_platform()
    
    if system_platform == "Linux":
        # For Linux, check for unused services using systemctl
        result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=inactive'], capture_output=True, text=True)
        misconfigurations = result.stdout.splitlines()

    elif system_platform == "Darwin":
        # macOS configuration checks (for example, inactive services)
        pass
    
    elif system_platform == "Windows":
        # Windows service checks could be done here
        result = subprocess.run(['sc', 'query', 'type= service'], capture_output=True, text=True)
        misconfigurations = result.stdout.splitlines()

    return misconfigurations

# Function to check Compliance (example with a basic check for missing firewall)
def check_compliance():
    print("[*] Checking compliance for firewall")
    system_platform = get_platform()
    compliance_issues = []
    
    if system_platform == "Linux":
        # Check for ufw
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if "inactive" in result.stdout:
                compliance_issues.append("Firewall is inactive")
        except FileNotFoundError:
            # If ufw is not found, check for firewalld
            try:
                result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
                if "running" not in result.stdout:
                    compliance_issues.append("Firewall is inactive")
            except FileNotFoundError:
                # If firewalld is not found, check for iptables
                try:
                    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                    if "Chain" not in result.stdout:
                        compliance_issues.append("No firewall rules found")
                except FileNotFoundError:
                    compliance_issues.append("No firewall tool found")
    
    elif system_platform == "Darwin":
        # macOS firewall check (example with pfctl)
        result = subprocess.run(['sudo', 'pfctl', '-s', 'info'], capture_output=True, text=True)
        if "No match" in result.stdout:
            compliance_issues.append("Firewall is inactive")

    elif system_platform == "Windows":
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
        if "State" in result.stdout and "OFF" in result.stdout:
            compliance_issues.append("Firewall is turned off")
    
    return compliance_issues

# Function to conduct a basic Vulnerability Scan (using nmap as an example)
def run_vulnerability_scan(ip):
    print("[*] Running vulnerability scan on IP:", ip)
    try:
        result = subprocess.run(['nmap', '-sV', ip], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "nmap is not installed. Install nmap to run vulnerability scans."

# Function to analyze Logs (simple example)
def analyze_logs():
    print("[*] Analyzing system logs")
    log_issues = []
    system_platform = get_platform()
    
    if system_platform == "Linux":
        # Read and parse system logs (e.g., /var/log/syslog)
        try:
            with open('/var/log/syslog', 'r') as f:
                logs = f.readlines()
                for line in logs:
                    if "error" in line.lower():
                        log_issues.append(line.strip())
        except FileNotFoundError:
            log_issues.append("No syslog found.")
    
    elif system_platform == "Darwin":
        # macOS log check could be done using system logs
        pass
    
    elif system_platform == "Windows":
        # Windows event log check (simplified)
        result = subprocess.run(['eventquery', '/l', 'System', '/fi', 'EventType eq error'], capture_output=True, text=True)
        log_issues = result.stdout.splitlines()
    
    return log_issues

# Function for Network Mapping (simple ping sweep for example)
def network_mapping(ip_range):
    print("[*] Conducting network mapping on range:", ip_range)
    active_ips = []
    for ip in range(1, 255):
        ip_address = ip_range + "." + str(ip)
        response = subprocess.run(['ping', '-c', '1', ip_address], capture_output=True, text=True)
        if "bytes from" in response.stdout:
            active_ips.append(ip_address)
    return active_ips

# Main function to run all checks and generate report
def generate_audit_report(ip_address, network_range):
    report = {}
    
    # Conduct checks
    report["Open Ports"] = scan_open_ports(ip_address)
    report["Outdated Software"] = check_outdated_software()
    report["Password Policy"] = check_password_policy()
    report["Configuration Misconfigurations"] = check_configuration_misconfigurations()
    report["Compliance Issues"] = check_compliance()
    report["Vulnerability Scan"] = run_vulnerability_scan(ip_address)
    report["Log Analysis"] = analyze_logs()
    report["Network Mapping"] = network_mapping(network_range)
    
    # Print audit report
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[*] Audit Report Generated: {timestamp}")
    for key, value in report.items():
        print(f"\n[{key}]")
        if isinstance(value, list):
            for item in value:
                print(f"  - {item}")
        else:
            print(f"  - {value}")
    
    # Optionally, save report to file
    with open("audit_report.txt", "w") as f:
        f.write(f"Audit Report Generated: {timestamp}\n\n")
        for key, value in report.items():
            f.write(f"\n[{key}]\n")
            if isinstance(value, list):
                for item in value:
                    f.write(f"  - {item}\n")
            else:
                f.write(f"  - {value}\n")

if __name__ == "__main__":
    ip_address = input("[*] Enter the IP address to audit: ")
    network_range = input("[*] Enter the network range (e.g., 192.168.1): ")
    generate_audit_report(ip_address, network_range)
