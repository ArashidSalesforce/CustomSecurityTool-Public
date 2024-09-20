import nmap
import subprocess
import socket
import os
import re
import json
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from threading import Thread

# ===== Email Sending Function =====
def send_email(subject, body, to_email):
    # Email Configuration
    sender_email = "your_email@gmail.com"  # Replace with your email
    sender_password = "your_password"  # Replace with your email password
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    # Create message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject

    # Add body to the email
    message.attach(MIMEText(body, "plain"))

    # Send email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, message.as_string())
        server.close()
        print(f"Email alert sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# ===== Vulnerability Scanner =====
def scan_vulnerabilities(target_ip):
    print(f"Starting vulnerability scan on {target_ip}")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-sV')  # -sV scans for versions
    scan_data = {}
    for host in nm.all_hosts():
        scan_data['host'] = host
        scan_data['status'] = nm[host].state()
        scan_data['ports'] = []
        for protocol in nm[host].all_protocols():
            ports = nm[host][protocol].keys()
            for port in ports:
                service_info = nm[host][protocol][port]
                scan_data['ports'].append({
                    'port': port,
                    'state': service_info['state'],
                    'service': service_info['name'],
                    'version': service_info.get('version', 'N/A')
                })
    print(f"Vulnerability scan completed for {target_ip}")
    send_email(
        subject="Vulnerability Scan Completed",
        body=f"Vulnerability scan completed for {target_ip}. Check report for details.",
        to_email="your_email@gmail.com"
    )
    return scan_data

# ===== Firewall Management =====
def block_ip(ip):
    try:
        command = f'sudo iptables -A INPUT -s {ip} -j DROP'
        subprocess.run(command, shell=True, check=True)
        print(f"Blocked IP: {ip}")
        send_email(
            subject="Blocked IP",
            body=f"Suspicious IP {ip} has been blocked.",
            to_email="your_email@gmail.com"
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP: {e}")

# ===== Port Monitoring =====
def check_open_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port} is open on {ip}")
        send_email(
            subject="Open Port Detected",
            body=f"Port {port} is open on {ip}.",
            to_email="your_email@gmail.com"
        )
    else:
        print(f"Port {port} is closed on {ip}")
    sock.close()

def monitor_ports(ip, ports):
    print(f"Starting continuous port monitoring on {ip}")
    while True:
        for port in ports:
            check_open_port(ip, port)
        time.sleep(30)  # Wait for 30 seconds before checking again

# ===== Log Monitoring =====
def monitor_log_for_failed_logins(log_file='/var/log/auth.log'):
    print(f"Monitoring log for failed login attempts: {log_file}")
    failed_logins = []
    while True:
        with open(log_file, 'r') as file:
            log_data = file.readlines()
        
        for line in log_data:
            if re.search('Failed password', line) and line not in failed_logins:
                print(f"Failed login detected: {line.strip()}")
                send_email(
                    subject="Failed Login Attempt",
                    body=f"Failed login attempt detected: {line.strip()}",
                    to_email="your_email@gmail.com"
                )
                failed_logins.append(line)
        
        time.sleep(60)  # Check logs every 60 seconds

# ===== Report Generation =====
def generate_report(scan_data, filename='security_report.json'):
    with open(filename, 'w') as report_file:
        json.dump(scan_data, report_file, indent=4)
    print(f"Security report saved to {filename}")

# ===== Scheduler for Vulnerability Scan =====
def scheduled_vulnerability_scan(ip, interval_hours=24):
    print(f"Scheduled vulnerability scan every {interval_hours} hours for {ip}")
    while True:
        scan_data = scan_vulnerabilities(ip)
        generate_report(scan_data)
        time.sleep(interval_hours * 3600)  # Convert hours to seconds

# ===== Main Function =====
def main():
    # Configuration
    target_ip = "192.168.1.1"  # Replace with your target IP
    ports_to_monitor = [22, 80, 443]  # Example ports to monitor
    recipient_email = "your_email@gmail.com"  # Replace with your email address

    # Start the port monitoring in a separate thread (runs continuously)
    port_monitoring_thread = Thread(target=monitor_ports, args=(target_ip, ports_to_monitor))
    port_monitoring_thread.start()

    # Start log monitoring in a separate thread (runs continuously)
    log_monitoring_thread = Thread(target=monitor_log_for_failed_logins)
    log_monitoring_thread.start()

    # Schedule vulnerability scans (runs every X hours)
    vulnerability_scan_thread = Thread(target=scheduled_vulnerability_scan, args=(target_ip,))
    vulnerability_scan_thread.start()

    # Join threads (to keep the main thread running)
    port_monitoring_thread.join()
    log_monitoring_thread.join()
    vulnerability_scan_thread.join()

if __name__ == "__main__":
    main()
