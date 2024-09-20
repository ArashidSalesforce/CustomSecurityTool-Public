import os
import nmap
import subprocess
import socket
import re
import json
import time
import asyncio
import smtplib
from dotenv import load_dotenv  # For loading environment variables
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from threading import Thread
from fail2ban.client import Fail2BanClient  # Example usage of fail2ban

# ===== Load Environment Variables =====
load_dotenv()  # Load sensitive data from .env file

SENDER_EMAIL = os.getenv("SENDER_EMAIL")  # Email stored in environment variables
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
TO_EMAIL = os.getenv("TO_EMAIL")

# ===== Email Sending Function =====
def send_email(subject, body, to_email):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    message = MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection with TLS
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, message.as_string())
        server.close()
        print(f"Email alert sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# ===== Vulnerability Scanner =====
async def scan_vulnerabilities(target_ip):
    print(f"Starting vulnerability scan on {target_ip}")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-sV')  # -sV scans for service versions
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
        to_email=TO_EMAIL
    )
    return scan_data

# ===== Firewall Management with fail2ban Integration =====
def block_ip(ip):
    client = Fail2BanClient()
    try:
        client.set_add_jail_action('sshd', 'ban', ip)
        print(f"Blocked IP: {ip}")
        send_email(
            subject="Blocked IP",
            body=f"Suspicious IP {ip} has been blocked.",
            to_email=TO_EMAIL
        )
    except Exception as e:
        print(f"Failed to block IP: {e}")

# ===== Port Monitoring (Async) =====
async def check_open_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port} is open on {ip}")
        send_email(
            subject="Open Port Detected",
            body=f"Port {port} is open on {ip}.",
            to_email=TO_EMAIL
        )
    sock.close()

async def monitor_ports(ip, ports):
    print(f"Starting continuous port monitoring on {ip}")
    while True:
        await asyncio.gather(*(check_open_port(ip, port) for port in ports))
        await asyncio.sleep(30)  # Wait 30 seconds before checking again

# ===== Log Monitoring with fail2ban =====
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
                    to_email=TO_EMAIL
                )
                failed_logins.append(line)
        
        time.sleep(60)  # Check logs every 60 seconds

# ===== Report Generation =====
def generate_report(scan_data, filename='security_report.json'):
    with open(filename, 'w') as report_file:
        json.dump(scan_data, report_file, indent=4)
    print(f"Security report saved to {filename}")

# ===== Scheduler for Vulnerability Scan =====
async def scheduled_vulnerability_scan(ip, interval_hours=24):
    print(f"Scheduled vulnerability scan every {interval_hours} hours for {ip}")
    while True:
        scan_data = await scan_vulnerabilities(ip)
        generate_report(scan_data)
        await asyncio.sleep(interval_hours * 3600)  # Convert hours to seconds

# ===== Main Function (Async) =====
async def main():
    # Configuration
    target_ip = "192.168.1.1"  # Replace with your target IP
    ports_to_monitor = [22, 80, 443]  # Example ports to monitor

    # Start the tasks asynchronously
    tasks = [
        monitor_ports(target_ip, ports_to_monitor),
        scheduled_vulnerability_scan(target_ip),
    ]

    # Run tasks concurrently
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
