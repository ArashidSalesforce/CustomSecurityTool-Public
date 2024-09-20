import os
import logging
import logging.handlers
from dotenv import load_dotenv
import nmap
import asyncio
import subprocess
import socket
import json
import time

# ===== Load Environment Variables =====
load_dotenv()

PAPERTRAIL_HOST = os.getenv("PAPERTRAIL_HOST")  # e.g., logsX.papertrailapp.com
PAPERTRAIL_PORT = int(os.getenv("PAPERTRAIL_PORT"))  # e.g., 12345
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
TO_EMAIL = os.getenv("TO_EMAIL")

# ===== Set up Papertrail logging =====
logger = logging.getLogger('PapertrailLogger')
logger.setLevel(logging.INFO)

# Set up SysLogHandler for Papertrail
syslog_handler = logging.handlers.SysLogHandler(address=(PAPERTRAIL_HOST, PAPERTRAIL_PORT))
formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s: %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)

# Log message example
logger.info("Papertrail logging initialized.")

# ===== Email Sending Function =====
def send_email(subject, body):
    # Here you can log the email details to Papertrail as well
    logger.info(f"Sending email: Subject: {subject}, Body: {body}")
    try:
        # Your email sending logic...
        logger.info(f"Email alert sent to {TO_EMAIL}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")

# ===== Vulnerability Scanner =====
async def scan_vulnerabilities(target_ip):
    logger.info(f"Starting vulnerability scan on {target_ip}")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-sV')
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
    logger.info(f"Vulnerability scan completed for {target_ip}")
    return scan_data

# ===== Firewall Management for Windows =====
def block_ip(ip):
    try:
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        subprocess.run(command, shell=True, check=True)
        logger.info(f"Blocked IP: {ip}")
        send_email(
            subject="Blocked IP",
            body=f"Suspicious IP {ip} has been blocked."
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP: {e}")

# ===== Port Monitoring (Async) =====
async def check_open_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip, port))
    if result == 0:
        logger.info(f"Port {port} is open on {ip}")
        send_email(
            subject="Open Port Detected",
            body=f"Port {port} is open on {ip}."
        )
    sock.close()

async def monitor_ports(ip, ports):
    logger.info(f"Starting continuous port monitoring on {ip}")
    while True:
        await asyncio.gather(*(check_open_port(ip, port) for port in ports))
        await asyncio.sleep(30)  # Wait 30 seconds before checking again

# ===== Report Generation =====
def generate_report(scan_data, filename='security_report.json'):
    with open(filename, 'w') as report_file:
        json.dump(scan_data, report_file, indent=4)
    logger.info(f"Security report saved to {filename}")

# ===== Scheduler for Vulnerability Scan =====
async def scheduled_vulnerability_scan(ip, interval_hours=24):
    logger.info(f"Scheduled vulnerability scan every {interval_hours} hours for {ip}")
    while True:
        scan_data = await scan_vulnerabilities(ip)
        generate_report(scan_data)
        await asyncio.sleep(interval_hours * 3600)  # Convert hours to seconds

# ===== Main Function (Async) =====
async def main():
    target_ip = "192.168.1.1"
    ports_to_monitor = [22, 80, 443]

    tasks = [
        monitor_ports(target_ip, ports_to_monitor),
        scheduled_vulnerability_scan(target_ip),
    ]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

