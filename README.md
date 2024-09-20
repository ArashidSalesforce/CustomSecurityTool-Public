# CustomSecurityTool-Public

# Custom Security Tool

This custom security tool provides comprehensive monitoring and protection for your system. It integrates several key security features, such as vulnerability scanning, port monitoring, firewall management, and log analysis, with real-time email alerts for any detected issues.

## Features

- **Vulnerability Scanning**: Uses `nmap` to detect open ports and services on a target IP.
- **Port Monitoring**: Continuously monitors specified ports and reports if any unexpected ports are open.
- **Firewall Management**: Blocks suspicious IP addresses using `iptables` (Linux).
- **Log Monitoring**: Monitors system logs for failed login attempts and sends alerts.
- **Email Alerts**: Sends real-time email notifications for important security events (e.g., open ports, failed logins, completed vulnerability scans).
- **Report Generation**: Generates a JSON report after every vulnerability scan.

## Getting Started

### Prerequisites

- **Python 3.x**: Make sure Python is installed.
- **nmap**: Install the `nmap` library on your system for vulnerability scanning.
  ```bash
  sudo apt-get install nmap  # For Ubuntu/Debian-based systems
  ```
- **Python Libraries**: Install the required Python packages:
  ```bash
  pip install python-nmap
  ```

### Running the Tool

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your_username/custom-security-tool.git
   cd custom-security-tool
   ```

2. **Configure Email Alerts**:
   - Update the email credentials in the `send_email()` function inside the Python script.
   - Replace the placeholder values for `your_email@gmail.com` and `your_password` with your actual email and password. (You might want to use environment variables or a more secure method in production.)

3. **Configure Target IP and Ports**:
   - Update the `target_ip` variable with the IP address of the machine you want to monitor.
   - Modify the `ports_to_monitor` list with the ports you want to track (e.g., HTTP, HTTPS, SSH).

4. **Run the Tool**:
   ```bash
   python3 security_tool.py
   ```

5. **Vulnerability Scanning**:
   - The tool automatically schedules vulnerability scans every 24 hours by default (can be changed in the code).

### Key Sections of the Tool

#### 1. Vulnerability Scanning
Uses `nmap` to scan the specified IP for open ports and running services.

#### 2. Firewall Management
Automatically blocks malicious IPs if detected. You can extend this to block any IP flagged as suspicious.

#### 3. Port Monitoring
Monitors important network ports for unexpected behavior. By default, it checks ports 22, 80, and 443, but you can customize it based on your requirements.

#### 4. Log Monitoring
Continuously monitors system logs (e.g., `/var/log/auth.log`) for failed login attempts and sends an email alert if such an event is detected.

#### 5. Email Alerts
Email notifications are sent for the following events:
- Open ports detected
- Failed login attempts
- Vulnerability scan completion
- IP blocking events

### Example Email Alert
Below is an example of the type of alert you would receive in your inbox:
```
Subject: Failed Login Attempt

Failed login attempt detected: Failed password for invalid user from 192.168.1.50 port 22 ssh2
```

## Customization

1. **Adjust Monitoring Frequency**:
   - Change the `time.sleep()` intervals for port monitoring and log monitoring to control how frequently the system checks for issues.
   
2. **Modify the Email Recipient**:
   - Change the `to_email` value in the code to send alerts to another email address.

3. **Add New Event Alerts**:
   - You can expand the email alert functionality to include more events by calling `send_email()` for any new conditions you want to track.

## Security Considerations

- **Email Credentials**: Ensure that your email credentials are secure. Consider using environment variables or a more secure method (like OAuth for Gmail) for production environments.
- **Root Privileges**: The firewall management component requires `sudo` or root privileges to modify `iptables` rules.

## Future Improvements

- Integration with an Intrusion Detection System (IDS) like **Snort** or **Suricata** for more advanced monitoring.
- **Cloud Integration**: Extend to AWS or GCP to monitor and protect cloud-based infrastructure.
- **File Integrity Monitoring**: Add functionality to monitor key files and detect unauthorized changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.
