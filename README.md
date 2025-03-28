#  Purple Team
## RDP Brute-Force and Command Injection Lab

A hands-on penetration testing project focused on exploiting and securing a vulnerable Windows VM. Demonstrates both offensive and defensive cybersecurity skills, including remote access exploitation, detection engineering, and system hardening.

---

## Skills Learned

- **Vulnerability Assessment** – Discovered a command injection flaw in a web application.
- **Network Reconnaissance** – Scanned and mapped open ports using Nmap.
- **Brute-Force Attacks** – Used Hydra to gain RDP access via password cracking.
- **Remote Access** – Connected to the target using FreeRDP on Linux.
- **PowerShell Scripting** – Created a script to detect and alert on successful RDP logins.
- **Log Analysis** – Parsed Windows Event Logs for login activity (Event ID 4624, Logon Type 10).
- **Input Validation** – Mitigated command injection using `escapeshellarg()` in PHP.
- **System Hardening** – Disabled SMBv1, enforced account lockout, and applied secure configuration.
- **Blue Team Awareness** – Implemented detection, alerting, and preventative controls.
- **Reporting & Documentation** – Detailed the attack lifecycle and corresponding defenses.

---

## Tools Used

- Nmap  
- Hydra  
- FreeRDP (tool to use RDP on linux)
- PowerShell  
- Windows Event Viewer  
- PHP (web app analysis)  
- Linux terminal (Kali-based environment)

---

## Summary

This project simulates a real-world attack chain on a vulnerable Windows VM. After identifying a command injection vulnerability, I escalated access by brute-forcing RDP credentials. Once access was obtained, I implemented detection and mitigation techniques to monitor and harden the system against future attacks.

---

## Exploitation Steps

### 1. Recon & Injection
- Discovered open ports with Nmap:
  ```bash
  nmap -sV 10.0.2.15
- This revealed port 80 and port 3389 were open for http and rdp respectively.
- ![image](https://github.com/user-attachments/assets/4de54071-ee01-4a54-beb7-fb3cb8b1be37)
- Injected payload 8.8.8.8 && whoami to confirm command injection.
- Output returned bob, confirming successfull.
- ![image](https://github.com/user-attachments/assets/44685505-d81d-4ef0-9be2-1ff79fb80de6)
### 2. Brute-Forcing RDP
- Used Hydra with a custom wordlist:
  ```bash
  hydra -l bob -P password.txt rdp://10.0.2.15
  ![image](https://github.com/user-attachments/assets/c64eb532-5535-4bf6-a1b6-dfba0e928a20)
- Cracked the password and used free RDP for remote access
  ```bash
  xfreerdp3 /v:10.0.2.15 /u:bob /p:password
### 3. Detection and Alerting
- Enabled auditing on the VM and built a PowerShell script to detect successful RDP logins via Event ID 4624 Logon Type 10.
- Whenever RDP logon is successful, an email is sent to the IT department.
- This is an excerpt from the script
  ![image](https://github.com/user-attachments/assets/0a0389af-e274-45d1-97f5-4d94237b9ec6)
- This Powershell script gets the date/time, IP and emails the IT team.
### 4. Mitigations
- Fixing command injection with input sanitation in php
  ```php
  $ip = escapeshellarg($_POST['ip']);
  $output = shell_exec("ping " . $ip);
- Fixed RDP brute-force
- Enforced account lockout policy after 5 failed login attempts via PowerShell
  ```powershell
  # Set maximum failed login attempts before account lockout
  net accounts /lockoutthreshold:5

  # Set lockout duration (in minutes) – how long account stays locked
  net accounts /lockoutduration:15
- SMB Hardening
- Disabled SMBv1 to reduce attack surface
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
  
