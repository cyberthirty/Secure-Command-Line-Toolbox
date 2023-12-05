# List of Linux commands and cybersecurity tools
### File System and Permissions:

#### List Files and Directories:
```bash
ls
ls -l
ls -a
```

#### Change Directory:
```bash
cd <directory>
cd ..
```

#### File Permissions:
```bash
chmod <permissions> <file>
chown <user>:<group> <file>
```

### Process Management:

#### List Running Processes:
```bash
ps aux
```

#### Kill a Process:
```bash
kill <process-id>
```

#### View Process Information:
```bash
top
htop
```

### Networking:

#### Check Network Connections:
```bash
netstat -tulpn
```

#### Check Open Ports:
```bash
nmap <target-ip>
```

#### Packet Capture with Wireshark:
```bash
wireshark
```

### System Information:

#### System Information:
```bash
uname -a
```

#### Disk Usage:
```bash
df -h
```

#### Memory Usage:
```bash
free -m
```

### Users and Authentication:

#### Add User:
```bash
sudo adduser <username>
```

#### Change User Password:
```bash
sudo passwd <username>
```

#### User Groups:
```bash
groups <username>
```

### Security Tools:

#### Firewall Configuration (iptables):
```bash
sudo iptables -L
```

#### SELinux Status:
```bash
sestatus
```

#### Check for Rootkits (rkhunter):
```bash
sudo rkhunter --check
```

#### Monitor Logs (e.g., /var/log/auth.log):
```bash
tail -f /var/log/auth.log
```

### Package Management:

#### Update Package List:
```bash
sudo apt update
```

#### Install Software:
```bash
sudo apt install <package-name>
```

#### Search for Packages:
```bash
apt search <search-term>
```

### Encryption and Hashing:

#### Generate SSH Key:
```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

#### Encrypt and Decrypt Files (GPG):
```bash
gpg --encrypt <file>
gpg --decrypt <file.gpg>
```

#### Calculate File Hash (MD5, SHA-256):
```bash
md5sum <file>
sha256sum <file>
```

### System Hardening:

#### Disable Root Login:
```bash
sudo passwd -l root
```

#### Disable Unused Services:
```bash
sudo systemctl disable <service-name>
```

#### Update and Upgrade System:
```bash
sudo apt update && sudo apt upgrade
```

### Incident Response:

#### Check for Suspicious Files:
```bash
find / -name "*.exe"
```

#### Investigate Network Traffic:
```bash
tcpdump -i <interface>
```

#### Analyze Log Files:
```bash
grep -i "error" /var/log/syslog
```

### Miscellaneous:

#### Download Files (e.g., wget):
```bash
wget <file-url>
```

#### Search for Files (e.g., find):
```bash
find / -name <filename>
```

#### View Running Services:
```bash
sudo service --status-all
```

### Advanced Networking:

#### Check Open Ports and Services (nmap):
```bash
nmap -sV -p- <target-ip>
```

#### Monitor Network Traffic (tcpdump):
```bash
sudo tcpdump -i <interface> -n -nn -vvv
```

#### Analyze Network Packets (Wireshark):
```bash
wireshark
```

#### VPN Connection (OpenVPN):
```bash
sudo openvpn <config-file.ovpn>
```

### Intrusion Detection and Prevention:

#### Snort IDS:
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i <interface>
```

#### Fail2Ban Configuration:
```bash
sudo nano /etc/fail2ban/jail.local
sudo fail2ban-client reload
```

### System Forensics:

#### Memory Analysis (Volatility Framework):
```bash
volatility -f <memory-dump-file> imageinfo
volatility -f <memory-dump-file> pslist
```

#### Disk Forensics (Autopsy):
```bash
sudo autopsy
```

### Web Application Security:

#### Web Application Scanning (Burp Suite):
```bash
java -jar burpsuite_community_v<version>.jar
```

#### Directory and File Enumeration (Dirb):
```bash
dirb http://<target-url>
```

### Penetration Testing:

#### Exploitation Framework (Metasploit):
```bash
msfconsole
```

#### Password Cracking (John the Ripper):
```bash
john --wordlist=<wordlist-file> --format=<hash-format> <hashed-passwords-file>
```

### Container Security:

#### Docker Security Scanning (Trivy):
```bash
trivy <image-name>
```

#### Docker Container Inspection:
```bash
docker inspect <container-id>
```

### Threat Intelligence:

#### IP Reputation Lookup (Cymon):
```bash
curl https://cymon.io/api/nexus/v1/ip/<ip-address>
```

#### Domain Reputation Lookup (VirusTotal):
```bash
curl --request GET --url 'https://www.virustotal.com/api/v3/domains/<domain>' --header 'x-apikey: <api-key>'
```

### Security Automation:

#### Bash Scripting:
```bash
#!/bin/bash
# Your script here
```

#### Python Scripting:
```python
#!/usr/bin/env python3
# Your script here
```

#### Ansible Playbook:
```yaml
---
- name: Your Playbook
  hosts: target_servers
  tasks:
    - name: Your Task
      command: /path/to/your/command
```

### Continuous Security Monitoring:

#### Security Information and Event Management (SIEM) - (e.g., ELK Stack):
```bash
sudo docker-compose up
```

#### Log Analysis with Logstash:
```bash
sudo /etc/init.d/logstash start
```

### Git Commands:

#### Clone a Repository:
```bash
git clone <repository-url>
```

#### Initialize a New Repository:
```bash
git init
```

#### Add Changes to Staging Area:
```bash
git add .
```

#### Commit Changes:
```bash
git commit -m "Your commit message"
```

#### Push Changes to Remote Repository:
```bash
git push origin <branch-name>
```

#### Pull Changes from Remote Repository:
```bash
git pull origin <branch-name>
```

#### Create a New Branch:
```bash
git branch <branch-name>
git checkout -b <branch-name>
```

#### Switch Between Branches:
```bash
git checkout <branch-name>
```

#### Merge Branches:
```bash
git merge <branch-name>
```

#### Check Status:
```bash
git status
```

#### View Commit History:
```bash
git log
```

### Security Scanning Tools:

#### Dependency Scanning (e.g., Snyk):
```bash
snyk test
```

#### Static Application Security Testing (SAST) - (e.g., SonarQube):
```bash
sonar-scanner
```

#### Dynamic Application Security Testing (DAST) - (e.g., OWASP ZAP):
```bash
zap-baseline.py -t <target-url>
```

#### Container Scanning (e.g., Clair):
```bash
clair-scanner <image-name>
```

#### Git Secrets Scan:
```bash
git-secrets --scan
```

#### Check for Common Vulnerabilities and Exposures (CVEs):
```bash
trivy <image-name>
```

### GitHub Actions:

#### Automated Security Checks:
```yaml
name: Security Checks

on:
  push:
    branches:
      - main

jobs:
  security_scan:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v2

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '14'

    - name: Install Dependencies
      run: npm install

    - name: Run Security Checks
      run: |
        snyk test
        sonar-scanner
        # Add other security checks as needed
```

#### Automated Deployment:
```yaml
name: Deploy to Production

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v2

    - name: Deploy to Production
      run: |
        git pull origin main
        # Add deployment commands here
```

### Git LFS (Large File Storage):

#### Track Large Files with Git LFS:
```bash
git lfs track "*.pdf"
```

#### Push Large Files to Git LFS:
```bash
git lfs push origin <branch-name>
```

#### Pull Large Files from Git LFS:
```bash
git lfs pull
```

### Repository Management:

#### Configure Remote Repositories:
```bash
git remote add upstream <upstream-repo-url>
git remote -v
```

#### Fetch Changes from Upstream:
```bash
git fetch upstream
```

#### Rebase Changes:
```bash
git rebase upstream/main
```

### Git Hooks:

#### Pre-Commit Hook (e.g., Format Code):
```bash
# Add to .git/hooks/pre-commit
#!/bin/bash
./format-code.sh
```

#### Post-Commit Hook (e.g., Notify Team):
```bash
# Add to .git/hooks/post-commit
#!/bin/bash
./notify-team.sh
```

### Encryption and Signing:

#### GPG Sign Commits:
```bash
git config --global user.signingkey <your-gpg-key>
git config --global commit.gpgSign true
```

#### Verify GPG Signature:
```bash
git log --show-signature
```

### Miscellaneous:

#### View Git Configuration:
```bash
git config --list
```

#### Create Git Alias:
```bash
git config --global alias.<alias-name> <command>
```

#### Ignore Files:
```bash
# Add to .gitignore
*.log
secrets.yaml
```
