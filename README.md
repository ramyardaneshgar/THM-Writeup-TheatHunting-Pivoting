TheatHunting-Pivoting
ThreatHunting: Pivioting -  DCSync, Pass-the-Hash, and SeImpersonatePrivilege abuse, using tools like SharpHound, Impacket, and PrintSpoofer to exploit credentials and achieve lateral movement.

By Ramyar Daneshgar

---

#### **Objective**
My goal in this lab was to identify adversarial activities in a compromised network, focusing on detecting signs of **Discovery**, **Privilege Escalation**, **Credential Access**, and **Lateral Movement** tactics. Using a structured approach, I relied on event log analysis, parent-child process tracing, and behavioral patterns to pinpoint the malicious activity.

---

### **Task 1: Discovery Tactic**

#### **Objective:**  
To identify reconnaissance activities that an adversary might perform to gather information about the systems and networks for further exploitation.

---

#### **Steps and Reasoning**

1. **Hunting Host Enumeration Commands**  
   - I started by looking for signs of **host reconnaissance**. These activities often involve built-in tools such as `whoami`, `net user`, and `systeminfo` that attackers abuse to gather system and user information. 
   - I ran the following **KQL query**:
     ```kql
     winlog.event_id: 1 AND process.name: (whoami.exe OR hostname.exe OR net.exe OR systeminfo.exe OR ipconfig.exe OR netstat.exe OR tasklist.exe)
     ```
   - The logs showed that `bill.hawkins` executed several enumeration commands on `WKSTN-2`. While these commands themselves are legitimate, their frequency and the fact that they were spawned by `cmd.exe` raised a red flag.

2. **Tracing Parent Processes**  
   - To dig deeper, I traced the `cmd.exe` processes back to their **parent process**, using the process ID (PID). My investigation revealed that the parent process was `PowerShell.exe`, which included suspicious arguments:
     - **`IEX` and `downloadstring`** suggested a remote payload execution.
     - **`-WindowStyle hidden`** and **`-ep bypass`** indicated an attempt to execute a PowerShell script covertly.
   - This confirmed that the attacker likely used **PowerShell** to download and execute a remote script, such as a reverse shell or a Command-and-Control (C2) agent.

3. **Detecting Internal Port Scanning**  
   - I then shifted my focus to **internal network scanning**. Using the **packetbeat-* index**, I identified unusual internal connections by querying for connections to well-known ports:
     ```kql
     source.ip: 10.0.0.0/8 AND destination.ip: 10.0.0.0/8 AND destination.port < 1024
     ```
   - The results showed that `WKSTN-2` initiated over 1,000 unique connections to `INTSRV01`. The process initiating these connections was identified as `n.exe`, and further analysis revealed that its parent was again `PowerShell.exe`.

4. **Identifying Active Directory Enumeration**  
   - Finally, I searched for **Active Directory reconnaissance**, focusing on processes initiating LDAP queries (ports 389 and 636). My query was:
     ```kql
     winlog.event_id: 3 AND destination.port: (389 OR 636) AND NOT process.name: mmc.exe
     ```
   - The analysis revealed that the binary `SharpHound.exe`—commonly associated with BloodHound—was executed to enumerate Active Directory objects. This indicated the attacker was mapping the domain for privileged accounts or misconfigurations.

**Findings:**  
The attacker used legitimate tools (`whoami`, `systeminfo`, etc.), PowerShell scripts, and reconnaissance utilities (SharpHound) to gather critical information about the environment.

---

### **Task 2: Privilege Escalation Tactic**

#### **Objective:**  
To identify how the attacker elevated their privileges to gain `SYSTEM`-level access.

---

#### **Steps and Reasoning**

1. **Detecting SeImpersonatePrivilege Abuse**  
   - I hunted for processes executed by the `SYSTEM` account but initiated by low-privileged users. This often indicates **privilege escalation** through tools like **PrintSpoofer**. My query was:
     ```kql
     winlog.event_id: 1 AND user.name: SYSTEM AND NOT winlog.event_data.ParentUser: "NT AUTHORITY\SYSTEM"
     ```
   - The results showed that `IIS APPPOOL\DefaultAppPool` executed a binary named `spoofer.exe`, which then spawned processes under the `SYSTEM` account. This account is typically used by IIS web servers and should not execute arbitrary binaries.
   - Further analysis of `spoofer.exe` via VirusTotal confirmed it as **PrintSpoofer**, a tool that exploits `SeImpersonatePrivilege`.

2. **Identifying Service Permission Abuse**  
   - To detect service exploitation, I searched for **registry modifications** to the `ImagePath` key, which attackers often modify to execute arbitrary binaries under elevated privileges:
     ```kql
     winlog.event_id: 13 AND registry.path: *HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath*
     ```
   - The logs showed that `bill.hawkins` modified the `SNMPTRAP` service to execute `update.exe` located in their user directory. Upon restarting the service, this binary ran with `SYSTEM` privileges.

**Findings:**  
The attacker exploited `SeImpersonatePrivilege` and abused service permissions to escalate their privileges to `SYSTEM`.

---

### **Task 3: Credential Access Tactic**

#### **Objective:**  
To uncover attempts to harvest credentials from memory, files, or domain controllers.

---

#### **Steps and Reasoning**

1. **Detecting LSASS Dumping**  
   - I searched for file creation events related to `lsass.DMP`, a common indicator of credential dumping:
     ```kql
     winlog.event_id: 11 AND file.path: *lsass.DMP
     ```
   - The results revealed that `taskmgr.exe` created a dump of the LSASS process in the `AppData\Local\Temp` directory, likely for offline credential extraction.

2. **Hunting DCSync Attacks**  
   - To detect **DCSync** attacks (which leverage replication privileges to dump domain credentials), I queried for unauthorized replication events:
     ```kql
     winlog.event_id: 4662 AND winlog.event_data.Properties: (*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*)
     ```
   - The logs showed that the account `backupadm`—with domain replication privileges—replicated directory information from `DC01`. This confirmed the theft of domain credentials.

**Findings:**  
The attacker used `taskmgr.exe` to dump LSASS and performed a DCSync attack to steal credentials.

---

### **Task 4: Lateral Movement Tactic**

#### **Objective:**  
To track adversarial movement between hosts using valid credentials and tools.

---

#### **Steps and Reasoning**

1. **Analyzing WMI Lateral Movement**  
   - I investigated suspicious **WMI activity**, often used by attackers to remotely execute commands:
     ```kql
     winlog.event_id: 1 AND process.parent.name: WmiPrvSE.exe
     ```
   - The process `WmiPrvSE.exe` spawned multiple `cmd.exe` processes on `WKSTN-1`, executed by `clifford.miller`. These commands included unusual output redirection to `ADMIN$`, strongly indicating the use of **Impacket’s wmiexec.py**.

2. **Detecting Pass-the-Hash Authentication**  
   - I searched for signs of **Pass-the-Hash** (PtH) attacks using this query:
     ```kql
     winlog.event_id: 4624 AND winlog.event_data.LogonType: 3 AND winlog.event_data.KeyLength: 0
     ```
   - The logs showed that `clifford.miller` authenticated to `WKSTN-1` from `10.10.184.105` using a hash. Subsequent process creation events confirmed malicious activity.

**Findings:**  
The attacker moved laterally using WMI and PtH, leveraging credentials harvested from earlier activities.

---

### **Lessons Learned**

1. **Indicators of Compromise (IoCs):**
   - Use of `SharpHound`, `PrintSpoofer`, and `Impacket` tools.
   - Suspicious modifications to service registry keys.
   - Unauthorized directory replication and LSASS dumping.

2. **Detection Improvements:**
   - Enable enhanced auditing for `PowerShell` execution and registry modifications.
   - Monitor processes like `WmiPrvSE.exe`, `cmd.exe`, and `taskmgr.exe` for unusual activity.

3. **Response Recommendations:**
   - Rotate credentials for compromised accounts (`bill.hawkins`, `backupadm`).
   - Harden service permissions and restrict the `SeImpersonatePrivilege`.
   - Isolate compromised hosts (`WKSTN-2`, `INTSRV01`) for forensic analysis.
