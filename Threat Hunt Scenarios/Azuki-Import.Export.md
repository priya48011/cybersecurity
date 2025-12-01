# Threat Hunt Report - Azuki Import/Export

**Analyst:** Priya  
**Date:** November 28, 2025  
**Environment:** Microsoft Defender for Endpoint logs  
**Compromised System:** AZUKI-SL (IT admin workstation)  
**Company:** Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia  
**Timeframe Investigated:** Nov 19, 2025 - Nov 20, 2025 

---

## Summary

Azuki Import/Export experienced a targeted compromise resulting in the theft of supplier contracts and pricing data, which later appeared on underground forums. The investigation identified unauthorized remote access to the IT administrator workstation (AZUKI-SL), followed by credential abuse, data discovery, data staging, and exfiltration using living-off-the-land (LOTL) tools. The adversary also attempted to establish persistence and cover their tracks. The activity is consistent with financially motivated corporate espionage.

### Scope

This report analyzes activity occurring between
2025-11-19 to 2025-11-20
on the compromised system AZUKI-SL using Microsoft Defender for Endpoint logs.

### The investigation addresses:

- Initial access method  
- Compromised accounts  
- Data accessed or stolen  
- Exfiltration method  
- Persistence attempts  
- Remaining risk

### Key actions included:

- Remote logon to AZUKI-SL using stolen administrative credentials.
- All malicious activity occurred under kenji.sato (IT admin) account.
- Directory and file enumeration using mkdir, attrib, and New-Item.
- Modification of Windows Defender exclusions to bypass malware detection.
- Deletion or clearing of event logs using wevtutil.exe.
- Usage of native tools (powershell.exe, certutil.exe, curl.exe) to download or stage files. 
- Creation of a scheduled task (schtasks.exe /create) to maintain access. 
- Dropping a “support chat log” as narrative misdirection
- Attempts to hide traces of activity and avoid detection.

---

## Hunt Scope

### Data sources analyzed:

- DeviceLogonEvents
- DeviceProcessEvents   
- DeviceNetworkEvents  
- DeviceRegistryEvents  

### Objectives:

- Identify how the attacker gained initial access and which accounts were compromised.
- Reconstruct attacker activity, including reconnaissance, data staging, and exfiltration attempts.
- Detect persistence mechanisms such as scheduled tasks and autorun registry entries.
- Assess what sensitive data was accessed or stolen and the overall business impact.
- Align with MITRE ATT&CK 
- Provide recommendations for containment, remediation, and improved monitoring.
---

# Flag Summary Table

| Flag | Phase / Focus | Key Event |
|------|---------------|-----------|
| 1 | Initial Access Validation | Successful remote logon to AZUKI-SL from 88.97.178.12 |
| 2 | Account Compromise Confirmation | All activity executed under compromised kenji.sato admin account |
| 3 | Network Reconnaissance | `"ARP.EXE" -a` ARP scans to enumerate nearby hosts |
| 4 | Malware Staging Directory | `C:\ProgramData\WindowsCache` |
| 5 | File Extension Exclusions | 3 Extensions were Exluded from MDE Scanning |
| 6 | Temporary Folder Exclusion | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` was excluded from MDE Scanning |
| 7 | Download Utility Abuse | `certutil.exe` was abused to download files |
| 8 | Scheduled Task Name | Windows Update Check |
| 9 | Scheduled Task Target | Executable path configured `C:\ProgramData\WindowsCache\svchost.exe` |
| 10 | C2 Server Address | 78.141.196.6 |
| 11 | C2 Communication Port | 443 |
| 12 | Credential Theft Tool | mm.exe |
| 13 | Memory Extraction Module | sekurlsa::logonpasswords|
| 14 | Data Staging Archive | export-data.zip |
| 15 | Exfiltration Channel | discord |
| 16 | Log Tampering | Security |
| 17 | Persistence Account | support was created |
| 18 | Malicious Script File |  wupdate.ps1 |
| 19 | Secondary Target | 10.1.0.188 was target for lateral movement |
| 20 | Remote Access Tool | mstsc.exe used for lateral movement |

---

# Flag-by-Flag Analysis  


---

## Flag 1 — Remote Access Source

### Objective:

Identify the source IP address of the Remote Desktop Protocol connection. 

### Finding: 

On Nov 19, at 2025 10:36:18 AM, Attacker successfully gained access from Source "88.97.178.12"

### Query Used:
```
DeviceLogonEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where ActionType == "LogonSuccess"
|order by Timestamp asc
|project Timestamp, DeviceName, ActionType, LogonType, RemoteIP
```
<img width="955" height="276" alt="image" src="https://github.com/user-attachments/assets/f6044772-757e-46c4-8e8f-4e268d5152bb" />

**Flag Answer:** 88.97.178.12

---

## Flag 2 — Compromised User Account

### Objective:

Identify the user account that was compromised for initial access.

### Finding: 

All activities were performed from account "kenji.sato"

### Query Used:
```
DeviceLogonEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where ActionType == "LogonSuccess"
|order by Timestamp asc
|project Timestamp, DeviceName, ActionType, LogonType, RemoteIP, AccountName

```
<img width="1085" height="210" alt="image" src="https://github.com/user-attachments/assets/8bd2c439-0f5a-4709-81a2-1b38a3d4de4b" />

**Flag Answer:** kenji.sato

---

## Flag 3 — Network Reconnaissance

### Objective:

Identify the command and argument used to enumerate network neighbours

### Finding:
ARP scans were used to enumerate nearby hosts using commnad ""ARP.EXE" -a"



### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine has_any("arp")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, ProcessCommandLine

```
<img width="723" height="79" alt="image" src="https://github.com/user-attachments/assets/f89b0ed7-94c7-4837-9acb-707917edf6eb" />


**Flag Answer:** "ARP.EXE" -a

---

## Flag 4 — Malware Staging Directory

### Objective:

Identify the PRIMARY staging directory where malware was stored

### Finding:

The attacker executed attrib.exe on AZUKI-SL using the kenji.sato account to modify folder attributes and hide files. The directory where malware was stored: C:\ProgramData\WindowsCache
### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine has_any("mkdir", "New-Item", "attrib")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine

```
<img width="1343" height="79" alt="image" src="https://github.com/user-attachments/assets/7cd439bf-3a14-4e39-b757-5e8f2819fe36" />

**Flag Answer:** C:\ProgramData\WindowsCache

---

## Flag 5 — File Extension Exclusions

### Objective:

Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

### Finding:

The attacker added 3 file extensions from MDE to prevent scanning. 
### Query Used:
```
DeviceRegistryEvents
|where DeviceName == "azuki-sl"
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where RegistryKey contains "Defender" and RegistryKey contains "Exclusions"
and RegistryKey contains "Extensions"
|summarize RegistryValueName = count()

```
<img width="206" height="79" alt="image" src="https://github.com/user-attachments/assets/5f60224b-df18-4a66-a5ee-7f047a94bc08" />

**Flag Answer:** 3

---

## Flag 6 — Temporary Folder Exclusion

### Objective:

Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

### Finding:

The temporary folder that was excluded from MDE Scanning - C:\Users\KENJI~1.SAT\AppData\Local\Temp

### Query Used:
```
DeviceRegistryEvents
|where DeviceName == "azuki-sl"
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where RegistryKey contains @"Microsoft\Windows Defender\Exclusions\paths"
|project Timestamp, RegistryValueName, RegistryKey

```
<img width="954" height="126" alt="image" src="https://github.com/user-attachments/assets/ab14dcf5-1451-4036-ac65-d6f0d0c06f20" />


**Flag Answer:** C:\Users\KENJI~1.SAT\AppData\Local\Temp

---

## Flag 7 — Download Utility Abuse

### Objective:

Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

### Finding:

The only tool actively used by kenji.sato on AZUKI-SL that can perform file download or data transfer operations was: certutil.exe

### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine has_any ("http://","https://", "C:", "<>")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessVersionInfoOriginalFileName
|distinct FileName

```
<img width="262" height="279" alt="image" src="https://github.com/user-attachments/assets/dc0599e6-3ab2-4d3a-9c31-9ce8b4608cd2" />

```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where FileName has_any ("powershell.exe","certutil.exe", "curl.exe")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessVersionInfoOriginalFileName

```

<img width="1405" height="279" alt="image" src="https://github.com/user-attachments/assets/71a1f3b6-19e4-4311-8bc5-4e5fa6f86638" />

**Flag Answer:** certutil.exe

---

## Flag 8 — Scheduled Task Name

### Objective:

Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

### Finding:

Windows Update Check was the scheduled task. 

**Query Used:**  
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine has_any ("schtasks.exe","/create")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessVersionInfoOriginalFileName

```
<img width="1405" height="112" alt="image" src="https://github.com/user-attachments/assets/2d6bdda4-d36f-4964-ac2f-2b629d1ec68e" />


**Flag Answer:** Windows Update Check

---

## Flag 9 — Scheduled Task Target

### Objective:

The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

### Finding:

The executable path that was configured in scheduled task: C:\ProgramData\WindowsCache\svchost.exe 

### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine has_any ("schtasks.exe","/create","/tr”")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessVersionInfoOriginalFileName

```
<img width="1405" height="303" alt="image" src="https://github.com/user-attachments/assets/6f83c955-df6c-424d-a3e2-606a059028c7" />

**Flag Answer:** C:\ProgramData\WindowsCache\svchost.exe 

---

## Flag 10 — COMMAND & CONTROL - C2 Server Address

### Objective:

Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

### Finding:

IP address belongs to C2 server is 78.141.196.6

### Query Used:
```
DeviceNetworkEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where InitiatingProcessAccountName == "kenji.sato"
|where InitiatingProcessFileName == "certutil.exe"
|project Timestamp, DeviceName, ActionType, RemoteIP, LocalIP,InitiatingProcessFileName, RemotePort

```
<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/d5938053-e990-4119-ab48-6e1d8f3d7078" />

**Flag Answer:** 78.141.196.6

---

## Flag 11 — C2 Communication Port

### Objective:

C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

### Finding:

Destination Port for C2 server is 443

**Flag Answer:** 443

---

## Flag 12 — Credential Theft Tool

### Objective:

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

### Finding:

The file name of credential dumping tool is mm.exe

### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where FileName has_any ("powershell.exe","certutil.exe", "curl.exe")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessVersionInfoOriginalFileName


```
<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/c9c6910e-2d4c-4987-9389-518165572c05" />


**Flag Answer:** mm.exe

---

## Flag 13- CREDENTIAL ACCESS - Memory Extraction Module

Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

### Finding:

sekurlsa::logonpasswords was used to logon passwords from memory. 

### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine  has_any ("::")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine

```
<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/ae36dad8-8bca-4dd5-a2fd-cc1ca4a085cb" />

**Flag Answer:** sekurlsa::logonpasswords

---

## Flag 14- Data Staging Archive
### Objective:

Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

### Finding:

The compressed archive filename used for data exfiltration is export-data.zip


### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where FileName has_any ("powershell.exe","certutil.exe", "curl.exe")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessVersionInfoOriginalFileName

```

<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/ba611234-34ad-44bd-81b4-c144a95c7b5d" />

**Flag Answer:** export-data.zip

---

## Flag 15- Exfiltration Channel

### Objective:

Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

### Finding:

The cloud service used to exfiltrate stolen data is discord

### Query Used:
```
DeviceNetworkEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where InitiatingProcessAccountName == "kenji.sato"
|project Timestamp, DeviceName, ActionType, RemoteIP, LocalIP,InitiatingProcessCommandLine, RemotePort

```
<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/d176f1df-26c2-4a8d-bad7-5cd1fb6bd931" />

**Flag Answer:** discord

---

## Flag 16 - Log Tampering
### Objective:

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

### Finding:

The first Windows event log cleared by the attacker is Security 

### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine  has_any ("wevtutil.exe")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessVersionInfoOriginalFileName

```
<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/344f1810-8a86-4a51-86b7-bf2955af128e" />


**Flag Answer:** Security

---

## Flag 17 - Persistence Account
### Objective:

Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

### Finding:

The backdoor account username created by the attacker is support

### Query Used:
```
DeviceProcessEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where AccountName == "kenji.sato"
|where ProcessCommandLine  has_any (" /add")
|order by Timestamp asc
|project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine

```
<img width="1405" height="93" alt="image" src="https://github.com/user-attachments/assets/e808f405-7390-4063-a4b3-e8be0f6fcaaf" />

**Flag Answer:** support

---

## Flag 18 - Malicious Script
### Objective:

Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

### Finding:

PowerShell script file used to automate the attack chain is  wupdate.ps1

### Query Used:
```
DeviceFileEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where InitiatingProcessAccountName == "kenji.sato"
|where FolderPath has_any ("temp", "download")
|project Timestamp, DeviceName, ActionType, FileName, FolderPath

```
<img width="855" height="252" alt="image" src="https://github.com/user-attachments/assets/3205e3ed-d4db-4088-a555-91b297112171" />


**Flag Answer:**  wupdate.ps1

---

## Flag 19 - LATERAL MOVEMENT - Secondary Target
### Objective:

Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

### Finding:

IP address was targeted for lateral movement is 10.1.0.188

### Query Used:
```
DeviceNetworkEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where InitiatingProcessAccountName == "kenji.sato"
|where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
|project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessCommandLine


```
<img width="969" height="252" alt="image" src="https://github.com/user-attachments/assets/80fc2ad0-dd6d-403c-94b1-4f59984299ca" />

**Flag Answer:**  10.1.0.188

---

## Flag 20 - LATERAL MOVEMENT - Remote Access Tool

### Objective:

Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

### Finding:

The remote access tool used for lateral movement is mstsc.exe

### Query Used:
```
DeviceNetworkEvents
|where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
|where DeviceName == "azuki-sl"
|where InitiatingProcessAccountName == "kenji.sato"
|where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
|project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessCommandLine


```
<img width="969" height="252" alt="image" src="https://github.com/user-attachments/assets/80fc2ad0-dd6d-403c-94b1-4f59984299ca" />

**Flag Answer:**  mstsc.exe

---

# MITRE ATT&CK Mapping

| Flag | Technique ID        | Technique Name                         | Description                               |
|------|----------------------|-----------------------------------------|-------------------------------------------|
| 1    | T1059.001           | PowerShell                              | Script executed with execution policy bypass |
| 2    | T1036               | Masquerading                            | Fake Defender tamper artifact             |
| 3    | T1115               | Clipboard Collection                    | Clipboard probing                         |
| 4,7  | T1033 / T1087       | Account & Session Discovery             | Session/user enumeration                  |
| 5    | T1083               | File and Directory Discovery            | Storage enumeration                       |
| 6,10 | T1016               | Network Discovery                       | Connectivity and DNS checks               |
| 8    | T1057               | Process Discovery                       | tasklist / process enumeration            |
| 9    | T1069               | Permission Group Discovery              | whoami group mapping                      |
| 11   | T1074               | Data Staging                            | Recon data archived                       |
| 12   | T1567               | Exfiltration Over Web                   | Outbound transfer attempt                 |
| 13   | T1053.005           | Scheduled Task                          | Persistence via SupportToolUpdater        |
| 14   | T1547.001           | Registry Run Key                        | Autorun fallback persistence              |
| 15   | T1036.004           | Masquerading: Deception Artifact        | Fake support chat log                     |

---

# Lessons Learned

The compromise of Azuki Import/Export’s IT admin workstation highlights the high risk of overused administrative accounts, insufficient endpoint hardening, and inadequate monitoring of critical security events. The attacker leveraged legitimate tools (LOTL), modified Defender exclusions, cleared logs, and exfiltrated sensitive data without detection. Weak segmentation, lack of multi-factor authentication, and absence of outbound data monitoring allowed rapid lateral movement and persistent access. Overall, the incident underscores the need for stronger privilege management, proactive monitoring, and hardened controls on high-value workstations.

---

# Recommendations

1. Immediately reset all administrative credentials and enforce strong password policies.
2. Remove malicious scheduled tasks, hidden accounts, and files (e.g., WindowsCache, svchost.exe).
3. Restore Microsoft Defender protections and remove any unauthorized exclusions.
4. Block identified C2 IP (78.141.196.6) and monitor suspicious outbound traffic.
5. Rebuild compromised workstations to ensure credential theft artifacts are removed.
6. Enable alerts for high-risk events: log clearing, new local admin accounts, Defender exclusion changes, and unusual RDP logins.
7. Implement MFA for all administrative and remote access accounts.
8. Restrict and monitor the use of administrative tools (certutil, PowerShell, wevtutil, etc.) using AppLocker/WDAC policies.
9. Segment networks to limit lateral movement and isolate administrative workstations.
10. Deploy DLP and outbound traffic monitoring to prevent unauthorized data exfiltration.
