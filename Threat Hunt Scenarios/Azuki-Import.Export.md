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

## Flag 11 — Bundling / Staging Artifacts

### Objective:

Detect consolidation of artifacts into a single location or package for transfer.

### Finding:

Recon artifacts were bundled into a ZIP file.

### Query Used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessUniqueId == 2533274790397065
| where ActionType == "FileCreated"
| where FileName contains ".zip"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1004" height="59" alt="image" src="https://github.com/user-attachments/assets/5083786f-0fa5-49f5-893b-dc7b6926e4fd" />

**Flag Answer:** C:\Users\Public\ReconArtifacts.zip

---

## Flag 12 — Outbound Transfer Attempt (Simulated)

### Objective:

Identify attempts to move data off-host or test upload capability.

### Finding:

After ReconArtifacts.zip was created, there were connection attempts to the outbound IP 100.29.147.161. No successful file upload confirmed. 

### Query Used:
```
DeviceNetworkEvents 
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where InitiatingProcessCommandLine == "\"powershell.exe\" "
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
```
<img width="1288" height="92" alt="image" src="https://github.com/user-attachments/assets/eee8c1df-c2cd-47fa-82a6-8c8334abcb8e" />

**Flag Answer:** 100.29.147.161

---

## Flag 13 — Scheduled Re-Execution Persistence

### Objective:

Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

### Finding:

A scheduled task named SupportToolUpdater ensured continued execution.

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where InitiatingProcessUniqueId == 2533274790397065
| where ProcessCommandLine has_any ("schtasks", "Create")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
<img width="1406" height="233" alt="image" src="https://github.com/user-attachments/assets/1565c419-8d93-4077-a340-707b76ac2846" />

**Flag Answer:** SupportToolUpdater

---

## Flag 14 — Autorun Fallback Persistence

### Objective:

Detect lightweight autorun entries placed as backup persistence in user scope.

### Finding:

Unable to retrieve autorun registry record in the available data due to data retention expiry. CTF Admin confirm RemoteAssistUpdater.

### Query Used:
```
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-15))
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="330" height="85" alt="image" src="https://github.com/user-attachments/assets/912a7b7b-4c72-47df-9405-84d72c4626ed" />

**Flag Answer:** RemoteAssistUpdater

---

## Flag 15 — Planted Narrative / Cover Artifact

### Objective:

Identify narrative or misdirection artifacts.

### Finding:

A shortcut file, SupportChat_log.lnk, was created and accessed. implying/mimicking help desk session. 

### Query Used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where ActionType == "FileCreated" 
    or ActionType == "FileModified"
| where FileName endswith ".txt" 
    or FileName endswith ".lnk" 
    or FileName endswith ".log"
| project TimeGenerated, FileName, ActionType, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="987" height="144" alt="image" src="https://github.com/user-attachments/assets/5d938ada-bd17-4bff-b0b9-295b2ea5cc55" />

**Flag Answer:** SupportChat_log.lnk

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

User directories remain among the highest-risk execution points.
Fake artifacts can distort later investigations.
Intern-operated systems require enhanced monitoring.
Telemetry gaps (registry/log rollover) hinder complete analysis.

---

# Recommendations

1. Quarantine infected endpoints.
2. Delete SupportTool.ps1, DefenderTamperArtifact.lnk, ReconArtifacts.zip, and SupportChat_log.lnk.
3. Remove SupportToolUpdater and registry key RemoteAssistUpdater
4. Enforce PowerShell restrictions and enable script block logging.
5. Block script execution from Downloads using AppLocker.
6. Harden intern systems with least privilege + mandatory MFA.
7. Monitor for recon commands (qwinsta, whoami, wmic, tasklist).
8. Restrict outbound traffic to known-good destinations.
9. Detect ZIP creation in public user paths.
10. Alert on scheduled task creation and Run key changes.
11. Train users on fake support session social engineering patterns.
