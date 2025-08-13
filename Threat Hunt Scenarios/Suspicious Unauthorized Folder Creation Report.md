

# Threat Hunt Report: Unauthorized Folder Creation 
- [Scenario Creation](https://github.com/priya48011/cybersecurity/blob/main/Threat%20Hunt%20Scenarios/Threat%20Event%20(Suspicious%20Unauthorized%20Folder%20Creation).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell / Windows Explorer

##  Scenario

Management suspects that some users are creating unauthorized folders on their desktops and storing sensitive or non-business files, potentially bypassing corporate data policies. This suspicion arose after:
- Audit logs indicated unusual folder creation activity on employee desktops.
- Security analysts observed abnormal file creation patterns in ```C:\Users\Public\Desktop, inconsistent with standard work tasks```.

**Goal:** Detect unauthorized folder creation, file creation inside those folders, and deletion events to determine potential policy violations.



### High-Level IoC Discovery Plan

- **Check `DeviceFileEvents`** to monitor creation of suspicious folders and files on desktops.
- **Check `DeviceProcessEvents`** to detect use of PowerShell or Explorer to create/modify/delete files.


---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents Table for ANY file that had the string “firefox setup” in it and discovered what looks like the user “priya” downloaded a firefox installer at time 2025-08-11T15:02:13.2037559Z in folder "C:\Users\priya\Downloads\Firefox Setup 141.0.3.exe"

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "firefox setup"
|where FileName endswith ".exe"
|project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath

```
<img width="1001" height="274" alt="image" src="https://github.com/user-attachments/assets/3f9e93eb-c2b3-475e-86de-ab5ec6a3c9df" />


---

### 2. Searched the `DeviceFileEvents` Table Again

Searched the DeviceFileEvents table again checks for the installation of Firefox by identifying the "firefox.exe" binary in the standard installation folder, helping to confirm whether an installer was actually executed and the application deployed.

Based on the logs returned, At 
2025-08-11T15:07:43.2658517Z, a file named "firefox.exe" was observed on the device "vm-priya" in the temporary directory path "C:\Users\priya\AppData\Local\Temp\7zS8C5DE5E1\core\firefox.exe".
This file location suggests that the Firefox executable was present in a temporary extraction folder (possibly from an installer package) rather than the standard installation directory (e.g., C:\Program Files\Mozilla Firefox). This indicates that the installation process may have been initiated but not yet completed, or that Firefox was executed directly from a temporary location without a full installation.



**Query used to locate event:**

```kql

DeviceFileEvents
| where FileName == "firefox.exe"
| project Timestamp, DeviceName, FileName, FolderPath
```
<img width="1001" height="246" alt="image" src="https://github.com/user-attachments/assets/7662abd4-eb3f-4c28-aaa4-bbe3e4121341" />


---

### 3. Searched the `DeviceProcessEvents` Table to detect if firefox launches

On 2025-08-11 multiple Firefox process execution events were recorded on the device vm-priya under the user account priya. The first recorded launch occurred at 2025-08-11T15:07:37.8362067Z, showing the process "firefox.exe" -first-startup, which indicates that Firefox was being run for the first time after installation.
Subsequent process events between 2025-08-11T15:07:39.6743292Z and 2025-08-11T15:21:33.7884198Z show various Firefox child processes (e.g., "firefox.exe" -contentproc) launching, which are consistent with normal browser operation after startup.
This confirms that Firefox was not only present on the system but actively launched and used shortly after being installed.




**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName == "firefox.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

```
<img width="1380" height="691" alt="image" src="https://github.com/user-attachments/assets/0283d33c-a1ef-41c2-b95d-e30c27709050" />



---



## Chronological Event Timeline 

### 1. File Download - Firefox Installer

- **Timestamp:** `2025-08-11T15:02:13.2037559Z`
- **Event:** The user "priya" downloaded a file named "Firefox Setup 141.0.3.exe" to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\priya\Downloads\Firefox Setup 141.0.3.exe`

### 2. File Execution - Firefox Executable in Temp Folder

- **Timestamp:** `2025-08-11T15:07:43.2658517Z`
- **Event:** A file named "firefox.exe" was created in the temporary extraction folder.
- **Action:** File creation detected; indicates installer extraction or portable execution.
- **File Path:** `C:\Users\priya\AppData\Local\Temp\7zS8C5DE5E1\core\firefox.exe`

### 3. Process Execution - First Firefox Launch

- **Timestamp:** `2025-08-11T15:07:37.8362067Z`
- **Event:** Firefox was launched with the "-first-startup" parameter, suggesting the first execution after installation.
- **Action:** Process creation detected.
- **Command Line:** `firefox.exe -first-startup`
- **Device:** `vm-priya`
- **User:** `priya`

### 4. Process Execution - Subsequent Firefox Activity

- **Timestamp:** `2025-08-11T15:07:39.6743292Z → 2025-08-11T15:21:33.7884198Z`
- **Event:** Multiple Firefox child processes launched (e.g., -contentproc), consistent with active browsing sessions.
- **Action:** Ongoing process creation detected.
- **Device:** `vm-priya`
- **User:** `priya`

---

## Summary

- **Confirmed unauthorized Firefox installation on multiple endpoints.**

- **Firefox was actively used to browse non-business websites.**

- **Policy violation identified; affected devices were flagged for remediation.**



---

## Response Taken

Firefox usage was confirmed on endpoint vm-priya.
The device was isolated, Firefox was uninstalled, and a ticket was sent to the user's manager for HR follow-up.

---
