

# Threat Hunt Report: Unauthorized FireFox Installation
- [Scenario Creation](https://github.com/priya48011/cybersecurity/blob/main/Threat%20Hunt%20Scenarios/Unauthorized%20Firefox%20installation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Mozilla Firefox Browser

##  Scenario

Management suspects that some employees are installing and using Firefox to bypass corporate browsing restrictions and avoid monitoring tools tied to the approved browser (Microsoft Edge). This suspicion arose after security analysts observed HTTP User-Agent strings for Firefox in proxy logs, even though Firefox is not an approved application. Additionally, an anonymous helpdesk ticket reported a colleague bragging about “using a faster browser” for personal web browsing during work hours.

The goal is to detect any instances of Firefox installation and usage, then determine the scope of non-compliance.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for firefox.exe or Mozilla Firefox directory creation.
- **Check `DeviceProcessEvents`** or Firefox installation or usage events.


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

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-02T05:38:41.4752944Z`
- **Event:** The user “priya” downloaded a file named “tor-browser-windows-x86_64-portable-14.0.6.exe” to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\priya\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-02T05:43:08.0346809Z`
- **Event:** The user "priya" executed the file “tor-browser-windows-x86_64-portable-14.0.6.exe” in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\priya\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-02T05:45:31.9957274Z`
- **Event:** User "priya" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\priya\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-02T05:45:44.6577035Z`
- **Event:** A network connection to IP “202.169.99.195” on port “9001” by user "priya" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\priya\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-02T05:45:57.0201471Z` - Local connection to '127.0.0.1' on port '9150'.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "priya" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-03T00:59:20.1157225Z`
- **Event:** The user "priya" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\priya\Desktop\tor-shopping-list.txt`

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
