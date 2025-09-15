

# Threat Hunt Report: Unauthorized Local User Creation
- [Scenario Creation](https://github.com/priya48011/cybersecurity/blob/main/Threat%20Hunt%20Scenarios/Unauthorized%20Local%20User%20Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

##  Scenario

Management suspects that an unauthorized local user account may have been created on endpoints to maintain persistence and bypass normal access controls. This suspicion arose after anomalous security events were detected in SecurityEvent logs (EventID 4720: user account created).

The goal is to detect any new local user accounts, verify their creation, and determine if elevated privileges were assigned.

### High-Level IoC Discovery Plan

- **Check `DeviceProcessEvents`** for execution of commands like net user /add or net localgroup administrators.
- **Check `DeviceLogonEvents`** for login and any suspicious action

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for any process execution involving net user to detect account creation. No additional file-based proof of activity (like desktop files) was performed.

Based on the logs returned, At 2025-09-15T17:08:28.5752212Z, an account was created from name 'hacker' by user 'labuser'. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("net", "user")
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

```
<img width="1075" height="152" alt="image" src="https://github.com/user-attachments/assets/07492e07-f7e9-45c0-9bfd-ab85303d0c18" />

---

### 2. Searched the `DeviceProcessEvents` Table Again

Searched the DeviceProcessEvents table again checks if new account was added to the local Administrators group.

Based on the logs returned, At 2025-09-15T17:09:11.088956Z, account "hacker" was added to local Administrators group.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine has "localgroup adminstrators"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
<img width="1075" height="152" alt="image" src="https://github.com/user-attachments/assets/a2719ed2-622f-40f5-a483-365125614958" />



---

### 3. Searched the `DeviceLogonEvents` Table to detect if user logged in

On 2025-09-15T17:19:09.7487224Z, User logged in to 'hacker' account for the first time, followed by multiple login attempts but no suspicious activity finds out. 

**Query used to locate events:**

```kql
DeviceLogonEvents
| where AccountName == "hacker"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP

```
<img width="1075" height="217" alt="image" src="https://github.com/user-attachments/assets/c544f173-3814-49df-8d4f-214da3f04199" />




---



## Chronological Event Timeline 

### 1. Local Account Creation

- **Timestamp:** `2025-09-15T17:08:28.5752212Z`
- **Event:** The user `labuser` executed a command to create a new local account named `hacker`.
- **Action:** Account creation detected via DeviceProcessEvents.
- **Device:** `labuser-vm`
- **Command Line:** `net localgroup administrators hacker /add`


### 2. Elevated Privileges Assigned

- **Timestamp:** `2025-09-15T17:09:11.088956Z`
- **Event:** The newly created hacker account was added to the local Administrators group.
- **Action:** Privilege escalation detected via DeviceProcessEvents.
- **File Path:** `C:\Users\priya\AppData\Local\Temp\7zS8C5DE5E1\core\firefox.exe`
- **Device:** `labuser-vm`
- **Command Line:** `net localgroup administrators hacker /add`

### 3. First Login Attempt

- **Timestamp:** `2025-09-15T17:19:09.7487224Z`
- **Event:** User labuser logged in to the hacker account for the first time.
- **Action:** Login detected via DeviceLogonEvents.
- **Device:** `labuser-vm`
- **Account:** `hacker`
- **Observation:** Multiple login attempts observed; no suspicious activity detected beyond the first login.
---

## Summary

- **Confirmed unauthorized local user creation (hacker).**

- **Account was added to Administrators group, providing elevated privileges.**

- **No additional activity (login or file creation) was observed**
- **This scenario demonstrates a persistence technique and insider risk that SOC teams should monitor.**

---

## Response Taken

- **Security team flagged the endpoint labuser-vm for review.**

- **The unauthorized user account hacker was removed.**

- **Elevated privileges were revoked.**

- **Incident documented for further HR and IT follow-up.**

---
