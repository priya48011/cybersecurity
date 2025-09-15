# Threat Event (Unauthorized Local User Creation)
**Detection of Unauthorized Account Created for Persistence**

## Reason for Hunt:
- ***Unusual System Behavior:*** SOC noticed local accounts being created outside of IT change windows.
- Threat actors often create ***hidden local users*** to maintain access after compromise.

  ---
  
## Steps the "Bad Actor" took Create Logs and IoCs:
1. Create a new local user account: ```net user hackeruser P@ssw0rd123! /add```
2. Add the new account to the local Administrators group: ```net localgroup administrators hackeruser /add```
3. Log in with the newly created hackeruser account.
4. Create a file on the desktop called ```persistence-proof.txt```.
5. Log out.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detects the Firefox installer download and the creation of firefox.exe in the application folder. |


---

## Related Queries:
```kql
// Detect Firefox installer downloads
DeviceFileEvents
| where FileName has "Firefox Setup"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath

// Detect Firefox being installed
DeviceFileEvents
| where FileName == "firefox.exe"
| where FolderPath contains "Mozilla Firefox"
| project Timestamp, DeviceName, FileName, FolderPath

// Detect Firefox launches
DeviceProcessEvents
| where FileName == "firefox.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

## Created By:
- **Author Name**: Priya Jindal 
- **Date**: August 11, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August 11, 2025`  | `Priya Jindal`   

