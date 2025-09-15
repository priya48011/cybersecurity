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

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**|Detect execution of net user and net localgroup commands.|
|||
| **Name**| DeviceLogonEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table|
| **Purpose**|Detect logins from the newly created hacker account.|


---

## Related Queries:
```kql
// Detect suspicious local user creation
DeviceProcessEvents
| where ProcessCommandLine has_any ("net", "user")
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

// Detect adding user to Administrators group
DeviceProcessEvents
| where ProcessCommandLine has "localgroup administrators"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

// Detect logins from suspicious local accounts
DeviceLogonEvents
| where AccountName == "hacker"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
```

---

## Created By:
- **Author Name**: Priya Jindal 
- **Date**: Sept 15, 2025

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
| 1.0         | Initial draft                  | `Sept 15, 2025`  | `Priya Jindal`   

