# Threat Event (Suspicious Unauthorized Folder Creation)
**Unauthorized Folder and File Creation on Desktop**

# Reason for Hunt
Unusual system behavior: Management wants to check if users are creating or modifying suspicious files on endpoints, which could indicate insider threat or malware testing.

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Open VM.
2. Create a folder on the Desktop called SecretData: ``` New-Item -Path "C:\Users\Public\Desktop\SecretData" -ItemType Directory ```
3. Create a few dummy text files inside the folder: ``` "This is confidential" | Out-File "C:\Users\Public\Desktop\SecretData\file1.txt"
"Do not share" | Out-File "C:\Users\Public\Desktop\SecretData\file2.txt"```
4. Delete one of the files to simulate a cover-up: ```Remove-Item "C:\Users\Public\Desktop\SecretData\file2.txt"```


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect creation, modification, renaming, and deletion of files/folders on endpoints. |
|||
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect the use of PowerShell or Explorer to create/modify/delete files.|


---

## Related Queries:
```kql
// Detect folder creation on Desktop
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName contains "SecretData"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ActionType, FolderPath
|order  by Timestamp desc

// Detect file creation inside folder
DeviceFileEvents
| where FolderPath contains "Desktop\\SecretData" and ActionType == "FileCreated"
| project Timestamp, DeviceName, RequestAccountName, FileName

// Detect file deletion
DeviceFileEvents
| where FolderPath contains "Desktop\\SecretData" and ActionType == "FileDelete"
| project Timestamp, DeviceName, RequestAccountName, FileName

```

---

## Created By:
- **Author Name**: Priya Jindal 
- **Date**: August 13, 2025

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
| 1.0         | Initial draft                  | `August 13, 2025`  | `Priya Jindal`   

