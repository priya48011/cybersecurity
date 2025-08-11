# Threat Event (Unauthorized Firefox Installation)
**Mozilla Firefox Installed Without Authorization on Corporate Device**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Downloaded Firefox installer from: https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US
2. Ran the installer manually with default settings.
3. Firefox installed in: C:\Program Files\Mozilla Firefox\firefox.exe
4. Opened Firefox and browsed to several non-work-related sites.

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

