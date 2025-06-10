<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ChauPham-security/Threat-Hunting-Scenario-Tor/blob/main/Threat-Hunting-Scenario-Tor-Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-06-07T16:59:40.681781Z`. These events began at `2025-06-07T16:34:34.6779361Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == 'employeetor'
| where InitiatingProcessAccountName == 'employee'
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-07T16:34:34.6779361Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1042" alt="TOR-download" src="https://github.com/user-attachments/assets/51736d3c-b383-4c52-93e9-dc0e0544c8ec" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2025-06-07T16:39:26.6343757Z`, an employee on the "employeetor" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == 'employeetor'
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1265" alt="TOR-install" src="https://github.com/user-attachments/assets/a6ed4443-5279-4e60-93a4-05bcb3c7fb84" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-06-07T16:41:45.230596Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == 'employeetor'
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1259" alt="TOR-process-creation" src="https://github.com/user-attachments/assets/f7076a5d-ee39-4eb9-8677-e0f881161c13" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-06-07T16:42:17.8089355Z`, an employee on the "employeetor" device successfully established a connection to the remote IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == 'employeetor'
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ( "9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName,InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath

```
<img width="1262" alt="TOR-usage" src="https://github.com/user-attachments/assets/f9940832-69c1-4383-96af-22cbd2c241ec" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-07T16:39:26.0000000Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-07T16:39:26.0000000Z`
- **Event:** The user "employee" ran `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, starting an automatic installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-06-07T16:41:45.230596Z`
- **Event:** The user "employee" opened the TOR Browser.  This also caused `tor.exe` to start running, showing the browser launched successfully.
- **Action:** Process creation of TOR browser components detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-07T16:41:57.0000000Z`
- **Event:** A network connection to IP `192.129.10.18` on port `443` was made by `tor.exe`, confirming TOR network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-06-07T16:42:00.0000000Z` – Connected to `217.160.49.126` on port `443`.  
  - `2025-06-07T16:42:17.8089355Z` – Connected to `127.0.0.1` on port `9150`.  
  - `2025-06-07T16:42:25.0000000Z` – Connected to `193.30.122.222` on port `443`.  
- **Event:** Further TOR network connections were established, indicating ongoing use of the TOR browser.
- **Action:** Multiple connection successes detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-07T16:59:40.681781Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, likely for jotting down TOR-related notes or links.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`


---

## Summary

The user "employee" on the "employeetor" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `employeetor` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
