# AppGate usage guide

This document provides step?by?step instructions and examples for using AppGate.

## Start the program
- Build AppGate (see README), then run it as Administrator.
- On launch you will see the main menu and banner:
```
===================================================
  ___              _____       _       
 / _ \            |  __ \     | |      
/ /_\ \_ __  _ __ | |  \/ __ _| |_ ___ 
|  _  | '_ \| '_ \| | __ / _` | __/ _ \
| | | | |_) | |_) | |_\ \ (_| | ||  __/
\_| |_/ .__/| .__/ \____/\__,_|\__\___|
      | |   | |                        
      |_|   |_|                        
                     AppGate
        Application Network Access Controller
=====================================================
```

```
1. List processes using network
2. List installed applications
3. Block process (by PID or Path)
4. Unblock process (by PID or Path)
5. Show active rules
6. Delete rule by serial number
7. Delete all rules created by this program
0. Exit
```

## 1) List processes using network
- Shows a table with one row per process (PID). Columns include Name, Path, Protocol (TCPv4/v6), and CSV lists of LocalPorts and RemotePorts.
- Notes:
  - Only active TCP connections are displayed (UDP not listed).
  - Processes with no sockets, or only idle listeners without connections, may not appear.

Example output (illustrative):
```
PID   Name         Path                         Proto   LocalPorts  RemotePorts
----  -----------  ---------------------------  ------  ----------  -----------
1234  chrome.exe   C:\\Program Files\\Google...   TCPv4   80,443     443
4321  discord.exe  C:\\Users\\User\\AppData...     TCPv6   443        443
```

## 2) List installed applications
- Aggregates from multiple sources:
  - Registry Uninstall keys (HKLM/HKCU, WOW6432Node)
  - Start Menu shortcuts (.lnk ? .exe target)
  - Filesystem scan (Program Files, Program Files (x86), LocalAppData, AppData)
  - Running processes
  - UWP packages (via PowerShell Get-AppxPackage)
- Results are deduplicated by path with a preference: UWP > Registry > Filesystem > Process.
- Interaction:
  - Type the row number to block the selected app by executable path.
  - Prefix with `u` (e.g., `u12`) to remove a block for the selected app.

## 3) Block process (by PID or Path)
- Enter either:
  - A PID (integer): AppGate resolves its executable path and applies a path?based WFP block.
  - A full executable path: AppGate applies a path?based WFP block directly.
- Under the hood:
  - AppGate adds filters at `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6` for both TCP and UDP, matching on `ALE_APP_ID` for the specified executable.

## 4) Unblock process (by PID or Path)
- Mirror of (3); removes rules that match the stored path.

## 5) Show active rules
- Lists all rules created by AppGate in the current session.
- Columns: serial index, process name, path, WFP filter id.

## 6) Delete rule by serial number
- Enter the serial (the leftmost index from the rule list) to delete that one rule.

## 7) Delete all rules created by this program
- Removes all rules created by AppGate in the current session.

## Tips and caveats
- Elevation is required: If WFP initialization fails, re?launch as Administrator (UAC prompt).
- Dynamic session: Rules are created under a dynamic WFP session and will be removed when AppGate exits.
- UWP packages: For UWP apps, install paths may not always map cleanly to a single executable; test the effect before relying on it.
- Non?ASCII paths: Internally, WFP calls use wide (UTF?16) paths; console output is UTF?8.
- Security note: Avoid blocking system?critical services unless you understand the impact.

## Troubleshooting
- No network processes listed: Only active TCP connections are shown.
- PowerShell errors on UWP listing: Enterprise execution policies may block `Get-AppxPackage`. Option 2 will still list non?UWP sources.
- Rule removal: If a rule seems to remain, ensure you are deleting by the correct serial number and that AppGate is running elevated.

## Uninstall/cleanup
- AppGate creates only dynamic rules during runtime; exiting the program removes them automatically.
- No changes are persisted unless you modify the source to use a non?dynamic WFP session.

