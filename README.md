# AppGate

AppGate is a comprehensive IP-based firewall management system for Windows. It leverages the **Windows Filtering Platform (WFP)** to provide robust traffic control through a C++ backend service, controlled via a modern Electron JS dashboard.

## Features

-   **Dual Operation Modes**:
    -   **Blacklist Mode**: Allow all traffic by default, block specific IPs/Ports.
    -   **Whitelist Mode**: Block all traffic by default, allow only specific IPs/Ports.
-   **Real-time Dashboard**: Visualize rule statistics and current status.
-   **REST API**: Fully controllable via HTTP endpoints.
-   **Persistence**: Rules are automatically saved and restored on restart.
-   **Port Control**: Block or allow specific ports per IP.

## Project Structure

```
AppGate/
├── IP-Manager/                 # C++ Backend Service
│   ├── main.cpp               # REST API Server (httplib)
│   ├── FirewallManager.cpp    # WFP Logic Implementation
│   ├── FirewallManager.h      # WFP Logic Header
│   ├── Utils.cpp              # Helper Functions
│   ├── CMakeLists.txt         # Build Configuration
│   └── ...
│
└── AppGate-Dashboard/         # Electron Frontend
    ├── main.js                # Electron Entry Point
    ├── renderer.js            # UI Logic & API Communication
    ├── index.html             # Dashboard Layout
    ├── styles.css             # Styling
    └── package.json           # Dependencies
```

## Prerequisites

-   **OS**: Windows 10 or Windows 11 (Administrator privileges required).
-   **C++ Build Tools**: Visual Studio 2019/2022 with "Desktop development with C++" workload.
-   **CMake**: Version 3.15 or later.
-   **Node.js**: LTS version recommended.

## Installation & Build

### 1. Build the C++ Backend (IP-Manager)

The backend requires Administrator privileges to manage Windows Firewall filters.

1.  Open a terminal (PowerShell or CMD).
2.  Navigate to the `IP-Manager` directory:
    ```powershell
    cd IP-Manager
    ```
3.  Create a build directory and compile:
    ```powershell
    mkdir build
    cd build
    cmake ..
    cmake --build . --config Release
    ```
4.  The executable will be located at `IP-Manager/build/Release/AppGate.exe`.

### 2. Setup the Frontend (AppGate-Dashboard)

1.  Open a new terminal.
2.  Navigate to the `AppGate-Dashboard` directory:
    ```powershell
    cd AppGate-Dashboard
    ```
3.  Install dependencies:
    ```powershell
    npm install
    ```

## Usage

### Running the Application

1.  **Start the Backend**:
    *   **Important**: You must run the backend as **Administrator**.
    *   Right-click your terminal and select "Run as Administrator".
    *   Run the compiled executable:
        ```powershell
        .\IP-Manager\build\Release\AppGate.exe
        ```
    *   You should see: `[+] Starting REST API on http://localhost:8080`

2.  **Start the Dashboard**:
    *   In a separate terminal (normal privileges is fine):
        ```powershell
        cd AppGate-Dashboard
        npm start
        ```
    *   The dashboard window will open and connect to the backend automatically.

### REST API Documentation

The backend exposes a REST API on port `8080`.

| Method | Endpoint | Description | Payload / Params |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/status` | Get service status & mode | - |
| `GET` | `/api/dashboard` | Get dashboard statistics | - |
| `POST` | `/api/mode` | Set Firewall Mode | `{"mode": "whitelist"}` or `{"mode": "blacklist"}` |
| `GET` | `/api/rules` | List all active rules | - |
| `POST` | `/api/rules` | Add a new rule | `{"ip": "1.2.3.4", "ports": [80, 443]}` (omit ports for all) |
| `DELETE` | `/api/rules` | Remove a rule | Query Param: `?ip=1.2.3.4` |
| `POST` | `/api/rules/clear` | Clear all rules | - |
| `POST` | `/api/rules/load` | Reload rules from disk | - |

## Troubleshooting

-   **Connection Failed**: Ensure the backend is running. If in Whitelist mode, ensure `127.0.0.1` is whitelisted (this happens automatically in the latest version).
-   **Permission Denied**: The backend **must** be run as Administrator to add/remove WFP filters.
-   **Build Errors**: Ensure you have the Windows SDK installed via the Visual Studio Installer.
