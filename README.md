
# Lightweight Host IDS

A minimal, host-based intrusion detection setup built from two scripts:

* `IDS.py` – monitors for suspicious activity and writes alerts to `alerts.log`
* `dashboardIDS.py` – simple Streamlit dashboard to view alerts in real time

## What It Detects

1. File tampering

   * Watches sensitive files and directories.
   * Computes and compares SHA-256 hashes to detect modifications, creations, and deletions.

2. Brute-force authentication attempts

   * Tails system authentication logs (or streams from the OS logging facility).
   * Counts failed logins per source/user in a sliding time window.
   * Raises an alert when failures exceed a threshold.

3. Suspicious process activity

   * Scans running processes and command lines for common reverse shell or abuse patterns.

4. Basic network scanning patterns (optional)

   * Uses packet inspection to flag fast Nmap attacks  or suspicious half-open patterns.
  

## How Detection Works

* A filesystem observer reports changes. On change, the script re-hashes the file and compares against a stored baseline. Mismatches or missing files produce a file tamper alert.
* An auth-log watcher reads authentication messages and updates counters by source (IP) and/or user. If the count within the configured time window crosses the threshold, a brute-force alert is written.
* A process monitor periodically inspects process lists for risky command substrings.
* A network watcher (if enabled) inspects traffic for scan-like behavior.

All alerts are appended as JSON lines to `alerts.log`. The Streamlit dashboard reads and renders these lines live.

## Libraries Used

* `watchdog` – filesystem events (inotify/FSEvents/ReadDirectoryChangesW)
* `hashlib` – SHA-256 hashing for integrity checks
* `psutil` – process inspection
* `scapy` – packet capture and simple traffic heuristics
* `pandas` – lightweight tabular handling in the dashboard
* `streamlit` and `streamlit-autorefresh` – live dashboard UI

## Installation

Create and activate a virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```

Pinned example:

```
pandas==2.1.4
psutil==5.9.0
scapy==2.6.1
streamlit==1.30.0
streamlit-autorefresh==1.0.1
watchdog==2.1.6
```

Note: packet capture and some file reads may require elevated privileges.

## Running

In one terminal, run the IDS:

```bash
sudo  python IDS.py
```

In another terminal, run the dashboard:

```bash
streamlit run dashboardIDS.py
```

Then open the URL Streamlit prints (usually [http://localhost:8501](http://localhost:8501)).

<img width="1438" height="559" alt="Screenshot 2025-10-07 at 5 56 44 AM" src="https://github.com/user-attachments/assets/854006c4-47a9-4d42-9ef8-993dd3024dfc" />



## Configuration

Key variables in `IDS.py` 

```python
# Paths to protect (files or directories). User home is expanded at runtime.
PROTECTED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "~/.ssh/authorized_keys",
]

# Brute-force detection parameters
BRUTE_FORCE_CNT = 10      # number of failures to trip an alert
BRUTE_FORCE_WIN = 60      # time window in seconds

# Authentication log input (see OS-specific sections below)
AUTH_LOG = "/var/log/auth.log"  # example default for Debian/Ubuntu

# Optional: suspicious command line substrings
REVERSE_SHELL_PATTERNS = [
    "/dev/tcp/",
    "nc -e",
    "bash -i",
    "powershell -enc",
]
```



## Detecting File Tampering on Each OS

This project uses `watchdog`, which supports Linux, macOS, and Windows. You mainly need to pick the right paths and run with sufficient privileges where necessary.

### Linux

Suggested targets:

```
/etc/passwd
/etc/shadow        (requires sudo)
~/.ssh/authorized_keys
/etc/ssh/          (directory)
```

Example configuration:

```python
PROTECTED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "~/.ssh/authorized_keys",
    "/etc/ssh",
]
```

### macOS (Sonoma and newer)

Suggested targets:

```
/etc/ssh/sshd_config
/etc/pam.d/sshd
~/.ssh/authorized_keys
```

Optional advanced targets (local user records):

```
/var/db/dslocal/nodes/Default/users
```

Example:

```python
PROTECTED_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/pam.d/sshd",
    "~/.ssh/authorized_keys",
]
```

Run with sudo if reading system files.

### Windows

Suggested targets:

```
C:\\Users\\<User>\\.ssh\\authorized_keys
C:\\ProgramData\\ssh\\sshd_config    (OpenSSH on Windows, if used)
```

Example:

```python
PROTECTED_FILES = [
    r"C:\Users\YOUR_USER\.ssh\authorized_keys",
    r"C:\ProgramData\ssh\sshd_config",
]
```

Note: Windows does not have `/etc/shadow`. Choose files that matter for your setup.

## Detecting Brute Force on Each OS

The detection logic is portable, but the log input source differs by OS. Choose one method for your platform and set the input in code.

### Linux

Option A: tail traditional log file

* Debian/Ubuntu: `/var/log/auth.log`
* RHEL/CentOS/Alma/Amazon Linux: `/var/log/secure`

```python
AUTH_LOG = "/var/log/auth.log"      # Debian/Ubuntu
# AUTH_LOG = "/var/log/secure"      # RHEL-family
```

Option B: stream journald (systemd)

```python
import subprocess, shlex

cmd = "journalctl -fu ssh --output=short"   # on some distros use 'sshd'
proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, text=True)
for line in proc.stdout:
    # reuse your existing failure parsing and threshold logic here
    if ("Failed password" in line) or ("authentication failure" in line) or ("Invalid user" in line):
        handle_failure_line(line)
```

Keep or extend your regex to include:

* `Failed password`
* `Invalid user`
* `pam_unix(sshd:auth): authentication failure`

### macOS (Sonoma and newer)

Option A: parse `/var/log/system.log` (simpler)

```python
AUTH_LOG = "/var/log/system.log"
```

Option B: stream Unified Logging (recommended)

```python
import subprocess, shlex

cmd = "log stream --style syslog --predicate 'process == \"sshd\"'"
proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, text=True)
for line in proc.stdout:
    if ("Failed password" in line) or ("authentication failure" in line):
        handle_failure_line(line)
```

Reuse your existing sliding window and threshold.

### Windows

Use the Windows Security Event Log for failed logons (Event ID 4625). If you run OpenSSH for Windows, relevant provider is usually `Microsoft-Windows-Security-Auditing` or `OpenSSH/Operational`.

Option A: use `wevtutil` and parse

```python
import subprocess, shlex

query = r"wevtutil qe Security /q:*[System[(EventID=4625)]] /f:Text /c:1 /rd:true"
# Increase /c for more events or use /r for remote.
while True:
    out = subprocess.check_output(shlex.split(query), text=True, errors="ignore")
    for line in out.splitlines():
        # parse Account Name, IP Address, and Failure Reason fields
        # then feed into your failure counters
        pass
```

Option B: PowerShell one-liner (wrap and parse)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1 | Format-List
```

Add patterns for RDP failures if that is in scope.



## Dashboard

Run:

```bash
streamlit run dashboardIDS.py
```

Features:

* Auto-refresh view of `alerts.log`
* Sorting and filtering by time and type
* Clear log button for local testing

## Notes

* Packet capture with `scapy` may require root/admin or special capabilities.
* If you do not need network detection, you can disable or omit the `scapy` parts.
* On systems without a traditional auth log file, prefer the native logging stream (journald on Linux, unified logging on macOS, event logs on Windows).

---

