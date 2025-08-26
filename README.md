# jovingdetector

⚠️ **Important Notice**
Intended for authorized security audits only.
This script is for educational purposes and for systems with **explicit permission**. Unauthorized use violates laws such as the Brazilian Penal Code (Art. 154-A), LGPD, or international regulations (e.g., GDPR). Use responsibly.

---

## Features

* **File Scanning**: Calculates SHA-256 hash (OpenSSL) and applies YARA rules (libyara) to detect malware.
* **Polymorphic Malware Analysis**: Detects obfuscation through entropy calculation (threshold: 7.0).
* **Process Monitoring**: Identifies processes with high CPU usage (GetProcessList on Windows, `/proc` on Linux, `libproc` on macOS, `libprocstat` on FreeBSD).
* **Memory Detection**: Scans memory for malicious patterns (`ReadProcessMemory`, `/proc/[pid]/mem`, `task_for_pid`, `/proc/[pid]/map`).
* **Modification Detection**:

  * Windows: Monitors registry changes (`HKEY_LOCAL_MACHINE\\Run`).
  * Linux/macOS/FreeBSD: Detects modifications in critical files (`/etc/passwd`, `/Library/Extensions`, `/boot/modules`).
* **Network Detection**: Identifies suspicious connections (`GetTcpTable`, `/proc/net`, `netstat`).
* **Rootkit Detection**: Scans for hidden processes and driver/module/kext alterations.
* **JSON Reports**: Exports results in JSON format (logs/reports/).
* **Alerting**: Supports file logging, webhook (Discord), email (SMTP with libesmtp), Splunk (HEC), ELK (HTTP), and SIEM (Windows events/syslog).
* **Expanded GUI**: Start/Stop/Export buttons, CPU/threat graphs, and real-time logs (WinAPI, GTK, Cocoa).
* **CPU Monitoring**: Pauses scans if CPU usage exceeds 80%.
* **Threading**: Uses pthread for continuous scanning, logging, and interface.

---

## Requirements

* **C Compiler**:

  * Windows: MinGW ([mingw-w64.org](https://mingw-w64.org))
  * Linux: Default GCC
  * macOS: Xcode
  * FreeBSD: Default

* **Supported OS**:

  * Windows 10/11
  * Linux (e.g., Ubuntu 24.04)
  * macOS (e.g., Sonoma 14)
  * FreeBSD (e.g., 14.0)

* **Dependencies**:

  * Windows: `windows.h`, `iphlpapi.h` (Windows SDK), `libcurl`, `OpenSSL`, `json-c`, `libesmtp`, `libyara`.
  * Linux: `libcurl`, `OpenSSL`, `json-c`, `libesmtp`, `libyara`, `libgtk-3-dev`.
  * macOS: `libproc`, `Cocoa`, `libcurl`, `OpenSSL`, `json-c`, `libesmtp`, `libyara`.
  * FreeBSD: `libprocstat`, `libcurl`, `OpenSSL`, `json-c`, `libesmtp`, `libyara`, `gtk3`.

---

## Installation

1. **Create a GitHub Repository (optional for versioning)**

   ```bash
   git clone https://github.com/hygark/jovingdetector.git
   ```

2. **Add the Script**
   Save the C code as `MalwareDetector.c` in your directory.

3. **Install Dependencies**

   * Windows: via mingw-get (`libcurl`, `libssl`, `json-c`, `libesmtp`, `libyara`)
   * Linux:

     ```bash
     sudo apt update && sudo apt install libcurl4-openssl-dev libssl-dev libjson-c-dev libesmtp-dev libyara-dev libgtk-3-dev
     ```
   * macOS:

     ```bash
     brew install libcurl openssl json-c libesmtp yara
     ```
   * FreeBSD:

     ```bash
     sudo pkg install libcurl openssl json-c libesmtp yara gtk3
     ```

4. **Compile the Program**

   * Windows:

     ```bash
     gcc -o malware_detector MalwareDetector.c -lws2_32 -lcurl -lcrypto -liphlpapi -ljson-c -lesmtp -lyara
     ```
   * Linux:

     ```bash
     gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -lgtk-3 -pthread
     ```
   * macOS:

     ```bash
     gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -framework Cocoa
     ```
   * FreeBSD:

     ```bash
     gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -lgtk-3 -pthread
     ```

---

## Configuration in C

Edit definitions at the beginning of the script:

* `SCAN_DIR`: Scan directory (default: `scan/`).
* `REPORT_DIR`: JSON reports directory (default: `logs/reports/`).
* `LOG_FILE`: Log file path (default: `logs/malware_detector.log`).
* `YARA_RULES`: YARA rules file (default: `rules.yar`).
* `SIGNATURES_FILE`: SHA-256 signatures file (default: `signatures.txt`).
* `WEBHOOK_URL`: Discord webhook URL.
* `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`: Splunk configuration.
* `ELK_URL`: ELK endpoint (e.g., `http://localhost:9200/_bulk`).
* `SMTP_*`: Email configuration.
* `SCAN_INTERVAL`: Default: 60 seconds.
* `CPU_THRESHOLD`: Default: 80%.
* `ENTROPY_THRESHOLD`: Default: 7.0.

Example:

```c
#define SCAN_DIR "scan/"
#define REPORT_DIR "logs/reports/"
#define LOG_FILE "logs/malware_detector.log"
#define YARA_RULES "rules.yar"
#define SIGNATURES_FILE "signatures.txt"
#define CPU_THRESHOLD 80
#define ENTROPY_THRESHOLD 7.0
```

---

## Usage

* **Run the program**

  ```bash
  ./malware_detector
  ```
* **Scan Test Files**: Place them inside `scan/` with hashes/rules in `signatures.txt` and `rules.yar`.
* **Logs**: Check `logs/malware_detector.log`.
* **Reports**: Found in `logs/reports/`.
* **Alerts**: Sent via webhook/email/Splunk/ELK/SIEM.
* **GUI**: Start/Stop/Export buttons with CPU graphs.
* **Stopping**: Press any key (CLI) or Stop button (GUI).

---

## Example Use Cases

* **Local Scanning**: Detects malicious files, polymorphic malware, suspicious processes, memory injections, rootkits, and system modifications.
* **Remote Monitoring**: Real-time alerts via Discord, Gmail (SMTP), Splunk HEC, ELK, or SIEM.
* **Report Analysis**: Review JSON reports for detailed results.
* **Expansion**: Add exploit detection, QRadar integration, or network traffic analysis.

---

## Legal & Ethical Disclaimer

This script is for **educational purposes** and **authorized testing only**.
Unauthorized use is illegal (Brazilian Penal Code Art. 154-A, LGPD, GDPR, etc.).
Always obtain **written authorization** before scanning any system.
Use in controlled environments (e.g., local machine with permission).
