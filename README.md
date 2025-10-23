# SOC Project – Splunk Lab: Monitor, Attack Simulation & Detection

## 🧭 Overview

This project demonstrates a complete SOC (Security Operations Center) simulation using **Splunk**, **Sysmon**, and **Kali Linux** to monitor, attack, and detect malicious activity in a safe virtual environment. The goal was to replicate a real-world endpoint compromise, analyze the resulting telemetry, and apply security monitoring and detection techniques using Splunk.

> ⚠️ **Note:** All testing was conducted in an **isolated lab network**. No part of this simulation involved any production or external systems.

---

## 🧱 Lab Summary

**Environment Setup:**

* **Splunk Enterprise (Ubuntu 22.04):** SIEM and log analysis platform.
* **Windows 11:** Target/victim machine running Sysmon and Splunk Universal Forwarder.
* **Kali Linux:** Attacker machine running Metasploit.

**Network:** Host-only adapter ensuring full isolation from the internet.

**Data Sources:**

* Windows Event Logs (Security, System, Application)
* Sysmon Event Logs (Process creation, network connections, etc.)
* Linux local logs (via /var/log monitoring)

---

## ⚔️ Attack Simulation

**Objective:** Simulate a Windows host compromise via a reverse TCP payload to test telemetry visibility.

**Execution Flow:**

1. Implemented a Recon phase using **Nmap** to scan the target victim.
1. Payload creation with **msfvenom** (reverse TCP Meterpreter).
2. Payload delivered and executed on Windows endpoint.
3. Metasploit listener on Kali received the callback.

**Observed Behavior:**

* `resume.pdf.exe` initiated a Meterpreter session.
* Sysmon captured process creation and network connection to attacker IP (port 4444).

---

## 🕵️ Detection in Splunk

**Telemetry Identified:**

* **Event ID 1:** Process creation (resume.pdf.exe)
* **Event ID 3:** Network connection to attacker IP
* **Event ID 10:** Process access (post-exploitation)

**Key SPL Queries:**

```spl
index=sysmon Image="*resume.pdf.exe" | table _time, host, User, ParentImage, CommandLine
```

```spl
index=sysmon EventCode=3 DestinationPort=4444 | table _time, Image, DestinationIp, DestinationPort
```

```spl
index=sysmon EventCode=1 Image="*powershell.exe" | table _time, ParentImage, Image, CommandLine
```

**Findings:**
The attack created a distinct process chain:

```
explorer.exe → resume.pdf.exe → cmd.exe → powershell.exe
```

This pattern clearly indicated malicious behavior and command execution.

---

## 📊 Results & Observations

* Splunk successfully ingested and indexed Sysmon and Windows logs.
* The attack’s network and process artifacts were visible and queryable.
* SPL queries effectively identified post-exploitation behavior.
* Sysmon provided high-fidelity endpoint telemetry essential for detection.

---

## 🧠 Lessons Learned

1. **Isolation is everything**: Internal-only networking keeps experiments safe.
User deception is trivial: Double extensions (.pdf.exe) still trick users. Enable “show file extensions.”
2. **Least privilege matters**: Admin users make attacker life easy; standardize non-admin daily use.
3. **Application control helps**: Use AppLocker/allow-listing to block unknown binaries (especially in user-write paths).
4. **EDR + Logging**: Keep Defender/EDR enabled with tamper protection; Sysmon + SIEM provide the forensic truth.
Detections to keep: Alert on suspicious parent/child combos (e.g., *.pdf.exe → cmd.exe, cmd.exe → net.exe) and unusual outbound connections from user processes.

5. **Documentation & repeatability** make the lab useful for continuous learning.

---

## 🚀 Future Work

* Develop **automated correlation searches** for alerts.
* Visualize detection data using Splunk dashboards.

---

## 📘 Full Report

For full setup instructions, commands, configurations, and analysis screenshots, please refer to the detailed report:

> [SOC Project – Splunk Lab: Monitor, Attack Simulation & Detection (Full Report)](./SOC%20Project-Splunk%20lab%20Monitor%2C%20Attack%20simulation%20%26%20Detection.docx)

---

**Author:** crab241
**Purpose:** Educational research on SOC detection engineering and endpoint visibility.
