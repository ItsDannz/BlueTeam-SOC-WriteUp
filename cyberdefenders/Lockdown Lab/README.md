# Lockdown Lab Write Up
**Platform:** CyberDefenders

---

## Scenario
TechNova Systems’ SOC has detected suspicious outbound traffic from a public-facing IIS server in its cloud platform—activity suggestive of a web-shell drop and covert connections to an unknown host.

As the forensic examiner, you have three critical artefacts in hand: a PCAP capturing the initial traffic, a full memory image of the server, and a malware sample recovered from disk. Reconstruct the intrusion and all of the attacker’s activities so TechNova can contain the breach and strengthen its defenses.

---

## Objective
Reconstruct a multi-stage intrusion by analyzing network traffic, memory, and malware artifacts using Wireshark, Volatility, and VirusTotal, mapping findings to MITRE ATT&CK. <br><br>
**Category:** Network Forensics <br>
**Difficulty:** Easy <br>

---

## Investigation Scope

This investigation focuses on reconstructing the suspected compromise of an IIS host by correlating network traffic, memory artifacts, and a suspicious executable.

The investigation covers:

- Identifying the source and sequence of reconnaissance activity.
- Examining HTTP requests and SMB share connection attempts.
- Reviewing processes and network connections recovered from memory.
- Looking for evidence of payload execution and persistence.
- Extracting relevant indicators and reconstructing an evidence-supported attack timeline.

Conclusions are limited to the supplied artifacts. Attempted activity, confirmed successful actions, and unresolved hypotheses are documented separately.

---

## Environment

### Analysis Setup

- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Kali Linux
- **Virtualization platform:** Oracle VirtualBox

### Analysis Tools & Tactics
- **Tools:** FLOSS/Strings, Wireshark, VirusTotal, MemProcFS, Volatility 3
- **Tactics:** Execution, Persistence, Privilege Escalation, Stealth, Discovery, Lateral Movement, Command and Control

### Artifacts
The analysis uses three provided artifacts:

- `capture.pcapng` - network traffic associated with the incident.
- `memdump.mem` - a memory image for examining host activity.
- `updatenow.exe` - an executable sample for static analysis.

---

## Investigation
### PCAP Analysis
**Q1. After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?**

**Steps taken:**

1. Opened `capture.pcapng` in Wireshark.
2. Navigated to **Statistics -> Conversations** and select IPv4 to review communication between hosts.
3. Identified the dominant conversation between `10.0.2.4` and `10.0.2.15`, containing **6,007 packets**:
   - **4,166 packets** from `10.0.2.4` to `10.0.2.15`.
   - **1,841 packets** in the reverse direction.
4. This traffic volume made `10.0.2.4` the primary candidate for further investigation.

- **Filter:**
  ```wireshark
  ip.addr == 10.0.2.4
  ```
- **Evidence:**
  - The IPv4 Conversations view shows that communication between `10.0.2.4` and `10.0.2.15` accounts for **6,007 packets**, substantially more than the other listed conversations.
  - Of these, **4,166 packets** were sent from `10.0.2.4` to `10.0.2.15`, while **1,841 packets** traveled in the reverse direction.
  - This identifies `10.0.2.4` as the primary reconnaissance candidate. Packet-level inspection is required to confirm the rapid probing pattern.
  - Packets **74, 76, 78, 79, ...** show TCP SYN probes from `10.0.2.4` to `10.0.2.15`, targeting ports **113, 135, 5900, 143, ...**, respectively.
  - These probes occurred between relative timestamps `78.082576` and `78.085296`, within approximately **2.72 milliseconds**.
  - The rapid sequence of SYN probes targeting multiple ports supports identifying `10.0.2.4` as the reconnaissance source.

- **Supporting Screenshots:**
  <img width="1269" height="582" alt="image" src="https://github.com/user-attachments/assets/8326d388-a1e1-4531-83de-909739c2373a" />
  <img width="1269" height="582" alt="image" src="https://github.com/user-attachments/assets/a949ad49-69d6-46b2-b169-4c6d9a269350" />

- Flag: `10.0.2.4`

**Q2. The attacker is carrying out targeted enumeration against the HTTP service on the IIS host. Based on the HTTP request headers, which tool is being used?**

**Steps taken:**

1. Opened `capture.pcapng` in Wireshark.
2. Applied an HTTP display filter to inspect traffic involving `10.0.2.4`.
3. Selected packet **2134**, containing an HTTP GET request from `10.0.2.4` to `10.0.2.15` on TCP port **80**.
4. Expanded **Hypertext Transfer Protocol** in the packet details pane.
5. Examined the **User-Agent** header to identify the tool associated with the request.

- **Filter:**
  ```wireshark
  ip.addr == 10.0.2.4 && http
  ```

- **Evidence:**
  - Packet **2134**, at relative timestamp `94.421647`, contains a `GET / HTTP/1.1` request to the IIS host.
  - The request includes the following header:
    ```http
    User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    ```
  - The header explicitly identifies **Nmap Scripting Engine**, supporting attribution of this HTTP enumeration activity to **Nmap**.
  - Nearby requests include `OPTIONS`, `PROPFIND`, and requests for `/robots.txt` and `/.git/HEAD`, providing additional context for the HTTP enumeration activity.

- **Supporting Screenshots:**
  <img width="1277" height="663" alt="image" src="https://github.com/user-attachments/assets/100c7052-36c9-4850-961f-e0463fcd6fa9" />
  
- **Flag:** `Nmap`

**Q3. While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?**

**Steps taken:**

1. Opened `capture.pcapng` in Wireshark.
2. Applied an SMB2 display filter to inspect traffic involving `10.0.2.4`.
3. Located **Tree Connect Request** packets sent from `10.0.2.4` to the IIS host at `10.0.2.15`.
4. Selected packets **2672** and **2678**, which contain consecutive Tree Connect requests.
5. Read the **Tree** values in the Info column and recorded both full UNC paths.

- **Filter:**
  ```wireshark
  ip.addr == 10.0.2.4 && smb2
  ```

- **Evidence:**
  - Packet **2672**, at relative timestamp `263.304629`, contains a Tree Connect request targeting:
    ```text
    \\10.0.2.15\IPC$
    ```
  - The next Tree Connect request, packet **2678**, at relative timestamp `263.312045`, targets:
    ```text
    \\10.0.2.15\Documents
    ```
  - Both requests originate from `10.0.2.4` and target `10.0.2.15`, identifying **IPC$** and **Documents** as the shares being probed.
  - An earlier request in packet **2629**, at relative timestamp `240.778552`, also targets `\\10.0.2.15\IPC$`, showing that this share was requested before the later sequence.

- **Supporting Screenshots:**
  <img width="1277" height="663" alt="Q3-1" src="https://github.com/user-attachments/assets/5f328d26-8931-4a1f-aa7a-14d00ce4758f" />
  <img width="1277" height="663" alt="Q3-2" src="https://github.com/user-attachments/assets/2bc8a5ae-4e97-4951-9a9f-b16b79a2ae18" />

- **Flag:** `\\10.0.2.15\IPC$`, `\\10.0.2.15\Documents`

**Q4. Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded?**

**Steps taken:**

1. Opened `capture.pcapng` in Wireshark.
2. Applied an SMB2 display filter to inspect traffic involving `10.0.2.4`.
3. Reviewed file operations sent from `10.0.2.4` to `10.0.2.15` following the share access.
4. Located a **Create Request**, followed by **Write** and **Close** requests, referencing `shell.aspx`.
5. Read the filename from the Info column.

- **Filter:**
  ```wireshark
  ip.addr == 10.0.2.4 && smb2
  ```

- **Evidence:**
  - Packet **2783**, at relative timestamp `342.482279`, contains a **Create Request** naming `shell.aspx`.
  - Packet **3505**, at relative timestamp `342.611215`, contains a **Write Request** for the same file, sent from `10.0.2.4` to `10.0.2.15`.
  - A corresponding **Write Response** appears in packet **3507**.
  - Packet **3509**, at relative timestamp `342.614219`, contains a **Close Request** for `shell.aspx`, followed by a Close Response in packet **3510**.
  - This sequence identifies `shell.aspx` as the file targeted by the upload operation. These SMB packets alone do not establish subsequent execution or remote code execution.

- **Supporting Screenshots:**
  <img width="1277" height="663" alt="image" src="https://github.com/user-attachments/assets/1fa08baa-cbc2-4870-a056-63f11e31deed" />

- **Flag:** `shell.aspx`

**Q5. The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?**

**Steps taken:**


1. Opened `capture.pcapng` in Wireshark.
2. Applied a display filter to locate TCP connection attempts initiated by the IIS host toward the attacker.
3. Selected packet **3585**, sent from `10.0.2.15` to `10.0.2.4`.
4. Examined the **Transmission Control Protocol** details and identified the **Destination Port** as `4443`.

**Filter:**

```wireshark
ip.src == 10.0.2.15 && ip.dst == 10.0.2.4 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Evidence:**

- Packet **3585**, at relative timestamp `401.496667`, contains a TCP SYN from the IIS host to the attacker.
- The connection attempt uses the following endpoints:
  ```text
  Source:      10.0.2.15:49688
  Destination: 10.0.2.4:4443
  ```
- The destination port identifies **TCP 4443** as the port targeted by the reverse-shell callback.
- This packet shows a connection attempt; confirmation of an established connection requires inspecting the subsequent TCP exchange.

**Supporting Screenshots:**
<img width="1277" height="663" alt="image" src="https://github.com/user-attachments/assets/d4fd0d70-0f44-4781-88ac-238b059778e7" />

**Flag:** `4443`

### Memory Dump Analysis
**Q6. Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?**
**Steps taken:**

1. Opened a terminal in the directory containing `memdump.mem`.
2. Ran the Volatility 3 `windows.info` plugin to retrieve system information from the memory dump.
3. Located the **Kernel Base** field in the output.
4. Recorded the reported address.

**Command:**

```bash
~/venvs/volatility3/bin/vol -f memdump.mem windows.info
```

**Evidence:**

- The `windows.info` output reports the following kernel base address:
  ```text
  Kernel Base    0xf80079213000
  ```

**Supporting Screenshots:**
<img width="1277" height="430" alt="image" src="https://github.com/user-attachments/assets/7d030677-e2c8-4efa-b513-654c993947da" />


**Flag:** `0xf80079213000`

**Q7. A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable?**
**Steps taken:**

1. Reviewed the process listing recovered from `memdump.mem`.
2. Identified `updatenow.exe` with **PID 900** and **PPID 4332**.
3. Matched PPID **4332** to `w3wp.exe`, identifying the IIS worker process as its recorded parent.
4. Ran the Volatility 3 `windows.cmdline` plugin for PID **900**.
5. Read the **Args** field and recorded the executable's full path.

**Command:**

```bash
~/venvs/volatility3/bin/vol -f memdump.mem windows.cmdline --pid 900
```

**Evidence:**

- The process listing shows `updatenow.exe` with PID **900**, whose PPID **4332** matches the PID of `w3wp.exe`.
- The process creation time is **2024-09-10 06:08:23 UTC**.
- The `windows.cmdline` output reports the following command line:
  ```text
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"
  ```
- This identifies the executable's reported location within the `Startup` directory.

**Supporting Screenshots:**
<img width="1277" height="694" alt="Q7-1" src="https://github.com/user-attachments/assets/01cdd36d-a0a7-41e9-b95c-d1c9b449f09e" />
<img width="1277" height="132" alt="Q7-2" src="https://github.com/user-attachments/assets/e0a87e46-3a09-4fe9-b092-b67b51fe808c" />

**Flag:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe`

**Q8. The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?**
**Steps taken:**

1. Reviewed the process listing recovered from `memdump.mem`.
2. Located `updatenow.exe` with **PID 900**.
3. Examined its **PPID**, which is **4332**.
4. Matched PID **4332** to `w3wp.exe`, identifying the process that spawned the implanted executable.

**Command:**

To check the process listing, use [`windows.pslist`](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.pslist.html):

```bash
~/venvs/volatility3/bin/vol -f memdump.mem windows.pslist
```

**Evidence:**

- The listing identifies `w3wp.exe` with **PID 4332**.
- The implanted executable, `updatenow.exe`, has **PID 900** and **PPID 4332**.
- These values establish the recorded parent–child relationship:
  ```text
  w3wp.exe (PID 4332)
    |-- updatenow.exe (PID 900, PPID 4332)
  ```
- This screenshot supports the process ancestry. Attribution of the reverse-shell connection to PID **4332** requires separate network evidence.

**Supporting Screenshots:**
<img width="1277" height="693" alt="image" src="https://github.com/user-attachments/assets/bc7bc1d0-d29c-4865-b5e8-77e17b605ee0" />

**Flag:** `w3wp.exe, 4332`

### Malware Sample Analysis
**Q9. Static inspection reveals the binary has been packed to hinder analysis. Which packer was used to obfuscate it?**
**Steps taken:**

1. Ran the `file` command against `updatenow.exe`.
2. Examined the reported executable format and packing information.
3. Identified the explicit `UPX compressed` classification.
4. Ran `strings` against the executable to look for supporting packer indicators.
5. Located the strings `UPX0`, `UPX1`, and `UPX!`, corroborating the UPX identification.

**Command:**

```bash
file updatenow.exe
strings updatenow.exe
```

**Evidence:**

- The `file` command returned:
  ```text
  updatenow.exe: PE32 executable for MS Windows 5.01 (GUI), Intel i386, UPX compressed, 3 sections
  ```
- The `UPX compressed` classification identifies **UPX** as the packer used on the executable.
- Additional inspection with `strings` revealed the following markers:
  ```text
  UPX0
  UPX1
  UPX!
  ```

**Supporting Screenshots:**
<img width="1277" height="60" alt="Q9-1" src="https://github.com/user-attachments/assets/a49c8ebd-bf22-44d1-a023-54b2f9504b7a" />
<img width="1267" height="186" alt="Q9-2" src="https://github.com/user-attachments/assets/a3b4276d-c9ba-4a69-bc75-f6c702aad578" />

**Flag:** `UPX`

**Q10. Threat-intel analysis shows the malware beaconing to its command-and-control host. Which fully qualified domain name (FQDN) does it contact?**
**Steps taken:**

1. Uploaded `updatenow.exe` through the VirusTotal web interface.
2. Opened the file report and navigated to the **Relations** tab.
3. Reviewed the **Contacted Domains** section.
4. Identified `cp8nl.hyperhost.ua`, which showed **4/92 detections**.
5. Recorded the complete FQDN as the suspected C2 endpoint.

**Evidence:**

- The **Contacted Domains** section lists `cp8nl.hyperhost.ua` among the domains contacted by the sample.
- The domain has **4 detections out of 92 engines** in the displayed report.
- This association and detection result support identifying the domain as a C2 candidate. The screenshot does not independently demonstrate periodic beaconing.

**Supporting Screenshots:**
<img width="1270" height="646" alt="image" src="https://github.com/user-attachments/assets/e6afb8a6-4c6e-4071-9d51-845933044d86" />

**Flag:** `cp8nl.hyperhost.ua`

**Q11. Open-source intel associates that hash with a well-known commodity RAT. To which malware family does the sample belong?**
**Steps taken:**

1. Opened the VirusTotal report for `updatenow.exe`.
2. Navigated to the **Detection** tab.
3. Reviewed the **Security vendors' analysis** section.
4. Located the AliCloud detection: `Trojan:Win/AgentTesla.SHZT`.
5. Identified **AgentTesla** as the malware family named in that detection.

**Evidence:**

- AliCloud reports the following detection:
  ```text
  Trojan:Win/AgentTesla.SHZT
  ```
- The detection explicitly references the **AgentTesla** malware family.
- Other vendors display different labels, including Nymeria and Formbooks. The attribution documented here follows the highlighted AliCloud verdict rather than a unanimous classification.

**Supporting Screenshots:**
<img width="1270" height="646" alt="image" src="https://github.com/user-attachments/assets/54df963c-5d8d-4993-ac1a-a94d740094af" />

**Flag:** `AgentTesla`

---

## Findings
The reviewed artifacts show reconnaissance against the IIS host `10.0.2.15`, SMB file-write activity involving `shell.aspx`, and a subsequent outbound TCP connection attempt to `10.0.2.4:4443`. Memory records link `updatenow.exe` to the IIS worker process `w3wp.exe` and report an executable path in the common Startup folder. Static inspection identifies UPX packing, while VirusTotal supplies a suspected C2 domain and a vendor-reported malware-family attribution.

### Key Findings

| Area | Finding | Evidence |
|---|---|---|
| Reconnaissance | `10.0.2.4` rapidly probed multiple ports on `10.0.2.15`. The HTTP User-Agent explicitly references Nmap Scripting Engine. | Q1–Q2; SYN probes and HTTP packet **2134**. |
| SMB share probing | Tree Connect requests targeted `\\10.0.2.15\IPC$` and `\\10.0.2.15\Documents`. | Q3; packets **2629**, **2672**, and **2678**. |
| Suspected web payload | SMB Create, Write, and Close requests reference `shell.aspx`. This documents an upload attempt; the file contents and web execution were not verified. | Q4; packets **2783**, **3505**, and **3509**. |
| Callback attempt | The IIS host initiated a TCP connection attempt from `10.0.2.15:49688` to `10.0.2.4:4443`. | Q5; SYN packet **3585**. |
| Process ancestry and location | `updatenow.exe` has PID **900** and PPID **4332**, matching `w3wp.exe`. Its command line points to the Startup-folder path listed below. | Q7–Q8; process listing and `windows.cmdline`. |
| Packing | `file` reports UPX compression; `strings` reveals `UPX0`, `UPX1`, and `UPX!`. | Q9; static inspection. |
| Threat intelligence | VirusTotal lists `cp8nl.hyperhost.ua` as a contacted domain with **4/92 detections**. AliCloud names **AgentTesla**, while other vendors use different labels. | Q10–Q11; VirusTotal Relations and Detection screenshots. |

### Activity Timeline

| PCAP-relative time (seconds) | Packet(s) | Observed activity |
|---|---|---|
| `78.082576–78.085296` | 74, 76, 78, 79 | Four SYN probes from `10.0.2.4` target ports **113**, **135**, **5900**, and **143** on the IIS host within approximately **2.72 ms**. |
| `94.421647` | 2134 | HTTP GET request contains the Nmap Scripting Engine User-Agent. |
| `240.778552` | 2629 | Tree Connect request targets `\\10.0.2.15\IPC$`. |
| `263.304629` | 2672 | Another Tree Connect request targets `\\10.0.2.15\IPC$`. |
| `263.312045` | 2678 | The next Tree Connect request targets `\\10.0.2.15\Documents`. |
| `342.482279–342.614219` | 2783, 3505, 3509 | SMB Create, Write, and Close requests reference `shell.aspx`. |
| `401.496667` | 3585 | `10.0.2.15:49688` sends a SYN to `10.0.2.4:4443`. |

### MITRE ATT&CK Mapping

These mappings describe observed behavior or explicitly marked hypotheses; they do not establish every tactic listed in the lab overview.

| Technique | Supporting evidence | Assessment |
|---|---|---|
| [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Rapid probes across multiple destination ports and HTTP service enumeration. | Observed service-discovery behavior. |
| [T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/) | SMB requests targeting the `IPC$` and `Documents` shares. | Observed share probing. |
| [T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) | SMB file operations involving `shell.aspx` on the IIS host. | Suspected web-shell placement; contents and execution remain unverified. |
| [T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | The executable's reported path is in the common Startup folder. | Potential logon persistence; automatic execution at logon was not observed. |
| [T1027.002 — Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002/) | UPX classification and supporting strings. | Packing observed; packing alone does not establish malicious intent. |

---

## Indicators
The IP addresses below identify hosts within the lab. Their roles are specific to this investigation.

| Type | Value | Context |
|---|---|---|
| Reconnaissance source / callback destination | `10.0.2.4` | Origin of the port probes and destination of the callback attempt. |
| Affected IIS host | `10.0.2.15` | Target of HTTP and SMB activity; source of the outbound SYN. |
| Callback destination port | `TCP 4443` | Target port in packet **3585**. |
| SMB share target | `\\10.0.2.15\IPC$` | Requested during SMB share probing. |
| SMB share target | `\\10.0.2.15\Documents` | Requested during SMB share probing. |
| Suspected web payload filename | `shell.aspx` | Referenced by SMB file-write operations; its full filesystem path was not established. |
| Suspicious executable path | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` | Reported by `windows.cmdline` for PID **900**. |
| Suspected C2 FQDN | `cp8nl.hyperhost.ua` | Listed in VirusTotal Contacted Domains; **4/92 detections** in the captured report. |

**Additional context:** The memory dump reports kernel base **`0xf80079213000`**, parent process **`w3wp.exe` PID 4332**, and child process **`updatenow.exe` PID 900**. These process IDs and the kernel address apply to this memory snapshot. **UPX** is the observed packer, **AgentTesla** is the family named by AliCloud's `Trojan:Win/AgentTesla.SHZT` verdict.

---

## Lessons Learned
- **Use traffic volume to prioritize, then inspect behavior.** The dominant conversation identified a candidate host; rapid SYN probes across different ports supplied the reconnaissance evidence.
- **Track connection direction.** For a connection initiated by the IIS host toward the attacker, the destination port identifies the candidate listener. A SYN alone establishes an attempt.
- **Correlate processes using PID, PPID, and path.** The matching parent ID links `updatenow.exe` to `w3wp.exe`; attributing a network connection requires additional evidence tying the endpoints to a process.
- **Separate persistence indicators from observed execution.** A Startup-folder path supports a persistence hypothesis, but does not show that the executable later ran automatically at logon.
- **Treat signatures and threat-intelligence labels as evidence to assess.** UPX packing is not inherently malicious, contacted domains are not automatically C2, and antivirus engines may disagree on family names.
- **Preserve the basis for each conclusion.** Record packet numbers, exact commands, process identifiers, timestamp formats, and screenshots so another analyst can follow the investigation.

Further investigation should check SMB response status and HTTP invocation of `shell.aspx`, inspect the full callback stream, correlate recovered network records with PID **4332**, and validate the suspected persistence and C2 configuration.

---

## Reference
- [CyberDefenders - Lockdown](https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/)
- [Microsoft - IIS Modules and Web-Shell Detection](https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/)
- [MITRE ATT&CK - T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK - T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [MITRE ATT&CK - T1505.003: Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1027.002: Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002/)

---
