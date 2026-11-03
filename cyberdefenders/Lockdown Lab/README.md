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





