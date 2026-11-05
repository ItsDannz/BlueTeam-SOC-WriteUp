# XLMRatLab Write Up
**Platform:** CyberDefenders

---

## Scenario
A compromised machine has been flagged due to suspicious network traffic. Your task is to analyze the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

---

## Objective
Analyze network traffic to identify malware delivery, deobfuscate scripts, and map attacker techniques using MITRE ATT&CK, focusing on stealthy execution and reflective code loading. <br><br>
**Category:** Network Forensics <br>
**Difficulty:** Easy <br>

---

## Investigation Scope

This investigation focuses on reconstructing the suspected malware delivery and execution chain by analyzing network traffic and examining scripts and payloads recovered from the supplied artifacts.

The investigation covers:

- Identifying the host involved in suspicious activity and the associated remote infrastructure.
- Tracing payload downloads and reconstructing the malware delivery sequence.
- Deobfuscating recovered scripts to understand their behavior and role in the execution chain.
- Examining evidence of stealthy execution and reflective code loading.
- Mapping supported attacker behaviors to relevant MITRE ATT&CK techniques.
- Extracting network and file indicators and reconstructing an evidence-supported attack timeline.

Conclusions are limited to the supplied artifacts and recovered content. Network evidence of payload delivery does not, by itself, confirm successful execution on the host. Observed activity, inferred behavior, and unresolved hypotheses are documented separately.

---

## Environment

### Analysis Setup

- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Kali Linux
- **Virtualization platform:** Oracle VirtualBox

### Analysis Tools & Tactics
- **Tools:** Wireshark, VirusTotal, CyberChef, PowerShell, Python3, Hosting Checker
- **Tactics:** Execution, Stealth

### Artifacts
The analysis uses one provided artifact:

- `236-XLMRat.pcap` - network traffic associated with the incident.

---

## Investigation
**Q1. The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?**

**Steps taken:**

1. Opened the supplied packet capture in Wireshark.
2. Applied the `http` display filter to review HTTP requests and responses.
3. Identified two GET requests from `10.1.9.101` to `45.126.209.4`:
   - Packet **4** requested `/xlm.txt`.
   - Packet **12** requested `/mdm.jpg`.
4. Selected the `/xlm.txt` request and navigated to **Follow -> HTTP Stream** to inspect the script returned by the server.
5. Examined the obfuscated string fragments in `LZeWX(42)` through `LZeWX(56)`. Concatenating these fragments reconstructed the URL `http://45.126.209.4:222/mdm.jpg`.
6. Correlated the reconstructed URL with the subsequent `/mdm.jpg` request and its **HTTP 200 OK** response.

- **Filter:**
  ```wireshark
  http
  ```

- **Evidence:**
  - Packet **4**, at relative timestamp `0.295141`, shows `10.1.9.101` requesting `/xlm.txt` from `45.126.209.4`.
  - Packet **7**, at `0.564818`, shows an **HTTP 200 OK** response with the content type `text/plain`.
  - The highlighted fragments in `LZeWX(42)` through `LZeWX(56)` reconstruct `http://45.126.209.4:222/mdm.jpg`, including the destination port `222`.
  - Packet **12**, at `1.585563`, shows the same host requesting `/mdm.jpg`.
  - Packet **344**, at `3.449781`, shows the corresponding **HTTP 200 OK** response, labeled `image/jpeg`.
  - Together, the reconstructed URL and matching HTTP exchange identify `/mdm.jpg` as the first malware-stage download requested by the preceding script. The earlier `/xlm.txt` request retrieves that script.

- **Supporting Screenshots:**
  <img width="931" height="153" alt="Q1-1" src="https://github.com/user-attachments/assets/f2870873-8527-4b46-86d5-3ce9c008a86b" />
  <img width="194" height="840" alt="image" src="https://github.com/user-attachments/assets/ff1e8432-f479-4d8b-95ec-b202d5cadb4b" />

- Flag: `http://45.126.209.4:222/mdm.jpg`

**Q2. Which hosting provider owns the associated IP address?**

**Steps taken:**

1. Used the IP address `45.126.209.4`, identified in the first-stage download URL from Q1.
2. Opened **Hosting Checker** and entered the IP address into the lookup field.
3. Clicked **FIND HOST** to retrieve the hosting information.
4. Reviewed the hosting provider, organization name, and autonomous system details returned by the lookup.

- **Lookup:**
  ```text
  45.126.209.4
  ```

- **Evidence:**
  - The result states **"It is hosted by: ReliableSite.Net LLC"**.
  - The **Organization name** field also lists **ReliableSite.Net LLC**.
  - The autonomous system information lists **AS23470 ReliableSite.Net LLC**, with the AS name **RELIABLESITE**.
  - These results identify **ReliableSite.Net LLC** as the hosting provider associated with `45.126.209.4` in the supplied lookup.

- **Supporting Screenshot:**
  <img width="834" height="684" alt="image" src="https://github.com/user-attachments/assets/eace7501-c6be-484a-9bae-179986655492" />

- **Flag:** `ReliableSite.Net`

**Q3. By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?**

**Steps taken:**

1. Opened `236-XLMRat.pcap` in Wireshark and applied the `http` display filter.
2. Located packet **12**, containing the `GET /mdm.jpg` request from `10.1.9.101` to `45.126.209.4`.
3. Selected the request and navigated to **Follow -> HTTP Stream** to inspect the response content in TCP stream **1**.
4. Examined the returned script and located the embedded, underscore-delimited hexadecimal payload data.
5. Copied the hexadecimal data for the malware executable into **CyberChef**, excluding the variable assignment, quotation marks, and surrounding script code.
6. Added **From Hex**, with **Delimiter** set to **Auto**, to reconstruct the executable bytes.
7. Added **SHA2**, with **Size** set to **256** and **Rounds** set to **64**, to calculate the SHA256 of the decoded bytes.
8. Recorded the hash displayed in the CyberChef output.

- **Filters:**

  Initial HTTP review:
  ```wireshark
  http
  ```

  Payload stream:
  ```wireshark
  http
  ```

- **CyberChef Recipe:**
  ```text
  From Hex (Delimiter: Auto)
  SHA2 (Size: 256, Rounds: 64)
  ```

- **Evidence:**
  - Packet **12** requests `/mdm.jpg`, and packet **344** shows an **HTTP 200 OK** response labeled `image/jpeg`.
  - The HTTP stream contains script content with embedded hexadecimal data, despite the `.jpg` filename and advertised content type.
  - The displayed hexadecimal block begins with `4D_5A`, which decodes to `MZ`, a header signature commonly found in Windows executables.
  - The CyberChef recipe applies **From Hex** before **SHA2**, so the hash is calculated from the decoded payload bytes rather than the hexadecimal text or the surrounding script.
  - The CyberChef output shows the SHA256 value `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`.

- **Supporting Screenshots:**
  <img width="882" height="153" alt="image" src="https://github.com/user-attachments/assets/6b08ce2c-3652-42f7-a64f-b639543e7971" />
  <img width="1281" height="899" alt="image" src="https://github.com/user-attachments/assets/0641989a-222b-4355-aff9-8dd14f19e578" />
  <img width="1361" height="916" alt="image" src="https://github.com/user-attachments/assets/fbc513b2-3596-4f53-9d0e-31d192835660" />

- **Flag:** `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`

**Q4. What is the malware family label based on Alibaba?**

**Steps taken:**

1. Used the malware executable's SHA256 obtained in Q3 to search for its report on **VirusTotal**.
2. Opened the **Detection** tab to review the security vendors' analysis results.
3. Located the **Alibaba** entry in the detection table.
4. Identified `AsyncRat` within Alibaba's detection label and recorded the malware family as **AsyncRAT**.

- **Lookup:**
  ```text
  1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798
  ```

- **Evidence:**
  - The SHA256 displayed in the VirusTotal report matches the executable hash obtained in Q3.
  - The **Alibaba** detection label contains the family name **AsyncRat**, highlighted in the screenshot.
  - This identifies the requested malware family as **AsyncRAT**, based on Alibaba's classification in the supplied report.

- **Supporting Screenshot:**
  <img width="1691" height="909" alt="image" src="https://github.com/user-attachments/assets/5d940e4d-b1df-4d24-8878-ff9d4f5a36ff" />

- **Flag:** `AsyncRAT`

**Q5. What is the PE header compile (Creation Time) timestamp of the malware?**

**Steps taken:**

1. Opened the **VirusTotal** report for the malware executable using the SHA256 obtained in Q3.
2. Selected the **Details** tab to inspect the file metadata.
3. Scrolled to the **History** section and located the **Creation Time** field.
4. Recorded the displayed timestamp as `2023-10-30 15:08:44 UTC`.

- **Lookup:**
  ```text
  1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798
  ```

- **Evidence:**
  - The SHA256 shown in the report matches the malware executable hash obtained in Q3.
  - Under **Details -> History**, the **Creation Time** field displays `2023-10-30 15:08:44 UTC`.
  - This is the reported PE creation/compilation timestamp. It is recorded as sample metadata when reconstructing the investigation timeline.

- **Supporting Screenshot:**
  <img width="1691" height="915" alt="image" src="https://github.com/user-attachments/assets/cf0bc84f-3a8d-4b1c-8b1e-e0a6388ff88a" />

- **Flag:** `2023-10-30 15:08`

**Q6. Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.**

**Steps taken:**

1. Reviewed the script recovered from the `/mdm.jpg` HTTP response.
2. Located the `$NA` and `$AC` variables, which construct an executable path using strings containing inserted `#` characters.
3. Used **Python 3** in a **Linux terminal** to reproduce the path reconstruction, representing the fragments as raw strings to preserve the backslashes.
4. Concatenated the fragments and applied `.replace('#', '')` to remove the inserted characters.
5. Recorded the resulting path: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`.
6. Reviewed the `$VA` argument array and the subsequent reflective method invocation to establish how the script uses this path.

- **Command:**
  ```bash
  python3 - <<'PY'
  prefix = r'C:\W#######indow############s\Mi####cr'
  suffix = r'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe'

  path = (prefix + suffix).replace('#', '')
  print(path)
  PY
  ```

- **Output:**
  ```text
  C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
  ```

- **Evidence:**
  - The original script uses `-replace '#', ''` to remove inserted characters from the path fragments.
  - The Python command reproduces this string transformation and outputs the full path to **RegSvcs.exe**.
  - The script resolves the `NewPE2.PE` type and its `Execute` method, then builds `$VA = @($AC, $NKbb)`.
  - The subsequent reflective invocation passes the reconstructed executable path and decoded payload bytes to that method. This identifies **RegSvcs.exe** as the script's intended LOLBin.

- **Supporting Screenshot:**
  <img width="1275" height="868" alt="image" src="https://github.com/user-attachments/assets/7428e557-b075-428d-85ad-ef7c3e83fe44" />
  <img width="921" height="146" alt="Q6-2" src="https://github.com/user-attachments/assets/440cd039-ac1a-4811-800d-4b71156a309a" />

- **Flag:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

**Q7. The script is designed to drop several files. List the names of the files dropped by the script.**

**Steps taken:**

1. Reviewed the script recovered from the `/mdm.jpg` HTTP response.
2. Located the `[IO.File]::WriteAllText` calls to identify the intended file-write destinations.
3. Recorded the three destination paths under `C:\Users\Public\` and extracted their filenames.
4. Examined the surrounding content blocks to understand how the generated scripts are intended to launch one another.

- **Evidence:**
  - The script contains three `[IO.File]::WriteAllText` calls targeting:
    - `C:\Users\Public\Conted.ps1`
    - `C:\Users\Public\Conted.bat`
    - `C:\Users\Public\Conted.vbs`
  - The content assigned to **Conted.bat** is configured to launch `Conted.ps1` through PowerShell with `-NoProfile`, `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass`.
  - The content assigned to **Conted.vbs** references `Conted.bat` and uses `WScript.Shell.Run` with a visibility value of `0` to request a hidden window.
  - These file-write statements identify **Conted.ps1**, **Conted.bat**, and **Conted.vbs** as the script's intended dropped files.

- **Supporting Screenshot:**
  <img width="1233" height="859" alt="image" src="https://github.com/user-attachments/assets/147dd843-ad06-46bd-90cb-39144d294f2e" />

- **Flag:** `Conted.bat,Conted.ps1,Conted.vbs`

---

## Findings

The investigation reconstructed a malware delivery chain involving an obfuscated script, content delivered under a `.jpg` filename, and a decoded executable classified by Alibaba as **AsyncRAT**.

1. **Payload delivery:** The investigated host, `10.1.9.101`, requested `/xlm.txt` and subsequently `/mdm.jpg` from `45.126.209.4`. Both requests received **HTTP 200 OK** responses. Script fragments reconstructed the first-stage download URL as `http://45.126.209.4:222/mdm.jpg`. **Evidence: Q1.**
2. **Encoded executable content:** Although `/mdm.jpg` was advertised as `image/jpeg`, its response contained script content with embedded hexadecimal payload data. The executable bytes were reconstructed using CyberChef before calculating their SHA256. **Evidence: Q3.**
3. **Malware identification:** The decoded executable's hash matched the VirusTotal report reviewed in Q4. The **Alibaba** detection label contained `AsyncRat`, supporting the family identification as **AsyncRAT**. **Evidence: Q3–Q4.**
4. **Intended execution and file creation:** Static analysis showed that the script constructs a path to `RegSvcs.exe` and passes it, together with decoded payload bytes, to `NewPE2.PE.Execute` through reflection. The script also specifies three file writes under `C:\Users\Public\`, forming an intended `Conted.vbs -> Conted.bat -> Conted.ps1` launcher chain. **Evidence: Q6–Q7.**
5. **Infrastructure and sample metadata:** Hosting Checker associated `45.126.209.4` with **ReliableSite.Net LLC**, under **AS23470**. The supplied VirusTotal report displayed a **Creation Time** of `2023-10-30 15:08:44 UTC`. This timestamp is recorded as reported PE metadata and it does not establish the date of the observed network activity. **Evidence: Q2 and Q5.**

### Reconstructed Timeline

| Relative time (seconds) | Packet | Observed activity |
| --- | --- | --- |
| `0.295141` | **4** | `10.1.9.101` sends `GET /xlm.txt` to `45.126.209.4`. |
| `0.564818` | **7** | An **HTTP 200 OK** response is displayed for `/xlm.txt`, labeled `text/plain`. |
| `1.585563` | **12** | `10.1.9.101` sends `GET /mdm.jpg` to `45.126.209.4`. |
| `3.449781` | **344** | An **HTTP 200 OK** response is displayed for `/mdm.jpg`, labeled `image/jpeg`. |

The reviewed evidence supports payload retrieval and analysis of the script's intended behavior. The initial access method, successful host execution, completed file creation, command-and-control communication, and established persistence were not independently confirmed.

---

## Indicators

| Type | Value | Context |
| --- | --- | --- |
| Delivery IP address | `45.126.209.4` | Remote host serving the reviewed script and payload content. |
| Download URL | `http://45.126.209.4:222/mdm.jpg` | Reconstructed from script fragments and correlated with the HTTP request. |
| HTTP request path | `/xlm.txt` | Preceding obfuscated script retrieval. |
| Payload filename | `mdm.jpg` | Script content containing encoded payload data, advertised as an image. |
| Intended dropped file | `C:\Users\Public\Conted.ps1` | PowerShell script targeted by a `WriteAllText` call. |
| Intended dropped file | `C:\Users\Public\Conted.bat` | Batch wrapper configured to launch `Conted.ps1`. |
| Intended dropped file | `C:\Users\Public\Conted.vbs` | VBScript wrapper configured to launch `Conted.bat` with a hidden window. |

**Decoded executable SHA256:**

```text
1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798
```

---

## Lessons Learned

- **Inspect content beyond filenames and MIME types.** The `/mdm.jpg` response contained script and encoded payload data despite its image-like presentation.
- **Preserve reproducible decoding steps.** Record the HTTP stream, extracted hexadecimal block, CyberChef recipe, and Linux commands used to reconstruct obfuscated strings.
- **Hash the intended artifact.** Calculate the executable hash from the decoded bytes and retain separate identities for the enclosing script, loader, and malware executable.
- **Correlate static behavior with endpoint evidence.** Process creation records, PowerShell logs, file-write telemetry, and scheduled-task records would help validate execution, file creation, and persistence.
- **Keep timestamps and evidence types explicit.** Label packet times as relative capture time, preserve the timezone of sample metadata, and attribute malware-family labels to the reporting vendor.

---

## Reference
- [CyberChef - decoding and hashing](https://gchq.github.io/CyberChef/)
- [Hosting Checker - hosting lookup](https://hostingchecker.com/)
- [Virus Total - reports finding](https://www.virustotal.com/gui/file/1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798)



