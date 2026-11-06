# JetBrains Lab Write Up
**Platform:** CyberDefenders

---

## Scenario
During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation. 

As part of the investigation, You are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

---

## Objective
Analyze network traffic using Wireshark to identify web server exploitation, extract attacker IOCs and persistence mechanisms, and map attack techniques to MITRE ATT&CK.<br><br>
**Category:** Network Forensics <br>
**Difficulty:** Easy <br>

---

## Investigation Scope

This investigation focuses on reconstructing a suspected web server
compromise using the network traffic provided in the CyberDefenders
JetBrains lab.

The investigation covers:

- Identifying suspicious source addresses and the targeted server.
- Examining web requests and responses for evidence of exploitation.
- Investigating network-visible evidence of payload delivery, command
  execution, persistence attempts, and command-and-control activity.
- Extracting relevant indicators of compromise and reconstructing
  an evidence-supported attack timeline.
- Mapping observed attacker behavior to MITRE ATT&CK techniques.

---

## Environment

### Analysis Setup

- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Ubuntu
- **Analysis environment:** CyberDefenders-provided lab environment

### Analysis Tools & Tactics
- **Tools:** Wireshark, Network Miner, Brim
- **Tactics:** Initial Access, Execution, Command and Control

### Artifacts
The analysis uses one provided artifact:

- `Capture.pcap` - network traffic associated with the incident.

---

## Investigation
**Q1. Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Navigated to **Statistics -> Conversations** and selected the **IPv4** tab.
3. Identified conversations involving `23.158.56.196`, communicating with `172.17.0.2` and `172.31.25.119`.
4. Recorded `23.158.56.196` as the primary candidate for further investigation.

**Filter:**

Use this filter to inspect the candidate's traffic:

```wireshark
ip.addr == 23.158.56.196
```

**Evidence:**

- The conversation between `23.158.56.196` and `172.17.0.2` contains **4,166 packets**.
- The conversation between `23.158.56.196` and `172.31.25.119` contains **2,083 packets**.
- These conversations identify `23.158.56.196` as a relevant candidate for further examination. Packet-level inspection is required to confirm malicious activity; traffic volume alone does not establish that an endpoint is the attacker.

**Supporting Screenshots:**
<img width="1704" height="709" alt="image" src="https://github.com/user-attachments/assets/e8cf4991-b045-4b3a-ae98-4f7e2acab8e0" />

**Flag:** `23.158.56.196`

**Q2. To identify potential vulnerability exploitation, what version of our web server service is running?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Applied the filter below to locate HTTP POST requests involving `23.158.56.196`.
3. Selected a matching packet and opened **Follow -> TCP Stream**.
4. Examined **TCP stream 364**, which also contains an earlier GET request to `/hax?jsp=/app/rest/server;.jsp`.
5. Reviewed the XML response to that GET request and identified the TeamCity version.

**Filter:**

```wireshark
ip.addr == 23.158.56.196 && http.request.method == "POST"
```

**Evidence:**

- The stream contains the following request:

  ```http
  GET /hax?jsp=/app/rest/server;.jsp HTTP/1.1
  Host: 3.71.79.4:8111
  ```

- The server returns an **HTTP/1.1 200** response containing the header:

  ```http
  TeamCity-Node-Id: MAIN_SERVER
  ```

- The XML response includes the following version attribute:

  ```xml
  version="2023.11.3"
  ```

- This identifies the service as **JetBrains TeamCity version 2023.11.3**, build **147512**.

**Supporting Screenshots:**
<img width="1699" height="514" alt="image" src="https://github.com/user-attachments/assets/b8738216-7416-4dfc-a60b-1a008b1abc1f" />
<img width="1135" height="837" alt="Q2-2" src="https://github.com/user-attachments/assets/a0e1d85f-dbf5-4b2a-a762-d7b99d8a4a04" />

**Flag:** `2023.11.3`

**Q3. After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?**

**Steps taken:**

1. Used the service version identified in Q2: **JetBrains TeamCity 2023.11.3**.
2. Searched for vulnerabilities affecting that version.
3. Reviewed Rapid7's technical analysis and JetBrains' security advisory.
4. Compared the request observed in Q2 with the documented authentication bypass pattern.
5. Identified the corresponding vulnerability as **CVE-2024-27198**.

**Search query:**

```text
web vulnerability teamcity version 2023.11.3
```

**Evidence:**

- The server reports **TeamCity 2023.11.3**, which falls within the affected version range. The vulnerability was fixed in **2023.11.4**.
- **CVE-2024-27198** is an authentication bypass vulnerability involving an alternative path issue in TeamCity's web component.
- TCP stream **364**, examined in Q2, contains the following request:

  ```http
  GET /hax?jsp=/app/rest/server;.jsp HTTP/1.1
  ```

- This URI matches the authentication bypass pattern documented by Rapid7.
- Correlating the observed request with the affected service version supports identifying **CVE-2024-27198** as the exploited vulnerability.

**Supporting Screenshots:**
<img width="984" height="283" alt="image" src="https://github.com/user-attachments/assets/245ddc35-4e80-4398-b6a9-c491a1a17ae7" />

**Flag:** `CVE-2024-27198`

**Q4. What credentials did the attacker successfully use for Basic Auth against the TeamCity server?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Applied the filter below to inspect HTTP POST requests involving `23.158.56.196`.
3. Opened **Follow -> TCP Stream** and examined **TCP stream 364**.
4. Located a POST request to `/hax?jsp=/app/rest/users;.jsp`.
5. Extracted the username and password from its JSON body.
6. Reviewed the server response to confirm that the account was created.

**Filter:**

```wireshark
ip.addr == 23.158.56.196 && http.request.method == "POST"
```

**Evidence:**

- The stream contains the following account-creation request:

  ```http
  POST /hax?jsp=/app/rest/users;.jsp HTTP/1.1
  Host: 3.71.79.4:8111
  Content-Type: application/json
  ```

- The JSON body includes these credential fields:

  ```json
  {
    "username": "c91oyemw",
    "password": "CL5vzdwLuK"
  }
  ```

- The request also assigns the account the **SYSTEM_ADMIN** role.
- The server returns **HTTP/1.1 200**, followed by an XML response identifying username `c91oyemw` and user ID `2`, supporting successful account creation.

**Supporting Screenshots:**
<img width="1699" height="514" alt="Q2-1   Q4-1" src="https://github.com/user-attachments/assets/b2e1863f-0414-48cc-a553-0d72c59ed419" />
<img width="1134" height="827" alt="Q4-2" src="https://github.com/user-attachments/assets/ea9e5c1a-cacd-4f00-8fe0-6dd98f2dab39" />

**Flag:** `c91oyemw:CL5vzdwLuK`

**Q5. The attacker uploaded a webshell to ensure his access to the system. What is the name of the file that the attacker uploaded?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Applied the filter below to inspect HTTP POST requests involving `23.158.56.196`.
3. Opened **Follow -> TCP Stream** and examined **TCP stream 364**.
4. Located a POST request to `/admin/pluginUpload.html`.
5. Examined the multipart form data and read the uploaded filename from the **Content-Disposition** header.
6. Correlated the embedded JSP filename with subsequent POST requests to the webshell.

**Filter:**

```wireshark
ip.addr == 23.158.56.196 && http.request.method == "POST"
```

**Evidence:**

- The stream contains a plugin upload request:

  ```http
  POST /admin/pluginUpload.html HTTP/1.1
  Host: 3.71.79.4:8111
  ```

- The multipart upload identifies the submitted file:

  ```http
  Content-Disposition: form-data; name="file:fileToUpload"; filename="NSt8bHTg.zip"
  Content-Type: application/zip
  ```

- The archive content includes `buildServerResources/NSt8bHTg.jsp`.
- The embedded JSP reads the `cmd` request parameter and uses `ProcessBuilder` to execute commands, supporting its identification as a webshell.
- Subsequent requests target the deployed JSP:

  ```http
  POST /plugins/NSt8bHTg/NSt8bHTg.jsp HTTP/1.1
  ```

- The uploaded archive is **NSt8bHTg.zip**, containing the JSP webshell **NSt8bHTg.jsp**.

**Supporting Screenshots:**

<img width="1699" height="514" alt="Q2-1, Q4-1,   Q5-1" src="https://github.com/user-attachments/assets/aac0ee4f-681d-4b71-975c-4139c8a25d1b" />
<img width="1134" height="827" alt="Q5-2" src="https://github.com/user-attachments/assets/86ec4d2c-942e-4a0b-a0b4-b08d8a6bb35c" />

**Flag:** `NSt8bHTg.zip`

**Q6. When did the attacker execute their first command via the web shell?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Applied the filter below to locate HTTP POST requests containing `cmd`.
3. Reviewed the requests chronologically and located the earliest displayed POST to the deployed webshell: **packet 25572**.
4. Opened **Follow -> TCP Stream** and examined **TCP stream 364**.
5. Identified the command `ls` in the request body and a directory listing in the server response.
6. Recorded the timestamp from the corresponding HTTP response's **Date** header.

**Filter:**

```wireshark
ip.addr == 23.158.56.196 && http.request.method == "POST" && http contains "cmd"
```

**Evidence:**

- Packet **25572**, at relative timestamp **1122.563990**, contains a request from `23.158.56.196` to `172.31.25.119` targeting:

  ```http
  POST /plugins/NSt8bHTg/NSt8bHTg.jsp HTTP/1.1
  ```

- The request body contains:

  ```text
  cmd=ls
  ```

- The server returns **HTTP/1.1 200** and a directory listing containing entries such as `bootstrap.jar`, `catalina.bat`, and `catalina.sh`, supporting successful command execution.
- The corresponding response includes:

  ```http
  Date: Sun, 30 Jun 2024 08:03:57 GMT
  ```

- This places the first observed webshell command execution at approximately **2024-06-30 08:03:57 UTC**. The timestamp comes from the server's response header and has one-second precision.

**Supporting Screenshots:**
<img width="1689" height="504" alt="image" src="https://github.com/user-attachments/assets/e5716797-e9ce-4cef-92fe-f041dd5b76c3" />
<img width="1141" height="931" alt="Q6-2" src="https://github.com/user-attachments/assets/96c8fbde-37fd-4040-987a-8bc11f8a8139" />

**Flag:** `2024-06-30 08:03`

**Q7. The attacker tampered with a text file that contained the credentials of the admin user of the webserver. What new username and password did the attacker write in the file?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Applied the filter below to locate HTTP POST requests from the attacker containing `username`.
3. Located the webshell requests at packets **31123** and **31124**.
4. Opened **Follow -> TCP Stream** and examined **TCP stream 547**.
5. Located a command reading `/tmp/Creds.txt`.
6. Extracted the username and password from the returned file contents.

**Filter:**

```wireshark
ip.src == 23.158.56.196 && http.request.method == "POST" && http contains "username"
```

**Evidence:**

- The stream contains a request to the deployed webshell:

  ```http
  POST /plugins/NSt8bHTg/NSt8bHTg.jsp HTTP/1.1
  ```

- The request body contains the URL-encoded command:

  ```text
  cmd=cat+%2Ftmp%2FCreds.txt
  ```

- Decoding the command gives:

  ```bash
  cat /tmp/Creds.txt
  ```

- The corresponding **HTTP/1.1 200** response returns the following file contents:

  ```text
  username:a1l4m,password:youarecompromised
  ```

- The credential values stored in the file are:
  - **Username:** `a1l4m`
  - **Password:** `youarecompromised`

**Supporting Screenshots:**
<img width="1700" height="410" alt="image" src="https://github.com/user-attachments/assets/f551c73b-4ed3-4d01-bd5c-9b562caaa645" />
<img width="1142" height="933" alt="Q7-2" src="https://github.com/user-attachments/assets/f8b3c3f1-5a22-4db1-b357-d5b4847246c6" />

**Flag:** `a1l4m:youarecompromised`

**Q8. Q7 showed the attacker writing false credentials into `Creds.txt`. Which MITRE ATT&CK sub-technique (Data Manipulation family) describes that specific file-write action?**

**Steps taken:**

1. Reviewed the file-tampering activity involving `/tmp/Creds.txt` identified in Q7.
2. Navigated to the **Impact** tactic in the MITRE ATT&CK matrix.
3. Expanded **Data Manipulation** and selected **Stored Data Manipulation**.
4. Confirmed the corresponding sub-technique ID as **T1565.001**.

**MITRE ATT&CK mapping:**

| Field | Value |
|---|---|
| Tactic | Impact |
| Parent technique | Data Manipulation — T1565 |
| Sub-technique | Stored Data Manipulation |
| Sub-technique ID | T1565.001 |

**Evidence:**

- The attacker wrote false credential values into `/tmp/Creds.txt`, modifying data stored on disk.
- The file contents examined in Q7 show:

  ```text
  username:a1l4m,password:youarecompromised
  ```

- This action changes the integrity of stored file contents, supporting the mapping to **Stored Data Manipulation**.
- The MITRE ATT&CK sub-techniques table associates **Stored Data Manipulation** with **T1565.001**.

**Reference:**

[MITRE ATT&CK - Data Manipulation (T1565)](https://attack.mitre.org/techniques/T1565/)

**Supporting Screenshots:**
<img width="1696" height="918" alt="image" src="https://github.com/user-attachments/assets/47031cbe-2772-4232-9b21-638ac7cb6a3c" />
<img width="1696" height="665" alt="image" src="https://github.com/user-attachments/assets/79fff3cd-a274-488e-8f97-f585550d2e64" />

**Flag:** `T1565.001`

**Q9. Immediately after gaining a shell, the attacker executed a docker command that mounted the host filesystem and chrooted into it — providing full host access. What was that exact command?**

**Steps taken:**

1. Opened `Capture.pcap` in Wireshark.
2. Applied the filter below to locate HTTP POST requests from the attacker containing `docker`.
3. Opened **Follow -> TCP Stream** and examined **TCP stream 601**.
4. Searched for `chroot` and located the relevant command in the webshell request body.
5. Decoded the form-urlencoded command to recover its exact syntax.

**Filter:**

```wireshark
ip.src == 23.158.56.196 && http.request.method == "POST" && http contains "docker"
```

**Evidence:**

- The command was submitted through the deployed webshell:

  ```http
  POST /plugins/NSt8bHTg/NSt8bHTg.jsp HTTP/1.1
  ```

- The request body contains:

  ```text
  cmd=docker+run+--rm+-it+-v+%2F%3A%2Fhost+ubuntu+chroot+%2Fhost
  ```

- Decoding the form data gives:

  ```bash
  docker run --rm -it -v /:/host ubuntu chroot /host
  ```

- The `-v /:/host` argument requests a bind mount of the Docker host's root filesystem at `/host` inside the container.
- The `chroot /host` command changes the process's root directory to that mounted filesystem.

**Supporting Screenshots:**
<img width="1696" height="365" alt="Q9-1" src="https://github.com/user-attachments/assets/442c3354-acd7-4373-b39c-642f3de63d82" />
<img width="1141" height="931" alt="Q9-2" src="https://github.com/user-attachments/assets/ebd45866-f4be-4d52-9180-0d83def7054a" />

**Flag:** `docker run --rm -it -v /:/host ubuntu chroot /host`

## Findings

The reviewed screenshots reconstruct a compromise involving **JetBrains TeamCity 2023.11.3 (build 147512)**. Requests associated with `23.158.56.196` use an authentication-bypass pattern matching **CVE-2024-27198**, create a privileged TeamCity account, and upload a plugin containing a JSP webshell. Subsequent responses demonstrate command execution and reveal the contents of a credential text file. A later request submits a Docker bind-mount and `chroot` command intended to access the Docker host's filesystem.

### Key Findings

| Area | Finding | Evidence |
|---|---|---|
| Attack source and target context | `23.158.56.196` appears in the investigated requests. Conversations involve `172.31.25.119` and `172.17.0.2`; HTTP requests specify `Host: 3.71.79.4:8111`. | Q1 and subsequent request screenshots. |
| Vulnerable service and exploitation | The server reports TeamCity **2023.11.3**, build **147512**. The URI `/hax?jsp=/app/rest/server;.jsp` matches the bypass documented for **CVE-2024-27198**. | Q2–Q3: TCP stream **364**; [Rapid7 technical analysis](https://www.rapid7.com/blog/post/ra-cve-2024-27198-analysis/). |
| Privileged account creation | A request creates user `c91oyemw` with the `SYSTEM_ADMIN` role. The response identifies user ID **2**. | Q4: JSON request and XML response in stream **364**. |
| Webshell deployment | The uploaded archive `NSt8bHTg.zip` contains `buildServerResources/NSt8bHTg.jsp`. Later requests target `/plugins/NSt8bHTg/NSt8bHTg.jsp`. | Q5: multipart upload, embedded JSP source, and subsequent POST requests. |
| Command execution | A webshell request submits `cmd=ls`; the response returns a directory listing. | Q6: request packet **25572** and stream **364**. |
| Credential-file contents | Reading `/tmp/Creds.txt` returns `username:a1l4m,password:youarecompromised`. The lab identifies these as false values written by the attacker. | Q7–Q8: read request and response in stream **547**. The modifying command is outside the supplied view. |
| Host-access attempt | The attacker submits `docker run --rm -it -v /:/host ubuntu chroot /host` through the webshell. | Q9: TCP stream **601**. Successful host access is not demonstrated by the displayed response. |

### Activity Timeline

All absolute times below are **UTC on 2024-06-30**, taken from server HTTP response `Date` headers. They place the associated activity to approximately one-second precision and do not establish exact command execution start times. The capture-relative timestamp is recorded separately where visible.

| Server response time (UTC) | Evidence location | Observed activity |
|---|---|---|
| `2024-06-30 08:02:49` | Q2 and Q4: stream **364** | The server returns its TeamCity version and a successful account-creation response identifying `c91oyemw`. |
| `2024-06-30 08:03:08` | Q6: stream **364**, preceding the first displayed command | A response contains `<response>Plugin loaded successfully</response>`. |
| `2024-06-30 08:03:57` | Q6: stream **364** | The first displayed webshell command, `ls`, returns a directory listing. Its request is packet **25572**, at capture-relative time **1122.563990 seconds**. |
| `2024-06-30 08:14:04` | Q7: stream **547** | The response to `cat /tmp/Creds.txt` returns the false credential values. |
| `2024-06-30 08:19:40` | Q9: stream **601** | The server responds to the submitted Docker bind-mount and `chroot` command. The screenshot does not establish its execution outcome. |

---

## Indicators

These values are specific to this investigation. The table includes malicious artifacts alongside victim and application context; interpret each value according to its recorded role.

| Type | Value | Context |
|---|---|---|
| Attack source IP | `23.158.56.196` | Source associated with the investigated exploitation and webshell requests. |
| HTTP Host header | `3.71.79.4:8111` | Target authority specified in the captured HTTP requests. |
| Observed internal addresses | `172.31.25.119`, `172.17.0.2` | Destinations in the captured conversations; their exact topology relationship remains unverified. |
| Exploitation URI | `/hax?jsp=/app/rest/server;.jsp` | Used to retrieve server information through the bypass pattern. |
| Exploitation URI | `/hax?jsp=/app/rest/users;.jsp` | Used in the privileged account-creation request. |
| Plugin upload endpoint | `/admin/pluginUpload.html` | Legitimate application endpoint used to submit the malicious archive. |
| Uploaded archive | `NSt8bHTg.zip` | Filename recorded in the multipart upload. |
| Embedded JSP path | `buildServerResources/NSt8bHTg.jsp` | Webshell entry visible in the uploaded archive data. |
| Deployed webshell URI | `/plugins/NSt8bHTg/NSt8bHTg.jsp` | Endpoint receiving command-bearing POST requests. |
| Created TeamCity account | `c91oyemw` | Account created with the `SYSTEM_ADMIN` role; returned user ID **2**. |
| Account password supplied during creation | `CL5vzdwLuK` | Observed in the JSON creation request; Basic Auth use is not independently shown. |
| Credential text file | `/tmp/Creds.txt` | File read through the webshell in stream **547**. |
| False credential values | `a1l4m:youarecompromised` | Values returned from the text file; distinct from the created TeamCity account. |

**Observed host-access command:**

```bash
docker run --rm -it -v /:/host ubuntu chroot /host
```

---

## Lessons Learned

- **Correlate version information with exploit behavior.** The TeamCity version identifies a potentially affected service; the crafted REST request provides stronger evidence for the specific CVE. [Rapid7's analysis](https://www.rapid7.com/blog/post/ra-cve-2024-27198-analysis/) documents the matching URI pattern.
- **Inspect complete conversations.** Following a POST request can reveal earlier GET requests and their responses within the same connection, as demonstrated in stream **364**. Wireshark documents this workflow in [Following Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html).
- **Validate outcomes using returned data.** The `ls` directory listing supports command execution. An HTTP 200 status alone does not establish successful authentication or Docker command execution.
- **Keep account creation and file manipulation separate.** A newly created TeamCity administrator account and false credentials stored in a text file represent different changes requiring different evidence.
- **Review Docker access as part of incident scope.** A host-root bind mount can expose host files to container processes.
- **Preserve evidence context.** Record packet numbers, stream IDs, raw and decoded commands, timestamp sources, and hashes of recovered artifacts. Keep the analyst's Ubuntu environment separate from conclusions about the affected server and Docker host.

## References
- [Rapid7 — Analysis: CVE-2024-27198](https://www.rapid7.com/blog/post/ra-cve-2024-27198-analysis/): authentication-bypass mechanism and matching request pattern.
- [JetBrains - Security Advisory for CVE-2024-27198 and CVE-2024-27199](https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/): affected versions and the historical fix in TeamCity 2023.11.4.
- [MITRE ATT&CK - T1565.001: Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/): mapping for the described false-credential file write.




