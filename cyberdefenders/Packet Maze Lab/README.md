<img width="1634" height="942" alt="image" src="https://github.com/user-attachments/assets/c9c715ba-3a00-48c3-82ea-bbcfa4acf435" /># JetBrains Lab Write Up
**Platform:** CyberDefenders

---

## Scenario
A company's internal server has been flagged for unusual network activity, with multiple outbound connections to an unknown external IP. Initial analysis suggests possible data exfiltration. Investigate the provided network logs to determine the source and method of compromise.

---

## Objective
Analyze network traffic using Wireshark to identify suspicious activity, extract IOCs, and uncover authentication details, file transfers, and server information across multiple protocols.<br><br>
**Category:** Network Forensics <br>
**Difficulty:** Medium <br>

---
## Investigation Scope

This investigation focuses on analyzing the network capture provided in the CyberDefenders PacketMaze lab to reconstruct communication activity, identify suspicious behavior, and recover relevant protocol-level evidence.

The investigation covers:

- Identifying relevant hosts, IP addresses, MAC addresses, services,
  and network conversations.
- Examining authentication exchanges to recover visible credentials
  and assess login outcomes from the corresponding responses.
- Investigating file transfers, identifying filenames and transfer
  metadata, and recovering transferred content where available.
- Extracting server information from application headers, service
  banners, and other protocol fields.
- Correlating requests, responses, and connection patterns to distinguish
  suspicious activity from normal communication.
- Documenting relevant indicators and an evidence-supported timeline.

---

## Environment

### Analysis Setup
- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Kali Linux
- **Virtualization platform:** Oracle VirtualBox

### Analysis Tools & Tactics
- **Tools:** Brim, suricatarunner, suricata.rules, NetworkMiner, Wireshark, MAC lookup
- **Tactics:** Initial Access

### Artifacts
The analysis uses one provided artifact:

- `UNODC-GPC-001-003-JohnDoe-NetworkCapture-2021-04-29.pcapng` - network traffic associated with the incident.

---

**Q1. What is the FTP password?**

**Steps taken:**

1. Opened the supplied packet capture in Wireshark.
2. Applied the `ftp` display filter to inspect the FTP control traffic.
3. Located **packet 496**, containing the username submitted by the client.
4. Examined **packet 500**, containing the password in the `PASS` command.
5. Checked **packet 502** for the server's authentication response.

**Filter:**

```wireshark
ftp
```

**Evidence:**

- The FTP client is `192.168.1.26`, communicating with the server at `192.168.1.20`.
- Packet **496** submits the username:

  ```text
  USER kali
  ```

- Packet **500** submits the password:

  ```text
  PASS AfricaCTF2021
  ```

- Packet **502** contains the server response:

  ```text
  230 Login successful.
  ```

- The readable `PASS` command identifies the password as **AfricaCTF2021**, and the server response confirms successful authentication.

**Supporting Screenshots:**
<img width="1898" height="592" alt="image" src="https://github.com/user-attachments/assets/beac6afa-4fbf-442a-a22c-4bb66bfb0f0f" />

**Flag:** `AfricaCTF2021`

**Q2. What is the IPv6 address of the DNS server used by `192.168.1.26`?**

**Steps taken:**

1. Opened the supplied packet capture in Wireshark.
2. Applied the `dns` display filter to inspect DNS traffic.
3. Located the IPv6 DNS query and response in **packets 474 and 475**.
4. Navigated to **Statistics -> Conversations** and selected the **IPv6** tab to read the complete addresses.
5. Identified the DNS server as the destination of the query and the source of the corresponding response.

**Filter:**

```wireshark
dns
```

**Evidence:**

- Packet **474** contains a DNS query for `t-ring.msedge.net`, with transaction ID **0x6820**.
- The IPv6 conversation shows these endpoints:

  ```text
  Query source:      fe80::b011:ed39:8665:3b0a
  Query destination: fe80::c80b:adff:feaa:1db7
  ```

- Packet **475** contains the corresponding DNS response, traveling from `fe80::c80b:adff:feaa:1db7` back to the query source.
- The query-response direction supports identifying **fe80::c80b:adff:feaa:1db7** as the DNS server's IPv6 address.

**Supporting Screenshots:**
<img width="1898" height="592" alt="Q2-1" src="https://github.com/user-attachments/assets/3460f7ed-dfa1-4b22-9a00-b032588038d1" />
<img width="1898" height="472" alt="Q2-2" src="https://github.com/user-attachments/assets/5d3be168-ca1e-4117-ac6e-c8e9b7f5b8bf" />

**Flag:** `fe80::c80b:adff:feaa:1db7`

**Q3. What domain is the user looking up in packet `15174`?**

**Steps taken:**

1. Applied a display filter in Wireshark to isolate packet **15174**.
2. Inspected the DNS query displayed in the **Info** column.
3. Identified the requested domain as `www.7-zip.org`.

**Filter:**

```wireshark
frame.number == 15174
```

**Evidence:**

- Packet **15174** contains a DNS query with transaction ID **0x1ad5**.
- The query requests an **A record** for `www.7-zip.org`:

  ```text
  Standard query 0x1ad5 A www.7-zip.org OPT
  ```

**Supporting Screenshots:**
<img width="1743" height="274" alt="image" src="https://github.com/user-attachments/assets/211d55c0-334c-4af5-aa6a-09befb7b994f" />

**Flag:** `www.7-zip.org`

**Q4. How many UDP packets were sent from `192.168.1.26` to `24.39.217.246`?**

**Steps taken:**

1. Applied a Wireshark display filter to select UDP packets sent from `192.168.1.26` to `24.39.217.246`.
2. Checked the filtered packet list and the **Displayed** count in the status bar.
3. Confirmed that **10 packets** matched the filter.

**Filter:**

```wireshark
ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp
```

**Evidence:**

- All displayed packets have source IP `192.168.1.26`, destination IP `24.39.217.246`, and protocol **UDP**.
- The Wireshark status bar shows **Displayed: 10**.
- The matching frame numbers are `15806`, `15808`, `15825`, `15851`, `15865`, `15942`, `16095`, `16695`, `16810`, and `16955`.

**Supporting Screenshots:**
<img width="1743" height="976" alt="image" src="https://github.com/user-attachments/assets/af661b79-0e01-40f8-b641-58ddfee063da" />

**Flag:** `10`

**Q5. What is the MAC address of the system under investigation in the PCAP file?**

**Steps taken:**

1. Located traffic originating from the investigated system, `192.168.1.26`.
2. Selected **packet 15806** and expanded the **Ethernet II** header.
3. Read the source MAC address and correlated it with the source IP address in the **IPv4** header.

**Filter:**

```wireshark
ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp
```

**Evidence:**

- Packet **15806** shows the following source addresses:

  ```text
  Ethernet II source: c8:09:a8:57:47:93
  IPv4 source:        192.168.1.26
  ```

- Both fields belong to the same packet, identifying `c8:09:a8:57:47:93` as the MAC address associated with the investigated system.

**Supporting Screenshots:**
<img width="1743" height="908" alt="image" src="https://github.com/user-attachments/assets/e7c8f06e-30d6-4abf-93b4-3ef2765a485d" />

**Flag:** `c8:09:a8:57:47:93`

**Q6. What was the camera model name used to take picture `20210429_152157.jpg`?**

**Steps taken:**

1. Filtered FTP traffic to locate requests containing `.jpg` filenames.
2. Identified the upload request for `20210429_152157.jpg` in **packet 7070**.
3. Opened **File -> Export Objects -> FTP-DATA** and saved the matching file listed under **packet 7076**.
4. Opened the exported image’s **Properties -> Details** and inspected its camera metadata.

**Filter:**

```wireshark
ftp contains ".jpg"
```

**Evidence:**

- Packet **7070** shows the FTP upload command:

  ```text
  STOR 20210429_152157.jpg
  ```

- The FTP-DATA export list contains the matching filename, allowing the transferred image to be recovered.
- The image’s metadata identifies the manufacturer and model:

  ```text
  Manufacturer: LG Electronics
  Model:        LM-Q725K
  ```

**Supporting Screenshots:**
<img width="930" height="153" alt="Q6-1" src="https://github.com/user-attachments/assets/c3bdd13d-b9a5-438b-a002-69b46e442245" />
<img width="757" height="537" alt="Q6-2" src="https://github.com/user-attachments/assets/760e6dac-1855-4411-8441-4d5f0db83a54" />
<img width="1855" height="636" alt="image" src="https://github.com/user-attachments/assets/b949b980-1739-409d-b888-fc4437f024f2" />

**Flag:** `LM-Q725K`

**Q7. What is the ephemeral public key provided by the server during the TLS handshake in the session with the session ID: `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?**

**Steps taken:**

1. Applied a Wireshark display filter using the supplied TLS session ID.
2. Selected **packet 26913**, sent from `52.162.219.173` to `192.168.1.26`.
3. Expanded **Handshake Protocol: Server Key Exchange -> EC Diffie-Hellman Server Params**.
4. Copied the **Pubkey** value and verified that its 194 hexadecimal characters represent the displayed **97-byte** length.

**Filter:**

```wireshark
tls.handshake.session_id == da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff
```

**Evidence:**

- Packet **26913** contains the server’s **TLSv1.2 Server Key Exchange** message.
- The key exchange parameters show:

  ```text
  Curve Type:    named_curve (0x03)
  Named Curve:   secp384r1 (0x0018)
  Pubkey Length: 97
  ```

- The requested ephemeral public key appears in the **Pubkey** field within these server parameters.

**Supporting Screenshots:**
<img width="1742" height="942" alt="image" src="https://github.com/user-attachments/assets/5a7bac40-b2a1-417b-8bbc-fd64e0b89752" />

**Flag:** `04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d`

**Q8. What is the first `TLS 1.3` client random that was used to establish a connection with `protonmail.com`?**

**Steps taken:**

1. Filtered TLS traffic by the Server Name Indication (SNI) value `protonmail.com`.
2. Selected the earliest matching **Client Hello**, shown as **TLSv1.3** in **packet 17992**.
3. Expanded **Transport Layer Security -> Handshake Protocol: Client Hello**.
4. Copied the **Random** field and verified its length as **64 hexadecimal characters (32 bytes)**.

**Filter:**

```wireshark
tls.handshake.extensions_server_name == "protonmail.com"
```

**Evidence:**

- Packet **17992** is the first matching Client Hello in the displayed sequence.
- The packet identifies the connection and requested server:

  ```text
  Source IP:        192.168.1.26
  Destination IP:   185.70.41.35
  Destination port: 443
  Server name:      protonmail.com
  ```

- The **Random** field within the Client Hello contains the requested client random.

**Supporting Screenshots:**
<img width="1634" height="942" alt="Q8" src="https://github.com/user-attachments/assets/6f9adf22-ba50-4fc0-bb08-976a430de525" />

**Flag:** `24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70`

**Q9. Which country is the manufacturer of the `FTP server’s MAC` address registered in?**

**Steps taken:**

1. Applied the `ftp` display filter to locate the FTP server’s responses.
2. Selected **packet 486**, sent from the FTP server at `192.168.1.20`.
3. Expanded **Ethernet II** and identified the source MAC address as `08:00:27:a6:1f:86`.
4. Checked the MAC-vendor lookup result and read its registered country code.

**Filter:**

```wireshark
ftp
```

**Evidence:**

- Packet **486** associates the FTP server with these source addresses:

  ```text
  IPv4 source:     192.168.1.20
  Ethernet source: 08:00:27:a6:1f:86
  ```

- The supplied lookup result reports:

  ```text
  Address Prefix:   080027
  Vendor / Company: PCS Systemtechnik GmbH
  Country Code:     US
  Company Address:  600 Suffolk St Lowell MA US 01854
  ```

- The registration record’s country code **US** corresponds to the **United States**.

**Supporting Screenshots:**
<img width="1291" height="572" alt="image" src="https://github.com/user-attachments/assets/b8b947d6-bc24-4ee7-8a1d-6c5a58faf006" />
<img width="727" height="847" alt="image" src="https://github.com/user-attachments/assets/ceb2c7e8-47de-4bd1-b21a-e523c57dd5de" />

**Flag:** `United States`

**Q10. What time was a `non-standard folder` created on the FTP server on the 20th of April?**

**Steps taken:**

1. Filtered FTP traffic to locate directory-listing responses.
2. Identified **packet 528**, containing `150 Here comes the directory listing`.
3. Inspected the corresponding FTP-DATA transfer in **packet 530**, within **TCP stream 11**.
4. Followed the TCP stream and located the non-standard folder named `ftp`.

**Filters:**

```wireshark
ftp contains "directory"
```

```wireshark
tcp.stream eq 11
```

**Evidence:**

- The directory listing contains an entry for the `ftp` folder:

  ```text
  dr-xr-x---  4 65534 65534 4096 Apr 20 17:53 ftp
  ```

- The entry shows **April 20 at 17:53**.
- This is the timestamp displayed in the directory listing; a separate creation timestamp and timezone are not shown.

**Supporting Screenshots:**
<img width="1414" height="944" alt="Q10-1" src="https://github.com/user-attachments/assets/8121e10e-8fd3-4804-90ab-0d2e71708a7c" />
<img width="1547" height="306" alt="Q10-2" src="https://github.com/user-attachments/assets/8ec47946-70bf-4310-ba0a-aec8838a3055" />
<img width="643" height="317" alt="Q10-3" src="https://github.com/user-attachments/assets/dead2aa0-41f8-4ec6-9710-5914b407ab7f" />

**Flag:** `17:53`

---

**Q11. What URL was visited by the user and connected to the IP address `104.21.89.171`?**

**Steps taken:**

1. Filtered HTTP traffic involving `104.21.89.171`.
2. Selected **packet 26257**, sent from `192.168.1.26` to the specified IP address.
3. Used **Follow -> TCP Stream** to inspect the HTTP request.
4. Combined the HTTP scheme, `Host` header, and requested path to identify the visited URL.

**Filter:**

```wireshark
ip.addr == 104.21.89.171 && http
```

**Evidence:**

- Packet **26257** contains this request:

  ```http
  GET / HTTP/1.1
  Host: dfir.science
  ```

- The request identifies the visited URL as `http://dfir.science`.
- Packet **26264** contains a redirect response:

  ```http
  HTTP/1.1 301 Moved Permanently
  Location: https://dfir.science/
  ```

- The HTTPS address is the redirect destination; the observed initial request used HTTP.

**Supporting Screenshots:**
<img width="995" height="264" alt="image" src="https://github.com/user-attachments/assets/cceb757c-b069-4a9a-b7bb-ad64cd3098f2" />
<img width="1257" height="390" alt="image" src="https://github.com/user-attachments/assets/bd6c6527-6e70-4467-9525-c7380185b8aa" />

**Flag:** `http://dfir.science/`

---

## Findings

The reviewed evidence identifies **192.168.1.26** as the investigated client and reconstructs its FTP, DNS, UDP, HTTP, and TLS activity. The client successfully authenticates to the FTP server at **192.168.1.20** using credentials visible in plaintext. The documented workflow recovers a JPEG from the FTP data transfer and identifies its reported camera model as **LM-Q725K**. Other findings establish the IPv6 DNS server, a queried domain, a count of outbound UDP packets, an HTTP destination, and specific TLS handshake values.

These observations establish communication and credential exposure. The supplied evidence does not establish that the FTP login, file transfers, or web connections were unauthorized, and it does not demonstrate an attacker-controlled host or malware execution.

### Key Findings

| Area | Finding | Evidence |
|---|---|---|
| Investigated system | The client uses IPv4 address `192.168.1.26` and source MAC address `c8:09:a8:57:47:93`. | Q5; Ethernet II and IPv4 source fields in packet **15806**. |
| FTP authentication | The client submits username `kali` and password `AfricaCTF2021` to `192.168.1.20`: the server returns `230 Login successful.` | Q1: packets **496**, **500**, and **502**. |
| IPv6 DNS server | `fe80::c80b:adff:feaa:1db7` receives an IPv6 DNS query and sends the corresponding response. | Q2: packets **474–475**, transaction ID **0x6820**, and IPv6 Conversations. |
| Domain lookup | Packet **15174** requests an A record for `www.7-zip.org`. | Q3: DNS query with transaction ID **0x1ad5**. |
| UDP traffic count | **10 UDP packets** travel from `192.168.1.26` to `24.39.217.246`: all displayed packets target destination port **54150**. | Q4: directional filter and Wireshark's **Displayed: 10** count. |
| Transferred image | The client issues `STOR 20210429_152157.jpg`. The FTP-DATA object is exported, and the image properties report manufacturer **LG Electronics** and model **LM-Q725K**. | Q6: request packet **7070**, export-list packet **7076**, and image metadata. |
| TLS server public key | The selected TLS 1.2 session contains a **97-byte** ephemeral EC public key using **secp384r1**. | Q7: packet **26913**, Server Key Exchange parameters. |
| First ProtonMail Client Hello | The earliest displayed Client Hello for SNI `protonmail.com` is packet **17992**, sent to `185.70.41.35`: its Random field contains the 32-byte value recorded below. | Q8: SNI filter, packet order, and Client Hello details. |
| FTP server MAC registration | The FTP server's MAC is `08:00:27:a6:1f:86`. The supplied lookup reports **PCS Systemtechnik GmbH**, country code **US**, giving the lab answer **United States**. | Q9: packet **486** and the supplied MAC-vendor lookup screenshot. |
| Directory timestamp | The FTP directory listing contains the folder `ftp` with timestamp **Apr 20 17:53**. | Q10: FTP-DATA packet **530**, TCP stream **11**. |
| HTTP destination | The client requests `/` from `104.21.89.171` with `Host: dfir.science`, identifying the initial URL as `http://dfir.science`. A response redirects to `https://dfir.science/`. | Q11: request packet **26257**, response packet **26264**, and the HTTP stream. |

### Activity Timeline

The table follows packet order and uses the capture-relative values displayed in the screenshots, rounded to milliseconds. Absolute packet arrival times were not inspected for this summary. 

| Capture-relative time (seconds) | Packet(s) | Observed activity |
|---|---|---|
| `25.432–25.539` | **474–475** | An IPv6 DNS query for `t-ring.msedge.net` is sent to `fe80::c80b:adff:feaa:1db7`, followed by its response. |
| `35.838–35.882` | **486–502**, selected packets | FTP greeting, username submission, plaintext password submission, and successful-login response between `192.168.1.26` and `192.168.1.20`. |
| `35.895` | **528**, **530** | The server announces a directory listing and returns it over the FTP data connection. The listing contains the `ftp` folder. |
| `60.087` | **606** | The client issues `STOR 20210429_152321.jpg`. |
| `65.245` | **7070** | The client issues `STOR 20210429_152157.jpg`: the associated export-list object is identified by packet **7076**. |
| `126.315` | **15174** | DNS query requests the A record for `www.7-zip.org`. |
| `128.281–147.222` | **15806–16955**, 10 matching packets | UDP packets travel from `192.168.1.26` to `24.39.217.246:54150`. |
| `218.651` | **17992** | First displayed Client Hello for `protonmail.com`, sent from `192.168.1.26` to `185.70.41.35:443`. |
| `348.547–348.746` | **26257**, **26264** | HTTP request to `dfir.science` at `104.21.89.171`, followed by a `301 Moved Permanently` response. |
| `391.350` | **26913** | `52.162.219.173` sends the TLS 1.2 server handshake containing the selected session ID and ephemeral public key. |

**Separate metadata timestamps:** The FTP listing reports **Apr 20 17:53** for the `ftp` directory, without a year or timezone. The HTTP redirect reports `Date: Fri, 30 Apr 2021 01:06:39 GMT`. This server-generated header has not been used to assign absolute UTC times to the other packets.

--- 

## Indicators

### Observed Network and Host Values

These values support correlation within this lab. The reviewed evidence does not classify them as malicious indicators.

| Type | Value | Context |
|---|---|---|
| Investigated client IPv4 | `192.168.1.26` | Source of the documented FTP requests, UDP packets, and web connections. |
| Investigated client MAC | `c8:09:a8:57:47:93` | Ethernet source in packet **15806**. |
| FTP server IPv4 | `192.168.1.20` | Sends the FTP greeting and login result: receives the JPEG upload requests. |
| FTP server MAC | `08:00:27:a6:1f:86` | Ethernet source in packet **486**: lookup prefix `080027`. |
| IPv4 DNS destination | `192.168.1.10` | Destination of IPv4 DNS requests visible in Q2. |
| IPv6 DNS query source | `fe80::b011:ed39:8665:3b0a` | Sends the IPv6 query documented in Q2. |
| IPv6 DNS server | `fe80::c80b:adff:feaa:1db7` | Receives that query and returns the DNS response. |
| Queried domain | `www.7-zip.org` | A-record query in packet **15174**. |
| UDP destination | `24.39.217.246:54150` | Destination of the 10 matching outbound UDP packets. |
| TLS SNI | `protonmail.com` | Server name in the first displayed matching Client Hello, packet **17992**. |
| ProtonMail handshake destination | `185.70.41.35:443` | Destination observed in that Client Hello. |
| Selected TLS 1.2 server | `52.162.219.173` | Source of the server handshake in packet **26913**. |
| Initial HTTP URL | `http://dfir.science` | Reconstructed from the HTTP request's scheme, Host header, and root path. |
| HTTP destination IP | `104.21.89.171` | Destination of packet **26257**. |
| Redirect URL | `https://dfir.science/` | `Location` header in the `301` response. |

### Recovered Artifacts and TLS Identifiers

| Type | Value | Context |
|---|---|---|
| FTP username | `kali` | `USER` command in packet **496**. |
| FTP password | `AfricaCTF2021` | `PASS` command in packet **500**, followed by successful authentication. |
| Investigated JPEG | `20210429_152157.jpg` | Upload request **7070**, export-list object **7076**. |
| Reported camera model | `LM-Q725K` | Image properties list manufacturer **LG Electronics**. |
| Additional JPEG | `20210429_152321.jpg` | Upload request **606**, also visible in the FTP-DATA export list. |
| Additional archive | `accountNum.zip` | Visible in the FTP-DATA export list, contents were not examined in this analysis. |
| Listed directory | `ftp` | Entry in the listing for `/home/kali`, showing `Apr 20 17:53`. |
| Selected TLS session ID | `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff` | Session filter identifying packet **26913**. |

**Server ephemeral public key - Q7, 97 bytes:**

```text
04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d
```

The key appears under **Server Key Exchange -> EC Diffie-Hellman Server Params**, with curve **secp384r1**. 

**First displayed ProtonMail client random - Q8, 32 bytes:**

```text
24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70
```

These are handshake correlation values, not recovered private keys or session secrets.

---

## Lessons Learned

- **Confirm outcomes from responses.** The plaintext `PASS` command identifies a submitted credential; the server's `230` response establishes that the login succeeded.
- **Inspect FTP control and data connections together.** Commands identify the requested action, while data streams contain the directory listing and image bytes. 
- **Protect credentials and transferred content.** This session exposes a usable password and recoverable file content to an observer with capture access. Use an approved encrypted file-transfer service and require encryption before authentication.
- **Use directional filters for counts.** Filtering with `ip.src`, `ip.dst`, and `udp` answers the stated one-way question. Preserve the filter and displayed count with the evidence.
- **Read the correct TLS field.** Client random, session ID, certificate public key, and ephemeral public key have different roles. Record the field path, endpoint, packet number, and byte length when extracting them.
- **Preserve timestamp meaning.** Keep capture-relative times, HTTP response dates, and directory metadata separate. Confirm creation time through explicit filesystem or server evidence before treating a listing time as a creation event.
- **Preserve artifacts and assess context.** Hash recovered files, retain original captures and metadata.

---

## References
`-`

