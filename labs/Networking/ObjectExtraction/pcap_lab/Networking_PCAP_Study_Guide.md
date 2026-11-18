# Networking & PCAP Forensics Study Guide
### For the Oman National Cybersecurity CTF finals (Networking / Network Forensics category)

This guide goes with the 10 labs in `pcap_lab.zip`. It has four jobs:

1. Teach the **networking foundations** that packet-capture challenges rely on.
2. Give you a **reference for each protocol** (full name, port, commands, what leaks, how to extract it).
3. Give a **deep walkthrough of each lab**: what is in it, why it works, how to solve it, and what the same trick looks like in real CTFs.
4. Give you **routines and checklists** to use under time pressure.

Flags are not in this file. They stay in `SOLUTIONS.md`. Each lab section ends with a short "where it was hidden" part that tells you where to look, not the flag itself, so read those only after you have tried the lab.

---

## Contents

- Part 1: Networking foundations
- Part 2: Wireshark and tshark mastery
- Part 3: Protocol reference (FTP, Telnet, HTTP, SMTP, POP3, IMAP, MIME, DNS, ICMP, ARP)
- Part 4: Encodings cheat sheet
- Part 5: Lab-by-lab deep dive (10 labs)
- Part 6: The 60-second triage routine and CTF patterns
- Part 7: Study plan
- Part 8: Glossary

---

# Part 1: Networking foundations

## 1.1 What a PCAP is

**PCAP** stands for **Packet CAPture**. A `.pcap` (or `.pcapng`, the newer format) file is a recording of network traffic: every packet, in order, with a timestamp. Someone ran a capture tool (Wireshark, `tcpdump`) on a network interface and saved the result.

A capture contains raw bytes exactly as they were on the wire. If the protocol is **unencrypted** (FTP, Telnet, HTTP, SMTP, POP3, IMAP), then everything that was sent, including usernames, passwords, emails and files, is sitting in the file in readable form. That is why these protocols are the core of network-forensics CTF challenges.

Forensics here means three things:
- **Reconstruct** the conversations (put packet fragments back together).
- **Extract** what was transferred (files, credentials, messages).
- **Decode** what you extracted (base64, hex, URL-encoding, images, archives).

## 1.2 Layers and encapsulation

Data is wrapped in headers as it goes down the stack, like envelopes inside envelopes. Wireshark's middle pane shows these layers.

| OSI layer | TCP/IP layer | Examples | Unit of data |
|---|---|---|---|
| 7 Application | Application | HTTP, FTP, SMTP, DNS | data / message |
| 6 Presentation | Application | TLS, encodings | data |
| 5 Session | Application | session handling | data |
| 4 Transport | Transport | TCP, UDP | **segment** (TCP) / datagram (UDP) |
| 3 Network | Internet | IP, ICMP | **packet** |
| 2 Data link | Link | Ethernet, ARP | **frame** |
| 1 Physical | Link | cable, Wi-Fi | bits |

A typical web request in a capture looks like this, outermost to innermost:

```
Ethernet II  (source MAC, destination MAC)
  IPv4       (source IP, destination IP, TTL)
    TCP      (source port, destination port, sequence number, flags)
      HTTP   (GET /index.html HTTP/1.1 ...)
```

In a CTF you spend almost all your time at the **application layer** (reading the data), but you need the **transport layer** (TCP) to understand how to stitch it together.

## 1.3 Addresses and ports

- **MAC address**: hardware address on the local network (e.g. `02:00:c0:a8:01:14`). Only matters within one local network segment.
- **IP address**: logical address (e.g. `192.168.1.20`). Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Port**: 16-bit number (0-65535) that identifies a service or a connection on a host.
  - The **server** listens on a well-known port (80 for HTTP).
  - The **client** uses a random high port (the "ephemeral port", often 32768-60999 on Linux) as its source.
- A **connection** is identified by the 4-tuple `(source IP, source port, destination IP, destination port)`. Wireshark numbers each one as a `tcp.stream` index.

Common well-known ports to recognise on sight:

| Port | Protocol | | Port | Protocol |
|---|---|---|---|---|
| 20 | FTP data (active mode) | | 110 | POP3 |
| 21 | FTP control | | 143 | IMAP |
| 22 | SSH | | 161 | SNMP |
| 23 | Telnet | | 389 | LDAP |
| 25 | SMTP | | 443 | HTTPS |
| 53 | DNS | | 445 | SMB |
| 67/68 | DHCP | | 587 | SMTP submission |
| 69 | TFTP | | 993 / 995 | IMAPS / POP3S (encrypted) |
| 80 | HTTP | | 3389 | RDP |

**Important:** a service can run on a non-standard port. If a port is unusual, check the data itself. Wireshark's right-click **Decode As...** lets you force a protocol onto a port.

## 1.4 TCP in detail (this is the heart of stream reconstruction)

**TCP** is the **Transmission Control Protocol**. It gives applications a reliable, ordered byte stream on top of unreliable packets. To do this it numbers every byte.

### The three-way handshake
```
Client                         Server
  | ---- SYN (seq = x) ----->   |    "I want to connect, my first byte number is x"
  | <--- SYN,ACK (seq = y, ack = x+1) ---|   "OK, mine is y, I expect your next byte to be x+1"
  | ---- ACK (ack = y+1) ----->   |    "Got it. Connection established."
```

### Flags
| Flag | Meaning | You see it when |
|---|---|---|
| **SYN** | Synchronise: start a connection | handshake (also port scans: many SYNs, no completion) |
| **ACK** | Acknowledgement: "I received up to byte N" | almost every packet |
| **PSH** | Push: deliver this data to the application now | data packets |
| **FIN** | Finish: I have no more data to send | graceful close |
| **RST** | Reset: abort the connection | closed ports, errors, scans |
| **URG** | Urgent pointer (rarely used) | covert-channel tricks |

### Sequence and acknowledgement numbers
- The **sequence number** says "the first byte of data in this packet is byte number N of my stream".
- The **acknowledgement number** says "I have received everything up to N-1; send byte N next".
- Each direction has its own independent numbering.
- Wireshark shows **relative** sequence numbers by default (starting from 0 per stream), which are easier to read. The real numbers start at a random initial sequence number (ISN).

**Why this matters for forensics:** a large message is split into pieces (segments). Each piece carries its sequence number. To rebuild the original data you sort the pieces **by sequence number, not by arrival order**, and drop duplicates. Wireshark does this automatically when you use Follow TCP Stream. Lab 10 is built to test exactly this.

### MTU and MSS
- **MTU** (Maximum Transmission Unit): largest IP packet on the link. Ethernet is **1500 bytes**.
- **MSS** (Maximum Segment Size): largest TCP payload per segment = MTU minus IP header (20) minus TCP header (20) = **1460 bytes**.
- So any file larger than about 1460 bytes arrives in several segments. That is why a 40 KB image shows up as about 28 packets, and why you cannot just read one packet to get a whole file.

### Retransmission, out-of-order, duplicates
- If a segment is lost or unacknowledged, the sender **retransmits** the same sequence number again. Result: duplicate data in the capture.
- Packets can arrive **out of order**.
- Wireshark marks these in black with red text (`TCP Retransmission`, `TCP Out-Of-Order`, `TCP Dup ACK`). Filter: `tcp.analysis.flags`.
- When you carve data manually (without Wireshark), you must handle both: sort by sequence number and discard repeats.

### Closing
A graceful close is `FIN, ACK` then `ACK`, then the other side's `FIN, ACK` then `ACK` (four packets). An abrupt close is a single `RST`.

## 1.5 UDP, ICMP, ARP and DNS (the non-TCP traffic you will meet)

- **UDP** (**User Datagram Protocol**): connectionless, no ordering, no handshake. Used by DNS, DHCP, TFTP, many games. No "Follow TCP Stream", but you can use **Follow UDP Stream**.
- **ICMP** (**Internet Control Message Protocol**): network diagnostics. `ping` is ICMP echo request (type 8) and echo reply (type 0). ICMP packets have a data payload, which can be used to **smuggle data** in CTFs ("ICMP exfiltration").
- **ARP** (**Address Resolution Protocol**): maps an IP address to a MAC address on the local network. "Who has 192.168.1.50? Tell 192.168.1.20". The owner replies "192.168.1.50 is at <MAC>". Lots of ARP replies for the same IP from different MACs suggests **ARP spoofing**.
- **DNS** (**Domain Name System**): translates names to IPs, UDP port 53 (TCP for large replies and zone transfers). Query types: A (IPv4), AAAA (IPv6), MX (mail server), TXT (free text), CNAME (alias), NS, PTR (reverse). CTF tricks: data hidden in very long or odd subdomain labels (**DNS tunneling/exfiltration**), or in TXT records.

## 1.6 Text protocols vs binary protocols

FTP, Telnet, HTTP, SMTP, POP3 and IMAP are **line-oriented text protocols**: commands are readable words ending in **CRLF** (carriage return `\r` = 0x0D, line feed `\n` = 0x0A). This is why you can read them in Follow Stream and `grep` them. Binary protocols (DNS, TLS, SMB) need dissectors.

---

# Part 2: Wireshark and tshark mastery

## 2.1 The window

1. **Packet list** (top): one row per packet. Columns: No., Time, Source, Destination, Protocol, Length, Info.
2. **Packet details** (middle): the layers, expandable.
3. **Packet bytes** (bottom): hex plus ASCII.

## 2.2 First 60 seconds on any capture

1. **Statistics → Protocol Hierarchy**: what protocols are present and how much of each. Tells you where to focus.
2. **Statistics → Conversations**: tabs for Ethernet, IPv4, TCP, UDP. Sort by bytes: the biggest conversation is often the interesting transfer. A conversation with many packets but tiny bytes might be a scan or a keystroke session (Telnet).
3. **Statistics → Endpoints**: which hosts talk the most.
4. **Analyze → Expert Information**: retransmissions, resets, warnings. Handy for oddities.

## 2.3 Display filters (the ones to memorise)

Display filters hide packets without deleting them. The bar turns green when the syntax is valid.

```
# protocol
ftp   ftp-data   telnet   http   smtp   pop   imap   dns   icmp   arp

# addresses and ports
ip.addr == 192.168.1.20            ip.src == 10.0.0.5          ip.dst == 10.0.0.5
tcp.port == 21                     tcp.dstport == 80           udp.port == 53
tcp.stream eq 4                    # one specific connection

# content search
frame contains "flag"              tcp contains "password"     http contains "login"
frame matches "(?i)flag\\{.*\\}"   # regex, case-insensitive

# HTTP
http.request.method == "POST"      http.request.uri contains "login"
http.host == "example.com"         http.response.code == 302
http.cookie                        http.set_cookie             http.authorization
http.user_agent                    http.content_type contains "image"
http.file_data                     urlencoded-form

# FTP
ftp.request.command == "USER"      ftp.request.command == "PASS"
ftp.request.command == "RETR"      ftp.response.code == 530     ftp.passive.port

# Email
smtp.req.command == "AUTH"         smtp.req.command == "DATA"   imf
pop.request.command == "RETR"      imap.request contains "LOGIN"

# TCP behaviour
tcp.flags.syn == 1 && tcp.flags.ack == 0     # connection attempts (scans)
tcp.flags.reset == 1                         # resets
tcp.analysis.retransmission                  tcp.analysis.out_of_order
tcp.analysis.flags                           # all TCP oddities

# combine with && || !
ip.addr == 192.168.1.20 && !(dns || arp)
```

Tip: after finding something, right-click a field → **Apply as Filter → Selected**, or **Prepare as Filter**. It builds the filter for you.

## 2.4 Follow Stream

Right-click a packet → **Follow → TCP Stream** (shortcut `Ctrl+Alt+Shift+T`). It reassembles the whole conversation:
- **Red** text = client to server. **Blue** text = server to client.
- The dropdown **"Show data as"** has: ASCII, Hex Dump, Raw, YAML, etc. Use **Raw** if you plan to **Save as** a binary file; ASCII mode can corrupt non-text bytes.
- The **direction dropdown** at the bottom lets you show only one side (essential for Telnet passwords and for extracting a client-side upload).
- The **Stream** spinbox steps through every stream number. In a hard capture, step through **all** of them; do not rely on the first hit.
- There are also Follow UDP Stream, Follow TLS Stream (if you have keys), Follow HTTP Stream, and Follow HTTP/2 Stream.

## 2.5 Export Objects

**File → Export Objects →** HTTP, IMF (emails), SMB, TFTP, DICOM, and FTP-DATA (in recent versions). A list of reassembled files appears; select and **Save**. It uses the HTTP/FTP metadata to name them. If a protocol is not in the menu, use Follow Stream → Raw → Save as, then trim the headers off yourself (see Lab 10).

## 2.6 Finding things

- **Edit → Find Packet** (`Ctrl+F`): search by String (in Packet list, Packet details, or Packet bytes), by Display filter, by Hex, or by Regex.
- **Packet bytes search with "String"** finds text inside payloads even when no filter covers the protocol.
- **Edit → Mark/Ignore Packet** and **Time Reference**: for keeping place in a long capture.
- **View → Coloring Rules**: default colours help (light green HTTP, black/red TCP problems, light blue UDP, etc.).

## 2.7 tshark (the command line twin)

Use this when the finals PC has no GUI, or when you want speed and scripting.

```bash
tshark -r f.pcap                                   # print packet list
tshark -r f.pcap -Y 'http.request'                 # apply a display filter
tshark -r f.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tshark -r f.pcap -c 20                             # first 20 packets only

# overview
tshark -r f.pcap -q -z io,phs                      # protocol hierarchy
tshark -r f.pcap -q -z conv,tcp                    # TCP conversations
tshark -r f.pcap -q -z endpoints,ip                # host

# follow a stream (N = stream index)
tshark -r f.pcap -q -z follow,tcp,ascii,N
tshark -r f.pcap -q -z follow,tcp,hex,N
tshark -r f.pcap -q -z follow,tcp,raw,N            # hex string you can convert: ... | xxd -r -p > out.bin

# extract files
tshark -r f.pcap --export-objects http,./out
tshark -r f.pcap --export-objects ftp-data,./out
tshark -r f.pcap --export-objects imf,./out        # emails

# credentials (modern builds)
tshark -r f.pcap -z credentials
```

**If you only have `strings`, `grep` and Python:** run `strings -a f.pcap | grep -i flag` as an early smoke test. It will fail if the data is encoded, split across packets, compressed or an image, but it costs two seconds.

---

# Part 3: Protocol reference

Each entry: **full name**, port, what it does, key commands and codes, what it leaks, how to read and extract it in a capture.

## 3.1 FTP: File Transfer Protocol (RFC 959)

- **Ports:** 21 (control), 20 (data in active mode), a random high port (data in passive mode).
- **Purpose:** upload and download files between a client and a server.
- **Unencrypted:** username, password, commands and file contents are all plaintext. (Secure versions: **FTPS** = FTP over TLS, and **SFTP** = SSH File Transfer Protocol, which is a different protocol on port 22.)

**Two-connection design:**
- The **control connection** carries commands and replies (`USER`, `PASS`, `LIST`, `RETR`...).
- The **data connection** is opened separately, once per file transfer or directory listing, and carries only the bytes of the file or listing.

**Active vs passive mode:**
- **Active:** client sends `PORT a,b,c,d,p1,p2` ("connect back to me at IP a.b.c.d, port p1*256+p2"). The server opens the data connection **to the client**, from port 20.
- **Passive:** client sends `PASV`. The server replies `227 Entering Passive Mode (a,b,c,d,p1,p2)`. The client opens the data connection **to the server** at port `p1*256 + p2`.
  Example: `(192,168,1,50,195,81)` → 195*256 + 81 = **50001**.
- **EPSV** (extended passive) replies `229 Entering Extended Passive Mode (|||50001|)`.
- Wireshark can usually link them automatically; the filter `ftp.passive.port` and the `ftp-data` protocol help.

**Common commands:** `USER`, `PASS`, `SYST`, `PWD`, `CWD`, `LIST`, `NLST`, `TYPE A` (ASCII) / `TYPE I` (binary/image), `PASV`, `RETR file` (download), `STOR file` (upload), `DELE`, `MKD`, `QUIT`.

**Reply codes:** `220` service ready, `331` password needed, `230` login OK, `530` login failed, `150` opening data connection, `226` transfer complete, `227` passive mode, `257` directory, `550` file unavailable/permission denied, `221` goodbye.

**What leaks:** credentials; file names; file contents; directory structure. Many `530` replies in a row = brute-force attempt. `STOR` = upload (maybe a webshell or exfiltration); `RETR` = download.

**How to extract:** read the control stream for context and the port; find the matching data connection (`tcp.port == <port>`); Follow Stream or Export Objects → FTP-DATA. Use `TYPE I` knowledge: binary files must be saved as Raw.

## 3.2 Telnet: Teletype Network (RFC 854)

- **Port:** 23.
- **Purpose:** remote text terminal login (the old, insecure predecessor of SSH, which is Secure Shell).
- **Unencrypted:** everything you type and see is in the clear.

**Key facts:**
- It runs on the **NVT** (**Network Virtual Terminal**) model: lines end with `CR LF` or `CR NUL`.
- By default each **keystroke is sent as its own TCP packet**, and the server **echoes** the character back so it appears on screen. When the server turns echo off (during password entry), you see client packets with **no echo**.
- **IAC** (**Interpret As Command**, byte `0xFF` = 255) introduces option negotiation:

| Byte | Name | Meaning |
|---|---|---|
| `0xFF` | IAC | start of a command |
| `0xFB` | WILL | "I will use this option" |
| `0xFC` | WONT | "I won't" |
| `0xFD` | DO | "please use this option" |
| `0xFE` | DONT | "please don't" |
| `0xFA` / `0xF0` | SB / SE | subnegotiation begin / end |

Common options: `0x01` ECHO, `0x03` Suppress-Go-Ahead, `0x18` Terminal-Type, `0x1F` NAWS (window size), `0x20` Terminal-Speed, `0x23` X-Display-Location, `0x27` New-Environment. You will see these as strange bytes (`ff fd 18`) at the start of a Telnet session. They are protocol housekeeping, not data.

**What leaks:** username, password, every command, every output (file contents via `cat`, config files, other secrets).

**How to extract:** Follow TCP Stream. To see only what the user typed, restrict to client→server. To pull data in tshark: `-Y telnet -T fields -e telnet.data`.

## 3.3 HTTP: HyperText Transfer Protocol (RFC 9110/9112)

- **Ports:** 80 (plain). 443 is **HTTPS** = HTTP over **TLS** (**Transport Layer Security**); it is encrypted and unreadable without keys. Alternative ports: 8080, 8000, 8888.
- **Purpose:** the web. Request-response over TCP.

**Request:**
```
POST /login HTTP/1.1
Host: portal.acme.local
User-Agent: Mozilla/5.0 ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Cookie: session=abc

username=jsmith&password=secret
```
- **Methods:** `GET` (fetch), `POST` (send data), `PUT`, `DELETE`, `HEAD`, `OPTIONS`.
- **Headers** end at a blank line (`\r\n\r\n`); the **body** follows. `Content-Length` says how many bytes the body is.

**Response:**
```
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=abc; HttpOnly
Content-Type: text/html
Content-Length: 123
```
- **Status codes:** `200 OK`, `301`/`302` redirect, `304` not modified, `400` bad request, `401` unauthorized, `403` forbidden, `404` not found, `500` server error.

**Headers that matter in forensics:**
- `Host`: which site. `User-Agent`: client software (odd UAs can mean tools like `curl`, `sqlmap`, `python-requests`).
- `Cookie` / `Set-Cookie`: session tokens. Stealing a cookie = session hijack.
- `Authorization: Basic <base64>`: base64 of `user:pass`. Decode it immediately.
- `Referer`, `Origin`: where a request came from.
- `Content-Type`: `application/x-www-form-urlencoded` (form body, percent-encoded), `multipart/form-data; boundary=...` (file uploads), `application/json`.
- `Content-Encoding: gzip` and `Transfer-Encoding: chunked`: the body is compressed and/or framed in chunks (each chunk prefixed with its size in hex). Wireshark decodes both for you; raw saves will not be.
- Custom headers like `X-Debug-Note`: developers and CTF authors hide data here.

**What leaks:** form credentials (POST), cookies, API keys in URLs/headers, uploaded and downloaded files, internal paths. Attack traffic too: SQL injection strings in URLs (`' OR 1=1`), directory traversal (`../`), scanner signatures.

**How to extract:** Follow HTTP/TCP stream; File → Export Objects → HTTP; filters above. For POST forms, Wireshark's bottom detail tree "HTML Form URL Encoded" shows decoded values.

## 3.4 SMTP: Simple Mail Transfer Protocol (RFC 5321)

- **Ports:** 25 (server-to-server relay), 587 (client **submission**, usually with STARTTLS), 465 (SMTP over implicit TLS, "SMTPS").
- **Purpose:** **sending** email (client to server, and server to server).

**A session:**
```
S: 220 mail.acme.local ESMTP Postfix
C: EHLO laptop.acme.local            (EHLO = extended HELO; HELO = hello)
S: 250-... 250-AUTH PLAIN LOGIN ... 250 8BITMIME
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6                  (= "Username:" in base64)
C: <base64 username>
S: 334 UGFzc3dvcmQ6                  (= "Password:" in base64)
C: <base64 password>
S: 235 2.7.0 Authentication successful
C: MAIL FROM:<alice@acme.local>
S: 250 Ok
C: RCPT TO:<bob@acme.local>
S: 250 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: <headers, blank line, body, attachments>
C: .                                 (a line with only a dot ends the message)
S: 250 Ok: queued as 4F2A81C3D9
C: QUIT
S: 221 Bye
```
- **Reply codes:** `220` ready, `250` OK, `334` auth challenge (base64), `235` auth OK, `535` auth failed, `354` start mail input, `221` closing, `550` mailbox unavailable.
- **AUTH PLAIN** sends one base64 string that decodes to `\0username\0password`. **AUTH LOGIN** sends username and password as separate base64 lines (decode each).
- If you see `STARTTLS` accepted (`220 Ready to start TLS`), everything after it is **encrypted** and unreadable without keys.

**What leaks:** sender, recipients, subject, body, attachments, and the login credentials (base64 is encoding, not encryption).

**How to extract:** Follow TCP Stream, client side. Or File → Export Objects → IMF. Attachments are base64 inside MIME (see 3.7).

## 3.5 POP3: Post Office Protocol version 3 (RFC 1939)

- **Ports:** 110 (plain), 995 (**POP3S**, over TLS).
- **Purpose:** **downloading** email from a server to a client. Simple: download and (usually) delete.

**Commands:** `USER name`, `PASS password`, `STAT` (count and total size), `LIST` (message sizes), `RETR n` (download message n), `DELE n` (mark for deletion), `TOP n lines`, `UIDL` (unique IDs), `CAPA`, `QUIT`.
**Responses:** `+OK ...` or `-ERR ...`. A multi-line response (like a message) ends with a line containing only `.`.

**What leaks:** credentials in plaintext; full message contents. Each `RETR` shows a whole email including headers and attachments.

## 3.6 IMAP: Internet Message Access Protocol (RFC 3501)

- **Ports:** 143 (plain, often upgraded with STARTTLS), 993 (**IMAPS**, over TLS).
- **Purpose:** **accessing and managing** mail on the server (folders, flags, searching), without necessarily downloading everything. More complex than POP3.

**Format:** every client command begins with a **tag** (`a001`, `a002`...), and the server's final reply repeats that tag with `OK`, `NO` or `BAD`. Lines starting with `*` are **untagged** server data.

**Commands:** `CAPABILITY`, `LOGIN user pass`, `LIST "" "*"` (folders), `SELECT INBOX`, `FETCH 1:3 (BODY[HEADER])`, `FETCH n BODY[TEXT]`, `SEARCH`, `STORE n +FLAGS (\Deleted)`, `UID ...`, `LOGOUT`, `STARTTLS`.

**Literals:** when a value contains arbitrary bytes, IMAP announces its length in braces, like `{128}`, and the next 128 bytes are the content, exactly. In a FETCH response that is how the message body is delivered.

**What leaks:** credentials (`LOGIN`), mailbox names, message headers and bodies, flags.

## 3.7 MIME: Multipurpose Internet Mail Extensions

Email was designed for plain 7-bit text. **MIME** lets it carry attachments, images, and non-ASCII text.

**Key headers:**
- `MIME-Version: 1.0`
- `Content-Type:` e.g. `text/plain; charset=UTF-8`, `image/png; name="x.png"`, `multipart/mixed; boundary="----=_Part_8841"`.
- `Content-Transfer-Encoding:` how the body bytes are represented: `7bit`, `8bit`, **`base64`**, **`quoted-printable`**, `binary`.
- `Content-Disposition: attachment; filename="x.png"`.

**Multipart structure:** the message is divided by a **boundary** string. Each part starts with `--BOUNDARY`, has its own headers, a blank line, then data. The message ends with `--BOUNDARY--`.

**Encodings in mail:**
- **base64**: 3 bytes become 4 characters from `A-Za-z0-9+/`, padded with `=`. Lines wrap at 76 characters. Decode with `base64 -d`. Remove the line breaks if needed.
- **quoted-printable (QP)**: mostly-readable text where unsafe characters become `=XX` (hex). `=3D` is a literal `=`. An `=` at the **end of a line** is a **soft line break** (the line continues, the break is not part of the data). Lines are limited to 76 characters so long text is split with these soft breaks. Decode with Python's `quopri`.
- **Encoded-word headers (RFC 2047):** non-ASCII subjects look like `=?UTF-8?B?...?=` (B = base64) or `=?UTF-8?Q?...?=` (Q = quoted-printable). Decode the middle part.

## 3.8 Also handy: other cleartext protocols to recognise

| Protocol | Port | Notes |
|---|---|---|
| **TFTP** (Trivial File Transfer Protocol) | UDP 69 | no auth, file transfer; Export Objects → TFTP |
| **SMB** (Server Message Block) | 445 | Windows file sharing; Export Objects → SMB |
| **SNMP** (Simple Network Management Protocol) | UDP 161 | community strings (like passwords) in plaintext in v1/v2c |
| **DHCP** (Dynamic Host Configuration Protocol) | UDP 67/68 | hostnames, assigned IPs |
| **LDAP** (Lightweight Directory Access Protocol) | 389 | directory queries, simple bind passwords |
| **RDP** (Remote Desktop Protocol) | 3389 | usually encrypted |
| **SSH** (Secure Shell) | 22 | encrypted; only the banner is visible |

---

# Part 4: Encodings cheat sheet

You will constantly decode after extracting. Recognise by look:

| Encoding | Looks like | Decode |
|---|---|---|
| **Base64** | `SGVsbG8gd29ybGQ=` letters+digits+`+/`, ends with `=` padding, length multiple of 4 | `echo '...' \| base64 -d` |
| **Hex** | `48656c6c6f` only 0-9a-f, even length | `echo '...' \| xxd -r -p` |
| **URL / percent-encoding** | `%7Bflag%7D`, `%20`, `+` for space | `python3 -c "import urllib.parse as u;print(u.unquote('...'))"` |
| **Quoted-printable** | `caf=C3=A9`, `=3D`, `=` at line ends | `python3 -c "import quopri,sys;print(quopri.decodestring(sys.stdin.buffer.read()).decode())"` |
| **ROT13** | readable-looking but wrong letters | `echo '...' \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| **Gzip** | bytes start `1f 8b` | `gunzip` / `zcat` |
| **Zip** | starts `PK` (`50 4B 03 04`) | `unzip -P pass file.zip` |
| **PNG** | starts `89 50 4E 47 0D 0A 1A 0A`, ends with `IEND` + 4 CRC bytes | `file`, `exiftool`, `pngcheck` |
| **JPEG** | starts `FF D8 FF`, ends `FF D9` | `file`, `exiftool`, `steghide`, `binwalk` |

**Layered encodings are common in CTFs.** If the output of a decode still looks encoded, decode again. Examples: base64 of hex; hex of base64; URL-encoded base64.

**File signatures ("magic bytes")** let you recognise a file even without an extension. `file x` reads them. When carving files from a raw stream, you cut from the start signature to the end marker.

---

# Part 5: Lab-by-lab deep dive

Each lab has: Scenario, What it teaches, Background, Method (Wireshark, then tshark/CLI), Pitfalls, Real-CTF variations, Where it was hidden (spoiler), and Self-check questions.

## Lab 01: FTP (easy)

**Scenario:** An admin (`192.168.1.20`) logs into an FTP server (`192.168.1.50`), lists a directory, and downloads a file called `notes.txt`.

**What it teaches:** FTP's two-connection model, passive mode port arithmetic, and the difference between what the control channel shows (commands) and what the data channel shows (contents).

**Background:** see 3.1. The capture contains one control connection (port 21) and two short data connections (ports 50001 and 50002). A beginner reads only the control channel, finds the password, and stops. The password is a **decoy**: valid, but not the answer.

**Method (Wireshark):**
1. Filter `ftp`. Read the whole control conversation top to bottom: `USER`, `PASS`, `SYST`, `TYPE I`, `PASV`, `LIST`, `RETR notes.txt`.
2. Look at each `227 Entering Passive Mode (...)` reply and compute the port: `p1*256 + p2`.
3. Filter `tcp.port == 50002` (the port used for the `RETR`). Right-click → Follow → TCP Stream. You are reading the actual file.
4. Alternative: File → Export Objects → FTP-DATA, or filter `ftp-data`.

**Method (tshark):**
```bash
tshark -r 01_ftp_easy.pcap -Y 'ftp' -T fields -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg
tshark -r 01_ftp_easy.pcap -q -z conv,tcp                  # find the stream with the file
tshark -r 01_ftp_easy.pcap -q -z follow,tcp,ascii,2        # try stream numbers until the file appears
```

**Pitfalls:** stopping at the control channel; using ASCII for a binary file; forgetting that `LIST` also opens a data connection (its content is the directory listing, not a file).

**Real-CTF variations:** active mode (`PORT` command, server connects back from port 20); a file transferred in several chunks; a deleted or renamed file visible only in the `RENAME`/`DELE` commands; a binary (image, zip) file in the data stream.

**Where it was hidden (spoiler):** inside the file downloaded with `RETR` on the second passive data connection.

**Self-check:**
- What are the two FTP connections and what does each carry?
- Given `(10,0,0,5,200,15)`, what is the data port? (200*256 + 15 = 51215)
- How do you tell an upload from a download in the control channel? (`STOR` vs `RETR`)

---

## Lab 02: Telnet (easy)

**Scenario:** Someone logs into a server called `web01` over Telnet, runs `whoami`, `ls`, `cat notes.txt`, and exits.

**What it teaches:** Telnet's per-keystroke packets, server echo, why a password does not appear in the server-to-client stream, and how to filter by direction.

**Background:** see 3.2. The session starts with IAC negotiation bytes (`ff fd 18 ...`). Then the login prompt appears. As the user types `admin`, each character goes in its own packet and the server echoes it back, so Follow Stream shows the text interleaved or doubled. When the password is typed, the server is not echoing, so the characters appear **only** in the client-to-server direction.

**Method (Wireshark):**
1. Filter `telnet`. Notice the 1-byte packets.
2. Follow → TCP Stream. Skim the whole session: you see the banner, `login:`, `Password:`, the shell prompt, commands and outputs.
3. In the direction dropdown choose **client → server only**. Now you see exactly what the user typed, in order, including the password (between the first and second line breaks).
4. Optional: remove the carriage-return/null bytes mentally: the Enter key is sent as `\r\x00`.

**Method (CLI):**
```bash
tshark -r 02_telnet_easy.pcap -Y 'ip.src==192.168.1.20 && telnet.data' -T fields -e telnet.data
# or reassemble the client side and split on the line terminator
```

**Pitfalls:** reading the doubled echo and miscounting characters; including the `\r\x00` as part of the password; reading only the server direction (no password there).

**Real-CTF variations:** the password typed with corrections (backspace characters `0x7f` or `0x08`), so you must replay the edits; a session where the user switches to `su` or `sudo` and types a second password; commands that print private keys or config files.

**Where it was hidden (spoiler):** typed by the client after the `Password:` prompt, not echoed back.

**Self-check:**
- What does `ff fd 01` mean? (IAC DO ECHO: "please echo")
- Why is the password missing from the server's side of the stream? (the server does not echo during password entry)
- Which tool feature isolates one direction? (Follow Stream's direction dropdown)

---

## Lab 03: HTTP POST login (easy)

**Scenario:** A user `jsmith` visits a portal, is redirected to `/login`, fails one login attempt, then logs in successfully and views `/dashboard`.

**What it teaches:** reading both the request and the response; identifying a successful attempt from status code and `Set-Cookie`; URL-decoding a form body.

**Background:** see 3.3. HTML forms submit with `application/x-www-form-urlencoded`: `key=value` pairs joined by `&`, special characters as `%XX`. The curly braces in a flag become `%7B` and `%7D`.

**Method (Wireshark):**
1. Filter `http.request.method == "POST"`: two requests.
2. Click each and look at the **response** that follows (`http.response.code`). The failed attempt returns `200` with an error page; the successful one returns `302 Found` with `Set-Cookie`.
3. In packet details open **HTML Form URL Encoded** to see the decoded fields. Or Follow HTTP stream and decode by hand.

**Method (tshark):**
```bash
tshark -r 03_http_post_easy.pcap -Y 'http.request.method==POST' -T fields -e frame.number -e http.file_data
tshark -r 03_http_post_easy.pcap -Y 'http.response' -T fields -e frame.number -e http.response.code -e http.set_cookie
```
Note `http.file_data` is in hex in some versions; pipe through `xxd -r -p`. Then URL-decode.

**Pitfalls:** copying the first POST (the wrong password); forgetting to decode `%7B`; missing that the cookie in the following request proves the second login worked.

**Real-CTF variations:** JSON body (`application/json`); `Authorization: Basic` header instead of a form; credentials in the URL query string of a GET; credentials in a cookie.

**Where it was hidden (spoiler):** the `password` field of the second POST body, percent-encoded.

**Self-check:**
- Which status code marks a redirect after login? (302)
- What does `%7D` decode to? (`}`)
- How do you prove which login worked using only the packets? (the response and the later authenticated request carrying the cookie)

---

## Lab 04: HTTP Export Objects (medium)

**Scenario:** A browser loads a corporate site: HTML, CSS, JavaScript, a logo, a banner, two missing files (404), and one file under `/assets/internal/`.

**What it teaches:** the Export Objects feature, sorting real objects from decoys, and the fact that a flag can live **inside an image** so no text search will find it.

**Background:** HTTP responses with `Content-Length` and `Content-Type` are reassembled by Wireshark into objects. Large objects span many TCP segments (MSS 1460). A 404 response is a small error page, not the requested file.

**Method (Wireshark):**
1. File → Export Objects → HTTP.
2. Read the list: Packet no., Hostname, **Content Type**, Size, Filename. Sort by Content Type or Size.
3. Ignore text/css, JavaScript and 404 pages. The two PNGs and one JPEG are candidates; one PNG's path says "internal".
4. Save all, open the images, read the text rendered in the internal one.

**Method (CLI):**
```bash
mkdir out && tshark -r 04_http_objects_medium.pcap --export-objects http,./out
file out/*           # confirm real types
```

**Pitfalls:** assuming `frame contains "flag"` will find it (it will not: the text is pixels); trusting file extensions instead of `file`; forgetting that responses with a 404 status have a body that is not the requested file.

**Real-CTF variations:** the object is a PDF or Word file; the image is a QR code; the flag is in image metadata or hidden with steganography (then use your stego tools: `zsteg`, `steghide`, `binwalk`, `exiftool`); the file is gzip-compressed or served in chunks.

**Where it was hidden (spoiler):** drawn as text in the PNG served from the "internal" assets path.

**Self-check:**
- Why can you not `grep` for the flag here? (it is rendered as pixels)
- How would you confirm an object's real type? (`file`, magic bytes)
- What is MSS, and why does an image span many packets? (max TCP payload, 1460)

---

## Lab 05: SMTP attachment (medium)

**Scenario:** Alice authenticates to the mail server and emails Bob a PNG scan of a signed contract.

**What it teaches:** an SMTP session end to end, base64 `AUTH LOGIN`, MIME multipart structure, and decoding a base64 attachment into a file.

**Background:** see 3.4 and 3.7. The server challenges with `334 VXNlcm5hbWU6` ("Username:") and `334 UGFzc3dvcmQ6` ("Password:"); the client answers with base64. After `DATA` the client sends headers, a blank line, then a multipart body. The image part has `Content-Transfer-Encoding: base64` and a long block of 76-character lines.

**Method (Wireshark):**
1. Filter `smtp`. Follow TCP Stream. Read the whole conversation.
2. Decode credentials: the two lines after `334` challenges, e.g. `echo '...' | base64 -d`.
3. In the body locate the attachment part. The base64 block starts after the blank line that follows `Content-Disposition` and ends before the next `--boundary` line.
4. Copy the block into a file, then: `base64 -d block.txt > contract_scan.png`. Open it.
5. Alternative: File → Export Objects → IMF saves the message as `.eml`; open it with an email client or extract the part with Python's `email` module.

**Method (Python, handy when GUI is limited):**
```python
import email, base64
msg = email.message_from_bytes(open("mail.eml","rb").read())
for part in msg.walk():
    if part.get_filename():
        open(part.get_filename(),"wb").write(part.get_payload(decode=True))
```

**Pitfalls:** including the boundary line or blank lines in the base64 block (decoder errors); copying from the ASCII view and losing characters; forgetting the final padding `=`.

**Real-CTF variations:** `AUTH PLAIN` with a single base64 token (`\0user\0pass`); a zip or PDF attachment (maybe password-protected, with the password in another email); the message split into multiple attachments; a hidden second recipient (`RCPT TO`) or `Bcc`.

**Where it was hidden (spoiler):** in the attached PNG (base64 in the DATA section), as text drawn in the image.

**Self-check:**
- What does `334 VXNlcm5hbWU6` decode to? ("Username:")
- What ends the DATA section? (`<CRLF>.<CRLF>`)
- Why are attachments base64? (email transport was 7-bit text)

---

## Lab 06: POP3 with quoted-printable (medium)

**Scenario:** Bob logs into the POP3 server, checks the mailbox (2 messages), reads both, deletes the first and quits.

**What it teaches:** POP3 commands and `+OK` multi-line responses; MIME encoded-word subjects; quoted-printable soft line breaks that defeat plain text search.

**Background:** see 3.5 and 3.7. The second email's body is `Content-Transfer-Encoding: quoted-printable`. The token inside it has been split by "soft line breaks" (`=` at the end of a line), so the text `flag{...}` never appears contiguously in the capture. Even `frame contains "flag"` fails.

**Method (Wireshark):**
1. Filter `pop`. Follow TCP Stream.
2. See the credentials (`USER`/`PASS`), then `STAT`, `LIST`, and two `RETR` responses.
3. In message 2 find the `Subject: =?UTF-8?B?...?=`. Decode the base64 part for the subject.
4. Look at the body: you see lines ending in `=`. Also `=3D` for an `=` sign. Join the broken lines and decode, or decode properly:
   `python3 -c "import quopri,sys;print(quopri.decodestring(sys.stdin.buffer.read()).decode())" < body.txt`

**Pitfalls:** searching for the flag as one string; leaving the `=` characters in when joining; mixing up message 1 (the decoy lunch email) and message 2.

**Real-CTF variations:** QP with non-ASCII characters (`=C3=A9`); a message with an attachment in QP; long base64 subjects; a flag split across multiple QP lines **and** hex-escaped.

**Where it was hidden (spoiler):** in the body of message 2, split across lines by soft breaks.

**Self-check:**
- What does `=3D` mean? (a literal `=`)
- What does a trailing `=` at the end of a QP line mean? (soft break: join with the next line)
- Which POP3 command downloads a message? (`RETR n`)

---

## Lab 07: IMAP layered encoding (medium)

**Scenario:** Carol logs in over IMAP, lists folders, opens `INBOX` (3 messages), fetches headers, reads message 3's body, flags it deleted and logs out.

**What it teaches:** IMAP tags and untagged responses, literals, and peeling **two layers** of encoding.

**Background:** see 3.6. Message 3 ("Config backup") contains a long base64-looking string. Decoding it does not give a flag directly. It gives a string of hex digits. Decoding the hex gives the flag. This is a **layered encoding**.

**Method (Wireshark):**
1. Filter `imap`, Follow TCP Stream.
2. Walk the commands: `a001 LOGIN`, `a002 LIST`, `a003 SELECT INBOX`, `a004 FETCH 1:3 (...)` (headers), `a005 FETCH 3 (BODY[TEXT])`, `a006 STORE`, `a007 LOGOUT`.
3. In the response to `a005` find `{n}` (the literal length) and the text that follows. Copy the encoded token.
4. `echo '<token>' | base64 -d` → hex digits. Then `... | xxd -r -p` → the flag.
   One liner: `echo '<token>' | base64 -d | xxd -r -p`

**Pitfalls:** decoding only once and stopping; including the trailing `)` from the IMAP syntax in the token; reading the wrong message number.

**Real-CTF variations:** three or four layers (base64 → hex → ROT13 → base64); XOR with a key given elsewhere in the capture; a message read with `UID FETCH` or `BODY.PEEK` (read without setting the Seen flag); credentials in `AUTHENTICATE PLAIN` instead of `LOGIN`.

**Where it was hidden (spoiler):** body of message 3, base64 of hex of the flag.

**Self-check:**
- What does `{128}` mean in an IMAP response? (the next 128 bytes are a literal)
- How do you tell a command's matching reply? (the tag, e.g. `a005 OK`)
- How do you recognise hex after decoding? (only 0-9 and a-f, even length)

---

## Lab 08: Mixed protocols, split flag (hard)

**Scenario:** A busy network capture. There is DNS, ARP and ICMP noise; a failed FTP brute-force from another host; a failed Telnet login; several HTTP sessions; plus the **real** activity: an HTTP API call, an FTP upload, and an email. The flag is divided into three parts, each marked "part N/3".

**What it teaches:** **triage**: using Conversations and Protocol Hierarchy to find signal in noise, searching across protocols, decoding a base64 header, reading an FTP upload (data flows client→server), and assembling pieces in order.

**Background:** the three parts live in three different protocols and three different TCP streams, on purpose. Decoys include things that look suspicious (an FTP brute force, a failed login) but contain no part of the flag. The capture is time-interleaved, so packets from different conversations are mixed together in the packet list.

**Method (Wireshark):**
1. Statistics → Protocol Hierarchy: confirm which protocols exist. Statistics → Conversations: list streams.
2. Search for the markers: filter `frame contains "part"` (or `tcp contains "part"`). You get hits in 3 different streams.
3. Follow each stream:
   - the HTTP hit: the marker is in a **request header** and its value is base64; decode it.
   - the FTP hit: it is on a **data connection**; direction is client → server because it was an upload (`STOR`).
   - the SMTP hit: in the email body after `DATA`.
4. Concatenate the parts in order 1, 2, 3.
5. Sanity check: the decoys do not contain "part" markers. If you have more than three, re-read.

**Method (CLI):**
```bash
tshark -r 08_mixed_split_flag_hard.pcap -q -z io,phs
tshark -r 08_mixed_split_flag_hard.pcap -q -z conv,tcp
tshark -r 08_mixed_split_flag_hard.pcap -Y 'frame contains "part"' -T fields -e frame.number -e tcp.stream -e _ws.col.Protocol
tshark -r 08_mixed_split_flag_hard.pcap -q -z follow,tcp,ascii,<stream>
```

**Pitfalls:** reading the packet list top to bottom (waste of time); following the brute-force stream and assuming it matters; forgetting to decode the base64 header; getting the order wrong.

**Real-CTF variations:** the parts are not labelled and you must infer order from timestamps; one part is in DNS (a TXT record or a long subdomain), another in ICMP payload bytes, another in an HTTP cookie; parts are XOR'd; a decoy flag that looks real but is wrong (check context and format).

**Where it was hidden (spoiler):** part 1 in an HTTP request header (base64), part 2 in the FTP upload data, part 3 in the email body.

**Self-check:**
- What are the first two Wireshark views you open on an unknown capture? (Protocol Hierarchy, Conversations)
- How can you tell an upload from a download in FTP? (`STOR`; data goes client→server)
- Why is time order important when assembling parts? (the flag's pieces concatenate in order)

---

## Lab 09: FTP zip, password in another stream (hard)

**Scenario:** Dave emails Erin that an encrypted backup is on the FTP server and gives the password in the email. Later, Erin logs into the FTP server and downloads `backup.zip`.

**What it teaches:** correlating **two different conversations**, extracting a **binary** file from an FTP data stream, and opening an encrypted zip.

**Background:** the zip is password-protected. The password is in a separate SMTP conversation recorded earlier in the capture. The zip bytes travel on an FTP passive data connection and begin with the signature `PK` (`50 4B 03 04`).

**Method (Wireshark):**
1. Follow the SMTP stream; read the email and find the password.
2. Follow the FTP control stream: note `LIST` (first data port) then `RETR backup.zip` (second data port).
3. Extract the zip: **File → Export Objects → FTP-DATA** (or Follow the data stream → **Raw** → **Save as** `backup.zip`).
4. Verify the file: `file backup.zip` should say "Zip archive data".
5. Open it: `unzip -P '<password>' backup.zip`; read `flag.txt`.

**Method (CLI):**
```bash
tshark -r 09_ftp_zip_cross_stream_hard.pcap -q -z conv,tcp
tshark -r 09_ftp_zip_cross_stream_hard.pcap --export-objects ftp-data,./out     # simplest; check the result with: file out/*
# or: follow the data stream with -z follow,tcp,raw,<data-stream>, delete the header and footer lines of the output,
# then convert the hex text to bytes with: xxd -r -p > backup.zip
unzip -P 'password' backup.zip
```

**Pitfalls:** saving as ASCII (corrupts binary); including the TCP-follow header text in the file; trying to crack the zip with a wordlist when the password is already in the capture; including quotes or trailing newline in the password.

**Real-CTF variations:** the password is hidden in an HTTP cookie or DNS query; the zip is transferred over HTTP as `application/octet-stream`; multiple zips; password-protected PDF or 7z; if the password is not in the capture, crack with `fcrackzip` / `zip2john` + `john` / `hashcat`.

**Where it was hidden (spoiler):** the zip's `flag.txt`; the password was in the SMTP email body.

**Self-check:**
- What are the first two bytes of a zip file? (`PK`)
- Which Wireshark view format must you use to save binary? (Raw)
- Where should you look for a missing password? (earlier or later conversations in the same capture)

---

## Lab 10: HTTP upload with out-of-order packets (advanced)

**Scenario:** A user uploads a photo via a multipart form. The network was flaky: some segments arrive out of order and one is retransmitted.

**What it teaches:** TCP reassembly by sequence number, multipart/form-data, **carving** a file from a raw stream, and finding a flag in **file metadata** rather than the picture.

**Background:** a multipart body looks like:
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="description"

holiday photo
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="vacation.png"
Content-Type: image/png

<raw PNG bytes>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```
The PNG's bytes are in the middle of the request body. A **PNG file** is a signature (`89 50 4E 47 0D 0A 1A 0A`) followed by **chunks**: `IHDR` (header), `IDAT` (pixel data), text chunks (`tEXt`, `iTXt`, `zTXt`) holding metadata such as `Comment` or `Software`, and the closing `IEND`. A `tEXt` chunk is stored **uncompressed**, so its text is visible in the bytes. The picture itself is irrelevant here.

In the capture, two of the middle segments are swapped in arrival order, and the first segment is sent again later (retransmission). If you concatenate packets in arrival order or include the duplicate, the PNG will be corrupted.

**Method (Wireshark):**
1. Filter `http`. Find `POST /upload` to `photos.acme.local`. Notice the TCP analysis colouring (black/red) flagging out-of-order and retransmitted segments (`tcp.analysis.flags`).
2. Right-click → Follow → TCP Stream. Wireshark reassembles by sequence number automatically, so the stream is correct. Choose **client → server** direction and **Raw**.
3. **Save as** `upload.bin`. (Export Objects → HTTP may also offer the uploaded file directly.)
4. Carve the PNG out of the request: it starts at the bytes `89 50 4E 47` and ends after `IEND` plus the 4-byte CRC.
   ```bash
   python3 - <<'EOF'
   d = open("upload.bin","rb").read()
   i = d.index(b"\x89PNG")
   j = d.index(b"IEND") + 8
   open("vacation.png","wb").write(d[i:j])
   EOF
   ```
5. Inspect it: `file vacation.png`, `exiftool vacation.png` (look at Comment), or `strings -a vacation.png | grep -i -B1 -A1 comment`. `pngcheck -t vacation.png` also lists text chunks.
6. Shortcut for speed: `strings -a upload.bin | grep -i flag` (works because tEXt is uncompressed).

**Method (manual reassembly in Python, to understand the mechanism):**
```python
from scapy.all import rdpcap, TCP, IP
segs = {}
for p in rdpcap("10_http_upload_oof_advanced.pcap"):
    if TCP in p and p[IP].dst == "192.168.1.80" and bytes(p[TCP].payload):
        segs.setdefault(p[TCP].seq, bytes(p[TCP].payload))   # setdefault drops retransmitted duplicates
stream = b"".join(segs[k] for k in sorted(segs))              # sort by sequence number, not arrival order
```

**Pitfalls:** concatenating in arrival order; keeping the duplicated segment; saving the ASCII view; cutting the file at the wrong boundary (the multipart closing boundary is *not* part of the PNG); forgetting that metadata, not the image, holds the flag.

**Real-CTF variations:** the flag is in EXIF GPS or comment fields of a JPEG; the file is a zip appended after the image end (`binwalk` finds it); LSB steganography in the pixels (`zsteg`); the upload is split across multiple POST requests (chunked upload); the body is gzip-compressed; packets are deliberately removed (missing segments) so you must infer the gap.

**Where it was hidden (spoiler):** in the PNG `tEXt` chunk named `Comment`.

**Self-check:**
- Why does Follow Stream still work with out-of-order packets? (it orders by sequence number)
- How do you recognise the end of a PNG? (`IEND` chunk, followed by a 4-byte CRC)
- Where do you look when the image looks normal? (metadata, trailing data, steganography)

---

# Part 6: The 60-second triage routine and CTF patterns

## 6.1 Triage routine (do this on every capture)

1. **Open Statistics → Protocol Hierarchy** (or `tshark -q -z io,phs`). Which protocols? Is there anything encrypted (TLS, SSH) or unusual?
2. **Statistics → Conversations (TCP + UDP)**. Sort by bytes, then by packets. Note the biggest and the weirdest.
3. **Quick searches:** `frame contains "flag"` and `frame contains "pass"` and `frame contains "CTF"` (and the competition's flag prefix). Also try `http.authorization`, `ftp.request.command == "PASS"`.
4. **Follow the obvious streams:** every FTP control, Telnet, SMTP/POP/IMAP, and each HTTP POST.
5. **Export Objects:** HTTP, IMF, FTP-DATA, SMB. Run `file` on everything.
6. **Check oddities:** `tcp.analysis.flags`, long DNS names, ICMP with large payloads, unusual ports, many RSTs/SYNs (scan).
7. **Decode** anything that looks encoded; keep decoding until readable.
8. **Look at metadata** of every extracted file (`exiftool`, `strings`, `binwalk`).

## 6.2 Typical question styles

| Question | What to do |
|---|---|
| "What password did the user use?" | find login traffic (FTP `PASS`, Telnet keystrokes, HTTP POST/Basic auth, SMTP AUTH, POP/IMAP LOGIN) |
| "What file was downloaded/uploaded?" | `RETR`/`STOR`, HTTP GET/POST, Export Objects |
| "What is the attacker's IP?" | find the host doing scanning/brute force/exploits; many SYNs or `530`s |
| "Which port was open on the target?" | SYN-ACK responses (open) vs RST (closed) in a scan |
| "What tool/User-Agent was used?" | `http.user_agent` |
| "What was the secret in the email?" | SMTP/POP/IMAP Follow Stream and decode |
| "What is the DNS domain exfiltrated to?" | `dns` filter, sort by query length, look at labels |
| "When did X happen?" | `frame.time`; set a time reference |
| "How many packets/streams ...?" | Statistics / `-z conv` counts |

## 6.3 Recognising scans and attacks

- **SYN scan:** many `SYN` packets from one source to many ports, replies `SYN,ACK` (open) or `RST,ACK` (closed), the scanner never completes the handshake. (nmap `-sS`.)
- **Brute force:** repeated login attempts, many `530 Login incorrect` (FTP) or `401`/`200 with error` (HTTP), same source IP, rapid timing.
- **SQL injection:** HTTP requests with `'`, `OR 1=1`, `UNION SELECT`, `--` in parameters.
- **Directory enumeration:** rapid `GET` requests for many paths, many `404`s.
- **Data exfiltration:** large uploads (`STOR`, big POST), or unusual DNS/ICMP volumes.

## 6.4 Things to remember under pressure

- **Do not trust the first hit;** step through all streams.
- **Direction matters:** client→server vs server→client.
- **Raw for binary, ASCII for text.**
- **Decode, then decode again.**
- **A decoy is normal:** a convincing password or "flag" that is wrong. Check it against the question and the context.
- **Write down what you tried,** especially in a team event; your teammate should not repeat it.
- **Time-box:** give an easy challenge 10 minutes before moving on; dynamic scoring rewards speed.

---

# Part 7: Study plan

## Week structure (until the finals on Dec 1)

| Day | Focus | Output |
|---|---|---|
| Today | Read Parts 1, 2 and 3 once (about 45 min). Do Labs 01-03 timed. | times + 3-line notes each |
| Next | Labs 04-07 timed. Read the matching protocol entries again after each. | times + notes |
| Next | Labs 08-10 timed. | times + notes |
| Next | Re-do your two slowest labs with no notes. Practise tshark-only on 01, 03, 05. | times under target |
| Then | picoCTF / CyberDefenders PCAP challenges; try to meet the target times. | writeups (short) |

## Target times
- Easy: under 3 minutes. Medium: under 6 minutes. Hard: under 12 minutes. Advanced: under 15 minutes.

## What to write in your own cheat sheet (one page)
- The 15 display filters you actually use.
- The tshark commands for follow, export, conversations.
- The decode one-liners (base64, hex, URL, QP).
- The signatures (`PK`, `89 50 4E 47`, `FF D8 FF`, `1f 8b`).
- The protocol quick facts (ports, `PASV` arithmetic, SMTP `334` base64, IMAP tags).

## Extra practice (after the 10 labs)
- Wireshark sample captures (wiki.wireshark.org/SampleCaptures): browse FTP, SMTP, Telnet, POP, IMAP, DNS files and just practise Follow Stream and Export Objects.
- picoCTF forensics (network category), CyberDefenders PCAP labs.
- Build your own: in your VM, run an FTP/HTTP/Telnet server, capture it with Wireshark, and analyse your own recording.

---

# Part 8: Glossary

| Term | Meaning |
|---|---|
| **ACK** | TCP acknowledgement flag/number |
| **ARP** | Address Resolution Protocol: IP-to-MAC mapping |
| **ASCII** | American Standard Code for Information Interchange: character encoding |
| **Base64** | encoding of bytes as 64 printable characters |
| **Boundary** | string separating MIME parts / multipart form fields |
| **Carving** | cutting a file out of a larger byte stream using its start/end signatures |
| **CRLF** | carriage return + line feed (`\r\n`), the text-protocol line ending |
| **DNS** | Domain Name System |
| **Encapsulation** | wrapping data in successive protocol headers |
| **EXIF** | Exchangeable Image File Format: image metadata |
| **FIN** | TCP flag: close the connection gracefully |
| **FTP** | File Transfer Protocol |
| **Frame** | link-layer (Ethernet) unit; what Wireshark counts as a "packet" in its list |
| **HTTP** | HyperText Transfer Protocol |
| **IAC** | Interpret As Command: Telnet command escape byte (0xFF) |
| **ICMP** | Internet Control Message Protocol |
| **IMAP** | Internet Message Access Protocol |
| **IMF** | Internet Message Format: how Wireshark labels emails |
| **IP** | Internet Protocol |
| **ISN** | Initial Sequence Number: TCP's random starting sequence |
| **Literal** | IMAP `{n}` followed by n raw bytes |
| **MAC** | Media Access Control (hardware address) |
| **MIME** | Multipurpose Internet Mail Extensions |
| **MSS** | Maximum Segment Size (TCP payload limit, 1460 on Ethernet) |
| **MTU** | Maximum Transmission Unit (link packet limit, 1500 on Ethernet) |
| **NVT** | Network Virtual Terminal: Telnet's terminal model |
| **OSI** | Open Systems Interconnection (7-layer model) |
| **PASV** | FTP passive mode command |
| **PCAP** | Packet CAPture file |
| **PNG** | Portable Network Graphics |
| **POP3** | Post Office Protocol version 3 |
| **PSH** | TCP push flag |
| **QP** | Quoted-Printable encoding |
| **RST** | TCP reset flag |
| **SMB** | Server Message Block |
| **SMTP** | Simple Mail Transfer Protocol |
| **STARTTLS** | command that upgrades a plaintext connection to TLS |
| **SYN** | TCP synchronise flag (start a connection) |
| **TCP** | Transmission Control Protocol |
| **Telnet** | Teletype Network |
| **TLS** | Transport Layer Security |
| **tshark** | Wireshark's command-line tool |
| **UDP** | User Datagram Protocol |
| **URL encoding** | percent-encoding (`%7B` = `{`) |

---

*End of guide. Pair it with `README.md` (the lab task list) and `SOLUTIONS.md` (answers).*
