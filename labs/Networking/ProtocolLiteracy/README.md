# Protocol Literacy Labs (L1-L7)

Seven captures covering the protocol-literacy Essentials: **ARP, DHCP, DNS, ICMP, TLS handshake, TLS decryption**.
Crypto and steganography are built into the labs, the way they show up in real Jeopardy boards.
Answers are in `ANSWERS.md` (separate file). Do not open it until you have tried.

**Rules:** tshark only (Wireshark is allowed afterwards, to compare). No AI. Time each lab.
Each lab has: *protocol questions* (answer these first, they are the literacy part) and a *flag hunt* (`flag{...}`).

| Lab | File | Protocol | Also tests | Target |
|---|---|---|---|---|
| L1 | L1_arp.pcap | ARP | hex/ASCII encoding | 6 min |
| L2 | L2_dhcp.pcap | DHCP | base32 | 8 min |
| L3 | L3_dns.pcap | DNS records | Vigenere cipher | 10 min |
| L4 | L4_icmp.pcap | ICMP | file reassembly + LSB steganography | 15 min |
| L5 | L5_tls_handshake.pcap | TLS handshake and certificate | base32, X.509 | 10 min |
| L6 | L6_tls_keylog.pcap + L6_keys.log | TLS 1.3 decryption | polyglot file carving (PNG + ZIP) | 12 min |
| L7 | L7_tls_rsa_key.pcap + L7_server.key | TLS 1.2 decryption with an RSA key | RSA small-e attack | 15 min |

---

## L1: ARP (L1_arp.pcap)
**Protocol questions**
1. How many ARP requests and how many ARP replies are in the capture?
2. Which hosts sent *gratuitous* ARP (an announcement, not a question)?
3. Host `192.168.1.250` asked who-has for 10 addresses. How many were answered and how many were not?
4. Which MAC address belongs to `192.168.1.40` (based on the capture, if it appears)? If it does not appear, how can you tell?
5. Why are ARP requests sent to `ff:ff:ff:ff:ff:ff` but replies are not?

**Flag hunt:** the answered replies to `192.168.1.250` carry something unusual in the MAC addresses.
**Hint:** read the MAC bytes as hex.

## L2: DHCP (L2_dhcp.pcap)
**Protocol questions**
1. List the four message types of a normal lease exchange, in order, and their DHCP type numbers.
2. Which UDP ports are used, and why is the first packet's source `0.0.0.0` and destination `255.255.255.255`?
3. How many clients completed a lease (got an ACK)?
4. What IP address was given to `oman-pc-07`, and what lease time (seconds) did the printers get?
5. What are the DHCP server, router, DNS server and domain name?
6. One client got a NAK. What was its MAC address, which address did it ask for, and why did it fail?
7. Which client released its address?

**Flag hunt:** one client has a very odd hostname.
**Hint:** the odd hostname is not random text. Base32 needs `=` padding to a multiple of 8 characters before decoding.

## L3: DNS (L3_dns.pcap)
**Protocol questions**
1. What are the mail servers for `acme.local`, with their preferences? Which is tried first?
2. Follow the answer for `www.acme.local`. What is the full CNAME chain and the final IP?
3. What is the IPv6 address of `ipv6.acme.local`?
4. Which name does `192.168.1.80` resolve to (reverse lookup), and what record type is that?
5. How many queries returned NXDOMAIN, and which names?
6. What name servers (NS) does `acme.local` have? What does the SPF TXT record say?

**Flag hunt:** two TXT records on names starting with an underscore matter.
**Hint:** one holds a key, the other holds a message. Classic cipher with a keyword. Non-letters stay unchanged.

## L4: ICMP (L4_icmp.pcap)
**Protocol questions**
1. A traceroute-style probe from `192.168.1.100` to `8.8.8.8` was captured. How many hops until the destination answers?
2. What is the IP of hop 4? Which hop never answered, and how can you tell from the packets?
3. Which ICMP type and code means "TTL expired"? Which means "port unreachable", and who sent it?
4. What is the round-trip time of the final reply (the last hop's echo reply)?

**Flag hunt:** one host sends echo requests to `203.0.113.9` that contain a file instead of the usual padding.
**Hints:** only use the *requests*, not the replies. Some sequence numbers were retransmitted, so deduplicate and sort by ICMP sequence. After reassembling the file, check the image for hidden data in the pixel bits (`zsteg`, or write your own extractor).

## L5: TLS handshake and certificate (L5_tls_handshake.pcap)
**Protocol questions**
1. What server name (SNI) did the client ask for?
2. What TLS version and cipher suite were negotiated? Spell out what each part of the cipher suite name means.
3. Is the certificate readable in this capture? What are its CN, SAN list, issuer, validity dates and serial number? Is it self-signed?
4. Can you read the HTTP traffic that follows? Why not?

**Flag hunt:** it is in the certificate's subject.
**Hint:** extract the certificate bytes from the handshake and give them to `openssl x509`. One subject field holds an encoded string.

## L6: TLS 1.3 decryption (L6_tls_keylog.pcap, L6_keys.log)
**Protocol questions**
1. How many TLS sessions are in the capture, and what SNI does each use?
2. Which TLS version and cipher suite were used? Is the server certificate visible in the handshake? Why or why not?
3. What does each line type in the key log file mean (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_TRAFFIC_SECRET_0`, ...)?
4. After decryption, what HTTP requests were made?

**Flag hunt:** decrypt, then find the downloaded file.
**Hint:** a file may contain more than one file. Check the end of it.

## L7: TLS 1.2 decryption with an RSA private key (L7_tls_rsa_key.pcap, L7_server.key)
**Protocol questions**
1. Which TLS version and cipher suite were used? Why can the server's *private key* decrypt this session, when it could not for a modern ECDHE session?
2. After decryption, what was requested and what came back?

**Flag hunt:** the response contains an RSA public key, a public exponent and a ciphertext.
**Hint:** look at the exponent. What happens when a small message is raised to a small power and the result is smaller than the modulus?

---

## What I did not build: SMB
The Network Essentials list includes SMB, but I did not generate an SMB lab. I could not run Wireshark or tshark in my environment to confirm that hand-built SMB2 packets would dissect correctly, and a broken SMB capture would waste your time.
For SMB use the **Wireshark sample captures page** (search for SMB2 file-transfer samples). Learn these: Negotiate Protocol, Session Setup (and NTLMSSP), Tree Connect, Create, Read/Write, `smb2.filename`, and File > Export Objects > SMB.

## How these were checked
I solved every lab from the capture file alone with an independent script. For L6 and L7 I decrypted the TLS traffic myself (TLS 1.3 using the key log, TLS 1.2 using the RSA key) and recovered the flags, so the key files are correct. I could not run Wireshark or tshark itself, so field names in `ANSWERS.md` come from standard usage. If a field name fails on your version, find it with `tshark -G fields | grep -i <word>` or `tshark -V -c 1`.
