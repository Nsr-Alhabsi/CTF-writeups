# ANSWERS for the Protocol Literacy Labs

Open only after you have tried. All flags and protocol answers below were verified from the capture files by an independent script
(and, for L6/L7, by decrypting the TLS traffic myself). tshark field names are from standard usage; if one is rejected on your version,
look it up with `tshark -G fields | grep -i <word>`.

---
## L1: ARP
**Flag:** `flag{4rp_h3x_1n_m4c_4ddr3ss3s_wh00t}`

**Protocol answers**
1. **84 requests and 76 replies** (counts include the gratuitous ones). `tshark -r L1_arp.pcap -Y 'arp.opcode==1' | wc -l` and `arp.opcode==2`.
2. Gratuitous ARP from **192.168.1.31, 192.168.1.12, 192.168.1.5** (sender IP equals target IP). Filter: `arp.isgratuitous`.
3. 192.168.1.250 sent **10** who-has requests (`.201`-`.210`): **6 answered** (`.201`-`.206`), **4 unanswered** (`.207`-`.210`).
4. `192.168.1.40` has MAC `02:00:c0:a8:01:28` if it replies in the capture. It may not appear at all; absence means nobody asked for it or it never answered. Always check the capture, not assumptions.
5. Requests are broadcast (`ff:ff:ff:ff:ff:ff`) because the asker does not know the owner's MAC. The reply is unicast straight back to the asker.

**Flag hunt**
```bash
tshark -r L1_arp.pcap -n -Y 'arp.opcode==2 && arp.dst.proto_ipv4==192.168.1.250' -T fields -e arp.src.hw_mac \
  | tr -d ':\n' | xxd -r -p ; echo
```
The six replies' MAC bytes are ASCII: `66:6c:61:67:7b:34` = `flag{4`, and so on. Keep capture order. Ignore all other ARP traffic.

---
## L2: DHCP
**Flag:** `flag{dhcp_h0stn4m3_b4s3_32_ok}`

**Protocol answers**
1. **Discover (1) → Offer (2) → Request (3) → ACK (5)**, called DORA. Others: Decline (4), NAK (6), Release (7), Inform (8).
2. **UDP 68 (client) to 67 (server).** The client has no IP yet, so the source is `0.0.0.0`, and it must broadcast (`255.255.255.255`) to find any server.
3. **11** clients got an ACK.
4. `oman-pc-07` got **192.168.1.102**. The printers (`printer-3f`, `printer-2f`) got a lease of **604800 s** (7 days). Other clients: 86400 s (1 day).
5. Server **192.168.1.1**, router 192.168.1.1, DNS 192.168.1.1, domain **acme.local**.
6. NAK: MAC `00:1a:aa:bb:cc:dd`, hostname `laptop-guest-01`, it requested **10.9.8.7**, which is on the wrong network; the server answered with "wrong network".
7. **printer-3f (192.168.1.103)** sent a DHCP Release (unicast to the server).

**Flag hunt**
```bash
tshark -r L2_dhcp.pcap -n -Y 'dhcp' -T fields -e dhcp.option.hostname | sort -u        # use bootp.option.hostname on older versions
# the odd one: MZWGCZ33MRUGG4C7NAYHG5DOGRWTGX3CGRZTGXZTGJPW6235
echo 'MZWGCZ33MRUGG4C7NAYHG5DOGRWTGX3CGRZTGXZTGJPW6235' | base32 -d
```
That string is already a multiple of 8 characters long; shorter base32 strings need `=` padding first. Useful fields: `dhcp.option.dhcp` (message type; `bootp.option.dhcp` on older versions), `dhcp.ip.your`, `dhcp.hw.mac_addr`, `dhcp.option.ip_address_lease_time`.

---
## L3: DNS
**Flag:** `flag{dns_txt_r3c0rds_v1g3n3r3}`

**Protocol answers**
1. MX: **10 mail1.acme.local** and **20 mail2.acme.local**. The **lowest preference number (10)** is tried first.
2. `www.acme.local` **CNAME** `web-lb.acme.local` **CNAME** `web01.acme.local` **A 192.168.1.80**.
3. `2001:db8:a0::10` (an AAAA record).
4. **web01.acme.local**, a **PTR** record, for the query `80.1.168.192.in-addr.arpa`.
5. **4 NXDOMAIN** (rcode 3): `intranet.acme.locl`, `mial.acme.local`, `vpn2.acme.local`, `backup.acme.local` (the last one was asked again later and succeeded, which is a useful detail).
6. NS: `ns1.acme.local`, `ns2.acme.local`. SPF: `v=spf1 mx ip4:192.168.1.0/24 -all` (mail may be sent by the MX hosts and the 192.168.1.0/24 range; everything else is rejected).

**Flag hunt**
```bash
tshark -r L3_dns.pcap -n -Y 'dns.qry.type==16 && dns.flags.response==1' -T fields -e dns.qry.name -e dns.txt
# _note.acme.local   k=orange
# _msg.acme.local    c=tcat{jrg_kxg_x3g0fus_i1m3r3f3}
```
Decrypt with the Vigenere cipher, key `orange`. Only letters are shifted, and the key position advances only on letters. CyberChef (Vigenere Decode) or Python:
```python
def vd(t, k):
    o, j = [], 0
    for ch in t:
        if ch.isalpha():
            b = ord('A') if ch.isupper() else ord('a')
            o.append(chr((ord(ch)-b-(ord(k[j%len(k)])-97))%26+b)); j += 1
        else: o.append(ch)
    return ''.join(o)
print(vd("tcat{jrg_kxg_x3g0fus_i1m3r3f3}", "orange"))
```
Useful filters: `dns.qry.type == 15` (MX), `== 5` (CNAME), `== 28` (AAAA), `== 12` (PTR), `dns.flags.rcode == 3` (NXDOMAIN).

---
## L4: ICMP
**Flag:** `flag{1cmp_png_lsb_st3g0_ch41n}`

**Protocol answers**
1. **8 hops** (7 intermediate routers plus the destination).
2. Hop 4 is **100.64.0.1**. **Hop 5** never answered: its probes (TTL 5) have no matching "time exceeded" reply (a `* * *` line in traceroute).
3. TTL expired: **type 11, code 0** (sent by the router that dropped it). Port unreachable: **type 3, code 3**, sent by **192.168.1.50** in answer to the UDP probe to port 33434 (the classic traceroute port).
4. The final echo replies from 8.8.8.8 took roughly **22-28 ms** each (three probes). Use `frame.time_delta` or compare request and reply times.

**Flag hunt**
```bash
# who sends odd payloads? compare payload sizes per destination
tshark -r L4_icmp.pcap -n -Y 'icmp.type==8' -T fields -e ip.src -e ip.dst -e data.len | sort | uniq -c | sort -rn
# reassemble the file: requests only, sorted by seq, duplicates removed
tshark -r L4_icmp.pcap -n -Y 'icmp.type==8 && ip.dst==203.0.113.9' -T fields -e icmp.seq -e data.data \
  | sort -n -u -k1,1 | cut -f2 | tr -d ':\n' | xxd -r -p > img.png
file img.png          # PNG image data, 140 x 140
zsteg -a img.png      # look for b1,rgb,msb,xy
```
If `data.data` is not the right field, run `tshark -r L4_icmp.pcap -V -Y icmp.type==8 -c 1` and read the field names. 81 requests (seq 1-81); seq 7, 21 and 33 were sent twice. Image: 38,704 bytes.
Fallback extractor (MSB-first LSB bits over R,G,B in raster order, null-terminated):
```python
from PIL import Image
im = Image.open("img.png").convert("RGB"); px = im.load(); bits = []
for y in range(im.size[1]):
    for x in range(im.size[0]): bits += [c & 1 for c in px[x, y]]
data = bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits)-7, 8))
print(data.split(b"\x00")[0])
```

---
## L5: TLS handshake and certificate
**Flag:** `flag{x509_subj3ct_ou_b4s3_32}`

**Protocol answers**
1. SNI: **portal.acme.local**. Field: `tls.handshake.extensions_server_name`.
2. **TLS 1.2**, cipher **TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256** (0xc02f): ECDHE = ephemeral elliptic-curve Diffie-Hellman key exchange; RSA = the certificate key signs it; AES_128_GCM = bulk encryption (128-bit AES in Galois/Counter Mode); SHA256 = the hash for the PRF.
3. Yes, readable (TLS 1.2 sends the certificate in clear). CN **portal.acme.local**; SANs **portal.acme.local, vpn.acme.local, files.acme.local**; self-signed (issuer = subject); RSA 2048; serial `0x72476b7b354094110e42c987e7047d05bd75f1c`; valid about 397 days (not before 2026-11-19, not after 2027-12-21).
4. **No.** ECDHE gives forward secrecy: the session keys are never sent and cannot be derived from the certificate's private key. You would need a key log file.

**Flag hunt**
```bash
tshark -r L5_tls_handshake.pcap -n -Y 'tls.handshake.type==11' -T fields -e tls.handshake.certificate \
  | cut -d, -f1 | tr -d ':' | xxd -r -p | openssl x509 -inform DER -noout -subject -nameopt multiline
```
The `organizationalUnitName` is `MZWGCZ33PA2TAOK7ON2WE2RTMN2F633VL5RDI4ZTL4ZTE7I`. It is base32 without padding; add `=` until the length is a multiple of 8 (this one is 47 characters, so add one `=`), then `base32 -d`. Without the padding, `base32 -d` fails with "invalid input".
(You can also use `-V | grep -iE 'organizationalUnit|commonName'` or Wireshark's certificate detail tree.)
Handshake type numbers worth knowing: 1 ClientHello, 2 ServerHello, 11 Certificate, 12 ServerKeyExchange, 14 ServerHelloDone, 16 ClientKeyExchange, 20 Finished.

---
## L6: TLS 1.3 decryption with a key log
**Flag:** `flag{tls_k3ylog_d3crypt3d_z1p}`

**Protocol answers**
1. **2 sessions**: SNI `api.acme.local` and `files.acme.local`.
2. **TLS 1.3**, cipher **TLS_AES_256_GCM_SHA384**. The certificate is **not** visible: in TLS 1.3 everything after ServerHello (including the certificate) is encrypted.
3. `CLIENT_HANDSHAKE_TRAFFIC_SECRET` / `SERVER_HANDSHAKE_TRAFFIC_SECRET` protect the handshake; `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` protect application data; `EXPORTER_SECRET` is for exporters. Each line is `LABEL <client_random hex> <secret hex>`; the client random links the line to a session.
4. `GET /health` (api.acme.local) and `GET /downloads/site_map.png` (files.acme.local).

**Flag hunt**
```bash
tshark -r L6_tls_keylog.pcap -o tls.keylog_file:L6_keys.log -Y http -T fields -e http.request.uri -e http.response.code
mkdir out
tshark -r L6_tls_keylog.pcap -o tls.keylog_file:L6_keys.log --export-objects http,out
file out/*                       # PNG image data ... (it is larger than a 320x200 PNG should be)
binwalk -e out/site_map.png      # or: unzip out/site_map.png
```
The "PNG" has a ZIP appended after its `IEND` chunk. `unzip` (it may warn about extra bytes) or `binwalk -e` gives `flag.txt`. On older versions the preference is `ssl.keylog_file`.

---
## L7: TLS 1.2 decryption with an RSA private key
**Flag:** `flag{rsa_sm4ll_e_cub3_r00t}`

**Protocol answers**
1. **TLS 1.2**, cipher **TLS_RSA_WITH_AES_128_GCM_SHA256** (`AES128-GCM-SHA256`). With RSA key exchange the client encrypts the pre-master secret *to the server's RSA public key*, so whoever holds the private key can recover it and every session key. ECDHE sessions never send the secret, so the private key is useless for them (and RSA key exchange has no forward secrecy).
2. After decryption: `GET /crypto/challenge.json` returned JSON with fields `note`, `n`, `e`, `c`.

**Flag hunt**
```bash
tshark -r L7_tls_rsa_key.pcap -o 'tls.keys_list:192.168.1.90,443,http,L7_server.key' -Y 'http.response' -T fields -e http.file_data | xxd -r -p
```
(`ssl.keys_list` on older versions; in the Wireshark GUI use Preferences > Protocols > TLS > RSA keys list.) The JSON gives a 2048-bit `n`, `e = 3` and `c`. The message is small, so `m^3 < n` and no modular reduction ever happened: `c = m^3`. Take the **integer cube root** of `c`:
```python
def icbrt(x):
    lo, hi = 0, 1 << (x.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 3 < x: lo = mid + 1
        else: hi = mid
    return lo
m = icbrt(C)             # paste the c value
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
```
Do not use floating-point `c ** (1/3)`; it loses precision on numbers this large.

---
## Protocol cheat sheet
| Protocol | Key facts |
|---|---|
| ARP | op 1 = request (broadcast), 2 = reply (unicast); gratuitous = sender IP equals target IP |
| DHCP | UDP 67/68; DORA = Discover(1), Offer(2), Request(3), ACK(5); NAK(6), Release(7); hostnames in option 12 |
| DNS | UDP/TCP 53; A, AAAA, MX (lowest preference first), CNAME, NS, PTR, TXT; rcode 3 = NXDOMAIN |
| ICMP | type 8/0 echo; 3 unreachable (code 3 = port); 11 time exceeded; payload can carry data |
| TLS | handshake types 1/2/11/12/14/16/20; TLS 1.3 hides the certificate; ECDHE needs a key log, RSA kex works with the private key |
