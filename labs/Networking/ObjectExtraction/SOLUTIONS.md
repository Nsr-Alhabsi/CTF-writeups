# SOLUTIONS - read only after you've tried

Every flag below was recovered programmatically from its pcap alone (stream reassembly by TCP sequence number),
so each one is guaranteed to be findable. These walkthroughs use the same steps you'd take in Wireshark.
Note: I could not run Wireshark/tshark itself in my environment, so the exact menu wording and tshark
field names are from standard usage; if one differs on your version, the idea is the same.

---
## 01 - FTP (easy)
**Flag:** `flag{ftp_d4ta_ch4nn3l_f0und}`

1. Filter `ftp`. You see `USER ftpadmin` / `PASS Sup3rS3cret!` - that password is a decoy, not the flag.
2. The control channel shows `PASV` replies with a port: `(192,168,1,50,195,81)` = 195*256+81 = **50001**, then **50002** for the `RETR notes.txt`.
3. The file contents travel on a separate connection. Filter `tcp.port == 50002`, Follow TCP Stream: `notes.txt` contains the flag.
4. Shortcut: Export Objects > FTP-DATA, or `frame contains "flag"`.

**Lesson:** FTP commands and file data are different streams. Always check the data connection.

---
## 02 - Telnet (easy)
**Flag:** `flag{t3ln3t_k3ystr0k3s_n0_3ch0}`

1. Follow TCP Stream. Login name is echoed by the server, so it shows doubled/interleaved with the client's keystrokes.
2. The password is **not echoed** by the server. In the Follow Stream window, set "Show data as" to the client-to-server direction only.
   The password is typed after the `Password:` prompt, one packet per character.
3. The password is the flag. (`ls` shows `notes.txt` saying the password is still the default, a hint it was typed in the clear.)

**Lesson:** Telnet = every keystroke in plaintext, and the direction filter separates what the user typed from what the server echoed.

---
## 03 - HTTP POST (easy)
**Flag:** `flag{h77p_p05t_b0dy_cr3d5_1n_cl34r}`

1. Filter `http.request.method == "POST"`. There are two. The first (`password=letmein`) got a 200 "Invalid username or password".
2. The second got a `302 Found` + `Set-Cookie: session=...` = successful login. Its body is URL-encoded:
   `password=flag%7Bh77p_p05t_b0dy_cr3d5_1n_cl34r%7D` (`%7B`=`{`, `%7D`=`}`).
3. Wireshark's "HTML Form URL Encoded" tree at the bottom of the packet shows the decoded value.

**Lesson:** read the response to know which attempt succeeded. URL-decode.

---
## 04 - HTTP objects (medium)
**Flag:** `flag{3xp0rt_0bj3cts_h7tp}`

1. File > Export Objects > HTTP. Objects: `/`, `style.css`, `app.js`, `logo.png`, `banner.jpg`, two 404s, and **`/assets/internal/notice.png`**.
2. Save `notice.png` and open it - the flag is rendered *in the image* (it will not appear in any text search).
3. CLI: `tshark -r 04_http_objects_medium.pcap --export-objects http,./out` then open the images.

**Lesson:** some flags are pixels. Look at suspicious file paths ("internal") and ignore 404s.

---
## 05 - SMTP attachment (medium)
**Flag:** `flag{smtp_mime_b4s364_4tt4chm3nt}`
**Bonus:** SMTP login = `alice@acme.local` / `Winter2026!` (the two base64 lines after `AUTH LOGIN`: `echo YWxpY2VAYWNtZS5sb2NhbA== | base64 -d`).

1. Filter `smtp`, Follow TCP Stream. The client side contains the whole email after `DATA`.
2. Find the part with `Content-Type: image/png; name="contract_scan.png"` and `Content-Transfer-Encoding: base64`.
3. Copy the base64 block (up to the next `--boundary`), save it, then `base64 -d block.txt > scan.png` and open it.
4. Shortcut: File > Export Objects > IMF saves the whole email; open it or decode the attachment from it.

**Lesson:** email attachments are base64 inside MIME parts.

---
## 06 - POP3 quoted-printable (medium)
**Flag:** `flag{p0p3_qu0t3d_pr1nt4bl3_s0ft_br34ks}`

1. Follow TCP Stream. Message 2 (`RETR 2`) has a base64-encoded `Subject:` (`Re: access token (details in body)`) and a **quoted-printable** body.
2. In the body the token is split by `=` + line break (soft line breaks), so searching for `flag{...}` as one string finds nothing.
   `=3D` is an encoded `=`.
3. Decode: save the body to a file, then
   `python3 -c "import quopri,sys;print(quopri.decodestring(sys.stdin.buffer.read()).decode())" < body.txt`
   or manually delete every `=` at the end of a line and join.

**Lesson:** `frame contains "flag"` can fail when the data is encoded. Check `Content-Transfer-Encoding`.

---
## 07 - IMAP layers (medium)
**Flag:** `flag{1m4p_l4y3r3d_3nc0d1ng_h3x_b64}`

1. Follow TCP Stream. Tagged commands: `a004` fetches headers of 3 messages; `a005 FETCH 3 (BODY[TEXT])` fetches the body of message 3 ("Config backup").
2. The `{n}` after `BODY[TEXT]` is a *literal* - the next n bytes are the body. It contains a long base64 string:
   `NjY2YzYxNjc3YjMxNmQzNDcwNWY2YzM0NzkzMzcyMzM2NDVmMzM2ZTYzMzA2NDMxNmU2NzVmNjgzMzc4NWY2MjM2MzQ3ZA==`
3. `echo '<blob>' | base64 -d` gives a hex string (`666c6167...`), then `| xxd -r -p` gives the flag. Two layers: base64 over hex.

**Lesson:** when decoded output looks like another encoding, keep peeling.
(Credentials `carol` / `P@ssw0rd2026` are visible in the `LOGIN` line.)

---
## 08 - Mixed, split flag (hard)
**Flag:** `flag{m1x3d_pr0t0c0ls_s33_th3_wh0l3_p1ctur3}`

Statistics > Protocol Hierarchy / Conversations shows: DNS, ARP, ICMP, 3 HTTP sessions, 2 FTP sessions, 1 Telnet, 1 SMTP. Most is noise.

- **Part 1/3 (HTTP):** request to `intranet.acme.local/api/status` has header `X-Debug-Note: part 1/3 -> ZmxhZ3ttMXgzZF9wcjB0MA==`.
  `base64 -d` gives `flag{m1x3d_pr0t0`. Quick find: `http.request.line contains "part"`.
- **Part 2/3 (FTP upload):** 192.168.1.20 logs in as `ftpadmin` and does `STOR report_q3.txt`. The file contents (on the passive data port, 50001)
  say `part 2/3 -> c0ls_s33_th3_`.
- **Part 3/3 (SMTP):** an email from dave to bob has `part 3/3 -> wh0l3_p1ctur3}` in the body.
- Decoys to skip: the FTP brute-force from 192.168.1.77 (all `530 Login incorrect`), the Telnet `guest` login failure, the news-site HTTP session, the banner image.

Fastest way in: `frame contains "part"`, then Follow the three hits.
**Lesson:** triage with Conversations/Hierarchy first, then search; don't read packets top to bottom.

---
## 09 - Cross-stream zip (hard)
**Flag:** `flag{z1p_p4ssw0rd_1n_4n0th3r_str34m}`

1. SMTP stream: email from Dave to Erin says the backup on FTP is encrypted and the password is **`Winter#Backup26`**.
2. FTP: login as `erin`, `RETR backup.zip` over passive port 50002 (after a LIST on 50001). The data stream starts with `PK`.
3. Extract: File > Export Objects > FTP-DATA, or Follow the data stream > "Raw" > Save as `backup.zip`.
4. `unzip -P 'Winter#Backup26' backup.zip` then `cat flag.txt`.

**Lesson:** the key is often in a different conversation than the locked file. Look at everything, and save binary data as Raw (not ASCII).

---
## 10 - Out-of-order upload (advanced)
**Flag:** `flag{pn6_t3xt_chunk_h1dd3n_1n_upl04d}`

1. Filter `http`; the interesting one is `POST /upload` (multipart/form-data) to `photos.acme.local`.
   In the packet list, the capture shows reordered segments and a retransmission (Wireshark flags `TCP Out-Of-Order` / `TCP Retransmission`). The Follow Stream view still reassembles correctly because it goes by sequence number.
2. Follow TCP Stream > show the client-to-server side > Raw > Save as `upload.bin`. (Export Objects > HTTP may also offer the file.)
3. Carve the PNG: it begins at the bytes `89 50 4E 47` and ends after `IEND`. For example:
   `python3 -c "d=open('upload.bin','rb').read();i=d.index(b'\x89PNG');j=d.index(b'IEND')+8;open('vacation.png','wb').write(d[i:j])"`
4. The image itself is just a landscape. The flag is in a PNG `tEXt` chunk: `exiftool vacation.png` (field `Comment`) or `strings -a vacation.png | grep -i -A1 comment`.
   Because tEXt is uncompressed, `strings -a upload.bin | grep flag` also finds it.

**Lesson:** metadata hides data, and sequence numbers (not packet order) define the stream.
