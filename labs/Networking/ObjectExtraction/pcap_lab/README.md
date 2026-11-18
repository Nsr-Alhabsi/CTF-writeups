# PCAP Stream & Object Extraction Lab

10 captures, easy to advanced. Protocols: FTP, Telnet, HTTP, SMTP, POP3, IMAP.
Every flag has the format `flag{...}`. Solutions are in a **separate file** (SOLUTIONS.md) - don't open it until you've tried.

Rules for yourself: do each one **timed**, with **no AI**, using only Wireshark + tshark + standard CLI tools
(`base64`, `xxd`, `strings`, `file`, `unzip`, `python3`). That is what the finals machines will give you.

| # | File | Level | Target time | Goal |
|---|------|-------|-------------|------|
| 1 | 01_ftp_easy.pcap | Easy | 5 min | Find the flag. (Is the password it?) |
| 2 | 02_telnet_easy.pcap | Easy | 5 min | Find the admin's password. It is the flag. |
| 3 | 03_http_post_easy.pcap | Easy | 5 min | Find the correct password jsmith logged in with. It is the flag. |
| 4 | 04_http_objects_medium.pcap | Medium | 8 min | Someone browsed a site. Find the flag. |
| 5 | 05_smtp_attachment_medium.pcap | Medium | 10 min | Someone emailed Bob a document. Find the flag. Also: what were Alice's SMTP login credentials? |
| 6 | 06_pop3_qp_medium.pcap | Medium | 10 min | Bob checked his mail. Find the token. (`grep` alone will not save you.) |
| 7 | 07_imap_layers_medium.pcap | Medium | 10 min | Carol read a backup notification. Find the token. |
| 8 | 08_mixed_split_flag_hard.pcap | Hard | 20 min | The flag is split in 3 parts across 3 different conversations, labeled "part N/3". Reassemble it. Lots of noise and decoys. |
| 9 | 09_ftp_zip_cross_stream_hard.pcap | Hard | 15 min | Someone grabbed an encrypted backup. Get what is inside. |
| 10 | 10_http_upload_oof_advanced.pcap | Advanced | 20 min | A photo was uploaded. The capture is messy (out-of-order and retransmitted packets). Find the flag. |

## One hint per challenge (use only if stuck for 5+ minutes)

1. FTP uses two connections. Which one carries the file contents?
2. Telnet sends one keystroke per packet. In Follow Stream, show only one direction.
3. There are two POSTs. How do you tell which login worked? Remember URL encoding.
4. File > Export Objects > HTTP. Not everything listed is useful; look at the paths.
5. Follow the client side of the stream. MIME parts are separated by a boundary string.
6. Look at the `Content-Transfer-Encoding` header of the email, and at what `=` followed by a line break means.
7. Fetch literals (`{n}`) hold the message body. The token is encoded more than once.
8. Statistics > Conversations, and Statistics > Protocol Hierarchy. Check each protocol's conversations in turn.
9. The password and the file are not in the same stream. Binary file: Follow Stream > Raw > Save as, or Export Objects.
10. Wireshark reassembles correctly even when packets arrive out of order. Once you have the raw upload body, look for the PNG header (`89 50 4E 47`). Metadata can hold more than pixels.

## Quick toolbox

Wireshark display filters:
```
ftp || ftp-data       telnet        http          smtp          pop || imap
http.request.method == "POST"       tcp.port == 50001
frame contains "flag"               tcp.stream eq 3
```
Right-click a packet > Follow > TCP Stream. Use the dropdown to show one direction or "Raw".
File > Export Objects > HTTP / IMF / FTP-DATA.  Statistics > Conversations / Protocol Hierarchy.

tshark (when you have no GUI):
```
tshark -r f.pcap -q -z conv,tcp                        # list conversations
tshark -r f.pcap -q -z follow,tcp,ascii,N              # follow stream N
tshark -r f.pcap -q -z follow,tcp,raw,N                # hex dump of stream N (save/convert with xxd -r -p)
tshark -r f.pcap --export-objects http,./out           # extract HTTP objects (also: ftp-data, imf, smb)
tshark -r f.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
```

Decoding:
```
echo 'BASE64' | base64 -d          echo 'HEX' | xxd -r -p
python3 -c "import quopri,sys;print(quopri.decodestring(sys.stdin.buffer.read()).decode())"
python3 -c "import urllib.parse as u;print(u.unquote('%7Bfoo%7D'))"
file x; strings -a x | grep -i flag; exiftool x; binwalk x; unzip -P PASSWORD x.zip
```

## After you finish

For each challenge write 3 lines: **what protocol trick it used, which tool got you there fastest, what slowed you down.**
Then redo your slowest 2 without notes. That list becomes your finals cheat sheet, and the time per challenge
is your progress metric: aim to get every Easy under 3 minutes and every Medium under 6.
