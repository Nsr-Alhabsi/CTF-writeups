# Traffic-Pattern Analysis (L9) and USB HID Keystrokes (L10)

Two more labs to close out Essential networking. Same rules: tshark first, time yourself, no AI.

---
## L9: Traffic-pattern analysis (L9_traffic_patterns.pcap)
One capture, three different anomalies mixed together. In a real CTF or SOC exercise you are rarely told
which is which — you detect the *shape* of the traffic, not just read a protocol.

**Tasks**
1. **Port scan.** One host sends SYN packets to many ports on one target with no replies. Find the scanning host, the target, how many ports, and the port range.
2. **Beaconing.** One host makes small, regular TCP connections to one external host, over and over. Find the source, destination, destination port, how many beacons, and the average interval between them (in seconds).
3. **DNS tunneling.** A host is leaking data in DNS queries to a domain that is not `acme.local`. Find the domain, how many queries carry data, and recover the flag.

**Hints**
1. Group by `(ip.src, ip.dst)` and count distinct destination ports among SYN-only packets with no SYN-ACK reply. `tshark -r L9_traffic_patterns.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head`
2. Use `-z conv,tcp` to see every TCP conversation and its packet/byte counts, then look at the **timestamps** of just the SYNs for the suspicious one: `tshark -r L9_traffic_patterns.pcap -Y 'ip.dst==<dst> && tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_relative`, then compute the differences between consecutive values.
3. Not every query to a weird-looking domain carries data — some are decoys to a normal domain. Filter for the one unfamiliar domain, pull the TXT query names, and notice each one starts with a two-digit index. Sort by that index before decoding.

---
## L10: USB HID keystroke capture (L10_usb_hid_reports.txt)
This is a simplified version of a real forensics task. A full USB capture (USBPcap on Windows, `usbmon` on Linux)
is a pcap with a USB link-layer, and in tshark you would pull the raw interrupt-transfer payload with the
`usb.capdata` field, one 8-byte HID report per keystroke event — tshark does not decode the keys itself.
Rather than build a fragile synthetic USB-layer pcap I could not verify here, this file gives you those
8-byte reports directly, one per line in hex, exactly as `usb.capdata` would give them to you. The decoding
step — which is the actual skill being tested — is identical either way.

**Boot-protocol keyboard report, 8 bytes:**
`[modifier][reserved][key1][key2][key3][key4][key5][key6]`
- Byte 0 (modifier) is a bitmask: `0x02` = left shift, `0x20` = right shift (others: ctrl, alt, gui).
- Byte 2 is the HID usage ID of the first key currently held down. `0x00` means no key (a key-release report).
- A real capture has one report when a key goes down and another all-zero report when it comes up; you only need the key-down reports.

**Task:** decode the full typed session and recover the flag.

**Hint:** build a usage-ID → character table for letters (`0x04`-`0x1d`), digits (`0x1e`-`0x27`), enter/space, and
the punctuation you need (`-=[];',./`). When the shift bit is set, letters become uppercase and the number-row
keys become their shifted symbol (`1`→`!`, `9`→`(`, `0`→`)`, etc.) — this is how the flag's braces and underscore appear.

---
## Answers

**L9**
- Port scan: **192.168.1.77 → 192.168.1.80**, **35 ports**, range **42–9848**.
- Beaconing: **192.168.1.64 → 203.0.113.50:8080**, **12** connections, average interval **≈59.9 s** (roughly once a minute — the small jitter is what separates a real beacon from a coincidence).
- DNS tunneling: domain **evil.example**, flag **`flag{dns_tunn3l_subd0ma1n_3xf1l}`**. The data queries are TXT queries shaped `NN-<base32chunk>.evil.example`; the decoy queries (A records to `*.acme.local`) are mixed in roughly every third query to make you filter, not just dump everything.

```bash
tshark -r L9_traffic_patterns.pcap -Y 'dns.qry.name contains "evil.example"' -T fields -e dns.qry.name \
  | grep -oE '^[0-9]+-[a-z0-9]+' | sort -t- -k1,1n | cut -d- -f2 | tr -d '\n' | tr a-z A-Z | python3 -c "
import sys, base64
s = sys.stdin.read()
print(base64.b32decode(s + '=' * (-len(s) % 8)).decode())"
```

**L10**
- Flag: **`flag{usb_hid_k3ystr0k3s_d3c0d3d}`**
- Full decoded text: `user login as admin` / `password attempt failed` / `retry with FLAG submission` / the flag / `logout`.
- A minimal Python decoder:
```python
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x0b:'h',0x0c:'i',0x0d:'j',
       0x0e:'k',0x0f:'l',0x10:'m',0x11:'n',0x12:'o',0x13:'p',0x14:'q',0x15:'r',0x16:'s',0x17:'t',
       0x18:'u',0x19:'v',0x1a:'w',0x1b:'x',0x1c:'y',0x1d:'z',0x1e:'1',0x1f:'2',0x20:'3',0x21:'4',
       0x22:'5',0x23:'6',0x24:'7',0x25:'8',0x26:'9',0x27:'0',0x28:'\n',0x2c:' ',0x2d:'-',0x2e:'=',
       0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.',0x38:'/'}
SHIFT = {0x1e:'!',0x1f:'@',0x20:'#',0x21:'$',0x22:'%',0x23:'^',0x24:'&',0x25:'*',0x26:'(',0x27:')',
         0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x36:'<',0x37:'>',0x38:'?'}
out = []
for line in open("L10_usb_hid_reports.txt"):
    if line.startswith('#') or not line.strip(): continue
    b = bytes.fromhex(line.strip())
    mod, code = b[0], b[2]
    if code == 0: continue
    sh = bool(mod & 0x22)
    ch = SHIFT.get(code) if sh else None
    ch = ch or HID.get(code)
    out.append(ch.upper() if sh and code in HID else ch)
print(''.join(out))
```

---
## On SMB
I still haven't built an SMB lab. Scapy does have an SMB2 layer, but I can't run tshark or Wireshark here to confirm
a hand-built capture actually dissects the way a real one does, and a broken lab wastes your time more than no lab.
Use the Wireshark SampleCaptures SMB2 files — they're real captures, so they're guaranteed to dissect correctly.
Walk through: Negotiate Protocol → Session Setup (and the NTLMSSP negotiate/challenge/authenticate messages inside it)
→ Tree Connect → Create → Read → Close, and use File → Export Objects → SMB to pull any transferred file straight out.
