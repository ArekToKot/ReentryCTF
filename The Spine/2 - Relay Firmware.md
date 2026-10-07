# The Spine 2/5 — Relay Firmware

**Main flag (Relay Firmware):** `reentry{r3v3rs3d_th3_r3l4y_fr4m3_crc}`
**Flag picked up on the way (Trunk Access / management console):** `reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}`

| | |
|---|---|
| Category | Reversing / Networking (ICS-style bus) |
| Entry | `ssh eng@tcp.reentry.lol -p 30081` (password `halley`) |
| Internal bus | `10.185.1.0/24` |
| Relay | `10.185.1.2` — mgmt `tcp/9601`, bus `udp/9600` |
| Core idea | Clone the MAC to enter the relay console → download the firmware → rebuild the MRDN frame format and CRC-16 → forge a "genuine" frame |

> **Challenge brief:** The relay's maintenance build came off its management port. It is the
> gateway's own frame decoder: hand it a frame and it will tell you what it made of it.
> Everything the bus says is in there — what the opcodes mean, which terminal is which, and
> the single check the bus uses to decide a frame is genuine. Learn to speak it.

---

## 0. Overview

We get a shell on the HALLEY "service laptop" patched into the instrument trunk of station
MERIDIAN. On the bus sits a **relay gateway** that, on its management port (`tcp/9601`), hands
out its own **frame decoder** (a maintenance build). The "Relay Firmware" task is to rebuild,
from that binary firmware, the bus frame format (`MRDN`), the meaning of the opcodes and
terminals, and **the single check the bus uses to decide a frame is genuine — a CRC-16
checksum**. A correctly forged "genuine" frame unlocks a hidden constant = the flag.

The relay management console is also gated by **MAC address** (admission list) — that is the
second flag.

---

## 1. Get onto the service laptop (Trunk Access)

Port `30081` is SSH (password auth). There is no `sshpass`, so use `pexpect` to send the
password.

```python
# ssh_run.py
import sys, pexpect
cmd = sys.argv[1]
child = pexpect.spawn(
    "ssh -p 30081 -o StrictHostKeyChecking=no -o PreferredAuthentications=password "
    "-o PubkeyAuthentication=no eng@tcp.reentry.lol " + "'" + cmd + "'",
    timeout=40, encoding='utf-8')
child.expect('[Pp]assword:'); child.sendline('halley'); child.expect(pexpect.EOF)
print(child.before)
```

```bash
python3 ssh_run.py 'id; hostname; ip a; cat /etc/motd'
```

Key facts about the environment:
- We are in a Docker container (`/.dockerenv`), as `eng` with **passwordless sudo**.
- Our interface: `eth0 = 10.185.1.4/24`, MAC **`02:4d:52:71:68:0d`** (already changed by the crew).
- MOTD: the instrument segment is `10.185.1.0/24`.

### 1.1. Read the HALLEY crew's `.bash_history` — it is our map

```bash
python3 ssh_run.py 'cat ~/.bash_history'
```

The important lines (the crew did exactly what we must redo):

```
nmap -sn 10.185.1.0/24
nc 10.185.1.2 9601                       # relay does not answer right away...
sudo ip link set eth0 down
sudo ip link set eth0 address 02:4d:52:71:68:0d   # <-- CLONE MAC
sudo ip link set eth0 up
find / -iname "*firmware*" 2>/dev/null
```

So the relay is at `10.185.1.2`, and entering it needs a specific MAC.

---

## 2. Enumerate the bus

```bash
python3 ssh_run.py 'nmap -sn 10.185.1.0/24 | grep report'
python3 ssh_run.py 'for h in 1 2 3 5 6 7 8; do echo "== .$h =="; nmap -p1-65535 -T4 --open 10.185.1.$h | grep /tcp; done'
```

Result:

| Host | Ports | Role |
|---|---|---|
| 10.185.1.1 | — | core router (gateway) |
| **10.185.1.2** | **9601/tcp** | **relay-gw (management)** |
| 10.185.1.4 | (us) | HALLEY laptop |
| 10.185.1.5 | 2601, 2602 | zebra/ripd (routing, out of scope here) |
| 10.185.1.6 / .7 | 22 | terminals (ssh) |

The neighbor ARP table shows the Docker MAC scheme `02:42:0a:b9:01:<ip>`:

```
10.185.1.2 lladdr 02:42:0a:b9:01:02
10.185.1.7 lladdr 02:42:0a:b9:01:07
```

…but **our** MAC is `02:4d:52:71:68:0d` — the hand-cloned "authorized console" address.

---

## 3. Relay management console → Trunk Access flag

The relay sends nothing in reply to "HELLO" — it sends the banner right after `connect()`.
Check it from the laptop (the filter is on the MAC, which we only have on the laptop's `eth0`):

```bash
python3 ssh_run.py "python3 -c \"import socket;s=socket.socket();s.connect(('10.185.1.2',9601));print(s.recv(4096).decode())\""
```

```
RELAY-GW MANAGEMENT :: authorised console

reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}

segment map:
  controller   lazarus-bc (bus udp/9600)
  relay        this node (bus udp/9600, mgmt tcp/9601)
  terminals    RT-1 THERMAL, RT-7 AIRLOCK, RT-9 ATTITUDE
  assembler    10.185.0.0/24 (beyond the core router)

firmware image: GET /firmware (this port, send the literal line)
```

> **Flag #1:** `reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}`

### 3.1. Proof it gates on MAC (admission list)

Change the MAC to the native Docker one and try again, then restore the clone:

```bash
sudo ip link set eth0 down
sudo ip link set eth0 address 02:42:0a:b9:01:04   # native MAC for .4
sudo ip link set eth0 up
# -> console refuses:
#   admission denied: this port is restricted to the authorised console
#   your hardware address: 02:42:0a:b9:01:04
sudo ip link set eth0 down
sudo ip link set eth0 address 02:4d:52:71:68:0d   # restore the clone
sudo ip link set eth0 up
```

Confirmed: **only** the host with MAC `02:4d:52:71:68:0d` gets into the console.

---

## 4. Download the firmware (maintenance build)

The banner hints: send `GET /firmware` as a literal line on the same port. The server returns
**the banner, then the binary image right after it** — you must cut the header off at `\x7fELF`.

```python
# getfw.py (run on the laptop)
import socket
s=socket.socket(); s.settimeout(10); s.connect(('10.185.1.2',9601))
s.sendall(b'GET /firmware\n')
d=b''
while True:
    try: c=s.recv(65536)
    except Exception: break
    if not c: break
    d+=c
open('/tmp/firmware.bin','wb').write(d)
print('LEN',len(d))
```

Copy it locally (for example through base64 over SSH) and strip the banner:

```python
d=open('relay_firmware_raw.bin','rb').read()
i=d.find(b'\x7fELF')                      # the ELF starts at offset 403
open('relay_firmware.elf','wb').write(d[i:])
```

```bash
file relay_firmware.elf
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

---

## 5. Reverse-engineer the frame decoder

### 5.1. Strings — the protocol dictionary

```bash
strings -n 4 relay_firmware.elf
```

```
MRDN                              magic (MERIDIAN)
THERMAL / AIRLOCK / ATTITUDE      terminals (RT-1 / RT-7 / RT-9)
POLL STATUS AUTH AUTH_OK COMMIT   opcodes
bad magic/version / truncated / SEALED
frame accepted :: %s
op=0x%02x %-7s term=%u %-8s seq=%u dlen=%u crc=%04x %s
```

Running the binary is an interactive decoder:

```bash
printf 'QUIT\n' | ./relay_firmware.elf
# == MERIDIAN relay gateway :: frame decoder (maintenance build) ==
# paste one MRDN frame as hex, or QUIT
```

### 5.2. Disassemble `main` — the exact format

```bash
objdump -d -M intel --no-show-raw-insn relay_firmware.elf | sed -n '/<main>:/,/_fini/p'
```

From `main`, the frame buffer lives at `rsp+0x40`:

```
offset  size  field
------  ----  ---------------------------------------------
0       4     MAGIC  = "MRDN"            (memcmp, must match)
4       1     VER    = 0x01              (cmp == 1)
5       1     OP     = opcode            (-> r13)
6       1     TERM   = terminal id       (-> r12)
7       2     SEQ    = big-endian u16     (b7<<8 | b8)
9       1     DLEN   = payload length     (-> r14)
10      DLEN  PAYLOAD
10+DLEN 2     CRC16  = big-endian         (b[10+DLEN]<<8 | b[11+DLEN])
```

Preconditions (otherwise "short frame" / "truncated" / "bad magic/version"):
- `strlen/2` bytes, needs `DLEN+12 <= 0x1f4+12`;
- `MAGIC=="MRDN"`, `VER==1`, and byte count `>= DLEN+12`.

### 5.3. "The single check" — CRC-16/CCITT-FALSE

The CRC loop (`0x401313`–`0x40133c`) is a classic CRC-16, MSB-first:

- **init = 0xFFFF**, **poly = 0x1021**, no reflection, no final XOR;
- computed over the **header + payload** (offset `0 .. 9+DLEN`), i.e. everything except the 2
  CRC bytes;
- compared with the `CRC16` stored in the frame (`cmp word, bx`).

```c
uint16_t crc = 0xFFFF;
for (byte b : header_and_payload) {
    crc ^= b << 8;
    for (int i=0;i<8;i++)
        crc = (crc & 0x8000) ? (crc<<1) ^ 0x1021 : (crc<<1);
}
```

### 5.4. Hidden constant — the "genuine frame" condition

After the CRC matches (`0x4013ed`), the firmware also requires one specific frame:

```
OP   == 0x81
TERM == 0x07          (RT-7 AIRLOCK)
DLEN == 0x06
PAYLOAD == "SEALED"
```

Then it decodes the `OBF` block @`0x402160` (37 bytes) by XOR with `0x79` and prints
`frame accepted :: %s`.

```bash
objdump -s -j .rodata relay_firmware.elf      # OBF block @0x402160
```

```python
obf = bytes.fromhex('0b1c1c170d0b00020b4a0f4a0b0a4a1d260d114a260b4a154d00261f0b4d144a261a0b1a04')
print(bytes(b ^ 0x79 for b in obf).decode())
# reentry{r3v3rs3d_th3_r3l4y_fr4m3_crc}
```

---

## 6. Forge a "genuine" frame and unlock the flag

```python
def crc16_ccitt(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc

magic=b'MRDN'; ver=1; op=0x81; term=7; seq=0; dlen=6; payload=b'SEALED'
body  = magic + bytes([ver, op, term, (seq>>8)&0xff, seq&0xff, dlen]) + payload
crc   = crc16_ccitt(body)
frame = body + bytes([(crc>>8)&0xff, crc&0xff])
print(frame.hex())
# 4d52444e0181070000065345414c4544176f
```

Feed the frame to the decoder:

```bash
printf '4d52444e0181070000065345414c4544176f\nQUIT\n' | ./relay_firmware.elf
```

```
op=0x81 STATUS  term=7 AIRLOCK  seq=0 dlen=6 crc=176f OK
frame accepted :: reentry{r3v3rs3d_th3_r3l4y_fr4m3_crc}
```

> **Flag #2 (Relay Firmware):** `reentry{r3v3rs3d_th3_r3l4y_fr4m3_crc}`

> **Verification note:** I re-ran the OBF XOR-0x79 decode (→ the flag) and the CRC-16 of the
> body. The CRC is `176f`, which matches the frame hex above. Both check out.

---

## 7. Flags

| Stage | Flag |
|---|---|
| Trunk Access (clone MAC → mgmt console) | `reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}` |
| **Relay Firmware (reverse frame + CRC)** | `reentry{r3v3rs3d_th3_r3l4y_fr4m3_crc}` |

---

## 8. TL;DR (command by command)

```bash
# 1) entry
ssh eng@tcp.reentry.lol -p 30081           # password: halley

# 2) map from history + enumeration
cat ~/.bash_history
nmap -sn 10.185.1.0/24
nmap -p1-65535 --open 10.185.1.2           # 9601/tcp

# 3) relay console (MAC already cloned to 02:4d:52:71:68:0d) -> FLAG #1
python3 -c "import socket;s=socket.socket();s.connect(('10.185.1.2',9601));print(s.recv(4096).decode())"

# 4) firmware
python3 -c "import socket;s=socket.socket();s.connect(('10.185.1.2',9601));s.sendall(b'GET /firmware\n');open('/tmp/fw','wb').write(s.recv(1<<20))"
# (copy locally, cut the banner to \x7fELF -> relay_firmware.elf)

# 5) reverse
strings relay_firmware.elf; objdump -d -M intel relay_firmware.elf | sed -n '/<main>:/,/_fini/p'

# 6) genuine frame -> FLAG #2
printf '4d52444e0181070000065345414c4544176f\nQUIT\n' | ./relay_firmware.elf
```

## 9. Why it works (the point)

- **Admission list = source-MAC filter.** The relay compares the frame's hardware address with
  one authorized MAC. Cloning `02:4d:52:71:68:0d` bypasses the control.
- **"The single check for frame authenticity" = CRC-16/CCITT-FALSE** (poly `0x1021`, init
  `0xFFFF`), computed over header+payload. There is no cryptographic signature — anyone who
  knows the polynomial (revealed in the firmware) can forge a "genuine" frame. That is the
  message in the flag: *reversed the relay frame CRC*.

> **Previous:** [1 - Patch In (Trunk Access)](1%20-%20Patch%20In%20%28Trunk%20Access%29.md)
> **Next:** [3 - Interpose](3%20-%20Interpose.md)
