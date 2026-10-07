# Reentry Bay 4/5 — Sequencer Firmware (INTERLOCK derivation)

**Flag:** `reentry{r3v3rs3d_th3_1nt3rl0ck_d3r1v4t10n}`

| | |
|---|---|
| Category | OT/ICS · firmware reverse engineering |
| Target | sequencer console `tcp.reentry.lol:30375` (offline now); firmware `sequencer.elf` served by the HMI |
| Tools | `objdump`, `python3` |
| Files | none (the ELF is fetched from the HMI, not a CTFd attachment) |

> **Challenge brief:** The HMI serves the sequencer's firmware image, and it is the same image the
> bay is running right now. The hold interlock is not a number stored inside it. It is a number the
> controller works out for itself, from its own nameplate, every time it starts — so the value is
> different on every controller, and grepping the image for it will get you nothing. Work out what
> it computes.

---

## How it works

1. **Reverse the firmware** (`objdump -d sequencer.elf`) → a function `derive_interlock`, a modified
   FNV-1a hash:
   - start `0x811c9dc5` (FNV-1a offset basis);
   - for each byte: `h ^= byte; h = (h * 0x1000193) & 0xffffffff` (FNV-1a prime), then `rol h, 7`;
   - final `h ^= 0xa5a5a5a5`.
2. The **"nameplate"** is the controller's unique id in the sequencer console welcome banner:
   `controller SEQ-6CA3F02E` (different on every instance).
3. Compute `derive_interlock("SEQ-6CA3F02E") = 0xf3dcc02e`.
4. Send `INTERLOCK f3dcc02e` to the sequencer → accepted.

## Solver

```python
import socket, re

def derive_interlock(s: str) -> int:
    h = 0x811c9dc5
    for b in s.encode():
        h ^= b
        h = (h * 0x1000193) & 0xffffffff
        h = ((h << 7) | (h >> 25)) & 0xffffffff   # rol 7
    h ^= 0xa5a5a5a5
    return h & 0xffffffff

sock = socket.create_connection(("tcp.reentry.lol", 30375))
welcome = sock.recv(4096).decode()
serial = re.search(r'controller\s+(\S+)', welcome).group(1)
code = derive_interlock(serial)
sock.sendall(f"INTERLOCK {code:08x}\n".encode())
print(sock.recv(4096).decode())
```

> **Verification note:** I ran `derive_interlock("SEQ-6CA3F02E")` and it returns `0xf3dcc02e`,
> exactly as the writeup states (and the word-swapped form `0xc02e, 0xf3dc` is what stage 5 writes
> to the Modbus ILOCK registers HR30:HR31). The service is offline now, so the live `INTERLOCK` send
> cannot be reproduced.

🚩 **Flag:** `reentry{r3v3rs3d_th3_1nt3rl0ck_d3r1v4t10n}`

---

## Lesson

"Security through obscurity" by deriving a secret dynamically from per-instance data (the serial
number) achieves nothing when the derivation algorithm is baked into a publicly available binary.
Reverse-engineering the firmware + reading the plain id from the banner = full bypass.

> **Previous:** [3 - Maintenance Endpoint](3%20-%20Maintenance%20Endpoint.md) · **Next:** [5 - Persistent Hold](5%20-%20Persistent%20Hold.md)
