# Reentry Bay 2/5 — Thruster Telemetry

**Flag:** `reentry{w0rd_0rd3r_unm4sk3d_th3_thrust3r_fl04ts}`

| | |
|---|---|
| Category | OT/ICS · Modbus/TCP (no auth) + endianness/word-order |
| Target | Modbus gateway `tcp.reentry.lol:30391` (offline now) |
| Files | none |

> **Challenge brief:** The deorbit gateway speaks Modbus and answers for every unit id on the bus —
> most of them with an excuse rather than data. The live nodes are in there somewhere. The telemetry
> node documents its blocks but not the one thing you need in order to read them: nobody ever wrote
> down which half of each value comes first. Read the chamber pressures.

> **Note:** Reentry Bay 5/5 later shows this HR200 text is a decoy relative to the *final* bay flag,
> but it is the accepted flag for this challenge (Thruster Telemetry, marked solved on the platform).

---

## 1. Scan unit IDs

The Modbus gateway answers for every unit id 0–255, but only a few carry live data (read via input
registers, FC4):

```
Unit 1:  "MERIDIAN OT GW :: node=GENERIC :: no process data"
Unit 17: "THRUSTER TELEMETRY :: P1..P6 float32 @HR100 kPa :: text @HR200 :: id @IR80"
Unit 40: "HOLD CTRL :: ILOCK=HR30:HR31 :: MAINT via OPC-UA :: SIS BYPASS KEY=HR120"
```

## 2. Unit 17 — decode the text

Holding Registers @HR200 (unit 17, FC3) hold the flag text, but the bytes are **word-swapped** —
each pair of 16-bit registers is in reversed order:

```
HR200: [0x6e72, 0x7465, 0x7972, 0x7b7d, ...]   # raw big-endian pairs
         "e n"  "t e"  "r y"  "{ }"            # reversed word order
```

Fix: swap adjacent register pairs, keeping the byte order within each register.

```python
import socket, struct

def modbus(unit, func, start, count):
    s = socket.create_connection(("tcp.reentry.lol", 30391), timeout=3)
    s.sendall(struct.pack('>HHHBBHH', 1, 0, 6, unit, func, start, count))
    resp = s.recv(4096); s.close()
    bc = resp[8]
    return [struct.unpack('>H', resp[9+i*2:9+i*2+2])[0] for i in range(bc//2)]

regs = modbus(17, 3, 200, 30)   # FC3 Holding Registers, start=200, count=30
text = ''
for i in range(0, len(regs) - 1, 2):
    for r in (regs[i+1], regs[i]):          # swap adjacent pair
        hi, lo = (r >> 8) & 0xff, r & 0xff
        if hi == 0 and lo == 0:
            continue
        text += chr(hi) + chr(lo)
print(text)   # reentry{w0rd_0rd3r_unm4sk3d_th3_thrust3r_fl04ts}
```

🚩 **Flag:** `reentry{w0rd_0rd3r_unm4sk3d_th3_thrust3r_fl04ts}`

> **Note:** The gateway is offline now, so this cannot be re-run. Units 17 and 40 (the SIS bypass
> key register HR120 and the ILOCK registers HR30:HR31) are the inputs to stages 4 and 5.

---

## Lessons

- **No access control:** Modbus/TCP has no built-in auth — telemetry is readable by anyone on the
  network.
- **Endianness gotcha:** the node documents *where* data lives (HR100, HR200) but not how the bytes
  are ordered (big/little-endian, word-swap). You must test or know the ICS convention.
- **Multi-protocol recon:** scan every protocol (TCP console, OPC-UA, Modbus); each exposes
  different, often linked, data.

> **Previous:** [1 - Deorbit HMI](1%20-%20Deorbit%20HMI.md) · **Next:** [3 - Maintenance Endpoint](3%20-%20Maintenance%20Endpoint.md)
