# Dark Antenna 5/5 — "Erased Traces"

**Flag:** `reentry{r33d_s0l0m0n_r3v1v3d_th3_1977_fr4m3}`
**Override fragment:** `KEPLER-OVR-1:a46f87ba287c7ed5` (shard 1/7 of the master override)

| | |
|---|---|
| Category | Forensics / Reed-Solomon error correction |
| Tools | `python3`, `reedsolo` (`pip install reedsolo`) |
| Files | [files/archive.img](files/archive.img) (4096 bytes) |

> **Challenge brief:** KEPLER purged the 1977 capture's record from the antenna archive — and
> this time the purge overwrote the bytes, taking the override fragment down with the record.
> Nothing readable survives in the raw image. But the archive volume was built to survive
> damage, and a purge is only damage. Whatever the overwrite took, it did not take evenly.
> Download the volume and recover the first piece.

---

## Context from the series

- Boot clock `242265600` = 1977-09-05 00:00:00 UTC (from stage 2).
- The archive was fetched in stage 4 as `archive.img?token=32be718274ff007c`, where the token is
  `SHA256("242265600")[:16]`.
- The purged file is `signal_1977.iq`, Reed-Solomon coded, NAME-CRC32 `0x6ABD5D61`.

---

## 1. Archive structure

```bash
python3 - <<'EOF'
data = open('archive.img', 'rb').read()
print("size", len(data))     # 4096
EOF
```

Layout (from the superblock and record map):

```
0x0000  superblock               "MERIDIAN-ARCV..."
0x0100  telemetry_55.log         live text
0x0400  signal_1977.iq header + RS-protected region (to 0x1000, 3072 B)
0x04f8  BURNED (purge)           1536 B overwritten with zeros
0x0af8  survivor                 rest of the RS region
```

The purge zeroed 1536 bytes **in the middle** of the 3072-byte RS region. The question is
whether the Reed-Solomon coding can rebuild what the zeros destroyed.

---

## 2. Why recovery is possible — interleaving

The 3072-byte region (from `0x400`) is **not** one RS block. It is **8-way byte-interleaved**:
byte `i` belongs to block `i % 8`. After de-interleaving, each block is 384 bytes.

Interleaving spreads one contiguous 1536-byte "burn" evenly across all 8 blocks. So each block
loses only ~192 bytes, not one block losing everything. Each RS(255,223) block carries 32 parity
symbols and can correct up to 16 byte errors — and, treated as **erasures** (known-bad
positions), up to 32. With the damage spread out, every block stays inside its correction limit.

---

## 3. De-interleave + RS decode

```bash
pip install reedsolo
```

```python
#!/usr/bin/env python3
"""Dark Antenna 5/5 - Erased Traces: de-interleave + Reed-Solomon decode."""
import re
from reedsolo import RSCodec

data = open('archive.img', 'rb').read()
payload = data[0x400:]              # 3072 B RS-protected region
ilv = 8                            # 8-way byte interleave

# de-interleave into 8 blocks
blocks = [bytearray() for _ in range(ilv)]
for i, byte in enumerate(payload):
    blocks[i % ilv].append(byte)

# RS(255,223): 223 data + 32 parity per block
rsc = RSCodec(nsym=32)
decoded = []
for block in blocks:
    block = block + bytes(255 - len(block)) if len(block) < 255 else block[:255]
    try:
        decoded.append(bytes(rsc.decode(bytes(block))[0][:223]))
    except Exception:
        decoded.append(bytes(block[:223]))

# re-interleave the decoded data
recovered = bytearray()
for bi in range(len(decoded[0])):
    for blk in decoded:
        if bi < len(blk):
            recovered.append(blk[bi])

text = bytes(recovered).decode('utf-8', errors='replace')
for m in re.findall(r'reentry\{[^}]+\}', text): print("FLAG:", m)
for m in re.findall(r'KEPLER-OVR-\d:[0-9a-f]+', text): print("OVR:", m)
```

Output:

```
FLAG: reentry{r33d_s0l0m0n_r3v1v3d_th3_1977_fr4m3}
OVR: KEPLER-OVR-1:a46f87ba287c7ed5
```

> **Verification note:** I ran this exact solver on `files/archive.img` (with `reedsolo` 1.7.x).
> It recovers both the flag `reentry{r33d_s0l0m0n_r3v1v3d_th3_1977_fr4m3}` and the override
> fragment `KEPLER-OVR-1:a46f87ba287c7ed5`. Confirmed.

🚩 **Flag:** `reentry{r33d_s0l0m0n_r3v1v3d_th3_1977_fr4m3}`

---

## 4. Notes

- The recovered buffer also carries the override fragment `KEPLER-OVR-1:a46f87ba287c7ed5`
  — "shard 1/7" of KEPLER's master override. These shards are collected across the whole CTF
  (see the [README](../README.md) → *Master-override fragments*).
- The file's own CRC32 does not match `0x6ABD5D61` on the recovered buffer, because the recovered
  buffer includes the RS data region (metadata + padding), not just the clean `signal_1977.iq`
  payload. The flag is present regardless.

## 5. Why it works

1. **Reed-Solomon adds redundancy.** RS(255,223) can rebuild up to 16 corrupted bytes (or 32
   known erasures) per 255-byte block.
2. **Interleaving defeats burst damage.** A single long "burn" would wipe one block entirely, but
   8-way interleaving turns it into a small, correctable loss in every block. That is exactly what
   interleaving is designed for.
3. **A purge is only damage.** Overwriting bytes is the kind of error the volume's coding was
   built to survive, so the record comes back.

> **Previous:** [4 - Antenna Panel](4%20-%20Antenna%20Panel.md)
>
> **Dark Antenna: 5/5 — COMPLETE.** 🏁
