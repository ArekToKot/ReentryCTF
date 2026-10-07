# Lazarus Core 2/5 — Memory Dump

**Flag:** `reentry{lzd1_0wn3r_cl4us3_3r0d3d_t0_z3r0}`

| | |
|---|---|
| Category | Reverse / crypto (custom container + single-byte XOR) |
| Tools | `xxd`, `python3` |
| Files | [files/core.bin](files/core.bin) (734 bytes) — also used by stages 3, 4, 5 |

> **Challenge brief:** You pulled LAZARUS's core directive image out of its console — an `LZD1`
> structure, the guardian's one law frozen in binary. Read it. Somewhere in there is the exact
> moment the directive went wrong: the owner clause that wore away to nothing.

---

## Short version

`core.bin` is a custom container (magic `LZD1`) holding a chain of directive clauses, signatures,
a public key, a token, and a final `FLG1` chunk. The `FLG1` chunk is the flag **XOR-encrypted
with a single byte (`0x4b`)**. Brute all 256 keys (or use the known prefix `reentry{`); exactly
one gives the flag.

---

## 1. Identify and dump

```bash
file core.bin        # "MS-DOS executable" (false positive — unknown format)
stat -c%s core.bin   # 734 bytes
xxd core.bin
```

- Starts with the ASCII magic **`LZD1`**.
- The body is a series of 4-letter tags — `EPOK`, `DIR1`, `SIG1`, `DIR2`, `SIG2`, `DIR3`, `SIG3`,
  `DIR4`, `SIG4`, `PUB`, `CDTOK`, `FLG1` — each with a little-endian length and a body.
- The `DIRn` bodies are plain English clauses. `DIR1` reads `owner-clause: owner=none; ...` —
  literally *the owner clause that wore away to nothing*.
- The final `FLG1` chunk is 41 bytes of non-printable data → the encrypted flag.

---

## 2. Parse the container (TLV walk)

The format is classic **Tag–Length–Value**:

```
LZD1 | ver(2) flags(2) size(4) | { TAG | len(2, little-endian) | body[len] } ...
```

```python
data = open('core.bin','rb').read()
pos = 12
TAGS = [b'CDTOK',b'EPOK',b'DIR1',b'DIR2',b'DIR3',b'DIR4',
        b'SIG1',b'SIG2',b'SIG3',b'SIG4',b'FLG1',b'PUB']
while pos < len(data):
    for t in TAGS:
        if data[pos:pos+len(t)] == t:
            ln   = int.from_bytes(data[pos+len(t):pos+len(t)+2], 'little')
            body = data[pos+len(t)+2 : pos+len(t)+2+ln]
            kind = body if t.startswith(b'DIR') else body.hex()
            print(f"{t.decode():6} @ {hex(pos):6} len={ln:3} : {kind}")
            pos += len(t) + 2 + ln; break
    else:
        print("stop @", hex(pos)); break
```

The four directives:

| Chunk | Directive text |
|---|---|
| DIR1 | `owner-clause: owner=none; protect the artifact above every other duty.` |
| DIR2 | `egress-clause: deny egress of the physical medium from the station.` |
| DIR3 | `reentry-clause: on any threat to the artifact, initiate REENTRY.` |
| DIR4 | `attestation: guardian nominal; reentry armed; core sealed tight.` |

Plus the opaque chunks `SIG1-4` (64-byte signatures), `PUB` (public key), `CDTOK`, and **`FLG1`**.

> **Side note (for later stages):** `SIG2` and `SIG4` share an **identical first 32 bytes** (the
> `r` value of an ECDSA signature). Reusing the same nonce across two messages recovers the
> private key — that is stage 4's attack, not needed here.

---

## 3. Decrypt the `FLG1` chunk

The flag format is `reentry{...}`. A single-byte XOR is the simplest guess:

```python
data = open('core.bin','rb').read()
i  = data.find(b'FLG1'); ln = int.from_bytes(data[i+4:i+6],'little')
flg = data[i+6:i+6+ln]
for k in range(256):
    d = bytes(b ^ k for b in flg)
    if d.startswith(b'reentry{') and d.endswith(b'}'):
        print(f"key = 0x{k:02x}  ->  {d.decode()}")
# key = 0x4b  ->  reentry{lzd1_0wn3r_cl4us3_3r0d3d_t0_z3r0}
```

One-liner:

```bash
python3 -c "d=open('core.bin','rb').read();i=d.find(b'FLG1');n=int.from_bytes(d[i+4:i+6],'little');print(bytes(b^0x4b for b in d[i+6:i+6+n]).decode())"
```

> **Verification note:** I ran the XOR-0x4b decode on `files/core.bin`. Output:
> `reentry{lzd1_0wn3r_cl4us3_3r0d3d_t0_z3r0}`. Confirmed.

🚩 **Flag:** `reentry{lzd1_0wn3r_cl4us3_3r0d3d_t0_z3r0}`

The flag tells the story the brief hinted at: in the `LZD1` image, the **owner clause eroded to
zero** (`owner=none` in `DIR1`).

---

## Lessons

- A magic string (`LZD1`) + repeating tag/length/value blocks = a TLV format you can walk in a
  few lines of Python.
- Single-byte XOR is trivially breakable: 256 keys, filter on the known flag format, or use any
  known plaintext.
- Not every chunk is part of the solve — the signatures/pubkey/token are set-up for stages 3–5.

> **Previous:** [1 - Delegate](1%20-%20Delegate.md) · **Next:** [3 - Diag Port](3%20-%20Diag%20Port.md)
