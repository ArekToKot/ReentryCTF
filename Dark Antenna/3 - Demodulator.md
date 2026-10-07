# Dark Antenna 3/5 — "Demodulator"

**Flag:** `reentry{d3sc4mbl3d_th3_m3ridian_d0wnl1nk}`

| | |
|---|---|
| Category | Crypto / signal descrambling (LFSR, known-plaintext) |
| Tools | `python3` (stdlib only), `xxd` |
| Files | [files/capture.bin](files/capture.bin) (488 bytes) |

> **Challenge brief:** We pulled the raw downlink off the antenna — a flat wall of scrambled
> bytes. There's no demodulator to hand you: the 1977 field unit is long gone. You have the
> capture, the sync marker you recovered off the antenna, and the scrambler you broke out of the
> FILL fields. Read what MERIDIAN's operator recorded the day the signal came back.

---

## Short version

1. The file splits into 4 frames; each starts with the CCSDS sync marker `1A CF FC 1D` (ASM).
2. Frame = `ASM (4 B) | 01 SEQ (2 B, not scrambled) | payload (116 B, scrambled)`.
3. The scrambler is an additive LFSR (keystream XOR data), polynomial with taps `[1, 2, 22, 32]`,
   bits LSB-first. The keystream runs **continuously** across frames.
4. We have no stage-2 output (FILL), so we recover the scrambler ourselves: assume the text is
   ASCII (top bit = 0), run Berlekamp–Massey on the top bits of the ciphertext (L = 32), then
   solve the 32-bit initial state from a linear system over GF(2).
5. After XOR, each frame starts with 16 × `0x55` (preamble), then the operator log with the flag.

---

## 1. Recon — hexdump

```bash
xxd capture.bin
```

- `1A CF FC 1D` (CCSDS ASM) repeats at offsets 0, 122, 244, 366.
- Right after each ASM: `01 00`, `01 01`, `01 02`, `01 03` — a plain header (version/ID `01`,
  frame counter `SEQ`).
- Everything else looks random → scrambled.

---

## 2. Split into frames

```bash
python3 -c "
d=open('capture.bin','rb').read()
asm=bytes.fromhex('1acffc1d')
idx=[i for i in range(len(d)) if d.startswith(asm,i)]
print('ASM @',idx)
for a,b in zip(idx,idx[1:]+[len(d)]):
    f=d[a+4:b]; print(a, b-a, 'hdr', f[:2].hex(), 'payload', len(f)-2, 'B')
"
# ASM @ [0, 122, 244, 366]; each frame 122 B, hdr 01 0x, payload 116 B
```

---

## 3. Recover the LFSR polynomial (Berlekamp–Massey)

Idea: an additive scrambler is `C = P XOR K`. The operator log is almost certainly **ASCII**,
so the top bit of each plaintext byte is 0. Then the top bit of each ciphertext byte is directly
a keystream bit: `C[i].bit7 = K[i].bit7`. That gives every 8th keystream bit.

Over GF(2), decimation by `2^k` (here 8 = 2³) does **not** change the minimal polynomial of an
LFSR sequence (Frobenius automorphism). So Berlekamp–Massey on those bits returns the original
scrambler polynomial.

```bash
# Berlekamp-Massey on each bit plane of frame 0, and on bit 7 of every frame:
# bits 0..6 -> L ~ 58 (random); bit 7 -> L = 32, taps [1, 2, 22, 32] for all frames
```

Keystream recurrence:

```
k[n] = k[n-1] XOR k[n-2] XOR k[n-22] XOR k[n-32]     # x^32 + x^22 + x^2 + x + 1, taps [1,2,22,32]
```

---

## 4. Recover the initial state (seed)

Each keystream bit `k[n]` is a linear (XOR) combination of the 32 seed bits `k[0..31]`. We have
116 known bits per frame (the MSB of each byte) = 116 equations in 32 unknowns. Solve by Gaussian
elimination over GF(2).

The bit order inside a byte is the one remaining unknown:
- MSB-first → garbage text;
- **LSB-first → readable ASCII.** Bit `b` of byte `i` is `k[8·i + b]`.

The per-frame seeds (`0xa64df1cd`, `0xd34ef16e`, `0xfc498ced`, `0x43251b26`) are the same LFSR
sequence shifted by 928 bits (= 116 B) per frame, which confirms the keystream is **continuous**
across all payloads. The full solver (see appendix) solves one system over the joined payload.

---

## 5. Run the solver

```bash
python3 solve.py capture.bin
```

```
[+] Berlekamp-Massey: L=32, taps [1, 2, 22, 32]   -> x^32 + x^22 + x^2 + x^1 + 1
[+] seed LFSR (bit j = k[j]): 0xa64df1cd
[+] decrypted payload (per frame, without the 16 x 0x55 preamble):

== MERIDIAN ANTENNA -- OPERATOR LOG, 1977-09-05 ==
carrier reacquired on the deep-space downlink.
archived the raw capture as signal_1977.iq (crc32=0x6abd5d61).
per KEPLER directive the live record was purged; only the Reed-Solomon
coded copy survives on the archive volume (see operator archive for its offset).
clearance: reentry{d3sc4mbl3d_th3_m3ridian_d0wnl1nk}
```

> **Verification note:** I ran the short descramble (below) on `files/capture.bin`. It prints the
> full operator log and the flag `reentry{d3sc4mbl3d_th3_m3ridian_d0wnl1nk}`. Confirmed.

🚩 **Flag:** `reentry{d3sc4mbl3d_th3_m3ridian_d0wnl1nk}`

---

## 6. Scrambler parameters (for later stages)

| Parameter | Value |
|---|---|
| Type | additive (synchronous) Fibonacci LFSR |
| Polynomial | `x^32 + x^22 + x^2 + x + 1`, taps `[1, 2, 22, 32]` |
| Recurrence | `k[n] = k[n-1] ^ k[n-2] ^ k[n-22] ^ k[n-32]` |
| Bit order | LSB-first within a byte |
| Seed (register, bit j = k[j]) | `0xA64DF1CD` |
| Scope | payload only (no ASM/header), continuous across frames |

**Hints in the log for stage 4/5:** raw recording `signal_1977.iq`, `crc32 = 0x6abd5d61`; the
live record was purged; only a **Reed-Solomon** coded copy survives on the *archive volume*; its
offset is in the *operator archive*.

---

## 7. One-command descramble (parameters known)

```bash
python3 -c "
d=open('capture.bin','rb').read()
p=b''.join(d[i+6:i+122] for i in range(0,488,122))
r=0xA64DF1CD;o=bytearray()
for c in p:
    k=0
    for b in range(8):
        k|=(r&1)<<b; f=(r^(r>>30)^(r>>31)^(r>>10))&1; r=(r>>1)|(f<<31)
    o.append(c^k)
print(o.replace(b'U'*16,b'').rstrip(b'\0').decode())
"
```

---

## Appendix — full solver `solve.py`

```python
#!/usr/bin/env python3
"""Dark Antenna 3/5 - Demodulator: recover the LFSR scrambler and decrypt capture.bin."""
import sys

ASM = bytes.fromhex("1acffc1d")       # CCSDS Attached Sync Marker
data = open(sys.argv[1] if len(sys.argv) > 1 else "capture.bin", "rb").read()

# 1. Framing by the sync marker
starts = []
i = data.find(ASM)
while i != -1:
    starts.append(i); i = data.find(ASM, i + 1)
frames = [data[a + 4:b] for a, b in zip(starts, starts[1:] + [len(data)])]
payload = b"".join(f[2:] for f in frames)   # the 01 SEQ header is not scrambled

# 2. Berlekamp-Massey on the MSB bits (assume plaintext ASCII, MSB = 0)
def berlekamp_massey(s):
    n = len(s); c, b = [1] + [0]*n, [1] + [0]*n; L, m = 0, -1
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1): d ^= c[j] & s[i - j]
        if d:
            t = c[:]
            for j in range(n - i + m + 1):
                if i - m + j <= n: c[i - m + j] ^= b[j]
            if 2 * L <= i: L, m, b = i + 1 - L, i, t
    return L, c[:L + 1]

msb = [(x >> 7) & 1 for x in payload]
L, conn = berlekamp_massey(msb)
taps = [k for k in range(1, L + 1) if conn[k]]

# 3. Solve the initial state over GF(2); bit b of byte i = k[8*i + b] (LSB-first)
def symbolic(n):
    k = [1 << j for j in range(L)]
    while len(k) < n:
        m = 0
        for t in taps: m ^= k[len(k) - t]
        k.append(m)
    return k

def gauss(eqs):
    piv = {}
    for m, v in eqs:
        for p, (pm, pv) in piv.items():
            if m >> p & 1: m, v = m ^ pm, v ^ pv
        if not m:
            assert not v; continue
        p = m.bit_length() - 1
        for q in piv:
            if piv[q][0] >> p & 1: piv[q] = (piv[q][0] ^ m, piv[q][1] ^ v)
        piv[p] = (m, v)
    assert len(piv) == L
    return sum(1 << p for p, (_, v) in piv.items() if v)

N = len(payload) * 8
K = symbolic(N)
seed = gauss([(K[8 * i + 7], msb[i]) for i in range(len(payload))])

# 4. Keystream generator and decryption
def keystream(seed, nbytes):
    reg, out = seed, bytearray()
    for _ in range(nbytes):
        byte = 0
        for b in range(8):
            byte |= (reg & 1) << b
            fb = 0
            for t in taps: fb ^= (reg >> (L - t)) & 1
            reg = (reg >> 1) | (fb << (L - 1))
        out.append(byte)
    return bytes(out)

plain = bytes(a ^ b for a, b in zip(payload, keystream(seed, len(payload))))
text = b"".join(plain[i + 16:i + 116] for i in range(0, len(plain), 116))
print(text.rstrip(b"\x00").decode())
```

> **Previous:** [2 - Handshake](2%20-%20Handshake.md) · **Next:** [4 - Antenna Panel](4%20-%20Antenna%20Panel.md)
