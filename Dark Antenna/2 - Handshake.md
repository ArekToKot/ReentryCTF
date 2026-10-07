# Dark Antenna 2/5 — "Handshake"

**Flag:** `reentry{r0lling_b4ck_t0_th3_1977_cl0ck}`
**Antenna power-on time:** `1977-09-05 00:00:00 UTC` (register state `0x0E70AE00` = Unix time `242265600`, the Voyager 1 launch day)

| | |
|---|---|
| Category | Crypto / stream cipher (LFSR recovery) |
| Tools | Linux, `python3` (stdlib only), `xxd`, `date` |
| Files | [files/intercept.bin](files/intercept.bin), [files/flag.enc](files/flag.enc), [files/downlink-frame-spec.txt](files/downlink-frame-spec.txt) |

> **Challenge brief:** Every frame MERIDIAN's antenna transmits is scrambled with a 32-bit
> rolling register seeded once, at power-on, from the station master clock. Each frame body
> opens with a fixed FILL field (a 0x55 energy-dispersal pattern) before the payload. We
> intercepted a handful of whole frames and the 1977 frame-format sheet — but not the generator
> polynomial.

**Goal:** recover the polynomial and register state, roll it back to power-on (that is the
"master clock"), then decrypt the flag.

---

## 1. Files and spec

```bash
file *            # intercept.bin and flag.enc are binary 'data'
wc -c intercept.bin flag.enc    # 488 B and 39 B
cat downlink-frame-spec.txt
```

Key points from the spec:

```
frame = ASM(4) | FCNT(2) | scrambled( FILL(16) | payload(100) )
FCNT  = frame counter, 2 B big-endian, frame 0 = boot
FILL  = 55555555555555555555555555555555 (constant)
SCRAMBLER: 32-bit Fibonacci LFSR, loaded ONCE at start-up with the station clock,
           runs continuously; the scrambled area of frame c starts at keystream byte c*116.
```

Conclusions:
- frame length = 4 + 2 + 16 + 100 = **122 B**, and 488 / 122 = **4 frames**;
- the scrambled body is 16 + 100 = **116 B**, hence the `c*116` offset;
- `ciphertext_FILL XOR 0x55` = **16 known keystream bytes (128 bits) per frame**;
- a 32-bit LFSR can be reconstructed from only 2·32 = 64 consecutive bits (Berlekamp–Massey),
  so one frame is more than enough.

An **LFSR** (linear-feedback shift register) is a register whose next bit is a fixed XOR of some
of its current bits. Its output is a linear recurrence, which is exactly why it is breakable.

---

## 2. Parse the frames

```bash
python3 - <<'EOF'
d = open('intercept.bin', 'rb').read()
for i in range(0, len(d), 122):
    f = d[i:i+122]
    print(f"off={i:3d} ASM={f[:4].hex()} FCNT={int.from_bytes(f[4:6],'big')} FILL(scr)={f[6:22].hex()}")
EOF
```

```
off=  0 ASM=1acffc1d FCNT=256 FILL(scr)=98a418f3b3f574bc61ade6747b09eb36
off=122 ASM=1acffc1d FCNT=257 FILL(scr)=3ba41b86a535f0c1004d15d52556f5fc
off=244 ASM=1acffc1d FCNT=258 FILL(scr)=b8d91ca961679f28064e52b664cbf141
off=366 ASM=1acffc1d FCNT=259 FILL(scr)=734e70162ec81f5111d74dd2f494f0c1
```

So we have frames **256–259**. We do not have frame 0 (boot), so we will have to roll the
register back by 256·116 bytes.

---

## 3. Recover the polynomial (Berlekamp–Massey)

The known keystream per frame is `FILL_scrambled XOR 0x55`. We do not know the bit order inside
a byte, so try both (MSB-first and LSB-first). The correct order gives linear complexity
**L = 32**, the same for every frame.

```python
# with the helper functions load_frames / fill_keystream / to_bits / berlekamp_massey
for lsb in (False, True):
    for c, body in load_frames():
        L, C = berlekamp_massey(to_bits(fill_keystream(body), lsb))
        print(lsb, c, L, [j for j in range(L+1) if C[j]])
```

Result: **LSB-first** gives `L=32` and taps `x^[0, 1, 2, 22, 32]` for all four frames.
The connection polynomial is:

```
C(x) = 1 + x + x^2 + x^22 + x^32
```

Keystream recurrence:

```
s[n] = s[n-1] ⊕ s[n-2] ⊕ s[n-22] ⊕ s[n-32]
```

The same result from four independent frames confirms it is the real polynomial, not chance.

---

## 4. Roll the register back to power-on (frame 0)

The recurrence can be reversed, because `s[n-32]` appears linearly:

```
s[n-32] = s[n] ⊕ s[n-1] ⊕ s[n-2] ⊕ s[n-22]
```

Frame 256 starts at bit `256·116·8 = 237568`. Roll back that many steps to get the first 32
bits of keystream — the state loaded at power-on:

```python
from lfsr import *
c, body = load_frames()[0]                      # frame 256
w = to_bits(fill_keystream(body))[:32]          # window s[k..k+31], k = 256*116*8
for _ in range(c * BODY * 8):                   # roll back to k = 0
    w = [w[31] ^ w[30] ^ w[29] ^ w[9]] + w[:31]
state = sum(b << i for i, b in enumerate(w))    # LSB-first
print(hex(state), state)                        # 0xe70ae00 242265600
```

---

## 5. Verify and decrypt the flag

Generate the keystream from the recovered state and check every frame decrypts to
`55555555…` (it does, `OK=True` for all four). The flag is XORed with the keystream from the
very start (offset 0 = boot):

```python
from lfsr import *
state = 242265600
enc = open('flag.enc', 'rb').read()
s = [(state >> i) & 1 for i in range(32)]
while len(s) < len(enc) * 8:
    n = len(s); s.append(s[n-1] ^ s[n-2] ^ s[n-22] ^ s[n-32])
print(bytes(a ^ b for a, b in zip(enc, from_bits(s))).decode())
# reentry{r0lling_b4ck_t0_th3_1977_cl0ck}
```

> **Verification note:** I ran the full rollback + decrypt on `files/intercept.bin` and
> `files/flag.enc`. Output: `L=32`, taps `[1,2,22,32]`, state `0xe70ae00` = `242265600`, boot
> `1977-09-05 00:00:00+00:00`, flag `reentry{r0lling_b4ck_t0_th3_1977_cl0ck}`. All match.

---

## 6. When did the antenna power on?

The register state = the station clock at power-on, read as a Unix timestamp:

```bash
date -u -d @242265600
# Mon Sep  5 00:00:00 UTC 1977        (Voyager 1 launch day)
```

**This timestamp (242265600) is the key fact for stages 4 and 5.**

---

## 7. Why it works

1. **Known plaintext → keystream.** The scrambler is a stream cipher: `C = P ⊕ K`. We know `P`
   (FILL = `0x55`…), so `K = C ⊕ P`.
2. **The LFSR is linear.** A sequence from an n-bit LFSR obeys a linear recurrence of degree n.
   Berlekamp–Massey finds the shortest such recurrence from `2n` bits. With n=32 you need 64
   bits; we have 128 per frame. A "secret" polynomial protects nothing.
3. **The LFSR is reversible.** The top bit appears linearly, so the register can be rolled back
   as far as you like — to the initial state, which is the clock at start-up.
4. **Bit-order trap.** With the wrong order (MSB-first) Berlekamp–Massey gives L ≈ 64 (random
   behaviour). The right order gives L = 32, identical for every frame.

🚩 **Flag:** `reentry{r0lling_b4ck_t0_th3_1977_cl0ck}`

---

## Appendix — helper library `lfsr.py`

```python
FRAME, BODY, FILL = 122, 116, b'\x55' * 16

def load_frames(path='intercept.bin'):
    d = open(path, 'rb').read()
    return [(int.from_bytes(d[i+4:i+6], 'big'), d[i+6:i+FRAME])
            for i in range(0, len(d), FRAME)]

def fill_keystream(body):
    """16 known keystream bytes = scrambled FILL XOR 0x55."""
    return bytes(a ^ b for a, b in zip(body[:16], FILL))

def to_bits(data, lsb_first=True):
    if lsb_first:
        return [(b >> i) & 1 for b in data for i in range(8)]
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]

def from_bits(bits):   # LSB-first
    return bytes(sum(bits[i + j] << j for j in range(8))
                 for i in range(0, len(bits) - 7, 8))

def berlekamp_massey(s):
    """Return (L, C): linear complexity and connection polynomial C(x) over GF(2)."""
    n = len(s)
    C, B = [1] + [0] * n, [1] + [0] * n
    L, m = 0, 1
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            d ^= C[j] & s[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            for j in range(m, n + 1):
                C[j] ^= B[j - m]
            L, B, m = i + 1 - L, T, 1
        else:
            for j in range(m, n + 1):
                C[j] ^= B[j - m]
            m += 1
    return L, C[:L + 1]
```

> **Previous:** [1 - Radio Silence](1%20-%20Radio%20Silence.md) · **Next:** [3 - Demodulator](3%20-%20Demodulator.md)
