# IDA 3/4 — CXTEA-F

**Flag:** `reentry{F3ist3l_N3tw0rk_C_Typ3_C4st1ng_M4st3r}`

| | |
|---|---|
| Category | Reverse / Crypto · 388 pts |
| Files | [files/encryptor.c](files/encryptor.c), [files/Makefile](files/Makefile), [files/target_data.dat](files/target_data.dat) (48 bytes, encrypted flag) |

> **Challenge brief:** A personal file store someone on the crew deck wrote for themselves. The
> key was never saved anywhere — it was meant to recompute itself from a polynomial, so there
> would be no password to remember. After a tidy-up of the helpers it stopped opening
> `target_data.dat`. Nothing about the program looks wrong: encrypt then decrypt still returns
> exactly what went in, so its two halves agree with each other — just not with what wrote the file.

Build: `gcc -O2 -s -o encryptor encryptor.c`. Running `./encryptor -d target_data.dat out.bin`
does **not** give the flag. The task is to find the bug the "tidy-up" introduced.

---

## 1. Code analysis

### Key schedule (deterministic, no password)

```c
/* P(x) = 0xA57B x^3 + 0xC31D x^2 + 0x91E3 x + 0x7F2A, then fold 64->32 */
static uint32_t poly_eval(uint32_t x) { ... return fold32(p); }

for (i = 0; i < 4; i++) {
    uint32_t s = poly_eval(seeds[i]);          // seeds = {17, 23, 31, 47}
    s = s * 1664525u + 1013904223u;            // LCG
    g_key[i] = s ^ (GOLDEN * (uint32_t)(i + 1));
}
g_delta = g_key[0] ^ g_key[1] ^ g_key[2] ^ g_key[3] ^ GOLDEN;
```

The polynomial is computed in `uint64_t`, the rest in `uint32_t`. This part is correct.

### Cipher — 32-round TEA-style Feistel on 8-byte little-endian blocks

```c
a += F(b, g_key[sum & 3], sum);
sum += g_delta;
b += F(a, g_key[(sum >> 11) & 3], sum);
```

with the round function:

```c
static uint32_t F(int32_t z, uint32_t k, uint32_t sum)
{
    uint32_t t = (uint32_t)rotl32(z, 4) ^ (uint32_t)rotr32(z, 5);
    t += (uint32_t)z;
    return t ^ (sum + k);
}
```

Decryption reverses the round order correctly.

---

## 2. The bug

The rotations — "copied from notes" — are wrong:

```c
static int32_t rotl32(int32_t x, unsigned n)
{
    uint32_t u = (uint32_t)x << n;
    int32_t  s = x >> (32u - n);      // <-- arithmetic shift!
    return (int32_t)(u | (uint32_t)s);
}
static int32_t rotr32(int32_t x, unsigned n)
{
    int32_t  s = x >> n;              // <-- arithmetic shift!
    uint32_t u = (uint32_t)x << (32u - n);
    return (int32_t)(u | (uint32_t)s);
}
```

The argument is `int32_t`, so `x >> k` is an **arithmetic** shift: on x86, GCC fills the vacated
bits with the sign bit. When the top bit of `x` is set, the shifted value has all-ones in the top
bits, and the `OR` then overwrites part of the result. The function stops being a rotation for
about half of all inputs.

Example for `rotl32(0x80000000, 4)`:

| | result |
|---|---|
| correct rotation | `0x00000008` |
| buggy version | `0xFFFFFFF8` |

### Why the round-trip still works

In a Feistel network, `F` does **not** have to be invertible. Encrypt and decrypt call the same
(buggy) `F` with the same arguments, so `decrypt(encrypt(x)) == x` still holds. But
`target_data.dat` was encrypted with the **original** rotations (true rotations on `uint32_t`),
which give different `F` values.

---

## 3. The fix

Do the rotations on an unsigned type:

```c
static uint32_t rotl32(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
```

---

## 4. Solver (Python port of the decryptor)

```python
import struct
M = 0xffffffff; G = 0x9E3779B9

def poly(x):
    p = (0xA57B*x**3 + 0xC31D*x**2 + 0x91E3*x + 0x7F2A) & ((1 << 64) - 1)
    return (p ^ (p >> 32)) & M

key = []
for i, s in enumerate([17, 23, 31, 47]):
    v = (poly(s) * 1664525 + 1013904223) & M
    key.append(v ^ ((G * (i + 1)) & M))
delta = key[0] ^ key[1] ^ key[2] ^ key[3] ^ G

rol = lambda x, n: ((x << n) | (x >> (32 - n))) & M      # correct rotations
ror = lambda x, n: ((x >> n) | (x << (32 - n))) & M

def F(z, k, s):
    t = (rol(z, 4) ^ ror(z, 5)) & M
    t = (t + z) & M
    return t ^ ((s + k) & M)

def dec(a, b):
    s = (delta * 32) & M
    for _ in range(32):
        b = (b - F(a, key[(s >> 11) & 3], s)) & M
        s = (s - delta) & M
        a = (a - F(b, key[s & 3], s)) & M
    return a, b

d = open('target_data.dat', 'rb').read(); out = b''
for i in range(0, len(d), 8):
    a, b = struct.unpack('<II', d[i:i+8]); out += struct.pack('<II', *dec(a, b))
print(out)
# b'reentry{F3ist3l_N3tw0rk_C_Typ3_C4st1ng_M4st3r}\x02\x02'
```

The trailing `\x02\x02` is PKCS#7 padding.

> **Verification note:** I ran this solver on `files/target_data.dat`. With the **correct**
> (unsigned) rotations it decrypts to `reentry{F3ist3l_N3tw0rk_C_Typ3_C4st1ng_M4st3r}` + PKCS#7
> padding. The buggy rotations give garbage, which confirms the diagnosis.

🚩 **Flag:** `reentry{F3ist3l_N3tw0rk_C_Typ3_C4st1ng_M4st3r}`

---

## 5. Lessons

- A right shift on a signed type (`int32_t`) is arithmetic in practice. Always do bitwise
  operations (rotations etc.) on `uint32_t`.
- In a Feistel network the round function need not be invertible, so a change in `F` does not
  break the round-trip but silently changes the cipher. An "encrypt then decrypt" test will not
  catch it — you need known-answer test vectors.

> **Previous:** [2 - Librarian](2%20-%20Librarian.md) · **Next:** [4 - Manifest Lock](4%20-%20Manifest%20Lock.md)
