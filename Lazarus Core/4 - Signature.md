# Lazarus Core 4/5 — Signature (ECDSA nonce reuse)

**Flag:** `reentry{n0nc3_r3us3_br0k3_th3_gu4rdi4n_k3y}`

| | |
|---|---|
| Category | Crypto (ECDSA secp256k1 nonce reuse + MGF1 unmask) |
| Tools | `python3` (no external libs — the curve is implemented by hand) |
| Files | [files/core.bin](files/core.bin) (LZD1 container), [files/flag.enc](files/flag.enc) (43 bytes) |

> **Challenge brief:** The core dump carries the guardian's directives — each one signed with the
> secp256k1 key KEPLER wired in so nothing could rewrite the core without it. The public key is in
> there too. The guardian was careful with its key. It was not careful with something else. Line
> up its signatures. What it sealed with that key is masked, not encrypted. The guardian only ever
> had one way of hashing anything...

---

## Short version

1. Two signatures in `core.bin` — **SIG2 and SIG4** — have an **identical `r`**. In ECDSA `r`
   depends only on the nonce `k` (`r = (k·G).x`), so **same `r` = same `k`**.
2. A reused nonce is fatal: from two signatures `(r,s₂)`, `(r,s₄)` over known messages you compute
   `k`, then the **private key `d`**.
3. The message the guardian hashes is `z = SHA256(EPOK ‖ directive_body)` — the same "one way of
   hashing", which you verify by checking `d·G == PUB`.
4. `flag.enc` is **masked** (XOR) with an **MGF1-SHA256** keystream seeded on `EPOK ‖ d`
   (the key as 32-byte big-endian), with a 4-byte **little-endian** counter. XOR → the flag.

| Value | |
|---|---|
| reused `r` | `0xfe3bf41a…59647caa` (SIG2 == SIG4) |
| nonce `k` | `0xc0ffee1234deadbeef00ff11ee22dd33cc44bb55aa66997788` |
| **private key `d`** | `0x5eafc0de19774b309c1e2a7d3f61b0c4a8e2d1f4c7a90b3e6d8f21` |

---

## Why nonce reuse kills ECDSA

An ECDSA signature over a message hash `z` with private key `d`:

```
k  = random nonce
r  = (k·G).x  mod n
s  = k⁻¹ · (z + r·d)  mod n
```

If the **same `k`** was used for two messages `z₂`, `z₄`:

```
s₂ − s₄ = k⁻¹ (z₂ − z₄)   ⇒   k = (z₂ − z₄) / (s₂ − s₄)  mod n
d = (s₂·k − z₂) / r       mod n
```

The reused nonce shows up as an **identical `r`** in both signatures — exactly the hint "line up
its signatures".

---

## 1. Extract the chunks from `core.bin`

```python
data = open('core.bin','rb').read()
def chunk(tag):
    i = data.find(tag); tl = len(tag)
    ln = int.from_bytes(data[i+tl:i+tl+2], 'little')
    return data[i+tl+2:i+tl+2+ln]
```

Each signature is **64 bytes = `r`(32) ‖ `s`(32)**; `PUB` is **64 bytes = `X`(32) ‖ `Y`(32)**.

`SIG2` and `SIG4` have the same first 32 bytes:

```
SIG2 r = fe3bf41a5a29f7149eba221ced0e73fc0e926c8ea944cd5bc1b970ac59647caa
SIG4 r = fe3bf41a5a29f7149eba221ced0e73fc0e926c8ea944cd5bc1b970ac59647caa   <-- == SIG2
```

So the same nonce `k` signed directives DIR2 and DIR4.

---

## 2. Message hashing — `z = SHA256(EPOK ‖ body)`

The hint "only ever had one way of hashing" = **SHA-256**. What is hashed is confirmed for free:
a candidate is correct when the recovered `d` satisfies **`d·G == PUB`**. Testing shows
`z = SHA256(EPOK_body ‖ directive_body)` is the scheme (the guardian "seals" each directive
together with the core load epoch).

---

## 3. Recover the private key

```python
import hashlib
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def inv(a,m): return pow(a%m, m-2, m)
epok = chunk(b'EPOK'); b2 = chunk(b'DIR2'); b4 = chunk(b'DIR4')
r  = int.from_bytes(chunk(b'SIG2')[:32], 'big')
s2 = int.from_bytes(chunk(b'SIG2')[32:], 'big')
s4 = int.from_bytes(chunk(b'SIG4')[32:], 'big')
z2 = int.from_bytes(hashlib.sha256(epok+b2).digest(), 'big')
z4 = int.from_bytes(hashlib.sha256(epok+b4).digest(), 'big')
k = ((z2-z4) * inv((s2-s4) % n, n)) % n
d = ((s2*k - z2) * inv(r, n)) % n
# d = 0x5eafc0de19774b309c1e2a7d3f61b0c4a8e2d1f4c7a90b3e6d8f21
```

Verify `d·G == PUB` with a hand-rolled secp256k1 point multiply (full code in the appendix). Note
the planted values: nonce `c0ffee…deadbeef…`, key `5eafc0de_1977…` ("safe code 1977").

---

## 4. Unmask `flag.enc`

"masked, not encrypted" + "one way of hashing" = an MGF1-SHA256 keystream XORed with the flag:
- **seed = `EPOK_body ‖ d`** with `d` as 32-byte big-endian;
- block `i` = `SHA256(seed ‖ counter_i)`, counter 4-byte **little-endian** (`0,1,2,…`);
- concatenate blocks and XOR with `flag.enc`.

```python
import struct
d = 0x5eafc0de19774b309c1e2a7d3f61b0c4a8e2d1f4c7a90b3e6d8f21
enc = open('flag.enc','rb').read()
seed = epok + d.to_bytes(32,'big')
ks = b''; c = 0
while len(ks) < len(enc):
    ks += hashlib.sha256(seed + struct.pack('<I', c)).digest(); c += 1
print(bytes(a ^ b for a, b in zip(enc, ks)).decode())
# reentry{n0nc3_r3us3_br0k3_th3_gu4rdi4n_k3y}
```

> **Verification note:** I ran the full attack on `files/core.bin` and `files/flag.enc`:
> `r(SIG2)==r(SIG4)` is True, `d = 0x5eafc0de1977…`, **`d·G == PUB` is True**, and the MGF1 unmask
> gives `reentry{n0nc3_r3us3_br0k3_th3_gu4rdi4n_k3y}`. Fully reproduced.

🚩 **Flag:** `reentry{n0nc3_r3us3_br0k3_th3_gu4rdi4n_k3y}`

---

## Lessons

- **ECDSA dies on nonce reuse.** `r` is public and reveals the collision; two signatures over
  different messages with the same `k` leak the private key through two linear equations mod `n`
  (real incidents: PS3, many Bitcoin wallets).
- `r` is your detector — "line up its signatures" = compare the `r` values.
- Find the hash scheme by verifying `d·G == PUB`, not by guessing — the curve confirms the hit.
- "Masked, not encrypted" means XOR with a keystream, not a block cipher. Here the keystream is
  MGF1-SHA256 from the key — the guardian's one hashing used against it.

The private key `d` recovered here is also what re-forges the core in stage 5.

---

## Appendix — secp256k1 (point multiply, for the `d·G == PUB` check)

```python
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)
def inv(a, m): return pow(a % m, m-2, m)
def padd(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%p==0: return None
    l=(3*x1*x1)*inv(2*y1,p)%p if P==Q else (y2-y1)*inv(x2-x1,p)%p
    x3=(l*l-x1-x2)%p; return (x3,(l*(x1-x3)-y1)%p)
def pmul(k, P):
    R=None
    while k:
        if k&1: R=padd(R,P)
        P=padd(P,P); k>>=1
    return R
# pmul(d, G) == (int.from_bytes(PUB[:32],'big'), int.from_bytes(PUB[32:],'big'))
```

> **Previous:** [3 - Diag Port](3%20-%20Diag%20Port.md) · **Next:** [5 - Let Go](5%20-%20Let%20Go.md)
