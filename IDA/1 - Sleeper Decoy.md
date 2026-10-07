# IDA 1/4 — Sleeper Decoy

**Flag:** `reentry{Fl0at_P0lym0rph1sm_M4st3r}`

| | |
|---|---|
| Category | Reverse engineering · 454 pts |
| File | [files/calculator](files/calculator) (ELF 64-bit, statically linked, **not stripped**) |

> **Challenge brief:** A 64-bit Linux CLI that looks like an ordinary floating-point calculator.
> After the `> ` prompt it takes one expression per line: `<number> <operator> <number>`, e.g.
> `2.5 + 2.5`. Operators `+ - * /`. There is no key check and no comparison to find — the only
> thing that validates your input is the processor itself. Find the flag.

---

## Short version

The binary is a floating-point calculator. The raw **64 bits of each result** are XORed into a
global `IV` (starting at `0xc0ffee1234567890`). After **6 valid operations** the program builds
a keystream = `SHA256(IV ‖ counter)`, uses it to decrypt a 77-byte `blob`, marks the memory
executable, and **runs it as code**. With the right `IV` this is a `write(flag)` shellcode; with
a wrong one it is garbage and `SIGSEGV`. That is the hint: "the only thing that validates your
input is the processor itself."

Target `IV = 0xbf21ee1234567890`. One way to reach it:

```bash
printf '1 * 1\n1 * 1\n1 * 1\n1 * 1\n1 * 1\n14 + 1\n' | ./calculator
# reentry{Fl0at_P0lym0rph1sm_M4st3r}
```

> **Verification note:** I ran the real `files/calculator` with this input and it printed
> `reentry{Fl0at_P0lym0rph1sm_M4st3r}`. A Python re-implementation (IV and blob read straight from
> the binary's `.data`) produces the same flag.

---

## 1. Identify and enumerate

```bash
file calculator      # ELF 64-bit, x86-64, statically linked, not stripped
nm calculator | grep -iE ' (t|T) (main|sha|key|decimal|calc)'
```

```
0000000000401ff5 t keystream
0000000000402109 t decimal_only
000000000040218e T main
00000000004019c5 t sha256_small
```

Only four author functions, and no `flag`/`correct`/`wrong` string — so there is no comparison,
exactly as the brief says.

---

## 2. `main` logic

```c
unsigned long IV = 0xc0ffee1234567890;   // global, .data @ 0x4d30e0
unsigned char blob[77] = { ... };         // .data @ 0x4d3100

int count = 0; char line[256];
while (fgets(line, 0x100, stdin)) {
    if (!decimal_only(line)) { puts("?"); continue; }
    double a, b; char op;
    if (sscanf(line, "%lf %c %lf", &a, &op, &b) != 3) continue;
    double r;
    switch (op) {
        case '+': r = a + b; break;
        case '-': r = b - a; break;    // note the order
        case '*': r = a * b; break;
        case '/': r = a / b; break;
        default:  puts("?"); continue;
    }
    printf("%g\n", r);

    IV ^= *(unsigned long*)&r;          // <<< raw bits of the result XORed into IV
    if (++count != 6) continue;         // need exactly 6 valid operations

    void *page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    unsigned char ks[77];
    keystream(IV, ks, 0x4d);
    for (int i = 0; i <= 0x4c; i++)
        ((unsigned char*)page)[i] = blob[i] ^ ks[i];
    mprotect(page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    ((void(*)())page)();                 // <<< run the decrypted code
}
```

So the final `IV = 0xc0ffee1234567890 ⊕ (bits(r1) ⊕ … ⊕ bits(r6))`. There is no `cmp` with a
flag — correctness is checked only when the CPU tries to run the decrypted bytes.

---

## 3. `decimal_only` — what characters are allowed

Allowed: `0-9`, `.`, `+`, `-`, `*`, `/`, **`e`, `E`**, space, tab, newline. Allowing `e`/`E` means
**scientific notation**, so you can produce almost any `double` bit pattern. That is the intended
hint (the theme: *Float Polymorphism*).

---

## 4. `keystream` and `sha256_small`

`keystream(iv, out, len)` builds a 12-byte message `IV(8 LE) ‖ counter(4 LE)`, hashes it with
`sha256_small`, and concatenates 32-byte blocks (counter 0,1,2,…) until `len` bytes:

```
keystream = SHA256(IV_LE ‖ 0) ‖ SHA256(IV_LE ‖ 1) ‖ …
```

`sha256_small` is standard SHA-256 (the init constant `6a09e667` and `K[0]=428a2f98` are present).
The keystream is one-way, so you cannot compute `IV` from it.

---

## 5. Read `IV` and `blob` from `.data`

Mapping VA→offset: `offset = VA - 0x400000`.

```python
d = open('calculator','rb').read(); base = 0x400000
IV   = int.from_bytes(d[0x4d30e0-base:0x4d30e0-base+8], 'little')   # 0xc0ffee1234567890
blob = d[0x4d3100-base:0x4d3100-base+0x4d]                          # 77 bytes
```

---

## 6. Find the right `IV`

SHA-256 is not invertible, but we know two things:
1. The correctly decrypted code prints the flag, so the plaintext almost certainly contains the
   literal `reentry{` — a perfect, zero-false-positive filter.
2. `IV = init ⊕ (XOR of the raw bits of 6 double results)`. With the *Float Polymorphism* theme,
   the author used **simple float values** whose bit patterns have little "junk" (most of the
   mantissa zeroed).

That makes the search space small: `IV = init ⊕ bits(a) ⊕ bits(b)` for simple `a, b`. Search it,
keeping any `IV` whose decryption contains `reentry`:

```python
import hashlib, struct
blob = bytes.fromhex("a797e085e3e765ce15e0e3eeb6dbab7bc456ee3fce77239764a56d25ac43ec9a"
                     "a66762a4041afc3dfc252c99011b2436fa492c904ed7dcf45c43bedb3d72d9ef"
                     "759f0d6b60708981298047bf2e")
init = 0xc0ffee1234567890
def ks(iv, n):
    o, c = b"", 0
    while len(o) < n:
        o += hashlib.sha256(struct.pack("<Q", iv & (2**64-1)) + struct.pack("<I", c)).digest(); c += 1
    return o[:n]
dec  = lambda iv: bytes(x ^ y for x, y in zip(blob, ks(iv, 77)))
bits = lambda x: struct.unpack("<Q", struct.pack("<d", x))[0]
NICE = {float(n) for n in range(-500000, 500001)}
for den in (10,100,1000,2,4,8,5,16): NICE |= {n/den for n in range(-100000,100001)}
for e in range(-30,31): NICE |= {m*10.0**e for m in range(1,500)} | {-m*10.0**e for m in range(1,500)}
for base in (0, bits(1.0)):
    for v in NICE:
        iv = (init ^ base ^ bits(v)) & (2**64-1)
        if b"reentry" in dec(iv):
            print(hex(iv), dec(iv)); raise SystemExit
```

Hit:

```
IV = 0xbf21ee1234567890   ...reentry{Fl0at_P0lym0rph1sm_M4st3r}.
```

The required change is `delta = IV_target ⊕ init = 0x7fde000000000000` — only the top 16 bits
(sign + exponent of a double) differ; the low 48 bits are 0.

---

## 7. The decrypted shellcode

```asm
mov    rax, 1              ; sys_write
mov    rdi, 1              ; fd = stdout
lea    rsi, [rip+0x15]     ; -> flag
mov    rdx, 0x23           ; len = 35
syscall
mov    rax, 0x3c           ; sys_exit
xor    rdi, rdi
syscall
db "reentry{Fl0at_P0lym0rph1sm_M4st3r}\n"
```

A plain `write(1, flag, 35)` + `exit(0)`, with the flag stored in clear at the end.

---

## 8. Build 6 operations that give `IV = 0xbf21ee1234567890`

Need the XOR of the 6 result bit patterns = `0x7fde000000000000`.

- `bits(1.0)  = 0x3ff0000000000000`
- `bits(15.0) = 0x402e000000000000`
- `0x3ff0 ⊕ 0x402e = 0x7fde`, and the low 48 bits of both are 0 ⇒ XOR = `0x7fde000000000000` ✅

So pick **five results = 1.0** (odd count → one `bits(1.0)` remains) and **one result = 15.0**:

```
1 * 1   -> 1.0   (x5)
14 + 1  -> 15.0
```

Any other set with the same XOR also works (e.g. `3 * 5` instead of `14 + 1`, or adding pairs
that cancel).

🚩 **Flag:** `reentry{Fl0at_P0lym0rph1sm_M4st3r}`

---

## Technique summary

| Element | Description |
|---|---|
| Hiding | Looks like a plain FP calculator; no `cmp`/flag string |
| Bit trap | Raw 64 bits of each `double` result XORed into `IV` (float polymorphism) |
| Decrypt | `keystream = SHA256(IV ‖ counter)`, XOR with a 77-byte blob |
| "Validation" | `mmap` + `mprotect(RWX)` + `call` — the CPU runs it or `SIGSEGV` |
| Attack | SHA is one-way → brute a small space `IV = init ⊕ bits(simple floats)`, filter on `reentry{` |
| Payload | `write(1, flag, 0x23)` + `exit(0)` with the flag in clear |

> **Next:** [2 - Librarian](2%20-%20Librarian.md)
