# Cold Spares 1/6 — "Sample Investigation"

**Flag:** `reentry{th3_b00th_upst41rs_r3m3mb3rs_1977}`

| | |
|---|---|
| Category | Hardware / Firmware reverse engineering |
| Points | 280 |
| Hardware | Seeed Studio XIAO ESP32-C3 (given by the organizers) |
| Tools | Linux, Python 3, `esptool`, `capstone` |
| Files | [files/flash_dump.bin](files/flash_dump.bin) (4 MB full flash dump) |

> **Challenge brief:** A crate of dead boards out of the fabrication bay — prototypes of
> the thing that became LAZARUS, abandoned before anyone wrote down what they were. One of
> them still holds its firmware. Pull it off and read it and you will have almost
> everything you need. Almost: the last piece is a name, and the firm that owns it is still
> trading. Some questions are not answered by a debugger.

---

## Short version

1. Put the ESP32-C3 into ROM download mode (hold **BOOT**, tap **RESET**, release **BOOT**).
2. Read the whole 4 MB flash with `esptool read-flash`.
3. Split the dump by its partition table. All code is in `app0`.
4. The flag is **not** in plain text. The firmware decodes it into a stack buffer and
   then wipes it with `memset`, so a serial (UART) capture shows nothing.
5. Read the RISC-V code, find the decode function, and re-run it offline.

**Decode rule:** `flag[i] = A[i] XOR K[i & 3] XOR ((i * 17 + 8) & 0xFF)` for `i` in `0..41`.

---

## 1. Set up the environment

```bash
mkdir -p ~/ctf/cold-spares && cd ~/ctf/cold-spares
python3 -m venv venv
./venv/bin/pip install esptool capstone
./venv/bin/esptool version
```

Check that your user is in the `dialout` group (serial port access without `sudo`):

```bash
id            # the output must contain 20(dialout)
```

If the group is missing, add yourself and then **log out and log in again**:

```bash
sudo usermod -aG dialout $USER
```

---

## 2. Connect the board and confirm the host sees it

List USB devices before and after you plug in the board, so you have a reference:

```bash
lsusb
```

You are looking for this line:

```
Bus 003 Device 0xx: ID 303a:1001 Espressif USB JTAG/serial debug unit
```

Check that a serial port appeared:

```bash
ls -l /dev/ttyACM*
```

> **Trap 1 — the cable.** At first the board was not visible at all (not in `lsusb`, not in
> `/dev/ttyACM*`). The cause was a charge-only USB-C cable with no data lines. A data-capable
> cable (for example a tablet cable) fixed it.

> **Trap 2 — the board disappears.** In normal mode the board showed up as `303a:1001` and
> then vanished a moment later. The device number in `lsusb` jumped around, which means the
> board connected and disconnected many times. The firmware resets the board (or kills USB)
> on purpose — that is why the brief calls them "dead boards". The fix is step 3.

---

## 3. Enter ROM download mode (bootloader)

The ESP32-C3 has a bootloader burned into silicon (ROM) that firmware **cannot disable**.
When you start it, the flash firmware does not run, so it cannot block the read.

The XIAO ESP32-C3 has two small buttons: **B** (BOOT) and **R** (RESET).

1. Plug the board into the host.
2. **Press and hold B (BOOT).**
3. Tap and release **R (RESET)**.
4. Release **B (BOOT)**.

Now confirm the board stays visible:

```bash
lsusb | grep 303a
ls -l /dev/ttyACM0
```

---

## 4. Identify the chip

The flags `--before no-reset --after no-reset` stop esptool from resetting the board, so it
stays in the bootloader between commands.

```bash
./venv/bin/esptool --port /dev/ttyACM0 --before no-reset --after no-reset flash-id
```

Key facts from the output: **4 MB flash** (`0x400000` bytes), core is **RISC-V** (ESP32-C3).

> In esptool v4 and older the commands use underscores: `flash_id`, `read_flash`, and the
> flags are `no_reset`.

---

## 5. Dump the whole flash

```bash
./venv/bin/esptool --port /dev/ttyACM0 --before no-reset --after no-reset -b 460800 read-flash 0 0x400000 flash_dump.bin
ls -l flash_dump.bin
sha256sum flash_dump.bin
```

Expected result (verified on the dump in this folder):

```
4194304 bytes
31d5928d3839f1dece622ef3e5bce87c3e12e1b2ab7072ca6381e9dc5b85458b  flash_dump.bin
```

> After this point the board is no longer needed; the rest is offline analysis. When you are
> done, tap RESET to return the board to normal operation.

---

## 6. Partition table and splitting the dump

ESP32 flash layout:

| Offset   | Content                     |
|----------|-----------------------------|
| `0x0000` | second-stage bootloader     |
| `0x8000` | **partition table**         |
| later    | partitions (nvs, app, …)    |

Each partition entry is 32 bytes and starts with magic bytes `AA 50`.

```python
# parts.py
import struct
d = open('flash_dump.bin', 'rb').read()
for i in range(0x8000, 0x9000, 32):
    e = d[i:i+32]
    if e[:2] != b'\xaa\x50':
        continue
    typ, sub = e[2], e[3]
    off, size = struct.unpack('<II', e[4:12])
    name = e[12:28].rstrip(b'\0').decode()
    part = d[off:off+size]
    used = sum(1 for b in part if b != 0xff)
    print(f'{name:10} off={off:#08x} size={size:#08x} type={typ} sub={sub:3}  used bytes: {used}')
    open(f'{name}.bin', 'wb').write(part)
```

Output:

```
nvs        off=0x009000 size=0x005000 type=1 sub=  2  used bytes: 0
otadata    off=0x00e000 size=0x002000 type=1 sub=  0  used bytes: 12
app0       off=0x010000 size=0x140000 type=0 sub= 16  used bytes: 294387
app1       off=0x150000 size=0x140000 type=0 sub= 17  used bytes: 0
spiffs     off=0x290000 size=0x160000 type=1 sub=130  used bytes: 0
coredump   off=0x3f0000 size=0x010000 type=1 sub=  3  used bytes: 0
```

**Result:** `nvs`, `spiffs`, `coredump`, and `app1` are empty (all `0xFF`), so everything is
in **`app0.bin`**.

---

## 7. String recon

First look for the obvious:

```bash
strings -n 6 app0.bin | grep -iE "flag|ctf|reentry|\{"
```

Nothing useful — the flag is not stored as plain text. Now read the sketch's own strings,
with ESP-IDF library noise filtered out:

```bash
strings -n 5 app0.bin | grep -vE "^(ESP_ERR|E \(|W \(|I \()|\.c$|\.h$|assert|pxRing|xTask|uxItem|%" | head -40
```

Interesting strings from the sketch itself:

```
Receiving ...
Data:
Length:
CRC mismatch!
Starting ...
Chip not found!
Send a character to transmit data!
 not here
another useless string
Transmitting:
XIAO_ESP32C3
```

Look at the start of the data section in hex:

```bash
xxd -s 0x0 -l 0x210 app0.bin
```

The application header (`esp_app_desc_t`) shows the project name, build date, and
ESP-IDF `v5.5.5` (Arduino core `3.3.12`).

Look for a copyright string:

```bash
strings -n 6 app0.bin | grep -i copyright
# Copyright (C) iFirma 1977
```

**Result:** this is an Arduino sketch for a 433 MHz radio (RadioLib library, CC1101 chip).
`not here` and `another useless string` are decoys. The flag is encoded, so you must read
the code.

---

## 8. ESP32 application image structure

The ESP app image format:

```
[24-byte header: magic 0xE9, segment count, entry point, ...]
[segment: load_address (4B) | length (4B) | data]
[segment: ...]
```

```python
# segs.py
import struct
d = open('app0.bin', 'rb').read()
print('magic', hex(d[0]), 'segments', d[1], 'entry', hex(struct.unpack('<I', d[4:8])[0]))
o = 24
for i in range(d[1]):
    addr, ln = struct.unpack('<II', d[o:o+8])
    print(f'{i}  file_off={o+8:#07x}  load={addr:#010x}  len={ln:#07x}')
    o += 8 + ln
```

Output:

```
magic 0xe9 segments 6 entry 0x403807ca
0  file_off=0x00020  load=0x3c030020  len=0x1033c   <- DROM (constant data / strings)
1  file_off=0x10364  load=0x3fc8cc00  len=0x01bb0   <- DRAM
2  file_off=0x11f1c  load=0x40380000  len=0x0ca10   <- IRAM (code)
3  file_off=0x1e934  load=0x50000000  len=0x00020   <- RTC
4  file_off=0x1e95c  load=0x00000000  len=0x016bc   <- padding
5  file_off=0x20020  load=0x42000020  len=0x2832c   <- IROM (main code, the sketch is here)
```

Address-to-file-offset rules:

- **data:** `file_offset = address - 0x3c030020 + 0x20 = address - 0x3c030000`
- **code:** `file_offset = address - 0x42000020 + 0x20020`

---

## 9. RISC-V disassembly and string cross-references

In RISC-V an address is loaded with a pair of instructions:

```
lui  a1, 0x3c030      # top 20 bits
addi a1, a1, 0x120    # bottom 12 bits  -> a1 = 0x3c030120
```

This script walks all the code and finds every place that builds an address in a given range:

```python
# xref.py
import capstone, struct, sys
d = open('app0.bin', 'rb').read()
segs = []; o = 24
for i in range(d[1]):
    a, l = struct.unpack('<II', d[o:o+8]); segs.append((a, o+8, l)); o += 8 + l
md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
for a, fo, l in segs:
    if a not in (0x42000020, 0x40380000):
        continue
    buf = d[fo:fo+l]; off = 0; luis = {}
    while off < l:
        insns = list(md.disasm(buf[off:off+0x10000], a + off))
        if not insns:
            off += 2; continue
        for ins in insns:
            ops = ins.op_str.split(', ')
            if ins.mnemonic in ('lui', 'c.lui'):
                luis[ops[0]] = (int(ops[1], 0) << 12) & 0xffffffff
            elif ins.mnemonic in ('addi', 'c.addi') and len(ops) == 3 and ops[1] in luis:
                v = (luis[ops[1]] + int(ops[2], 0)) & 0xffffffff
                if lo <= v < hi:
                    print(hex(ins.address), '->', hex(v))
        off = insns[-1].address + insns[-1].size - a
```

Find references to the sketch strings (`0x3c030100`–`0x3c030200`):

```bash
./venv/bin/python xref.py 3c030100 3c030200
```

The whole user sketch sits at the very start of IROM, around `0x42000020`–`0x42000460`.
Disassemble that part:

```python
# dis.py
import capstone, sys
d = open('app0.bin', 'rb').read()
start = int(sys.argv[1], 16); n = int(sys.argv[2], 16)
fo = start - 0x42000020 + 0x20020
md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
for ins in md.disasm(d[fo:fo+n], start):
    print(f'{ins.address:#x}  {ins.mnemonic:10} {ins.op_str}')
```

```bash
./venv/bin/python dis.py 42000020 0x290
```

---

## 10. The decode function

### `setup()` — from `0x4200014a`

```asm
0x42000158  c.lui a1, 0x1c
0x42000162  addi  a1, a1, 0x200        ; 0x1c200 = 115200
0x4200016e  jal   ...                  ; Serial.begin(115200)
0x42000172  addi  a0, zero, 0x7d0      ; 2000
0x42000176  jal   ...                  ; delay(2000)
0x4200017e  ...   "Starting ..."       ; Serial.println
0x4200018a  c.addi4spn a0, sp, 0xc     ; a0 = stack buffer
0x4200018c  c.jal -0x16c               ; ---> call 0x42000020  (DECODER)
0x42000196  a2 = 0x3c03906c            ; "Copyright (C) iFirma 1977..."
0x420001a2  jal   ...                  ; Serial.printf(...)
0x420001a6  addi  a2, zero, 0x40
0x420001aa  c.li  a1, 0
0x420001ac  c.addi4spn a0, sp, 0xc
0x420001b2  jalr  ...                  ; memset(buffer, 0, 64)  <- WIPES THE DECODED FLAG
0x420001be  lw ... 0x3c0390d0/d8       ; 4.0, 433.5 -> radio.begin(433.5 MHz, 4 kbps, ...)
```

The flag is decoded into a stack buffer and **wiped immediately** by `memset`. It never
reaches the serial port, so a UART capture would show nothing. You must decode it yourself.

### Decoder — `0x42000020`

```asm
0x42000020  c.li  a5, 0                ; i = 0
0x42000022  lui   t3, 0x3c039
0x42000026  lui   t1, 0x3c039
0x4200002a  c.li  a6, 0x11             ; 17
0x4200002c  addi  a2, zero, 0x2a       ; 42 = length
loop:
0x42000030  andi  a3, a5, 3            ; i & 3
0x42000034  addi  a4, t3, 0xa0         ; A = 0x3c0390a0  (encrypted data)
0x42000038  addi  a7, t1, 0x9c         ; K = 0x3c03909c  (4-byte key)
0x4200003c  c.add a4, a5               ; &A[i]
0x4200003e  c.add a3, a7               ; &K[i & 3]
0x42000040  lbu   a4, 0(a4)            ; A[i]
0x42000044  lbu   a3, 0(a3)            ; K[i & 3]
0x42000048  add   a1, a0, a5           ; &out[i]
0x4200004c  c.xor a4, a3               ; A[i] ^ K[i&3]
0x4200004e  mul   a3, a5, a6           ; i * 17
0x42000052  c.addi a5, 1              ; i++
0x42000054  c.addi a3, 8              ; i*17 + 8
0x42000056  c.xor a4, a3               ; ^ (i*17 + 8)
0x42000058  sb    a4, 0(a1)            ; out[i] = ...
0x4200005c  bne   a5, a2, loop         ; while i != 42
0x42000060  sb    zero, 0x2a(a0)       ; out[42] = '\0'
0x42000064  c.jr  ra
```

The same logic in C:

```c
void decode(char *out) {
    for (int i = 0; i < 42; i++)
        out[i] = A[i] ^ K[i & 3] ^ (uint8_t)(i * 17 + 8);
    out[42] = 0;
}
```

The data in the file (`address - 0x3c030000`):

```bash
xxd -s 0x909c -l 0x30 app0.bin
```

```
0000909c: a53c 9107                                  <- K (key)
000090a0: df40 de52 9d13 8603 41f5 109b 13e9 5774    <- A (42 bytes)
000090b0: d54a de3c 8a25 dbb9 77fe 0ca6 72a4 a47d
000090c0: ef36 a92f 9670 26af 2280
```

---

## 11. Recover the flag

```python
# solve.py
d = open('app0.bin', 'rb').read()
f = lambda addr: addr - 0x3c030000          # DROM address -> app0.bin offset
K = d[f(0x3c03909c):f(0x3c03909c) + 4]
A = d[f(0x3c0390a0):f(0x3c0390a0) + 42]
flag = bytes(A[i] ^ K[i & 3] ^ ((i * 17 + 8) & 0xff) for i in range(42))
print(flag.decode())
```

```bash
python3 solve.py
# reentry{th3_b00th_upst41rs_r3m3mb3rs_1977}
```

> **Verification note (this folder):** I re-ran this decode on the real `files/flash_dump.bin`.
> `K = a53c9107`, `A = df40de52…2280`, and the output is exactly
> `reentry{th3_b00th_upst41rs_r3m3mb3rs_1977}`. The SHA-256 and the partition table also match.

🚩 **Flag:** `reentry{th3_b00th_upst41rs_r3m3mb3rs_1977}`

---

## 12. Extra observations

- **Radio parameters** (doubles in DROM at `0x3c0390d0`–`0x3c0390ec`): `4.0` kbps, `433.5`
  MHz, `431.5`, `24.04`. This is a CC1101 config through RadioLib, and may be useful in
  later parts of the "Cold Spares" series.
- The block at `0x3c039294` is the CC1101 PA (output-power) table from the library, not a
  secret.
- **Hint from the brief:** *"the last piece is a name, and the firm that owns it is still
  trading"* and *"Some questions are not answered by a debugger."* Next to the flag sits
  `Copyright (C) iFirma 1977`, and the flag ends with `_1977`. This points at an OSINT step
  (identify the firm / name), not more debugging.

---

## 13. Common problems

| Symptom | Cause | Fix |
|---|---|---|
| No board in `lsusb`, no `/dev/ttyACM*` | charge-only cable | use a cable with data lines |
| Board appears and disappears | firmware resets the board / kills USB | enter bootloader: hold BOOT, tap RESET, release BOOT |
| `Permission denied: /dev/ttyACM0` | not in `dialout` group | `sudo usermod -aG dialout $USER`, then log out/in |
| `invalid choice: 'read-flash'` | different esptool version | v5: `read-flash`, `flash-id`, `no-reset`; v4: `read_flash`, `flash_id`, `no_reset` |
| `Failed to connect` | board not in bootloader | repeat BOOT/RESET, run esptool right away |
| `No module named capstone` | using system Python | use `./venv/bin/python` |

---

## 14. One-shot

Board connected with a data cable and put into bootloader (BOOT + RESET):

```bash
python3 -m venv venv && ./venv/bin/pip install esptool capstone
./venv/bin/esptool --port /dev/ttyACM0 --before no-reset --after no-reset -b 460800 read-flash 0 0x400000 flash_dump.bin
python3 -c "d=open('flash_dump.bin','rb').read()[0x10000:0x150000];K=d[0x909c:0x90a0];A=d[0x90a0:0x90ca];print(bytes(A[i]^K[i&3]^((i*17+8)&255) for i in range(42)).decode())"
# reentry{th3_b00th_upst41rs_r3m3mb3rs_1977}
```
