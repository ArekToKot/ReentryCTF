# Meridian Deck 5/5 — Latch

**Flag:** `reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}`
**Override fragment:** `KEPLER-OVR-2:1fb62fc27cd272b9` (in the EVA locker, next to the flag)

| | |
|---|---|
| Category | Crypto / Web — hash length-extension on a secret-prefix MAC (SM3) |
| Target | `https://reentry-latch.chals.io` (was still live — solved here) |
| Stack | Flask + gunicorn; grant MAC = `SM3(key ‖ payload)` |
| Files | [files/latch_solve.py](files/latch_solve.py) — complete, tested solver (pure-python SM3 + length extension + the attack). Uses the grant from stage 4 and the `/maint` password from stage 2. |

> **Challenge brief:** The records bridge pointed you at KEPLER's sealed EVA locker on the deck —
> now the MERIDIAN access controller has to actually release its latch. It opens a door when you
> present a signed access grant that covers it. The grant you were issued covers crew quarters, not
> KEPLER's locker. The controller signs grants with a key you don't have. You won't need it.

"You won't need it [the key]" is a direct invitation to a length-extension attack.

---

## Short version

1. The controller opens a door given a **signed grant** `sm3$<hex(payload)>$<mac>`. From stage 4 we
   have KEPLER's grant: payload `relay=lsu-relay-3391&door=CREW-QTRS`, `mac = 6618a1eb…` — valid,
   but it covers `CREW-QTRS`, not `EVA-LKR-07`.
2. The MAC is **`SM3(key ‖ payload)`** — a naive secret-prefix MAC. SM3 is a Merkle–Damgård hash
   (like SHA-256) → vulnerable to **length extension**. The brief confirms it.
3. Append `&door=EVA-LKR-07` and compute a **valid MAC without the key**. The server parses `door=`
   into a **list**, so `EVA-LKR-07` joins the authorized doors.
4. `/open` rejects "stray bytes" (the glue contains binary), so raw grants go to **`/maint`**,
   protected by **HTTP Basic**. The password is the maintenance code **`MER-MNT-7F3A`** recovered
   in stage 2. `maint:MER-MNT-7F3A` → 200, grant accepted, latch released, flag.

---

## 1. Recon

Two endpoints: `/open` (POST `grant`, rejects binary bytes) and `/maint` (GET/POST `grant`, "RAW
GRANTS", HTTP Basic).

```bash
URL=https://reentry-latch.chals.io
G='sm3$72656c61793d6c73752d72656c61792d3333393126646f6f723d435245572d51545253$6618a1eb...'
curl -s -X POST "$URL/open" --data-urlencode "grant=$G" | sed 's/<[^>]*>//g' | grep -i authoriz
# Grant authenticated. Authorized doors: ['CREW-QTRS']. KEPLER's EVA locker (EVA-LKR-07) is not among them.
```

- Changing `door` without re-signing → `SM3 grant signature mismatch`.
- `door=` goes into a **list** (`['CREW-QTRS']`) — so appending a second `door=EVA-LKR-07` works.

## 2. Why length extension works

MAC = `SM3(key ‖ payload)`. SM3 is Merkle–Damgård: the final hash is the full internal state after
processing `key ‖ payload ‖ padding`. Knowing the MAC and the length of `key ‖ payload`, you can:

1. set the SM3 registers to the MAC value,
2. keep hashing an arbitrary **suffix** `S`,
3. get `SM3(key ‖ payload ‖ glue ‖ S)` — a valid MAC for the extended message,

where `glue` is the original padding (`0x80 ‖ 0x00… ‖ 64-bit bit-length`). You do not need the key,
only its **length** (brute 1..64).

New payload: `relay=lsu-relay-3391&door=CREW-QTRS` ‖ `glue` ‖ `&door=EVA-LKR-07`. After query-string
parsing, the `door` list contains `EVA-LKR-07` (the last, clean token).

## 3. Exploit

The snippet below imports an `sm3` module for clarity; a complete, self-contained and tested
version (pure-python SM3 + length extension, no external module needed) is in
[files/latch_solve.py](files/latch_solve.py) — just run `python3 latch_solve.py`.

```python
import sm3, urllib.request, urllib.parse, ssl, base64, re
ctx = ssl._create_unverified_context()
P   = b"relay=lsu-relay-3391&door=CREW-QTRS"
MAC = "6618a1ebc84cfd759e4b5cf12316f49bd680839f5e5f02313cb06d141100eb96"
S   = b"&door=EVA-LKR-07"
auth = base64.b64encode(b"maint:MER-MNT-7F3A").decode()   # code from stage 2

for L in range(1, 65):                       # brute key length
    new_mac, glue = sm3.sm3_extend(MAC, L + len(P), S)
    grant = "sm3$" + (P + glue + S).hex() + "$" + new_mac
    data  = urllib.parse.urlencode({"grant": grant}).encode()
    req   = urllib.request.Request("https://reentry-latch.chals.io/maint", data=data,
              headers={"Authorization": "Basic " + auth}, method="POST")
    body  = urllib.request.urlopen(req, timeout=15, context=ctx).read().decode("utf-8", "replace")
    m = re.search(r"reentry\{[^}]*\}", body)
    if m:
        print("KEYLEN", L, "->", m.group(0)); break
# KEYLEN 24 -> reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}
```

Key length = 24. Server reply:

```
Grant authenticated for EVA-LKR-07 — latch released.
KEPLER — EVA LOCKER EVA-LKR-07
The latch is released. Recovered from KEPLER's EVA locker:
  clearance token          : reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}
  master-override fragment : KEPLER-OVR-2:1fb62fc27cd272b9
```

> **Verification note (recovered live):** I re-ran this end to end against the live instances. I
> pulled KEPLER's current grant from the Records Bridge via `alg:none` (payload
> `relay=lsu-relay-3391&door=CREW-QTRS`, MAC `6618a1eb…` — the HMAC key is fixed across spawns),
> implemented SM3 + length extension by hand (self-tested against `SM3("abc")` and a known-key
> length-extension vector), appended `&door=EVA-LKR-07`, and brute-forced the key length. **KEYLEN =
> 24** unlocked the locker and returned both the flag and the override fragment
> `KEPLER-OVR-2:1fb62fc27cd272b9`.

Details that cost time:
- `/open` blocks binary glue ("Raw grants are only accepted on the maintenance channel"); `/maint`
  (raw) accepts it.
- `/maint` uses HTTP Basic, user `maint`, password **`MER-MNT-7F3A`** — the code recovered from the
  SQLite freelist in stage 2.

> **Note:** The web service is offline now, so the end-to-end run cannot be reproduced. The inputs
> it relies on are verified elsewhere in this folder: the grant hex decodes to
> `relay=lsu-relay-3391&door=CREW-QTRS` (stage 4), and the `/maint` password `MER-MNT-7F3A` is the
> code in the recovered `panel_recovered.jpg` (stage 2).

🚩 **Flag:** `reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}`

---

## Why it works / lessons

- `SM3(key ‖ msg)` is **not** a secure MAC. All Merkle–Damgård hashes (MD5, SHA-1, SHA-256, SM3)
  allow length extension; use **HMAC** (`HMAC-SM3`) instead.
- Parsing `door=` into a list lets the appended `&door=EVA-LKR-07` add an authorized door.
- Do not hide a sensitive channel (`/maint`) behind a secret that leaked elsewhere in the system.

---

## Meridian Deck — complete (1–5)

| # | Challenge | Flag | Core |
|---|---|---|---|
| 1 | Crew Intranet | `reentry{sh4r3d_cr3w_l0gin_l34ks_th3_br1dg3}` | shared account in a PDF |
| 2 | Last Messages | `reentry{th3_fr33list_r3m3mb3rs_d3l3t3d_ch4t}` | SQLite freelist + OpenSSL |
| 3 | Life Support | `reentry{c0nfus3d_g4t3w4y_l34ks_th3_l4z4rus_f33d}` | MQTT confused deputy |
| 4 | Records Bridge | `reentry{4lg_n0n3_w4lks_r1ght_p4st_th3_gu4rd}` | JWT `alg:none` |
| 5 | Latch | `reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}` | SM3 length extension |

> **Previous:** [4 - Records Bridge](4%20-%20Records%20Bridge.md)
>
> **Meridian Deck: 5/5 — COMPLETE.** 🏁
