# Meridian Deck 2/5 — Last Messages

**Flag:** `reentry{th3_fr33list_r3m3mb3rs_d3l3t3d_ch4t}`
**Recovered bonus:** aft bulkhead maintenance code `MER-MNT-7F3A` (needed in stage 5)

| | |
|---|---|
| Category | Forensics / crypto (SQLite internals + OpenSSL) |
| Tools | `sqlite3`, `openssl`, `binwalk`, `python3` |
| Files | [files/crew_msgr.db](files/crew_msgr.db) (82944 bytes, 81 pages × 1024 B) · recovered: [files/panel_recovered.jpg](files/panel_recovered.jpg) |

> **Challenge brief:** We pulled an archived crew messenger database off the MERIDIAN deck — an old
> thread from '77. The crew knew better than to paste secrets in the clear — but "better" only goes
> so far. The deck audit token is right there in the log, just encrypted — and someone helpfully
> posted the password too. Then read the rest of the thread: they were careful about one thing, and
> a lot less careful about deleting.

---

## Short version

1. `crew_msgr.db` is SQLite with one `messages` table (10 visible rows).
2. Message #6 holds an encrypted token (OpenSSL `Salted__` format); message #7 posts the password
   next to it.
3. `openssl enc -d -aes-256-cbc -pbkdf2` with that password gives the flag directly.
4. The thread also mentions a photo of a panel with a maintenance code that Voss "pulled back"
   (deleted). SQLite does not zero deleted data: the deleted leaf page and the whole **overflow
   page** chain went onto the **freelist**, but their content is untouched.
5. Rebuilding the overflow chain (skipping the 4-byte "next page" pointer at the start of each
   page) recovers a **complete JPEG** of the panel with access code `MER-MNT-7F3A`.

---

## 1. Recon

```bash
file crew_msgr.db
sqlite3 crew_msgr.db ".schema"
# CREATE TABLE messages (id INTEGER PRIMARY KEY, ts TEXT, sender TEXT, body TEXT, attachment BLOB);
```

The header already says **81 pages total, 77 free** — almost the whole file is "dead" (deleted)
content.

```bash
sqlite3 crew_msgr.db "SELECT id, sender, body FROM messages ORDER BY id;"
```

Key rows:

| id | sender | body |
|----|--------|------|
| 5 | kepler | "...posting it encrypted, don't repost it:" |
| 6 | kepler | `U2FsdGVkX19NRVJJRElBTiz0l3ZqQ4pza4zdCThcZQNQ8yIuBu2QOMogxAWrKqC6RQoFrOHALoXc1w5pBl24YA==` |
| 7 | kepler | "pass: meridian-deck-1977" |
| 8 | harlan | "...the aft bulkhead maintenance code? i'm not typing that in here after last time." |
| 9 | voss | "photographed the panel and dropped it in the thread, then pulled it back..." |

No visible row has an active `attachment` — matching Voss deleting his message in #9.

---

## 2. Decrypt the deck audit token

The base64 in #6 decodes to a `Salted__` header — standard OpenSSL `enc`:

```bash
printf '%s' 'U2FsdGVkX19NRVJJRElBTiz0l3ZqQ4pza4zdCThcZQNQ8yIuBu2QOMogxAWrKqC6RQoFrOHALoXc1w5pBl24YA==' | base64 -d > token.enc
openssl enc -d -aes-256-cbc -pbkdf2 -in token.enc -pass pass:meridian-deck-1977
# reentry{th3_fr33list_r3m3mb3rs_d3l3t3d_ch4t}
```

(The 8-byte salt is literally ASCII `MERIDIAN` — a flavor touch, not needed for the attack.)

> **Verification note:** I ran this on `files/crew_msgr.db` and the decrypt gives
> `reentry{th3_fr33list_r3m3mb3rs_d3l3t3d_ch4t}`. Confirmed.

🚩 **Flag:** `reentry{th3_fr33list_r3m3mb3rs_d3l3t3d_ch4t}`

---

## 3. Recover the "deleted" attachment

The flag name is the hint: *the freelist remembers deleted chat*. `binwalk` finds a JPEG inside,
but a naive carve is corrupt — SQLite stores large BLOBs in a chain of **overflow pages**, and
each overflow page starts with a 4-byte "next page" pointer that breaks the raw stream every 1024
bytes. You must skip those pointers.

The leaf fragment of the deleted record (the text `panel photo (aft bulkhead):` + the JPEG start
`FF D8`) survives in the slack space of the active page #4. A 4-byte big-endian pointer right after
the local payload points to the first overflow page; follow the chain (pages 5 → 6 → … → 79),
taking bytes `[4:]` of each page:

```python
import struct
data = open('crew_msgr.db','rb').read(); PS = 1024
page = lambda n: data[(n-1)*PS:n*PS]
p4 = page(4)
jpg_start = p4.find(b'panel photo (aft bulkhead):') + len(b'panel photo (aft bulkhead):')
ptr_pos = p4.find(struct.pack(">I", 5), jpg_start)
local = p4[jpg_start:ptr_pos]
nxt = struct.unpack(">I", p4[ptr_pos:ptr_pos+4])[0]
blob = bytearray(local)
while nxt != 0:
    pg = page(nxt); nxt = struct.unpack(">I", pg[0:4])[0]; blob.extend(pg[4:])
end = blob.rfind(b'\xff\xd9')
open('panel_recovered.jpg','wb').write(bytes(blob[:end+2]))
```

> **Verification note:** I ran this on `files/crew_msgr.db`. It produces a valid 76453-byte JPEG
> (`FF D8 … FF D9`, 1417×1500), saved as `files/panel_recovered.jpg`. The photo shows the
> **"MERIDIAN STATION — AFT MAINTENANCE BULKHEAD — PANEL 3"** plate with a sticky note:
> `aft bulkhead access code: MER-MNT-7F3A`. That is the code Harlan asked for in #8 and Voss
> "deleted" in #9 — it never left the file. It is reused as the `/maint` password in stage 5.

---

## Why it works / lessons

- Posting the password next to the ciphertext in the same thread breaks the whole encryption.
- `DELETE` is not `shred`. SQLite removes the row from the active b-tree but does **not** zero the
  freed pages. Until a `VACUUM` (or overwrite), deleted records — including large BLOBs split
  across overflow chains — are fully recoverable from the `.db` file.
- `strings`/`binwalk` detect the signal but cannot correctly rebuild structured page formats; you
  must understand the container (SQLite pages, overflow pointers).
- To delete securely: overwrite then `VACUUM`, or `PRAGMA secure_delete = ON`.

> **Previous:** [1 - Crew Intranet](1%20-%20Crew%20Intranet.md) · **Next:** [3 - Life Support](3%20-%20Life%20Support.md)
