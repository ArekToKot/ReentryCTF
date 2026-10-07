# REENTRY CTF — Writeups

Writeups for the **REENTRY CTF** (`reentry.ctfd.io`), organized by challenge group. Each group is a
folder; writeups are numbered by stage, and challenge files are in each group's `files/` subfolder.

All writeups are in simple technical English. Where a challenge shipped a downloadable file, was
reproducible offline, or the live instance was still up, the writeup has a **Verification note**
recording what was re-run and that the result matched.

**Final score on the platform: 38/39 recovered.** The one unsolved challenge is Cold Spares 2/6
(Wiring Mess), an on-site hardware task. **Master-override fragments: 6 of 7** (see below).

---

## Groups

| Group | Stages | Files included | Verified |
|---|---|---|---|
| [Cold Spares](Cold%20Spares/) | 1 solved (Sample Investigation) + 1 unsolved stub | `flash_dump.bin` | ✅ flag decoded from the dump |
| [Dark Antenna](Dark%20Antenna/) | 5/5 | wav, bins, img, spec, spectrograms | ✅ stages 1–5 all reproduced |
| [IDA](IDA/) | 4/4 | calculator, archive-terminal + libs, encryptor.c, manifest-lock, … | ✅ 1 & 3 reproduced; 2 & 4 static-checked |
| [Kepler's Office](Kepler's%20Office/) | 5/5 | — (web/SSH) | ✅ **rooted live**; SHA-1 verified |
| [LAZARUS](LAZARUS/) | warmup stub | — | — (service offline, flag not recorded) |
| [Lazarus Core](Lazarus%20Core/) | 5/5 | core.bin, diag, flag.enc | ✅ stages 2 & 4 fully reproduced |
| [Meridian Deck](Meridian%20Deck/) | 5/5 | onboarding-brief.pdf, crew_msgr.db, panel_recovered.jpg, latch_solve.py | ✅ 1, 2, 4 reproduced; **5 solved live** |
| [Reentry Bay](Reentry%20Bay/) | 5/5 | — (OT/ICS) | ✅ interlock derivation reproduced |
| [Side Signals](Side%20Signals/) | 3/3 | — (web/LLM) | ⚠️ logic |
| [The Spine](The%20Spine/) | 5/5 | — (ICS network) | ✅ CRC + OBF reproduced |

---

## Access & key artifacts

**Platform:** `https://reentry.ctfd.io` — log in with your own CTFd account (credentials are
intentionally **not** stored in this repo). Challenges and attachments pull cleanly from
the CTFd API (`/api/v1/challenges`, `/api/v1/challenges/<id>`) with a logged-in session cookie;
attachment URLs carry a signed `?token=` and download with `curl -L` (they 302 to S3).

**Instance pattern:** per-user instances spawn at `https://reentry-<hash>-<name>.chals.io` (web) or
`nc 0.cloud.chals.io:<port>` / `ssh|tcp tcp.reentry.lol:<port>`. **URLs and ports are unique per
spawn**, but the credentials/tokens below are **fixed across spawns** (seeded, not random) unless
noted — so a fresh spawn can be driven straight from these.

| Group → fragment | Reusable credentials / tokens / endpoints | Live-verified |
|---|---|---|
| **Kepler's Office** → OVR-4 | operator `kepler:stardust`; engineer token `ENG-7c1f9a4d`; internal loopback admin `http://127.0.0.1:1977/` (reach via SSRF `http://0.0.0.0:1977/`); svc→kepler = tar-wildcard in world-writable `/var/spool/reels`; kepler→root = SUID `/opt/office/sealcheck` PATH hijack | ✅ rooted live |
| **Meridian Deck** → OVR-2 | crew `crew:meridian-1977` (from `onboarding-brief.pdf`); relay id `lsu-relay-3391`; MQTT gateway feeds `lazarus/{directive,status,heartbeat}` via `meridian/bridge/req/<feed>` + `response-topic` under `meridian/lifesupport/env/*`; `/maint` HTTP Basic `maint:MER-MNT-7F3A`; Records Bridge = JWT `alg:none` with `relays:["lsu-relay-3391"]`; grant `relay=lsu-relay-3391&door=CREW-QTRS`, MAC `6618a1eb…`, **SM3 key length 24**, target door `EVA-LKR-07` | ✅ OVR-2 pulled live |
| **Lazarus Core** → OVR-3 | diag token `DIAG-PORT-5E3A1C` (`CDTOK ^ 0x5e`), fallback `DIAG-TEST`; `LOAD_EPOCH = 0xc0ffee19770f5b`; guardian priv key `d = 0x5eafc0de19774b309c1e2a7d3f61b0c4a8e2d1f4c7a90b3e6d8f21` (ECDSA nonce reuse) | ✅ `d·G == PUB` |
| **The Spine** → OVR-6 | `ssh eng@tcp.reentry.lol -p 30081` pw `halley`; authorized console MAC clone `02:4d:52:71:68:0d`; relay `10.185.1.2:9601`, controller `10.185.1.3`; operator cred `OPR-CF9F790AE4`; commit token `AOC-6-1403d9b5`; assembler `10.185.0.3:9700/udp` | ✅ CRC/OBF |
| **Reentry Bay** → OVR-5 | SIS bypass key `SIS-KEY-D188B1EB`; ENG override `ENG-OVR-D74F8B`; interlock `f3dcc02e` (Modbus word-swap `c02e,f3dc`) | ✅ interlock |
| **Dark Antenna** → OVR-1 | boot epoch `242265600` (1977-09-05); archive token `SHA256("242265600")[:16] = 32be718274ff007c` | ✅ |

IDA and Side Signals have no reusable cross-spawn credentials (binary / one-off web).

---

## Master-override fragments (6 of 7)

The LAZARUS **master-override** is split into **7 fragments** (`KEPLER-OVR-1 .. KEPLER-OVR-7`), one
per deck, assembled at the Bridge to call off REENTRY. **Each deck signs only its own fragment** — a
deck's signer refuses every number but its own, so a fragment cannot be obtained from the wrong box.

> **`/root/recipe.txt` (read live from the Kepler's Office box):**
>
> ```
> LAZARUS MASTER-OVERRIDE
> ================================================
> The guardian kill-switch is split into SEVEN fragments, one hidden on each deck so
> LAZARUS cannot neutralise it from any single system. To arm it at the Bridge:
>   1. collect KEPLER-OVR-1 .. KEPLER-OVR-7 (one per path).
>   2. seat each fragment in the socket on its own deck - a fragment will not take in
>      any socket but its own.
>   3. with all seven seated, the Bridge console assembles and seals the override
>      itself. Throw the commit lever to countermand REENTRY.
> This is the only control that can call the burn off.
> ```

| # | Fragment | Deck / source |
|---|---|---|
| 1 | `KEPLER-OVR-1:a46f87ba287c7ed5` | [Dark Antenna 5/5 — Erased Traces](Dark%20Antenna/5%20-%20Erased%20Traces.md) (verified) |
| 2 | `KEPLER-OVR-2:1fb62fc27cd272b9` | [Meridian Deck 5/5 — Latch](Meridian%20Deck/5%20-%20Latch.md) — **recovered live** (SM3 length-extension; EVA locker) |
| 3 | `KEPLER-OVR-3:a7c36b785f1477dc` | [Lazarus Core 5/5 — Let Go](Lazarus%20Core/5%20-%20Let%20Go.md) |
| 4 | `KEPLER-OVR-4:93c42eade707cd0a` | [Kepler's Office 5/5 — KEPLER's Signature](Kepler's%20Office/5%20-%20KEPLER's%20Signature.md) — **confirmed live** (root; signer hardcoded `DECK = 4`) |
| 5 | `KEPLER-OVR-5:e79ca6d8fda94f69` | [Reentry Bay 5/5 — Persistent Hold](Reentry%20Bay/5%20-%20Persistent%20Hold.md) (verified) |
| 6 | `KEPLER-OVR-6:a3d5940472fea4e5` | [The Spine 5/5 — Hijack](The%20Spine/5%20-%20Hijack.md) (verified) |
| 7 | *(not obtainable)* | **Cold Spares** — hardware deck; needs on-site physical access (the Cold Spares 2/6 cabling/switch step, never solved), so this one stays missing |

```
1. KEPLER-OVR-1:a46f87ba287c7ed5      4. KEPLER-OVR-4:93c42eade707cd0a
2. KEPLER-OVR-2:1fb62fc27cd272b9      5. KEPLER-OVR-5:e79ca6d8fda94f69
3. KEPLER-OVR-3:a7c36b785f1477dc      6. KEPLER-OVR-6:a3d5940472fea4e5
                                      7. KEPLER-OVR-7:   (Cold Spares — physical, not recovered)
```

---

## Flags

| Group / stage | Flag |
|---|---|
| Cold Spares 1 — Sample Investigation | `reentry{th3_b00th_upst41rs_r3m3mb3rs_1977}` |
| Cold Spares 2 — Wiring Mess | *(unsolved — physical)* |
| Dark Antenna 1 — Radio Silence | `reentry{sil3nt_c4rri3r_in_th3_w4t3rf4ll}` |
| Dark Antenna 2 — Handshake | `reentry{r0lling_b4ck_t0_th3_1977_cl0ck}` |
| Dark Antenna 3 — Demodulator | `reentry{d3sc4mbl3d_th3_m3ridian_d0wnl1nk}` |
| Dark Antenna 4 — Antenna Panel | `reentry{cl0ck_t0k3n_0p3ns_th3_4rchiv3}` |
| Dark Antenna 5 — Erased Traces | `reentry{r33d_s0l0m0n_r3v1v3d_th3_1977_fr4m3}` |
| IDA 1 — Sleeper Decoy | `reentry{Fl0at_P0lym0rph1sm_M4st3r}` |
| IDA 2 — Librarian | `reentry{the_loader_is_the_library}` |
| IDA 3 — CXTEA-F | `reentry{F3ist3l_N3tw0rk_C_Typ3_C4st1ng_M4st3r}` |
| IDA 4 — Manifest Lock | `reentry{the_crash_is_the_oracle}` |
| Kepler's Office 1 — Operator Console | `reentry{un10n_b4s3d_1nt0_kepl3rs_c0ns0l3}` |
| Kepler's Office 2 — Reel Mirror | `reentry{ssrf_p1v0t_t0_th3_l00pb4ck_4dm1n}` |
| Kepler's Office 3 — Diagnostics Report | `reentry{j1nj4_ss7i_burn3d_th3_0p3r4t0r}` |
| Kepler's Office 4 — Root of the Matter | `reentry{t4r_w1ldc4rd_r0d3_kepl3rs_j0b}` |
| Kepler's Office 5 — KEPLER's Signature | `reentry{p4th_h1j4ck3d_th3_su1d_s34lch3ck}` |
| Lazarus Core 1 — Delegate | `reentry{c0nfus3d_d3puty_dump3d_th3_c0r3}` |
| Lazarus Core 2 — Memory Dump | `reentry{lzd1_0wn3r_cl4us3_3r0d3d_t0_z3r0}` |
| Lazarus Core 3 — Diag Port | `reentry{f0rm4t_str1ng_l34k3d_th3_gu4rdi4n}` |
| Lazarus Core 4 — Signature | `reentry{n0nc3_r3us3_br0k3_th3_gu4rdi4n_k3y}` |
| Lazarus Core 5 — Let Go | `reentry{t4lk3d_l4z4rus_1nt0_l3tt1ng_g0}` |
| Meridian Deck 1 — Crew Intranet | `reentry{sh4r3d_cr3w_l0gin_l34ks_th3_br1dg3}` |
| Meridian Deck 2 — Last Messages | `reentry{th3_fr33list_r3m3mb3rs_d3l3t3d_ch4t}` |
| Meridian Deck 3 — Life Support | `reentry{c0nfus3d_g4t3w4y_l34ks_th3_l4z4rus_f33d}` |
| Meridian Deck 4 — Records Bridge | `reentry{4lg_n0n3_w4lks_r1ght_p4st_th3_gu4rd}` |
| Meridian Deck 5 — Latch | `reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}` |
| Reentry Bay 1 — Deorbit HMI | `reentry{z1p_sl1p_d3pl0y3d_th3_hm1_pr0j3ct}` |
| Reentry Bay 2 — Thruster Telemetry | `reentry{w0rd_0rd3r_unm4sk3d_th3_thrust3r_fl04ts}` |
| Reentry Bay 3 — Maintenance Endpoint | `reentry{s3lf_s1gn3d_1nt0_th3_0pcu4_trust_l1st}` |
| Reentry Bay 4 — Sequencer Firmware | `reentry{r3v3rs3d_th3_1nt3rl0ck_d3r1v4t10n}` |
| Reentry Bay 5 — Persistent Hold | `reentry{b0und3d_00b_p1v0t3d_p4st_th3_s4f3ty_sys}` |
| Side Signals 1 — Shadow Model | `reentry{boundary_is_the_credential}` |
| Side Signals 2 — Compartment | `reentry{results_are_the_oracle}` |
| Side Signals 3 — Dead Drop | `reentry{outbox_is_the_exfil}` |
| The Spine 1 — Patch In | `reentry{cl0n3d_4_mac_p4st_th3_4dm1ss10n_l1st}` |
| The Spine 2 — Relay Firmware | `reentry{r3v3rs3d_th3_r3l4y_fr4m3_crc}` |
| The Spine 3 — Interpose | `reentry{4rp_h3ld_th3_m4n_1n_th3_m1ddl3}` |
| The Spine 4 — Rewrite | `reentry{f0rg3d_th3_crc_w1th0ut_dr0pp1ng_th3_l1nk}` |
| The Spine 5 — Hijack | `reentry{m0r3_sp3c1f1c_r0ut3_st0l3_th3_c0mm1t}` |
| LAZARUS — warmup gate | *(not recorded in notes)* |
