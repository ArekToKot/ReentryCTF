# Cold Spares 2/6 — "Wiring Mess"  ·  ❌ UNSOLVED

**Status:** Not solved. This is the one challenge (39/39) that was never recovered.
**Flag:** — (unknown)

| | |
|---|---|
| Category | Hardware |
| Points | 500 |
| Files | none on the platform (physical hardware challenge) |

> **Challenge brief (official):**
>
> **UPDATE:** *Due to the difficulty of the problem we're narrowing the challenge — please
> find one of the organizers once you have a working cable — this will be enough to solve the
> challenge.*
>
> A length of twisted pair cut out of the station's run, still live at the far end. Whoever
> terminated this cable had never heard of T568A or T568B and would not have cared. Both ends
> agree with each other and with nothing else. Put an end on it and listen.
>
> HARDWARE CHALLENGE — VISIT US FOR HARDWARE.

---

## What the challenge asks for

This is an **on-site hardware challenge**. You are given a physical length of twisted-pair
cable (the kind used for Ethernet). The two ends are wired to a non-standard pinout — not
T568A and not T568B — but the two ends match each other. The task is to build a matching
adapter / re-terminate a cable with the **same custom pinout** so that a network interface
can link up over it and you can capture the traffic ("listen").

Per the organizers' update, the win condition was narrowed: **bring a working cable to an
organizer** and that is enough — no capture/flag-recovery step was required online.

## Why it is not solved here

- It needs **physical hardware** handed out on site ("VISIT US FOR HARDWARE") and an
  organizer to confirm the cable.
- There is no downloadable file or network service, so it cannot be solved remotely or
  after the event closed.

## How it would be approached (notes for completeness)

1. Use a **cable tester** or a multimeter (continuity mode) to map which pin on end A
   connects to which pin on end B. This reveals the custom pinout.
2. Ethernet (10/100BASE-T) only needs two pairs: TX (pins 1–2) and RX (pins 3–6). Gigabit
   needs all four pairs. The pairs must stay **twisted together** (1&2, 3&6, 4&5, 7&8 in the
   standard) to keep the differential signalling clean.
3. Crimp a new end (or an adapter) that maps the custom pinout back to a standard NIC's
   expected pins, keeping each signal pair on a real twisted pair.
4. Plug in, bring the link up (`ip link set ... up`, check for carrier), and capture with
   `tcpdump` / Wireshark to "listen".

> If you later solve it, replace this stub with the full writeup and the recovered flag.
