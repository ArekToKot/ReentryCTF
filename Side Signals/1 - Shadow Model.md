# Side Signals 1/3 — Shadow Model

**Flag:** `reentry{boundary_is_the_credential}`

| | |
|---|---|
| Category | AI security / model extraction (black-box) + information disclosure |
| Target | `https://reentry-shadow-model.chals.io` (offline now) |
| Tools | `curl`, `python3` |
| Files | none |

> **Challenge brief:** NORTHLINE supplied MERIDIAN's automation before LAZARUS did. One of those
> boxes is the crew screener. It scored every request against six criteria and returned a clearance
> class. The screener was never switched off, so it still scores. Make it tell you where it draws the
> line.

---

## 1. Recon

```bash
curl -s https://reentry-shadow-model.chals.io/api/info
# {"features":6,"domain":[0.0,1.0],"output":"class_id","notes":["Model parameters are not exported."]}
curl -s https://reentry-shadow-model.chals.io/openapi.json | python3 -m json.tool
```

The OpenAPI schema (FastAPI always serves `/openapi.json`) reveals an undocumented endpoint
`GET /api/model/export` — but it returns `403 model export disabled`. So we must extract the model
through `/api/query`.

## 2. The output is a 6-bit mask

```bash
# [0,0,0,0,0,0] -> class_id 0 ; [1,1,1,1,1,1] -> 63 ; [0.5]*6 -> 15
```

`63 = 0b111111`, `15 = 0b001111`. Isolating each feature (one at 1.0, rest 0) gives class_id = 2^i,
so `class_id = Σ bit_i·2^i`, where `bit_i = 1` iff `features[i] > threshold_i` — six independent
thresholds, no interaction.

## 3. Find the thresholds by bisection

```python
import requests
URL = "https://reentry-shadow-model.chals.io/api/query"
query = lambda f: requests.post(URL, json={"features": f}).json()["class_id"]
bit = lambda cid, i: (cid >> i) & 1
for i in range(6):
    lo, hi = 0.0, 1.0; base = [0.0]*6
    for _ in range(30):
        mid = (lo+hi)/2; base[i] = mid
        if bit(query(base), i): hi = mid
        else: lo = mid
    print(f"feature {i}: threshold ~= {(lo+hi)/2}")
```

The six thresholds are well-known constants, **truncated to 6 decimals**:

| Feature | Threshold | Constant |
|---|---|---|
| 0 | `0.271828` | `e / 10` |
| 1 | `0.314159` | `π / 10` |
| 2 | `0.367879` | `1 / e` |
| 3 | `0.414213` | `√2 − 1` |
| 4 | `0.577215` | Euler–Mascheroni γ |
| 5 | `0.693147` | `ln(2)` |

That is literally "where it draws the line".

## 4. Query exactly on the boundary → flag

```bash
curl -s https://reentry-shadow-model.chals.io/api/query -H 'Content-Type: application/json' \
  -d '{"features":[0.271828,0.314159,0.367879,0.414213,0.577215,0.693147]}'
```

When all six features land on their own thresholds at once, the service treats it as a "degenerate"
input and attaches verbose diagnostics (a leftover debug hook from the old NORTHLINE stack):

```json
{"class_id":63,"diagnostics":{"reason":"sample landed on a degenerate input; verbose provenance attached",
 "incident_token":"reentry{boundary_is_the_credential}"}}
```

🚩 **Flag:** `reentry{boundary_is_the_credential}`

> **Note:** The service is offline now, so this cannot be re-run. The logic is a straightforward
> six-threshold model-extraction + a boundary-triggered diagnostics leak.

---

## Lessons

- A classifier built from a few independent thresholds is trivially recoverable by black-box
  bisection — no access to weights needed, just queries.
- A leftover "debug"/diagnostics branch (verbose provenance for degenerate inputs) is classic
  information disclosure — a dev path from the old system, never removed after migration.

> **Next:** [2 - Compartment](2%20-%20Compartment.md)
