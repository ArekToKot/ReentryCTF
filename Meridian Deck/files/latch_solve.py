#!/usr/bin/env python3
"""
Meridian Deck 5/5 - Latch: SM3 secret-prefix MAC length-extension attack.

Unlocks KEPLER's EVA locker (door EVA-LKR-07) and returns the clearance token
plus the override fragment KEPLER-OVR-2.

Chain:
  1. KEPLER's grant (from Records Bridge 4/5, alg:none JWT):
       payload = b"relay=lsu-relay-3391&door=CREW-QTRS"
       MAC     = SM3(key || payload)  with |key| = 24  (key is fixed across spawns)
  2. MAC = SM3(key||payload) is a naive secret-prefix MAC -> length-extendable
     (SM3 is Merkle-Damgue1rd). Append "&door=EVA-LKR-07"; the controller parses
     door= into a LIST, so the appended door becomes authorized.
  3. /open rejects the binary glue ("stray bytes"); send the raw grant to /maint,
     which is HTTP Basic (user maint, password MER-MNT-7F3A -- the code recovered
     from the SQLite freelist photo in Meridian Deck 2/5).

Verified live: KEYLEN = 24 unlocks the latch and returns
  reentry{l3ngth_3xt3nsi0n_unl4tch3s_th3_d00r}
  KEPLER-OVR-2:1fb62fc27cd272b9
"""
import ssl, base64, re, urllib.request, urllib.parse

# ---------- SM3 (pure python) with length extension ----------
IV = [0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
      0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]

def rotl(x, n): n &= 31; return ((x << n) | (x >> (32 - n))) & 0xffffffff
def P0(x): return x ^ rotl(x, 9)  ^ rotl(x, 17)
def P1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)
def Tj(j):  return 0x79cc4519 if j < 16 else 0x7a879d8a
def FFj(j, x, y, z): return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))
def GGj(j, x, y, z): return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x & 0xffffffff) & z))

def _cf(V, B):
    W = [0] * 68
    for i in range(16):
        W[i] = int.from_bytes(B[i*4:i*4+4], 'big')
    for i in range(16, 68):
        W[i] = (P1(W[i-16] ^ W[i-9] ^ rotl(W[i-3], 15)) ^ rotl(W[i-13], 7) ^ W[i-6]) & 0xffffffff
    W1 = [(W[i] ^ W[i+4]) & 0xffffffff for i in range(64)]
    A, B2, C, D, E, F, G, H = V
    for j in range(64):
        SS1 = rotl((rotl(A, 12) + E + rotl(Tj(j), j % 32)) & 0xffffffff, 7)
        SS2 = SS1 ^ rotl(A, 12)
        TT1 = (FFj(j, A, B2, C) + D + SS2 + W1[j]) & 0xffffffff
        TT2 = (GGj(j, E, F, G) + H + SS1 + W[j])  & 0xffffffff
        D = C; C = rotl(B2, 9); B2 = A; A = TT1
        H = G; G = rotl(F, 19); F = E; E = P0(TT2)
    return [(V[i] ^ v) & 0xffffffff for i, v in enumerate([A, B2, C, D, E, F, G, H])]

def _pad(mlen):
    bl = mlen * 8
    return b'\x80' + b'\x00' * ((56 - (mlen + 1)) % 64) + bl.to_bytes(8, 'big')

def sm3(msg):
    V = IV[:]
    m = msg + _pad(len(msg))
    for i in range(0, len(m), 64):
        V = _cf(V, m[i:i+64])
    return ''.join('%08x' % x for x in V)

def sm3_extend(mac_hex, orig_len, suffix):
    """Return (new_mac_hex, glue) for SM3(secret||...||glue||suffix) given the
    original MAC and the original message length (bytes)."""
    V = [int(mac_hex[i*8:i*8+8], 16) for i in range(8)]
    glue = _pad(orig_len)
    tail = suffix + _pad(orig_len + len(glue) + len(suffix))
    for i in range(0, len(tail), 64):
        V = _cf(V, tail[i:i+64])
    return ''.join('%08x' % x for x in V), glue

# ---------- self-tests ----------
def _selftest():
    assert sm3(b"abc") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    key = b"K" * 24
    P = b"relay=lsu-relay-3391&door=CREW-QTRS"
    S = b"&door=EVA-LKR-07"
    mac0 = sm3(key + P)
    nm, glue = sm3_extend(mac0, len(key + P), S)
    assert nm == sm3(key + P + glue + S)

# ---------- attack ----------
def solve(latch_url="https://reentry-latch.chals.io/maint"):
    _selftest()
    P   = b"relay=lsu-relay-3391&door=CREW-QTRS"
    MAC = "6618a1ebc84cfd759e4b5cf12316f49bd680839f5e5f02313cb06d141100eb96"
    S   = b"&door=EVA-LKR-07"
    auth = base64.b64encode(b"maint:MER-MNT-7F3A").decode()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    for L in range(1, 65):                       # brute the (unknown) key length
        new_mac, glue = sm3_extend(MAC, L + len(P), S)
        grant = "sm3$" + (P + glue + S).hex() + "$" + new_mac
        data = urllib.parse.urlencode({"grant": grant}).encode()
        req = urllib.request.Request(latch_url, data=data,
                                     headers={"Authorization": "Basic " + auth}, method="POST")
        try:
            body = urllib.request.urlopen(req, timeout=15, context=ctx).read().decode("utf-8", "replace")
        except Exception as e:
            body = str(e)
        if "reentry{" in body.lower() or "ovr" in body.lower():
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
            print(f"[+] KEYLEN = {L}\n{text}")
            return
    print("[-] no key length in 1..64 worked (service down or grant changed)")

if __name__ == "__main__":
    solve()
