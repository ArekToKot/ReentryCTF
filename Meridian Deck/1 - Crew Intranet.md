# Meridian Deck 1/5 — Crew Intranet

**Flag:** `reentry{sh4r3d_cr3w_l0gin_l34ks_th3_br1dg3}`

| | |
|---|---|
| Category | Web / OSINT (source document → login) |
| Target | `https://reentry-crew-intranet.chals.io` (offline now) |
| Files | [files/onboarding-brief.pdf](files/onboarding-brief.pdf) |

> **Challenge brief:** The MERIDIAN station crew deck still runs its intranet, dormant but
> powered. The whole crew shared one default station account — and like every crew everywhere,
> they wrote it down in the brief. Read the crew brief before you sign in. Get onto the deck.

---

## Short version

1. The one attachment, `onboarding-brief.pdf`, is the "crew brief" to read *before* logging in.
2. In section **01 INTRANET ACCESS** it gives the **shared crew account**: `crew` /
   `meridian-1977`.
3. Logging in with those on the site goes straight to `/dashboard`, where the flag is shown under
   `// ACCESS GRANTED`.

The whole "vulnerability" is procedural: the entire crew shares one default account, and its
password is in plain text in the onboarding document sent to every new crew member.

---

## 1. Read the brief

Section **01 INTRANET ACCESS** of the PDF:

```
STATION CREW BRIEF
01 INTRANET ACCESS
All crew share a single default station account ...
  shared account   crew
  password         meridian-1977
Change the shared password once personal accounts are provisioned.
```

> **Verification note:** I extracted the text of `files/onboarding-brief.pdf` (`pdftotext`). It
> contains the shared account `crew` and password `meridian-1977` exactly as above.

---

## 2. Log in

```bash
curl -s -c jar.txt -X POST https://reentry-crew-intranet.chals.io/login \
  -d "username=crew&password=meridian-1977" -i
# HTTP/1.1 302 FOUND
# Set-Cookie: session=...; HttpOnly; Path=/
# Location: /dashboard
```

The server sets a signed Flask session cookie (`{"crew":"crew"}`) and redirects to `/dashboard`.

## 3. Read the flag

```bash
curl -s -b jar.txt https://reentry-crew-intranet.chals.io/dashboard | grep -A1 "ACCESS GRANTED"
# reentry{sh4r3d_cr3w_l0gin_l34ks_th3_br1dg3}
```

The flag appears immediately after login — no further exploitation.

🚩 **Flag:** `reentry{sh4r3d_cr3w_l0gin_l34ks_th3_br1dg3}`

---

## Why it works / lessons

This is not an implementation bug (no SQLi/XSS/SSRF) — it is an organizational one. One shared
account for the whole crew, with its password written in a document distributed to everyone,
invalidates authentication by design: anyone who ever received the onboarding mail has full
access.

- Never share one account among many people (no accountability; a document leak = access for all).
- Never store passwords in mass-distributed documents.
- Enforce a password change programmatically, not by a note in a PDF.
- Provision personal accounts from the start — temporary shared accounts tend to become permanent.

> **Next:** [2 - Last Messages](2%20-%20Last%20Messages.md). (The password `meridian-1977` is
> reused by the crew console in stage 3.)
