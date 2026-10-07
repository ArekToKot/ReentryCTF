# Cargo lock - manifest interface

The event endpoint is the tracked Linux/amd64 container the lock runs in. The
supplied ELF is that same binary, so anything you measure in it holds on the
service.

## Session

On connect the lock sends its banner and then a prompt, as these exact bytes:

```text
MERIDIAN CARGO LOCK  manifest interface  rev 4.2
cycle <n>   faults <m>
> 
```

The trailing `> ` has no newline after it. One command per line, `\n` or
`\r\n`, and the lock answers each with a prompt again.

| Command            | Effect                                                    |
| ------------------ | --------------------------------------------------------- |
| `LOAD <manifest>`  | Submit one encoded manifest (see below)                   |
| `LIST`             | Crate index. Needs a manifest the lock accepted first     |
| `STAT`             | Lock status, cycle and fault count                        |
| `QUIT`             | Close                                                     |

A connection serves one command at a time, in order, and stays open for as many as
you care to send. It closes on `QUIT`, on end of input, or when a transfer faults.

## Encoding

`<manifest>` is the manifest body in the station's base32: five bits per
character, most significant bits first, the final group zero-padded. `=` is
accepted and ignored. The character table is **not** RFC 4648 - it is a fixed
32-character table carried in the binary.

A character outside the table is rejected with
`manifest rejected: encoding`.

## Manifest body

Little-endian, no alignment padding:

| Offset   | Size       | Field                                            |
| -------- | ---------- | ------------------------------------------------ |
| `0`      | 4          | magic, ASCII `MRDN`                              |
| `4`      | 2          | crate count                                      |
| `6`      | 2          | `name_len`, declared length of the name field    |
| `8`      | `name_len` | crate name                                       |
| `8+name_len` | 32     | seal                                             |

The decoded body must be at least 40 bytes, and `8 + name_len + 32` must not
run past the end of what you sent - otherwise
`manifest rejected: declared length past end of manifest`.

The **seal** is 32 bytes computed by the lock over every byte of the body
before it, keyed by a 32-byte value the lock draws at startup and never
transmits. A manifest whose seal does not match is answered with
`seal mismatch`; the manifest is not loaded and `LIST` stays unauthorised.

## Faults and cycles

Each transfer runs in its own child process, so a transfer that faults closes
only its own connection - the lock keeps listening. The banner's `faults`
counter reports how many transfers have ended abnormally.

After enough faults the lock recycles itself: it reports `lock recycling`,
restarts, and the `cycle` number in the banner increments. **Anything you
measured about the previous cycle stops being true when the cycle changes.**
Watch the banner.

## Running it yourself

The supplied binary is the service, not a stub. It needs the sealed value in
its environment and listens on port 9000:

```sh
FLAG='reentry{local_test}' ./manifest-lock
```

Run locally it behaves identically, including the banner, so you can develop
against your own copy before touching the event instance.
