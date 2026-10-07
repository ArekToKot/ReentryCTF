# Public TCP protocol

The event endpoint is a tracked Linux/amd64 container. Its TCP wrapper sends
these exact ASCII bytes before reading client data and starts one target
process when a request begins:

```text
{"task":"archive-terminal","frame":"u16le+payload"}
input>
```

The newline after `input>` is part of the announcement. There are no other
pre-input bytes.

After the announcement, the connection is a byte stream with this contract:

1. The client sends an unsigned 16-bit little-endian length `L`.
2. It sends exactly `L` first-stage bytes, where `73 <= L <= 512`.
3. If the first stage invokes the supplied exact-read primitive, the next bytes
   on the same connection are consumed as its second stage. That second stage
   has no delimiter or additional length prefix; its required length is chosen
   by the first-stage chain.
4. TCP packet boundaries have no meaning. The service reads exact byte counts,
   so either stage may be split or coalesced across packets.
5. EOF before an exact read completes is a failed request and returns no proof.
   One connection handles one request and closes when its target exits.

An idle connection closes after ten seconds if it sends no first byte. After
the first byte, an individual inactive read has a ten-second timeout, and the
whole request has a sixty-second deadline. Prepare your payload before opening
the connection; these limits do not change byte-stream framing.

On the intended path the target writes exactly 257 bytes: the UTF-8 proof,
followed by a NUL byte and NUL padding. The submitted value is the byte sequence
before the first NUL; no newline is promised.

The supplied ELF and loader are the process _behind_ this TCP wrapper. When run
directly for local analysis they intentionally emit no announcement; send the
same `u16le + first stage + second stage` stream to their standard input.
