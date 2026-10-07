# Dark Antenna 1/5 — "Radio Silence"

**Flag:** `reentry{sil3nt_c4rri3r_in_th3_w4t3rf4ll}`

| | |
|---|---|
| Category | Audio steganography / forensics |
| Tools | `file`, `xxd`, `strings`, `sox`, `python3` (numpy, scipy) |
| Files | [files/capture.wav](files/capture.wav) · pre-made images: [files/flag_spectrogram.png](files/flag_spectrogram.png), [files/full_spectrogram.png](files/full_spectrogram.png) |

> **Challenge brief:** MERIDIAN's deep-space antenna never really went quiet. Comms logged one
> last capture before the module was sealed — a flat, hissing carrier that reads as dead air on
> a scope. LAZARUS filed it as noise. It isn't. There's a second, much fainter carrier riding
> the band. You won't hear it, and you won't see it in the waveform — but no operator of the
> period would ever have trusted the waveform on its own.

**Short version:** the flag is drawn into the **spectrogram** (the "waterfall"), not hidden in
the bytes. Make a spectrogram and read it.

Run all commands from the folder that holds `capture.wav`.

---

## 1. Identify the file

```bash
file capture.wav
# capture.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 16000 Hz
ls -la capture.wav
# 192044 bytes
```

Math: 6 s × 16000 samples/s × 2 bytes = **192000 data bytes**, plus a **44-byte** WAV header =
192044. Nothing is appended after the audio.

```bash
xxd capture.wav | head -5
```

A standard header: `RIFF`, `WAVE`, `fmt `, then `data`. No extra `LIST`/`INFO` chunks to hide
text in.

```bash
strings -n 6 capture.wav | head -30   # only junk from the audio samples; no plaintext flag
```

---

## 2. Audio statistics

```bash
sox capture.wav -n stat
```

```
Length (seconds):      6.000000
RMS     amplitude:     0.252893
```

6 seconds of a hum with noise. For CTF audio tasks the next step is almost always the same:
**spectrogram**.

---

## 3. Spectrogram of the whole file

```bash
sox capture.wav -n spectrogram -o spec.png -x 1600 -y 800
xdg-open spec.png
```

The spectrogram shows:
- **~3.8–4.6 kHz:** the text `reentry{sil3nt_c4rri3r_in_th3_w4t3rf4ll}`
- **~1.8–2.5 kHz:** the text `SYNC ASM: 1ACFFC1D`
- **320 Hz and 640 Hz:** two thin horizontal lines — steady tones for the full 6 seconds

The text is "painted" in the frequency domain. The flag title confirms it: *silent carrier in
the waterfall* ("waterfall" is the radio term for a spectrogram).

---

## 4. Zoom in on the flag text

On the full spectrogram the characters are small and easy to misread (`l` vs `1`, `3` vs `e`).
Cut out just the flag band and draw it at high resolution:

```bash
sox capture.wav -n remix 1 sinc 3000-5000 spectrogram -o flaga.png -x 2400 -y 400 -z 60 -r -l
xdg-open flaga.png
```

| Parameter | Meaning |
|---|---|
| `remix 1` | take channel 1 (the file is mono anyway) |
| `sinc 3000-5000` | band-pass filter, keep only 3–5 kHz |
| `-z 60` | 60 dB dynamic range, the background drops out |
| `-r` | raw, no axes/legend |
| `-l` | light background, easier to read |

It reads, without doubt:

```
reentry{sil3nt_c4rri3r_in_th3_w4t3rf4ll}
```

> **Verification note:** I ran exactly this command on `files/capture.wav` and read the flag off
> the image. The result is saved as [files/flag_spectrogram.png](files/flag_spectrogram.png).

The second text zooms the same way (`SYNC ASM: 1ACFFC1D`):

```bash
sox capture.wav -n remix 1 sinc 1500-2800 spectrogram -o sync.png -x 2400 -y 400 -z 60 -r -l
```

`1ACFFC1D` is the standard **Attached Sync Marker (ASM)** from CCSDS satellite protocols — a
bit pattern that marks the start of a frame. It is a hint toward the later stages (where the
real framed signal lives); in this stage it is just a label, not data.

---

## 5. Dead ends (checked for completeness)

- **320/640 Hz tones** — clean sine and its second harmonic; no AM/OOK or phase modulation
  (I/Q check shows amplitude varies by a few percent and phase by a fraction of a radian). No
  data.
- **LSB stego** — bits 0–3 of the samples are ~50% ones and look random; no `1ACFFC1D` marker,
  no `reentry`. Nothing hidden in the low bits.
- **Noise spectrum** — only the 1.75–2.5 kHz and 3.5–4.5 kHz bands are lifted (where the two
  texts are drawn). The last 0.5 s (no text) is flat white noise. No sub-noise transmission.

---

## 6. GUI alternative (no terminal)

- **Audacity:** open the file → click the track name → **Spectrogram** → set 0–8000 Hz and
  window size 1024/2048. The flag shows near 4 kHz.
- **Sonic Visualiser:** open the file → *Layer → Add Spectrogram*. The text shows on the
  waterfall immediately.

---

## 7. Summary

| Location | What is there | Data? |
|---|---|---|
| Spectrogram, 3.8–4.6 kHz | `reentry{sil3nt_c4rri3r_in_th3_w4t3rf4ll}` | **yes, the flag** |
| Spectrogram, 1.8–2.5 kHz | `SYNC ASM: 1ACFFC1D` | hint for later stages |
| Tones 320/640 Hz | clean sine + harmonic | no |
| Sample LSBs | random noise | no |

Shortest path to the flag:

```bash
sox capture.wav -n remix 1 sinc 3000-5000 spectrogram -o flaga.png -x 2400 -y 400 -z 60 -r -l && xdg-open flaga.png
```

**Lesson:** for any audio task, make a spectrogram first. Text or an image painted into the
spectrum is one of the most common CTF tricks. The flag says it plainly: *silent carrier in the
waterfall*.

🚩 **Flag:** `reentry{sil3nt_c4rri3r_in_th3_w4t3rf4ll}`

> **Next:** [2 - Handshake](2%20-%20Handshake.md)
