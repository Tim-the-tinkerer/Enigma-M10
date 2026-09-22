# Enigma – M 10

Native macOS app that encrypts files and folders to a **`.enigmam10`** archive with a custom **ten-rotor Enigma**. Cipher suites: **Alpha-36**, **ASCII-94** (from EnigmaVault), and **Base-256**. Default suite is Base-256.

**Experimental Enigma** — not FileVault, age, or GPG. Argon2id / HKDF / HMAC are modern; the payload cipher is still a rotor machine.

![Version](https://img.shields.io/badge/version-1.5.0-blue)
![macOS](https://img.shields.io/badge/macOS-13%2B-lightgrey)

## Three key modes

**Password (default).** A per-file salt and Argon2id (64 MiB / 3 / 1) derive the entire machine (rotors, reflector, notches, rings, positions, plugs, HMAC key). The archive is an opaque binary (`M10PW04`): salt, Argon2 parameters, nonce, encrypted name, HMAC, padded ciphertext. Exact sizes and CRC-32 are inside the ciphertext. No JSON, no rotors, no `.m10key`. Decrypt with the same password.

**External key.** You carry a machine, not a password. The on-screen codebook is unused. Encrypt writes that configuration to a sibling **`.m10key`** (catalog rotor *order*, rings, positions, plugs — wirings stay in the public catalog), then generates a new unused machine. Decrypt loads the sidecar. The demonstration codebook is public and cannot encrypt.

**Internal key.** Same catalog codebook, stored inside the `.enigmam10` (JSON `codebook`). No password and no sidecar. Anyone who has the file can decrypt. The demonstration codebook cannot encrypt.

## Features

- **M10 rotors** — 10 stepping rotors (I–X) plus `UKW-M10` / `UKW-M10B` (external key) or Argon2id-derived wirings (password)
- **v3/v4 carry cascade** — a rotor steps only when its right neighbour is itself stepping and on a notch (v2 parked-notch decrypt is preserved)
- **Suites** — Alpha-36, ASCII-94, Base-256 (default), Base-512 (9 bits/symbol)
- **Streaming** — files ≥ 1 MiB pack from disk; up to 2 GiB payload / 16 GiB archive
- **Encrypt-then-MAC** on v3+ JSON and on `M10PW04` (header + ciphertext, before rotor decrypt)
- **Automatic padding** — 4 KiB, or 64 KiB when the original file or inner payload is 64 KiB or larger; filenames are a fixed-width field
- Drag-and-drop, Open… (⌘O), Encrypt / Decrypt All (⌘↩)
- Encrypted filenames by default

## Requirements

- macOS 13 or later
- Swift toolchain (`xcode-select --install` if needed)

## Build & run

```bash
cd ~/Apps-Usefull/Enigma-M10
chmod +x build-app.sh run.sh
./build-app.sh       # builds EnigmaM10.app and opens it
```

```bash
./build-app.sh --no-launch
swift run EnigmaM10TestRunner
```

Use **`~/Apps-Usefull/Enigma-M10/EnigmaM10.app`**. Other copies on disk may be older.

## How it works

Each symbol goes through the plugboard, ten rotors forward, the reflector, ten rotors back, and the plugboard again. Reciprocal: encrypting ciphertext with the same start positions restores the plaintext. The reflector is fixed-point-free (a symbol never encrypts to itself).

Payloads: optional zlib, then dense-36 / dense-94 packing, or 1:1 for Base-256.

**Password files** sniff as `M10PW04` (`M10PW03` / `M10PW02` / `M10PW01` still decrypt). **External-key files** sniff as `ENIGMAM10 v7` (JSON, optional binary region; v2–v6 still decrypt). EnigmaVault cannot open these files.

## How to use

### Password encrypt

1. Key = **Password**, enter the password
2. Suite (Base-256 is default)
3. Drop files or folders → Encrypt

### Password decrypt

Stay in Password mode with the same password, drop the `.enigmam10`.

### External key

1. Key = **External key**
2. Encrypt → `.enigmam10` + `.m10key` beside it (that machine is then burned)
3. Decrypt: drop the archive; the sidecar is loaded automatically

**Legacy Import…** is only for genuine unauthenticated v1 JSON files. Output is named `UNAUTHENTICATED-`.

## Demonstration codebook (external key, public)

| Field | Alpha-36 |
|-------|----------|
| Rotors | X-VII-III-IX-I-VI-II-VIII-V-IV |
| Reflector | UKW-M10 |
| Rings | `T7O6AR65JS` |
| Positions | `ZENRR8AQVH` |
| Plugs | A0 B1 C2 D3 E4 F5 G6 H7 I8 J9 KL MN |

Self-test: `00000` → `V661T`. ASCII-94 and Base-256 factories are in **FORMAT.md**.

## Documents

| File | What it is |
|------|------------|
| [FORMAT.md](FORMAT.md) | On-disk `M10PW04` and `ENIGMAM10 v7` (plus older decrypt) |
| [SECURITY.md](SECURITY.md) | Threat model; CRC vs HMAC; what this is not |
| [CHANGELOG.md](CHANGELOG.md) | App versions |

## Troubleshooting

- **“Not a valid archive”** on a password file — that copy of the app did not sniff `M10PW04`. Use this tree’s `EnigmaM10.app` (1.5.0+).
- **ASCII-94 “Each plugboard pair must be two symbols”** in Password mode — 1.2.1 and earlier validated hidden catalog plugs. `,` and `;` are alphabet symbols; pairs are space-separated. 1.2.2 encrypts without that check.
- **No `.m10key` next to a password archive** — password mode does not write a sidecar. External key mode writes `stem.m10key` next to `stem.enigmam10`.
- **Lost `.m10key`** — that unused machine is gone. The matching archive cannot be recovered from the app.
