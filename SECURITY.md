# Security notes — Enigma – M 10

This is an **experimental Enigma-inspired cipher**, not audited cryptography and not protection for sensitive files.

Argon2id, HKDF-SHA256, HMAC-SHA256, and `SecRandomCopyBytes` are modern primitives. The payload cipher is still a ten-rotor Enigma. Treat a successful encrypt as “encoded under this password or this `.m10key`,” not as AES-GCM.

## Password mode (default)

Argon2id (64 MiB / 3 / 1) turns password + per-file salt into a 32-byte master. HKDF domain tags (`M10-ROTOR-0`…`9`, `M10-REFLECTOR`, `M10-RINGS`, `M10-POSITIONS`, `M10-PLUGS`, `M10-AUTH`) expand into Fisher-Yates rotors, a fixed-point-free reflector, notches, rings, positions, plugs, and the HMAC key.

The `M10PW04` file stores salt, Argon2 parameters, nonce, encrypted name, HMAC, and padded ciphertext. Original/stored sizes and CRC-32 sit inside the rotor ciphertext, not in the public header. Rotors are not stored. HMAC (`M10PW-aad-1`) is encrypt-then-MAC over header + ciphertext and is checked before rotor decrypt or zlib.

New writes always pad: 4 KiB only when both the original file and the unpadded inner payload are under 64 KiB; otherwise 64 KiB. A large compressible file does not look like a 4 KiB blob after zlib. Filenames are stored in a fixed 256-byte field so the public `nameLen` does not track the real name. The on-disk length is therefore a 4 KiB or 64 KiB bucket, not the exact payload. `M10PW01` / `M10PW02` still decrypt and did publish sizes.

A weak password is still weak. Argon2id raises guessing cost; it does not make a short password strong.

## External key mode

You carry a **machine configuration** for the public catalog (order, rings, positions, plugs), not a conventional password. Each unused codebook encrypts once, is written as a sibling `.m10key`, then is replaced. Anyone with both the `.enigmam10` and that `.m10key` can decrypt. The demonstration codebook ships in source and cannot encrypt.

## Internal key mode

The catalog codebook is stored in the archive (`keyMode: internal` + `codebook`). There is no password and no sidecar. Anyone who has the file can decrypt. HMAC still detects bit-flips; it does not keep the key secret. The demonstration codebook cannot encrypt.

## Integrity

| Check | What it is | What it is not |
|-------|------------|----------------|
| CRC-32 of plaintext | Recovery check | Not authentication |
| v2 JSON `authTag` | HMAC of recovered plaintext + interpretation fields, after decrypt | Not encrypt-then-MAC |
| v3/v4 JSON `authTag` | HMAC of header + ciphertext, before decrypt (v4 also binds `createdAt`) | Not AES-GCM |
| `M10PW04` tag | HMAC of binary header + padded ciphertext, before decrypt | Not AES-GCM |
| `M10PW01` / `M10PW02` tag | HMAC of binary header + ciphertext, before decrypt | Not AES-GCM |

**Decrypt** accepts authenticated JSON v2–v7 and `M10PW01`–`M10PW04`. Relabeling as v1 is rejected on that path.

**Legacy Import** is only for genuine v1 JSON. Output is prefixed `UNAUTHENTICATED-`.

## Stepping and reflector

v2 parked-notch stepping is decrypt-only. New writes use the v3 carry cascade. The reflector never maps a symbol to itself (classic Enigma leak); that preserves encrypt == decrypt.

## Threat model (honest)

| Attacker | Password | External key | Internal key |
|----------|----------|--------------|--------------|
| File only | Needs the password | Needs the matching `.m10key` | Can decrypt (codebook is in the file) |
| File + password / `.m10key` | Can decrypt | Can decrypt | Can decrypt |
| Neither | Nothing to decrypt | Nothing to decrypt | Nothing to decrypt |

For real secrets use FileVault, age, GPG, or another audited tool.
