# Changelog

## 1.3.5

- **Internal key** mode stores the catalog codebook in the archive. No password, no `.m10key`. Password and External key modes are unchanged

## 1.3.4

- Filename field trims on unicode scalar boundaries so a long CJK/emoji name cannot produce an unopenable archive
- Hybrid `payloadOffset + payloadLength` and DensePack `storedLength` use checked arithmetic (no wrapping add)
- Decrypt fuzz: all factory codebooks, authenticated and Legacy Import, JSON v6/v4/v1 and password blobs

## 1.3.3

- Padding bucket uses original file size as well as inner size, so zlib cannot hide a large file in a 4 KiB blob
- Filenames are a fixed 256-byte padded field (512 symbols on Alpha-36 / ASCII-94)
- Removed unused post-ciphertext `appendPad`

## 1.3.2

- Switching suite no longer reuses a plugboard symbol (Base-256 indices were taken modulo 36/94)

## 1.3.1

- Password decrypt of archives larger than 1 MiB no longer fails in `readPrefix` (ciphertext length is checked against the full file, not the 1 MiB header window)
- ENIGMAM10 v6 parse requires 4 KiB-aligned ciphertext
- HMAC compare is constant-time; invalid UTF-8 plaintext names fail closed
- Header-biased parser fuzz, `readPrefix` fuzz, and a streaming password round-trip

## 1.3.0

- Automatic size padding on new writes: 4 KiB, or 64 KiB when the inner payload is 64 KiB or larger
- Exact original/stored sizes and CRC-32 moved inside the ciphertext (`M10PW03` / ENIGMAM10 v6)
- `M10PW01`, `M10PW02`, and ENIGMAM10 v2–v5 still decrypt
- Parser fuzz: truncated headers, absurd lengths, bad Argon2 fields, unknown flags, random mutations

## 1.2.2

- Password mode no longer validates hidden catalog plugs (ASCII-94 encrypt was blocked)
- ASCII-94 plugboard pairs split on whitespace only (`,` and `;` are alphabet symbols)
- README, FORMAT, SECURITY, and in-app help match password binary, ENIGMAM10 v4, and carry stepping

## 1.2.1

- Recognize opaque `M10PW01` password archives in header peek so Decrypt no longer reports “not a valid archive”

## 1.2.0

- Password mode writes an opaque `M10PW01` binary (salt, Argon2 params, nonce, sizes, name, HMAC, ciphertext). External-key JSON archives are unchanged.

## 1.1.1

- **ENIGMAM10 v4:** v3 encrypt-then-MAC transcript also binds `createdAt`. v3 files still decrypt.

## 1.1.0

- **ENIGMAM10 v3** writes: carry-only rotor stepping, unbiased Alpha-36/ASCII-94 nonce positions, encrypt-then-MAC (header+ciphertext before decrypt).
- v2 decryption is unchanged (parked-notch stepping, plaintext HMAC).
- `SecRandomCopyBytes` failure aborts encryption (no Swift RNG fallback).

## 1.0.9

- External key mode is single-use: after encrypt, that machine is written to the `.m10key` sidecar and a new unused machine is generated. Decrypt still uses the sidecar.

## 1.0.8

- **Password mode** (default): Argon2id (64 MiB / 3 / 1) → master seed → domain-separated Fisher-Yates rotors. Salt + KDF params in the archive; no rotors stored.
- Current codebook/sidecar workflow is **External key** mode.

## 1.0.7

- Encrypt writes a matching `.m10key` next to each `.enigmam10`; decrypt loads that sidecar when present
- Sidecar write falls back when atomic replace fails (cloud/NAS); Finder selects both files

## 1.0.6

- Random codebook every launch; no longer restored from Application Support. Save a `.m10key` to keep a session key.

## 1.0.5

- Base-256 decrypt accepts pre-1.0.4 raw encrypted filenames (unicode-scalar bytes, then `processBytes`) as well as `hex:` fields

## 1.0.4

- Base-256 encrypted filenames use `processBytes` and JSON-safe `hex:` encoding so CR/LF (0D 0A) cannot collapse in Swift `String`

## 1.0.3

- **Base-256** cipher suite: every byte is a symbol; 1:1 packing after optional zlib. Rings, positions, and plugs are hex.

## 1.0.2

- Decrypt opens authenticated v2 only; relabeling v2 as v1 no longer skips HMAC
- **Legacy Import** recovers v1 files explicitly; output is named `UNAUTHENTICATED-`

## 1.0.1

- Archive format **ENIGMAM10 v2**: `messageNonce` and `authTag` are required; stripping them fails closed
- v2 HMAC covers interpretation fields (including `kind`) plus filename and payload
- v1 archives remain readable

## 1.0.0

- First release of **Enigma – M 10**
- Custom 10-rotor M10 catalog (I–X, UKW-M10 / UKW-M10B) for Alpha-36 and ASCII-94
- EnigmaVault Alpha-36 and ASCII-94 alphabets, pair encoding, and dense packing
- `.enigmam10` archives (`ENIGMAM10 v1`) with **no machine settings in the file**
- Large-file streaming (≥ 1 MiB): hybrid JSON + binary payload; 2 GiB per file / 16 GiB archive
- Personal codebook by default; demonstration codebook is public and cannot encrypt
- Per-archive `messageNonce` derives separate filename/payload start positions (legacy archives without a nonce still decrypt)
- Stepping documented as notch-of-neighbour, not a true odometer
- Optional `.m10key` save/load
- File and folder encrypt/decrypt, CRC-32 codebook check, encrypted names
