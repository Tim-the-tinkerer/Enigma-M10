# Enigma – M 10 archive format

**App version:** 1.5.0

Two on-disk shapes share the `.enigmam10` extension. Sniff the first bytes:

| Magic | Mode | Notes |
|-------|------|--------|
| `M10PW04` | Password | Opaque binary. Current password **write** path (v7). |
| `M10PW03` | Password | v6 decrypt. Base-512 uses 1–2 notches (with ~20-notch fallback). |
| `M10PW02` | Password | Leftover decrypt. Public sizes; optional pad flags. |
| `M10PW01` | Password | Legacy decrypt. Public sizes, no padding. |
| `ENIGMAM10 vN` | External key, Internal key (and old JSON password files) | UTF-8 JSON ± binary region. Current **write** is **v7**. v1–v6 remain readable. |

Password and External Key modes do not embed machine settings. Internal Key mode stores its catalog codebook in the archive.

This is not EnigmaVault (`ENIGMAVAULT vN`).

## 1. Password binary (`M10PW04`)

Current password-mode output. Big-endian. Unknown flag bits are rejected.

```
u8[7] magic          "M10PW04"
u8    flags          bit0 name encrypted, bit2 folder, bits3–4 suite
                     (0=alpha36, 1=ascii, 2=base256, 3=base512). Other bits must be 0.
u32   memoryKiB      Argon2id memory (default 65536)
u32   iterations     Argon2id t_cost (default 3)
u8    parallelism    default 1
u8    hashLength     default 32
u8    saltLen
u8    salt[saltLen]
u8    nonce[16]
u16   nameLen        Base-256: 256; Alpha-36 / ASCII-94: 512; Base-512: 456
u8    name[nameLen]  256-byte name field (u16be length + UTF-8 + random pad),
                     then pair-encoded (Alpha-36 / ASCII-94) or 9-bit packed
                     (Base-512: 228 symbols × 2 UTF-8 bytes = 456), then optionally rotor-encrypted
u8    authTag[32]    HMAC-SHA256
u8    ciphertext[]   Enigma(inner ‖ random padding), length a multiple of 4096
```

Inner plaintext (before padding and rotor encryption):

```
u32   crc32          IEEE of original plaintext
u64   originalBytes
u64   storedBytes    packed wire size
u8    innerFlags     bit0 zlib; other bits must be 0
u8    packed[]       storedBytes of packed payload (Base-256 bytes, or dense symbols)
```

Padding is automatic: 4 KiB only when **both** the original file and the unpadded inner payload are under 64 KiB; otherwise 64 KiB. zlib cannot drop a large file into a 4 KiB bucket. A full extra block is added when the unpadded length is already aligned. Exact original and packed sizes are not in the public header. Ciphertext length is always a multiple of 4096. The public name field is a fixed 256-byte padded filename (512 symbols on Alpha-36 / ASCII-94), so name length is not visible.

HMAC label `M10PW-aad-1` over (header through `name`) ‖ `0x00` ‖ ciphertext, key = HKDF(`M10-AUTH`) from Argon2id. Verified **before** rotor decrypt or zlib.

Password + stored salt rebuilds rotors, reflector, notches, rings, positions, plugs. Filename vs payload start positions still use the nonce (unbiased). Stepping is the v3 carry cascade.

On-disk basename is the nonce in hex, not the original name.

`M10PW02` / `M10PW01` still decrypt. Older JSON password archives (`"keyMode":"password"` + `kdf` in `ENIGMAM10`) still decrypt.

## 2. External-key JSON (`ENIGMAM10 v7`)

```
ENIGMAM10 v7
{ compact JSON, sorted keys, ISO-8601 dates }
[optional binary ciphertext]
```

| Field | Meaning |
|-------|---------|
| `version` | Must match header (`1`–`7`). New writes: **7**. v7 Base-512 uses ~20 notches; v6 Base-512 uses 1–2 (decrypt also tries ~20). |
| `kind` | `file` or `folder` |
| `cipherSuite` | `alpha36`, `ascii`, `base256`, or `base512` |
| `ciphertext` | Inline symbols (small Alpha-36 / ASCII-94). Omitted when hybrid. v6 ciphertext is padded inner. |
| `createdAt` | ISO-8601 UTC; bound in v4+ HMAC |
| `payloadOriginalBytes` / `payloadStoredBytes` | v6 writes `0`; real sizes are inside the ciphertext. Older versions store the true sizes. |
| `payloadCodec` | omitted on v6; `zlib` or omitted on older files |
| `crc32` | v6 writes `0`; real CRC is inside the ciphertext |
| `encryptedFilename` / `originalFilename` | Name handling |
| `payloadOffset` / `payloadLength` | Hybrid binary region (padded length on v6) |
| `messageNonce` | Required on v2+ (16-byte hex) |
| `authTag` | Required on v2+ |
| `keyMode` | `password`, `external`, or `internal`. Omitted on old files (treated as external). |
| `codebook` | Catalog settings. Required for `internal`; forbidden on password/external. |

**Forbidden top-level JSON keys:** `configuration`, `rotorNames`, `reflector`, `rings`, `positions`, `plugPairs`. Internal mode nests those under `codebook`.

### HMAC (JSON)

- **v2:** recovered plaintext, after decrypt. Covers kind and other interpretation fields.
- **v3:** encrypt-then-MAC, header fields + ciphertext, before decrypt. No `createdAt`.
- **v4:** v3 plus canonical ISO-8601 `createdAt`.
- **v6:** v4 over the padded ciphertext; public size fields are zeros.

### Decrypt policy

Normal **Decrypt** accepts authenticated v2–v7 JSON and `M10PW01`–`M10PW04`. Relabeling v2+ as v1 is rejected on that path.

**Legacy Import** is only for genuine v1 JSON (no required HMAC). Output names get the prefix `UNAUTHENTICATED-`. v2+ is rejected on that path.

### Hybrid streaming (JSON)

Files ≥ 1 MiB (and folder ZIPs of that size): zlib if it shrinks → dense pack → inner header + pad → M10, then binary after the JSON line. Limits: 2 GiB payload, 16 GiB archive. v6+ ciphertext length is a multiple of 4096 (enforced on parse for `M10PW03`/`M10PW04` and ENIGMAM10 v6+).

## 3. Cipher suites

### Alpha-36

`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`. Dense: 17 bytes → 27 symbols. Filename: two symbols per byte.

### ASCII-94

Printable ASCII `0x21`–`0x7E` (no space), case-sensitive. Dense: 17 bytes → 21 symbols. Plugboard tokens are separated by **whitespace only** (`,` and `;` are alphabet symbols). Suggested names map `\ / : * ? " < > |` to `_`.

### Base-256

Every byte is a symbol; packing is 1:1 after optional zlib. JSON encrypted names use `hex:` plus hex digits (`processBytes` on `Data`). Pre-1.0.4 raw JSON names still decrypt via unicode scalars so CR/LF stay two bytes. Password binary stores filename ciphertext as raw bytes.

## 4. Machine

Signal path: plugboard → step → rotors right-to-left → reflector → rotors left-to-right → plugboard.

**Stepping**

- **v2 parked-notch (decrypt only):** step if the right neighbour *sits* on a notch.
- **v3+ carry cascade (writes):** step only if that neighbour is *itself stepping* and on a notch. Rightmost always steps.

**Nonce positions:** v2 `SHA256 byte % n` (biased for 36 and 94). v3+ rejection sampling. Base-256 is unbiased in both.

Reflector is a fixed-point-free involution (never encrypts a symbol to itself). Encrypt == decrypt.

External-key wirings are the public catalog. Password mode derives new permutations from Argon2id.

### Factory Alpha-36 (external key, public)

```
rotors:     X-VII-III-IX-I-VI-II-VIII-V-IV
reflector:  UKW-M10
rings:      T7O6AR65JS
positions:  ZENRR8AQVH
plugPairs:  A0 B1 C2 D3 E4 F5 G6 H7 I8 J9 KL MN
```

Self-test: `00000` → `V661T`.

### Factory ASCII-94

```
rotors:     X-VII-III-IX-I-VI-II-VIII-V-IV
reflector:  UKW-M10
rings:      k#M9q+R5b!
positions:  N4p&W1h^C~
plugPairs:  A0 B1 C2 D3 E4 F5 G6 H7 I8 J9 K{ L}
```

### Factory Base-256

Rings/positions/plugs are hex (20 hex digits; 4-hex-digit pairs). See `M10Configuration.base256Factory` in source.

## 5. Folders

Packed with `ditto -c -k --keepParent` (ZIP), then encrypted as one payload (`kind=folder` or the binary folder flag).

## 6. External-key codebook (`.m10key`)

JSON, never inside the archive. Holds `cipherSuite`, `rotorNames`, `reflector`, `rings`, `positions`, `plugPairs` for the **public catalog**. Encrypt in external-key mode writes `stem.m10key` next to `stem.enigmam10` and then replaces the unused machine. Decrypt loads that sidecar when present.
