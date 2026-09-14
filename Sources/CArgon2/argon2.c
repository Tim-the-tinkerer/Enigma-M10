/*
 * Self-contained Argon2id for Enclave.
 *
 * Implements BLAKE2b and the Argon2id KDF (RFC 9106) with no external
 * dependencies. Public entry point: enclave_argon2id_raw().
 *
 * This is a clean-room implementation written to the RFC and validated against
 * the official RFC 9106 Argon2id test vector. It is intentionally compact and
 * favours clarity over peak performance.
 *
 * Argon2 reference algorithm: Biryukov, Dinu, Khovratovich (CC0 / public domain
 * specification). BLAKE2b: Aumasson, Neves, Wilcox-O'Hearn, Winnerlein.
 */

#include "argon2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ===================== BLAKE2b ===================== */

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

static uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

static uint64_t load64(const uint8_t *p) {
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x |= (uint64_t)p[i] << (8 * i);
    return x;
}

static void store64(uint8_t *p, uint64_t x) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(x >> (8 * i));
}

static void store32(uint8_t *p, uint32_t x) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(x >> (8 * i));
}

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint8_t  buf[128];
    size_t   buflen;
    size_t   outlen;
} blake2b_state;

#define B2B_G(a,b,c,d,x,y)                 \
    do {                                   \
        v[a] = v[a] + v[b] + x;            \
        v[d] = rotr64(v[d] ^ v[a], 32);    \
        v[c] = v[c] + v[d];                \
        v[b] = rotr64(v[b] ^ v[c], 24);    \
        v[a] = v[a] + v[b] + y;            \
        v[d] = rotr64(v[d] ^ v[a], 16);    \
        v[c] = v[c] + v[d];                \
        v[b] = rotr64(v[b] ^ v[c], 63);    \
    } while (0)

static void blake2b_compress(blake2b_state *S, const uint8_t block[128], int last) {
    uint64_t m[16], v[16];
    for (int i = 0; i < 16; i++) m[i] = load64(block + 8 * i);
    for (int i = 0; i < 8; i++) v[i] = S->h[i];
    for (int i = 0; i < 8; i++) v[i + 8] = blake2b_IV[i];
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    if (last) v[14] = ~v[14];

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = blake2b_sigma[r];
        B2B_G(0, 4,  8, 12, m[s[0]],  m[s[1]]);
        B2B_G(1, 5,  9, 13, m[s[2]],  m[s[3]]);
        B2B_G(2, 6, 10, 14, m[s[4]],  m[s[5]]);
        B2B_G(3, 7, 11, 15, m[s[6]],  m[s[7]]);
        B2B_G(0, 5, 10, 15, m[s[8]],  m[s[9]]);
        B2B_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2B_G(2, 7,  8, 13, m[s[12]], m[s[13]]);
        B2B_G(3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) S->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_init(blake2b_state *S, size_t outlen) {
    memset(S, 0, sizeof(*S));
    for (int i = 0; i < 8; i++) S->h[i] = blake2b_IV[i];
    /* parameter block: digest_length, key_length=0, fanout=1, depth=1 */
    S->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;
    S->outlen = outlen;
}

static void blake2b_update(blake2b_state *S, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        if (S->buflen == 128) {
            S->t[0] += 128;
            if (S->t[0] < 128) S->t[1]++;
            blake2b_compress(S, S->buf, 0);
            S->buflen = 0;
        }
        size_t space = 128 - S->buflen;
        size_t take = inlen < space ? inlen : space;
        memcpy(S->buf + S->buflen, in, take);
        S->buflen += take;
        in += take;
        inlen -= take;
    }
}

static void blake2b_final(blake2b_state *S, uint8_t *out) {
    S->t[0] += S->buflen;
    if (S->t[0] < S->buflen) S->t[1]++;
    memset(S->buf + S->buflen, 0, 128 - S->buflen);
    blake2b_compress(S, S->buf, 1);
    uint8_t tmp[64];
    for (int i = 0; i < 8; i++) store64(tmp + 8 * i, S->h[i]);
    memcpy(out, tmp, S->outlen);
}

static void blake2b(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    blake2b_state S;
    blake2b_init(&S, outlen);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out);
}

/* Argon2 variable-length hash H' producing outlen bytes. */
static void blake2b_long(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint8_t lenbuf[4];
    store32(lenbuf, (uint32_t)outlen);

    if (outlen <= 64) {
        blake2b_state S;
        blake2b_init(&S, outlen);
        blake2b_update(&S, lenbuf, 4);
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, out);
        return;
    }

    uint8_t V[64];
    blake2b_state S;
    blake2b_init(&S, 64);
    blake2b_update(&S, lenbuf, 4);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, V);

    size_t pos = 0;
    memcpy(out + pos, V, 32);
    pos += 32;
    size_t remaining = outlen - 32;
    while (remaining > 64) {
        blake2b(V, 64, V, 64);
        memcpy(out + pos, V, 32);
        pos += 32;
        remaining -= 32;
    }
    blake2b(V, remaining, V, 64);
    memcpy(out + pos, V, remaining);
}

/* ===================== Argon2id ===================== */

#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8) /* 128 */
#define ARGON2_SYNC_POINTS 4
#define ARGON2_VERSION 0x13
#define ARGON2_TYPE_ID 2

typedef struct { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } block;

static void block_xor(block *dst, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) dst->v[i] ^= src->v[i];
}
static void block_copy(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(dst->v));
}
static void block_from_bytes(block *b, const uint8_t *bytes) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) b->v[i] = load64(bytes + 8 * i);
}
static void block_to_bytes(uint8_t *bytes, const block *b) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) store64(bytes + 8 * i, b->v[i]);
}

/* fBlaMka modular addition used inside Argon2's G. */
static uint64_t fBlaMka(uint64_t x, uint64_t y) {
    const uint64_t m = 0xFFFFFFFFULL;
    uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

#define G_ARGON(a,b,c,d)                   \
    do {                                   \
        a = fBlaMka(a, b);                 \
        d = rotr64(d ^ a, 32);             \
        c = fBlaMka(c, d);                 \
        b = rotr64(b ^ c, 24);            \
        a = fBlaMka(a, b);                 \
        d = rotr64(d ^ a, 16);             \
        c = fBlaMka(c, d);                 \
        b = rotr64(b ^ c, 63);            \
    } while (0)

/* BLAKE2 round over 16 64-bit words (no message). */
#define P_ROUND(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) \
    do {                                                              \
        G_ARGON(v0, v4,  v8, v12);                                    \
        G_ARGON(v1, v5,  v9, v13);                                    \
        G_ARGON(v2, v6, v10, v14);                                    \
        G_ARGON(v3, v7, v11, v15);                                    \
        G_ARGON(v0, v5, v10, v15);                                    \
        G_ARGON(v1, v6, v11, v12);                                    \
        G_ARGON(v2, v7,  v8, v13);                                    \
        G_ARGON(v3, v4,  v9, v14);                                    \
    } while (0)

/* next = (with_xor ? next : 0) ^ G(prev, ref) */
static void fill_block(const block *prev, const block *ref, block *next, int with_xor) {
    block R, Z;
    block_copy(&R, ref);
    block_xor(&R, prev);          /* R = prev ^ ref */
    block_copy(&Z, &R);

    /* rows */
    for (int i = 0; i < 8; i++) {
        uint64_t *p = R.v + 16 * i;
        P_ROUND(p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
    }
    /* columns */
    for (int i = 0; i < 8; i++) {
        uint64_t *p = R.v + 2 * i;
        P_ROUND(p[0],p[1],p[16],p[17],p[32],p[33],p[48],p[49],
                p[64],p[65],p[80],p[81],p[96],p[97],p[112],p[113]);
    }

    if (with_xor) {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
            next->v[i] = Z.v[i] ^ R.v[i] ^ next->v[i];
    } else {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
            next->v[i] = Z.v[i] ^ R.v[i];
    }
}

typedef struct {
    block   *mem;
    uint32_t lanes;
    uint32_t lane_length;     /* q: blocks per lane */
    uint32_t segment_length;  /* q / 4 */
    uint32_t memory_blocks;   /* m' */
    uint32_t passes;          /* t */
} argon2_instance;

/* Map J1 into a reference index given the reference area size. */
static uint32_t index_alpha(const argon2_instance *inst,
                            uint32_t pass, uint32_t slice, uint32_t lane,
                            uint32_t index, uint32_t pseudo_rand, int same_lane) {
    (void)lane; /* present for parity with the reference signature */
    uint64_t area_size;
    if (pass == 0) {
        if (slice == 0) {
            area_size = (index == 0) ? 0 : index - 1;
        } else if (same_lane) {
            area_size = (uint64_t)slice * inst->segment_length + index - 1;
        } else {
            area_size = (uint64_t)slice * inst->segment_length + (index == 0 ? -1 : 0);
        }
    } else {
        if (same_lane) {
            area_size = (uint64_t)inst->lane_length - inst->segment_length + index - 1;
        } else {
            area_size = (uint64_t)inst->lane_length - inst->segment_length + (index == 0 ? -1 : 0);
        }
    }

    uint64_t rel = pseudo_rand;
    rel = (rel * rel) >> 32;
    rel = area_size - 1 - ((area_size * rel) >> 32);

    uint32_t start = 0;
    if (pass != 0) {
        start = (slice == ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * inst->segment_length;
    }
    return (uint32_t)(((uint64_t)start + rel) % inst->lane_length);
}

/* Build the address block used for data-independent indexing (Argon2i half). */
static void next_addresses(block *address, block *input, block *zero) {
    input->v[6]++;
    fill_block(zero, input, address, 0);
    fill_block(zero, address, address, 0);
}

static void fill_segment(const argon2_instance *inst,
                         uint32_t pass, uint32_t lane, uint32_t slice) {
    int data_independent = (pass == 0 && slice < ARGON2_SYNC_POINTS / 2); /* Argon2id */

    block address, input, zero;
    if (data_independent) {
        memset(&zero, 0, sizeof(zero));
        memset(&input, 0, sizeof(input));
        input.v[0] = pass;
        input.v[1] = lane;
        input.v[2] = slice;
        input.v[3] = inst->memory_blocks;
        input.v[4] = inst->passes;
        input.v[5] = ARGON2_TYPE_ID;
        input.v[6] = 0;
    }

    uint32_t start = 0;
    if (pass == 0 && slice == 0) start = 2; /* first two columns are pre-filled */

    /* The pass0/slice0 segment begins at index 2, so the i%128==0 trigger below
     * never fires for its first block. Generate the initial address block here so
     * data-independent indexing never reads an uninitialized block. */
    if (data_independent && pass == 0 && slice == 0) {
        next_addresses(&address, &input, &zero);
    }

    uint32_t curr_offset = lane * inst->lane_length + slice * inst->segment_length + start;
    uint32_t prev_offset = (curr_offset % inst->lane_length == 0)
                               ? curr_offset + inst->lane_length - 1
                               : curr_offset - 1;

    for (uint32_t i = start; i < inst->segment_length; i++, curr_offset++, prev_offset++) {
        if (curr_offset % inst->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        uint64_t pseudo_rand;
        if (data_independent) {
            if (i % ARGON2_QWORDS_IN_BLOCK == 0) {
                next_addresses(&address, &input, &zero);
            }
            pseudo_rand = address.v[i % ARGON2_QWORDS_IN_BLOCK];
        } else {
            pseudo_rand = inst->mem[prev_offset].v[0];
        }

        uint32_t ref_lane = (uint32_t)((pseudo_rand >> 32) % inst->lanes);
        if (pass == 0 && slice == 0) {
            ref_lane = lane;
        }

        uint32_t ref_index = index_alpha(inst, pass, slice, lane, i,
                                         (uint32_t)(pseudo_rand & 0xFFFFFFFFULL),
                                         ref_lane == lane);

        block *ref_block = inst->mem + (uint64_t)ref_lane * inst->lane_length + ref_index;
        block *curr_block = inst->mem + curr_offset;
        fill_block(&inst->mem[prev_offset], ref_block, curr_block, pass != 0);
    }
}

int enclave_argon2id_raw(const uint8_t *pwd, size_t pwdlen,
                         const uint8_t *salt, size_t saltlen,
                         uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                         uint8_t *out, size_t outlen) {
    return enclave_argon2id_raw_ex(pwd, pwdlen, salt, saltlen,
                                   NULL, 0, NULL, 0,
                                   t_cost, m_cost_kib, parallelism, out, outlen);
}

int enclave_argon2id_raw_ex(const uint8_t *pwd, size_t pwdlen,
                            const uint8_t *salt, size_t saltlen,
                            const uint8_t *secret, size_t secretlen,
                            const uint8_t *ad, size_t adlen,
                            uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                            uint8_t *out, size_t outlen) {
    if (parallelism < 1 || t_cost < 1 || outlen < 4) return 1;
    if (m_cost_kib < 8 * parallelism) return 1;

    uint32_t memory_blocks = m_cost_kib;
    uint32_t segments = ARGON2_SYNC_POINTS * parallelism;
    memory_blocks = (memory_blocks / segments) * segments; /* m' */
    if (memory_blocks < 8 * parallelism) return 1;

    argon2_instance inst;
    inst.lanes = parallelism;
    inst.memory_blocks = memory_blocks;
    inst.lane_length = memory_blocks / parallelism;
    inst.segment_length = inst.lane_length / ARGON2_SYNC_POINTS;
    inst.passes = t_cost;
    inst.mem = (block *)calloc(memory_blocks, sizeof(block));
    if (!inst.mem) return 2;

    /* ---- H0 ---- */
    uint8_t H0[72]; /* 64-byte hash + 8 bytes for the (block, lane) suffix later */
    {
        blake2b_state S;
        uint8_t u32[4];
        blake2b_init(&S, 64);
        store32(u32, parallelism);        blake2b_update(&S, u32, 4);
        store32(u32, (uint32_t)outlen);   blake2b_update(&S, u32, 4);
        store32(u32, m_cost_kib);         blake2b_update(&S, u32, 4);
        store32(u32, t_cost);             blake2b_update(&S, u32, 4);
        store32(u32, ARGON2_VERSION);     blake2b_update(&S, u32, 4);
        store32(u32, ARGON2_TYPE_ID);     blake2b_update(&S, u32, 4);
        store32(u32, (uint32_t)pwdlen);   blake2b_update(&S, u32, 4);
        blake2b_update(&S, pwd, pwdlen);
        store32(u32, (uint32_t)saltlen);  blake2b_update(&S, u32, 4);
        blake2b_update(&S, salt, saltlen);
        store32(u32, (uint32_t)secretlen);blake2b_update(&S, u32, 4);
        if (secretlen) blake2b_update(&S, secret, secretlen);
        store32(u32, (uint32_t)adlen);    blake2b_update(&S, u32, 4);
        if (adlen) blake2b_update(&S, ad, adlen);
        blake2b_final(&S, H0);
    }

    /* ---- first two blocks of each lane ---- */
    uint8_t blockhash_in[72];
    uint8_t block_bytes[ARGON2_BLOCK_SIZE];
    memcpy(blockhash_in, H0, 64);
    for (uint32_t lane = 0; lane < parallelism; lane++) {
        store32(blockhash_in + 64, 0);
        store32(blockhash_in + 68, lane);
        blake2b_long(block_bytes, ARGON2_BLOCK_SIZE, blockhash_in, 72);
        block_from_bytes(&inst.mem[lane * inst.lane_length + 0], block_bytes);

        store32(blockhash_in + 64, 1);
        store32(blockhash_in + 68, lane);
        blake2b_long(block_bytes, ARGON2_BLOCK_SIZE, blockhash_in, 72);
        block_from_bytes(&inst.mem[lane * inst.lane_length + 1], block_bytes);
    }

    /* ---- fill memory ---- */
    for (uint32_t pass = 0; pass < inst.passes; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            for (uint32_t lane = 0; lane < parallelism; lane++) {
                fill_segment(&inst, pass, lane, slice);
            }
        }
    }

    /* ---- finalize: XOR last column across lanes, then H' to out ---- */
    block final;
    block_copy(&final, &inst.mem[inst.lane_length - 1]);
    for (uint32_t lane = 1; lane < parallelism; lane++) {
        block_xor(&final, &inst.mem[lane * inst.lane_length + inst.lane_length - 1]);
    }
    block_to_bytes(block_bytes, &final);
    blake2b_long(out, outlen, block_bytes, ARGON2_BLOCK_SIZE);

    /* wipe and free */
    memset(inst.mem, 0, (size_t)memory_blocks * sizeof(block));
    free(inst.mem);
    memset(H0, 0, sizeof(H0));
    memset(block_bytes, 0, sizeof(block_bytes));
    return 0;
}

#ifdef ARGON2_TEST
#include <stdio.h>
static void hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}
int main(void) {
    /* RFC 9106 Argon2id test vector */
    uint8_t pwd[32], salt[16], secret[8], ad[12], out[32];
    memset(pwd, 0x01, sizeof(pwd));
    memset(salt, 0x02, sizeof(salt));
    memset(secret, 0x03, sizeof(secret));
    memset(ad, 0x04, sizeof(ad));
    int rc = enclave_argon2id_raw_ex(pwd, 32, salt, 16, secret, 8, ad, 12,
                                     3, 32, 4, out, 32);
    printf("rc=%d\n", rc);
    printf("got     : "); hex(out, 32);
    printf("expected: 0d640df58d7876 6c08c037a34a8b53c9d01ef0452d75b6 5eb52520e96b01e659\n");

    /* Production-path KAT (empty secret/AD, p=1) used by the Swift test suite. */
    uint8_t kpwd[11] = "enclave-kat";
    uint8_t ksalt[16];
    memset(ksalt, 0x02, sizeof(ksalt));
    uint8_t kout[32];
    rc = enclave_argon2id_raw(kpwd, 11, ksalt, 16, 3, 64, 1, kout, 32);
    printf("kat rc=%d\n", rc);
    printf("KAT     : "); hex(kout, 32);
    return 0;
}
#endif
