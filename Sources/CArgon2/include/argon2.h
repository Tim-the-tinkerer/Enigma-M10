#ifndef ENCLAVE_ARGON2_H
#define ENCLAVE_ARGON2_H

#include <stddef.h>
#include <stdint.h>

/*
 * Argon2id raw key derivation.
 *
 * Returns 0 on success, non-zero on error (bad parameters or allocation
 * failure). `out` receives exactly `outlen` bytes of derived key material.
 *
 * Parameters mirror the conventional Argon2 API so a vetted third-party
 * implementation (e.g. phc-winner-argon2's argon2id_hash_raw) can be
 * substituted with only a name change if desired.
 */
int enclave_argon2id_raw(const uint8_t *pwd, size_t pwdlen,
                         const uint8_t *salt, size_t saltlen,
                         uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                         uint8_t *out, size_t outlen);

/* Extended form with optional secret key and associated data (used for the
 * RFC 9106 known-answer test; production code uses the raw form above). */
int enclave_argon2id_raw_ex(const uint8_t *pwd, size_t pwdlen,
                            const uint8_t *salt, size_t saltlen,
                            const uint8_t *secret, size_t secretlen,
                            const uint8_t *ad, size_t adlen,
                            uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                            uint8_t *out, size_t outlen);

#endif
