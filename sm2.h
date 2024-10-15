/* sm2.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifndef WOLF_CRYPT_ECC_SM2_H
#define WOLF_CRYPT_ECC_SM2_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SM2

#include <wolfssl/wolfcrypt/ecc.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Size of the private key. */
#define SM2_KEY_SIZE    32

/* ID to use when signing/verifying a certificate. */
#define CERT_SIG_ID     ((byte*)"1234567812345678")
/* Length of ID to use when signing/verifying a certificate. */
#define CERT_SIG_ID_SZ  16

WOLFSSL_API
int wc_ecc_sm2_gen_k(WC_RNG* rng, mp_int* k, mp_int* order);
WOLFSSL_API
int wc_ecc_sm2_make_key(WC_RNG* rng, ecc_key* key, int flags);

WOLFSSL_API
int wc_ecc_sm2_shared_secret(ecc_key* priv, ecc_key* pub, byte* out,
    word32* outlen);

WOLFSSL_API
int wc_ecc_sm2_sign_hash_ex(const byte* hash, word32 hashSz, WC_RNG* rng,
    ecc_key* key, mp_int* r, mp_int* s);
WOLFSSL_API
int wc_ecc_sm2_sign_hash(const byte* hash, word32 hashSz, byte* sig,
    word32 *sigLen, WC_RNG* rng, ecc_key* key);

WOLFSSL_API
int wc_ecc_sm2_create_digest(const byte *id, word16 idSz,
        const byte* msg, int msgSz, enum wc_HashType hashType,
        byte* out, int outSz, ecc_key* key);
WOLFSSL_API
int wc_ecc_sm2_verify_hash_ex(mp_int *r, mp_int *s, const byte *hash,
        word32 hashSz, int *res, ecc_key *key);
WOLFSSL_API
int wc_ecc_sm2_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                    word32 hashlen, int* stat, ecc_key* key);

#ifdef __cplusplus
    }    /* extern "C" */
#endif
#endif /* WOLFSSL_SM2 */
#endif /* WOLF_CRYPT_ECC_SM2_H */

