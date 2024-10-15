/* sm4.h
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

#ifndef WOLF_CRYPT_SM4_H
#define WOLF_CRYPT_SM4_H

#include <wolfssl/wolfcrypt/types.h>
/* Needed for GCM type, functions and constants and CCM constants. */
#include <wolfssl/wolfcrypt/aes.h>

#ifdef WOLFSSL_SM4

enum {
    /* Key size for SM4 algorithm. */
    SM4_KEY_SIZE    = 16,  /* for 128 bit */
    /* IV size for SM4 algorithm. */
    SM4_IV_SIZE     = 16,  /* for 128 bit */
};


enum {
    /* Block size of SM4 algorithm. */
    SM4_BLOCK_SIZE      = 16,

    /* Number of words stored in key schedule for SM4 algorithm. */
    SM4_KEY_SCHEDULE    = 32,
};

/* Data for SM4 algorithm. */
typedef struct wc_Sm4 {
    /* Key schedule. */
    ALIGN16 word32 ks[SM4_KEY_SCHEDULE];
#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR) || \
    defined(WOLFSSL_SM4_GCM) || \
    (defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CCM))
    /* Cached IV. */
    ALIGN16 byte iv[SM4_IV_SIZE];
#endif
#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR)
    /* Temporary buffer when encrypting/decrypting.
     * Used in CBC decrypt and CTR encrypt.
     */
    byte tmp[SM4_IV_SIZE];
#endif
#ifdef WOLFSSL_SM4_CTR
    /* For CTR encrypt, unused encrypted IV/counter bytes in tmp. */
    byte unused;
#endif
#ifdef WOLFSSL_SM4_GCM
    /* GCM data. */
    Gcm gcm;
#endif
#if (defined(WOLFSSL_SM4_GCM) || defined(WOLFSSL_SM4_CCM)) && \
    defined(OPENSSL_EXTRA)
    int nonceSz;
#endif
#ifdef WOLF_CRYPTO_CB
    int devId;
    void* devCtx;
#endif
    void* heap; /* memory hint to use */

    byte keySet:1;
#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR) || \
    defined(WOLFSSL_SM4_GCM)
    byte ivSet:1;
#endif
} wc_Sm4;


#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int wc_Sm4Init(wc_Sm4* sm4, void* heap, int devId);
WOLFSSL_API void wc_Sm4Free(wc_Sm4* sm4);

WOLFSSL_API int wc_Sm4SetKey(wc_Sm4* sm4, const byte* key, word32 len);
WOLFSSL_API int wc_Sm4SetIV(wc_Sm4* sm4, const byte* iv);
WOLFSSL_API int wc_Sm4EcbEncrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz);
WOLFSSL_API int wc_Sm4EcbDecrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz);
WOLFSSL_API int wc_Sm4CbcEncrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz);
WOLFSSL_API int wc_Sm4CbcDecrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz);
WOLFSSL_API int wc_Sm4CtrEncrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz);

WOLFSSL_API int wc_Sm4GcmSetKey(wc_Sm4* sm4, const byte* key, word32 len);
WOLFSSL_API int wc_Sm4GcmEncrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz, const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz);
WOLFSSL_API int wc_Sm4GcmDecrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz, const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz);

WOLFSSL_API int wc_Sm4CcmEncrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz, const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz);
WOLFSSL_API int wc_Sm4CcmDecrypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz, const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SM4 */

#endif /* WOLF_CRYPT_SM4_H */
