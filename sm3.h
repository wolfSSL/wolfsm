/* sm3.h
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


#ifndef WOLF_CRYPT_SM3_H
#define WOLF_CRYPT_SM3_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SM3

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    /* SM3 algorithm id. */
    WC_SM3              = WC_HASH_TYPE_SM3,
    /* Number of bytes in a block. */
    WC_SM3_BLOCK_SIZE   = 64,
    /* Number of bytes in digest output. */
    WC_SM3_DIGEST_SIZE  = 32,
    /* Number of bytes to pad to. */
    WC_SM3_PAD_SIZE     = 56
};

struct wc_Sm3 {
    /* Values of state. */
    ALIGN16 word32 v[8];
    /* Buffer holding unprocessed message bytes. */
    ALIGN16 word32 buffer[16];
#ifdef WOLFSSL_SMALL_STACK
    ALIGN16 word32 w[68];
#endif
    /* Length of unprocessed message bytes. */
    word32         buffLen;
    /* Low 32 bits of message length (in bytes). */
    word32         loLen;
    /* High 32 bits of message length (in bytes). */
    word32         hiLen;
    /* Dynamic allocation hint. */
    void*          heap;
#ifdef WOLFSSL_HASH_FLAGS
    /* Flags of hash object - see enum wc_HashFlags. */
    word32         flags;
#endif
};

#ifndef WC_SM3_TYPE_DEFINED
/* Typedef for SM3 structure. */
typedef struct wc_Sm3   wc_Sm3;
#define WC_SM3_TYPE_DEFINED
#endif


WOLFSSL_API int wc_InitSm3(wc_Sm3* sm3, void* heap, int devId);
WOLFSSL_API int wc_Sm3Update(wc_Sm3* sm3, const byte* data, word32 len);
WOLFSSL_API int wc_Sm3FinalRaw(wc_Sm3* sm3, byte* hash);
WOLFSSL_API int wc_Sm3Final(wc_Sm3* sm3, byte* hash);
WOLFSSL_API void wc_Sm3Free(wc_Sm3* sm3);
WOLFSSL_API int wc_Sm3Copy(const wc_Sm3* src, wc_Sm3* dst);
WOLFSSL_API int wc_Sm3GetHash(wc_Sm3* sm3, byte* hash);

#ifdef WOLFSSL_HASH_FLAGS
WOLFSSL_API int wc_Sm3SetFlags(wc_Sm3* sm3, word32 flags);
WOLFSSL_API int wc_Sm3GetFlags(const wc_Sm3* sm3, word32* flags);
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SM3 */

#endif /* WOLF_CRYPT_SM3_H */

