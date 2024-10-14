/* sm2.c
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

/* Based on 'SM2 Digital Signature Algorithm draft-shen-sm2-ecdsa-02'
 *   https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SM2) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/sm2.h>
#include <wolfssl/wolfcrypt/sp.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Maximum number of signature generations to attempt before giving up. */
#define ECC_SM2_MAX_SIG_GEN     64

#ifndef NO_HASH_WRAPPER
/* Convert hex string to binary and hash it.
 *
 * @param [in] hash      Hash algorithm object.
 * @param [in] hashType  Type of hash to perform.
 * @param [in] hexIn     Hexadecimal string.
 * @param [in] hexSz     Number of characters to hash.
 * @param [in] tmp       Buffer to encode into.
 * @return  0 on success
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int ecc_sm2_digest_hashin(wc_HashAlg* hash, enum wc_HashType hashType,
    const char* hexIn, int hexSz, byte* tmp)
{
    int err = 0;
    word32 tmpSz;

    /* Number of bytes in binary as type word32. */
    tmpSz = (word32)hexSz;
    if (err == 0) {
        /* Convert hexadecimal string to binary. */
        err = Base16_Decode((const byte*)hexIn, tmpSz, tmp, &tmpSz);
    }
    if (err == 0) {
        /* Update the hash with the binary data. */
        err = wc_HashUpdate(hash, hashType, tmp, tmpSz);
    }

    return err;
}

/* Calculate ZA with hash type specified for sign/verify.
 *
 * 5.1.4.4:
 *   ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
 *
 * @param [in]  id        ID of A to be hashed.
 * @param [in]  idSz      Size of ID of A in bytes.
 * @param [in]  hash      Hash algorithm object.
 * @param [in]  hashType  Hash type to use.
 * @param [in]  key       SM2 ECC key that has already been setup.
 * @param [out] out       Buffer to hold final digest.
 * @return  0 on success.
 * @return  Negative on failure.
 */
static int _ecc_sm2_calc_za(const byte *id, word16 idSz,
    wc_HashAlg* hash, enum wc_HashType hashType, ecc_key* key, byte* out)
{
    int err = 0;
    byte entla[2];  /* RFC draft states ID size is always encoded in 2 bytes. */
    word16 sz = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* xA = NULL;
    byte* yA = NULL;
#else
    /* Modify if more than one SM2 curve. */
    byte xA[33];
    byte yA[33];
#endif
    word32 xASz;
    word32 yASz;

    /* Get ID of A size in bits. */
    sz = idSz * WOLFSSL_BIT_SIZE;
    /* Set big-endian 16-bit word. */
    entla[0] = (byte)(sz >> WOLFSSL_BIT_SIZE);
    entla[1] = (byte)(sz & 0xFF);

#ifdef DEBUG_ECC_SM2
    WOLFSSL_MSG("ENTLA");
    WOLFSSL_BUFFER(entla, 2);
#endif

    /* Get ordinate size. */
    xASz = yASz = (word32)wc_ecc_size(key);
#ifdef WOLFSSL_SMALL_STACK
    /* Allocate memory for the x-ordinate. */
    xA = (byte*)XMALLOC(xASz  + 1, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (xA == NULL) {
        err = MEMORY_E;
    }
    if (err == 0) {
        /* Allocate memory for the y-ordinate. */
        yA = (byte*)XMALLOC(yASz  + 1, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (yA == NULL) {
            err = MEMORY_E;
        }
    }
#endif


    if (err == 0) {
        /* Hash the ENTLA - length of ID of A. */
        err = wc_HashUpdate(hash, hashType, (byte*)&entla, 2);
    }
    if (err == 0) {
        /* Hash the ID of A. */
        err = wc_HashUpdate(hash, hashType, id, idSz);
    }

    if (err == 0) {
        /* Hash the a coefficient of the curve. */
        err = ecc_sm2_digest_hashin(hash, hashType, key->dp->Af,
                (int)XSTRLEN(key->dp->Af), xA);
    }
    if (err == 0) {
        /* Hash the b coefficient of the curve. */
        err = ecc_sm2_digest_hashin(hash, hashType, key->dp->Bf,
                (int)XSTRLEN(key->dp->Bf), xA);
    }
    if (err == 0) {
        /* Hash the x-ordinate of the base point. */
        err = ecc_sm2_digest_hashin(hash, hashType, key->dp->Gx,
                (int)XSTRLEN(key->dp->Gx), xA);
    }
    if (err == 0) {
        /* Hash the y-ordinate of the base point. */
        err = ecc_sm2_digest_hashin(hash, hashType, key->dp->Gy,
                (int)XSTRLEN(key->dp->Gy), xA);
    }

    if (err == 0) {
        /* Get the x and y ordinates. */
        err = wc_ecc_export_public_raw(key, xA, &xASz, yA, &yASz);
    }
    if (err == 0) {
        /* Hash the x-ordinate of the public key. */
        err = wc_HashUpdate(hash, hashType, xA, xASz);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(xA, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (err == 0) {
        /* Hash the y-ordinate of the public key. */
        err = wc_HashUpdate(hash, hashType, yA, yASz);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(yA, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (err == 0) {
        /* Output the hash - ZA. */
        err = wc_HashFinal(hash, hashType, out);
    }
#ifdef DEBUG_ECC_SM2
    if (err == 0) {
        WOLFSSL_MSG("ZA");
        WOLFSSL_BUFFER(out, wc_HashGetDigestSize(hashType));
    }
#endif

    return err;
}

/* Calculate SM2 hash of the type specified for sign/verify.
 *
 * 5.2.1, A2:
 *   Hash Out = Hash(ZA || M)
 *
 * @param [in]  za        ZA to be hashed.
 * @param [in]  zaSz      Size of ZA in bytes.
 * @param [in]  msg       Message to be signed.
 * @param [in]  msgSz     Size of message in bytes.
 * @param [in]  hash      Hash algorithm object.
 * @param [in]  hashType  Hash type to use.
 * @param [out] out       Buffer to hold final digest.
 * @return  0 on success.
 * @return  Negative on failure.
 */
static int _ecc_sm2_calc_msg_hash(const byte* za, int zaSz, const byte* msg,
    int msgSz, wc_HashAlg* hash, enum wc_HashType hashType, byte* out)
{
    int err;

    /* Initialize the hash for new operation. */
    err = wc_HashInit_ex(hash, hashType, NULL, 0);
    if (err == 0) {
        /* Hash ZA. */
        err = wc_HashUpdate(hash, hashType, za, (word32)zaSz);
    }
    if (err == 0) {
        /* Hash the message. */
        err = wc_HashUpdate(hash, hashType, msg, (word32)msgSz);
    }
    if (err == 0) {
        /* Output the hash. */
        err = wc_HashFinal(hash, hashType, out);
    }
#ifdef DEBUG_ECC_SM2
    if (err == 0) {
        WOLFSSL_MSG("Hv(ZA || M)");
        WOLFSSL_BUFFER(out, wc_HashGetDigestSize(hashType));
    }
#endif

    return err;
}

/* Create SM2 hash of the type specified for sign/verify.
 *
 * 5.1.4.4:
 *   ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
 * 5.2.1:
 *   A1: M~=ZA || M
 *   A2: e=Hv(M~)
 *
 * @param [in]  id        ID of A to be hashed.
 * @param [in]  idSz      Size of ID of A in bytes.
 * @param [in]  msg       Message to be signed.
 * @param [in]  msgSz     Size of message in bytes.
 * @param [in]  hashType  Hash type to use.
 * @param [out] out       Buffer to hold final digest.
 * @param [in]  outSz     Size of output buffer in bytes.
 * @param [in]  key       SM2 ECC key that has already been setup.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, out, msg or id is NULL.
 * @return  BAD_FUNC_ARG when hash type is not supported.
 * @return  BUFFER_E when hash size is larger than output size.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
int wc_ecc_sm2_create_digest(const byte *id, word16 idSz,
    const byte* msg, int msgSz, enum wc_HashType hashType, byte* out, int outSz,
    ecc_key* key)
{
    int err = 0;
    int hashSz = 0;
#ifdef WOLFSSL_SMALL_STACK
    wc_HashAlg* hash = NULL;
#else
    wc_HashAlg hash[1];
#endif
    int hash_inited = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->dp == NULL) || (out == NULL) || (msg == NULL) ||
            (id == NULL)) {
        err = BAD_FUNC_ARG;
    }
    /* Get hash size. */
    if ((err == 0) && ((hashSz = wc_HashGetDigestSize(hashType)) < 0)) {
        err = BAD_FUNC_ARG;
    }
    /* Check hash size fits in output. */
    if ((err == 0) && (hashSz > outSz)) {
        err = BUFFER_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == 0) {
        hash = (wc_HashAlg*)XMALLOC(sizeof(wc_HashAlg), key->heap,
            DYNAMIC_TYPE_HASHES);
        if (hash == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == 0) {
        /* Initialize hash algorithm object. */
        err = wc_HashInit_ex(hash, hashType, key->heap, 0);
    }

    if (err == 0) {
        hash_inited = 1;
    }

    /* Calculate ZA. */
    if (err == 0) {
        err = _ecc_sm2_calc_za(id, idSz, hash, hashType, key, out);
    }
    /* Calculate message hash. */
    if (err == 0) {
        err = _ecc_sm2_calc_msg_hash(out, hashSz, msg, msgSz, hash, hashType,
            out);
    }

    /* Dispose of allocated data. */
    if (hash_inited) {
        (void)wc_HashFree(hash, hashType);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(hash, key->heap, DYNAMIC_TYPE_HASHES);
#endif
    return err;
}
#endif /* NO_HASH_WRAPPER */

/* Make a key on the SM2 curve.
 *
 * @param [in]  rng    Random number generator.
 * @param [out] key    ECC key to hold generated key.
 * @param [in]  flags  Flags to set against ECC key.
 * @return  0 on success.
 */
int wc_ecc_sm2_make_key(WC_RNG* rng, ecc_key* key, int flags)
{
    return wc_ecc_make_key_ex2(rng, 32, key, ECC_SM2P256V1, flags);
}

/* Create a shared secret from the private key and peer's public key.
 *
 * @param [in]      priv    Private key.
 * @param [in]      pub     Peer's public key.
 * @param [out]     out     Array containing secret.
 * @param [in, out] outLen  On in, length of array in bytes.
 *                          On out, number of bytes in secret.
 */
int wc_ecc_sm2_shared_secret(ecc_key* priv, ecc_key* pub, byte* out,
    word32* outLen)
{
    return wc_ecc_shared_secret(priv, pub, out, outLen);
}

#ifdef HAVE_ECC_SIGN
#ifndef WOLFSSL_SP_MATH
/* Calculate r and s of signature.
 *
 * @param [in]  x      Private key.
 * @param [in]  px     Ephemeral point's x-ordinate.
 * @param [in]  k      Ephemeral private key.
 * @param [in]  e      Hash of message.
 * @param [in]  order  Order of curve.
 * @param [in]  b      Blinding value.
 * @param [out] r      'r' value of signature.
 * @param [out] s      's' value of signature.
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _ecc_sm2_calc_r_s(mp_int* x, mp_int* px, mp_int* k, mp_int* e,
    mp_int* order, mp_int* b, mp_int* r, mp_int* s)
{
    int err;

    /* r = p->x + e */
    err = mp_addmod_ct(px, e, order, r);
    /* Check r != 0 */
    if ((err == MP_OKAY) && mp_iszero(r)) {
        err = MP_ZERO_E;
    }
    /* Calc r + k */
    if (err == MP_OKAY) {
        err = mp_addmod_ct(r, k, order, s);
    }
    /* Check r + k != 0 */
    if ((err == MP_OKAY) && mp_iszero(s)) {
        err = MP_ZERO_E;
    }

    /* s = x.r */
    if (err == MP_OKAY) {
        err = mp_mulmod(r, x, order, s);
    }

    /* x' = x + 1 */
    if (err == MP_OKAY) {
        err = mp_add_d(x, 1, x);
    }
    /* x'' = x'.b = (x+1).b */
    if (err == MP_OKAY) {
        err = mp_mulmod(x, b, order, x);
    }
    /* x''' = 1/x'' = 1/((x+1).b) */
    if (err == MP_OKAY) {
        err = mp_invmod(x, order, x);
    }

    /* k' = k * x''' = k / ((x+1).b) */
    if (err == MP_OKAY) {
        err = mp_mulmod(k, x, order, k);
    }

    /* s' = s * x''' = x.r / ((x+1).b) */
    if (err == MP_OKAY) {
        err = mp_mulmod(s, x, order, s);
    }
    /* s'' = k' - s' = (k - x.r) / ((x+1).b) */
    if (err == MP_OKAY) {
        err = mp_submod_ct(k, s, order, s);
    }
    /* s''' = s'' * b = (k - x.r) / (x+1) */
    if (err == MP_OKAY) {
        err = mp_mulmod(s, b, order, s);
    }

    return err;
}
#endif

/* Calculate the signature from the hash with a key on the SM2 curve.
 *
 * Use wc_ecc_sm2_create_digest to calculate the digest.
 *
 * @param [in]  hash    Array of bytes holding hash value.
 * @param [in]  hashSz  Size of hash in bytes.
 * @param [in]  rng     Random number generator.
 * @param [in]  key     ECC private key.
 * @param [out] r       'r' part of signature as an MP integer.
 * @param [out] s       's' part of signature as an MP integer.
 * @return  MP_OKAY on success.
 * @return  ECC_BAD_ARGE_E when hash, r, s, key or rng is NULL.
 * @return  ECC_BAD_ARGE_E when key is not on SM2 curve.
 */
int wc_ecc_sm2_sign_hash_ex(const byte* hash, word32 hashSz, WC_RNG* rng,
    ecc_key* key, mp_int* r, mp_int* s)
{
    int err = MP_OKAY;
#ifndef WOLFSSL_SP_MATH
    mp_int* x = NULL;
    mp_int* e = NULL;
    mp_int* b = NULL;
    mp_int* order = NULL;
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* pub = NULL;
    mp_int* data = NULL;
#else
    ecc_key pub[1];
    mp_int data[4];
#endif
    int i;
#endif

    /* Validate parameters. */
    if ((hash == NULL) || (r == NULL) || (s == NULL) || (key == NULL) ||
            (key->dp == NULL) || (rng == NULL)) {
        err = BAD_FUNC_ARG;
    }
    /* SM2 signature must be with a key on the SM2 curve. */
    if ((err == MP_OKAY) && (key->dp->id != ECC_SM2P256V1) &&
        (key->idx != ECC_CUSTOM_IDX)) {
        err = BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(WOLFSSL_SP_SM2)
    if ((err == MP_OKAY) && (key->dp->id == ECC_SM2P256V1)) {
        /* Use optimized code in SP to perform signing. */
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        err = sp_ecc_sign_sm2_256(hash, hashSz, rng, key->k, r, s, NULL,
            key->heap);
        RESTORE_VECTOR_REGISTERS();
        return err;
    }
#endif

#ifndef WOLFSSL_SP_MATH
#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        /* Allocate ECC key. */
        pub = (ecc_key*)XMALLOC(sizeof(ecc_key), key->heap, DYNAMIC_TYPE_ECC);
        if (pub == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        /* Allocate MP integers. */
        data = (mp_int*)XMALLOC(sizeof(mp_int) * 4, key->heap,
            DYNAMIC_TYPE_ECC);
        if (data == NULL) {
            err = MEMORY_E;
        }
    }
#endif
    if (err == MP_OKAY) {
        x = data;
        e = data + 1;
        b = data + 2;
        order = data + 3;
    }

    /* Initialize MP integers needed. */
    if (err == MP_OKAY) {
        err = mp_init_multi(x, e, b, order, NULL, NULL);
    }
    if (err == MP_OKAY) {
        /* Initialize ephemeral key. */
        err = wc_ecc_init_ex(pub, key->heap, INVALID_DEVID);
        if (err == MP_OKAY) {
           /* Load the order into an MP integer for generating blinding value.
            */
            err = mp_read_radix(order, key->dp->order, MP_RADIX_HEX);
        }
        if (err == MP_OKAY) {
            /* Convert hash to a number. */
            err = mp_read_unsigned_bin(e, hash, hashSz);
        }
        if (err == MP_OKAY) {
            /* Reduce the hash value to that of the order once. */
            err = mp_mod(e, order, e);
        }
        if (err == MP_OKAY) {
            do {
                /* Generate blinding value. */
                err = wc_ecc_gen_k(rng, 32, b, order);
            }
            while (err == MP_ZERO_E);

            /* Try generating a signature a number of times. */
            for (i = 0; (err == MP_OKAY) && (i < ECC_SM2_MAX_SIG_GEN); i++) {
                /* Make a new ephemeral key. */
                err = wc_ecc_sm2_make_key(rng, pub, WC_ECC_FLAG_NONE);
                if (err == MP_OKAY) {
                    /* Copy the private key into temporary. */
                    err = mp_copy(wc_ecc_key_get_priv(key), x);
                }
                if (err == MP_OKAY) {
                    /* Calculate R and S. */
                    err = _ecc_sm2_calc_r_s(x, pub->pubkey.x,
                        wc_ecc_key_get_priv(pub), e, order, b, r, s);
                }
                /* Done if it worked. */
                if (err == MP_OKAY) {
                    break;
                }
                /* Try again if random values not usable. */
                if (err == MP_ZERO_E) {
                    err = MP_OKAY;
                }
            }

            /* Dispose of emphemeral key. */
            wc_ecc_free(pub);
        }

        /* Dispose of temproraries - x and b are sensitive data. */
        mp_forcezero(x);
        mp_forcezero(b);
        mp_free(e);
        mp_free(order);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(pub, key->heap, DYNAMIC_TYPE_ECC);
    XFREE(data, key->heap, DYNAMIC_TYPE_ECC);
#endif
#else
    (void)hashSz;

    err = NOT_COMPILED_IN;
#endif

    return err;
}

/* Calculate the signature from the hash with a key on the SM2 curve.
 *
 * Use wc_ecc_sm2_create_digest to calculate the digest.
 *
 * @param [in]  hash    Array of bytes holding hash value.
 * @param [in]  hashSz  Size of hash in bytes.
 * @param [in]  rng     Random number generator.
 * @param [in]  key     ECC private key.
 * @param [out] sig     DER encoded DSA signature.
 * @param [out] sigSz   On in, size of signature buffer in bytes.
 *                      On out, length of signature in bytes.
 * @return  MP_OKAY on success.
 * @return  ECC_BAD_ARGE_E when hash, r, s, key or rng is NULL.
 * @return  ECC_BAD_ARGE_E when key is not on SM2 curve.
 */
int wc_ecc_sm2_sign_hash(const byte* hash, word32 hashSz, byte* sig,
    word32 *sigSz, WC_RNG* rng, ecc_key* key)
{
    int err = MP_OKAY;
#if !defined(WOLFSSL_ASYNC_CRYPT) || !defined(WC_ASYNC_ENABLE_ECC)
#ifdef WOLFSSL_SMALL_STACK
    mp_int *r = NULL, *s = NULL;
#else
    mp_int r[1], s[1];
#endif
#endif

    /* Validate parameters. */
    if ((hash == NULL) || (sig == NULL) || (sigSz == NULL) || (key == NULL) ||
            (key->dp == NULL) || (rng == NULL)) {
        err = BAD_FUNC_ARG;
    }
    /* SM2 signature must be with a key on the SM2 curve. */
    if ((err == MP_OKAY) && (key->dp->id != ECC_SM2P256V1) &&
        (key->idx != ECC_CUSTOM_IDX)) {
        err = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        /* Allocate MP integers. */
        r = (mp_int*)XMALLOC(sizeof(mp_int), key->heap, DYNAMIC_TYPE_ECC);
        if (r == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        s = (mp_int*)XMALLOC(sizeof(mp_int), key->heap, DYNAMIC_TYPE_ECC);
        if (s == NULL) {
            err = MEMORY_E;
        }
    }
#endif
    /* Clear out MP integers. */
#ifdef WOLFSSL_SMALL_STACK
    if (r != NULL)
#endif
        XMEMSET(r, 0, sizeof(mp_int));
#ifdef WOLFSSL_SMALL_STACK
    if (s != NULL)
#endif
        XMEMSET(s, 0, sizeof(mp_int));

    /* Initialize MP integers. */
    if (err == MP_OKAY)
        err = mp_init_multi(r, s, NULL, NULL, NULL, NULL);
    /* Generate signature into numbers. */
    if (err == MP_OKAY)
        err = wc_ecc_sm2_sign_hash_ex(hash, hashSz, rng, key, r, s);

    /* Encode r and s in DER DSA signature format. */
    if (err == MP_OKAY)
        err = StoreECC_DSA_Sig(sig, sigSz, r, s);

    /* Dispose of temporaries. */
    mp_clear(r);
    mp_clear(s);

#ifdef WOLFSSL_SMALL_STACK
    /* Free allocated data. */
    XFREE(s, key->heap, DYNAMIC_TYPE_ECC);
    XFREE(r, key->heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif

#ifdef HAVE_ECC_VERIFY
#ifndef WOLFSSL_SP_MATH
/* Scalar multiply two scalars against respective points and add result.
 *
 * @param [in]  mG       First point to multiply.
 * @param [in]  u1       First scalar.
 * @param [in]  mQ       Second point to multiply.
 * @param [in]  u2       Second scalar.
 * @param [out] mR       Point to store result in.
 * @param [in]  a        Coefficient a of the curve.
 * @param [in]  modulus  Modulus of curve.
 * @param [in]  heap     Dynamic memory allocation hint.
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a parameter is invalid.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int ecc_sm2_mul2add(ecc_point* mG, mp_int* u1, ecc_point* mQ, mp_int* u2,
    ecc_point* mR, mp_int* a, mp_int* modulus, void* heap)
{
    int err;
#ifndef ECC_SHAMIR
    mp_digit mp = 0;

    /* Calculate the Montgomery multiplier. */
    err = mp_montgomery_setup(modulus, &mp);
    if ((err == 0) && (!mp_iszero(u1))) {
        /* Compute mR = u1 * mG + u2 * mQ */

        /* mG = u1 * mG */
        err = wc_ecc_mulmod_ex(u1, mG, mG, a, modulus, 0, heap);
        if (err == MP_OKAY) {
            /* mQ = u2 * mQ */
            err = wc_ecc_mulmod_ex(u2, mQ, mR, a, modulus, 0, heap);
        }

        if (err == MP_OKAY) {
            /* mR = mQ + mG */
            err = ecc_projective_add_point(mR, mG, mR, a, modulus, mp);
        }
        if (err == MP_OKAY && mp_iszero(mR->z)) {
            /* When all zero then should have done a double instead. */
            if (mp_iszero(mR->x) && mp_iszero(mR->y)) {
                /* mR = mQ * 2 (mG = mQ) */
                err = ecc_projective_dbl_point(mQ, mR, a, modulus, mp);
            }
            else {
                /* When only Z zero then result is infinity. */
                err = mp_set(mR->x, 0);
                if (err == MP_OKAY)
                    err = mp_set(mR->y, 0);
                if (err == MP_OKAY)
                    err = mp_set(mR->z, 1);
            }
        }
    }
    else if (err == 0) {
        /* Compute mR = 0 * mG + u2 * mQ  =>  mR = u2 * mQ */
        err = wc_ecc_mulmod_ex(u2, mQ, mR, a, modulus, 0, heap);
    }

    /* Convert from Jacobian to affine. */
    if (err == MP_OKAY) {
        err = ecc_map(mR, modulus, mp);
    }
#else
    /* Use Shamir's trick to compute u1 * mG + u2 * mQ using half the doubles.
     */
    err = ecc_mul2add(mG, u1, mQ, u2, mR, a, modulus, heap);
#endif /* ECC_SHAMIR */

    return err;
}
#endif /* !WOLFSSL_SP_MATH */

/* Verify digest of hash(ZA || M) using key on SM2 curve and R and S.
 *
 * res gets set to 1 on successful verify and 0 on failure
 *
 * Use wc_ecc_sm2_create_digest to calculate the digest.
 *
 * @param [in]  r       MP integer holding r part of signature.
 * @param [in]  s       MP integer holding s part of signature.
 * @param [in]  hash    Array of bytes holding hash value.
 * @param [in]  hashSz  Size of hash in bytes.
 * @param [out] res     1 on successful verify and 0 on failure.
 * @param [in]  key     Public key on SM2 curve.
 * @return  0 on success (note this is even when successfully finding verify is
 * incorrect)
 * @return  BAD_FUNC_ARG when key, res, r, s or hash is NULL.
 * @return  MP_VAL when r + s = 0.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int wc_ecc_sm2_verify_hash_ex(mp_int *r, mp_int *s, const byte *hash,
    word32 hashSz, int *res, ecc_key *key)
{
    int err = MP_OKAY;
#ifndef WOLFSSL_SP_MATH
    ecc_point* PO = NULL;
    ecc_point* G = NULL;
    mp_int* t = NULL;
    mp_int* e = NULL;
    mp_int* prime = NULL;
    mp_int* Af = NULL;
    mp_int* order = NULL;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* data = NULL;
#else
    mp_int data[5];
#endif
#endif

    /* Validate parameters. */
    if ((key == NULL) || (key->dp == NULL) || (res == NULL) || (r == NULL) ||
            (s == NULL) || (hash == NULL)) {
        err = BAD_FUNC_ARG;
    }
    /* SM2 signature must be with a key on the SM2 curve. */
    if ((err == MP_OKAY) && (key->dp->id != ECC_SM2P256V1) &&
        (key->idx != ECC_CUSTOM_IDX)) {
        err = BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(WOLFSSL_SP_SM2)
    if ((err == MP_OKAY) && (key->dp->id == ECC_SM2P256V1)) {
        /* Use optimized code in SP to perform verification. */
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        err = sp_ecc_verify_sm2_256(hash, hashSz, key->pubkey.x,
            key->pubkey.y, key->pubkey.z, r, s, res, key->heap);
        RESTORE_VECTOR_REGISTERS();
        return err;
    }
#endif

#ifndef WOLFSSL_SP_MATH
    if (res != NULL) {
        /* Assume failure. */
        *res = 0;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        /* Allocate temporary MP integer. */
        data = (mp_int*)XMALLOC(sizeof(mp_int) * 5, key->heap,
            DYNAMIC_TYPE_ECC);
        if (data == NULL) {
            err = MEMORY_E;
        }
    }
#endif
    if (err == MP_OKAY) {
        t = data;
        e = data + 1;
        prime = data + 2;
        Af = data + 3;
        order = data + 4;
    }

    if (err == MP_OKAY) {
        /* Initialize temporary MP integers. */
        err = mp_init_multi(e, t, prime, Af, order, NULL);
    }
    if (err == MP_OKAY) {
        /* Get order. */
        err = mp_read_radix(order, key->dp->order, MP_RADIX_HEX);
    }
    /* B5: calculate t = (r' + s') modn -- if t is 0 then failed */
    if (err == MP_OKAY) {
        /* t = r + s */
        err = mp_addmod(r, s, order, t);
    }
    if (err == MP_OKAY) {
        /* Check sum is valid. */
        if (mp_iszero(t) == MP_YES)
            err = MP_VAL;
    }
#ifdef DEBUG_ECC_SM2
    mp_dump("t = ", t, 0);
#endif

    /* B6: calculate the point (x1', y1')=[s']G + [t]PA */
    if (err == MP_OKAY) {
        /* Create two new points. */
        PO = wc_ecc_new_point_h(key->heap);
        if (PO == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        G  = wc_ecc_new_point_h(key->heap);
        if (G == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        /* Get the base point x-ordinate for SM2 curve. */
        err = mp_read_radix(G->x, key->dp->Gx, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        /* Get the base point y-ordinate for SM2 curve. */
        err = mp_read_radix(G->y, key->dp->Gy, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        /* Base point is in affine so z-ordinate is one. */
        err = mp_set(G->z, 1);
    }
    if (err == MP_OKAY) {
        /* Get a coefficient of SM2 curve. */
        err = mp_read_radix(Af, key->dp->Af, MP_RADIX_HEX);
    }
    if (err == MP_OKAY) {
        /* Get a prime of SM2 curve. */
        err = mp_read_radix(prime, key->dp->prime, MP_RADIX_HEX);
    }
#ifdef DEBUG_ECC_SM2
    printf("\n");
    mp_dump("G->x = ", G->x, 0);
    mp_dump("G->y = ", G->y, 0);
    mp_dump("s    = ", s, 0);
    mp_dump("P->x = ", key->pubkey.x, 0);
    mp_dump("P->y = ", key->pubkey.y, 0);
    mp_dump("t    = ", t, 0);
    mp_dump("Af   = ", Af, 0);
    mp_dump("prime= ", prime, 0);
#endif
    if (err == MP_OKAY) {
        /* [s']G + [t]PA */
        err = ecc_sm2_mul2add(G, s, &(key->pubkey), t, PO, Af, prime,
                key->heap);
    }
#ifdef DEBUG_ECC_SM2
    mp_dump("PO->x = ", PO->x, 0);
    mp_dump("PO->y = ", PO->y, 0);
    printf("\n\n");
#endif


    /* B7: calculate R=(e'+x1') modn, if R=r then passed */
    if (err == MP_OKAY) {
        /* Convert hash to an MP integer. */
        err = mp_read_unsigned_bin(e, hash, hashSz);
    }
    if (err == MP_OKAY) {
        /* e' + x1' */
        err = mp_addmod(e, PO->x, order, t);
    }
    /* Calculated value must be same as r. */
    if (err == MP_OKAY && mp_cmp(t, r) == MP_EQ) {
        *res = 1;
    }

    /* Dispose of allocated points. */
    if (PO != NULL) {
        wc_ecc_del_point_h(PO, key->heap);
    }
    if (G != NULL) {
        wc_ecc_del_point_h(G, key->heap);
    }

    /* Dispose of allocated MP integers. */
    if (e != NULL) {
        mp_free(e);
    }
    if (t != NULL) {
        mp_free(t);
    }
    if (prime != NULL) {
        mp_free(prime);
    }
    if (Af != NULL) {
        mp_free(Af);
    }
    if (order != NULL) {
        mp_free(order);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free allocated data. */
    XFREE(data, key->heap, DYNAMIC_TYPE_ECC);
#endif
#else
    (void)hashSz;

    err = NOT_COMPILED_IN;
#endif

    return err;
}


#ifndef NO_ASN
/* Verify digest of hash(ZA || M) using key on SM2 curve and encoded signature.
 *
 * res gets set to 1 on successful verify and 0 on failure
 *
 * Use wc_ecc_sm2_create_digest to calculate the digest.
 *
 * @param [in]  sig     DER encoded DSA signature.
 * @param [in]  sigSz   Length of signature in bytes.
 * @param [in]  hash    Array of bytes holding hash value.
 * @param [in]  hashSz  Size of hash in bytes.
 * @param [out] res     1 on successful verify and 0 on failure.
 * @param [in]  key     Public key on SM2 curve.
 * @return  0 on success (note this is even when successfully finding verify is
 * incorrect)
 * @return  BAD_FUNC_ARG when key, res, sig or hash is NULL.
 * @return  MP_VAL when r + s = 0.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int wc_ecc_sm2_verify_hash(const byte* sig, word32 sigSz, const byte* hash,
    word32 hashSz, int* res, ecc_key* key)
{
    int err = 0;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* r = NULL;
    mp_int* s = NULL;
#else
    mp_int r[1];
    mp_int s[1];
#endif

    /* Validate parameters. */
    if ((sig == NULL) || (hash == NULL) || (res == NULL) || (key == NULL) ||
            (key->dp == NULL)) {
        err = BAD_FUNC_ARG;
    }
    /* SM2 signature must be with a key on the SM2 curve. */
    if ((err == MP_OKAY) && (key->dp->id != ECC_SM2P256V1) &&
        (key->idx != ECC_CUSTOM_IDX)) {
        err = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == 0) {
        /* Allocate MP integers. */
        r = (mp_int*)XMALLOC(sizeof(mp_int), key->heap, DYNAMIC_TYPE_ECC);
        if (r == NULL) {
            err = MEMORY_E;
        }
        else {
            XMEMSET(r, 0, sizeof(*r));
        }
    }
    if (err == MP_OKAY) {
        s = (mp_int*)XMALLOC(sizeof(mp_int), key->heap, DYNAMIC_TYPE_ECC);
        if (s == NULL) {
            err = MEMORY_E;
        }
        else {
            XMEMSET(s, 0, sizeof(*s));
        }
    }
#else
    XMEMSET(r, 0, sizeof(*r));
    XMEMSET(s, 0, sizeof(*s));
#endif

    if (err == 0) {
        /* Decode the signature into R and S. */
        err = DecodeECC_DSA_Sig(sig, sigSz, r, s);
    }
    if (err == 0) {
        /* Verify the signature with hash, key, R and S. */
        err = wc_ecc_sm2_verify_hash_ex(r, s, hash, hashSz, res, key);
    }

    /* Dispose of allocated data. */
#ifdef WOLFSSL_SMALL_STACK
    if (r != NULL)
#endif
    {
        mp_free(r);
     }
#ifdef WOLFSSL_SMALL_STACK
    if (s != NULL)
#endif
    {
        mp_free(s);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free allocated data. */
    XFREE(s, key->heap, DYNAMIC_TYPE_ECC);
    XFREE(r, key->heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif /* NO_ASN */
#endif /* HAVE_ECC_VERIFY */

#endif /* WOLFSSL_SM2 && HAVE_ECC */
