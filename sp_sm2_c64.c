/* sp.c
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

/* Implementation by Sean Parkinson. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(WOLFSSL_HAVE_SP_ECC)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef RSA_LOW_MEM
#ifndef SP_RSA_PRIVATE_EXP_D
#define SP_RSA_PRIVATE_EXP_D
#endif

#ifndef WOLFSSL_SP_SMALL
#define WOLFSSL_SP_SMALL
#endif
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
#undef WOLFSSL_SP_SMALL_STACK
#define WOLFSSL_SP_SMALL_STACK
#endif

#include <wolfssl/wolfcrypt/sp.h>

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif

#ifndef WOLFSSL_SP_ASM
#if SP_WORD_SIZE == 64
#define SP_PRINT_NUM(var, name, total, words, bits)   \
    do {                                              \
        int ii;                                       \
        byte nb[((bits) + 7) / 8];                    \
        sp_digit _s[words];                           \
        XMEMCPY(_s, var, sizeof(_s));                 \
        sp_##total##_norm_##words(_s);                \
        sp_##total##_to_bin_##words(_s, nb);          \
        fprintf(stderr, name "=0x");                  \
        for (ii=0; ii<((bits) + 7) / 8; ii++)         \
            fprintf(stderr, "%02x", nb[ii]);          \
        fprintf(stderr, "\n");                        \
    } while (0)

#define SP_PRINT_VAL(var, name)                       \
    fprintf(stderr, name "=0x" SP_PRINT_FMT "\n", var)

#define SP_PRINT_INT(var, name)                       \
    fprintf(stderr, name "=%d\n", var)

#if defined(WOLFSSL_SP_SMALL) && defined(WOLFSSL_SP_SM2)
/* Mask for address to obfuscate which of the two address will be used. */
static const size_t addr_mask[2] = { 0, (size_t)-1 };
#endif

#if defined(WOLFSSL_SP_NONBLOCK) && (!defined(WOLFSSL_SP_NO_MALLOC) || \
                                     !defined(WOLFSSL_SP_SMALL))
    #error SP non-blocking requires small and no-malloc (WOLFSSL_SP_SMALL and WOLFSSL_SP_NO_MALLOC)
#endif

#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_SM2

/* Point structure to use. */
typedef struct sp_point_256 {
    /* X ordinate of point. */
    sp_digit x[2 * 5];
    /* Y ordinate of point. */
    sp_digit y[2 * 5];
    /* Z ordinate of point. */
    sp_digit z[2 * 5];
    /* Indicates point is at infinity. */
    int infinity;
} sp_point_256;

/* The modulus (prime) of the curve SM2 P256. */
static const sp_digit p256_sm2_mod[5] = {
    0xfffffffffffffL,0xff00000000fffL,0xfffffffffffffL,0xfffffffffffffL,
    0x0fffffffeffffL
};
/* The Montgomery normalizer for modulus of the curve P256. */
static const sp_digit p256_sm2_norm_mod[5] = {
    0x0000000000001L,0x00ffffffff000L,0x0000000000000L,0x0000000000000L,
    0x0000000010000L
};
/* The Montgomery multiplier for modulus of the curve P256. */
static const sp_digit p256_sm2_mp_mod = 0x0000000000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P256. */
static const sp_digit p256_sm2_order[5] = {
    0xbf40939d54123L,0x6b21c6052b53bL,0xfffffff7203dfL,0xfffffffffffffL,
    0x0fffffffeffffL
};
#endif
/* The order of the curve P256 minus 2. */
static const sp_digit p256_sm2_order2[5] = {
    0xbf40939d54121L,0x6b21c6052b53bL,0xfffffff7203dfL,0xfffffffffffffL,
    0x0fffffffeffffL
};
#if defined(HAVE_ECC_SIGN)
/* The Montgomery normalizer for order of the curve P256. */
static const sp_digit p256_sm2_norm_order[5] = {
    0x40bf6c62abeddL,0x94de39fad4ac4L,0x00000008dfc20L,0x0000000000000L,
    0x0000000010000L
};
#endif
#if defined(HAVE_ECC_SIGN)
/* The Montgomery multiplier for order of the curve P256. */
static const sp_digit p256_sm2_mp_order = 0xf9e8872350975L;
#endif
/* The base point of curve P256. */
static const sp_point_256 p256_sm2_base = {
    /* X ordinate */
    {
        0xa4589334c74c7L,0xbff2660be1715L,0xa39c9948fe30bL,0x81195f9904466L,
        0x032c4ae2c1f19L,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Y ordinate */
    {
        0xf32e52139f0a0L,0x7cc62a474002dL,0xb692153d0a987L,0x779c59bdcee36L,
        0x0bc3736a2f4f6L,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Z ordinate */
    {
        0x0000000000001L,0x0000000000000L,0x0000000000000L,0x0000000000000L,
        0x0000000000000L,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* infinity */
    0
};
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p256_sm2_b[5] = {
    0xcbd414d940e93L,0xf515ab8f92ddbL,0xf6509a7f39789L,0x5e344d5a9e4bcL,
    0x028e9fa9e9d9fL
};
#endif

#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_256_mul_sm2_5(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[4]) * b[4];
    r[9] = (sp_digit)(c >> 52);
    c &= 0xfffffffffffffL;
    for (k = 7; k >= 0; k--) {
        if (k >= 5) {
            i = k - 4;
            imax = 4;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint128)a[i]) * b[k - i];
        }
        c += lo >> 52;
        r[k + 2] += (sp_digit)(c >> 52);
        r[k + 1]  = (sp_digit)(c & 0xfffffffffffffL);
        c = lo & 0xfffffffffffffL;
    }
    r[0] = (sp_digit)c;
}

#else
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_256_mul_sm2_5(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_int128 t0   = ((sp_int128)a[ 0]) * b[ 0];
    sp_int128 t1   = ((sp_int128)a[ 0]) * b[ 1]
                 + ((sp_int128)a[ 1]) * b[ 0];
    sp_int128 t2   = ((sp_int128)a[ 0]) * b[ 2]
                 + ((sp_int128)a[ 1]) * b[ 1]
                 + ((sp_int128)a[ 2]) * b[ 0];
    sp_int128 t3   = ((sp_int128)a[ 0]) * b[ 3]
                 + ((sp_int128)a[ 1]) * b[ 2]
                 + ((sp_int128)a[ 2]) * b[ 1]
                 + ((sp_int128)a[ 3]) * b[ 0];
    sp_int128 t4   = ((sp_int128)a[ 0]) * b[ 4]
                 + ((sp_int128)a[ 1]) * b[ 3]
                 + ((sp_int128)a[ 2]) * b[ 2]
                 + ((sp_int128)a[ 3]) * b[ 1]
                 + ((sp_int128)a[ 4]) * b[ 0];
    sp_int128 t5   = ((sp_int128)a[ 1]) * b[ 4]
                 + ((sp_int128)a[ 2]) * b[ 3]
                 + ((sp_int128)a[ 3]) * b[ 2]
                 + ((sp_int128)a[ 4]) * b[ 1];
    sp_int128 t6   = ((sp_int128)a[ 2]) * b[ 4]
                 + ((sp_int128)a[ 3]) * b[ 3]
                 + ((sp_int128)a[ 4]) * b[ 2];
    sp_int128 t7   = ((sp_int128)a[ 3]) * b[ 4]
                 + ((sp_int128)a[ 4]) * b[ 3];
    sp_int128 t8   = ((sp_int128)a[ 4]) * b[ 4];

    t1   += t0  >> 52; r[ 0] = t0  & 0xfffffffffffffL;
    t2   += t1  >> 52; r[ 1] = t1  & 0xfffffffffffffL;
    t3   += t2  >> 52; r[ 2] = t2  & 0xfffffffffffffL;
    t4   += t3  >> 52; r[ 3] = t3  & 0xfffffffffffffL;
    t5   += t4  >> 52; r[ 4] = t4  & 0xfffffffffffffL;
    t6   += t5  >> 52; r[ 5] = t5  & 0xfffffffffffffL;
    t7   += t6  >> 52; r[ 6] = t6  & 0xfffffffffffffL;
    t8   += t7  >> 52; r[ 7] = t7  & 0xfffffffffffffL;
    r[9] = (sp_digit)(t8 >> 52);
                       r[8] = t8 & 0xfffffffffffffL;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_sm2_5(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[4]) * a[4];
    r[9] = (sp_digit)(c >> 52);
    c = (c & 0xfffffffffffffL) << 52;
    for (k = 7; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 4) {
            imax = k;
        }
        else {
            imax = 4;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint128)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 104);
        r[k + 1]  = (sp_digit)((c >> 52) & 0xfffffffffffffL);
        c = (c & 0xfffffffffffffL) << 52;
    }
    r[0] = (sp_digit)(c >> 52);
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_sm2_5(sp_digit* r, const sp_digit* a)
{
    sp_int128 t0   =  ((sp_int128)a[ 0]) * a[ 0];
    sp_int128 t1   = (((sp_int128)a[ 0]) * a[ 1]) * 2;
    sp_int128 t2   = (((sp_int128)a[ 0]) * a[ 2]) * 2
                 +  ((sp_int128)a[ 1]) * a[ 1];
    sp_int128 t3   = (((sp_int128)a[ 0]) * a[ 3]
                 +  ((sp_int128)a[ 1]) * a[ 2]) * 2;
    sp_int128 t4   = (((sp_int128)a[ 0]) * a[ 4]
                 +  ((sp_int128)a[ 1]) * a[ 3]) * 2
                 +  ((sp_int128)a[ 2]) * a[ 2];
    sp_int128 t5   = (((sp_int128)a[ 1]) * a[ 4]
                 +  ((sp_int128)a[ 2]) * a[ 3]) * 2;
    sp_int128 t6   = (((sp_int128)a[ 2]) * a[ 4]) * 2
                 +  ((sp_int128)a[ 3]) * a[ 3];
    sp_int128 t7   = (((sp_int128)a[ 3]) * a[ 4]) * 2;
    sp_int128 t8   =  ((sp_int128)a[ 4]) * a[ 4];

    t1   += t0  >> 52; r[ 0] = t0  & 0xfffffffffffffL;
    t2   += t1  >> 52; r[ 1] = t1  & 0xfffffffffffffL;
    t3   += t2  >> 52; r[ 2] = t2  & 0xfffffffffffffL;
    t4   += t3  >> 52; r[ 3] = t3  & 0xfffffffffffffL;
    t5   += t4  >> 52; r[ 4] = t4  & 0xfffffffffffffL;
    t6   += t5  >> 52; r[ 5] = t5  & 0xfffffffffffffL;
    t7   += t6  >> 52; r[ 6] = t6  & 0xfffffffffffffL;
    t8   += t7  >> 52; r[ 7] = t7  & 0xfffffffffffffL;
    r[9] = (sp_digit)(t8 >> 52);
                       r[8] = t8 & 0xfffffffffffffL;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_add_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_add_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_sub_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_sub_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] - b[ 0];
    r[ 1] = a[ 1] - b[ 1];
    r[ 2] = a[ 2] - b[ 2];
    r[ 3] = a[ 3] - b[ 3];
    r[ 4] = a[ 4] - b[ 4];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_256_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 52
    int i;
    sp_digit j = (sp_digit)0 - (sp_digit)a->used;
    int o = 0;

    for (i = 0; i < size; i++) {
        sp_digit mask = (sp_digit)0 - (j >> 51);
        r[i] = a->dp[o] & mask;
        j++;
        o += (int)(j >> 51);
    }
#elif DIGIT_BIT > 52
    unsigned int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < (unsigned int)a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xfffffffffffffL;
        s = 52U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 52U) <= (word32)DIGIT_BIT) {
            s += 52U;
            r[j] &= 0xfffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = (sp_digit)0;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    unsigned int i;
    int j = 0;
    int s = 0;

    r[0] = 0;
    for (i = 0; i < (unsigned int)a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 52) {
            r[j] &= 0xfffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 52 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Convert a point of type ecc_point to type sp_point_256.
 *
 * p   Point of type sp_point_256 (result).
 * pm  Point of type ecc_point.
 */
static void sp_256_point_from_ecc_point_5(sp_point_256* p,
        const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_256_from_mp(p->x, 5, pm->x);
    sp_256_from_mp(p->y, 5, pm->y);
    sp_256_from_mp(p->z, 5, pm->z);
    p->infinity = 0;
}

/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_256_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (256 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 52
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 5);
        r->used = 5;
        mp_clamp(r);
#elif DIGIT_BIT < 52
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 5; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 52) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 52 - s;
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 5; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 52 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 52 - s;
            }
            else {
                s += 52;
            }
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Convert a point of type sp_point_256 to type ecc_point.
 *
 * p   Point of type sp_point_256.
 * pm  Point of type ecc_point (result).
 * returns MEMORY_E when allocation of memory in ecc_point fails otherwise
 * MP_OKAY.
 */
static int sp_256_point_to_ecc_point_5(const sp_point_256* p, ecc_point* pm)
{
    int err;

    err = sp_256_to_mp(p->x, pm->x);
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, pm->y);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, pm->z);
    }

    return err;
}

#define sp_256_mont_reduce_order_sm2_5         sp_256_mont_reduce_sm2_5

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_256_cmp_sm2_5(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=4; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 51);
    }
#else
    r |= (a[ 4] - b[ 4]) & (0 - (sp_digit)1);
    r |= (a[ 3] - b[ 3]) & ~(((sp_digit)0 - r) >> 51);
    r |= (a[ 2] - b[ 2]) & ~(((sp_digit)0 - r) >> 51);
    r |= (a[ 1] - b[ 1]) & ~(((sp_digit)0 - r) >> 51);
    r |= (a[ 0] - b[ 0]) & ~(((sp_digit)0 - r) >> 51);
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_256_cond_sub_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    r[ 0] = a[ 0] - (b[ 0] & m);
    r[ 1] = a[ 1] - (b[ 1] & m);
    r[ 2] = a[ 2] - (b[ 2] & m);
    r[ 3] = a[ 3] - (b[ 3] & m);
    r[ 4] = a[ 4] - (b[ 4] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_add_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 4; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0xfffffffffffffL;
        t[1] += t[0] >> 52;
        r[i+1] = t[1] & 0xfffffffffffffL;
        t[2] += t[1] >> 52;
        r[i+2] = t[2] & 0xfffffffffffffL;
        t[3] += t[2] >> 52;
        r[i+3] = t[3] & 0xfffffffffffffL;
        t[0]  = t[3] >> 52;
    }
    t[0] += (tb * a[4]) + r[4];
    r[4] = t[0] & 0xfffffffffffffL;
    r[5] +=  (sp_digit)(t[0] >> 52);
#else
    sp_int128 tb = b;
    sp_int128 t[5];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    r[ 0] += (sp_digit)                 (t[ 0] & 0xfffffffffffffL);
    r[ 1] += (sp_digit)((t[ 0] >> 52) + (t[ 1] & 0xfffffffffffffL));
    r[ 2] += (sp_digit)((t[ 1] >> 52) + (t[ 2] & 0xfffffffffffffL));
    r[ 3] += (sp_digit)((t[ 2] >> 52) + (t[ 3] & 0xfffffffffffffL));
    r[ 4] += (sp_digit)((t[ 3] >> 52) + (t[ 4] & 0xfffffffffffffL));
    r[ 5] += (sp_digit) (t[ 4] >> 52);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 52 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_256_norm_5(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 4; i++) {
        a[i+1] += a[i] >> 52;
        a[i] &= 0xfffffffffffffL;
    }
#else
    a[1] += a[0] >> 52; a[0] &= 0xfffffffffffffL;
    a[2] += a[1] >> 52; a[1] &= 0xfffffffffffffL;
    a[3] += a[2] >> 52; a[2] &= 0xfffffffffffffL;
    a[4] += a[3] >> 52; a[3] &= 0xfffffffffffffL;
#endif /* WOLFSSL_SP_SMALL */
}

/* Shift the result in the high 256 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_256_mont_shift_5(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_uint64 n;

    n = a[4] >> 48;
    for (i = 0; i < 4; i++) {
        n += (sp_uint64)a[5 + i] << 4;
        r[i] = n & 0xfffffffffffffL;
        n >>= 52;
    }
    n += (sp_uint64)a[9] << 4;
    r[4] = n;
#else
    sp_uint64 n;

    n  = a[4] >> 48;
    n += (sp_uint64)a[ 5] << 4U; r[ 0] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (sp_uint64)a[ 6] << 4U; r[ 1] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (sp_uint64)a[ 7] << 4U; r[ 2] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (sp_uint64)a[ 8] << 4U; r[ 3] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (sp_uint64)a[ 9] << 4U; r[ 4] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[5], 0, sizeof(*r) * 5U);
}

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_256_mont_reduce_sm2_5(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    if (mp != 1) {
        for (i=0; i<4; i++) {
            mu = (a[i] * mp) & 0xfffffffffffffL;
            sp_256_mul_add_sm2_5(a+i, m, mu);
            a[i+1] += a[i] >> 52;
        }
        mu = (a[i] * mp) & 0xffffffffffffL;
        sp_256_mul_add_sm2_5(a+i, m, mu);
        a[i+1] += a[i] >> 52;
        a[i] &= 0xfffffffffffffL;
    }
    else {
        for (i=0; i<4; i++) {
            mu = a[i] & 0xfffffffffffffL;
            sp_256_mul_add_sm2_5(a+i, p256_sm2_mod, mu);
            a[i+1] += a[i] >> 52;
        }
        mu = a[i] & 0xffffffffffffL;
        sp_256_mul_add_sm2_5(a+i, p256_sm2_mod, mu);
        a[i+1] += a[i] >> 52;
        a[i] &= 0xfffffffffffffL;
    }

    sp_256_mont_shift_5(a, a);
    sp_256_cond_sub_sm2_5(a, a, m, 0 - (((a[4] >> 48) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(a);
}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_mul_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_256_mul_sm2_5(r, a, b);
    sp_256_mont_reduce_sm2_5(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_sqr_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_256_sqr_sm2_5(r, a);
    sp_256_mont_reduce_sm2_5(r, m, mp);
}

#if !defined(WOLFSSL_SP_SMALL)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * n   Number of times to square.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_sqr_n_sm2_5(sp_digit* r,
    const sp_digit* a, int n, const sp_digit* m, sp_digit mp)
{
    sp_256_mont_sqr_sm2_5(r, a, m, mp);
    for (; n > 1; n--) {
        sp_256_mont_sqr_sm2_5(r, r, m, mp);
    }
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Mod-2 for the SM2 P256 curve. */
static const uint64_t p256_sm2_mod_minus_2[4] = {
    0xfffffffffffffffdU,0xffffffff00000000U,0xffffffffffffffffU,
    0xfffffffeffffffffU
};
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P256 curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_256_mont_inv_sm2_5(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 5);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_sm2_5(t, t, p256_sm2_mod, p256_sm2_mp_mod);
        if (p256_sm2_mod_minus_2[i / 64] & ((sp_digit)1 << (i % 64)))
            sp_256_mont_mul_sm2_5(t, t, a, p256_sm2_mod, p256_sm2_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 5);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 5;
    sp_digit* t3 = td + 4 * 5;
    sp_digit* t4 = td + 6 * 5;
    /* 0x2 */
    sp_256_mont_sqr_sm2_5(t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0x3 */
    sp_256_mont_mul_sm2_5(t2, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xc */
    sp_256_mont_sqr_n_sm2_5(t1, t2, 2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xd */
    sp_256_mont_mul_sm2_5(t3, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf */
    sp_256_mont_mul_sm2_5(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf0 */
    sp_256_mont_sqr_n_sm2_5(t1, t2, 4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfd */
    sp_256_mont_mul_sm2_5(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff */
    sp_256_mont_mul_sm2_5(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff00 */
    sp_256_mont_sqr_n_sm2_5(t1, t2, 8, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffd */
    sp_256_mont_mul_sm2_5(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff */
    sp_256_mont_mul_sm2_5(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff0000 */
    sp_256_mont_sqr_n_sm2_5(t1, t2, 16, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffd */
    sp_256_mont_mul_sm2_5(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe */
    sp_256_mont_mul_sm2_5(t2, t3, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffffffff */
    sp_256_mont_mul_sm2_5(t4, t2, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe00000000 */
    sp_256_mont_sqr_n_sm2_5(t2, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff */
    sp_256_mont_mul_sm2_5(t2, t4, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff00000000 */
    sp_256_mont_sqr_n_sm2_5(t1, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff */
    sp_256_mont_mul_sm2_5(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_5(t1, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_5(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_5(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_5(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff0000000000000000 */
    sp_256_mont_sqr_n_sm2_5(r, r, 64, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff */
    sp_256_mont_mul_sm2_5(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff00000000 */
    sp_256_mont_sqr_n_sm2_5(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd */
    sp_256_mont_mul_sm2_5(r, r, t3, p256_sm2_mod, p256_sm2_mp_mod);
#endif /* WOLFSSL_SP_SMALL */
}

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_256_map_sm2_5(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    sp_int64 n;

    sp_256_mont_inv_sm2_5(t1, p->z, t + 2*5);

    sp_256_mont_sqr_sm2_5(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    /* x /= z^2 */
    sp_256_mont_mul_sm2_5(r->x, p->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->x + 5, 0, sizeof(sp_digit) * 5U);
    sp_256_mont_reduce_sm2_5(r->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_256_cmp_sm2_5(r->x, p256_sm2_mod);
    sp_256_cond_sub_sm2_5(r->x, r->x, p256_sm2_mod, (sp_digit)~(n >> 51));
    sp_256_norm_5(r->x);

    /* y /= z^3 */
    sp_256_mont_mul_sm2_5(r->y, p->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->y + 5, 0, sizeof(sp_digit) * 5U);
    sp_256_mont_reduce_sm2_5(r->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_256_cmp_sm2_5(r->y, p256_sm2_mod);
    sp_256_cond_sub_sm2_5(r->y, r->y, p256_sm2_mod, (sp_digit)~(n >> 51));
    sp_256_norm_5(r->y);

    XMEMSET(r->z, 0, sizeof(r->z) / 2);
    r->z[0] = 1;
}

/* Add two Montgomery form numbers (r = a + b % m).
 *
 * r   Result of addition.
 * a   First number to add in Montgomery form.
 * b   Second number to add in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_add_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    sp_digit over;
    (void)sp_256_add_sm2_5(r, a, b);
    sp_256_norm_5(r);
    over = r[4] > m[4];
    sp_256_cond_sub_sm2_5(r, r, m, ~((over - 1) >> 63));
    sp_256_norm_5(r);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_dbl_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit over;
    (void)sp_256_add_sm2_5(r, a, a);
    sp_256_norm_5(r);
    over = r[4] > m[4];
    sp_256_cond_sub_sm2_5(r, r, m, ~((over - 1) >> 63));
    sp_256_norm_5(r);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_tpl_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit over;
    (void)sp_256_add_sm2_5(r, a, a);
    sp_256_norm_5(r);
    over = r[4] > m[4];
    sp_256_cond_sub_sm2_5(r, r, m, ~((over - 1) >> 63));
    sp_256_norm_5(r);
    (void)sp_256_add_sm2_5(r, r, a);
    sp_256_norm_5(r);
    over = r[4] > m[4];
    sp_256_cond_sub_sm2_5(r, r, m, ~((over - 1) >> 63));
    sp_256_norm_5(r);
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_256_cond_add_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] + (b[i] & m);
    }
}
#endif /* WOLFSSL_SP_SMALL */

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_256_cond_add_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    r[ 0] = a[ 0] + (b[ 0] & m);
    r[ 1] = a[ 1] + (b[ 1] & m);
    r[ 2] = a[ 2] + (b[ 2] & m);
    r[ 3] = a[ 3] + (b[ 3] & m);
    r[ 4] = a[ 4] + (b[ 4] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_sub_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_256_sub_sm2_5(r, a, b);
    sp_256_norm_5(r);
    sp_256_cond_add_sm2_5(r, r, m, r[4] >> 48);
    sp_256_norm_5(r);
}

/* Shift number left one bit.
 * Bottom bit is lost.
 *
 * r  Result of shift.
 * a  Number to shift.
 */
SP_NOINLINE static void sp_256_rshift1_sm2_5(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<4; i++) {
        r[i] = (a[i] >> 1) + ((a[i + 1] << 51) & 0xfffffffffffffL);
    }
#else
    r[0] = (a[0] >> 1) + ((a[1] << 51) & 0xfffffffffffffL);
    r[1] = (a[1] >> 1) + ((a[2] << 51) & 0xfffffffffffffL);
    r[2] = (a[2] >> 1) + ((a[3] << 51) & 0xfffffffffffffL);
    r[3] = (a[3] >> 1) + ((a[4] << 51) & 0xfffffffffffffL);
#endif
    r[4] = a[4] >> 1;
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
static void sp_256_mont_div2_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_256_cond_add_sm2_5(r, a, m, 0 - (a[0] & 1));
    sp_256_norm_5(r);
    sp_256_rshift1_sm2_5(r, r);
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_sm2_5(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;

    x = r->x;
    y = r->y;
    z = r->z;
    /* Put infinity into result. */
    if (r != p) {
        r->infinity = p->infinity;
    }

    /* T1 = Z * Z */
    sp_256_mont_sqr_sm2_5(t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = Y * Z */
    sp_256_mont_mul_sm2_5(z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = 2Z */
    sp_256_mont_dbl_sm2_5(z, z, p256_sm2_mod);
    /* T2 = X - T1 */
    sp_256_mont_sub_sm2_5(t2, p->x, t1, p256_sm2_mod);
    /* T1 = X + T1 */
    sp_256_mont_add_sm2_5(t1, p->x, t1, p256_sm2_mod);
    /* T2 = T1 * T2 */
    sp_256_mont_mul_sm2_5(t2, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* T1 = 3T2 */
    sp_256_mont_tpl_sm2_5(t1, t2, p256_sm2_mod);
    /* Y = 2Y */
    sp_256_mont_dbl_sm2_5(y, p->y, p256_sm2_mod);
    /* Y = Y * Y */
    sp_256_mont_sqr_sm2_5(y, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = Y * Y */
    sp_256_mont_sqr_sm2_5(t2, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = T2/2 */
    sp_256_mont_div2_sm2_5(t2, t2, p256_sm2_mod);
    /* Y = Y * X */
    sp_256_mont_mul_sm2_5(y, y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = T1 * T1 */
    sp_256_mont_sqr_sm2_5(x, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_5(x, x, y, p256_sm2_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_5(x, x, y, p256_sm2_mod);
    /* Y = Y - X */
    sp_256_mont_sub_sm2_5(y, y, x, p256_sm2_mod);
    /* Y = Y * T1 */
    sp_256_mont_mul_sm2_5(y, y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* Y = Y - T2 */
    sp_256_mont_sub_sm2_5(y, y, t2, p256_sm2_mod);
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_dbl_5_ctx {
    int state;
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
} sp_256_proj_point_dbl_5_ctx;

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_dbl_sm2_5_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_point_256* p, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_dbl_5_ctx* ctx = (sp_256_proj_point_dbl_sm2_5_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_proj_point_dbl_5_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0:
        ctx->t1 = t;
        ctx->t2 = t + 2*5;
        ctx->x = r->x;
        ctx->y = r->y;
        ctx->z = r->z;

        /* Put infinity into result. */
        if (r != p) {
            r->infinity = p->infinity;
        }
        ctx->state = 1;
        break;
    case 1:
        /* T1 = Z * Z */
        sp_256_mont_sqr_sm2_5(ctx->t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        /* Z = Y * Z */
        sp_256_mont_mul_sm2_5(ctx->z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        /* Z = 2Z */
        sp_256_mont_dbl_sm2_5(ctx->z, ctx->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4:
        /* T2 = X - T1 */
        sp_256_mont_sub_sm2_5(ctx->t2, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 5;
        break;
    case 5:
        /* T1 = X + T1 */
        sp_256_mont_add_sm2_5(ctx->t1, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 6;
        break;
    case 6:
        /* T2 = T1 * T2 */
        sp_256_mont_mul_sm2_5(ctx->t2, ctx->t1, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* T1 = 3T2 */
        sp_256_mont_tpl_sm2_5(ctx->t1, ctx->t2, p256_sm2_mod);
        ctx->state = 8;
        break;
    case 8:
        /* Y = 2Y */
        sp_256_mont_dbl_sm2_5(ctx->y, p->y, p256_sm2_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Y = Y * Y */
        sp_256_mont_sqr_sm2_5(ctx->y, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 10;
        break;
    case 10:
        /* T2 = Y * Y */
        sp_256_mont_sqr_sm2_5(ctx->t2, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 11;
        break;
    case 11:
        /* T2 = T2/2 */
        sp_256_mont_div2_sm2_5(ctx->t2, ctx->t2, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* Y = Y * X */
        sp_256_mont_mul_sm2_5(ctx->y, ctx->y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        /* X = T1 * T1 */
        sp_256_mont_sqr_sm2_5(ctx->x, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        /* X = X - Y */
        sp_256_mont_sub_sm2_5(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 15;
        break;
    case 15:
        /* X = X - Y */
        sp_256_mont_sub_sm2_5(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 16;
        break;
    case 16:
        /* Y = Y - X */
        sp_256_mont_sub_sm2_5(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
        ctx->state = 17;
        break;
    case 17:
        /* Y = Y * T1 */
        sp_256_mont_mul_sm2_5(ctx->y, ctx->y, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        /* Y = Y - T2 */
        sp_256_mont_sub_sm2_5(ctx->y, ctx->y, ctx->t2, p256_sm2_mod);
        ctx->state = 19;
        /* fall-through */
    case 19:
        err = MP_OKAY;
        break;
    }

    if (err == MP_OKAY && ctx->state != 19) {
        err = FP_WOULDBLOCK;
    }

    return err;
}
#endif /* WOLFSSL_SP_NONBLOCK */
/* Compare two numbers to determine if they are equal.
 * Constant time implementation.
 *
 * a  First number to compare.
 * b  Second number to compare.
 * returns 1 when equal and 0 otherwise.
 */
static int sp_256_cmp_equal_5(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
            (a[3] ^ b[3]) | (a[4] ^ b[4])) == 0;
}

/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_256_iszero_5(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4]) == 0;
}


/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_sm2_5(sp_point_256* r,
        const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t6 = t;
    sp_digit* t1 = t + 2*5;
    sp_digit* t2 = t + 4*5;
    sp_digit* t3 = t + 6*5;
    sp_digit* t4 = t + 8*5;
    sp_digit* t5 = t + 10*5;

    /* U1 = X1*Z2^2 */
    sp_256_mont_sqr_sm2_5(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t1, t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_5(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_5(t3, t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_5(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    /* Check double */
    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_5(t2, t1) &
            sp_256_cmp_equal_5(t4, t3)) {
        sp_256_proj_point_dbl_sm2_5(r, p, t);
    }
    else {
        sp_digit* x = t6;
        sp_digit* y = t1;
        sp_digit* z = t2;

        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_5(t2, t2, t1, p256_sm2_mod);
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_5(t4, t4, t3, p256_sm2_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_5(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(y, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_5(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(z, z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_5(x, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(x, x, t5, p256_sm2_mod);
        sp_256_mont_mul_sm2_5(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_5(t3, y, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(x, x, t3, p256_sm2_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_5(y, y, x, p256_sm2_mod);
        sp_256_mont_mul_sm2_5(y, y, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(y, y, t5, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 5; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 5; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 5; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_add_5_ctx {
    int state;
    sp_256_proj_point_dbl_5_ctx dbl_ctx;
    const sp_point_256* ap[2];
    sp_point_256* rp[2];
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* t3;
    sp_digit* t4;
    sp_digit* t5;
    sp_digit* t6;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
} sp_256_proj_point_add_5_ctx;

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_add_sm2_5_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_add_5_ctx* ctx = (sp_256_proj_point_add_sm2_5_ctx*)sp_ctx->data;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_256* a = p;
        p = q;
        q = a;
    }

    typedef char ctx_size_test[sizeof(sp_256_proj_point_add_5_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0: /* INIT */
        ctx->t6 = t;
        ctx->t1 = t + 2*5;
        ctx->t2 = t + 4*5;
        ctx->t3 = t + 6*5;
        ctx->t4 = t + 8*5;
        ctx->t5 = t + 10*5;
        ctx->x = ctx->t6;
        ctx->y = ctx->t1;
        ctx->z = ctx->t2;

        ctx->state = 1;
        break;
    case 1:
        /* U1 = X1*Z2^2 */
        sp_256_mont_sqr_sm2_5(ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        sp_256_mont_mul_sm2_5(ctx->t3, ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        sp_256_mont_mul_sm2_5(ctx->t1, ctx->t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 4;
        break;
    case 4:
        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_sm2_5(ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 5;
        break;
    case 5:
        sp_256_mont_mul_sm2_5(ctx->t4, ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 6;
        break;
    case 6:
        sp_256_mont_mul_sm2_5(ctx->t2, ctx->t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* S1 = Y1*Z2^3 */
        sp_256_mont_mul_sm2_5(ctx->t3, ctx->t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 8;
        break;
    case 8:
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_sm2_5(ctx->t4, ctx->t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Check double */
        if ((~p->infinity) & (~q->infinity) &
                sp_256_cmp_equal_5(ctx->t2, ctx->t1) &
                sp_256_cmp_equal_5(ctx->t4, ctx->t3)) {
            XMEMSET(&ctx->dbl_ctx, 0, sizeof(ctx->dbl_ctx));
            sp_256_proj_point_dbl_sm2_5(r, p, t);
            ctx->state = 25;
        }
        else {
            ctx->state = 10;
        }
        break;
    case 10:
        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_5(ctx->t2, ctx->t2, ctx->t1, p256_sm2_mod);
        ctx->state = 11;
        break;
    case 11:
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_5(ctx->t4, ctx->t4, ctx->t3, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_5(ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        sp_256_mont_mul_sm2_5(ctx->y, ctx->t1, ctx->t5, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        sp_256_mont_mul_sm2_5(ctx->t5, ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 15;
        break;
    case 15:
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_5(ctx->z, p->z, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 16;
        break;
    case 16:
        sp_256_mont_mul_sm2_5(ctx->z, ctx->z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 17;
        break;
    case 17:
        sp_256_mont_sqr_sm2_5(ctx->x, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        sp_256_mont_sub_sm2_5(ctx->x, ctx->x, ctx->t5, p256_sm2_mod);
        ctx->state = 19;
        break;
    case 19:
        sp_256_mont_mul_sm2_5(ctx->t5, ctx->t5, ctx->t3, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 20;
        break;
    case 20:
        sp_256_mont_dbl_sm2_5(ctx->t3, ctx->y, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(ctx->x, ctx->x, ctx->t3, p256_sm2_mod);
        ctx->state = 21;
        break;
    case 21:
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_5(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
        ctx->state = 22;
        break;
    case 22:
        sp_256_mont_mul_sm2_5(ctx->y, ctx->y, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 23;
        break;
    case 23:
        sp_256_mont_sub_sm2_5(ctx->y, ctx->y, ctx->t5, p256_sm2_mod);
        ctx->state = 24;
        break;
    case 24:
    {
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 5; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (ctx->x[i] & maskt);
            }
            for (i = 0; i < 5; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (ctx->y[i] & maskt);
            }
            for (i = 0; i < 5; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (ctx->z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
        ctx->state = 25;
        break;
    }
    case 25:
        err = MP_OKAY;
        break;
    }

    if (err == MP_OKAY && ctx->state != 25) {
        err = FP_WOULDBLOCK;
    }
    return err;
}
#endif /* WOLFSSL_SP_NONBLOCK */

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_d_sm2_5(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 5; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0xfffffffffffffL);
        t >>= 52;
    }
    r[5] = (sp_digit)t;
#else
    sp_int128 tb = b;
    sp_int128 t[5];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    r[ 0] = (sp_digit)                 (t[ 0] & 0xfffffffffffffL);
    r[ 1] = (sp_digit)((t[ 0] >> 52) + (t[ 1] & 0xfffffffffffffL));
    r[ 2] = (sp_digit)((t[ 1] >> 52) + (t[ 2] & 0xfffffffffffffL));
    r[ 3] = (sp_digit)((t[ 2] >> 52) + (t[ 3] & 0xfffffffffffffL));
    r[ 4] = (sp_digit)((t[ 3] >> 52) + (t[ 4] & 0xfffffffffffffL));
    r[ 5] = (sp_digit) (t[ 4] >> 52);
#endif /* WOLFSSL_SP_SMALL */
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_d_sm2_10(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 10; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0xfffffffffffffL);
        t >>= 52;
    }
    r[10] = (sp_digit)t;
#else
    sp_int128 tb = b;
    sp_int128 t[10];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    t[ 5] = tb * a[ 5];
    t[ 6] = tb * a[ 6];
    t[ 7] = tb * a[ 7];
    t[ 8] = tb * a[ 8];
    t[ 9] = tb * a[ 9];
    r[ 0] = (sp_digit)                 (t[ 0] & 0xfffffffffffffL);
    r[ 1] = (sp_digit)((t[ 0] >> 52) + (t[ 1] & 0xfffffffffffffL));
    r[ 2] = (sp_digit)((t[ 1] >> 52) + (t[ 2] & 0xfffffffffffffL));
    r[ 3] = (sp_digit)((t[ 2] >> 52) + (t[ 3] & 0xfffffffffffffL));
    r[ 4] = (sp_digit)((t[ 3] >> 52) + (t[ 4] & 0xfffffffffffffL));
    r[ 5] = (sp_digit)((t[ 4] >> 52) + (t[ 5] & 0xfffffffffffffL));
    r[ 6] = (sp_digit)((t[ 5] >> 52) + (t[ 6] & 0xfffffffffffffL));
    r[ 7] = (sp_digit)((t[ 6] >> 52) + (t[ 7] & 0xfffffffffffffL));
    r[ 8] = (sp_digit)((t[ 7] >> 52) + (t[ 8] & 0xfffffffffffffL));
    r[ 9] = (sp_digit)((t[ 8] >> 52) + (t[ 9] & 0xfffffffffffffL));
    r[10] = (sp_digit) (t[ 9] >> 52);
#endif /* WOLFSSL_SP_SMALL */
}

SP_NOINLINE static void sp_256_rshift_sm2_5(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<4; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (52 - n))) & 0xfffffffffffffL;
    }
#else
    for (i=0; i<0; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (52 - n)) & 0xfffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (52 - n)) & 0xfffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (52 - n)) & 0xfffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (52 - n)) & 0xfffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (52 - n)) & 0xfffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (52 - n)) & 0xfffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (52 - n)) & 0xfffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (52 - n)) & 0xfffffffffffffL);
    }
    r[0] = (a[0] >> n) | ((a[1] << (52 - n)) & 0xfffffffffffffL);
    r[1] = (a[1] >> n) | ((a[2] << (52 - n)) & 0xfffffffffffffL);
    r[2] = (a[2] >> n) | ((a[3] << (52 - n)) & 0xfffffffffffffL);
    r[3] = (a[3] >> n) | ((a[4] << (52 - n)) & 0xfffffffffffffL);
#endif /* WOLFSSL_SP_SMALL */
    r[4] = a[4] >> n;
}

static WC_INLINE sp_digit sp_256_div_word_5(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 52) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 52) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 52) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 52);
    sp_digit t0 = (sp_digit)(d & 0xfffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 50; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 51) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 52);
    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 104) - (sp_digit)(d >> 104);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 52) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 21) + 1;

    t = (sp_digit)(d >> 42);
    t = (t / dv) << 21;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 11);
    t = t / (dv << 10);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_256_word_div_word_5(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_256_div_sm2_5(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t1 = NULL;
#else
    sp_digit t1[4 * 5 + 3];
#endif
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;

#ifdef WOLFSSL_SP_SMALL_STACK
    t1 = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 5 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (t1 == NULL)
        err = MEMORY_E;
#endif

    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 10 + 1;
        sd = t2 + 5 + 1;

        sp_256_mul_d_sm2_5(sd, d, (sp_digit)1 << 4);
        sp_256_mul_d_sm2_10(t1, a, (sp_digit)1 << 4);
        dv = sd[4];
        t1[5 + 5] += t1[5 + 5 - 1] >> 52;
        t1[5 + 5 - 1] &= 0xfffffffffffffL;
        for (i=5; i>=0; i--) {
            r1 = sp_256_div_word_5(t1[5 + i], t1[5 + i - 1], dv);

            sp_256_mul_d_sm2_5(t2, sd, r1);
            (void)sp_256_sub_sm2_5(&t1[i], &t1[i], t2);
            sp_256_norm_5(&t1[i]);
            t1[5 + i] -= t2[5];
            t1[5 + i] += t1[5 + i - 1] >> 52;
            t1[5 + i - 1] &= 0xfffffffffffffL;
            r1 = sp_256_div_word_5(-t1[5 + i], -t1[5 + i - 1], dv);
            r1 -= t1[5 + i];
            sp_256_mul_d_sm2_5(t2, sd, r1);
            (void)sp_256_add_sm2_5(&t1[i], &t1[i], t2);
            t1[5 + i] += t1[5 + i - 1] >> 52;
            t1[5 + i - 1] &= 0xfffffffffffffL;
        }
        t1[5 - 1] += t1[5 - 2] >> 52;
        t1[5 - 2] &= 0xfffffffffffffL;
        r1 = sp_256_word_div_word_5(t1[5 - 1], dv);

        sp_256_mul_d_sm2_5(t2, sd, r1);
        sp_256_sub_sm2_5(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 10U);
        for (i=0; i<4; i++) {
            r[i+1] += r[i] >> 52;
            r[i] &= 0xfffffffffffffL;
        }
        sp_256_cond_add_sm2_5(r, r, sd, r[4] >> 63);

        sp_256_norm_5(r);
        sp_256_rshift_sm2_5(r, r, 4);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(t1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_256_mod_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_256_div_sm2_5(a, m, NULL, r);
}

/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mod_mul_norm_sm2_5(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_256_mul_sm2_5(r, a, p256_sm2_norm_mod);
    return sp_256_mod_sm2_5(r, r, m);
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Small implementation using add and double that is cache attack resistant but
 * allocates memory rather than use large stacks.
 * 256 adds and doubles.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_sm2_5(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[3];
    sp_digit tmp[2 * 5 * 6];
#endif
    sp_digit n;
    int i;
    int c;
    int y;
    int err = MP_OKAY;

    /* Implementation is constant time. */
    (void)ct;
    (void)heap;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 3, heap,
                                     DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 6, heap,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        XMEMSET(t, 0, sizeof(sp_point_256) * 3);

        /* t[0] = {0, 0, 1} * norm */
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_256_mod_mul_norm_sm2_5(t[1].x, g->x, p256_sm2_mod);
    }
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_sm2_5(t[1].y, g->y, p256_sm2_mod);
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_sm2_5(t[1].z, g->z, p256_sm2_mod);

    if (err == MP_OKAY) {
        i = 4;
        c = 48;
        n = k[i--] << (52 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = k[i--];
                c = 52;
            }

            y = (n >> 51) & 1;
            n <<= 1;

            sp_256_proj_point_add_sm2_5(&t[y^1], &t[0], &t[1], tmp);

            XMEMCPY(&t[2], (void*)(((size_t)&t[0] & addr_mask[y^1]) +
                                   ((size_t)&t[1] & addr_mask[y])),
                    sizeof(sp_point_256));
            sp_256_proj_point_dbl_sm2_5(&t[2], &t[2], tmp);
            XMEMCPY((void*)(((size_t)&t[0] & addr_mask[y^1]) +
                            ((size_t)&t[1] & addr_mask[y])), &t[2],
                    sizeof(sp_point_256));
        }

        if (map != 0) {
            sp_256_map_sm2_5(r, &t[0], tmp);
        }
        else {
            XMEMCPY(r, &t[0], sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (tmp != NULL)
#endif
    {
        ForceZero(tmp, sizeof(sp_digit) * 2 * 5 * 6);
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
    #endif
    }
#ifdef WOLFSSL_SP_SMALL_STACK
    if (t != NULL)
#endif
    {
        ForceZero(t, sizeof(sp_point_256) * 3);
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    #endif
    }

    return err;
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_ecc_mulmod_5_ctx {
    int state;
    union {
        sp_256_proj_point_dbl_5_ctx dbl_ctx;
        sp_256_proj_point_add_5_ctx add_ctx;
    };
    sp_point_256 t[3];
    sp_digit tmp[2 * 5 * 6];
    sp_digit n;
    int i;
    int c;
    int y;
} sp_256_ecc_mulmod_5_ctx;

static int sp_256_ecc_mulmod_sm2_5_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* g, const sp_digit* k, int map, int ct, void* heap)
{
    int err = FP_WOULDBLOCK;
    sp_256_ecc_mulmod_sm2_5_ctx* ctx = (sp_256_ecc_mulmod_5_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_ecc_mulmod_5_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    /* Implementation is constant time. */
    (void)ct;

    switch (ctx->state) {
    case 0: /* INIT */
        XMEMSET(ctx->t, 0, sizeof(sp_point_256) * 3);
        ctx->i = 4;
        ctx->c = 48;
        ctx->n = k[ctx->i--] << (52 - ctx->c);

        /* t[0] = {0, 0, 1} * norm */
        ctx->t[0].infinity = 1;
        ctx->state = 1;
        break;
    case 1: /* T1X */
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_256_mod_mul_norm_sm2_5(ctx->t[1].x, g->x, p256_sm2_mod);
        ctx->state = 2;
        break;
    case 2: /* T1Y */
        err = sp_256_mod_mul_norm_sm2_5(ctx->t[1].y, g->y, p256_sm2_mod);
        ctx->state = 3;
        break;
    case 3: /* T1Z */
        err = sp_256_mod_mul_norm_sm2_5(ctx->t[1].z, g->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4: /* ADDPREP */
        if (ctx->c == 0) {
            if (ctx->i == -1) {
                ctx->state = 7;
                break;
            }

            ctx->n = k[ctx->i--];
            ctx->c = 52;
        }
        ctx->y = (ctx->n >> 51) & 1;
        ctx->n <<= 1;
        XMEMSET(&ctx->add_ctx, 0, sizeof(ctx->add_ctx));
        ctx->state = 5;
        break;
    case 5: /* ADD */
        err = sp_256_proj_point_add_sm2_5_nb((sp_ecc_ctx_t*)&ctx->add_ctx,
            &ctx->t[ctx->y^1], &ctx->t[0], &ctx->t[1], ctx->tmp);
        if (err == MP_OKAY) {
            XMEMCPY(&ctx->t[2], (void*)(((size_t)&ctx->t[0] & addr_mask[ctx->y^1]) +
                                        ((size_t)&ctx->t[1] & addr_mask[ctx->y])),
                    sizeof(sp_point_256));
            XMEMSET(&ctx->dbl_ctx, 0, sizeof(ctx->dbl_ctx));
            ctx->state = 6;
        }
        break;
    case 6: /* DBL */
        err = sp_256_proj_point_dbl_sm2_5_nb((sp_ecc_ctx_t*)&ctx->dbl_ctx, &ctx->t[2],
            &ctx->t[2], ctx->tmp);
        if (err == MP_OKAY) {
            XMEMCPY((void*)(((size_t)&ctx->t[0] & addr_mask[ctx->y^1]) +
                            ((size_t)&ctx->t[1] & addr_mask[ctx->y])), &ctx->t[2],
                    sizeof(sp_point_256));
            ctx->state = 4;
            ctx->c--;
        }
        break;
    case 7: /* MAP */
        if (map != 0) {
            sp_256_map_sm2_5(r, &ctx->t[0], ctx->tmp);
        }
        else {
            XMEMCPY(r, &ctx->t[0], sizeof(sp_point_256));
        }
        err = MP_OKAY;
        break;
    }

    if (err == MP_OKAY && ctx->state != 7) {
        err = FP_WOULDBLOCK;
    }
    if (err != FP_WOULDBLOCK) {
        ForceZero(ctx->tmp, sizeof(ctx->tmp));
        ForceZero(ctx->t, sizeof(ctx->t));
    }

    (void)heap;

    return err;
}

#endif /* WOLFSSL_SP_NONBLOCK */

#else
/* A table entry for pre-computed points. */
typedef struct sp_table_entry_256 {
    sp_digit x[5];
    sp_digit y[5];
} sp_table_entry_256;

/* Conditionally copy a into r using the mask m.
 * m is -1 to copy and 0 when not.
 *
 * r  A single precision number to copy over.
 * a  A single precision number to copy.
 * m  Mask value to apply.
 */
static void sp_256_cond_copy_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit m)
{
    sp_digit t[5];
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 5; i++) {
        t[i] = r[i] ^ a[i];
    }
    for (i = 0; i < 5; i++) {
        r[i] ^= t[i] & m;
    }
#else
    t[ 0] = r[ 0] ^ a[ 0];
    t[ 1] = r[ 1] ^ a[ 1];
    t[ 2] = r[ 2] ^ a[ 2];
    t[ 3] = r[ 3] ^ a[ 3];
    t[ 4] = r[ 4] ^ a[ 4];
    r[ 0] ^= t[ 0] & m;
    r[ 1] ^= t[ 1] & m;
    r[ 2] ^= t[ 2] & m;
    r[ 3] ^= t[ 3] & m;
    r[ 4] ^= t[ 4] & m;
#endif /* WOLFSSL_SP_SMALL */
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_sm2_5(sp_point_256* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*5;
    sp_digit* b = t + 4*5;
    sp_digit* t1 = t + 6*5;
    sp_digit* t2 = t + 8*5;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_5(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_5(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_5(w, w, p256_sm2_mod, p256_sm2_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_5(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_5(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_5(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_5(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_5(t2, b, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(x, x, t2, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_sub_sm2_5(t2, b, x, p256_sm2_mod);
        sp_256_mont_dbl_sm2_5(b, t2, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_5(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_5(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_5(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_5(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(y, y, t1, p256_sm2_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_256_mont_sqr_sm2_5(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_5(t1, t1, w, p256_sm2_mod);
    sp_256_mont_tpl_sm2_5(a, t1, p256_sm2_mod);
    /* B = X*Y^2 */
    sp_256_mont_sqr_sm2_5(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = A^2 - 2B */
    sp_256_mont_sqr_sm2_5(x, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_dbl_sm2_5(t2, b, p256_sm2_mod);
    sp_256_mont_sub_sm2_5(x, x, t2, p256_sm2_mod);
    /* B = 2.(B - X) */
    sp_256_mont_sub_sm2_5(t2, b, x, p256_sm2_mod);
    sp_256_mont_dbl_sm2_5(b, t2, p256_sm2_mod);
    /* Z = Z*Y */
    sp_256_mont_mul_sm2_5(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* t1 = Y^4 */
    sp_256_mont_sqr_sm2_5(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_256_mont_mul_sm2_5(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_5(y, y, t1, p256_sm2_mod);
#endif /* WOLFSSL_SP_SMALL */
    /* Y = Y/2 */
    sp_256_mont_div2_sm2_5(y, y, p256_sm2_mod);
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_store_sm2_5(sp_point_256* r,
        const sp_point_256* p, int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*5;
    sp_digit* b = t + 4*5;
    sp_digit* t1 = t + 6*5;
    sp_digit* t2 = t + 8*5;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;
    int j;

    for (i=0; i<5; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<5; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<5; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_5(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_5(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_5(w, w, p256_sm2_mod, p256_sm2_mp_mod);
    j = m;
    for (i=1; i<=n; i++) {
        j *= 2;

        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_5(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_5(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_5(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        x = r[j].x;
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_5(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_5(t2, b, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(x, x, t2, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_sub_sm2_5(t2, b, x, p256_sm2_mod);
        sp_256_mont_dbl_sm2_5(b, t2, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_5(r[j].z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        z = r[j].z;
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_5(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_5(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_5(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(y, y, t1, p256_sm2_mod);
        /* Y = Y/2 */
        sp_256_mont_div2_sm2_5(r[j].y, y, p256_sm2_mod);
        r[j].infinity = 0;
    }
}

/* Add two Montgomery form projective points.
 *
 * ra  Result of addition.
 * rs  Result of subtraction.
 * p   First point to add.
 * q   Second point to add.
 * t   Temporary ordinate data.
 */
static void sp_256_proj_point_add_sub_sm2_5(sp_point_256* ra,
        sp_point_256* rs, const sp_point_256* p, const sp_point_256* q,
        sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    sp_digit* t3 = t + 4*5;
    sp_digit* t4 = t + 6*5;
    sp_digit* t5 = t + 8*5;
    sp_digit* t6 = t + 10*5;
    sp_digit* xa = ra->x;
    sp_digit* ya = ra->y;
    sp_digit* za = ra->z;
    sp_digit* xs = rs->x;
    sp_digit* ys = rs->y;
    sp_digit* zs = rs->z;


    XMEMCPY(xa, p->x, sizeof(p->x) / 2);
    XMEMCPY(ya, p->y, sizeof(p->y) / 2);
    XMEMCPY(za, p->z, sizeof(p->z) / 2);
    ra->infinity = 0;
    rs->infinity = 0;

    /* U1 = X1*Z2^2 */
    sp_256_mont_sqr_sm2_5(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t1, t1, xa, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_5(t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t4, t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_5(t3, t3, ya, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_5(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* H = U2 - U1 */
    sp_256_mont_sub_sm2_5(t2, t2, t1, p256_sm2_mod);
    /* RS = S2 + S1 */
    sp_256_mont_add_sm2_5(t6, t4, t3, p256_sm2_mod);
    /* R = S2 - S1 */
    sp_256_mont_sub_sm2_5(t4, t4, t3, p256_sm2_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_256_mont_mul_sm2_5(za, za, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(za, za, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(zs, za, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_256_mont_sqr_sm2_5(xa, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_5(xs, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_5(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(ya, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_5(xa, xa, t5, p256_sm2_mod);
    sp_256_mont_sub_sm2_5(xs, xs, t5, p256_sm2_mod);
    sp_256_mont_dbl_sm2_5(t1, ya, p256_sm2_mod);
    sp_256_mont_sub_sm2_5(xa, xa, t1, p256_sm2_mod);
    sp_256_mont_sub_sm2_5(xs, xs, t1, p256_sm2_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_256_mont_sub_sm2_5(ys, ya, xs, p256_sm2_mod);
    sp_256_mont_sub_sm2_5(ya, ya, xa, p256_sm2_mod);
    sp_256_mont_mul_sm2_5(ya, ya, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_sub_sm2_5(t6, p256_sm2_mod, t6);
    sp_256_mont_mul_sm2_5(ys, ys, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_5(ya, ya, t5, p256_sm2_mod);
    sp_256_mont_sub_sm2_5(ys, ys, t5, p256_sm2_mod);
}

/* Structure used to describe recoding of scalar multiplication. */
typedef struct ecc_recode_256 {
    /* Index into pre-computation table. */
    uint8_t i;
    /* Use the negative of the point. */
    uint8_t neg;
} ecc_recode_256;

/* The index into pre-computation table to use. */
static const uint8_t recode_index_5_6[66] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const uint8_t recode_neg_5_6[66] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     0,  0,
};

/* Recode the scalar for multiplication using pre-computed values and
 * subtraction.
 *
 * k  Scalar to multiply by.
 * v  Vector of operations to perform.
 */
static void sp_256_ecc_recode_6_5(const sp_digit* k, ecc_recode_256* v)
{
    int i;
    int j;
    uint8_t y;
    int carry = 0;
    int o;
    sp_digit n;

    j = 0;
    n = k[j];
    o = 0;
    for (i=0; i<43; i++) {
        y = (uint8_t)(int8_t)n;
        if (o + 6 < 52) {
            y &= 0x3f;
            n >>= 6;
            o += 6;
        }
        else if (o + 6 == 52) {
            n >>= 6;
            if (++j < 5)
                n = k[j];
            o = 0;
        }
        else if (++j < 5) {
            n = k[j];
            y |= (uint8_t)((n << (52 - o)) & 0x3f);
            o -= 46;
            n >>= o;
        }

        y += (uint8_t)carry;
        v[i].i = recode_index_5_6[y];
        v[i].neg = recode_neg_5_6[y];
        carry = (y >> 6) + v[i].neg;
    }
}

#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible point that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entries to access
 * idx    Index of entry to retrieve.
 */
static void sp_256_get_point_33_sm2_5(sp_point_256* r, const sp_point_256* table,
    int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    r->z[4] = 0;
    for (i = 1; i < 33; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
        r->z[4] |= mask & table[i].z[4];
    }
}
#endif /* !WC_NO_CACHE_RESISTANT */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Window technique of 6 bits. (Add-Sub variation.)
 * Calculate 0..32 times the point. Use function that adds and
 * subtracts the same two points.
 * Recode to add or subtract one of the computed points.
 * Double to push up.
 * NOT a sliding window.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_win_add_sub_sm2_5(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[33+2];
    sp_digit tmp[2 * 5 * 6];
#endif
    sp_point_256* rt = NULL;
    sp_point_256* p = NULL;
    sp_digit* negy;
    int i;
    ecc_recode_256 v[43];
    int err = MP_OKAY;

    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_point_256*)XMALLOC(sizeof(sp_point_256) *
        (33+2), heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 6,
                                 heap, DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        rt = t + 33;
        p  = t + 33+1;

        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_256_mod_mul_norm_sm2_5(t[1].x, g->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_5(t[1].y, g->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_5(t[1].z, g->z, p256_sm2_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_256_proj_point_dbl_n_store_sm2_5(t, &t[ 1], 5, 1, tmp);
        sp_256_proj_point_add_sm2_5(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[ 6], &t[ 3], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[10], &t[ 5], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[12], &t[ 6], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[14], &t[ 7], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[18], &t[ 9], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[20], &t[10], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[22], &t[11], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[24], &t[12], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[26], &t[13], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[28], &t[14], tmp);
        sp_256_proj_point_dbl_sm2_5(&t[30], &t[15], tmp);
        sp_256_proj_point_add_sub_sm2_5(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_256_ecc_recode_6_5(k, v);

        i = 42;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_point_33_sm2_5(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_256));
        }
        for (--i; i>=0; i--) {
            sp_256_proj_point_dbl_n_sm2_5(rt, 6, tmp);

        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_point_33_sm2_5(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
        #endif
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_256));
            }
            sp_256_sub_sm2_5(negy, p256_sm2_mod, p->y);
            sp_256_norm_5(negy);
            sp_256_cond_copy_sm2_5(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_256_proj_point_add_sm2_5(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_256_map_sm2_5(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(t, heap, DYNAMIC_TYPE_ECC);
    XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef FP_ECC
#endif /* FP_ECC */
/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_qz1_sm2_5(sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*5;
    sp_digit* t6 = t + 4*5;
    sp_digit* t1 = t + 6*5;
    sp_digit* t4 = t + 8*5;
    sp_digit* t5 = t + 10*5;

    /* Calculate values to subtract from P->x and P->y. */
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_5(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_5(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_5(p->x, t2) &
            sp_256_cmp_equal_5(p->y, t4)) {
        sp_256_proj_point_dbl_sm2_5(r, p, t);
    }
    else {
        sp_digit* x = t2;
        sp_digit* y = t3;
        sp_digit* z = t6;

        /* H = U2 - X1 */
        sp_256_mont_sub_sm2_5(t2, t2, p->x, p256_sm2_mod);
        /* R = S2 - Y1 */
        sp_256_mont_sub_sm2_5(t4, t4, p->y, p256_sm2_mod);
        /* Z3 = H*Z1 */
        sp_256_mont_mul_sm2_5(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_256_mont_sqr_sm2_5(t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(t3, p->x, t1, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(t1, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_5(t2, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(t2, t2, t1, p256_sm2_mod);
        sp_256_mont_dbl_sm2_5(t5, t3, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(x, t2, t5, p256_sm2_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_sub_sm2_5(t3, t3, x, p256_sm2_mod);
        sp_256_mont_mul_sm2_5(t3, t3, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_5(t1, t1, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_5(y, t3, t1, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 5; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 5; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 5; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef FP_ECC
/* Convert the projective point to affine.
 * Ordinates are in Montgomery form.
 *
 * a  Point to convert.
 * t  Temporary data.
 */
static void sp_256_proj_to_affine_sm2_5(sp_point_256* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 5;
    sp_digit* tmp = t + 4 * 5;

    sp_256_mont_inv_sm2_5(t1, a->z, tmp);

    sp_256_mont_sqr_sm2_5(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    sp_256_mont_mul_sm2_5(a->x, a->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_5(a->y, a->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(a->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
}

/* Generate the pre-computed table of points for the base point.
 *
 * width = 8
 * 256 entries
 * 32 bits between
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temporary data.
 * heap  Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_sm2_5(const sp_point_256* a,
        sp_table_entry_256* table, sp_digit* tmp, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
#else
    sp_point_256 t[3];
#endif
    sp_point_256* s1 = NULL;
    sp_point_256* s2 = NULL;
    int i;
    int j;
    int err = MP_OKAY;

    (void)heap;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 3, heap,
                                     DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        s1 = t + 1;
        s2 = t + 2;

        err = sp_256_mod_mul_norm_sm2_5(t->x, a->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_5(t->y, a->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_5(t->z, a->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_sm2_5(t, tmp);

        XMEMCPY(s1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s1->infinity = 0;
        XMEMCPY(s2->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s2->infinity = 0;

        /* table[0] = {0, 0, infinity} */
        XMEMSET(&table[0], 0, sizeof(sp_table_entry_256));
        /* table[1] = Affine version of 'a' in Montgomery form */
        XMEMCPY(table[1].x, t->x, sizeof(table->x));
        XMEMCPY(table[1].y, t->y, sizeof(table->y));

        for (i=1; i<8; i++) {
            sp_256_proj_point_dbl_n_sm2_5(t, 32, tmp);
            sp_256_proj_to_affine_sm2_5(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_sm2_5(t, s1, s2, tmp);
                sp_256_proj_to_affine_sm2_5(t, tmp);
                XMEMCPY(table[j].x, t->x, sizeof(table->x));
                XMEMCPY(table[j].y, t->y, sizeof(table->y));
            }
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(t, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#endif /* FP_ECC */
#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible entry that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entries to access
 * idx    Index of entry to retrieve.
 */
static void sp_256_get_entry_256_sm2_5(sp_point_256* r,
    const sp_table_entry_256* table, int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    for (i = 1; i < 256; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
    }
}
#endif /* !WC_NO_CACHE_RESISTANT */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^32, ...
 * Pre-generated: products of all combinations of above.
 * 8 doubles and adds (with qz=1)
 *
 * r      Resulting point.
 * k      Scalar to multiply by.
 * table  Pre-computed table.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_stripe_sm2_5(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* t = NULL;
#else
    sp_point_256 rt[2];
    sp_digit t[2 * 5 * 6];
#endif
    sp_point_256* p = NULL;
    int i;
    int j;
    int y;
    int x;
    int err = MP_OKAY;

    (void)g;
    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;


#ifdef WOLFSSL_SP_SMALL_STACK
    rt = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                      DYNAMIC_TYPE_ECC);
    if (rt == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 6, heap,
                               DYNAMIC_TYPE_ECC);
        if (t == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        p = rt + 1;

        XMEMCPY(p->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        XMEMCPY(rt->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));

        y = 0;
        x = 31;
        for (j=0; j<8; j++) {
            y |= (int)(((k[x / 52] >> (x % 52)) & 1) << j);
            x += 32;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_256_sm2_5(rt, table, y);
        } else
    #endif
        {
            XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        }
        rt->infinity = !y;
        for (i=30; i>=0; i--) {
            y = 0;
            x = i;
            for (j=0; j<8; j++) {
                y |= (int)(((k[x / 52] >> (x % 52)) & 1) << j);
                x += 32;
            }

            sp_256_proj_point_dbl_sm2_5(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_256_sm2_5(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_256_proj_point_add_qz1_sm2_5(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_sm2_5(r, rt, t);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(t, heap, DYNAMIC_TYPE_ECC);
    XFREE(rt, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef FP_ECC
#ifndef FP_ENTRIES
    #define FP_ENTRIES 16
#endif

/* Cache entry - holds precomputation tables for a point. */
typedef struct sp_cache_256_t {
    /* X ordinate of point that table was generated from. */
    sp_digit x[5];
    /* Y ordinate of point that table was generated from. */
    sp_digit y[5];
    /* Precomputation table for point. */
    sp_table_entry_256 table[256];
    /* Count of entries in table. */
    uint32_t cnt;
    /* Point and table set in entry. */
    int set;
} sp_cache_256_t;

/* Cache of tables. */
static THREAD_LS_T sp_cache_256_t sp_cache_256[FP_ENTRIES];
/* Index of last entry in cache. */
static THREAD_LS_T int sp_cache_256_last = -1;
/* Cache has been initialized. */
static THREAD_LS_T int sp_cache_256_inited = 0;

#ifndef HAVE_THREAD_LS
    #ifndef WOLFSSL_MUTEX_INITIALIZER
    static volatile int initCacheMutex_256 = 0;
    #endif
    static wolfSSL_Mutex sp_cache_256_lock WOLFSSL_MUTEX_INITIALIZER_CLAUSE(sp_cache_256_lock);
#endif

/* Get the cache entry for the point.
 *
 * g      [in]   Point scalar multiplying.
 * cache  [out]  Cache table to use.
 */
static void sp_ecc_get_cache_256(const sp_point_256* g, sp_cache_256_t** cache)
{
    int i;
    int j;
    uint32_t least;

    if (sp_cache_256_inited == 0) {
        for (i=0; i<FP_ENTRIES; i++) {
            sp_cache_256[i].set = 0;
        }
        sp_cache_256_inited = 1;
    }

    /* Compare point with those in cache. */
    for (i=0; i<FP_ENTRIES; i++) {
        if (!sp_cache_256[i].set)
            continue;

        if (sp_256_cmp_equal_5(g->x, sp_cache_256[i].x) &
                           sp_256_cmp_equal_5(g->y, sp_cache_256[i].y)) {
            sp_cache_256[i].cnt++;
            break;
        }
    }

    /* No match. */
    if (i == FP_ENTRIES) {
        /* Find empty entry. */
        i = (sp_cache_256_last + 1) % FP_ENTRIES;
        for (; i != sp_cache_256_last; i=(i+1)%FP_ENTRIES) {
            if (!sp_cache_256[i].set) {
                break;
            }
        }

        /* Evict least used. */
        if (i == sp_cache_256_last) {
            least = sp_cache_256[0].cnt;
            for (j=1; j<FP_ENTRIES; j++) {
                if (sp_cache_256[j].cnt < least) {
                    i = j;
                    least = sp_cache_256[i].cnt;
                }
            }
        }

        XMEMCPY(sp_cache_256[i].x, g->x, sizeof(sp_cache_256[i].x));
        XMEMCPY(sp_cache_256[i].y, g->y, sizeof(sp_cache_256[i].y));
        sp_cache_256[i].set = 1;
        sp_cache_256[i].cnt = 1;
    }

    *cache = &sp_cache_256[i];
    sp_cache_256_last = i;
}
#endif /* FP_ECC */

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_sm2_5(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_win_add_sub_sm2_5(r, g, k, map, ct, heap);
#else
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp;
#else
    sp_digit tmp[2 * 5 * 6];
#endif
    sp_cache_256_t* cache;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 6, heap, DYNAMIC_TYPE_ECC);
    if (tmp == NULL) {
        err = MEMORY_E;
    }
#endif
#ifndef HAVE_THREAD_LS
    if (err == MP_OKAY) {
        #ifndef WOLFSSL_MUTEX_INITIALIZER
        if (initCacheMutex_256 == 0) {
            wc_InitMutex(&sp_cache_256_lock);
            initCacheMutex_256 = 1;
        }
        #endif
        if (wc_LockMutex(&sp_cache_256_lock) != 0) {
            err = BAD_MUTEX_E;
        }
    }
#endif /* HAVE_THREAD_LS */

    if (err == MP_OKAY) {
        sp_ecc_get_cache_256(g, &cache);
        if (cache->cnt == 2)
            sp_256_gen_stripe_table_sm2_5(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_win_add_sub_sm2_5(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_5(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif
    return err;
#endif
}

#endif
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km    Scalar to multiply by.
 * p     Point to multiply.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_sm2_256(const mp_int* km, const ecc_point* gm, ecc_point* r,
        int map, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* point = NULL;
    sp_digit* k = NULL;
#else
    sp_point_256 point[1];
    sp_digit k[5];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 5, km);
        sp_256_point_from_ecc_point_5(point, gm);

            err = sp_256_ecc_mulmod_sm2_5(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_5(point, r);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Multiply the point by the scalar, add point a and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km      Scalar to multiply by.
 * p       Point to multiply.
 * am      Point to add to scalar multiply result.
 * inMont  Point to add is in montgomery form.
 * r       Resulting point.
 * map     Indicates whether to convert result to affine.
 * heap    Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_add_sm2_256(const mp_int* km, const ecc_point* gm,
    const ecc_point* am, int inMont, ecc_point* r, int map, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* point = NULL;
    sp_digit* k = NULL;
#else
    sp_point_256 point[2];
    sp_digit k[5 + 5 * 2 * 6];
#endif
    sp_point_256* addP = NULL;
    sp_digit* tmp = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(
            sizeof(sp_digit) * (5 + 5 * 2 * 6), heap,
            DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 5;

        sp_256_from_mp(k, 5, km);
        sp_256_point_from_ecc_point_5(point, gm);
        sp_256_point_from_ecc_point_5(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_5(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_5(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_5(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_sm2_5(point, point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_5(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_5(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_5(point, r);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_sm2_5(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    /* No pre-computed values. */
    return sp_256_ecc_mulmod_sm2_5(r, &p256_sm2_base, k, map, ct, heap);
}

#ifdef WOLFSSL_SP_NONBLOCK
static int sp_256_ecc_mulmod_base_5_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_digit* k, int map, int ct, void* heap)
{
    /* No pre-computed values. */
    return sp_256_ecc_mulmod_sm2_5_nb(sp_ctx, r, &p256_sm2_base, k, map, ct, heap);
}
#endif /* WOLFSSL_SP_NONBLOCK */


#else
/* Striping precomputation table.
 * 8 points combined into a table of 256 points.
 * Distance of 32 between points.
 */
static const sp_table_entry_256 p256_sm2_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x28990f418029eL,0xeddca6c050613L,0xc24c3c33e7981L,0x3b05d6a1ed99aL,
        0x091167a5ee1c1L },
      { 0x54e593c2d0dddL,0x788d3295fac13L,0xe2a48f8c1f5e5L,0x35bd8d4cfb066L,
        0x063cd65d481d7L } },
    /* 2 */
    { { 0x8f92d0cf4efe5L,0x14960e2d22ecbL,0x059f07988c472L,0xda7cca9549ef6L,
        0x0d0a3774a7016L },
      { 0xc95f61d001cabL,0xefa3feeec1d51L,0xafedf2b2d744dL,0x44a5b7c20cc20L,
        0x0bf16c5f171d1L } },
    /* 3 */
    { { 0x4ea0bad9c635eL,0x5685246e15668L,0x6bb637348a44aL,0xef8e16926cc45L,
        0x0b9966ebd43efL },
      { 0x57f14350e7f7dL,0x95a25bdfd6aceL,0xed4a5925c026cL,0x4a24f30be3759L,
        0x074dde4e55123L } },
    /* 4 */
    { { 0x3e020bad830d2L,0x9e590dffb34b3L,0xc80ecb05c101fL,0x293ecd0e0498bL,
        0x0302787f852aaL },
      { 0x64ced220f8fc8L,0xe0be0ee377bfdL,0x913b128cf5cebL,0x3279dc03a0388L,
        0x04b096971fde2L } },
    /* 5 */
    { { 0xe84e239a0d9dcL,0xcc061edfa5b4eL,0x4cf33d0f7d229L,0x9f599765b24bdL,
        0x0511c69f11332L },
      { 0x95bb7a07ae316L,0xf1387f0e5a410L,0x9827e4a3a4650L,0x243a4624421c9L,
        0x07b1e814404b4L } },
    /* 6 */
    { { 0x17662f8f2bc34L,0x16171ae6a15deL,0xc7cbaa0884087L,0x2e60c65b64704L,
        0x0b56909fcbdceL },
      { 0xdcb393e73ddb0L,0x1f5d5e0850465L,0x6717cfb5cca77L,0xd4fb96fe1e148L,
        0x0fda13692c1dcL } },
    /* 7 */
    { { 0xc47aa043f38e8L,0x9159faf190d50L,0x03d00cb5397ebL,0x818fa9d1027ebL,
        0x01d04d612a59aL },
      { 0xddc860328d2b3L,0xe887d6813259cL,0xf18049306f881L,0xfcbe42914fc4bL,
        0x0d6a600a80820L } },
    /* 8 */
    { { 0x9b8941abd31f0L,0x8d9a1da7d3459L,0x0f0217ddb3419L,0x884ea8b89523aL,
        0x02014cc43e56bL },
      { 0x94f8849efd4eeL,0x10287f4ae06fbL,0x9fd2debf1b817L,0x7a5389d38a9a9L,
        0x08179277a72b6L } },
    /* 9 */
    { { 0x2f1958e4b53dfL,0xb98bc1f19ca75L,0x75b202815b855L,0x651bd3bcd58fbL,
        0x03e7e284149b7L },
      { 0x8e4cb0b47b1aaL,0x7b9750b86a69aL,0xf1415edc3b27cL,0xa56a65dc9f783L,
        0x0baab4dbc468bL } },
    /* 10 */
    { { 0xe09badf4f7cb3L,0x1553cfe07a33fL,0x86f167dbedb98L,0xeb4c35e0c4fa5L,
        0x0dd4c37c90821L },
      { 0x5240ca0e9402aL,0x627f049720236L,0xb7723d8694b03L,0xe3051c60260d9L,
        0x0e488f0af52f8L } },
    /* 11 */
    { { 0x89930eec04411L,0x1a15b89af47bbL,0x64883ced659c7L,0x1648be21fc69bL,
        0x0fcdd9de002adL },
      { 0xb555d799d29feL,0x58971489ef072L,0x45a0f682c517aL,0x8b95dbdcc979fL,
        0x0b268b83f3cd0L } },
    /* 12 */
    { { 0xc104936aed763L,0x99d4a079be676L,0xa194f338c8712L,0x925cdfafad16dL,
        0x02ab29161c5d4L },
      { 0x4761c1970c4f8L,0x348312b03a226L,0xb580022c768d9L,0x63c0187f20505L,
        0x016406b19d133L } },
    /* 13 */
    { { 0xa8d428f11a1b7L,0xf1deee83a5534L,0x25c6bd3938477L,0xca87d77237f6fL,
        0x046ef139540e6L },
      { 0x0e76079dbd954L,0xb6a3a9aa6d083L,0xc1aa064e22981L,0x478c07719e76cL,
        0x06c909a3ad044L } },
    /* 14 */
    { { 0x09dbd3ab4c047L,0x20c51725dd3cdL,0x18a00d88c8578L,0x5feda0cefbac8L,
        0x06bf4b678d93dL },
      { 0x8b7649c1c77f8L,0xb53bb210aeb7bL,0x9f40ce0d3c82dL,0x9f9c27f5ec751L,
        0x01c742c6d60a3L } },
    /* 15 */
    { { 0x3d806608acdd0L,0xc54dbe6185792L,0x4c14789119764L,0x15b9582849404L,
        0x0ba5f5971ebe0L },
      { 0x235a273d216f3L,0xa00360f2601bcL,0x1aaed4999624bL,0x415a4c8b3eefcL,
        0x0a302e8b77cdeL } },
    /* 16 */
    { { 0xf561a8a914b50L,0x0e9154d3777b9L,0x19b4c352bf713L,0x4c566800f6965L,
        0x0c9e65040568bL },
      { 0x06e006d98a331L,0xf6e211ce1e307L,0x0562e5f781a12L,0x67471fff9e3d4L,
        0x06356cf468c16L } },
    /* 17 */
    { { 0x4e4f3897518d9L,0x0c66f75b0d96cL,0x7f7ceb53825d8L,0xef24fa0bd6c00L,
        0x05c01af69a303L },
      { 0x5cf9e6bfcbc92L,0x53248dceaedd7L,0x53734218bfe4aL,0xcb86519362c69L,
        0x06f350880168cL } },
    /* 18 */
    { { 0xcabbf442e4248L,0xea5ee1ab7ae61L,0xbacbbb024194cL,0xabde21b5f5319L,
        0x07d554b80abc8L },
      { 0x6a6127268ca65L,0x15fe9b7a84aebL,0x35591333c6f7cL,0xe0815be8a9ff6L,
        0x09d17778c11efL } },
    /* 19 */
    { { 0x2b7532d347f7fL,0xb33a25167a65fL,0xafb45ac2f70c2L,0x61bead9c7fb5eL,
        0x09fcd997c1c39L },
      { 0x72ce3337ca7ddL,0xd55a88b6bd25bL,0x8834ffe255e90L,0xc0db7b1d4dc83L,
        0x00cb91039f241L } },
    /* 20 */
    { { 0x5c510cf13b772L,0x90d95aca7cfa9L,0xcb1a435a9b3fcL,0xe6a08e6e77904L,
        0x0840b63d98754L },
      { 0x6798133196bd2L,0x61ef85911fcfaL,0xbd94af615ab05L,0x0fb5504d9402fL,
        0x0063173d3fcc9L } },
    /* 21 */
    { { 0x8e50e11fa5996L,0xbacce6427b6d5L,0x5291d185a7db9L,0x47637d30d5aa9L,
        0x09e69e861cd35L },
      { 0xcbca9706bd6f9L,0xb0af3bda5f2d0L,0x6d6cc0d63cc64L,0x0b6b09cc5dbf0L,
        0x0533ba1aa81e5L } },
    /* 22 */
    { { 0x72c2425a4c565L,0x0ad3f80897a5fL,0xb50c4d9c86413L,0xed5040f41882fL,
        0x0499c14995551L },
      { 0x04d8861ee4b05L,0x53d2729bef324L,0xdbfb28b4a3f19L,0x4decff878e9aeL,
        0x0ca18c856e81bL } },
    /* 23 */
    { { 0x4c14e1b87826eL,0x73ce8326da8caL,0x0192797e4b2b8L,0x22e45e0b6c47bL,
        0x0a95e1b9ebed3L },
      { 0xba8c04f98438bL,0xb76afd2a0994bL,0xa7461868e5301L,0x8ad0e12fa56a9L,
        0x031b5268e3aa6L } },
    /* 24 */
    { { 0x7b871e0b8f9c6L,0x96e6ce880f2f6L,0xd8b362f101bdeL,0xaf4207f08fb22L,
        0x0e8cfc6413f1dL },
      { 0x8324668742a60L,0x9da244b370e08L,0x2887b39eb5497L,0x906e34cd326d0L,
        0x068fd6b647fe7L } },
    /* 25 */
    { { 0x921740774bf91L,0x8290aaeb2e47cL,0x89b5af56879e6L,0x1c7dd66bc8cf2L,
        0x0dc9ead3435d2L },
      { 0x439d95400fd22L,0x0a6df86577e55L,0xcd5bfedb4d120L,0xd89e79f852715L,
        0x0f1e74dd8a33fL } },
    /* 26 */
    { { 0xde7878eadd7c7L,0xae6c9cf9455d1L,0x69c63d226883aL,0xe13bf4c8d3ee4L,
        0x07e163562549fL },
      { 0x4e7f88a1e5a2dL,0xa5bf1a43d26c2L,0x268f8dd7f5550L,0x3634c3fc954efL,
        0x02b0d677191f2L } },
    /* 27 */
    { { 0x2a87bbaef1d85L,0xf7ac4393acff2L,0x74b1d81cf774cL,0xfd6a1cdda1375L,
        0x0cda8f0dbc004L },
      { 0xe9d096a5c7738L,0xabfca4584f711L,0x5b9c75c7189aaL,0x0ed1eb8edd271L,
        0x00532d2b778dbL } },
    /* 28 */
    { { 0x2fd017e93d304L,0x91b6455b4246cL,0xa3146eb6df3f9L,0x3c15ad3fff985L,
        0x09dbadcfac12cL },
      { 0x15d6248adf57dL,0x60e7f0ad3e87aL,0x115bb269c0ee7L,0x23fc7ddcf16ffL,
        0x0ee787b988774L } },
    /* 29 */
    { { 0x9c9cda35b2fe6L,0xfa58c7b139cfdL,0xf28ce21c46ffcL,0x37dfdbafc8738L,
        0x04798d018e798L },
      { 0xe3e66adf63b8cL,0x3efd7aa8fe5bbL,0x33e5359bc5d67L,0x3fc80e5bb7fb1L,
        0x0645aa53c9dabL } },
    /* 30 */
    { { 0x4b573d26b8292L,0x00343e518684eL,0x574a3b60d52bfL,0x9e25783f1d8cbL,
        0x0dbe3f8ecd76aL },
      { 0xdce0399b642b8L,0x1a770f5a79d57L,0xdafa422511318L,0xaea72b59683ecL,
        0x09a73de8a61a0L } },
    /* 31 */
    { { 0x7e4a267ef03fcL,0x88421bbfd0136L,0xe233f885b1dd6L,0x0c32a6789acb8L,
        0x0bcc0ad09b905L },
      { 0xe81a82256ea88L,0x44c2083a41cd5L,0x30d63002c8013L,0x59e7029922210L,
        0x0561e593522acL } },
    /* 32 */
    { { 0xf4c2e24424a48L,0xee37d4471c11cL,0x17a488b843c73L,0x861cb3047fc56L,
        0x0f2a91709e3cfL },
      { 0x444211c3a60f7L,0x3626679148844L,0x3d9404b74787aL,0xcef0115fbd065L,
        0x070fd33656244L } },
    /* 33 */
    { { 0xad1a91350a8acL,0x4455da889e825L,0x4df2c5ea9527dL,0x31fca957f05c8L,
        0x05061719a9ff1L },
      { 0xda998a296a530L,0x89df7b5a9fecdL,0x84869a14f5af5L,0xfd96c2d1d040cL,
        0x08401cc8a6417L } },
    /* 34 */
    { { 0xb8d3129853c8cL,0x995864b1c5c89L,0x2c2b19154dec3L,0x12b732c4b3a4fL,
        0x04b4b9beef084L },
      { 0xcee6a97ac6061L,0xf35b2c2c331a7L,0x903a0f673038fL,0xaa54a11ffda5aL,
        0x0d8a0fa39ec43L } },
    /* 35 */
    { { 0xca2f3b6c18ad6L,0xc4757eed8f7f2L,0xadaca59fc2c34L,0x786fbdbf5e28aL,
        0x0979a3f6a6facL },
      { 0xf10cc50a130bcL,0xdb4323bd8de7dL,0xd207c466a3f62L,0xc829fc590a108L,
        0x066a7b0592e98L } },
    /* 36 */
    { { 0x69debdff39f50L,0x5f4ebcd6d496bL,0x23455cb2a3d86L,0xfb306ffadbd98L,
        0x0b1f617cd764fL },
      { 0xd713ce8cb5759L,0x5c09a6e01a01eL,0x7d99e5e31c4b2L,0x1c863a4272ec7L,
        0x049ee3010f466L } },
    /* 37 */
    { { 0x671bb612270deL,0x12ddf060ca4b4L,0xaee95dd0cc601L,0x8f2dd6fb85003L,
        0x0120d05eec244L },
      { 0x713421070c2baL,0x592ac04adbacbL,0x5519c656eb1f7L,0x997e6f41914b0L,
        0x0af69c4193b4aL } },
    /* 38 */
    { { 0x8c59ac4b11a5bL,0x4257bdb1fdcadL,0xb66574d05d689L,0xab7c22d7b638dL,
        0x0d060d0a930dfL },
      { 0xc0102e0c8e41dL,0x934a22e5c25edL,0x280fd21e47182L,0xb4719d5a138cdL,
        0x0e47ed3fcdfd6L } },
    /* 39 */
    { { 0xfe174ce30e491L,0x2e4081468a5f0L,0xae38ff1b66438L,0x103f8e14c7145L,
        0x021b63d385ea3L },
      { 0x86cca312036e2L,0xb422b39fe3afaL,0xe1061f21fbf7bL,0x2e5759f85460eL,
        0x086565def2809L } },
    /* 40 */
    { { 0xa7870a2d0b7ffL,0xe560786676593L,0x4e51639286a76L,0x362800016a4a1L,
        0x0176e05d81ba8L },
      { 0xb39caccd7f1c9L,0x0e32f77ef286eL,0x7fa33f089dbbfL,0xf6057e6ff400cL,
        0x01a174b70406dL } },
    /* 41 */
    { { 0xc0d1a4d69fcdeL,0xe6910960ad78aL,0x23393535aedf5L,0x34e167103e799L,
        0x00adf982c3915L },
      { 0xfd8b7dbf326a6L,0x4f530e4fa6e98L,0x05ba2a93f7166L,0x8aa17772c027dL,
        0x05ecf1ee5db67L } },
    /* 42 */
    { { 0x88e90924bd676L,0x145ddf5faa3aeL,0xf44bde9c7e2a6L,0xd8960c01b5a7fL,
        0x09b16db80f664L },
      { 0x4bb3c5c63dee2L,0xcf013c90b9d7fL,0x59a92ed1e57e0L,0xc564e6a403dcdL,
        0x0901515084c61L } },
    /* 43 */
    { { 0x36835222ca5cbL,0x44528a8c2bc07L,0x091a70e4b7bbcL,0x8302f2e9a9b59L,
        0x002bdce5aca8cL },
      { 0x0d35a0c61cf3dL,0xc43401929e329L,0x264664f13e152L,0xea41acb5ad500L,
        0x0c8f83b90947dL } },
    /* 44 */
    { { 0x529972325b5b4L,0xe5dc8f28b8797L,0xc23c663da8348L,0xc92cf8bbb6ff4L,
        0x06a8708872182L },
      { 0x5c17db800dd46L,0x723f52f048f14L,0x859b9fc5eaac8L,0x90beda05888a5L,
        0x03a66e9ca8887L } },
    /* 45 */
    { { 0x596be59f902b6L,0xf31c4919f3774L,0x57c9558c6eb3cL,0xcc9c9e379b344L,
        0x03c86aee9554cL },
      { 0x79ed8d9efa09aL,0x3eb1a68c0d3fbL,0xb7fd4c8109863L,0xdab86e8bb88e6L,
        0x00a7fccc0a4c7L } },
    /* 46 */
    { { 0x38c6d3309ddffL,0x3a0ea5b0f2205L,0x791025680206fL,0x861b333fba72bL,
        0x0f80eb58aab78L },
      { 0x07ab3b58fc705L,0xcbfb3578ff58aL,0x7eb90f5043d1aL,0x6eebcb923accfL,
        0x0251a6cf81cb2L } },
    /* 47 */
    { { 0xaffe3850afc51L,0x7efb637b74b58L,0x7fe16b9dc8a48L,0x72fa946c07b35L,
        0x02483b8808d82L },
      { 0x2687a1c79f6acL,0xaab9468ce8c40L,0xa8e900f90ef68L,0xe5ee077aacb67L,
        0x047e3cd8e0a82L } },
    /* 48 */
    { { 0x385c647c08a1aL,0x73b0a4c2b7015L,0x745f557928d3eL,0xf6ba95f60e9caL,
        0x06584670ea969L },
      { 0x92f36190948d2L,0x8debbe384dc0dL,0x71fa5859d79c9L,0xceaf6bcc83209L,
        0x07793c29636f0L } },
    /* 49 */
    { { 0x5669b6d970f51L,0x598d88c22df05L,0x685ba68e83b3cL,0xd05e624f33f09L,
        0x09a1653a54a34L },
      { 0x9dd5bfe134e8cL,0xedafd7e22b4e8L,0x28662239cda5eL,0xbfe849d8322bfL,
        0x01b43287c8a8aL } },
    /* 50 */
    { { 0xc091fdaef42deL,0x9743e9d6bacddL,0x0a805af6c1130L,0x19f33b8b17068L,
        0x082209792ada9L },
      { 0x4559f99d0b57aL,0xc3b3befc8c320L,0xabe5d446c27caL,0x4d49a6378ef40L,
        0x01afa934b8537L } },
    /* 51 */
    { { 0x2400473c2d262L,0x0dc41da1fbf3cL,0xb52f63b3a9f06L,0x3c9444a96fffeL,
        0x0a466df13601eL },
      { 0xe8d8b24901485L,0xb3d80ac88509aL,0x50ed93fcaf436L,0x085eca82f1590L,
        0x04be695fe908cL } },
    /* 52 */
    { { 0xe00fa344fdb3eL,0x0dabeb75b9fe2L,0xf7ef79b560475L,0xa15de9eba9b07L,
        0x02ac3e192f574L },
      { 0x0dd56a5cde112L,0xed93f7edda98bL,0x533a370ddbf00L,0x9f90b27f899ecL,
        0x02002df2f8160L } },
    /* 53 */
    { { 0x55f35bc8978a6L,0xcea66eb954744L,0xc4d08181d50ccL,0xff8edfa4cbd89L,
        0x0b52e8f303511L },
      { 0xf2b7fa2efeb7aL,0x1e5d526232e6cL,0x59b88e4582234L,0x80340e06413bdL,
        0x0cf119b2bfaa2L } },
    /* 54 */
    { { 0x2280a789f943cL,0x4b71d42ef1549L,0x0dfdfc9fd788bL,0x1a205a521b47dL,
        0x09bd24038af6dL },
      { 0xad554df050a75L,0xf20353da857adL,0x88e6b4b72f639L,0x0b65586588879L,
        0x06ff2c2be2e9dL } },
    /* 55 */
    { { 0x22eb47aff0b43L,0x895a15a720518L,0x2b4b00a9f92dfL,0xed6be368c2213L,
        0x0036951e3140cL },
      { 0x5ea3565bea331L,0xbb3ce5c9208f1L,0x8884ef7bf0324L,0xbcbfda95e3bfcL,
        0x0d72c7e1327c9L } },
    /* 56 */
    { { 0x1fa97eeee6b16L,0xd040ed83fc7f0L,0xfce79a6cce129L,0x9e84c93919f13L,
        0x08dafd0de96e0L },
      { 0xd9049fc60c529L,0x1055fdb769d65L,0x1a2cfd15843b7L,0xa22da6f973e6aL,
        0x09f0dcab7970fL } },
    /* 57 */
    { { 0x20cfd728aadf3L,0x28c070b46ff90L,0x1f9a432376d8fL,0xbb4824a02f313L,
        0x0a9a6c13f4c77L },
      { 0xe5c45ab369b55L,0x044f5ac90de4dL,0xc80e8156cc8cbL,0x9300131852e17L,
        0x08504f3550f67L } },
    /* 58 */
    { { 0x3fbe53a22cc5dL,0xc7daa6bdccb4dL,0x301480f612067L,0xafae2919eb5b6L,
        0x04238725e6f5bL },
      { 0xf69a2d8ae2dfeL,0x3f3dedbd0925aL,0x4ffcf12992c6cL,0x06d5232e6f43aL,
        0x0e0ff26347b92L } },
    /* 59 */
    { { 0x98e1c5f6a97ebL,0x49a12e0bc9233L,0x1afaf63feec3bL,0xad9d2db029d0cL,
        0x0caf10eeef6b1L },
      { 0x54e4da8f02497L,0xe1712c4b88871L,0xebe9643ae1a98L,0x505ff627d2414L,
        0x0ca4c47ed2861L } },
    /* 60 */
    { { 0xf1959cee1f8dfL,0xc3eba36ac535fL,0xf4a0d4afae13dL,0xb7965a426de78L,
        0x05019e48a606dL },
      { 0x141321628aa47L,0x705a5e065ddc8L,0x065b51175ff85L,0xc426898919888L,
        0x07880810a513cL } },
    /* 61 */
    { { 0xc4dc0ab8bbe28L,0xe50846ba34b6dL,0x93bfba75dbe49L,0x21ff1abeba8ceL,
        0x071c0d8d2aa10L },
      { 0xcc527bba1651dL,0xc8183a2ae4ce2L,0xc221e0ad328e4L,0x14367836996d6L,
        0x01a3181c9758eL } },
    /* 62 */
    { { 0x381f19224e28eL,0x05366bb0d87bcL,0xe8cafd88b125fL,0xfd7ccfefc04f7L,
        0x05bd73477063aL },
      { 0x169ab0a245316L,0x329104f04fccdL,0xac7762fac7c88L,0x15d8b1a611643L,
        0x04c80bb71f0b3L } },
    /* 63 */
    { { 0x7831a63b9249eL,0x5bbbbda95e07cL,0xf4517e8e5e0f4L,0x1d799d1b6c0fdL,
        0x0d01cde0669bdL },
      { 0xd69a7ea498130L,0x938451ab5e36dL,0x4ad3deddaa651L,0xf1b088a3cdedeL,
        0x032c2a71bffc9L } },
    /* 64 */
    { { 0x992a4202bde39L,0x643d6bab98fb3L,0x77125122549f5L,0x7e500b5646428L,
        0x0d52442b47fdeL },
      { 0xefd08a3d3e16eL,0x0ac83b29bda6cL,0x06dec8c5b194fL,0x0c1e6db0edd89L,
        0x07a0909590257L } },
    /* 65 */
    { { 0x6ce6dbfab3d26L,0x3b668edf1804dL,0x06250baf2aa22L,0xd66deb899557fL,
        0x0ef6bba074940L },
      { 0x3763bb78ca345L,0x4f3f08ff72b48L,0xbca92b215867bL,0x04db91225b725L,
        0x0ccead6634988L } },
    /* 66 */
    { { 0xc13fb58d49df0L,0x0f5003f43d233L,0x472130f3d2555L,0x3deff6f920a28L,
        0x03b9507a3142cL },
      { 0x8608f697ac7d4L,0x90bb84db98810L,0x61853b9fe1cfdL,0xb38ccf2ac224dL,
        0x0ac6fe44c6ae3L } },
    /* 67 */
    { { 0xd14a7a42c8ed7L,0xf9c988a8479b4L,0x3dca61f1ec02aL,0x2f913a6fcf6e3L,
        0x031d28b007285L },
      { 0x89bf66eefcf6aL,0x24c1c5002ccc6L,0x36c179f835e6fL,0x7883716fa5076L,
        0x02ec87a6a62bbL } },
    /* 68 */
    { { 0xef5e8487bdc21L,0x75858c0310d7aL,0x8d1054f626fbdL,0x12658cd9250d0L,
        0x025a65ab1d083L },
      { 0xac007fec04e2cL,0x558ddf0f4c4d0L,0x31dd8a0859f43L,0x799db1d58e0b0L,
        0x09df8ab409618L } },
    /* 69 */
    { { 0xcca5543d44adfL,0x956bf2e90e4cfL,0xf8b275d6ed6f6L,0x71f5ff878d621L,
        0x04ac007748464L },
      { 0x08905d59b5eaaL,0x4fc904e73ae8fL,0x419c14cf961ebL,0x1d6e512829438L,
        0x0591e7dcf94e4L } },
    /* 70 */
    { { 0x90e7ff2bad284L,0xf3855fe1aadcdL,0xc15c1e86a6b30L,0x48878561f9048L,
        0x03e06e03174d1L },
      { 0xa67b2e6db2203L,0x94d2e66bd5777L,0x65cf7b058db5eL,0x035728df0d59bL,
        0x02dab3a07c626L } },
    /* 71 */
    { { 0x3c73cd2792b23L,0x954a6613a4cf3L,0x22cb6f31f2cfcL,0x0cba1174a86acL,
        0x04ae01cb017f3L },
      { 0x7c15ebad7d330L,0xb43b414fc58b0L,0x201c68e53295cL,0x8ccf555022e19L,
        0x007bce7c292adL } },
    /* 72 */
    { { 0xfec91cf71938fL,0x443cc010db955L,0x5c813906176f0L,0x41fa5cbfa71cdL,
        0x0780408917241L },
      { 0x0f9f24211fcc4L,0x6869d456119d2L,0x3bb5005f5a0c9L,0x095cfbafd81b9L,
        0x07b9d8d7b0e95L } },
    /* 73 */
    { { 0x07473565cb6c4L,0x137f738e873baL,0x93003e9f2fc43L,0xb45b0edefd718L,
        0x0ce96d07bce48L },
      { 0x81f9645a3e43eL,0x92e6e75f809d1L,0xcf10bab4d1c09L,0x4a8b3651ec38eL,
        0x060fa83fc179dL } },
    /* 74 */
    { { 0xfea09db2f8c7cL,0x81f767bafd965L,0xc0c2017c05410L,0xda0867da4ff02L,
        0x0472c556ae428L },
      { 0xcb20a7c717933L,0x7c0dddf8a0b85L,0x8b0ba3788d447L,0x62d5c36017df8L,
        0x03412b1362c61L } },
    /* 75 */
    { { 0x133f07a26cf67L,0x450f3ed6c4602L,0xf7819be231fa3L,0xe1b9a8183f392L,
        0x0f403ddb0cc40L },
      { 0x111d8fd14746eL,0xb7fc2a4978623L,0x0bde2be4ed1d1L,0x148d4bc2ae2e5L,
        0x042cc90f7dd66L } },
    /* 76 */
    { { 0x4232d5471c5c7L,0x6f35c69a9d2ceL,0xfed117e90c84cL,0x330557b5a756eL,
        0x089a7a62adee7L },
      { 0xe8ce21e5add63L,0x3f977005b01e9L,0x61dc97747e20bL,0x1699de442f5dfL,
        0x0e8222d95dafdL } },
    /* 77 */
    { { 0x16ab6fb21173fL,0x6213b2332013fL,0x03dc5887d6505L,0x6025fd35f3698L,
        0x01ff1996ab6c2L },
      { 0x2441c7e49ae4bL,0xadc1d4d2b3593L,0x01f9a86e58d8cL,0xd2cbfc26aeae7L,
        0x0f3043fe53826L } },
    /* 78 */
    { { 0xc6070beb74735L,0x623b016809d27L,0xfffa491662f49L,0x8a68f2f821c4fL,
        0x0e80d0d2a8de0L },
      { 0x783785152be84L,0xa64d940804064L,0xf729581e65b70L,0xa0685b390ac93L,
        0x0b39a11e413b0L } },
    /* 79 */
    { { 0x43e88edc47a03L,0x448163d1ebbe9L,0x02cfc25db0400L,0xa0ad7673179c4L,
        0x0a7842fb6858eL },
      { 0x97369c3a823a2L,0x4febda0548694L,0xb2363f48af3d5L,0xa5868975de556L,
        0x05e931dec707aL } },
    /* 80 */
    { { 0x4de6e805f0ed8L,0x7905ad4708725L,0x339058ee0ad1dL,0x8957f3212455aL,
        0x0f176c2f9834bL },
      { 0x2a6929162ff84L,0xb5eaa628e86a4L,0xda655e17af37aL,0x77b6e6605aa80L,
        0x0840eabd99bceL } },
    /* 81 */
    { { 0x2a820b891bf80L,0xd63dcfd53c15eL,0x354f5d6f218d7L,0x6c0b0b3fbb91cL,
        0x0d2907e2060ecL },
      { 0x584dd4a8c701aL,0xb29f829e572baL,0x33ce8351edfa8L,0x6197482e8e37fL,
        0x04f8b758175b0L } },
    /* 82 */
    { { 0x95107bfbe555aL,0x7e77b3851c2beL,0x18b7f279b76fbL,0xe126beb031483L,
        0x0425194eb80fdL },
      { 0xa386a2996474bL,0xafcd1ed314489L,0x07c380c318df1L,0xbe26e01451dc8L,
        0x0c0dfbdab2a38L } },
    /* 83 */
    { { 0xa05bc4043ce80L,0xdc28e09c50cc5L,0xab5ee6b4101c7L,0xfbeccec16f691L,
        0x06e0539e03f02L },
      { 0x6e66a57b36485L,0x62e5c8d145dc3L,0x04068af07d552L,0x0491ae754a391L,
        0x0c47aefb71c47L } },
    /* 84 */
    { { 0x039f848e761abL,0x3ca4db0990c1fL,0x5ba216cb75d92L,0x7cdcfe8fffc18L,
        0x05f193c876466L },
      { 0x2f35c78ed1f3cL,0x9e77a90887dceL,0x21fca7182cbb5L,0x141f0c6bb6345L,
        0x0bf0b44e88d79L } },
    /* 85 */
    { { 0x4f15dc6fe11e5L,0x4919a25ef3c42L,0xbb313341e866aL,0xa903419ace92dL,
        0x01bd3b4412408L },
      { 0x62300cad2225bL,0xabcf204b841bbL,0xd229aa644db4cL,0x23849fcf0afacL,
        0x038d13bedcc49L } },
    /* 86 */
    { { 0x9a1145e4fb378L,0xe6a1c8e94d7bdL,0xfa18b0a56be5aL,0x86969322de412L,
        0x0983fb47e5aafL },
      { 0xe624928cde8eaL,0x7d2bf0d003d32L,0x571b4e8c23526L,0x5049fbc55e890L,
        0x0d119056fbd60L } },
    /* 87 */
    { { 0x6c659e5729482L,0x67f29b3b869b1L,0xeedf6f34b02beL,0x3e0136702e4bcL,
        0x0f518950b6c02L },
      { 0x536f0c01c7886L,0x46093b1218b2bL,0x7b6836499704fL,0xe9c5500ac8e07L,
        0x065f724789231L } },
    /* 88 */
    { { 0xf545bcbb602b5L,0x14bd8413abb3fL,0xb5d352a566e51L,0x7ed2e9aefd984L,
        0x05bae49a80f45L },
      { 0x4695bf11d8800L,0xb6fd4ec25d07eL,0x2b7067101ac54L,0x05d4d6644e6edL,
        0x028bb3e5e1d86L } },
    /* 89 */
    { { 0x1887e69044ab8L,0xb35cb4f30be7bL,0xd7b9891933044L,0x32217aa537a5dL,
        0x042072798f19fL },
      { 0x297e3c51f50d8L,0xfceef90e536b8L,0xe5c70595b21edL,0x81becb57951efL,
        0x06d2d15fbfab5L } },
    /* 90 */
    { { 0xe6f835d33b0b6L,0xdb95d73cc3690L,0x7cfebf4bb452cL,0xc9ce62ebea7c3L,
        0x09035b6273193L },
      { 0x5279e40f4d7b7L,0x5328f329ba5c4L,0x5fc993d799d67L,0x4c1d07bc499f3L,
        0x07d579db8009aL } },
    /* 91 */
    { { 0xee57d9cbe4314L,0xaaa8584f9a26eL,0xdb21946b5ebf1L,0xed08dfe924e88L,
        0x07c2f8c186de2L },
      { 0x56c8862204329L,0x2dfd970ace72aL,0x32737160e5af1L,0x08f7391a62eccL,
        0x011796fed8e92L } },
    /* 92 */
    { { 0x1d01464c0138cL,0xc41ac403c5d9cL,0x37f20f30f1bc4L,0x067eede9cc665L,
        0x00814c5e4f1d4L },
      { 0x4e4238e58bd95L,0x86fc9a7231ee0L,0xb8fdf12cd262eL,0x8dd08a2c8b6cbL,
        0x0772a46b08169L } },
    /* 93 */
    { { 0xba56dbb35551eL,0xf5663c3ba9bb5L,0x13f92fa07c04bL,0x28a62658e49ecL,
        0x0d8002bf04b05L },
      { 0x5a44f6e19feaeL,0x31d32f85bde5aL,0xf326a5d5182c8L,0xc6ab7391563e2L,
        0x0c04b58b31043L } },
    /* 94 */
    { { 0xb1957d98d1a35L,0x98d2dae5ee77cL,0xdb024c175fa17L,0x7f3521387bf6dL,
        0x0b3706b48057dL },
      { 0xedf390d7e2ad4L,0x7825ab3e0af2cL,0x25ec8be09b707L,0x4b5f67f4ebfd9L,
        0x06ffb26eddfcaL } },
    /* 95 */
    { { 0x24628bae85738L,0xeadd316b90f95L,0xc6ed7828699f4L,0xfbe1d8d0f1101L,
        0x04175889e7e60L },
      { 0xf3defcc11b1cdL,0xf80e5e9428aafL,0x292d76e87177fL,0x3f56d1cec6790L,
        0x0dbbabaaf8732L } },
    /* 96 */
    { { 0x696e9afe9099fL,0x15407a925c862L,0xdae1f954f695fL,0x4cb18701f30a2L,
        0x0f984c561f45eL },
      { 0xfee1c6ebb4441L,0x53fa59ad454faL,0x0ba55c7fbf96fL,0x423da530b86e2L,
        0x06efa587b90e0L } },
    /* 97 */
    { { 0x55bfeb7bdf0b3L,0xfe806394fcbe3L,0x6c8e8f1f1d290L,0x01f3f517a0865L,
        0x032756a1d09b3L },
      { 0xe1fb393704c72L,0xa1d2c711e90e7L,0x36ec5995a3ebaL,0x1036aea7952e9L,
        0x04493678e4652L } },
    /* 98 */
    { { 0x61f6d525ca4c6L,0xc1b4c96eaee41L,0x70338db1b969aL,0xdf12f9975658cL,
        0x0a064cc6ea08dL },
      { 0x38c3e1c73ca8eL,0xf1c825e7b0db4L,0x659f59a0eeac3L,0x731c874903d94L,
        0x02270c0c10d98L } },
    /* 99 */
    { { 0x21bcba16a8f1dL,0xe98748f6a50c8L,0x8991a9ab559c2L,0x2758d7ad00eceL,
        0x056cc2caf98faL },
      { 0x09406b185924fL,0x70008daf7a69aL,0x82b81d1d56e18L,0x12d01a3071686L,
        0x0b51075f6a6a7L } },
    /* 100 */
    { { 0x7375f82da577dL,0x842dda1fa87bfL,0xa9fbd96f191d5L,0x339006a737400L,
        0x0a81aa04badc7L },
      { 0x7b3ac0627446cL,0x86b8bc08b77e7L,0xfa625604e6621L,0x78d38315b1bddL,
        0x0912ba4fd6196L } },
    /* 101 */
    { { 0x244e7e21bda2fL,0xd7cea4ad07aa6L,0x2f8a4ae82aec7L,0x032fa391e63f9L,
        0x00811b0a9eda9L },
      { 0xc72930c1e7599L,0x655c36a1cbbb8L,0x41883c602a318L,0x0352be014f1a6L,
        0x098c6cb62116dL } },
    /* 102 */
    { { 0xd9e52a1df225bL,0xe97fefdd9c331L,0x9f9af11133b0aL,0x1433c003f65e2L,
        0x0ad884879ddf0L },
      { 0x1e2f6a4af26ffL,0x621f6ff193726L,0xaca40cf57e94bL,0xd73b4640a4d41L,
        0x0bb2ca6ef3c5cL } },
    /* 103 */
    { { 0xb73cb4664d8b9L,0x1232302861fbdL,0x6b814c6403c24L,0xa1fd9000ce620L,
        0x028ad9c95cd3aL },
      { 0x585831d012d1dL,0x385f8eef3afc4L,0xe859d464d784cL,0x537c15d7456ccL,
        0x02002b79d8fddL } },
    /* 104 */
    { { 0xa8e8358ff29caL,0x767d4a65f9269L,0x0457f21b49c4fL,0x479c758233f94L,
        0x0149755a491caL },
      { 0x0482340cdad3bL,0x010edf5d429f2L,0x843c0a952efa2L,0x3b47e0cf812a6L,
        0x03e9b4d515ee1L } },
    /* 105 */
    { { 0x25c441851bb43L,0xfdb1d5f4c5587L,0x561ed22d6ab9aL,0xe7f1cc47d6ce4L,
        0x036e9257944fbL },
      { 0x595f778e47086L,0xe40cd235329ddL,0xbd666e8b90420L,0x1ae64eec937e8L,
        0x05fda90a90c85L } },
    /* 106 */
    { { 0x87e43fe3ece65L,0xed2e511f19ecdL,0xbc895e42c4a07L,0xb7830cef0a332L,
        0x05a4e679c81b1L },
      { 0x77167f35bef34L,0x887e9a98acff5L,0x2e42034fd949aL,0x249aecd9b69a8L,
        0x03960b999e0a3L } },
    /* 107 */
    { { 0x34531341a4ca7L,0x74653c48eab06L,0x05211b9a97b2fL,0x97fffe7fcd35eL,
        0x03abfb61a2fa8L },
      { 0x65714b67a9b8fL,0x74d4f1f720c46L,0x9e9012877c3f3L,0xd209ea8882f87L,
        0x02a201265d100L } },
    /* 108 */
    { { 0x15d09bfd9fe05L,0x9f3764454af4cL,0xfbcee9ebfd526L,0x9a3d757375b95L,
        0x0d64872463049L },
      { 0xeea190dd0e3dfL,0xf399b2c184d4aL,0x76f6787dba477L,0xcbedffa9671c4L,
        0x0404358f232d1L } },
    /* 109 */
    { { 0x9656845ba70a1L,0x8ed7c02846880L,0x0e79c61c1025dL,0xd71d10070d7a1L,
        0x0da5545e6cc51L },
      { 0x00592d36071a4L,0xbd2cb84b66861L,0xf09a3ae7ccf96L,0x45fb8c04ec149L,
        0x090263635f07cL } },
    /* 110 */
    { { 0x21a6f15a02c24L,0xd6b345c3eb6c0L,0x346cb58d8fd90L,0x3a004deeb0f86L,
        0x08e319f9928c6L },
      { 0x5c88f3fbe9596L,0x262c57f362ae6L,0x7874cb4cd4412L,0xeff4b491d9b37L,
        0x01a6cc217ca29L } },
    /* 111 */
    { { 0x498d382b02298L,0x1970c81c1f81aL,0x06009e171934dL,0x368bab24b353dL,
        0x0270bad312a10L },
      { 0x8be031acf8d51L,0x9e96fe90ff4a5L,0xa2cbad7e9f051L,0x1451f74b13736L,
        0x0558377b9d050L } },
    /* 112 */
    { { 0xacf3161f8c84bL,0x1e6e47a3110f7L,0x373f8c6a5a72cL,0x395416c2690e4L,
        0x0c05d2da159d0L },
      { 0x30c542c7e9247L,0x17ce9531dd702L,0x0f1f78ec29d93L,0x755d9683a0ef9L,
        0x07dd05c855053L } },
    /* 113 */
    { { 0xf32c2d935116fL,0xe928550a73369L,0x5d579b6f776c2L,0x7ade7e449b09cL,
        0x02caffed8217aL },
      { 0xec3fb17ca913fL,0x31299bdfe4acfL,0x8bbbc6e1b5926L,0x5edc58016260aL,
        0x06ab392fca90fL } },
    /* 114 */
    { { 0xd2c9d0ccceecbL,0x9fd0705967904L,0x813ef3c89102fL,0x5335d12f41938L,
        0x02ec8a831f7feL },
      { 0xe1674736d8979L,0x6bb00549a6b60L,0x64085eb911593L,0xa207df4f2d15aL,
        0x04517fa550f72L } },
    /* 115 */
    { { 0x664b9b807c6e6L,0xb4ae45a4c6269L,0x3791c1431ef23L,0x3887e2076e09eL,
        0x0b8c4f5677a38L },
      { 0x1e21cbc149a92L,0xc3d3a787bea83L,0x3ffd766a4e6c3L,0xe8bc0eb26c57cL,
        0x0a9f8c4f67796L } },
    /* 116 */
    { { 0xfcd0bc2df4bf3L,0xe5aca2333beceL,0xd23fb04f34c21L,0x8ac8bf4bc9d7dL,
        0x08188fc44aefaL },
      { 0x8a9308d27e4ffL,0x4b56de52828f9L,0x53ba693176f52L,0x7bc3ac3573426L,
        0x01184e8d4c791L } },
    /* 117 */
    { { 0xf080c3ec27426L,0x34314f618d819L,0x56058821bf33dL,0x8ebc59d87c260L,
        0x0614c5091be74L },
      { 0xc1bcb6b12648eL,0xb0b1ead712bbeL,0x27f376d84575aL,0xb2d70d567c957L,
        0x0f7138698d689L } },
    /* 118 */
    { { 0x15b85002936ddL,0xc585ff129e58aL,0xc76679f32db35L,0x75d31c85d85f2L,
        0x01c4e12bd8209L },
      { 0x049647a93eaa8L,0x28636767448fcL,0x04c293ff3aba4L,0x307107fa73fa1L,
        0x090c82500988dL } },
    /* 119 */
    { { 0xaf557dbff4effL,0x2d97c3fa174c8L,0x0949630c63c07L,0x25455f7276b41L,
        0x034db1d0e2ea8L },
      { 0x2e7dae950c2ceL,0x05ccc61dd3528L,0xb48882ec05841L,0x17d9cd364e40cL,
        0x062e3bc4ec467L } },
    /* 120 */
    { { 0xad306f4d76e8dL,0xdcb922a0bedc9L,0xffb545337e687L,0x1951d06acfe9dL,
        0x0c85252901639L },
      { 0xe48cfcc8601a9L,0xb758b7337334dL,0x8bd9fffc4f078L,0x34d62a3cc0962L,
        0x05bec709befd1L } },
    /* 121 */
    { { 0x4abadf4d0a639L,0x10fe612ba54e4L,0x0e58c0cbb4c99L,0x0e9aab2e5b413L,
        0x09a6a2fa53e80L },
      { 0xc57882ca0d01cL,0xa189a25d59f5cL,0x53fbaa73f8412L,0x9ab64ba569e04L,
        0x09e33bd82e062L } },
    /* 122 */
    { { 0xe957c61613f97L,0xdff35694cbd4fL,0x0a7f9c2b86e9dL,0xf4ac65700b9aaL,
        0x0349a4dbfa789L },
      { 0xb7cf8483553c7L,0x55e07dff25836L,0x48bb8e4e41f0eL,0x7fa8e71ca7128L,
        0x0625b33bcc00aL } },
    /* 123 */
    { { 0x1f45ac7068002L,0x2f78affb63bf4L,0xf3207fb9f4b86L,0xb4e2523f30d1fL,
        0x0af6534307212L },
      { 0xb18f6bd9269e3L,0x2a5bbb73b4595L,0x381044d0ddc25L,0x1aabb59634a82L,
        0x072550c74c4dfL } },
    /* 124 */
    { { 0xead414997b745L,0xc580ab76980f4L,0x5719bf1ab3e46L,0x4bd3e010d55a8L,
        0x00fe9667be730L },
      { 0x12a0a44eae3c6L,0xf58a4808a78e1L,0xc32d57dd30ce0L,0x0e1c3fac78315L,
        0x01e4b2152c95dL } },
    /* 125 */
    { { 0xb885864a0b46cL,0x53ec200e699c6L,0x74942ce6a3c12L,0xd452db0e573faL,
        0x01ef64607257dL },
      { 0xfd2e589b9b886L,0x874ef3df9bb3eL,0x10a57e02046deL,0x139c4b837cee1L,
        0x0c8b4274479f3L } },
    /* 126 */
    { { 0x7f4deecd31b38L,0x1b946b43e6fd5L,0xf27e71a506463L,0xcdb45f75a0e83L,
        0x0b98d159a8539L },
      { 0xcaf0746fc3042L,0x3f862ec3fd941L,0xdc6a175b0e4e2L,0xc36f637e2cb2fL,
        0x0524255843589L } },
    /* 127 */
    { { 0xbee0f63fb7688L,0x0416ad1233b80L,0xeab742f4b03ddL,0x2028b2aa0667dL,
        0x03af71b2d7d62L },
      { 0xa50b4725b4531L,0xec08af5e894caL,0xc77438abb4342L,0xf5752b61fa9d3L,
        0x001d25439db0aL } },
    /* 128 */
    { { 0xe265bc25dfad3L,0xb9493f44b6e74L,0xfd6d473d03630L,0xe992b3270892bL,
        0x05b2d95431c5eL },
      { 0x94537a36f7c5fL,0x1d8ab0b81deebL,0x88b45e59befc0L,0x648b483cdb081L,
        0x044c753b701e4L } },
    /* 129 */
    { { 0xee42d924195acL,0xa00cec6c21779L,0x11bd34344ccd6L,0x826e1a0df86e2L,
        0x02f73a627a7fcL },
      { 0xc9d7cdd4b2facL,0xb365a3f70b179L,0x3270b3de09df4L,0x7f02169b58ea6L,
        0x05934a0a05721L } },
    /* 130 */
    { { 0x905bff471c90dL,0xf530de94b7488L,0x218ea8f2fe5dcL,0x558fef4366988L,
        0x0986125e879e5L },
      { 0x9c17a2ce9c497L,0xe21ddab4b12e5L,0x00352188131f0L,0x69e4408daea72L,
        0x0cd71798ed404L } },
    /* 131 */
    { { 0xfd6520fe2e160L,0x2305bcf84f3c3L,0x151f451569f81L,0x45ec022bf0e95L,
        0x0054574f4ac28L },
      { 0x7853dd524a547L,0x2733d6e7b0bb1L,0x4d10a83bf1b6fL,0x37e75d71af25dL,
        0x0d4cfa938e8aeL } },
    /* 132 */
    { { 0x9e364843e3cb6L,0x8d61812528da3L,0x7862e0af259a3L,0x8c1394912e515L,
        0x08142ba4a2e97L },
      { 0x48db9244620d5L,0x53a46c8074b83L,0x1e6346ee67f90L,0xb73d21ab9bffaL,
        0x00441577064f1L } },
    /* 133 */
    { { 0x55d5874019e33L,0x2218e26d25d43L,0xa91876fdb1c1bL,0x83fb9a39a7d6eL,
        0x0c1d29df0ef2dL },
      { 0x781209cfaf04fL,0xbbc33a65eef23L,0x5364c6b5ca4b4L,0x3666529e4d14cL,
        0x09cd549d00b9cL } },
    /* 134 */
    { { 0xcb8240d561bbcL,0xd1753ced327daL,0x3afb0377c7c2fL,0x3a55d9774757fL,
        0x0213fe3710d6eL },
      { 0x3d8d550d4f212L,0x8198665a38a6dL,0xf2a518a674c0aL,0x2353112e0ed54L,
        0x01b995abf8f90L } },
    /* 135 */
    { { 0xb8d220f049d2fL,0xb2eea425afa06L,0x051b012415763L,0xbae0027b304b8L,
        0x0b8cdb43fef51L },
      { 0xe11fed7109f5cL,0x5d7298d02f492L,0x34f9a120b57beL,0xd326eeda24c46L,
        0x00b0aab291592L } },
    /* 136 */
    { { 0x48c8d1d0ad6b2L,0x4bde384635a4aL,0x9b7e3243b996eL,0x055b09d5a0fe1L,
        0x05847aae5efacL },
      { 0x1627fa0c3770eL,0x706fc34e82f6bL,0xc0ede6237cb26L,0xe059fdcb37fb6L,
        0x04e41298d2a34L } },
    /* 137 */
    { { 0x04e369a3b63adL,0x53bc32306384bL,0x0045b9a8353abL,0x582806987ecacL,
        0x0b461ba8846f4L },
      { 0xef067e5943cccL,0x25cdc4de91d37L,0x24ac769e5d366L,0x2b9d4f72a9d30L,
        0x00ad61f173c8eL } },
    /* 138 */
    { { 0x4fdc8b5c95125L,0x86c9341981511L,0x9b74fc057637bL,0x7e41b66786bd3L,
        0x0c9e138be230bL },
      { 0x6d5fede050283L,0xa3d609a03e0bcL,0x1ae24f0a7c743L,0x96681233df12bL,
        0x0b2ea42ec57dbL } },
    /* 139 */
    { { 0xb88401363c862L,0x3039a4b7179f9L,0x87a216d9a850bL,0x9a0caeffb727fL,
        0x0754cb279b3d9L },
      { 0xe6946bade742cL,0x4f3b3ea466046L,0x3aa2b1c05669aL,0x4fe1c64392ba2L,
        0x0a218279dfd71L } },
    /* 140 */
    { { 0x3d984235b46aaL,0x71e219d5a2420L,0xc5ba535b35f0cL,0xaaca93a429b23L,
        0x07eefbb779111L },
      { 0x99023c45d8760L,0x543ce3938867bL,0xbf34ec0a0f786L,0xd638aafb1901dL,
        0x049498c8b2dceL } },
    /* 141 */
    { { 0x5cc8a99e4ef46L,0x670ef0d4b194fL,0xfb89f143321e6L,0x9a20db2d0224fL,
        0x09bf748039d06L },
      { 0xd6b134f1c1f1eL,0x852162dd15a64L,0x77423251ab102L,0xefc17c7f6a09aL,
        0x0c5a9082dc823L } },
    /* 142 */
    { { 0xfb6793d087141L,0x2dfbdb7ff5393L,0xba6c9d3e87293L,0x760b21bff1a24L,
        0x03193dea297adL },
      { 0x5a74110c7e145L,0x29b18493bf0aeL,0x871111e9e7cf4L,0xcf39a0a3bfa1cL,
        0x0322f34eada10L } },
    /* 143 */
    { { 0x375dcee32db92L,0x01416f8eb4482L,0x04ba196a7e02dL,0x8715224fb2c10L,
        0x0165f5f16c648L },
      { 0xd71bfd1125e78L,0xf437d5cc464caL,0xfd065aff7a1b1L,0xe5e7b54a9fe1eL,
        0x03a954eb0dbfbL } },
    /* 144 */
    { { 0x4a643ff76620aL,0x331823303445fL,0xebce0abdb8391L,0xe3d8b777abeeaL,
        0x0e610ded6b961L },
      { 0xf85ddd7bc0322L,0x4f05bcf887848L,0x5d3ed9864dec6L,0x4bf832f43df08L,
        0x02e150e9a0af9L } },
    /* 145 */
    { { 0x0c658c7de998eL,0x3a3509373d589L,0xd290312c418a4L,0x762a04661baf7L,
        0x087a24bdad4f3L },
      { 0x6493dcaf8e73aL,0x49a475ba0d3a4L,0xfa35fe6694bceL,0x94ac9af7566e1L,
        0x03ee19601d7bcL } },
    /* 146 */
    { { 0x209eedfb0faecL,0x718a6ec9775bfL,0x04a9727514ea8L,0x631395b71f0edL,
        0x04650bc76db49L },
      { 0xc758d58184292L,0xf9ec9aceab22cL,0x91f0bb7152d43L,0x4e794b47606e0L,
        0x06da270ef1b7dL } },
    /* 147 */
    { { 0x7022b935c7726L,0xb7d1af2fac4eeL,0xdf9e72f2f7e7bL,0xb2d855a2f594fL,
        0x0edf46a3014b8L },
      { 0xba600cdc3292fL,0x3a58c6f6a4e5fL,0x023369e04b54aL,0xa1ad1263dc16bL,
        0x00ac721ddbfc3L } },
    /* 148 */
    { { 0xe1d9127351b84L,0x394dba475be62L,0x67c92195c99d2L,0xe29b6cafe0d05L,
        0x08db1ed2a5418L },
      { 0x4e136e729b5e4L,0x79ed50249436dL,0x48095070c714cL,0x027920d538d3fL,
        0x0c187d5fbb0b2L } },
    /* 149 */
    { { 0xa10ce51ad0a16L,0x24679b780468cL,0xb25aa043150dbL,0x0e220e9496a5bL,
        0x071237e21ac09L },
      { 0x11b2b8454f658L,0xe399498743d39L,0x6a6a08eb4cc8bL,0x05963eec8fbaeL,
        0x03230250589d4L } },
    /* 150 */
    { { 0x8b046ad144097L,0xf824c88b1ae89L,0xcf479aec5ca6fL,0x59009d01b59b8L,
        0x05ecd93aa9211L },
      { 0x4b1d861716de7L,0x0758d641b5f4bL,0xa3f3a12187b1eL,0x15183c6948c5cL,
        0x03841240cee7eL } },
    /* 151 */
    { { 0xbc16a69f16249L,0x50dddb15107d5L,0x6d23cc9aa9323L,0x00ebe5df51047L,
        0x02f2a1306bb09L },
      { 0xf3047699413ccL,0x3026394d949fdL,0x939646171f3cdL,0xbffaad22fa8c5L,
        0x06c6253bc469fL } },
    /* 152 */
    { { 0xfbc3e1e33c180L,0x63615e3e38b79L,0x7111e5e754fb9L,0x57bba3a408383L,
        0x0d8780e0449f7L },
      { 0x41a11e545fb38L,0x1b55d54231bb9L,0xfcc068d227ba2L,0xe2775d80da73cL,
        0x0d3b0557be600L } },
    /* 153 */
    { { 0x524f5595a7415L,0xfc657a5920286L,0x477845c1e8dcdL,0xb3ba04d7efa91L,
        0x086bd1af717d2L },
      { 0x833c706b56786L,0x61028130b208eL,0xe05001dff007bL,0x292afcafe0826L,
        0x041556b5537feL } },
    /* 154 */
    { { 0xd38190baaa8ffL,0x7b45bc51befddL,0xa86f8a9d916d1L,0x6491f981a07a6L,
        0x023111568b2c3L },
      { 0x28fa0da2059abL,0xe8a2f34fea516L,0x0d7894c62537eL,0x567bf34ce38a3L,
        0x0c464b9dd967eL } },
    /* 155 */
    { { 0xe55926fd5fc85L,0xe99d5e37410e4L,0x835d025cccec5L,0x825c3c297adefL,
        0x040e40ff81250L },
      { 0x20ecf1953cfa2L,0x6405e32613d41L,0xe8fe373295c5bL,0x15fc0eb531c0eL,
        0x05c4d24707ea3L } },
    /* 156 */
    { { 0x43946918fd269L,0xdd7c10b8ee735L,0xfcf9bb761cd97L,0xa4a75f88e7815L,
        0x0ce83e70e4cc5L },
      { 0x1847f7d845599L,0x73e052a4ac489L,0x6932c5db1a2b3L,0x79646996b90efL,
        0x04e53f3708122L } },
    /* 157 */
    { { 0x5b8eb55856253L,0x8b47b465f5213L,0xb8090acba19eeL,0xed6a8e2b91a11L,
        0x0f80bb6bf7857L },
      { 0x1366173d12c59L,0x11c74599e60a8L,0xda2a2dfa75a8eL,0xc463ad08ee3ecL,
        0x070d54102c87aL } },
    /* 158 */
    { { 0x6584f49af46ffL,0xef2f98bce9673L,0xe133b91096d00L,0x04eb77f019424L,
        0x0d10b349e5f39L },
      { 0x31a1380429c3bL,0x82f0fabf71961L,0x8a64ffe479ab8L,0xc3cf40a22cde7L,
        0x0165920d31952L } },
    /* 159 */
    { { 0xf1c1afc086dd0L,0x8512956035ab5L,0x5a58ddc07063eL,0xd60ffe92b742cL,
        0x0a58aeb140cd4L },
      { 0xf3323ef78f77aL,0x1266687342975L,0xa031ecef31f29L,0xab9ad92b874a6L,
        0x0f1b36156554dL } },
    /* 160 */
    { { 0x9fa744396acccL,0x79f00e49e82ceL,0x6694beeef9c4aL,0x785c9c32ee8deL,
        0x06fba4bbe0e8fL },
      { 0xa8e0378a65c2cL,0x6918cb8f4065fL,0xb188e1a7ac38eL,0x3ec824f743ab6L,
        0x0c39006b456ebL } },
    /* 161 */
    { { 0xba583732d3604L,0x810b6b3459519L,0x20f4fc59bfeb4L,0x23501897d0c91L,
        0x0de080cba4a7bL },
      { 0xd8414a7d2b287L,0x2b3f4fd647b8bL,0x5bb04278a78b7L,0x0cf8bfa1061d4L,
        0x0e6f95dae7594L } },
    /* 162 */
    { { 0x29b49f0bade5dL,0xf643f806b81cbL,0xc73ee16742025L,0x57a8890214eabL,
        0x0cbbacf134e93L },
      { 0x32714d4970cf8L,0x50433f00da71bL,0x78913cdec4f8eL,0x20e3a92b3b9d1L,
        0x0892fad976305L } },
    /* 163 */
    { { 0x5194f02648f13L,0x6c27b6be015faL,0x709091b169f29L,0x703e7971c34d5L,
        0x0c4390edc01caL },
      { 0xe8745f36dac3aL,0x738cd0c336ba5L,0xfd290ae25a85dL,0x0dc425af152f1L,
        0x09fa06153ccc5L } },
    /* 164 */
    { { 0xa778c61604b75L,0x639e8033174adL,0x581908461e464L,0x6feebc7f3a0aaL,
        0x0b4f2a6baf361L },
      { 0xbafb8540da7f8L,0xcff4d6225a482L,0x1c5e50e9fd559L,0xb407a0f1d758aL,
        0x035c216e7e872L } },
    /* 165 */
    { { 0x013fc04a1c7e2L,0x5ca946f3ffaceL,0x83d06acc6990dL,0x15b471dbec407L,
        0x0e30a6d8543ebL },
      { 0xd7d4294673feaL,0xb47c17e5f0dfeL,0xde2e1b0f3191fL,0x269d091f8e0bbL,
        0x0e4ef3600d38bL } },
    /* 166 */
    { { 0x14bc7a4f41f17L,0x04cfa30c21ae1L,0xf5c1e5c9279e4L,0xc925fa5eb2050L,
        0x018722e9fb881L },
      { 0xd7a37bc23bf33L,0x5da01c1056ff8L,0x79bed471d5cc7L,0x3e5638b6e7ed8L,
        0x01aae4f6e8ecaL } },
    /* 167 */
    { { 0x4895b690e1ed5L,0x0c39da8dc360aL,0xf566fa4391a0dL,0xc22dfa6239a05L,
        0x05d1bd75bdd56L },
      { 0x4adaefdab28fcL,0x0a80d52bcc302L,0xebbfdb1cb81feL,0x73a10b8947a6dL,
        0x0727d4cc2a0b6L } },
    /* 168 */
    { { 0x9ed48661e7a89L,0x2cffaf4d15fa3L,0x94fb83ebbabf2L,0x890625e4c3086L,
        0x01082cd04abd0L },
      { 0x4dfcedfcf1eeeL,0xdf7ce8427f6faL,0x3533d4cb1f0e4L,0x175fa6d9bcbf7L,
        0x01cc91dfd973eL } },
    /* 169 */
    { { 0xc2fc5a0d41758L,0xe37783739cf8eL,0x3526559ae5419L,0x5eef1654d7ddaL,
        0x075dde554efd8L },
      { 0x0accb71da8cbaL,0xa191e56cf0876L,0x1d8f13a485d4bL,0xfcfd81e620348L,
        0x0f4b5c1eb8522L } },
    /* 170 */
    { { 0x973ce50dd7082L,0x23708c6f264c3L,0x5af64832bae6aL,0xe2082f88f4466L,
        0x025a78b5ee21bL },
      { 0xc29cc908c8150L,0x1698fd5ffbe66L,0xdc660289829b6L,0x9b00c04624bcaL,
        0x0505f95611a19L } },
    /* 171 */
    { { 0x3f41859dabf11L,0xacbc4d2d5bd52L,0x790e997570f20L,0x992ad2ce247cfL,
        0x085fa298ed574L },
      { 0xed5f34b273bd3L,0xf9765f65a562eL,0x3f38d8afe8b6aL,0x67befb2f462a0L,
        0x05f6122f4057aL } },
    /* 172 */
    { { 0xd731e5b5100ccL,0xa739d4313f124L,0x120c6384f7860L,0x5ad03d8293301L,
        0x00b9786d4c64eL },
      { 0x427c023985e90L,0x00c889b882acaL,0x1d4f290dbc70cL,0xda0da292ff816L,
        0x0970f1f5a5b2dL } },
    /* 173 */
    { { 0xff2c3fb1d91cfL,0x1219aa012ecd1L,0x29e18ee6d2784L,0x4762c9d1cbd62L,
        0x0a815433ea80fL },
      { 0xd4b4f8e920554L,0x45d0aa369b83eL,0x7a905b01d3f0cL,0xa60c17275152fL,
        0x0f1a03dd31ab9L } },
    /* 174 */
    { { 0x10eda48c26023L,0x50af3927c892cL,0x8916b9db2227cL,0xf95a1cbe20e76L,
        0x0cfd53e67a602L },
      { 0xc9993a0130dd5L,0xcbe4cbe0fa3cdL,0xaa67f6e9bb6f3L,0xba184d2daa7e8L,
        0x0f626df7ea206L } },
    /* 175 */
    { { 0x53d4a56c08f54L,0xcbdfd00c53ff0L,0xcca3d258cb873L,0xea68b49844d18L,
        0x058257196e113L },
      { 0x29282d26f6bdfL,0x6c66135148a0eL,0x48a385a7621dcL,0xe1b0057dbc3f1L,
        0x049badc079b26L } },
    /* 176 */
    { { 0xb2df7c47731afL,0xa57b9a1f37353L,0x6a16fa4767106L,0x003fd5fe65f77L,
        0x04d65eb8d1c39L },
      { 0x702fb0e6d9389L,0x46490998797d1L,0xe4d0c8ebf49d2L,0x6e64a84e2ff34L,
        0x0bdbc377344f0L } },
    /* 177 */
    { { 0x219e040209feaL,0xb36286c965150L,0x8a4e72c56e604L,0x0883f118efad4L,
        0x0c6f889c8294bL },
      { 0x8d1648e7e0c57L,0x2a23d600abe4cL,0xedb4278a92c6aL,0x34ca24dd2751fL,
        0x0ffd8a7e1d93eL } },
    /* 178 */
    { { 0x627ed160722afL,0x0228bf0d0f2d2L,0xec4d61c3c8b81L,0xf2cc6eaf4d9c8L,
        0x01b4baff52c17L },
      { 0xa3e23b4594092L,0x457d829bf54f5L,0xa5a422214b4a2L,0xe001fa5ee05e5L,
        0x003a0d850ec0fL } },
    /* 179 */
    { { 0x1d6c669ade883L,0x56d7fab9b59a3L,0xc61b5ac9d49c8L,0x50de578ab41a0L,
        0x07e4f29023323L },
      { 0xbd4ed196ac4bbL,0x05afcea98d719L,0xc85a02c71c88eL,0x8e8e5b441bbeaL,
        0x04132c66dfa01L } },
    /* 180 */
    { { 0x42d5cbd80c757L,0xed3966b1a6862L,0x2e7fcf4d3423fL,0xf3f05d0ad4d69L,
        0x0545bb52a4a79L },
      { 0x226342037745aL,0xfe5c9a47cca12L,0x140baadb58d29L,0x69a3ccda98272L,
        0x0603e39d376c7L } },
    /* 181 */
    { { 0xa6ec367c3d4aaL,0xd108bef96fae9L,0x664d0a8444f55L,0x13aa50996abedL,
        0x0a44601dd6086L },
      { 0x256f9ba37b00aL,0x0aea4489ca076L,0xf3567819d9f73L,0x9ac2e8e1af338L,
        0x09da72c5c1b0cL } },
    /* 182 */
    { { 0x80cd28056721fL,0xe4cd67f6a3a54L,0xfdbf0a9f8ba48L,0xedacc8dc6652dL,
        0x03d7064afb7e1L },
      { 0x4ea36a309625eL,0x23896c1810445L,0x7e52615026a02L,0x703be9f500118L,
        0x0f7a1b2533c3dL } },
    /* 183 */
    { { 0xdfac66194a9a7L,0xe7ec1c3185f4aL,0x0a0ea4631a944L,0x35c5fde9ce814L,
        0x016a7b783abf6L },
      { 0x9d62487106be1L,0x56baeedd58cf4L,0x5e3b59af11081L,0xc90053bfdc636L,
        0x089acded0c0a7L } },
    /* 184 */
    { { 0xb380b9c0c7c04L,0xac9f01cc9ca6eL,0x85b6c6e23007cL,0xe7adc4ddfb2f2L,
        0x0bcdc7f514d2fL },
      { 0xc65344a8963d2L,0x5e27b55dd742bL,0x8e798742fa0bdL,0xf9377e493fb2dL,
        0x017108a6cc84bL } },
    /* 185 */
    { { 0xd2e9ca0ae33b0L,0x660e3cd0538f8L,0x0587996403cc7L,0xfab6f78165852L,
        0x00f662d5669c8L },
      { 0x35eacd4e35be1L,0x016ab0035dfaeL,0x783bcd45ff472L,0xa9d54cdb6ea1cL,
        0x03ad2e46a5247L } },
    /* 186 */
    { { 0x6bef1962b769bL,0xc5ba79d9f3f06L,0xfe70b111834feL,0x55de0c3d474bcL,
        0x0ff3146e61814L },
      { 0x4292fe9fda5a1L,0x0c29e2297690bL,0xa2df711100d54L,0x2117041186a3aL,
        0x0cfd8a211f3bcL } },
    /* 187 */
    { { 0xa164ca4e1e3f9L,0x4c5076c4ecabaL,0x97154250ffc5dL,0xd3588d6a76462L,
        0x0d50913ead9ecL },
      { 0x841d137f9e5baL,0xfca756c925a39L,0x35855ad6a90abL,0xe210d29c4f843L,
        0x03a8a3ffe90beL } },
    /* 188 */
    { { 0x29ea282775465L,0x6505de46b0205L,0xfe0203d96bd39L,0xe1dceafdf7576L,
        0x0033709f7b849L },
      { 0x0f2627440bc88L,0xda562bda86d99L,0xb3ab66419fd98L,0xd54c6f6090801L,
        0x0e39bc8f9ee05L } },
    /* 189 */
    { { 0x3d7d0b7fee211L,0x77cc72f995ba6L,0xdf5863de5cfd6L,0x36195e64ab103L,
        0x02e6ad6bddc86L },
      { 0xe115fdeffbe49L,0xcdbb1c3c09f91L,0xbe68cfd154edfL,0xc1ec5fbc8d3b0L,
        0x0dc5630bcb13bL } },
    /* 190 */
    { { 0x93624a9924c34L,0xd72e11428f85fL,0x7f9defd8478bfL,0xf9938149f8574L,
        0x00610508bf509L },
      { 0xebe1f513724eaL,0xa1725c8b24419L,0x72bddfbcff020L,0x103894f36584aL,
        0x0aec05fd5bbecL } },
    /* 191 */
    { { 0xcb1709b77bf82L,0x31babca0c3ebfL,0xd409ac7191478L,0x811233fee22ddL,
        0x0c370cff2511fL },
      { 0x3d2984151c5beL,0x8b2ef5ec6fe02L,0xa09fbcbf1097eL,0x18997907a2bd3L,
        0x07e8f0a83bbfaL } },
    /* 192 */
    { { 0xf2cf4da638608L,0x97e7b68ac0cc2L,0xb95ff63b21443L,0x69177f18bf77dL,
        0x0d0bf3e2a3984L },
      { 0x5e86ea7315affL,0x522f3bf9e5410L,0x235119965a0a5L,0xd33a3109f61c9L,
        0x0f0119421c464L } },
    /* 193 */
    { { 0x330e56fb23d10L,0xdb8ea63c77051L,0x9cbfade96026eL,0x8b97f3541172eL,
        0x0ea56376a873cL },
      { 0x0793d44d8110bL,0xecc6beed1d7f4L,0x5b721c40779b1L,0xd6666c03806efL,
        0x0d2827a004203L } },
    /* 194 */
    { { 0xeca283c0f3250L,0x6d0fa8aef9e63L,0x8c00b3cb430c9L,0x45f9c9b9cb9f6L,
        0x0efba8043c386L },
      { 0xe077b13d1e454L,0xd5d2ee51afbe5L,0xc3aa41b994033L,0xb2463790fdae3L,
        0x066714c6e6458L } },
    /* 195 */
    { { 0x9f742924fb9f6L,0x83ec8a9cb88eeL,0x0a4f49bac3699L,0x001704285109bL,
        0x0ca5a01f04c55L },
      { 0xd0e516442c569L,0x59207a07e4c36L,0xbc85b18c58b30L,0x90b3a9755fd73L,
        0x0da0e7c16cc21L } },
    /* 196 */
    { { 0x13cf6d0bf8406L,0x600af68e16c1bL,0x39ca65648d0f3L,0xa48f1c0547188L,
        0x00ae2237a5a41L },
      { 0xc679711f0d902L,0xd1419ea87cefdL,0xf0677cf13ac5bL,0xd453e069d8cd6L,
        0x042b06a0b3016L } },
    /* 197 */
    { { 0x27c886f4e1f14L,0x250ace79d8db4L,0x8c06c520b5ab2L,0x7cd96326177fdL,
        0x099a08f0231c3L },
      { 0xd31ab13aa5906L,0x594dd755b0a81L,0xc8da586001f47L,0x4d258b56793f9L,
        0x0b99c3583cec6L } },
    /* 198 */
    { { 0x184fa6ae869ddL,0xf644d4becbfddL,0x0bb9801a3bf5fL,0x79acf1763825aL,
        0x0ca93f5abfabfL },
      { 0xdfd230ab2c9c7L,0x572e90ea27ba7L,0x7bc97d5464308L,0x8297969231733L,
        0x0955dca021c2bL } },
    /* 199 */
    { { 0x8f40eb2e176c2L,0xe1074758c0ccbL,0x2422f90384a64L,0xe31a62cc8b9bdL,
        0x00462a7798d32L },
      { 0xe1ec553aa56f7L,0xba67bcf05d683L,0x09ea3bfb40bb0L,0x8b0212f21d32bL,
        0x07b5c0a3c9bb5L } },
    /* 200 */
    { { 0xb288e19486bf4L,0x78221d922e7f6L,0xc3358f740ba61L,0x0105d1bef20ddL,
        0x0ebea60f6a373L },
      { 0x79c281762e27fL,0xc539fa2505eebL,0x487bd907659eaL,0x7c5bf495d6024L,
        0x07b6d4af5ff79L } },
    /* 201 */
    { { 0x2cbf8bacaa0ebL,0x98796b8656220L,0x1e01a8a84547eL,0x78eeb66b87a98L,
        0x02755125c933dL },
      { 0x555d4ed33f8cbL,0xade2e677f8684L,0x1a1e9fff1de0cL,0xd35f0ee5ad535L,
        0x0b34315b3f98aL } },
    /* 202 */
    { { 0x4eb13131cd75dL,0x35cb0e3be27a6L,0x399ddf391f74fL,0xe5a0e41450032L,
        0x0371b86710dffL },
      { 0xc13f4682d0f80L,0xbca5dbd72e769L,0xb9a531c24381aL,0x0abde21a333cdL,
        0x0aeddc99c73f6L } },
    /* 203 */
    { { 0x49e69b5f2259cL,0x16044a64135cfL,0x5d0a46eb04986L,0xda21510e24515L,
        0x0d83c7ca16e27L },
      { 0xde6d2635891b5L,0x889ebf310207bL,0xc069792df5187L,0x20140a99d5208L,
        0x047202f65cdf9L } },
    /* 204 */
    { { 0x47bff2f443a32L,0x64d8e7a6c0cdbL,0x2a9e45d9023bcL,0x37dcf6b48ca56L,
        0x03ad3dfcefd77L },
      { 0x2fced4b805be2L,0xceeb1b5ad7378L,0x059b7363c062eL,0x46ae3f59fe860L,
        0x0f7cedd0ba36cL } },
    /* 205 */
    { { 0x5e367433b78c5L,0x079ff6a006bb1L,0x5bc7d71a23719L,0xc0908f3d622d1L,
        0x0525c2ed4fa1fL },
      { 0x3073ae68d4b0fL,0xc210fe195993aL,0x47ac5a5df19b8L,0xae1128faba36eL,
        0x02da6d62b18a7L } },
    /* 206 */
    { { 0x9b3bb5629d133L,0x94ad127129a48L,0x082982ef9f09bL,0xeb9d53b7fedf7L,
        0x0c55733738d2bL },
      { 0xa38e55cb75589L,0xb05f665eef847L,0xe3c259bcb7bbdL,0x5d8c641fdfc9aL,
        0x080e34ca15770L } },
    /* 207 */
    { { 0xc29f6001ef72fL,0x37678789b2609L,0xde1553060ffe0L,0xac3a700ceefcfL,
        0x0981994692aa8L },
      { 0xaa06441ca3125L,0x4ebc0c9a94c39L,0xf8610683e9f50L,0xd6f32c613728fL,
        0x05951fcb4a442L } },
    /* 208 */
    { { 0xb2251b97e8fceL,0xc5ae42fa937e9L,0xa79f665a5d521L,0x18435c73d3e37L,
        0x0929a59161e7cL },
      { 0x733ba2453f77aL,0x84808bd44e308L,0x4b263b220191cL,0x3ac817f9f06c2L,
        0x0fffdcd9a2750L } },
    /* 209 */
    { { 0x45355fa2e3d35L,0xfc2deaba0a978L,0xa11a38a2f9fa6L,0x986682884be4eL,
        0x038ceee09fc77L },
      { 0x38305565550eeL,0x69c2090b6791fL,0xbb97c29037d24L,0xe185612d55895L,
        0x045a8c6a73ffcL } },
    /* 210 */
    { { 0x991af948986b4L,0x4822500ec143eL,0xe7de9230c39d1L,0xf4ded93c272b9L,
        0x0219e13869690L },
      { 0x282bcaa62b42bL,0x9684e8bc91bc0L,0x78144e378d261L,0x3d8a143930f44L,
        0x05ec12735cc91L } },
    /* 211 */
    { { 0x8510f92dd1b0dL,0x34cbc479cc00eL,0xe583ebc8fa556L,0xaf4f6585d80adL,
        0x03500e41cdb09L },
      { 0x917278edc1c6bL,0xb569973edf797L,0x3ac36f2aa6de3L,0xa69703c5e9cd1L,
        0x0c274afcc6c77L } },
    /* 212 */
    { { 0x788ad3c423efcL,0x51b7ff9bf0998L,0xfe82e4e22c6a7L,0x45f97a11b0cd8L,
        0x07538db2b0c8cL },
      { 0xe5fa856d33e22L,0xe3bb0e5708964L,0x57dfa92319d22L,0x0a03c67e4321cL,
        0x0465b5b2efa2eL } },
    /* 213 */
    { { 0x0b2371248e296L,0x34e125ba03af9L,0xb58f21af7e7ffL,0x46a0673bf50e7L,
        0x09613120d2a56L },
      { 0xa3ec535fa20a4L,0x10815b674fed2L,0x917c28cffc2f5L,0x0143217b49a80L,
        0x05febff8d63e9L } },
    /* 214 */
    { { 0x0bad9883048a7L,0x6fde2fb311e18L,0x2f10918edf0d7L,0x4056f22f60ff4L,
        0x0d9a441c6017eL },
      { 0xb00eb4c2ad962L,0x8e9ccf4c871b5L,0x5f8f97f0e301dL,0xe478557f614d4L,
        0x06cc18f2ee0f1L } },
    /* 215 */
    { { 0xc01d7f78b96abL,0xebb47e0f8e48cL,0xffb8a4b1ea8bdL,0x8be4adca92ffeL,
        0x0e998d32e7743L },
      { 0x42eb0d4e6087eL,0x556b241876099L,0xcbc1c483fbc22L,0xe76daa2ec237aL,
        0x09aecd9305732L } },
    /* 216 */
    { { 0x7d9b8958b5d43L,0x98e1eb773b566L,0xf548b8607bf18L,0xb46d851a6cd8bL,
        0x0242d842242d6L },
      { 0xba08d7b655c2fL,0x0dcdf7c978d50L,0x06b780f227891L,0x18739d5bfd7b3L,
        0x06ca437e06e30L } },
    /* 217 */
    { { 0x265ccf9feae4eL,0x75997592a0d7cL,0x86249e4bdd4bdL,0x6028518ae1d2eL,
        0x05909fa1bccb0L },
      { 0xf96595746eb81L,0x93dc812fff7a2L,0x0abaf4f409d29L,0xfc8f031ad114bL,
        0x0e0a7ecede531L } },
    /* 218 */
    { { 0x0de76201217ccL,0x60553cec6edd2L,0xf672846c9a48cL,0x93dfbde5f1dfcL,
        0x0957ce1060036L },
      { 0x92916067c0809L,0xdc03a61c6f025L,0xe8aa5272bcf52L,0x4b118acdfba67L,
        0x0dad8f454b728L } },
    /* 219 */
    { { 0xf3af86aa83bd4L,0x0f8338a645442L,0x690dd50415a0eL,0x26f087689c929L,
        0x07a127cc08628L },
      { 0x90cb193e33b5aL,0x9fab75c410482L,0x0a845c4124d39L,0xc15a1653bdaceL,
        0x02cd1819672ceL } },
    /* 220 */
    { { 0x023c9676a8a56L,0x9c78d282d58f4L,0xc6d6b1c0c90e9L,0xe402e4bea5a6fL,
        0x06cf1b326a89cL },
      { 0xb1dd21046702dL,0xca252ac152066L,0x24182b65fb766L,0x042c6c678ab5dL,
        0x09fc957468b18L } },
    /* 221 */
    { { 0xfcb21387f9611L,0x0788404b4349eL,0xc7526c6ff2d25L,0x6a7355590cd91L,
        0x090a22fc358e8L },
      { 0xbdc009ce2f640L,0x7104d6346a6f7L,0x07d181c92fbaeL,0xde9e3bffa7bc9L,
        0x06b54f6c09268L } },
    /* 222 */
    { { 0xe2d45f91e135dL,0x8947f90edaf96L,0xb73b22954b7f8L,0x1b78336da15dfL,
        0x04d971d020d21L },
      { 0x4c3fc50ff0147L,0x5c86c808cc197L,0xc112d671b1450L,0x31fece66ab026L,
        0x069fafa320c02L } },
    /* 223 */
    { { 0x5195605a94617L,0x980c5f7fee8d8L,0x07711f8be07ecL,0xb814e0ccb0829L,
        0x0c6709cbe3b82L },
      { 0x1bae0df8014a0L,0xb20b547f763daL,0x4a0cc363f78beL,0x7ce198d0b7fd9L,
        0x0b87de6512b2eL } },
    /* 224 */
    { { 0x41222c3219f63L,0xdb4a84763633aL,0x82146e7070730L,0x808849f5cdda4L,
        0x00f3b01a28f7eL },
      { 0xd3c7024ed5675L,0x8fd12ebd84d50L,0x6e5ebd67e5657L,0x90bfae574c6a3L,
        0x03a6a70043114L } },
    /* 225 */
    { { 0x7397e9dc3afa7L,0xaaf1475d2b94eL,0xb1ad3e04a2bf9L,0xe504c8b14f38bL,
        0x065657f7c3493L },
      { 0x2a58d4162798fL,0x8f47f1f764334L,0xc10275a446a20L,0x97a011795deb3L,
        0x062e54572270cL } },
    /* 226 */
    { { 0x537c03fd3001aL,0x3695687faa199L,0xed75bf6292d87L,0xe56363e199580L,
        0x0fad9dbb037bbL },
      { 0x248816330d6f7L,0x0a7ac23a2c8a3L,0xc4e295d03b5f1L,0x2f193a939dbcbL,
        0x0a3e6119ab1b1L } },
    /* 227 */
    { { 0x7cecdb42823a4L,0x6873f43db3fb6L,0x2f1c5fa26ecf0L,0x5042fb86e1085L,
        0x074ba5c89b818L },
      { 0x584288c74b8afL,0x67a1dbf80aa5fL,0x23854cb33716fL,0xcaca172190af2L,
        0x0bffbbbc4676cL } },
    /* 228 */
    { { 0x2064ee28b90c5L,0x97f79d0be9f66L,0x6becae0563d7eL,0xe3de34330aca5L,
        0x07c64d2beb6b1L },
      { 0x53abe31b53678L,0x9f650da6098dcL,0x6f66c1834608aL,0x6c4f4f1b089c1L,
        0x0d0a9d4cabf5cL } },
    /* 229 */
    { { 0x31e858dd922a9L,0xac8691bd151f6L,0x8860f68a5394eL,0x34bdd77571b3cL,
        0x006bad558e7d2L },
      { 0x6272769d6c786L,0x851dd44649299L,0x03038745f02f3L,0x67dbf0b87128bL,
        0x01184eb38260fL } },
    /* 230 */
    { { 0xc2176f646a2d8L,0x2dfcaf9f984fbL,0x398fd97b59a9dL,0x0bdd63d4394beL,
        0x0026ff9bc9448L },
      { 0xb2a85b25eb68fL,0xab1ed33abc31cL,0xc5042873700d8L,0x8624653c3e89cL,
        0x0f81ba865f1f7L } },
    /* 231 */
    { { 0xeb2d4ec2b7ab7L,0x765a60f91e19aL,0x7a33ad4fae73eL,0x022d59ebf10deL,
        0x0731217a1dfafL },
      { 0xeb3423e5c73d5L,0x281242033344fL,0xa0632637b46a6L,0xe3a88dbf2725cL,
        0x02f19658b9ceeL } },
    /* 232 */
    { { 0xeeb8bee1aa4efL,0xdb53f8bc251b0L,0xbe31aa5881f09L,0x079ede19ed0feL,
        0x0c1205040b421L },
      { 0xe613d7f9fbb19L,0x3f4c02f1ae6abL,0xc78a4aa480eb3L,0xc59f98272198bL,
        0x073bd74b90060L } },
    /* 233 */
    { { 0x7d0f0b7f909a1L,0x177e4c5a4826fL,0x8442ea1ffc76bL,0xad3b793ea04b8L,
        0x0e389c45d3936L },
      { 0x076b6843ffd3cL,0xec43e56892cefL,0xad106e5364ac1L,0x86acbfc58bb0dL,
        0x0aed22ac264b8L } },
    /* 234 */
    { { 0x334cc869ae3ddL,0x4398110baee31L,0xb8dd6cc52b641L,0xd12c256fe087bL,
        0x029f73d4c519dL },
      { 0xce3d3e2b5be53L,0xeebd5f83443feL,0x10be10155687bL,0x6eff257f64560L,
        0x038390f01b9abL } },
    /* 235 */
    { { 0xae41b0cdf4b26L,0x0a7e774fa6d67L,0x5d979c584236cL,0xd2dcbbdc69a09L,
        0x0d5bc73583605L },
      { 0x84dd379a77475L,0x5a02a480f7de3L,0xbeeea569f094fL,0x58ba2e77bf030L,
        0x0a6a6adcb8651L } },
    /* 236 */
    { { 0x7c70d155cbb33L,0xe69ea44142d7dL,0xc91a3d747823aL,0x2c3a47e9c5addL,
        0x05ce9047c7531L },
      { 0x98cc514696568L,0x99641ab64470eL,0x1dafe319a2efcL,0xb71f47efa05a2L,
        0x02cefaab25ac5L } },
    /* 237 */
    { { 0xdb2047bccf3caL,0x5277e8fa88b12L,0x24a58ae15dfedL,0x8bc9e981a6508L,
        0x0e47a22d5b862L },
      { 0x65f01688432d8L,0xbbedacb523b79L,0xa53ba8ecc3015L,0x6f3b4d8c847e8L,
        0x019601827beeaL } },
    /* 238 */
    { { 0x323281feb5071L,0x2df54a0cf7fffL,0x38f89bfd16cd0L,0xd3b8eb6f98ed1L,
        0x0531647157ff7L },
      { 0x104efc992b998L,0xb23b19571e01dL,0xb93dc125a7c4cL,0x4891a872e7375L,
        0x022e7a9db7495L } },
    /* 239 */
    { { 0x198e80283ccdfL,0xb9f78cd2c69f6L,0x86042948b0eaeL,0x69340d9fecea7L,
        0x0d0ac75fee9b2L },
      { 0xccb4a36fdf44fL,0x2390828426ba2L,0x31013ac828b51L,0x41761b76b83c6L,
        0x0f8d1bf636987L } },
    /* 240 */
    { { 0x0150533c6d17cL,0x600c76fbcb1e6L,0x0604f65ec3d5bL,0x050b23ebbee10L,
        0x012959cbc5644L },
      { 0x8df49f023a933L,0x89920421e2ea5L,0x097920058b9ccL,0x622af2b13f1bcL,
        0x01aac8e329af1L } },
    /* 241 */
    { { 0x3c86754e44471L,0x9cd60f959e56dL,0x800aa6d16cfa7L,0x5cb5e1a0a9b33L,
        0x00347857363cfL },
      { 0x3f256281c0625L,0xd5c6e710c45d9L,0xfa7caf84eda2eL,0x2e3b76d998461L,
        0x05fbd4e1b1b6cL } },
    /* 242 */
    { { 0xe9c0e2628bd27L,0xc96f8d8926deeL,0xa6c67025ed1edL,0x97e84bbc7968bL,
        0x071c11b59c47bL },
      { 0xaf35cd93fdd98L,0xe7ad98d80f269L,0xa878b4d250f63L,0x0c5d9640ec914L,
        0x0d994d23b05ebL } },
    /* 243 */
    { { 0x9852ce2eb6f86L,0x0faff1aad5034L,0x9a9359db7e362L,0xe0760f8a633cbL,
        0x0c89a70270b99L },
      { 0x553236661ebadL,0x68da88f0ba185L,0xb0f4d3785ec6eL,0x8616a8542f32dL,
        0x004e03ee082eeL } },
    /* 244 */
    { { 0x63c2686460df0L,0xcfefd5e793aa4L,0x409d3d908b775L,0x958d14e179758L,
        0x0e68e9468737aL },
      { 0x9e649ca015c8bL,0x75a35c7b2a651L,0xab343f8d6310fL,0x7af7f1faec99cL,
        0x01b23979c32f7L } },
    /* 245 */
    { { 0x6d4202b5e0c0cL,0xd9528c897f352L,0x6bfcd0299db2bL,0xcd27b64d880d2L,
        0x0dd78c263ef2eL },
      { 0x3507895822826L,0xe5acf21c03a0bL,0xbe7e6015ea1c0L,0x15b43d5b1d01dL,
        0x0139c073f8d92L } },
    /* 246 */
    { { 0x222c7670e8ca9L,0x76a4b03512bd9L,0x946fc83381bd9L,0x316d9c5d3aca6L,
        0x05a13dc71a6f3L },
      { 0xf23640f25e97bL,0x0b6fe55b35bcbL,0x5cdaacedd741aL,0x1b82748a77078L,
        0x002d9d8147721L } },
    /* 247 */
    { { 0x514ee83eca061L,0x7cca7faa4c766L,0x850fc7d38df09L,0x986b88886165cL,
        0x05f4fcb7a7c80L },
      { 0x498cbc8612b88L,0x4ad0029d3958cL,0x1118e41a26ed7L,0xe5f4ed010aa41L,
        0x001239ca90808L } },
    /* 248 */
    { { 0x1551b771f2025L,0xf01dad71878b4L,0x4d1d1878931e6L,0xec83633b0ba58L,
        0x0801760261fb4L },
      { 0x740c3a3fed11fL,0xa10e31c6ca0a1L,0x1079e1b49dcadL,0xedf5b96f0bd6dL,
        0x0d325b1ba5035L } },
    /* 249 */
    { { 0xca10c45614b0cL,0x1b0f520a059ecL,0x96af3b365d4b7L,0xc25bc875ce5b4L,
        0x01993daac089eL },
      { 0x7531e9b44405fL,0x16e83270556c2L,0x6a45d437166a0L,0x31a0ba7ed0556L,
        0x01da832bb3d35L } },
    /* 250 */
    { { 0xe0e7ab92d1d40L,0x7a2c66c63b8b4L,0x735ec72869241L,0x8949cf340c588L,
        0x0b5856961b5f7L },
      { 0xa0b91b1715164L,0xc7bd2dabfad10L,0x94db101864c17L,0x8493480dd9f7aL,
        0x0a7dff8828f03L } },
    /* 251 */
    { { 0xc5bbdedf73f04L,0x08724545d9d39L,0x4f7306a3a8feaL,0xf241ca6835877L,
        0x07094aeb4b97eL },
      { 0x23559d72ebf79L,0x1dfa95a003066L,0x716a892de24a9L,0x453f34e73d4eaL,
        0x0f0477a2cddc9L } },
    /* 252 */
    { { 0x2471c1fb80211L,0xb5629f78eda03L,0x4d3483847c322L,0xc98492a62b56bL,
        0x02400e4248e88L },
      { 0x24289d3dbc9d8L,0xa674a08df6af9L,0xa095105257c14L,0xd383959020166L,
        0x0f5ac54528bfdL } },
    /* 253 */
    { { 0x7e5ba42980d58L,0x6175657f91fb3L,0x483bd4d2c031eL,0x2fbbf9e45e924L,
        0x043b13ea66413L },
      { 0x081a4d6665e37L,0xefa715ddd6ddfL,0xb03952893f75dL,0xeab04c76d8fa2L,
        0x04ee3a221839aL } },
    /* 254 */
    { { 0xf049d3a6ef7baL,0xd5f217b13497fL,0x50cc2abbcc779L,0xcbefea1533708L,
        0x093967c32ea78L },
      { 0x2faa2c18605eaL,0x6f5e16939cdb7L,0xae0e4f8ddee2fL,0x580ff53bf342eL,
        0x014e25972fddcL } },
    /* 255 */
    { { 0x4dcd8950d7f94L,0x663ea3b4d6085L,0xf8b5b2f07006aL,0x2f4aa91fa63fdL,
        0x0aad30b11060cL },
      { 0x0c0164254ba5dL,0xaac5847aea1a3L,0x49eab3c31450eL,0x588841c6740cdL,
        0x0bcc984efb97dL } },
};

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^32, ...
 * Pre-generated: products of all combinations of above.
 * 8 doubles and adds (with qz=1)
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_sm2_5(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_5(r, &p256_sm2_base, p256_sm2_table,
                                      k, map, ct, heap);
}

#endif

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km    Scalar to multiply by.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_base_sm2_256(const mp_int* km, ecc_point* r, int map, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* point = NULL;
    sp_digit* k = NULL;
#else
    sp_point_256  point[1];
    sp_digit k[5];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 5, km);

            err = sp_256_ecc_mulmod_base_sm2_5(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_5(point, r);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Multiply the base point of P256 by the scalar, add point a and return
 * the result. If map is true then convert result to affine coordinates.
 *
 * km      Scalar to multiply by.
 * am      Point to add to scalar multiply result.
 * inMont  Point to add is in montgomery form.
 * r       Resulting point.
 * map     Indicates whether to convert result to affine.
 * heap    Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_base_add_sm2_256(const mp_int* km, const ecc_point* am,
        int inMont, ecc_point* r, int map, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* point = NULL;
    sp_digit* k = NULL;
#else
    sp_point_256 point[2];
    sp_digit k[5 + 5 * 2 * 6];
#endif
    sp_point_256* addP = NULL;
    sp_digit* tmp = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(
            sizeof(sp_digit) * (5 + 5 * 2 * 6),
            heap, DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 5;

        sp_256_from_mp(k, 5, km);
        sp_256_point_from_ecc_point_5(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_5(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_5(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_5(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_5(point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_5(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_5(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_5(point, r);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                                        defined(HAVE_ECC_VERIFY)
#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN | HAVE_ECC_SIGN | HAVE_ECC_VERIFY */
/* Add 1 to a. (a = a + 1)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_add_one_sm2_5(sp_digit* a)
{
    a[0]++;
    sp_256_norm_5(a);
}

/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_256_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 44U) {
            r[j] &= 0xfffffffffffffL;
            s = 52U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Generates a scalar that is in the range 1..order-1.
 *
 * rng  Random number generator.
 * k    Scalar value.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
static int sp_256_ecc_gen_k_sm2_5(WC_RNG* rng, sp_digit* k)
{
#ifndef WC_NO_RNG
    int err;
    byte buf[32];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_256_from_bin(k, 5, buf, (int)sizeof(buf));
            if (sp_256_cmp_sm2_5(k, p256_sm2_order2) <= 0) {
                sp_256_add_one_sm2_5(k);
                break;
            }
        }
    }
    while (err == 0);

    return err;
#else
    (void)rng;
    (void)k;
    return NOT_COMPILED_IN;
#endif
}

/* Makes a random EC key pair.
 *
 * rng   Random number generator.
 * priv  Generated private value.
 * pub   Generated public point.
 * heap  Heap to use for allocation.
 * returns ECC_INF_E when the point does not have the correct order, RNG
 * failures, MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_make_key_sm2_256(WC_RNG* rng, mp_int* priv, ecc_point* pub, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* point = NULL;
    sp_digit* k = NULL;
#else
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256 point[2];
    #else
    sp_point_256 point[1];
    #endif
    sp_digit k[5];
#endif
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256* infinity = NULL;
#endif
    int err = MP_OKAY;


    (void)heap;

#ifdef WOLFSSL_SP_SMALL_STACK
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap, DYNAMIC_TYPE_ECC);
    #else
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap, DYNAMIC_TYPE_ECC);
    #endif
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
        infinity = point + 1;
    #endif

        err = sp_256_ecc_gen_k_sm2_5(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_5(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_5(infinity, point, p256_sm2_order, 1, 1, NULL);
    }
    if (err == MP_OKAY) {
        if (sp_256_iszero_5(point->x) || sp_256_iszero_5(point->y)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_256_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_5(point, pub);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    /* point is not sensitive, so no need to zeroize */
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_ecc_key_gen_256_ctx {
    int state;
    sp_256_ecc_mulmod_5_ctx mulmod_ctx;
    sp_digit k[5];
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256  point[2];
#else
    sp_point_256 point[1];
#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN */
} sp_ecc_key_gen_256_ctx;

int sp_ecc_make_key_256_nb(sp_ecc_ctx_t* sp_ctx, WC_RNG* rng, mp_int* priv,
    ecc_point* pub, void* heap)
{
    int err = FP_WOULDBLOCK;
    sp_ecc_key_gen_256_ctx* ctx = (sp_ecc_key_gen_256_ctx*)sp_ctx->data;
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256* infinity = ctx->point + 1;
#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN */

    typedef char ctx_size_test[sizeof(sp_ecc_key_gen_256_ctx)
                               >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
        case 0:
            err = sp_256_ecc_gen_k_5(rng, ctx->k);
            if (err == MP_OKAY) {
                err = FP_WOULDBLOCK;
                ctx->state = 1;
            }
            break;
        case 1:
            err = sp_256_ecc_mulmod_base_5_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      ctx->point, ctx->k, 1, 1, heap);
            if (err == MP_OKAY) {
                err = FP_WOULDBLOCK;
            #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
                XMEMSET(&ctx->mulmod_ctx, 0, sizeof(ctx->mulmod_ctx));
                ctx->state = 2;
            #else
                ctx->state = 3;
            #endif
            }
            break;
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
        case 2:
            err = sp_256_ecc_mulmod_5_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      infinity, ctx->point, p256_sm2_order, 1, 1);
            if (err == MP_OKAY) {
                if (sp_256_iszero_5(ctx->point->x) ||
                    sp_256_iszero_5(ctx->point->y)) {
                    err = ECC_INF_E;
                }
                else {
                    err = FP_WOULDBLOCK;
                    ctx->state = 3;
                }
            }
            break;
    #endif /* WOLFSSL_VALIDATE_ECC_KEYGEN */
        case 3:
            err = sp_256_to_mp(ctx->k, priv);
            if (err == MP_OKAY) {
                err = sp_256_point_to_ecc_point_5(ctx->point, pub);
            }
            break;
    }

    if (err != FP_WOULDBLOCK) {
        XMEMSET(ctx, 0, sizeof(sp_ecc_key_gen_256_ctx));
    }

    return err;
}
#endif /* WOLFSSL_SP_NONBLOCK */

#ifdef HAVE_ECC_DHE
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 32
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_256_to_bin_5(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<4; i++) {
        r[i+1] += r[i] >> 52;
        r[i] &= 0xfffffffffffffL;
    }
    j = 263 / 8 - 1;
    a[j] = 0;
    for (i=0; i<5 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 52) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 52);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

/* Multiply the point by the scalar and serialize the X ordinate.
 * The number is 0 padded to maximum size on output.
 *
 * priv    Scalar to multiply the point by.
 * pub     Point to multiply.
 * out     Buffer to hold X ordinate.
 * outLen  On entry, size of the buffer in bytes.
 *         On exit, length of data in buffer in bytes.
 * heap    Heap to use for allocation.
 * returns BUFFER_E if the buffer is to small for output size,
 * MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_secret_gen_sm2_256(const mp_int* priv, const ecc_point* pub, byte* out,
                          word32* outLen, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* point = NULL;
    sp_digit* k = NULL;
#else
    sp_point_256 point[1];
    sp_digit k[5];
#endif
    int err = MP_OKAY;

    if (*outLen < 32U) {
        err = BUFFER_E;
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
        if (point == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 5, priv);
        sp_256_point_from_ecc_point_5(point, pub);
            err = sp_256_ecc_mulmod_sm2_5(point, point, k, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_256_to_bin_5(point->x, out);
        *outLen = 32;
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_ecc_sec_gen_256_ctx {
    int state;
    union {
        sp_256_ecc_mulmod_5_ctx mulmod_ctx;
    };
    sp_digit k[5];
    sp_point_256 point;
} sp_ecc_sec_gen_256_ctx;

int sp_ecc_secret_gen_256_nb(sp_ecc_ctx_t* sp_ctx, const mp_int* priv,
    const ecc_point* pub, byte* out, word32* outLen, void* heap)
{
    int err = FP_WOULDBLOCK;
    sp_ecc_sec_gen_256_ctx* ctx = (sp_ecc_sec_gen_256_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_ecc_sec_gen_256_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    if (*outLen < 32U) {
        err = BUFFER_E;
    }

    switch (ctx->state) {
        case 0:
            sp_256_from_mp(ctx->k, 5, priv);
            sp_256_point_from_ecc_point_5(&ctx->point, pub);
            ctx->state = 1;
            break;
        case 1:
            err = sp_256_ecc_mulmod_sm2_5_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      &ctx->point, &ctx->point, ctx->k, 1, 1, heap);
            if (err == MP_OKAY) {
                sp_256_to_bin_5(ctx->point.x, out);
                *outLen = 32;
            }
            break;
    }

    if (err == MP_OKAY && ctx->state != 1) {
        err = FP_WOULDBLOCK;
    }
    if (err != FP_WOULDBLOCK) {
        XMEMSET(ctx, 0, sizeof(sp_ecc_sec_gen_256_ctx));
    }

    return err;
}
#endif /* WOLFSSL_SP_NONBLOCK */
#endif /* HAVE_ECC_DHE */

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#ifdef WOLFSSL_SP_SMALL
/* Order-2 for the SM2 P256 curve. */
static const uint64_t p256_sm2_order_minus_2[4] = {
    0x53bbf40939d54121U,0x7203df6b21c6052bU,0xffffffffffffffffU,
    0xfffffffeffffffffU
};
#else
#ifdef HAVE_ECC_SIGN
/* The low half of the order-2 of the SM2 P256 curve. */
static const uint64_t p256_sm2_order_low[2] = {
    0x53bbf40939d54121U,0x7203df6b21c6052bU
};
#endif /* HAVE_ECC_SIGN */
#endif /* WOLFSSL_SP_SMALL */

#ifdef HAVE_ECC_SIGN
/* Multiply two number mod the order of P256 curve. (r = a * b mod order)
 *
 * r  Result of the multiplication.
 * a  First operand of the multiplication.
 * b  Second operand of the multiplication.
 */
static void sp_256_mont_mul_order_sm2_5(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_sm2_5(r, a, b);
    sp_256_mont_reduce_order_sm2_5(r, p256_sm2_order, p256_sm2_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_order_sm2_5(sp_digit* r, const sp_digit* a)
{
    sp_256_sqr_sm2_5(r, a);
    sp_256_mont_reduce_order_sm2_5(r, p256_sm2_order, p256_sm2_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P256 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_n_order_sm2_5(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_256_mont_sqr_order_sm2_5(r, a);
    for (i=1; i<n; i++) {
        sp_256_mont_sqr_order_sm2_5(r, r);
    }
}
#endif /* !WOLFSSL_SP_SMALL */
/* Invert the number, in Montgomery form, modulo the order of the P256 curve.
 * (r = 1 / a mod order)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_256_mont_inv_order_sm2_5(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 5);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_order_sm2_5(t, t);
        if ((p256_sm2_order_minus_2[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_5(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 5U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 5;
    sp_digit* t3 = td + 4 * 5;
    sp_digit* t4 = td + 6 * 5;
    int i;

    /* t4= a^2 */
    sp_256_mont_sqr_order_sm2_5(t4, a);
    /* t = a^3 = t4* a */
    sp_256_mont_mul_order_sm2_5(t, t4, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_order_sm2_5(t2, t, 2);
    /* t4= a^e = t2 * t4 */
    sp_256_mont_mul_order_sm2_5(t4, t2, t4);
    /* t3= a^f = t2 * t */
    sp_256_mont_mul_order_sm2_5(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_256_mont_sqr_n_order_sm2_5(t2, t3, 4);
    /* t4 = a^fe = t2 * t4 */
    sp_256_mont_mul_order_sm2_5(t4, t2, t4);
    /* t = a^ff = t2 * t3 */
    sp_256_mont_mul_order_sm2_5(t, t2, t3);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_order_sm2_5(t2, t, 8);
    /* t4 = a^fffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_5(t4, t2, t4);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_order_sm2_5(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_order_sm2_5(t2, t, 16);
    /* t4= a^fffffffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_5(t4, t2, t4);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_5(t, t2, t);
    /* t2= a^fffffffe00000000 = t4 ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_5(t4, t4, 32);
    /* t4= a^fffffffeffffffff = t4 * t */
    sp_256_mont_mul_order_sm2_5(t4, t4, t);
    /* t2= a^ffffffff00000000 = t ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_5(t2, t, 32);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_5(t, t2, t);
    /* t4= a^fffffffeffffffff0000000000000000 = t4 ^ 2 ^ 64 */
    sp_256_mont_sqr_n_order_sm2_5(t4, t4, 64);
    /* t2= a^fffffffeffffffffffffffffffffffff = t4 * t2 */
    sp_256_mont_mul_order_sm2_5(t2, t4, t);
    /* t2= a^fffffffeffffffffffffffffffffffff7203d */
    for (i=127; i>=108; i--) {
        sp_256_mont_sqr_order_sm2_5(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_5(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df */
    sp_256_mont_sqr_n_order_sm2_5(t2, t2, 4);
    sp_256_mont_mul_order_sm2_5(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bb */
    for (i=103; i>=48; i--) {
        sp_256_mont_sqr_order_sm2_5(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_5(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf */
    sp_256_mont_sqr_n_order_sm2_5(t2, t2, 4);
    sp_256_mont_mul_order_sm2_5(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412 */
    for (i=43; i>=4; i--) {
        sp_256_mont_sqr_order_sm2_5(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_5(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54120 */
    sp_256_mont_sqr_n_order_sm2_5(t2, t2, 4);
    /* r = a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121 */
    sp_256_mont_mul_order_sm2_5(r, t2, a);
#endif /* WOLFSSL_SP_SMALL */
}
#endif /* HAVE_ECC_SIGN */

#endif /* HAVE_ECC_SIGN || HAVE_ECC_VERIFY */
#ifdef HAVE_ECC_SIGN
#ifndef SP_ECC_MAX_SIG_GEN
#define SP_ECC_MAX_SIG_GEN  64
#endif

/* Sign the hash using the private key.
 *
 * hash     Hash to sign.
 * hashLen  Length of the hash data.
 * rng      Random number generator.
 * priv     Private part of key - scalar.
 * rm       First part of result as an mp_int.
 * sm       Sirst part of result as an mp_int.
 * heap     Heap to use for allocation.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
int sp_ecc_sign_sm2_256(const byte* hash, word32 hashLen, WC_RNG* rng,
    const mp_int* priv, mp_int* rm, mp_int* sm, mp_int* km, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
    sp_point_256* point = NULL;
#else
    sp_digit d[4 * 10*5];
    sp_point_256 point[1];
#endif
    sp_digit* e = NULL;
    sp_digit* x = NULL;
    sp_digit* k = NULL;
    sp_digit* r = NULL;
    sp_digit* tmp = NULL;
    sp_digit* s = NULL;
    sp_digit* xInv = NULL;
    int err = MP_OKAY;
    sp_int64 c;
    int i;

    (void)heap;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8 * 2 * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
            DYNAMIC_TYPE_ECC);
        if (point == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        e = d + 0 * 5;
        x = d + 2 * 5;
        k = d + 4 * 5;
        r = d + 6 * 5;
        tmp = d + 8 * 5;
        s = e;
        xInv = x;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_bin(e, 5, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_256_from_mp(x, 5, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_256_ecc_gen_k_sm2_5(rng, k);
        }
        else {
            sp_256_from_mp(k, 5, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
                err = sp_256_ecc_mulmod_base_sm2_5(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = (point->x + e) mod order */
            sp_256_add_sm2_5(r, point->x, e);
            sp_256_norm_5(r);
            c = sp_256_cmp_sm2_5(r, p256_sm2_order);
            sp_256_cond_sub_sm2_5(r, r, p256_sm2_order, 0L - (sp_digit)(c >= 0));
            sp_256_norm_5(r);

            /* Try again if r == 0 */
            if (sp_256_iszero_5(r)) {
                continue;
            }

            /* Try again if r + k == 0 */
            sp_256_add_sm2_5(s, k, r);
            sp_256_norm_5(s);
            c += sp_256_cmp_sm2_5(s, p256_sm2_order);
            sp_256_cond_sub_sm2_5(s, s, p256_sm2_order, 0L - (sp_digit)(c >= 0));
            sp_256_norm_5(s);
            if (sp_256_iszero_5(s)) {
                continue;
            }

            /* Conv x to Montgomery form (mod order) */
                sp_256_mul_sm2_5(x, x, p256_sm2_norm_order);
            err = sp_256_mod_sm2_5(x, x, p256_sm2_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_5(x);

            /* s = k - r * x */
                sp_256_mont_mul_order_sm2_5(s, x, r);
        }
        if (err == MP_OKAY) {
            sp_256_norm_5(s);
            sp_256_sub_sm2_5(s, k, s);
            sp_256_cond_add_sm2_5(s, s, p256_sm2_order, s[4] >> 48);
            sp_256_norm_5(s);

            /* xInv = 1/(x+1) mod order */
            sp_256_add_sm2_5(x, x, p256_sm2_norm_order);
            sp_256_norm_5(x);
            x[4] &= (((sp_digit)1) << 52) - 1;

                sp_256_mont_inv_order_sm2_5(xInv, x, tmp);
            sp_256_norm_5(xInv);

            /* s = s * (x+1)^-1 mod order */
                sp_256_mont_mul_order_sm2_5(s, s, xInv);
            sp_256_norm_5(s);

            c = sp_256_cmp_sm2_5(s, p256_sm2_order);
            sp_256_cond_sub_sm2_5(s, s, p256_sm2_order,
                0L - (sp_digit)(c >= 0));
            sp_256_norm_5(s);

            /* Check that signature is usable. */
            if (sp_256_iszero_5(s) == 0) {
                break;
            }
        }
    }

    if (i == 0) {
        err = RNG_FAILURE_E;
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(r, rm);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(s, sm);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 5);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
    if (point != NULL) {
        XFREE(point, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 4U * 2U * 5U);
#endif

    return err;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
int sp_ecc_verify_sm2_256(const byte* hash, word32 hashLen, const mp_int* pX,
    const mp_int* pY, const mp_int* pZ, const mp_int* rm, const mp_int* sm,
    int* res, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
    sp_point_256* p1 = NULL;
#else
    sp_digit d[8*5 * 7];
    sp_point_256 p1[2];
#endif
    sp_digit* e = NULL;
    sp_digit* r = NULL;
    sp_digit* s = NULL;
    sp_digit* tmp = NULL;
    sp_point_256* p2 = NULL;
    sp_digit carry;
    int err = MP_OKAY;
    int done = 0;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 20 * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        p1 = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
            DYNAMIC_TYPE_ECC);
        if (p1 == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        e   = d + 0 * 5;
        r   = d + 2 * 5;
        s   = d + 4 * 5;
        tmp = d + 6 * 5;
        p2 = p1 + 1;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_mp(r, 5, rm);
        sp_256_from_mp(s, 5, sm);
        sp_256_from_mp(p2->x, 5, pX);
        sp_256_from_mp(p2->y, 5, pY);
        sp_256_from_mp(p2->z, 5, pZ);


        if (sp_256_iszero_5(r) ||
            sp_256_iszero_5(s) ||
            (sp_256_cmp_sm2_5(r, p256_sm2_order) >= 0) ||
            (sp_256_cmp_sm2_5(s, p256_sm2_order) >= 0)) {
            *res = 0;
            done = 1;
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        carry = sp_256_add_sm2_5(e, r, s);
        sp_256_norm_5(e);
        if (carry || sp_256_cmp_sm2_5(e, p256_sm2_order) >= 0) {
            sp_256_sub_sm2_5(e, e, p256_sm2_order);            sp_256_norm_5(e);
        }

        if (sp_256_iszero_5(e)) {
           *res = 0;
           done = 1;
        }
    }
    if ((err == MP_OKAY) && (!done)) {
            err = sp_256_ecc_mulmod_base_sm2_5(p1, s, 0, 0, heap);
    }
    if ((err == MP_OKAY) && (!done)) {
        {
            err = sp_256_ecc_mulmod_sm2_5(p2, p2, e, 0, 0, heap);
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        {
            sp_256_proj_point_add_sm2_5(p1, p1, p2, tmp);
            if (sp_256_iszero_5(p1->z)) {
                if (sp_256_iszero_5(p1->x) && sp_256_iszero_5(p1->y)) {
                    sp_256_proj_point_dbl_sm2_5(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    p1->x[4] = 0;
                    XMEMCPY(p1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
                }
            }
        }

        /* z' = z'.z' */
        sp_256_mont_sqr_sm2_5(p1->z, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        XMEMSET(p1->x + 5, 0, 5U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_5(p1->x, p256_sm2_mod, p256_sm2_mp_mod);
        /* (r - e + n*order).z'.z' mod prime == (s.G + t.Q)->x' */
        /* Load e, subtract from r. */
        sp_256_from_bin(e, 5, hash, (int)hashLen);
        if (sp_256_cmp_sm2_5(r, e) < 0) {
            (void)sp_256_add_sm2_5(r, r, p256_sm2_order);
        }
        sp_256_sub_sm2_5(e, r, e);
        sp_256_norm_5(e);
        /* x' == (r - e).z'.z' mod prime */
        sp_256_mont_mul_sm2_5(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        *res = (int)(sp_256_cmp_sm2_5(p1->x, s) == 0);
        if (*res == 0) {
            carry = sp_256_add_sm2_5(e, e, p256_sm2_order);
            if (!carry && sp_256_cmp_sm2_5(e, p256_sm2_mod) < 0) {
                /* x' == (r - e + order).z'.z' mod prime */
                sp_256_mont_mul_sm2_5(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
                *res = (int)(sp_256_cmp_sm2_5(p1->x, s) == 0);
            }
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL)
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    if (p1 != NULL)
        XFREE(p1, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_CHECK_KEY
/* Check that the x and y ordinates are a valid point on the curve.
 *
 * point  EC point.
 * heap   Heap to use if dynamically allocating.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */
static int sp_256_ecc_is_point_sm2_5(const sp_point_256* point,
    void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t1 = NULL;
#else
    sp_digit t1[5 * 4];
#endif
    sp_digit* t2 = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t1 = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5 * 4, heap, DYNAMIC_TYPE_ECC);
    if (t1 == NULL)
        err = MEMORY_E;
#endif
    (void)heap;

    if (err == MP_OKAY) {
        t2 = t1 + 2 * 5;

        /* y^2 - x^3 - a.x = b */
        sp_256_sqr_sm2_5(t1, point->y);
        (void)sp_256_mod_sm2_5(t1, t1, p256_sm2_mod);
        sp_256_sqr_sm2_5(t2, point->x);
        (void)sp_256_mod_sm2_5(t2, t2, p256_sm2_mod);
        sp_256_mul_sm2_5(t2, t2, point->x);
        (void)sp_256_mod_sm2_5(t2, t2, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(t1, t1, t2, p256_sm2_mod);

        /* y^2 - x^3 + 3.x = b, when a = -3  */
        sp_256_mont_add_sm2_5(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_5(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_5(t1, t1, point->x, p256_sm2_mod);


        if (sp_256_cmp_sm2_5(t1, p256_sm2_b) != 0) {
            err = MP_VAL;
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(t1, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Check that the x and y ordinates are a valid point on the curve.
 *
 * pX  X ordinate of EC point.
 * pY  Y ordinate of EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */
int sp_ecc_is_point_sm2_256(const mp_int* pX, const mp_int* pY)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* pub = NULL;
#else
    sp_point_256 pub[1];
#endif
    const byte one[1] = { 1 };
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    pub = (sp_point_256*)XMALLOC(sizeof(sp_point_256), NULL,
                                       DYNAMIC_TYPE_ECC);
    if (pub == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(pub->x, 5, pX);
        sp_256_from_mp(pub->y, 5, pY);
        sp_256_from_bin(pub->z, 5, one, (int)sizeof(one));

        err = sp_256_ecc_is_point_sm2_5(pub, NULL);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(pub, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Check that the private scalar generates the EC point (px, py), the point is
 * on the curve and the point has the correct order.
 *
 * pX     X ordinate of EC point.
 * pY     Y ordinate of EC point.
 * privm  Private scalar that generates EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve, ECC_INF_E if the point does not have the correct order,
 * ECC_PRIV_KEY_E when the private scalar doesn't generate the EC point and
 * MP_OKAY otherwise.
 */
int sp_ecc_check_key_sm2_256(const mp_int* pX, const mp_int* pY,
    const mp_int* privm, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* priv = NULL;
    sp_point_256* pub = NULL;
#else
    sp_digit priv[5];
    sp_point_256 pub[2];
#endif
    sp_point_256* p = NULL;
    const byte one[1] = { 1 };
    int err = MP_OKAY;


    /* Quick check the lengs of public key ordinates and private key are in
     * range. Proper check later.
     */
    if (((mp_count_bits(pX) > 256) ||
        (mp_count_bits(pY) > 256) ||
        ((privm != NULL) && (mp_count_bits(privm) > 256)))) {
        err = ECC_OUT_OF_RANGE_E;
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        pub = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                           DYNAMIC_TYPE_ECC);
        if (pub == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY && privm) {
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                                  DYNAMIC_TYPE_ECC);
        if (priv == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        p = pub + 1;

        sp_256_from_mp(pub->x, 5, pX);
        sp_256_from_mp(pub->y, 5, pY);
        sp_256_from_bin(pub->z, 5, one, (int)sizeof(one));
        if (privm)
            sp_256_from_mp(priv, 5, privm);

        /* Check point at infinitiy. */
        if ((sp_256_iszero_5(pub->x) != 0) &&
            (sp_256_iszero_5(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    /* Check range of X and Y */
    if ((err == MP_OKAY) &&
            ((sp_256_cmp_sm2_5(pub->x, p256_sm2_mod) >= 0) ||
             (sp_256_cmp_sm2_5(pub->y, p256_sm2_mod) >= 0))) {
        err = ECC_OUT_OF_RANGE_E;
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_256_ecc_is_point_sm2_5(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
            err = sp_256_ecc_mulmod_sm2_5(p, pub, p256_sm2_order, 1, 1, heap);
    }
    /* Check result is infinity */
    if ((err == MP_OKAY) && ((sp_256_iszero_5(p->x) == 0) ||
                             (sp_256_iszero_5(p->y) == 0))) {
        err = ECC_INF_E;
    }

    if (privm) {
        if (err == MP_OKAY) {
            /* Base * private = point */
                err = sp_256_ecc_mulmod_base_sm2_5(p, priv, 1, 1, heap);
        }
        /* Check result is public key */
        if ((err == MP_OKAY) &&
                ((sp_256_cmp_sm2_5(p->x, pub->x) != 0) ||
                 (sp_256_cmp_sm2_5(p->y, pub->y) != 0))) {
            err = ECC_PRIV_KEY_E;
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(pub, heap, DYNAMIC_TYPE_ECC);
    XFREE(priv, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif
#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
/* Add two projective EC points together.
 * (pX, pY, pZ) + (qX, qY, qZ) = (rX, rY, rZ)
 *
 * pX   First EC point's X ordinate.
 * pY   First EC point's Y ordinate.
 * pZ   First EC point's Z ordinate.
 * qX   Second EC point's X ordinate.
 * qY   Second EC point's Y ordinate.
 * qZ   Second EC point's Z ordinate.
 * rX   Resultant EC point's X ordinate.
 * rY   Resultant EC point's Y ordinate.
 * rZ   Resultant EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_proj_add_point_sm2_256(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* qX, mp_int* qY, mp_int* qZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp = NULL;
    sp_point_256* p = NULL;
#else
    sp_digit tmp[2 * 5 * 6];
    sp_point_256 p[2];
#endif
    sp_point_256* q = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, NULL,
                                         DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 6, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        q = p + 1;

        sp_256_from_mp(p->x, 5, pX);
        sp_256_from_mp(p->y, 5, pY);
        sp_256_from_mp(p->z, 5, pZ);
        sp_256_from_mp(q->x, 5, qX);
        sp_256_from_mp(q->y, 5, qY);
        sp_256_from_mp(q->z, 5, qZ);
        p->infinity = sp_256_iszero_5(p->x) &
                      sp_256_iszero_5(p->y);
        q->infinity = sp_256_iszero_5(q->x) &
                      sp_256_iszero_5(q->y);

            sp_256_proj_point_add_sm2_5(p, p, q, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->x, rX);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, rY);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, rZ);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    XFREE(p, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Double a projective EC point.
 * (pX, pY, pZ) + (pX, pY, pZ) = (rX, rY, rZ)
 *
 * pX   EC point's X ordinate.
 * pY   EC point's Y ordinate.
 * pZ   EC point's Z ordinate.
 * rX   Resultant EC point's X ordinate.
 * rY   Resultant EC point's Y ordinate.
 * rZ   Resultant EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_proj_dbl_point_sm2_256(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp = NULL;
    sp_point_256* p = NULL;
#else
    sp_digit tmp[2 * 5 * 2];
    sp_point_256 p[1];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256), NULL,
                                         DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 2, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 5, pX);
        sp_256_from_mp(p->y, 5, pY);
        sp_256_from_mp(p->z, 5, pZ);
        p->infinity = sp_256_iszero_5(p->x) &
                      sp_256_iszero_5(p->y);

            sp_256_proj_point_dbl_sm2_5(p, p, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->x, rX);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, rY);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, rZ);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    XFREE(p, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Map a projective EC point to affine in place.
 * pZ will be one.
 *
 * pX   EC point's X ordinate.
 * pY   EC point's Y ordinate.
 * pZ   EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_map_sm2_256(mp_int* pX, mp_int* pY, mp_int* pZ)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp = NULL;
    sp_point_256* p = NULL;
#else
    sp_digit tmp[2 * 5 * 5];
    sp_point_256 p[1];
#endif
    int err = MP_OKAY;


#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256), NULL,
                                         DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 5, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 5, pX);
        sp_256_from_mp(p->y, 5, pY);
        sp_256_from_mp(p->z, 5, pZ);
        p->infinity = sp_256_iszero_5(p->x) &
                      sp_256_iszero_5(p->y);

            sp_256_map_sm2_5(p, p, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->x, pX);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, pY);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, pZ);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    XFREE(p, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif /* WOLFSSL_PUBLIC_ECC_ADD_DBL */
#ifdef HAVE_COMP_KEY
/* Square root power for the P256 curve. */
static const uint64_t p256_sm2_sqrt_power[4] = {
    0x4000000000000000,0xffffffffc0000000,0xffffffffffffffff,
    0x3fffffffbfffffff
};

/* Find the square root of a number mod the prime of the curve.
 *
 * y  The number to operate on and the result.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mont_sqrt_sm2_5(sp_digit* y)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t = NULL;
#else
    sp_digit t[2 * 5];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5, NULL, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {

        {
            int i;

            XMEMCPY(t, y, sizeof(sp_digit) * 5);
            for (i=252; i>=0; i--) {
                sp_256_mont_sqr_sm2_5(t, t, p256_sm2_mod, p256_sm2_mp_mod);
                if (p256_sm2_sqrt_power[i / 64] & ((sp_digit)1 << (i % 64)))
                    sp_256_mont_mul_sm2_5(t, t, y, p256_sm2_mod, p256_sm2_mp_mod);
            }
            XMEMCPY(y, t, sizeof(sp_digit) * 5);
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (t != NULL)
        XFREE(t, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}


/* Uncompress the point given the X ordinate.
 *
 * xm    X ordinate.
 * odd   Whether the Y ordinate is odd.
 * ym    Calculated Y ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_uncompress_sm2_256(mp_int* xm, int odd, mp_int* ym)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* x = NULL;
#else
    sp_digit x[4 * 5];
#endif
    sp_digit* y = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    x = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 5, NULL, DYNAMIC_TYPE_ECC);
    if (x == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        y = x + 2 * 5;

        sp_256_from_mp(x, 5, xm);
        err = sp_256_mod_mul_norm_sm2_5(x, x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
        {
            sp_256_mont_sqr_sm2_5(y, x, p256_sm2_mod, p256_sm2_mp_mod);
            sp_256_mont_mul_sm2_5(y, y, x, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = x^3 - 3x */
        sp_256_mont_sub_sm2_5(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_5(y, y, x, p256_sm2_mod);
        /* y = x^3 - 3x + b */
        err = sp_256_mod_mul_norm_sm2_5(x, p256_sm2_b, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        sp_256_mont_add_sm2_5(y, y, x, p256_sm2_mod);
        /* y = sqrt(x^3 - 3x + b) */
        err = sp_256_mont_sqrt_sm2_5(y);
    }
    if (err == MP_OKAY) {
        XMEMSET(y + 5, 0, 5U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_5(y, p256_sm2_mod, p256_sm2_mp_mod);
        if ((((word32)y[0] ^ (word32)odd) & 1U) != 0U) {
            sp_256_mont_sub_sm2_5(y, p256_sm2_mod, y, p256_sm2_mod);
        }

        err = sp_256_to_mp(y, ym);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif
#endif /* WOLFSSL_SP_SM2 */
#endif /* WOLFSSL_HAVE_SP_ECC */
#endif /* SP_WORD_SIZE == 64 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
