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
#if SP_WORD_SIZE == 32
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
    sp_digit x[2 * 9];
    /* Y ordinate of point. */
    sp_digit y[2 * 9];
    /* Z ordinate of point. */
    sp_digit z[2 * 9];
    /* Indicates point is at infinity. */
    int infinity;
} sp_point_256;

/* The modulus (prime) of the curve SM2 P256. */
static const sp_digit p256_sm2_mod[9] = {
    0x1fffffff,0x1fffffff,0x0000003f,0x1ffffe00,0x1fffffff,0x1fffffff,
    0x1fffffff,0x1fdfffff,0x00ffffff
};
/* The Montgomery normalizer for modulus of the curve P256. */
static const sp_digit p256_sm2_norm_mod[9] = {
    0x00000001,0x00000000,0x1fffffc0,0x000001ff,0x00000000,0x00000000,
    0x00000000,0x00200000,0x00000000
};
/* The Montgomery multiplier for modulus of the curve P256. */
static const sp_digit p256_sm2_mp_mod = 0x0000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P256. */
static const sp_digit p256_sm2_order[9] = {
    0x19d54123,0x1ddfa049,0x11814ad4,0x07bed643,0x1ffff720,0x1fffffff,
    0x1fffffff,0x1fdfffff,0x00ffffff
};
#endif
/* The order of the curve P256 minus 2. */
static const sp_digit p256_sm2_order2[9] = {
    0x19d54121,0x1ddfa049,0x11814ad4,0x07bed643,0x1ffff720,0x1fffffff,
    0x1fffffff,0x1fdfffff,0x00ffffff
};
#if defined(HAVE_ECC_SIGN)
/* The Montgomery normalizer for order of the curve P256. */
static const sp_digit p256_sm2_norm_order[9] = {
    0x062abedd,0x02205fb6,0x0e7eb52b,0x184129bc,0x000008df,0x00000000,
    0x00000000,0x00200000,0x00000000
};
#endif
#if defined(HAVE_ECC_SIGN)
/* The Montgomery multiplier for order of the curve P256. */
static const sp_digit p256_sm2_mp_order = 0x12350975;
#endif
/* The base point of curve P256. */
static const sp_point_256 p256_sm2_base = {
    /* X ordinate */
    {
        0x134c74c7,0x0ad22c49,0x1982f85c,0x06177fe4,0x1c9948fe,0x0223351c,
        0x04657e64,0x0583e330,0x0032c4ae,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Y ordinate */
    {
        0x0139f0a0,0x16f99729,0x0a91d000,0x130ef98c,0x12153d0a,0x0771b5b4,
        0x1e7166f7,0x145e9ece,0x00bc3736,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Z ordinate */
    {
        0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
        0x00000000,0x00000000,0x00000000,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* infinity */
    0
};
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p256_sm2_b[9] = {
    0x0d940e93,0x0de5ea0a,0x0ae3e4b7,0x0f13ea2b,0x109a7f39,0x0f25e7b2,
    0x18d1356a,0x13d3b3eb,0x0028e9fa
};
#endif

#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_256_mul_sm2_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[8]) * b[8];
    r[17] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 15; k >= 0; k--) {
        if (k >= 9) {
            i = k - 8;
            imax = 8;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint64)a[i]) * b[k - i];
        }
        c += lo >> 29;
        r[k + 2] += (sp_digit)(c >> 29);
        r[k + 1]  = (sp_digit)(c & 0x1fffffff);
        c = lo & 0x1fffffff;
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
SP_NOINLINE static void sp_256_mul_sm2_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_int64 t0;
    sp_int64 t1;
    sp_digit t[9];

    t0 = ((sp_int64)a[ 0]) * b[ 0];
    t1 = ((sp_int64)a[ 0]) * b[ 1]
       + ((sp_int64)a[ 1]) * b[ 0];
    t[ 0] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 0]) * b[ 2]
       + ((sp_int64)a[ 1]) * b[ 1]
       + ((sp_int64)a[ 2]) * b[ 0];
    t[ 1] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 0]) * b[ 3]
       + ((sp_int64)a[ 1]) * b[ 2]
       + ((sp_int64)a[ 2]) * b[ 1]
       + ((sp_int64)a[ 3]) * b[ 0];
    t[ 2] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 0]) * b[ 4]
       + ((sp_int64)a[ 1]) * b[ 3]
       + ((sp_int64)a[ 2]) * b[ 2]
       + ((sp_int64)a[ 3]) * b[ 1]
       + ((sp_int64)a[ 4]) * b[ 0];
    t[ 3] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 0]) * b[ 5]
       + ((sp_int64)a[ 1]) * b[ 4]
       + ((sp_int64)a[ 2]) * b[ 3]
       + ((sp_int64)a[ 3]) * b[ 2]
       + ((sp_int64)a[ 4]) * b[ 1]
       + ((sp_int64)a[ 5]) * b[ 0];
    t[ 4] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 0]) * b[ 6]
       + ((sp_int64)a[ 1]) * b[ 5]
       + ((sp_int64)a[ 2]) * b[ 4]
       + ((sp_int64)a[ 3]) * b[ 3]
       + ((sp_int64)a[ 4]) * b[ 2]
       + ((sp_int64)a[ 5]) * b[ 1]
       + ((sp_int64)a[ 6]) * b[ 0];
    t[ 5] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 0]) * b[ 7]
       + ((sp_int64)a[ 1]) * b[ 6]
       + ((sp_int64)a[ 2]) * b[ 5]
       + ((sp_int64)a[ 3]) * b[ 4]
       + ((sp_int64)a[ 4]) * b[ 3]
       + ((sp_int64)a[ 5]) * b[ 2]
       + ((sp_int64)a[ 6]) * b[ 1]
       + ((sp_int64)a[ 7]) * b[ 0];
    t[ 6] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 0]) * b[ 8]
       + ((sp_int64)a[ 1]) * b[ 7]
       + ((sp_int64)a[ 2]) * b[ 6]
       + ((sp_int64)a[ 3]) * b[ 5]
       + ((sp_int64)a[ 4]) * b[ 4]
       + ((sp_int64)a[ 5]) * b[ 3]
       + ((sp_int64)a[ 6]) * b[ 2]
       + ((sp_int64)a[ 7]) * b[ 1]
       + ((sp_int64)a[ 8]) * b[ 0];
    t[ 7] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 1]) * b[ 8]
       + ((sp_int64)a[ 2]) * b[ 7]
       + ((sp_int64)a[ 3]) * b[ 6]
       + ((sp_int64)a[ 4]) * b[ 5]
       + ((sp_int64)a[ 5]) * b[ 4]
       + ((sp_int64)a[ 6]) * b[ 3]
       + ((sp_int64)a[ 7]) * b[ 2]
       + ((sp_int64)a[ 8]) * b[ 1];
    t[ 8] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 2]) * b[ 8]
       + ((sp_int64)a[ 3]) * b[ 7]
       + ((sp_int64)a[ 4]) * b[ 6]
       + ((sp_int64)a[ 5]) * b[ 5]
       + ((sp_int64)a[ 6]) * b[ 4]
       + ((sp_int64)a[ 7]) * b[ 3]
       + ((sp_int64)a[ 8]) * b[ 2];
    r[ 9] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 3]) * b[ 8]
       + ((sp_int64)a[ 4]) * b[ 7]
       + ((sp_int64)a[ 5]) * b[ 6]
       + ((sp_int64)a[ 6]) * b[ 5]
       + ((sp_int64)a[ 7]) * b[ 4]
       + ((sp_int64)a[ 8]) * b[ 3];
    r[10] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 4]) * b[ 8]
       + ((sp_int64)a[ 5]) * b[ 7]
       + ((sp_int64)a[ 6]) * b[ 6]
       + ((sp_int64)a[ 7]) * b[ 5]
       + ((sp_int64)a[ 8]) * b[ 4];
    r[11] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 5]) * b[ 8]
       + ((sp_int64)a[ 6]) * b[ 7]
       + ((sp_int64)a[ 7]) * b[ 6]
       + ((sp_int64)a[ 8]) * b[ 5];
    r[12] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 6]) * b[ 8]
       + ((sp_int64)a[ 7]) * b[ 7]
       + ((sp_int64)a[ 8]) * b[ 6];
    r[13] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = ((sp_int64)a[ 7]) * b[ 8]
       + ((sp_int64)a[ 8]) * b[ 7];
    r[14] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = ((sp_int64)a[ 8]) * b[ 8];
    r[15] = t1 & 0x1fffffff; t0 += t1 >> 29;
    r[16] = t0 & 0x1fffffff;
    r[17] = (sp_digit)(t0 >> 29);
    XMEMCPY(r, t, sizeof(t));
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_sm2_9(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[8]) * a[8];
    r[17] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 15; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 8) {
            imax = k;
        }
        else {
            imax = 8;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint64)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 58);
        r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
        c = (c & 0x1fffffff) << 29;
    }
    r[0] = (sp_digit)(c >> 29);
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_sm2_9(sp_digit* r, const sp_digit* a)
{
    sp_int64 t0;
    sp_int64 t1;
    sp_digit t[9];

    t0 =  ((sp_int64)a[ 0]) * a[ 0];
    t1 = (((sp_int64)a[ 0]) * a[ 1]) * 2;
    t[ 0] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 0]) * a[ 2]) * 2
       +  ((sp_int64)a[ 1]) * a[ 1];
    t[ 1] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 0]) * a[ 3]
       +  ((sp_int64)a[ 1]) * a[ 2]) * 2;
    t[ 2] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 0]) * a[ 4]
       +  ((sp_int64)a[ 1]) * a[ 3]) * 2
       +  ((sp_int64)a[ 2]) * a[ 2];
    t[ 3] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 0]) * a[ 5]
       +  ((sp_int64)a[ 1]) * a[ 4]
       +  ((sp_int64)a[ 2]) * a[ 3]) * 2;
    t[ 4] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 0]) * a[ 6]
       +  ((sp_int64)a[ 1]) * a[ 5]
       +  ((sp_int64)a[ 2]) * a[ 4]) * 2
       +  ((sp_int64)a[ 3]) * a[ 3];
    t[ 5] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 0]) * a[ 7]
       +  ((sp_int64)a[ 1]) * a[ 6]
       +  ((sp_int64)a[ 2]) * a[ 5]
       +  ((sp_int64)a[ 3]) * a[ 4]) * 2;
    t[ 6] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 0]) * a[ 8]
       +  ((sp_int64)a[ 1]) * a[ 7]
       +  ((sp_int64)a[ 2]) * a[ 6]
       +  ((sp_int64)a[ 3]) * a[ 5]) * 2
       +  ((sp_int64)a[ 4]) * a[ 4];
    t[ 7] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 1]) * a[ 8]
       +  ((sp_int64)a[ 2]) * a[ 7]
       +  ((sp_int64)a[ 3]) * a[ 6]
       +  ((sp_int64)a[ 4]) * a[ 5]) * 2;
    t[ 8] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 2]) * a[ 8]
       +  ((sp_int64)a[ 3]) * a[ 7]
       +  ((sp_int64)a[ 4]) * a[ 6]) * 2
       +  ((sp_int64)a[ 5]) * a[ 5];
    r[ 9] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 3]) * a[ 8]
       +  ((sp_int64)a[ 4]) * a[ 7]
       +  ((sp_int64)a[ 5]) * a[ 6]) * 2;
    r[10] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 4]) * a[ 8]
       +  ((sp_int64)a[ 5]) * a[ 7]) * 2
       +  ((sp_int64)a[ 6]) * a[ 6];
    r[11] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 5]) * a[ 8]
       +  ((sp_int64)a[ 6]) * a[ 7]) * 2;
    r[12] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 = (((sp_int64)a[ 6]) * a[ 8]) * 2
       +  ((sp_int64)a[ 7]) * a[ 7];
    r[13] = t1 & 0x1fffffff; t0 += t1 >> 29;
    t1 = (((sp_int64)a[ 7]) * a[ 8]) * 2;
    r[14] = t0 & 0x1fffffff; t1 += t0 >> 29;
    t0 =  ((sp_int64)a[ 8]) * a[ 8];
    r[15] = t1 & 0x1fffffff; t0 += t1 >> 29;
    r[16] = t0 & 0x1fffffff;
    r[17] = (sp_digit)(t0 >> 29);
    XMEMCPY(r, t, sizeof(t));
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_add_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 9; i++) {
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
SP_NOINLINE static int sp_256_add_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];

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
SP_NOINLINE static int sp_256_sub_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 9; i++) {
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
SP_NOINLINE static int sp_256_sub_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] - b[ 0];
    r[ 1] = a[ 1] - b[ 1];
    r[ 2] = a[ 2] - b[ 2];
    r[ 3] = a[ 3] - b[ 3];
    r[ 4] = a[ 4] - b[ 4];
    r[ 5] = a[ 5] - b[ 5];
    r[ 6] = a[ 6] - b[ 6];
    r[ 7] = a[ 7] - b[ 7];
    r[ 8] = a[ 8] - b[ 8];

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
#if DIGIT_BIT == 29
    int i;
    sp_digit j = (sp_digit)0 - (sp_digit)a->used;
    int o = 0;

    for (i = 0; i < size; i++) {
        sp_digit mask = (sp_digit)0 - (j >> 28);
        r[i] = a->dp[o] & mask;
        j++;
        o += (int)(j >> 28);
    }
#elif DIGIT_BIT > 29
    unsigned int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < (unsigned int)a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffff;
        s = 29U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 29U) <= (word32)DIGIT_BIT) {
            s += 29U;
            r[j] &= 0x1fffffff;
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
        if (s + DIGIT_BIT >= 29) {
            r[j] &= 0x1fffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 29 - s;
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
static void sp_256_point_from_ecc_point_9(sp_point_256* p,
        const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_256_from_mp(p->x, 9, pm->x);
    sp_256_from_mp(p->y, 9, pm->y);
    sp_256_from_mp(p->z, 9, pm->z);
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
#if DIGIT_BIT == 29
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 9);
        r->used = 9;
        mp_clamp(r);
#elif DIGIT_BIT < 29
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 9; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 29) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 29 - s;
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 9; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 29 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 29 - s;
            }
            else {
                s += 29;
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
static int sp_256_point_to_ecc_point_9(const sp_point_256* p, ecc_point* pm)
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

#define sp_256_mont_reduce_order_sm2_9         sp_256_mont_reduce_sm2_9

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_256_cmp_sm2_9(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=8; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }
#else
    r |= (a[ 8] - b[ 8]) & (0 - (sp_digit)1);
    r |= (a[ 7] - b[ 7]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 6] - b[ 6]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 5] - b[ 5]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 4] - b[ 4]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 3] - b[ 3]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 2] - b[ 2]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 1] - b[ 1]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[ 0] - b[ 0]) & ~(((sp_digit)0 - r) >> 28);
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
static void sp_256_cond_sub_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 9; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    r[ 0] = a[ 0] - (b[ 0] & m);
    r[ 1] = a[ 1] - (b[ 1] & m);
    r[ 2] = a[ 2] - (b[ 2] & m);
    r[ 3] = a[ 3] - (b[ 3] & m);
    r[ 4] = a[ 4] - (b[ 4] & m);
    r[ 5] = a[ 5] - (b[ 5] & m);
    r[ 6] = a[ 6] - (b[ 6] & m);
    r[ 7] = a[ 7] - (b[ 7] & m);
    r[ 8] = a[ 8] - (b[ 8] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_add_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 9; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[9] += (sp_digit)t;
#else
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 8; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[8]) + r[8];
    r[8] = t[0] & 0x1fffffff;
    r[9] +=  (sp_digit)(t[0] >> 29);
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 8; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[4] += t[3] >> 29;
        r[i+4] = t[4] & 0x1fffffff;
        t[5] += t[4] >> 29;
        r[i+5] = t[5] & 0x1fffffff;
        t[6] += t[5] >> 29;
        r[i+6] = t[6] & 0x1fffffff;
        t[7] += t[6] >> 29;
        r[i+7] = t[7] & 0x1fffffff;
        t[0]  = t[7] >> 29;
    }
    t[0] += (tb * a[8]) + r[8];
    r[8] = t[0] & 0x1fffffff;
    r[9] +=  (sp_digit)(t[0] >> 29);
#endif /* WOLFSSL_SP_SMALL */
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_256_norm_9(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 8; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    a[1] += a[0] >> 29; a[0] &= 0x1fffffff;
    a[2] += a[1] >> 29; a[1] &= 0x1fffffff;
    a[3] += a[2] >> 29; a[2] &= 0x1fffffff;
    a[4] += a[3] >> 29; a[3] &= 0x1fffffff;
    a[5] += a[4] >> 29; a[4] &= 0x1fffffff;
    a[6] += a[5] >> 29; a[5] &= 0x1fffffff;
    a[7] += a[6] >> 29; a[6] &= 0x1fffffff;
    a[8] += a[7] >> 29; a[7] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

/* Shift the result in the high 256 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_256_mont_shift_9(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_int64 n = a[8] >> 24;
    n += ((sp_int64)a[9]) << 5;

    for (i = 0; i < 8; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[10 + i]) << 5;
    }
    r[8] = (sp_digit)n;
#else
    sp_int64 n = a[8] >> 24;
    n += ((sp_int64)a[9]) << 5;
    r[ 0] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[10]) << 5;
    r[ 1] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[11]) << 5;
    r[ 2] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[12]) << 5;
    r[ 3] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[13]) << 5;
    r[ 4] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[14]) << 5;
    r[ 5] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[15]) << 5;
    r[ 6] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[16]) << 5;
    r[ 7] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[17]) << 5;
    r[8] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[9], 0, sizeof(*r) * 9U);
}

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_256_mont_reduce_sm2_9(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    if (mp != 1) {
        for (i=0; i<8; i++) {
            mu = (a[i] * mp) & 0x1fffffff;
            sp_256_mul_add_sm2_9(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = (a[i] * mp) & 0xffffffL;
        sp_256_mul_add_sm2_9(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
    else {
        for (i=0; i<8; i++) {
            mu = a[i] & 0x1fffffff;
            sp_256_mul_add_sm2_9(a+i, p256_sm2_mod, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = a[i] & 0xffffffL;
        sp_256_mul_add_sm2_9(a+i, p256_sm2_mod, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }

    sp_256_mont_shift_9(a, a);
    sp_256_cond_sub_sm2_9(a, a, m, 0 - (((a[8] >> 24) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_256_norm_9(a);
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
SP_NOINLINE static void sp_256_mont_mul_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_256_mul_sm2_9(r, a, b);
    sp_256_mont_reduce_sm2_9(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_sqr_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_256_sqr_sm2_9(r, a);
    sp_256_mont_reduce_sm2_9(r, m, mp);
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
SP_NOINLINE static void sp_256_mont_sqr_n_sm2_9(sp_digit* r,
    const sp_digit* a, int n, const sp_digit* m, sp_digit mp)
{
    sp_256_mont_sqr_sm2_9(r, a, m, mp);
    for (; n > 1; n--) {
        sp_256_mont_sqr_sm2_9(r, r, m, mp);
    }
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Mod-2 for the SM2 P256 curve. */
static const uint32_t p256_sm2_mod_minus_2[8] = {
    0xfffffffdU,0xffffffffU,0x00000000U,0xffffffffU,0xffffffffU,0xffffffffU,
    0xffffffffU,0xfffffffeU
};
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P256 curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_256_mont_inv_sm2_9(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 9);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_sm2_9(t, t, p256_sm2_mod, p256_sm2_mp_mod);
        if (p256_sm2_mod_minus_2[i / 32] & ((sp_digit)1 << (i % 32)))
            sp_256_mont_mul_sm2_9(t, t, a, p256_sm2_mod, p256_sm2_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 9);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 9;
    sp_digit* t3 = td + 4 * 9;
    sp_digit* t4 = td + 6 * 9;
    /* 0x2 */
    sp_256_mont_sqr_sm2_9(t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0x3 */
    sp_256_mont_mul_sm2_9(t2, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xc */
    sp_256_mont_sqr_n_sm2_9(t1, t2, 2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xd */
    sp_256_mont_mul_sm2_9(t3, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf */
    sp_256_mont_mul_sm2_9(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf0 */
    sp_256_mont_sqr_n_sm2_9(t1, t2, 4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfd */
    sp_256_mont_mul_sm2_9(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff */
    sp_256_mont_mul_sm2_9(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff00 */
    sp_256_mont_sqr_n_sm2_9(t1, t2, 8, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffd */
    sp_256_mont_mul_sm2_9(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff */
    sp_256_mont_mul_sm2_9(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff0000 */
    sp_256_mont_sqr_n_sm2_9(t1, t2, 16, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffd */
    sp_256_mont_mul_sm2_9(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe */
    sp_256_mont_mul_sm2_9(t2, t3, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffffffff */
    sp_256_mont_mul_sm2_9(t4, t2, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe00000000 */
    sp_256_mont_sqr_n_sm2_9(t2, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff */
    sp_256_mont_mul_sm2_9(t2, t4, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff00000000 */
    sp_256_mont_sqr_n_sm2_9(t1, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff */
    sp_256_mont_mul_sm2_9(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_9(t1, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_9(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_9(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_9(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff0000000000000000 */
    sp_256_mont_sqr_n_sm2_9(r, r, 64, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff */
    sp_256_mont_mul_sm2_9(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff00000000 */
    sp_256_mont_sqr_n_sm2_9(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd */
    sp_256_mont_mul_sm2_9(r, r, t3, p256_sm2_mod, p256_sm2_mp_mod);
#endif /* WOLFSSL_SP_SMALL */
}

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_256_map_sm2_9(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*9;
    sp_int32 n;

    sp_256_mont_inv_sm2_9(t1, p->z, t + 2*9);

    sp_256_mont_sqr_sm2_9(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    /* x /= z^2 */
    sp_256_mont_mul_sm2_9(r->x, p->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->x + 9, 0, sizeof(sp_digit) * 9U);
    sp_256_mont_reduce_sm2_9(r->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_256_cmp_sm2_9(r->x, p256_sm2_mod);
    sp_256_cond_sub_sm2_9(r->x, r->x, p256_sm2_mod, (sp_digit)~(n >> 28));
    sp_256_norm_9(r->x);

    /* y /= z^3 */
    sp_256_mont_mul_sm2_9(r->y, p->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->y + 9, 0, sizeof(sp_digit) * 9U);
    sp_256_mont_reduce_sm2_9(r->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_256_cmp_sm2_9(r->y, p256_sm2_mod);
    sp_256_cond_sub_sm2_9(r->y, r->y, p256_sm2_mod, (sp_digit)~(n >> 28));
    sp_256_norm_9(r->y);

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
static void sp_256_mont_add_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    sp_digit over;
    (void)sp_256_add_sm2_9(r, a, b);
    sp_256_norm_9(r);
    over = r[8] > m[8];
    sp_256_cond_sub_sm2_9(r, r, m, ~((over - 1) >> 31));
    sp_256_norm_9(r);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_dbl_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit over;
    (void)sp_256_add_sm2_9(r, a, a);
    sp_256_norm_9(r);
    over = r[8] > m[8];
    sp_256_cond_sub_sm2_9(r, r, m, ~((over - 1) >> 31));
    sp_256_norm_9(r);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_tpl_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit over;
    (void)sp_256_add_sm2_9(r, a, a);
    sp_256_norm_9(r);
    over = r[8] > m[8];
    sp_256_cond_sub_sm2_9(r, r, m, ~((over - 1) >> 31));
    sp_256_norm_9(r);
    (void)sp_256_add_sm2_9(r, r, a);
    sp_256_norm_9(r);
    over = r[8] > m[8];
    sp_256_cond_sub_sm2_9(r, r, m, ~((over - 1) >> 31));
    sp_256_norm_9(r);
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
static void sp_256_cond_add_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 9; i++) {
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
static void sp_256_cond_add_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    r[ 0] = a[ 0] + (b[ 0] & m);
    r[ 1] = a[ 1] + (b[ 1] & m);
    r[ 2] = a[ 2] + (b[ 2] & m);
    r[ 3] = a[ 3] + (b[ 3] & m);
    r[ 4] = a[ 4] + (b[ 4] & m);
    r[ 5] = a[ 5] + (b[ 5] & m);
    r[ 6] = a[ 6] + (b[ 6] & m);
    r[ 7] = a[ 7] + (b[ 7] & m);
    r[ 8] = a[ 8] + (b[ 8] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_sub_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_256_sub_sm2_9(r, a, b);
    sp_256_norm_9(r);
    sp_256_cond_add_sm2_9(r, r, m, r[8] >> 24);
    sp_256_norm_9(r);
}

/* Shift number left one bit.
 * Bottom bit is lost.
 *
 * r  Result of shift.
 * a  Number to shift.
 */
SP_NOINLINE static void sp_256_rshift1_sm2_9(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<8; i++) {
        r[i] = (a[i] >> 1) + ((a[i + 1] << 28) & 0x1fffffff);
    }
#else
    r[0] = (a[0] >> 1) + ((a[1] << 28) & 0x1fffffff);
    r[1] = (a[1] >> 1) + ((a[2] << 28) & 0x1fffffff);
    r[2] = (a[2] >> 1) + ((a[3] << 28) & 0x1fffffff);
    r[3] = (a[3] >> 1) + ((a[4] << 28) & 0x1fffffff);
    r[4] = (a[4] >> 1) + ((a[5] << 28) & 0x1fffffff);
    r[5] = (a[5] >> 1) + ((a[6] << 28) & 0x1fffffff);
    r[6] = (a[6] >> 1) + ((a[7] << 28) & 0x1fffffff);
    r[7] = (a[7] >> 1) + ((a[8] << 28) & 0x1fffffff);
#endif
    r[8] = a[8] >> 1;
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
static void sp_256_mont_div2_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_256_cond_add_sm2_9(r, a, m, 0 - (a[0] & 1));
    sp_256_norm_9(r);
    sp_256_rshift1_sm2_9(r, r);
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_sm2_9(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*9;
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
    sp_256_mont_sqr_sm2_9(t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = Y * Z */
    sp_256_mont_mul_sm2_9(z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = 2Z */
    sp_256_mont_dbl_sm2_9(z, z, p256_sm2_mod);
    /* T2 = X - T1 */
    sp_256_mont_sub_sm2_9(t2, p->x, t1, p256_sm2_mod);
    /* T1 = X + T1 */
    sp_256_mont_add_sm2_9(t1, p->x, t1, p256_sm2_mod);
    /* T2 = T1 * T2 */
    sp_256_mont_mul_sm2_9(t2, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* T1 = 3T2 */
    sp_256_mont_tpl_sm2_9(t1, t2, p256_sm2_mod);
    /* Y = 2Y */
    sp_256_mont_dbl_sm2_9(y, p->y, p256_sm2_mod);
    /* Y = Y * Y */
    sp_256_mont_sqr_sm2_9(y, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = Y * Y */
    sp_256_mont_sqr_sm2_9(t2, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = T2/2 */
    sp_256_mont_div2_sm2_9(t2, t2, p256_sm2_mod);
    /* Y = Y * X */
    sp_256_mont_mul_sm2_9(y, y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = T1 * T1 */
    sp_256_mont_sqr_sm2_9(x, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_9(x, x, y, p256_sm2_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_9(x, x, y, p256_sm2_mod);
    /* Y = Y - X */
    sp_256_mont_sub_sm2_9(y, y, x, p256_sm2_mod);
    /* Y = Y * T1 */
    sp_256_mont_mul_sm2_9(y, y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* Y = Y - T2 */
    sp_256_mont_sub_sm2_9(y, y, t2, p256_sm2_mod);
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_dbl_9_ctx {
    int state;
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
} sp_256_proj_point_dbl_9_ctx;

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_dbl_sm2_9_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_point_256* p, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_dbl_9_ctx* ctx = (sp_256_proj_point_dbl_sm2_9_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_proj_point_dbl_9_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0:
        ctx->t1 = t;
        ctx->t2 = t + 2*9;
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
        sp_256_mont_sqr_sm2_9(ctx->t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        /* Z = Y * Z */
        sp_256_mont_mul_sm2_9(ctx->z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        /* Z = 2Z */
        sp_256_mont_dbl_sm2_9(ctx->z, ctx->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4:
        /* T2 = X - T1 */
        sp_256_mont_sub_sm2_9(ctx->t2, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 5;
        break;
    case 5:
        /* T1 = X + T1 */
        sp_256_mont_add_sm2_9(ctx->t1, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 6;
        break;
    case 6:
        /* T2 = T1 * T2 */
        sp_256_mont_mul_sm2_9(ctx->t2, ctx->t1, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* T1 = 3T2 */
        sp_256_mont_tpl_sm2_9(ctx->t1, ctx->t2, p256_sm2_mod);
        ctx->state = 8;
        break;
    case 8:
        /* Y = 2Y */
        sp_256_mont_dbl_sm2_9(ctx->y, p->y, p256_sm2_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Y = Y * Y */
        sp_256_mont_sqr_sm2_9(ctx->y, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 10;
        break;
    case 10:
        /* T2 = Y * Y */
        sp_256_mont_sqr_sm2_9(ctx->t2, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 11;
        break;
    case 11:
        /* T2 = T2/2 */
        sp_256_mont_div2_sm2_9(ctx->t2, ctx->t2, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* Y = Y * X */
        sp_256_mont_mul_sm2_9(ctx->y, ctx->y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        /* X = T1 * T1 */
        sp_256_mont_sqr_sm2_9(ctx->x, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        /* X = X - Y */
        sp_256_mont_sub_sm2_9(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 15;
        break;
    case 15:
        /* X = X - Y */
        sp_256_mont_sub_sm2_9(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 16;
        break;
    case 16:
        /* Y = Y - X */
        sp_256_mont_sub_sm2_9(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
        ctx->state = 17;
        break;
    case 17:
        /* Y = Y * T1 */
        sp_256_mont_mul_sm2_9(ctx->y, ctx->y, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        /* Y = Y - T2 */
        sp_256_mont_sub_sm2_9(ctx->y, ctx->y, ctx->t2, p256_sm2_mod);
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
static int sp_256_cmp_equal_9(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
            (a[3] ^ b[3]) | (a[4] ^ b[4]) | (a[5] ^ b[5]) |
            (a[6] ^ b[6]) | (a[7] ^ b[7]) | (a[8] ^ b[8])) == 0;
}

/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_256_iszero_9(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7] |
            a[8]) == 0;
}


/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_sm2_9(sp_point_256* r,
        const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t6 = t;
    sp_digit* t1 = t + 2*9;
    sp_digit* t2 = t + 4*9;
    sp_digit* t3 = t + 6*9;
    sp_digit* t4 = t + 8*9;
    sp_digit* t5 = t + 10*9;

    /* U1 = X1*Z2^2 */
    sp_256_mont_sqr_sm2_9(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t1, t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_9(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_9(t3, t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_9(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    /* Check double */
    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_9(t2, t1) &
            sp_256_cmp_equal_9(t4, t3)) {
        sp_256_proj_point_dbl_sm2_9(r, p, t);
    }
    else {
        sp_digit* x = t6;
        sp_digit* y = t1;
        sp_digit* z = t2;

        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_9(t2, t2, t1, p256_sm2_mod);
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_9(t4, t4, t3, p256_sm2_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_9(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(y, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_9(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(z, z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_9(x, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(x, x, t5, p256_sm2_mod);
        sp_256_mont_mul_sm2_9(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_9(t3, y, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(x, x, t3, p256_sm2_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_9(y, y, x, p256_sm2_mod);
        sp_256_mont_mul_sm2_9(y, y, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(y, y, t5, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 9; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 9; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 9; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_add_9_ctx {
    int state;
    sp_256_proj_point_dbl_9_ctx dbl_ctx;
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
} sp_256_proj_point_add_9_ctx;

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_add_sm2_9_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_add_9_ctx* ctx = (sp_256_proj_point_add_sm2_9_ctx*)sp_ctx->data;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_256* a = p;
        p = q;
        q = a;
    }

    typedef char ctx_size_test[sizeof(sp_256_proj_point_add_9_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0: /* INIT */
        ctx->t6 = t;
        ctx->t1 = t + 2*9;
        ctx->t2 = t + 4*9;
        ctx->t3 = t + 6*9;
        ctx->t4 = t + 8*9;
        ctx->t5 = t + 10*9;
        ctx->x = ctx->t6;
        ctx->y = ctx->t1;
        ctx->z = ctx->t2;

        ctx->state = 1;
        break;
    case 1:
        /* U1 = X1*Z2^2 */
        sp_256_mont_sqr_sm2_9(ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        sp_256_mont_mul_sm2_9(ctx->t3, ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        sp_256_mont_mul_sm2_9(ctx->t1, ctx->t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 4;
        break;
    case 4:
        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_sm2_9(ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 5;
        break;
    case 5:
        sp_256_mont_mul_sm2_9(ctx->t4, ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 6;
        break;
    case 6:
        sp_256_mont_mul_sm2_9(ctx->t2, ctx->t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* S1 = Y1*Z2^3 */
        sp_256_mont_mul_sm2_9(ctx->t3, ctx->t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 8;
        break;
    case 8:
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_sm2_9(ctx->t4, ctx->t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Check double */
        if ((~p->infinity) & (~q->infinity) &
                sp_256_cmp_equal_9(ctx->t2, ctx->t1) &
                sp_256_cmp_equal_9(ctx->t4, ctx->t3)) {
            XMEMSET(&ctx->dbl_ctx, 0, sizeof(ctx->dbl_ctx));
            sp_256_proj_point_dbl_sm2_9(r, p, t);
            ctx->state = 25;
        }
        else {
            ctx->state = 10;
        }
        break;
    case 10:
        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_9(ctx->t2, ctx->t2, ctx->t1, p256_sm2_mod);
        ctx->state = 11;
        break;
    case 11:
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_9(ctx->t4, ctx->t4, ctx->t3, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_9(ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        sp_256_mont_mul_sm2_9(ctx->y, ctx->t1, ctx->t5, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        sp_256_mont_mul_sm2_9(ctx->t5, ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 15;
        break;
    case 15:
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_9(ctx->z, p->z, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 16;
        break;
    case 16:
        sp_256_mont_mul_sm2_9(ctx->z, ctx->z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 17;
        break;
    case 17:
        sp_256_mont_sqr_sm2_9(ctx->x, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        sp_256_mont_sub_sm2_9(ctx->x, ctx->x, ctx->t5, p256_sm2_mod);
        ctx->state = 19;
        break;
    case 19:
        sp_256_mont_mul_sm2_9(ctx->t5, ctx->t5, ctx->t3, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 20;
        break;
    case 20:
        sp_256_mont_dbl_sm2_9(ctx->t3, ctx->y, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(ctx->x, ctx->x, ctx->t3, p256_sm2_mod);
        ctx->state = 21;
        break;
    case 21:
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_9(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
        ctx->state = 22;
        break;
    case 22:
        sp_256_mont_mul_sm2_9(ctx->y, ctx->y, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 23;
        break;
    case 23:
        sp_256_mont_sub_sm2_9(ctx->y, ctx->y, ctx->t5, p256_sm2_mod);
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

            for (i = 0; i < 9; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (ctx->x[i] & maskt);
            }
            for (i = 0; i < 9; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (ctx->y[i] & maskt);
            }
            for (i = 0; i < 9; i++) {
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
SP_NOINLINE static void sp_256_mul_d_sm2_9(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 9; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[9] = (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[9];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    t[ 5] = tb * a[ 5];
    t[ 6] = tb * a[ 6];
    t[ 7] = tb * a[ 7];
    t[ 8] = tb * a[ 8];
    r[ 0] = (sp_digit)                 (t[ 0] & 0x1fffffff);
    r[ 1] = (sp_digit)((t[ 0] >> 29) + (t[ 1] & 0x1fffffff));
    r[ 2] = (sp_digit)((t[ 1] >> 29) + (t[ 2] & 0x1fffffff));
    r[ 3] = (sp_digit)((t[ 2] >> 29) + (t[ 3] & 0x1fffffff));
    r[ 4] = (sp_digit)((t[ 3] >> 29) + (t[ 4] & 0x1fffffff));
    r[ 5] = (sp_digit)((t[ 4] >> 29) + (t[ 5] & 0x1fffffff));
    r[ 6] = (sp_digit)((t[ 5] >> 29) + (t[ 6] & 0x1fffffff));
    r[ 7] = (sp_digit)((t[ 6] >> 29) + (t[ 7] & 0x1fffffff));
    r[ 8] = (sp_digit)((t[ 7] >> 29) + (t[ 8] & 0x1fffffff));
    r[ 9] = (sp_digit) (t[ 8] >> 29);
#endif /* WOLFSSL_SP_SMALL */
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_d_sm2_18(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 18; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[18] = (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 16; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[16];
    r[16] = (sp_digit)(t & 0x1fffffff);
    t >>= 29;
    t += tb * a[17];
    r[17] = (sp_digit)(t & 0x1fffffff);
    t >>= 29;
    r[18] = (sp_digit)(t & 0x1fffffff);
#endif /* WOLFSSL_SP_SMALL */
}

SP_NOINLINE static void sp_256_rshift_sm2_9(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<8; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
#else
    for (i=0; i<8; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (29 - n)) & 0x1fffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (29 - n)) & 0x1fffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (29 - n)) & 0x1fffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (29 - n)) & 0x1fffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (29 - n)) & 0x1fffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (29 - n)) & 0x1fffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (29 - n)) & 0x1fffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (29 - n)) & 0x1fffffff);
    }
#endif /* WOLFSSL_SP_SMALL */
    r[8] = a[8] >> n;
}

static WC_INLINE sp_digit sp_256_div_word_9(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_256_word_div_word_9(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
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
static int sp_256_div_sm2_9(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t1 = NULL;
#else
    sp_digit t1[4 * 9 + 3];
#endif
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;

#ifdef WOLFSSL_SP_SMALL_STACK
    t1 = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 9 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (t1 == NULL)
        err = MEMORY_E;
#endif

    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 18 + 1;
        sd = t2 + 9 + 1;

        sp_256_mul_d_sm2_9(sd, d, (sp_digit)1 << 5);
        sp_256_mul_d_sm2_18(t1, a, (sp_digit)1 << 5);
        dv = sd[8];
        t1[9 + 9] += t1[9 + 9 - 1] >> 29;
        t1[9 + 9 - 1] &= 0x1fffffff;
        for (i=9; i>=0; i--) {
            r1 = sp_256_div_word_9(t1[9 + i], t1[9 + i - 1], dv);

            sp_256_mul_d_sm2_9(t2, sd, r1);
            (void)sp_256_sub_sm2_9(&t1[i], &t1[i], t2);
            sp_256_norm_9(&t1[i]);
            t1[9 + i] -= t2[9];
            t1[9 + i] += t1[9 + i - 1] >> 29;
            t1[9 + i - 1] &= 0x1fffffff;
            r1 = sp_256_div_word_9(-t1[9 + i], -t1[9 + i - 1], dv);
            r1 -= t1[9 + i];
            sp_256_mul_d_sm2_9(t2, sd, r1);
            (void)sp_256_add_sm2_9(&t1[i], &t1[i], t2);
            t1[9 + i] += t1[9 + i - 1] >> 29;
            t1[9 + i - 1] &= 0x1fffffff;
        }
        t1[9 - 1] += t1[9 - 2] >> 29;
        t1[9 - 2] &= 0x1fffffff;
        r1 = sp_256_word_div_word_9(t1[9 - 1], dv);

        sp_256_mul_d_sm2_9(t2, sd, r1);
        sp_256_sub_sm2_9(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 18U);
        for (i=0; i<8; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_256_cond_add_sm2_9(r, r, sd, r[8] >> 31);

        sp_256_norm_9(r);
        sp_256_rshift_sm2_9(r, r, 5);
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
static int sp_256_mod_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_256_div_sm2_9(a, m, NULL, r);
}

/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mod_mul_norm_sm2_9(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_256_mul_sm2_9(r, a, p256_sm2_norm_mod);
    return sp_256_mod_sm2_9(r, r, m);
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
static int sp_256_ecc_mulmod_sm2_9(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[3];
    sp_digit tmp[2 * 9 * 6];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 6, heap,
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
        err = sp_256_mod_mul_norm_sm2_9(t[1].x, g->x, p256_sm2_mod);
    }
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_sm2_9(t[1].y, g->y, p256_sm2_mod);
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_sm2_9(t[1].z, g->z, p256_sm2_mod);

    if (err == MP_OKAY) {
        i = 8;
        c = 24;
        n = k[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = k[i--];
                c = 29;
            }

            y = (n >> 28) & 1;
            n <<= 1;

            sp_256_proj_point_add_sm2_9(&t[y^1], &t[0], &t[1], tmp);

            XMEMCPY(&t[2], (void*)(((size_t)&t[0] & addr_mask[y^1]) +
                                   ((size_t)&t[1] & addr_mask[y])),
                    sizeof(sp_point_256));
            sp_256_proj_point_dbl_sm2_9(&t[2], &t[2], tmp);
            XMEMCPY((void*)(((size_t)&t[0] & addr_mask[y^1]) +
                            ((size_t)&t[1] & addr_mask[y])), &t[2],
                    sizeof(sp_point_256));
        }

        if (map != 0) {
            sp_256_map_sm2_9(r, &t[0], tmp);
        }
        else {
            XMEMCPY(r, &t[0], sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (tmp != NULL)
#endif
    {
        ForceZero(tmp, sizeof(sp_digit) * 2 * 9 * 6);
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
typedef struct sp_256_ecc_mulmod_9_ctx {
    int state;
    union {
        sp_256_proj_point_dbl_9_ctx dbl_ctx;
        sp_256_proj_point_add_9_ctx add_ctx;
    };
    sp_point_256 t[3];
    sp_digit tmp[2 * 9 * 6];
    sp_digit n;
    int i;
    int c;
    int y;
} sp_256_ecc_mulmod_9_ctx;

static int sp_256_ecc_mulmod_sm2_9_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* g, const sp_digit* k, int map, int ct, void* heap)
{
    int err = FP_WOULDBLOCK;
    sp_256_ecc_mulmod_sm2_9_ctx* ctx = (sp_256_ecc_mulmod_9_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_ecc_mulmod_9_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    /* Implementation is constant time. */
    (void)ct;

    switch (ctx->state) {
    case 0: /* INIT */
        XMEMSET(ctx->t, 0, sizeof(sp_point_256) * 3);
        ctx->i = 8;
        ctx->c = 24;
        ctx->n = k[ctx->i--] << (29 - ctx->c);

        /* t[0] = {0, 0, 1} * norm */
        ctx->t[0].infinity = 1;
        ctx->state = 1;
        break;
    case 1: /* T1X */
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_256_mod_mul_norm_sm2_9(ctx->t[1].x, g->x, p256_sm2_mod);
        ctx->state = 2;
        break;
    case 2: /* T1Y */
        err = sp_256_mod_mul_norm_sm2_9(ctx->t[1].y, g->y, p256_sm2_mod);
        ctx->state = 3;
        break;
    case 3: /* T1Z */
        err = sp_256_mod_mul_norm_sm2_9(ctx->t[1].z, g->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4: /* ADDPREP */
        if (ctx->c == 0) {
            if (ctx->i == -1) {
                ctx->state = 7;
                break;
            }

            ctx->n = k[ctx->i--];
            ctx->c = 29;
        }
        ctx->y = (ctx->n >> 28) & 1;
        ctx->n <<= 1;
        XMEMSET(&ctx->add_ctx, 0, sizeof(ctx->add_ctx));
        ctx->state = 5;
        break;
    case 5: /* ADD */
        err = sp_256_proj_point_add_sm2_9_nb((sp_ecc_ctx_t*)&ctx->add_ctx,
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
        err = sp_256_proj_point_dbl_sm2_9_nb((sp_ecc_ctx_t*)&ctx->dbl_ctx, &ctx->t[2],
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
            sp_256_map_sm2_9(r, &ctx->t[0], ctx->tmp);
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
    sp_digit x[9];
    sp_digit y[9];
} sp_table_entry_256;

/* Conditionally copy a into r using the mask m.
 * m is -1 to copy and 0 when not.
 *
 * r  A single precision number to copy over.
 * a  A single precision number to copy.
 * m  Mask value to apply.
 */
static void sp_256_cond_copy_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit m)
{
    sp_digit t[9];
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 9; i++) {
        t[i] = r[i] ^ a[i];
    }
    for (i = 0; i < 9; i++) {
        r[i] ^= t[i] & m;
    }
#else
    t[ 0] = r[ 0] ^ a[ 0];
    t[ 1] = r[ 1] ^ a[ 1];
    t[ 2] = r[ 2] ^ a[ 2];
    t[ 3] = r[ 3] ^ a[ 3];
    t[ 4] = r[ 4] ^ a[ 4];
    t[ 5] = r[ 5] ^ a[ 5];
    t[ 6] = r[ 6] ^ a[ 6];
    t[ 7] = r[ 7] ^ a[ 7];
    t[ 8] = r[ 8] ^ a[ 8];
    r[ 0] ^= t[ 0] & m;
    r[ 1] ^= t[ 1] & m;
    r[ 2] ^= t[ 2] & m;
    r[ 3] ^= t[ 3] & m;
    r[ 4] ^= t[ 4] & m;
    r[ 5] ^= t[ 5] & m;
    r[ 6] ^= t[ 6] & m;
    r[ 7] ^= t[ 7] & m;
    r[ 8] ^= t[ 8] & m;
#endif /* WOLFSSL_SP_SMALL */
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_sm2_9(sp_point_256* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*9;
    sp_digit* b = t + 4*9;
    sp_digit* t1 = t + 6*9;
    sp_digit* t2 = t + 8*9;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_9(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_9(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_9(w, w, p256_sm2_mod, p256_sm2_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_9(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_9(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_9(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_9(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_9(t2, b, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(x, x, t2, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_sub_sm2_9(t2, b, x, p256_sm2_mod);
        sp_256_mont_dbl_sm2_9(b, t2, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_9(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_9(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_9(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_9(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(y, y, t1, p256_sm2_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_256_mont_sqr_sm2_9(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_9(t1, t1, w, p256_sm2_mod);
    sp_256_mont_tpl_sm2_9(a, t1, p256_sm2_mod);
    /* B = X*Y^2 */
    sp_256_mont_sqr_sm2_9(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = A^2 - 2B */
    sp_256_mont_sqr_sm2_9(x, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_dbl_sm2_9(t2, b, p256_sm2_mod);
    sp_256_mont_sub_sm2_9(x, x, t2, p256_sm2_mod);
    /* B = 2.(B - X) */
    sp_256_mont_sub_sm2_9(t2, b, x, p256_sm2_mod);
    sp_256_mont_dbl_sm2_9(b, t2, p256_sm2_mod);
    /* Z = Z*Y */
    sp_256_mont_mul_sm2_9(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* t1 = Y^4 */
    sp_256_mont_sqr_sm2_9(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_256_mont_mul_sm2_9(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_9(y, y, t1, p256_sm2_mod);
#endif /* WOLFSSL_SP_SMALL */
    /* Y = Y/2 */
    sp_256_mont_div2_sm2_9(y, y, p256_sm2_mod);
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_store_sm2_9(sp_point_256* r,
        const sp_point_256* p, int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*9;
    sp_digit* b = t + 4*9;
    sp_digit* t1 = t + 6*9;
    sp_digit* t2 = t + 8*9;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;
    int j;

    for (i=0; i<9; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<9; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<9; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_9(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_9(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_9(w, w, p256_sm2_mod, p256_sm2_mp_mod);
    j = m;
    for (i=1; i<=n; i++) {
        j *= 2;

        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_9(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_9(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_9(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        x = r[j].x;
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_9(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_9(t2, b, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(x, x, t2, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_sub_sm2_9(t2, b, x, p256_sm2_mod);
        sp_256_mont_dbl_sm2_9(b, t2, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_9(r[j].z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        z = r[j].z;
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_9(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_9(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_9(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(y, y, t1, p256_sm2_mod);
        /* Y = Y/2 */
        sp_256_mont_div2_sm2_9(r[j].y, y, p256_sm2_mod);
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
static void sp_256_proj_point_add_sub_sm2_9(sp_point_256* ra,
        sp_point_256* rs, const sp_point_256* p, const sp_point_256* q,
        sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*9;
    sp_digit* t3 = t + 4*9;
    sp_digit* t4 = t + 6*9;
    sp_digit* t5 = t + 8*9;
    sp_digit* t6 = t + 10*9;
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
    sp_256_mont_sqr_sm2_9(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t1, t1, xa, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_9(t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t4, t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_9(t3, t3, ya, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_9(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* H = U2 - U1 */
    sp_256_mont_sub_sm2_9(t2, t2, t1, p256_sm2_mod);
    /* RS = S2 + S1 */
    sp_256_mont_add_sm2_9(t6, t4, t3, p256_sm2_mod);
    /* R = S2 - S1 */
    sp_256_mont_sub_sm2_9(t4, t4, t3, p256_sm2_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_256_mont_mul_sm2_9(za, za, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(za, za, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(zs, za, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_256_mont_sqr_sm2_9(xa, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_9(xs, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_9(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(ya, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_9(xa, xa, t5, p256_sm2_mod);
    sp_256_mont_sub_sm2_9(xs, xs, t5, p256_sm2_mod);
    sp_256_mont_dbl_sm2_9(t1, ya, p256_sm2_mod);
    sp_256_mont_sub_sm2_9(xa, xa, t1, p256_sm2_mod);
    sp_256_mont_sub_sm2_9(xs, xs, t1, p256_sm2_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_256_mont_sub_sm2_9(ys, ya, xs, p256_sm2_mod);
    sp_256_mont_sub_sm2_9(ya, ya, xa, p256_sm2_mod);
    sp_256_mont_mul_sm2_9(ya, ya, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_sub_sm2_9(t6, p256_sm2_mod, t6);
    sp_256_mont_mul_sm2_9(ys, ys, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_9(ya, ya, t5, p256_sm2_mod);
    sp_256_mont_sub_sm2_9(ys, ys, t5, p256_sm2_mod);
}

/* Structure used to describe recoding of scalar multiplication. */
typedef struct ecc_recode_256 {
    /* Index into pre-computation table. */
    uint8_t i;
    /* Use the negative of the point. */
    uint8_t neg;
} ecc_recode_256;

/* The index into pre-computation table to use. */
static const uint8_t recode_index_9_6[66] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const uint8_t recode_neg_9_6[66] = {
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
static void sp_256_ecc_recode_6_9(const sp_digit* k, ecc_recode_256* v)
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
        if (o + 6 < 29) {
            y &= 0x3f;
            n >>= 6;
            o += 6;
        }
        else if (o + 6 == 29) {
            n >>= 6;
            if (++j < 9)
                n = k[j];
            o = 0;
        }
        else if (++j < 9) {
            n = k[j];
            y |= (uint8_t)((n << (29 - o)) & 0x3f);
            o -= 23;
            n >>= o;
        }

        y += (uint8_t)carry;
        v[i].i = recode_index_9_6[y];
        v[i].neg = recode_neg_9_6[y];
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
static void sp_256_get_point_33_sm2_9(sp_point_256* r, const sp_point_256* table,
    int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->x[5] = 0;
    r->x[6] = 0;
    r->x[7] = 0;
    r->x[8] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
    r->y[8] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    r->z[4] = 0;
    r->z[5] = 0;
    r->z[6] = 0;
    r->z[7] = 0;
    r->z[8] = 0;
    for (i = 1; i < 33; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->x[7] |= mask & table[i].x[7];
        r->x[8] |= mask & table[i].x[8];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
        r->y[8] |= mask & table[i].y[8];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
        r->z[4] |= mask & table[i].z[4];
        r->z[5] |= mask & table[i].z[5];
        r->z[6] |= mask & table[i].z[6];
        r->z[7] |= mask & table[i].z[7];
        r->z[8] |= mask & table[i].z[8];
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
static int sp_256_ecc_mulmod_win_add_sub_sm2_9(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[33+2];
    sp_digit tmp[2 * 9 * 6];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 6,
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
        err = sp_256_mod_mul_norm_sm2_9(t[1].x, g->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_9(t[1].y, g->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_9(t[1].z, g->z, p256_sm2_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_256_proj_point_dbl_n_store_sm2_9(t, &t[ 1], 5, 1, tmp);
        sp_256_proj_point_add_sm2_9(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[ 6], &t[ 3], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[10], &t[ 5], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[12], &t[ 6], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[14], &t[ 7], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[18], &t[ 9], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[20], &t[10], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[22], &t[11], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[24], &t[12], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[26], &t[13], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[28], &t[14], tmp);
        sp_256_proj_point_dbl_sm2_9(&t[30], &t[15], tmp);
        sp_256_proj_point_add_sub_sm2_9(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_256_ecc_recode_6_9(k, v);

        i = 42;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_point_33_sm2_9(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_256));
        }
        for (--i; i>=0; i--) {
            sp_256_proj_point_dbl_n_sm2_9(rt, 6, tmp);

        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_point_33_sm2_9(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
        #endif
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_256));
            }
            sp_256_sub_sm2_9(negy, p256_sm2_mod, p->y);
            sp_256_norm_9(negy);
            sp_256_cond_copy_sm2_9(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_256_proj_point_add_sm2_9(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_256_map_sm2_9(r, rt, tmp);
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
static void sp_256_proj_point_add_qz1_sm2_9(sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*9;
    sp_digit* t6 = t + 4*9;
    sp_digit* t1 = t + 6*9;
    sp_digit* t4 = t + 8*9;
    sp_digit* t5 = t + 10*9;

    /* Calculate values to subtract from P->x and P->y. */
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_9(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_9(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_9(p->x, t2) &
            sp_256_cmp_equal_9(p->y, t4)) {
        sp_256_proj_point_dbl_sm2_9(r, p, t);
    }
    else {
        sp_digit* x = t2;
        sp_digit* y = t3;
        sp_digit* z = t6;

        /* H = U2 - X1 */
        sp_256_mont_sub_sm2_9(t2, t2, p->x, p256_sm2_mod);
        /* R = S2 - Y1 */
        sp_256_mont_sub_sm2_9(t4, t4, p->y, p256_sm2_mod);
        /* Z3 = H*Z1 */
        sp_256_mont_mul_sm2_9(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_256_mont_sqr_sm2_9(t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(t3, p->x, t1, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(t1, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_9(t2, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(t2, t2, t1, p256_sm2_mod);
        sp_256_mont_dbl_sm2_9(t5, t3, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(x, t2, t5, p256_sm2_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_sub_sm2_9(t3, t3, x, p256_sm2_mod);
        sp_256_mont_mul_sm2_9(t3, t3, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_9(t1, t1, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_9(y, t3, t1, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 9; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 9; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 9; i++) {
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
static void sp_256_proj_to_affine_sm2_9(sp_point_256* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 9;
    sp_digit* tmp = t + 4 * 9;

    sp_256_mont_inv_sm2_9(t1, a->z, tmp);

    sp_256_mont_sqr_sm2_9(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    sp_256_mont_mul_sm2_9(a->x, a->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_9(a->y, a->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
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
static int sp_256_gen_stripe_table_sm2_9(const sp_point_256* a,
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

        err = sp_256_mod_mul_norm_sm2_9(t->x, a->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_9(t->y, a->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_9(t->z, a->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_sm2_9(t, tmp);

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
            sp_256_proj_point_dbl_n_sm2_9(t, 32, tmp);
            sp_256_proj_to_affine_sm2_9(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_sm2_9(t, s1, s2, tmp);
                sp_256_proj_to_affine_sm2_9(t, tmp);
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
static void sp_256_get_entry_256_sm2_9(sp_point_256* r,
    const sp_table_entry_256* table, int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->x[5] = 0;
    r->x[6] = 0;
    r->x[7] = 0;
    r->x[8] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
    r->y[8] = 0;
    for (i = 1; i < 256; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->x[7] |= mask & table[i].x[7];
        r->x[8] |= mask & table[i].x[8];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
        r->y[8] |= mask & table[i].y[8];
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
static int sp_256_ecc_mulmod_stripe_sm2_9(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* t = NULL;
#else
    sp_point_256 rt[2];
    sp_digit t[2 * 9 * 6];
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
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 6, heap,
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
            y |= (int)(((k[x / 29] >> (x % 29)) & 1) << j);
            x += 32;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_256_sm2_9(rt, table, y);
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
                y |= (int)(((k[x / 29] >> (x % 29)) & 1) << j);
                x += 32;
            }

            sp_256_proj_point_dbl_sm2_9(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_256_sm2_9(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_256_proj_point_add_qz1_sm2_9(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_sm2_9(r, rt, t);
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
    sp_digit x[9];
    /* Y ordinate of point that table was generated from. */
    sp_digit y[9];
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

        if (sp_256_cmp_equal_9(g->x, sp_cache_256[i].x) &
                           sp_256_cmp_equal_9(g->y, sp_cache_256[i].y)) {
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
static int sp_256_ecc_mulmod_sm2_9(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_win_add_sub_sm2_9(r, g, k, map, ct, heap);
#else
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp;
#else
    sp_digit tmp[2 * 9 * 6];
#endif
    sp_cache_256_t* cache;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 6, heap, DYNAMIC_TYPE_ECC);
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
            sp_256_gen_stripe_table_sm2_9(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_win_add_sub_sm2_9(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_9(r, g, cache->table, k,
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
    sp_digit k[9];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 9, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 9, km);
        sp_256_point_from_ecc_point_9(point, gm);

            err = sp_256_ecc_mulmod_sm2_9(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_9(point, r);
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
    sp_digit k[9 + 9 * 2 * 6];
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
            sizeof(sp_digit) * (9 + 9 * 2 * 6), heap,
            DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 9;

        sp_256_from_mp(k, 9, km);
        sp_256_point_from_ecc_point_9(point, gm);
        sp_256_point_from_ecc_point_9(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_9(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_9(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_9(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_sm2_9(point, point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_9(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_9(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_9(point, r);
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
static int sp_256_ecc_mulmod_base_sm2_9(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    /* No pre-computed values. */
    return sp_256_ecc_mulmod_sm2_9(r, &p256_sm2_base, k, map, ct, heap);
}

#ifdef WOLFSSL_SP_NONBLOCK
static int sp_256_ecc_mulmod_base_9_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_digit* k, int map, int ct, void* heap)
{
    /* No pre-computed values. */
    return sp_256_ecc_mulmod_sm2_9_nb(sp_ctx, r, &p256_sm2_base, k, map, ct, heap);
}
#endif /* WOLFSSL_SP_NONBLOCK */


#else
/* Striping precomputation table.
 * 8 points combined into a table of 256 points.
 * Distance of 32 between points.
 */
static const sp_table_entry_256 p256_sm2_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x1418029e,0x09944c87,0x09b01418,0x1303dbb9,0x0c3c33e7,0x16ccd612,
        0x0c175a87,0x0bdc3827,0x0091167a },
      { 0x1c2d0ddd,0x09aa72c9,0x0ca57eb0,0x0bcaf11a,0x048f8c1f,0x1d833715,
        0x16f63533,0x1a903ae6,0x0063cd65 } },
    /* 2 */
    { { 0x0cf4efe5,0x05c7c968,0x038b48bb,0x08e4292c,0x1f07988c,0x04f7b02c,
        0x09f32a55,0x094e02db,0x00d0a377 },
      { 0x1d001cab,0x08e4afb0,0x1fbbb075,0x089bdf47,0x0df2b2d7,0x0661057f,
        0x1296df08,0x1e2e3a28,0x00bf16c5 } },
    /* 3 */
    { { 0x0d9c635e,0x1427505d,0x091b8559,0x0894ad0a,0x1637348a,0x16622b5d,
        0x1e385a49,0x17a87dfd,0x00b9966e },
      { 0x150e7f7d,0x072bf8a1,0x16f7f5ab,0x04d92b44,0x0a5925c0,0x11bacf6a,
        0x0893cc2f,0x1caa2469,0x0074dde4 } },
    /* 4 */
    { { 0x1ad830d2,0x199f0105,0x037fecd2,0x003f3cb2,0x0ecb05c1,0x024c5e40,
        0x04fb3438,0x1f0a5545,0x00302787 },
      { 0x020f8fc8,0x1eb26769,0x03b8ddef,0x19d7c17c,0x1b128cf5,0x101c4489,
        0x09e7700e,0x0e3fbc46,0x004b0969 } },
    /* 5 */
    { { 0x19a0d9dc,0x07742711,0x07b7e96d,0x0453980c,0x133d0f7d,0x1925ea67,
        0x1d665d96,0x1e226653,0x00511c69 },
      { 0x007ae316,0x084addbd,0x1fc39690,0x0ca1e270,0x07e4a3a4,0x010e4cc1,
        0x10e91891,0x08809684,0x007b1e81 } },
    /* 6 */
    { { 0x18f2bc34,0x0f0bb317,0x06b9a857,0x010e2c2e,0x0baa0884,0x1238263e,
        0x1983196d,0x1f97b9c5,0x00b56909 },
      { 0x1e73ddb0,0x12ee59c9,0x17821411,0x14ee3eba,0x17cfb5cc,0x0f0a4338,
        0x13ee5bf8,0x12583b9a,0x00fda136 } },
    /* 7 */
    { { 0x043f38e8,0x08623d50,0x1ebc6435,0x0fd722b3,0x100cb539,0x013f581e,
        0x063ea744,0x0254b350,0x001d04d6 },
      { 0x0328d2b3,0x0e6ee430,0x15a04c96,0x1103d10f,0x0049306f,0x07e25f8c,
        0x12f90a45,0x1501041f,0x00d6a600 } },
    /* 8 */
    { { 0x1abd31f0,0x0ccdc4a0,0x0769f4d1,0x08331b34,0x0217ddb3,0x0a91d078,
        0x013aa2e2,0x087cad71,0x002014cc },
      { 0x09efd4ee,0x1dca7c42,0x1fd2b81b,0x102e2050,0x12debf1b,0x054d4cfe,
        0x094e274e,0x0f4e56cf,0x00817927 } },
    /* 9 */
    { { 0x0e4b53df,0x1a978cac,0x107c6729,0x10ab7317,0x1202815b,0x0ac7dbad,
        0x146f4ef3,0x082936ec,0x003e7e28 },
      { 0x0b47b1aa,0x0d472658,0x142e1a9a,0x04f8f72e,0x015edc3b,0x0fbc1f8a,
        0x15a99772,0x1788d174,0x00baab4d } },
    /* 10 */
    { { 0x1f4f7cb3,0x1ff04dd6,0x13f81e8c,0x17302aa7,0x1167dbed,0x027d2c37,
        0x0d30d783,0x1921043d,0x00dd4c37 },
      { 0x00e9402a,0x1b292065,0x0125c808,0x1606c4fe,0x123d8694,0x1306cdbb,
        0x0c147180,0x15ea5f1c,0x00e488f0 } },
    /* 11 */
    { { 0x0ec04411,0x1dc4c987,0x0e26bd1e,0x138e342b,0x083ced65,0x1e34db24,
        0x1922f887,0x1c0055a2,0x00fcdd9d },
      { 0x199d29fe,0x195aaaeb,0x05227bc1,0x02f4b12e,0x00f682c5,0x04bcfa2d,
        0x0e576f73,0x07e79a11,0x00b268b8 } },
    /* 12 */
    { { 0x16aed763,0x1b608249,0x081e6f99,0x0e2533a9,0x14f338c8,0x168b6d0c,
        0x09737ebe,0x0c38ba92,0x002ab291 },
      { 0x1970c4f8,0x1323b0e0,0x04ac0e88,0x11b26906,0x00022c76,0x10282dac,
        0x0f0061fc,0x033a266c,0x0016406b } },
    /* 13 */
    { { 0x0f11a1b7,0x1a546a14,0x1ba0e954,0x08efe3bd,0x06bd3938,0x1bfb792e,
        0x0a1f5dc8,0x12a81cd9,0x0046ef13 },
      { 0x19dbd954,0x01873b03,0x0a6a9b42,0x13036d47,0x0a064e22,0x0f3b660d,
        0x1e301dc6,0x075a0888,0x006c909a } },
    /* 14 */
    { { 0x1ab4c047,0x0684ede9,0x05c9774f,0x0af0418a,0x000d88c8,0x1dd640c5,
        0x1fb6833b,0x0f1b27ab,0x006bf4b6 },
      { 0x1c1c77f8,0x1dc5bb24,0x0c842bad,0x105b6a77,0x00ce0d3c,0x163a8cfa,
        0x1e709fd7,0x0dac1473,0x001c742c } },
    /* 15 */
    { { 0x008acdd0,0x091ec033,0x0f98615e,0x0ec98a9b,0x14789119,0x04a02260,
        0x16e560a1,0x0e3d7c02,0x00ba5f59 },
      { 0x13d216f3,0x1e11ad13,0x183c9806,0x04974006,0x0ed49996,0x1f77e0d5,
        0x0569322c,0x16ef9bc8,0x00a302e8 } },
    /* 16 */
    { { 0x0a914b50,0x1cfab0d4,0x1534ddde,0x0e261d22,0x14c352bf,0x1b4b28cd,
        0x1159a003,0x080ad169,0x00c9e650 },
      { 0x0d98a331,0x03837003,0x0473878c,0x1425edc4,0x02e5f781,0x0f1ea02b,
        0x1d1c7ffe,0x08d182cc,0x006356cf } },
    /* 17 */
    { { 0x097518d9,0x1627279c,0x1dd6c365,0x0bb018cd,0x1ceb5382,0x0b6003fb,
        0x1c93e82f,0x0d34607d,0x005c01af },
      { 0x0bfcbc92,0x0bae7cf3,0x0373abb7,0x1c94a649,0x134218bf,0x11634a9b,
        0x0e19464d,0x1002d199,0x006f3508 } },
    /* 18 */
    { { 0x042e4248,0x10e55dfa,0x186adeb9,0x1299d4bd,0x0bbb0241,0x1a98cdd6,
        0x0f7886d7,0x10157915,0x007d554b },
      { 0x1268ca65,0x15b53093,0x06dea12b,0x1ef82bfd,0x191333c6,0x14ffb1aa,
        0x02056fa2,0x11823dfc,0x009d1777 } },
    /* 19 */
    { { 0x0d347f7f,0x0f95ba99,0x09459e99,0x01856674,0x145ac2f7,0x1fdaf57d,
        0x06fab671,0x0f83872c,0x009fcd99 },
      { 0x137ca7dd,0x0db96719,0x022daf49,0x1d21aab5,0x14ffe255,0x06e41c41,
        0x036dec75,0x073e4838,0x000cb910 } },
    /* 20 */
    { { 0x0f13b772,0x14ae2886,0x16b29f3e,0x07f921b2,0x1a435a9b,0x1bc82658,
        0x1a8239b9,0x1b30ea9c,0x00840b63 },
      { 0x13196bd2,0x1d33cc09,0x016447f3,0x160ac3df,0x14af615a,0x0a017dec,
        0x1ed54136,0x1a7f9921,0x00063173 } },
    /* 21 */
    { { 0x11fa5996,0x0ac72870,0x19909edb,0x1b737599,0x11d185a7,0x0ad54a94,
        0x1d8df4c3,0x0c39a6a8,0x009e69e8 },
      { 0x106bd6f9,0x0865e54b,0x0ef697cb,0x18c9615e,0x0cc0d63c,0x0edf836b,
        0x0dac2731,0x15503ca1,0x00533ba1 } },
    /* 22 */
    { { 0x05a4c565,0x0fb96121,0x1e0225e9,0x082615a7,0x0c4d9c86,0x0c417da8,
        0x154103d0,0x132aaa3d,0x00499c14 },
      { 0x01ee4b05,0x12026c43,0x1ca6fbcc,0x1e32a7a4,0x1b28b4a3,0x074d76df,
        0x17b3fe1e,0x0add0369,0x00ca18c8 } },
    /* 23 */
    { { 0x1b87826e,0x05260a70,0x00c9b6a3,0x0570e79d,0x12797e4b,0x1623d80c,
        0x0b91782d,0x13d7da64,0x00a95e1b },
      { 0x0f98438b,0x05dd4602,0x1f4a8265,0x06036ed5,0x061868e5,0x12b54d3a,
        0x0b4384be,0x11c754d1,0x0031b526 } },
    /* 24 */
    { { 0x00b8f9c6,0x1b3dc38f,0x13a203cb,0x17bd2dcd,0x1362f101,0x07d916c5,
        0x1d081fc2,0x0827e3b5,0x00e8cfc6 },
      { 0x08742a60,0x04419233,0x112cdc38,0x092f3b44,0x07b39eb5,0x19368144,
        0x01b8d334,0x0c8ffcf2,0x0068fd6b } },
    /* 25 */
    { { 0x0774bf91,0x1e490ba0,0x0abacb91,0x13cd0521,0x15af5687,0x0467944d,
        0x11f759af,0x0686ba43,0x00dc9ead },
      { 0x1400fd22,0x0aa1ceca,0x1e195df9,0x024014db,0x1bfedb4d,0x0938ae6a,
        0x0279e7e1,0x1b1467fb,0x00f1e74d } },
    /* 26 */
    { { 0x0eadd7c7,0x08ef3c3c,0x073e5157,0x10755cd9,0x063d2268,0x09f7234e,
        0x04efd323,0x0c4a93fc,0x007e1635 },
      { 0x0a1e5a2d,0x01273fc4,0x0690f49b,0x0aa14b7e,0x0f8dd7f5,0x0aa77934,
        0x18d30ff2,0x0e323e46,0x002b0d67 } },
    /* 27 */
    { { 0x1aef1d85,0x191543dd,0x10e4eb3f,0x0e99ef58,0x11d81cf7,0x109baba5,
        0x15a87376,0x1b78009f,0x00cda8f0 },
      { 0x0a5c7738,0x08f4e84b,0x091613dc,0x135557f9,0x1c75c718,0x0e938adc,
        0x1b47ae3b,0x16ef1b61,0x000532d2 } },
    /* 28 */
    { { 0x1e93d304,0x1617e80b,0x1156d091,0x07f3236c,0x146eb6df,0x1fcc2d18,
        0x1056b4ff,0x1f582587,0x009dbadc },
      { 0x08adf57d,0x1d0aeb12,0x1c2b4fa1,0x1dcec1cf,0x1bb269c0,0x18b7f88a,
        0x0ff1f773,0x1310ee84,0x00ee787b } },
    /* 29 */
    { { 0x035b2fe6,0x1ece4e6d,0x11ec4e73,0x1ff9f4b1,0x0ce21c46,0x0439c794,
        0x1f7f6ebf,0x031cf306,0x004798d0 },
      { 0x0df63b8c,0x1df1f335,0x1eaa3f96,0x1ace7dfa,0x05359bc5,0x1bfd899f,
        0x1f20396e,0x0793b567,0x00645aa5 } },
    /* 30 */
    { { 0x126b8292,0x0725ab9e,0x0f9461a1,0x057e0068,0x0a3b60d5,0x0ec65aba,
        0x1895e0fc,0x1d9aed53,0x00dbe3f8 },
      { 0x19b642b8,0x0bee701c,0x03d69e75,0x063034ee,0x1a422511,0x141f66d7,
        0x1a9cad65,0x114c3415,0x009a73de } },
    /* 31 */
    { { 0x07ef03fc,0x1b3f2513,0x06eff404,0x1bad1084,0x13f885b1,0x0d65c711,
        0x10ca99e2,0x013720a1,0x00bcc0ad },
      { 0x0256ea88,0x0af40d41,0x020e9073,0x00268984,0x163002c8,0x11108186,
        0x079c0a64,0x06a4558b,0x00561e59 } },
    /* 32 */
    { { 0x04424a48,0x0e7a6171,0x1511c704,0x18e7dc6f,0x0488b843,0x1fe2b0bd,
        0x1872cc11,0x013c79f0,0x00f2a917 },
      { 0x1c3a60f7,0x02222108,0x19e45221,0x10f46c4c,0x1404b747,0x1e8329ec,
        0x1bc0457e,0x0cac4899,0x0070fd33 } },
    /* 33 */
    { { 0x1350a8ac,0x12d68d48,0x16a227a0,0x04fa88ab,0x12c5ea95,0x182e426f,
        0x07f2a55f,0x1353fe26,0x00506171 },
      { 0x0296a530,0x06ed4cc5,0x1ed6a7fb,0x15eb13be,0x069a14f5,0x08206424,
        0x165b0b47,0x114c82ff,0x008401cc } },
    /* 34 */
    { { 0x09853c8c,0x04dc6989,0x192c7172,0x1d8732b0,0x0b19154d,0x19d27961,
        0x0adccb12,0x1dde1082,0x004b4b9b },
      { 0x17ac6061,0x13e77354,0x0b0b0cc6,0x071fe6b6,0x1a0f6730,0x1ed2d481,
        0x0952847f,0x073d8875,0x00d8a0fa } },
    /* 35 */
    { { 0x16c18ad6,0x1965179d,0x1fbb63df,0x186988ea,0x0ca59fc2,0x0f14556d,
        0x01bef6fd,0x0d4df58f,0x00979a3f },
      { 0x10a130bc,0x1ef88662,0x08ef6379,0x1ec5b686,0x07c466a3,0x05084690,
        0x00a7f164,0x0b25d319,0x0066a7b0 } },
    /* 36 */
    { { 0x1ff39f50,0x15b4ef5e,0x0f35b525,0x1b0cbe9d,0x055cb2a3,0x0decc11a,
        0x0cc1bfeb,0x19aec9ff,0x00b1f617 },
      { 0x08cb5759,0x0f6b89e7,0x09b80680,0x0964b813,0x19e5e31c,0x19763bec,
        0x1218e909,0x021e8cc3,0x0049ee30 } },
    /* 37 */
    { { 0x012270de,0x1a338ddb,0x1c183292,0x0c0225bb,0x095dd0cc,0x02801d77,
        0x1cb75bee,0x1dd84891,0x00120d05 },
      { 0x1070c2ba,0x05b89a10,0x1012b6eb,0x03eeb255,0x19c656eb,0x08a582a8,
        0x05f9bd06,0x03276953,0x00af69c4 } },
    /* 38 */
    { { 0x04b11a5b,0x16c62cd6,0x0f6c7f72,0x0d1284af,0x0574d05d,0x1b1c6db3,
        0x0df08b5e,0x15261bf5,0x00d060d0 },
      { 0x00c8e41d,0x16e00817,0x08b97097,0x03052694,0x0fd21e47,0x09c66940,
        0x11c67568,0x1f9bfad6,0x00e47ed3 } },
    /* 39 */
    { { 0x0e30e491,0x187f0ba6,0x0051a297,0x08705c81,0x18ff1b66,0x038a2d71,
        0x00fe3853,0x070bd462,0x0021b63d },
      { 0x112036e2,0x1d436651,0x0ce7f8eb,0x1ef76845,0x061f21fb,0x0a307708,
        0x195d67e1,0x1de50125,0x0086565d } },
    /* 40 */
    { { 0x02d0b7ff,0x09d3c385,0x1e199d96,0x14edcac0,0x11639286,0x15250a72,
        0x18a00005,0x1b037506,0x00176e05 },
      { 0x0cd7f1c9,0x1759ce56,0x1ddfbca1,0x177e1c65,0x033f089d,0x1a0063fd,
        0x1815f9bf,0x0e080dbe,0x001a174b } },
    /* 41 */
    { { 0x0d69fcde,0x056068d2,0x02582b5e,0x1bebcd22,0x193535ae,0x1f3cc919,
        0x13859c40,0x058722a6,0x000adf98 },
      { 0x1bf326a6,0x0c7ec5be,0x0393e9ba,0x02cc9ea6,0x1a2a93f7,0x0013e82d,
        0x0a85ddcb,0x1cbb6cf1,0x005ecf1e } },
    /* 42 */
    { { 0x124bd676,0x17447484,0x17d7ea8e,0x054c28bb,0x0bde9c7e,0x1ad3ffa2,
        0x02583006,0x101ecc9b,0x009b16db },
      { 0x1c63dee2,0x1fa5d9e2,0x0f242e75,0x0fc19e02,0x092ed1e5,0x01ee6acd,
        0x15939a90,0x01098c38,0x00901515 } },
    /* 43 */
    { { 0x022ca5cb,0x039b41a9,0x02a30af0,0x177888a5,0x1a70e4b7,0x14dac848,
        0x0c0bcba6,0x0b595190,0x0002bdce },
      { 0x0c61cf3d,0x14869ad0,0x0064a78c,0x02a58868,0x0664f13e,0x16a80132,
        0x0906b2d6,0x12128fbd,0x00c8f83b } },
    /* 44 */
    { { 0x0325b5b4,0x0ba94cb9,0x03ca2e1e,0x0691cbb9,0x1c663da8,0x1b7fa611,
        0x04b3e2ee,0x10e43059,0x006a8708 },
      { 0x1800dd46,0x0a2e0bed,0x14bc123c,0x1590e47e,0x1b9fc5ea,0x04452c2c,
        0x02fb6816,0x195110f2,0x003a66e9 } },
    /* 45 */
    { { 0x19f902b6,0x1a2cb5f2,0x12467cdd,0x1679e638,0x09558c6e,0x0d9a22be,
        0x127278de,0x1d2aa999,0x003c86ae },
      { 0x19efa09a,0x1dbcf6c6,0x09a3034f,0x10c67d63,0x1d4c8109,0x1c4735bf,
        0x0ae1ba2e,0x181498fb,0x000a7fcc } },
    /* 46 */
    { { 0x1309ddff,0x029c6369,0x096c3c88,0x00de741d,0x10256802,0x1d395bc8,
        0x186cccfe,0x11556f10,0x00f80eb5 },
      { 0x158fc705,0x0503d59d,0x0d5e3fd6,0x1a3597f6,0x190f5043,0x1d667bf5,
        0x1baf2e48,0x1f03964d,0x00251a6c } },
    /* 47 */
    { { 0x050afc51,0x0c57ff1c,0x18dedd2d,0x1490fdf6,0x016b9dc8,0x03d9abff,
        0x0bea51b0,0x1011b04e,0x002483b8 },
      { 0x1c79f6ac,0x001343d0,0x11a33a31,0x1ed15572,0x0900f90e,0x165b3d47,
        0x17b81dea,0x11c1505c,0x0047e3cd } },
    /* 48 */
    { { 0x07c08a1a,0x0a9c2e32,0x0930adc0,0x1a7ce761,0x1f557928,0x074e53a2,
        0x1aea57d8,0x01d52d3e,0x00658467 },
      { 0x190948d2,0x06c979b0,0x0f8e1370,0x13931bd7,0x1a5859d7,0x01904b8f,
        0x1abdaf32,0x12c6de19,0x007793c2 } },
    /* 49 */
    { { 0x0d970f51,0x02ab34db,0x02308b7c,0x1678b31b,0x1ba68e83,0x19f84b42,
        0x0179893c,0x14a9469a,0x009a1653 },
      { 0x1e134e8c,0x144eeadf,0x15f88ad3,0x14bddb5f,0x062239cd,0x1915f943,
        0x1fa12760,0x0f915157,0x001b4328 } },
    /* 50 */
    { { 0x1aef42de,0x0ee048fe,0x1a75aeb3,0x02612e87,0x005af6c1,0x0b834054,
        0x07ccee2c,0x1255b523,0x00822097 },
      { 0x19d0b57a,0x1022acfc,0x0fbf230c,0x0f958767,0x05d446c2,0x077a055f,
        0x152698de,0x0970a6e9,0x001afa93 } },
    /* 51 */
    { { 0x13c2d262,0x1e120023,0x07687efc,0x1e0c1b88,0x0f63b3a9,0x17fff5a9,
        0x125112a5,0x026c03c7,0x00a466df },
      { 0x04901485,0x0d746c59,0x02b22142,0x086d67b0,0x0d93fcaf,0x18ac8287,
        0x017b2a0b,0x1fd21181,0x004be695 } },
    /* 52 */
    { { 0x144fdb3e,0x117007d1,0x1add6e7f,0x08ea1b57,0x0f79b560,0x14d83fbf,
        0x0577a7ae,0x125eae94,0x002ac3e1 },
      { 0x05cde112,0x0586eab5,0x1dfb76a6,0x1e01db27,0x1a370ddb,0x04cf6299,
        0x1e42c9fe,0x05f02c13,0x002002df } },
    /* 53 */
    { { 0x1c8978a6,0x022af9ad,0x1bae551d,0x01999d4c,0x108181d5,0x05ec4e26,
        0x1e3b7e93,0x0606a23f,0x00b52e8f },
      { 0x02efeb7a,0x16795bfd,0x14988cb9,0x04683cba,0x188e4582,0x009deacd,
        0x00d03819,0x057f5450,0x00cf119b } },
    /* 54 */
    { { 0x189f943c,0x04914053,0x150bbc55,0x111696e3,0x1dfc9fd7,0x0da3e86f,
        0x08816948,0x0715eda3,0x009bd240 },
      { 0x1f050a75,0x16d6aaa6,0x14f6a15e,0x0c73e406,0x06b4b72f,0x0443cc47,
        0x0d956196,0x17c5d3a1,0x006ff2c2 } },
    /* 55 */
    { { 0x1aff0b43,0x0c1175a3,0x0569c814,0x05bf12b4,0x0b00a9f9,0x0110995a,
        0x15af8da3,0x1c62819d,0x00036951 },
      { 0x05bea331,0x18af51ab,0x19724823,0x06497679,0x04ef7bf0,0x11dfe444,
        0x12ff6a57,0x0264f937,0x00d72c7e } },
    /* 56 */
    { { 0x0eee6b16,0x180fd4bf,0x1b60ff1f,0x0253a081,0x079a6cce,0x0cf89fe7,
        0x1a1324e4,0x1bd2dc13,0x008dafd0 },
      { 0x1c60c529,0x12ec824f,0x1f6dda75,0x076e20ab,0x0cfd1584,0x19f350d1,
        0x08b69be5,0x16f2e1f4,0x009f0dca } },
    /* 57 */
    { { 0x128aadf3,0x081067eb,0x1c2d1bfe,0x1b1e5180,0x1a432376,0x179898fc,
        0x0d209280,0x07e98ef7,0x00a9a6c1 },
      { 0x0b369b55,0x06f2e22d,0x16b24379,0x1196089e,0x0e8156cc,0x0970be40,
        0x0c004c61,0x0aa1ecf2,0x008504f3 } },
    /* 58 */
    { { 0x1a22cc5d,0x069fdf29,0x09af732d,0x00cf8fb5,0x1480f612,0x15adb180,
        0x1eb8a467,0x0bcdeb75,0x00423872 },
      { 0x18ae2dfe,0x0d7b4d16,0x1b6f4249,0x18d87e7b,0x1cf12992,0x17a1d27f,
        0x1b548cb9,0x068f7240,0x00e0ff26 } },
    /* 59 */
    { { 0x1f6a97eb,0x19cc70e2,0x0b82f248,0x18769342,0x1af63fee,0x14e860d7,
        0x1674b6c0,0x1dded635,0x00caf10e },
      { 0x08f02497,0x18aa726d,0x0b12e221,0x1531c2e2,0x09643ae1,0x0920a75f,
        0x017fd89f,0x1da50c2a,0x00ca4c47 } },
    /* 60 */
    { { 0x0ee1f8df,0x0ff8cace,0x08dab14d,0x027b87d7,0x00d4afae,0x16f3c7a5,
        0x1e596909,0x114c0db6,0x005019e4 },
      { 0x1628aa47,0x040a0990,0x17819777,0x1f0ae0b4,0x1b51175f,0x0cc44032,
        0x109a2624,0x014a2798,0x00788081 } },
    /* 61 */
    { { 0x0b8bbe28,0x16e26e05,0x11ae8d2d,0x1c93ca10,0x1fba75db,0x1d46749d,
        0x07fc6afa,0x1a554204,0x0071c0d8 },
      { 0x1ba1651d,0x1166293d,0x0e8ab933,0x11c99030,0x01e0ad32,0x0cb6b611,
        0x10d9e0da,0x192eb1c2,0x001a3181 } },
    /* 62 */
    { { 0x1224e28e,0x1e1c0f8c,0x1aec361e,0x04be0a6c,0x0afd88b1,0x0027bf46,
        0x15f33fbf,0x0ee0c75f,0x005bd734 },
      { 0x0a245316,0x068b4d58,0x013c13f3,0x19106522,0x1762fac7,0x08b21d63,
        0x1762c698,0x0e3e1662,0x004c80bb } },
    /* 63 */
    { { 0x03b9249e,0x1e3c18d3,0x0f6a5781,0x01e8b777,0x117e8e5e,0x1607efa2,
        0x15e6746d,0x00cd37a3,0x00d01cde },
      { 0x0a498130,0x16eb4d3f,0x146ad78d,0x0ca32708,0x13deddaa,0x06f6f256,
        0x06c2228f,0x037ff93e,0x0032c2a7 } },
    /* 64 */
    { { 0x002bde39,0x19cc9521,0x1aeae63e,0x13eac87a,0x12512254,0x032143b8,
        0x19402d59,0x168ffbcf,0x00d52442 },
      { 0x03d3e16e,0x1677e845,0x0eca6f69,0x129e1590,0x1ec8c5b1,0x16ec4836,
        0x1079b6c3,0x0b204ae1,0x007a0909 } },
    /* 65 */
    { { 0x1fab3d26,0x06b6736d,0x03b7c601,0x144476cd,0x050baf2a,0x0aabf831,
        0x19b7ae26,0x00e9281a,0x00ef6bba },
      { 0x178ca345,0x041bb1dd,0x023fdcad,0x0cf69e7e,0x092b2158,0x0db92de5,
        0x136e4489,0x0c693100,0x00ccead6 } },
    /* 66 */
    { { 0x18d49df0,0x19e09fda,0x00fd0f48,0x0aaa1ea0,0x0130f3d2,0x10514239,
        0x17bfdbe4,0x14628587,0x003b9507 },
      { 0x097ac7d4,0x0843047b,0x0136e620,0x19fb2177,0x053b9fe1,0x01126b0c,
        0x0e333cab,0x098d5c76,0x00ac6fe4 } },
    /* 67 */
    { { 0x042c8ed7,0x1a68a53d,0x022a11e6,0x0055f393,0x0a61f1ec,0x07b719ee,
        0x1e44e9bf,0x000e50a5,0x0031d28b },
      { 0x0eefcf6a,0x0344dfb3,0x11400b33,0x1cde4983,0x0179f835,0x1283b1b6,
        0x020dc5be,0x0d4c576f,0x002ec87a } },
    /* 68 */
    { { 0x087bdc21,0x1d77af42,0x0300c435,0x1f7aeb0b,0x1054f626,0x12868468,
        0x09963364,0x163a1062,0x0025a65a },
      { 0x1ec04e2c,0x0856003f,0x17c3d313,0x1e86ab1b,0x1d8a0859,0x0705818e,
        0x0676c756,0x0812c30f,0x009df8ab } },
    /* 69 */
    { { 0x03d44adf,0x07e652aa,0x1cba4393,0x0ded2ad7,0x1275d6ed,0x06b10fc5,
        0x07d7fe1e,0x0e908c8e,0x004ac007 },
      { 0x159b5eaa,0x0784482e,0x0139ceba,0x03d69f92,0x1c14cf96,0x14a1c20c,
        0x15b944a0,0x19f29c83,0x00591e7d } },
    /* 70 */
    { { 0x12bad284,0x06c873ff,0x17f86ab7,0x1661e70a,0x1c1e86a6,0x1c82460a,
        0x021e1587,0x062e9a29,0x003e06e0 },
      { 0x06db2203,0x1bd33d97,0x199af55d,0x16bd29a5,0x0f7b058d,0x06acdb2e,
        0x0d5ca37c,0x00f8c4c0,0x002dab3a } },
    /* 71 */
    { { 0x12792b23,0x199e39e6,0x1984e933,0x19f92a94,0x0b6f31f2,0x14356116,
        0x12e845d2,0x1602fe61,0x004ae01c },
      { 0x1ad7d330,0x183e0af5,0x1053f162,0x12b96876,0x1c68e532,0x1170c900,
        0x133d5540,0x185255b1,0x0007bce7 } },
    /* 72 */
    { { 0x0f71938f,0x0aff648e,0x100436e5,0x0de08879,0x01390617,0x138e6ae4,
        0x07e972fe,0x122e4828,0x00780408 },
      { 0x0211fcc4,0x0907cf92,0x15158467,0x0192d0d3,0x15005f5a,0x0c0dc9dd,
        0x0573eebf,0x0f61d2a1,0x007b9d8d } },
    /* 73 */
    { { 0x165cb6c4,0x1d03a39a,0x1ce3a1ce,0x188626fe,0x003e9f2f,0x1eb8c498,
        0x116c3b7b,0x0f79c916,0x00ce96d0 },
      { 0x05a3e43e,0x08c0fcb2,0x19d7e027,0x181325cd,0x10bab4d1,0x161c7678,
        0x0a2cd947,0x1f82f3a9,0x0060fa83 } },
    /* 74 */
    { { 0x1b2f8c7c,0x12ff504e,0x19eebf65,0x082103ee,0x02017c05,0x07f81606,
        0x08219f69,0x0d5c851b,0x00472c55 },
      { 0x1c717933,0x02e59053,0x177e282e,0x088ef81b,0x0ba3788d,0x0befc458,
        0x0b570d80,0x06c58c2c,0x003412b1 } },
    /* 75 */
    { { 0x1a26cf67,0x01099f83,0x0fb5b118,0x1f468a1e,0x019be231,0x1f9c97bc,
        0x06e6a060,0x1619881c,0x00f403dd },
      { 0x1d14746e,0x11888ec7,0x0a925e18,0x03a36ff8,0x1e2be4ed,0x1717285e,
        0x12352f0a,0x1efbacc2,0x0042cc90 } },
    /* 76 */
    { { 0x1471c5c7,0x0721196a,0x11a6a74b,0x1098de6b,0x1117e90c,0x13ab77f6,
        0x0c155ed6,0x055bdce6,0x0089a7a6 },
      { 0x1e5add63,0x14f46710,0x1c016c07,0x04167f2e,0x1c97747e,0x17aefb0e,
        0x1a677910,0x12bb5fa2,0x00e8222d } },
    /* 77 */
    { { 0x1b21173f,0x1f8b55b7,0x0c8cc804,0x0a0ac427,0x1c5887d6,0x19b4c01e,
        0x0097f4d7,0x0d56d84c,0x001ff199 },
      { 0x1e49ae4b,0x099220e3,0x1534acd6,0x1b195b83,0x19a86e58,0x1757380f,
        0x0b2ff09a,0x1ca704da,0x00f3043f } },
    /* 78 */
    { { 0x1eb74735,0x13e30385,0x005a0274,0x1e92c476,0x1a491662,0x10e27fff,
        0x09a3cbe0,0x0551bc11,0x00e80d0d },
      { 0x1152be84,0x123c1bc2,0x05020101,0x16e14c9b,0x09581e65,0x05649fb9,
        0x01a16ce4,0x1c827614,0x00b39a11 } },
    /* 79 */
    { { 0x0dc47a03,0x14a1f447,0x18f47aef,0x08008902,0x0fc25db0,0x0bce2016,
        0x02b5d9cc,0x16d0b1d4,0x00a7842f },
      { 0x03a823a2,0x0a4b9b4e,0x1681521a,0x07aa9fd7,0x163f48af,0x0f2ab591,
        0x161a25d7,0x1d8e0f54,0x005e931d } },
    /* 80 */
    { { 0x005f0ed8,0x12a6f374,0x0b51c21c,0x1a3af20b,0x1058ee0a,0x122ad19c,
        0x055fcc84,0x1f306971,0x00f176c2 },
      { 0x1162ff84,0x12153494,0x098a3a1a,0x06f56bd5,0x055e17af,0x0d5406d3,
        0x1edb9981,0x1b3379ce,0x00840eab } },
    /* 81 */
    { { 0x1891bf80,0x0f154105,0x13f54f05,0x11afac7b,0x0f5d6f21,0x1dc8e1aa,
        0x102c2cfe,0x040c1d8d,0x00d2907e },
      { 0x0a8c701a,0x1d2c26ea,0x00a795ca,0x1f51653f,0x0e8351ed,0x071bf99e,
        0x065d20ba,0x102eb60c,0x004f8b75 } },
    /* 82 */
    { { 0x1fbe555a,0x1f4a883d,0x0ce1470a,0x0df6fcef,0x17f279b7,0x18a418c5,
        0x049afac0,0x1d701fbc,0x00425194 },
      { 0x0996474b,0x04d1c351,0x07b4c512,0x1be35f9a,0x0380c318,0x08ee403e,
        0x189b8051,0x15654717,0x00c0dfbd } },
    /* 83 */
    { { 0x0043ce80,0x02d02de2,0x18271433,0x038fb851,0x1ee6b410,0x17b48d5a,
        0x0fb33b05,0x1c07e05f,0x006e0539 },
      { 0x17b36485,0x01b73352,0x12345177,0x0aa4c5cb,0x068af07d,0x051c8820,
        0x1246b9d5,0x16e388e0,0x00c47aef } },
    /* 84 */
    { { 0x08e761ab,0x0f81cfc2,0x16c26430,0x1b247949,0x0216cb75,0x1fe0c2dd,
        0x1373fa3f,0x10ec8ccf,0x005f193c },
      { 0x18ed1f3c,0x07179ae3,0x0a4221f7,0x176b3cef,0x1ca7182c,0x1b1a290f,
        0x107c31ae,0x1d11af22,0x00bf0b44 } },
    /* 85 */
    { { 0x06fe11e5,0x01278aee,0x0897bcf1,0x0cd49233,0x113341e8,0x07496dd9,
        0x040d066b,0x08248115,0x001bd3b4 },
      { 0x0ad2225b,0x1db11806,0x0812e106,0x1699579e,0x09aa644d,0x057d6691,
        0x0e127f3c,0x1db98924,0x0038d13b } },
    /* 86 */
    { { 0x1e4fb378,0x1ecd08a2,0x123a535e,0x1cb5cd43,0x18b0a56b,0x0f2097d0,
        0x1a5a4c8b,0x0fcb55f0,0x00983fb4 },
      { 0x08cde8ea,0x19731249,0x1c3400f4,0x0a4cfa57,0x1b4e8c23,0x0f4482b8,
        0x0127ef15,0x0df7ac0a,0x00d11905 } },
    /* 87 */
    { { 0x05729482,0x18b632cf,0x06cee1a6,0x057ccfe5,0x1f6f34b0,0x1725e776,
        0x1804d9c0,0x016d8047,0x00f51895 },
      { 0x001c7886,0x15a9b786,0x0ec4862c,0x009e8c12,0x08364997,0x04703bdb,
        0x0715402b,0x0f12463d,0x0065f724 } },
    /* 88 */
    { { 0x0bb602b5,0x1ffaa2de,0x0104eaec,0x1ca2297b,0x1352a566,0x1ecc25ae,
        0x1b4ba6bb,0x1501e8af,0x005bae49 },
      { 0x111d8800,0x1f234adf,0x13b09741,0x18a96dfa,0x1067101a,0x0737695b,
        0x17535991,0x0bc3b0c0,0x0028bb3e } },
    /* 89 */
    { { 0x09044ab8,0x1d8c43f3,0x0d3cc2f9,0x008966b9,0x19891933,0x1bd2eebd,
        0x0885ea94,0x131e33e6,0x00420727 },
      { 0x051f50d8,0x1c14bf1e,0x1e4394da,0x03dbf9dd,0x070595b2,0x0a8f7f2e,
        0x06fb2d5e,0x1f7f56b0,0x006d2d15 } },
    /* 90 */
    { { 0x1d33b0b6,0x08737c1a,0x15cf30da,0x0a59b72b,0x1ebf4bb4,0x153e1be7,
        0x07398baf,0x04e63279,0x009035b6 },
      { 0x00f4d7b7,0x02293cf2,0x1cca6e97,0x1acea651,0x0993d799,0x04cf9afe,
        0x10741ef1,0x17001349,0x007d579d } },
    /* 91 */
    { { 0x1cbe4314,0x17772bec,0x1613e689,0x17e35550,0x01946b5e,0x127446d9,
        0x14237fa4,0x030dbc5d,0x007c2f8c },
      { 0x02204329,0x152b6443,0x05c2b39c,0x15e25bfb,0x137160e5,0x11766193,
        0x03dce469,0x1db1d241,0x0011796f } },
    /* 92 */
    { { 0x04c0138c,0x0e0e80a3,0x1100f176,0x17898835,0x120f30f1,0x063329bf,
        0x19fbb7a7,0x1c9e3a80,0x000814c5 },
      { 0x0e58bd95,0x1027211c,0x069c8c7b,0x0c5d0df9,0x1df12cd2,0x05b65dc7,
        0x174228b2,0x16102d31,0x00772a46 } },
    /* 93 */
    { { 0x1b35551e,0x1add2b6d,0x0f0eea6e,0x0097eacc,0x192fa07c,0x124f609f,
        0x02989963,0x1e0960a5,0x00d8002b },
      { 0x0e19feae,0x0d2d227b,0x0be16f79,0x059063a6,0x06a5d518,0x0b1f1799,
        0x1aadce45,0x16620878,0x00c04b58 } },
    /* 94 */
    { { 0x198d1a35,0x1e58cabe,0x16b97b9d,0x142f31a5,0x024c175f,0x1dfb6ed8,
        0x1cd484e1,0x0900afaf,0x00b3706b },
      { 0x0d7e2ad4,0x1676f9c8,0x0acf82bc,0x0e0ef04b,0x0c8be09b,0x15fec92f,
        0x0d7d9fd3,0x1dbbf949,0x006ffb26 } },
    /* 95 */
    { { 0x1ae85738,0x0a923145,0x0c5ae43e,0x13e9d5ba,0x0d782869,0x18880e37,
        0x0f876343,0x13cfcc1f,0x00417588 },
      { 0x0c11b1cd,0x17f9ef7e,0x17a50a2a,0x0efff01c,0x0d76e871,0x033c8149,
        0x1d5b473b,0x15f0e647,0x00dbbaba } },
    /* 96 */
    { { 0x0fe9099f,0x1134b74d,0x1ea49721,0x12be2a80,0x01f954f6,0x198516d7,
        0x12c61c07,0x0c3e8bc9,0x00f984c5 },
      { 0x0ebb4441,0x1d7f70e3,0x166b5153,0x12dea7f4,0x055c7fbf,0x1c37105d,
        0x08f694c2,0x0f721c08,0x006efa58 } },
    /* 97 */
    { { 0x17bdf0b3,0x11aadff5,0x18e53f2f,0x0521fd00,0x0e8f1f1d,0x10432b64,
        0x07cfd45e,0x03a13660,0x0032756a },
      { 0x13704c72,0x13f0fd9c,0x11c47a43,0x1d7543a5,0x0c5995a3,0x0a9749b7,
        0x00daba9e,0x11c8ca42,0x00449367 } },
    /* 98 */
    { { 0x125ca4c6,0x00b0fb6a,0x125babb9,0x0d358369,0x138db1b9,0x0b2c6381,
        0x1c4be65d,0x0dd411bb,0x00a064cc },
      { 0x1c73ca8e,0x1a1c61f0,0x0979ec36,0x1587e390,0x1f59a0ee,0x01eca32c,
        0x0c721d24,0x1821b30e,0x002270c0 } },
    /* 99 */
    { { 0x016a8f1d,0x0410de5d,0x123da943,0x1385d30e,0x11a9ab55,0x0076744c,
        0x1d635eb4,0x15f31f44,0x0056cc2c },
      { 0x1185924f,0x0d04a035,0x036bde9a,0x1c30e001,0x181d1d56,0x18b43415,
        0x0b4068c1,0x1ed4d4e2,0x00b51075 } },
    /* 100 */
    { { 0x02da577d,0x1fb9bafc,0x1687ea1e,0x03ab085b,0x1bd96f19,0x1ba0054f,
        0x0e401a9c,0x0975b8e6,0x00a81aa0 },
      { 0x0627446c,0x13bd9d60,0x0f022ddf,0x0c430d71,0x025604e6,0x18deefd3,
        0x034e0c56,0x1fac32cf,0x00912ba4 } },
    /* 101 */
    { { 0x021bda2f,0x1312273f,0x092b41ea,0x1d8faf9d,0x0a4ae82a,0x131fc97c,
        0x0cbe8e47,0x153db520,0x000811b0 },
      { 0x0c1e7599,0x1c639498,0x0da872ee,0x0630cab8,0x083c602a,0x078d320c,
        0x0d4af805,0x0c422da0,0x0098c6cb } },
    /* 102 */
    { { 0x01df225b,0x18ecf295,0x1bf7670c,0x1615d2ff,0x1af11133,0x1b2f14fc,
        0x10cf000f,0x0f3bbe02,0x00ad8848 },
      { 0x04af26ff,0x130f17b5,0x1bfc64dc,0x1296c43e,0x040cf57e,0x126a0d65,
        0x1ced1902,0x1de78b9a,0x00bb2ca6 } },
    /* 103 */
    { { 0x0664d8b9,0x1edb9e5a,0x0c0a187e,0x18482464,0x014c6403,0x0731035c,
        0x07f64003,0x12b9a754,0x0028ad9c },
      { 0x1d012d1d,0x022c2c18,0x03bbcebf,0x109870bf,0x19d464d7,0x02b66742,
        0x0df0575d,0x13b1fbaa,0x002002b7 } },
    /* 104 */
    { { 0x18ff29ca,0x14d4741a,0x12997e49,0x189eecfa,0x17f21b49,0x19fca022,
        0x1e71d608,0x14923948,0x00149755 },
      { 0x00cdad3b,0x1902411a,0x17d750a7,0x1f44021d,0x1c0a952e,0x00953421,
        0x0d1f833e,0x0a2bdc27,0x003e9b4d } },
    /* 105 */
    { { 0x1851bb43,0x0392e220,0x157d3156,0x1735fb63,0x1ed22d6a,0x0b6722b0,
        0x1fc7311f,0x0f289f7c,0x0036e925 },
      { 0x18e47086,0x0eacafbb,0x148d4ca7,0x0841c819,0x066e8b90,0x09bf45eb,
        0x0b993bb2,0x152190a3,0x005fda90 } },
    /* 106 */
    { { 0x1e3ece65,0x06c3f21f,0x1447c67b,0x140fda5c,0x095e42c4,0x051995e4,
        0x1e0c33bc,0x13903636,0x005a4e67 },
      { 0x135bef34,0x1abb8b3f,0x06a62b3f,0x093510fd,0x02034fd9,0x1b4d4172,
        0x126bb366,0x133c1464,0x003960b9 } },
    /* 107 */
    { { 0x141a4ca7,0x031a2989,0x0f123aac,0x165ee8ca,0x011b9a97,0x069af029,
        0x1ffff9ff,0x0345f512,0x003abfb6 },
      { 0x167a9b8f,0x0332b8a5,0x1c7dc831,0x07e6e9a9,0x1012877c,0x017c3cf4,
        0x0827aa22,0x0cba201a,0x002a2012 } },
    /* 108 */
    { { 0x1fd9fe05,0x060ae84d,0x191152bd,0x0a4d3e6e,0x0ee9ebfd,0x1adcafde,
        0x08f5d5cd,0x08c60933,0x00d64872 },
      { 0x0dd0e3df,0x057750c8,0x0cb06135,0x08efe733,0x16787dba,0x138e23b7,
        0x0fb7fea5,0x1e465a39,0x00404358 } },
    /* 109 */
    { { 0x05ba70a1,0x004b2b42,0x100a11a2,0x04bb1daf,0x19c61c10,0x06bd0873,
        0x1c74401c,0x1cd98a3a,0x00da5545 },
      { 0x136071a4,0x10802c96,0x0e12d9a1,0x1f2d7a59,0x1a3ae7cc,0x160a4f84,
        0x17ee3013,0x06be0f88,0x00902636 } },
    /* 110 */
    { { 0x15a02c24,0x0010d378,0x1170fadb,0x1b21ad66,0x0cb58d8f,0x187c31a3,
        0x080137ba,0x132518c7,0x008e319f },
      { 0x1fbe9596,0x132e4479,0x15fcd8ab,0x08244c58,0x14cb4cd4,0x0cd9bbc3,
        0x1fd2d247,0x02f9453d,0x001a6cc2 } },
    /* 111 */
    { { 0x02b02298,0x0d24c69c,0x120707e0,0x069a32e1,0x009e1719,0x19a9e830,
        0x1a2eac92,0x06254206,0x00270bad },
      { 0x1acf8d51,0x12c5f018,0x1fa43fd2,0x00a33d2d,0x0bad7e9f,0x09b9b516,
        0x1147dd2c,0x173a0a02,0x00558377 } },
    /* 112 */
    { { 0x01f8c84b,0x1bd6798b,0x11e8c443,0x0e583cdc,0x1f8c6a5a,0x148721b9,
        0x05505b09,0x142b3a07,0x00c05d2d },
      { 0x0c7e9247,0x011862a1,0x054c775c,0x1b262f9d,0x1f78ec29,0x1077c878,
        0x15765a0e,0x10aa0a6e,0x007dd05c } },
    /* 113 */
    { { 0x1935116f,0x14f99616,0x15429ccd,0x0d85d250,0x179b6f77,0x0d84e2ea,
        0x0b79f912,0x1b042f4f,0x002caffe },
      { 0x17ca913f,0x07f61fd8,0x06f7f92b,0x124c6253,0x1bc6e1b5,0x1130545d,
        0x1b716005,0x1f9521eb,0x006ab392 } },
    /* 114 */
    { { 0x0ccceecb,0x026964e8,0x1c1659e4,0x005f3fa0,0x1ef3c891,0x00c9c409,
        0x0cd744bd,0x063effca,0x002ec8a8 },
      { 0x136d8979,0x1070b3a3,0x015269ad,0x0b26d760,0x085eb911,0x168ad320,
        0x081f7d3c,0x0aa1ee54,0x004517fa } },
    /* 115 */
    { { 0x1807c6e6,0x14b325cd,0x11693189,0x1e47695c,0x11c1431e,0x1704f1bc,
        0x021f881d,0x0cef4707,0x00b8c4f5 },
      { 0x1c149a92,0x018f10e5,0x09e1efaa,0x0d8787a7,0x1d766a4e,0x162be1ff,
        0x02f03ac9,0x1ecef2dd,0x00a9f8c4 } },
    /* 116 */
    { { 0x02df4bf3,0x077e685e,0x088ccefb,0x1843cb59,0x1fb04f34,0x04ebee91,
        0x0b22fd2f,0x0895df51,0x008188fc },
      { 0x0d27e4ff,0x1cc54984,0x1794a0a3,0x1ea496ad,0x1a693176,0x19a1329d,
        0x0f0eb0d5,0x1a98f22f,0x001184e8 } },
    /* 117 */
    { { 0x1ec27426,0x0cf84061,0x13d86360,0x067a6862,0x058821bf,0x1e1302b0,
        0x1af16761,0x1237ce91,0x00614c50 },
      { 0x0b12648e,0x1f60de5b,0x1ab5c4ae,0x0eb56163,0x1376d845,0x1e4ab93f,
        0x0b5c3559,0x131ad136,0x00f71386 } },
    /* 118 */
    { { 0x002936dd,0x050adc28,0x1fc4a796,0x166b8b0b,0x0679f32d,0x0c2f963b,
        0x174c7217,0x17b0412e,0x001c4e12 },
      { 0x1a93eaa8,0x1e024b23,0x19d9d123,0x174850c6,0x0293ff3a,0x19fd0826,
        0x01c41fe9,0x001311a6,0x0090c825 } },
    /* 119 */
    { { 0x1bff4eff,0x0457aabe,0x10fe85d3,0x180e5b2f,0x09630c63,0x1b5a084a,
        0x15157dc9,0x01c5d504,0x0034db1d },
      { 0x0950c2ce,0x14173ed7,0x118774d4,0x10820b99,0x0882ec05,0x072065a4,
        0x1f6734d9,0x09d88ce2,0x0062e3bc } },
    /* 120 */
    { { 0x14d76e8d,0x04d69837,0x08a82fb7,0x0d0fb972,0x1545337e,0x07f4effd,
        0x054741ab,0x1202c723,0x00c85252 },
      { 0x0c8601a9,0x06f2467e,0x0dccdccd,0x00f16eb1,0x19fffc4f,0x004b145e,
        0x1358a8f3,0x137dfa26,0x005bec70 } },
    /* 121 */
    { { 0x14d0a639,0x12255d6f,0x184ae953,0x193221fc,0x18c0cbb4,0x0da09872,
        0x1a6aacb9,0x14a7d001,0x009a6a2f },
      { 0x0ca0d01c,0x0e62bc41,0x0897567d,0x08254313,0x1baa73f8,0x14f0229f,
        0x0ad92e95,0x105c0c53,0x009e33bd } },
    /* 122 */
    { { 0x01613f97,0x07f4abe3,0x15a532f5,0x1d3bbfe6,0x1f9c2b86,0x05cd5053,
        0x12b195c0,0x17f4f13e,0x00349a4d },
      { 0x083553c7,0x1b5be7c2,0x1f7fc960,0x1e1cabc0,0x1b8e4e41,0x13894245,
        0x1ea39c72,0x1798014f,0x00625b33 } },
    /* 123 */
    { { 0x07068002,0x1a0fa2d6,0x0bfed8ef,0x170c5ef1,0x007fb9f4,0x1868ff99,
        0x138948fc,0x060e4256,0x00af6534 },
      { 0x1d9269e3,0x0ad8c7b5,0x0edced16,0x184a54b7,0x1044d0dd,0x1a5411c0,
        0x0aaed658,0x0e989be3,0x0072550c } },
    /* 124 */
    { { 0x0997b745,0x1a756a0a,0x0adda603,0x1c8d8b01,0x19bf1ab3,0x0aad42b8,
        0x0f4f8043,0x0f7ce609,0x000fe966 },
      { 0x04eae3c6,0x10895052,0x120229e3,0x19c1eb14,0x0d57dd30,0x1c18ae19,
        0x1870feb1,0x0a592ba1,0x001e4b21 } },
    /* 125 */
    { { 0x04a0b46c,0x035c42c3,0x08039a67,0x1824a7d8,0x142ce6a3,0x0b9fd3a4,
        0x114b6c39,0x00e4afba,0x001ef646 },
      { 0x09b9b886,0x1f7e972c,0x1cf7e6ec,0x0dbd0e9d,0x057e0204,0x1e770885,
        0x0e712e0d,0x088f3e62,0x00c8b427 } },
    /* 126 */
    { { 0x0cd31b38,0x0abfa6f7,0x1ad0f9bf,0x08c63728,0x1e71a506,0x10741f93,
        0x16d17dd6,0x1350a739,0x00b98d15 },
      { 0x06fc3042,0x00e5783a,0x0bb0ff65,0x09c47f0c,0x0a175b0e,0x16597ee3,
        0x0dbd8df8,0x1086b138,0x00524255 } },
    /* 127 */
    { { 0x03fb7688,0x005f707b,0x0b448cee,0x07ba082d,0x1742f4b0,0x0333ef55,
        0x00a2caa8,0x05afac44,0x003af71b },
      { 0x125b4531,0x055285a3,0x0bd7a253,0x0685d811,0x1438abb4,0x1d4e9e3b,
        0x15d4ad87,0x073b615e,0x0001d254 } },
    /* 128 */
    { { 0x025dfad3,0x1a7132de,0x0fd12db9,0x0c617292,0x0d473d03,0x04495feb,
        0x064acc9c,0x08638bdd,0x005b2d95 },
      { 0x036f7c5f,0x15ca29bd,0x0c2e077b,0x1f803b15,0x145e59be,0x0d840c45,
        0x122d20f3,0x16e03c8c,0x0044c753 } },
    /* 129 */
    { { 0x124195ac,0x1cf7216c,0x1b1b085d,0x19ad4019,0x1d34344c,0x1c37108d,
        0x09b86837,0x04f4ff90,0x002f73a6 },
      { 0x1d4b2fac,0x1ce4ebe6,0x08fdc2c5,0x1be966cb,0x10b3de09,0x0c753193,
        0x1c085a6d,0x140ae42f,0x005934a0 } },
    /* 130 */
    { { 0x1471c90d,0x04482dff,0x17a52dd2,0x0bb9ea61,0x0ea8f2fe,0x134c410c,
        0x163fbd0d,0x1d0f3caa,0x00986125 },
      { 0x0ce9c497,0x12ce0bd1,0x16ad2c4b,0x03e1c43b,0x15218813,0x17539001,
        0x07910236,0x11da808d,0x00cd7179 } },
    /* 131 */
    { { 0x0fe2e160,0x01feb290,0x0f3e13cf,0x1f02460b,0x1f451569,0x1874a8a8,
        0x17b008af,0x1e958508,0x00054574 },
      { 0x1524a547,0x18bc29ee,0x15b9ec2e,0x16de4e67,0x10a83bf1,0x1792ea68,
        0x1f9d75c6,0x071d15c6,0x00d4cfa9 } },
    /* 132 */
    { { 0x043e3cb6,0x11cf1b24,0x00494a36,0x13471ac3,0x02e0af25,0x1728abc3,
        0x104e5244,0x0945d2f1,0x008142ba },
      { 0x044620d5,0x01a46dc9,0x1b201d2e,0x1f20a748,0x0346ee67,0x0dffd0f3,
        0x1cf486ae,0x0e0c9e36,0x00044157 } },
    /* 133 */
    { { 0x14019e33,0x01aaeac3,0x189b4975,0x18364431,0x1876fdb1,0x13eb7548,
        0x0fee68e6,0x1e1de5b0,0x00c1d29d },
      { 0x1cfaf04f,0x11bc0904,0x0e997bbc,0x09697786,0x04c6b5ca,0x068a629b,
        0x19994a79,0x1a017386,0x009cd549 } },
    /* 134 */
    { { 0x0d561bbc,0x0d65c120,0x0f3b4c9f,0x185fa2ea,0x1b0377c7,0x03abf9d7,
        0x095765dd,0x0e21adc7,0x00213fe3 },
      { 0x10d4f212,0x169ec6aa,0x19968e29,0x18150330,0x0518a674,0x076aa795,
        0x0d4c44b8,0x17f1f204,0x001b995a } },
    /* 135 */
    { { 0x0f049d2f,0x035c6910,0x09096be8,0x0ec765dd,0x1b012415,0x1825c028,
        0x0b8009ec,0x07fdea37,0x00b8cdb4 },
      { 0x17109f5c,0x09708ff6,0x06340bd2,0x0f7cbae5,0x19a120b5,0x126231a7,
        0x0c9bbb68,0x0522b25a,0x000b0aab } },
    /* 136 */
    { { 0x1d0ad6b2,0x05246468,0x0e118d69,0x12dc97bc,0x1e3243b9,0x107f0cdb,
        0x156c2756,0x1cbdf580,0x005847aa },
      { 0x00c3770e,0x158b13fd,0x10d3a0bd,0x164ce0df,0x0de6237c,0x1bfdb607,
        0x0167f72c,0x11a5469c,0x004e4129 } },
    /* 137 */
    { { 0x1a3b63ad,0x058271b4,0x0c8c18e1,0x0756a778,0x05b9a835,0x1f656002,
        0x00a01a61,0x1108de8b,0x00b461ba },
      { 0x05943ccc,0x1bf7833f,0x1137a474,0x06cc4b9b,0x0c769e5d,0x14e98125,
        0x0e753dca,0x02e791c5,0x000ad61f } },
    /* 138 */
    { { 0x15c95125,0x08a7ee45,0x0d066054,0x06f70d92,0x14fc0576,0x035e9cdb,
        0x1906d99e,0x17c4616f,0x00c9e138 },
      { 0x1e050283,0x1e36aff6,0x02680f82,0x0e8747ac,0x024f0a7c,0x0f8958d7,
        0x19a048cf,0x1d8afb72,0x00b2ea42 } },
    /* 139 */
    { { 0x1363c862,0x1cdc4200,0x092dc5e7,0x0a166073,0x0216d9a8,0x1b93fc3d,
        0x0832bbfe,0x0f367b33,0x00754cb2 },
      { 0x1ade742c,0x03734a35,0x0fa91981,0x0d349e76,0x02b1c056,0x095d11d5,
        0x1f87190e,0x13bfae29,0x00a21827 } },
    /* 140 */
    { { 0x035b46aa,0x101ecc21,0x06756890,0x1e18e3c4,0x1a535b35,0x14d91e2d,
        0x0b2a4e90,0x0ef22235,0x007eefbb },
      { 0x045d8760,0x1dcc811e,0x18e4e219,0x0f0ca879,0x14ec0a0f,0x0c80edf9,
        0x18e2abec,0x1165b9da,0x0049498c } },
    /* 141 */
    { { 0x19e4ef46,0x07ae6454,0x1c352c65,0x03ccce1d,0x09f14332,0x01127fdc,
        0x08836cb4,0x0073a0d3,0x009bf748 },
      { 0x0f1c1f1e,0x126b589a,0x18b74569,0x02050a42,0x023251ab,0x1504d3ba,
        0x1f05f1fd,0x05b9047d,0x00c5a908 } },
    /* 142 */
    { { 0x1d087141,0x09fdb3c9,0x16dffd4e,0x05265bf7,0x0c9d3e87,0x18d125d3,
        0x182c86ff,0x1452f5ae,0x003193de },
      { 0x10c7e145,0x172d3a08,0x0124efc2,0x19e85363,0x1111e9e7,0x1fd0e438,
        0x1ce6828e,0x1d5b4219,0x00322f34 } },
    /* 143 */
    { { 0x0e32db92,0x011baee7,0x1be3ad12,0x005a0282,0x1a196a7e,0x19608025,
        0x1c54893e,0x02d8c910,0x00165f5f },
      { 0x11125e78,0x056b8dfe,0x15731193,0x0363e86f,0x065aff7a,0x0ff0f7e8,
        0x179ed52a,0x161b7f7c,0x003a954e } },
    /* 144 */
    { { 0x1f76620a,0x0fa5321f,0x08cc0d11,0x07226630,0x0e0abdb8,0x15f7575e,
        0x0f62ddde,0x1ad72c3c,0x00e610de },
      { 0x17bc0322,0x047c2eee,0x0f3e21e1,0x1d8c9e0b,0x1ed9864d,0x1ef842e9,
        0x0fe0cbd0,0x13415f29,0x002e150e } },
    /* 145 */
    { { 0x07de998e,0x048632c6,0x024dcf56,0x1148746a,0x10312c41,0x0dd7be94,
        0x18a81198,0x1b5a9e6e,0x0087a24b },
      { 0x0af8e73a,0x123249ee,0x1d6e834e,0x179c9348,0x15fe6694,0x0b370fd1,
        0x12b26bdd,0x003af792,0x003ee196 } },
    /* 146 */
    { { 0x1fb0faec,0x1f904f76,0x1bb25dd6,0x1d50e314,0x09727514,0x0f876825,
        0x0c4e56dc,0x0edb692c,0x004650bc },
      { 0x18184292,0x1663ac6a,0x06b3aac8,0x1a87f3d9,0x10bb7152,0x1037048f,
        0x19e52d1d,0x1de36fa9,0x006da270 } },
    /* 147 */
    { { 0x135c7726,0x1738115c,0x0bcbeb13,0x1cf76fa3,0x1e72f2f7,0x1aca7efc,
        0x0b61568b,0x06029716,0x00edf46a },
      { 0x0dc3292f,0x0fdd3006,0x11bda939,0x0a9474b1,0x1369e04b,0x0e0b5811,
        0x06b4498f,0x1bb7f874,0x000ac721 } },
    /* 148 */
    { { 0x07351b84,0x1170ec89,0x0e91d6f9,0x13a4729b,0x092195c9,0x10682b3e,
        0x0a6db2bf,0x054a831c,0x008db1ed },
      { 0x0729b5e4,0x16a709b7,0x1409250d,0x0298f3da,0x095070c7,0x1c69fa40,
        0x09e48354,0x1f761640,0x00c187d5 } },
    /* 149 */
    { { 0x11ad0a16,0x06508672,0x06de011a,0x01b648cf,0x1aa04315,0x0b52dd92,
        0x18883a52,0x04358121,0x0071237e },
      { 0x0454f658,0x1c88d95c,0x1261d0f4,0x1917c732,0x0a08eb4c,0x07dd7353,
        0x1658fbb2,0x00b13a80,0x00323025 } },
    /* 150 */
    { { 0x0d144097,0x04c58235,0x1222c6ba,0x14dff049,0x079aec5c,0x1acdc67a,
        0x04027406,0x1552422b,0x005ecd93 },
      { 0x01716de7,0x05a58ec3,0x15906d7d,0x163c0eb1,0x13a12187,0x0462e51f,
        0x1460f1a5,0x019dcfc2,0x00384124 } },
    /* 151 */
    { { 0x09f16249,0x0ade0b53,0x16c5441f,0x0646a1bb,0x03cc9aa9,0x08823b69,
        0x03af977d,0x00d76120,0x002f2a13 },
      { 0x099413cc,0x1ef9823b,0x0e536527,0x079a604c,0x1646171f,0x1d462c9c,
        0x1feab48b,0x1788d3f7,0x006c6253 } },
    /* 152 */
    { { 0x1e33c180,0x1cfde1f0,0x178f8e2d,0x1f72c6c2,0x11e5e754,0x041c1b88,
        0x1eee8e90,0x00893eea,0x00d8780e },
      { 0x0545fb38,0x1ca0d08f,0x15508c6e,0x174436ab,0x0068d227,0x0d39e7e6,
        0x09dd7603,0x0f7cc01c,0x00d3b055 } },
    /* 153 */
    { { 0x195a7415,0x032927aa,0x1e96480a,0x1b9bf8ca,0x1845c1e8,0x17d48a3b,
        0x0ee8135f,0x1ee2fa56,0x0086bd1a },
      { 0x06b56786,0x07419e38,0x004c2c82,0x00f6c205,0x1001dff0,0x10413702,
        0x04abf2bf,0x0aa6ffc5,0x0041556b } },
    /* 154 */
    { { 0x0baaa8ff,0x0ee9c0c8,0x0f146fbf,0x0da2f68b,0x0f8a9d91,0x103d3543,
        0x1247e606,0x0d16586c,0x00231115 },
      { 0x1a2059ab,0x0b147d06,0x1cd3fa94,0x06fdd145,0x1894c625,0x11c5186b,
        0x19efcd33,0x1bb2cfca,0x00c464b9 } },
    /* 155 */
    { { 0x0fd5fc85,0x1272ac93,0x178dd043,0x1d8bd33a,0x1d025ccc,0x1d6f7c1a,
        0x0970f0a5,0x1f024a10,0x0040e40f },
      { 0x1953cfa2,0x00907678,0x18c984f5,0x18b6c80b,0x1e373295,0x18e07747,
        0x17f03ad4,0x0e0fd462,0x005c4d24 } },
    /* 156 */
    { { 0x118fd269,0x1aa1ca34,0x042e3b9c,0x1b2fbaf8,0x19bb761c,0x13c0afe7,
        0x129d7e23,0x01c998b4,0x00ce83e7 },
      { 0x1d845599,0x048c23fb,0x14a92b12,0x0566e7c0,0x12c5db1a,0x1c877b49,
        0x0591a65a,0x0e10244f,0x004e53f3 } },
    /* 157 */
    { { 0x15856253,0x09adc75a,0x0d197d48,0x13dd168f,0x090acba1,0x08d08dc0,
        0x15aa38ae,0x17ef0afd,0x00f80bb6 },
      { 0x13d12c59,0x1409b30b,0x11667982,0x151c238e,0x0a2dfa75,0x171f66d1,
        0x118eb423,0x00590f58,0x0070d541 } },
    /* 158 */
    { { 0x09af46ff,0x19b2c27a,0x062f3a59,0x1a01de5f,0x13b91096,0x0ca12709,
        0x13addfc0,0x13cbe720,0x00d10b34 },
      { 0x00429c3b,0x1098d09c,0x1eafdc65,0x157105e1,0x04ffe479,0x166f3c53,
        0x0f3d0288,0x1a632a58,0x00165920 } },
    /* 159 */
    { { 0x1c086dd0,0x1af8e0d7,0x05580d6a,0x0c7d0a25,0x18ddc070,0x1ba162d2,
        0x183ffa4a,0x02819a9a,0x00a58aeb },
      { 0x0f78f77a,0x1af9991f,0x1a1cd0a5,0x1e5224cc,0x11ecef31,0x03a53501,
        0x0e6b64ae,0x0acaa9b5,0x00f1b361 } },
    /* 160 */
    { { 0x0396accc,0x074fd3a2,0x03927a0b,0x1894f3e0,0x14beeef9,0x1746f334,
        0x017270cb,0x17c1d1ef,0x006fba4b },
      { 0x18a65c2c,0x0fd4701b,0x12e3d019,0x071cd231,0x08e1a7ac,0x01d5b58c,
        0x1b2093dd,0x168add67,0x00c39006 } },
    /* 161 */
    { { 0x132d3604,0x0cdd2c1b,0x1acd1654,0x1d690216,0x14fc59bf,0x08648907,
        0x0d40625f,0x17494f64,0x00de080c },
      { 0x07d2b287,0x05ec20a5,0x13f591ee,0x116e567e,0x104278a7,0x030ea2dd,
        0x13e2fe84,0x15ceb281,0x00e6f95d } },
    /* 162 */
    { { 0x10bade5d,0x0594da4f,0x1e01ae07,0x004bec87,0x1ee16742,0x0a755e39,
        0x1ea22408,0x0269d26a,0x00cbbacf },
      { 0x14970cf8,0x0d9938a6,0x0fc0369c,0x1f1ca086,0x113cdec4,0x1dce8bc4,
        0x038ea4ac,0x12ec60a4,0x00892fad } },
    /* 163 */
    { { 0x02648f13,0x1d28ca78,0x0daf8057,0x1e52d84f,0x1091b169,0x01a6ab84,
        0x00f9e5c7,0x1b80394e,0x00c4390e },
      { 0x136dac3a,0x12f43a2f,0x1430cdae,0x10bae719,0x090ae25a,0x0a978fe9,
        0x171096bc,0x0a7998a1,0x009fa061 } },
    /* 164 */
    { { 0x01604b75,0x16d3bc63,0x000cc5d2,0x08c8c73d,0x1908461e,0x1d0552c0,
        0x1fbaf1fc,0x175e6c2d,0x00b4f2a6 },
      { 0x140da7f8,0x015d7dc2,0x15889692,0x0ab39fe9,0x1e50e9fd,0x0bac50e2,
        0x101e83c7,0x1cfd0e56,0x0035c216 } },
    /* 165 */
    { { 0x04a1c7e2,0x07009fe0,0x11bcffeb,0x121ab952,0x106acc69,0x16203c1e,
        0x16d1c76f,0x10a87d62,0x00e30a6d },
      { 0x14673fea,0x1f6bea14,0x05f97c37,0x123f68f8,0x0e1b0f31,0x0705def1,
        0x1a74247e,0x001a7164,0x00e4ef36 } },
    /* 166 */
    { { 0x04f41f17,0x108a5e3d,0x08c3086b,0x13c8099f,0x01e5c927,0x190287ae,
        0x0497e97a,0x13f71039,0x0018722e },
      { 0x1c23bf33,0x1c6bd1bd,0x070415bf,0x198ebb40,0x1ed471d5,0x13f6c3cd,
        0x1958e2db,0x0dd1d947,0x001aae4f } },
    /* 167 */
    { { 0x090e1ed5,0x05244adb,0x16a370d8,0x141a1873,0x06fa4391,0x1cd02fab,
        0x08b7e988,0x0b7baad8,0x005d1bd7 },
      { 0x1dab28fc,0x01256d77,0x154af30c,0x03fc1501,0x1fdb1cb8,0x03d36f5d,
        0x0e842e25,0x185416ce,0x00727d4c } },
    /* 168 */
    { { 0x061e7a89,0x11cf6a43,0x0bd3457e,0x17e459ff,0x1b83ebba,0x018434a7,
        0x04189793,0x00957a11,0x001082cd },
      { 0x1fcf1eee,0x1d26fe76,0x1a109fdb,0x01c9bef9,0x13d4cb1f,0x1e5fb9a9,
        0x1d7e9b66,0x1fb2e7c2,0x001cc91d } },
    /* 169 */
    { { 0x00d41758,0x07617e2d,0x00dce73e,0x0833c6ef,0x06559ae5,0x0beed1a9,
        0x1bbc5953,0x0a9dfb0b,0x0075dde5 },
      { 0x11da8cba,0x1b05665b,0x195b3c21,0x1a974323,0x0f13a485,0x101a40ec,
        0x13f60798,0x1d70a45f,0x00f4b5c1 } },
    /* 170 */
    { { 0x10dd7082,0x01cb9e72,0x031bc993,0x1cd446e1,0x164832ba,0x1a2332d7,
        0x0820be23,0x0bdc437c,0x0025a78b },
      { 0x108c8150,0x13614e64,0x1f57fef9,0x136c2d31,0x06028982,0x125e56e3,
        0x0c030118,0x0c234333,0x00505f95 } },
    /* 171 */
    { { 0x19dabf11,0x091fa0c2,0x134b56f5,0x1e415978,0x0e997570,0x123e7bc8,
        0x04ab4b38,0x11daae93,0x0085fa29 },
      { 0x0b273bd3,0x1776af9a,0x17d96958,0x16d5f2ec,0x18d8afe8,0x031501f9,
        0x1efbecbd,0x1e80af4c,0x005f6122 } },
    /* 172 */
    { { 0x1b5100cc,0x126b98f2,0x150c4fc4,0x10c14e73,0x0c6384f7,0x09980890,
        0x0b40f60a,0x1a98c9cb,0x000b9786 },
      { 0x03985e90,0x05213e01,0x026e20ab,0x0e180191,0x0f290dbc,0x1fc0b0ea,
        0x08368a4b,0x0b4b65bb,0x00970f1f } },
    /* 173 */
    { { 0x1b1d91cf,0x08ff961f,0x0a804bb3,0x0f082433,0x018ee6d2,0x05eb114f,
        0x1d8b2747,0x07d501e8,0x00a81543 },
      { 0x0e920554,0x1f6a5a7c,0x0a8da6e0,0x1e188ba1,0x105b01d3,0x08a97bd4,
        0x18305c9d,0x1a635734,0x00f1a03d } },
    /* 174 */
    { { 0x08c26023,0x160876d2,0x0e49f224,0x04f8a15e,0x16b9db22,0x1073b448,
        0x056872f8,0x0cf4c05f,0x00cfd53e },
      { 0x00130dd5,0x06e4cc9d,0x12f83e8f,0x0de797c9,0x07f6e9bb,0x153f4553,
        0x086134b6,0x0fd440d7,0x00f626df } },
    /* 175 */
    { { 0x16c08f54,0x1829ea52,0x140314ff,0x10e797bf,0x03d258cb,0x0268c665,
        0x09a2d261,0x12dc227d,0x00582571 },
      { 0x126f6bdf,0x07149416,0x04d45228,0x03b8d8cc,0x0385a762,0x1e1f8a45,
        0x06c015f6,0x00f364dc,0x0049badc } },
    /* 176 */
    { { 0x047731af,0x09d96fbe,0x0687cdcd,0x020d4af7,0x16fa4767,0x12fbbb50,
        0x00ff57f9,0x11a38720,0x004d65eb },
      { 0x0e6d9389,0x08b817d8,0x02661e5f,0x13a48c92,0x10c8ebf4,0x17f9a726,
        0x1992a138,0x0e689e0d,0x00bdbc37 } },
    /* 177 */
    { { 0x00209fea,0x0810cf02,0x01b25945,0x0c0966c5,0x0e72c56e,0x17d6a452,
        0x020fc463,0x19052961,0x00c6f889 },
      { 0x0e7e0c57,0x06468b24,0x15802af9,0x18d45447,0x14278a92,0x13a8ff6d,
        0x13289374,0x1c3b27c6,0x00ffd8a7 } },
    /* 178 */
    { { 0x160722af,0x09313f68,0x0fc343cb,0x17020451,0x0d61c3c8,0x06ce4762,
        0x0b31babd,0x1ea582fe,0x001b4baf },
      { 0x14594092,0x1ad1f11d,0x00a6fd53,0x09448afb,0x0422214b,0x102f2d2d,
        0x0007e97b,0x0a1d81fc,0x0003a0d8 } },
    /* 179 */
    { { 0x09ade883,0x118eb633,0x1eae6d66,0x1390adaf,0x1b5ac9d4,0x1a0d0630,
        0x03795e2a,0x0046646a,0x007e4f29 },
      { 0x196ac4bb,0x0cdea768,0x13aa635c,0x111c0b5f,0x1a02c71c,0x0ddf5642,
        0x1a396d10,0x0dbf4031,0x004132c6 } },
    /* 180 */
    { { 0x1d80c757,0x11216ae5,0x19ac69a1,0x047fda72,0x1fcf4d34,0x0a6b4973,
        0x0fc1742b,0x05494f3e,0x00545bb5 },
      { 0x0037745a,0x091131a1,0x0691f328,0x1a53fcb9,0x0baadb58,0x0c1390a0,
        0x068f336a,0x1a6ed8ed,0x00603e39 } },
    /* 181 */
    { { 0x07c3d4aa,0x14d3761b,0x0fbe5beb,0x1eaba211,0x0d0a8444,0x155f6b32,
        0x0ea94265,0x1bac10c2,0x00a44601 },
      { 0x1a37b00a,0x1b12b7cd,0x11227281,0x1ee615d4,0x167819d9,0x1799c79a,
        0x0b0ba386,0x0b836193,0x009da72c } },
    /* 182 */
    { { 0x0056721f,0x0a406694,0x19fda8e9,0x1491c99a,0x1f0a9f8b,0x13296fed,
        0x16b32371,0x15f6fc3d,0x003d7064 },
      { 0x0309625e,0x02a751b5,0x1b060411,0x14044712,0x12615026,0x0008c3f2,
        0x00efa7d4,0x0a6787ae,0x00f7a1b2 } },
    /* 183 */
    { { 0x0194a9a7,0x056fd633,0x070c617d,0x1289cfd8,0x0ea4631a,0x0740a050,
        0x1717f7a7,0x10757ec6,0x0016a7b7 },
      { 0x07106be1,0x1a4eb124,0x1bb75633,0x0102ad75,0x1b59af11,0x0e31b2f1,
        0x04014eff,0x1a1814f9,0x0089acde } },
    /* 184 */
    { { 0x1c0c7c04,0x1759c05c,0x00732729,0x00f9593e,0x16c6e230,0x1d97942d,
        0x1eb71377,0x0a29a5fc,0x00bcdc7f },
      { 0x0a8963d2,0x15e329a2,0x0d5775d0,0x017abc4f,0x198742fa,0x1fd96c73,
        0x04ddf924,0x0d99097f,0x0017108a } },
    /* 185 */
    { { 0x00ae33b0,0x1c6974e5,0x0f3414e3,0x198ecc1c,0x07996403,0x12c2902c,
        0x0adbde05,0x0acd391f,0x000f662d },
      { 0x14e35be1,0x171af566,0x0c00d77e,0x08e402d5,0x1bcd45ff,0x1750e3c1,
        0x0755336d,0x0d4a48f5,0x003ad2e4 } },
    /* 186 */
    { { 0x162b769b,0x0335f78c,0x1e767cfc,0x09fd8b74,0x10b11183,0x03a5e7f3,
        0x177830f5,0x1cc3028a,0x00ff3146 },
      { 0x09fda5a1,0x05a1497f,0x188a5da4,0x1aa81853,0x1f711100,0x0351d516,
        0x045c1046,0x023e7784,0x00cfd8a2 } },
    /* 187 */
    { { 0x04e1e3f9,0x1d50b265,0x1db13b2a,0x18ba98a0,0x154250ff,0x1b2314b8,
        0x0d6235a9,0x1d5b3d9a,0x00d50913 },
      { 0x17f9e5ba,0x1cc20e89,0x15b24968,0x0157f94e,0x055ad6a9,0x07c219ac,
        0x08434a71,0x1fd217dc,0x003a8a3f } },
    /* 188 */
    { { 0x02775465,0x0294f514,0x1791ac08,0x1a72ca0b,0x0203d96b,0x1babb7f0,
        0x0773abf7,0x1ef7093c,0x00033709 },
      { 0x1440bc88,0x0c879313,0x0af6a1b6,0x1b31b4ac,0x0b66419f,0x08400d9d,
        0x1531bd82,0x1f3dc0ba,0x00e39bc8 } },
    /* 189 */
    { { 0x17fee211,0x131ebe85,0x1cbe656e,0x1facef98,0x1863de5c,0x15881efa,
        0x18657992,0x17bb90c6,0x002e6ad6 },
      { 0x1effbe49,0x08f08afe,0x070f027e,0x1dbf9b76,0x08cfd154,0x069d85f3,
        0x07b17ef2,0x17962778,0x00dc5630 } },
    /* 190 */
    { { 0x09924c34,0x0fc9b125,0x0450a3e1,0x117fae5c,0x1defd847,0x1c2ba3fc,
        0x064e0527,0x117ea13f,0x00061050 },
      { 0x113724ea,0x0cf5f0fa,0x1722c910,0x004142e4,0x1ddfbcff,0x12c25395,
        0x00e253cd,0x1ab77d82,0x00aec05f } },
    /* 191 */
    { { 0x1b77bf82,0x1fe58b84,0x0f2830fa,0x08f06375,0x09ac7191,0x1116eea0,
        0x0448cffb,0x1e4a23f0,0x00c370cf },
      { 0x0151c5be,0x011e94c2,0x1d7b1bf8,0x12fd165d,0x1fbcbf10,0x115e9d04,
        0x0265e41e,0x10777f43,0x007e8f0a } },
    /* 192 */
    { { 0x1a638608,0x017967a6,0x0da2b033,0x08872fcf,0x1ff63b21,0x1fbbedca,
        0x045dfc62,0x0547308d,0x00d0bf3e },
      { 0x07315aff,0x082f4375,0x0efe7950,0x014aa45e,0x1119965a,0x1b0e491a,
        0x0ce8c427,0x04388c9a,0x00f01194 } },
    /* 193 */
    { { 0x0fb23d10,0x0899872b,0x098f1dc1,0x04ddb71d,0x1fade960,0x08b974e5,
        0x0e5fcd50,0x0d50e791,0x00ea5637 },
      { 0x04d8110b,0x1a03c9ea,0x0fbb475f,0x1363d98d,0x121c4077,0x00377adb,
        0x1999b00e,0x0008407a,0x00d2827a } },
    /* 194 */
    { { 0x1c0f3250,0x11f65141,0x0a2bbe79,0x0192da1f,0x00b3cb43,0x05cfb460,
        0x17e726e7,0x087870c8,0x00efba80 },
      { 0x13d1e454,0x12f03bd8,0x1b946bef,0x0067aba5,0x0a41b994,0x1ed71e1d,
        0x0918de43,0x0dcc8b16,0x0066714c } },
    /* 195 */
    { { 0x124fb9f6,0x174fba14,0x02a72e23,0x0d3307d9,0x0f49bac3,0x0884d852,
        0x005c10a1,0x1e098aa0,0x00ca5a01 },
      { 0x0442c569,0x1b68728b,0x1e81f930,0x1660b240,0x05b18c58,0x0feb9de4,
        0x02cea5d5,0x02d98432,0x00da0e7c } },
    /* 196 */
    { { 0x10bf8406,0x0d89e7b6,0x1da385b0,0x01e6c015,0x0a65648d,0x038c41ce,
        0x123c7015,0x0f4b4834,0x000ae223 },
      { 0x11f0d902,0x1ee33cb8,0x07aa1f3b,0x18b7a283,0x077cf13a,0x0c66b783,
        0x114f81a7,0x016602da,0x0042b06a } },
    /* 197 */
    { { 0x0f4e1f14,0x1a13e443,0x139e7636,0x15644a15,0x06c520b5,0x0bbfec60,
        0x13658c98,0x0046386f,0x0099a08f },
      { 0x13aa5906,0x00e98d58,0x15d56c2a,0x1e8eb29b,0x1a586001,0x1c9fce46,
        0x14962d59,0x1079d8c9,0x00b99c35 } },
    /* 198 */
    { { 0x0ae869dd,0x0e8c27d3,0x152fb2ff,0x1ebfec89,0x19801a3b,0x1c12d05d,
        0x06b3c5d8,0x157f57ef,0x00ca93f5 },
      { 0x0ab2c9c7,0x13efe918,0x043a89ee,0x0610ae5d,0x097d5464,0x18b99bde,
        0x0a5e5a48,0x00438570,0x00955dca } },
    /* 199 */
    { { 0x12e176c2,0x05c7a075,0x11d63033,0x14c9c20e,0x02f90384,0x05cde921,
        0x0c698b32,0x0f31a65c,0x000462a7 },
      { 0x13aa56f7,0x01f0f62a,0x0f3c175a,0x176174cf,0x0a3bfb40,0x0e99584f,
        0x0c084bc8,0x079376b1,0x007b5c0a } },
    /* 200 */
    { { 0x19486bf4,0x1b594470,0x07648b9f,0x14c2f044,0x158f740b,0x1906ee19,
        0x041746fb,0x1ed46e60,0x00ebea60 },
      { 0x1762e27f,0x15bce140,0x1e89417b,0x13d58a73,0x1bd90765,0x0b012243,
        0x116fd257,0x1ebfef2f,0x007b6d4a } },
    /* 201 */
    { { 0x1acaa0eb,0x10165fc5,0x1ae19588,0x08fd30f2,0x01a8a845,0x03d4c0f0,
        0x03bad9ae,0x0b9267af,0x00275512 },
      { 0x0d33f8cb,0x022aaea7,0x199dfe1a,0x1c195bc5,0x1e9fff1d,0x16a9a8d0,
        0x0d7c3b96,0x167f315a,0x00b34315 } },
    /* 202 */
    { { 0x131cd75d,0x13275898,0x038ef89e,0x0e9e6b96,0x1ddf391f,0x080191cc,
        0x16839051,0x0e21bffc,0x00371b86 },
      { 0x082d0f80,0x14e09fa3,0x16f5cb9d,0x1035794b,0x0531c243,0x199e6dcd,
        0x0af78868,0x138e7ec1,0x00aeddc9 } },
    /* 203 */
    { { 0x15f2259c,0x07a4f34d,0x129904d7,0x130c2c08,0x0a46eb04,0x1228aae8,
        0x08854438,0x142dc4fb,0x00d83c7c },
      { 0x035891b5,0x1def3693,0x0fcc4081,0x030f113d,0x09792df5,0x0a904603,
        0x00502a67,0x0cb9bf24,0x0047202f } },
    /* 204 */
    { { 0x0f443a32,0x0da3dff9,0x19e9b033,0x0778c9b1,0x1e45d902,0x0652b154,
        0x1f73dad2,0x19dfaee6,0x003ad3df },
      { 0x0b805be2,0x1c17e76a,0x06d6b5cd,0x0c5d9dd6,0x1b7363c0,0x1f43002c,
        0x1ab8fd67,0x01746d88,0x00f7cedd } },
    /* 205 */
    { { 0x033b78c5,0x18af1b3a,0x1da801ae,0x0e320f3f,0x07d71a23,0x11168ade,
        0x02423cf5,0x1a9f43f8,0x00525c2e },
      { 0x068d4b0f,0x1d1839d7,0x1f865664,0x13718421,0x0c5a5df1,0x1d1b723d,
        0x1844a3ea,0x056314f5,0x002da6d6 } },
    /* 206 */
    { { 0x1629d133,0x044d9dda,0x049c4a69,0x0137295a,0x0982ef9f,0x1f6fb841,
        0x0e754edf,0x0e71a57d,0x00c55733 },
      { 0x1cb75589,0x03d1c72a,0x1997bbe1,0x177b60be,0x0259bcb7,0x0fe4d71e,
        0x1631907f,0x142aee0b,0x0080e34c } },
    /* 207 */
    { { 0x001ef72f,0x04e14fb0,0x01e26c98,0x1fc06ecf,0x1553060f,0x177e7ef0,
        0x10e9c033,0x0d255515,0x00981994 },
      { 0x01ca3125,0x1cd50322,0x0326a530,0x1ea09d78,0x010683e9,0x1b947fc3,
        0x1bccb184,0x1694885a,0x005951fc } },
    /* 208 */
    { { 0x197e8fce,0x14d9128d,0x10bea4df,0x0a438b5c,0x1f665a5d,0x09f1bd3c,
        0x010d71cf,0x02c3cf83,0x00929a59 },
      { 0x0453f77a,0x04399dd1,0x02f5138c,0x12390901,0x063b2201,0x18361259,
        0x0b205fe7,0x1344ea07,0x00fffdcd } },
    /* 209 */
    { { 0x1a2e3d35,0x1c229aaf,0x1aae82a5,0x1f4df85b,0x1a38a2f9,0x05f27508,
        0x019a0a21,0x013f8ef3,0x0038ceee },
      { 0x165550ee,0x0f9c182a,0x0242d9e4,0x1a48d384,0x17c29037,0x0ac4addc,
        0x061584b5,0x14e7ff9c,0x0045a8c6 } },
    /* 210 */
    { { 0x148986b4,0x1f4c8d7c,0x1403b050,0x13a29044,0x1e9230c3,0x1395cf3e,
        0x137b64f0,0x10d2d21e,0x00219e13 },
      { 0x0a62b42b,0x001415e5,0x1a2f246f,0x04c32d09,0x144e378d,0x187a23c0,
        0x162850e4,0x06b99227,0x005ec127 } },
    /* 211 */
    { { 0x12dd1b0d,0x0742887c,0x111e7300,0x0aac6997,0x03ebc8fa,0x0c056f2c,
        0x1d3d9617,0x039b6135,0x003500e4 },
      { 0x0edc1c6b,0x0bc8b93c,0x05cfb7de,0x1bc76ad3,0x036f2aa6,0x14e689d6,
        0x1a5c0f17,0x198d8ef4,0x00c274af } },
    /* 212 */
    { { 0x1c423efc,0x0c3c4569,0x1fe6fc26,0x0d4ea36f,0x02e4e22c,0x1866c7f4,
        0x17e5e846,0x05619188,0x007538db },
      { 0x16d33e22,0x1272fd42,0x0395c225,0x1a45c776,0x1fa92319,0x0190e2be,
        0x080f19f9,0x05df45c1,0x00465b5b } },
    /* 213 */
    { { 0x1248e296,0x1c8591b8,0x096e80eb,0x0ffe69c2,0x0f21af7e,0x1a873dac,
        0x1a819cef,0x01a54ac8,0x00961312 },
      { 0x15fa20a4,0x0951f629,0x16d9d3fb,0x05ea2102,0x1c28cffc,0x04d4048b,
        0x050c85ed,0x11ac7d20,0x005febff } },
    /* 214 */
    { { 0x083048a7,0x0c05d6cc,0x0becc478,0x01aedfbc,0x10918edf,0x107fa178,
        0x015bc8bd,0x18c02fc8,0x00d9a441 },
      { 0x0c2ad962,0x1ad8075a,0x13d321c6,0x003b1d39,0x0f97f0e3,0x10a6a2fc,
        0x11e155fd,0x05dc1e3c,0x006cc18f } },
    /* 215 */
    { { 0x178b96ab,0x06600ebf,0x1f83e392,0x117bd768,0x18a4b1ea,0x097ff7fd,
        0x0f92b72a,0x05cee871,0x00e998d3 },
      { 0x14e6087e,0x0ca17586,0x09061d82,0x1844aad6,0x01c483fb,0x011bd65e,
        0x1db6a8bb,0x060ae65c,0x009aecd9 } },
    /* 216 */
    { { 0x158b5d43,0x133ecdc4,0x1addced5,0x1e3131c3,0x08b8607b,0x166c5faa,
        0x11b61469,0x04485ad6,0x00242d84 },
      { 0x1b655c2f,0x085d046b,0x1df25e35,0x11221b9b,0x1780f227,0x1ebd9835,
        0x01ce756f,0x1c0dc603,0x006ca437 } },
    /* 217 */
    { { 0x19feae4e,0x1e132e67,0x1d64a835,0x097aeb32,0x049e4bdd,0x10e97431,
        0x00a1462b,0x0379960c,0x005909fa },
      { 0x1746eb81,0x117cb2ca,0x004bffde,0x1a5327b9,0x1af4f409,0x088a5855,
        0x123c0c6b,0x1dbca63f,0x00e0a7ec } },
    /* 218 */
    { { 0x001217cc,0x0906f3b1,0x0f3b1bb7,0x0918c0aa,0x12846c9a,0x18efe7b3,
        0x0f7ef797,0x00c006d2,0x00957ce1 },
      { 0x067c0809,0x12c948b0,0x09871bc0,0x1ea5b807,0x0a5272bc,0x1dd33f45,
        0x0c462b37,0x0a96e509,0x00dad8f4 } },
    /* 219 */
    { { 0x0aa83bd4,0x0179d7c3,0x0e299151,0x141c1f06,0x0dd50415,0x0e494b48,
        0x1bc21da2,0x1810c504,0x007a127c },
      { 0x13e33b5a,0x0148658c,0x1d710412,0x1a733f56,0x045c4124,0x1ed67054,
        0x0568594e,0x12ce59d8,0x002cd181 } },
    /* 220 */
    { { 0x076a8a56,0x1a011e4b,0x14a0b563,0x01d338f1,0x16b1c0c9,0x12d37e36,
        0x100b92fa,0x04d5139c,0x006cf1b3 },
      { 0x1046702d,0x1358ee90,0x0ab05481,0x0ecd944a,0x182b65fb,0x055ae920,
        0x10b1b19e,0x08d16300,0x009fc957 } },
    /* 221 */
    { { 0x187f9611,0x0f7e5909,0x1012d0d2,0x1a4a0f10,0x126c6ff2,0x066c8e3a,
        0x09cd5564,0x186b1d0d,0x0090a22f },
      { 0x1ce2f640,0x1bdee004,0x158d1a9b,0x175ce209,0x1181c92f,0x13de483e,
        0x1a78effe,0x18124d1b,0x006b54f6 } },
    /* 222 */
    { { 0x191e135d,0x0b716a2f,0x1e43b6be,0x0ff1128f,0x1b22954b,0x10aefdb9,
        0x0de0cdb6,0x0041a423,0x004d971d },
      { 0x10ff0147,0x0ba61fe2,0x12023306,0x08a0b90d,0x12d671b1,0x15813608,
        0x07fb399a,0x06418046,0x0069fafa } },
    /* 223 */
    { { 0x05a94617,0x0c28cab0,0x17dffba3,0x0fd93018,0x111f8be0,0x1841483b,
        0x00538332,0x17c77057,0x00c6709c },
      { 0x1f8014a0,0x0d0dd706,0x151fdd8f,0x117d6416,0x0cc363f7,0x1bfeca50,
        0x13866342,0x0a2565cf,0x00b87de6 } },
    /* 224 */
    { { 0x03219f63,0x1d209116,0x011d8d8c,0x0e61b695,0x146e7070,0x06ed2410,
        0x022127d7,0x1451efd0,0x000f3b01 },
      { 0x04ed5675,0x0869e381,0x0baf6135,0x0caf1fa2,0x1ebd67e5,0x06351b72,
        0x02feb95d,0x00862292,0x003a6a70 } },
    /* 225 */
    { { 0x1dc3afa7,0x0739cbf4,0x11d74ae5,0x17f355e2,0x0d3e04a2,0x079c5d8d,
        0x141322c5,0x0f86927c,0x0065657f },
      { 0x0162798f,0x1a152c6a,0x1c7dd90c,0x14411e8f,0x0275a446,0x0ef59e08,
        0x1e8045e5,0x0e44e192,0x0062e545 } },
    /* 226 */
    { { 0x1fd3001a,0x0ca9be01,0x1a1fea86,0x1b0e6d2a,0x15bf6292,0x0cac076b,
        0x158d8f86,0x1606f77c,0x00fad9db },
      { 0x0330d6f7,0x1192440b,0x108e8b22,0x0be214f5,0x0295d03b,0x0ede5e27,
        0x1c64ea4e,0x13563625,0x00a3e611 } },
    /* 227 */
    { { 0x142823a4,0x1b3e766d,0x1d0f6cfe,0x19e0d0e7,0x1c5fa26e,0x10842978,
        0x010bee1b,0x1137030a,0x0074ba5c },
      { 0x0c74b8af,0x0fac2144,0x16fe02a9,0x02decf43,0x054cb337,0x0857911c,
        0x0b285c86,0x188ced99,0x00bffbbb } },
    /* 228 */
    { { 0x028b90c5,0x13103277,0x0742fa7d,0x1afd2fef,0x0cae0563,0x05652b5f,
        0x0f78d0cc,0x17d6d63c,0x007c64d2 },
      { 0x11b53678,0x0e29d5f1,0x03698263,0x01153eca,0x06c18346,0x044e0b7b,
        0x113d3c6c,0x1957eb8d,0x00d0a9d4 } },
    /* 229 */
    { { 0x0dd922a9,0x1b18f42c,0x046f4547,0x129d590d,0x00f68a53,0x18d9e443,
        0x12f75dd5,0x0b1cfa46,0x0006bad5 },
      { 0x09d6c786,0x0cb1393b,0x1511924a,0x05e70a3b,0x038745f0,0x18945818,
        0x1f6fc2e1,0x0704c1ec,0x001184eb } },
    /* 230 */
    { { 0x1646a2d8,0x1de10bb7,0x0be7e613,0x153a5bf9,0x0fd97b59,0x1ca5f1cc,
        0x0f758f50,0x17928901,0x00026ff9 },
      { 0x125eb68f,0x0e59542d,0x14ceaf0c,0x01b1563d,0x04287370,0x1f44e628,
        0x189194f0,0x0cbe3ef0,0x00f81ba8 } },
    /* 231 */
    { { 0x0c2b7ab7,0x0d7596a7,0x183e4786,0x0e7cecb4,0x13ad4fae,0x1886f3d1,
        0x08b567af,0x143bf5e0,0x00731217 },
      { 0x1e5c73d5,0x07f59a11,0x1080ccd1,0x0d4c5024,0x032637b4,0x1392e503,
        0x0ea236fc,0x11739ddc,0x002f1965 } },
    /* 232 */
    { { 0x0e1aa4ef,0x18775c5f,0x1e2f0946,0x1e13b6a7,0x11aa5881,0x1687f5f1,
        0x1e7b7867,0x08168420,0x00c12050 },
      { 0x1f9fbb19,0x15f309eb,0x00bc6b9a,0x1d667e98,0x0a4aa480,0x10cc5e3c,
        0x167e609c,0x17200c18,0x0073bd74 } },
    /* 233 */
    { { 0x17f909a1,0x17be8785,0x13169209,0x0ed62efc,0x02ea1ffc,0x1025c422,
        0x14ede4fa,0x0ba726d5,0x00e389c4 },
      { 0x043ffd3c,0x1783b5b4,0x195a24b3,0x1583d887,0x106e5364,0x05d86d68,
        0x1ab2ff16,0x184c9710,0x00aed22a } },
    /* 234 */
    { { 0x069ae3dd,0x1899a664,0x0442ebb8,0x0c828730,0x1d6cc52b,0x1043ddc6,
        0x04b095bf,0x098a33ba,0x0029f73d },
      { 0x02b5be53,0x1f671e9f,0x17e0d10f,0x10f7dd7a,0x1e101556,0x122b0085,
        0x1bfc95fd,0x0037356d,0x0038390f } },
    /* 235 */
    { { 0x0cdf4b26,0x13d720d8,0x1dd3e9b5,0x06d814fc,0x179c5842,0x14d04aec,
        0x0b72ef71,0x0b06c0ba,0x00d5bc73 },
      { 0x19a77475,0x11c26e9b,0x09203df7,0x129eb405,0x0ea569f0,0x1f8185f7,
        0x02e8b9de,0x1970ca2b,0x00a6a6ad } },
    /* 236 */
    { { 0x155cbb33,0x1ebe3868,0x091050b5,0x0475cd3d,0x1a3d7478,0x02d6ee48,
        0x10e91fa7,0x0f8ea625,0x005ce904 },
      { 0x14696568,0x074c6628,0x06ad911c,0x1df932c8,0x0fe319a2,0x102d10ed,
        0x1c7d1fbe,0x164b58b6,0x002cefaa } },
    /* 237 */
    { { 0x1bccf3ca,0x096d9023,0x1a3ea22c,0x1fdaa4ef,0x058ae15d,0x13284125,
        0x0f27a606,0x1ab70c51,0x00e47a22 },
      { 0x088432d8,0x1cb2f80b,0x0b2d48ed,0x002b77db,0x1ba8ecc3,0x023f4529,
        0x1ced3632,0x04f7dd4d,0x00196018 } },
    /* 238 */
    { { 0x1feb5071,0x1f991940,0x12833dff,0x19a05bea,0x189bfd16,0x0c7689c7,
        0x0ee3adbe,0x02affefa,0x00531647 },
      { 0x0992b998,0x0e88277e,0x0655c780,0x18996476,0x1dc125a7,0x139badc9,
        0x0246a1cb,0x1b6e92a9,0x0022e7a9 } },
    /* 239 */
    { { 0x0283ccdf,0x1b0cc740,0x0334b1a7,0x1d5d73ef,0x042948b0,0x16753c30,
        0x04d0367f,0x1fdd364d,0x00d0ac75 },
      { 0x16fdf44f,0x11665a51,0x00a109ae,0x16a24721,0x013ac828,0x1c1e3188,
        0x05d86dda,0x0c6d30e8,0x00f8d1bf } },
    /* 240 */
    { { 0x13c6d17c,0x1300a829,0x1dbef2c7,0x1ab6c018,0x04f65ec3,0x1f708030,
        0x142c8fae,0x178ac880,0x0012959c },
      { 0x1023a933,0x12c6fa4f,0x010878ba,0x13991324,0x1920058b,0x1f8de04b,
        0x08abcac4,0x06535e2c,0x001aac8e } },
    /* 241 */
    { { 0x14e44471,0x169e433a,0x03e56795,0x1f4f39ac,0x0aa6d16c,0x14d99c00,
        0x12d78682,0x0e6c79eb,0x00034785 },
      { 0x081c0625,0x0c9f92b1,0x19c43117,0x145dab8d,0x1caf84ed,0x0c230fd3,
        0x18eddb66,0x03636d85,0x005fbd4e } },
    /* 242 */
    { { 0x0628bd27,0x1774e071,0x036249b7,0x03db92df,0x067025ed,0x1cb45d36,
        0x1fa12ef1,0x0b388f72,0x0071c11b },
      { 0x193fdd98,0x14d79ae6,0x063603c9,0x1ec7cf5b,0x18b4d250,0x1648a543,
        0x11765903,0x0760bd61,0x00d994d2 } },
    /* 243 */
    { { 0x02eb6f86,0x1a4c2967,0x1c6ab540,0x06c41f5f,0x1359db7e,0x119e5cd4,
        0x01d83e29,0x04e1733c,0x00c89a70 },
      { 0x0661ebad,0x02aa991b,0x023c2e86,0x18dcd1b5,0x14d3785e,0x17996d87,
        0x185aa150,0x1c105dd0,0x0004e03e } },
    /* 244 */
    { { 0x06460df0,0x1231e134,0x1579e4ea,0x0eeb9fdf,0x1d3d908b,0x1cbac204,
        0x16345385,0x0d0e6f52,0x00e68e94 },
      { 0x0a015c8b,0x08cf324e,0x171eca99,0x021eeb46,0x143f8d63,0x164ce559,
        0x0bdfc7eb,0x13865eef,0x001b2397 } },
    /* 245 */
    { { 0x0b5e0c0c,0x0936a101,0x03225fcd,0x1657b2a5,0x1cd0299d,0x0406935f,
        0x149ed936,0x0c7de5d9,0x00dd78c2 },
      { 0x15822826,0x059a83c4,0x1c8700e8,0x0381cb59,0x1e6015ea,0x0e80edf3,
        0x16d0f56c,0x07f1b242,0x00139c07 } },
    /* 246 */
    { { 0x070e8ca9,0x0c91163b,0x0c0d44af,0x17b2ed49,0x0fc83381,0x1d6534a3,
        0x05b67174,0x0e34de66,0x005a13dc },
      { 0x0f25e97b,0x05f91b20,0x1956cd6f,0x083416df,0x1aacedd7,0x1b83c2e6,
        0x0e09d229,0x028ee423,0x0002d9d8 } },
    /* 247 */
    { { 0x03eca061,0x1328a774,0x1fea931d,0x1e12f994,0x0fc7d38d,0x10b2e428,
        0x01ae2221,0x0f4f9013,0x005f4fcb },
      { 0x08612b88,0x0624c65e,0x00a74e56,0x1dae95a0,0x18e41a26,0x05520888,
        0x17d3b404,0x1521011c,0x0001239c } },
    /* 248 */
    { { 0x171f2025,0x1a0aa8db,0x0b5c61e2,0x03cde03b,0x1d187893,0x05d2c268,
        0x120d8cec,0x04c3f69d,0x00801760 },
      { 0x03fed11f,0x10ba061d,0x0c71b282,0x195b421c,0x19e1b49d,0x05eb6883,
        0x17d6e5bc,0x174a06bd,0x00d325b1 } },
    /* 249 */
    { { 0x05614b0c,0x16650862,0x14828167,0x096e361e,0x0f3b365d,0x072da4b5,
        0x096f21d7,0x158113d8,0x001993da },
      { 0x1b44405f,0x013a98f4,0x0c9c155b,0x0d402dd0,0x05d43716,0x082ab352,
        0x0682e9fb,0x1767a6a6,0x001da832 } },
    /* 250 */
    { { 0x192d1d40,0x1a7073d5,0x19b18ee2,0x0482f458,0x1ec72869,0x062c439a,
        0x05273cd0,0x0c36bef1,0x00b58569 },
      { 0x11715164,0x08505c8d,0x0b6afeb4,0x182f8f7a,0x1b101864,0x0cfbd4a6,
        0x124d2037,0x1051e070,0x00a7dff8 } },
    /* 251 */
    { { 0x0df73f04,0x1ce2ddef,0x11517674,0x1fd410e4,0x1306a3a8,0x1ac3ba7b,
        0x090729a0,0x16972fde,0x007094ae },
      { 0x172ebf79,0x1311aace,0x056800c1,0x09523bf5,0x0a892de2,0x1ea7538b,
        0x14fcd39c,0x059bb928,0x00f0477a } },
    /* 252 */
    { { 0x1fb80211,0x019238e0,0x07de3b68,0x06456ac5,0x1483847c,0x15ab5a69,
        0x06124a98,0x0491d119,0x002400e4 },
      { 0x13dbc9d8,0x1c92144e,0x08237dab,0x18294ce9,0x15105257,0x100b3504,
        0x0e0e5640,0x0a517fba,0x00f5ac54 } },
    /* 253 */
    { { 0x02980d58,0x19bf2dd2,0x195fe47e,0x063cc2ea,0x1bd4d2c0,0x0f492241,
        0x1eefe791,0x14cc8265,0x0043b13e },
      { 0x16665e37,0x0f840d26,0x057775b7,0x0ebbdf4e,0x1952893f,0x0c7d1581,
        0x0ac131db,0x0430735d,0x004ee3a2 } },
    /* 254 */
    { { 0x1a6ef7ba,0x1ff824e9,0x05ec4d25,0x0ef3abe4,0x0c2abbcc,0x19b84286,
        0x0fbfa854,0x065d4f19,0x0093967c },
      { 0x018605ea,0x1b97d516,0x05a4e736,0x1c5edebc,0x0e4f8dde,0x19a17570,
        0x003fd4ef,0x0e5fbb8b,0x0014e259 } },
    /* 255 */
    { { 0x150d7f94,0x02a6e6c4,0x08ed3582,0x00d4cc7d,0x15b2f070,0x131fefc5,
        0x1d2aa47e,0x0220c185,0x00aad30b },
      { 0x0254ba5d,0x118600b2,0x011eba86,0x0a1d558b,0x0ab3c314,0x1a066a4f,
        0x02210719,0x1df72fab,0x00bcc984 } },
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
static int sp_256_ecc_mulmod_base_sm2_9(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_9(r, &p256_sm2_base, p256_sm2_table,
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
    sp_digit k[9];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 9, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 9, km);

            err = sp_256_ecc_mulmod_base_sm2_9(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_9(point, r);
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
    sp_digit k[9 + 9 * 2 * 6];
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
            sizeof(sp_digit) * (9 + 9 * 2 * 6),
            heap, DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 9;

        sp_256_from_mp(k, 9, km);
        sp_256_point_from_ecc_point_9(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_9(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_9(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_9(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_9(point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_9(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_9(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_9(point, r);
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
SP_NOINLINE static void sp_256_add_one_sm2_9(sp_digit* a)
{
    a[0]++;
    sp_256_norm_9(a);
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
        if (s >= 21U) {
            r[j] &= 0x1fffffff;
            s = 29U - s;
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
static int sp_256_ecc_gen_k_sm2_9(WC_RNG* rng, sp_digit* k)
{
#ifndef WC_NO_RNG
    int err;
    byte buf[32];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_256_from_bin(k, 9, buf, (int)sizeof(buf));
            if (sp_256_cmp_sm2_9(k, p256_sm2_order2) <= 0) {
                sp_256_add_one_sm2_9(k);
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
    sp_digit k[9];
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
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 9, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
        infinity = point + 1;
    #endif

        err = sp_256_ecc_gen_k_sm2_9(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_9(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_9(infinity, point, p256_sm2_order, 1, 1, NULL);
    }
    if (err == MP_OKAY) {
        if (sp_256_iszero_9(point->x) || sp_256_iszero_9(point->y)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_256_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_9(point, pub);
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
    sp_256_ecc_mulmod_9_ctx mulmod_ctx;
    sp_digit k[9];
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
            err = sp_256_ecc_gen_k_9(rng, ctx->k);
            if (err == MP_OKAY) {
                err = FP_WOULDBLOCK;
                ctx->state = 1;
            }
            break;
        case 1:
            err = sp_256_ecc_mulmod_base_9_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
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
            err = sp_256_ecc_mulmod_9_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      infinity, ctx->point, p256_sm2_order, 1, 1);
            if (err == MP_OKAY) {
                if (sp_256_iszero_9(ctx->point->x) ||
                    sp_256_iszero_9(ctx->point->y)) {
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
                err = sp_256_point_to_ecc_point_9(ctx->point, pub);
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
static void sp_256_to_bin_9(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<8; i++) {
        r[i+1] += r[i] >> 29;
        r[i] &= 0x1fffffff;
    }
    j = 263 / 8 - 1;
    a[j] = 0;
    for (i=0; i<9 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 29) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 29);
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
    sp_digit k[9];
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
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 9, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 9, priv);
        sp_256_point_from_ecc_point_9(point, pub);
            err = sp_256_ecc_mulmod_sm2_9(point, point, k, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_256_to_bin_9(point->x, out);
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
        sp_256_ecc_mulmod_9_ctx mulmod_ctx;
    };
    sp_digit k[9];
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
            sp_256_from_mp(ctx->k, 9, priv);
            sp_256_point_from_ecc_point_9(&ctx->point, pub);
            ctx->state = 1;
            break;
        case 1:
            err = sp_256_ecc_mulmod_sm2_9_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      &ctx->point, &ctx->point, ctx->k, 1, 1, heap);
            if (err == MP_OKAY) {
                sp_256_to_bin_9(ctx->point.x, out);
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
static const uint32_t p256_sm2_order_minus_2[8] = {
    0x39d54121U,0x53bbf409U,0x21c6052bU,0x7203df6bU,0xffffffffU,0xffffffffU,
    0xffffffffU,0xfffffffeU
};
#else
#ifdef HAVE_ECC_SIGN
/* The low half of the order-2 of the SM2 P256 curve. */
static const uint32_t p256_sm2_order_low[4] = {
    0x39d54121U,0x53bbf409U,0x21c6052bU,0x7203df6bU
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
static void sp_256_mont_mul_order_sm2_9(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_sm2_9(r, a, b);
    sp_256_mont_reduce_order_sm2_9(r, p256_sm2_order, p256_sm2_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_order_sm2_9(sp_digit* r, const sp_digit* a)
{
    sp_256_sqr_sm2_9(r, a);
    sp_256_mont_reduce_order_sm2_9(r, p256_sm2_order, p256_sm2_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P256 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_n_order_sm2_9(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_256_mont_sqr_order_sm2_9(r, a);
    for (i=1; i<n; i++) {
        sp_256_mont_sqr_order_sm2_9(r, r);
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
static void sp_256_mont_inv_order_sm2_9(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 9);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_order_sm2_9(t, t);
        if ((p256_sm2_order_minus_2[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_9(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 9U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 9;
    sp_digit* t3 = td + 4 * 9;
    sp_digit* t4 = td + 6 * 9;
    int i;

    /* t4= a^2 */
    sp_256_mont_sqr_order_sm2_9(t4, a);
    /* t = a^3 = t4* a */
    sp_256_mont_mul_order_sm2_9(t, t4, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_order_sm2_9(t2, t, 2);
    /* t4= a^e = t2 * t4 */
    sp_256_mont_mul_order_sm2_9(t4, t2, t4);
    /* t3= a^f = t2 * t */
    sp_256_mont_mul_order_sm2_9(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_256_mont_sqr_n_order_sm2_9(t2, t3, 4);
    /* t4 = a^fe = t2 * t4 */
    sp_256_mont_mul_order_sm2_9(t4, t2, t4);
    /* t = a^ff = t2 * t3 */
    sp_256_mont_mul_order_sm2_9(t, t2, t3);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_order_sm2_9(t2, t, 8);
    /* t4 = a^fffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_9(t4, t2, t4);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_order_sm2_9(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_order_sm2_9(t2, t, 16);
    /* t4= a^fffffffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_9(t4, t2, t4);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_9(t, t2, t);
    /* t2= a^fffffffe00000000 = t4 ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_9(t4, t4, 32);
    /* t4= a^fffffffeffffffff = t4 * t */
    sp_256_mont_mul_order_sm2_9(t4, t4, t);
    /* t2= a^ffffffff00000000 = t ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_9(t2, t, 32);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_9(t, t2, t);
    /* t4= a^fffffffeffffffff0000000000000000 = t4 ^ 2 ^ 64 */
    sp_256_mont_sqr_n_order_sm2_9(t4, t4, 64);
    /* t2= a^fffffffeffffffffffffffffffffffff = t4 * t2 */
    sp_256_mont_mul_order_sm2_9(t2, t4, t);
    /* t2= a^fffffffeffffffffffffffffffffffff7203d */
    for (i=127; i>=108; i--) {
        sp_256_mont_sqr_order_sm2_9(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_9(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df */
    sp_256_mont_sqr_n_order_sm2_9(t2, t2, 4);
    sp_256_mont_mul_order_sm2_9(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bb */
    for (i=103; i>=48; i--) {
        sp_256_mont_sqr_order_sm2_9(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_9(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf */
    sp_256_mont_sqr_n_order_sm2_9(t2, t2, 4);
    sp_256_mont_mul_order_sm2_9(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412 */
    for (i=43; i>=4; i--) {
        sp_256_mont_sqr_order_sm2_9(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_9(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54120 */
    sp_256_mont_sqr_n_order_sm2_9(t2, t2, 4);
    /* r = a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121 */
    sp_256_mont_mul_order_sm2_9(r, t2, a);
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
    sp_digit d[4 * 10*9];
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
    sp_int32 c;
    int i;

    (void)heap;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8 * 2 * 9, heap,
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
        e = d + 0 * 9;
        x = d + 2 * 9;
        k = d + 4 * 9;
        r = d + 6 * 9;
        tmp = d + 8 * 9;
        s = e;
        xInv = x;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_bin(e, 9, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_256_from_mp(x, 9, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_256_ecc_gen_k_sm2_9(rng, k);
        }
        else {
            sp_256_from_mp(k, 9, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
                err = sp_256_ecc_mulmod_base_sm2_9(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = (point->x + e) mod order */
            sp_256_add_sm2_9(r, point->x, e);
            sp_256_norm_9(r);
            c = sp_256_cmp_sm2_9(r, p256_sm2_order);
            sp_256_cond_sub_sm2_9(r, r, p256_sm2_order, 0L - (sp_digit)(c >= 0));
            sp_256_norm_9(r);

            /* Try again if r == 0 */
            if (sp_256_iszero_9(r)) {
                continue;
            }

            /* Try again if r + k == 0 */
            sp_256_add_sm2_9(s, k, r);
            sp_256_norm_9(s);
            c += sp_256_cmp_sm2_9(s, p256_sm2_order);
            sp_256_cond_sub_sm2_9(s, s, p256_sm2_order, 0L - (sp_digit)(c >= 0));
            sp_256_norm_9(s);
            if (sp_256_iszero_9(s)) {
                continue;
            }

            /* Conv x to Montgomery form (mod order) */
                sp_256_mul_sm2_9(x, x, p256_sm2_norm_order);
            err = sp_256_mod_sm2_9(x, x, p256_sm2_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_9(x);

            /* s = k - r * x */
                sp_256_mont_mul_order_sm2_9(s, x, r);
        }
        if (err == MP_OKAY) {
            sp_256_norm_9(s);
            sp_256_sub_sm2_9(s, k, s);
            sp_256_cond_add_sm2_9(s, s, p256_sm2_order, s[8] >> 24);
            sp_256_norm_9(s);

            /* xInv = 1/(x+1) mod order */
            sp_256_add_sm2_9(x, x, p256_sm2_norm_order);
            sp_256_norm_9(x);
            x[8] &= (((sp_digit)1) << 29) - 1;

                sp_256_mont_inv_order_sm2_9(xInv, x, tmp);
            sp_256_norm_9(xInv);

            /* s = s * (x+1)^-1 mod order */
                sp_256_mont_mul_order_sm2_9(s, s, xInv);
            sp_256_norm_9(s);

            c = sp_256_cmp_sm2_9(s, p256_sm2_order);
            sp_256_cond_sub_sm2_9(s, s, p256_sm2_order,
                0L - (sp_digit)(c >= 0));
            sp_256_norm_9(s);

            /* Check that signature is usable. */
            if (sp_256_iszero_9(s) == 0) {
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
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 9);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
    if (point != NULL) {
        XFREE(point, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 9U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 9U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 9U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 9U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 9U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 4U * 2U * 9U);
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
    sp_digit d[8*9 * 7];
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
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 20 * 9, heap,
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
        e   = d + 0 * 9;
        r   = d + 2 * 9;
        s   = d + 4 * 9;
        tmp = d + 6 * 9;
        p2 = p1 + 1;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_mp(r, 9, rm);
        sp_256_from_mp(s, 9, sm);
        sp_256_from_mp(p2->x, 9, pX);
        sp_256_from_mp(p2->y, 9, pY);
        sp_256_from_mp(p2->z, 9, pZ);


        if (sp_256_iszero_9(r) ||
            sp_256_iszero_9(s) ||
            (sp_256_cmp_sm2_9(r, p256_sm2_order) >= 0) ||
            (sp_256_cmp_sm2_9(s, p256_sm2_order) >= 0)) {
            *res = 0;
            done = 1;
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        carry = sp_256_add_sm2_9(e, r, s);
        sp_256_norm_9(e);
        if (carry || sp_256_cmp_sm2_9(e, p256_sm2_order) >= 0) {
            sp_256_sub_sm2_9(e, e, p256_sm2_order);            sp_256_norm_9(e);
        }

        if (sp_256_iszero_9(e)) {
           *res = 0;
           done = 1;
        }
    }
    if ((err == MP_OKAY) && (!done)) {
            err = sp_256_ecc_mulmod_base_sm2_9(p1, s, 0, 0, heap);
    }
    if ((err == MP_OKAY) && (!done)) {
        {
            err = sp_256_ecc_mulmod_sm2_9(p2, p2, e, 0, 0, heap);
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        {
            sp_256_proj_point_add_sm2_9(p1, p1, p2, tmp);
            if (sp_256_iszero_9(p1->z)) {
                if (sp_256_iszero_9(p1->x) && sp_256_iszero_9(p1->y)) {
                    sp_256_proj_point_dbl_sm2_9(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    p1->x[4] = 0;
                    p1->x[5] = 0;
                    p1->x[6] = 0;
                    p1->x[7] = 0;
                    p1->x[8] = 0;
                    XMEMCPY(p1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
                }
            }
        }

        /* z' = z'.z' */
        sp_256_mont_sqr_sm2_9(p1->z, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        XMEMSET(p1->x + 9, 0, 9U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_9(p1->x, p256_sm2_mod, p256_sm2_mp_mod);
        /* (r - e + n*order).z'.z' mod prime == (s.G + t.Q)->x' */
        /* Load e, subtract from r. */
        sp_256_from_bin(e, 9, hash, (int)hashLen);
        if (sp_256_cmp_sm2_9(r, e) < 0) {
            (void)sp_256_add_sm2_9(r, r, p256_sm2_order);
        }
        sp_256_sub_sm2_9(e, r, e);
        sp_256_norm_9(e);
        /* x' == (r - e).z'.z' mod prime */
        sp_256_mont_mul_sm2_9(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        *res = (int)(sp_256_cmp_sm2_9(p1->x, s) == 0);
        if (*res == 0) {
            carry = sp_256_add_sm2_9(e, e, p256_sm2_order);
            if (!carry && sp_256_cmp_sm2_9(e, p256_sm2_mod) < 0) {
                /* x' == (r - e + order).z'.z' mod prime */
                sp_256_mont_mul_sm2_9(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
                *res = (int)(sp_256_cmp_sm2_9(p1->x, s) == 0);
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
static int sp_256_ecc_is_point_sm2_9(const sp_point_256* point,
    void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t1 = NULL;
#else
    sp_digit t1[9 * 4];
#endif
    sp_digit* t2 = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t1 = (sp_digit*)XMALLOC(sizeof(sp_digit) * 9 * 4, heap, DYNAMIC_TYPE_ECC);
    if (t1 == NULL)
        err = MEMORY_E;
#endif
    (void)heap;

    if (err == MP_OKAY) {
        t2 = t1 + 2 * 9;

        /* y^2 - x^3 - a.x = b */
        sp_256_sqr_sm2_9(t1, point->y);
        (void)sp_256_mod_sm2_9(t1, t1, p256_sm2_mod);
        sp_256_sqr_sm2_9(t2, point->x);
        (void)sp_256_mod_sm2_9(t2, t2, p256_sm2_mod);
        sp_256_mul_sm2_9(t2, t2, point->x);
        (void)sp_256_mod_sm2_9(t2, t2, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(t1, t1, t2, p256_sm2_mod);

        /* y^2 - x^3 + 3.x = b, when a = -3  */
        sp_256_mont_add_sm2_9(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_9(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_9(t1, t1, point->x, p256_sm2_mod);


        if (sp_256_cmp_sm2_9(t1, p256_sm2_b) != 0) {
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
        sp_256_from_mp(pub->x, 9, pX);
        sp_256_from_mp(pub->y, 9, pY);
        sp_256_from_bin(pub->z, 9, one, (int)sizeof(one));

        err = sp_256_ecc_is_point_sm2_9(pub, NULL);
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
    sp_digit priv[9];
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
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 9, heap,
                                  DYNAMIC_TYPE_ECC);
        if (priv == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        p = pub + 1;

        sp_256_from_mp(pub->x, 9, pX);
        sp_256_from_mp(pub->y, 9, pY);
        sp_256_from_bin(pub->z, 9, one, (int)sizeof(one));
        if (privm)
            sp_256_from_mp(priv, 9, privm);

        /* Check point at infinitiy. */
        if ((sp_256_iszero_9(pub->x) != 0) &&
            (sp_256_iszero_9(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    /* Check range of X and Y */
    if ((err == MP_OKAY) &&
            ((sp_256_cmp_sm2_9(pub->x, p256_sm2_mod) >= 0) ||
             (sp_256_cmp_sm2_9(pub->y, p256_sm2_mod) >= 0))) {
        err = ECC_OUT_OF_RANGE_E;
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_256_ecc_is_point_sm2_9(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
            err = sp_256_ecc_mulmod_sm2_9(p, pub, p256_sm2_order, 1, 1, heap);
    }
    /* Check result is infinity */
    if ((err == MP_OKAY) && ((sp_256_iszero_9(p->x) == 0) ||
                             (sp_256_iszero_9(p->y) == 0))) {
        err = ECC_INF_E;
    }

    if (privm) {
        if (err == MP_OKAY) {
            /* Base * private = point */
                err = sp_256_ecc_mulmod_base_sm2_9(p, priv, 1, 1, heap);
        }
        /* Check result is public key */
        if ((err == MP_OKAY) &&
                ((sp_256_cmp_sm2_9(p->x, pub->x) != 0) ||
                 (sp_256_cmp_sm2_9(p->y, pub->y) != 0))) {
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
    sp_digit tmp[2 * 9 * 6];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 6, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        q = p + 1;

        sp_256_from_mp(p->x, 9, pX);
        sp_256_from_mp(p->y, 9, pY);
        sp_256_from_mp(p->z, 9, pZ);
        sp_256_from_mp(q->x, 9, qX);
        sp_256_from_mp(q->y, 9, qY);
        sp_256_from_mp(q->z, 9, qZ);
        p->infinity = sp_256_iszero_9(p->x) &
                      sp_256_iszero_9(p->y);
        q->infinity = sp_256_iszero_9(q->x) &
                      sp_256_iszero_9(q->y);

            sp_256_proj_point_add_sm2_9(p, p, q, tmp);
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
    sp_digit tmp[2 * 9 * 2];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 2, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 9, pX);
        sp_256_from_mp(p->y, 9, pY);
        sp_256_from_mp(p->z, 9, pZ);
        p->infinity = sp_256_iszero_9(p->x) &
                      sp_256_iszero_9(p->y);

            sp_256_proj_point_dbl_sm2_9(p, p, tmp);
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
    sp_digit tmp[2 * 9 * 5];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9 * 5, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 9, pX);
        sp_256_from_mp(p->y, 9, pY);
        sp_256_from_mp(p->z, 9, pZ);
        p->infinity = sp_256_iszero_9(p->x) &
                      sp_256_iszero_9(p->y);

            sp_256_map_sm2_9(p, p, tmp);
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
static const uint32_t p256_sm2_sqrt_power[8] = {
    0x00000000,0x40000000,0xc0000000,0xffffffff,0xffffffff,0xffffffff,
    0xbfffffff,0x3fffffff
};

/* Find the square root of a number mod the prime of the curve.
 *
 * y  The number to operate on and the result.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mont_sqrt_sm2_9(sp_digit* y)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t = NULL;
#else
    sp_digit t[2 * 9];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 9, NULL, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {

        {
            int i;

            XMEMCPY(t, y, sizeof(sp_digit) * 9);
            for (i=252; i>=0; i--) {
                sp_256_mont_sqr_sm2_9(t, t, p256_sm2_mod, p256_sm2_mp_mod);
                if (p256_sm2_sqrt_power[i / 32] & ((sp_digit)1 << (i % 32)))
                    sp_256_mont_mul_sm2_9(t, t, y, p256_sm2_mod, p256_sm2_mp_mod);
            }
            XMEMCPY(y, t, sizeof(sp_digit) * 9);
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
    sp_digit x[4 * 9];
#endif
    sp_digit* y = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    x = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 9, NULL, DYNAMIC_TYPE_ECC);
    if (x == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        y = x + 2 * 9;

        sp_256_from_mp(x, 9, xm);
        err = sp_256_mod_mul_norm_sm2_9(x, x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
        {
            sp_256_mont_sqr_sm2_9(y, x, p256_sm2_mod, p256_sm2_mp_mod);
            sp_256_mont_mul_sm2_9(y, y, x, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = x^3 - 3x */
        sp_256_mont_sub_sm2_9(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_9(y, y, x, p256_sm2_mod);
        /* y = x^3 - 3x + b */
        err = sp_256_mod_mul_norm_sm2_9(x, p256_sm2_b, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        sp_256_mont_add_sm2_9(y, y, x, p256_sm2_mod);
        /* y = sqrt(x^3 - 3x + b) */
        err = sp_256_mont_sqrt_sm2_9(y);
    }
    if (err == MP_OKAY) {
        XMEMSET(y + 9, 0, 9U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_9(y, p256_sm2_mod, p256_sm2_mp_mod);
        if ((((word32)y[0] ^ (word32)odd) & 1U) != 0U) {
            sp_256_mont_sub_sm2_9(y, p256_sm2_mod, y, p256_sm2_mod);
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
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
