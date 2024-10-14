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

#ifdef WOLFSSL_SP_X86_64_ASM
#define SP_PRINT_NUM(var, name, total, words, bits)         \
    do {                                                    \
        int ii;                                             \
        fprintf(stderr, name "=0x");                        \
        for (ii = (((bits) + 63) / 64) - 1; ii >= 0; ii--)  \
            fprintf(stderr, SP_PRINT_FMT, (var)[ii]);       \
        fprintf(stderr, "\n");                              \
    } while (0)

#define SP_PRINT_VAL(var, name)                             \
    fprintf(stderr, name "=0x" SP_PRINT_FMT "\n", var)

#define SP_PRINT_INT(var, name)                             \
    fprintf(stderr, name "=%d\n", var)

#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_SM2

/* Point structure to use. */
typedef struct sp_point_256 {
    /* X ordinate of point. */
    sp_digit x[2 * 4];
    /* Y ordinate of point. */
    sp_digit y[2 * 4];
    /* Z ordinate of point. */
    sp_digit z[2 * 4];
    /* Indicates point is at infinity. */
    int infinity;
} sp_point_256;

/* The modulus (prime) of the curve SM2 P256. */
static const sp_digit p256_sm2_mod[4] = {
    0xffffffffffffffffL,0xffffffff00000000L,0xffffffffffffffffL,
    0xfffffffeffffffffL
};
/* The Montgomery normalizer for modulus of the curve P256. */
static const sp_digit p256_sm2_norm_mod[4] = {
    0x0000000000000001L,0x00000000ffffffffL,0x0000000000000000L,
    0x0000000100000000L
};
/* The Montgomery multiplier for modulus of the curve P256. */
static const sp_digit p256_sm2_mp_mod = 0x0000000000000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P256. */
static const sp_digit p256_sm2_order[4] = {
    0x53bbf40939d54123L,0x7203df6b21c6052bL,0xffffffffffffffffL,
    0xfffffffeffffffffL
};
#endif
/* The order of the curve P256 minus 2. */
static const sp_digit p256_sm2_order2[4] = {
    0x53bbf40939d54121L,0x7203df6b21c6052bL,0xffffffffffffffffL,
    0xfffffffeffffffffL
};
#if defined(HAVE_ECC_SIGN)
/* The Montgomery normalizer for order of the curve P256. */
static const sp_digit p256_sm2_norm_order[4] = {
    0xac440bf6c62abeddL,0x8dfc2094de39fad4L,0x0000000000000000L,
    0x0000000100000000L
};
#endif
#if defined(HAVE_ECC_SIGN)
/* The Montgomery multiplier for order of the curve P256. */
static const sp_digit p256_sm2_mp_order = 0x327f9e8872350975L;
#endif
#ifdef WOLFSSL_SP_SMALL
/* The base point of curve P256. */
static const sp_point_256 p256_sm2_base = {
    /* X ordinate */
    {
        0x715a4589334c74c7L,0x8fe30bbff2660be1L,0x5f9904466a39c994L,
        0x32c4ae2c1f198119L,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Y ordinate */
    {
        0x02df32e52139f0a0L,0xd0a9877cc62a4740L,0x59bdcee36b692153L,
        0xbc3736a2f4f6779cL,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Z ordinate */
    {
        0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,
        0x0000000000000000L,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* infinity */
    0
};
#endif /* WOLFSSL_SP_SMALL */
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p256_sm2_b[4] = {
    0xddbcbd414d940e93L,0xf39789f515ab8f92L,0x4d5a9e4bcf6509a7L,
    0x28e9fa9e9d9f5e34L
};
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mul_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mul_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#endif /* HAVE_INTEL_AVX2 */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_sqr_sm2_4(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_sqr_avx2_sm2_4(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif
#endif /* HAVE_INTEL_AVX2 */
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_256_add_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_256_sub_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_256_sub_in_place_sm2_4(sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_256_cond_sub_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_256_cond_sub_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mul_d_sm2_4(sp_digit* r, const sp_digit* a, sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mul_d_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit b);
#ifdef __cplusplus
}
#endif
#if defined(_WIN64) && !defined(__clang__)
#if _MSC_VER < 1920
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit div_256_word_asm_4(sp_digit d1, sp_digit d0, sp_digit div);
#ifdef __cplusplus
}
#endif
#endif /* _MSC_VER < 1920 */
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_256_word_4(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
#if _MSC_VER >= 1920
    return _udiv128(d1, d0, div, NULL);
#else
    return div_256_word_asm_4(d1, d0, div);
#endif
}
#else
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_256_word_4(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    register sp_digit r asm("rax");
    ASSERT_SAVED_VECTOR_REGISTERS();
    __asm__ __volatile__ (
        "divq %3"
        : "=a" (r)
        : "d" (d1), "a" (d0), "r" (div)
        :
    );
    return r;
}
#endif /* _WIN64 && !__clang__ */
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_256_mask_4(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<4; i++) {
        r[i] = a[i] & m;
    }
#else
    r[0] = a[0] & m;
    r[1] = a[1] & m;
    r[2] = a[2] & m;
    r[3] = a[3] & m;
#endif
}

#ifdef __cplusplus
extern "C" {
#endif
extern sp_int64 sp_256_cmp_sm2_4(const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_256_div_sm2_4(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[8];
    sp_digit t2[5];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[3];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 4);
    r1 = sp_256_cmp_sm2_4(&t1[4], d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_256_cond_sub_avx2_sm2_4(&t1[4], &t1[4], d, (sp_digit)0 - r1);
    else
#endif
        sp_256_cond_sub_sm2_4(&t1[4], &t1[4], d, (sp_digit)0 - r1);
    for (i = 3; i >= 0; i--) {
        sp_digit mask = (sp_digit)0 - (t1[4 + i] == div);
        sp_digit hi = t1[4 + i] + mask;
        r1 = div_256_word_4(hi, t1[4 + i - 1], div);
        r1 |= mask;

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_256_mul_d_avx2_sm2_4(t2, d, r1);
        else
#endif
            sp_256_mul_d_sm2_4(t2, d, r1);
        t1[4 + i] += sp_256_sub_in_place_sm2_4(&t1[i], t2);
        t1[4 + i] -= t2[4];
        sp_256_mask_4(t2, d, t1[4 + i]);
        t1[4 + i] += sp_256_add_sm2_4(&t1[i], &t1[i], t2);
        sp_256_mask_4(t2, d, t1[4 + i]);
        t1[4 + i] += sp_256_add_sm2_4(&t1[i], &t1[i], t2);
    }

    r1 = sp_256_cmp_sm2_4(t1, d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_256_cond_sub_avx2_sm2_4(r, t1, d, (sp_digit)0 - r1);
    else
#endif
        sp_256_cond_sub_sm2_4(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_256_mod_sm2_4(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_256_div_sm2_4(a, m, NULL, r);
}

/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mod_mul_norm_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_256_mul_sm2_4(r, a, p256_sm2_norm_mod);
    return sp_256_mod_sm2_4(r, r, m);
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_256_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 64
    int i;
    sp_digit j = (sp_digit)0 - (sp_digit)a->used;
    int o = 0;

    for (i = 0; i < size; i++) {
        sp_digit mask = (sp_digit)0 - (j >> 63);
        r[i] = a->dp[o] & mask;
        j++;
        o += (int)(j >> 63);
    }
#elif DIGIT_BIT > 64
    unsigned int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < (unsigned int)a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffffffffffffl;
        s = 64U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 64U) <= (word32)DIGIT_BIT) {
            s += 64U;
            r[j] &= 0xffffffffffffffffl;
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
        if (s + DIGIT_BIT >= 64) {
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            s = 64 - s;
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
static void sp_256_point_from_ecc_point_4(sp_point_256* p,
        const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_256_from_mp(p->x, 4, pm->x);
    sp_256_from_mp(p->y, 4, pm->y);
    sp_256_from_mp(p->z, 4, pm->z);
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
#if DIGIT_BIT == 64
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 4);
        r->used = 4;
        mp_clamp(r);
#elif DIGIT_BIT < 64
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 4; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 64) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 64 - s;
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 4; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 64 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 64 - s;
            }
            else {
                s += 64;
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
static int sp_256_point_to_ecc_point_4(const sp_point_256* p, ecc_point* pm)
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_cond_copy_sm2_4(sp_digit* r, const sp_digit* a, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_mul_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_sqr_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#if !defined(WOLFSSL_SP_SMALL)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * n   Number of times to square.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_sqr_n_sm2_4(sp_digit* r,
    const sp_digit* a, int n, const sp_digit* m, sp_digit mp)
{
    sp_256_mont_sqr_sm2_4(r, a, m, mp);
    for (; n > 1; n--) {
        sp_256_mont_sqr_sm2_4(r, r, m, mp);
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
static void sp_256_mont_inv_sm2_4(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 4);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_sm2_4(t, t, p256_sm2_mod, p256_sm2_mp_mod);
        if (p256_sm2_mod_minus_2[i / 64] & ((sp_digit)1 << (i % 64)))
            sp_256_mont_mul_sm2_4(t, t, a, p256_sm2_mod, p256_sm2_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 4);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 4;
    sp_digit* t3 = td + 4 * 4;
    sp_digit* t4 = td + 6 * 4;
    /* 0x2 */
    sp_256_mont_sqr_sm2_4(t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0x3 */
    sp_256_mont_mul_sm2_4(t2, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xc */
    sp_256_mont_sqr_n_sm2_4(t1, t2, 2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xd */
    sp_256_mont_mul_sm2_4(t3, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf */
    sp_256_mont_mul_sm2_4(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf0 */
    sp_256_mont_sqr_n_sm2_4(t1, t2, 4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfd */
    sp_256_mont_mul_sm2_4(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff */
    sp_256_mont_mul_sm2_4(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff00 */
    sp_256_mont_sqr_n_sm2_4(t1, t2, 8, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffd */
    sp_256_mont_mul_sm2_4(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff */
    sp_256_mont_mul_sm2_4(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff0000 */
    sp_256_mont_sqr_n_sm2_4(t1, t2, 16, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffd */
    sp_256_mont_mul_sm2_4(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe */
    sp_256_mont_mul_sm2_4(t2, t3, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffffffff */
    sp_256_mont_mul_sm2_4(t4, t2, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe00000000 */
    sp_256_mont_sqr_n_sm2_4(t2, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff */
    sp_256_mont_mul_sm2_4(t2, t4, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff00000000 */
    sp_256_mont_sqr_n_sm2_4(t1, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff */
    sp_256_mont_mul_sm2_4(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_4(t1, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_4(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_4(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_4(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff0000000000000000 */
    sp_256_mont_sqr_n_sm2_4(r, r, 64, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff */
    sp_256_mont_mul_sm2_4(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff00000000 */
    sp_256_mont_sqr_n_sm2_4(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd */
    sp_256_mont_mul_sm2_4(r, r, t3, p256_sm2_mod, p256_sm2_mp_mod);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_256_norm_4(a)

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_reduce_sm2_4(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_reduce_order_sm2_4(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_256_map_sm2_4(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*4;
    sp_int64 n;

    sp_256_mont_inv_sm2_4(t1, p->z, t + 2*4);

    sp_256_mont_sqr_sm2_4(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    /* x /= z^2 */
    sp_256_mont_mul_sm2_4(r->x, p->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->x + 4, 0, sizeof(sp_digit) * 4U);
    sp_256_mont_reduce_sm2_4(r->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_256_cmp_sm2_4(r->x, p256_sm2_mod);
    sp_256_cond_sub_sm2_4(r->x, r->x, p256_sm2_mod, (sp_digit)~(n >> 63));
    sp_256_norm_4(r->x);

    /* y /= z^3 */
    sp_256_mont_mul_sm2_4(r->y, p->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->y + 4, 0, sizeof(sp_digit) * 4U);
    sp_256_mont_reduce_sm2_4(r->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_256_cmp_sm2_4(r->y, p256_sm2_mod);
    sp_256_cond_sub_sm2_4(r->y, r->y, p256_sm2_mod, (sp_digit)~(n >> 63));
    sp_256_norm_4(r->y);

    XMEMSET(r->z, 0, sizeof(r->z) / 2);
    r->z[0] = 1;
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_add_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, const sp_digit* m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_dbl_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_tpl_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_sub_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, const sp_digit* m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_div2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_rsb_sub_dbl_sm2_4(sp_digit* r, const sp_digit* a, sp_digit* b, const sp_digit* m);
#ifdef __cplusplus
}
#endif
/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_sm2_4(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*4;
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
    sp_256_mont_sqr_sm2_4(t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = Y * Z */
    sp_256_mont_mul_sm2_4(z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = 2Z */
    sp_256_mont_dbl_sm2_4(z, z, p256_sm2_mod);
    /* T2 = X - T1 */
    sp_256_mont_sub_sm2_4(t2, p->x, t1, p256_sm2_mod);
    /* T1 = X + T1 */
    sp_256_mont_add_sm2_4(t1, p->x, t1, p256_sm2_mod);
    /* T2 = T1 * T2 */
    sp_256_mont_mul_sm2_4(t2, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* T1 = 3T2 */
    sp_256_mont_tpl_sm2_4(t1, t2, p256_sm2_mod);
    /* Y = 2Y */
    sp_256_mont_dbl_sm2_4(y, p->y, p256_sm2_mod);
    /* Y = Y * Y */
    sp_256_mont_sqr_sm2_4(y, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = Y * Y */
    sp_256_mont_sqr_sm2_4(t2, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = T2/2 */
    sp_256_mont_div2_sm2_4(t2, t2, p256_sm2_mod);
    /* Y = Y * X */
    sp_256_mont_mul_sm2_4(y, y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = T1 * T1 */
    sp_256_mont_sqr_sm2_4(x, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = X - 2*Y */
    /* Y = Y - X */
    sp_256_mont_rsb_sub_dbl_sm2_4(x, x, y, p256_sm2_mod);
    /* Y = Y * T1 */
    sp_256_mont_mul_sm2_4(y, y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* Y = Y - T2 */
    sp_256_mont_sub_sm2_4(y, y, t2, p256_sm2_mod);
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_dbl_4_ctx {
    int state;
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
} sp_256_proj_point_dbl_4_ctx;

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_dbl_sm2_4_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_point_256* p, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_dbl_4_ctx* ctx = (sp_256_proj_point_dbl_sm2_4_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_proj_point_dbl_4_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0:
        ctx->t1 = t;
        ctx->t2 = t + 2*4;
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
        sp_256_mont_sqr_sm2_4(ctx->t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        /* Z = Y * Z */
        sp_256_mont_mul_sm2_4(ctx->z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        /* Z = 2Z */
        sp_256_mont_dbl_sm2_4(ctx->z, ctx->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4:
        /* T2 = X - T1 */
        sp_256_mont_sub_sm2_4(ctx->t2, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 5;
        break;
    case 5:
        /* T1 = X + T1 */
        sp_256_mont_add_sm2_4(ctx->t1, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 6;
        break;
    case 6:
        /* T2 = T1 * T2 */
        sp_256_mont_mul_sm2_4(ctx->t2, ctx->t1, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* T1 = 3T2 */
        sp_256_mont_tpl_sm2_4(ctx->t1, ctx->t2, p256_sm2_mod);
        ctx->state = 8;
        break;
    case 8:
        /* Y = 2Y */
        sp_256_mont_dbl_sm2_4(ctx->y, p->y, p256_sm2_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Y = Y * Y */
        sp_256_mont_sqr_sm2_4(ctx->y, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 10;
        break;
    case 10:
        /* T2 = Y * Y */
        sp_256_mont_sqr_sm2_4(ctx->t2, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 11;
        break;
    case 11:
        /* T2 = T2/2 */
        sp_256_mont_div2_sm2_4(ctx->t2, ctx->t2, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* Y = Y * X */
        sp_256_mont_mul_sm2_4(ctx->y, ctx->y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        /* X = T1 * T1 */
        sp_256_mont_sqr_sm2_4(ctx->x, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        /* X = X - 2*Y */
        /* Y = Y - X */
        sp_256_mont_rsb_sub_dbl_sm2_4(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 15;
        break;
    case 15:
        ctx->state = 16;
        break;
    case 16:
        ctx->state = 17;
        break;
    case 17:
        /* Y = Y * T1 */
        sp_256_mont_mul_sm2_4(ctx->y, ctx->y, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        /* Y = Y - T2 */
        sp_256_mont_sub_sm2_4(ctx->y, ctx->y, ctx->t2, p256_sm2_mod);
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
/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_sm2_4(sp_point_256* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*4;
    sp_digit* b = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_4(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_4(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_4(w, w, p256_sm2_mod, p256_sm2_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_4(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_4(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_4(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_4(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_rsb_sub_dbl_sm2_4(x, x, b, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_dbl_sm2_4(b, b, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_4(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_4(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_4(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_4(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(y, y, t1, p256_sm2_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_256_mont_sqr_sm2_4(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_4(t1, t1, w, p256_sm2_mod);
    sp_256_mont_tpl_sm2_4(a, t1, p256_sm2_mod);
    /* B = X*Y^2 */
    sp_256_mont_sqr_sm2_4(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = A^2 - 2B */
    sp_256_mont_sqr_sm2_4(x, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_rsb_sub_dbl_sm2_4(x, x, b, p256_sm2_mod);
    /* B = 2.(B - X) */
    sp_256_mont_dbl_sm2_4(b, b, p256_sm2_mod);
    /* Z = Z*Y */
    sp_256_mont_mul_sm2_4(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* t1 = Y^4 */
    sp_256_mont_sqr_sm2_4(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_256_mont_mul_sm2_4(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_4(y, y, t1, p256_sm2_mod);
#endif /* WOLFSSL_SP_SMALL */
    /* Y = Y/2 */
    sp_256_mont_div2_sm2_4(y, y, p256_sm2_mod);
}

/* Compare two numbers to determine if they are equal.
 * Constant time implementation.
 *
 * a  First number to compare.
 * b  Second number to compare.
 * returns 1 when equal and 0 otherwise.
 */
static int sp_256_cmp_equal_4(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
            (a[3] ^ b[3])) == 0;
}

/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_256_iszero_4(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}


/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_sm2_4(sp_point_256* r,
        const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t6 = t;
    sp_digit* t1 = t + 2*4;
    sp_digit* t2 = t + 4*4;
    sp_digit* t3 = t + 6*4;
    sp_digit* t4 = t + 8*4;
    sp_digit* t5 = t + 10*4;

    /* U1 = X1*Z2^2 */
    sp_256_mont_sqr_sm2_4(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t1, t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_4(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_4(t3, t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_4(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    /* Check double */
    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_4(t2, t1) &
            sp_256_cmp_equal_4(t4, t3)) {
        sp_256_proj_point_dbl_sm2_4(r, p, t);
    }
    else {
        sp_digit* x = t6;
        sp_digit* y = t1;
        sp_digit* z = t2;

        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_4(t2, t2, t1, p256_sm2_mod);
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_4(t4, t4, t3, p256_sm2_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_4(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(y, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_4(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(z, z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_4(x, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(x, x, t5, p256_sm2_mod);
        sp_256_mont_mul_sm2_4(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_rsb_sub_dbl_sm2_4(x, x, y, p256_sm2_mod);
        sp_256_mont_mul_sm2_4(y, y, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(y, y, t5, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 4; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_add_4_ctx {
    int state;
    sp_256_proj_point_dbl_4_ctx dbl_ctx;
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
} sp_256_proj_point_add_4_ctx;

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_add_sm2_4_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_add_4_ctx* ctx = (sp_256_proj_point_add_sm2_4_ctx*)sp_ctx->data;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_256* a = p;
        p = q;
        q = a;
    }

    typedef char ctx_size_test[sizeof(sp_256_proj_point_add_4_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0: /* INIT */
        ctx->t6 = t;
        ctx->t1 = t + 2*4;
        ctx->t2 = t + 4*4;
        ctx->t3 = t + 6*4;
        ctx->t4 = t + 8*4;
        ctx->t5 = t + 10*4;
        ctx->x = ctx->t6;
        ctx->y = ctx->t1;
        ctx->z = ctx->t2;

        ctx->state = 1;
        break;
    case 1:
        /* U1 = X1*Z2^2 */
        sp_256_mont_sqr_sm2_4(ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        sp_256_mont_mul_sm2_4(ctx->t3, ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        sp_256_mont_mul_sm2_4(ctx->t1, ctx->t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 4;
        break;
    case 4:
        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_sm2_4(ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 5;
        break;
    case 5:
        sp_256_mont_mul_sm2_4(ctx->t4, ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 6;
        break;
    case 6:
        sp_256_mont_mul_sm2_4(ctx->t2, ctx->t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* S1 = Y1*Z2^3 */
        sp_256_mont_mul_sm2_4(ctx->t3, ctx->t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 8;
        break;
    case 8:
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_sm2_4(ctx->t4, ctx->t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Check double */
        if ((~p->infinity) & (~q->infinity) &
                sp_256_cmp_equal_4(ctx->t2, ctx->t1) &
                sp_256_cmp_equal_4(ctx->t4, ctx->t3)) {
            XMEMSET(&ctx->dbl_ctx, 0, sizeof(ctx->dbl_ctx));
            sp_256_proj_point_dbl_sm2_4(r, p, t);
            ctx->state = 25;
        }
        else {
            ctx->state = 10;
        }
        break;
    case 10:
        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_4(ctx->t2, ctx->t2, ctx->t1, p256_sm2_mod);
        ctx->state = 11;
        break;
    case 11:
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_4(ctx->t4, ctx->t4, ctx->t3, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_4(ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        sp_256_mont_mul_sm2_4(ctx->y, ctx->t1, ctx->t5, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        sp_256_mont_mul_sm2_4(ctx->t5, ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 15;
        break;
    case 15:
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_4(ctx->z, p->z, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 16;
        break;
    case 16:
        sp_256_mont_mul_sm2_4(ctx->z, ctx->z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 17;
        break;
    case 17:
        sp_256_mont_sqr_sm2_4(ctx->x, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        sp_256_mont_sub_sm2_4(ctx->x, ctx->x, ctx->t5, p256_sm2_mod);
        ctx->state = 19;
        break;
    case 19:
        sp_256_mont_mul_sm2_4(ctx->t5, ctx->t5, ctx->t3, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 20;
        break;
    case 20:
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_rsb_sub_dbl_sm2_4(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 21;
        break;
    case 21:
        ctx->state = 22;
        break;
    case 22:
        sp_256_mont_mul_sm2_4(ctx->y, ctx->y, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 23;
        break;
    case 23:
        sp_256_mont_sub_sm2_4(ctx->y, ctx->y, ctx->t5, p256_sm2_mod);
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

            for (i = 0; i < 4; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (ctx->x[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (ctx->y[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
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

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_store_sm2_4(sp_point_256* r,
        const sp_point_256* p, int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*4;
    sp_digit* b = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;
    int j;

    for (i=0; i<4; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<4; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<4; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_4(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_4(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_4(w, w, p256_sm2_mod, p256_sm2_mp_mod);
    j = m;
    for (i=1; i<=n; i++) {
        j *= 2;

        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_4(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_4(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_4(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        x = r[j].x;
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_4(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_rsb_sub_dbl_sm2_4(x, x, b, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_dbl_sm2_4(b, b, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_4(r[j].z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        z = r[j].z;
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_4(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_4(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_4(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(y, y, t1, p256_sm2_mod);
        /* Y = Y/2 */
        sp_256_mont_div2_sm2_4(r[j].y, y, p256_sm2_mod);
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
static void sp_256_proj_point_add_sub_sm2_4(sp_point_256* ra,
        sp_point_256* rs, const sp_point_256* p, const sp_point_256* q,
        sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*4;
    sp_digit* t3 = t + 4*4;
    sp_digit* t4 = t + 6*4;
    sp_digit* t5 = t + 8*4;
    sp_digit* t6 = t + 10*4;
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
    sp_256_mont_sqr_sm2_4(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t1, t1, xa, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_4(t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t4, t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_4(t3, t3, ya, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_4(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* H = U2 - U1 */
    sp_256_mont_sub_sm2_4(t2, t2, t1, p256_sm2_mod);
    /* RS = S2 + S1 */
    sp_256_mont_add_sm2_4(t6, t4, t3, p256_sm2_mod);
    /* R = S2 - S1 */
    sp_256_mont_sub_sm2_4(t4, t4, t3, p256_sm2_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_256_mont_mul_sm2_4(za, za, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(za, za, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(zs, za, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_256_mont_sqr_sm2_4(xa, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_4(xs, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_4(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(ya, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_4(xa, xa, t5, p256_sm2_mod);
    sp_256_mont_sub_sm2_4(xs, xs, t5, p256_sm2_mod);
    sp_256_mont_dbl_sm2_4(t1, ya, p256_sm2_mod);
    sp_256_mont_sub_sm2_4(xa, xa, t1, p256_sm2_mod);
    sp_256_mont_sub_sm2_4(xs, xs, t1, p256_sm2_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_256_mont_sub_sm2_4(ys, ya, xs, p256_sm2_mod);
    sp_256_mont_sub_sm2_4(ya, ya, xa, p256_sm2_mod);
    sp_256_mont_mul_sm2_4(ya, ya, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_sub_sm2_4(t6, p256_sm2_mod, t6);
    sp_256_mont_mul_sm2_4(ys, ys, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_4(ya, ya, t5, p256_sm2_mod);
    sp_256_mont_sub_sm2_4(ys, ys, t5, p256_sm2_mod);
}

/* Structure used to describe recoding of scalar multiplication. */
typedef struct ecc_recode_256 {
    /* Index into pre-computation table. */
    uint8_t i;
    /* Use the negative of the point. */
    uint8_t neg;
} ecc_recode_256;

/* The index into pre-computation table to use. */
static const uint8_t recode_index_4_6[66] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const uint8_t recode_neg_4_6[66] = {
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
static void sp_256_ecc_recode_6_4(const sp_digit* k, ecc_recode_256* v)
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
        if (o + 6 < 64) {
            y &= 0x3f;
            n >>= 6;
            o += 6;
        }
        else if (o + 6 == 64) {
            n >>= 6;
            if (++j < 4)
                n = k[j];
            o = 0;
        }
        else if (++j < 4) {
            n = k[j];
            y |= (uint8_t)((n << (64 - o)) & 0x3f);
            o -= 58;
            n >>= o;
        }

        y += (uint8_t)carry;
        v[i].i = recode_index_4_6[y];
        v[i].neg = recode_neg_4_6[y];
        carry = (y >> 6) + v[i].neg;
    }
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_get_point_33_sm2_4(sp_point_256* r, const sp_point_256* table, int idx);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_get_point_33_avx2_sm2_4(sp_point_256* r, const sp_point_256* table, int idx);
#ifdef __cplusplus
}
#endif
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
static int sp_256_ecc_mulmod_win_add_sub_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[33+2];
    sp_digit tmp[2 * 4 * 6];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 6,
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
        err = sp_256_mod_mul_norm_sm2_4(t[1].x, g->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_4(t[1].y, g->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_4(t[1].z, g->z, p256_sm2_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_256_proj_point_dbl_n_store_sm2_4(t, &t[ 1], 5, 1, tmp);
        sp_256_proj_point_add_sm2_4(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[ 6], &t[ 3], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[10], &t[ 5], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[12], &t[ 6], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[14], &t[ 7], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[18], &t[ 9], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[20], &t[10], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[22], &t[11], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[24], &t[12], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[26], &t[13], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[28], &t[14], tmp);
        sp_256_proj_point_dbl_sm2_4(&t[30], &t[15], tmp);
        sp_256_proj_point_add_sub_sm2_4(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_256_ecc_recode_6_4(k, v);

        i = 42;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_point_33_sm2_4(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_256));
        }
        for (--i; i>=0; i--) {
            sp_256_proj_point_dbl_n_sm2_4(rt, 6, tmp);

        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_point_33_sm2_4(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
        #endif
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_256));
            }
            sp_256_sub_sm2_4(negy, p256_sm2_mod, p->y);
            sp_256_norm_4(negy);
            sp_256_cond_copy_sm2_4(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_256_proj_point_add_sm2_4(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_256_map_sm2_4(r, rt, tmp);
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

#ifdef HAVE_INTEL_AVX2
#ifdef HAVE_INTEL_AVX2
/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mod_mul_norm_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_256_mul_avx2_sm2_4(r, a, p256_sm2_norm_mod);
    return sp_256_mod_sm2_4(r, r, m);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_mul_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_sqr_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#if !defined(WOLFSSL_SP_SMALL)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * n   Number of times to square.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_sqr_n_avx2_sm2_4(sp_digit* r,
    const sp_digit* a, int n, const sp_digit* m, sp_digit mp)
{
    sp_256_mont_sqr_avx2_sm2_4(r, a, m, mp);
    for (; n > 1; n--) {
        sp_256_mont_sqr_avx2_sm2_4(r, r, m, mp);
    }
}

#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P256 curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_256_mont_inv_avx2_sm2_4(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 4);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_avx2_sm2_4(t, t, p256_sm2_mod, p256_sm2_mp_mod);
        if (p256_sm2_mod_minus_2[i / 64] & ((sp_digit)1 << (i % 64)))
            sp_256_mont_mul_avx2_sm2_4(t, t, a, p256_sm2_mod, p256_sm2_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 4);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 4;
    sp_digit* t3 = td + 4 * 4;
    sp_digit* t4 = td + 6 * 4;
    /* 0x2 */
    sp_256_mont_sqr_avx2_sm2_4(t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0x3 */
    sp_256_mont_mul_avx2_sm2_4(t2, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xc */
    sp_256_mont_sqr_n_avx2_sm2_4(t1, t2, 2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xd */
    sp_256_mont_mul_avx2_sm2_4(t3, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf */
    sp_256_mont_mul_avx2_sm2_4(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf0 */
    sp_256_mont_sqr_n_avx2_sm2_4(t1, t2, 4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfd */
    sp_256_mont_mul_avx2_sm2_4(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff */
    sp_256_mont_mul_avx2_sm2_4(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff00 */
    sp_256_mont_sqr_n_avx2_sm2_4(t1, t2, 8, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffd */
    sp_256_mont_mul_avx2_sm2_4(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff */
    sp_256_mont_mul_avx2_sm2_4(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff0000 */
    sp_256_mont_sqr_n_avx2_sm2_4(t1, t2, 16, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffd */
    sp_256_mont_mul_avx2_sm2_4(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe */
    sp_256_mont_mul_avx2_sm2_4(t2, t3, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffffffff */
    sp_256_mont_mul_avx2_sm2_4(t4, t2, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe00000000 */
    sp_256_mont_sqr_n_avx2_sm2_4(t2, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff */
    sp_256_mont_mul_avx2_sm2_4(t2, t4, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff00000000 */
    sp_256_mont_sqr_n_avx2_sm2_4(t1, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff */
    sp_256_mont_mul_avx2_sm2_4(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff00000000 */
    sp_256_mont_sqr_n_avx2_sm2_4(t1, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff */
    sp_256_mont_mul_avx2_sm2_4(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff00000000 */
    sp_256_mont_sqr_n_avx2_sm2_4(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff */
    sp_256_mont_mul_avx2_sm2_4(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff0000000000000000 */
    sp_256_mont_sqr_n_avx2_sm2_4(r, r, 64, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff */
    sp_256_mont_mul_avx2_sm2_4(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff00000000 */
    sp_256_mont_sqr_n_avx2_sm2_4(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd */
    sp_256_mont_mul_avx2_sm2_4(r, r, t3, p256_sm2_mod, p256_sm2_mp_mod);
#endif /* WOLFSSL_SP_SMALL */
}

#define sp_256_mont_reduce_avx2_sm2_4         sp_256_mont_reduce_sm2_4
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_reduce_order_avx2_sm2_4(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_256_map_avx2_sm2_4(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*4;
    sp_int64 n;

    sp_256_mont_inv_avx2_sm2_4(t1, p->z, t + 2*4);

    sp_256_mont_sqr_avx2_sm2_4(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    /* x /= z^2 */
    sp_256_mont_mul_avx2_sm2_4(r->x, p->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->x + 4, 0, sizeof(sp_digit) * 4U);
    sp_256_mont_reduce_avx2_sm2_4(r->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_256_cmp_sm2_4(r->x, p256_sm2_mod);
    sp_256_cond_sub_sm2_4(r->x, r->x, p256_sm2_mod, (sp_digit)~(n >> 63));
    sp_256_norm_4(r->x);

    /* y /= z^3 */
    sp_256_mont_mul_avx2_sm2_4(r->y, p->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->y + 4, 0, sizeof(sp_digit) * 4U);
    sp_256_mont_reduce_avx2_sm2_4(r->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_256_cmp_sm2_4(r->y, p256_sm2_mod);
    sp_256_cond_sub_sm2_4(r->y, r->y, p256_sm2_mod, (sp_digit)~(n >> 63));
    sp_256_norm_4(r->y);

    XMEMSET(r->z, 0, sizeof(r->z) / 2);
    r->z[0] = 1;
}

#define sp_256_mont_add_avx2_sm2_4 sp_256_mont_add_sm2_4
#define sp_256_mont_dbl_avx2_sm2_4 sp_256_mont_dbl_sm2_4
#define sp_256_mont_tpl_avx2_sm2_4 sp_256_mont_tpl_sm2_4
#define sp_256_mont_sub_avx2_sm2_4 sp_256_mont_sub_sm2_4
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_mont_div2_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m);
#ifdef __cplusplus
}
#endif
#define sp_256_mont_rsb_sub_dbl_avx2_sm2_4 sp_256_mont_rsb_sub_dbl_sm2_4
/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_avx2_sm2_4(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*4;
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
    sp_256_mont_sqr_avx2_sm2_4(t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = Y * Z */
    sp_256_mont_mul_avx2_sm2_4(z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = 2Z */
    sp_256_mont_dbl_avx2_sm2_4(z, z, p256_sm2_mod);
    /* T2 = X - T1 */
    sp_256_mont_sub_avx2_sm2_4(t2, p->x, t1, p256_sm2_mod);
    /* T1 = X + T1 */
    sp_256_mont_add_avx2_sm2_4(t1, p->x, t1, p256_sm2_mod);
    /* T2 = T1 * T2 */
    sp_256_mont_mul_avx2_sm2_4(t2, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* T1 = 3T2 */
    sp_256_mont_tpl_avx2_sm2_4(t1, t2, p256_sm2_mod);
    /* Y = 2Y */
    sp_256_mont_dbl_avx2_sm2_4(y, p->y, p256_sm2_mod);
    /* Y = Y * Y */
    sp_256_mont_sqr_avx2_sm2_4(y, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = Y * Y */
    sp_256_mont_sqr_avx2_sm2_4(t2, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = T2/2 */
    sp_256_mont_div2_avx2_sm2_4(t2, t2, p256_sm2_mod);
    /* Y = Y * X */
    sp_256_mont_mul_avx2_sm2_4(y, y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = T1 * T1 */
    sp_256_mont_sqr_avx2_sm2_4(x, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = X - 2*Y */
    /* Y = Y - X */
    sp_256_mont_rsb_sub_dbl_avx2_sm2_4(x, x, y, p256_sm2_mod);
    /* Y = Y * T1 */
    sp_256_mont_mul_avx2_sm2_4(y, y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* Y = Y - T2 */
    sp_256_mont_sub_avx2_sm2_4(y, y, t2, p256_sm2_mod);
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_dbl_avx2_4_ctx {
    int state;
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
} sp_256_proj_point_dbl_avx2_4_ctx;

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_dbl_avx2_sm2_4_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_point_256* p, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_dbl_avx2_4_ctx* ctx = (sp_256_proj_point_dbl_avx2_sm2_4_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_proj_point_dbl_avx2_4_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0:
        ctx->t1 = t;
        ctx->t2 = t + 2*4;
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
        sp_256_mont_sqr_avx2_sm2_4(ctx->t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        /* Z = Y * Z */
        sp_256_mont_mul_avx2_sm2_4(ctx->z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        /* Z = 2Z */
        sp_256_mont_dbl_avx2_sm2_4(ctx->z, ctx->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4:
        /* T2 = X - T1 */
        sp_256_mont_sub_avx2_sm2_4(ctx->t2, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 5;
        break;
    case 5:
        /* T1 = X + T1 */
        sp_256_mont_add_avx2_sm2_4(ctx->t1, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 6;
        break;
    case 6:
        /* T2 = T1 * T2 */
        sp_256_mont_mul_avx2_sm2_4(ctx->t2, ctx->t1, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* T1 = 3T2 */
        sp_256_mont_tpl_avx2_sm2_4(ctx->t1, ctx->t2, p256_sm2_mod);
        ctx->state = 8;
        break;
    case 8:
        /* Y = 2Y */
        sp_256_mont_dbl_avx2_sm2_4(ctx->y, p->y, p256_sm2_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Y = Y * Y */
        sp_256_mont_sqr_avx2_sm2_4(ctx->y, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 10;
        break;
    case 10:
        /* T2 = Y * Y */
        sp_256_mont_sqr_avx2_sm2_4(ctx->t2, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 11;
        break;
    case 11:
        /* T2 = T2/2 */
        sp_256_mont_div2_avx2_sm2_4(ctx->t2, ctx->t2, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* Y = Y * X */
        sp_256_mont_mul_avx2_sm2_4(ctx->y, ctx->y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        /* X = T1 * T1 */
        sp_256_mont_sqr_avx2_sm2_4(ctx->x, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        /* X = X - 2*Y */
        /* Y = Y - X */
        sp_256_mont_rsb_sub_dbl_avx2_sm2_4(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 15;
        break;
    case 15:
        ctx->state = 16;
        break;
    case 16:
        ctx->state = 17;
        break;
    case 17:
        /* Y = Y * T1 */
        sp_256_mont_mul_avx2_sm2_4(ctx->y, ctx->y, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        /* Y = Y - T2 */
        sp_256_mont_sub_avx2_sm2_4(ctx->y, ctx->y, ctx->t2, p256_sm2_mod);
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
/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_avx2_sm2_4(sp_point_256* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*4;
    sp_digit* b = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_256_mont_dbl_avx2_sm2_4(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_avx2_sm2_4(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_avx2_sm2_4(w, w, p256_sm2_mod, p256_sm2_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_avx2_sm2_4(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_avx2_sm2_4(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_avx2_sm2_4(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        /* X = A^2 - 2B */
        sp_256_mont_sqr_avx2_sm2_4(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_rsb_sub_dbl_avx2_sm2_4(x, x, b, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_dbl_avx2_sm2_4(b, b, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_avx2_sm2_4(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        /* t1 = Y^4 */
        sp_256_mont_sqr_avx2_sm2_4(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_256_mont_mul_avx2_sm2_4(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_avx2_sm2_4(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(y, y, t1, p256_sm2_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_256_mont_sqr_avx2_sm2_4(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_avx2_sm2_4(t1, t1, w, p256_sm2_mod);
    sp_256_mont_tpl_avx2_sm2_4(a, t1, p256_sm2_mod);
    /* B = X*Y^2 */
    sp_256_mont_sqr_avx2_sm2_4(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = A^2 - 2B */
    sp_256_mont_sqr_avx2_sm2_4(x, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_rsb_sub_dbl_avx2_sm2_4(x, x, b, p256_sm2_mod);
    /* B = 2.(B - X) */
    sp_256_mont_dbl_avx2_sm2_4(b, b, p256_sm2_mod);
    /* Z = Z*Y */
    sp_256_mont_mul_avx2_sm2_4(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* t1 = Y^4 */
    sp_256_mont_sqr_avx2_sm2_4(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_256_mont_mul_avx2_sm2_4(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_avx2_sm2_4(y, y, t1, p256_sm2_mod);
#endif /* WOLFSSL_SP_SMALL */
    /* Y = Y/2 */
    sp_256_mont_div2_avx2_sm2_4(y, y, p256_sm2_mod);
}


/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_avx2_sm2_4(sp_point_256* r,
        const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t6 = t;
    sp_digit* t1 = t + 2*4;
    sp_digit* t2 = t + 4*4;
    sp_digit* t3 = t + 6*4;
    sp_digit* t4 = t + 8*4;
    sp_digit* t5 = t + 10*4;

    /* U1 = X1*Z2^2 */
    sp_256_mont_sqr_avx2_sm2_4(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t1, t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_avx2_sm2_4(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_avx2_sm2_4(t3, t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_avx2_sm2_4(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    /* Check double */
    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_4(t2, t1) &
            sp_256_cmp_equal_4(t4, t3)) {
        sp_256_proj_point_dbl_avx2_sm2_4(r, p, t);
    }
    else {
        sp_digit* x = t6;
        sp_digit* y = t1;
        sp_digit* z = t2;

        /* H = U2 - U1 */
        sp_256_mont_sub_avx2_sm2_4(t2, t2, t1, p256_sm2_mod);
        /* R = S2 - S1 */
        sp_256_mont_sub_avx2_sm2_4(t4, t4, t3, p256_sm2_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_avx2_sm2_4(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(y, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_avx2_sm2_4(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(z, z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_avx2_sm2_4(x, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(x, x, t5, p256_sm2_mod);
        sp_256_mont_mul_avx2_sm2_4(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_rsb_sub_dbl_avx2_sm2_4(x, x, y, p256_sm2_mod);
        sp_256_mont_mul_avx2_sm2_4(y, y, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(y, y, t5, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 4; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_add_avx2_4_ctx {
    int state;
    sp_256_proj_point_dbl_avx2_4_ctx dbl_ctx;
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
} sp_256_proj_point_add_avx2_4_ctx;

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_add_avx2_sm2_4_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_add_avx2_4_ctx* ctx = (sp_256_proj_point_add_avx2_sm2_4_ctx*)sp_ctx->data;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_256* a = p;
        p = q;
        q = a;
    }

    typedef char ctx_size_test[sizeof(sp_256_proj_point_add_avx2_4_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0: /* INIT */
        ctx->t6 = t;
        ctx->t1 = t + 2*4;
        ctx->t2 = t + 4*4;
        ctx->t3 = t + 6*4;
        ctx->t4 = t + 8*4;
        ctx->t5 = t + 10*4;
        ctx->x = ctx->t6;
        ctx->y = ctx->t1;
        ctx->z = ctx->t2;

        ctx->state = 1;
        break;
    case 1:
        /* U1 = X1*Z2^2 */
        sp_256_mont_sqr_avx2_sm2_4(ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        sp_256_mont_mul_avx2_sm2_4(ctx->t3, ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        sp_256_mont_mul_avx2_sm2_4(ctx->t1, ctx->t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 4;
        break;
    case 4:
        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_avx2_sm2_4(ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 5;
        break;
    case 5:
        sp_256_mont_mul_avx2_sm2_4(ctx->t4, ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 6;
        break;
    case 6:
        sp_256_mont_mul_avx2_sm2_4(ctx->t2, ctx->t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* S1 = Y1*Z2^3 */
        sp_256_mont_mul_avx2_sm2_4(ctx->t3, ctx->t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 8;
        break;
    case 8:
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_avx2_sm2_4(ctx->t4, ctx->t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Check double */
        if ((~p->infinity) & (~q->infinity) &
                sp_256_cmp_equal_4(ctx->t2, ctx->t1) &
                sp_256_cmp_equal_4(ctx->t4, ctx->t3)) {
            XMEMSET(&ctx->dbl_ctx, 0, sizeof(ctx->dbl_ctx));
            sp_256_proj_point_dbl_avx2_sm2_4(r, p, t);
            ctx->state = 25;
        }
        else {
            ctx->state = 10;
        }
        break;
    case 10:
        /* H = U2 - U1 */
        sp_256_mont_sub_avx2_sm2_4(ctx->t2, ctx->t2, ctx->t1, p256_sm2_mod);
        ctx->state = 11;
        break;
    case 11:
        /* R = S2 - S1 */
        sp_256_mont_sub_avx2_sm2_4(ctx->t4, ctx->t4, ctx->t3, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_avx2_sm2_4(ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        sp_256_mont_mul_avx2_sm2_4(ctx->y, ctx->t1, ctx->t5, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        sp_256_mont_mul_avx2_sm2_4(ctx->t5, ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 15;
        break;
    case 15:
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_avx2_sm2_4(ctx->z, p->z, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 16;
        break;
    case 16:
        sp_256_mont_mul_avx2_sm2_4(ctx->z, ctx->z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 17;
        break;
    case 17:
        sp_256_mont_sqr_avx2_sm2_4(ctx->x, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        sp_256_mont_sub_avx2_sm2_4(ctx->x, ctx->x, ctx->t5, p256_sm2_mod);
        ctx->state = 19;
        break;
    case 19:
        sp_256_mont_mul_avx2_sm2_4(ctx->t5, ctx->t5, ctx->t3, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 20;
        break;
    case 20:
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_rsb_sub_dbl_avx2_sm2_4(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 21;
        break;
    case 21:
        ctx->state = 22;
        break;
    case 22:
        sp_256_mont_mul_avx2_sm2_4(ctx->y, ctx->y, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 23;
        break;
    case 23:
        sp_256_mont_sub_avx2_sm2_4(ctx->y, ctx->y, ctx->t5, p256_sm2_mod);
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

            for (i = 0; i < 4; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (ctx->x[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (ctx->y[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
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

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_store_avx2_sm2_4(sp_point_256* r,
        const sp_point_256* p, int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*4;
    sp_digit* b = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;
    int j;

    for (i=0; i<4; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<4; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<4; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_256_mont_dbl_avx2_sm2_4(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_avx2_sm2_4(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_avx2_sm2_4(w, w, p256_sm2_mod, p256_sm2_mp_mod);
    j = m;
    for (i=1; i<=n; i++) {
        j *= 2;

        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_avx2_sm2_4(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_avx2_sm2_4(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_avx2_sm2_4(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        x = r[j].x;
        /* X = A^2 - 2B */
        sp_256_mont_sqr_avx2_sm2_4(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_rsb_sub_dbl_avx2_sm2_4(x, x, b, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_dbl_avx2_sm2_4(b, b, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_avx2_sm2_4(r[j].z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        z = r[j].z;
        /* t1 = Y^4 */
        sp_256_mont_sqr_avx2_sm2_4(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_256_mont_mul_avx2_sm2_4(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_avx2_sm2_4(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(y, y, t1, p256_sm2_mod);
        /* Y = Y/2 */
        sp_256_mont_div2_avx2_sm2_4(r[j].y, y, p256_sm2_mod);
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
static void sp_256_proj_point_add_sub_avx2_sm2_4(sp_point_256* ra,
        sp_point_256* rs, const sp_point_256* p, const sp_point_256* q,
        sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*4;
    sp_digit* t3 = t + 4*4;
    sp_digit* t4 = t + 6*4;
    sp_digit* t5 = t + 8*4;
    sp_digit* t6 = t + 10*4;
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
    sp_256_mont_sqr_avx2_sm2_4(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t1, t1, xa, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_avx2_sm2_4(t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t4, t2, za, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_avx2_sm2_4(t3, t3, ya, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_avx2_sm2_4(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* H = U2 - U1 */
    sp_256_mont_sub_avx2_sm2_4(t2, t2, t1, p256_sm2_mod);
    /* RS = S2 + S1 */
    sp_256_mont_add_avx2_sm2_4(t6, t4, t3, p256_sm2_mod);
    /* R = S2 - S1 */
    sp_256_mont_sub_avx2_sm2_4(t4, t4, t3, p256_sm2_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_256_mont_mul_avx2_sm2_4(za, za, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(za, za, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(zs, za, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_256_mont_sqr_avx2_sm2_4(xa, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_avx2_sm2_4(xs, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_avx2_sm2_4(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(ya, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_avx2_sm2_4(xa, xa, t5, p256_sm2_mod);
    sp_256_mont_sub_avx2_sm2_4(xs, xs, t5, p256_sm2_mod);
    sp_256_mont_dbl_avx2_sm2_4(t1, ya, p256_sm2_mod);
    sp_256_mont_sub_avx2_sm2_4(xa, xa, t1, p256_sm2_mod);
    sp_256_mont_sub_avx2_sm2_4(xs, xs, t1, p256_sm2_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_256_mont_sub_avx2_sm2_4(ys, ya, xs, p256_sm2_mod);
    sp_256_mont_sub_avx2_sm2_4(ya, ya, xa, p256_sm2_mod);
    sp_256_mont_mul_avx2_sm2_4(ya, ya, t4, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_sub_sm2_4(t6, p256_sm2_mod, t6);
    sp_256_mont_mul_avx2_sm2_4(ys, ys, t6, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_avx2_sm2_4(ya, ya, t5, p256_sm2_mod);
    sp_256_mont_sub_avx2_sm2_4(ys, ys, t5, p256_sm2_mod);
}

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
static int sp_256_ecc_mulmod_win_add_sub_avx2_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[33+2];
    sp_digit tmp[2 * 4 * 6];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 6,
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
        err = sp_256_mod_mul_norm_avx2_sm2_4(t[1].x, g->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_avx2_sm2_4(t[1].y, g->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_avx2_sm2_4(t[1].z, g->z, p256_sm2_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_256_proj_point_dbl_n_store_avx2_sm2_4(t, &t[ 1], 5, 1, tmp);
        sp_256_proj_point_add_avx2_sm2_4(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[ 6], &t[ 3], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[10], &t[ 5], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[12], &t[ 6], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[14], &t[ 7], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[18], &t[ 9], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[20], &t[10], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[22], &t[11], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[24], &t[12], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[26], &t[13], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[28], &t[14], tmp);
        sp_256_proj_point_dbl_avx2_sm2_4(&t[30], &t[15], tmp);
        sp_256_proj_point_add_sub_avx2_sm2_4(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_256_ecc_recode_6_4(k, v);

        i = 42;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_point_33_avx2_sm2_4(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_256));
        }
        for (--i; i>=0; i--) {
            sp_256_proj_point_dbl_n_avx2_sm2_4(rt, 6, tmp);

        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_point_33_avx2_sm2_4(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
        #endif
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_256));
            }
            sp_256_sub_sm2_4(negy, p256_sm2_mod, p->y);
            sp_256_norm_4(negy);
            sp_256_cond_copy_sm2_4(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_256_proj_point_add_avx2_sm2_4(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_256_map_avx2_sm2_4(r, rt, tmp);
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

#endif /* HAVE_INTEL_AVX2 */
/* A table entry for pre-computed points. */
typedef struct sp_table_entry_256 {
    sp_digit x[4];
    sp_digit y[4];
} sp_table_entry_256;

#if defined(FP_ECC) || defined(WOLFSSL_SP_SMALL)
#endif /* FP_ECC | WOLFSSL_SP_SMALL */
/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_qz1_sm2_4(sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*4;
    sp_digit* t6 = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* t4 = t + 8*4;

    /* Calculate values to subtract from P->x and P->y. */
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_4(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_4(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_4(p->x, t2) &
            sp_256_cmp_equal_4(p->y, t4)) {
        sp_256_proj_point_dbl_sm2_4(r, p, t);
    }
    else {
        sp_digit* x = t2;
        sp_digit* y = t3;
        sp_digit* z = t6;

        /* H = U2 - X1 */
        sp_256_mont_sub_sm2_4(t2, t2, p->x, p256_sm2_mod);
        /* R = S2 - Y1 */
        sp_256_mont_sub_sm2_4(t4, t4, p->y, p256_sm2_mod);
        /* Z3 = H*Z1 */
        sp_256_mont_mul_sm2_4(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_256_mont_sqr_sm2_4(t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(t3, p->x, t1, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(t1, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_4(t2, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(t2, t2, t1, p256_sm2_mod);
        sp_256_mont_rsb_sub_dbl_sm2_4(x, t2, t3, p256_sm2_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_mul_sm2_4(t3, t3, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_4(t1, t1, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_4(y, t3, t1, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 4; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
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
static void sp_256_proj_to_affine_sm2_4(sp_point_256* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 4;
    sp_digit* tmp = t + 4 * 4;

    sp_256_mont_inv_sm2_4(t1, a->z, tmp);

    sp_256_mont_sqr_sm2_4(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    sp_256_mont_mul_sm2_4(a->x, a->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_4(a->y, a->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(a->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
}

/* Generate the pre-computed table of points for the base point.
 *
 * width = 6
 * 64 entries
 * 42 bits between
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temporary data.
 * heap  Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_sm2_4(const sp_point_256* a,
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

        err = sp_256_mod_mul_norm_sm2_4(t->x, a->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_4(t->y, a->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_4(t->z, a->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_sm2_4(t, tmp);

        XMEMCPY(s1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s1->infinity = 0;
        XMEMCPY(s2->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s2->infinity = 0;

        /* table[0] = {0, 0, infinity} */
        XMEMSET(&table[0], 0, sizeof(sp_table_entry_256));
        /* table[1] = Affine version of 'a' in Montgomery form */
        XMEMCPY(table[1].x, t->x, sizeof(table->x));
        XMEMCPY(table[1].y, t->y, sizeof(table->y));

        for (i=1; i<6; i++) {
            sp_256_proj_point_dbl_n_sm2_4(t, 43, tmp);
            sp_256_proj_to_affine_sm2_4(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<6; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_sm2_4(t, s1, s2, tmp);
                sp_256_proj_to_affine_sm2_4(t, tmp);
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
#if defined(FP_ECC) || defined(WOLFSSL_SP_SMALL)
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_get_entry_64_sm2_4(sp_point_256* r, const sp_table_entry_256* table, int idx);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_get_entry_64_avx2_sm2_4(sp_point_256* r, const sp_table_entry_256* table, int idx);
#ifdef __cplusplus
}
#endif
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^42, ...
 * Pre-generated: products of all combinations of above.
 * 6 doubles and adds (with qz=1)
 *
 * r      Resulting point.
 * k      Scalar to multiply by.
 * table  Pre-computed table.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_stripe_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* t = NULL;
#else
    sp_point_256 rt[2];
    sp_digit t[2 * 4 * 5];
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
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 5, heap,
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
        x = 42;
        for (j=0; j<6 && x<256; j++) {
            y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
            x += 43;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_64_sm2_4(rt, table, y);
        } else
    #endif
        {
            XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        }
        rt->infinity = !y;
        for (i=41; i>=0; i--) {
            y = 0;
            x = i;
            for (j=0; j<6 && x<256; j++) {
                y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
                x += 43;
            }

            sp_256_proj_point_dbl_sm2_4(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_64_sm2_4(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_256_proj_point_add_qz1_sm2_4(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_sm2_4(r, rt, t);
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

#endif /* FP_ECC | WOLFSSL_SP_SMALL */
#ifdef FP_ECC
#ifndef FP_ENTRIES
    #define FP_ENTRIES 16
#endif

/* Cache entry - holds precomputation tables for a point. */
typedef struct sp_cache_256_t {
    /* X ordinate of point that table was generated from. */
    sp_digit x[4];
    /* Y ordinate of point that table was generated from. */
    sp_digit y[4];
    /* Precomputation table for point. */
    sp_table_entry_256 table[64];
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

        if (sp_256_cmp_equal_4(g->x, sp_cache_256[i].x) &
                           sp_256_cmp_equal_4(g->y, sp_cache_256[i].y)) {
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
static int sp_256_ecc_mulmod_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_win_add_sub_sm2_4(r, g, k, map, ct, heap);
#else
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp;
#else
    sp_digit tmp[2 * 4 * 6];
#endif
    sp_cache_256_t* cache;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);
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
            sp_256_gen_stripe_table_sm2_4(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_win_add_sub_sm2_4(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_4(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif
    return err;
#endif
}

#ifdef HAVE_INTEL_AVX2
#if defined(FP_ECC) || defined(WOLFSSL_SP_SMALL)
#endif /* FP_ECC | WOLFSSL_SP_SMALL */
/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_qz1_avx2_sm2_4(sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*4;
    sp_digit* t6 = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* t4 = t + 8*4;

    /* Calculate values to subtract from P->x and P->y. */
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_avx2_sm2_4(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_avx2_sm2_4(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_4(p->x, t2) &
            sp_256_cmp_equal_4(p->y, t4)) {
        sp_256_proj_point_dbl_avx2_sm2_4(r, p, t);
    }
    else {
        sp_digit* x = t2;
        sp_digit* y = t3;
        sp_digit* z = t6;

        /* H = U2 - X1 */
        sp_256_mont_sub_avx2_sm2_4(t2, t2, p->x, p256_sm2_mod);
        /* R = S2 - Y1 */
        sp_256_mont_sub_avx2_sm2_4(t4, t4, p->y, p256_sm2_mod);
        /* Z3 = H*Z1 */
        sp_256_mont_mul_avx2_sm2_4(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_256_mont_sqr_avx2_sm2_4(t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(t3, p->x, t1, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(t1, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_avx2_sm2_4(t2, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(t2, t2, t1, p256_sm2_mod);
        sp_256_mont_rsb_sub_dbl_avx2_sm2_4(x, t2, t3, p256_sm2_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_mul_avx2_sm2_4(t3, t3, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_avx2_sm2_4(t1, t1, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_avx2_sm2_4(y, t3, t1, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 4; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 4; i++) {
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
static void sp_256_proj_to_affine_avx2_sm2_4(sp_point_256* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 4;
    sp_digit* tmp = t + 4 * 4;

    sp_256_mont_inv_avx2_sm2_4(t1, a->z, tmp);

    sp_256_mont_sqr_avx2_sm2_4(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    sp_256_mont_mul_avx2_sm2_4(a->x, a->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_avx2_sm2_4(a->y, a->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(a->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
}

/* Generate the pre-computed table of points for the base point.
 *
 * width = 6
 * 64 entries
 * 42 bits between
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temporary data.
 * heap  Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_avx2_sm2_4(const sp_point_256* a,
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

        err = sp_256_mod_mul_norm_avx2_sm2_4(t->x, a->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_avx2_sm2_4(t->y, a->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_avx2_sm2_4(t->z, a->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_avx2_sm2_4(t, tmp);

        XMEMCPY(s1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s1->infinity = 0;
        XMEMCPY(s2->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s2->infinity = 0;

        /* table[0] = {0, 0, infinity} */
        XMEMSET(&table[0], 0, sizeof(sp_table_entry_256));
        /* table[1] = Affine version of 'a' in Montgomery form */
        XMEMCPY(table[1].x, t->x, sizeof(table->x));
        XMEMCPY(table[1].y, t->y, sizeof(table->y));

        for (i=1; i<6; i++) {
            sp_256_proj_point_dbl_n_avx2_sm2_4(t, 43, tmp);
            sp_256_proj_to_affine_avx2_sm2_4(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<6; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_avx2_sm2_4(t, s1, s2, tmp);
                sp_256_proj_to_affine_avx2_sm2_4(t, tmp);
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
#if defined(FP_ECC) || defined(WOLFSSL_SP_SMALL)
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^42, ...
 * Pre-generated: products of all combinations of above.
 * 6 doubles and adds (with qz=1)
 *
 * r      Resulting point.
 * k      Scalar to multiply by.
 * table  Pre-computed table.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_stripe_avx2_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* t = NULL;
#else
    sp_point_256 rt[2];
    sp_digit t[2 * 4 * 5];
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
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 5, heap,
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
        x = 42;
        for (j=0; j<6 && x<256; j++) {
            y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
            x += 43;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_64_avx2_sm2_4(rt, table, y);
        } else
    #endif
        {
            XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        }
        rt->infinity = !y;
        for (i=41; i>=0; i--) {
            y = 0;
            x = i;
            for (j=0; j<6 && x<256; j++) {
                y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
                x += 43;
            }

            sp_256_proj_point_dbl_avx2_sm2_4(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_64_avx2_sm2_4(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_256_proj_point_add_qz1_avx2_sm2_4(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_avx2_sm2_4(r, rt, t);
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

#endif /* FP_ECC | WOLFSSL_SP_SMALL */
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
static int sp_256_ecc_mulmod_avx2_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_win_add_sub_avx2_sm2_4(r, g, k, map, ct, heap);
#else
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp;
#else
    sp_digit tmp[2 * 4 * 6];
#endif
    sp_cache_256_t* cache;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);
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
            sp_256_gen_stripe_table_avx2_sm2_4(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_win_add_sub_avx2_sm2_4(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_avx2_sm2_4(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif
    return err;
#endif
}

#endif /* HAVE_INTEL_AVX2 */
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
    sp_digit k[4];
#endif
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 4, km);
        sp_256_point_from_ecc_point_4(point, gm);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_avx2_sm2_4(point, point, k, map, 1, heap);
        }
        else
#endif
            err = sp_256_ecc_mulmod_sm2_4(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_4(point, r);
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
    sp_digit k[4 + 4 * 2 * 6];
#endif
    sp_point_256* addP = NULL;
    sp_digit* tmp = NULL;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(
            sizeof(sp_digit) * (4 + 4 * 2 * 6), heap,
            DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 4;

        sp_256_from_mp(k, 4, km);
        sp_256_point_from_ecc_point_4(point, gm);
        sp_256_point_from_ecc_point_4(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_4(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_4(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_4(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_avx2_sm2_4(point, point, k, 0, 0, heap);
        }
        else
#endif
            err = sp_256_ecc_mulmod_sm2_4(point, point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            sp_256_proj_point_add_avx2_sm2_4(point, point, addP, tmp);
        }
        else
#endif
            sp_256_proj_point_add_sm2_4(point, point, addP, tmp);

        if (map) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                    IS_INTEL_AVX2(cpuid_flags)) {
                sp_256_map_avx2_sm2_4(point, point, tmp);
            }
            else
#endif
                sp_256_map_sm2_4(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_4(point, r);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Striping precomputation table.
 * 6 points combined into a table of 64 points.
 * Distance of 43 between points.
 */
static const sp_table_entry_256 p256_sm2_table[64] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x61328990f418029eL,0x3e7981eddca6c050L,0xd6a1ed99ac24c3c3L,
        0x91167a5ee1c13b05L },
      { 0xc1354e593c2d0dddL,0xc1f5e5788d3295faL,0x8d4cfb066e2a48f8L,
        0x63cd65d481d735bdL } },
    /* 2 */
    { { 0xc89fc5d00f01c7ceL,0x6fc45ffd7283bdf0L,0x71dece8181151923L,
        0xed1cb14cc433fcc9L },
      { 0x4279612bd3959bcfL,0xe163880b35b5732fL,0x35414ca771d0a1caL,
        0xe8b9e6512c1e47f3L } },
    /* 3 */
    { { 0x03e6bee81775471fL,0x6ae34269f3376607L,0xb11a06bf20376ef0L,
        0x9e9cada1ab3ded4bL },
      { 0x0a2970959450f9a2L,0xd736d2d861aebfafL,0x9236dfba45d99caeL,
        0x16f5d44a57e128efL } },
    /* 4 */
    { { 0x7e2c5852126506ccL,0xba94aac708b3567dL,0x6905cdf4c05a3f24L,
        0xbf5f559b3547f8b3L },
      { 0x9e4b4e62aade7a1dL,0x56b8b9d61fda3088L,0xea3eb4c64c43d89fL,
        0xfb7e537c9c69e047L } },
    /* 5 */
    { { 0xaf6ea6e4c6dae187L,0x055769cc7a57cc35L,0x61b1b38f2e2bd6d3L,
        0x49e72575fedd2b2dL },
      { 0xf13fbc501dd3fa13L,0x59372da068989c52L,0x47d1d3fdd57e252aL,
        0xe2258efb4702d9ffL } },
    /* 6 */
    { { 0x7632f8cb8428b2ecL,0x5ce75123861aff25L,0xb85c8ae2ad7135c9L,
        0x3cbd06d58feab59aL },
      { 0x1d23ea10278f7d53L,0xa20abf6a6be94d6fL,0xd827dabdb0617ea2L,
        0xf8a489b1dbfb2450L } },
    /* 7 */
    { { 0x0b45f275eaf0d6eeL,0xc42fd33ff5aafa87L,0x5b495473a7652578L,
        0x774d93483effd670L },
      { 0x4d7ca2e480b18d20L,0xfcc00a1f7718af75L,0xf942b780a26c5bdfL,
        0xa19656c1ab1952b6L } },
    /* 8 */
    { { 0x7a748d63003b40ddL,0x8a6824023951b7aeL,0x41e92dd9704a91b0L,
        0x2dfb3eb9858cd3eaL },
      { 0xc3c2af35f5094667L,0xffa287dc7435aa2dL,0xd03f39797462714fL,
        0xdb550f67203e5b0eL } },
    /* 9 */
    { { 0x64a231da5310c3f7L,0x6b0bdac4ea55a959L,0x74060b60fe7e19a4L,
        0xb7c3ca32980dd9ffL },
      { 0x543abc818c31d481L,0xe2eabc01e3b65787L,0x5e8fae7613cf6575L,
        0xba7bdf8c049f75c7L } },
    /* 10 */
    { { 0x650ca1b15d0372a0L,0x0bab653b4760783aL,0x43861d978b275a3eL,
        0x2a5e58c4a460c35bL },
      { 0x0d05e066d42e647aL,0x1d405d5194b35397L,0xe8267117c1475d81L,
        0x48ee0aeff17fc683L } },
    /* 11 */
    { { 0x7e220220bf104cafL,0xa836513fdfb4687bL,0xd3b2d18b75f7aa30L,
        0x0cdb2832d4a43fd6L },
      { 0xc3d76c6df6fe7f98L,0xfc4e7340cf7bffaeL,0xe9be89752162ddbdL,
        0xd3e5b2f579d8566cL } },
    /* 12 */
    { { 0xf7fe95db0a7c6fb3L,0xa55173a668dc4aadL,0x9c967a36b430fa70L,
        0x3cbffc0337044e9eL },
      { 0xef93d4d40646acc4L,0x887280cf82055396L,0x115ca645037ae10dL,
        0x6e09a0ec3efa445cL } },
    /* 13 */
    { { 0x37f3a20f4c217638L,0x8374f92e0d81de77L,0x600d889c3c25242eL,
        0x5d550413848e366cL },
      { 0xba3269e0b8946effL,0x8caed7c6b14de08eL,0x67d11be5e1343a97L,
        0x37c1956307b5cd60L } },
    /* 14 */
    { { 0x2bf93798cbe1c850L,0x71629f3559ee1d84L,0xda6a2579fe666b67L,
        0x4122226051d853c2L },
      { 0xa1bf9f71aea91d83L,0x4b8f59ac8d4fc31eL,0xd679a7afb30715b1L,
        0x0e4efa3b8ebec869L } },
    /* 15 */
    { { 0xfd9f6381566ddca3L,0xd8e9aa4a4ee8f6a2L,0xe1480afb3aa991d6L,
        0x4fde55b2f3071a92L },
      { 0xf994324570c76750L,0xe6185026974a84ceL,0x29404c8fa67c0418L,
        0x4eb6b70b1dc29e21L } },
    /* 16 */
    { { 0x271b2e2a0133903bL,0x5b3686f2e495ee32L,0x89bcc9740c991f28L,
        0xadd20cce34f93b8aL },
      { 0x5f5a1768680b65b6L,0x0c453ab8aad41c40L,0xd479630fa7fb4269L,
        0x60039d0152c4e929L } },
    /* 17 */
    { { 0x9f8c30f666dc3ed1L,0x8ec40a13ea254aa9L,0x7cf83e30d5180500L,
        0x88f1ea0c126222b5L },
      { 0x09622560358d6219L,0x5e69e63c95cff0dbL,0x70609d57bd89b6c3L,
        0x1e188a57726966beL } },
    /* 18 */
    { { 0x262140c71da61f33L,0xdaae0867b70a4a07L,0xe6a09476be206839L,
        0x07c295d031bb6bd3L },
      { 0xb65e35bdc20d02b9L,0xa840efcccd5738c5L,0xafd37765161c60beL,
        0x992b3b72f7366165L } },
    /* 19 */
    { { 0xe378fa9528468650L,0x04c034f56ef109f1L,0xeb283555d6f82709L,
        0xe60cccee5658e1abL },
      { 0x1c562f62977d30e0L,0x85306434a0ab1406L,0x0cefba77831055beL,
        0x183a6ae70c888c92L } },
    /* 20 */
    { { 0x91dd768392335229L,0xbb0c7c8343b781eaL,0x2737878cc3eddf7eL,
        0xfdb400b4a95403e9L },
      { 0x3c9b8bbc8e431d8fL,0x2c4edaeff9bbb6deL,0x201e84518da24782L,
        0x6bc7cbfcebddcb9bL } },
    /* 21 */
    { { 0x95feb14a944ccd35L,0x5252113d891bf931L,0xd04dfb7d5781c433L,
        0x8817cfe0e962bfbeL },
      { 0x7d7eca9a3925ff3bL,0x7435a2613c0041a4L,0xe6068793008d032eL,
        0x536c1bbac5e5d7a5L } },
    /* 22 */
    { { 0x471c390fdb26e28bL,0xaf61796edb086005L,0x3c18b8d86ebbf57cL,
        0xd935b255a276a92cL },
      { 0xe950cf0c08f9cb54L,0xa49b27e467194534L,0xa45fc842d76e2637L,
        0xefa7c80bebfca758L } },
    /* 23 */
    { { 0xa874199483e6b67fL,0x757043c6e57811bcL,0x834a5582cf6a3c78L,
        0x3f5ab9765a6b2ab4L },
      { 0xbb72a841009b2afaL,0x8697c0c85f97324cL,0x262443b6c4a9cd13L,
        0x180f086ce10bd389L } },
    /* 24 */
    { { 0x6512675fee8996deL,0x94a7c9d596a43e0cL,0x5d2b859339dab3b2L,
        0x05f908e6e002c8e5L },
      { 0x2adf1b219ca29d0bL,0x6f9fa5b45d684bccL,0xc16af991e7e8a40eL,
        0x99f8c0addfd9babeL } },
    /* 25 */
    { { 0x16ea65e4a50f622bL,0x989f438cd8b8ad64L,0x38ee81384cd0c37bL,
        0xce3ef92d864e7b1dL },
      { 0x3164b64bcbe452e7L,0x8e911fffb1e3dc56L,0xb04fbe9fcbb4d37cL,
        0x9923046257142dc6L } },
    /* 26 */
    { { 0xd3681a404fe28249L,0x32580387052afcffL,0x196c4c68e2da7ea5L,
        0x7100d19638420b0dL },
      { 0x8a53dce1588d6c08L,0x1adffad3bdbd568bL,0xb2660875ac6eda79L,
        0x08bd204ada1a4bb1L } },
    /* 27 */
    { { 0xe18eb0fd9d58bc9dL,0x4718154c3fed99f8L,0xb9c59a3154945dd0L,
        0x6619b39df95038c4L },
      { 0x4f5742677122f279L,0x8b3df2ae21f78499L,0x9408279284852c7eL,
        0x5e6b8140674b9319L } },
    /* 28 */
    { { 0x4259a967ab96a0c2L,0x669a67fffdcf89d9L,0xf7605114950da6cfL,
        0xcf59adc7fac8af08L },
      { 0x60d642bcaf53bbb3L,0x3cd619404c60c225L,0x87ab40e93ed6c81dL,
        0xa64309cac4a97b64L } },
    /* 29 */
    { { 0xc0f067f4148fb37fL,0x0c212ebc1ecec765L,0xb6959c9f708e3383L,
        0x2b3502560633c263L },
      { 0x422b9022f1f230aaL,0x67e89ca6908ca8bdL,0xe1968463a274f18fL,
        0x444b01fca201aac3L } },
    /* 30 */
    { { 0x704c3d22c0e27894L,0xd7aa64a9c8aa6755L,0x16caef7397f0418bL,
        0xbb0ac091a2060ba1L },
      { 0xd769c871569136abL,0xcdb28245eaeb6c8eL,0x9d8c7f9cd03914e3L,
        0xeae4c0183b409589L } },
    /* 31 */
    { { 0x5dd457a08ea18527L,0xfe86938b489cadeeL,0x01b868d40ea433f8L,
        0x448836b9c4e0ddb1L },
      { 0x612aaab44b6d19f6L,0xacc943e95b8e6130L,0x8056f93affdc4812L,
        0x95b00890c1e028a7L } },
    /* 32 */
    { { 0x0366065a848bdc53L,0xba2af074078554ddL,0x3c755fba19ff3b4dL,
        0x5ea9337235a22cbbL },
      { 0x0e55fe021eb3e23bL,0x2626ecca765dede4L,0x187bf09481f445daL,
        0xba0110179df30578L } },
    /* 33 */
    { { 0x09e4b407a800dec6L,0xc9c5a716454268d8L,0x62d2d1dd42a43b38L,
        0x4d8411e4d05e0136L },
      { 0xc2c01d33178f2108L,0x4d9544cde4598b1fL,0xe62f7c8f8b3e78f8L,
        0x2dc054e6a33f242dL } },
    /* 34 */
    { { 0x1df6903a4ed2dff4L,0x9d78abe9e6404314L,0x8e3844e5d4e48171L,
        0x827ffe4138ace54cL },
      { 0x33d11d70720e65ffL,0xdd8752733311cbc2L,0xb66bc81a394991adL,
        0x0396de3fc3fc72d2L } },
    /* 35 */
    { { 0xcb12dc9c6042668dL,0xf7317aa7a3bbbe3cL,0x993c8f443a43a529L,
        0xd6f2643528d87e08L },
      { 0xd037d26ba653a204L,0x72eb6e05ccfd59e1L,0xd1433730cfc645ebL,
        0xd7cb9383e5c093e5L } },
    /* 36 */
    { { 0xc5b62430e017a629L,0x70e42fa403a48841L,0xf0fe1d0fe3ab0806L,
        0x109327cacc6233ebL },
      { 0x1ff546245feb876fL,0x46d5fb56b254c229L,0xc412436db26ae61fL,
        0xe8279e370b49099aL } },
    /* 37 */
    { { 0xd4b1e6a3534cf2dfL,0x7b5ec3f14f291315L,0x961b126e257471ecL,
        0x461c7b4e9632df8bL },
      { 0xfd7d38fbaad44894L,0x262635904f0e6e0fL,0xf8a9f0be38ae5310L,
        0x49b2aa694221fb72L } },
    /* 38 */
    { { 0x513ad9399aee80a0L,0x8804476b678dbd40L,0xae6e49cccfad7a0eL,
        0xad6b3fbff41f3f8eL },
      { 0x3f4e7f175835adc4L,0xb1032928922f5307L,0x2de4eba25164b1f4L,
        0xe567159a2cdc2c54L } },
    /* 39 */
    { { 0xf6444d096c194996L,0xfade09439cbef1edL,0x5a5a6d45d7be29ceL,
        0x7631df01c0b73cf4L },
      { 0xc90ba5d7d2bb0069L,0x921640ae1a99a8cbL,0xe6d067bc8f99071aL,
        0x5d22d09bb44d3654L } },
    /* 40 */
    { { 0x829e36cd1134a20fL,0xf79d07d8d76df092L,0x419e14a306a5ceffL,
        0x275eed0e209f6f79L },
      { 0xe4ce05fca9f844dfL,0x01cbb95be90403f0L,0xd251a3fb12f13683L,
        0x9fbb39730f07a135L } },
    /* 41 */
    { { 0x5cfbd82facf72d73L,0x63fbf2f4b9c163a1L,0x725f974e7c5644f4L,
        0x0f702d38bbf90a87L },
      { 0x04014bf1a7437e4eL,0x6934f2dcf389a23eL,0x2ec175779b909ed5L,
        0x0d7cad3712baef70L } },
    /* 42 */
    { { 0x274e22b791421ad5L,0x663e14f342ee0c42L,0x13963062e369531fL,
        0xbd230aca5766547aL },
      { 0x9a8628de978457abL,0xbc0d00d460bb5ab6L,0xfccf09deaf3dfbbaL,
        0x98f8a195c4410fd7L } },
    /* 43 */
    { { 0x4ec518c6055b5914L,0xa56d9e9328349fdeL,0xeff2d295b9dda089L,
        0x22ecc53b26ac82b8L },
      { 0xfbeb4dc21ae6374eL,0xceec19353f968bb2L,0x9527386bd4535de2L,
        0xdd068e57ae45c83dL } },
    /* 44 */
    { { 0x83feecbb2a2e5d97L,0x84ea0bc9535109d3L,0x26487d87072b59a2L,
        0x390af66c39436e6dL },
      { 0x634b5d2ed0f7b5c7L,0x9a45246da89d0f8aL,0x08cc623a743c9aeaL,
        0xbf3785590307a6e2L } },
    /* 45 */
    { { 0xdb0566e318f1453cL,0xc30c4d5ef1820e92L,0x946bb26f0104820dL,
        0x52eff5477aa37647L },
      { 0x67da4d36853a1f4dL,0xabeb9771a5172b8cL,0xfd096bf58968109bL,
        0xfb80b4ca931611e7L } },
    /* 46 */
    { { 0xea1b1d54ba6abc43L,0xd08af21976ce6f34L,0xf63d918fa4d6fd64L,
        0x5bff36213b6e555dL },
      { 0x929a7fd87be5d71fL,0x133eb1164d7c241fL,0x69fba4932e300990L,
        0x0632d2ccd9780058L } },
    /* 47 */
    { { 0xbcf5cf01151442b3L,0x7f91456c46774bb0L,0x2e5a3e13d1c03fd8L,
        0xabfc31f805dafc7aL },
      { 0x45e9855f0937b9beL,0xc9b90fa55f32245fL,0x9b5e163261ebd410L,
        0x201dc9f04572809eL } },
    /* 48 */
    { { 0x2a6a131da46981e1L,0x7a71ec309ef9f995L,0x3a55270cfd7a9dd8L,
        0x5999fc08a4369df0L },
      { 0x18cb84ec8274efc0L,0x454464a5ee279286L,0x30b5e826779c17d9L,
        0xda646ece02b6ff99L } },
    /* 49 */
    { { 0x9dba43088326dd52L,0x3eda387989bbd3ceL,0x29413dbd22b90ba0L,
        0x3515655d7ed0ddb9L },
      { 0x80056e448642c882L,0x0893fff437885d62L,0xdff9620369d2a264L,
        0xfd7a37992b8f4148L } },
    /* 50 */
    { { 0x22a7c2036145bbcfL,0x287d10447d336846L,0x572595abb966911aL,
        0x93f6465b9b7de253L },
      { 0xbbc833ec7d36e6fdL,0x684593d75ca89a1bL,0xd27ee8c505ceec9aL,
        0xc6e0423c13f4a4fcL } },
    /* 51 */
    { { 0xa4a8ef1e6915aa07L,0xcb6b482499e5ac0fL,0x2e33149247ad6549L,
        0x733611d2de0af084L },
      { 0x1394038cc808c5a7L,0xc0485790d41fc3d3L,0x196fb1f27bc72b81L,
        0xdf5018d6f99a6d7eL } },
    /* 52 */
    { { 0xd935751528128edaL,0xe6e7e969fdbab36aL,0xf80fe45f7d26d962L,
        0x18ce483bb609afebL },
      { 0x413f7890d589ed7cL,0x8b17a3ccf5f04540L,0x2ab07087c47d4c2eL,
        0x2871c1643b4ac7f5L } },
    /* 53 */
    { { 0x2f8bb6e6931038dcL,0xa68fe535b99250cdL,0x9cc8e0727fcc5d1fL,
        0x9e535e0d8b10b1d3L },
      { 0x93b637f33559d110L,0x4ffe97e6f7564a04L,0x4340fc2086808165L,
        0x47f14460beea7182L } },
    /* 54 */
    { { 0xec67c13a6a3a2ee7L,0x54dae96ba307c00cL,0x92b4ddf2dc5268c5L,
        0xc79c8796a40ab72aL },
      { 0x29d9095107774e86L,0xb8918b60cadd1808L,0x7c0637c8d801e9d4L,
        0xf914ebe45f729cd7L } },
    /* 55 */
    { { 0xb464e806b0704149L,0x8b5c7e6bb45001e7L,0x748c21c20194031dL,
        0x51b9f9d7e1b289b0L },
      { 0xf1cc95951a78d70fL,0x45b9a18eb3cd4521L,0x932fb8f48eae7bb7L,
        0x767e802a9807fa18L } },
    /* 56 */
    { { 0xf946a7b08b335257L,0x576b173683ea43f7L,0x7af015ff1e56637cL,
        0x42eabbfda7f2d2f5L },
      { 0x95986a387447b4e3L,0xd6ddc3376e6f45ddL,0x3d1ba7fafc575cebL,
        0xd685d6e82f38033cL } },
    /* 57 */
    { { 0x2ed744f72668abefL,0xcf17dc9af6868848L,0xdb09d173d8f40e07L,
        0xe789042909484ae5L },
      { 0x8d264ad636694f88L,0xb0cc9320c04c26a3L,0xed073d07904a8594L,
        0xc14e342088c5d1aaL } },
    /* 58 */
    { { 0x8dcdf2b252501d68L,0x181d1b097b98b283L,0x71c3c4f7ed582d16L,
        0x4d86bbaf5990f8f3L },
      { 0x8ffead8565158631L,0x4f6763ace47c4d59L,0x728b3d15a9400fb3L,
        0xd77fe278c02477a4L } },
    /* 59 */
    { { 0x63bde3cd88d9bd7dL,0x8d3b6522ae241860L,0x8beb9b7405b4d897L,
        0x5cd2178d02987215L },
      { 0x183e675a16f6f682L,0xe5fa2966b3ad7388L,0x4114c83206c8a170L,
        0x72dc010a294dcbf1L } },
    /* 60 */
    { { 0xb4c679eb874695ddL,0x61f3e3d5f7735356L,0x122ead380071d1d5L,
        0xee50373f69f6625fL },
      { 0xcd499f6ab797fc43L,0xcc06f969e01d177aL,0xb88f7c660aed3e14L,
        0xbc5c5d409c5e5c95L } },
    /* 61 */
    { { 0xe80bb01d2c3a5664L,0x4fe6493c84f7c2e7L,0xe5b16177eb66340bL,
        0xadc3c70d36c55aabL },
      { 0x90a6958dc475f280L,0xae3d6ebe7bfa2433L,0x9fe1b791de46e63bL,
        0x45b8bf5e657b1b03L } },
    /* 62 */
    { { 0x8ff7204538446503L,0x9de88cabdb467f46L,0x6e98df586a790728L,
        0x1e7300439babedacL },
      { 0x7de951828fdd9e50L,0x5bc6df866360db7cL,0x2d603e28e61397e9L,
        0x3b03c6a12e564f8fL } },
    /* 63 */
    { { 0xb1ccda1bcb864301L,0xa0fd1edac2df2becL,0xd08dcf732ba5dfc0L,
        0x86e4e54c4d11ab86L },
      { 0x925999e61a610213L,0x7566b7c3793cc32aL,0x6ccc08654ae87f34L,
        0x675e11437c772043L } },
};

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^42, ...
 * Pre-generated: products of all combinations of above.
 * 6 doubles and adds (with qz=1)
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_sm2_4(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_4(r, &p256_sm2_base, p256_sm2_table,
                                      k, map, ct, heap);
}

#ifdef HAVE_INTEL_AVX2
/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^42, ...
 * Pre-generated: products of all combinations of above.
 * 6 doubles and adds (with qz=1)
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_avx2_sm2_4(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_avx2_sm2_4(r, &p256_sm2_base, p256_sm2_table,
                                      k, map, ct, heap);
}

#endif /* HAVE_INTEL_AVX2 */
#else /* WOLFSSL_SP_SMALL */
/* The index into pre-computation table to use. */
static const uint8_t recode_index_4_7[130] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49,
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const uint8_t recode_neg_4_7[130] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
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
static void sp_256_ecc_recode_7_4(const sp_digit* k, ecc_recode_256* v)
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
    for (i=0; i<37; i++) {
        y = (uint8_t)(int8_t)n;
        if (o + 7 < 64) {
            y &= 0x7f;
            n >>= 7;
            o += 7;
        }
        else if (o + 7 == 64) {
            n >>= 7;
            if (++j < 4)
                n = k[j];
            o = 0;
        }
        else if (++j < 4) {
            n = k[j];
            y |= (uint8_t)((n << (64 - o)) & 0x7f);
            o -= 57;
            n >>= o;
        }

        y += (uint8_t)carry;
        v[i].i = recode_index_4_7[y];
        v[i].neg = recode_neg_4_7[y];
        carry = (y >> 7) + v[i].neg;
    }
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_get_entry_65_sm2_4(sp_point_256* r, const sp_table_entry_256* table, int idx);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_get_entry_65_avx2_sm2_4(sp_point_256* r, const sp_table_entry_256* table, int idx);
#ifdef __cplusplus
}
#endif
static const sp_table_entry_256 p256_sm2_table[2405] = {
    /* 0 << 0 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 0 */
    { { 0x61328990f418029eL,0x3e7981eddca6c050L,0xd6a1ed99ac24c3c3L,
        0x91167a5ee1c13b05L },
      { 0xc1354e593c2d0dddL,0xc1f5e5788d3295faL,0x8d4cfb066e2a48f8L,
        0x63cd65d481d735bdL } },
    /* 2 << 0 */
    { { 0x0af037bfbc3be46aL,0x83bdc9ba2d8fa938L,0x5349d94b5788cd24L,
        0x0d7e9c18caa5736aL },
      { 0x6a7e1a1d69db9ac1L,0xccbd8d37c4a8e82bL,0xc7b145169b7157acL,
        0x947e74656c21bdf5L } },
    /* 3 << 0 */
    { { 0x1cda54fdab589e4aL,0x26765289db4f0a0dL,0x0a265a308ceb4a0aL,
        0x3019fd6bfe887c64L },
      { 0x0a10fbe94b2fc190L,0xf40aa52b87cbce60L,0xcc496bfa6dc13c97L,
        0x28ad34785bb3fbb4L } },
    /* 4 << 0 */
    { { 0x393f7c5a98615060L,0x487ea27fe9016209L,0x8a86bcb4a09f9020L,
        0x50dc8e3ac899dbe1L },
      { 0xfc099043fd619998L,0x1de135ea7c7383bdL,0x4d0bd55632cf70edL,
        0x6ffc31c525bce9e3L } },
    /* 5 << 0 */
    { { 0x9a5756336a9c8162L,0x15aa58f221dfcc53L,0x7ad354bf1ef5f4c5L,
        0x0f443ef363f875b9L },
      { 0x2e81d68fd3450133L,0xb30f4bbde3607d18L,0xb1826a4c362258efL,
        0x7b415276142a6768L } },
    /* 6 << 0 */
    { { 0x136a9c4c0acd72baL,0xb1274a255e7ec73cL,0xf15a876e5de34db6L,
        0x85e74ca08cba8047L },
      { 0x08454cddb469eb37L,0x8fbf6d1fc99754f8L,0x1060e7f8ec30e984L,
        0xb568bc974b8c598aL } },
    /* 7 << 0 */
    { { 0xaa3531c781f06784L,0x0b89419307132520L,0x84ee5b69acfe18c5L,
        0xbbf492e0d9fbec28L },
      { 0x313a35c1e5f6186dL,0x0e449a2e757a01b8L,0x96c9b9922bd99bafL,
        0x2ba05a8f3b84d777L } },
    /* 8 << 0 */
    { { 0xde523a1c09122670L,0x90be6f2a22cc810cL,0x086e63414387df9eL,
        0x115c2fc0d9c44134L },
      { 0x9334430d8799302aL,0x693b3500e27b7ea4L,0xcbe1136f9a8f3382L,
        0xe77fd5f2b5778247L } },
    /* 9 << 0 */
    { { 0x98e795c330fbde86L,0x8e5e0495ab21af8fL,0x3925bf83b48669b4L,
        0x77d88740469522c8L },
      { 0x8fbf8b5b987b04ceL,0x63c563a83aff4428L,0x5dc1116553a6e969L,
        0x822a6c2432697f4cL } },
    /* 10 << 0 */
    { { 0x6774298a642cb143L,0xecdb60d82d110e71L,0xe810b11b1388728eL,
        0x2e8237d8d8603a8aL },
      { 0x673968fc50aeeae1L,0x08c65d196746a3f4L,0x7a61a6b5d7dd7165L,
        0xe31bbfd9a9b6df3aL } },
    /* 11 << 0 */
    { { 0x2b252ad03421e115L,0x7557c8c7c6affc01L,0xd90c19fd8a509267L,
        0x483da168e0d871c8L },
      { 0x72d6f9b3c10729bfL,0x5dd8402115b7061eL,0x9bfea2db9f2c587dL,
        0x528398a798641ec2L } },
    /* 12 << 0 */
    { { 0x18a65d8df3afdd62L,0x89f38500d6d7e4e4L,0x65708c6a9d8d4f07L,
        0xb90ea13cd0bdc7f4L },
      { 0x589858558c3e2b32L,0xfa48d5c5bcfad3a1L,0x5c3544e762385ffaL,
        0xb6bd39ed7e72aeb7L } },
    /* 13 << 0 */
    { { 0x34e51c6a8000fe4eL,0x7da2bdfd89c46941L,0x667ba91de1bc2b2eL,
        0x3c80c9d010a73e5cL },
      { 0x4fadebbec7f5c64dL,0xaef09eb43ea35052L,0x167ee11b26ec55f9L,
        0x45fa508a85189260L } },
    /* 14 << 0 */
    { { 0xa0e9a43922542fc3L,0x3f194a6cddac78dcL,0xa75ae72d6f74d053L,
        0x0f8babeb097c6617L },
      { 0x1d12bc5c4303c247L,0xfe0c027abd1e246cL,0xe9ca1a99b69b55adL,
        0xff6cd2b0117cd63aL } },
    /* 15 << 0 */
    { { 0xf3489343dde97d4dL,0x9c14e38abbb2ce1fL,0x25866911cfddf221L,
        0x0df89411460efef1L },
      { 0xf713f30e73ae8326L,0xd9be66a8cdd274a1L,0xdf915ae236885947L,
        0x2c5c1e9e7878b781L } },
    /* 16 << 0 */
    { { 0xf71560c939e8a120L,0x7121d6b87273b59aL,0x649535ce8ef4639dL,
        0xcd01076e14cc6d58L },
      { 0x2705729a96e74f8aL,0xb07e32305533037eL,0x0846dcc1663c5c62L,
        0x6a4759c110fc3ac1L } },
    /* 17 << 0 */
    { { 0x3c126193cfbdfeffL,0x4a31dd204996d845L,0x48a76ba019f2b658L,
        0xbe3301428890a8bcL },
      { 0x287b34e1308aa041L,0xcbf5da24813adf29L,0xcdfc5a58cdcdc439L,
        0xbda3bda2198a6075L } },
    /* 18 << 0 */
    { { 0x639f92bc1497fe38L,0x8ed8eeacd58bd278L,0xcf5d7ce6b417bfe4L,
        0xf617c54e44400c59L },
      { 0xde6356357d8dc939L,0x2e6a3a75241baaffL,0x02f324e5e07e8e97L,
        0xeb71548770f9fc9dL } },
    /* 19 << 0 */
    { { 0xbefd338086712116L,0x9b9e9707884efe46L,0x611a1eec8c9e513fL,
        0xe2d8e3f53b6dbcecL },
      { 0x7cedab1c4f8964e4L,0xee12d062f4e139f8L,0x8e63c9c09a9af4f3L,
        0xe3246dbb8b907b23L } },
    /* 20 << 0 */
    { { 0x70d5bda271099001L,0x3d876d4a15fae7ddL,0xaba0500f7b69c20eL,
        0xa8e3e0949834adf2L },
      { 0x69db851b980b21b9L,0x274c1de2788c2a30L,0x5caa5336d47d153dL,
        0xada6987757cef318L } },
    /* 21 << 0 */
    { { 0x83879486a0551c80L,0x1611dea0658e61beL,0x1fe95c821b935068L,
        0x8f01e0195b229223L },
      { 0x23017e057e93c389L,0xce4ac99d9840dd64L,0xddc9b9001de86399L,
        0x6abe5cc388015785L } },
    /* 22 << 0 */
    { { 0xc09545a9b3c50898L,0xbd4433616c05d902L,0xed71f70c2c6bcc8cL,
        0x8dbc0b88bdf8e908L },
      { 0x56eb5b984fcbcd9aL,0xafb6fedc08114397L,0x0500ce5bb35f7927L,
        0x7005bcf995efe710L } },
    /* 23 << 0 */
    { { 0x125cbed22eba7f39L,0xc7c42e766c488d44L,0xdb8991f9676915c4L,
        0xdf6ae5949183839fL },
      { 0x4f69c304c79f8bd1L,0x638cb070aa1662faL,0xc7f68c72ba6f2599L,
        0x11bb84d91f6edfa9L } },
    /* 24 << 0 */
    { { 0x9ed156eca215fda2L,0x19de7a9120c5ddb6L,0xc1ed949d0668c65dL,
        0x96683044d0826f6aL },
      { 0x1e6325e01adaa8ffL,0xbc53bc2407ac392aL,0x2c342db5d9f06e44L,
        0x3f52938530db8c1aL } },
    /* 25 << 0 */
    { { 0xc5957d29e7492326L,0x3addc3df0663f829L,0x8faa3169728cfdc1L,
        0xde53aa7c6b975134L },
      { 0xf481759befddc764L,0xd605474b09edaff3L,0xc7df1eb9653d48c9L,
        0xa71e6854c5040212L } },
    /* 26 << 0 */
    { { 0x136d8342afe945b5L,0x91707e7de9d239c7L,0xeda23dc5fb2e80deL,
        0x892bed73ff614966L },
      { 0x2ded2367838dc12dL,0x73fd298cb002bd9cL,0xc548b4262c4629dfL,
        0x93605d178f7e03b7L } },
    /* 27 << 0 */
    { { 0x32861816d37c24ccL,0x5bb54ee2e427975aL,0x6da013d232f943a9L,
        0x0746a77a9bc202e5L },
      { 0x6db07a84cd1def5bL,0x9421fe7f861d9f9bL,0x71767292692181fbL,
        0x0560e7e5c9d2441dL } },
    /* 28 << 0 */
    { { 0xf1496afd4d7e922aL,0x67f42a3fe11fa533L,0x9f903e5b977956cdL,
        0x37671e241eb49608L },
      { 0x967950a021fb2047L,0x141f96fb35da3c6bL,0xe07c3c40d27bba59L,
        0xbde5ed1d0e1af754L } },
    /* 29 << 0 */
    { { 0xdc64c4b054f1f257L,0xecb033c8b01196dcL,0x54e65f4d8202d5bdL,
        0x63afcc932b2fd451L },
      { 0x1e929a3930640fb7L,0xdc91387e5b361718L,0x10aadecbf8f0bbe8L,
        0x81d8f4660977e2bbL } },
    /* 30 << 0 */
    { { 0xdcaa3790bd64cd96L,0xbc8ac152cee698d3L,0xde7192f7a1143c45L,
        0xf7c9d826f5fb9ea0L },
      { 0x54aea92ec9468f50L,0x340f4459cc427ed4L,0x3fec5be902ad5467L,
        0xec780d9c2cc6c8b5L } },
    /* 31 << 0 */
    { { 0x7b179a8bb889c78aL,0x069a7ab90aca32c5L,0xe4e5215e591b9a36L,
        0x7802fb3e3bd54630L },
      { 0x9a479313233c6eebL,0x18c612ad4e1cbabcL,0x28a29273c0e36f3bL,
        0xf4e2dfb17d3deb26L } },
    /* 32 << 0 */
    { { 0xa6c11369adbb3c8bL,0xd78af40b4c8ec378L,0xffb3a80d03f0a982L,
        0x550e3e71a83be50aL },
      { 0x845c0fb2418ee45bL,0x5297cf430791b964L,0x676b638ccc47e33bL,
        0xb1c52facfecf85b2L } },
    /* 33 << 0 */
    { { 0xf011b5e53dba2c0eL,0xa6c68448026d4f11L,0x11596db3c3f206fbL,
        0xc91c76dc29414a3cL },
      { 0x1839b9d1b94ddc7cL,0xdfb20ce756ae8610L,0x3e2b1cd9d8734400L,
        0x59f9329af01ea540L } },
    /* 34 << 0 */
    { { 0x7d4c140c2351a2a9L,0x575c1e1bbf4c9823L,0x8f11c2ca31068df9L,
        0xe3c17aa005e6def0L },
      { 0xe6281c70501c8630L,0xad240917c88a412eL,0x6f21bfb7390492d7L,
        0x61ea1385c3a3ccb7L } },
    /* 35 << 0 */
    { { 0x60494a8333733cbcL,0x8da622a027ed8157L,0x0022b1540471ad90L,
        0x3bd0a4c5d3568003L },
      { 0xdc8e2d03d932df23L,0x859ed9407a1f5159L,0xad670e632a375b0fL,
        0x15922fae9520db97L } },
    /* 36 << 0 */
    { { 0xfb73d16f59eb1a9bL,0x3ee8cc1f8511e541L,0x20d72d591590c321L,
        0x62eab5663bd075d4L },
      { 0xac07a7c7fae123abL,0x83b89abf1f10af6eL,0x469962ec1da8ac5dL,
        0x09761c358c58c3b3L } },
    /* 37 << 0 */
    { { 0x2c086d5e7da90fc9L,0x458e5ffd5cc27782L,0xc3f48611b9268939L,
        0x39fed873de4b9110L },
      { 0x16ef8f78fda698ccL,0xb028dc21a973bb50L,0x45eb849ee29b725bL,
        0xd41b5b6d14c6eae9L } },
    /* 38 << 0 */
    { { 0x5e931b21c55d5720L,0xb628ccb2a0e40b19L,0x42044ffe000651a5L,
        0x2130b4de076544e7L },
      { 0x384285943677c70fL,0xfdcdb038f8945d86L,0xfb2e3d4c4169ae44L,
        0xd4695e9b0d13bce2L } },
    /* 39 << 0 */
    { { 0x45191390039d646dL,0x983b7a2eb12ba339L,0xdfd30d3e5923e7d6L,
        0xae3590f0ba9d206aL },
      { 0x7d58d334b6d5e62aL,0xb15b05447e402b12L,0xac57e11362ae8e01L,
        0x4d83804cf473edeeL } },
    /* 40 << 0 */
    { { 0x2faa7c4dc81bc828L,0xb16ed9d7fb62561fL,0x4c9da27049c2fa93L,
        0x3b014c73b311d90dL },
      { 0xd29c5d65f5443332L,0xb6457d54eebdb7c2L,0xc6a0bf3a4cce9480L,
        0xd434a3b085355854L } },
    /* 41 << 0 */
    { { 0x178ca01b8b2c703cL,0x605bba530ab71a51L,0x2140948e3db948d5L,
        0xc45b26895fb6b8c1L },
      { 0x421f66def17b47bdL,0x57627a5a2e9b3ee5L,0xedf3920a66614339L,
        0x7ea619034b638a46L } },
    /* 42 << 0 */
    { { 0x7203d5423c030643L,0x7112bb3d5e631461L,0x2604eac72bc3da9cL,
        0x2e4964e732d2541bL },
      { 0x940faf46e8b6482aL,0x8f772fcb24d27c9eL,0x125c34d7ca7c5f88L,
        0x9903eadbd1f47795L } },
    /* 43 << 0 */
    { { 0x11aaa417e2147129L,0x3ccef5c2f88a0a30L,0x78d5207a90283f97L,
        0xba1261e9d25226b6L },
      { 0xbfc79248d1e7a01cL,0x373f1cd5941ab2bdL,0xf0881e2119a0668bL,
        0x7b7937891f77bf0aL } },
    /* 44 << 0 */
    { { 0x49c2769b63d4523dL,0xf8df2cbaf0399eafL,0x5ae94c6922a2a74dL,
        0xd08f8d45efd1e193L },
      { 0x64341fc4c681f376L,0x3a8e25c8ec918711L,0xdf35304d0608f50fL,
        0x9b4c69679a973742L } },
    /* 45 << 0 */
    { { 0xb5c1f5d3bfba043bL,0xaff4f896e975f03bL,0xea1f39bdae2cbb01L,
        0x4cc1c4cba62915ffL },
      { 0x5eb4afa389e943b8L,0x8c4d27e5154e565aL,0x4e2e5a7e7f2bced6L,
        0x7af408e24487f6a3L } },
    /* 46 << 0 */
    { { 0xe5dacbae97a60de7L,0x9774834c4401b0adL,0x7683bb008a9113f9L,
        0xc6fe7e8b42b2ba67L },
      { 0xc0c0564d54e760c8L,0xf7b05401118606c2L,0x554a9b0fec3cd7b9L,
        0xce75ecfb27916a21L } },
    /* 47 << 0 */
    { { 0xf663899712118abdL,0x2ba6e754097da3a7L,0x1df820850fdf9985L,
        0xbf73502a546c864aL },
      { 0xdfde9323c02d9ce0L,0x580491e2e4dd0e7dL,0xe71522d2ae43b9b4L,
        0x876e36276a231a41L } },
    /* 48 << 0 */
    { { 0xfa8ff511b36362ecL,0x11c5a9f634085959L,0x272b86f29770c62bL,
        0xf06262257c7e8827L },
      { 0x929168bfea1e13ebL,0xdb892971ce59b0f5L,0x6769e31d4f826f34L,
        0xfa1dd9340a955cecL } },
    /* 49 << 0 */
    { { 0x123d9ca2a294d7eaL,0x8699063b4492569bL,0x6a50eae9a8dd86c3L,
        0x3d757d1012c06c38L },
      { 0x5a92c2c03e41e556L,0xa64595eb6330c21aL,0x70d8141ae184d925L,
        0x8543f2cea2f10304L } },
    /* 50 << 0 */
    { { 0x4559b0a29eaca504L,0xb9843a4b2617bc9bL,0x5b28d4ee1b641003L,
        0x3e9af8e14ced538aL },
      { 0x3790fe897bdf7dc2L,0xc7c74941c32549eeL,0xdcc8295babcd2f42L,
        0x48b29a4fead078b6L } },
    /* 51 << 0 */
    { { 0x8e8b28e32040178eL,0xceff8f3e971725fcL,0x4a97b6fafcee2cc1L,
        0x775df6a9bac85b56L },
      { 0x32e5cbe6d28a21ccL,0xe8b86adaae2b82dbL,0x44dfbb5086e38e96L,
        0x45d3fe7d1afc2d4bL } },
    /* 52 << 0 */
    { { 0x838b356ed23f620dL,0x2e8fa8ac4592fe4bL,0x1396e1b33af5b1d8L,
        0x9c0c2ef3cbf50fb0L },
      { 0xd9efb6c9836e93e9L,0xe6eb58700899163fL,0x3a2f6d77dca00d1bL,
        0x36f55f89b40ba0d6L } },
    /* 53 << 0 */
    { { 0xf3b1701f32866e57L,0xf076847359de0f2eL,0xe55d7aedab57962dL,
        0x450049852b60cabbL },
      { 0x8d539d6ed5498888L,0x176ce1a0a5e0ff6aL,0xcb7c15efdc088c50L,
        0x90393d7ac9a9ae2fL } },
    /* 54 << 0 */
    { { 0xd9c1a140d396bdceL,0x4215b78b6fb2800fL,0x8939109f2f76b0dfL,
        0x0f2508972adb40a8L },
      { 0x4db0007c3a86e009L,0x6ef0ad95f968a635L,0x58a82d4b8eaefa78L,
        0xe8a181cb493604a4L } },
    /* 55 << 0 */
    { { 0x36c84e34520d216dL,0x2b2ef6b5c666171cL,0x9469b91f2ce29d37L,
        0x3ecd84e7c15f20aaL },
      { 0xf1090635292edd2cL,0x6d4393627c3447f6L,0x51b9a0a93eea3fdfL,
        0x68e0d1f89e57e450L } },
    /* 56 << 0 */
    { { 0x25d249d57380931eL,0x87f03fad2011a45bL,0x89df0324efde1ca3L,
        0x52ae43cd9a9b4330L },
      { 0xfe48bc64a1867c1bL,0xdd874f669866920eL,0x6942a7e4fcf50251L,
        0xf5c100489c5f6298L } },
    /* 57 << 0 */
    { { 0x305183eb00973d66L,0x1ce6676095baf07cL,0x74c9d97174822e13L,
        0x2ccd7fbb76b5e6efL },
      { 0x51688b49a3e1ca18L,0x1beb5bbba603f2f1L,0x09a231d1962534b6L,
        0x70417ce1afa92f75L } },
    /* 58 << 0 */
    { { 0xb86b6d82e154bc00L,0x5a0b19e8895483e5L,0xb15f6c05a0ff1e44L,
        0x2938b88afdd8615dL },
      { 0x81800a05971615c3L,0x6be6d56bc03d2039L,0xff3e57d2c476ce64L,
        0x5b509b7b6f583ee8L } },
    /* 59 << 0 */
    { { 0x1d92c36c7c1f5d3bL,0x1e60b19be11df757L,0x20261501e37e36f6L,
        0xb68a9aaa29bc86e3L },
      { 0xfba81eaaf61d23caL,0x63440834d5adaa18L,0xa80d76eda5f93bb8L,
        0x3264283d5a728480L } },
    /* 60 << 0 */
    { { 0xd6171111e4b8c48eL,0x3ee227a1de557ccaL,0x2bebc09a3cb59841L,
        0x2f8047fe99bf6205L },
      { 0xb78b243e4c43845fL,0x484ac18346d3b5e0L,0xa07be4760314524dL,
        0xc0a3aa351ab4c447L } },
    /* 61 << 0 */
    { { 0x2f302d589c341f84L,0x264911a784f130baL,0x30bed4083ee64343L,
        0xd7d6e92d5dc5868aL },
      { 0x9207456880adb3fbL,0x005ab33ca133123eL,0x105119fd42e1da50L,
        0x6987117db7f6b1e8L } },
    /* 62 << 0 */
    { { 0xa2315af3c2bccb7aL,0x95ddd3ee8672c98aL,0xa90326455f48f607L,
        0x76861e62c5273603L },
      { 0x71aaa35f88817217L,0x57e95b6c2892afacL,0xf65e909b9e84c791L,
        0x257bcc2daa52f3b1L } },
    /* 63 << 0 */
    { { 0xd5f6110a865c665aL,0xddc3afe130c08b4cL,0x4df3d04aefec26fcL,
        0xf229bddfb035af5dL },
      { 0x364913cfd191b439L,0xf41b8f6d5a7fa8a4L,0x677cc51b6f6c1219L,
        0x593afe4a148b7f64L } },
    /* 64 << 0 */
    { { 0x80ffa5ae0d038ad4L,0xf44d3df336256c8fL,0x0a3077c8bc978dceL,
        0xf3d9b4b0745b8317L },
      { 0x8bbf4484b6b1852cL,0x0cd02ed40e78ff07L,0x91cb827e49c24238L,
        0x58adaee5daa3cb55L } },
    /* 0 << 7 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 7 */
    { { 0x07e6ce4d033fc12aL,0xba4f98a14886f316L,0xb24b38f3e66f3f11L,
        0xe3f6205a5ea4bde3L },
      { 0x00705387a77b998fL,0x2c9b44579549f3b1L,0xdef6625b533a61d6L,
        0x4eda7e2a7e4f781aL } },
    /* 2 << 7 */
    { { 0xe9730aaafd120134L,0xb22b9089c057309cL,0x98e7956584726ce7L,
        0x0e1431a0d635a584L },
      { 0xbd387023e834ffa6L,0x64198ddf036ab1aeL,0x46e5ebb19124b684L,
        0xa316fa44233b3c6dL } },
    /* 3 << 7 */
    { { 0xec2a932584782513L,0xd67c8ab72903d20bL,0x6b65b262157f9aeeL,
        0x547be60c69f964a2L },
      { 0x001bf327ee0419dbL,0x92fa0800f20c7005L,0x1e11e745cdc1ccdaL,
        0xa785ec10e471f822L } },
    /* 4 << 7 */
    { { 0xbc970210a1371aa4L,0xaff481a054b5424eL,0xbcdf91fd0e64269bL,
        0x18bb37bbb02fc7cfL },
      { 0xd99edd796f69d439L,0x4e27a58f169514b2L,0x80eca1ca66e19ae4L,
        0x0470e9650788696dL } },
    /* 5 << 7 */
    { { 0xa6b1992f8c9d34f6L,0xaf062ffea5ed969eL,0xbca2580d3a6d7ae2L,
        0xf30cd9e6c8999158L },
      { 0x93e5789749d1ab0dL,0xcfa3aa4d30214280L,0x0ca8b4fd0a814831L,
        0xdad179db0b10097cL } },
    /* 6 << 7 */
    { { 0x63778bfc3dfdc228L,0xc0bae0adb9648a36L,0xda8cb8ab015a99b5L,
        0xb045cccb8366b58aL },
      { 0x74ef8ef44164cebdL,0x41e71fc8c5e00e5fL,0x753cf9064479468eL,
        0x78b5223f332ea72dL } },
    /* 7 << 7 */
    { { 0x8fc3e370ddebafa2L,0x15ffcce0351f9f04L,0x3fbd5f5c45b0efdcL,
        0xb82166230fe3b460L },
      { 0xe8322fbd533c7db6L,0xf3866d1500a243ffL,0xf1194ae2a0e5aaeaL,
        0x3e93eb01b9287b3dL } },
    /* 8 << 7 */
    { { 0x528a9e2f5876d6e8L,0x93c48f85d2b622d7L,0x88d9eac83e5411d7L,
        0xb7e4a6ba00a70e91L },
      { 0xaf18e5baf1c43b2eL,0x46578c7ea2f347deL,0x19ca736df009638fL,
        0xa6563f1ebd1acd29L } },
    /* 9 << 7 */
    { { 0xdf9bcd3a2f4126e7L,0xecc22d13d62efebdL,0xd9b29b4b10943242L,
        0x499ffa74670136f9L },
      { 0xa2a9ad2c2b889952L,0x945f306efd132dadL,0xfd05b88415cebfd7L,
        0x653e70afc7a5627fL } },
    /* 10 << 7 */
    { { 0xfefc54b5577dae35L,0x9d2f0546aac3a655L,0xb96bd298fac31d00L,
        0x3328a51cee69563dL },
      { 0x5e19098e43195f4eL,0x657f4ba5a998010bL,0x45f29a844047ccb6L,
        0x833a54436e423da6L } },
    /* 11 << 7 */
    { { 0x97e480c6ca33f42bL,0x20a5103306e52a05L,0x85e872550a9be572L,
        0xe8bc857ab988b582L },
      { 0x782495e8c183c500L,0xf33a87fdfee0ae2fL,0xf069fe20c64d1decL,
        0x0b6dd98af4b08816L } },
    /* 12 << 7 */
    { { 0x6e6cf29899229a90L,0xa6840bc81d71d532L,0x803e540771e3a8b7L,
        0xd5611ee46afd9a0eL },
      { 0xd739ca0ebbbefa73L,0x6082dbabc5ec48b7L,0xa0ab10dfbbdea0ecL,
        0xb1b7ebe4f1633e03L } },
    /* 13 << 7 */
    { { 0xfa7524967be26441L,0xf52cb1b60ef683e6L,0x1c96401f39dd611dL,
        0x09c5a35b7bb19083L },
      { 0xa2f002b800a5d5a1L,0x4e300dddacf4e8edL,0x0d26b600b4cc58c6L,
        0x5a53863a50062651L } },
    /* 14 << 7 */
    { { 0x62e64475ad1cac22L,0x2008653ec7e11395L,0xa875ad01d9479c4aL,
        0x3e6cf633804b30d1L },
      { 0x58b3ef6eb6b06e46L,0x74c45dbef7b8410bL,0x02675759c278458dL,
        0xb2ef4956acd30bd1L } },
    /* 15 << 7 */
    { { 0x1a4a5773339aae8dL,0xa775b9520c0fe175L,0x7b39ac1b5d5d5ac1L,
        0x3f183d4911a511b6L },
      { 0x9524e286045ac045L,0x0498d2964934c52fL,0x1fec54749b636528L,
        0xec6f7a37c3e9b84bL } },
    /* 16 << 7 */
    { { 0x870b12dd12ee579dL,0x2a9a12ab06dd62d6L,0xbcd52599071d7582L,
        0x7a36193aa869c457L },
      { 0xd29e6592e976ae5bL,0xe82c8712adfecd58L,0xbc83a440f714686dL,
        0xfe19344a0c21e3baL } },
    /* 17 << 7 */
    { { 0x2a32c989d7a191aeL,0x00a251634e58cacaL,0x2c6501b8e4a11597L,
        0xb3e45d097f1891e6L },
      { 0xb7f532b1659fd516L,0x99cf64dea7002930L,0x56357ed4f2cd2d4dL,
        0xa94cf5c53447951fL } },
    /* 18 << 7 */
    { { 0x26c7f24476a164beL,0xbd83e20ba72e974cL,0x64e9c241da31de06L,
        0x022bc0f01cdb203dL },
      { 0x5eec4fcb55c0601fL,0xa1504f91b168a484L,0xb9cf98b11243026dL,
        0x6a009debfb3e5a1cL } },
    /* 19 << 7 */
    { { 0xf1df375260657650L,0xa5bbd8f5cb1b8d9eL,0x9e0d944781b6af13L,
        0x8572cecf624cb828L },
      { 0x28319d57d003617aL,0x175c4766996fde09L,0x168514b204878e13L,
        0x58a541d7ec83a771L } },
    /* 20 << 7 */
    { { 0xafdaad3b29fb000fL,0x1977a8dec20f56f5L,0x450faf6fc5b7ba77L,
        0x93253964e5954518L },
      { 0x11ee0f31644c3385L,0x6c24de9da8a57badL,0xe8ff408c5533a7baL,
        0x660a74d9eace56faL } },
    /* 21 << 7 */
    { { 0xb4b2543b8cc2a866L,0x69f23f18effc0cbfL,0x0db4682a5308b9b1L,
        0xce7fac5317037e08L },
      { 0xf02098c40a885b01L,0xd375c03db2e4eb6eL,0xb6d4f6c170d4b81bL,
        0xa2b5e9cd7ce5f297L } },
    /* 22 << 7 */
    { { 0x787229ccb8a233c3L,0x44ef5dd83419867fL,0x00316d2279d3d8dcL,
        0xdcf3200390bb1410L },
      { 0x62ad0125835d2264L,0x768c86580ed6605cL,0xa31abf17fc44e760L,
        0xc91848acbb22e570L } },
    /* 23 << 7 */
    { { 0xad1882f5b16c805fL,0xb74cc0ed7ccf9e9aL,0x9635af237b122dd7L,
        0x48a209035c3cd11bL },
      { 0xa24820b634c1eb54L,0x31a3c3305284dcb3L,0xd966cf59069c2ee4L,
        0xa74eec6fb3ff9335L } },
    /* 24 << 7 */
    { { 0xf44eeb994620e739L,0x7663a596f4159a9aL,0x79c54f42b4b745b1L,
        0xa8d3493759db9482L },
      { 0x35fad92a579501dfL,0x1d81bbe3289d7c2bL,0x1d60a274ddf3d371L,
        0xf08e23e546df1233L } },
    /* 25 << 7 */
    { { 0x4bc4c079f3a95f04L,0x0b43e660a8626015L,0xedb31526246ae3acL,
        0xa8536eb641247209L },
      { 0x6893a7dffdfacc62L,0xf3de226fc557777bL,0xa68c8d8c0d7f4265L,
        0x55a628eb15c685e3L } },
    /* 26 << 7 */
    { { 0x8cad8f875ecec6eeL,0x4aefda2d2a06c242L,0x46a2103357f00a7dL,
        0x91910c3a7ed125cfL },
      { 0x0b7f0e4a541165d2L,0x15ed1b93553eeec1L,0xadf5b4dbd24e020bL,
        0xf05307a3a7493b8bL } },
    /* 27 << 7 */
    { { 0x725548dc62070042L,0x74d71526c274916aL,0x3269851e6f098d01L,
        0xb2e01cb7f9ec928cL },
      { 0x96c2d9222b4368cdL,0x8eb84b03a0ec45d1L,0x733ad06826e5b3acL,
        0xced3679e93c5a962L } },
    /* 28 << 7 */
    { { 0x23c6a22ddd6eb876L,0xbd98ad9aa343dc3bL,0x61933d0356054515L,
        0x4a64b769e45cd744L },
      { 0x617a63f312586de6L,0x04984a9f7976e7d1L,0xb00ba446cd2a0a6bL,
        0x5b64e7f57d059d46L } },
    /* 29 << 7 */
    { { 0x8801ce046a4b08e6L,0x66f31460b13bbe9cL,0xb174e8874d87114eL,
        0xb2fee192f348e94fL },
      { 0xfede22837c822d05L,0x8d50c49c8f82b14aL,0x21ea4f6e0f5f1b5dL,
        0x68627cf0c1818095L } },
    /* 30 << 7 */
    { { 0xc1c0650c8a7b2458L,0x82ab62bb8bbc6affL,0x7b3665d76ce6989dL,
        0x2ad7991f7579e973L },
      { 0x701287aa7e9e8510L,0xb296a0380a18da53L,0xf8c3af862bf00fdcL,
        0x55776951b220dc06L } },
    /* 31 << 7 */
    { { 0x4e6e4b4f7d7dd541L,0x812feac7fe5c7431L,0x6bdfa63e340297b1L,
        0xecc11e5598009910L },
      { 0xee4c6165b25b98c0L,0x8a07b0d202c5939cL,0x9b36c17623147c40L,
        0x396054a2de2eab3aL } },
    /* 32 << 7 */
    { { 0x1f41010b2c439171L,0x3ff85ee6e8139388L,0x4ada4c7d8f077633L,
        0x9976011a824e6023L },
      { 0xa2501197eaf49f63L,0xdff2122fd60b0c4cL,0x1a6a3abbbab3df90L,
        0x854bbcc6b66ffd5fL } },
    /* 33 << 7 */
    { { 0x525964a9728572c1L,0x8a4923a2fadbd14bL,0x03830df9cd90b61bL,
        0xcdb00f4a79c2afe9L },
      { 0xff2f84bba6c3f13dL,0xdee45c305c0de4ddL,0x3e1dd748fba2e933L,
        0xe9dcc6907c51124cL } },
    /* 34 << 7 */
    { { 0x725177af28e11f62L,0xc8e120a18a64fdf5L,0x82ab73dff24fb357L,
        0x2d5d161844724879L },
      { 0x09627e2696c66b86L,0x1d547caec81d38c1L,0xbe8991a4d0f76658L,
        0xf1508662cf11a976L } },
    /* 35 << 7 */
    { { 0xa5dafebd3be3e582L,0xd9f545ba07399295L,0xd9f564a4676f9598L,
        0xec00bddf9294431eL },
      { 0xc1971113c1fdc758L,0xe32f572f69a001deL,0x048d7776b907f044L,
        0x4a474e6e5ca10e67L } },
    /* 36 << 7 */
    { { 0x6476dd403039a4b7L,0x85de9baa018ee2b8L,0x0c945aebfd7365f2L,
        0x2b47dc0d96c7267eL },
      { 0xb12b48a70410de25L,0x3ba7a11a177242c1L,0x44e6cee76504ff87L,
        0xb2605ff69d19f26cL } },
    /* 37 << 7 */
    { { 0xa56bb58950fb1b6bL,0x98dc118071d2fb53L,0xa4fdc6f8a1b78e04L,
        0xbea745b039d9349dL },
      { 0xac47422962d7eb73L,0x7b7651388b808ac3L,0x882370afd0ca219fL,
        0x28dcff7b9d1c23e8L } },
    /* 38 << 7 */
    { { 0xc6dc70eb3872f0a9L,0xb2f21248dfb642b1L,0x86838f0f65bbdfc9L,
        0x1d04a8b540b28364L },
      { 0xd4fa229d1e4d8d58L,0x74ee5e20fad0a9cdL,0x25a59aae5a40ec4aL,
        0x73be91f33727d6cdL } },
    /* 39 << 7 */
    { { 0x9c31405ed63f64ebL,0x9943c34c91d2f1c1L,0x70ad75d74fcdbf34L,
        0xa6ce7145b239e00dL },
      { 0x136bceedcd04b9e9L,0xb9ebeb8d44ed7f96L,0x068b43a55d136280L,
        0x2e1b66244c559b6bL } },
    /* 40 << 7 */
    { { 0xe3808e725472d67bL,0x73450378ce74546eL,0xc1b1b66eea1d58f7L,
        0x2b576e4fe34c2a7dL },
      { 0xc2b1bdf72f732803L,0x37aea3909f8e48c3L,0x8bbbb61e944f1cf3L,
        0x5cc7ccaa86c59643L } },
    /* 41 << 7 */
    { { 0xaf4c18e38d5b000aL,0x23b0edd02b6d561cL,0x11b67ef00d6cbe27L,
        0x679d789bb1b50e9dL },
      { 0xda198336372c4015L,0x5da50baf65781ea7L,0x00b3a6d4550201baL,
        0x988b89f7ecfffc72L } },
    /* 42 << 7 */
    { { 0xf2f08a0925948852L,0x4036bbb7406d1a34L,0x1cd57f0823d2dd87L,
        0x11a4387e4704dac3L },
      { 0xb8091a7ac5413b59L,0xe58940c609b5fa71L,0x70fd51546a75397cL,
        0xea5443755c59ff75L } },
    /* 43 << 7 */
    { { 0x15e5bed3ac25bd3aL,0x1bed3c336b17971eL,0x046fc1cdbaa96968L,
        0xda1b010d7090256fL },
      { 0xeec55752e6677d20L,0x8eac5d0624c9bb42L,0xc2f6270e8f4120e0L,
        0xd9ae9fff07748faaL } },
    /* 44 << 7 */
    { { 0x5a1b2634e8f7b7afL,0x1fcd743d81b1612dL,0x6b065aa23d420398L,
        0xe758b9c741e06643L },
      { 0xe1e52b537f111b3bL,0xb9ee0a5d83498731L,0x49c19631ea8154f4L,
        0x8f5a3479e1c08746L } },
    /* 45 << 7 */
    { { 0xe032d7c165dd5561L,0x6c3420fe442bef09L,0x1d390561a64eff47L,
        0x0d8fbf07902763bfL },
      { 0x0262f26da4bc6856L,0x7c1b59a79f4f2101L,0x663d9b3851240642L,
        0x39a0b4c277ce53ccL } },
    /* 46 << 7 */
    { { 0x1c896beb61f5e655L,0x75c4c0499f4bfd2dL,0xb8799a1510111b02L,
        0xc76f8641a4c2fa0eL },
      { 0xd77ff7fd185fc036L,0x53212bd6f5acbd16L,0x4ef7431f0408cff8L,
        0x45aa9d99fb082c4bL } },
    /* 47 << 7 */
    { { 0x22c1fa8ef0438565L,0x8e3a2ee34cb43ab5L,0x457df338232081d1L,
        0xd1293d9b482ff47bL },
      { 0x802a300e68106365L,0xa8f27aa1e51978c9L,0x6ca0eddaa6a6a4d3L,
        0x4cab122324c9526aL } },
    /* 48 << 7 */
    { { 0x26234b2e56730245L,0x9a04c15de1b54be4L,0x153fb6cfee89282bL,
        0x5901ca12d79d81adL },
      { 0xbe6853d87c3c5ffdL,0x16d3efb535e1942aL,0x3491f2073b56beceL,
        0x0d75e0c15b818cfdL } },
    /* 49 << 7 */
    { { 0x79a0e31940969df4L,0x75e4632c9ae34b31L,0x4a47585c68e8df30L,
        0x4a4a40e42a495467L },
      { 0x92b8a6f52762eae9L,0xa204cd80c9a3d133L,0xa441ecfdd1ff23cfL,
        0xd06feb584550ee57L } },
    /* 50 << 7 */
    { { 0xe14ca6a1dc032002L,0x9a780e5705505a36L,0xad93852e08cb2b29L,
        0xa54deaab008b00c4L },
      { 0x8cd2c71ae1042350L,0x2014b85da8915596L,0x1228b3e497ddd1dcL,
        0xa97282ce4a3b3ab7L } },
    /* 51 << 7 */
    { { 0xd978cd730f1559adL,0x2e877fa286b14d3cL,0x01d3dc943660f189L,
        0x90ad950d0d2b4dddL },
      { 0xa8d2676092245e3eL,0xfc1bf8d54964245dL,0x31206c72ac3d97ebL,
        0x39dfd972a58c64cbL } },
    /* 52 << 7 */
    { { 0xd631907f7efbbd16L,0x4fdc84e2174f1fd5L,0xe81e89b35c277996L,
        0xcb277b4e5f79f1deL },
      { 0x2eff44b32ed1962cL,0xbe36a64072883505L,0x14a1fac0545e69a0L,
        0x76dbbcbdd6f658b9L } },
    /* 53 << 7 */
    { { 0x0720c58478e2e86dL,0x52fccffbcaeead35L,0x06f28c72587fd1b2L,
        0xec36a9129e48bf69L },
      { 0x74874436daa3cdbdL,0xb3f7409fcdc2f2a3L,0x0e50d7fa1951c078L,
        0xd97ff34eee8949f0L } },
    /* 54 << 7 */
    { { 0x00db635e742d7b1dL,0x5c0b280e29f0d0f9L,0xafa7e616eabf9b35L,
        0x7341e2c72c8a76e8L },
      { 0x9679e34d2e96f198L,0x8c2661c090ee26caL,0x9c6dab3567a6516eL,
        0x7c8edc4b46b4b34fL } },
    /* 55 << 7 */
    { { 0xc502cf2f2afba4feL,0x76847ae06776dbf1L,0xace02706a2c3c83eL,
        0x0012645f4601c550L },
      { 0x1940e14aef6189bdL,0xba7f615f2cdf5e89L,0x698101aa438a3781L,
        0xf568a45da9e22357L } },
    /* 56 << 7 */
    { { 0x83af640e1f913210L,0x529a29fd8d505edcL,0xdf3d3090d6b0c85aL,
        0x46e238866897ea43L },
      { 0x97cca980416577aeL,0x1f5a96a89aa08fc3L,0xcb014b3356c05c30L,
        0x1944765a05ec9be4L } },
    /* 57 << 7 */
    { { 0x2d6789ccddc4371dL,0xd768f5a6f3618fc2L,0x77065e113da93c1cL,
        0x4ea3fbc30e27b3ebL },
      { 0x7c1bfba011ba30e9L,0xfc6fba671036ebe6L,0x0053a30cd3231aedL,
        0x7f0613d9ee3ac524L } },
    /* 58 << 7 */
    { { 0x95ec2fd963093df6L,0xfbc637687c0eea52L,0xf767b2868b64ea48L,
        0x6959b0ecf75bc633L },
      { 0x47e34c3bc9f63154L,0xd616b19fa524bc76L,0xefc9bb54632ac100L,
        0xd9abba10b4d96a7dL } },
    /* 59 << 7 */
    { { 0x3b7dd91afe2ad7e8L,0x29134cd7b4ebf343L,0x49d1c305152864fdL,
        0x3afd83d080efc220L },
      { 0x3552517e3f2f0d27L,0x0a2b5006fda48969L,0x568863ed3c3e8ec9L,
        0xd99d5c62891edec9L } },
    /* 60 << 7 */
    { { 0xb0ddc129d1c9d6eeL,0x373dad7457db23b4L,0x7c178b0bb416c7dfL,
        0x77431dac4f8a7153L },
      { 0xf528888841c1367eL,0xf1518939b838c91cL,0x81e17838541f3281L,
        0x7003024465b2bde5L } },
    /* 61 << 7 */
    { { 0xdc3094247350251cL,0xfac0c6ad7c811130L,0x3817aa1a6a141269L,
        0x1aa5a92fe10b4a6dL },
      { 0x996cca7f34648a96L,0x517a25b94e2a4f52L,0xff95ac4238b1547cL,
        0x01d981b6d9b9cd4fL } },
    /* 62 << 7 */
    { { 0xcc34d15e88d60ebaL,0x45851bf4a0ea1a51L,0x5d5f9b3082854ee0L,
        0x914be21f176ea156L },
      { 0xecac86d12a05c368L,0x255cb9c073a666a8L,0x5e4799d978c0eec5L,
        0x40ed89898fc05a71L } },
    /* 63 << 7 */
    { { 0x54888ac28ae03eddL,0xef3e9865a83b554bL,0x47b41822b7612fe4L,
        0xf6e16fd58f76cd2eL },
      { 0x091c7b12a977b5ddL,0x7051bf6b8f99d4aaL,0x9f737902fed218feL,
        0xd8112477b752c612L } },
    /* 64 << 7 */
    { { 0xbb45c28718d13bd3L,0xbbf3a89423c6dd1aL,0xc8171c5e13b9cf87L,
        0x2dfc779234f5348dL },
      { 0x9b9a662d985cabd4L,0x588a6ebc4d971de0L,0xda9fd894574cba64L,
        0x7e0f0cca651e6e67L } },
    /* 0 << 14 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 14 */
    { { 0x88ca276c4b8bceb8L,0x6d4ec101752d1106L,0x2ad98063f834dcbfL,
        0x4da81d19dfff19d0L },
      { 0x4ccc7cd23a9828ffL,0xf1e389b02e64b332L,0xe2fb6a6c7308b81cL,
        0xc6df66b25bcc0ac6L } },
    /* 2 << 14 */
    { { 0x5ccb8c75e1c58c80L,0x2ba9de0483fcc95aL,0xccdeb0eedfccbcf9L,
        0x1d667d4f70f3d3adL },
      { 0xc6aa14a536269820L,0x329a308b0fe87940L,0x39869970ede5cfb2L,
        0xc33c3068f601bb2cL } },
    /* 3 << 14 */
    { { 0x3087444aa1a8781bL,0x6cb5b7065cff3cbfL,0x7673a8e483082714L,
        0xc4bce0150842a792L },
      { 0xae71a03353e2a531L,0x147b28f88b5315f9L,0xcc4601336c5ab37aL,
        0xb1dd088b540dde16L } },
    /* 4 << 14 */
    { { 0xec25045511c09289L,0x83042ba7164079c9L,0x4881640c6e3879a2L,
        0x77c5babc802452eeL },
      { 0x7a7759a67088f360L,0x02da352cb74be7e9L,0x15800cdbe0338289L,
        0xad69f7c9501688c6L } },
    /* 5 << 14 */
    { { 0xb7d3506357ae1213L,0xd536753a97024ecdL,0x9d68071624938196L,
        0xac1bee4c44ed6d4eL },
      { 0x6dd9c9bf33e95503L,0x5ee9f1fd88fc1c3dL,0x4a701ff421654473L,
        0x9a316450bd2ffe36L } },
    /* 6 << 14 */
    { { 0xe9130a63103b5fa2L,0xe97f71208eee983bL,0x54b7f85be8749cbaL,
        0x69976910bb1bca55L },
      { 0x9ec4034ff4e621d3L,0xaad567ed695e17daL,0x7647f054cedb2ea8L,
        0xf85f944c09fc7433L } },
    /* 7 << 14 */
    { { 0x30af23b3b95eedddL,0xfd1d565a89985f3dL,0xfbb531734c254738L,
        0xb07ba56a171170a4L },
      { 0x5069882c294d55d1L,0xae0385c4792694c1L,0x0a0c792711225dc6L,
        0xadcc5f08e22867c9L } },
    /* 8 << 14 */
    { { 0x164ac67faee03999L,0x4de174d379ff7f91L,0x063e4943548da6eaL,
        0x5264880bdb7ccdf7L },
      { 0x4a18f34b49b992ccL,0xe16b6f4d14065870L,0xd32479ac4cdb0e21L,
        0xce8151f6162bc9f8L } },
    /* 9 << 14 */
    { { 0x0f8d9a2fe8f78545L,0x091643db3145b086L,0x5915a58223a1bcc9L,
        0x97348efd8a280fc7L },
      { 0x3f9d623665eccf5dL,0xd1a3493701ac8146L,0x1b8e51288ad0d5c1L,
        0x5cbcc9efd581dd11L } },
    /* 10 << 14 */
    { { 0x947ceaffed059f1dL,0xf5754d037460a186L,0x37698fa60164ff7bL,
        0x630900d235805339L },
      { 0xe467a6beeddd6bbcL,0xc53bffec5e36b12eL,0x06dfd3f9f831fc7dL,
        0xd995fcc4daef86acL } },
    /* 11 << 14 */
    { { 0x7d14846832d5b2e3L,0x7796b94c6335f566L,0x693983d66769b8bdL,
        0xff0306aaed5244faL },
      { 0x2e90d41a89b8e801L,0x1af09d8639e732f3L,0x96d14e1f320ccb1dL,
        0xbaf21c6fc05dceceL } },
    /* 12 << 14 */
    { { 0x8ae82a1cc216cf37L,0xac437f45773828bfL,0x8c12ff189d51a85bL,
        0xfeb563be34c16578L },
      { 0x9d9353b6c6706966L,0xcdc6eb5a0cda8733L,0x033c186e3e4953dbL,
        0x2ba46a66b2e37f7cL } },
    /* 13 << 14 */
    { { 0xb32115e2b9f3ee06L,0x1bc12cecdd6346a9L,0x6b9c2142321242feL,
        0xcf9b9bb35c68ea06L },
      { 0x7fe554ac920d49bcL,0x90b3a9b437aedebbL,0xacb181e07695af86L,
        0xd1c99c55fd567feaL } },
    /* 14 << 14 */
    { { 0xb7c18083fccf76ebL,0xc693bdbbf93113a3L,0x215ff05d66e03205L,
        0x4424aaeaf76d2a12L },
      { 0xb23f2782e7f30891L,0xad814d5e062db479L,0x347ec1d04aea78c3L,
        0x3d0f0a7e6a2332f2L } },
    /* 15 << 14 */
    { { 0x02ecefa68ad9e323L,0x16c812480d45e0c9L,0xd4b6253d2757306cL,
        0xe90203a381e42d04L },
      { 0xbcef10fbc13782f0L,0x823efe5d156267d4L,0x18add11afddb0092L,
        0x27068a29b104561aL } },
    /* 16 << 14 */
    { { 0x7eb7f516da0abf3eL,0x3c92ac9461b3381fL,0xbad7320ed3418870L,
        0xbab7a12607dbe066L },
      { 0xe7ce59be2def303fL,0x0bf1f2372d1e0c9fL,0x12c18d1e38f418dcL,
        0x7fcc5e3eb85bb676L } },
    /* 17 << 14 */
    { { 0x0bcf25ad1b038ac6L,0x35388760ddf1becbL,0x5734bf378a1ad137L,
        0x92f3a250b7645056L },
      { 0x6ed926a4718a5aceL,0x8e63f0a2b967f1cfL,0x6d9cccc9d835fe33L,
        0xb1b5efee31f82e18L } },
    /* 18 << 14 */
    { { 0x997aa2a424f2c6b1L,0xde87114f9e536a91L,0x01938bd20f819ec8L,
        0x012e9031ef772a43L },
      { 0x1578eb4c77aa9256L,0x052b408861a0c8edL,0x1153a3306ab5a380L,
        0xa3e7f085132f5675L } },
    /* 19 << 14 */
    { { 0x5e946e00909b8a41L,0x55f7d23116a3c156L,0xcd9524648ac8f8e3L,
        0x7c5184d4cd8d67f7L },
      { 0xb346896439ef93a7L,0xf4aa0b7e4e9058c8L,0xa409403e4b7c713fL,
        0x9d55e33c41a83e50L } },
    /* 20 << 14 */
    { { 0x9efee7047e1754b8L,0x54085471b1c0027bL,0xc5e7a6fa45af4e6dL,
        0xb4d3cd5830048569L },
      { 0xd2c20014f3ae8e79L,0xd0b6af13849f3f23L,0x3a1db91517982a8cL,
        0xea3c8099f9ffcf90L } },
    /* 21 << 14 */
    { { 0x25d9eb827bada472L,0xff84d98c09afd498L,0x5e2c1ffe56ff21f4L,
        0xafd072012f2f3a94L },
      { 0xb0227fe6cdb673bcL,0x58fc0e7efe8d7326L,0xb988d3eb191bfd4dL,
        0x824990932474d8b6L } },
    /* 22 << 14 */
    { { 0xd1ef53cb68caff21L,0x3cff018c5074160aL,0x609a468898f982fcL,
        0xee5caaac562a099eL },
      { 0xf650365bf8c6cfd7L,0x2652aa239cbc10eeL,0x904fd66e6ab86f4eL,
        0x6a25bbc32d82f3d8L } },
    /* 23 << 14 */
    { { 0xd3e6ecad19c7a275L,0x05ed04513604b2ddL,0xdd1d87e200c71863L,
        0xd9fc87938cd23356L },
      { 0x3337f8ba0036b81fL,0x63b5a762b5300622L,0x4cf696f1ce8800e3L,
        0x12cb326107e3cbc3L } },
    /* 24 << 14 */
    { { 0x18eac9530fa12b5bL,0x45ccf07377d159b5L,0xa74804446e844a0dL,
        0x4404e6c6d77d1c18L },
      { 0x003e43a6ce1af18fL,0x8a82808117fdffccL,0x91b63c11cabf3d17L,
        0xa4dedc21ad26f286L } },
    /* 25 << 14 */
    { { 0x6bf62b691a2b1579L,0x3b67b87bceeb29ffL,0x451ffadb40d4b996L,
        0x10c6ae50080978f8L },
      { 0x959d47e22c242dc5L,0xced9e9225423e158L,0x9a212d4c8d8a68f1L,
        0xeff3d6443708393fL } },
    /* 26 << 14 */
    { { 0x43f51810fbaffdedL,0x3886ccb40f6fd7c3L,0xb939247b13c31946L,
        0xbc1ee613aa1fd72aL },
      { 0x6d40140a631fd790L,0x9382e3bad26b3fd9L,0xff414370b3af96c3L,
        0x38c813cfe0ea9ad6L } },
    /* 27 << 14 */
    { { 0xf8844c3c157594daL,0x2a7b514fcac628bdL,0xc023e4e2c08c5107L,
        0x6c1644963f2722feL },
      { 0x842e1d06c03a22adL,0x5dbc286537ddae0dL,0x46dfc88d0342bc72L,
        0x873c805ca4a3c65cL } },
    /* 28 << 14 */
    { { 0xd202853b60aa5c14L,0x1dc35d343850cc05L,0x8014357e0cabccfdL,
        0x1aa44ce9c5a5225aL },
      { 0xa3cef9203a8444b4L,0xcf3f91b3c95384b1L,0x1d625ba1c9e5da54L,
        0xbf1fba37b1d0f46aL } },
    /* 29 << 14 */
    { { 0xdcef4fadfb3f4885L,0xa49debb23267f912L,0x6417d37a1e121cb8L,
        0xa6d871fc533e94c9L },
      { 0x89f802082e4834fbL,0x27e83f0fb353452fL,0xaf009f3ce1f8f322L,
        0xa5b77a7789319fd8L } },
    /* 30 << 14 */
    { { 0x0a89e741edf71900L,0xd679b841d514d93fL,0x8878577fb0a03702L,
        0xc9607b7885a209aeL },
      { 0xb7bd061659432a28L,0x0da060a2ed567145L,0x44e35a7a1a449f52L,
        0x9c9a2c82bbaccc0fL } },
    /* 31 << 14 */
    { { 0x83abd436d83701f4L,0x56e8bfe84bb9cbe8L,0x5b545cc8c631cd1eL,
        0x6d03426f955aca7dL },
      { 0x049fc9fa2f8db817L,0xfcec1799dc59675fL,0xa00ed3920455f095L,
        0x6d7cfa5fe5096b18L } },
    /* 32 << 14 */
    { { 0x2cda5caee30ae90bL,0x2cc34290caabea0dL,0x564afcd941e67856L,
        0x210c7a09cf6ef8b7L },
      { 0xc316d352f82a591dL,0x5fe8cc4dab43d2a1L,0xd8ebce978b4e9470L,
        0x26c78f44ba321a07L } },
    /* 33 << 14 */
    { { 0xa63f4b34d75e509cL,0x9122bbc5b9a6c63bL,0x8bf792a317942443L,
        0x95b05d687f4f70f9L },
      { 0x57d7dee513b70dc8L,0xe84259edfc376fddL,0xf8c4c4ffe3e313b4L,
        0xf8e2d3da13fa8ff1L } },
    /* 34 << 14 */
    { { 0x9692c390f8e4eedeL,0x3b5145510e95a902L,0x45c1670c7360623eL,
        0xf7a74f556abd2a82L },
      { 0x99b16e7e24e8e721L,0xae52fa2a512f1401L,0x46c60e803f3a09d5L,
        0xf803d1b30750e968L } },
    /* 35 << 14 */
    { { 0x17840d2f1791644eL,0x3e32b3db3b7981e6L,0x2d0830a5d3dfae10L,
        0x1b28d1186cc6dd0dL },
      { 0x944a988978368274L,0x310da94a55b1bf81L,0x503061ec0d739056L,
        0x1947e940b4d73288L } },
    /* 36 << 14 */
    { { 0x760ee8460228346fL,0x108765b3c5cff077L,0x22092b39beb12160L,
        0xa631d553b63001afL },
      { 0x9340cac40af3d43aL,0xe6cbfb5460d338a3L,0x2280ff0c7ca3f604L,
        0xaf48f86b3ba738cbL } },
    /* 37 << 14 */
    { { 0x7435dd7847d372ffL,0xbf9c7149f005c006L,0x624084b97a8d0e81L,
        0x50b578f34840496cL },
      { 0x414ca2c1b52a4266L,0xa3c302755535ef0bL,0xd4b808c1b50f7f47L,
        0xe6781ae29a199920L } },
    /* 38 << 14 */
    { { 0x5014123427a91ef8L,0x2f4f59375b77d060L,0x1be8269ec2dcb03dL,
        0xa293017c9f65043fL },
      { 0x1678dfe08caac401L,0x4942d8ce968b1716L,0xa9b55faeae36e201L,
        0xcfe4bde3d5279632L } },
    /* 39 << 14 */
    { { 0x6126d74479d637e6L,0x8491f1a8d63b4aadL,0xdf97b7369816b82cL,
        0xafca2c36796408c1L },
      { 0xc17f3f017a8e8058L,0xb3335a24e74705e2L,0xee20002346e3e3b0L,
        0x07bce06140630e08L } },
    /* 40 << 14 */
    { { 0x46b42c00ee8f9dfcL,0x3b8e85099e9b7f58L,0x83df4b18d36e8e89L,
        0x09631af515d50555L },
      { 0xb7906b77ef1ee3f1L,0x8272dc834bd1e17bL,0xf160bfd94903faacL,
        0x7fe9e9990dc71e59L } },
    /* 41 << 14 */
    { { 0x6ee9b790e714187dL,0x7391ec2a9d5a656fL,0xcbb55ec6e10b20f0L,
        0xbba3b57bec3645d6L },
      { 0x9c3265bce18322e8L,0xdb49b0f393328c91L,0xa911db7249c2bbecL,
        0xf71b4df36e5bd229L } },
    /* 42 << 14 */
    { { 0xdccede337ba27baaL,0x1af4476a4b712a97L,0xf0aaabec8a8683adL,
        0x138cdac56fa8e84cL },
      { 0xd2d50b00dc78b1adL,0x26fc0b72696442b9L,0x12cd5d8b125bf11bL,
        0x2a2ce980c4f82ca6L } },
    /* 43 << 14 */
    { { 0x9921c0a652e00dd3L,0x98e8707af1d7e1afL,0xaa7aa8b8df03b040L,
        0xb3ba8b23dff6bd74L },
      { 0x2fd0faab31db8c0bL,0x4697e9bf2819b732L,0x2dc3a5d00425b866L,
        0x4b9e7899d97816f1L } },
    /* 44 << 14 */
    { { 0x1355c4124c756c70L,0x2d4c4eee0fa089afL,0x4d8425a83b8a01b5L,
        0xcc26b8a9a3531d3aL },
      { 0x6eebe11b7ebd9eeaL,0xd511a79792c0f858L,0xaa863f01ec49a0c8L,
        0x7fb65625a8242995L } },
    /* 45 << 14 */
    { { 0x9de9d3f43dbc00c3L,0xb846152f3f7d61abL,0xc060fdbdd0d74549L,
        0xe722aab27b273702L },
      { 0x9e54f098d81b6f6eL,0x32dbaa5f9e2fde1fL,0x14cc99959ebbc796L,
        0x4ca6686c0eb83921L } },
    /* 46 << 14 */
    { { 0x6e65d7c610a0c0bdL,0x1f6930d7b3c0f6cdL,0xe4e0a9334d783d6fL,
        0xc945ee7f70b20ad4L },
      { 0x521bd135034b0265L,0xeb5d96e00fa9be95L,0x834c28c2357ef592L,
        0x08ab5b4cb81df99fL } },
    /* 47 << 14 */
    { { 0x6be99d80f464825dL,0x1cc837199a0c1293L,0x76616803e7e43c6aL,
        0x6fa3371591cc47acL },
      { 0xc3fdb99bdbfc08b9L,0x66e1ef2d68e2b249L,0xd3d8ef7f64a4a438L,
        0x775a70fca6f25b00L } },
    /* 48 << 14 */
    { { 0x2444c682a0cb5443L,0x264c26624b743ee7L,0xd7a1adc4a303eb20L,
        0x3f14821bf60a5b98L },
      { 0xa439102d1a1d7661L,0x47c25a378d8a5a1aL,0xdf4a48dba34c66a9L,
        0xab4673644c828c73L } },
    /* 49 << 14 */
    { { 0xd3caad733459cc8bL,0x08eeb442181b16c2L,0x3444abbb70600d33L,
        0xaa2a39c4cd0f8e70L },
      { 0x5fc6ae8f24836d70L,0xc119be8447d32fd4L,0x2b3f37710d6000ceL,
        0x439893a8e602337aL } },
    /* 50 << 14 */
    { { 0x4b75ff6ec1e8e564L,0x6185413ce451cf42L,0x0276d3b6162c3150L,
        0x844539e03aea9c55L },
      { 0xfc629ee642e9d70bL,0x4eb9b7e60be610c9L,0x8c53fda139ca3d92L,
        0xd2e4cfa614c2e9e2L } },
    /* 51 << 14 */
    { { 0x3c1f6895f14b31b2L,0xad42d951eb951fadL,0x5b20a169b8f10fc1L,
        0x284810bd586c61cdL },
      { 0x0c4a89aae863d781L,0x2eda48479c235d5cL,0x8e141950e6005150L,
        0x75716e1b52785efaL } },
    /* 52 << 14 */
    { { 0x290ced588305624eL,0x398956a806650920L,0xd057a47bdb5bd5b6L,
        0xf2d85299be9e119cL },
      { 0x4783095c7c5fc039L,0x72f7e7cd05363915L,0xe46b90d1df3e2968L,
        0xaadb3daeaaea2e53L } },
    /* 53 << 14 */
    { { 0xf5d374960cc4f426L,0xa59bffa859d78369L,0x7ad4cc11f0a46b04L,
        0xcbd63351b8e21b9eL },
      { 0x60d255e65653ebbfL,0x3eaa59af4d6b5843L,0x90049d259e1df2e2L,
        0x9a185a6de56aa105L } },
    /* 54 << 14 */
    { { 0xbd31c5cf80e3d909L,0x30caad3ba1f034d1L,0xaca74fa1d9c7c342L,
        0xac722cfc9565cf8aL },
      { 0x8b172ce65b42e582L,0x9e99e4e59b0607b2L,0x284eb5799446ca45L,
        0x6c5464bac57c9febL } },
    /* 55 << 14 */
    { { 0x1437fc95e511bc3bL,0x22d7bc16834d0889L,0x62e545b2c5071c43L,
        0x4c644d488cb4acd6L },
      { 0xd9efbe5068246492L,0xc9d169e7cbd8ad0eL,0xcb7365dc798ae01fL,
        0x5783f98f6d0dea3aL } },
    /* 56 << 14 */
    { { 0x9b4a7e38ec454423L,0x27405d0896ff4c8cL,0x9769f0970c462f7cL,
        0xcbda54127dc946aaL },
      { 0xdacb510fe7dd5146L,0x9c9a0d3930507b37L,0xa605730b05ded0acL,
        0x7e6834726c6c7b5bL } },
    /* 57 << 14 */
    { { 0xb378d92c7c952984L,0xec76370d72ae34d6L,0x1fde0bdeacda665bL,
        0xc8f648f4b931afc1L },
      { 0x2b55adb2b960f6ceL,0x71b3bdd47336a643L,0xf66e77bf73cc39e7L,
        0xf582c5e82fa3999aL } },
    /* 58 << 14 */
    { { 0x30ecd0c7af986d1dL,0xa2ae53ed4557dd65L,0x97ebccfb7d618a1dL,
        0xcbf5414911eed889L },
      { 0xdd0ff0e7d8f2bdd4L,0x6ac4a9fbfa769e74L,0xdfdfc7e993e5ababL,
        0x0c7151c5dffc6fccL } },
    /* 59 << 14 */
    { { 0x6d75e9625cbae56cL,0x77fae15296dccb89L,0x275c49466cc0e535L,
        0xc4a400a981781318L },
      { 0x8b9f872c77ba50e6L,0x971b6cb3a138eeb4L,0xa7e7d1f953f552a7L,
        0x360512ce8447c730L } },
    /* 60 << 14 */
    { { 0xf0c73bbbc5454439L,0x7f1b9b18a3a24b5cL,0xc5bb48dc51fa7d6bL,
        0xd264d6ec8b05a553L },
      { 0x123caaf2e9371f83L,0xdf5da393b149f564L,0x38e02eb6853b9babL,
        0xc6aab96e95bf6647L } },
    /* 61 << 14 */
    { { 0x4890be893141219bL,0x7afe4c2f7883fe8eL,0xc27bd13c59b86241L,
        0x1b9720f5aacebdc9L },
      { 0xa054e203f6b2174cL,0xd4e7b95260f6de8eL,0xcf7b1aeaf4558633L,
        0x43fc1881befa40a6L } },
    /* 62 << 14 */
    { { 0x592164dde23cef63L,0xfe57d6e8f7b4aaf2L,0x38a5e2c9e8aef9bcL,
        0x576bd78c1ac2b10bL },
      { 0x2357944c14309d10L,0x9933d7eded0ed94aL,0xb8792ea30339f299L,
        0xcfb4432287fd9bd1L } },
    /* 63 << 14 */
    { { 0x864f2fd592966739L,0x7435ecc5d3cfd83eL,0x8516d277ec4249f2L,
        0xaa7e1a8afc158b34L },
      { 0xfc0fc22bfbe640a1L,0xf287767f91121fecL,0x0ce482733f590dcbL,
        0x5e994e2ff087c249L } },
    /* 64 << 14 */
    { { 0x681a38c765604726L,0x4f8c6ae3247a421eL,0x1a51eaa01294956eL,
        0x0984b1ef47c9b324L },
      { 0x3749bd0d597b7696L,0x9d432b7808e57ee7L,0x3092afe12ba112d2L,
        0x89ccee4916c5a7f5L } },
    /* 0 << 21 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 21 */
    { { 0x355e9d7b54089685L,0x9f0ec68f40818349L,0x4cf4d8cd3861b80fL,
        0xcce669fdc1f5fa14L },
      { 0xea2125091788f9daL,0x32953613f3ccf239L,0x1048d09250027f3bL,
        0xe807b39d4270fbcbL } },
    /* 2 << 21 */
    { { 0x5099dc5595e388c3L,0xd0670ff5ea44e3eaL,0xd212c99361b41f7bL,
        0x4f594af9faf13305L },
      { 0xbc508bf205c01232L,0x7683353639ff08a5L,0xa1cf70bdb837741aL,
        0xba8e6616aaf7bd2aL } },
    /* 3 << 21 */
    { { 0xde04c343def27938L,0x3f15ca9148cee32aL,0xcb61573b9dd142daL,
        0xc094eefd126dd9bcL },
      { 0x5d42f1a5136bb4daL,0x75693952db2f3449L,0x98017cd65c16795eL,
        0x9e4015302afb67dbL } },
    /* 4 << 21 */
    { { 0x6376749f9b7c6c75L,0x680eacdcacbca35dL,0xe87fd5b55e145b32L,
        0xeb20d1ba36b886afL },
      { 0xca499055779b12bbL,0x6f290ff20be39fb7L,0x33ad6fe0f4a128ceL,
        0xf09e2a409b31da81L } },
    /* 5 << 21 */
    { { 0xb2ed3d7012039372L,0xb87e02c42ff46c13L,0x164246c6fb27dce2L,
        0xe34ee8f6e6d95811L },
      { 0x66cc601c3ec1fde9L,0x056b319480ffdd56L,0xff0098689626aa21L,
        0xc3e4982c2d931092L } },
    /* 6 << 21 */
    { { 0xbc0da9c1c3d42729L,0x4905da24720df0a0L,0x0e5e1fa045f6eadfL,
        0xc02033f32aab7523L },
      { 0x45ba916fedde75e1L,0xf43919bd75c68e52L,0x00e7c07684892e6aL,
        0x259f848870dfeb08L } },
    /* 7 << 21 */
    { { 0x3bfd5f2cd8a869a0L,0x1df48669574e7d67L,0x16d6ed5ae14cfd3bL,
        0x583aac2cfcf78465L },
      { 0x67210e6b67da2ae9L,0x0b024e70cfee511dL,0xf27e122c13839a4fL,
        0xfa5356c9b79dfa97L } },
    /* 8 << 21 */
    { { 0xf0c24783f357999bL,0x2c21474c26bfacb3L,0xe3abed6ad3ddb945L,
        0xbb21b7646031a5eaL },
      { 0x6db3b68b8afc2a09L,0x1aac2f0881306b71L,0x882c3371852eb6f5L,
        0xadfe0c1ad98e9b6fL } },
    /* 9 << 21 */
    { { 0x0247ee7b7edcb9e5L,0xe29ec0131f29918bL,0x5d1629e66099b6ceL,
        0x68587803cb534584L },
      { 0x6ccfeddb8ce551d3L,0x7ef98b72f85123a8L,0x19af4771f9711dcdL,
        0x8f67858bfd80e4ddL } },
    /* 10 << 21 */
    { { 0xa4c8c0167d607ee3L,0x15db36d74015a479L,0x0cb58eee9d28ea30L,
        0xb3d469b0becb7b4eL },
      { 0x811081b96f476e2cL,0x264da3aa59c78fabL,0xd6e5813d3cd73147L,
        0xce9e34a4e905362cL } },
    /* 11 << 21 */
    { { 0xe551ec2ecb3afa55L,0x2c9bef254b05589cL,0xd36ddeb7bcd083bcL,
        0x1c180b52ddb54a24L },
      { 0xb84220f3c0961f32L,0xa71103fbfe3ae670L,0x6a14d31946902477L,
        0x516701d2778b8eeeL } },
    /* 12 << 21 */
    { { 0x1cdb10254c3166d5L,0x3a0ba2c23d6fcb6eL,0xa218b4afb3820defL,
        0xda6de958bfe8a8f8L },
      { 0xc2b3c7554ceabdfaL,0xd35346918d73edcbL,0x453b8e630ce17182L,
        0x6507a5b001654263L } },
    /* 13 << 21 */
    { { 0xb2b8e424d5da0e59L,0x7e599c7561ac4c2eL,0xc64cb4c341aff49aL,
        0x0e231e63ea3e378eL },
      { 0x707cc0e3e08edaceL,0x18918dd25410779fL,0xcdd576902eef6bb3L,
        0x4c54d7d8ff758569L } },
    /* 14 << 21 */
    { { 0x494592042c89683cL,0x93596a167827e518L,0x6198954b2b20c939L,
        0x6672c94d8044d3baL },
      { 0x55e95fd3199b16ddL,0xa84841354185999aL,0x5e8709c8fe36e449L,
        0x47470e2e91401957L } },
    /* 15 << 21 */
    { { 0x0058bb090874afceL,0x19fb1d56606c3e52L,0xe1208b2a710903a0L,
        0xecabc372d47dfd1cL },
      { 0xd9daa7f45e94818fL,0x1302ac8f5dc99882L,0x7b4c6b15c44d37beL,
        0x0bcf6d4c72d19e0dL } },
    /* 16 << 21 */
    { { 0x1e0bf0633fd5a1deL,0x5d05e901a75b5b8cL,0xbbbdb1abcb3c617aL,
        0x44954a8c1aef4706L },
      { 0xbc3ceea3ff6a6e47L,0x6140f4210ded1275L,0xbb4b4c044dabe95fL,
        0xc55e87da7135e813L } },
    /* 17 << 21 */
    { { 0x15ad105cd963dd6bL,0x33d18f73666941a3L,0x860ccabe5d9253d6L,
        0x2af702fdd16e8b69L },
      { 0x7e46aadd74e525c0L,0xd9958a44af59f48fL,0xd8ca872f8e7de482L,
        0xc2270c14cf7d007dL } },
    /* 18 << 21 */
    { { 0x87c6204ea200e574L,0x0ee014cb7b69e79eL,0x176ff37882b23226L,
        0x802d829d8dbbb2f3L },
      { 0xb902924fe0a4dc31L,0x1f1a9ec75fe522f2L,0xbcd95d854da7c04aL,
        0x3a3a2e63b1543c0cL } },
    /* 19 << 21 */
    { { 0x9e70a3fff3271bf8L,0xd2522d88d2cd68adL,0xb777851ba6b727b9L,
        0x58953d6f63ff5264L },
      { 0x5e111c22b65c70d2L,0xaae73c5bd3a5143fL,0x2daa2bfc85ef5dc0L,
        0x5e7258d2ea13ded3L } },
    /* 20 << 21 */
    { { 0x4161127c2e3ce423L,0x7e35a0a26b1af415L,0x004483a8eed24b7bL,
        0x2816180a9f9d44f1L },
      { 0x214add93062829a1L,0x262a0bef225e847cL,0x4bb1b1ce5d6c53c4L,
        0xd02f829a91d06e53L } },
    /* 21 << 21 */
    { { 0xcdc8ba5c784da27cL,0x78a6c0d2161b5836L,0x6bea92c48373c6a4L,
        0x815f1a30a881f59aL },
      { 0x699c8642227cb8e2L,0x515d1e2b25a2b9d0L,0xcb5f1c6c1787b3e5L,
        0xc9a10260104dddc6L } },
    /* 22 << 21 */
    { { 0x18be4f2a0f3811e5L,0x8c05d3fc71e727d3L,0xecae3e5ffa707140L,
        0x4bb05b16d275b463L },
      { 0x74bad373b02a5ac8L,0x7232875a520344eeL,0x32cef98c65059d8fL,
        0x68e0fdb654e1b11dL } },
    /* 23 << 21 */
    { { 0x683424f33f3db43fL,0xf5f0878fabf4a83fL,0x681350d94ac2c5c9L,
        0x825e9ecb47dd3652L },
      { 0x420743f020713db6L,0x95db7427d1b082e5L,0xa0e1117f1affa57dL,
        0x62c87b5ef940f325L } },
    /* 24 << 21 */
    { { 0x6a65fda84e1d5d9aL,0x0c0fe385345ccdefL,0x19ff360fd6d72c0aL,
        0x1be1e8d7fb016131L },
      { 0xe2f27e91025b45e1L,0x25bec26605259bf1L,0xd7b8b4e7e51cc67eL,
        0x3a839aa5ab80a20eL } },
    /* 25 << 21 */
    { { 0x04a9b6959f85320dL,0xb939cd8398d669f3L,0x24464cede6948957L,
        0x463de507a43928e8L },
      { 0x4e1844e7f8755845L,0xc9c710915447e61cL,0x1798f394599d4bd7L,
        0x758f76301e072c64L } },
    /* 26 << 21 */
    { { 0x83c93728739b1925L,0x692017d7fa8eb048L,0x4a3a2a59478d1ee3L,
        0xb8e62912022640cdL },
      { 0x4689a4dd8572b8d7L,0x6281ddfe8f79da63L,0x788bf9aa212a153cL,
        0xb67e18f5b3438da6L } },
    /* 27 << 21 */
    { { 0x3fbafc5131cebdb8L,0x7f8ad590b042bd47L,0xf5d26c88e3055004L,
        0x7f23a1493d7d6f5cL },
      { 0x2fee54288758ccc0L,0xb08c91b7e1b80dfaL,0xf2bcc903ea0c0a53L,
        0xcdf2eae004e684ffL } },
    /* 28 << 21 */
    { { 0x354b2c07e1d9a693L,0x93b1fa2d97a833a8L,0x2dcd22c7e9e5f2b1L,
        0xf040a69c18aa3163L },
      { 0x4f9a4b2976939874L,0x58e5947f15e24d44L,0x9b47a945b0c2ef6fL,
        0xc4a15b7df630e92cL } },
    /* 29 << 21 */
    { { 0x8d7a33e77b1d4141L,0x44dabde9966486bcL,0x387a6016ef31dc9dL,
        0x76744b231462ff61L },
      { 0x2ad6395420cdd726L,0x9cff7e860e7803daL,0xaf5b8b4afd124ed3L,
        0x466dbbbd050c1149L } },
    /* 30 << 21 */
    { { 0x6835263606b296a3L,0x0ab400807f3fe1efL,0x1fc3895105bf08f8L,
        0x69b54ae4633c457fL },
      { 0x2ad428c61a206c53L,0xd67256878b09b3f9L,0x552d4d0e0bc619c9L,
        0x0e88b3133113c689L } },
    /* 31 << 21 */
    { { 0xb2483b80e87a91b4L,0xb9f842d70c75377bL,0x50463f385a78145eL,
        0xf2d3810d830817a9L },
      { 0x1819261e39cc886aL,0x697de51d8415699bL,0x688a874e5cab106eL,
        0xde48f3bbcb8692ecL } },
    /* 32 << 21 */
    { { 0xffa1de9738f4194dL,0x33d2726a3b996b63L,0x787c0ec30d2053a7L,
        0x9447e9cbeecd5c0cL },
      { 0x077f121c284773c0L,0x496427e4815829a1L,0x4b11978694def08bL,
        0x9e7b29e69c15a778L } },
    /* 33 << 21 */
    { { 0xa4d6d2befd4a8a47L,0x4f000a124333baefL,0xc9049d86642c570bL,
        0x9424e8f925e6aa6aL },
      { 0x84de7fe9e011cfecL,0xf273f9561e8c83b0L,0x98960835a47a40a6L,
        0xd91a20f10a13c27bL } },
    /* 34 << 21 */
    { { 0xaf08b4efed703e13L,0xefcbcf34c9994946L,0x019e6f382d53b069L,
        0x3d62c3c09b160894L },
      { 0xac7ad700adfc8f3bL,0x41cc0cc30042fce6L,0x0228ae7521cf742cL,
        0x56a1152af4c9a1a9L } },
    /* 35 << 21 */
    { { 0x5d8a3321febd27dcL,0x89bce7007c525f7fL,0xe8f815a91c1039eeL,
        0x9f6db69862e86536L },
      { 0x1ea6e7a666fe804dL,0x652acc41261aea16L,0xde28e5d8f9df596bL,
        0x18f453c11553a545L } },
    /* 36 << 21 */
    { { 0xa224f76384eeb5c8L,0x8ac452f5835ba87eL,0x9b2b5939c5f4c054L,
        0xb25779433ac1cdccL },
      { 0x1ba2cd0d772c60dcL,0x1fa52c43d7a9bd1cL,0x2efd4f4a60444f34L,
        0x7d188c052bdcfc9dL } },
    /* 37 << 21 */
    { { 0x49ef6825e1913711L,0xbca95ded600d6c46L,0x63916baaaf8d66d3L,
        0x049812022dc837a8L },
      { 0xb501e5170d3ae79dL,0x99ff7864b4edb859L,0x5099edeeaf4ec081L,
        0x89574889964f4052L } },
    /* 38 << 21 */
    { { 0x1690fdb852066d70L,0xb403207d671f4e7fL,0x8ebc1d1bd7413111L,
        0x1432d7feb4cfdf14L },
      { 0x9277666a65ad5d0eL,0xbd5ae578a928e194L,0x2f6c10d5b64962fbL,
        0xe3d756c02e794187L } },
    /* 39 << 21 */
    { { 0xf04fd82ad3e6349cL,0xde602dbacc7d39b6L,0x0886e20a044e7debL,
        0x6e30c75fe9ba917eL },
      { 0x763961fc4a322edeL,0x6df4a3cb2324bb92L,0x9fe823238f2ac967L,
        0x3c372afe2345372aL } },
    /* 40 << 21 */
    { { 0xbf7e9c5550b66fecL,0x5db7dd710c065cfaL,0x3525e31050d459eaL,
        0xad7abe5a8122941aL },
      { 0xc7aeba80122d92faL,0x066c3765efcc1c24L,0xa6d767ca8ffd71b1L,
        0x4a75fab59cc16dbcL } },
    /* 41 << 21 */
    { { 0x9acf8b89bb58b63dL,0x226cdcd36fc8c090L,0x852965b7ae7fbd0bL,
        0x4cadd176b8bfe65fL },
      { 0x4ccc11d1cfa2ac11L,0x8abf7420800319abL,0x24ab82cb88bb3ef1L,
        0x4d3db003524c0ce1L } },
    /* 42 << 21 */
    { { 0x384836413a431e8cL,0xfc0c04a0792848adL,0x2fc52bb8a07701b0L,
        0xdfdced3df29c72cbL },
      { 0x677e3d845280c2e0L,0x2dda1451e98cbec5L,0xba28b181aec26be2L,
        0x166947175ddea39bL } },
    /* 43 << 21 */
    { { 0x911ec5f04b9aa9b0L,0x24b9aaa03594ae7dL,0x0ccfa661c3c136a0L,
        0x5518964db7474319L },
      { 0xf0b0427b2175c3dcL,0x08db4cfc966b7badL,0x6f61428a5e888ad1L,
        0xfaa9617657b52d37L } },
    /* 44 << 21 */
    { { 0xe834013b10aac879L,0x73397bb095a62172L,0x9780683933a244b2L,
        0x0ab3806cc3bec0d0L },
      { 0x4fc7a8592a72512dL,0x964749390a4228b9L,0x8e5d79a84de4b4a5L,
        0x5a60d1b005d62667L } },
    /* 45 << 21 */
    { { 0xd31be21d08d90c20L,0x3f7ed5f2cc14dbb1L,0xdc8f58f9d7d431c4L,
        0x714f6dee82b5c63fL },
      { 0x6b28546676d2de93L,0x3c2f5d8fc39dd98cL,0x9bba0075ea3760a2L,
        0x75e0389a2411742eL } },
    /* 46 << 21 */
    { { 0x87d6715a7ffdb955L,0x702108fc9efb199dL,0xf11db1f96c010f8aL,
        0xf52b1e0f7eb6871bL },
      { 0xc49c0dc797c3ed9eL,0x18846f9577220a50L,0xdb2273bc97afddcbL,
        0x5b9a16d6cc469f75L } },
    /* 47 << 21 */
    { { 0xee3643943beedaf4L,0x825e01d6528a9239L,0xb60ba965ffd0f17cL,
        0xc00106b0b888384bL },
      { 0x6e24322f31751f74L,0xfe4d074c1821d05aL,0xf2493c73bf072932L,
        0xa797e20821089f21L } },
    /* 48 << 21 */
    { { 0xf1b318af2988abcdL,0xf887558f8e7da518L,0xb8b9939c97836b57L,
        0xf793e3b5c0a74cf3L },
      { 0xe191008a37684170L,0x7708823b05cb453cL,0xec221d40361beb2cL,
        0x0e5a6cceeb1b68f4L } },
    /* 49 << 21 */
    { { 0x3dc535f09644e937L,0xf506d720fda6c1b7L,0xc78c0e0bf99437bdL,
        0xa920b4d3cc9e2b09L },
      { 0x550965fef089b0e0L,0xf98134920109d910L,0xd2496f208c9d5d83L,
        0x751b69003e3e661fL } },
    /* 50 << 21 */
    { { 0x921edbde9e6ac190L,0x75891359f02d0e7aL,0xdeb0f83b1c4da092L,
        0x7b4279154feb2375L },
      { 0x24637c727c3a85c3L,0xbbfabf863f214ac3L,0xe8765740ae22fbfaL,
        0x3a09fab05f14045aL } },
    /* 51 << 21 */
    { { 0x546d574f8190dd41L,0xdfcf0b7348b5a39fL,0xf26c69de74097b2dL,
        0x37aa27ff3a7e3e90L },
      { 0x0942447b83bbe3dfL,0xe779fe209ab378aaL,0xad18ad2391e2264fL,
        0xe1dad926aaabd6d1L } },
    /* 52 << 21 */
    { { 0x9de0aa4f5db5e5c8L,0x45c3d73edb67e44eL,0x440862a15cd83936L,
        0x9f2b9a88ffce9a79L },
      { 0x6329906976cc6265L,0xf596a67f7a8830f5L,0x7051c8428d1d8284L,
        0xa00d05a83e5561fcL } },
    /* 53 << 21 */
    { { 0x15ce42d57a34d5bcL,0x4d9b3f5fb0e37254L,0x26e8409438841ab4L,
        0xa7afd35d9a8ede27L },
      { 0x4e8bcdb814835fa9L,0x85d04ddc79493e39L,0xbfa8fa79df8f65aeL,
        0xe31d759ada6c7c62L } },
    /* 54 << 21 */
    { { 0x76f27e707600aea7L,0xbec79f15d4d9acf5L,0x0f10bd0f5eae2ff6L,
        0x96c9eef17116a0c4L },
      { 0x30add2cc0cb6f595L,0x0c70b548943efe90L,0x2ce8026f0a05f4a8L,
        0xaa3da153b7c53c00L } },
    /* 55 << 21 */
    { { 0xcc46bf678e385a26L,0x64bcf06e99bae0f6L,0x49480a36035dcb4cL,
        0x2cc1a299e3cbae58L },
      { 0x849f8633b5480cb2L,0x1d8fa56d5607d83eL,0xcc3f0eeecea9f22bL,
        0x7d5ece291a23f3daL } },
    /* 56 << 21 */
    { { 0xc6f0a0068ae66f00L,0x2620157e78d648f0L,0xfc71776240d2880fL,
        0x2e0e293cbe105017L },
      { 0xb320f214854116f4L,0x5e4fa7002d5cd4ecL,0x83fa0a23dffc1c55L,
        0x18fcb8d2c9a9ca15L } },
    /* 57 << 21 */
    { { 0x9e9baccdd0ac70feL,0x8ba02fb727fe06ceL,0x2708804c3868fdd4L,
        0x355eaf0c9ba83df4L },
      { 0x014089babe43993aL,0xc8b59eda469cccd6L,0x77c94507b893a5a7L,
        0x0dffd39b8e517fd5L } },
    /* 58 << 21 */
    { { 0x71b6edb713dbeadfL,0x1617b77ffea2d0cbL,0xf745473648ff989fL,
        0x27357890b618bfa3L },
      { 0xf08c70aca7181331L,0x33b6cfe5b8bc036dL,0x75ed10f97163f883L,
        0x979875fc47d1cbbdL } },
    /* 59 << 21 */
    { { 0x6644b2347ad23938L,0x0f09e7f1d82e2bc8L,0x1e6c512b5588a39dL,
        0xb44e6694ce8eae85L },
      { 0x107336e2f392a4c7L,0x2619b284dbcd7b43L,0x7b7ec516b7f476a5L,
        0x0de74ef343081af2L } },
    /* 60 << 21 */
    { { 0x93d08bc6d8d54fafL,0x88d343a7f2ae6c9fL,0x7cdb9003bc147c27L,
        0xd740b19d69248562L },
      { 0x7f3c48bb464b3b60L,0xfc4cd7e9c91d92c1L,0x8172af80d7420ac9L,
        0x66907b77b9a50be9L } },
    /* 61 << 21 */
    { { 0xed99fea19ec8e974L,0x624a8c9454f39b1cL,0x9c4d608ace9798d1L,
        0x81e1652ea4812277L },
      { 0xa2cf7509f58b7db8L,0xef2cd193745e450eL,0x48ee84319d9da493L,
        0x7b471698b8ce96fdL } },
    /* 62 << 21 */
    { { 0x14dbaff8e7553998L,0xb0b14e4a822de823L,0x11032354429d7c51L,
        0xc1bb3327d572d20eL },
      { 0xff4738116a9c189eL,0x7cf2354e9c7b3b83L,0x29681ff67662df92L,
        0x0929622751c297d1L } },
    /* 63 << 21 */
    { { 0x1b800b345e3da635L,0xb5fd32d2745116e4L,0xdae17a1f2565abb0L,
        0x4f39d3d71fec80c2L },
      { 0xb4a19cc2290c2f4bL,0x1a1b049e0b6e5ae0L,0x41be6e926a823b6bL,
        0x35648873969649ceL } },
    /* 64 << 21 */
    { { 0xe85f995e2a8ed3d7L,0x9dc712e82f319e47L,0xc4402eff536d98a2L,
        0xca61e31037521e35L },
      { 0xfed39621c3196672L,0x29e7743fff17e8a7L,0x47eca488412a7c49L,
        0xf011451333a2a6daL } },
    /* 0 << 28 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 28 */
    { { 0x5675a12ae6880b5fL,0x9ba1e92ce2606d25L,0xb012facbeb3b2125L,
        0x3c50fdfbc37b0099L },
      { 0xc9ce461c9ce223e9L,0xcb90bdd6eefbd8acL,0xf657e5a4c631ea8eL,
        0x6584520b38a83ff6L } },
    /* 2 << 28 */
    { { 0xd959f317635abcf0L,0xa516a43f99e17618L,0xed90ccf2ce3bd99bL,
        0x2fc6d460a9fb3290L },
      { 0xb61ebe090cde4302L,0x5a3b061ff908003bL,0xf51bb736f60f5787L,
        0x1717f6e9057efc2fL } },
    /* 3 << 28 */
    { { 0x565acf931ca260efL,0x7d6e797df1811d23L,0xe63c6920783e42c8L,
        0xdc9dbce88dcb5158L },
      { 0x1426dc7ac8e39022L,0xf3037f3430ebfe47L,0x75aa6845f87d6395L,
        0xbf792fd561f53539L } },
    /* 4 << 28 */
    { { 0xa8bf21726ddc3d83L,0xf68deb6ed88207bbL,0xa8eae2ebcd03bd7eL,
        0x64c7f57e951f59a4L },
      { 0x8badb223a1786d57L,0x2e7fda6071182790L,0x9dc90e369a5a9457L,
        0x6eca838bf4b07e07L } },
    /* 5 << 28 */
    { { 0xad2e235b03264871L,0xb4c56243b8b933deL,0xd9c2bdda91354c8eL,
        0x97d743ff6a73fc76L },
      { 0xbed4109dce88013eL,0xa2428275f3b3bf4fL,0x900d3560011e761cL,
        0x34925d7de24fd6c2L } },
    /* 6 << 28 */
    { { 0x08b966caa8198235L,0x355d098ced2d764aL,0xfac27f7ca3d63f3aL,
        0x3e553f6cd3edc140L },
      { 0x64d72c7f11ff4334L,0x48735aabbc62cb57L,0xcf064294eba21082L,
        0xc1f9e456bb8d96fdL } },
    /* 7 << 28 */
    { { 0x1d24bdbc293cd945L,0x76985bcbea254e36L,0x3df2cb6a876fb485L,
        0x0176969fcd1f673dL },
      { 0x8b41cacb642133a7L,0x31ea88f8373880e2L,0xccf1ff85b3b1463fL,
        0x88fffa15aca74a27L } },
    /* 8 << 28 */
    { { 0x9a4b9b92167cdd1fL,0xa9118fc0f879b894L,0xf6e73387c55479f5L,
        0xfadf82edc626d292L },
      { 0xa03bb76156e80e6aL,0x59a783f9f27555d1L,0x027d63b63d087e43L,
        0x29f9ff3202fdededL } },
    /* 9 << 28 */
    { { 0x88a9173d371d0ec5L,0x04ac4d0d08c0227aL,0x002130119c7ec715L,
        0x0d2b7c76d9d6b472L },
      { 0xe678d53a5050bdffL,0x8f929d5765a5fcd5L,0x0793920b1dc3e712L,
        0x9a6a690f4b073699L } },
    /* 10 << 28 */
    { { 0x329d9a81758bdc9dL,0xebbaadd97d867b66L,0x0d7e6b19e6025f68L,
        0x50184374c53dce26L },
      { 0x298cb00f3ed13916L,0x835fe31ef5d45b26L,0x373a9c49f5a7fb7aL,
        0x59ed7e2334d3d8a8L } },
    /* 11 << 28 */
    { { 0x1a8dfe333baf6fa3L,0x926ccce7da53714fL,0xda4feaed18ef6fe2L,
        0xeddaf090c3ca5cddL },
      { 0xc39c2046bfe06d45L,0x1d9e889e0d7f549fL,0x209ace738d537d0aL,
        0x6f182c880e31e1ceL } },
    /* 12 << 28 */
    { { 0x865e07611b8c82e2L,0xcf11bcb9a659f2abL,0x1804bbeb7c868143L,
        0x2fa89a0e453e36ebL },
      { 0x42d69d8f2e17bad1L,0xe7fcea6fdc2ec741L,0xe7f19b45379ceb37L,
        0x84f0bd8949bb35a0L } },
    /* 13 << 28 */
    { { 0xa8a506785264b33dL,0x8cfae763ab1c9e26L,0x1e837dc3ff9b931aL,
        0x76164be8796ac029L },
      { 0x26a8bb2b1266db27L,0xfba4ab8354822255L,0x7a5adcfd38524458L,
        0xa056c88244ee212cL } },
    /* 14 << 28 */
    { { 0xe8db6fee55018577L,0xf71256b691955960L,0xeb1c118e10abe8d8L,
        0x984efc9fd45a8426L },
      { 0x4e1b323a00f2c6edL,0x1759a7af331baae2L,0xf15871892e00ba6cL,
        0xbd8a877ebb385d39L } },
    /* 15 << 28 */
    { { 0x440d1eae57d6c1aeL,0x092abdefa957dc67L,0x1065cbc674554b3fL,
        0x67062382710566c7L },
      { 0xd327679d6d04ae2bL,0x11507b00b0340551L,0x2e571583a2f52d80L,
        0x673628f4e8578507L } },
    /* 16 << 28 */
    { { 0xecb8f92d0cf4efe5L,0x88c47214960e2d22L,0xca9549ef6059f079L,
        0xd0a3774a7016da7cL },
      { 0xd51c95f61d001cabL,0x2d744defa3feeec1L,0xb7c20cc20afedf2bL,
        0xbf16c5f171d144a5L } },
    /* 17 << 28 */
    { { 0x003847273dc0d12eL,0xaa95f450b01cc80fL,0x19be3106a6f8e927L,
        0x6d6e10aa0417ba8bL },
      { 0x149f120c870e3491L,0x27380b41026dde94L,0x97d00840f29b04e6L,
        0x21d5d7e34bf9eb19L } },
    /* 18 << 28 */
    { { 0xea1daad9d5327f05L,0xf1f45d949c88c17cL,0xc5f3dee23f8ee0abL,
        0x706b777c75238a56L },
      { 0xf7aee379f834c60bL,0x5c24dae613cfe17bL,0x354c82e58091804bL,
        0x0dec2fdf102a577bL } },
    /* 19 << 28 */
    { { 0xbf3b70305253f8fcL,0xe516fa69d913c01cL,0x053afef4a105ba64L,
        0x91a1f36cc89c1e76L },
      { 0x3375865c7e724e18L,0x4313214429327b2bL,0x9cb2fc3b6f7bb24eL,
        0x20a6a16d6319e789L } },
    /* 20 << 28 */
    { { 0x20bfbd77642c467aL,0x3452bb12259d50c8L,0x0d3ba9c7ec7ffab2L,
        0xbbdb54543560e541L },
      { 0xab1d6e22d63ba04bL,0xdf6f11d37d24f015L,0x7c4d61d2f3df15faL,
        0xd5269f7940b3288cL } },
    /* 21 << 28 */
    { { 0xf8516b9e0e7c7b6cL,0x48750d82c203dac8L,0x89845d36a13d3083L,
        0xb3db3cfa280a131aL },
      { 0x40045401fbf752e6L,0x0289f97b1432e856L,0x41a9f3715fc1aa11L,
        0xe5c1e5a58d464042L } },
    /* 22 << 28 */
    { { 0xfbee2ea2589b71a7L,0xdd6ee5bd5de7056cL,0xcf8a45418fd6b6deL,
        0xb47831dcb15e33b1L },
      { 0x126a21692064321eL,0xa21d2d226e517eddL,0x1f8072be5ba5a30bL,
        0x24cca576c6a24b7dL } },
    /* 23 << 28 */
    { { 0x57eab82f5c282027L,0x1620f5e6557344b3L,0x59e852e0460b3385L,
        0xc906e3dbf050816cL },
      { 0xc031f8cf3eb398e8L,0x9c25b69b507ac07fL,0x652baf2b9cf7bdbeL,
        0x06fedc535ad91107L } },
    /* 24 << 28 */
    { { 0xa8ca0be24c4b12c5L,0x633292b628762d5dL,0xc04983f2827c0d5eL,
        0xcb6b867dc707ef03L },
      { 0xa7fc0d5bb9ac1124L,0xa5ce085baab7dcafL,0xb85e8f1c1cfda998L,
        0x8208df4227822503L } },
    /* 25 << 28 */
    { { 0xeaa82320a8dd6d76L,0x7b2fb4aead36eb73L,0x24d7319197a7b040L,
        0xc3ff64ae4001e02fL },
      { 0xd5d8715788799d94L,0x559142d093ceb95aL,0x798a453c59c3009aL,
        0x546b6fab7d6c83a2L } },
    /* 26 << 28 */
    { { 0xe263b23a5c76029aL,0x856305324ac62973L,0x14ee0643ecb007acL,
        0xf9e062977ca60905L },
      { 0x21b2fb2392f1f170L,0x31c4091846528ab2L,0x43b532423395cfd2L,
        0x4042138f6d14fb40L } },
    /* 27 << 28 */
    { { 0x80899c8c4464f342L,0x0f54c993084be305L,0xfacecac3fbf84810L,
        0xa65859368ae5244fL },
      { 0xb467c3c09a9f8d4aL,0x3e5f219cfd394895L,0x39f0767a9bf85fa8L,
        0xd97cc55dd8ee6022L } },
    /* 28 << 28 */
    { { 0xc480938fc83f86c4L,0x6479b8efe43bfcc6L,0x8e6f2e2238cabad7L,
        0x48e57fdd31f8c6aaL },
      { 0x66dd6a77cfbbdcacL,0xc7d9950b50ece329L,0x2e31f2050747a937L,
        0xc0f8a7e2a07acb8aL } },
    /* 29 << 28 */
    { { 0x578477bd15eaa686L,0xd72fb935f2f58b50L,0xe9fdbc6fd3a64d22L,
        0xa3e42674492dc89fL },
      { 0x42410ffda8fb7d24L,0x08a37dfd52676ed7L,0x4607c41bcb5d6125L,
        0x7db48af84001fa42L } },
    /* 30 << 28 */
    { { 0xe2264eb150cd30f0L,0xbb6fe952e215f8d7L,0xf3ce241197e3fe73L,
        0xe52e217937f19247L },
      { 0x9c7fc8c020c233c1L,0x91c7e721b383b101L,0x1163c472a7ac883fL,
        0xbe1c3b3a9d3b0f1eL } },
    /* 31 << 28 */
    { { 0x07be716fa3536bafL,0x764d9f4e62e9c19aL,0x15af34998eaf19f4L,
        0x987a7c4738ea0aceL },
      { 0xb03740b84a1f0117L,0x5cd1164ffe098a9fL,0xaf952cefc9d6fee5L,
        0x4e86dcbb3c0ad28bL } },
    /* 32 << 28 */
    { { 0x81125450677b7a8fL,0xba889fcee69273d2L,0x4a40a859582c5990L,
        0x836638b3f48934c3L },
      { 0xe964e189f3596ba6L,0x2f417c0ede8b0754L,0xd883169fd5f93f1bL,
        0x0318fe4ed45bb389L } },
    /* 33 << 28 */
    { { 0xe2c998a1db03273eL,0xc34f544d33ec151bL,0xae0456b1eb92d963L,
        0xaab61ec49738857fL },
      { 0x4fb6a34ef71d9c39L,0xaa9dbd8cd816ec44L,0xf6532e375efdf950L,
        0x7151dc4467109c55L } },
    /* 34 << 28 */
    { { 0xb18b586a3f4e322cL,0x27b300663553a18bL,0xbd31ea241ae4cd85L,
        0xe8f88f4aa64de69aL },
      { 0x8c946a97609c13bbL,0xbf8cc55a0eebd9f0L,0x446aa2e47a8892b9L,
        0x660c0a5565b98c31L } },
    /* 35 << 28 */
    { { 0x568c56fcd3463522L,0xfa6bf3a6eb130aa5L,0x16c1568b008dc0daL,
        0x9c4132ccfed70a87L },
      { 0x3e983d09d497fdffL,0xd7a0e542f0ebe6b0L,0x193a07e068b542caL,
        0x4909776b07c6ab4fL } },
    /* 36 << 28 */
    { { 0x55b77ef4418acd7bL,0x64ba62d347a77d32L,0xaec1aa932d1f562eL,
        0x3468725b10dc5999L },
      { 0x422851b16ff0d478L,0x15da84298e7dddccL,0x38567920b8ac5238L,
        0xfd29eb4a2e3344d8L } },
    /* 37 << 28 */
    { { 0x7b2af70c4fc636b5L,0x242acfc8879e7640L,0x88e89786b5e25c7bL,
        0x85576b1b16ec1bfdL },
      { 0xb31c82531891e595L,0x14315dfeca5608a5L,0xb9d61b76b0c14fd9L,
        0x5d5ad8a3734b6cabL } },
    /* 38 << 28 */
    { { 0xc2ea321d44aee005L,0xd68abd2c147ed658L,0x31152d60893db877L,
        0x4807ac46281487b6L },
      { 0x58ebd15e65da04b5L,0xf0f74fd4b2f9d1fdL,0x3d04aa65393c7d91L,
        0xb46fb59a8e7e6a2cL } },
    /* 39 << 28 */
    { { 0x9236fdf1ae1eed5dL,0x71936f567810e2beL,0xa1ead7d56d9ff147L,
        0x32670ed8149a9b6dL },
      { 0x12772fddcb58ea59L,0xfce260b39df52ddbL,0x3221f2fbccab1e97L,
        0xf8ff7e3757762484L } },
    /* 40 << 28 */
    { { 0xb0a31a1c855512cfL,0x293a819ed71d4c4eL,0xc1ebc896cd6a900fL,
        0xc727a6469b9e0a4bL },
      { 0x06124fc00018f29fL,0x67bd8fed41b7730cL,0xeeebf0f0c77be72eL,
        0x427fe6fe474d747aL } },
    /* 41 << 28 */
    { { 0xa7fb9a4f932ccbf0L,0xabb9c85e5f3d489fL,0xe7e4f956bdf26442L,
        0xd014848e38d17422L },
      { 0xae37d855d3e9bff6L,0x88fbae1dca5aeb09L,0x1a8a740bf025feaaL,
        0xc1a67821b9475ebbL } },
    /* 42 << 28 */
    { { 0xb6cb6accde2bf8a2L,0x9b2ab1ca66a0f14eL,0xcbfbc06883b2ba59L,
        0x336ab62c68447934L },
      { 0xd3a016a9f19719b8L,0x819a31bb0b5b9d6eL,0x7b24be2b3e1c6c0bL,
        0x10834b4a013f6821L } },
    /* 43 << 28 */
    { { 0xe5e5de2786f21d2cL,0x56b46a2de9e35ad5L,0xfc4e861de2111e59L,
        0x7472ce5e6e37ca63L },
      { 0xafab9a7127d2210eL,0x1644a0a69ff6245aL,0xee498acb8dbef51fL,
        0xd4c70da12e9604d3L } },
    /* 44 << 28 */
    { { 0xde4873646fecb64cL,0xa8fda1fdd15fb62fL,0x97e2febe088de028L,
        0x4a769019ecdce095L },
      { 0x4cb6a33850a58ddbL,0x08df59d817028d36L,0xfe3a80ffb51722b7L,
        0xa3cc2fe2963c2383L } },
    /* 45 << 28 */
    { { 0x40b2df4953cc5341L,0xf3e90d4ca3c4bf2fL,0x3f25c5ec20f02731L,
        0xd84f5b5a69065d9aL },
      { 0x156d350e129921beL,0xe98787cc1b116922L,0xba5f9b8239e77b13L,
        0xee4d79f5044449a5L } },
    /* 46 << 28 */
    { { 0xb54b7388dd6d852dL,0xf7554c5cf9ca5fdfL,0x864d1fbf51228a81L,
        0x721e1add9a80f90bL },
      { 0x89d4e297ad0efa62L,0x4e471a876dba9404L,0x9a38158b1c1008b0L,
        0x3dfe81a795c47ec2L } },
    /* 47 << 28 */
    { { 0xcb02ce9b28603026L,0xfd3207aa3bd357fcL,0xb3807bddf296f5f2L,
        0x7895918d23c2ea7eL },
      { 0xdc0eb62f88feb3baL,0x024dfd84bdd75674L,0xe5bd38280a1e0496L,
        0xb8b1cd8624c8f30cL } },
    /* 48 << 28 */
    { { 0xb559e34d674d10cfL,0x6955bb699f962ec5L,0x8bf1ab6c542af42dL,
        0x3f2f33fadfa61256L },
      { 0x3214019573d1049eL,0xf5089278dfd7f39bL,0xb42eb51cb4237be0L,
        0xdf747f44874d0e57L } },
    /* 49 << 28 */
    { { 0xbe64bb2277b5d475L,0x2c3d5ecb28308634L,0x936a2987cb999c46L,
        0x5a30ddfae26489eaL },
      { 0x8bfc782ec8eabf9cL,0xb9995bb074c8c6e3L,0x4f99c7ac391f5c5aL,
        0x67f4092b5270c4adL } },
    /* 50 << 28 */
    { { 0x6771a29de6e8135eL,0x988dfb2b6c698cecL,0x7818600f77812aa1L,
        0x04393c83fd98e1c1L },
      { 0xe448232e864ef146L,0x9b70ecf4a465ab71L,0x31df0531b13cc704L,
        0x401ae0b316e48426L } },
    /* 51 << 28 */
    { { 0xa81066307fc514edL,0xda798170de4b1614L,0xde892efcc2c684feL,
        0xd5205bc105d64effL },
      { 0x84df4eade1d59ba5L,0x65245ca189bb2ea7L,0x3de6ca3464edbf51L,
        0x115296e456bcebf9L } },
    /* 52 << 28 */
    { { 0x0851631f7fd52a3dL,0x9881db71949ad4beL,0x4b2337dd88caf772L,
        0x02da59de33ec7979L },
      { 0x2473c620afe840dfL,0x2965ebffa92ef1d0L,0x2452854f6fcd9651L,
        0x97092935bac2ed99L } },
    /* 53 << 28 */
    { { 0xf0743ce708242246L,0x76fdd82c6d1a8439L,0x3627c89061079258L,
        0x312f98f182b21983L },
      { 0xd87dceece9173891L,0xad16cfe0d7a30e32L,0xc404a1a6c9c7efafL,
        0x46e34671d6df357eL } },
    /* 54 << 28 */
    { { 0x92fec7c47a02aa32L,0x567fef7e5a6a7bb9L,0x35fd570ca3f97b5dL,
        0x456bad8c4a4b0dfaL },
      { 0x85a3f42ca677f090L,0x35060bb822a68d53L,0x1cea9d1153567530L,
        0xf2cbc8dd8169fbceL } },
    /* 55 << 28 */
    { { 0xa3e1d52d86cde794L,0x72a258cbb3bdf344L,0x2997cd5931b8614dL,
        0x31ce2ea48164b632L },
      { 0xe495e9b70eba7545L,0xaad69130bc4403b5L,0x37f6389b45760d9bL,
        0x00f4d58db871b17dL } },
    /* 56 << 28 */
    { { 0x91973d4d4aa359d7L,0x249f510cc8dd0582L,0xef11ac877608be27L,
        0xce116714d940b1c7L },
      { 0xf34881f3fef20037L,0x2622247298203f4eL,0x4c9e98ede9363154L,
        0xa806b3a603a8158dL } },
    /* 57 << 28 */
    { { 0xdd974d6609d16ce3L,0xe1bcc51359ae977aL,0x0e6201c7218464d6L,
        0x057898119e35c7afL },
      { 0xb1596f7a8b33a863L,0x8fa93aeb42bd8284L,0xf197c20246e11559L,
        0x356b9c81add27d86L } },
    /* 58 << 28 */
    { { 0x3c4080fd1695cb70L,0xc10c28cc20f20318L,0xe9d7ed93ce1ffab9L,
        0xb23976b34f9de9bdL },
      { 0x9b1b81dd6d61a6f2L,0x7537d729f6318874L,0xb75022f420cee7abL,
        0x425fddbaaa430952L } },
    /* 59 << 28 */
    { { 0x54c4306d1ccfb3fdL,0xf10a54f146a30a37L,0x2d332a2974fd4925L,
        0x8d2fa9211438feb2L },
      { 0x46a9c6b5fbb41bd2L,0x87e98550d30c65fdL,0xfbcb2ca666cd9a20L,
        0xc176530e91719670L } },
    /* 60 << 28 */
    { { 0xdd4a1a18cec38056L,0xe6ef179375544998L,0xf58f69cf30583fb6L,
        0x12197860aa76bf2bL },
      { 0x717813e53bb686fcL,0x9beeb1ae0f06c403L,0xd83416ee2782dc86L,
        0x5fc89c01b5500cccL } },
    /* 61 << 28 */
    { { 0x063aee258e110ed3L,0x1a87377c45963073L,0x86944f595110634fL,
        0x50659ae10ba76459L },
      { 0xa00e48ffde9eb40dL,0x49235afafe5b118cL,0x81705008c425ee38L,
        0x3c01abc82d5f2f92L } },
    /* 62 << 28 */
    { { 0x4a21bc956fdf148bL,0xea5cc30e0b7e6871L,0x90b4abb611713844L,
        0x3b7d734ff2001af9L },
      { 0xfc616b89782b2020L,0x68b3935cd8b0e02dL,0x54cf5b8c1cbb2de4L,
        0x42b0432aa7c0f7acL } },
    /* 63 << 28 */
    { { 0xa04e06efbdffae5eL,0x36cac28ed4b636eeL,0x08a06b2fc3a98127L,
        0x1ef0b57b290c5385L },
      { 0x14e184b827154c46L,0xa5dd344460910b3eL,0xd0008ac43c67a74bL,
        0x2649cba4efed9fd1L } },
    /* 64 << 28 */
    { { 0x26bc537af0c1bb4fL,0x37f376ffd06b90f5L,0x4d48d994be7c89cfL,
        0x511c21588d572003L },
      { 0xc26fbac1088dda1eL,0xc3d551897ad4934cL,0x5233c17685dcaf7cL,
        0xec3a8a29a88b473dL } },
    /* 0 << 35 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 35 */
    { { 0xfd96667ab1f0c175L,0xa256a6112ab99e7dL,0xff07c1ea05e43f9dL,
        0x305700bc7e1c9cd6L },
      { 0x3f1e25462b2887a3L,0xdd782f49c772fd14L,0x9125f99638584057L,
        0x19fd039616a02cf9L } },
    /* 2 << 35 */
    { { 0xa8d62bd34c58174dL,0x872251d3a900551fL,0x06f5862df12802c3L,
        0x5d93c48add925555L },
      { 0xc39b67d5bd6006f8L,0xea6f756bf96ccc67L,0x140e853e543014dbL,
        0x2bdc5674e9de42c0L } },
    /* 3 << 35 */
    { { 0x01dfda7be01c073dL,0x07a6bb65ff9e1234L,0x2a4f7f18622cee4eL,
        0xdf4cead850f0a3a7L },
      { 0x152b3c8e1b8c2903L,0x9e82e9995f2a89b3L,0x0e6cfa7e68ce7a3cL,
        0xebb34d900ca0464cL } },
    /* 4 << 35 */
    { { 0xfa1a58faeda49f74L,0xddb899570e4545a3L,0xd3576489c74c07e4L,
        0x64e4b39eb59b1008L },
      { 0x3b090340f66b546cL,0x0e0f4013cdeb912fL,0xbb00b46c01e55ccaL,
        0x55b61b3499ad0768L } },
    /* 5 << 35 */
    { { 0xb06b71fce8bbda5bL,0x8de64d84a24b0a63L,0xb73dc262b5d4603fL,
        0x5d5fa9641965a916L },
      { 0xb48a40533bc98966L,0xaa8718636f564743L,0x88b00822e76a6a3eL,
        0x58c9e92eb38d9e0dL } },
    /* 6 << 35 */
    { { 0xc0d22337e989963eL,0x2c4831ced3778d5aL,0xd775c6a5ee8c4178L,
        0xe23916549d0c2894L },
      { 0xf7d4fe865d0eb314L,0x42801b8f8b2290d3L,0x73e9b332cdcefa78L,
        0xc0d169d93e877feaL } },
    /* 7 << 35 */
    { { 0x29c8138bffee23faL,0xbff98230fb92e3b8L,0x14077ad58fa75007L,
        0x4d3a6e1088e61b81L },
      { 0x218a867d3bcf733dL,0x20ff6566665e37fcL,0xe39c0581da5cbf67L,
        0x4a6e1d7c8add8c4cL } },
    /* 8 << 35 */
    { { 0xcab02370734a1327L,0xa1df7afc1951afa8L,0x581cfbaf42638b8aL,
        0x39db6d2b2130eaa6L },
      { 0x4bbc805bda2f91a5L,0x3dcb0a7ee569add8L,0x724ab65ad721fa7dL,
        0xa5152b95f88f8008L } },
    /* 9 << 35 */
    { { 0x7fe7f1b9281615baL,0x419d1a5341d5aa0cL,0xafc556dc9fb0917eL,
        0xab2a69f3616ce893L },
      { 0xfb9a6eb1c0861e05L,0x0b74ae115eb02b8fL,0xccff0ad53b1e44feL,
        0x86dfe0e688824f53L } },
    /* 10 << 35 */
    { { 0xedf38dc441177a46L,0xd9a955bb7f039a7bL,0x4f1525814d8ae7c2L,
        0x063c9f834f848819L },
      { 0x54ea4526841e8783L,0xe86a4119aa5f2b32L,0xb7529a3b19846dcfL,
        0x91356a0735689d70L } },
    /* 11 << 35 */
    { { 0xbe66f5db8f049ef8L,0x0f5fd99ec38dd5edL,0x1896d52b1b4ae7a7L,
        0xf27c45c6480b1ebbL },
      { 0xd88cff4c3fede5c1L,0x57d902c9da27560bL,0x84aa7f0752d57debL,
        0x8da4c7c808bb6028L } },
    /* 12 << 35 */
    { { 0x658f4dea8910763eL,0x6e5fcb48076a0f80L,0x6a5447a4ab65f9b9L,
        0xd7d863d4a75bb0c5L },
      { 0x806c34a7e87e7916L,0x05391559cd961e88L,0x5def2d8874fe6aebL,
        0x8ac350b2f9226ca1L } },
    /* 13 << 35 */
    { { 0xffa8a64912401813L,0xd61827625337c55dL,0xfce9d7ff3be902e3L,
        0xb3b275d1ea0dd7a5L },
      { 0x342620f42cb48ac9L,0xc0369384a8b38a74L,0x04b0ee6ac0695d3aL,
        0x4d02558594c5394dL } },
    /* 14 << 35 */
    { { 0xff9635d081443d16L,0x2342cbfaa6cc364bL,0x63b0a03225bf8438L,
        0x6ccd3ce5a078d298L },
      { 0xf93bd10891292fd3L,0xc887a31b14073286L,0xeb1275bf9f62cd16L,
        0x0335bae361578b46L } },
    /* 15 << 35 */
    { { 0x810d5efd53348e4eL,0xf9cd822a63c74225L,0x93d2e810a426bf44L,
        0x95a47a97019d36b3L },
      { 0x1da421b9d5d1f840L,0xe5b8a55fd6c46e3cL,0x2dd3a5e7c9244881L,
        0xd50f9cde70c1fd2fL } },
    /* 16 << 35 */
    { { 0xbee2aca7614d9ff3L,0xd1f13b2c358f245aL,0x9e92d83fc46f62abL,
        0xc1dd32dd827d7374L },
      { 0x1636d593c3e566e7L,0x81c2f4e704ccb02bL,0xb57782c6cd35b652L,
        0xad88787e88210d42L } },
    /* 17 << 35 */
    { { 0x3ad52d72fbd7d35aL,0x4117f50237a2a095L,0xed03d415d356b3b6L,
        0x135d5a8c15ca6087L },
      { 0xfbaba41fef5dca2aL,0x660e5cd0afb4787dL,0xe0e66378a55e9ef0L,
        0xf24513cf69939f56L } },
    /* 18 << 35 */
    { { 0x0f38f09cab4f6bd9L,0xec3037b4922dcac1L,0x706b201a08a1a51eL,
        0x159113518ffff040L },
      { 0x239d7b6accf63d87L,0xeca37dc85187f595L,0x04ea79e4ad5a0ab3L,
        0xcdd81522e9520e8fL } },
    /* 19 << 35 */
    { { 0x7fe6b6aac35e1020L,0x57b63c9e140ac884L,0xc45c23fc33f19077L,
        0x468d2c36b71273c5L },
      { 0xeb6839d6fc305ac2L,0xf6e310ff0183793aL,0xbca206e432da639dL,
        0x8eb5cac18518e27eL } },
    /* 20 << 35 */
    { { 0xfeed0feb66ed96f9L,0x1632632eecc3a8dcL,0x904493631455c8aeL,
        0x8d7619d40aeada65L },
      { 0x2f2fa8989f630ee9L,0xd78caf0c370db87cL,0x46fa0fc9c45898cfL,
        0xa509cc3e2d84244fL } },
    /* 21 << 35 */
    { { 0xbdbea4b4a5b099aaL,0x8e8fe2847592587bL,0x0226d38742000897L,
        0xb678055136db5cd9L },
      { 0xd8fe5eb1ca64f047L,0x6f21474bb77cf8cbL,0xab8fcae7ee45ae34L,
        0x73eaf9eb1f19cd67L } },
    /* 22 << 35 */
    { { 0x5bb96415ee4df6ceL,0xd1e27bcfa3ae4cf3L,0x9bf7ace3c7f1868eL,
        0xe821aa8b82091dcaL },
      { 0xf732e6bcd381b6c4L,0x5feda346dd01864fL,0x0933b92cb6387846L,
        0xbf1f1e83a0028029L } },
    /* 23 << 35 */
    { { 0x0848bf8ca3e38124L,0xfe295fdf208fda8fL,0x733792398913a1c4L,
        0x59354b247e78564eL },
      { 0x042b752932dcafbcL,0x752173d3fa93c5c7L,0x6ffd45909737135aL,
        0x249712b00f983005L } },
    /* 24 << 35 */
    { { 0xdbba28741f25da8bL,0x14027f11097ba4a9L,0xe429b3c734b8e4a2L,
        0xd66a43e3056b4afcL },
      { 0x158644ad2ac351e6L,0xff4aecd9164bc6ccL,0xbb5b0c87f6c615eeL,
        0xc497d8eed7679b1bL } },
    /* 25 << 35 */
    { { 0xf666c625f1c6e97aL,0xe89f84b2c73a277fL,0x2403d513746af4c0L,
        0xe6858fdfb7101febL },
      { 0x1a42c51b84f1dcb7L,0xc57f12e08202bc04L,0xf8326a93754df5aeL,
        0x3d3daf0481a46aefL } },
    /* 26 << 35 */
    { { 0x8bb8c27601232d03L,0xd446c82efb371cf1L,0xe5e8b639efa495f4L,
        0x51a7b34a477e6493L },
      { 0xffba5466824f2b6eL,0xcc67ddadf0eaa6a9L,0xcf0f8ce1fee19b24L,
        0x3430912783b3df41L } },
    /* 27 << 35 */
    { { 0xc8b13e8c9719a6cdL,0xb408e505619d5c33L,0x8c1b831ba3158864L,
        0x506b3c160b3d02bbL },
      { 0xf23846bcbf11ff8dL,0xf0f043e816e0328aL,0x30b7b9cd65986a7aL,
        0x0951b10221b660cdL } },
    /* 28 << 35 */
    { { 0x72a26c5f52bf29a5L,0xb513d669b6534592L,0xb8ac15ad578195eaL,
        0xd6ed33eac0785f88L },
      { 0x39e23dbfb9e33946L,0xeadb2453f43e88ebL,0x6d82fefa2746c34bL,
        0xe9172aa0cc542b54L } },
    /* 29 << 35 */
    { { 0x8af6b819ecb50699L,0x4af769391c1d0af9L,0x5a7dbbbe99dddb1aL,
        0x97b0a3aa891ea41dL },
      { 0x32b457e66e35ea4fL,0xe2a21c2a9d77b900L,0xb18718d62ac991cfL,
        0xc4416237740743cdL } },
    /* 30 << 35 */
    { { 0xcc3f76b66a05ab55L,0x2ab4b29e98091425L,0xbf373ad1b6478fc8L,
        0x8a1a9489178b5844L },
      { 0xb5295edf09daf4beL,0x07fbb1194ed54766L,0x6e44367b7d0b9d8fL,
        0x6dc4d8f6edb96a10L } },
    /* 31 << 35 */
    { { 0x2ba6910637fc19a3L,0x522eba390b138296L,0x751544c7fda58cf3L,
        0xaba6fe160ba33938L },
      { 0x48e085be94dac7d6L,0x06c8701419f99faaL,0x33b9a8d61a587f89L,
        0xdae382ca3fd8d8feL } },
    /* 32 << 35 */
    { { 0xb5b383c6150b0fcdL,0xf948da80ed9b0f4cL,0xcf075225ccd05413L,
        0x3f31b12c4f62be64L },
      { 0x23b21fc8368c17f6L,0x423d5369400bc690L,0x5335dd1edeac140eL,
        0xe631c2499493ad61L } },
    /* 33 << 35 */
    { { 0xc274c69532fe490aL,0x42bcb4e16d8ebd70L,0x69059e1e65d7a1d0L,
        0xf36dfe2f29fdd109L },
      { 0xacfea1ec0c4e6370L,0x97e7f7227a935ff4L,0x83e7c7c3f8006bbdL,
        0x87a8b84d78e6792cL } },
    /* 34 << 35 */
    { { 0x5cbe488394d3d60fL,0x6eba464d91cbc054L,0xf9c880d0021c38faL,
        0x6200faf121af4942L },
      { 0xd5b2b12d5f03e261L,0x1659a0acf3ea3e07L,0x8008f18d836757a8L,
        0xfb2f467b75a8f8e0L } },
    /* 35 << 35 */
    { { 0x9a6183c79c9b00ccL,0x82ca07e33bf842b0L,0xe7089191ee1f83d9L,
        0xc41ecde42d0cd2daL },
      { 0x0ce421b04d1feacdL,0xe80a1395431c53f1L,0xae9b2018e6bfccf5L,
        0xdf9f86ad8b359c3bL } },
    /* 36 << 35 */
    { { 0x9887e28fb6170a5fL,0xf5b85d21f3c0c30cL,0x30861cf8632af7a4L,
        0x2fb670adbb4ec123L },
      { 0x0668b84c3c425976L,0x55c21b4e02883af7L,0x0fad58b5f8698d29L,
        0xef21077068b671c5L } },
    /* 37 << 35 */
    { { 0x534d510a23f232b8L,0xdb66fec149c99708L,0xf1a6f3e76d54721bL,
        0x8d37ab644480f858L },
      { 0x7fcfca6cb0f7f354L,0x58c7ff5f95bfd318L,0x3048e9af903f9d91L,
        0xe480bc0e75357af0L } },
    /* 38 << 35 */
    { { 0x4f915e1ca5a1162eL,0xdd539c2137efa40cL,0x61a45c53789201c2L,
        0x1bc2333de7890746L },
      { 0xeed38f50bbed8f77L,0xc1e93732178501a0L,0xfed5b1d1a8fb8623L,
        0xa3be3e2cdc3e1148L } },
    /* 39 << 35 */
    { { 0x62fc1633a71a390aL,0x4be2868e2891c4c3L,0x6573fe492a0c3c23L,
        0x182d0bd4de1589d0L },
      { 0x17c6a7805a7aa63dL,0x9d84cfa812543191L,0xcdb22db7950c85c9L,
        0xd03589e0119010c4L } },
    /* 40 << 35 */
    { { 0xbcd02e8a8220dee8L,0xbd4d1f2a705632fdL,0x00119bfd22f8e30bL,
        0x06c6e73e6eb97c32L },
      { 0xa26f0a6a35abff53L,0x7d79a89f8564c37dL,0x0347bb171b207495L,
        0x1baf90e9b5c8253aL } },
    /* 41 << 35 */
    { { 0x01059b5f37affc96L,0xbe76c578ffee0a60L,0x45d7291b75d6b83cL,
        0x212ff131e0b58129L },
      { 0x4acc5748aa5d46edL,0x9fc557d99193931bL,0x17568fcfda4eba9bL,
        0x2cf3690ca0edc975L } },
    /* 42 << 35 */
    { { 0x0e8b0e7e953df6fdL,0x38ea7cea62036a87L,0x57e01428655c3685L,
        0xaedfee73c39d8a43L },
      { 0xed7f65985fb27e0aL,0x524c3653946888e0L,0xd84a299be949b72fL,
        0x76c1397ab0c61ea4L } },
    /* 43 << 35 */
    { { 0xfd9f7ed01afe465aL,0x832c69addbbaf852L,0xcd888c2203713338L,
        0x4e1fe026e3306617L },
      { 0xa87adf8623521b97L,0x673d3625f9fbb2a0L,0xf29a14135d8f5b80L,
        0x6e9be0c4d3526501L } },
    /* 44 << 35 */
    { { 0x6129f861e8bfd84dL,0x1df491d677e35a47L,0xefe0e9a9a84a82cbL,
        0x972bc3bc6d949612L },
      { 0x8d7795f53a766ecaL,0x6119383f12fcc6d4L,0xa66d9836c95f0e21L,
        0x77a0aa0a684e434bL } },
    /* 45 << 35 */
    { { 0x3d55d2567dd7b05aL,0xda6162430fed8362L,0x24bd0fe8383e94feL,
        0xbc2b73346bfd0cd2L },
      { 0xf9497232321f7a70L,0x37a4c2f66a3df54fL,0x7ba783bf4ddc49d6L,
        0x4d14231704408c76L } },
    /* 46 << 35 */
    { { 0x7502146b38b99f23L,0x479ab73c21992e8fL,0xf605370ad52c41d3L,
        0x358b746d3a60435fL },
      { 0xb2cbab945bc537b8L,0x1fd24431b99057d3L,0xff2242a0b8510f3cL,
        0x74b4965d0733bc53L } },
    /* 47 << 35 */
    { { 0x30a3a63486edc9b2L,0x99c9cf1949c07c7fL,0x9d8a50c25b0cd506L,
        0x0ed9da5abbcb3d65L },
      { 0x6de1fb5e013f88ecL,0xc9356bff09086f8cL,0xa272e1ac2b8825d7L,
        0x3ad83acbf2c5ba33L } },
    /* 48 << 35 */
    { { 0x721ca22c275bce43L,0xf058b8a7d24f78e8L,0xd178eb57eed46b97L,
        0x4ad7d425259fdb5bL },
      { 0x669ed8531b515fe5L,0x9f14b8e576fa1b5eL,0xfaba8d0c3da46b02L,
        0x759c2c95338f7652L } },
    /* 49 << 35 */
    { { 0x9a369cb0b5c0ceb3L,0xc1d2d1ab28a2a633L,0x676190e3fcb48cd3L,
        0x9af97ab3ee09c3b1L },
      { 0x39323719f7e918f5L,0xc657cb57fd3cd554L,0x78a33d05a2a02d5cL,
        0xda3b79df64ada03fL } },
    /* 50 << 35 */
    { { 0x7115ab5c61b3a72aL,0xdd19f34b337194fcL,0x0f23bfec8f0a14c3L,
        0x1fe19eeca60485d3L },
      { 0x1ca308c3a463dc9bL,0x83e18dd05e1ae8beL,0x849eabdfd928c0e7L,
        0x2d131ff56bd3e7b3L } },
    /* 51 << 35 */
    { { 0xc84cd28445be4c14L,0xdee94092f8f4c719L,0xe8f223ef3cb73831L,
        0x24382f8818c2361eL },
      { 0x205366d0be91c8ddL,0x1e17b50c56024b95L,0x3c3487da742cabd3L,
        0xbe4513878bad494cL } },
    /* 52 << 35 */
    { { 0xfae6c0bf18ffaef0L,0x2e7b0ee385ed1edeL,0x3cebaa05125d1488L,
        0xcd0de0fe7c8b7fb8L },
      { 0x59434d54464bc74aL,0x17472da2a03fd77bL,0xab23d0422c1a9edcL,
        0x5390625ed9cf4b37L } },
    /* 53 << 35 */
    { { 0x43b858440531264eL,0x8d71805eee7aedcaL,0x4ace3068fbe643adL,
        0xc98d1cd25f7d46c1L },
      { 0xd4888744f59b3acdL,0xcf662d6127288b99L,0xf27045615bce2649L,
        0x33a8f3f9206ae654L } },
    /* 54 << 35 */
    { { 0xe834843f9bce2b39L,0x8de8e41da90cfc7dL,0x398800edd81115b4L,
        0x4d33f7c5ff2532daL },
      { 0x5ae37fb2dcc59e2cL,0xca27b62224015306L,0x51beca8911e8d6e6L,
        0x08c0b7e2a9693774L } },
    /* 55 << 35 */
    { { 0x795e1a2172fa713eL,0x5ec1c1234be58266L,0x5d8e87da1be14fc3L,
        0x82cefc1e80283ad5L },
      { 0x820a385bdab7865eL,0x11e32d62f3daf96cL,0xf022ade75835a989L,
        0x2cbc255400242233L } },
    /* 56 << 35 */
    { { 0x653335a0e7ce649cL,0x8b30baef6857eff7L,0x7ea7c856f3288377L,
        0x1387b347e8572f5dL },
      { 0x8a6b0352be10c0cfL,0x2a74e834037c97b9L,0xfe10bf59197b122eL,
        0xd1ee174c1918acedL } },
    /* 57 << 35 */
    { { 0x568e5fb93958c20dL,0x1188cbe60484a92fL,0x00ec14f44b0d29e3L,
        0x2b2e078e16a2796dL },
      { 0x48b8cffa20440444L,0xd4b877a0661ab68dL,0x1f352ab1c4b459faL,
        0x33accbe6c53aa54cL } },
    /* 58 << 35 */
    { { 0xce4ff56602bb383bL,0xcad561c6fd62813dL,0x0927c34801dfc9a8L,
        0x0dde73fb00fb9a61L },
      { 0xd859809ffce59f34L,0x225bd9b681872a46L,0x2642add20314bb90L,
        0x82dc79580ae61eb8L } },
    /* 59 << 35 */
    { { 0x84c9747822d5b667L,0xb2fe94d16214f46dL,0x834740f212cb20deL,
        0x336dc7a78aa69c94L },
      { 0x8ca085a4939a33e6L,0xd59c9ae975a94543L,0x83c97f983c47dd07L,
        0x0985f73ee3177231L } },
    /* 60 << 35 */
    { { 0xe556c3fcebbc623dL,0x30a3242fb1b968faL,0x842ce9b0bcd05a51L,
        0x241a35ed0ad576ceL },
      { 0x49ccaf3cbb4a793eL,0x6e6c7a7b4492a828L,0x72f4f5fcba53eb42L,
        0x0ca4ba533ea74dabL } },
    /* 61 << 35 */
    { { 0xe7b5fb06bbaf9d5fL,0xd49c2e17b02d3b20L,0x4d31052a2d933cc8L,
        0x5346e0b407299aecL },
      { 0x952a620579aa99ecL,0xaab9bc32ecb34e97L,0xd539d7e458ffe9aeL,
        0x915993939d994472L } },
    /* 62 << 35 */
    { { 0x6b1d4868e8822711L,0x8857e28273d452b8L,0xad59adfdf08ed046L,
        0xdb755d65c1c47abeL },
      { 0x2df8520b63275d49L,0xc3c712ec7f8a3249L,0x55f2a1085215ef57L,
        0x955e07a33ee2f149L } },
    /* 63 << 35 */
    { { 0x2194ff5333f344f4L,0xb455b9febad16820L,0xfe69ea78610b4e4cL,
        0x2957be968ab11fe8L },
      { 0x3efdee3c2ce14366L,0x42043f9f01eddf9fL,0xfb7998b193524f6cL,
        0x95ea64c0dfecf763L } },
    /* 64 << 35 */
    { { 0xb23d262021afa86fL,0xea757f0386b11457L,0x0bc4d2d1b0148d30L,
        0x119b553588ce4170L },
      { 0xaab5bb670aa9c8f6L,0xdfc9693c88e05de2L,0x6cae7e57e3f1e9c3L,
        0x2b1ceb546f6c3b9cL } },
    /* 0 << 42 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 42 */
    { { 0x12e335ca87636183L,0x1461a65a719d1ca3L,0x8150080ab14161d8L,
        0x08da4ebfc612e112L },
      { 0xc95dfb6ba8498a9aL,0x099cf91dba0f8dbaL,0x12d2ae144fb4f497L,
        0xfa3a28b033cb7306L } },
    /* 2 << 42 */
    { { 0xc89fc5d00f01c7ceL,0x6fc45ffd7283bdf0L,0x71dece8181151923L,
        0xed1cb14cc433fcc9L },
      { 0x4279612bd3959bcfL,0xe163880b35b5732fL,0x35414ca771d0a1caL,
        0xe8b9e6512c1e47f3L } },
    /* 3 << 42 */
    { { 0x4ff11b0cc8df0a74L,0x346ba520e095ea9aL,0x81dd2268cc2bc6c0L,
        0x2fb2e99fc2701468L },
      { 0x0d21336198053f0eL,0xe0b8280df7ae879aL,0xd92b7a75952560f7L,
        0x8d17dfad9723b62eL } },
    /* 4 << 42 */
    { { 0x5ce8a78a08b21362L,0xf37f5e7fd9fe0b36L,0xdca66c7f2c87837cL,
        0x92524b940bf2e993L },
      { 0xfc0f020c71745788L,0x6018de463cbfbf4cL,0xa8446691ac3de1c8L,
        0xb194d4195de5ae41L } },
    /* 5 << 42 */
    { { 0x1586cdff2ff27af2L,0xee628535de26b5efL,0x58480040c682923eL,
        0x4dd4596b5e37da30L },
      { 0x247b9fd72f64225fL,0xdcc6de5f51ca2121L,0x99fb41ac86e7ab9aL,
        0x54c782a0952b413aL } },
    /* 6 << 42 */
    { { 0x7641190e7298c7d9L,0x499c35ed716eda14L,0x316134bfbb764e90L,
        0x4d23467e884fc34eL },
      { 0xfd1208a9f1d13484L,0x089d9605cd298a74L,0xb398c85a73c4346aL,
        0x50064076f37f13deL } },
    /* 7 << 42 */
    { { 0xfe10d25aa6ebb83dL,0xc5e3edf8a834b30dL,0x546b5d5c683e09ffL,
        0x02f96218c6dc44c6L },
      { 0x64528c55c0edfc04L,0xb5a44a2cb0fc3058L,0x9f09b116ceeff21cL,
        0x077bcd676b0fbbcdL } },
    /* 8 << 42 */
    { { 0x29aaa4a89ce76a94L,0x847cd081c0725c97L,0x0c099e9097e16665L,
        0xe409ffc98f7b1fc4L },
      { 0xc0575b80690941edL,0x8e25100a92c0ee9dL,0x71662d279b75837dL,
        0x6eeb9e97e56bb22bL } },
    /* 9 << 42 */
    { { 0xf1d6333f85c6a60bL,0x982fee9d1d7ccfaaL,0x1c5e28e7d4634535L,
        0xa76e1d2794fec469L },
      { 0x1fe944d6afe377ecL,0xbd579a252f68ae6bL,0x10eabb93ab6b515eL,
        0xa17b5f6c31b4e4b8L } },
    /* 10 << 42 */
    { { 0x05e785fbaf72c239L,0x597e20168af42e92L,0x663f5a72b32ae6c9L,
        0x3040ff1345541cc6L },
      { 0x6140081fdeca6b32L,0xcdaccaf7c735001bL,0x62de5066daef0e68L,
        0x056e9021d837df99L } },
    /* 11 << 42 */
    { { 0xba39928316cd1be7L,0x2a486323cfacf7adL,0x00c15730277777ceL,
        0x5d2f200fd49a254cL },
      { 0xf38a1f3bdb68078dL,0x595dea3f33604a36L,0x14749d8c904b60b2L,
        0xe70c96d8246348ffL } },
    /* 12 << 42 */
    { { 0x04340d52390e35daL,0xc098e3d327a9947cL,0xe6d781989ecc7a3fL,
        0x2c39102e23aa6df6L },
      { 0xb83fed0d300f3cb1L,0xc0b1e356dcfbe054L,0x3da2224c20cf45a8L,
        0x5be55df72f30dedaL } },
    /* 13 << 42 */
    { { 0x4d31c29d2faa9530L,0x1d5783ae49d42f79L,0xe588c224f618b3f3L,
        0x7d8a6f90f8f5b65dL },
      { 0xa802a3d262d09174L,0x4f1a93d9bddd1cb7L,0xe08e1d3c35a5c1dcL,
        0x856b2323f9d2958eL } },
    /* 14 << 42 */
    { { 0xefd1e3ba96f00090L,0xd489943f3e0d25deL,0x082c40ae30c8626fL,
        0xf6e5b5efa4f428e0L },
      { 0x660414a338a7f623L,0xcd4e68de23eefed8L,0x6dcadc62fc14e750L,
        0xcb78b3bcbeae89b6L } },
    /* 15 << 42 */
    { { 0x445acc561d5e580eL,0xbf6547efc43abe19L,0xd160a81bc922d50fL,
        0x3877c7f8f68eed4eL },
      { 0x395745eaf8a9f64aL,0x9085b253603350f6L,0x2a4c71f18b1df366L,
        0x49b9e818abe332dcL } },
    /* 16 << 42 */
    { { 0xb3e76e66528960b1L,0x445dc393d84aecb3L,0x136184361612ad64L,
        0x3ccbeccc8c831e37L },
      { 0x0fb0bd416121383cL,0x316164a380d895a3L,0xc3d34153233f2f1eL,
        0x2905906fe0d92225L } },
    /* 17 << 42 */
    { { 0xe12d66e295456622L,0x10469942ff554b13L,0xa894af86f7126c09L,
        0x448f3267f581d3f5L },
      { 0xb5512926a2b5e758L,0x08f0298843fddd90L,0x5f4370358ba319e6L,
        0xd254188e865b37e7L } },
    /* 18 << 42 */
    { { 0x5b281b238a5cb63aL,0xa15a27126dd136c2L,0x00fab229169beae4L,
        0x400d3f37de31b4a1L },
      { 0x275877a4f8545cb0L,0xb396a51336df0277L,0xf9896978838ced07L,
        0x86e68167715cea8dL } },
    /* 19 << 42 */
    { { 0x0eb0f0de06a5a96dL,0x2c7a36721fcf91aeL,0x287bf614630eca3aL,
        0x65347473f60c9d2dL },
      { 0xed15a229906efa7fL,0xe7be6381d549b5b3L,0x23f329722ce9141bL,
        0x9618d9a1fcf823f8L } },
    /* 20 << 42 */
    { { 0x3d0ef0d3a3d89e15L,0x4d5a30c90d07f5ebL,0xc359e31073e4887aL,
        0x2f4c6b7edbdec349L },
      { 0xc5a1d3e9ba142643L,0x8f4fd58e11c794b6L,0xcad091d11810c63dL,
        0x5b616239f0bfa76cL } },
    /* 21 << 42 */
    { { 0xe3433562a838792aL,0x4aead02b54148e98L,0x809f2bafdb66f216L,
        0x09cc90ffeabfe5daL },
      { 0x69eb235a63e8edadL,0x64f7acb5a7f95997L,0xe999ea18fae20f25L,
        0xcd7ff2083c4966b3L } },
    /* 22 << 42 */
    { { 0x595e0cc0345c8929L,0xfe43c73cde5e2498L,0x0cdefc98503f216dL,
        0x8e4e170df98826fbL },
      { 0x1492247db6c79b1cL,0xf8e24b38ef0532aaL,0x9f349d51044bc458L,
        0x2ef04ead1002d315L } },
    /* 23 << 42 */
    { { 0xaf322f23da60d581L,0x07deaa880681173fL,0x86b97444a78feca0L,
        0x64d336eac633a54dL },
      { 0x10dd4b1f2a426cbfL,0x08d97c157af59869L,0xb8cc814b2d7fe97eL,
        0x7eacd2e13bfb60feL } },
    /* 24 << 42 */
    { { 0x967dafb7b790881cL,0x2002b8e43663e76cL,0x3bd28edef8e82490L,
        0x44dd2e814bb2a47aL },
      { 0xde750dfedbc3f2f8L,0xd9b6e9126e2eec70L,0xe8400e2f1e4c4d2fL,
        0xd332569723217be2L } },
    /* 25 << 42 */
    { { 0x030b7e39d4231a1dL,0x1f72e8b1613d17d8L,0xcd42351201857d37L,
        0x9ecd682c0b4b7926L },
      { 0xfe4ac1c38ec44636L,0x4a030cbf9aacc091L,0x12bb252e0b133f54L,
        0xbf90ea5df970d266L } },
    /* 26 << 42 */
    { { 0xe00d25f7f5484410L,0xb4984eeb2a922894L,0x498102fd8e1e09ceL,
        0x8f8c9fcbe1d731bfL },
      { 0xdb8976690b4983b7L,0x7a7767f97b2468f5L,0x1a2f9fe872f4d5f4L,
        0x10e95aa9a6169daaL } },
    /* 27 << 42 */
    { { 0x9487e50f520166e9L,0x6f6b115bc4ee6a95L,0xaf29926fcf7560f8L,
        0x20a324581f989e46L },
      { 0x165a2232d3bd2473L,0x93d841ffe9fecdf8L,0x71d63fa7bf9978c0L,
        0x381bcf34e7de184bL } },
    /* 28 << 42 */
    { { 0x317c8e40347dfaefL,0x795b0f7d64464bf3L,0x15dc99d61364ec20L,
        0xc07fce2891600d3fL },
      { 0x9825338bc8bebbdaL,0x5e5e89f6a8547c03L,0x3c50032f1a040b84L,
        0xcea7544f2b3a533dL } },
    /* 29 << 42 */
    { { 0xea26d87d43247e19L,0x7e753390fba8368eL,0xb35e75cb3c7bcfc6L,
        0xf78cb5ce7e44aab3L },
      { 0x4a3534e9a98d7104L,0x2b83ea6c6f5852eaL,0x11337fff68dced7cL,
        0xcca0f2c6d1a2a294L } },
    /* 30 << 42 */
    { { 0xb547c662426bf202L,0xec50423e66194a34L,0x11d3486578161e84L,
        0x83508c0664f04decL },
      { 0xd1c72976f7732345L,0xd624bacd18e77e0aL,0x71344b75ba79bdd9L,
        0xe4bfe0858d6c1474L } },
    /* 31 << 42 */
    { { 0x505e8fd9cc5eb43aL,0x612ab1d0daaf0621L,0xde170783e6672368L,
        0xfee7df4483788673L },
      { 0x364d6885d119271dL,0xdd70bae8e1b0cea2L,0xb4b873ad5832adbaL,
        0xad3ecc188c683749L } },
    /* 32 << 42 */
    { { 0x963d87934d217a2eL,0x099e8c561fa4702dL,0x6d91bc47e6431f1bL,
        0x3fd21287a5f61399L },
      { 0x2fc90bae682fa08bL,0x51699c85c1ca371cL,0x16f29d74831c428fL,
        0x0ecefb669fa2b504L } },
    /* 33 << 42 */
    { { 0xd04ac53fa75c5a91L,0xcbe624213bf0524bL,0x91dcb3ceb8792826L,
        0x28a6bf887885092aL },
      { 0x24798e5964c1e218L,0x18e848dc3fec97dcL,0x935e0f509da457b7L,
        0x46b67ab7b8f497a6L } },
    /* 34 << 42 */
    { { 0x15a381407651e4ffL,0x6ba6c6174890cd7fL,0xa527b8d25fe253caL,
        0x945277b8ff3d603bL },
      { 0x1079615575392f01L,0xcac8f7132bd9619dL,0x71a87ecadebb8e28L,
        0xe8e6179e52ab1792L } },
    /* 35 << 42 */
    { { 0x4ce3998be33705e7L,0xf9a0661a48ba56e4L,0x47f06b30d9e4e184L,
        0xda465f75f9f8f6dfL },
      { 0xb05acbbec0ad3e20L,0xec8776a492bc2c13L,0xbb3971b7240a908bL,
        0x80a14367bbd0ceccL } },
    /* 36 << 42 */
    { { 0x40911e50086949bcL,0x39b3ab694064a19dL,0x538c6d966b07eaa7L,
        0x38c05b47d3723bdeL },
      { 0x1e669308080d2a64L,0x6b44dbe52a77601fL,0x35579681e7c6ce9aL,
        0xd2950b0ea16afa75L } },
    /* 37 << 42 */
    { { 0xd228a3baeaf7fafcL,0x9324e71dee878f00L,0xa853bfc1e413c1ceL,
        0xfe916368dcf17d1cL },
      { 0x8611383a2546154bL,0xdbdf225de715b375L,0x874d70a68dbb0651L,
        0x84e588959ed56391L } },
    /* 38 << 42 */
    { { 0xca83d8ad3776503cL,0x2cf38b4e46e82d65L,0x65af46e6adf3a8d1L,
        0x4f09a4ab1d31056dL },
      { 0xdba27b42cacc81d5L,0xb6caa0ca5d6e1bddL,0x1086e441f7198b26L,
        0x15dfe6cbac572f9bL } },
    /* 39 << 42 */
    { { 0xd9444337d2051dd5L,0x6c34b236834cd72dL,0x8478321658df3f28L,
        0x59b8808e2e921372L },
      { 0x3b26824955835302L,0x3299cbe09f4863f1L,0x616e3cdd4c4e213aL,
        0xa3c848688c824317L } },
    /* 40 << 42 */
    { { 0x884be61c460ed764L,0x388df47bb6041177L,0x2708976360b29b0bL,
        0xd66d7d53e502ba08L },
      { 0xadec85ca5acbfaf4L,0xfbacf9b7470c9519L,0x5d18b7f6dbcda5b2L,
        0x7615c0360f228ed5L } },
    /* 41 << 42 */
    { { 0xdfcd8273d6000825L,0xdacfcf119d440eb3L,0xa82578347738fa46L,
        0x7db548af76281df3L },
      { 0x71dd19f63e0b052cL,0x811feef2d876613fL,0x7536e854f9c3155cL,
        0x3e5949734c8c1220L } },
    /* 42 << 42 */
    { { 0xf8c5c72d069b4228L,0xc077d3941f2f6b02L,0x0032dfb976393a52L,
        0x5e52c880706c3572L },
      { 0x4a9d6e9de003750fL,0x3d54814d6147cee7L,0x09ed7f7723b655faL,
        0x14fff651f1988361L } },
    /* 43 << 42 */
    { { 0x742f3abdfb263d48L,0xedb557dc53699a0cL,0xc692a4747ecd0f61L,
        0xdc64f583058f0d17L },
      { 0x68a9ce753227d3edL,0xfd0b03204601d083L,0x7167b3309c2cee38L,
        0xef658993710e350dL } },
    /* 44 << 42 */
    { { 0x75a83be116910648L,0x5b32e77d2e7d446cL,0x8e0534e5a86ba2deL,
        0xc8a92eacb692aeeeL },
      { 0x3cf686ebf663150fL,0x840eaade01962bafL,0x3e06154fa264d877L,
        0xbbd0413724630300L } },
    /* 45 << 42 */
    { { 0x0b0151bd58631468L,0x570ef82c9f99bbe5L,0x03565f47b30f7b96L,
        0x000628e098c04b24L },
      { 0xd34a90aed6ccdb2bL,0x1a584858a99a761cL,0xa640ddca65e29f1bL,
        0xffb672f9728d3208L } },
    /* 46 << 42 */
    { { 0x550f63925433abd8L,0x4f35e11613ff0107L,0xbb2b0fabe731a37bL,
        0x1e8a5a08c83d6e74L },
      { 0xf617e177c6565e23L,0x8e370e5a76da0795L,0xa5631e0203936a55L,
        0xe576bee9d41293adL } },
    /* 47 << 42 */
    { { 0xfcfd9bc75381bc98L,0x8a42ddfd000a98abL,0xd6091ca6b49463c4L,
        0xf37f6b9f9754ce07L },
      { 0xe1543897fa399fdaL,0x7b029ead8810063cL,0xa98a46bdec5a5b52L,
        0xdd162811d50cc504L } },
    /* 48 << 42 */
    { { 0x4d725c1d67a95e56L,0xc36d6e8b8e17af44L,0x38ffb699313454c1L,
        0x22c3da8c991e4eaaL },
      { 0xfa36ee150bb72dc0L,0x356bbf744fd01d32L,0x9ff71a303c7939a3L,
        0xa0ad2fb5691786e9L } },
    /* 49 << 42 */
    { { 0x7d7f4770283c34c1L,0x0148a4f02454a31cL,0xdcbb138aeab3b646L,
        0x7834bdb9f101223eL },
      { 0x49de6cc3965baa81L,0x5462f15e15471215L,0xd77e7a5681d17760L,
        0xa08c5ad953f00de3L } },
    /* 50 << 42 */
    { { 0x2e6e6686397ed010L,0xe444a5a92bef28cbL,0x1ab9d6164073cbe4L,
        0x24c6b9e018f0b7ddL },
      { 0x456482b6c2a93055L,0x0f89129fefbe8715L,0xb50818c362e5f6f2L,
        0x1d74a1ca3d63c663L } },
    /* 51 << 42 */
    { { 0x9a9124eed84bfa55L,0x6cf81f41254b3f04L,0x7c9b7c3ea1051109L,
        0x71c3d6d6640e8df2L },
      { 0x5657115762f6af2fL,0x2ec61a3fe1bc9ae8L,0x20caa2ff2fcc848bL,
        0x71e30dacdc5c297eL } },
    /* 52 << 42 */
    { { 0x11901efcfbc0740aL,0x4994fc5fb6e35fcaL,0x4dc09eba177de7ddL,
        0xedfdd25c0494bebfL },
      { 0xc4821ed90cbaeb8bL,0xa9ef7a4866788fbdL,0x5b7a7ca5d65efbc2L,
        0xe18feb42a9cb1fc6L } },
    /* 53 << 42 */
    { { 0x2cc74b9c56b00ab5L,0xf559a140db4bf3f4L,0x283136d4b8a4b54eL,
        0xe969e4f837032aa2L },
      { 0x5635fb66d85beed3L,0x32bc4fdda72a54bbL,0xc1e5ee2b4c386a49L,
        0x979fd877795a0b08L } },
    /* 54 << 42 */
    { { 0x5acef24d431f0b8eL,0x9f1c4a80d13cafefL,0xf19ac70b4659f447L,
        0x82bab6b610f561aeL },
      { 0x1268e7f3bbc879a7L,0x7e7d714179c37165L,0x491f049d597e313fL,
        0x6ca7e73eecc98736L } },
    /* 55 << 42 */
    { { 0xd7712aa480a31eb9L,0xbf7376ca2d8b99d7L,0xc1166cdc2b8e5f7bL,
        0x562bf290f1a48c9bL },
      { 0xa6e7223831c38c75L,0x51a9a100b5f42defL,0xa0931d81a100b75fL,
        0x7022479d967830beL } },
    /* 56 << 42 */
    { { 0x53eaaa1fc192bc29L,0x09504e7a4123a9f2L,0xe897397f90671997L,
        0xc56185d24294fda2L },
      { 0xb531f2789819b185L,0x390155ffe9dda4ccL,0x1258a5d914d26bf9L,
        0x47d8f5ae7e5f13a1L } },
    /* 57 << 42 */
    { { 0xef9e05e3e9591945L,0x92d20e07846441beL,0x28cc70ef1d897ad1L,
        0xee962e740bac861fL },
      { 0x9b7a4236bed368e4L,0xe65ac22ae49b9720L,0x851f003222c1bd82L,
        0x771573ec1e75ab15L } },
    /* 58 << 42 */
    { { 0x2e0a4635702eb71aL,0x65167c74ee924cd9L,0xe16b351510ccabb5L,
        0x63cf15c410ea5907L },
      { 0x59dacdc6616f5290L,0x19eb409b8e372a43L,0x5c879337e3c36bebL,
        0x5841e7e20555fa1eL } },
    /* 59 << 42 */
    { { 0xce197347f346ec2dL,0xe14818a8221db43dL,0x1bf37115c935c025L,
        0xb22bdb03fee14ce0L },
      { 0x893c5efaf0e3dfd6L,0x8fe9d56cb1f95e1eL,0x6ee580e5407e4db0L,
        0x0292bfc49fb33911L } },
    /* 60 << 42 */
    { { 0x598ce787b2869cacL,0xd2f777204798690aL,0x2689e0f39cb6015aL,
        0x8831ddeb7127b0e8L },
      { 0x44db087b5c4fd58cL,0x04a0c68ecda33285L,0xe55f00d7e1a4c364L,
        0xb3a2ea9ab6393b21L } },
    /* 61 << 42 */
    { { 0x99ef4da35e9d8db9L,0xa01f11d917b484bcL,0xc2283fbf1767f6caL,
        0xbb5244799e77f389L },
      { 0xc4ea3c6610149726L,0x4b71d64482ec5f64L,0x0fe49d52642944c7L,
        0x69fef6895a17a7bdL } },
    /* 62 << 42 */
    { { 0x2f3588fc8c3dce23L,0x9d42923168e0c237L,0x6375607686fa61d2L,
        0x1d89c6b8729bc192L },
      { 0x85e098d200d3ffd1L,0x5bf292c2de6f9109L,0xb20dc9943e7b8f23L,
        0xcbe51bad87c6eb54L } },
    /* 63 << 42 */
    { { 0x263fd8620517b914L,0x447624ad225499a7L,0xfbb831bb71f807d9L,
        0x9514fe382fe2e021L },
      { 0x881e876352418e9aL,0x268e4655f1d9b43bL,0xf917044a1f780af9L,
        0x3727b2d93d758ba5L } },
    /* 64 << 42 */
    { { 0x8487eb9068755cf3L,0x1887394e7fe12541L,0x2e4c65d446af8ca8L,
        0x72aae645b9e119dcL },
      { 0x958e00941ec6ad73L,0x84a7eec48ce4573eL,0x3d6d00d4f9254b96L,
        0x4ef44f588e421732L } },
    /* 0 << 49 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 49 */
    { { 0xf59de0f87d3ad2acL,0xd2670cb1c0f92c5cL,0x8f05944ac900b6a5L,
        0x11aeed238d9668ebL },
      { 0x21b038e47c488ea6L,0x406ea3f778083d75L,0xd22197b43bd31fe2L,
        0xdc8f8ccb28a6ef9aL } },
    /* 2 << 49 */
    { { 0x679a648302887281L,0x13f3d39b7f9de66fL,0x289c3c50f1a7dee2L,
        0xa510a53c40b698b8L },
      { 0xc566c3fb06f799adL,0xcc95a879b5374650L,0xbd7343c061c947b2L,
        0xbbbff69d9543e51bL } },
    /* 3 << 49 */
    { { 0xb80d38dcba75aba9L,0xe9b61ac6d150f881L,0x9f56af52ca7b47c5L,
        0x040300d977fb3128L },
      { 0x36877184c01fd0c1L,0x40112a048b6e134bL,0x56daed90ccd71653L,
        0xec553aa6b74bd62eL } },
    /* 4 << 49 */
    { { 0x0398381d11476ddeL,0x4959204d1ea0923fL,0xd67427ad017745bdL,
        0xef022a746935e467L },
      { 0x57e799f524e0380aL,0x6ee2b64fb5f1a730L,0x9aeaac48521771d8L,
        0x02c8521c0992a13cL } },
    /* 5 << 49 */
    { { 0x25dd9f4148f6934aL,0x8d1919883e38e31fL,0x3554884432899837L,
        0xf87c696bf56b07d6L },
      { 0xbc66e7d773e927b9L,0x04cdac77bb0bedc5L,0x1e6f29030bcd022aL,
        0xafa637be22c574b5L } },
    /* 6 << 49 */
    { { 0xcdca4b1e55c1759bL,0x3d46ee3ba6819d39L,0xf7497adeb4b0fce9L,
        0x54aef506dcb613c3L },
      { 0xbc11d721522ff464L,0xf53f16f237bd3c51L,0x88f29955485695b9L,
        0x428ce742dac00fe3L } },
    /* 7 << 49 */
    { { 0xd971fbd2a3520c27L,0x2204fe54e05e1b9dL,0xb08be507f0c15c89L,
        0xfeeda919901a15c3L },
      { 0x6576ad3b84b60eb5L,0x40d4b9a159e951daL,0xbe96e1b876244608L,
        0x3af35ec958ef9f37L } },
    /* 8 << 49 */
    { { 0xbfe5c43b153adbf7L,0x07a66edf80351fecL,0x3d8042353b109e60L,
        0x4dc97176a832c162L },
      { 0x03fec75fb1db1e5cL,0x6aa02da6a15b9900L,0x5f9e808f4faa1cffL,
        0x90aa28bda6412a26L } },
    /* 9 << 49 */
    { { 0x2fb2c15be041d453L,0x2b847efa86c18ef0L,0x84f5ee9d115b7318L,
        0xd568b08071699936L },
      { 0x34658ae76ea5c852L,0x99f918b3126d10ceL,0x75e3d9cc09b9407fL,
        0x11c6a0bb7883f978L } },
    /* 10 << 49 */
    { { 0x522a6925876db0fdL,0xc5401ca17a9a4211L,0x89163b576789e755L,
        0xd2b2c99a0fd6f1b8L },
      { 0x427eea22a7b452dcL,0xce8e6682ef9db65cL,0xfd835810da9c80f7L,
        0xdb91bfbbea916411L } },
    /* 11 << 49 */
    { { 0x7a5aefad798b5051L,0xbd7ebc8842a0d4cdL,0x958e327abac28520L,
        0xfa8bf6d47d010c77L },
      { 0x8a7040aa579752f4L,0x47974d84e573d895L,0xfd2a0cdcfe16f77bL,
        0x0f08f86adbf71fdcL } },
    /* 12 << 49 */
    { { 0xb19de6f12983bd4dL,0xb990931e1e3a28b3L,0x43b71b8b00cbc4f9L,
        0x35d1ddd0f4d75a0eL },
      { 0xc211951dc653f111L,0xbbc4682488750928L,0x0cf6e752174803e3L,
        0x81f5e0ac8960d80cL } },
    /* 13 << 49 */
    { { 0xe03ca0850c52fcf9L,0xa795382e0865ced4L,0x03bd561ce7117376L,
        0x8608dde13fd7184aL },
      { 0xfd48fd50a2a98accL,0x902fa58711df74b0L,0x683f101dfa73b8f1L,
        0xc805d31be7c0efa6L } },
    /* 14 << 49 */
    { { 0xe5effb4e5b11d6c0L,0xba30f74701c8374cL,0x8733511b0c275aecL,
        0xf140b74097354e36L },
      { 0xb01ded690341268eL,0x17bc317627eac17bL,0x880977038984992cL,
        0x37bfafab3e05061cL } },
    /* 15 << 49 */
    { { 0x7eca9f09111d0eb8L,0xda7eb0238f243481L,0xac3cb2d659b5e491L,
        0x56e725b14f794842L },
      { 0x4324525445b2dff6L,0xeafe73b9ef10ec78L,0x0d3cb2bc78819dbfL,
        0xff1cd617e784eb22L } },
    /* 16 << 49 */
    { { 0x0dbaf1c99ce0fcd6L,0x732ea65e3232a847L,0xdb2ce2186a75d822L,
        0x88ffd4793d2273caL },
      { 0x89092ad2f2f26b61L,0xfb7041bd686706abL,0xe3d5fa755e23597cL,
        0xa2035bf85995fc84L } },
    /* 17 << 49 */
    { { 0x1feecd2c4514b8bdL,0x57cb78b4434b9233L,0x59bd2ad724215322L,
        0x41437de21ce8daa0L },
      { 0x401bbece7147ce80L,0x5e4621375abb61e8L,0xbbf210335a3790ebL,
        0x9a791c095134dee3L } },
    /* 18 << 49 */
    { { 0xc8ded766cedd2cc1L,0xa3e48e9d6447b925L,0xc73282a369efa728L,
        0x8cb72c308d408becL },
      { 0xfb4f279741cf92ebL,0xef3f42a026f2412eL,0xdbc0f972a941ab5aL,
        0xc7bd62dd98337613L } },
    /* 19 << 49 */
    { { 0x318927444e45dcbdL,0x3b2979cbb51b7f91L,0x41e002f529b27fecL,
        0x9007ee684dd51b0fL },
      { 0x82f417a36e23d565L,0x3321f34377127820L,0x8d09d965199b32beL,
        0x948429eb5bc2017bL } },
    /* 20 << 49 */
    { { 0x22b639f9124eb248L,0xed097f74125f8c22L,0xdbc025175f8bed34L,
        0xb93f5b4251aa29c3L },
      { 0x6fedd599c7368c44L,0x99a5a7952c772a9aL,0x30b35ba77a5f156eL,
        0x9dc50978191c45afL } },
    /* 21 << 49 */
    { { 0xe8d241f5b5b4c4feL,0xda89eac1b75f54f8L,0xb399dba09ef86ae5L,
        0x2337bb4651c1b8c6L },
      { 0xfe60b0c54d02f348L,0x709f12350afc6cd0L,0x8a0b458bb40fce18L,
        0xefe143aae3929cfaL } },
    /* 22 << 49 */
    { { 0xab3a4b0d0ca6cec0L,0xcb23537467246ec3L,0xdf9b0e891ec2538fL,
        0x3ec2ea1380c7b53dL },
      { 0x920c55f2d0ae3146L,0xd3ac4e1e43946090L,0xeba7258397ebe7a4L,
        0x5031644a393d401fL } },
    /* 23 << 49 */
    { { 0x802c34099714de1aL,0xc62d66d0de5bacbaL,0xb6c2abeb903b8148L,
        0x203531ef5bffe1c4L },
      { 0x186266dee862ead7L,0x21e643d51a23bebbL,0x15c13d116edda603L,
        0x39b4a3a3b1bebc77L } },
    /* 24 << 49 */
    { { 0xdb456c1ab9ac4754L,0xf497e6e94d3f305aL,0x84d27e3a3fa62dc0L,
        0xc18c35692524b94fL },
      { 0x92198954e380f5cbL,0x81d8221c272ea458L,0x6fa082f65f328491L,
        0x810ca5af8e304ccfL } },
    /* 25 << 49 */
    { { 0xda9f1c150d76e6d5L,0x4bd38afcb7abad72L,0x14b5cc2608aa20f5L,
        0x010a1af881061318L },
      { 0xaf9d7a7303c287c0L,0x9ba5105abc4d40abL,0x99e4b824b07937a6L,
        0x026d294cc869f63cL } },
    /* 26 << 49 */
    { { 0xaaebde75c910b521L,0xc803ded4a7d5dd9cL,0xc8b713b062764be2L,
        0x5ea9ea2b92540cf3L },
      { 0xbaa999c66930bd0eL,0x57052e531f4b254cL,0xfb9fd6992b0b27eeL,
        0x86b709324cc83793L } },
    /* 27 << 49 */
    { { 0x09ab4dd7fba59bbeL,0x83204fee04f4609eL,0x251cb39093934977L,
        0x8add9e8b647c13e8L },
      { 0x444815d3e7ea7006L,0x22333c0abd032c32L,0xe7728dc84058b7cbL,
        0xde8eb503d1bc061fL } },
    /* 28 << 49 */
    { { 0x5d3ece2e493d76c2L,0xa425f3aed804954aL,0x49100271eac95eb8L,
        0x94e4dfa038b4be56L },
      { 0xa855893f650f9930L,0x1fa0a07d50264765L,0x37a3c1690d1d40beL,
        0xfedb51e42eed2a0dL } },
    /* 29 << 49 */
    { { 0xa6e0c2b21b3348b4L,0x9e361f42c414464eL,0x3e14e2ee176e109aL,
        0x5f1a6bbef4af92fdL },
      { 0xf15d464784beb8e5L,0xac3f01c197d36132L,0x36e669bf84ca42aeL,
        0xf789bdbdd9433ca1L } },
    /* 30 << 49 */
    { { 0x384f37f4f71e84d4L,0x57de947359d6481aL,0xa9a81f99f5e6fa70L,
        0x26f0a64f6cb57bf3L },
      { 0xc07e1c13061d38feL,0x6fae70e94a475732L,0x6cfb6b1d840e595cL,
        0xb23cf1f262848351L } },
    /* 31 << 49 */
    { { 0xef6094c74fcf8743L,0x7dc4221805fab119L,0x3207463f5c220d15L,
        0xdf51b3f022c4bfb2L },
      { 0x13db445b1572735bL,0xd76625372f6db574L,0x692f1e057796f888L,
        0x9f3d7a5b33f45593L } },
    /* 32 << 49 */
    { { 0xb5deb892313de667L,0x75c872d766a478a8L,0xb67b5513c4992428L,
        0xf97e010ef70fde09L },
      { 0x49b0f05360ee268cL,0x981b5141f67cd321L,0xb5a1ac8d4fbc187cL,
        0x162417e2c12e6da8L } },
    /* 33 << 49 */
    { { 0x07bb6fff62914938L,0xd385285b19f44438L,0x05a610a1a28904dcL,
        0xd80a70995a29b9f8L },
      { 0x72ccb553c177af4aL,0xac0bd91b5e3752f4L,0x8e8ae6687ae838a0L,
        0xcaa5a46c1fdfe7c3L } },
    /* 34 << 49 */
    { { 0x2cc2c1a593d34156L,0x22beffb161fe4572L,0x66f9f3cefcdc7418L,
        0xbaccda416af66892L },
      { 0x775c783d1af43f56L,0x1b23b1870ae04034L,0x5a9325f4e99b486bL,
        0x36d5bfe98367ab05L } },
    /* 35 << 49 */
    { { 0x17d8d2fba519d028L,0x27b6beb2be00e7e0L,0x8d51c36c15a3f03aL,
        0xbf90e78b5faac8ddL },
      { 0x4e8c28e7b27ab69fL,0x37ecf0c74a553da4L,0x3a39682f210fe720L,
        0x60c62e800b0cdd0cL } },
    /* 36 << 49 */
    { { 0x893aa225a16647cdL,0xcffb728e64ce0455L,0x81891d39c4f0fe79L,
        0x1abe3073f9c39f00L },
      { 0x88336c27f961d05cL,0xc9033a88a5fc96dfL,0x0d084405864b39f8L,
        0x866aa904851e95c9L } },
    /* 37 << 49 */
    { { 0x0c36da0898bae4a8L,0x9f88d799b5feb202L,0xcd9aeb4a8054e4daL,
        0x005206bf1e9134cbL },
      { 0xd5f32bf817ee6649L,0x9431dcd860847ad2L,0xbe6d62c78a3e4050L,
        0x3ae68f7aedf10d40L } },
    /* 38 << 49 */
    { { 0xa95c9ea04604d71fL,0x01aa3fea415f8028L,0x3dd55ca55a41970aL,
        0x05978ad40b5776b4L },
      { 0x7c9f5bdd787fe20cL,0x23b9fb7d75fdba0bL,0xfb1a724d5fcf3a0fL,
        0xd63b351587817071L } },
    /* 39 << 49 */
    { { 0xecae282d44e40138L,0x8732df2387605748L,0x0ef49da0d11188cbL,
        0xc047813851146cc0L },
      { 0x4ba4232346621921L,0x8836dd4447dfa4ebL,0xdb6a01008ec16442L,
        0xabdd9b819cdd2e87L } },
    /* 40 << 49 */
    { { 0x205ee262502e26d1L,0xb961ef9c3294e240L,0x7178f1fb6da7733dL,
        0x989b69fb232ecf73L },
      { 0xb7278a359a9bccaeL,0xb1c81a0b400a01f3L,0x0781855aa6b213baL,
        0x8acc1b783429817eL } },
    /* 41 << 49 */
    { { 0x527e3a9ffb4e1aaeL,0xc18c1cfd4c0b0f4cL,0x0676c3651fa7d9f0L,
        0x3314509f4454cc7cL },
      { 0xb0f45371c7c48245L,0x913fe759695ef470L,0xbb676070c8d3e0adL,
        0x0db98fcc902e1638L } },
    /* 42 << 49 */
    { { 0x42874e9cfc4dfaa8L,0xcbf894627084b2cbL,0xd6d46f778a846ab8L,
        0x9e4506ca14c183b1L },
      { 0xc2d0f9b7c53b7631L,0xe47c3d8f294d6c34L,0x04e3c868c05d3f1cL,
        0xbacec4f3a5957fefL } },
    /* 43 << 49 */
    { { 0x4f4530ba3b77893eL,0x4c234f5469a18bd9L,0xb45aadd85071f5e3L,
        0x73e4160ad1bd0b86L },
      { 0x43fcb30d1c474f64L,0xedef0769617d1612L,0x920767340eec330eL,
        0xd77677705b0a21b5L } },
    /* 44 << 49 */
    { { 0x4b7dea31183e26f4L,0x59d6ff20c9fd2e70L,0x7bdea00fd5d914f5L,
        0xc736dd0d56376640L },
      { 0x593ae6ef38ae8300L,0xdafe49f1df0355bfL,0x094ccd860db4491fL,
        0x32295701fe4271abL } },
    /* 45 << 49 */
    { { 0x2b7690e45db7014eL,0x1bbc9c36d7766bfbL,0xc52249f07d986d0cL,
        0xc7eec37b324f20aeL },
      { 0xd376afa30e912329L,0xbc35e94904268fa3L,0x617bf7659e91a4acL,
        0xb1e932ed1d483eccL } },
    /* 46 << 49 */
    { { 0xd4e31672ac493266L,0x1c779fe2ecdafb85L,0xed09eb4a06280499L,
        0x3dd8d965cd4e1f33L },
      { 0x0fb4308df34576dcL,0xa8ccbf5e85781a43L,0x8dbf488ace623a24L,
        0xb0e71d306118cfd4L } },
    /* 47 << 49 */
    { { 0xfc68da688cc9d957L,0x7e5e6b6583815670L,0x2c16f5ef3f185dfeL,
        0x23a4098b98952b33L },
      { 0x15a80298d515f551L,0x71a2e7fca7f8f341L,0xed42b1b68cf4f7b6L,
        0x02743db21504d390L } },
    /* 48 << 49 */
    { { 0x2bded3a83016e513L,0xa3c508affb0f7bfbL,0xa6a490deaa2be716L,
        0x5a04d9e5f4485b9fL },
      { 0xd07b99d16ad25b5dL,0xa184010965a72cb4L,0xc8e2b32d14c45a95L,
        0x0fae6e86e4f2ecffL } },
    /* 49 << 49 */
    { { 0xd09f454bd94b6fe7L,0xa776a63323006b62L,0x6c700a1cd332b4b9L,
        0x50c3fb34ce016225L },
      { 0x4b805bc38af71463L,0x049143e25f1fb3b7L,0xbcaf4b615a6d1dd3L,
        0x02093dd74733abacL } },
    /* 50 << 49 */
    { { 0x1a23c3f6df59f061L,0x87a6c14180c4efb7L,0x47635ae4d88e4363L,
        0x75e2089fbf8d2072L },
      { 0xa2bc1b27ac83803bL,0x8ae61522e2aafecfL,0x4b459205d0010193L,
        0x900f6a319205f876L } },
    /* 51 << 49 */
    { { 0x49cddbc9f808f044L,0x9463769295094eadL,0x3c9c7c0cb87c9bbfL,
        0x1699670a4e1844d1L },
      { 0xd8a978f2cbcf85c3L,0x83e7b8066a36e1c9L,0x6f28a73ffaff9c52L,
        0x51341222b71eaa80L } },
    /* 52 << 49 */
    { { 0x195461da9328a676L,0xefcc93e521766180L,0xed82c930771a5485L,
        0x34f15ce0205a8bffL },
      { 0x88ab72cbb8b3bfd8L,0xbb59a5be8110fe55L,0x9ce8a082c7d61a31L,
        0xfe81d0725b1c63d2L } },
    /* 53 << 49 */
    { { 0x9fae0be1e9ff8421L,0x4254f89d967e13a6L,0x1c09462035da926fL,
        0x84eda2724a76583dL },
      { 0xa4033064e0e0ffb8L,0x47951945abc72d0cL,0x0af6bb4cb72c32e7L,
        0x6c73357bda797f9eL } },
    /* 54 << 49 */
    { { 0xd7a726c92ac2e99dL,0xf44b4731cd62e7ccL,0xf89f8e29e6225822L,
        0xa44bb9b08d713d92L },
      { 0x3291e8d39404f6c6L,0x50b7a4ff37bdb22dL,0xe008662e216a0f13L,
        0x150fa2d6cf382547L } },
    /* 55 << 49 */
    { { 0xe5e47c553138acbcL,0x595cf1e240d7f3dbL,0x2872392d2ee1949dL,
        0xdbd15bf88a4fb721L },
      { 0x30e78cdc183351dcL,0xa39b8efb6b294729L,0x0df4d23ec7b553e8L,
        0x434f38fa659d3ffcL } },
    /* 56 << 49 */
    { { 0x1764115e55a0c931L,0x34ea18b9a5c920a4L,0x6a099ddcaf903710L,
        0x4b937dc1e49f2c7aL },
      { 0xacfc4a1a430f0a7eL,0x8f106a58421dbe96L,0x48ac70261811d3feL,
        0x5484226ab80f13c5L } },
    /* 57 << 49 */
    { { 0xf692e17b8da7ca79L,0x4827aaa2718691b9L,0x881f1c385c5ea68cL,
        0x1620f5d688bdf643L },
      { 0xe5703cb20b9a5addL,0x392e6ea5be925061L,0x2a66ce20b0bab0d5L,
        0x83a8e0e5f98e8dadL } },
    /* 58 << 49 */
    { { 0x53532223deec2329L,0x6a740238346eea96L,0xa54afbdf1dde2a6aL,
        0x0e6ca8c1f2b5b190L },
      { 0xcccaa3c6f3cd4e46L,0x168d66bd0eb7bb3cL,0xf127514408d4f4e9L,
        0x2ae8c946139811fcL } },
    /* 59 << 49 */
    { { 0x4973c726c870713aL,0x298465eeba54b13fL,0x9f901403940f224fL,
        0x5cd6a07bb9950a40L },
      { 0x9d4095e6069a8484L,0xe6bf3181d4f8831fL,0x37ceb29a39243da8L,
        0xb3887f312693653cL } },
    /* 60 << 49 */
    { { 0x685d217242c98a56L,0x350fbab83969dd9aL,0x728edca9e8ac84ecL,
        0xf42beab359bbb0c4L },
      { 0x9793e74627d3c3fdL,0xbf6016dec732b37eL,0x3688173adf0f248fL,
        0x84fbd0407ed59dfaL } },
    /* 61 << 49 */
    { { 0x2bad638fa6731b1bL,0x1c7b4b13b7355979L,0xf21550e0b8e77093L,
        0x14d0bc9d53efc63cL },
      { 0x119ae9fbd56e1f29L,0x3511309c4d60bc5aL,0xec654f06e3574e43L,
        0x2d6695dfbef6aea2L } },
    /* 62 << 49 */
    { { 0x27ece6115d6abff7L,0xa706d42d640c9ab8L,0x7a7252d95a6f8fa6L,
        0x32be7195349aaf8cL },
      { 0xffb48a3dff734e23L,0xa9b36c827d27b99cL,0x85b7a57e0ccaedbcL,
        0xb93b14fdc04f2394L } },
    /* 63 << 49 */
    { { 0x3a3a78c5160700e0L,0xbd7ae60a961e4af8L,0xe1deb736d9472cd7L,
        0x276b51b73880bbbeL },
      { 0xcf0c4b9a1aa99bfbL,0xaf949d5f689d7f58L,0x0087848865f33328L,
        0x0f1a178ce7d7b484L } },
    /* 64 << 49 */
    { { 0xd44550f8849e6d32L,0xe7bc29d4fe16485eL,0x29bbfec62f343924L,
        0xeeb802f240f2b5ceL },
      { 0x2b337542bbb64f33L,0x4c1d3a369f9bdb3cL,0x1067cf3bc7a1cb88L,
        0x3f12a31d4601fb6eL } },
    /* 0 << 56 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 56 */
    { { 0xb720a78f1f8a4a91L,0x59e22211753dbe73L,0x9f5ad99cadd0991aL,
        0x3a0db8027380726fL },
      { 0x37f0761c7dfb4f1cL,0x68e7098a5ac819cdL,0x9683d61037ffe348L,
        0x5bf205e52b7b5140L } },
    /* 2 << 56 */
    { { 0x9846b5f661a97262L,0xedf2cacb974a82f7L,0x3dfab85faf439654L,
        0x43fb0ef9c724ee09L },
      { 0xd0d5016f53b0119aL,0x684453635bc8fc81L,0x6d10b6491f65d298L,
        0x0f3c88c621a4e64fL } },
    /* 3 << 56 */
    { { 0x320372a17f34c517L,0x5602bd162378bc27L,0x666a592d91aae024L,
        0x716886ab317bbdaaL },
      { 0xce55fe68e3045103L,0xf2c4b0b27de1d701L,0x8da358857d724cb6L,
        0x9aac623c9ec47314L } },
    /* 4 << 56 */
    { { 0x824cff46b8529a01L,0x6e4d82a24856b95cL,0x58c6b833c65af7f7L,
        0x8a6c4125ae110e53L },
      { 0x38207c304f083340L,0x71aa384b176cdb31L,0x1ada294142882de1L,
        0x38b1ad2ec16a2e4aL } },
    /* 5 << 56 */
    { { 0xbdda2720142bcb30L,0x56175263faf604d1L,0x086189c1e6796314L,
        0xdab01c685b04dd19L },
      { 0xce54e4b0ba8ed3c1L,0xf616513be281acfbL,0xaf1796295e0a6319L,
        0x85e79ac9328b587bL } },
    /* 6 << 56 */
    { { 0x11d84588c9fd7da0L,0xa78682d01238d0c4L,0x333ddde0829d6475L,
        0x80c8844069de9e18L },
      { 0x5d15f21ac6d8176fL,0xdaff9434a509d470L,0x0191bb0a8bbbfcd5L,
        0xff7732b808fc2688L } },
    /* 7 << 56 */
    { { 0x02fe772d5ab3d89eL,0xf1580ec99a786c91L,0x8fd834175a323866L,
        0x93711d49badec96fL },
      { 0x2020c34a6b9b4a30L,0xbf10e000b8b0de24L,0x2a5f298d28de3ce5L,
        0x807a398efe1a1c63L } },
    /* 8 << 56 */
    { { 0x9fb640cd73f7c45cL,0xeb1f87ad0afe059cL,0xa3c3979a52b168d4L,
        0x6eef460c7b1e403fL },
      { 0x6d943e502724bb3fL,0x53f3f1bbf9d922d1L,0x547e7a03cd538b4aL,
        0x37631e20d2c4145fL } },
    /* 9 << 56 */
    { { 0xe7e49922b1f810bfL,0xacafdb0ff2645825L,0x0f22216a15f35bdaL,
        0x6f2b4d95d85bd0b7L },
      { 0x2f203db8bedc9ecdL,0x26639ff6b91e090dL,0x94cd65963486eb84L,
        0x32747db342c05747L } },
    /* 10 << 56 */
    { { 0xcd3e7a52cebfa9f1L,0x5e792d76fb2b3007L,0x9669523db9ecce81L,
        0x9263cc8504f191e1L },
      { 0x192019c069655fe1L,0x1c5cc5eb4d984e59L,0x9ad10ed6df33f336L,
        0x0ca4838741d94897L } },
    /* 11 << 56 */
    { { 0xbd1ddf67f222476cL,0xb4ad712612d6dc4dL,0x5c327b1893ed702aL,
        0x7e3a27b1fa70cd9fL },
      { 0xdca750bdc0c4f415L,0x98197c90213a5d61L,0x9bbd014a6f10fcc7L,
        0xb06061e12ceed4fbL } },
    /* 12 << 56 */
    { { 0xaf6dbbe2a8ad25f9L,0xe70e9f407ade697dL,0xb829e0166eb872d7L,
        0xc330e15c1b04173fL },
      { 0xd4868e290d4763d8L,0x37867f724c18c9fbL,0x5fd2f47f28019486L,
        0xe6bfdf81b16e9bddL } },
    /* 13 << 56 */
    { { 0xace2a977783e43c5L,0xe179128876eed46aL,0x3884a5b2d1767739L,
        0x14eddddb427c50a3L },
      { 0xbeeed5ac1c9b1fccL,0x50b1cb444ecdb47aL,0xcbf695550dcb78d5L,
        0xe60bf9c7f2b17a99L } },
    /* 14 << 56 */
    { { 0x0edae6b09e9ade95L,0xb5c6e13dcb78b1e1L,0x32860fba1c257848L,
        0xfc9aa9f4ef7f5080L },
      { 0xccef850832aac870L,0x4b237704fb5310a0L,0x4c3cf970feebb972L,
        0x5dd3c7a0763d5f67L } },
    /* 15 << 56 */
    { { 0xa656797eccbf29c6L,0x6d77f2115a76a56bL,0xc627156b0e3daff3L,
        0xa4bd37f57646fb1cL },
      { 0x5fd7e286a8cd3e5aL,0x3889951a2f5fed51L,0xf8186fc5e48c49beL,
        0x0d3d308ac662ee38L } },
    /* 16 << 56 */
    { { 0xb7c9bf06970e164dL,0xc27a88d8bd3d3087L,0x8a37c9cdf4e7c899L,
        0x18494d5aab411371L },
      { 0x06532375d9d8b29cL,0xb92dd45c915a2f74L,0x8a23f6bf515acb02L,
        0x0e69248c435bfa89L } },
    /* 17 << 56 */
    { { 0x8bf41ec36866c5e4L,0xf059e6520999159dL,0xf906838fd29d7cd8L,
        0xc30100f63a269735L },
      { 0xb7742bc86280e70bL,0x0067d971867b54e1L,0xafe9032bf544622aL,
        0x6b441e39118a2042L } },
    /* 18 << 56 */
    { { 0x905c8655cdd66b70L,0xe88cce1bc1e2110dL,0x8cc23c0cee674093L,
        0x55ded4d9b2ea3fc3L },
      { 0xdd14502bb58dfbedL,0x523a4dd949f698f8L,0xf843a50101c83e5aL,
        0xf11fd4c1fe71ee1eL } },
    /* 19 << 56 */
    { { 0xeedd7229162d7c0bL,0xd42d6a9e4ccad713L,0xa082fffd2b0c7b93L,
        0xee3abd482a5016b9L },
      { 0x5079c95fc117e22bL,0x5d4b9169814b8666L,0x9e0f5e879bf90a6dL,
        0x4346bd29744bf7abL } },
    /* 20 << 56 */
    { { 0x4d85af0ebfb551b6L,0xb48e3da831f7a958L,0x3b474ce66f5bc50dL,
        0x9fdb47bce7c8dcedL },
      { 0x2064450e53003272L,0x6bb230f3839e69daL,0xb69415124d822be5L,
        0xb51bc6aaf11a9dc1L } },
    /* 21 << 56 */
    { { 0x866447f8b23047dcL,0xe02dbd63e5f52c2dL,0xe6ea43cb02770a76L,
        0x853f5fe356fa6c25L },
      { 0xfe9615f0960de6d5L,0x37c8b0c8f4b1b945L,0xa6e838054618629dL,
        0x38fb526423a2ac61L } },
    /* 22 << 56 */
    { { 0x5dfd700501751c20L,0x7e100245ce72773aL,0xdf09f92a0776794aL,
        0xc4a8de811b730fdcL },
      { 0x72c302abf0c7b031L,0xdddff68e1283913bL,0x24889098e32517b5L,
        0x2483a0f5856a2934L } },
    /* 23 << 56 */
    { { 0xdf6d7dcca1c3d56dL,0x07f9c00b09afb797L,0xe90da23d083d9557L,
        0x80ae6e53cbc03826L },
      { 0x1fd6ff6d7c0e1b23L,0x1e90f3c8b1100226L,0xf179e00e05a24e23L,
        0xe5361efe946f16bdL } },
    /* 24 << 56 */
    { { 0x50f12e4a4c662091L,0xdad2c7a328608585L,0x55c66749f7429473L,
        0x440b77de045ea1b4L },
      { 0x9f707b4991229927L,0x3501e29ec6725715L,0x5626fabb1225a8e6L,
        0x270a9c2b9507e709L } },
    /* 25 << 56 */
    { { 0xe0d629dabdcb9039L,0xb4d7cd2220255b7cL,0x10c8614b5ed874a6L,
        0x36891e704e67d406L },
      { 0x020da8341dce66feL,0xae69e1e7abd64deaL,0x9cf153a1cc71b37bL,
        0xa6e9d02444771c7eL } },
    /* 26 << 56 */
    { { 0xb15e31c78840fc17L,0x57853112349124a4L,0x78a9d807bac542eeL,
        0xe7b4d81238fe1188L },
      { 0x874adc70b3a3b801L,0x80c0e02a4694cec2L,0xd05c8c0ee97805e1L,
        0x8eaebceb89d8cd40L } },
    /* 27 << 56 */
    { { 0x888c777b378d055fL,0x6956795eb104a132L,0xe4bce719be8472d7L,
        0x23c9f0bf5f51729eL },
      { 0xfe7f7e1936a3bf3eL,0xf8f5d2ca20a32d37L,0xf383b46793b8a344L,
        0x7eab76f527a6e2c5L } },
    /* 28 << 56 */
    { { 0x86c31b0e93b54bc1L,0xb9405ea9fc4ecab2L,0x09485578a0f6d341L,
        0x88053bb84b77e8e7L },
      { 0xcde9b77729a07dddL,0xec8ea63f97649102L,0xf74d082ac516777aL,
        0xf4e26d89bacf0dd3L } },
    /* 29 << 56 */
    { { 0x6a919da8d0b3b578L,0x0bcc3b29a0b5f7d8L,0xbf4565e59e55924bL,
        0x13b361877889dbb6L },
      { 0xad0e59c6533981bdL,0xea941b620bd0cb7aL,0xe5e35e9aa9e7aa7cL,
        0x27f61727088bfd7dL } },
    /* 30 << 56 */
    { { 0xda2a5a208b3c7fbcL,0x33cdd403ba55cb48L,0xb72b51cf90e7ff36L,
        0x8cc4b5536f215840L },
      { 0xf7b80ad9d2671224L,0x560b43876a45436bL,0xdca90694ff9e8faeL,
        0x2e7e9546f97aa84eL } },
    /* 31 << 56 */
    { { 0x71e9ff45f37cd717L,0x6edf335e0d73e98fL,0xf355690c9f715170L,
        0xf74df40b3f5a82bdL },
      { 0x28b6d93195e5b105L,0x8827f47c2841a54cL,0x159cb94362b4312dL,
        0x277943d78db37edbL } },
    /* 32 << 56 */
    { { 0x561454fd6113a9f8L,0x78ebe733e70e67e6L,0x8764360b903f2febL,
        0x2ba3b3d897902f36L },
      { 0x28808cef87490b8aL,0xb1175954f05f31b3L,0xbd5d60056c9b4f4dL,
        0x12b13fcadd254e60L } },
    /* 33 << 56 */
    { { 0x38d4e81214959566L,0xe253b75036fe9a6cL,0x24b2c81a809450c1L,
        0x0aa899668fec36b1L },
      { 0x9a99deb5053e97e7L,0x5e57321ce31d3a6eL,0xcd7a4f338dbe78a2L,
        0x9f809d4f3299e070L } },
    /* 34 << 56 */
    { { 0xd6de8cfaa26a9ecaL,0x33d5705ba158a735L,0x08dd3fccc2293743L,
        0x1f8d0a4668bbbaeaL },
      { 0x53ff76f961bc4105L,0x6445e88d7c4a8fc9L,0xfd9a8d04c285d0e6L,
        0xf08d0d6bfe62b449L } },
    /* 35 << 56 */
    { { 0x08c27292c062810cL,0x955629f66663fa28L,0xbaf96c0e9d86fee8L,
        0x1dbc540646bb9894L },
      { 0x8d6b620793dd45c7L,0xaf3baef63ee989fcL,0xf66cfdb159b7b2f7L,
        0x287fc2bfda16c637L } },
    /* 36 << 56 */
    { { 0xa44ca8fa2d71f863L,0xa116196284d5dee5L,0x5a5c8ce33957b610L,
        0xdbb3225317f50b57L },
      { 0xc6a4eb7d76056358L,0xff9eb424c359d90fL,0xdf4afe23a88cb38cL,
        0x2ae727cba696b75dL } },
    /* 37 << 56 */
    { { 0x47cc63efd20a58c8L,0xd319dc3ac492ab36L,0x887a7d8336c7f76eL,
        0x65ed5e3efcd4cf49L },
      { 0x0e6f2f34da301d39L,0xf2f7c10238ad4533L,0x8a3a003bae834622L,
        0x94084169a060a0d4L } },
    /* 38 << 56 */
    { { 0xb673168b13c8a1ebL,0x80109609459f8da1L,0x68003fa15c82007bL,
        0x9f634159248e0430L },
      { 0x188156abfb9b6510L,0xc35be1cce62844deL,0x21e8f908b0c84d39L,
        0xa886d3ebdad3ae53L } },
    /* 39 << 56 */
    { { 0x9e20cd5682b0f5fdL,0xc0c12f0bc465c721L,0xfeeb10516f913a6eL,
        0x9e7c76b9aa32d6feL },
      { 0x820b49a0b8637b5fL,0xe9ae172af4abccf0L,0xccc050b1fb270e67L,
        0x0b51d7e32269d1deL } },
    /* 40 << 56 */
    { { 0xca772ec1678c8d8bL,0x74eea3f877ae7c7bL,0x51550df11e1bcbd3L,
        0xa931c17c3458b249L },
      { 0x192c3a45f204aed5L,0x93abf63dc993c881L,0xc60aa2cb83421891L,
        0x11ce6735f6b70284L } },
    /* 41 << 56 */
    { { 0x53e8a3ee69e152e4L,0x6889ece00033da23L,0xada569047d585418L,
        0xaf81a877f5e5abb9L },
      { 0x36e0267ddf515727L,0xe04b532d3daad2a9L,0x290e3ee71a11ced6L,
        0x5be7c42965e7a651L } },
    /* 42 << 56 */
    { { 0xc0662cd38ef9b498L,0x0ec5fbf06c4dcbf9L,0x26694c70ce4d7e3aL,
        0xc1699a93fa52de99L },
      { 0x2e0d394b6dae3e97L,0xe3af28cf4c66e572L,0x9caf7bf8ba1e27e4L,
        0xd5c39337d5a4bdaaL } },
    /* 43 << 56 */
    { { 0xbb5d95519ec8ad6dL,0xfb3bc1f1609fc2e1L,0x0d95ad2a95fe12b5L,
        0xf6fd6e895341dc74L },
      { 0x1532991e7537b803L,0x77772fd3eaf96f9cL,0x4ed09840f832749aL,
        0x69a194ce95f19d25L } },
    /* 44 << 56 */
    { { 0x5464471a041cc340L,0x26f7e5501c442289L,0x38f2c20eb5ce9706L,
        0xcf73f8f28a44efd3L },
      { 0x5176eda5586e8f77L,0x47e3384463ece447L,0x83826e8f86b00be2L,
        0x49cffcdb539807b7L } },
    /* 45 << 56 */
    { { 0x543d1fad414d3fb1L,0xd56aac6a38b1ef44L,0x9980bb6496c89050L,
        0xc300cb46b169b8a9L },
      { 0x5ab01a6b83413df4L,0x179b8922f3c91edaL,0x4060b94343cccc06L,
        0x4f6adeb59458ec1eL } },
    /* 46 << 56 */
    { { 0x0a4c6437e339e40eL,0x9cb6c53202aefe83L,0xb072d02b23dce7eaL,
        0x2cd7b11759a9032fL },
      { 0x01220cea81dbfaefL,0xffe0026c0905332dL,0x95ec2cb20197adffL,
        0x853bf6f54c3d0e49L } },
    /* 47 << 56 */
    { { 0x04ed54fb25d78f7cL,0x45aae3e1bb68cb9fL,0xf4f1a2c6e32d7421L,
        0x646ade6545a05771L },
      { 0xab241cfa91eab45eL,0xb1cf204c7b214af0L,0x92dfb3e3851d311cL,
        0x56479ffb144ae0daL } },
    /* 48 << 56 */
    { { 0xbf8474449a7a4edeL,0xb26b1f15f5cfd20fL,0xf380ed7d83b33b64L,
        0xa21f95643d1998c9L },
      { 0xd985c7d3a720e347L,0x980789748bdf09d5L,0xa1f34ce2ce947692L,
        0xf69e6144f419c385L } },
    /* 49 << 56 */
    { { 0xe19265268c3adcc6L,0x848974fb42746263L,0xa731261f97791569L,
        0xfed39da2065b721bL },
      { 0x8369b04c836a7e20L,0x5758a76153c19f62L,0x457463830ebea868L,
        0x201799273b7d71a8L } },
    /* 50 << 56 */
    { { 0xb466ed4f57632243L,0xc8d918cb120577c9L,0xbab307e5eda40e9cL,
        0xe6dbc7d4d5f65d1bL },
      { 0xcae0c64960619e10L,0xffddf6d16b0df67cL,0x60488755b32ee5d1L,
        0xcb278aaf47164a55L } },
    /* 51 << 56 */
    { { 0x354c33920bfb732dL,0xcd4fc821649bc125L,0xa8e1253f770ffdb8L,
        0xf7eec5950ff0c37eL },
      { 0xe5a652797149b102L,0x1cbbb56bd0528224L,0x40b1a8d9b51c5df4L,
        0xccb43d2639e1ca25L } },
    /* 52 << 56 */
    { { 0x48f74dc2fdcfe8c5L,0x3ccb31b6fa5b8dafL,0x6f8dc5bc7de6300fL,
        0x2a373fd3f247bc0bL },
      { 0xefe1353917825306L,0xeb253484c50c47b4L,0x4a7f2af33c739f02L,
        0x3a3eb3859a3c6746L } },
    /* 53 << 56 */
    { { 0xa90afa2a588978e2L,0x501fcebf8d80894fL,0x1de1d06d6bf1a4cbL,
        0xb0f4a61d6cc42a07L },
      { 0x975cb8de78d406f0L,0x560b0d7be3d293e3L,0x5746227c32e686caL,
        0xd12854f53fcb0205L } },
    /* 54 << 56 */
    { { 0x8c0eaba8499512e3L,0x8d97c229ade99108L,0xd80da38eff2b5782L,
        0xf8c30ba1aef08107L },
      { 0x9068d7d0076b97c3L,0x851d1cb9b1b7eba5L,0x02bb728c318e4675L,
        0x0efe970776ddc683L } },
    /* 55 << 56 */
    { { 0x6985d3586a248b04L,0x75eb6019f8969ed1L,0xecb66a20606a0c64L,
        0xd1252f64fe39b5e5L },
      { 0x93d5d61c2aa222a9L,0x16c0d6f91ffff8ecL,0x0f1f962d5dfab0feL,
        0x88776fe1cedcccb0L } },
    /* 56 << 56 */
    { { 0x410333c6a32cbff1L,0xca13ce28093bcbdaL,0xd97b06840e479259L,
        0x8b2b3ad8bf505c93L },
      { 0x42092d6471761412L,0x9d0c842d918acf33L,0x904d3addac9ade57L,
        0x025e4177e0d5ef6aL } },
    /* 57 << 56 */
    { { 0xce406ec00b33d4edL,0xf73ac4da57b5c958L,0x5f96cb8c6ef70849L,
        0x702ccc6f77b32d5dL },
      { 0x75bda8d8cea6885cL,0xbfc3e62ec0c0432eL,0x46db9cc654631c9aL,
        0x1669075bba1d1550L } },
    /* 58 << 56 */
    { { 0x5ccc4e342d227656L,0x0724e41b02cb0644L,0xc5e2077d435601fbL,
        0x356155c568d6aee2L },
      { 0x0ea00013fde58906L,0x79fa13c337a9eda4L,0x7d09479d8f51a6a6L,
        0x86e955b71f979fedL } },
    /* 59 << 56 */
    { { 0x9cb22960e39ab804L,0x6aeae78303535a39L,0xeb4741deb9909be6L,
        0xb957c5da1a5f4139L },
      { 0xafdb3e8bedc1819fL,0x33545722e7caa690L,0x0ef33e288bb66ed0L,
        0x5907374270e667b5L } },
    /* 60 << 56 */
    { { 0x0390fb3c5c7773b8L,0xb80b4a2f286a809dL,0xd17d6103fac46467L,
        0x9a09a0d691a48972L },
      { 0xa2124b6239e44585L,0x14c8a671174d241aL,0x99abfa37ada8ba26L,
        0x847f3040fbb457aeL } },
    /* 61 << 56 */
    { { 0x0587aaa47529a18cL,0x23b3f7249bb45ee6L,0x4d7f57122aa81155L,
        0xa9185804a4f16d09L },
      { 0xab6381413fc992d1L,0xb6c326fa0cad0bb0L,0xe21c362560f2cb10L,
        0x6c7af09e2fac20a9L } },
    /* 62 << 56 */
    { { 0x31e892fadc6f72abL,0x71d5c6a321b81f7bL,0xc3e2d70d298a0dd2L,
        0xbc0c37e213ecdc80L },
      { 0xd3191146e6496ba4L,0x15f8154135115466L,0x162be77d07d1937fL,
        0x38b4d1947b176367L } },
    /* 63 << 56 */
    { { 0x4485966db8cafbc9L,0x7cfc0d67f44c2a81L,0xe9e7ec4de624cefeL,
        0x4db8bec3581d4e48L },
      { 0xe76edf007fc8615aL,0x1b62c4a59a02cdb8L,0x8b56574983938a6dL,
        0xd813864e50c86c19L } },
    /* 64 << 56 */
    { { 0x7fc071ef16f55d40L,0x701954389bb45ea5L,0x83cf09f2a35543caL,
        0x07e91a8420554c19L },
      { 0x51ecd70162a9d06eL,0x00e14c622044a663L,0xb1317c1300423dd9L,
        0xf49431bca46eab4cL } },
    /* 0 << 63 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 63 */
    { { 0x35118434d0614aa1L,0x8bae9779d1418434L,0xf5641d82b8c15b89L,
        0x2383af56416432ebL },
      { 0xa552d3f02c73f990L,0x8df82e9ea6bbdc7dL,0x0f336aa8d75ec634L,
        0xc42e3b2d1603e53fL } },
    /* 2 << 63 */
    { { 0x4b33e020bad830d2L,0x5c101f9e590dffb3L,0xcd0e0498bc80ecb0L,
        0x302787f852aa293eL },
      { 0xbfd64ced220f8fc8L,0xcf5cebe0be0ee377L,0xdc03a0388913b128L,
        0x4b096971fde23279L } },
    /* 3 << 63 */
    { { 0xb0f8c0ded2d638adL,0x47fc8c774f299d5fL,0xd1720a929b68d48eL,
        0xf944e708a1c6f103L },
      { 0x36e34e04a146889bL,0xb0aad2d6e74a2a28L,0xedbb034bca52f53cL,
        0xe987a8e187fb2713L } },
    /* 4 << 63 */
    { { 0x6c5389aff727ef3aL,0x95ffeb9533db88fbL,0x27cb70429dae0777L,
        0xd20afe81616dbf02L },
      { 0x0fab8e18914bf706L,0x3b1e66f30517cd09L,0x24b46dce12e40644L,
        0x0ff1016808f2d8faL } },
    /* 5 << 63 */
    { { 0xe08a10dfea2d8d84L,0xe31f05e7e97dda79L,0xfe95f84a4e9ab132L,
        0xacd6f7fc927e216fL },
      { 0x025e27bd83c5a3eaL,0xed010c0d50f120fcL,0x443b3b8ab828101fL,
        0xd83848198cfc0deaL } },
    /* 6 << 63 */
    { { 0xe55f34c883dc5447L,0xbe76243b04e4e9a0L,0x78fb4cbc819166a2L,
        0x0bdfb703ae37f80aL },
      { 0xf869288ec217cda8L,0x2662bb7162af4156L,0xce64f29150ae9d30L,
        0xee0d4440dc0353c9L } },
    /* 7 << 63 */
    { { 0x3e61a9eabd25609cL,0x4ccaea93b3839c8bL,0x721cefa3e43736e2L,
        0x229cb244d0035908L },
      { 0x936bc1dc7f10aebbL,0xc93a1002b67332e7L,0xf4b53dd4f98d1132L,
        0x7b99a196d5a75030L } },
    /* 8 << 63 */
    { { 0xb13caaddca9a9526L,0x701c63fa69a303e9L,0xb97d667ab0a50f3cL,
        0x27c03d7c68e6557fL },
      { 0xab24e712eb105607L,0x4936aedd8dd86ccbL,0x32196f8a0a986d68L,
        0x0307b826248f5a65L } },
    /* 9 << 63 */
    { { 0x20e14b4cfcadb2adL,0x4cb4a0928c3b8c23L,0x50fe3c1a1caa9db1L,
        0x23cc56e881c0a4e9L },
      { 0x5ab091990867753fL,0x5a253d19f9d47c55L,0x422b4e031a9bcc88L,
        0x4e1ce22b671e4f36L } },
    /* 10 << 63 */
    { { 0x588f58b5ebbe949fL,0xb77622966982215bL,0x3cc83dd6cff863c0L,
        0x81ec094d01098f51L },
      { 0x214d69aabe0432d0L,0xe4e52a9c6455957dL,0x94743ba8fadc1eabL,
        0x2c395d978176316fL } },
    /* 11 << 63 */
    { { 0xeab6400ce6bb4d34L,0x7364dc55c0d49bf2L,0xd6fa6e40e6959c7eL,
        0x7960a9977eaae61cL },
      { 0x918b3c6394ea77c2L,0x2cf4997f76866dd1L,0xc4214abfbcbba8caL,
        0x349a61337aa4aab2L } },
    /* 12 << 63 */
    { { 0xd64bab7799458b24L,0x6fe19e252eba3064L,0x9aabd83d74068f03L,
        0xaef812186fdf8655L },
      { 0xf506d27b65593fefL,0x0a1ad85dfaa457b2L,0x266d0f06a303dff4L,
        0xe8114f4eabb416e3L } },
    /* 13 << 63 */
    { { 0xe743f6176aa5a1b8L,0xaf84652d1b5b2bd6L,0x8b1beab1092e2c46L,
        0x7e857549e2518383L },
      { 0x6be2ece1a9383124L,0x8309442a7fc20081L,0x1f00eb8bc3046cabL,
        0x959f315526f39f8cL } },
    /* 14 << 63 */
    { { 0xaacfe2d38fc2ed93L,0x8344664578f0f858L,0x58de6f09dda35ec4L,
        0x891e5ecdf78c69b1L },
      { 0xff4a4ba991c13d67L,0x6e78063d487d5575L,0x226b621e8d303a7eL,
        0x5c9bc103c95987edL } },
    /* 15 << 63 */
    { { 0x289801085e3be13eL,0x5e8c0ac5414af955L,0x0f08e93beaaa71a5L,
        0x1bc50407ce4524f0L },
      { 0x6a6a2e6a921be66bL,0x37113baac27da9f2L,0xc7b3c63652e90e29L,
        0xc075d178c8558307L } },
    /* 16 << 63 */
    { { 0x605f581a88a45b65L,0xcb78920068e58c1cL,0x14cbed65bc5bfe1cL,
        0xd1af7dc7f02b11d7L },
      { 0xb8341bc0cd3a7cc8L,0x8e9aefe8a01a77b7L,0x8eeafe875ae2a402L,
        0x27a0698fc11f3859L } },
    /* 17 << 63 */
    { { 0xc5e49f07f7af9756L,0xffd65bcc9e5b871fL,0x62a95357423eed7bL,
        0x93cf64d5b2ec687cL },
      { 0x04b87dd7be5da479L,0xdcceabd71a134c0bL,0xa4875091c5c6925cL,
        0x3bf947df8e9c098dL } },
    /* 18 << 63 */
    { { 0xb261727111d1323bL,0x7769247ce4c6046dL,0xf9c1aaabcfa6aac3L,
        0xf7f13317354492e2L },
      { 0x4bd65afde91befb6L,0x3e78cd8cf25b8f8dL,0x2adf53ede60ff4d9L,
        0x81ec38533d288d4cL } },
    /* 19 << 63 */
    { { 0xda852a71ee3bf44aL,0x39b4ef6cd7b5c6daL,0x472e699644f4e720L,
        0xbbd19d389191614bL },
      { 0xa2bcc2ec30c0e99dL,0x29318d7b57ba0582L,0x322faf40d315963aL,
        0x49ba55700c0619d1L } },
    /* 20 << 63 */
    { { 0xc28c1f81e5dcd066L,0x64d1268dff9e3493L,0xab0db38ebdf8992cL,
        0xe3790c26320cce30L },
      { 0x59b408a026e3e4b0L,0xe9e5fe296ab8504eL,0x45c827bd83c9eaf3L,
        0xc298e23689518edbL } },
    /* 21 << 63 */
    { { 0xb79a8b158d3ab381L,0x6bb951e8db0bb7c0L,0x5ebd3854be4b3353L,
        0x107ba27d2eb3b0feL },
      { 0x9d01654d46786cb4L,0xf46d8352cf3a1aa2L,0xa8f669a0a1662f72L,
        0xc979209f68a1d3e1L } },
    /* 22 << 63 */
    { { 0xc64975fa65471473L,0x1f8eec02ff1f2aadL,0x1b520fcc8d0dd401L,
        0xcd73209215e14346L },
      { 0x616478d88f878a76L,0x3579d49c7423e0f5L,0x119f6d6e1b2af15fL,
        0xbbe33d81b08c2c8cL } },
    /* 23 << 63 */
    { { 0x051d99c98534a355L,0xe3f3ddd3458b764bL,0xbd7e51aabc8c03bdL,
        0xcd7abf4ae8d42e38L },
      { 0xf0d974283160e63fL,0x258bba0734d13871L,0x4fedb6473dcb885eL,
        0x009fca2750f0a645L } },
    /* 24 << 63 */
    { { 0x3f06c14699775c4eL,0xb10a4ed3f66e7d05L,0x9300e3ca3a3ab903L,
        0x0a5610e0de3c3e1fL },
      { 0xe28273121af56fb7L,0x7e2a2365d75d9a9cL,0x9c3bb05af11f8963L,
        0xdf94cac730c80488L } },
    /* 25 << 63 */
    { { 0xaff1682f2d1143f5L,0x5837e83ab4d6ed7fL,0xf3e179beb4bce662L,
        0xfa8d78628caa5fbbL },
      { 0xbdde016f59ea54c1L,0xc488c8293c1ac962L,0xabe8b36714b46863L,
        0xbcfde36382897d1aL } },
    /* 26 << 63 */
    { { 0x87ddf0ec8c152354L,0xdec85db77a953398L,0x927a8b100b57108fL,
        0xb38b732f525f78f2L },
      { 0x7e696084eb306d56L,0x9befefef50269227L,0xfa86e376caddfa11L,
        0xd50a08da404be227L } },
    /* 27 << 63 */
    { { 0xb7408e3303bb523cL,0x6d21aa4ac093aaf1L,0x52aae4c9a85d6fcfL,
        0xf5d057c9b726afa9L },
      { 0x7979bb5cf92ca5b2L,0x4b1f7936c4e3e4f3L,0x2c534200071ec517L,
        0x47b52ffe67d3f86aL } },
    /* 28 << 63 */
    { { 0x4a0b581d84d1c5b2L,0xfc825a4a0dfa90cbL,0x2df2ec9811c72996L,
        0x82077a6e7dde922eL },
      { 0x89acda109f28b584L,0x54578eb8e49fe66fL,0x90a5f7004a1c29d7L,
        0x2de4719cb3b44748L } },
    /* 29 << 63 */
    { { 0x6944fe1418d85e6bL,0x90bd8208de7b904fL,0x5811f3b6a4597137L,
        0x7ea43767d4ab5433L },
      { 0x7ec39109a204a36fL,0xa43a4a57a30fb76eL,0x4fd514f8e090f2beL,
        0x3918138eda1c97f8L } },
    /* 30 << 63 */
    { { 0x2b466ae215145a20L,0x28ccb2cefbac86b7L,0xb891b70704106b98L,
        0xe40a231029696a08L },
      { 0x1210fed0636d9e11L,0xdaea218d2043caa1L,0x10c2ed0f0aef7dcdL,
        0x926be98affa5db7bL } },
    /* 31 << 63 */
    { { 0xe762191c36abac30L,0xe21acfaa8b75b5cbL,0x4f5e6b9fd180cc32L,
        0x0135830955deffddL },
      { 0x1b1ab943992a66f3L,0x1ebe0246ceef1a9cL,0xa24c9e257a01dcb9L,
        0x3d45c4e3326505f5L } },
    /* 32 << 63 */
    { { 0x9b805759c8544885L,0xbe9b99ca7bfcad78L,0xd1db36e12b8fe78eL,
        0x37255a2dd5387bcfL },
      { 0x044b3a3ea150ad32L,0xc65bc2a36671ae59L,0x41ce078e1d52384bL,
        0x3115f1b19e72c300L } },
    /* 33 << 63 */
    { { 0x487ff9dad0a358a0L,0x4b20c3699c242aecL,0x7813a44c1c7b145fL,
        0x87c6beded6f2d3eeL },
      { 0x34d2a89b47d393b1L,0x1e9f97c673f78679L,0xcb614fe02edce91cL,
        0x62b960097e9a5fa9L } },
    /* 34 << 63 */
    { { 0x7eb2aeb558c34b85L,0xa256a478cf5074fcL,0x73f23a5698c1de9bL,
        0xeffd490e61ce6535L },
      { 0x2569df2a4a6c15c8L,0x91e202a0fffc97a5L,0xd83c428e28dc7a57L,
        0x03bc53c79fc8dca8L } },
    /* 35 << 63 */
    { { 0xed394cfa9b60487bL,0xa4259f91b483a686L,0x11f51779179a5ccaL,
        0x00b00ef086c1d1c7L },
      { 0x6e596d2af1231aedL,0x6c1a702bd80eaa89L,0xd28f8c15d23f1d64L,
        0x93e85bea6d01728fL } },
    /* 36 << 63 */
    { { 0xd4288fb51c704922L,0xaadd19688c1363c5L,0x9b5c42d752f2cc4eL,
        0xf9e4bc96c298e794L },
      { 0xd604f076af0804acL,0xa441140ab3bb2628L,0x761eabcad37bf6bdL,
        0x7d192922be1cf79cL } },
    /* 37 << 63 */
    { { 0x2365739e3da7073dL,0xfb7423ea8e2c078fL,0x08f5132e3adfb6f3L,
        0x470a4205710a26feL },
      { 0xbe0afeb42b6c9b33L,0x94d9edc83cd813bfL,0xa2c7a7a0440a1699L,
        0xbdc4ea3b4eaf0c10L } },
    /* 38 << 63 */
    { { 0x5a5455db52fdc8d3L,0x60485f39b2945868L,0x54ce956700af0abeL,
        0x17bff77be8d15f54L },
      { 0x0021c5310e14a7ecL,0x3efdb22ddc9c800aL,0x9a9e27474d947adaL,
        0x19417bc4b37fc947L } },
    /* 39 << 63 */
    { { 0x71ca8da88f02c551L,0x782d5da4074cebc0L,0x99094980c1a43a2dL,
        0xe1b02ff024890d9bL },
      { 0x4eedaddb45d82f7cL,0x7ae170a55061c943L,0xaf8c7ea04d47c578L,
        0xcad17044ad3a6eaeL } },
    /* 40 << 63 */
    { { 0x51383e614f4c9c8bL,0x78d171829182fc81L,0xbed6f0d490d72cb4L,
        0x987612917bea62f0L },
      { 0x27594570ef3cd3fcL,0xf475953491a8c364L,0xf5c607c52744eb2dL,
        0x0d6264ebd8d8f337L } },
    /* 41 << 63 */
    { { 0xb54867a6a8701750L,0x1387e94087691191L,0xc451f178bd2f75dcL,
        0x31a099d3d1da6080L },
      { 0x0d0fcf9749f87f03L,0x0b7585f80af6273dL,0x3619cf2c1142265dL,
        0xf84d3f9605c559a4L } },
    /* 42 << 63 */
    { { 0xc3d3c80eb83f2cb9L,0xf4ef0b548f602141L,0x3afb343db9612928L,
        0x7abe56208db5c907L },
      { 0xcd692215cf019b08L,0x98d70b389ae12255L,0xb459e2568dfda5f2L,
        0x066a445e8f3f403eL } },
    /* 43 << 63 */
    { { 0x5663e123423fbbb6L,0xcc55ce365424d48fL,0x8bca99b93b6d5467L,
        0x299ff0ea316fc956L },
      { 0xd973a8d8a0ceb256L,0x443ecdb96d9956b9L,0x8c16a75d2f64f912L,
        0x89e490c2bbf7ab50L } },
    /* 44 << 63 */
    { { 0x4bd00db0b8dbf031L,0x866e0bbe7d2cb92dL,0xad36406e1dd3db2cL,
        0x969dc881e4e3f194L },
      { 0xcb3ac9e42a115bc8L,0xb45efd5de0a5ab75L,0x1709c29355377d5cL,
        0x06d11ba4de6bc25dL } },
    /* 45 << 63 */
    { { 0x84a09347ccf2d10bL,0x571cd4d908ee5aefL,0x1379ac02a450dd82L,
        0x5b7f02f5ae404542L },
      { 0x17366e7f2a7df4ceL,0x5bb3560c9830ebecL,0x5c5825807c254726L,
        0xea13f8fd70ab7b3dL } },
    /* 46 << 63 */
    { { 0x868c0f8d314e2a25L,0x4b3dad3a0be90b12L,0x09970da432aaffcfL,
        0xe711e9cf8a6d894dL },
      { 0x511521af0a80d07aL,0xe38147168a2a2851L,0xde76d41b1de9183eL,
        0x8a9fc79aaac779e5L } },
    /* 47 << 63 */
    { { 0xd7d1f23526879f8bL,0xcc849c85e37d5f9fL,0x26b5488a6b9cd82fL,
        0x1b068e8d91099141L },
      { 0x040dc00f35ee636fL,0xab40f94bd84a9cbbL,0x2e4cf65cdb303776L,
        0x42eaa12e78e8affbL } },
    /* 48 << 63 */
    { { 0x7835e4e9876f8f38L,0xcd421d77090ca6b6L,0x71a1d12dad0604f7L,
        0x51c2d1581a22e872L },
      { 0xfe7dfcc8429e45e9L,0x20028f5c48224b6fL,0xf7afed3750abf907L,
        0x92183692c4ce1a69L } },
    /* 49 << 63 */
    { { 0x0b93365c2d128addL,0x883f43c313200221L,0x9d3b5a534d309b2dL,
        0x60f0db16cf91a023L },
      { 0x20f0ebbd5b0e47beL,0xcc20dde8317d8b4bL,0xab033b485303dd7cL,
        0x6703eac77a9c1974L } },
    /* 50 << 63 */
    { { 0x92f0b738351c8f26L,0xadd39ac808569159L,0x80866e5e61098dd5L,
        0x7d0c1c6fcae578f6L },
      { 0x13d89cee975f59e4L,0x86006ed40092de2cL,0xda825b0a819adda4L,
        0x74fefb46de710934L } },
    /* 51 << 63 */
    { { 0x7c2ec289d3dc8683L,0x25898cd8690e5d08L,0x9bed0f32bcc67531L,
        0x356ba80cac762453L },
      { 0xd3224c577680da5eL,0xaae2597b3399d679L,0xb2a2a1e568df6e74L,
        0x49d23e8c2301b373L } },
    /* 52 << 63 */
    { { 0xcb89b484170dd677L,0x36b1d3d16b3ee110L,0xe50ada4f0d7b51b4L,
        0xa2f4fb57fd9afdbcL },
      { 0xb1b9b81daa6dd8e8L,0x616056a00be328aaL,0x8f6dd943e12b07c8L,
        0x4bb551c6325abaf6L } },
    /* 53 << 63 */
    { { 0xa546038068fbed5fL,0xa65d059f87ed0d37L,0xff60beda208aa8ccL,
        0xc91ff11b33d2d65eL },
      { 0x078c4e5ef65f65d2L,0xa92ed905f347dccfL,0x261ad25df59e3be9L,
        0x95903d913b69faccL } },
    /* 54 << 63 */
    { { 0xcf0a2f94e789d854L,0x9d39cd5110fbf531L,0x980ed5d46de44e3cL,
        0xaedbae3778425caaL },
      { 0x35804bc17bd278b8L,0xf4bee96a6a2d7beeL,0xc6c553a6a605671cL,
        0x182c923886f010d2L } },
    /* 55 << 63 */
    { { 0x94343b7a9cd6f37aL,0xa71e3853237190a9L,0xfcbebde7a8a28451L,
        0xfa928367d711d2beL },
      { 0xba8fd2eac3668951L,0x00fad1ed2d241329L,0x61b82e195dbdffd1L,
        0x0e5e57825a181dfeL } },
    /* 56 << 63 */
    { { 0x1c1bf593c60f1799L,0x388d695064ef800fL,0xf78ef00fce927a87L,
        0x2a0104196abfff9fL },
      { 0x13a7b08eb0b7ffe2L,0x4619da3e6da4cc8fL,0x8ac191907937e0bdL,
        0xf97d3fcb1af4f84cL } },
    /* 57 << 63 */
    { { 0xaea2abd08ac425a1L,0xc619c17d4a02e136L,0xf09a57d31b2c4acbL,
        0xc6fce6fc87b4eb40L },
      { 0xa161bb70b21b02f7L,0x075301fb95bcb925L,0x1d408003e1b440ceL,
        0xb42a47af606b3142L } },
    /* 58 << 63 */
    { { 0xd4ad09c71c832c35L,0x5bebe9130e17fb8fL,0xbf8efbcd8b45b250L,
        0xbef3cafee5ca21e4L },
      { 0x08a18be7688076f1L,0xabbb3fc50c3a2648L,0xa77086e8fb54720eL,
        0x8427775719c29e8eL } },
    /* 59 << 63 */
    { { 0x551768ca5b95b36dL,0x8850a9b0c7df6d3fL,0xe5a2737f5008c00aL,
        0x9a577c0dad076e3cL },
      { 0xbe7c611c2afa6a8aL,0x5dd9142a04259dacL,0xd14253bb422bf3d1L,
        0x8c9dc4c66805c78bL } },
    /* 60 << 63 */
    { { 0xb9837258d430488cL,0xf9fc178b7abc184bL,0x035d30790c5e6a11L,
        0x20cbe540fbc2182bL },
      { 0x849994e29d76812fL,0x166a9279f7a85553L,0x15ff064319d70affL,
        0x3c58e0b04bc6a829L } },
    /* 61 << 63 */
    { { 0x3809904b84df75ffL,0x454c63fd67a7c214L,0x79e0ffde2d873c09L,
        0x620a3293cef301bfL },
      { 0x8f38c8e8237c2bdfL,0x61cf96de13203c2cL,0xdff401d6d0bef848L,
        0x3c8ed7ceee4bcbb6L } },
    /* 62 << 63 */
    { { 0x3e128e2d07ff8f9aL,0x0653c0b2ad7e8d5eL,0x7bb30bb5b1930408L,
        0x91d187054c158386L },
      { 0xc4cf843c80c21fb4L,0x97a72d758a04133aL,0x6b7c49f34218755aL,
        0xc1a5a44768a40f68L } },
    /* 63 << 63 */
    { { 0x0ab9650e15ca3037L,0x16b1fa71ac06feb0L,0x501796600faa3dcaL,
        0x368b2d891c1aaeaeL },
      { 0xf6fa652ab46f0310L,0x86a4d62779fcbc59L,0x78169b8e6106a132L,
        0x40a741eb9e387d16L } },
    /* 64 << 63 */
    { { 0x14a4517480eed542L,0xadd645613362ef7fL,0x39228bfcc5dd0396L,
        0xe9fdf903ea0c538bL },
      { 0x6bfd91ec74d235deL,0x96ec237824aa0a47L,0xf5699241af8d6168L,
        0x0a7b9be3c548a60bL } },
    /* 0 << 70 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 70 */
    { { 0xe5255c302ade9556L,0xe328af1b75ba2e9bL,0x9d3391ef41ce9e47L,
        0xb74cd668fb0ffcc9L },
      { 0xc67103e4e3226acfL,0xa65ad22cd2959e42L,0x3aaa840699d490fcL,
        0x3e26a1c29ecc6356L } },
    /* 2 << 70 */
    { { 0x71c975de4e92defcL,0x81aeb173d0089883L,0x8a30ce4a2ec09190L,
        0x426e783869a36d64L },
      { 0x5899a0b6309bd2d7L,0x3b1c24af3cc1a4afL,0xb2aa8142345163b3L,
        0xd2ad9a692c78c86dL } },
    /* 3 << 70 */
    { { 0xde59fe5d8e7a4174L,0xaedff2d2ab3b0f3dL,0x4688e9e01f053470L,
        0x29ff3fb197c95c7cL },
      { 0xffb930cc85e6a8dfL,0xaa4d3175623b6068L,0x682101ddf9716623L,
        0xa3bc9f5f402db696L } },
    /* 4 << 70 */
    { { 0xf67233c6ba4e4651L,0x8cf956600714d4acL,0xd70decc371f1f8daL,
        0xb674732a7078370eL },
      { 0x4270416d4ccc773bL,0xc848ff35de87951eL,0xa61506a8493dfb56L,
        0xd8371ea9767eb110L } },
    /* 5 << 70 */
    { { 0xb468c3829e6b1d70L,0x1a9019784cd025fbL,0x4bf50c7e5e6879e8L,
        0x6b862c0f71cf7119L },
      { 0x6a53ce8906240e95L,0x3ddfaa0a04107ff4L,0x317093cc65532b51L,
        0xf1e0f8590e27b5fcL } },
    /* 6 << 70 */
    { { 0x96a97a12fe4674b4L,0x2a132ae6f7c97b12L,0x5afcd087a5f5ae91L,
        0xfd1d3a32d4805ddbL },
      { 0x0a989dc0d7b5c8bdL,0x35d186e44429af19L,0x65623ad242935fbaL,
        0x4e274314e79b867dL } },
    /* 7 << 70 */
    { { 0x47d9201608aaba2aL,0x12b62343f3f4c812L,0xb35bf043464f4b4cL,
        0xdc9391c0d8e8ba16L },
      { 0xcc0f8c4a5d460c0dL,0x04ce64bfe20fc6adL,0xd0289df5aa4b7db5L,
        0xe0ea15c5e5299815L } },
    /* 8 << 70 */
    { { 0xc066ee2fda3adfe0L,0xce6a9bdc0c964e7dL,0x04a0115b0c859476L,
        0xb5e02dc99c95699cL },
      { 0xf8301f6211377eb9L,0x57b245a2172bca2eL,0xa7d9b4707b47cf1fL,
        0x1b469bab1774b1c1L } },
    /* 9 << 70 */
    { { 0xbb9ec3e9da2dce70L,0x02d5353ed29bcddaL,0xc193244ab215233cL,
        0xb8d5727fd27a4e2aL },
      { 0x79e56194b6c5b114L,0xe2c20e715ce727f0L,0xc92f34a5236cbfeaL,
        0xcc47dfd156a02b8fL } },
    /* 10 << 70 */
    { { 0x5cdbda39e983ba13L,0x20f3de576e96c8b2L,0x2ff05aa766b76faaL,
        0xa876bc62d7f84b47L },
      { 0x962ef8a90d677d1fL,0xabc7bb1e801d3001L,0xdb5f0b1a7d13a23fL,
        0x2664f3ab20b819e4L } },
    /* 11 << 70 */
    { { 0x96be66c5dc45375aL,0x780ee0624a6c24e8L,0xc6fbfd1a013a13eeL,
        0x6ce1496c21fc4f9cL },
      { 0x03130c0981f272c5L,0x06e59457a26609cdL,0xf4c5e564ee5363b4L,
        0x1cd19a117df0775dL } },
    /* 12 << 70 */
    { { 0xcdfcfa67dfd6586eL,0x358953e51ba23faaL,0x0f467275aeec5d6fL,
        0xb815967a5b0e6b2aL },
      { 0xb01bf133012b89b4L,0xdd924bbc6839cc04L,0xa5cd2180120dfd73L,
        0x1abb11ef19bf8098L } },
    /* 13 << 70 */
    { { 0xd56c11ce6a281d1dL,0xfb01f45570daeb19L,0xbb442a0d8f29fcc1L,
        0x9aa60157e9b2f829L },
      { 0x1f3f6e6190ae8113L,0xc701a1856c946c0dL,0xb4b8926852ba7caaL,
        0xd657c679b0a5c77fL } },
    /* 14 << 70 */
    { { 0x0f14eb110dd26330L,0xff6222969b036325L,0xaf833fb8186e735aL,
        0x7801b02fc7e710f5L },
      { 0xa0bf821f5c948f43L,0x3be31aea86225c71L,0xe98f4f7be60b1c88L,
        0x6306588d73c5281bL } },
    /* 15 << 70 */
    { { 0xd617827783c9f829L,0x67b20e6cc06675f1L,0x8a63fb89cb2d5b9dL,
        0xcb28128c038c00feL },
      { 0x070a51418c7c6c6eL,0xc05e18c38789c3b7L,0x09fd03c2d5c67731L,
        0xc59e2abbf54010ecL } },
    /* 16 << 70 */
    { { 0x03977889f1ef2232L,0xbe2c82f19c7409a5L,0x35ac44f932004e03L,
        0x048bb359856823a3L },
      { 0x2e108d6cec1cf253L,0xe98e74d7703eb1d2L,0xcaf64f60570ac34dL,
        0xff814e7d4d7797faL } },
    /* 17 << 70 */
    { { 0x93b6abc370818472L,0x0e984be6888357afL,0x2a7ca1b03fe0c135L,
        0x0c6c4a1194a82d67L },
      { 0x0c90c359bb83ae74L,0x49b25e5e328b8af1L,0x26a36032798ff0a6L,
        0xbbf89c991fc28ca3L } },
    /* 18 << 70 */
    { { 0x4ce174e2e679eb71L,0x17c76176d1c183bdL,0x4bf67be803a69f58L,
        0x937a391cc0ee530cL },
      { 0x2daa9d901f7daaffL,0xa47e99b2c54f14d0L,0x6be357e7c57feecaL,
        0x3753fad2cfdfd5ddL } },
    /* 19 << 70 */
    { { 0x74e1457a48f90174L,0xb80926429b4734daL,0x291e75ba5800ea72L,
        0x25a21b38c72c28f7L },
      { 0x2193e0c9505aa4d2L,0x2f6829e3ada9d3f8L,0x66cd5a1d92900e29L,
        0x1360d2877414dc1dL } },
    /* 20 << 70 */
    { { 0x5deeb2eb0d1b96aaL,0x25783ce33e52ccf1L,0xe4e251f429d534efL,
        0x9fe9693d55797dadL },
      { 0x6a173d69c6ab9935L,0x239913187721ca8eL,0x38cbcd30c393eb26L,
        0xe3627ab971d95a9eL } },
    /* 21 << 70 */
    { { 0xdf1218be7f6fe2d4L,0x850c8598fabd8326L,0x1214d3d7b0f7cf49L,
        0xeaf60d311805345bL },
      { 0xc5caf65bbfee2c5fL,0x7012797945e23043L,0xda36e794500fbad2L,
        0x38fa60b04156e3a6L } },
    /* 22 << 70 */
    { { 0x45934bdd3cbab88aL,0x72821e741b19dce4L,0x532f706d8661e32dL,
        0x3dbfc22573a9930eL },
      { 0x72d1cb2a3cbeb0f1L,0x795b0696e20f5613L,0x6e3469e89fc88717L,
        0xf4bf0531483864d2L } },
    /* 23 << 70 */
    { { 0xc92e6a8cfa19ddd9L,0x7db7e2ee3528e628L,0x997a00ebf321fc88L,
        0x7605a2c9acdf205fL },
      { 0x9fca58cfea9c3ed0L,0x833078cb56ff0e98L,0x75159b8f662a1695L,
        0x186560b71919f51fL } },
    /* 24 << 70 */
    { { 0xe9b60e575ef764b4L,0x61ad29fcbe73c698L,0x18489017dd2be1eeL,
        0xac95e3b67febda71L },
      { 0xa69853465ac96092L,0x906265c3bfc83566L,0x1692c8125972fa4aL,
        0x4e76f87900773540L } },
    /* 25 << 70 */
    { { 0xba9a6268542b137eL,0x43a52b904c7926e2L,0x28785bf5feae554eL,
        0xc023b6880ab61576L },
      { 0xb3ec818110933a55L,0x756344596331678eL,0xe0dfa14117c50b5dL,
        0x4cbe7fdae2151f25L } },
    /* 26 << 70 */
    { { 0x3f3072acce81fbafL,0xa387bb200ff56a32L,0x2b08a81199865968L,
        0x7279f913084cb1f2L },
      { 0x78cca6c9dad70f5aL,0x72469f6aff47647dL,0x2505c7ffe358b597L,
        0x7c5268a8998ff0dcL } },
    /* 27 << 70 */
    { { 0x32d7012999d5b1c1L,0x72727c1524a90c34L,0x57dad21c715662b1L,
        0x76b4b6ec132f3294L },
      { 0xd03b46b1267d246eL,0xc7c848ec29b47516L,0x5eab3dbc1660af51L,
        0x818894c404c66383L } },
    /* 28 << 70 */
    { { 0x26a45c3ea7b82f5cL,0x494694deea98adfbL,0x44a06ec3134b182cL,
        0x5570befa75b82b41L },
      { 0x819f6808129f952eL,0xa6fad25f914f87c4L,0x831e56687c7be905L,
        0x93107f38e623a5c2L } },
    /* 29 << 70 */
    { { 0xa9d884695e40c5f4L,0x4314d233aa5993c5L,0x5eab88d09c19bbc5L,
        0x795e1c21b385d3cdL },
      { 0x532a1871ce163fbeL,0x727cb126b867aea4L,0xfc7047ebf7f30476L,
        0x18031271fcc4fe35L } },
    /* 30 << 70 */
    { { 0x4b84fa4a884a4c6dL,0x82cb9aee55c830abL,0xd4cfdf040cc927ccL,
        0x787efddea16bef30L },
      { 0xd1fb2dd632e3c763L,0x8739566f16737272L,0xf9ae4f4603a1055aL,
        0x199970cdf9a7472bL } },
    /* 31 << 70 */
    { { 0xf9893cfb1d33ac50L,0x74cf7dd41e5ff4e5L,0x72ec32e5f7165331L,
        0xa082c59abb4679cfL },
      { 0x3cd0a4675c75461aL,0xd2872d6840f06206L,0x08271eefb5122795L,
        0x7006d3501475e22bL } },
    /* 32 << 70 */
    { { 0xf7cd1bcc89e35108L,0x924efa4393f1cbafL,0xe3716559f35b13acL,
        0xa0a88e8760370a1dL },
      { 0x1203be0a8c286ea3L,0x97fc5ab66ebd50c7L,0x2b5b360274284d08L,
        0x3055716f694a20e0L } },
    /* 33 << 70 */
    { { 0x793c8a89193520c0L,0x356402d0655f5ff2L,0x0cf889ee1af5ddd6L,
        0x3eb7eb35b3f149b2L },
      { 0x5254b57c68e07e0eL,0xb1971de29c5bbfa7L,0xcc85a53a0ad81e7eL,
        0xbaaa4d2bed3cbb10L } },
    /* 34 << 70 */
    { { 0xbdf9941c8f3a7eecL,0x6e1b7daba1f26666L,0xe7a0dfa42d79a58fL,
        0x25e0ddb51f2b9667L },
      { 0x4b3b51055fd96351L,0x123258328874abd1L,0x56e90310795d91a5L,
        0x376a79d22c32eec8L } },
    /* 35 << 70 */
    { { 0xd9dd8817a8a16445L,0xd61f6aec0e00fa92L,0x594a620d17d95f07L,
        0xa1534fdaf4b15001L },
      { 0xe94026010974f4a3L,0x4c3fc1308f671f13L,0x8eaab35ac5f35bfbL,
        0x13b984724626bacaL } },
    /* 36 << 70 */
    { { 0xf48703adcdee6f8dL,0xf1ba030912d39694L,0xeb2d4d929fcda52cL,
        0x984f51115507b401L },
      { 0xe3aa26aef6bab9ecL,0x557b5e3f6b2e077dL,0x7185ab4f2f9c5f35L,
        0x96f21a331680bcbcL } },
    /* 37 << 70 */
    { { 0x2e7f6e072ddb1173L,0xa704416e816ffc8dL,0x55acfaa352e26265L,
        0x9c2442538b758c94L },
      { 0x4012e0a60479936dL,0x12749e936d8541d8L,0x374f420dce56a2a1L,
        0x6a8e3614c79da17fL } },
    /* 38 << 70 */
    { { 0x3602ad09157cc9e1L,0xf3c4a54c13603196L,0x354fc6ed8473ae27L,
        0xb4cf4251651b8003L },
      { 0x456b1b9b3415b5f0L,0xe078a858c4c71507L,0xf42104099a0a11fbL,
        0x76de42a0f930ec45L } },
    /* 39 << 70 */
    { { 0x82ecd0afcfa869a1L,0xa637938adccf2e47L,0x1d2858f2c041648aL,
        0xcf9abfe8c0dfacd2L },
      { 0x3af77e19bdddebe1L,0x15f6b0bb180b535fL,0x497de678549d34c1L,
        0x31495c9e3dba7d6fL } },
    /* 40 << 70 */
    { { 0x47b9368b393ab61cL,0xdb8ee3a827441f92L,0x214a6a5ffb0b0117L,
        0x429e61ad43759430L },
      { 0x78116e8877316c0eL,0x59c82616a6a29e98L,0xbfed454faaef4619L,
        0x673327c435926335L } },
    /* 41 << 70 */
    { { 0xaa66d8c518c616a7L,0xa93946a66d28fb98L,0x4fc30de5133336ddL,
        0x7e000a347f0c805eL },
      { 0xa82dcf54cf7eab23L,0x679e67a88dc24371L,0x26b2dffc1af582d8L,
        0x4c1d692ad3fe2155L } },
    /* 42 << 70 */
    { { 0x2475b1102d024923L,0x0cc9245dc303c1e7L,0x290b7a7703667a7aL,
        0x2ab8eb6dd87dbd9cL },
      { 0x7089e481c098719eL,0x17dd6d7412c022c8L,0x90efa01f8b7aca14L,
        0x8b601fbaf55fbe83L } },
    /* 43 << 70 */
    { { 0xf800bd76415aa7a5L,0x015573d33aa74349L,0xd5143779af5ec789L,
        0x32330b4bd76dd2ddL },
      { 0xec6caa4d82331ef1L,0x92cc886525ad1965L,0xf8209a40134370b0L,
        0x320a37b9b883cf95L } },
    /* 44 << 70 */
    { { 0x94237ba25d39731dL,0x6359d1958532a968L,0x8bca94c9f86b8b75L,
        0xdb5c6a9cde316226L },
      { 0xdf300c59a2fa0c26L,0x6dbf608248af4357L,0x25066c6c06535fc9L,
        0xba2e774ea29b2477L } },
    /* 45 << 70 */
    { { 0x5157e93d1931299bL,0xd6249c103a8035a4L,0xcb18fcf181245740L,
        0xb4d84c9dad5ebe1fL },
      { 0x95050bec8df0d59dL,0x190a4860ac2a2e0cL,0x29029e0ffd1bbb11L,
        0x341f73deb075b432L } },
    /* 46 << 70 */
    { { 0xa825c3c574836028L,0xec4fd74b8f55343aL,0x009bcab560a683b3L,
        0x29877303cd3adea6L },
      { 0x9f264bf2684a33acL,0xc8bf19e684b3c379L,0x8ac35fb8a1215470L,
        0x2919d9da405386d6L } },
    /* 47 << 70 */
    { { 0xb4e4aa3019780b2aL,0x639b8fcb356ddd4eL,0x6ed7b10c9322c245L,
        0x84ec0bc657f39c76L },
      { 0x6a1be66c879176fbL,0x4cab3151e10e0f77L,0x01c6321fe2ae0777L,
        0x04d6a04c65e57ff1L } },
    /* 48 << 70 */
    { { 0x8c1725ed142596dcL,0xd321d49ab2d413a6L,0x19c25fc32b5e8ae7L,
        0xfc32cbebbd3c7dc6L },
      { 0xf3ec98b857b98ff5L,0x52e5f1adf75b1a00L,0x16812bb48f8ad463L,
        0x9d67cb11a274f0c3L } },
    /* 49 << 70 */
    { { 0xdec7205580064047L,0x3f828c014319f87bL,0xffcad5c3ff4d6c4aL,
        0xee6659b267a6e030L },
      { 0x9cb5c7290478715fL,0xc63fc2815a1c926eL,0x1b8788cadeb11155L,
        0xbe2eebf14f0c00b2L } },
    /* 50 << 70 */
    { { 0x9b72ffd0a6af09d1L,0xcbac42bda9a459f3L,0x150806c0f560dc93L,
        0x71c636e4c57787eeL },
      { 0xe4f3acb82a951b0dL,0x510dc7713b18d294L,0xfbb3fb53b060e782L,
        0x0659cadd0358210eL } },
    /* 51 << 70 */
    { { 0x23638245ecde1629L,0xee6e9a65cc09daa5L,0xf440bb81ee18f9cfL,
        0x99e4d6e8955200e0L },
      { 0x34555b5893e69354L,0xa6080e13fb29b19bL,0x3bfa47965100ab06L,
        0xf5db4b1322eec8fcL } },
    /* 52 << 70 */
    { { 0x2c1a229ee5aaa980L,0x446cd46bd29eb83eL,0xe0c044da7f5aa015L,
        0xa55d5f23a18f23f7L },
      { 0xd71e58c1b6b70f51L,0x77c72d10b5862c51L,0x01db731afce94cebL,
        0x877703a813a47553L } },
    /* 53 << 70 */
    { { 0x4878b0b13b75e6d9L,0xbe8421f0fe60f98aL,0x6312821bc69d6820L,
        0x4c01937400d2db20L },
      { 0xb1bd51752a1d8b74L,0xa0a24ad2ef7fdad6L,0xf29fd27d929fc488L,
        0x8e28b4ed162a02deL } },
    /* 54 << 70 */
    { { 0x434cbdb3c166afcfL,0x7b79e808bf663e65L,0xd445f1b0a3c3b159L,
        0xdf9f92b7b35b2be9L },
      { 0x815b57f3788a9bbcL,0x9e03e357abbba2e0L,0x3fc574d591a658d8L,
        0x83b35d8aadf4e250L } },
    /* 55 << 70 */
    { { 0xa0e15175acd1e4f0L,0xeca899a4868b4e04L,0x713b4e9e782b7ee7L,
        0xed177e1eb7d58c1aL },
      { 0x4778df76ac8364b2L,0x6898fb312e8f7ef7L,0xfccf4c53a03975b0L,
        0x0f908d148597436fL } },
    /* 56 << 70 */
    { { 0xbeaf1a1696671c53L,0x9be643296bc4cbbfL,0xc8f66f6380017bf3L,
        0x92d700f28836ff35L },
      { 0x9ddd7a8113a4daf1L,0xb3c427239b72664bL,0x3d96f79a81babf43L,
        0xa46c9c0c7ce5830dL } },
    /* 57 << 70 */
    { { 0x54dfec97f5999a71L,0xdb5be461e586a578L,0xf9bc3f04cfb4e7adL,
        0x6e5448a9b11f07aaL },
      { 0x29ef779170132d5aL,0x4fe486c328ba851aL,0x6743fecdb62f7f8aL,
        0xeb26438744d24d01L } },
    /* 58 << 70 */
    { { 0xf93c05bc72ebb976L,0xe65b30c0aaae099eL,0x4194721ac8427104L,
        0x3af3487f3025853eL },
      { 0xb33a2893dbf48435L,0x2c5ac6392d79334eL,0x8fc199f8b16b05a6L,
        0xc145358e7661a77bL } },
    /* 59 << 70 */
    { { 0x15b580b61841f719L,0x24f5fadbd7045528L,0xe443c25798df2c22L,
        0x48acf5a7d7eed58bL },
      { 0xe24e6571edeb9e4bL,0xcd047b81562533fdL,0x618ddd86d1566e36L,
        0x09a77b70dba1ecedL } },
    /* 60 << 70 */
    { { 0x0e9de4106968ddb9L,0x10f0f42912985b32L,0xbe21b10f8ca7d2faL,
        0x0844d8e8c610ae2bL },
      { 0x58a08694d57107d5L,0x45f44bd5c34441f3L,0xe8b3b3df79a54186L,
        0x6496d668b8b5f26bL } },
    /* 61 << 70 */
    { { 0xd69cefb8192503beL,0xb692128d40f928fcL,0x13b11dfda7ed8c47L,
        0x90bd279f5a196756L },
      { 0x78f2e8c617ff33ebL,0xa7b233d4aaf6c182L,0x63d6250376a31f46L,
        0x53143dc31449dc97L } },
    /* 62 << 70 */
    { { 0x5bb8680294922922L,0x2f45a7dc89181334L,0xf7c466d51ec5cce4L,
        0x52d15eedbb3bd5f3L },
      { 0x150bd5f6e6eacf86L,0x7fecaf3a0ba66988L,0xcdd7fadb11f6f528L,
        0x60f64c6855042fafL } },
    /* 63 << 70 */
    { { 0x1615919d961ddf76L,0xdba095cb53f2f514L,0xf04960ba1e6c076cL,
        0xe52767224c9f17d5L },
      { 0x93ff80f961c186a9L,0xd17378b03c58ab92L,0xc67f9ae1769492e8L,
        0xaccfc8680c3d023bL } },
    /* 64 << 70 */
    { { 0x7d67a63d5b99708dL,0xfb29bef74b80189aL,0x3cb7eeaa241c402eL,
        0x328cb6de2c5c2767L },
      { 0x0d24a7b49cec231dL,0x725955fc0e2e6a7fL,0xa2040cfab7f17b13L,
        0x215eff8da25c71cfL } },
    /* 0 << 77 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 77 */
    { { 0xe4d9cab1c0d41a94L,0xc38b202a9e60f7d4L,0x2bbf6b179336116cL,
        0x2f9aa8772e068f13L },
      { 0xf8820627a4bac9fdL,0x2209cb9e8a593cb4L,0xaa78ec63c7417931L,
        0x42d212517cfccfbfL } },
    /* 2 << 77 */
    { { 0x40cee5ae3e611940L,0x4e2d9ea90aa090ecL,0x73d167ef1b926e42L,
        0x7fff36df5d5112a3L },
      { 0x25587745caffa3fbL,0x224f7f4ec5a83504L,0x5ceff0183b47bf2aL,
        0xed9bfa73ecfab5c6L } },
    /* 3 << 77 */
    { { 0xf3d570b8d9b429c9L,0x69460116c5ad81cbL,0x30833a082f6825bdL,
        0xa297122a7c99f36aL },
      { 0x6fc9b84805c3abdfL,0xefe952985f2e24b2L,0xf045275a8915d922L,
        0x79146aab298a9726L } },
    /* 4 << 77 */
    { { 0x0c7d59054f831d0bL,0xfaaaa26c2d47d4feL,0x5ac2859985042e12L,
        0x7eda370b7796977dL },
      { 0x9f0bd71d95c0be63L,0x7c4601bc8e821005L,0xf1ecbc604c2ffae9L,
        0x7e3efc579b688173L } },
    /* 5 << 77 */
    { { 0x868c672bf4ea7641L,0x4fa90a82d94243dcL,0xbd82913ef5eab489L,
        0xceebc159e966b39dL },
      { 0x31fe4f5f35c51e2bL,0x2fea6ab1c79c1725L,0x5856cd8583afad40L,
        0x7f9609884ca89b88L } },
    /* 6 << 77 */
    { { 0x9d237c2d1ed8fed0L,0x69b4ec804e0c6f10L,0x11f83283e4648395L,
        0x6f4636a7306e152aL },
      { 0xf70fd23a804539b3L,0x4db0903ab3cdb981L,0xe506ae6f6691eb18L,
        0xaa69c7aa1d8e9d9dL } },
    /* 7 << 77 */
    { { 0x540af9503e4e2088L,0x8fab01d595f04e57L,0x51bf909aa8c51a67L,
        0x01299f5efd19beb7L },
      { 0xdf703400b8f15aebL,0x19c709872d890394L,0xf5fcc675203d2d99L,
        0xabbf3f21c3d4ddeaL } },
    /* 8 << 77 */
    { { 0x8348ca15587feffaL,0x585d07407d69e4adL,0x6fbe5619885a0745L,
        0x04ee9ebab10b24ddL },
      { 0x5c27075c0f4c12d7L,0xacf4acdc3c51c605L,0x782fa52bfce336d0L,
        0x6e1d078f483621d2L } },
    /* 9 << 77 */
    { { 0xa2253bfbd4dc3277L,0x3a0143074691bc12L,0x415aa5b2ebdef616L,
        0x1008a44a16fe065bL },
      { 0x4004a90a16dfa94dL,0x0e24f5418464785bL,0xd2715c8988d30ea8L,
        0xaf81a9ff1f05a312L } },
    /* 10 << 77 */
    { { 0x958da4703e8d5eefL,0x09561898d3c80414L,0xba6b731c8bb74691L,
        0x6b7355cd577f2ef9L },
      { 0xd1f416edb8a98efaL,0xd4a1293a11590271L,0x2c4d59344658e9ebL,
        0x51803651d1f15d39L } },
    /* 11 << 77 */
    { { 0x9b9f0c053c95fffeL,0x8f02145131acd6caL,0x5fee2961f9dba549L,
        0x0521797517ea0456L },
      { 0xc0591906d13a6a4aL,0xa7f5ed0290daf370L,0x1f8b7158fc4c304dL,
        0x77016c291b7f0246L } },
    /* 12 << 77 */
    { { 0xc27d18472ea265d2L,0xec0789c62862781eL,0x0a79ac1f5d86a60eL,
        0xe325b563130670a5L },
      { 0xf47944606d33bfeeL,0x126e703eec25bb10L,0xeae22fd3a7bf902fL,
        0x8b2fb28228eef62eL } },
    /* 13 << 77 */
    { { 0xb68de35b059138b4L,0xfc44bf56d46e68e3L,0x71567daaff11f76aL,
        0x9110e8496b17cd2aL },
      { 0x7c4027e369573b93L,0x84ee945a1eb9bf01L,0xa3fadc6d28c26cdbL,
        0x7037a74d575dfc1bL } },
    /* 14 << 77 */
    { { 0x58c96a919b2223ddL,0x912fc79551461b94L,0xc18ced632df3329aL,
        0x79d6f75f88a002d0L },
      { 0x73d7a089f44d3d84L,0x98c78aa78c058073L,0x0ab8b3c7333ae8ffL,
        0xf5a8f5ecebd4e536L } },
    /* 15 << 77 */
    { { 0x2c7df9fd83a5f52bL,0x314fc7c3cc062097L,0x6c3195f8c5a3113cL,
        0xf130cef92c25a629L },
      { 0x10c8cc5b70c8dd70L,0xecb7a35f01cd40d3L,0xfbee538f6fe21c93L,
        0x57ec19592ba12ee8L } },
    /* 16 << 77 */
    { { 0x74387a1bb2b806a8L,0x14efa300bad5d0f4L,0xee7e442123a0e9e4L,
        0x504ae4283b6abdecL },
      { 0xb8c06fcb927b1aacL,0x55e1c85c323b71d3L,0xf47e180f48d6dae1L,
        0x6d80dd63a84cb0b8L } },
    /* 17 << 77 */
    { { 0xf8e07d53d75d7785L,0x3edf19b737614325L,0xf03709b0357946edL,
        0x567d8c0dd12105e7L },
      { 0xecf6abc0a9383b49L,0xfe9c760bcab329a7L,0x425e62fa43928852L,
        0x27945ae06194b51fL } },
    /* 18 << 77 */
    { { 0x756f0f543ee4f7cdL,0x4337ac7b26e4c865L,0xf94596c335b9c3aeL,
        0x066fd3da4d6aa5d2L },
      { 0xce1a5b7e43c8d94cL,0xaed496a8614c0fc2L,0x355e16f52a6d5481L,
        0x8f934639a09d3afeL } },
    /* 19 << 77 */
    { { 0xd170daef2bf2a099L,0x3920d87aae6ee507L,0xbdac1c8e248158e3L,
        0x99033a9a05c54e69L },
      { 0x4513bdf041872197L,0x15634020d3f0f889L,0x76c1855a05d42aa8L,
        0x23079179e8ba47ccL } },
    /* 20 << 77 */
    { { 0xf80b787b728429e6L,0x896b6ea53dd8c4f8L,0x711eef39c7d9fe06L,
        0xfff28d03ebced829L },
      { 0x5d7823b84ad40c88L,0x40a5a1663b112bd4L,0x84230bfa63bce926L,
        0x39d2e6bdbe17e7cdL } },
    /* 21 << 77 */
    { { 0xa772e242ef03ee6cL,0x888bc969fa009e67L,0x0f06ee834893e1f0L,
        0xf28f0d3c6b89e124L },
      { 0xb3e70ef871f5cbc5L,0xff0f7e626cad191eL,0x990697bef028d276L,
        0x144c101c4ad8f830L } },
    /* 22 << 77 */
    { { 0xbcaafb453556d74fL,0xbc216224eb4c7ea0L,0x73ad1043234a62c8L,
        0xa644eb6a2d95ff46L },
      { 0xd545b60a0a3373f8L,0xf7a0572cd4edaa10L,0xa7177049a97a85b4L,
        0x529dbadd7d3ec769L } },
    /* 23 << 77 */
    { { 0xc45610f67822dd37L,0xfad07fab98258666L,0xac27001f87259c1bL,
        0xa9bdc6a91b849745L },
      { 0xc7ee721604c862b1L,0x32c1541e0012f591L,0x8198aadd5a366d79L,
        0x03cd312e68866e1bL } },
    /* 24 << 77 */
    { { 0xa0dbc3819ec64698L,0x770e4d111ef36dd2L,0x01d179158d56bdfdL,
        0xb48153cd75eb9947L },
      { 0xc1d17a54fde98390L,0x0817eaf70fe2d6fcL,0x44a63591a6a704f1L,
        0x9423465f7f554182L } },
    /* 25 << 77 */
    { { 0xc7c23cbd13e0574eL,0x6e06e2cb439941b6L,0xa8aebd2cafa39c79L,
        0x1b859e2bedede735L },
      { 0x2f4857816b4f5465L,0xec3093f0624c81e8L,0xc1f027c1c282644cL,
        0x2f6e990b2b74ab51L } },
    /* 26 << 77 */
    { { 0x9a988d1ced2ea3dfL,0xa3f50efdff39d3dfL,0x418a3627ec1d7614L,
        0xafc1520c3d4fa3e8L },
      { 0x741305af891a9c69L,0xe87064d45d6f8296L,0x47c9394c12307b05L,
        0x6b038acbc35f0f40L } },
    /* 27 << 77 */
    { { 0xa6e776471ccca008L,0x58e4cfb69dd71746L,0xdf649c98c1fe84aeL,
        0x2e308ddc90db4388L },
      { 0xc2641332e9362400L,0x92dd984242d265e5L,0xe0e4ed9b31eb91bdL,
        0x62ec7dd1145535c5L } },
    /* 28 << 77 */
    { { 0x1ff29a09f810812fL,0x56b64acb15e9b102L,0xb5f6d4d45b353184L,
        0xc3c9292c1c593774L },
      { 0x167810362c700292L,0xf0948fc93ae2f0c6L,0x40e353cc4da778eaL,
        0x07febf09a34df03aL } },
    /* 29 << 77 */
    { { 0x349812ae9ec397ffL,0x7c78812f330f02d0L,0xf956700b7d241ea2L,
        0x864b1809ebed08beL },
      { 0xe4cec3dfb9eb1635L,0x7dd65ad6ab49fb60L,0x0655116386788a28L,
        0xda8792d511fb4214L } },
    /* 30 << 77 */
    { { 0x82140df3cec09c3eL,0xcd34ca30539db03fL,0xf07cf030e7dd0e09L,
        0x7b08a24256ae3487L },
      { 0x9c0fd607bf5a6549L,0x0b1fc745d189d68eL,0x0d91be749cf52022L,
        0x6013f31f43ff7fc3L } },
    /* 31 << 77 */
    { { 0x3bf90bd5b5654233L,0xd0a17969202bf534L,0xff373b8bc97e02baL,
        0x4606de54d31dba07L },
      { 0xb045c50a8114562aL,0xc123acac7b8d8915L,0xa8f7cd87b60aa324L,
        0x077cab67abc48200L } },
    /* 32 << 77 */
    { { 0x88a686430d7fff59L,0x82b9219367bfe743L,0x1a8b86cfc2ce06f9L,
        0xa38414a0f9ad6134L },
      { 0x7f10261028e2c39fL,0x34805c20480856a0L,0x1b3f930218c3034dL,
        0x1713f457574c0c9dL } },
    /* 33 << 77 */
    { { 0xd84fa26f690ce2a5L,0xd4cfa19fe01a4637L,0x4807fb82cc6fad47L,
        0xc9d84b48f933226aL },
      { 0x9b7c530e7cd2c9ddL,0x6436a001f44818e3L,0xbae0ceeddfb00461L,
        0xed6a7c5f51c8c8a3L } },
    /* 34 << 77 */
    { { 0xa6e7fa540463ac73L,0xa0deed89c77b19e5L,0x4e0a3396ff218725L,
        0x7cfbbd572edf2704L },
      { 0x8114d0ca4e8608c5L,0xceae65b938c935b7L,0x052b1407330af8fdL,
        0x02e189a1723c422bL } },
    /* 35 << 77 */
    { { 0xf1cd6216657560c8L,0x099eec2fe5068361L,0x68ef58fb3de78037L,
        0x83e0d34ef3e399e9L },
      { 0x3a2a14c8f9a17095L,0xc7a360beaaf9f08aL,0x6420155f30e99527L,
        0x8f6109609f180405L } },
    /* 36 << 77 */
    { { 0x871a832f02bc97feL,0xa14b33268dc7f1f2L,0xc9bd8b4187f78ad1L,
        0xd378d02a0b59b9c5L },
      { 0x418a32a535c0dc14L,0x4c96979df53d85afL,0xb6f40e9708eb4b26L,
        0xa21349cacaa6252fL } },
    /* 37 << 77 */
    { { 0xb13d80625de38e2dL,0x54ea36849b43c5d6L,0xc0ad58d7b1d6521dL,
        0x182f882322085236L },
      { 0x9d50cecc2a08449eL,0xeb85e78517ab0b68L,0xb8a22ab78d74e26bL,
        0x7751552477d03987L } },
    /* 38 << 77 */
    { { 0x117a63f277ad71deL,0x1cca30d0c94c8c82L,0xe5fefba92f05382dL,
        0xcc9e89169b4b42f1L },
      { 0xbe939e139fe716c1L,0xbf2b9c8095e38cc2L,0xf60c449137adde62L,
        0x3eb3338af4df75a3L } },
    /* 39 << 77 */
    { { 0x16398af3fe4d84dfL,0xed752cf8faf3e5f2L,0x746a4339b4cf0e1cL,
        0xb8bd479a39fb6018L },
      { 0x3a9a045b57dffed3L,0x2b46ea98a5ae3c78L,0x74b5163fde6b0399L,
        0x069628a080e511c5L } },
    /* 40 << 77 */
    { { 0x19cfc8821b96672bL,0x2759c76b379d1f57L,0xa6cc7a982269a514L,
        0x1bc2015b683b1413L },
      { 0xc43b11781bf4be62L,0xd29419757bf2b0beL,0x1eac3587c4591cfdL,
        0x283169e60e66d495L } },
    /* 41 << 77 */
    { { 0xd39bedb7052352e1L,0xb04af7f2d719cd43L,0x702143d4e92956d7L,
        0x53498722a0e5b847L },
      { 0xf0e8edc5574885fbL,0x4d9418ac8b5187c6L,0x70e99cb3d2a00019L,
        0xf0da5be4e7f8a61bL } },
    /* 42 << 77 */
    { { 0x52704cbe7dd34fdeL,0x0fb7224a2926bb6aL,0x0d58bdddf2b0af92L,
        0x2f986a070e9cad36L },
      { 0xc85549d480e3a6f9L,0xa013e913322cb14cL,0x8a19cf30f25ac201L,
        0x130e4ce0ffb8f2e4L } },
    /* 43 << 77 */
    { { 0x21ad2c8c0ce56c13L,0x13ed2106b15f6a2fL,0xa217b5f69453ce96L,
        0x93b1cdc764e0bf9cL },
      { 0x753d894dc4fe8e72L,0x46c6cea3f3a3916aL,0xc1fb78e1383dd581L,
        0x1b7ba1a917376a3eL } },
    /* 44 << 77 */
    { { 0xa14112875df66852L,0x4e9d333ca30445d3L,0xb5a26c14917568a9L,
        0x885f1857e857a6acL },
      { 0x05fbd3ee84b1f8cfL,0x5c1f40971e81e4e1L,0x43999be4011f30e6L,
        0xa8aab3bda890719dL } },
    /* 45 << 77 */
    { { 0x49d598cec7088eb2L,0x7a892468e341047cL,0x8e69b5c407cb6075L,
        0x83d066fd8c37dc04L },
      { 0x4fcc6d026ffff7acL,0x1afaaf747edfb968L,0x2972b75370d529deL,
        0xf65bff0d08218b2eL } },
    /* 46 << 77 */
    { { 0x119b3c4b4182b9fcL,0xcab6659127b5e101L,0xfff2e9392ab87a02L,
        0x1c10c40deec5949bL },
      { 0x9836622430aa1242L,0x833e9deef225a4e7L,0x07f1cfec992e8475L,
        0x377a9d791ef83a8aL } },
    /* 47 << 77 */
    { { 0xaf1d0863c6715544L,0x34dd65c11fd71505L,0x74d55c2204fed293L,
        0x31b1e50e86d2f3beL },
      { 0x876148b9c09594acL,0x73aace3b8900b56eL,0x4617258aa2cf4c37L,
        0x554e8f16c6f38a92L } },
    /* 48 << 77 */
    { { 0xd8594800da0723bcL,0x524452dff3c8381dL,0x846dfa02138ca980L,
        0xaa77a80ce2d32e56L },
      { 0x27573fbc419c86b5L,0xe7486807b70216c3L,0x8b7a685ac72036e6L,
        0xa176462715fae3d8L } },
    /* 49 << 77 */
    { { 0x0a1f2361815f379cL,0x9811607e01ab64d2L,0x31841038ff2c75cdL,
        0x8751674e474982aaL },
      { 0x2f32b55b52a2523fL,0x6ff8d2a7e85f2025L,0xd2ec31ee707b2dcbL,
        0xdac81e596e277971L } },
    /* 50 << 77 */
    { { 0x5445e3a20e78191bL,0x134dba0b8c80db2fL,0xe9925a8794002b55L,
        0xe56fa2be4293c71dL },
      { 0x72aca4d2a9d009c2L,0x0c1219dd02fb0741L,0x689fbc66208fd227L,
        0x8266f2f7e4bb09d8L } },
    /* 51 << 77 */
    { { 0x1a791f9b2a61b8bbL,0xb29b31b73eff4f21L,0x2f97803aab7812dbL,
        0xdbf27bae880ceb4cL },
      { 0xecb8488745e9db5bL,0x3dfd84e15cb7d0ecL,0xc89f61c277c0b1e0L,
        0x7ada1d37b7656544L } },
    /* 52 << 77 */
    { { 0x0bca9585910a966cL,0x80385b476f12c20cL,0xf63a1605a4b30374L,
        0x2f91b24c104b4783L },
      { 0x9210f5b9b3ab423fL,0xb9aa656d2fd424a6L,0x63c615d5f7e8d640L,
        0xd567ff98bb59cfecL } },
    /* 53 << 77 */
    { { 0x78121697f7692947L,0xb9166739bd9f5ed5L,0x58d9a4f4b64b20e2L,
        0x291898d9c9fcc93cL },
      { 0xbce6509ed6c6065aL,0x39af658fb84834a4L,0x0f919d4494b49185L,
        0x3b80fc515dbe7308L } },
    /* 54 << 77 */
    { { 0xb9fd8ae4e321c228L,0x4a46bd2d360692baL,0x91d5396ed05b84b0L,
        0x266e89fdd6b058d0L },
      { 0x6fb142d7b2c42e38L,0x93c9fe18994ebc2fL,0x90e17885104b04a3L,
        0x6a5fa420654eb6acL } },
    /* 55 << 77 */
    { { 0x26c8a9b43f349b26L,0x39387f7eb4e528aeL,0xa74bea435eb46726L,
        0x0b3e82dc9150b043L },
      { 0xc69ffac9e2fc799fL,0xd047969748921338L,0x91a682640a4e061bL,
        0x93a6c41e3f410bccL } },
    /* 56 << 77 */
    { { 0xaea8d0556b1fb104L,0x2ff339a431fe146fL,0x3d7ef85bcf63c413L,
        0x1f0f57c5289a097bL },
      { 0x82f2f83b5bda1160L,0x433eea4d6fea66e8L,0x1f3fff4fcae11651L,
        0xfa71c3fd6b1c243bL } },
    /* 57 << 77 */
    { { 0x59f36add674832a4L,0x7b6d38022891e4e6L,0x47b313bc084fa3c6L,
        0x90003ac66584c9c0L },
      { 0x9718c2ddbc802849L,0x9a5a26982870ca08L,0xb5cfe625cf68f352L,
        0x90d0e2ed6e6b0caaL } },
    /* 58 << 77 */
    { { 0xb30780c3ba64d50bL,0x163283457acb4fcaL,0xf64e01fd84b258deL,
        0x2a25873e35dcd2f1L },
      { 0x36606813ce4b39daL,0x5285c91ea69a93e3L,0x4da13aaadcb501d6L,
        0xb90d0a5252e3dc24L } },
    /* 59 << 77 */
    { { 0x6882d15e60a57d0fL,0x52142caf167612feL,0x532ccfb1463d39ccL,
        0xcdecde85e5a969f3L },
      { 0xa89c1d1dd1bc4480L,0x9373f36283f32199L,0x42f3493d6d653c44L,
        0xa867e4db6c80e27eL } },
    /* 60 << 77 */
    { { 0x954fbd835cb7623dL,0xba8b30070b83d55cL,0x71946b92e2b23256L,
        0xe0a2a7bffaf95492L },
      { 0x32ed3d914e0c81efL,0xb8c8b14c46f058d6L,0xc76c917f67221924L,
        0xd26c1d512ddf3cd4L } },
    /* 61 << 77 */
    { { 0x184e13954fc9b14aL,0x651a0c29c1969b8bL,0x05687179c9d5bf9cL,
        0xb2f18ed1ebcd85b6L },
      { 0x8b662764e446f1efL,0x6c0e051e71699f5aL,0xf94a115127d93da8L,
        0x751235c6a05fe7a4L } },
    /* 62 << 77 */
    { { 0x40aaf88f624e9ae2L,0x6499b3f5f5f6e5c5L,0x01fb0b8e98157f61L,
        0x070438f333827220L },
      { 0x7409012f50ab0b43L,0xdbbba56363c50e65L,0x6b572ca3c0d084adL,
        0xf10f66847b76cd6cL } },
    /* 63 << 77 */
    { { 0x32bcca970c34363bL,0x7a9cef10b40e8157L,0x3d5ffc516eaec234L,
        0x7d7b41a55f23d481L },
      { 0xe5276c22eecdfe73L,0xa9b2725b8ac8c30dL,0xee449588ed0c743bL,
        0x6d3b82a348df73b7L } },
    /* 64 << 77 */
    { { 0xcb52edc2023cb0dfL,0x08773a4dd5a24591L,0x0d9a6aaae12a9072L,
        0x4261f56f5bf5586eL },
      { 0x184b040260a08106L,0x1b398053b09cfa61L,0xdf7f55b1d5dae483L,
        0x9554210e86ef2cdeL } },
    /* 0 << 84 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 84 */
    { { 0x564d6e859204db30L,0x139bb9282aa84cdfL,0x9413d7ea88476456L,
        0x5c5544835a1ffa66L },
      { 0x7b8630892ed18080L,0x589aaf20d14e5dafL,0xeee4f96f7b5f81caL,
        0x88d470071bb0b415L } },
    /* 2 << 84 */
    { { 0x1bb400d355c9bd11L,0x8402465c06fc2851L,0xa81ba22d65063b3eL,
        0xbab2dcbc6e1aa0c6L },
      { 0xe5f43f1abe645e25L,0x623205334df84be1L,0x14ac708021a2eaf4L,
        0x3f94646458beb26fL } },
    /* 3 << 84 */
    { { 0x5f2a3e9a7a82d20fL,0x399e015c191011f2L,0xfbec312a886ac8e6L,
        0x0dd5140aeda47f96L },
      { 0x0d4df31326b47318L,0xe2c9ec78e6685ec8L,0x4df119aecd8442cdL,
        0xdb1ca9557b32a1cfL } },
    /* 4 << 84 */
    { { 0x7e2c5852126506ccL,0xba94aac708b3567dL,0x6905cdf4c05a3f24L,
        0xbf5f559b3547f8b3L },
      { 0x9e4b4e62aade7a1dL,0x56b8b9d61fda3088L,0xea3eb4c64c43d89fL,
        0xfb7e537c9c69e047L } },
    /* 5 << 84 */
    { { 0xc23d9491dfe5f6abL,0x42fc362dc1a9c0afL,0x04170b01127d2b35L,
        0x4f0f17bc04116aebL },
      { 0x716c01dfc9184cf6L,0x914dc877895ceae7L,0x696b2ae8390bff2eL,
        0xf6ccd628f88af5dbL } },
    /* 6 << 84 */
    { { 0xdada9bb90f88095aL,0x7155c28f919ce305L,0x32a01e476d78b266L,
        0x6da94459b652c4f8L },
      { 0xa31783a6827ea8efL,0x4d69b7c6bdb1af2bL,0x2874eb38af31dab9L,
        0xa0ed9910afd9baceL } },
    /* 7 << 84 */
    { { 0x7d892e3a4037f17eL,0x81fa98415f91a4faL,0x17c7292d961cf02fL,
        0x35af0c0e388bcc75L },
      { 0x340bec90127a29b0L,0x955714a43d087445L,0xfd430880a587c273L,
        0x715ecd50d24dfda2L } },
    /* 8 << 84 */
    { { 0x4ade066daafd6cefL,0xce59c8def8c1deccL,0x3e12a24a77b96eceL,
        0xee7c32fc44cc710cL },
      { 0x70700e4f240e9bb7L,0x837ada546a63b06eL,0xa58ce980d19644eeL,
        0xcaa5d14d27e7451cL } },
    /* 9 << 84 */
    { { 0x8e78d2ed387272fcL,0x9163a377fd8a0f13L,0x858436bd635c55f0L,
        0x0a414f9b5ba5b0ebL },
      { 0x2b58373a7d7383b1L,0x5e7b9d366030a376L,0x9c69af86543514efL,
        0x044698cc26080ff3L } },
    /* 10 << 84 */
    { { 0x76f54954a2e23074L,0x9039326417526081L,0x0d095055f3b78a50L,
        0x1f3a377669d8b26dL },
      { 0x0575e3bbf5e7c8fbL,0xee7dd406ee40b0c5L,0xe6522e5d55dab556L,
        0x2d1b5709b61cd918L } },
    /* 11 << 84 */
    { { 0x0ea9278e01400b8dL,0x9552e7456464f584L,0x67f5645b12fc094fL,
        0x77c40f3cde303128L },
      { 0x16d7e9a50e3f3381L,0x017795ab59947693L,0xb69b57089222eaf5L,
        0x61b213e01b77f122L } },
    /* 12 << 84 */
    { { 0xa7cc8bbfdc8db00eL,0x1c51f5e43aa7fc1fL,0xb85b782eb4ac2d0cL,
        0x32fde94b0468e5eaL },
      { 0x8ad5b9a27f7ff0a9L,0xcd26f4188fdbb3f9L,0x853bc95d6ebf89dbL,
        0x1da0a323a066b849L } },
    /* 13 << 84 */
    { { 0xc4cc7aab4bce0fa7L,0xd4a05b696bc940f1L,0xc77300e6392dbd11L,
        0x0dc2eac621f70aaeL },
      { 0x9d4b513b4b2ad7e0L,0x19822167a6daee1dL,0x7d71d20269b98eeeL,
        0xdfd435dc35f3f150L } },
    /* 14 << 84 */
    { { 0x66d46ad3ddfd45edL,0xf0325189e50a2f01L,0xe19b95003ec5683dL,
        0xc46ab0a291dd97e9L },
      { 0x74c971d7ed682c4aL,0xafedac2da14da289L,0xd17838fee39ba740L,
        0xeb497bca053536bcL } },
    /* 15 << 84 */
    { { 0x551ba4cade6d4c38L,0xa67be2474f52298bL,0x984131889a5b40a8L,
        0x083a26aabb0acfb5L },
      { 0x4929ff5e11d16ebbL,0x91f08b63a942ae7eL,0xaa428ef3876663ecL,
        0xfaabd3091e97cbb2L } },
    /* 16 << 84 */
    { { 0xca0ed50cf1edd62fL,0xc3c7ae6fd29f48d9L,0xff47bf288a72ae88L,
        0x584ddfe5348c6666L },
      { 0x271137e936731fdfL,0x714bc7db88d98bc8L,0xcea912c10da6be30L,
        0x91cb844dbe62d6a5L } },
    /* 17 << 84 */
    { { 0xe16ca42aec027bfaL,0x0c88f70117603e76L,0x799418e363d5a31aL,
        0x033bb53bebb063f6L },
      { 0xbcd05461625d3909L,0x2d7b786885f23129L,0x23b0788795090997L,
        0x216c08ae18d2c218L } },
    /* 18 << 84 */
    { { 0xe1ccb6c1eebdbcf9L,0x89ca4552e873842eL,0x4837f1373c2fcdd5L,
        0x805874e8108a8c0aL },
      { 0xe7e524f43d442fa7L,0x580d82bef8131f8aL,0x6dcb7d2793d3d50fL,
        0x51207d3eb5b39168L } },
    /* 19 << 84 */
    { { 0x9a3ce11709110fe9L,0x8f3c6e4f48721d93L,0x60a62b4887bdfa61L,
        0x086dac657c01d84aL },
      { 0x4af7878c53841493L,0x3b1a8935b3bd5aa1L,0x65c8445b902e5686L,
        0xde16cfa52e3b1822L } },
    /* 20 << 84 */
    { { 0x19879e780a3e3684L,0xec553912ee249180L,0x8eb73faef8f4c1eeL,
        0xdee59877b81fd20dL },
      { 0x2452e63f20b5ece3L,0x17be9422b632dddbL,0x01f8922094311e6dL,
        0x8f0fe052a332f84fL } },
    /* 21 << 84 */
    { { 0x59657aab1b9784d5L,0x6f2ce032d8a7f347L,0x842477936b95e6e9L,
        0x34301cf44395b044L },
      { 0x98ebfd98f7fb5401L,0x14fd494bfcdb31a4L,0x042f89d8f90e0481L,
        0x6b90a0084134ab52L } },
    /* 22 << 84 */
    { { 0x8fa225557fe2ffecL,0xc6dc3d32a778448fL,0x4886fedb85f45aadL,
        0x5bdef90e51704d0cL },
      { 0x46ad596de2d1fdafL,0x914e009004126f0dL,0x71aaeb18aef960a6L,
        0x8f4601e5ac77472cL } },
    /* 23 << 84 */
    { { 0x42e5a186d8d9768cL,0x8cbf3a6c00f6004fL,0x9d4bf5acc1ddebdcL,
        0x13354792a9c066fbL },
      { 0x72e0b81c923fe808L,0x1e73b868c526d6e4L,0x3f7bedc6a81f1e24L,
        0xed1ff363e920ba24L } },
    /* 24 << 84 */
    { { 0x58234c89659604c5L,0xa6a421adce4b0872L,0x5dc8848acc19578fL,
        0xfcb418d04f28bdfcL },
      { 0xf2e748208d6442f5L,0x0c481d854dcf6378L,0x4987d1a64556438bL,
        0x763593633157c6beL } },
    /* 25 << 84 */
    { { 0x29bbf3b71c1dceefL,0x0995c340576f1dbdL,0x0405db3d8fa61304L,
        0x63438f3dcc7d345eL },
      { 0x688174dd942120e5L,0xc7dd05bdcd70c93cL,0xdc8a32dc5e871ae0L,
        0x1a7896b96178647aL } },
    /* 26 << 84 */
    { { 0x1fc3f7a259c437e3L,0x737de2e324235e5eL,0x589a56e37a5eaabdL,
        0x5a79da8ecca140f3L },
      { 0x3d8b0d82a12463faL,0x63fc83d80875daf5L,0x42a30803bd9211f7L,
        0x62f6167f32d3935fL } },
    /* 27 << 84 */
    { { 0x70cd64676f269922L,0xf694ca2196163b47L,0xf3bafb2d5f5ba669L,
        0xcf7cf341b8ed8333L },
      { 0x34b2022d9997edc2L,0x57e6f4b5309c6508L,0xf6fbf86464841008L,
        0xbc9821f5ed075d44L } },
    /* 28 << 84 */
    { { 0x78c80f73f37cc6b7L,0x41d286266ab88fc2L,0x2126981c58ca26fcL,
        0x7a956c64be3dbf87L },
      { 0x2f41e27dce0ce9f3L,0x0cb49ae0f4c98e5bL,0xba6224a6cace473eL,
        0x25dddbc0393e092fL } },
    /* 29 << 84 */
    { { 0x747daf46a4fb974dL,0xfb775fe7c76dbe2eL,0xb7b3ad6d9670c22eL,
        0xc6580b2310a380bcL },
      { 0x4ea226f592087c3dL,0xe67c379fb53aa3c7L,0x4133f831991c3c9bL,
        0x80f9e5bd4fa0dd18L } },
    /* 30 << 84 */
    { { 0x0094e7c6c6f80fb4L,0x16e99ebc351bebd3L,0xc555ed44aae16a6fL,
        0xe9d2846f2f6367ebL },
      { 0xb34c93d083d46d0fL,0xc0cb137a894fadc6L,0x21e289f8ab31f937L,
        0xac5e05161bc72a35L } },
    /* 31 << 84 */
    { { 0x6221871bf3d4db0dL,0x72d1fdcea039826cL,0x69d9cc8b668c8022L,
        0x0bf359cefee064ffL },
      { 0xb8e636b7e8d16f19L,0xde88f403443160acL,0x4228177a032836eeL,
        0xee8fac37e9801d86L } },
    /* 32 << 84 */
    { { 0x496c93634626e343L,0xf6999578f4e4c8faL,0xce7306f6b8648a06L,
        0xe2775c8cae7996e5L },
      { 0x7b47e678bf09d221L,0xf5251e1e515c2aceL,0x087f912177b48b41L,
        0xc40e7725eb38d74bL } },
    /* 33 << 84 */
    { { 0x1d559f4ace95134aL,0x1048a1bc320c8bc6L,0xad2ddaf8e3085f1bL,
        0xf1cfc4cb0ad35636L },
      { 0x2bd8d4fb57db1e96L,0xd1813026e1976ab7L,0xa80e501c15867022L,
        0xecaf149701f68017L } },
    /* 34 << 84 */
    { { 0xd82c5e7948ab68b7L,0xa0f117e4204d2962L,0x99b3bda17dedbf05L,
        0xb872dbff52786ecdL },
      { 0x56253c3257592d3cL,0x495fbb054d570c07L,0x073c49cbfaecad3eL,
        0xec8c1f57b46bad46L } },
    /* 35 << 84 */
    { { 0x13800a76ce3b07c7L,0x9bbf87d70ffaec55L,0xf69a9ee3af2426c3L,
        0x2d0c201f2fd70c22L },
      { 0x957e5be1c42bb661L,0x3e6ae19d1dc771dfL,0x60af970de3cfafa7L,
        0x721ce8695ebd1883L } },
    /* 36 << 84 */
    { { 0xab0a80a5b87d0edeL,0x33576f022954a3e3L,0xcc2fe8c0c413fc00L,
        0x5ae762bdeb86a18bL },
      { 0xbc309dde3fe6c6dcL,0xb4f9d001bf0d1eb5L,0xf3f3c5b9d4fa748cL,
        0x78e8867f2ca78fddL } },
    /* 37 << 84 */
    { { 0x8f85f872cdf1624bL,0xfdce003ba7db0248L,0x0ad33ef71ad9866bL,
        0x27d12937296248a4L },
      { 0x23bf35ebc99c656aL,0xcfb64da217753aceL,0x8bc0e7416fbf7969L,
        0x131018efe719cff9L } },
    /* 38 << 84 */
    { { 0x98f4ef66d1c02b67L,0xe8aa6cdb1f81f578L,0xa6f97fb3159469deL,
        0xf8e834cde3906d9eL },
      { 0x33ccda6d71bbd3d1L,0xeac76a4af952c038L,0x2891eaa0e5b53383L,
        0xd629dbddedcf6de7L } },
    /* 39 << 84 */
    { { 0x4af093cda3fb0fa1L,0x130fd0570d1ea294L,0xb553cb13b57747bfL,
        0x107c0f0e024e856bL },
      { 0xfd63a2ffbd631fefL,0x8df62ec212c01222L,0xacbce197c0af11a9L,
        0x35fa3e805c4922b5L } },
    /* 40 << 84 */
    { { 0xbc257ccfc3de57baL,0xb481ca1c293ad2dfL,0xb123f3bb2058e222L,
        0x219cde82efe46989L },
      { 0x58ac87b8e9a316daL,0xa8294237d4d25c91L,0xb54dad8862d14158L,
        0x9250885fb3da2a84L } },
    /* 41 << 84 */
    { { 0xb4e3bedfd54776bdL,0x81a4c58278043ee5L,0x279a09634eb87133L,
        0x827d333cf2bfdb52L },
      { 0x3601c6d1ed71e119L,0x3d9b17720d64df1dL,0x2f5bcc093fa3c40eL,
        0x74b7b30d8e26aef5L } },
    /* 42 << 84 */
    { { 0x98fd949b3d3ac848L,0xd99e99d092e259f1L,0x344042658d353c77L,
        0xffc05a7d4d8dfb1fL },
      { 0xbaf2f4714e9d92c9L,0xf354f8b25ea9cef3L,0xf2be0feab8b2c8a0L,
        0xa392d3e3fbce308fL } },
    /* 43 << 84 */
    { { 0x58cd793d02619258L,0x16a8c9e7fea6eaccL,0x3fcae1edb90f9cb5L,
        0x1df76d07d59bc4ceL },
      { 0x392482178574a3ceL,0x9d0df2b703b6e82eL,0x64227c0f33206733L,
        0xb909614fb342da7dL } },
    /* 44 << 84 */
    { { 0xe46e977fb8e15a20L,0xdf2aa89d744eaa18L,0xa40b36b77ff12f89L,
        0xbf7ed78886b0e7d4L },
      { 0x35930c5c9e044a5bL,0x599cfa2b4ac6b8a0L,0x68f5f40da8f06839L,
        0xe838649be8a1b9d5L } },
    /* 45 << 84 */
    { { 0x2e3c91a9dd45fedaL,0x5f73aa3858de0625L,0xcc2b23977535cddcL,
        0x60e69d0bca7825faL },
      { 0x8f1a95c462424bd7L,0x5e175a13f6f21e23L,0x594e5b824fa48b20L,
        0x2bfed2049b14fed3L } },
    /* 46 << 84 */
    { { 0x87c925fc74484bc3L,0x052b634f5639abc5L,0x169549b6290426dcL,
        0xfe515a22daaefd38L },
      { 0x8a63a39cb4d87ccbL,0x3dec5f624034acdcL,0x59969d8161090db0L,
        0xb089b8f7f157248dL } },
    /* 47 << 84 */
    { { 0x42b0ca549d59a29fL,0x522b3e3e9be7ee82L,0x894aade2ac166a7eL,
        0x57aaf19a9184ec33L },
      { 0x84406a115e50711aL,0x0cafd1481614f8d3L,0xc6174fdc3f7d19f8L,
        0xca5bed9aff4958beL } },
    /* 48 << 84 */
    { { 0x8dc18aaae4fdd396L,0xf6e8a9eed371c3f4L,0xc6b58042a5dfefdeL,
        0xccc3bbb6fc4f3577L },
      { 0x9f583e4adedfdd55L,0x9ea45133b48c5fb2L,0xca2b3229232d61e0L,
        0x642101a8b0b5cb38L } },
    /* 49 << 84 */
    { { 0x0cfac5fca9ebda1aL,0x02398bd6d2dc9c7cL,0xd95511d980591234L,
        0x0e5cc99ce8230901L },
      { 0x943350f6140eaba1L,0x9fe19108e0623c93L,0x052bf5d9d74e189bL,
        0x3e341bff40cd7173L } },
    /* 50 << 84 */
    { { 0x89b5b355cb7d384dL,0xedee32da50b76f18L,0x6a9cfb195804d9dfL,
        0xccf638f8376fc2d8L },
      { 0xebdce7a5e14de014L,0x0135085f7f606fa5L,0xf8a3de5f69b58c3bL,
        0xbaa8044559ca19d1L } },
    /* 51 << 84 */
    { { 0x3252147d0ce7238dL,0xd446960bd57bc36fL,0x9b1743ceb275f5caL,
        0xda048c4827629de8L },
      { 0x005354dbd3bbac67L,0x62c392fb1ba1faccL,0xb066bfaea18da892L,
        0xdb090711367a8320L } },
    /* 52 << 84 */
    { { 0xbb7092e26f90249aL,0x6de14155e22da86bL,0xe16136d3b38d4ad8L,
        0x9deaa5c9d0fbb940L },
      { 0x54a54ba3aacf50e3L,0x66e5645ab9ba4570L,0x77e28d9448cb742aL,
        0xc795b138ed98a2c9L } },
    /* 53 << 84 */
    { { 0x899331f61daa17eeL,0xac9506534a77734fL,0xd7f6304f71f3e3b6L,
        0xe725695565fc119cL },
      { 0x3e60a04cbe527794L,0xdaf53be47c578fb0L,0xf785a4f8ebc0754bL,
        0x8b21b116de1b78b4L } },
    /* 54 << 84 */
    { { 0xfe47e04f62fb1c56L,0x8a92f9e6229f1017L,0x2d73dd2368b7842cL,
        0x3b43f7dca56dbc4fL },
      { 0x9435defed0f3f4caL,0xdabfb1ba500594e3L,0x70e929e8428f5eadL,
        0x44adf585bdc7716eL } },
    /* 55 << 84 */
    { { 0x7b7ff07702204867L,0xf2f306be0c78476cL,0x48849fd57e783793L,
        0xc2dc3c7daf77e3c7L },
      { 0x5eb2b691a980cdf6L,0x7ca7b7a4204e25dfL,0x1e7c2f82c5070eabL,
        0x32ca4b364eb7cd3bL } },
    /* 56 << 84 */
    { { 0x38ffde8ff94ad1abL,0xb4757ae159921b25L,0x856cd3f3b4d2f624L,
        0x905939291eb40708L },
      { 0xffc4b89a1193b3e4L,0x6afba7a8bd2f804fL,0x72aabbaa69dc21edL,
        0x5d1da32ee7fb6de1L } },
    /* 57 << 84 */
    { { 0x56c0f44098d1e26bL,0x9456a6c3f7cc7d6cL,0x9eb0aebb14f2f24dL,
        0x51d7c6997dd788a5L },
      { 0x053b809846a22e97L,0x27d8ea2a8c025be8L,0xe0bd464a10d5afaaL,
        0x137c452de7cf120cL } },
    /* 58 << 84 */
    { { 0xd06bd227d091397bL,0x4b307bf321bc796fL,0x701eaf3a7f5a37b0L,
        0x8d5a0f61ac7d4718L },
      { 0x0cf9eea3ed8b1a37L,0x10854f102aa9061cL,0x0aaf430ca30eb4e6L,
        0xb74342f52a050dfbL } },
    /* 59 << 84 */
    { { 0x2feee9d720e1899fL,0x49464a8ef2a1dbfcL,0x4d7cf25e5762d68eL,
        0xe7b6e7597bf43462L },
      { 0x71fce28479daf6e0L,0x2d3ff71f03858705L,0x07d8d288bc4af4e6L,
        0x6777d19718f1c7d4L } },
    /* 60 << 84 */
    { { 0xb57700410e85f036L,0xe1bb263e4c8d9768L,0x4fcc1d44e3917798L,
        0x274d1d9007abcde4L },
      { 0xc9b8ae9fb7a10472L,0x6632e3be8d10e8ecL,0xb6876fb050f3a172L,
        0x753692d4b4cf4867L } },
    /* 61 << 84 */
    { { 0xfe3624e658e598f7L,0x15f904186d81fb40L,0xae762f7b9bea3649L,
        0xc48d2262161e85cbL },
      { 0x8e8726a1cf5a21f0L,0x536c441fa1f6653bL,0x0716bad067ec5b86L,
        0xa423a957b2147d1fL } },
    /* 62 << 84 */
    { { 0x8eec96c8dca2e393L,0x3619e36d2843ef12L,0xdc16fe2d2ef695e1L,
        0x04ed2cadffea8124L },
      { 0x5018a0ce180ce636L,0xc34b0bbfdce7b2f8L,0x645a02a90c54fc30L,
        0x6ee6772bf3f819d9L } },
    /* 63 << 84 */
    { { 0xe2bbbdcd7cecded6L,0x9ae4fd553f038851L,0xc30664aba2f316c7L,
        0x3cccf4a163ffb50aL },
      { 0xc37ee6cad00fb8f2L,0x593db6d5ad906eb1L,0x8f75b5944aa84505L,
        0xeff39d829e5939f0L } },
    /* 64 << 84 */
    { { 0x4b7fab3cc064f530L,0x731153aede175892L,0x335e65033d4c4e60L,
        0xb0876a8a776ce13aL },
      { 0xa8a566ee22241ecdL,0xb7456b3e011e861cL,0xa9aff4eb177dd490L,
        0x189b1ed9c8f77c40L } },
    /* 0 << 91 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 91 */
    { { 0x624de6872857a1fcL,0xbd0a0d9c2ff8f505L,0xeecb4fadc381bc9aL,
        0x72386292fa94e41bL },
      { 0x354d3f83e75fc753L,0x06afc753a7a5a6bfL,0x1ce792eeb2f568dcL,
        0xc5faaee3bd2f9647L } },
    /* 2 << 91 */
    { { 0x175fbeb0f912b74fL,0x45fbe8e16e0ceeddL,0xf0e1aa68d9233ee7L,
        0xe55fc1ce406a626eL },
      { 0x20efa1b9e08712e7L,0x5fd108b5bcfd6360L,0xea431df6eec1edacL,
        0xae1c0521940803f1L } },
    /* 3 << 91 */
    { { 0x584a16d015407ffeL,0xa977f70208a82a69L,0x52eefecf67f8a198L,
        0xec21373819f7a7e0L },
      { 0x6795cfef35987b9aL,0xb243403b97028480L,0xac24b12b9c1b9124L,
        0x1f379501a90f8aebL } },
    /* 4 << 91 */
    { { 0xa8e97fb664bc0f09L,0x0b913991c953cd08L,0x8385a1b37fc3bf00L,
        0xb6e74decb09ccd8fL },
      { 0x6e1df026ec473ea7L,0xf2f7fbbe530766bdL,0xf18cb47a3292052bL,
        0x7f8d45929114866aL } },
    /* 5 << 91 */
    { { 0xf0a1c5658bfa2c22L,0xc28518c32b326c0eL,0xabafc6f0ec107d66L,
        0xbc7a6abf8478907aL },
      { 0x8c1c8f6aa2920288L,0x6c87579d930c043eL,0x25ee808db309696dL,
        0x433bbbdab7a71041L } },
    /* 6 << 91 */
    { { 0x48d6d957b3086691L,0x9946a29b26640916L,0x932ca93c43db59a9L,
        0xaa61a0c5e4fe91baL },
      { 0x9e22e112815bf003L,0xa9ed1b18c86ba8d3L,0x1b5d3c141069f434L,
        0x3cd2ebd01cc01754L } },
    /* 7 << 91 */
    { { 0x5c06b2443350f670L,0x7557dc9df6f9c751L,0xa7ebd3b8de66fd97L,
        0xc126dbaa2befe6feL },
      { 0x312f4897396f434aL,0xe05cfcd661a4124dL,0xc83b86881525c05eL,
        0x4646dbf211899f64L } },
    /* 8 << 91 */
    { { 0x2b7507cb8e419e08L,0x785328d7af855eecL,0x875db0c77b8683a5L,
        0x3d1bc96890a597e9L },
      { 0x7d4afa1047eeeab4L,0x2668dd43d680ca71L,0xc3210d1f17365023L,
        0xd5bb2ee417fb31ccL } },
    /* 9 << 91 */
    { { 0xbefb6a4f08e9ba09L,0xc6beedb8b0c1b6e1L,0x59daf0573510ef35L,
        0x604047cfdbbabc65L },
      { 0xfabc80a8a06b7340L,0x7433dee7df765977L,0x149a2c4afd807cfbL,
        0x14e8ad3b3480a086L } },
    /* 10 << 91 */
    { { 0xb0c3156fb22c5f89L,0xd10ece4abf78675aL,0xe270e31780b8ad9fL,
        0xfe7a6210b0c2b420L },
      { 0xf091d738125ef635L,0xf1f277d6c1a6f202L,0xe2727e7b3587d9bbL,
        0x83b209a9b3e2b84bL } },
    /* 11 << 91 */
    { { 0xc9eb445d7a13effaL,0x89b856f10d697480L,0x834bbae225c03cb7L,
        0x0d8adb85e0b4a7b2L },
      { 0x7b6884afc7fbc240L,0x6b485409aa4f9097L,0x4d0a367f290c106fL,
        0xab87d2183f0efdfdL } },
    /* 12 << 91 */
    { { 0x15b9bab750f2b65bL,0xa7403d4b5e5d53e4L,0x2e23e37628529212L,
        0x6fe903a26e050767L },
      { 0x4c5291a16cf570fbL,0x4bfb86077a30b326L,0xec4905f827c572a9L,
        0x72eeb8c90f381c31L } },
    /* 13 << 91 */
    { { 0x33346cec460adca0L,0xd4d5bba87b34756aL,0x02b2e2d4eac84addL,
        0xa129845bdc1053b5L },
      { 0x53f067e0dca6f9ceL,0x6e9998ed3526aba6L,0xa4aef9e21c0982daL,
        0xfe5b606e93f5d96fL } },
    /* 14 << 91 */
    { { 0x26b8502e9c14b699L,0xf1bcdca60948a291L,0x73e43a322aefd415L,
        0x7f523357d1e2cfb5L },
      { 0xa60151c097d3fa94L,0x820c0d5872129630L,0xb8f2e1ed5854acf5L,
        0x86d6646c3c656ac3L } },
    /* 15 << 91 */
    { { 0x2284a612bef1d0daL,0x2e7c5f4ea8c8fabaL,0xfd441ae770303ea3L,
        0x9613f3295161cf82L },
      { 0x65a3cc652e19531fL,0x177a277534281f69L,0x0cc692a47c82e094L,
        0x9d62a55bb6f377f0L } },
    /* 16 << 91 */
    { { 0xa24cf6acf96ec2b8L,0xd06747c3a961cc16L,0x57c7001cbd17f0a2L,
        0x5f298db034afe2d6L },
      { 0x51b01ef2df12f671L,0xc01c50665ce712feL,0xac0f403492a74776L,
        0xa3e9934f08d696bdL } },
    /* 17 << 91 */
    { { 0xafb6981ae7daaff8L,0x5f8998d973bdcafcL,0x23ec39e1baf9906cL,
        0x5e248410c999c9c0L },
      { 0xd14c7a8917dad895L,0xfde9d01acbb3f6b9L,0x1d6b26ef5f698f1bL,
        0xc6495cd1f0baff97L } },
    /* 18 << 91 */
    { { 0x5a72dc07587674ecL,0x100f9ff0db09cd65L,0xec0fb71fb30cf6e6L,
        0xf54cb59781066143L },
      { 0x0090e997633857c4L,0x7326ed15da92c5d2L,0x794cd8af47c56e86L,
        0xb272112ff89214c9L } },
    /* 19 << 91 */
    { { 0x379608613445879dL,0xc5e496b0f2fcfc55L,0xfe74e95f6559e153L,
        0x1e18b2b554a772afL },
      { 0xd146980c157c157cL,0x31ee3f25a11d77b5L,0x7762a07d5707db6dL,
        0x00804bcbbd2022b8L } },
    /* 20 << 91 */
    { { 0xdf3f4658d571c59eL,0xc49e7a34cf45c1eeL,0xf401ba3d43972cffL,
        0x146d989ce509c2b6L },
      { 0x7c68d6c8eb72392fL,0xdd048de50658b8e6L,0xc9dc61b79a0aeb72L,
        0x98b080e0b741d644L } },
    /* 21 << 91 */
    { { 0xa6ec0eedb1c5982aL,0x58d283175ebbc26fL,0xac8f1e1e33e5b7dcL,
        0x31e4f65e9d8f9fedL },
      { 0x6c9af383904ad76dL,0xfc38c53c9bdb0517L,0x9ae278ee0e69f85eL,
        0x18b362b7efd9d887L } },
    /* 22 << 91 */
    { { 0x65a5f74b5bbbd3acL,0x41eb4593077bfb4fL,0xb642934b83b38100L,
        0x643ceed7ac1a99bbL },
      { 0x9c27e66dee7cd5f7L,0x2ccf87d56ddbaa6bL,0xd51ca739447b1192L,
        0x7847105395f5f142L } },
    /* 23 << 91 */
    { { 0x915f50cd3a650829L,0xe032bdc5898a6a1cL,0xde8fb4f12d15959fL,
        0x1fc5fc73bad56140L },
      { 0xdafbf2068e60c3c3L,0x4963dc95e428adb5L,0x1538e081d49584fbL,
        0xb34add66bc0e5fa9L } },
    /* 24 << 91 */
    { { 0x404ecf12a7f28b2fL,0x6ddc3ce17fa9c435L,0xda887e3f61ee755eL,
        0x4b5da6618f71280aL },
      { 0xee5a86dfdc79a4cdL,0xd8514b8a99be4d36L,0x674793eacc82c751L,
        0xf3a2123a437aedcdL } },
    /* 25 << 91 */
    { { 0xf825ff37fcd6f027L,0x60a056d8a681a001L,0x92a39248aa92c135L,
        0x61884e23dcd190a7L },
      { 0xec0d142024cc911cL,0xbdb0baae5aa16ad7L,0xf12726b58a1694d7L,
        0x8c7cf113c93673f9L } },
    /* 26 << 91 */
    { { 0x02fb6c697f2edc38L,0xcc4d43042fbe8690L,0x405b2491e89c80d5L,
        0xdef46c763d938bc1L },
      { 0xd92ec0fa2520e3b0L,0x2501cfa31fe2dfdaL,0xe7c5753d1d5c8474L,
        0xc059abc0e6226dcfL } },
    /* 27 << 91 */
    { { 0x2dceefe655a9011dL,0x8799064abbbbef00L,0x7fe944c20b49b5efL,
        0x722bbef0225b21dcL },
      { 0x84687cbbd2bb14afL,0xfc4ab4f09b6f6cafL,0xb7b7bb592c146a52L,
        0xb90d67f21dfea10bL } },
    /* 28 << 91 */
    { { 0xca4ca8c8713e1d30L,0x50cbb994f8a13db8L,0x2bee12b2a5b0e3e5L,
        0xa7c5d6d1e71e19fbL },
      { 0x284424239e0314cdL,0xc95c274666cda5c0L,0xfe52a79a1c5ffd19L,
        0xb93875cc38a0339fL } },
    /* 29 << 91 */
    { { 0x6a94196cb49fb049L,0xbeb1eb4bcc12a38dL,0xbc136771f5e8d167L,
        0xa91e1232d5f8ae87L },
      { 0xb2e812c795172460L,0xc699d376b8f81870L,0x9e4a3b70a8900827L,
        0xe0d4b2f4506c0b29L } },
    /* 30 << 91 */
    { { 0x13b4d1c77246fd96L,0x84ea215833965581L,0x9b9f071b2e53c024L,
        0xcb005908864a1b78L },
      { 0x03daddf53f742c2fL,0xd29230e5df595911L,0x3f7d4e6bca0406a1L,
        0xeb646f66b1db7e47L } },
    /* 31 << 91 */
    { { 0xb896003e590e3107L,0x7a0dc361f754ac01L,0xe877a6f3e63ab0acL,
        0xd43b54f3df60d307L },
      { 0x65ef91ba59cf0addL,0x35e9939318990eb4L,0xc186ab168e46fbf6L,
        0x4c0eb22f8c1eaa91L } },
    /* 32 << 91 */
    { { 0x4599b8941abd31f0L,0xdb34198d9a1da7d3L,0xa8b89523a0f0217dL,
        0x2014cc43e56b884eL },
      { 0x6fb94f8849efd4eeL,0xf1b81710287f4ae0L,0x89d38a9a99fd2debL,
        0x8179277a72b67a53L } },
    /* 33 << 91 */
    { { 0x0ef6ce561a03755bL,0x8dc768f2fcdb3469L,0x0be58a91a21d959dL,
        0xea44861a9b103cd0L },
      { 0x332e86e7808b8a46L,0x9882015c8772c3f8L,0xe6b272fe9f4b5d29L,
        0x0e183a28a29b023bL } },
    /* 34 << 91 */
    { { 0xf2fab88f2286ebf3L,0xb7532cedfce83e6fL,0x17999d7ce0cde4fcL,
        0x7230fd85c1b7668aL },
      { 0x97a57d39ef588309L,0x7e175f28f906f6e7L,0x51f6741372b70bfeL,
        0x2132f5952f82218cL } },
    /* 35 << 91 */
    { { 0x9cc0746e9d8727cbL,0xa2af77fbbba1ec8eL,0xc75aee6031a67cc9L,
        0xaeab9e0f57408325L },
      { 0xf24de697ec34bb89L,0x06b900395d958bdfL,0x6f55222e0603d6ccL,
        0x496537b52eb0b239L } },
    /* 36 << 91 */
    { { 0x083e58898be08323L,0xc573596ef8dc0a78L,0xc3e988fae8901ecaL,
        0x7f7b48f66e350257L },
      { 0xed820567a216e329L,0x55f467378ce989c1L,0x7f48c5f1eeab9441L,
        0x1d3cac1186fe0831L } },
    /* 37 << 91 */
    { { 0xe0364bae408a0306L,0xe8d8aba07a4eb2cbL,0xe548725e1fd7d5daL,
        0x8de04491ed5ed958L },
      { 0x3e75eba261d73977L,0x4f58040055420386L,0x54642fa4d859a690L,
        0x2c905f7e296e336eL } },
    /* 38 << 91 */
    { { 0x4e287e6622e260bcL,0x71a2ec994a28d5bdL,0x5528da21a7c5c3e3L,
        0xae9f6856a49471e0L },
      { 0xdcd8e66b587cd94fL,0x91afbd796c7b7db8L,0xdf2e6625067e3cddL,
        0x15b5a329a6375f59L } },
    /* 39 << 91 */
    { { 0x3b8b3b1db6586c5fL,0xe4d50a77d34f10fbL,0x26cb86f57c3c01f7L,
        0x36e9d3cc8c57e6f7L },
      { 0xaa8e7ce162c6dbaeL,0x7f6b768960d7fae5L,0x519a7659c797ee16L,
        0xa1c7b30eb36a6b1bL } },
    /* 40 << 91 */
    { { 0x8da05ba674dff201L,0xd2eac07f40d0a835L,0x2701eb31610a7d6fL,
        0x5c17a91ebf893c4fL },
      { 0x68b92e886bc8b161L,0xa312fd5bf52e6ec0L,0xf7daf4606b7952cfL,
        0x847f0cf318aeb57aL } },
    /* 41 << 91 */
    { { 0x27b178edb0146708L,0x85a2355454ca2aa5L,0x80dd123c395a7b16L,
        0x64a9337b0058bfceL },
      { 0xf6ae9380f4addc4aL,0x0f84385a464536f1L,0x41fc227016534f6cL,
        0x13d8976fb8795ec3L } },
    /* 42 << 91 */
    { { 0x2e90b3e48e12c560L,0x242a86ec239b2c58L,0x6fb42ecc0768275cL,
        0xee341cd0bd96de9eL },
      { 0xfd1833ac84355d11L,0xf062392c5f55ec6cL,0x6ee7b59bfee33fbaL,
        0x8113f0caabf86e0fL } },
    /* 43 << 91 */
    { { 0x2285aaafcc68033cL,0x850b732b78430646L,0x50fa4b612b3fa03dL,
        0x4d893ecc3caf050dL },
      { 0x454764e6988df419L,0x055d8a4bfb61f1a4L,0x3b7c5f4b8475e07aL,
        0xf93a198ba6a228e4L } },
    /* 44 << 91 */
    { { 0xe0a8ce61ec8d566aL,0xe41397d6c55f4bd6L,0x4cc18d48654bdf55L,
        0xe1b49f9e9325ac25L },
      { 0x7984075272c68871L,0x8930d8b56d806fe8L,0x11c8b5a80bd5f65eL,
        0xe931c025bf37d7a8L } },
    /* 45 << 91 */
    { { 0x25b17fd9ae8af083L,0xd589fd8bde4215edL,0x56378f044b3f61fdL,
        0xf0f392136bfb4f9aL },
      { 0x6b0f9596e906cc6aL,0x441f13da096f8296L,0x08f933d41e4940e0L,
        0x6c35391c5a53e7eeL } },
    /* 46 << 91 */
    { { 0x5f41c4d319c3d18eL,0xc0804e091d389d95L,0x7323a9ab18a5a3f2L,
        0x7b7c2475410a6381L },
      { 0xd362eb9ab02cfe18L,0x79ef3d0a553b2970L,0x371f77603d2acdabL,
        0x6cd378907f241dfdL } },
    /* 47 << 91 */
    { { 0x592a242edf4a28e4L,0x1e623cdc1bb45217L,0x5a9633a6494074d3L,
        0x81b74307d52fbfd8L },
      { 0x98292651dec4c5ffL,0xe1b7bc863e0f6edfL,0x3d5fd86a6bb8fb31L,
        0xa830e9a21cf29f19L } },
    /* 48 << 91 */
    { { 0xfffc5482cf69c747L,0x7748a0f4a83549fdL,0xba1c8a0de7ccf4a6L,
        0x6cd1399aa2ede6b7L },
      { 0x8fb634e687bb90d9L,0xfa8e659bc59a5304L,0xcd6bfc75a9122d95L,
        0xdb107defdfa6d75aL } },
    /* 49 << 91 */
    { { 0xb0ec4cfccc27760aL,0xf24c1e22bed3a1a1L,0x4f8522a1819bffc7L,
        0x263c7b5ba93d97e1L },
      { 0xab1d31e0a4b4de49L,0x374e968bebbfe8f5L,0xe82e975651ca0d08L,
        0xc05715a27df3f2dfL } },
    /* 50 << 91 */
    { { 0x941f02c5038004adL,0xc136a2a5a0fd46d4L,0x85db7d243d31d26cL,
        0x05bba6afbfefeeccL },
      { 0xf803b5395a60aebfL,0x9bb8a479813d0e6dL,0xb689c813066abdfbL,
        0xd93b3f4b0072e530L } },
    /* 51 << 91 */
    { { 0x242140a4987446adL,0x40b3f70906a02f0cL,0x33f9bf20a0fd6018L,
        0x58517c18f21abfdcL },
      { 0xa33dc5dbc1f80f3fL,0xbb7dfe277ec91c80L,0xd2cf93388ca97dd8L,
        0x5761f87132e43d44L } },
    /* 52 << 91 */
    { { 0x3c8ffb0ee513ea90L,0x91ecda3679bcdeccL,0xdad3fdd59b1a5514L,
        0x8fb630f9640d3af0L },
      { 0x82949b09f9d2e0beL,0x079ca0ffeba23663L,0x51e62c53135238d4L,
        0xf5fa0c61c446bd67L } },
    /* 53 << 91 */
    { { 0x19dcdd2fe8da43d6L,0x46fbf7ea95f29b5bL,0x7f3eaa05635e8388L,
        0x5ef817c35369750bL },
      { 0x06025893c860c4aaL,0xa2f6684d5551c9efL,0xd6af67dcfbc0c667L,
        0xfd8d7394cd2fe44bL } },
    /* 54 << 91 */
    { { 0x011968ae302a17ccL,0x2206ff24c3e5a5cbL,0x4c7f0df3a20dbfb7L,
        0x59566376a395dd6fL },
      { 0x68ff3d9f373ea76bL,0x2394f93af6cf8adaL,0x3acc5dbae7514a94L,
        0x0340da7a5ddfa11bL } },
    /* 55 << 91 */
    { { 0xc3f030221a05155dL,0x6cbbdc6b4f7656c0L,0x6e30dbdd0b0875f5L,
        0x5e7c28833471b0d5L },
      { 0x49cfd71c408b4bc8L,0xd29a184ef01c002bL,0x308be85cff415b0fL,
        0x1b4176f001a8fe7dL } },
    /* 56 << 91 */
    { { 0xb850acc70c33bed3L,0x76aac64023af7af0L,0x049187ee21d5853fL,
        0x44fbf6e56620195cL },
      { 0xf0abf14b36158178L,0x9866ffca90e419c2L,0x7522e2779e8523a8L,
        0x2f2590f308e90f1dL } },
    /* 57 << 91 */
    { { 0xde1c0c5266d3f75bL,0x47dc9ceb6c299b57L,0x4ad1284751f7f2b5L,
        0xeedf9d8d452b07a5L },
      { 0x207b06273dad76c6L,0xccbb52015d4c0280L,0x0bdca05bb019ae8dL,
        0xb5f8d088f2da7eb4L } },
    /* 58 << 91 */
    { { 0x4e79a0be4626c00cL,0xf6fdd64f5af82c0fL,0x7a8282245f7cba0fL,
        0xc2214834b0765493L },
      { 0x5b0d0d1aabd53ccfL,0x3b03a22df4a1b517L,0xb235c8626ece453eL,
        0xf43ac344f66471c7L } },
    /* 59 << 91 */
    { { 0xeaff93dda1552fa5L,0xef1b40dccf3ae702L,0x35ced3fd9ca613a4L,
        0x90e350aba2f33a0dL },
      { 0x47bb89aa002b5738L,0xafc01bba032b8b08L,0x688ae11961588b4bL,
        0xdb7d820acf66ef14L } },
    /* 60 << 91 */
    { { 0x83b654db084910bfL,0xbb581f8b60ea75a1L,0x6917f2821cdae7c4L,
        0xb719f931a40a07c3L },
      { 0xf8efb8b931297b3bL,0x74246ded4d6fc5c6L,0x5a111754d2c61503L,
        0xf64d2b8871654764L } },
    /* 61 << 91 */
    { { 0x4b4526926ad8f168L,0x907beb210cc6fc91L,0xe876d523bf13c18bL,
        0x4d28e4574cf37ca1L },
      { 0x4c0dc22d6d3d1172L,0x7935a8d25a753137L,0x03484e3dda44d652L,
        0x05a3d80fc50025a9L } },
    /* 62 << 91 */
    { { 0x6d43c503ff477c6dL,0x35f4c4cf1ccd416aL,0x7070f471d5088349L,
        0x678460ca281d30c8L },
      { 0x8923cd9ac6defb33L,0x44930f56e2557cabL,0x33b020bbad156c4aL,
        0xfdab31e3bcaf4805L } },
    /* 63 << 91 */
    { { 0xffe79bec864b5564L,0x0510e35210c60d52L,0x66203aaf328a652eL,
        0x9d5403bf54fea042L },
      { 0xb3fe67436e5e5c7cL,0x6deef667ecc66e02L,0x199ee15244eacacbL,
        0x9f49fcd4d8803fd9L } },
    /* 64 << 91 */
    { { 0xdd5fee9e2d3a6e28L,0x8eed56d4686d8ca3L,0x36889a2778083491L,
        0xea1a6555bef20457L },
      { 0xe7e6b609a501e2a3L,0x1ea0ae29fb23de2fL,0x5f537d07632c9a6bL,
        0x61770d1f9a3db961L } },
    /* 0 << 98 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 98 */
    { { 0x325c60db7497e8a5L,0x05d8eab88c6949a9L,0x3169e466c7bd5898L,
        0xadc06264192d8e3fL },
      { 0x1ff468f4d55959feL,0x97b33ee0202dba19L,0xaa0c3fe221cf84bbL,
        0x48cdc0af04a8d176L } },
    /* 2 << 98 */
    { { 0x53d8c4489c0d4009L,0xd37146172e24dbaaL,0xdd92e7309b62e5f1L,
        0x97b344d79922cc8aL },
      { 0x416b009b0bfe3e8fL,0x56873834f3c82269L,0xf82a980fe6623555L,
        0xb027ecaa5ce68e54L } },
    /* 3 << 98 */
    { { 0x005a4b24fe87680dL,0xd92532dc4cf6ee32L,0xfcd27c8c4bd3e01fL,
        0xda7d9949e1b59ffaL },
      { 0xe3d5f31f2735d373L,0x7e139ca5288e71fbL,0xe474bc8093979cb4L,
        0x7f4f6017f6fcc665L } },
    /* 4 << 98 */
    { { 0xe6982c86fbd613c3L,0xf4af69d5c366f17aL,0x8683eed6b85c2343L,
        0xf5bb244a24bc2116L },
      { 0x997a74bcc9fc77d4L,0xe202eb916f44b54bL,0x77886412a6997e76L,
        0x6996c8fb02c8837eL } },
    /* 5 << 98 */
    { { 0x0986df8a2c61382cL,0x90607b92667c8ee9L,0x051fcbf7084eacdeL,
        0x84e3dba46e685877L },
      { 0x35861a82e458da50L,0xd036823fcf392b51L,0x431814813dd86e74L,
        0x8dcfe17d3741a385L } },
    /* 6 << 98 */
    { { 0x8e1a77cf40f56786L,0xc5bca7f66d4b7774L,0x86b588a0c81ec077L,
        0x88952a019206354fL },
      { 0x5444a98943a8519aL,0xe29dd68c2857b210L,0x366589039a144624L,
        0x8c4dedb0e423e899L } },
    /* 7 << 98 */
    { { 0x482040c5ea886e5cL,0x42fe5a561cdd50f7L,0xf034f132453b6e7fL,
        0xba3fa97db3c69762L },
      { 0x34262560cadb598eL,0x7ed74b5107afe0a8L,0x2261d849ebe0e8bbL,
        0x23747e55608cea1cL } },
    /* 8 << 98 */
    { { 0xb2e9371c902c343dL,0xf57b2de8da4fdba1L,0x43f9afa4b67703a1L,
        0xeafafb41f79fe203L },
      { 0xfec99dc9f649a494L,0x14799ef9fe378232L,0xba3f81147184e31eL,
        0x0abbb815dc0e987fL } },
    /* 9 << 98 */
    { { 0x1dc7221f6fb5d02cL,0xa0dfb11340f1607cL,0xd217f238dbe8db86L,
        0xc02547ebe91f2859L },
      { 0x41df6bcba98d0875L,0xf51a807778f6be54L,0x3ebdf28dba66bef5L,
        0xc65c7b389175ec20L } },
    /* 10 << 98 */
    { { 0x2302981d475589d5L,0xbd479708199d8ad4L,0xcb508be98db46795L,
        0xba1e066e6b224eb4L },
      { 0xae9096331326ab8aL,0xac989728f5bbe5e6L,0x1de663f5b1729b41L,
        0x2018f58c00c3d293L } },
    /* 11 << 98 */
    { { 0xe647c0e671efe25bL,0xaa30f8716104ebd6L,0x1003eebe3c166de6L,
        0x0c3085381cbc42d3L },
      { 0x98b6c31256cba120L,0x9065ae66860d2916L,0x2162062ba7dabb6bL,
        0x1422386b8e011036L } },
    /* 12 << 98 */
    { { 0xd2589ad6e069de1cL,0x3fe8e67a7ee09300L,0x5b8818602f8ae49bL,
        0x186a1482263a6a90L },
      { 0xc6079b399b35b33aL,0x6c38d78953d3411dL,0x743c4462720b2f99L,
        0x4d903dd729e14d08L } },
    /* 13 << 98 */
    { { 0x625dfce07b963913L,0x60a83dafcc65e41fL,0x9e88c26c93e185a2L,
        0x6d950e9213707ac3L },
      { 0xbd7df2dca0a23dd0L,0x5fad27f2c2116cc8L,0x0703b868da4430beL,
        0x5ebf0e2f83cc41dfL } },
    /* 14 << 98 */
    { { 0xebb91900f9e83fc8L,0xf95395916d60bb8aL,0x3bdd7a8bb604935aL,
        0x2cae8c6764e5eec0L },
      { 0x30cf58bb60aaf21dL,0x5e0f6f5d359f63ccL,0xda2450550547e03aL,
        0xa83fd8bbb9e143ceL } },
    /* 15 << 98 */
    { { 0xa564435a1b0215aaL,0xecffccec354ba769L,0xd846149abdbbd594L,
        0x9137df3665dd1597L },
      { 0xc4f39f37a9f3ac33L,0xf594bb74961d7e8dL,0x41fa4b58835befbcL,
        0xa983eae9ed79139eL } },
    /* 16 << 98 */
    { { 0xd4085efcb4e31aa4L,0xc760aec018b26adfL,0x14c1f78e76a7400dL,
        0x87b8aced317fe128L },
      { 0x4433582ecbd85bb4L,0x58f0142686adc041L,0x3596dd508f0d5781L,
        0x2e7f3b801a31a82fL } },
    /* 17 << 98 */
    { { 0xcac7ccc82d1ede3eL,0xc9b9a8f3e89573dbL,0xbf744f6954b40df9L,
        0x88eb2281a85ecb47L },
      { 0x6b115026426ec49dL,0xebda4660c8c41110L,0x0a4a32acdf392aaeL,
        0x2a28f9b337cb7080L } },
    /* 18 << 98 */
    { { 0xfed99d1a6bd9414dL,0x15f59c415715620eL,0x93edd9fcac431919L,
        0xed1d43aee1ccc47fL },
      { 0xafed2acd556d1ab5L,0x817b967d02e039c0L,0x335d15dae02a68bbL,
        0x4fa75ea067df767cL } },
    /* 19 << 98 */
    { { 0x384704b344833943L,0x7809ed3c4084ef35L,0x2abab3c479c7ff41L,
        0x2b7ef5b2a833fb73L },
      { 0x12b0335b4901a4ffL,0x3eea607b44d58617L,0x7161b669d7f57746L,
        0xee17e43fb1e93442L } },
    /* 20 << 98 */
    { { 0x95c9bd80d6d7878cL,0xe1ef20ee34ff7c75L,0x3fab197ad2ccd599L,
        0x9e480593952ef4f9L },
      { 0x69777fd206ea3410L,0xb028045474fa7dd5L,0x641b6860c43bb5fcL,
        0x9f359d5becd7b8a8L } },
    /* 21 << 98 */
    { { 0x4431d4ed70be68cdL,0x712117f408b55f8fL,0x449e131923d0b6caL,
        0x658323ccfdee5357L },
      { 0xa1ef811462879a95L,0xc21257e569963eebL,0x1016ab74c5bbee13L,
        0x99bb310a43d81a86L } },
    /* 22 << 98 */
    { { 0xdef03c441d33a15aL,0x3e78cf1849127148L,0xe8d9336830b0cc00L,
        0xb05458fbbd7ccd85L },
      { 0x8c2896dddbaa76b0L,0x0d82660079e4cacbL,0x50a45b23ff730ed0L,
        0x4a0e079ceba9030eL } },
    /* 23 << 98 */
    { { 0x3ead3fdce3129aa0L,0xa93b39f348aac890L,0x0fd73860f362465eL,
        0x69177f2cf8df2764L },
      { 0x4cd58c50824ebddfL,0x1478981f2fcef01dL,0x511bd380980524b3L,
        0xc95252b14d23e8e9L } },
    /* 24 << 98 */
    { { 0x7ff12c379ce08452L,0x3dd8dd09a3a87024L,0x61ff0d39b849dcb6L,
        0x3f5eab86fefad6deL },
      { 0xb6146886251523f9L,0x45ac1d525be2135bL,0x6350799541d2c5d4L,
        0x7f19f799b3064e72L } },
    /* 25 << 98 */
    { { 0x7280ad9ba2efb9beL,0xbc8fbb60ba9659deL,0xa4861c12875a8062L,
        0x78c920c82f2387caL },
      { 0xfe0a6ea703b7da99L,0x936a44b848e3afa3L,0x618a0ecf89fd127bL,
        0xa35614cd06f24bc5L } },
    /* 26 << 98 */
    { { 0x21a1002e8d49c05fL,0xceeacfd12fd7989dL,0x8c058f4b8f5f4ea5L,
        0xf31bd38e563e214bL },
      { 0xbe47bd98245c7585L,0x70d1a05c6bc2a404L,0x830d7f30c68257f7L,
        0x1abbbfbb8136c932L } },
    /* 27 << 98 */
    { { 0x6fbc43b76e03597bL,0xc18fddb65fca14a2L,0xd3c4ca78e8f506e2L,
        0x6b8711dda47e27deL },
      { 0xc308c18916382b5bL,0xe9d3145bcf96bd7aL,0x5c290ec1afb26629L,
        0xb4eb8130209438ffL } },
    /* 28 << 98 */
    { { 0x7335044ae1118539L,0xed6d43fc5192a007L,0x1a8bf622a43a2bd4L,
        0xefec3fb6efa9f3a5L },
      { 0x6d224bbc6d834bdeL,0xaaebfcb8b0fbc744L,0x383b2bfcc4ea1652L,
        0x9cd26d90751ae816L } },
    /* 29 << 98 */
    { { 0xae614386f47f0f9aL,0x9987378773c6ecd0L,0x0b56c1ade5414fc7L,
        0x9b85e6b5fd40286cL },
      { 0x7117aacdd64687dcL,0x85d148e7ad8a8c4dL,0xf62f8eb57962655cL,
        0x8386b37e7f0c6a2cL } },
    /* 30 << 98 */
    { { 0x6b4715a390c47d7fL,0x1fc4ced1458a54e4L,0x018539430ed97b0aL,
        0x58a280be5b370e0eL },
      { 0x8d488cb6344f3960L,0x9050c5990741604bL,0x0878fb1b07954771L,
        0xd927ea8cdbb3c82bL } },
    /* 31 << 98 */
    { { 0x2fe71d59384f01faL,0x66d2b790238bb66bL,0xceaec11fb8fd803bL,
        0xbb9199146dd09c0cL },
      { 0xab5992e62ccb2f67L,0x2421878fcca50326L,0x363d933d9ee6dc73L,
        0xa374ab0b084b1fa3L } },
    /* 32 << 98 */
    { { 0x2d832a29161f6475L,0x435b8d78fc8797ebL,0x66bc156dd71b609cL,
        0xb3dca798fe0c2004L },
      { 0x445d47bf02fd92d7L,0x1d1c9798c8b03083L,0xca46d98d079a7c51L,
        0xb93f286c1afeb89aL } },
    /* 33 << 98 */
    { { 0x1c174510eeb6665dL,0x65874b6a7479a932L,0x28d16a852335e3b8L,
        0x5e22bd3bc747eae6L },
      { 0xa770e0a704be16b4L,0x9f5f9ca940b3ff57L,0x3f39e529845ec39fL,
        0x5d5f4d60ebe697ceL } },
    /* 34 << 98 */
    { { 0xea2a262fbd90d4f4L,0xa1ce74acfe1b6494L,0x4e419004fa0fc472L,
        0xdef0e4404e691060L },
      { 0x57195a3aa9f4baf3L,0xf14e108b5e758c53L,0x10a34f9d920895e0L,
        0xc3f18af9feb57a63L } },
    /* 35 << 98 */
    { { 0x4b1c988cda1bef0dL,0x8b328cd93df6915bL,0x5ddc5eccf45586d5L,
        0x426468b9040322fcL },
      { 0xf7f44765be981558L,0x250939911855504aL,0x72c51f2ef7d6df43L,
        0x858637fb849c99e5L } },
    /* 36 << 98 */
    { { 0x68b84dfd0ee9f78bL,0xff42fc9bf2ee390eL,0xaca71e10531e1dcfL,
        0x391620e27feaedfaL },
      { 0x7b2d6a02acf3e5daL,0x261823d2d20a16d3L,0xf9afa5d6bb00cd30L,
        0xba151f4a1084580dL } },
    /* 37 << 98 */
    { { 0xb5f4b3a926a3fcc3L,0x5d84a8236729f4daL,0x51540c41fc35f732L,
        0x81b0cb58a6ae5bf7L },
      { 0x91c7ae07bd81bd27L,0x0868980e1d56ff5dL,0xaef85a3165224df6L,
        0x112eba3b17a69e35L } },
    /* 38 << 98 */
    { { 0x07c34677c3a9d932L,0x3b6b7cce8ac45e37L,0x5e0e2b6e31b6248aL,
        0x14ee5b66453d9685L },
      { 0x4c5e2be7bd4d807aL,0xc03f37f8c121fea8L,0xcf34911e8df7b5e7L,
        0x00e7f18e5f754191L } },
    /* 39 << 98 */
    { { 0x89a8c9e12dcea4aaL,0xcc1cc31a50f6db55L,0x4a6f542c9046955fL,
        0x85fed580da2485d4L },
      { 0xa70f62d19ac53748L,0xc2fbb850655870a7L,0xaeb2d4388c859aefL,
        0xe3cc5ae5cc9ff51eL } },
    /* 40 << 98 */
    { { 0xf8d8c55d0a3ebbfcL,0xdcd838d5ed48f61aL,0x032f91ead4cba7abL,
        0xeb0ed88d2f70235eL },
      { 0xd4498170000ef325L,0xfd34e07f4b923c4aL,0xf71c07a9b19b84cbL,
        0x000a669ced9690a3L } },
    /* 41 << 98 */
    { { 0xf45eb0efb5705e16L,0x8cfd6a627d9ce007L,0x76ba9a5fd9e52885L,
        0x13f728818aa9ffd6L },
      { 0x0a11e8dd85528e4aL,0x58f1993dcee8d663L,0xb49d750ba1c81fd3L,
        0xaae29861e7de2e6bL } },
    /* 42 << 98 */
    { { 0x9a40644e5dd7de70L,0x67fbae1c937a5546L,0xb3e02907956c2fa8L,
        0xaf78537421b4aedeL },
      { 0xf42a1e969c0a8bfeL,0x3f6690e678957181L,0x1b1c9575a6c5e0a7L,
        0x6def8124f9cfb9bdL } },
    /* 43 << 98 */
    { { 0xde552cf972faa1b0L,0xfac2f4ad9b5ebbbcL,0x4b60a5a58ef89ba1L,
        0xb6d9be578012f3b1L },
      { 0x3992a6f79b2b083dL,0xe79ec527ac640f77L,0xf6cca7753f1e632eL,
        0x5dae84138fb80790L } },
    /* 44 << 98 */
    { { 0xf0d4146cb572407cL,0x829cfb383f84cc39L,0xd7c9fed4e31f007eL,
        0x93b2a5bc09e68ce9L },
      { 0x073fb24ad01482b9L,0xfe494244b8d44e62L,0xe59a16493dc49858L,
        0x071776f7f005b31fL } },
    /* 45 << 98 */
    { { 0xaa368f59285439afL,0xb0821574e27e783dL,0xe16903f6098746baL,
        0x436a95ae69dc00d0L },
      { 0x9ae5a91a877bfcecL,0x5d8758d91416ad3aL,0xa420ce4025fd9a9aL,
        0x99610fdf39b0fbfaL } },
    /* 46 << 98 */
    { { 0x782af22241cc1e9bL,0x346a4a9286ff4cf6L,0x9dc4c6cdabc900c1L,
        0x7ed2476ce7fade51L },
      { 0x68a721854f1dd24bL,0xcefcf0fdb08260cbL,0x0199a1478a6f61b6L,
        0x176b6079cb5769c5L } },
    /* 47 << 98 */
    { { 0x6dbcceb0347d5a63L,0x26433ebc9c4dc505L,0x5257031805d5e74dL,
        0x692f1d81057ca464L },
      { 0xa09554a0477f424eL,0xbd3f9bbd176a695dL,0x8c7f52f35972db27L,
        0xacee8234f28b2aa4L } },
    /* 48 << 98 */
    { { 0xb853465a3a4a0217L,0x74a2534f66f3a4d5L,0xae1a7ff3eff0423bL,
        0xd2a01a09bb126028L },
      { 0xff84c6f04963e855L,0x63db264c6bc18d50L,0x39792dcacc6a5e25L,
        0xf20cdf3eedb37a25L } },
    /* 49 << 98 */
    { { 0x6a460f3d8730f2c4L,0xe9b786c46a0ab6bbL,0xa9720a6b084015c2L,
        0x28add2e20dbe6f0fL },
      { 0x90fb0ba726be7de7L,0xfae8b5d4e40f15fdL,0x007363a1ceb9c856L,
        0x6d8bfe14586b770eL } },
    /* 50 << 98 */
    { { 0x63e7d78eb7bcc0e0L,0x56c569f83ed4ab62L,0x76c6a5bb9e103abbL,
        0xeb24afeb638fc44dL },
      { 0x15e00239f0be16f1L,0x7db92f678778f084L,0x5198680e63de2befL,
        0x69031d0ee0510421L } },
    /* 51 << 98 */
    { { 0x8058f8aab94753c1L,0x412d4c97454bf609L,0xb8dbfe8a95f9fd19L,
        0x6cd3221a68b43233L },
      { 0x384a9f15a5adaaffL,0x60c70f9042b2ef95L,0x085b2f3b2c7da919L,
        0x1e5d23d1bc8407e1L } },
    /* 52 << 98 */
    { { 0x9ea95bc9adb45b3eL,0xb5a28feced06ec67L,0xd678df4662a3c143L,
        0x80f0bc9d6793284aL },
      { 0xeb7865a907d4afc7L,0x0fc5eafec1301d87L,0x50a8e7f54823349bL,
        0x97800fa22d019e96L } },
    /* 53 << 98 */
    { { 0xfeff25791bdd1d9cL,0x4d938c5d23886156L,0x25e3a8066979b9f6L,
        0xeeef8fa037bb6199L },
      { 0x4d917977d7d308b8L,0x60ca7ff94ae672ccL,0xb24ec1542a68db6eL,
        0x7b0604ec9e9942f5L } },
    /* 54 << 98 */
    { { 0xfdf4794fca4fad9eL,0x086020f83df5de22L,0x653da6cad601533cL,
        0xf97c1865735709f3L },
      { 0x2457ffd07cbd6ab6L,0xce05a482d003a502L,0x5c0c0cba33ee2740L,
        0x8146ca00f37174aaL } },
    /* 55 << 98 */
    { { 0xec118827587262bbL,0x8468c0297e2a402cL,0xe1c3a9e3bd6eb2aaL,
        0x77d09b4db496bde8L },
      { 0x454e767a854693bfL,0x6bbcc22ea4de85bcL,0x66452f10b180f206L,
        0x110c5a050f5b1744L } },
    /* 56 << 98 */
    { { 0xb7be75d8a6b3f6e4L,0xf64bb3fd2c0d2e1dL,0xad17a039935ae640L,
        0x7304ad638f243748L },
      { 0x04316bb4d278caa9L,0x19b89c621e84f91dL,0xdf4a47e96e7a2511L,
        0xdef32df9998b6bc0L } },
    /* 57 << 98 */
    { { 0xf1253ce0cee95a1fL,0xbacf52060ae96e31L,0x4ba2e24a0b343e63L,
        0xca64d07f79929dc6L },
      { 0xf2823ac89424ce75L,0x2d4add370207ee9fL,0x44d9ecd0387cde5fL,
        0xa5095ccbe180a21fL } },
    /* 58 << 98 */
    { { 0x901cec8a7c0cedf8L,0xf291dc783b8c759cL,0x98b8efdc49401234L,
        0x8f2b16e3058e9d9eL },
      { 0x16ce800727dba00fL,0x5bb8fca96d66d2f1L,0x092eda987b85a96bL,
        0xec53f4bc973eae20L } },
    /* 59 << 98 */
    { { 0xe6e0df591b93a60fL,0x65e06ecf2f6b0abfL,0xb8c2ec3e569a9e1dL,
        0x27f9fe72aa8c1cc3L },
      { 0x9cf3908fccd4d5e2L,0x5a40e0a9725c8528L,0x27b15a1ed470b0b0L,
        0x50a09ec133d81bffL } },
    /* 60 << 98 */
    { { 0xba976a58da99fcf5L,0x3881ef1ec3536b7cL,0xec65a069fbc931b1L,
        0xab7f57b4fc929a0eL },
      { 0xc7c63491bc61f452L,0x5c1aa935c1750dbcL,0x35b8789b9ff0465cL,
        0x8ff8589b727647b7L } },
    /* 61 << 98 */
    { { 0x2b56fe50a95022b6L,0x242205692adbdbbdL,0x2370d94fd2b80ea8L,
        0xe5d47b7371d9e6f7L },
      { 0x2fe84b728d858032L,0x0411034b4ffd7cfeL,0x0819a9f37c2c84e0L,
        0xf8248dfd30228f9eL } },
    /* 62 << 98 */
    { { 0x75c77f0a4fdf6c79L,0x195b4b5915579cc7L,0x274c7c81f8d3705cL,
        0x45a2209f70ee9be1L },
      { 0x4a4fce690b1e818bL,0x74d05e5fbb9926b1L,0xb64639ce3f2a796bL,
        0x2d168d5bae957d59L } },
    /* 63 << 98 */
    { { 0x067c227016171846L,0x7bb71d151a03f8d1L,0x2badd196495a09a1L,
        0x024db16351b990c4L },
      { 0xc19edc61e79dcaacL,0xf17f54bd60df81e9L,0x4560262e9ae347e4L,
        0x1d2c254259eb711dL } },
    /* 64 << 98 */
    { { 0x40372d2d4919affeL,0x2d4a2ea3a009bd16L,0x48f1e7f8c1a62eb1L,
        0xce083725587a1124L },
      { 0xe874261be7ebadd3L,0x7ca5c156057b93e9L,0xe8b381e5fe39e6ffL,
        0x2d16b32fd30815c3L } },
    /* 0 << 105 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 105 */
    { { 0xdfd30b28ad2e996aL,0x64d4eeec9df0fc37L,0x8e049e3dddc39763L,
        0x9f55e0ce37ea2e8eL },
      { 0xf3fcba4e4bf01984L,0x764d5c3d9d55bc4bL,0x98cb92a1cfda895fL,
        0x27dfe7955c7bca69L } },
    /* 2 << 105 */
    { { 0x86dfdecf23a86e2cL,0x02ac466b3387f712L,0xc30a1ac2d63509d1L,
        0xd391342263aebbd1L },
      { 0xdc7b789f068ae34fL,0x499f2d01487dcd10L,0x68e2a3bca3e8a4b4L,
        0xdf87ba7114d2a26cL } },
    /* 3 << 105 */
    { { 0x9e3ab99934479e7bL,0x9d5f2dc3b026e780L,0x131374fd4f1bd429L,
        0x92e2e7389be1379aL },
      { 0x6cc32f80d13bc111L,0x6fbfc35086f81c92L,0x12ca1b309263913aL,
        0x6f7da1ffe06ab75cL } },
    /* 4 << 105 */
    { { 0x4780f12a19301b16L,0x233bc231bc368a20L,0xd9650892cbadb344L,
        0x38a0d964ad9425a1L },
      { 0x277abcf24a8d4d7eL,0x4ccd16b1b806ce9eL,0x82ff40f07570d473L,
        0x57491414df130780L } },
    /* 5 << 105 */
    { { 0x9f1f39f2a96ef42bL,0x1fd967ed107f1321L,0x9383249729d4767eL,
        0x7761a38b3fa9e796L },
      { 0x3e408c5966318df2L,0x9283ca4441745f03L,0xfedf8fa32cce1a86L,
        0x8363860db44600b4L } },
    /* 6 << 105 */
    { { 0x3dbfde5545f45a89L,0x8800c86026ce399cL,0xfb25e8dac25e9479L,
        0x6ff0d6cbf7d367a2L },
      { 0x70b0ba36a93f9890L,0xc07ca40349bd5a80L,0x5f4feda6ed54d1aaL,
        0xfa1e2efd671ad0b4L } },
    /* 7 << 105 */
    { { 0xda4654678c56e7aaL,0x39d04cdc25e45bc0L,0x26661bd6af21c637L,
        0xf757ff5cb55ddfa5L },
      { 0x07318fd14394eb20L,0xe010b19d2bcf3ad1L,0x71e2031c8e5c7e7fL,
        0xee35f346edbfda69L } },
    /* 8 << 105 */
    { { 0x8d8d41205d8f6fabL,0x5e420839abed09c8L,0x5120e0794aacbb1eL,
        0xf7e840f8ec1bc996L },
      { 0xd921d63b9707c3bbL,0x3ab4b8b8ae891a71L,0xbe46575673bb2278L,
        0x776ce040553ee91cL } },
    /* 9 << 105 */
    { { 0x86f07c2e88222e0aL,0x3f3688f1df97816eL,0x20d2d944a6df9d3aL,
        0xff399057b2cb925aL },
      { 0x010c747e27f1de19L,0xbe9406697fc1fbc3L,0x3ab94600877ef709L,
        0x9af40a6b8f4c8a8eL } },
    /* 10 << 105 */
    { { 0xf7c0f202713f023aL,0xbe0bf3dbd0a8dc63L,0x0978992664a41337L,
        0xbb4a89642c2823cfL },
      { 0x9279cb27b90e45c6L,0x80283fd3382564acL,0x3a746b01fa5f0bcdL,
        0x28667a8e0afaf10aL } },
    /* 11 << 105 */
    { { 0xeccfd0ee015d5295L,0xbd6678a573ce8e21L,0x132a87f2336ecb65L,
        0x09de4efcbe7dc659L },
      { 0xbedadd106f69b3bdL,0x357c61e2e8303650L,0x6b3c613aa45777e6L,
        0x51dd30ad08d41179L } },
    /* 12 << 105 */
    { { 0xa7b53f3ff98feac3L,0xe8e00328f9497319L,0x1f3b080d0ca20b40L,
        0x06dc5456e19b088eL },
      { 0x1f3f18d70dce02cbL,0x2d2155446fd1ade9L,0x4c6de38c055550d0L,
        0x5d535e6ff33f4973L } },
    /* 13 << 105 */
    { { 0xdcfd4163744c033dL,0x0706a49076fc420aL,0xdc9db55c394f5b6dL,
        0x1a050a62e040a093L },
      { 0x60367ebbd0ab26f3L,0xb9c07239c3d91820L,0x14a8bed5a3e32db2L,
        0x23b19cd3d49f37ddL } },
    /* 14 << 105 */
    { { 0xd048c64fea6c85ceL,0x8aefff19d5716cfeL,0x199fddb1ab85bdcfL,
        0x3f592e7ebaea49d0L },
      { 0x8c8decb6f1d58ff6L,0x02598a997fe8f425L,0xe4c73ae264a93fd6L,
        0x208a0f61878db06bL } },
    /* 15 << 105 */
    { { 0xff0272fe27c4a266L,0xccfc96ae69e7c6a2L,0xbd7e715f8e78d74aL,
        0xd04ae9a432ed35bcL },
      { 0x302af41305614c5fL,0x9817663733943b5aL,0xa4d1c9b28a58cfd8L,
        0xf0ebd5f4ac2f3f79L } },
    /* 16 << 105 */
    { { 0xebadb010fdc7945fL,0x62c9cff003750a4bL,0x75192383a0c85b9dL,
        0x2aba7b5316eb0bf9L },
      { 0x93d4adaaa4c06f9aL,0x573a86a25f8e482cL,0x109c6fdce791a79fL,
        0xd9ed02ceb37eeec2L } },
    /* 17 << 105 */
    { { 0x7b1fb4b47dd63c8bL,0xae6e276722493b49L,0x5ef6beb76a411bc9L,
        0x4d88918de1bf4242L },
      { 0x7ba26f8c02a97fbcL,0xf45b2a507f41c518L,0x6c35fb6983249e23L,
        0xc4a951347a5778ccL } },
    /* 18 << 105 */
    { { 0x6173f86008287cf7L,0xdcfc71d9fac3a444L,0x894f3b33079ce3c9L,
        0x842bf7da916b661cL },
      { 0x94299d6fa758a243L,0x0e23f984b242389aL,0x653050f0c03a7aa2L,
        0x2ec3041b9559ad9cL } },
    /* 19 << 105 */
    { { 0xa61dd49997cf6e9bL,0xfd090f38448fa6c6L,0x4f1b75ac39b126bfL,
        0xb48d03721ef1a280L },
      { 0xe40c310df2b2941fL,0x5b9a73698d9d5aceL,0xbe0415c17ad9ad95L,
        0xffd864b6a8510622L } },
    /* 20 << 105 */
    { { 0x2aceddcd898f28e8L,0xa0cfc30aba89a51fL,0xd87db983e105e448L,
        0x16ba795e5e5ea6fbL },
      { 0x5f48e45a352ad094L,0x1971a10f55fd75e7L,0xfb0f1767fd1c8d68L,
        0x904229d986df0665L } },
    /* 21 << 105 */
    { { 0xc2c88671e87ab22bL,0xcbe384a133611a50L,0x38eec58ead2eb708L,
        0xaa19b17486d7bdeeL },
      { 0xa9f416d751832b61L,0x10b751ff355e7b6dL,0x6dd520634ff07a5aL,
        0x6a6090c14e3505c1L } },
    /* 22 << 105 */
    { { 0x53addd1cd4c80f29L,0xe76d668b0d3d793eL,0xbdcdc4c9191eedd9L,
        0x806753200f8e4877L },
      { 0xc41426dd32f5661bL,0x9fcbe1ac06199185L,0x62fa2198404a1207L,
        0xc742fdc233c8190eL } },
    /* 23 << 105 */
    { { 0x16ec1b96778ee765L,0xda656f58e29d992dL,0x5393775bb4369e7fL,
        0x512f5c7b0674fc45L },
      { 0x55b8bd3860efa8e0L,0x1ab6d2df155b57abL,0xed0aa777e26ad439L,
        0x5b16333ed9b04376L } },
    /* 24 << 105 */
    { { 0x321119d38fc7ea72L,0x390b4ef57211ef45L,0x289f39451feda1a2L,
        0xcee9cb33605c8596L },
      { 0x91109e96971b6897L,0xdf70c17319701ea7L,0xa07d0ecda92c6b2bL,
        0xf8eb97fea9eab766L } },
    /* 25 << 105 */
    { { 0xbb2cf63b0e3cf9e8L,0xffa6c503dda02b26L,0x42c1ec1a9cb18efdL,
        0x13cdda9cc45d5b22L },
      { 0x6b3baf33c820cdf5L,0xa337bc5e610c8bfcL,0x8818681806a9ca6bL,
        0x382a34eea0c455afL } },
    /* 26 << 105 */
    { { 0x725006c9e8fc59dfL,0x0d46b697f929c670L,0x7bd6eceb893a9f6eL,
        0xf25aa6371cd04e5aL },
      { 0xf1563d79f6612d4aL,0x8c9372cf5efc49d8L,0x09cc051396c5bdc5L,
        0x70f19d46d3cc34d8L } },
    /* 27 << 105 */
    { { 0xe62f6891fdfbe16cL,0x8b7db2fddc60110bL,0x3557bff8f7868674L,
        0x2b414c8e95a638d6L },
      { 0x3b6610ac6d19ac65L,0x20864204d641b0eaL,0xee372a46892161fbL,
        0xc7c5bd874125868aL } },
    /* 28 << 105 */
    { { 0x5edc6afca61ee957L,0xa4374ba1d37faed4L,0xf0684f461e52b0abL,
        0x0812cbca2a007b66L },
      { 0xf3442afde68c4893L,0xb02ac6df2d9dd9a2L,0xa4fe98dc068c08bbL,
        0xfcd5dc057795e2e9L } },
    /* 29 << 105 */
    { { 0x28983aeea0f55cd8L,0xb390daf4e96cf557L,0xbfd2f5ab3f119098L,
        0xed1145876386c0adL },
      { 0x578995b969539392L,0xc8a7794836b880abL,0x7e03cfb6e4c8b560L,
        0x018cd4db06cdcbe0L } },
    /* 30 << 105 */
    { { 0xbd7f2e3ab006f8d5L,0xf25d1718d6d9f30eL,0x9ef6e2ee1b22ae3dL,
        0x89a2695d416154abL },
      { 0x1975e0c8da261e39L,0x8fe66aedda2c2031L,0x6f93f83997e1e00cL,
        0xcba9a773a742b328L } },
    /* 31 << 105 */
    { { 0x9529fec13417df8bL,0x37a27cd954e314b1L,0x93feb0f865f94a63L,
        0x65978b84b5e029c1L },
      { 0x576fd83081b705f1L,0x37d07a37688e8c52L,0x3b91d360332838dcL,
        0xcca9cbf8b0b14a94L } },
    /* 32 << 105 */
    { { 0x86f18c448b63b669L,0x53c6eba66972d2d1L,0x2a522d8c8cff59bcL,
        0xbc181d156ed25ce5L },
      { 0x913f173d5feb0ecaL,0x34273f8da207bd71L,0x41b7572efa1715aeL,
        0x8a8ffea27f16f4aeL } },
    /* 33 << 105 */
    { { 0x2b852908f95bdf78L,0xa75adbb3a26328b9L,0x992ac179dae21d25L,
        0x8c99927a78e14467L },
      { 0x23fb2fee0c16e0c2L,0x58e797bbdbcb5f4eL,0x33d6956ea07bd7deL,
        0xc921fdb37172d36aL } },
    /* 34 << 105 */
    { { 0x035f1744158267b5L,0xc7495f33a291374dL,0xe07db2f54a41a6a0L,
        0xfdb2987ed1238792L },
      { 0x616df62449741ce6L,0x90ecd21b8a693880L,0x447c729d341fe21bL,
        0x06ad3c90c012a8abL } },
    /* 35 << 105 */
    { { 0x13dc4fa9ddfd6b5aL,0x238a1add64cfc0f3L,0x874a3c2fc34a2b1eL,
        0x427b6e3c0deb1dd4L },
      { 0x78a1ad1d876f2621L,0x34f9207c252f6837L,0x1c812fbb047d667bL,
        0xc3512ea33ee03ba7L } },
    /* 36 << 105 */
    { { 0x762de5f0527a1b55L,0x7873d692ae3221afL,0xa8ac73c7b112d35fL,
        0x1d118c30815414f6L },
      { 0xbc686118865ab6f6L,0x01e75348ecf8c02dL,0x9b131840e6220bf9L,
        0x3d72dac4a67512b5L } },
    /* 37 << 105 */
    { { 0xd9e49eccaf95e16eL,0x1297c5601e2aa105L,0x925301aca1a5e8c2L,
        0x3b0ea863990ab503L },
      { 0x7860b66015f258c4L,0xa4497040397253e4L,0x88562ed014a4774dL,
        0x325d8b0d7adbd093L } },
    /* 38 << 105 */
    { { 0xd4df8df241e24010L,0xe7cb8663580031beL,0xd653593ad7fc7e5fL,
        0x429a8863e9f1fe9dL },
      { 0x18a0a70963e71cedL,0x39d9316da498140eL,0x44466cff40f40117L,
        0x58d27cd664602832L } },
    /* 39 << 105 */
    { { 0xf4a4c22b86018a70L,0x7a4d41026d703f04L,0x4f5a0037b424b0fbL,
        0xfb591cfd322b1876L },
      { 0xb45798b0632e0f56L,0x83ef9febfdcbcf20L,0x0a23b09c115749acL,
        0x3b950273946248f8L } },
    /* 40 << 105 */
    { { 0x5ed75e681e13eaeeL,0xbebd474409dafdb9L,0x8b46621f69941fc4L,
        0x1fd3c13f91129bc0L },
      { 0x371448d0b7b9da22L,0xd452ccead87a4742L,0xe2f04778f91c38b9L,
        0xfb443a5dbd516bfeL } },
    /* 41 << 105 */
    { { 0xd7bd4056044d666bL,0xb4546ffd2a9b17c4L,0xf66765ae818fe55aL,
        0xc375126c1b5dc7a0L },
      { 0xe9a7ed20c1a81c63L,0xaef2e23df8cf06b9L,0xf45368653e67b95bL,
        0x25cbb5a624309537L } },
    /* 42 << 105 */
    { { 0x8a230e683256c020L,0x4a33e462215dca7bL,0xefef49362935b6d1L,
        0xb383df4e852c39f4L },
      { 0x197ddd7757c21e90L,0x236f98dd2164127fL,0x464b86ecbbd61847L,
        0x107a387cfb89d515L } },
    /* 43 << 105 */
    { { 0xe01e50b7400d66d5L,0x4377af2b5f864426L,0xde21c49af8fe847aL,
        0xc133e58f887c0674L },
      { 0xda5b4c3bd2fda17cL,0x24157f13fed8fe68L,0x1c4483f38b6bb6bfL,
        0x940fab9ecf1bed73L } },
    /* 44 << 105 */
    { { 0xce3fca793c15c7e5L,0xb83fce10066de109L,0xbd42ed010cd5a04aL,
        0xba5446b8407fcb03L },
      { 0x4a8cb929e5d35bdaL,0x6338fd7ebff8631fL,0xc85d4ee44656a8cdL,
        0x83b1f39a92c99820L } },
    /* 45 << 105 */
    { { 0x153fa4d47e90c823L,0xc15809ba15326196L,0x320b8fe96eb4b379L,
        0x27cc07c058704d9eL },
      { 0x301840b2f13d6ee7L,0xf1f6530fc6d8c930L,0x3e9254ea96a22034L,
        0xf8c0ee68af5b8a2eL } },
    /* 46 << 105 */
    { { 0x88e9e44eb8207fdeL,0xdea11cbd29bc1310L,0xa20c2f179c9d7df7L,
        0x2a954927bceac495L },
      { 0x3f405f5c2a58d6baL,0x64df53642ac9aeaaL,0xb618f6dbe8aa74a5L,
        0x22dadc7f74ef61e3L } },
    /* 47 << 105 */
    { { 0x306ee8329cfdc4cdL,0xaff5332140698a5bL,0x9889344389567341L,
        0xdfefbdd4ac7c68ecL },
      { 0xd3da70943261a582L,0xd23e3fa562ce96e7L,0x62c060c0d773337eL,
        0x5cb2becaa041f910L } },
    /* 48 << 105 */
    { { 0xe21ab4797e8215d8L,0x84384686923b4b27L,0xa93c08fe6a3d21efL,
        0x7bd962482fa6de1cL },
      { 0xb858ecd7ca6de3e0L,0x466a48c847c9fcedL,0x23ca9b75c708239eL,
        0x860d553db5bbe833L } },
    /* 49 << 105 */
    { { 0x45804f1a9e76e71dL,0x9fdb8b8d51e59be2L,0xa76db4b73bbc2a19L,
        0xaebb47ee96f82cd0L },
      { 0x7a9b95b597b1dd04L,0xcc149a8d5f0b1d7cL,0xbba40e4d47a50eecL,
        0x4e635d7056b72539L } },
    /* 50 << 105 */
    { { 0x31c40e90b18659c4L,0x080262246f694b35L,0x8ed3d7b8e0cd6e15L,
        0x157e2a9d9293cb36L },
      { 0x7b457bb196e54583L,0x756474982609c44dL,0x54667671970a8cf2L,
        0x3b7da9c83af72572L } },
    /* 51 << 105 */
    { { 0x8fbba9774d63473aL,0x7af5af4323001221L,0x99093197ea29d97eL,
        0x4409f6a9fa564089L },
      { 0x64fd1cda2f70e06fL,0x8b7c83a62e9d55eaL,0x0dffbe4b6385fcefL,
        0x4513f5847a6fe72dL } },
    /* 52 << 105 */
    { { 0x6a64f166ba1de4aeL,0x1f8550a989069fbdL,0x72b411fdda7ef7fcL,
        0xa185d2c3829ea712L },
      { 0x82f5ffb8ccc1868dL,0xb484473aff9fafa9L,0xe1857f3c089132edL,
        0xdad885a908ef378fL } },
    /* 53 << 105 */
    { { 0xbdbdfc0e7af9e2aaL,0x366c07bb95486202L,0x37040d45fc9d979fL,
        0xf279ed10a0f80630L },
      { 0x278552618f31b39cL,0xea0c3b1cf26f91cbL,0x90b4e8c2b38c050fL,
        0x7acb26b11623ab47L } },
    /* 54 << 105 */
    { { 0xb6cc3cd9a4a064d2L,0xa410880c97245482L,0xfb470e113a6e6a1fL,
        0xf19080b193f347e4L },
      { 0x23253dcfb75a53d9L,0x550470499c95d567L,0x8c75631e7b20202aL,
        0x58fccf32834b8380L } },
    /* 55 << 105 */
    { { 0xaf6bdbd8243ddddeL,0xa3ca3e2ccf38f705L,0xa2357b4bca38c9a2L,
        0x8bf0d2706eba095bL },
      { 0xe4a43b7c9d998070L,0xdf412faa8469214cL,0xd2578cc4000f1802L,
        0x2feb563ff8515863L } },
    /* 56 << 105 */
    { { 0xe66ce02a5022112cL,0x8415df811461b1c6L,0xc2546e6aad247c38L,
        0x4b9788e69a9c74d6L },
      { 0x9d0cb2e0a22be3e8L,0x15db086c295f76adL,0x9758f99ba2337670L,
        0x61ae09bb9ab57f54L } },
    /* 57 << 105 */
    { { 0x7af4d4aa93926a37L,0xa895f386f25cadb4L,0x90e13821c6f4f514L,
        0x46738d954eef97abL },
      { 0x66f559f3f0b479a2L,0x9ea62dcd3262fb2bL,0x91a39a5e6a857025L,
        0x11bdd19abb3e6e11L } },
    /* 58 << 105 */
    { { 0xfa411fd69353cc19L,0x275d094c94cd2276L,0xe2069b2225243d1bL,
        0x9f02f1e2630c8cbcL },
      { 0x85c942fd379b6b63L,0x293dcf87bdcc9307L,0x56856d8edc212ca8L,
        0x1927e93123a0c56dL } },
    /* 59 << 105 */
    { { 0xacfed2889c2f8b66L,0x20f6b94e386ad1e3L,0x0e622304dcbeff77L,
        0x67e895fa5978f2f6L },
      { 0x12a63bde20029bfeL,0x0ed75b6c8d968b8cL,0x611739ee57cec33eL,
        0xeffaae7242b9fc44L } },
    /* 60 << 105 */
    { { 0xa7de79ce971a90a9L,0x529bd8a24fead0d5L,0x78434c309a1a43efL,
        0x904d1db24f3c848cL },
      { 0xedb3c11e6d4234adL,0x4e0c9ec45975e9a0L,0xc51236dbff16ec74L,
        0xde652cff36d09231L } },
    /* 61 << 105 */
    { { 0x0d7c18b7e60a0bc5L,0xaf0413839d7df012L,0x9c0ff3f447d4cfd0L,
        0x64c7e6c23d97bac7L },
      { 0x239d25008cb44d50L,0x47189764bba96026L,0x2244932831ddca37L,
        0xa53a1886fb7c29efL } },
    /* 62 << 105 */
    { { 0x2515b66597a3789bL,0x825c5031540ea258L,0x7668065609a5b24bL,
        0x833c240f60fb8bccL },
      { 0x758e0b1001e55cc7L,0x8b799c488d260572L,0x0981a8026c5dd0cdL,
        0x6f6da55d1b9c6cc9L } },
    /* 63 << 105 */
    { { 0x3457b6858c4d503aL,0xc537730f009a7a94L,0x334d46b4d01dfdffL,
        0x3e5dc6a815e20bc7L },
      { 0x1833b0bf6ce8b8abL,0xe21b99aec57a4292L,0x743cb5951713ba15L,
        0x550e41bce0bb44a7L } },
    /* 64 << 105 */
    { { 0xf356917a2f8ebcf5L,0x6f2c400b953f056cL,0x09d9ac41dd84bb48L,
        0x50dc7a8ea61e98e3L },
      { 0x1179a9d33d3a6776L,0xdda312e716de8b3eL,0x62a8b7c3ce6e2beaL,
        0x2b00036c645e4ca0L } },
    /* 0 << 112 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 112 */
    { { 0x9ad2cbd7ab6cf0b4L,0x7a1e67f4f13d1ddfL,0xa58f0c73746003baL,
        0x8263e888a64a8fccL },
      { 0x535cbe37be2452f7L,0x931257666ae81a76L,0x7d2ed0ab3a553701L,
        0x93d7e7dfb0717d78L } },
    /* 2 << 112 */
    { { 0x61bc013cf9cf03baL,0x36223b88feee3a78L,0x86efc9233d7e4c95L,
        0xaf3801be965625e4L },
      { 0xa7bba1413f32fd9dL,0x70724dec4e564acbL,0x52587f32b7edcac1L,
        0x0b1cd94cb3969985L } },
    /* 3 << 112 */
    { { 0x9f08407a661fbdabL,0xc4d7c53658e52151L,0xa3765bce63dfe954L,
        0xc6829bfbac2dddd1L },
      { 0x97393f65dc6e4487L,0x9ba29422bf04c930L,0x493c691418838c0aL,
        0x41b137ff4b2f35cdL } },
    /* 4 << 112 */
    { { 0xc9e4aa244e1c5e60L,0x54bb528913253d51L,0xf4a86ab39bbabe53L,
        0xd561feae6ac0aa64L },
      { 0x27a896ab1911bad7L,0x9cb22b9864337303L,0xf14262fb161f6928L,
        0x1661885c59ba6c9fL } },
    /* 5 << 112 */
    { { 0x4666ebd3b82574dbL,0xc5e866728d8af3f6L,0xcc645205209319bfL,
        0xc183c12e3834d1a8L },
      { 0x533d73da49eb0f40L,0x3bcab0bc6aca649eL,0xa02f4c41e39e8361L,
        0x2391e7aea89bdc85L } },
    /* 6 << 112 */
    { { 0x88067c5e608cbe2fL,0xcdec82f6f16c22f2L,0x80aa719af1faf9dcL,
        0x261fe9512340185cL },
      { 0xcb4113669713e72eL,0xdb1e405e6d8a2a46L,0xed17475711106ce0L,
        0x6d70cf6ef71c0e69L } },
    /* 7 << 112 */
    { { 0xb5310322cf707c76L,0x3a1eb2ff40b4b7d7L,0xb83259fbb1a2d26dL,
        0xa83ffb0f799720c0L },
      { 0xeecb19280bedb326L,0x4473e820e9271715L,0x506e6d202f2d71a9L,
        0xe7b253b14319756dL } },
    /* 8 << 112 */
    { { 0x27e19335f576cb3cL,0xe16e4573dfb3b78fL,0xaf96d78563da0001L,
        0xb38deafdf7444c5eL },
      { 0xaca6b38cc0eb0e28L,0xa6ca35417fe41b98L,0xfeb37b4718965b31L,
        0x739cc322597d5bc6L } },
    /* 9 << 112 */
    { { 0x827760414cb1fbc3L,0xcdaa873d8e2a3ad1L,0xb5f87b34c01318bfL,
        0x0c692268229cb81eL },
      { 0xb0724016a53089f5L,0xb2976a5305415313L,0x436eab75cee8fdf2L,
        0x8794e1a6d82b13e5L } },
    /* 10 << 112 */
    { { 0x0d51a072d5516e3dL,0x7bae61ce4b2fdb3cL,0x0d987e89550728eeL,
        0xfd5a656eee6778dbL },
      { 0x942ee623bb4d9d7aL,0xfc06d64b2dc1baf8L,0x5244fcd847c3dc8eL,
        0x5e37e1568568653eL } },
    /* 11 << 112 */
    { { 0xe5c2c6ff048c8355L,0x480872eca0474046L,0x67e3089d7ff92484L,
        0xdc07189329971b3eL },
      { 0x3857db2b5a63e8adL,0xf617d94e5f2e0a09L,0x267e98185844de79L,
        0xfdb103b2861f5f92L } },
    /* 12 << 112 */
    { { 0xb969bd3c1570d6e9L,0x7350b9dbe0fb517eL,0x083b142e55aa543bL,
        0x424757beaa2bc581L },
      { 0x4bd50f6469ea3302L,0x053dcf83ed4c8288L,0xac2b3074c118ac52L,
        0x57f066a8e76ca88bL } },
    /* 13 << 112 */
    { { 0xb9ac28fd0a3207cbL,0x0ec2ad13205829b0L,0x76216e564f403b64L,
        0x7eaef6626621dd5cL },
      { 0x9e0cc8364b06ac54L,0x16ac3c6c9648523cL,0xe1208a1a08eec1d8L,
        0x1e90b3a2be054a54L } },
    /* 14 << 112 */
    { { 0xdfab7f9223a836cbL,0x624d6bd26f7674c8L,0xc34a914cea06210aL,
        0xba5314ecf26c4f23L },
      { 0xd440b196a33a11cdL,0xf81ab63e75eb951fL,0x05ebb91a39350f0cL,
        0x3f3c08ec92e9528fL } },
    /* 15 << 112 */
    { { 0x54ff88444fe6f4e6L,0x217c0e0279b7ba49L,0x13c4372bbf3a4179L,
        0x6e5ad10ba1434264L },
      { 0xc842654062bd8ff2L,0x7c3dd28485fe6ef1L,0x2c59b30005da0e84L,
        0xf303ed9417468e18L } },
    /* 16 << 112 */
    { { 0xe19fac99a211ffd3L,0x408f94243f1f6bcaL,0x1f5b76d1a5648244L,
        0xef3942e895b2bd67L },
      { 0x1b9dee7fb538f1d7L,0x1cb78620444b8f85L,0x9f8ecd63cb8ea6a3L,
        0xca111b2eb9d3b71fL } },
    /* 17 << 112 */
    { { 0xff83d71ebdc4e8e2L,0x43745ddb3f76a9d5L,0x72db22a9a25856eeL,
        0xf34d5aa25e9a9ff7L },
      { 0x01f6b5f3bc529902L,0xadf5d31e086f4867L,0xbd88674fca556b56L,
        0xfd00120dfdc81625L } },
    /* 18 << 112 */
    { { 0x90fbaba0fdde77f6L,0x266d3bfe559ec6e7L,0x372acf54c8094357L,
        0x772bd8e46c61bb78L },
      { 0xcb2ac5921af9aefcL,0xacc3dc9b5b178386L,0x0996308423438463L,
        0xae84f9738359f1e6L } },
    /* 19 << 112 */
    { { 0xc3b19aa0a4cee642L,0xcd5ca5c8b19a918fL,0x46ac0d2ee67cb207L,
        0x2ae45e1073ffebf2L },
      { 0xf84aad8e10ef065cL,0xa0af57fa32a7e903L,0x4229590443d346dcL,
        0x8d6f711d7f170965L } },
    /* 20 << 112 */
    { { 0x11aa7070b110cffeL,0x091a100d9755605dL,0xc5a0c654d27d86a6L,
        0x1031a244db30feaaL },
      { 0x36804045c02228d9L,0x1877fc678b746039L,0xba554015e09bb238L,
        0xc50d8f921de9b40dL } },
    /* 21 << 112 */
    { { 0x29e40d88032f7a2cL,0x514b56dd1d315ec2L,0x9052652e61778f04L,
        0x0d2bc606e1a1c195L },
      { 0x375fd7ecb05043aeL,0x03b825776eba4d1bL,0x8e61b567c349b39aL,
        0xa670973ab35fc43bL } },
    /* 22 << 112 */
    { { 0x80c05ca75571b4a7L,0x95d14f498a4af0baL,0x96767cdb67bf4290L,
        0xb293372f46870ef1L },
      { 0xc64944051afe1027L,0x9f027a1c9019c4c2L,0xa392ac59188a593aL,
        0x68acca2ffcb6e1caL } },
    /* 23 << 112 */
    { { 0xd8f86cbe68ed921bL,0x24679ac2712d2c07L,0x18fbdb214e672cd9L,
        0x401bb71851d1f8e1L },
      { 0x688792e1aa8da4a1L,0xedf9266f3ca93d06L,0x5ddba14aaed484dfL,
        0xa5dab102b0ea10a5L } },
    /* 24 << 112 */
    { { 0xd397edcd833396eaL,0x78a75693ed5e6747L,0xf2c844ba1a5f8260L,
        0xbcafe59d5fb9fec5L },
      { 0xa2413d5fd3147e7eL,0x130dd9e3afdf26cdL,0x44be87ec9ad1abdeL,
        0xe925c4956e77fbe8L } },
    /* 25 << 112 */
    { { 0x07ce8d96f26ced16L,0x36c8564386ef7306L,0x62545902c7e3d409L,
        0x1747bf4a2ed4d38eL },
      { 0x6fe6fc3d55adc839L,0x20a3cc098eaf64a8L,0xc1e9b766622887b1L,
        0x7b9d2f96c41ac659L } },
    /* 26 << 112 */
    { { 0xfdb897cef2a65e45L,0x0c09c90597889eb8L,0xa15df10fe4becf5bL,
        0x14a3d4feccef7e40L },
      { 0xedaa11f6a8fc67bdL,0x7bf6fe9b5d185b42L,0x7bb9f1f56f9cb5c9L,
        0x1b4ab74ef97ea9cdL } },
    /* 27 << 112 */
    { { 0xe9ebf11d07638d62L,0x413a4a87a78cf538L,0x93785f86570dd371L,
        0xba431a91fb48063cL },
      { 0xf1f2ea5b4ed4e5faL,0x91a72c475308325aL,0x4e6518e7c9ea6acbL,
        0xfeaf4c3c208f67e3L } },
    /* 28 << 112 */
    { { 0x98c5d7682c16bb1aL,0xbf91b62dee31dc08L,0xe9ad408d33a54959L,
        0x9d754a6438b7170bL },
      { 0x106db7bcd9d6da2bL,0xf556cbb4add533afL,0x62db0de0f16d3b58L,
        0x78a1b0be1fa579baL } },
    /* 29 << 112 */
    { { 0xda96740b7b552058L,0x0c689cc6626c4d93L,0xee3dd5c9af68e53bL,
        0x78653a9f134d763bL },
      { 0xec9c1b723ca5aa67L,0x67471dac7d56992eL,0x0a97dffead1d8580L,
        0x11c7d93d0063c040L } },
    /* 30 << 112 */
    { { 0xb79e355c6e90b157L,0x2c06edcbd9c894c4L,0x9b93189771a75ed7L,
        0xd7f002478e95ad91L },
      { 0xfce1b489b85bf054L,0xa3ffb8fd503b38bfL,0xe7ea3ad4e0fe2ec9L,
        0x0f32f5200049865dL } },
    /* 31 << 112 */
    { { 0x33afa324cff21b51L,0x3d6847d762a1cd24L,0xf534e1590b06ce2fL,
        0x24d27b3dae7cdae0L },
      { 0xb727db294ad68ab5L,0x7e8e47e3b63c0bc9L,0xe81f312202389039L,
        0x0c281f5288e6a17cL } },
    /* 32 << 112 */
    { { 0x3cc00e21091e1c4cL,0xd500db44867ccc75L,0xa8e2e84bf5ebbbe4L,
        0xc3266881c4279ac0L },
      { 0x2e8fb4de7a170658L,0x219c5ec151da4a2eL,0xda69a3fdeeacee19L,
        0x9d4c6fbd30462243L } },
    /* 33 << 112 */
    { { 0x43673fe8a978c29eL,0x6e825c955861bbc1L,0xb41d1435dba8e7baL,
        0x0f286f78b885d004L },
      { 0xea42b7fdee57436fL,0xcdae14bcef7e29c7L,0x50cff3f024251056L,
        0xf60809fe6f6e8cb1L } },
    /* 34 << 112 */
    { { 0xee9f1d1512932e53L,0xa6e55cd6167d5097L,0x5df8816d9d926359L,
        0x108e2117797b7ecaL },
      { 0x7ba2031991921587L,0x304138e4ad23652eL,0x73d0ed5751ebc32fL,
        0xe0c10a38f01d0fc3L } },
    /* 35 << 112 */
    { { 0x14c6b72f78c49b19L,0x4f952b7e3b7c7418L,0x3fe75d21a2d019bfL,
        0x4837bfd27ca33e87L },
      { 0x4597729b3946e7eaL,0xbe22c14a4c37ea10L,0x91106c7cd7909474L,
        0xfbf1e7dbbf5551a1L } },
    /* 36 << 112 */
    { { 0x8e06336c55ffea13L,0x0deaeda00a1f99f5L,0x9b738c4bfda98fc9L,
        0x061cc613a59c98baL },
      { 0x5ceb5b83b477692cL,0x5db775591fcc473bL,0x77214b6283df476cL,
        0x2ffac971427ea01dL } },
    /* 37 << 112 */
    { { 0xf29f600b49fd0ba7L,0x1106f8b27233ef79L,0x706bc171e8a0ca35L,
        0x4da7a9e6acbff08bL },
      { 0x17c2fa4e7725f97cL,0xab459314e84a5095L,0x01556f146b24d47eL,
        0x01399059b016dc1aL } },
    /* 38 << 112 */
    { { 0x154b84c728eca6c6L,0x88ed8612d9084e68L,0x4dfd508000bf9b5bL,
        0x853cd8abba9a0ccaL },
      { 0x8cbf9bd88af0e94bL,0x50782b7383035d16L,0x694d3e654f44533cL,
        0x155d4bf4a6e534ebL } },
    /* 39 << 112 */
    { { 0x9028e2abee908b6bL,0x36e5aac0a6743060L,0xd26f5a513c37d6f1L,
        0x8483703e33729b9eL },
      { 0xf27a66032e5f82a5L,0x33bf2bdcca55d187L,0x894c415c7724a85fL,
        0x9255d416a2ea178dL } },
    /* 40 << 112 */
    { { 0x35ecb4e20a6dc5b9L,0x8b3fc2c851c54ed2L,0x059f86eb9eede13dL,
        0xa796c750791dd5ebL },
      { 0xb2f33680ea88555bL,0x927309501245348cL,0x1a5545f8d1e63bfbL,
        0xfebc9a14bebb7858L } },
    /* 41 << 112 */
    { { 0x13cce7676bdf0c84L,0x1aa9dc07a1d341faL,0xd46e8ff61ee6fa43L,
        0x4198e5d64b1dda64L },
      { 0xe82a81342782abd1L,0xe6f7b1b4b6d64830L,0xabe002747f0fb374L,
        0xf1a8e2b77494d7d3L } },
    /* 42 << 112 */
    { { 0xd16b0d9ef274f296L,0x3c94a7ac65246ee9L,0xd32c32da91ec2262L,
        0x04c7bb9083116ec1L },
      { 0x70fa040678524a06L,0x8d2d517607df8064L,0x13e589f2e2c8d48aL,
        0x3b110ac4122aed4eL } },
    /* 43 << 112 */
    { { 0xe8e0eb5234e972cfL,0xc082944afb3a77feL,0xcdaff7a36a32c23bL,
        0x88cc568dc37b4a2cL },
      { 0xc9979a9ce27b2552L,0x8612ae7dd6ef51f9L,0x7bf0f937ef4e8f85L,
        0x2f360a583f12d45cL } },
    /* 44 << 112 */
    { { 0x3ec9d0e39b336663L,0x5ac2df38b1438d2bL,0x7f2de910ff93fde4L,
        0xbbc460dad92534baL },
      { 0x74de315959a94ab9L,0xd51cfd32c45b80dcL,0x9f1f349c6e5b2397L,
        0xbdbd16ed995f7271L } },
    /* 45 << 112 */
    { { 0x4a7efc1cf59709a6L,0x74e2760d4b3db99aL,0xa7238e9e7726a2e1L,
        0x477642081a376013L },
      { 0xbc96f3967e33ebc0L,0x31e159e6c9e4ec0dL,0x26a5aef26a2ab9f6L,
        0x23add07c320eeea7L } },
    /* 46 << 112 */
    { { 0xa79a97c9833b45b6L,0xb08da907c51885e6L,0x23f5e651ae8d5659L,
        0x1eb0be481faff2f2L },
      { 0xe414ee3da1e090daL,0x16e4f8fa7fcb664fL,0x7a15a7e498c36865L,
        0xea60e8fdaf89dacfL } },
    /* 47 << 112 */
    { { 0x4e009f4586c1a4b4L,0x78c1bebf769644adL,0xa41b480f0b4b3501L,
        0x98be503757f0a0e9L },
      { 0x069348873af24657L,0xe2503ddb2b6260f9L,0x37c936c2d1d0caaaL,
        0xd371e99116431f50L } },
    /* 48 << 112 */
    { { 0xd9621d166087c5e5L,0xae49c2cec53a8bc5L,0xd7868882cad314cdL,
        0xfde10dc7aa57af18L },
      { 0x3fa8a60d3800f397L,0xcec8ae7b388b333cL,0xefd8d69285fa8129L,
        0x33d5685b90776c32L } },
    /* 49 << 112 */
    { { 0x47ecec0a65971a6eL,0xe8a20bbead7c5755L,0xbeed0a4d87372016L,
        0xd0d499bb1d9b8dc0L },
      { 0xf4ce27cd2800907dL,0x07a30b778622bbb7L,0x7532f43577e264dbL,
        0xfdd1a9c3d64f0710L } },
    /* 50 << 112 */
    { { 0x92ca210fa6543720L,0x2f19ed665bb6985aL,0x08a4ac61f9399b43L,
        0x0b7bac5d757f241dL },
      { 0x93ef27cc3763c20dL,0xda3b206ea86b1f05L,0x8f19c74ad62467c0L,
        0x3ec5ef6d6a3ad263L } },
    /* 51 << 112 */
    { { 0x249aa6362bc8b9f0L,0x0fca73187f70990cL,0x6d4aabc56f038497L,
        0x4647f72b5afaaaefL },
      { 0xc7cbe03a7bf90444L,0x6beb69accac2efb0L,0x58544ebabb3c6dc0L,
        0x569cdcd696aefc2fL } },
    /* 52 << 112 */
    { { 0x2e8a4c575e4c950dL,0x6f5341d74dd32002L,0xd0345db66efa5908L,
        0x4b043197f1d2bbe6L },
      { 0xde8a4cb6e8730baeL,0x9a89231fa485cb62L,0xb24ace89fcd9bcd4L,
        0x01892cc03ed5801dL } },
    /* 53 << 112 */
    { { 0x80ce2f30413408f9L,0xaf67343af8773b6aL,0x91acc6d2dd6ade17L,
        0x9d2ffecae5eb3defL },
      { 0x72f8af0650b029fdL,0x339c802c79c0aabdL,0x46161fffafc0a6adL,
        0x1046d9f8bac9a2d4L } },
    /* 54 << 112 */
    { { 0x2f12eb06ab920e51L,0xfc0049002892e552L,0x9aadf93e13e61154L,
        0x4468da94abcfd127L },
      { 0x6a5d3ffe152f220eL,0xe6260c234737fe79L,0x8b5dd1c95e6b4251L,
        0x044f06569af02b98L } },
    /* 55 << 112 */
    { { 0x434d475ca97ff366L,0xbae8db8e2c4bcc46L,0x2ba43a8bf9777251L,
        0x7ff430a5dd019f1aL },
      { 0x65e9f290630064baL,0xfc57a54e7e871c0eL,0x54107bbb5791ae48L,
        0xdfce137f5c334de0L } },
    /* 56 << 112 */
    { { 0xab65c8f6aed5be73L,0x838c3958174bf00bL,0x27c57199f1c7e594L,
        0x62643d810d02fae6L },
      { 0xc1e70c125f4431faL,0xfac86124b2b41f7eL,0x062ac35af0108e3cL,
        0xd7d34dfca43d3a28L } },
    /* 57 << 112 */
    { { 0xc40fb44a3143de4dL,0x06eac4edd2e0f9aeL,0x998f321195d9a69aL,
        0xb268f6a0e950bd2eL },
      { 0xadfab2101e9d4e40L,0xc453a68c73ce9324L,0x5e2f254480881171L,
        0xe4f596dbee7e543eL } },
    /* 58 << 112 */
    { { 0x77f48e4e76b6698eL,0x47b5165f227365c6L,0xf56ec8d414ef39e6L,
        0x1638d64774ce46faL },
      { 0x244d0fac08aa8b9aL,0x98ccc4d0298326c9L,0x492d7661ce0d2983L,
        0x728b3e3f73158cdaL } },
    /* 59 << 112 */
    { { 0x7959ca67c4948011L,0x32044ae908425a38L,0x05a7a6a7b1070c2bL,
        0x34ed541fcc129ba5L },
      { 0x4b6bf65cb2f1c3e2L,0x6f090ce6d0d8aec8L,0x11ade23ad4fe39c1L,
        0x50510c08a5a35528L } },
    /* 60 << 112 */
    { { 0xb7e2a5dead6fd7c6L,0x9d6919392745dca8L,0xff669c38ad053184L,
        0x394ca6b7ecd0703eL },
      { 0x59e32e8060b15e75L,0x82dde88913c14864L,0x0fd1624c64d4f086L,
        0x7fb502a7c9893d7fL } },
    /* 61 << 112 */
    { { 0x59b86bcf711479a1L,0xfd4bc4d8c40b44bcL,0x2fae18f5988100c3L,
        0xe4af2f4f615867d7L },
      { 0x7d45e1e8be479e28L,0x547accbda04798a5L,0xe88a85b11c458b5eL,
        0xe144f7f26032f0ccL } },
    /* 62 << 112 */
    { { 0xad5276d33f807365L,0x5b6519e7b318a6eaL,0x5889cbb52d0fcf50L,
        0xdce91cab2bdab4e0L },
      { 0x17b6249f41b78954L,0xc9320b656f10449bL,0xe38a7cc0f264ae8fL,
        0xaab8803e52b85829L } },
    /* 63 << 112 */
    { { 0x63668621dd97973cL,0x5aaedce7d04138c7L,0x8e8e66141762874cL,
        0xd0cefcf4163fc862L },
      { 0x0ebe0048ffed1aceL,0x070c33487a8c2673L,0xb801d1599b0d3fd7L,
        0xf1d55911922d4842L } },
    /* 64 << 112 */
    { { 0xf0acf768680dcbf9L,0x5072b8254f0a51dfL,0x3a74751cd88df9c5L,
        0x9d20f9891cc1a332L },
      { 0x4e90042b6926c34aL,0x5c728b1e00766880L,0xf2e3bfe8f76e9dcbL,
        0xd9822f0a15a125aeL } },
    /* 0 << 119 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 119 */
    { { 0xbf84db58f51b14b0L,0xdf73ccf5a39a79f0L,0x0ce1e5842b5a1f11L,
        0x841fa6a3185fc400L },
      { 0x94b09c682455c32aL,0x383c9bdebfa71cc3L,0xb63814861e797929L,
        0x33036faf623d0a5dL } },
    /* 2 << 119 */
    { { 0x41b6cf7c90f17cbaL,0x5d655ff430c7c5f4L,0xc64f29d54ccc7f38L,
        0xf28e85316124a79eL },
      { 0x1efa8d5167bf1e98L,0x8610027f5d7a33b0L,0x35fe2bb2cb9a40a4L,
        0xc5cc1bf143d50a0bL } },
    /* 3 << 119 */
    { { 0x84dbc60546e33870L,0x23d8d2e5843c4e1eL,0x69964b5e4cf8b569L,
        0x2a5228e8e0c546a5L },
      { 0x4c0467ed96d6e111L,0x25764cdfa12bd298L,0x92a3e7fafbaaad46L,
        0x08ac1d36d12fa469L } },
    /* 4 << 119 */
    { { 0x60ae2bbfa32106c2L,0xef155b2a3e917750L,0x5567c3c713853a30L,
        0xa6be8290eddb305bL },
      { 0x2db58c21ade26eecL,0xfa3c895c003c17edL,0x96ab0de16293f8a2L,
        0xbd2365ecac3710c6L } },
    /* 5 << 119 */
    { { 0x93ea85536aa24f73L,0xf75140d0e0410c40L,0x760cfa2faff0f7f2L,
        0xc6dfb3c73e580d68L },
      { 0x25fc2091c16d39e2L,0xa05b0c8119e1d5e2L,0xd4d223d862bbec7aL,
        0x11a93775f293f34aL } },
    /* 6 << 119 */
    { { 0x9ab03e73e194c642L,0x607b7106789e3c85L,0x952aab024bdacd55L,
        0x31ca3ee221cc6084L },
      { 0xd3149b2b1c6b93f9L,0xcbc5ef3bead930f8L,0xed04984f22872630L,
        0xef5d052d6c4b6fe2L } },
    /* 7 << 119 */
    { { 0x808ae6c06010ffa2L,0x88b6fcd81143166aL,0xa27802635ab945ecL,
        0x4777b4aa36db5012L },
      { 0x2156bf83059aa3c7L,0xcbef6fb72a660260L,0x189fa2218b366ce5L,
        0xd6f5bdaa08290914L } },
    /* 8 << 119 */
    { { 0xd2028d0557028677L,0x90eebeebce9aabdfL,0xab977aee06d4e5d0L,
        0x7a98c527f9361873L },
      { 0xe49b1251b7c2474dL,0xcdaf2a365f3e7b02L,0x638bcaf46fe54af1L,
        0xfec426241dac06b7L } },
    /* 9 << 119 */
    { { 0x422be2253741a88bL,0x1f3b82c35304f139L,0x101eab8e181c2fc2L,
        0x8522738e5898163cL },
      { 0x0372d05f2d2bac1bL,0xb65c786c1d1f3c42L,0xbd59694b64e2f5b3L,
        0xf1c424bf24c5671bL } },
    /* 10 << 119 */
    { { 0xda738cf51eafe37bL,0x503eac2430dd7c2bL,0xf9b7b7a511dd77afL,
        0x0ade03afe9dcfe7cL },
      { 0x489bd34af479e3b5L,0x993ab403030a33f3L,0xaef322bf9fb64068L,
        0xa47cc71b0e27f110L } },
    /* 11 << 119 */
    { { 0x1c445554efab99c8L,0x7c3c51e7a7f10e58L,0xaa8b43ee78a87474L,
        0x037d63972418475aL },
      { 0xc9c751fe10324911L,0x3d65d9e03e0797d4L,0x98b68d2b7dea2a63L,
        0xa211ed3bf4afca19L } },
    /* 12 << 119 */
    { { 0xe19ff8f8c63b9e75L,0x43f6b4fc0d7d130aL,0xdba3385d7c8490b7L,
        0x97889df70252c14aL },
      { 0xfccfca86b2f18b9fL,0xf092ff9ec3a87422L,0xf96dd67567474838L,
        0x039e82875bad2e9fL } },
    /* 13 << 119 */
    { { 0x7ed85e7052e041f6L,0x3d6ef1e7cfdeb19fL,0x9f9fe3990d9ac66eL,
        0x5825e7bf16cb8554L },
      { 0xecffdf90d954a4d5L,0x8617ffdd20678fc5L,0x3e974054666df77bL,
        0x748379d1b5d92788L } },
    /* 14 << 119 */
    { { 0x46a609112da32c0aL,0xb2e1ac32b2676ca3L,0xfb74093f17614dc6L,
        0xf44939e43f27f965L },
      { 0x4656a402c922422bL,0xd60a55ba3ff5c56fL,0x0d061b41ab9aa62eL,
        0xc9ceacfeaca3acd2L } },
    /* 15 << 119 */
    { { 0x056d5718d946003bL,0xf8530d6d2c7815f3L,0xbae14342706536b8L,
        0x45c96dda2b901188L },
      { 0x386d88b6c64ed946L,0xb70170226c00f1c2L,0x28519811ec8988dfL,
        0x3b011fe25a05cffcL } },
    /* 16 << 119 */
    { { 0x4f581d47515f954cL,0x145f925b7f470a40L,0xfee6b6b0736feaafL,
        0xf90744af2ea5743bL },
      { 0x4d8e8ceaa2f36f56L,0x4239a6cee3ed4007L,0x0906b5bdd515e6dbL,
        0x536229908ac973d1L } },
    /* 17 << 119 */
    { { 0x472ceb94eb2fe229L,0x0775ed416a121363L,0xc0492e07761ddb38L,
        0x80c24d51aef9be2fL },
      { 0xa2a3982bdcba73a1L,0xe0d839784e26d062L,0x794959a8cd41c930L,
        0x7d2a88d770131161L } },
    /* 18 << 119 */
    { { 0x48f93fc3f4f966daL,0xf92691a0ed5b6487L,0xc5a93e5dada2c1fcL,
        0x4a7aca524b7d9243L },
      { 0x810aba93d7c5598bL,0x98f9ead225109638L,0xe8c6e893a388481aL,
        0x56e96b9be91ce74bL } },
    /* 19 << 119 */
    { { 0xfa1e5dc3d935f591L,0x985bb06c555eb816L,0x6478c518c4d14e69L,
        0x48afbdbcc7f47349L },
      { 0xbde9093326fed96cL,0xf9b96f41cd468186L,0x22de6a29730e8518L,
        0x7a3dc912915db842L } },
    /* 20 << 119 */
    { { 0x8d13b665fc1f9449L,0x6e9932a9dd4bba75L,0xa90ce8e5564083daL,
        0x8a7cf362bbf7989dL },
      { 0x652eccb71b07ee2fL,0x0c0dcf1a6857a141L,0xa87ec410b7bfb43eL,
        0xaebdb7e782b8d179L } },
    /* 21 << 119 */
    { { 0xeb3bc468625a24ddL,0x7e45e47b463b1f89L,0xc301353500c75a48L,
        0xafea920d13778807L },
      { 0x0d1e927722dcef16L,0xa2a10f6786cecfd6L,0xad40e29cd7160bf2L,
        0xe78e6589eac1265eL } },
    /* 22 << 119 */
    { { 0xd3a243100c62c041L,0x4d27344a6c03c747L,0x0b19e4a67d3ee9d1L,
        0x9cf2eccdcd90de33L },
      { 0x673a9d1ffda636a9L,0xb7349981a86ee501L,0x11ca1e49e43766edL,
        0x0806af6fe3ff3b08L } },
    /* 23 << 119 */
    { { 0x213043388a01f119L,0x58a6d3bef3cb268fL,0x40ceaccae37d7851L,
        0x18694595ef5b81e8L },
      { 0x35678ed784bad32aL,0x4f280f92d1624256L,0xdecb1f1efb28709cL,
        0x2a7f3048164911d7L } },
    /* 24 << 119 */
    { { 0x32551d31579d8a41L,0x754c7c2460a5ee33L,0x2c53fbff6a88f85fL,
        0x6ad0bda72c7a36a0L },
      { 0x8b3674f815724d6cL,0x614727ceb9b7b34aL,0x384fba9882ca9cd7L,
        0x8ef4343c0c566025L } },
    /* 25 << 119 */
    { { 0x5645fefb64886c98L,0x702befb30f5c29e8L,0x6d74a7e046de1523L,
        0xcb2bcdb9b1302163L },
      { 0xe65cff39ab4ca69bL,0xeacb7103f2d4f6ecL,0x15826c2d1770d3efL,
        0x38b008f13f710600L } },
    /* 26 << 119 */
    { { 0xc68450cb4bc7dccbL,0xb5f11b269e5f2400L,0x2af58e9e9c3a833bL,
        0xb60e2672a058abaaL },
      { 0xe891bf8c75b080c0L,0x5b09b2762434bf38L,0x0d90a040700b8739L,
        0x995cb042e69f4a0bL } },
    /* 27 << 119 */
    { { 0xe30df0a144a56b84L,0xbaf92d161ead5a62L,0xe214a0626e0193a4L,
        0xd41de5bce9758b9eL },
      { 0xcf214213732d82d5L,0xaa1421f6f949f07bL,0x5f38c91ef7fb101cL,
        0x47ce2ec22a3e41e4L } },
    /* 28 << 119 */
    { { 0x6bb34768240c7897L,0x80ff54ea7b45473eL,0x16acd40f82fe5aacL,
        0xa3e76f524350449fL },
      { 0xf7a3579eacacbeb9L,0x9791e0e07bc40732L,0xb26da7b5bc58cb9dL,
        0x11d9fc80987e18f4L } },
    /* 29 << 119 */
    { { 0xc3c189a81d8e0d34L,0x3011097c2d42e0b5L,0x4e38593294ab9371L,
        0x79e0c2ce0c237147L },
      { 0xc9f171227172e6ceL,0xf8d73b1d9b89a008L,0x91690c6ba945995dL,
        0x089eb941c15306c6L } },
    /* 30 << 119 */
    { { 0xee5f526d12ac8df5L,0xf1dd23f73bf94c65L,0x594ceaac81a3cb0eL,
        0x07d41d3b9757cc8bL },
      { 0x9eb0081dfc5603d5L,0xfb5d329857bd230cL,0xf2c0402ecde3f845L,
        0xa2defd6741e8aba6L } },
    /* 31 << 119 */
    { { 0xb300802a2dd9573dL,0x64e401a560c1ded3L,0x19d4a6778ab1d3d8L,
        0x3c2092f2cca04f74L },
      { 0xf4827ba5ac40056aL,0x49d4cf229c09ddc2L,0xb2b00f6bdbf20277L,
        0xc9ac48d45b281e9bL } },
    /* 32 << 119 */
    { { 0x648d667432efbbceL,0x64a6c2b3e9639719L,0x38c0465730662e7dL,
        0x15d1d7ca352c9184L },
      { 0x70e8630ccc3020ccL,0xe4b56c9cb09f038fL,0xdb9cb5edfe76a744L,
        0x4c85f0206947b988L } },
    /* 33 << 119 */
    { { 0x7e50012629d8add4L,0xdbcfd295bfaf6d7eL,0xc1a1c22838df80beL,
        0xcfa6272af606ce3dL },
      { 0xbf2a57208e0af540L,0xb9c544fd5b599ab0L,0xd6dc994dd0a22c9aL,
        0xa8a12acfd23e4c0eL } },
    /* 34 << 119 */
    { { 0x41f7ac85ba588a5eL,0x5425fa00ccdb9687L,0x12fbce76ec9398f0L,
        0x2ad692514f550b9bL },
      { 0x120ff0f2bb318636L,0x9378346c01ecd90bL,0x1b98fe99d0ba149bL,
        0xd69d5462c9c481c8L } },
    /* 35 << 119 */
    { { 0x11c79184959e428eL,0x9de61a8dcff227ccL,0x144dfdcd1e09b860L,
        0x110c3a47f8ebe350L },
      { 0x59e574dcfadf86b0L,0xe6ff6e12cf3b8d30L,0xe2d512fc19c77143L,
        0x6346154360279af1L } },
    /* 36 << 119 */
    { { 0xff65189c32b4d371L,0x022fecca0faf5ba7L,0xd08fe9bf414707b4L,
        0x0ef8af2b722d5fd2L },
      { 0xbef060634e6fa14aL,0x1c41f752cca29177L,0x17dc7e1865091fe1L,
        0x693d72d223f13c18L } },
    /* 37 << 119 */
    { { 0xce88eb02ce8e2d30L,0x7071f98ae972facaL,0xb7388d61549c38eeL,
        0x7cfccee20b788b8cL },
      { 0xdc470705cb93b5e8L,0xea053c18ab96d485L,0x70e96456d634c9b3L,
        0x2c58c20bd5999cf2L } },
    /* 38 << 119 */
    { { 0xcd392b3ca77c1767L,0x14471fab7c4e6bd9L,0x312e154775c905ffL,
        0x45764654ace47038L },
      { 0xa34a0b0e8fc3d697L,0x5d9ad31ad309ed3aL,0xbba340c00918f957L,
        0x768e06e831fd72a1L } },
    /* 39 << 119 */
    { { 0x77e5dd923e1a4a54L,0x0970719f3fdbc1e1L,0xd4f1da6fb0371fe2L,
        0x3635f433fd7f895aL },
      { 0x0e8e40e6411c8e6fL,0x31d126bdec18103cL,0x415a0cc1c299d7ccL,
        0xdf528e7b3a8e97f1L } },
    /* 40 << 119 */
    { { 0x4551a8c7eed95e91L,0x8de8988832bcfb03L,0x25da4f5f2eac5c3aL,
        0x6d0b2e255f88d63fL },
      { 0x8d158d14575d6145L,0xe5601a6b345f62b0L,0x6f951699113c6895L,
        0x79e29fd5b87e50efL } },
    /* 41 << 119 */
    { { 0xf1ab215cd5fa51ffL,0x4fc5c4eaaf2c3094L,0x1baeda402c006042L,
        0xcdfcc37c3e30e75fL },
      { 0xdd64e5dd467f57ebL,0xa5b1373122902d21L,0x856866dd1c52cb7bL,
        0x05cf0f7a16a08caaL } },
    /* 42 << 119 */
    { { 0xa46e8a55533b4d09L,0xfc8039984e073af1L,0x8e3825c8e0d589c3L,
        0x505e8e5d4c1daef3L },
      { 0x9f8363b1c5f3db12L,0xe7d4670074f569e2L,0x551fd2ed4d68461aL,
        0x26248da5a8bbe83dL } },
    /* 43 << 119 */
    { { 0x8d90c47f65681dbdL,0xe726d25e2200ba6bL,0xa2fe408f65a3bc9bL,
        0x94a804579c443b57L },
      { 0x95f7f02407364677L,0xe9d9bc87daf0fb34L,0xe90825485588e979L,
        0xede1f94da0e61ff2L } },
    /* 44 << 119 */
    { { 0xcb89a1e845e1c230L,0xee014c2350a15304L,0xf25d8ffa2bab57e1L,
        0x8a92068026223c6eL },
      { 0xc5abb7afaadf7e6aL,0xcb57c8939e7d8da5L,0x839bcda07d589a91L,
        0x1fa774c077e82027L } },
    /* 45 << 119 */
    { { 0xeca669cfba6504d7L,0x7bf095446845e47dL,0x5eb6c33e607b3641L,
        0xf445556e64bab450L },
      { 0xed0b1c0286096fdeL,0x2c5ba6668ea41693L,0xe578b31537ec248dL,
        0x97ef44fef64ed28fL } },
    /* 46 << 119 */
    { { 0xfa5a6c46ce419462L,0x29336dc99cce80e9L,0x9e9054b9eee7617fL,
        0xcea9a100f3d51cbaL },
      { 0xc3cce5e813267ec6L,0x650c8383a4e807e7L,0x1338e22e9b2726dcL,
        0x220c50b2bf79b47aL } },
    /* 47 << 119 */
    { { 0xe160d496a0e0962aL,0xe1a26460e1ed5cdcL,0x9a1ed8c331427c62L,
        0x65ef5300e99a096aL },
      { 0x38abea5f4e3ad558L,0x03bb15e90880ba0cL,0x1e6dda7e0141b036L,
        0xd31b08bf5bf37669L } },
    /* 48 << 119 */
    { { 0x948e036668da20d2L,0x36998a244108fe36L,0x7606e6edf9d6563bL,
        0xcf7cbdd3e42172baL },
      { 0x2335a9a4a1265b99L,0x64776cdc30ac3f69L,0x04040362a59b595eL,
        0x82df96b92cbc03cdL } },
    /* 49 << 119 */
    { { 0xe9d18c7f6cea2796L,0x3112c4f6e1ea7e35L,0xf9cbc2055f8a786dL,
        0x36cc6d422097da0dL },
      { 0x540933502153e665L,0xebe9db0fce937bb9L,0x9d1a5972d95942f8L,
        0x81c1f94ad4bd5c74L } },
    /* 50 << 119 */
    { { 0x61dc7318aa04152eL,0xdf636db195e5ec9fL,0x64a80d4648090850L,
        0x2b37679ece890a30L },
      { 0x9f46d5b9ff6025e3L,0x6eed5a44f24534ddL,0xc56b5cb1f740a84bL,
        0xb4641c28228cc826L } },
    /* 51 << 119 */
    { { 0x676289beaf62b943L,0xe3f3810c1eae5409L,0x73613f3204b5be78L,
        0xe6359179398b556cL },
      { 0x6a342b12c0263f77L,0x6b093bbdc10a6db5L,0x8f3fc90d29832fb9L,
        0xb3f2d8fcff03b2ffL } },
    /* 52 << 119 */
    { { 0x1de7bd1c64457331L,0x0a03a06b43bb1380L,0x6720cc3d8bf17419L,
        0x2627c7da33938d5aL },
      { 0x204da0588d98f34cL,0x80e29f4651cbd284L,0x11b22dd4a46f93d5L,
        0xd7341655e971a61aL } },
    /* 53 << 119 */
    { { 0x36a748b7ee69f782L,0xa374002094f08ac0L,0x383fb245c36099f3L,
        0xa7cb0ef900137fdcL },
      { 0x5371052f6e1dd2e5L,0xed3ab7b57976a1d3L,0xb0119c0d9df822e6L,
        0xafd2a477358685d1L } },
    /* 54 << 119 */
    { { 0x82879cb04ae1103cL,0x61cd6ca894385be6L,0x7c551809d85d4a62L,
        0x9632ac5fb318d965L },
      { 0x67baad2ce1340605L,0x39c2c8c7ac6ed4f7L,0x42c4a7b171211c2fL,
        0x43c778bb9bf758f6L } },
    /* 55 << 119 */
    { { 0x2dc8fc39f519acb2L,0xd3c30a6d08eff177L,0xf889c0215144484bL,
        0x01b82327ca376af3L },
      { 0x168a0b2fd3e71253L,0x5e92c6ba3f9ff89dL,0x8c74c1325b4c6844L,
        0x707c4a4033de6858L } },
    /* 56 << 119 */
    { { 0xb13f6abd9c36dd9eL,0x4baaef529b3aa9f5L,0x0a4fa929cd156392L,
        0xde0f19566506f42fL },
      { 0xe43dd7f0150d4ee7L,0xf7afe7db7247f552L,0x9abc8d1c9072b450L,
        0x5d0645d5c9a8e159L } },
    /* 57 << 119 */
    { { 0x863d3e8f01c6f17aL,0x3a0575acdf080690L,0xcad62d872b0fb150L,
        0xa1f54744625c35c6L },
      { 0x7d3bcec341fe59ecL,0x0fd3e40e169f1e04L,0xbde8c8272ed9aa4bL,
        0x71562ee613046c6eL } },
    /* 58 << 119 */
    { { 0xaf049c5ce9acac7aL,0x7efec06c261dd422L,0xa530fbfd095564c4L,
        0x000c0c822a57af79L },
      { 0x9f79868f2ce1315cL,0x0dd994531b5d575eL,0xf1a494191e534cfdL,
        0xc7de8756ed7e8b39L } },
    /* 59 << 119 */
    { { 0xef61f5c83ed2ccb2L,0x032ee76634af2a15L,0xe0692ed59f69ae9dL,
        0xd34fc2d5f64900dfL },
      { 0x1c51c950aca6d51bL,0x10ae0fb2a7717dfbL,0x9fa305f7a7ec7ca8L,
        0xb215a8abb5728214L } },
    /* 60 << 119 */
    { { 0x62628fdf8819505bL,0x3cefd86c004ba54eL,0xa17bed74c571da3dL,
        0x362dfef693a5faa5L },
      { 0x1bee6899f8aeea05L,0xd7bf7e3116f18b7aL,0x3f3cf39d1cb7685cL,
        0x1df41f23e2e57c8eL } },
    /* 61 << 119 */
    { { 0x8f62ecb8e2fd94f1L,0x652099c94c30a178L,0xaa2454e14262e9e6L,
        0x7f0d440f2015d4a9L },
      { 0xa2c76313bb5b39faL,0x46e57ab21ab47bb3L,0xd181f4448697e682L,
        0x55db129e33273dfeL } },
    /* 62 << 119 */
    { { 0xda188361e71d029fL,0x3e3e19dab5def631L,0x7431f513087ad30bL,
        0x2537887e9f27c84eL },
      { 0x0c228c62ac9df89dL,0xdcd2c5e910031289L,0x5cc767820321d1b6L,
        0x4e460bdf6cb3d600L } },
    /* 63 << 119 */
    { { 0x6f356aab9a870166L,0x21aecb3b497d4ac0L,0xd981a4b0f0495ef1L,
        0x615e8bff0fb7704bL },
      { 0xc148e8ea8478bf12L,0x7011ec5b364eee52L,0xd9075965f692bc12L,
        0x3019c824e622ad51L } },
    /* 64 << 119 */
    { { 0x349e4873ec83c953L,0xb4f59fb33a21ef0aL,0x3872d31440f7d93eL,
        0x479e1d02c2568c82L },
      { 0xd7e4dc9a65d43d22L,0xcc068e81e775efa8L,0xb78ccae9326defa6L,
        0x8f92b2962da64956L } },
    /* 0 << 126 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 126 */
    { { 0xb721f8d5dea227eeL,0xf48c766c3dda8ba0L,0x0583d94be43e3520L,
        0xebda36c9e1d898b6L },
      { 0x1808286a6627adaaL,0x19c4c6209938368eL,0xe0dbd707f750949fL,
        0xcadf4bea0cf356d9L } },
    /* 2 << 126 */
    { { 0xf5de21262dc890a7L,0x76b7b67595aa75a3L,0x475fc1432a070b32L,
        0x7429a6468e31d68fL },
      { 0xec3a9aaa09be3dcaL,0x07e119a9af780ed7L,0x6212562564fd96c4L,
        0xb571494fe8e80577L } },
    /* 3 << 126 */
    { { 0x955ee3495228d735L,0xa04ef2bb8fc5d4b6L,0x0c5328913600814fL,
        0x41f1f63759f85bd4L },
      { 0x72f1d731e3dcdfb4L,0x28a4ddb93aa5edb3L,0x116a68e1f702dcdbL,
        0x1975bc423bde657eL } },
    /* 4 << 126 */
    { { 0x7b9f561a8a914b50L,0x2bf7130e9154d377L,0x6800f696519b4c35L,
        0xc9e65040568b4c56L },
      { 0x30706e006d98a331L,0x781a12f6e211ce1eL,0x1fff9e3d40562e5fL,
        0x6356cf468c166747L } },
    /* 5 << 126 */
    { { 0x80e87329429945a7L,0xc619fe17b7ab06adL,0x9116bc2e6fd86b17L,
        0x64a41877b9116aacL },
      { 0xe3ed867e32ba4f3bL,0x013e263b68b4ebe6L,0x305ebfe7e779e4ecL,
        0x5536d45d50178251L } },
    /* 6 << 126 */
    { { 0x5abb939f8873a93dL,0x0263ba488c4c9cb1L,0x36764b8d6b78a4b5L,
        0x205bb45d28bebc1eL },
      { 0x16df4bb0ae89dcd5L,0x85994670316fadb7L,0x71f756643af3c724L,
        0x43e30313e8520c9cL } },
    /* 7 << 126 */
    { { 0x3ab9ec5429e91921L,0xd931436ee3299f47L,0xb56da7bfb89cd49fL,
        0x90623412cff7f637L },
      { 0x751e7944714022deL,0x86bcc3422c338262L,0x85f6a9bc314c23bbL,
        0xedbe8e741f0a3991L } },
    /* 8 << 126 */
    { { 0x7a748d63003b40ddL,0x8a6824023951b7aeL,0x41e92dd9704a91b0L,
        0x2dfb3eb9858cd3eaL },
      { 0xc3c2af35f5094667L,0xffa287dc7435aa2dL,0xd03f39797462714fL,
        0xdb550f67203e5b0eL } },
    /* 9 << 126 */
    { { 0x6df7801be241ed0cL,0xb52c0a3fb642fd3aL,0xdd35e1cf1977a29dL,
        0x8e793d60a661404cL },
      { 0x393e2b876b9442aeL,0x123b893a2aa6b707L,0xeec88682db8d306aL,
        0x92c2d93dce847879L } },
    /* 10 << 126 */
    { { 0x725f1e7d80ec63b4L,0xcb8f53d974113de0L,0x2132a072b819f730L,
        0xfabf3c47b4c61f06L },
      { 0x79c1bc862cb243d8L,0x442833c5757e3600L,0xfa4f69ad4e918b8aL,
        0x5816f3f373bc193eL } },
    /* 11 << 126 */
    { { 0xc671c7a430f40e93L,0x6041aa035c51cfa4L,0x3a7135492fac25d7L,
        0xf505323724a7df01L },
      { 0x99efb34ad29f4ec5L,0x7481052371d2cb1bL,0xacefaf8ff3a029abL,
        0xc82e4f5a069d9545L } },
    /* 12 << 126 */
    { { 0xd759549dd3341d80L,0x079e9fa731a2a0a4L,0x75da56c72a164f75L,
        0x9313ef5abeefc182L },
      { 0x0aa365b6bde130adL,0x4426597798411180L,0xa65373f7aa26466aL,
        0x1a43bee62e2cf404L } },
    /* 13 << 126 */
    { { 0xe029ed6db37a9390L,0x5c2351ca34970065L,0x7c4f3c301c46d72cL,
        0x09ce770a7262ce20L },
      { 0x0cfeefaddd58a9f8L,0x06797d79408addaaL,0x76a87c0605aed325L,
        0xe002b6728a46d0c6L } },
    /* 14 << 126 */
    { { 0xcf77ea3105b6e1a4L,0x3bf900bca5d92b00L,0x05996d8cdccfe144L,
        0x73d4dfd7951a602cL },
      { 0x033f39590ed8885dL,0x8332dc7336400817L,0x963722952d8ebda7L,
        0x3fb32cf6b5da0c67L } },
    /* 15 << 126 */
    { { 0xcb521d653e36defcL,0xc293d170a67f00f0L,0x6a3a2fd4fb35bd06L,
        0x537937dd0bd490a5L },
      { 0x898d94bcc274ee5aL,0xdc70f9bd7515b5e7L,0xa94673db3749900fL,
        0x3e6e2af049ad3b04L } },
    /* 16 << 126 */
    { { 0xb9dae1b8207eecd9L,0xd3f50d63ec07b47cL,0x02b4d909364292daL,
        0x919a6df3fc35975bL },
      { 0xb41ed4aab616452eL,0xe58689cd5cfc6abbL,0xeac325d9f389b025L,
        0x45ceb1e68f255de5L } },
    /* 17 << 126 */
    { { 0xda4a07155e46cdffL,0x8a860a550f6c761cL,0xe13952745fe1eef1L,
        0x256e296af7bc535fL },
      { 0xf3d4b06c2755dd27L,0x3ced6ee5bb530c26L,0x73249ad796ba599dL,
        0x5de8dab3e8a66027L } },
    /* 18 << 126 */
    { { 0xa4892840c2f97e01L,0xbe0dbe49427945beL,0x6fd86a7ba57d4e4fL,
        0x7f56c3e004a2e778L },
      { 0x734708ccffc13d49L,0x3c1d9413788d31feL,0xfe85545b8d3e4c36L,
        0xcca441fc8815129cL } },
    /* 19 << 126 */
    { { 0x2e2095e215e3d172L,0xc0c8d3c464b43e81L,0x084557abc68e802eL,
        0xa6b7359030d239b9L },
      { 0x61ec00a9b67b0548L,0x630059deb8ab138dL,0x800abf0136ca9888L,
        0xe26d644a9517149eL } },
    /* 20 << 126 */
    { { 0x775d5a9858bf21d9L,0x00eb6846dbeab706L,0x9d714c9f8232d477L,
        0x7cde2c3eb70f91c2L },
      { 0xe6d0a8cee9871f0cL,0x902bc60b19e8444aL,0x8651ed57ff0cd43aL,
        0x4418cc07d480d222L } },
    /* 21 << 126 */
    { { 0xb5e0c7e3f3cbe01dL,0xbf4a899fe43adcdfL,0xb89b022c78f8f79dL,
        0x79cbbf97f42c797cL },
      { 0x46d73cc559d53cc1L,0x99f683e64ffca67cL,0x527c16ec98865e5bL,
        0xc844b70ff68f8ee0L } },
    /* 22 << 126 */
    { { 0xcffcccc0c9854994L,0x4aafcc1574926d5dL,0xeb084832835aea59L,
        0xcb317b5f20df21cfL },
      { 0x3c45b084e43d1853L,0xd12c9411b93b9167L,0xb090198219316bdfL,
        0x76bfa2acd11ab5e2L } },
    /* 23 << 126 */
    { { 0x22bf23cb4e84d3e9L,0x96ec9f8ed1572d4aL,0x31594ae4080ba39aL,
        0x105b5677adc6bae4L },
      { 0x501e45dda644e230L,0xeb571f2764573126L,0x1fc3d478a36ac1efL,
        0xbd5fcee8327c7da7L } },
    /* 24 << 126 */
    { { 0x1b2b188534a70bfeL,0xcfa421f7a36345c5L,0x2f33f4cc6f322ae9L,
        0xdac0bb754dabb7a0L },
      { 0xfba35536923cea0aL,0xc16f73e56d9cb50cL,0x23216dc625812c96L,
        0x82945e673d7ab424L } },
    /* 25 << 126 */
    { { 0x829577b20796605dL,0x47fa09785026907fL,0x997011692d0f68b2L,
        0xa0d24be4bc1e46dbL },
      { 0xcf409c2e2eb2ac98L,0x7b59c3c597f3ff5cL,0x2f4576bd81ed7f02L,
        0xe41339e510399c22L } },
    /* 26 << 126 */
    { { 0x562d77442ecce0e6L,0x1afc38699a1656c2L,0x5714820e86200621L,
        0xee36f7b6566da805L },
      { 0xe66941046e5a2a06L,0xd4390b748caabaabL,0x9db2099893b0d142L,
        0xe1811b817926baf3L } },
    /* 27 << 126 */
    { { 0xd578f2ed08bc1965L,0x9a7e31e235f00d5dL,0x3725b65cc9007327L,
        0x157cfe9529c36f38L },
      { 0xb1c3d0f123a521d7L,0x3e65fb7cb8a9ae08L,0xed48bcf9690b8f78L,
        0xe5f46b2c90d5dfdeL } },
    /* 28 << 126 */
    { { 0x14aebb350b6da2b6L,0x91fef3367b65ee55L,0xdb77b57b1a0a004dL,
        0x1c59b62823aef1f7L },
      { 0xa79c8c893ec88d18L,0x52cca38a4fde31f1L,0xe2f64a94cf4e30b6L,
        0x2b4cdbd737ff1cbbL } },
    /* 29 << 126 */
    { { 0xcb542f680b566632L,0xedab69a6676fae9fL,0xc4531e0bc45cb6f0L,
        0xf967ec6eb88fe4a5L },
      { 0x4ab4e6452919785dL,0x2dcaefca7a17b20fL,0x65c89c05da7afaa0L,
        0x59ea00e94dafc6a2L } },
    /* 30 << 126 */
    { { 0xa6362bf88eb43733L,0xae2dddc112011803L,0xbbf516b10bb2aaf8L,
        0x9f2627e9d8de21a3L },
      { 0xaf30439a43a20b74L,0xac7e07b04ce86408L,0xc54cdff27c10566bL,
        0xe3ee06226279af0aL } },
    /* 31 << 126 */
    { { 0x57d09708f7770f95L,0x6f0ba223123e020bL,0x6c123fb96cd41559L,
        0xc54f5c656fb30f58L },
      { 0x5e168af3bbf7101cL,0xf6d6dbdbce974455L,0xa001f3b988313516L,
        0xe6e4a26ddfb4ac20L } },
    /* 32 << 126 */
    { { 0x74e7b7fc506f7dcdL,0x985e85465d037d69L,0xff00a4da1ec8d374L,
        0x8c339ae3505b4180L },
      { 0x78bcd4f23a5f71c4L,0x2fb4d99f67ac3e9fL,0x7dd25aa6ee65dad1L,
        0x2fd63fc2b62c34dcL } },
    /* 33 << 126 */
    { { 0xdee42663f7700192L,0x9925a2062c3248e9L,0x4a55a55d2ea9f052L,
        0xe1d6efcd16ac67feL },
      { 0x7f82246d9bb02415L,0x2fadbb9b72cd7a6cL,0xe977a037712004dcL,
        0xe8c449b2b3c9f4b9L } },
    /* 34 << 126 */
    { { 0xa2cb838a861ea138L,0xfcbe219a356ae003L,0x15c024961838504fL,
        0x58cef52c0769d5dcL },
      { 0x7e94ff7db3fef999L,0xf55501e004e4fc87L,0xcdb5fd36c05430dcL,
        0x49872453778c5cd4L } },
    /* 35 << 126 */
    { { 0x4c4855ff1b5e7aceL,0x89fc6309b159fe74L,0xaca004043c9ebbe2L,
        0x4c030591866bf867L },
      { 0xa7e8f5999b18a535L,0x9203ebfc5c0a0a44L,0xbf1b30cc463207c9L,
        0x90b590019d135aebL } },
    /* 36 << 126 */
    { { 0xedc44d04794cb3abL,0xb3baa4750ad7be70L,0xb7d8c7c56c09fc91L,
        0x2a362d71f45a5bd6L },
      { 0x36e308c38cf3e5a6L,0x4caf2cd10a649c31L,0xbae328f5b3c501c7L,
        0x2efeca0383a0eeb3L } },
    /* 37 << 126 */
    { { 0xc3a275857086093aL,0x78e865156d686d83L,0x18cf3ac1edf0def6L,
        0x2f6a56da5a1d6cf4L },
      { 0x350c822e30084873L,0x82d4808765843610L,0xa4e752c1f393ecd1L,
        0xe3034d6deeb74f25L } },
    /* 38 << 126 */
    { { 0x1793727cb8b0c5c7L,0xde561ca67ec9ce37L,0xd9eddc506190f612L,
        0xb52dc77cca89a191L },
      { 0x990010b24bf1e87aL,0x073136b215b91691L,0x5011126115546011L,
        0x17d488640196cb8dL } },
    /* 39 << 126 */
    { { 0x7ec44104fd61d824L,0x213550eff088d3dbL,0x5e8d321facbbb608L,
        0xc317c1f839312b64L },
      { 0x7a4a1cd027de4329L,0xbfb33f07f9b135e4L,0xcf82b63959b94480L,
        0xca62d95770b118e6L } },
    /* 40 << 126 */
    { { 0x95b2ff032b1d45fbL,0x472dd56c2570686cL,0x4fbae8a0d3d50e32L,
        0xa31c65dd65796a08L },
      { 0xe261f6f8037ce5bbL,0x3b7816bfd042073bL,0x6d0ebbeebfba45f8L,
        0xf2d99979c9522e36L } },
    /* 41 << 126 */
    { { 0x707f2a1877cb5b0cL,0x954b5a91dfc02b82L,0x246b9a55c20ae04bL,
        0xa14867759dd79f93L },
      { 0xd4092830c11f6d8eL,0x74ca482f267a4dabL,0xe3c80bb69c58706fL,
        0x245f04b7099154c1L } },
    /* 42 << 126 */
    { { 0x3a4b25b5f149259fL,0xeac735f865ccbe91L,0x260e749f572788a4L,
        0x30b9c736e34d40cbL },
      { 0x65981d50f524a17fL,0x6c462f5dcddbbefcL,0x245bfa18a1e57312L,
        0x3b4b003c46dc8ae0L } },
    /* 43 << 126 */
    { { 0xb19587975d262a35L,0x83f6e604ffafd8c5L,0x60843f9cbc2e0801L,
        0x11d85ac1c783ad3dL },
      { 0x1ce477dd2e016e43L,0x2b628f06fb4a0201L,0x897b7f62bf4f77d7L,
        0x52e04f2210277d8aL } },
    /* 44 << 126 */
    { { 0x171323515f3f0d6aL,0x13c9e06459a96c4dL,0xc73892b086f05ae8L,
        0x94545c8a4212ad65L },
      { 0x0591b0913dc4984cL,0x06845698f2ec1ca9L,0xb0e1e1d0b3ac894bL,
        0x962ca1daa7c915cdL } },
    /* 45 << 126 */
    { { 0xb0640de895331bd5L,0x2544348a478c1b6dL,0x3c3bd4155647a67eL,
        0xd7970ef85b20e5fbL },
      { 0xd6e6f6bee06b4fa6L,0x5ae29e5e871390ffL,0xc79241887256daa1L,
        0xfae5e50159f61750L } },
    /* 46 << 126 */
    { { 0xfac83eced1ef1d2bL,0xa567060c554736daL,0x697571f41dba8bc7L,
        0xd3fc5aeb553fbcfcL },
      { 0xe665970a9755fab0L,0x30fbe8d9b5537da8L,0x7a7d001397c2b5f0L,
        0x9fea5c9c1b700a02L } },
    /* 47 << 126 */
    { { 0xcfc0166ee9a377daL,0xcc78f3d8ac502375L,0x803fbbdaba64c3b7L,
        0xe53c7d6b4d70cc42L },
      { 0x6b927bba5189b7daL,0x2c86253b8b05322aL,0x333e7491f3869873L,
        0x9308348a4b492879L } },
    /* 48 << 126 */
    { { 0x39bfa2a8b9ab0a36L,0x560f80a618f71ac7L,0xca9b265a45e24412L,
        0x6796bece8e2ddac3L },
      { 0x87f1eee517bfcabbL,0x624db4d9195c9bb2L,0xf7110fcf2b4db6d2L,
        0x41d3fb0db432d19dL } },
    /* 49 << 126 */
    { { 0x3344ea7d73554a3cL,0x4c968dad830a3881L,0x5df71ad2687f71ecL,
        0x4c4df41f259cbc07L },
      { 0x8d12d2e0eb541d72L,0x94c0dab6a20fb162L,0x9bbc25241eda0516L,
        0x696c924edd7871ffL } },
    /* 50 << 126 */
    { { 0x97efb4951db84dc1L,0x7d293ce503cbfbf8L,0x79e25d3ebc48d007L,
        0xc900a5808591a1eaL },
      { 0xf0277a09d37508c3L,0xbf583aa4e84557bfL,0x2e258d60d8228591L,
        0xb037e17c117da3a9L } },
    /* 51 << 126 */
    { { 0x4b35355e243d588dL,0xbe6dfa36cce2539eL,0xa57d58234843c9daL,
        0xe3d91511f59348faL },
      { 0xb5d1395c2791c08fL,0x04129e5df6fdcc93L,0x635a63ba0f53087bL,
        0x66da6becf237612eL } },
    /* 52 << 126 */
    { { 0xc3d052e522755420L,0xc37a9b47d7a1bd35L,0xf19613f39b347e02L,
        0xee84dbacbbda7ae0L },
      { 0x603be21d3a85f2e5L,0x5f0927c2ff679451L,0x799013ad8674f8d7L,
        0x17b248d300f465e5L } },
    /* 53 << 126 */
    { { 0x2a29135f96ca19deL,0xc8e56e32957d1844L,0x935e7eafa11a4349L,
        0x717308e1741b73d3L },
      { 0x40477acb7233a9dfL,0x7a78dac2d2c83b72L,0xfb8824612c5d79d2L,
        0x984505fb76f44fa0L } },
    /* 54 << 126 */
    { { 0x5cdded16dfdc4a9dL,0x4cbea1353f0ff597L,0x38daf27a8a79078eL,
        0xb4b0085dce1bbf0eL },
      { 0xb6b0d8d786f19fd0L,0xe0fdcdae1778ca6aL,0x257c7df90b26b9b5L,
        0x4b82422c141dcafcL } },
    /* 55 << 126 */
    { { 0xcf8a2dad4d3cf148L,0xf1a4e2925f17e914L,0xc40755bb60de8f64L,
        0x412449f88718f49dL },
      { 0xdabb99688737b6cbL,0xdd94ae816236ea05L,0xb5223cd005c5aca2L,
        0x6b81bd33762210edL } },
    /* 56 << 126 */
    { { 0x1f0921db5d4164dfL,0xf6fdb08f8d4a35dfL,0x1efcf3c7c602d4d8L,
        0xa2ecd9e6057f3aa0L },
      { 0x13a6c576eb4fcba2L,0x16425bd413130559L,0xa9eac848416b4968L,
        0x617c32a92119600eL } },
    /* 57 << 126 */
    { { 0x1a84eca50bb49e40L,0x2ed98d25bc2310b3L,0xad191f885edbc719L,
        0xd8d667d50376ae08L },
      { 0xb855a8eef0b4fe29L,0xc3fe79fbe75354f7L,0x1ee9b9e6403b651eL,
        0x99ddbb3c2baa2c6eL } },
    /* 58 << 126 */
    { { 0xc6a84c47eccce37dL,0x71a05a24038c9821L,0x8d32194c9a6353d8L,
        0x14cd3ea6cf0a1462L },
      { 0x40d70aa27bdbe521L,0x200f0b2195c80cd8L,0x4c79dab93efdf656L,
        0xafa44e4ca981d8b5L } },
    /* 59 << 126 */
    { { 0x811b9387a7111315L,0x0255a2347590c35dL,0xb18e87c0f1af875cL,
        0x0a930b41ced5cc1fL },
      { 0x6ff4fca496094a55L,0x74095b886a9dc519L,0x44492273afa4894aL,
        0x54f16f88a2e6f56eL } },
    /* 60 << 126 */
    { { 0xd613fbb434485e31L,0xc716c370d2464242L,0x215358371644f2e1L,
        0x7719474bbe417c3aL },
      { 0x31bfb1582045d2beL,0x10855524f50e6828L,0xdb9490ad98a67af1L,
        0x41a34aa61c281ff3L } },
    /* 61 << 126 */
    { { 0x87109ba8a8bf2580L,0x70c2e9362d7eb52dL,0xefe9fe2cfb3fc109L,
        0xfd3f4d7b780526bfL },
      { 0x6f9a48d89ed0c3bcL,0x0aec850f5d8205b2L,0xa378f8c61c6a13efL,
        0xac02f3679d10e11bL } },
    /* 62 << 126 */
    { { 0x79c6b3963b9bbf54L,0xfb586d7142779c58L,0x5d975728889eecb3L,
        0xda2ec867434537d8L },
      { 0x15a3c9c362f31813L,0xc4b357c83c30433eL,0xf26d281fc464e972L,
        0x99fa49e74512ffcfL } },
    /* 63 << 126 */
    { { 0x456db1b2725b9753L,0xec501760b42941c5L,0xd822a9d57d6d406fL,
        0x4bb7a8207bbcd4d6L },
      { 0x079b1fe0cc96a5b7L,0xf83e575524aa4901L,0x317cdd1d20da7fcbL,
        0x487fd70693b04a81L } },
    /* 64 << 126 */
    { { 0x43e0671fe43332efL,0x71c5dd5b441c2218L,0x4c1d2c1fe922ba18L,
        0x558e9c2fd619cb67L },
      { 0xd04acde01ec51255L,0x824b3740af824507L,0x62d1b9de744c6afeL,
        0xb99616dbab0d52e3L } },
    /* 0 << 133 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 133 */
    { { 0x5ec9c0847f6a1cdaL,0x68839c14823d6350L,0xcbbb678b03bad007L,
        0x6a7272554788854eL },
      { 0xc747fea2ef5c7294L,0x748527784875e775L,0xad7b8e8baa61a893L,
        0x18ff333540da98b1L } },
    /* 2 << 133 */
    { { 0xa51e9f4f5529ec80L,0x0420274a6fd146d1L,0xbbf1ab668e300c2cL,
        0x2d0b3a9d41653feaL },
      { 0x2be2180f23a495b9L,0x6ef3c3745415d73bL,0x1d3e1ec8c67ae4fcL,
        0xa5839e9c98d31f5fL } },
    /* 3 << 133 */
    { { 0xf54114d637d77c01L,0xc2e18a4b41023c87L,0x6fa6c3d39e6e1221L,
        0x9a6cf4e2410e48f9L },
      { 0xe0881140b181828fL,0x17c6df2978cb7833L,0xc1eb8df1a7cd2367L,
        0xb78f1c8dca89f922L } },
    /* 4 << 133 */
    { { 0xf25d4777d0d42887L,0x4b4892182b7a2707L,0x1b4dbf9b2d3966feL,
        0x4bac5f4841ae2becL },
      { 0x68db27331733964eL,0xa10c5dff6a814a69L,0x84ebdaf0a9898348L,
        0x60e46823a74da3f4L } },
    /* 5 << 133 */
    { { 0x452b6b1d93420649L,0x9dd6452b6ed5d7f6L,0x4a9b8fa1e687b577L,
        0x1e203166854c49d7L },
      { 0xf523667ea45feba8L,0x9ecb4d445f9f4a56L,0xb8655a5f7fb1c641L,
        0x5516401a87c26201L } },
    /* 6 << 133 */
    { { 0x246777540d2face6L,0xd9f7da7fa8ade59cL,0x27e3ad777fa7df06L,
        0x35a4caf0f60395adL },
      { 0xfaef231ce4e701acL,0x9e13597623755489L,0x7caa73ab43554ad3L,
        0x9d8554d994f0d878L } },
    /* 7 << 133 */
    { { 0xe42040cea85b81d5L,0x4d28aca740fa9631L,0x076fed3d7e04b755L,
        0xdde3d3471129ce4cL },
      { 0x77f785d71179af95L,0x4782f842f74e0672L,0xbd068cc10b4597cbL,
        0x3d6d4b2a8f4c65b7L } },
    /* 8 << 133 */
    { { 0xe0642d18f9066d73L,0xbe1d2ec3a098b3bfL,0xefee860c21b4954cL,
        0x4d7c4e6d27b629bbL },
      { 0xcd8f1e038e8b81b0L,0x4a80168e7fe77eb0L,0x4d977591ce247c73L,
        0x9b30c9f2857e0356L } },
    /* 9 << 133 */
    { { 0xc02495ba2940e9deL,0x357299f5b6d2b72cL,0x132b4c6306a9c2e4L,
        0xe90a90c5084d8c67L },
      { 0x0f0c9e94ace1b471L,0x769457e1f1e3d8f6L,0xc4c30ce3d71118c6L,
        0xdb5fd8d66b652a3dL } },
    /* 10 << 133 */
    { { 0x090df1074def5978L,0x1abcfa322d8a5f3aL,0x2976b012a34b70dbL,
        0x90f541d4fa5e75b9L },
      { 0x50c991a937a6e9a0L,0xf51e8693903bffdaL,0xa2697ab48d344776L,
        0x77134fe8e34a7850L } },
    /* 11 << 133 */
    { { 0x723e5d3da72597acL,0x4a49847a4269aff7L,0x75ad9088443b8db6L,
        0x9b7d00d5a51d80a1L },
      { 0xce1c7049e5e04ac2L,0xb8c2793c2a792bdeL,0xde9220a0e410e175L,
        0x4b3a9b859401bc2aL } },
    /* 12 << 133 */
    { { 0xc7eaf2c5f037d15fL,0x410b627ec7afbf8bL,0x243cdb79d7bedf50L,
        0x04813b51be6512d0L },
      { 0x2fb77cab26beca2fL,0xbb6019757baa3099L,0x8c327e5940bda4d0L,
        0x85b9c76413c23444L } },
    /* 13 << 133 */
    { { 0x26960d9c08ed59d8L,0x9b76dced4a72854dL,0xca2f579afdc3b7f5L,
        0xac27028a6cae8b4fL },
      { 0x48fd1a4942326aa5L,0xb95fdb4f5759c63fL,0x27655358e0a96abfL,
        0x26d38b6436ed53b0L } },
    /* 14 << 133 */
    { { 0x03cfdd49fc6d1f3eL,0x20af588615adaba0L,0x74c6c943754dd268L,
        0xe7d52cdf7977717eL },
      { 0x9a81d4403b414dd2L,0x697c7b4ad790a4c7L,0xb1b7735fedbce1f2L,
        0xbd90e63fbefa7210L } },
    /* 15 << 133 */
    { { 0x2e2b0dad7ab207d1L,0x89abbd839b373211L,0x45d34ebc8e35e2bbL,
        0x67ba3ac5064856f6L },
      { 0xb5527dbea52c7676L,0x906fb21771294012L,0x65fca552ab305260L,
        0x89ac52a314ee193bL } },
    /* 16 << 133 */
    { { 0x673aead488c06b1cL,0xea8af42049d9d4e8L,0xa7b4409acb9e86bfL,
        0x49f76f715414aa56L },
      { 0x6603c8018c13857aL,0x7c26f1c2ce742384L,0x042fb2242a665719L,
        0x2619f254e175b0c6L } },
    /* 17 << 133 */
    { { 0x5b3b71ea7c092397L,0xd9087023f18c29aeL,0x48dbecbd2008841dL,
        0x658c998e22622bbaL },
      { 0x38a2cc6d578e463fL,0x7002380fcbb88796L,0xc545baff71695101L,
        0x064a0500ce65b49cL } },
    /* 18 << 133 */
    { { 0x3651d926b1ae0398L,0x33c9ea8f4ace0e86L,0x481fab1b1a6debd7L,
        0x65b58a794d365031L },
      { 0xb73ec84b811e8f01L,0xb6aa395551342ef2L,0xdbce3d9f9efcdbccL,
        0x5791b35fcfbf2a4fL } },
    /* 19 << 133 */
    { { 0x670241586eaad1f0L,0xe8dbaa880063ae25L,0x6d2051cc9fedc144L,
        0x136c2ab118b5e86dL },
      { 0x3b2d3d63c89241d4L,0x843cfa3d4a82dec6L,0x64fa5860f0a5f163L,
        0x2d9b60951ae3be83L } },
    /* 20 << 133 */
    { { 0x75f97753b01a91e5L,0xd374dfa2cd0d8cacL,0xe5dbffef8eb72ba0L,
        0x61049807d7b8a624L },
      { 0x9c8b5e93a39277d3L,0x6e5ba5933b1cc635L,0x8bd0a69e21cde059L,
        0xd0a19b53071ec0c8L } },
    /* 21 << 133 */
    { { 0x8c87785ad1bb088dL,0xd801d5a67e249c39L,0x002ee5988688914fL,
        0x52b014fc6b68413dL },
      { 0xaf1d7e88507946dfL,0xa38e436f84ccebf1L,0x37d9b946aa86a4b6L,
        0x55da0db6c506a394L } },
    /* 22 << 133 */
    { { 0x856928c302b900bdL,0x9eb926a37bc6a67bL,0x2f4d392dd0f39446L,
        0xb12f276101c49daaL },
      { 0x07b8d23f13874ac7L,0xa473ef4c1efaa157L,0x550765f6df8cf2abL,
        0xeba88504d23d3750L } },
    /* 23 << 133 */
    { { 0xf05791d42434fa2eL,0x8c0899c34e2a05eaL,0x40a53bdd898bc9b0L,
        0x6c255f6f40c8bf7cL },
      { 0x203db8c5e164b910L,0x070baaeec1c4de69L,0x896606295df5c0a7L,
        0x0b9c2f4bdb364b99L } },
    /* 24 << 133 */
    { { 0x012c699444bb5a79L,0xf5928e0c9bd1fdc0L,0xd30b8a973ce49191L,
        0x52792b85e3a05dd3L },
      { 0x0da089161d3d69c3L,0x931759e8ed59a28dL,0x412148d96ca05485L,
        0xb1517aa03d6e9964L } },
    /* 25 << 133 */
    { { 0x15204ba9de75812dL,0x49e377e05698b03fL,0xe7790d4105c9072eL,
        0xf79adbeddba28e80L },
      { 0x6aad9f964644840dL,0xc3f3d0322e0a695bL,0x3eb739d2aa4aa737L,
        0x45c6b66537d8d520L } },
    /* 26 << 133 */
    { { 0xc3ba24089917cb85L,0x1c729ffbd7bf6304L,0x56b9935ecc160245L,
        0x42379567e03cb227L },
      { 0x2dc20028b66bfc5dL,0xfaf7d22495de8ed3L,0xa75411583214024eL,
        0x2f7755d850aabdb6L } },
    /* 27 << 133 */
    { { 0xb74ac27b7ea9b93aL,0xc1c5a8fea2e0516cL,0xe9f4f2226b64f56fL,
        0xf3c0c7fb8fbc4a64L },
      { 0x43ac0ac2a16edc23L,0x0e26e4ad6d086e9eL,0x5b8ef9495bc0961fL,
        0xa0d16d39d2b77c29L } },
    /* 28 << 133 */
    { { 0x50b43efa78845d09L,0x3899e1becb3acdd9L,0xa93a28e318d4ec31L,
        0x18a4eeed0a66fe47L },
      { 0xd7a7bf4687333831L,0xbbf5c1a8dbe14699L,0xf2a3da7380b9c9d0L,
        0x133c138a82bceb4eL } },
    /* 29 << 133 */
    { { 0xcfd4b885335a923aL,0xf9b69b3f8fc82f3bL,0x08908b608784c35cL,
        0x76bf1082d843b66eL },
      { 0x1ba730bfbb57a641L,0x3bb4a8d734e9f095L,0x0342d32bc28d5414L,
        0x8fb13cbfcfd99e1aL } },
    /* 30 << 133 */
    { { 0x3845e5071d02f47cL,0x4d77af8914ef0b26L,0x934544805ef578d9L,
        0x23138c57bdc408ecL },
      { 0xdac833ed47cf528aL,0xd18e986529d7cf20L,0x93208743cdc8e55aL,
        0xbfe570c8724025a0L } },
    /* 31 << 133 */
    { { 0xb75c3de03aee838eL,0x29304886e0f21f23L,0xe46792ab82791dafL,
        0x3d798d923f124394L },
      { 0x2446dc8129a6fb5eL,0x2446e5b3bd68c23aL,0xe1b5c76d689b1176L,
        0x3fb666619a852082L } },
    /* 32 << 133 */
    { { 0x8d6fbcc7d9b45206L,0x00ab735deabc4640L,0x428c7017810e37d1L,
        0xa436587227af5718L },
      { 0x8f1958230a910146L,0xc13ccdd70ff76704L,0x59d34ad644d6f1c8L,
        0xd3dfa6b2795b61b4L } },
    /* 33 << 133 */
    { { 0x1ec0801012eea439L,0xafbbea327b2cd52aL,0x99428f9a68cfe98bL,
        0x4ff9a5bc95628fe7L },
      { 0x212baeb77ac41e9aL,0x595cf03f29206e86L,0x4b62a429733f37c4L,
        0xa1fac4ae4d3cb6a6L } },
    /* 34 << 133 */
    { { 0x2d6cb0e61aed3c45L,0xf67034934e6da48dL,0xa0036fb42d13f9c1L,
        0x7db5078a7fe3ea2eL },
      { 0x152a1fc0d5992163L,0xd63270e9744b44ffL,0x56730292f177c075L,
        0x470f5e7217c3e08cL } },
    /* 35 << 133 */
    { { 0xbf53d223ecb927f5L,0xc80fbc1b629e8aa1L,0xed59f18624d72477L,
        0xc266f5a638811583L },
      { 0xc6f37bc17c404560L,0xd58c10e50c5b68e9L,0x696de793916e8f3cL,
        0x7298af8e56a7781fL } },
    /* 36 << 133 */
    { { 0xaf063553b16679d5L,0xa509f4494316ed7eL,0xe3d6ec43b53cc0e2L,
        0x9e957ce016ba34cdL },
      { 0x2b0c7fbc7857d80dL,0xc2c671fe3daffbf3L,0xebcbf0120d251d41L,
        0xedcfe7f7ffef45f5L } },
    /* 37 << 133 */
    { { 0xf5b66555334a1734L,0x4354ccfae505f4bbL,0x6ee0b5b952a59260L,
        0xb7bb64c15a699a93L },
      { 0x85e34c0e6de84422L,0xca9bacfe8bbe0560L,0xa08c780f952a52d2L,
        0x0e794b053919176bL } },
    /* 38 << 133 */
    { { 0x8a496598154d282dL,0xb2999dc4dc34508cL,0xfc304fe39db4410aL,
        0xbc09aee4e1bc07c8L },
      { 0x1d2f0147ef6d497dL,0x3b9e06e096488fc1L,0x37635d0434cb97a7L,
        0x9a294b898757f955L } },
    /* 39 << 133 */
    { { 0x38c568ac59508819L,0x854370fc46e15b82L,0x9f676404ee57f0b4L,
        0x268854cc8f45319cL },
      { 0x4256d25c63746274L,0x0a5538210496cf9cL,0xb6bf27de15e2fc17L,
        0x6848f83a99bd538aL } },
    /* 40 << 133 */
    { { 0x00e15d0a1685e460L,0x6fae8b37155d00b6L,0x277126d8dc561456L,
        0x331c02e56bf70c63L },
      { 0xc9b7da4e515f39b7L,0xb7e0d135966c2060L,0x9a801457c401f926L,
        0xcc560825ffb0137eL } },
    /* 41 << 133 */
    { { 0xbcfac5f85c7e38fcL,0xd542c1a4174e97baL,0xbea67b1e0bb507b8L,
        0xf008cc2c3b782fd8L },
      { 0x865834da0aa329bcL,0x0fd746f22b6db70aL,0x8e72e5f765fbe439L,
        0xac23881d005295eeL } },
    /* 42 << 133 */
    { { 0xc2c45fefad9d013cL,0x0df7427771c311f9L,0x69caf9676bb32b66L,
        0x9fbd32ffb8e4a3e5L },
      { 0x39d94e3178c0c439L,0x7489a8f0ffa4b625L,0x59af0ec38aac717cL,
        0xdd3b470ea12d996fL } },
    /* 43 << 133 */
    { { 0x6d60cb978da3fef0L,0x5164d722044d64fcL,0xefe06eadfc21305bL,
        0x72b4c45eceed89c1L },
      { 0x072cf1dc8cabf0dfL,0x0a0d7c0ca5371d3eL,0xb13ba7072ae831d5L,
        0x7702c3c5269f189eL } },
    /* 44 << 133 */
    { { 0xfb8e903ec8239fe7L,0x5805c2ef524f213cL,0xdf056e4570645f7fL,
        0xfe10ecfb454c4577L },
      { 0x422126da990dc567L,0x95a5d753bf55cd81L,0x2705a00c8c2688edL,
        0xd079ecb42f8f91afL } },
    /* 45 << 133 */
    { { 0x8cd13fa02b69a2c8L,0x7b0f310a36b657b8L,0xa7247cfd251c595bL,
        0xda352dc85a36e4b1L },
      { 0x588d2e88f43312deL,0xef80a48fdb9f6decL,0x395836343fb2d6e3L,
        0x0fbfa7695a46bc46L } },
    /* 46 << 133 */
    { { 0x3570a3f2fe701598L,0xd1d0d091ac815fbbL,0x4d7bfaddd7f2b1b2L,
        0x509298d466496326L },
      { 0xb7accafccad9fb50L,0xcdbcb7629c592deeL,0xfe47a3b16888482aL,
        0x312be210e8b8c133L } },
    /* 47 << 133 */
    { { 0xc474b07f00167f93L,0x19457000a637f35eL,0x3eafa14e5005d8a1L,
        0x2a84723aadf25f29L },
      { 0x2c9d7ebba741cf9eL,0x94024dc2c3913acfL,0xac2db91d97b98f1fL,
        0xfb9a050246a7bf92L } },
    /* 48 << 133 */
    { { 0x8874ffb56487a5d4L,0xc02a12b52f53e25fL,0x38654a57416ba8fcL,
        0x226356f20c0b25d6L },
      { 0x34f2eaa66030f2acL,0xb788baa19cea9176L,0x66fbe9f74e912104L,
        0x982ef71d39a69e3dL } },
    /* 49 << 133 */
    { { 0x9f361d17bbe5733aL,0xc79569a01988f31eL,0xf2b96ecb9e0f52feL,
        0xc78e44dc80235136L },
      { 0x96053ab58462ef4fL,0xf83c1f6d81506701L,0xc7313eb1a65c09e9L,
        0xf5dfaa4a4efcf558L } },
    /* 50 << 133 */
    { { 0x8b4819e4e65ede91L,0x5a5824ba6dc0a533L,0x89d18b20b4c930f8L,
        0xaad7a5d8fcefa378L },
      { 0x2ef790c2298dba63L,0x3e4b31b6e90c322fL,0xa257bb8152ce2ee4L,
        0xb8c2966ed39c36bbL } },
    /* 51 << 133 */
    { { 0x13954df8487719c7L,0xcb0f7ae5791b00e7L,0x367a1cadc8d21fafL,
        0x44dd204d3fbd8a7cL },
      { 0x778fdb565f67ec30L,0xfb2887905de5caebL,0x310b4d56ca53300cL,
        0x37dbb7c4325c54b1L } },
    /* 52 << 133 */
    { { 0xc80c83a4fe771ef7L,0xe212050f1c1c1b92L,0x0f12bb88f09c666fL,
        0x8ec5f39610a2eca2L },
      { 0xdaf9699690a22eb7L,0xeb77eee5450de941L,0x13823c5858fb0165L,
        0x2157ba6e31272111L } },
    /* 53 << 133 */
    { { 0x110ee33e2b4f9e7eL,0x7e1b550bf682d48fL,0x8fd8c6c13e17cb9bL,
        0x91cfbcf7e1843894L },
      { 0x5fc643462917b1c7L,0x06f56d0fba86d14aL,0xb8874d88af219f21L,
        0xf8803b3711ab8b0bL } },
    /* 54 << 133 */
    { { 0x7e63cf63be12841eL,0x9c9cc421bc90765aL,0x0264a5971084fa84L,
        0xce260a60252a9bbeL },
      { 0xfaff225c2fefa4f2L,0x02b900ad05bd09b0L,0x631e5cfb11b1b81cL,
        0x4d93de460a193140L } },
    /* 55 << 133 */
    { { 0xd92a710ae3173750L,0xd712d3a1671a3833L,0xbc9caad14116e26bL,
        0xeb24f658a72fbd71L },
      { 0x3986a2079055f802L,0x212446f8e2707793L,0x602541d61721b395L,
        0x4099a2e6b07160c2L } },
    /* 56 << 133 */
    { { 0x765390f62369ce91L,0x2dc376395754d219L,0xbc5523697c018afbL,
        0xca83507735bf6b66L },
      { 0x61b83e4361d4b0a6L,0x8f87f59727cf66c5L,0xace578409357cbf2L,
        0x24834481abe47fb7L } },
    /* 57 << 133 */
    { { 0xa434c950db3c6e47L,0x1f479519aa1da775L,0x338c9cd2f14f9d5eL,
        0x4666ce7e1e75f72eL },
      { 0x4fce4d95e56564e5L,0x0db55ed589e0ff6fL,0x88796e8500190b73L,
        0xfdf6492a454e31d0L } },
    /* 58 << 133 */
    { { 0x30cb3fbeb9ed6e3bL,0x5c796282de8f0544L,0xe11b36bdb6af89bcL,
        0x0a91cf73ec439d95L },
      { 0xbbe74a5e0a93fe1cL,0xcf1f376fa5d75083L,0x6718bce5f7725460L,
        0x6654d7b1a316d17fL } },
    /* 59 << 133 */
    { { 0xdaa925e50393aa3bL,0x81217e189446cdbdL,0x07708483a7afc408L,
        0xa4c76c4f44709dfeL },
      { 0x72557d713a1c412bL,0xeb4c2648b49b0e1cL,0xcdd24b77e4d6c002L,
        0x3384ea5b77113e0dL } },
    /* 60 << 133 */
    { { 0x906fb7486a10a9eaL,0x46cda42e0a3b0e89L,0x10b9096d7ae4ad43L,
        0xe1f239963bf2afeaL },
      { 0xcb50b9410dd82d19L,0x008e593c832d93a0L,0x0b1fb0e6d86a71e0L,
        0x75f2aa6bb1730860L } },
    /* 61 << 133 */
    { { 0xed5d4d7c7efc480aL,0x500b9d8cc76c64deL,0x28904003ec4fc026L,
        0xe41b3f23dec8b315L },
      { 0xa9b5caff70c06860L,0x5cb9a4d128343b2dL,0xec157abd9986a0c3L,
        0xbcad3bc6b5fc67e9L } },
    /* 62 << 133 */
    { { 0x6e64dd2613aa9c17L,0xa347c4a2271aef54L,0x47b26cb9883d90bfL,
        0xe84d9c6ae1c412c9L },
      { 0xd2eacc101c67439fL,0xd7797bb3c61b2b5dL,0x0deda6528ebdb4beL,
        0x9e04455dac3fc2f4L } },
    /* 63 << 133 */
    { { 0xbbfc6e6927c86688L,0xf7cf2947a1715a33L,0xe047a3e347bc6409L,
        0xefeb573a6f2a5b28L },
      { 0xbf3ea3afd105ba3bL,0x5f01b4c2426c6482L,0x778a5240968390b1L,
        0xc9c7162572bcf6a6L } },
    /* 64 << 133 */
    { { 0x698ec2c96fd8b309L,0x512ea17aa055809fL,0x28cb44e78822943cL,
        0x434dc709deb7d3e6L },
      { 0xb8b324d11be76434L,0x7cf24ed3382ff0b1L,0xda8265fe2905e726L,
        0xd57b3915ee6c3abcL } },
    /* 0 << 140 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 140 */
    { { 0xf9010095d2a819b5L,0x5291aaf948f2f653L,0xfa533907f0afe366L,
        0x88a58ecf8e279e27L },
      { 0x0f077127fae130bcL,0xee9ccf1af8a54c75L,0x38a6783ebed82b6aL,
        0x9a1acb3ded414524L } },
    /* 2 << 140 */
    { { 0xe4e53ceed9c12e2aL,0x11983fc17fc1308fL,0x3eb4d84d892c2d0fL,
        0xa0bfc1ca74499723L },
      { 0x708344d90145176bL,0xbb2988e06f12e75bL,0xdf73ceadada67545L,
        0xf37069d12bb8f989L } },
    /* 3 << 140 */
    { { 0xa24a35e69cc17f65L,0xc49b3e9a89d9abe0L,0x82f403032fc09ae3L,
        0xbffe7d4d002cc587L },
      { 0x5511f4e6424ef713L,0xb86bf654a658f660L,0x623388d91c8baea2L,
        0x60664a7133656759L } },
    /* 4 << 140 */
    { { 0x18996198d8447e16L,0x17195d76662171ddL,0x28cfe6a1f448b8e6L,
        0x8a3c28230658c923L },
      { 0x0c548d899c35e852L,0xadf1cd2f2b378157L,0x999e41aff30113b6L,
        0xf87515a59cf4696fL } },
    /* 5 << 140 */
    { { 0x6c332c559778aa8eL,0x290ae3ead1b8d8b2L,0x3e2bfa0bbf533883L,
        0xe48e37471a523ee2L },
      { 0x4d40f1d550fde3edL,0xb57e695b48710433L,0xa41012581b241f3fL,
        0xa0cabf7b3042cabcL } },
    /* 6 << 140 */
    { { 0x68eb19c7edfea522L,0x68e028b8a400db7bL,0x6cd97bf7a8f03a08L,
        0x09f4d266f442fe36L },
      { 0x1ac77f915d713a1fL,0x356e3a352f58ccb5L,0x31d657f1f8ddc47dL,
        0xfea7aede90092115L } },
    /* 7 << 140 */
    { { 0x2aeba1d24ad49f66L,0x16ff2bad9d40861bL,0x25464f377da225f5L,
        0xa2fe66cc1ffc3f0bL },
      { 0x74074d7fac757f41L,0x5c85d3d1cd0a2c20L,0xccda2a05c974b266L,
        0x5c2e2511cc10a04fL } },
    /* 8 << 140 */
    { { 0x01ea2535510d515fL,0xc861c54c489e7856L,0x9bc8485b680d17bcL,
        0x71472c11819ccc86L },
      { 0xa7ef94850e9b5d8bL,0x698c9fe8d029720dL,0x6ce987d161f50161L,
        0x035f6f329d240bf6L } },
    /* 9 << 140 */
    { { 0xe7c03c9d44ec2bedL,0x0bc4f4a276cf95c5L,0x0722d57c88f014eeL,
        0xae40634876fa941bL },
      { 0x046424df23ee068dL,0xd30b6530e8c130c5L,0x17b69098554f149dL,
        0x887e04f792f95b71L } },
    /* 10 << 140 */
    { { 0x414e7371941c1244L,0x1d48fe5394f1da50L,0xc18bcd896519802aL,
        0xfae7c2d848925019L },
      { 0x0f311ddff2ece2afL,0x7e8e0e080a779f79L,0x47daa5f9b6207944L,
        0xf29dc331efd08d6eL } },
    /* 11 << 140 */
    { { 0x9c096e1923e48f60L,0xbcc6fe538dd36f0cL,0x452e60f9bb86a9caL,
        0xad35f732ed16cf06L },
      { 0xcbdd01a22bf445f7L,0xb7848e94f60ce893L,0x5e65e8ca2939a977L,
        0x304ebedc63cfa5e4L } },
    /* 12 << 140 */
    { { 0x79bae721252cc655L,0xa3b9a4e5c4743792L,0xf32dcfeb36fdba1cL,
        0xadbd0c1f7ac19885L },
      { 0xefb4fb68dc42a2cdL,0x78b1ca372289a71fL,0x7e1f70fe87fc6df4L,
        0x8d02430190a9faecL } },
    /* 13 << 140 */
    { { 0x37c0867246cd4141L,0x3c0fed171a60d8e5L,0xab18bf060f56fea1L,
        0x879ee748372e757bL },
      { 0x84b19b801d280206L,0xa40d7ce3d96ac240L,0x5d493fb1fea42ebcL,
        0x9a5fdafd40d79bbdL } },
    /* 14 << 140 */
    { { 0x790c0b30383b371cL,0x6dae5df9676f8168L,0x101bb4fe4c584948L,
        0xe3d7e99f55faafebL },
      { 0xd2c9aefa134c2e3bL,0x0aa2a71f79e27788L,0x4082f7a67ed0a606L,
        0x843c12bb6a1be308L } },
    /* 15 << 140 */
    { { 0xae72ee7456e9e473L,0xcecde6c1743e16eeL,0x9a06f1057c48ca04L,
        0x79179cd25f822a31L },
      { 0x570d3eebe3530605L,0xbacb30c34c7b03b0L,0x0a8fe2540eea0cb4L,
        0xa052a5552cdf203aL } },
    /* 16 << 140 */
    { { 0xee0315879c34971bL,0x5829eb07e76545cfL,0xb7a3a6ae33a81bb9L,
        0xff42daff49c9f710L },
      { 0x894eae85bffb951bL,0x815fe3e2ce70f324L,0x636564cb428b1f12L,
        0x722e0050a029b0bdL } },
    /* 17 << 140 */
    { { 0xf45cb816d373a65bL,0xf2210e006078d95eL,0xf767d7a620d2924aL,
        0x06d6b55225b66987L },
      { 0x5c4a3999790563a1L,0xcea00a913c85510cL,0x7e37da9cd2db6297L,
        0xfca4735ff67303e8L } },
    /* 18 << 140 */
    { { 0x324ca06eaf76f475L,0x3367845e76391adbL,0x222aa1cea26fe169L,
        0xb15a86657ede94c7L },
      { 0x5b7363426b6a1f33L,0x25db61e18562f392L,0xfd4d720df2066206L,
        0x26ef773f82c555c3L } },
    /* 19 << 140 */
    { { 0xb6e35b3afde6caa3L,0x34eb5e1387fabf4aL,0x4ad6863586236a62L,
        0x2651d3e628510f8fL },
      { 0x88073e34e0873ba6L,0x3becce7022f63746L,0xff8f9b617c08dac6L,
        0xc8b45a9c8c28aa65L } },
    /* 20 << 140 */
    { { 0xe09c063bd87b59dcL,0xf3e4b9efcbbdd4ecL,0x1b6b17934855a43eL,
        0x594d55654ada74acL },
      { 0x10ee400fb410c5efL,0xfc11811335695fe9L,0x766cfe488f75d723L,
        0xc72023ebff63aa76L } },
    /* 21 << 140 */
    { { 0xc503a8589df9a165L,0x9b1099ef851acc4bL,0x9246c61a66202ca0L,
        0xaba9778881390ccdL },
      { 0x3309fa65ba9e2785L,0xbc0388be2220f385L,0x94c01a9e00ddc8baL,
        0xaa54aed9bccfdec8L } },
    /* 22 << 140 */
    { { 0x1a959c58059fc0d6L,0xd0f34c38f518e1c1L,0x38aa2b1db53be8feL,
        0xd95a2a19acdc872fL },
      { 0x97bde382b4140bd6L,0x4084ba9d4cfd5718L,0xed016bfafd22450cL,
        0xf00cdccfa5d1f5bcL } },
    /* 23 << 140 */
    { { 0x905114cc111696eaL,0x1f58a4d33a46e782L,0x899d1856a5e57fa0L,
        0x2518695468c45c2fL },
      { 0x806deb4afa6e3eecL,0x3c358d4865a063a6L,0xce28ed1f3feacdcdL,
        0xef9ee31caaa8e601L } },
    /* 24 << 140 */
    { { 0xddd4fe3d87c1c66bL,0xfc2b063eb3dbfac5L,0x52d37cd020c81dc5L,
        0xb628f163083b5f53L },
      { 0xd92950947e42860bL,0xb877a744307316abL,0xadec0d2d6b8d99b6L,
        0xa75183bd190bc675L } },
    /* 25 << 140 */
    { { 0x2b1e02154ad6bd44L,0xda01ad529e020c66L,0x65afd73d0c2913d9L,
        0x67024b45f0035373L },
      { 0xf501bb4c4d308206L,0xfa020c8877e2e936L,0x662b72bd936476a3L,
        0x07f76845bae57d17L } },
    /* 26 << 140 */
    { { 0x77a43055f34ca404L,0x8e4032944eebc853L,0xe19ee69a402fde89L,
        0x9092acd0fe00df56L },
      { 0x640c035cfb225f92L,0x92d94246dce3aa84L,0x7fe8d3f9971e9886L,
        0xc569905e014b2a74L } },
    /* 27 << 140 */
    { { 0xbafb8c4d7b7c299bL,0x3d289c60d534cd21L,0x95e7032bd311dee4L,
        0xac0c46dd6e8892a4L },
      { 0x9fedef00e5bd6486L,0x3f4d8daa99f703aaL,0x78e47925f0c0ecd2L,
        0x8f143c2bfdac73deL } },
    /* 28 << 140 */
    { { 0x1f88f5a9c14bd094L,0x6cc19e4399d9532bL,0x6e474499639ba66cL,
        0x5d9a283bf5d06b03L },
      { 0xc7e8164faa25dbb5L,0x7ab42a48f03faec8L,0x4135765b647a0d72L,
        0x9562a676e196b571L } },
    /* 29 << 140 */
    { { 0x62cc4c05a720cc20L,0x9ed3f63713fa1ad2L,0xe5816f517f59bac9L,
        0x738e1544b6884359L },
      { 0x83bb266634d0fb02L,0x0e582c6b8014c57bL,0xbb4069ae145e2bffL,
        0xd1965cdf4f5f1d7dL } },
    /* 30 << 140 */
    { { 0xaf77f98b3cead86dL,0x0ba278bd0e51cbd8L,0xf11f20f6ac2ebb7cL,
        0xafd2333fc9992b55L },
      { 0x425dd0e4322472b6L,0x0027a74a0958215eL,0xddb301e74cf7e0e4L,
        0xd0656ed5cbb70c2eL } },
    /* 31 << 140 */
    { { 0xa40f629f0e7662e8L,0xdaa85755e399a5caL,0x4c119aba7297010cL,
        0x4a4a6a43e5df7140L },
      { 0x6d90d303474f7873L,0xc5b0e19cd1f8f867L,0x188bcae64f6dc217L,
        0x51ce999a6777357fL } },
    /* 32 << 140 */
    { { 0xdfc9578b41aeb39fL,0xeeda86fe7dd55c1fL,0xd4b8fc54fb814075L,
        0x12e32a7833a1317cL },
      { 0xeb79cd2b2fd217d1L,0x5f5f20c0dbd07638L,0xfc57643a53dc7d8bL,
        0x65126014f08350e2L } },
    /* 33 << 140 */
    { { 0x737ef5b4871b0d3dL,0x6b7e04ceae3143a5L,0x0e5ab52eb7ae12b9L,
        0x1a956daadb66ee0eL },
      { 0x59657e47eaa7042eL,0xbbc35318bf84a2cfL,0xef55429c78679b8bL,
        0xef92df9d60cb7678L } },
    /* 34 << 140 */
    { { 0x176555801dd267d6L,0x00a3ec71eb0bc1faL,0xafa0a25650514840L,
        0x68c28d0cf161c685L },
      { 0x069f7862b1c766dcL,0x6868a463d5ad4568L,0xf9c3d67070e46d7dL,
        0xd2432cc96c875260L } },
    /* 35 << 140 */
    { { 0x534c3425088cecd9L,0x3f1818e6b4e34c6cL,0x3aedf0a8028f153bL,
        0xe0a1cb9d50d9433aL },
      { 0x9b4e225fe523b764L,0xcba6cba9e5f8542cL,0x59c307e4a8f6b81eL,
        0x36abf4b701bb44fcL } },
    /* 36 << 140 */
    { { 0xf7692c14dd62528cL,0x0d4a8341df57773eL,0xece6957dc9b4f968L,
        0x82eda20052779586L },
      { 0xb902c4882f06ec6bL,0x127dd7ba91a876f0L,0x06eb96d833ad0c13L,
        0xd7394080fc5985ceL } },
    /* 37 << 140 */
    { { 0x624c8f61661aaa4dL,0x6fe10a116717a3e1L,0x6c288c5353168ad0L,
        0x91b8779b8b52d037L },
      { 0x89e664d41b5b0ab9L,0x9f69b44ff30d47d3L,0xfe67cad503176019L,
        0xb83efd48b346a205L } },
    /* 38 << 140 */
    { { 0x63fc4863aeea0c91L,0xbabf9042db56004bL,0xdb19f2eea9917defL,
        0x1d12f2dc54c3fae1L },
      { 0x7bb496af55e36d40L,0x1f6c11f86be63b27L,0x96d79804caf9a5b9L,
        0x03a085c40648051cL } },
    /* 39 << 140 */
    { { 0x3b54c223b56baf4cL,0x04af8c4c559c1fc1L,0x05d55266abd3cebbL,
        0xd2d3ae9bf865e262L },
      { 0x3bd3ca3aedfedc54L,0x30a6ff1c922776c4L,0xfecd88451616a6f2L,
        0x4e7bc2e894948d8cL } },
    /* 40 << 140 */
    { { 0x16e0d824edca784bL,0x84584f9867ea1eeaL,0xeceb14188625626bL,
        0xa487cf9fc34fc1f3L },
      { 0x4ecfedd2a57cec36L,0x08624865d24a0709L,0x47bb19096a48f3eeL,
        0x54c5dd0cc69bc041L } },
    /* 41 << 140 */
    { { 0x15a291e67527166eL,0x8a92370d4a9a8315L,0xe9fe705dda584bd6L,
        0xed441dc33625a669L },
      { 0xa57929ce3063f2deL,0x2809fe4b6348cc31L,0x92041d5404cc19c0L,
        0xd7c227fcb62c1f94L } },
    /* 42 << 140 */
    { { 0xecfeee53cd0d497cL,0x8d1ea9fd128818a8L,0xb5cf2c282ae4725dL,
        0x7de9f967c6abad3aL },
      { 0xc64a11fcb14a183cL,0x7f14d0fed5777d77L,0xbe79846c12957444L,
        0x4cf23abf0e3257caL } },
    /* 43 << 140 */
    { { 0x8da0fd8d6e01b48eL,0x63a7ff165ee87ca4L,0x90dff4d35cc96b94L,
        0xff1b41c3406fc905L },
      { 0xdd9329253ac71c41L,0xec57f1b8cf65e59dL,0xa3116d6f3ce0512bL,
        0x3b46fd3ca2e28316L } },
    /* 44 << 140 */
    { { 0x5a6c031460156a5eL,0xfab3afe355d46fd0L,0x4617926c9846f0dbL,
        0xc2d5a447121ef237L },
      { 0x789498d1f1cda3b1L,0xa195cf03ccd64aacL,0xe8d1a1629440be2bL,
        0x7399890a3ad5373eL } },
    /* 45 << 140 */
    { { 0x65dcea2f4fbf1899L,0x44d9c8ab44ee1a5aL,0x2e94f8c8406880fbL,
        0x70732bad51faab7dL },
      { 0xd69309ddf1e92b52L,0x25f9a6753c7685d0L,0x3604f30b1dbfbaa0L,
        0x5ac0001b2ff28c22L } },
    /* 46 << 140 */
    { { 0x648ec4fa52762d8dL,0x4fc248c60cef95f8L,0xfc0f7030e5fbb57dL,
        0x2e6447295ff2db51L },
      { 0xd85877ec3775471cL,0xe25800586076a271L,0x58a4a24f09cb3873L,
        0xb412928bb142da8cL } },
    /* 47 << 140 */
    { { 0x1da7964b5997987aL,0x69765ff01825d97bL,0xde8ae4074c97095cL,
        0xb257a968bb59316cL },
      { 0x80e5240dcf2dfbd2L,0x2b3b04b01fccd0e7L,0x949f12348ff1093eL,
        0xa4df329065f62273L } },
    /* 48 << 140 */
    { { 0x305b7479d0058ffaL,0xe459ecff180b0de6L,0xfbe00c088ca0585fL,
        0xc169e23ac3dd4fa0L },
      { 0x65d9009a44026f6eL,0xbbc258c31d96fe58L,0xd7ed379c328ed1e0L,
        0xe8b4574423970884L } },
    /* 49 << 140 */
    { { 0x2f44c8ceed1095b5L,0x25725b0dc59404aaL,0xea926278a273e09fL,
        0x102b120b529143d5L },
      { 0xbd2c012d81174d10L,0x0bf5cf894e8333adL,0x6b93e3b0b2f60645L,
        0x040298b8f38df3ceL } },
    /* 50 << 140 */
    { { 0x6433b6fcb89e18fdL,0x48d6584a6bd6af88L,0x46c8a0610e1747a5L,
        0xe225d3cd1ed79faaL },
      { 0x6c579abb5c28a48bL,0xc7a5ff4dda3889d6L,0x037ebc4b008febdfL,
        0x03b60593a7c5cbc9L } },
    /* 51 << 140 */
    { { 0x0840804ddcaa3319L,0x38b0f084b7481f45L,0xfdb059c9112e794eL,
        0xb62bce05e1afb614L },
      { 0xc15035b653be7c02L,0x66fc7106153ee8e5L,0x27fd2ea48258727fL,
        0x8e012416b470105eL } },
    /* 52 << 140 */
    { { 0x3d24685bd7711aeeL,0x66a83c3b021bab69L,0x6e1112a75501d69dL,
        0x2219fe0b068b0504L },
      { 0xaaa553c1a926ab1bL,0x1c81af9556d6ca58L,0x0a997380221ef447L,
        0x881a62faf5f55487L } },
    /* 53 << 140 */
    { { 0xf88fa0bd4f1b618aL,0xb20e161ccbac98e8L,0x443352b53bc6a7adL,
        0xbc8e03ff0fd5748aL },
      { 0x64006aff0ca427fcL,0x1a4775937cbbda99L,0x21ef1afd1a347c47L,
        0xfe056287dee162b6L } },
    /* 54 << 140 */
    { { 0x9d4eb7da797a0b14L,0xe4e01a46951c4bd0L,0xaf8fa17f7fe354a6L,
        0xd71f160cc430b12bL },
      { 0x5bb6843783d46be0L,0x99d10d82619bba86L,0x95c2219df4327042L,
        0xdace23229c19ab57L } },
    /* 55 << 140 */
    { { 0x88abbc67c8750fe7L,0x81ab300ad3abe7d2L,0x62a6d8d545aa8948L,
        0x76175bbd5d4ce8c3L },
      { 0x095cb1818ea70976L,0x785de3fcf7e62a19L,0xc478bce8ed11a7feL,
        0xb7e5993b1528aee2L } },
    /* 56 << 140 */
    { { 0xb9ec58d776c32e4bL,0xef8156132dbc9a61L,0x372c38565e07410dL,
        0xa1b16510033276d0L },
      { 0xd858958182640d26L,0x1cb981809053fff0L,0x41519ce7c1ff11f1L,
        0x2f21a48f666431e4L } },
    /* 57 << 140 */
    { { 0x2c223ed1e83ee840L,0x833ae7081e7cf4dcL,0xec8853d8acd13385L,
        0x559115ab6a7a8cb1L },
      { 0xe2f4ab2aeb184e71L,0x679abbcec10194dfL,0x10199c843aca0828L,
        0x7474e113978cc1d6L } },
    /* 58 << 140 */
    { { 0xa4460ef144e8eb9aL,0x4cde5260828aa4bfL,0xd3d23790249bff50L,
        0x2e6660da6bc7fbbcL },
      { 0x3e3cc14661494df0L,0x6e9a15710bcda8baL,0x68ce233e096e00b7L,
        0x247a5c495106c85bL } },
    /* 59 << 140 */
    { { 0xe6f0cb5c55fc5757L,0x452682b9b7585799L,0x84509dfe869e747eL,
        0x904366e58d23be04L },
      { 0x7324a14db0f72c6dL,0x9fbe31161913a9ffL,0x2f9fa62a428a6b5dL,
        0x8039270ff8a34d9eL } },
    /* 60 << 140 */
    { { 0x0e3ce7ae407aec78L,0x4d935d3d826458cdL,0xf75db7dbfc6f46d4L,
        0x3ab7ba6888586874L },
      { 0xec92749f9a198b50L,0x0ffc7681efc51cdbL,0x951406d5e17bc0e3L,
        0x39cd2d07c898a018L } },
    /* 61 << 140 */
    { { 0x9dc3803cf2f79af6L,0x292f31640a56cd68L,0xdcac21f9f6fbdbdfL,
        0x6f9ce2a423e9e959L },
      { 0x2011d221970f6c34L,0xd2e637119e2decfbL,0x19c7a489118ff327L,
        0xe19d7e83bb6e534eL } },
    /* 62 << 140 */
    { { 0xc685389abd1a426bL,0x432ff7b08c679952L,0x516cbdfac5e2687fL,
        0x8242405dba1eac8fL },
      { 0x63af31520b09854eL,0xcecd0faa231ec979L,0x4746733f7273f0b2L,
        0x69b28d878f001365L } },
    /* 63 << 140 */
    { { 0x0d87d506c6f2623cL,0xd209a9c686c40ed2L,0xa5b7fde20fa20f3bL,
        0x54550dc54f5b2129L },
      { 0x36884047feddaa1bL,0x51398fa0d899a29fL,0x14a416becdf11867L,
        0x86351ac63e466b62L } },
    /* 64 << 140 */
    { { 0xd63e91e139bb481aL,0xdcdc072a99984155L,0x9fce6e38d2d8e622L,
        0xbf6978b68e8c8034L },
      { 0xaa1ae8748c37990aL,0xd1f0e0680e749b86L,0x5aa303b1cbdc7c12L,
        0x9a78baafc9130211L } },
    /* 0 << 147 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 147 */
    { { 0x5eeba910b3e2087bL,0xbd016dd344a61a33L,0xffd1f08148cd5c0fL,
        0x041c6aa02e6a8e94L },
      { 0xe09c35c5c4ac3d91L,0x58298105634767a4L,0x6120e7cb1040c2b5L,
        0x32a661efa713589fL } },
    /* 2 << 147 */
    { { 0x5a056a90bd74c70eL,0x44f7d00d8af672f3L,0xdc25ab68ef4e9a48L,
        0xadd15cc3fdfb1069L },
      { 0xb1f4fd289f3033bfL,0x088a49bbebb8b8a7L,0xea485869a8d2861cL,
        0x46dbfdaf6b977fb5L } },
    /* 3 << 147 */
    { { 0x04e6461ed88ae888L,0x112d204a9be2d7adL,0x952dc813db558427L,
        0x39b0165227e35200L },
      { 0x8b89bfceff02cdbbL,0x1381a99b3e854e4cL,0x68185218999efd2bL,
        0xeb41e1bb86dc62e1L } },
    /* 4 << 147 */
    { { 0xa264ef4002d0aaffL,0xa678c07d6e679fe2L,0xcff13be7fd88bdceL,
        0x9a8efe8d617badb8L },
      { 0x1388a815ad5a22f4L,0x8f821400fec398b3L,0x85a6a565ff4fc2daL,
        0x681f0181858dd4f3L } },
    /* 5 << 147 */
    { { 0xdc87074591ee75bcL,0xbadbf94064f20e50L,0xf3ea437f49d3d417L,
        0x7bebd868c02109d0L },
      { 0xe6c8d93cd16bb240L,0x2087141afdab9bbdL,0x8dba80ff20a3b470L,
        0x960a0c7b29d3a8d7L } },
    /* 6 << 147 */
    { { 0xae61b637f8ec1151L,0x415dd36baadc8545L,0xed21d17669d0985aL,
        0xc4d062af97893f50L },
      { 0x4d93ba1a337b81f9L,0xb995fe9eb7c163a2L,0x447eff3b5416e4edL,
        0xd76603000bf4a8e7L } },
    /* 7 << 147 */
    { { 0x9e14c6a256d9e00fL,0xa228491cfa1f60e0L,0xd540713e8782a9beL,
        0x5d3fcce8dcd55e21L },
      { 0xa176c34e35c87b90L,0xc1d80aa1f9508f35L,0x14f7e7fc92302d47L,
        0x459372ba2b076e72L } },
    /* 8 << 147 */
    { { 0x44168fbc4e933b19L,0xaf2db74ce54ea969L,0x36fade13aeacbb56L,
        0x2970866584e6cd1dL },
      { 0x6f7ff1e1b692df97L,0x5a68c1a26ae66307L,0x85bc544ce7685f20L,
        0xb3f42e6d0f65eeecL } },
    /* 9 << 147 */
    { { 0xef209f445b91b644L,0x808b930a50cb02b6L,0xc5da5e86099f684fL,
        0xd8f1dbcc4330c2d8L },
      { 0x52e8cab5d8608776L,0x13c8977116e56f5dL,0x7d7d802ab135282bL,
        0x69762c39e9be8a20L } },
    /* 10 << 147 */
    { { 0x13f6bbad2a08a1dcL,0xa7131e4a7f2dba7aL,0x751dce487864f5a3L,
        0xc5af1b4508135109L },
      { 0x3c4d75f74f08636eL,0x9949b2f52e251e48L,0xd04979779bd98853L,
        0x09d8e627909b0e84L } },
    /* 11 << 147 */
    { { 0x505753ee4ceff1c9L,0x03ca4571460710caL,0x0cf72dee5480abc0L,
        0x55d5a30ec19c8ef3L },
      { 0x9e47641b86541f6fL,0x89b2e48f10c9d6fbL,0x9d16382b0860915cL,
        0x770ac417f54b337fL } },
    /* 12 << 147 */
    { { 0x366d078177ef7f67L,0xfefec9472b6340c9L,0x7ce3a056097acf63L,
        0x26538c7caf306decL },
      { 0x8a8bb55e287dc8d1L,0x9431095b448823aeL,0x8358087a7970fc51L,
        0x95299959413509acL } },
    /* 13 << 147 */
    { { 0xb165f92a8b0911d4L,0xdde855eebfb37459L,0xe672eed43d9ce36eL,
        0xf7da91e574bae261L },
      { 0x1f67323cb741c8e6L,0x8efd4661c92c91ceL,0x556f0b1a78e73c42L,
        0x7d326b7f16101f96L } },
    /* 14 << 147 */
    { { 0x8814ef0bfb48bd3aL,0x1bbbe13ec508309eL,0x7ddaf06167709c10L,
        0x82b678476436f655L },
      { 0x2a5601c603712e64L,0xac1f03623e3f9b2eL,0xcc7e6a0909184b5dL,
        0x1258b265b4625149L } },
    /* 15 << 147 */
    { { 0xd9f21461384a6b54L,0xde4831616cfe9311L,0x593dae45889f43ccL,
        0x8454335bedee221bL },
      { 0x90f3fb433a2cbcedL,0x895ed692cc8dcb75L,0x9857d71914233aa7L,
        0x91b1a2ab48166d5fL } },
    /* 16 << 147 */
    { { 0xfbf7033a675b47a0L,0xcb3669c46542378fL,0x96abb0f7125ec248L,
        0x6d5d2047795fc346L },
      { 0xa6c6c9e88f5cffb6L,0xb968f2c7bea5ee09L,0x2f2ce735844ffd6fL,
        0x7931b87727e40ac8L } },
    /* 17 << 147 */
    { { 0xe1f62dcf2b63d538L,0x395681ddf44d7bf9L,0xf02eedf754aec359L,
        0xc64b6233a0ad5eb7L },
      { 0xc65093c7346b086aL,0xfcf8ecc9e957b243L,0xe1accffa1ca48020L,
        0xe1f297924047bbebL } },
    /* 18 << 147 */
    { { 0xb1097d409fc6be25L,0x02d33d19923eb7b4L,0x9e25200c1f58f545L,
        0x2ffae306da51efcbL },
      { 0x7e6d76c1c0b011f2L,0xedbd8398f680676bL,0x38517fc28d7fc8c2L,
        0x55a7fcf95c3ab05cL } },
    /* 19 << 147 */
    { { 0x047e24228e6dd02dL,0x7b3bf0e61f290d6aL,0xbcf326fc6a99a6d0L,
        0x1e3f38fa2eef8232L },
      { 0x9890780e15bac529L,0x94202e0e9f143ba0L,0xbd574712885e4ed5L,
        0x2404c223396f938dL } },
    /* 20 << 147 */
    { { 0xd54d401cacde8286L,0x80397794e7af01fdL,0x94457d07f615a8ebL,
        0x34680480d22d9ef7L },
      { 0x04d4b3022c489ccfL,0x11dea4bdc3673daeL,0x8fbb4df558cdfe41L,
        0x494251840f10a70eL } },
    /* 21 << 147 */
    { { 0x831b977a077a59ceL,0xee08fb0c894627f3L,0x213605072f8553f0L,
        0xca77ccd10487171bL },
      { 0xc17d20c207e11059L,0xcf74be6bbe613256L,0x06f185e6a5fe18c1L,
        0x8d2cf4f52b57ce3eL } },
    /* 22 << 147 */
    { { 0x7179273cc9c983e7L,0xc7d27357153f58d8L,0xc02730694f400bd4L,
        0x23309c7f26262553L },
      { 0xf26b6e11712d0314L,0xb925cebff96ee39aL,0x6df5710873944251L,
        0x95419b24589d90aaL } },
    /* 23 << 147 */
    { { 0x57a1bcc5796a8ee2L,0x22a225302acee09dL,0xa4c2cc0366fa2911L,
        0x9cc2b7fad85f13dcL },
      { 0xf2498b8ace152790L,0xd84060071caf39d1L,0x7ff5006484c0822fL,
        0xaf14ca4b155f1280L } },
    /* 24 << 147 */
    { { 0x113f094b89b781c2L,0x996bf893013833a5L,0x26bc6210c0b9cf6dL,
        0x18e2d3ac6a88f1cfL },
      { 0xc0ff2b3ca21a2d35L,0x409c2598a79e918eL,0xffcf65a0b6917e22L,
        0x8036897fbb4f8f3cL } },
    /* 25 << 147 */
    { { 0xac6603659ec27fd7L,0x3c5ca1a90c56cbb1L,0x01c5dce1be9e9ec7L,
        0xdc21b01a386edb4aL },
      { 0x47e02a924b1dde01L,0x0613b7ca44af3e0bL,0x644ac7081c445b6fL,
        0xb5566f0f87243e2aL } },
    /* 26 << 147 */
    { { 0x5b244172ba9f354aL,0xaca4e9d3eb653a5eL,0x6ff6904a514809f2L,
        0xf87a329b96595230L },
      { 0x39ebe6eb8d4bd051L,0x66f05f5c07d17d59L,0xfa1ee673e0f81731L,
        0xf41c1042d12804a9L } },
    /* 27 << 147 */
    { { 0x1c4a655aacd14cf5L,0xdc72f5bcef47548fL,0xab07ceff0b3ee6c7L,
        0xcfa88319bb501a28L },
      { 0xcec9c2e2d8f03f7cL,0x3098d752e0c98d62L,0xa41a07940a8681b3L,
        0x0e58807623587932L } },
    /* 28 << 147 */
    { { 0x4617dc665ef86f7cL,0x51de8430cedb5377L,0x0dda704a737381b6L,
        0x83a44653008f4671L },
      { 0x71bbb73e38401c11L,0x879fe49c4894d378L,0x8875eef9eab186a2L,
        0xedefe27812a382a9L } },
    /* 29 << 147 */
    { { 0x95ef41b813b897fdL,0xfefd495f2a98ddd9L,0x09cbccfc680b12e8L,
        0xc1888a21167da5dcL },
      { 0x2a2049123bb290b4L,0xdcac95fcd9613190L,0x4df94f62709c76f7L,
        0xc8c3a8aba5cea926L } },
    /* 30 << 147 */
    { { 0x15c876b237a2b813L,0x9b52803e9c3c821cL,0x40f2268ccb3d6ff1L,
        0x689f1696a1573601L },
      { 0x8d7566dd8e921f56L,0x5d8a990cd992335aL,0x6339153a20dc4f4bL,
        0x0b07419cdc5d06abL } },
    /* 31 << 147 */
    { { 0xe9cc014d97c201f9L,0xec04a52ea635f472L,0x6aac504aa538a84fL,
        0x4d0288e35762fe7cL },
      { 0xaa8539f034cbd09aL,0x6f7e0e942619bcf7L,0x178303dd0dd338d0L,
        0x6b58c2b18326f40eL } },
    /* 32 << 147 */
    { { 0x98bb15ecfe73e699L,0x7533abdc47526489L,0x4b269607491dcc6dL,
        0x325ec2a077187363L },
      { 0x766faa197e9ab865L,0x1c105b4ac25a9448L,0x0b6b89630531b5baL,
        0x32691f112db1a579L } },
    /* 33 << 147 */
    { { 0x24d90a57643e479cL,0x048b27cbb98578dfL,0x0600f93fe53bed53L,
        0x1fd57dfc0aac585fL },
      { 0xc3d7212171d0e4e0L,0x5ff10dfbf612fc4eL,0x9edf4b23b5a7ec79L,
        0x975165c7d87706abL } },
    /* 34 << 147 */
    { { 0x8b99db047095c3c4L,0x65196441897faf50L,0x5d23d7d9dd5b64cbL,
        0xec734b06e95fe601L },
      { 0x03a5f53f0b5fcde9L,0x0186ad22ebe35310L,0xe9a65eef84846603L,
        0xe99e5188a7c6e5beL } },
    /* 35 << 147 */
    { { 0xa917327df0887da6L,0x49965f78e3f9fa70L,0x02ed227d4f10b31dL,
        0x535b4386b6120be5L },
      { 0xdff21a8acc1bf98aL,0x5b52a09aeb1634bcL,0x60f8690da3f61fa2L,
        0x58a02566b863c790L } },
    /* 36 << 147 */
    { { 0xf9b90a9e5c6b2929L,0xd552e84c22fca36eL,0x6b23da4f9eabcb58L,
        0x01111d075d4136dcL },
      { 0xfaa80059b3642a09L,0x1de667f45f49d533L,0xb326877617525176L,
        0x75b0b102da729fdeL } },
    /* 37 << 147 */
    { { 0x4ec7f6786e9fe6edL,0x28d295782717f8b0L,0x6a713c37d4cc149fL,
        0x4804e04f7dfdf8c6L },
      { 0xe7c6daab5c931aa6L,0x793e411da0394f29L,0xc0741c0d79ed9819L,
        0x3f2ba70b24d5d992L } },
    /* 38 << 147 */
    { { 0xa61dc03fca9c987aL,0x78201cb8e64b50c1L,0x45a23c251861f4e4L,
        0x10f19f4fc4ee5d82L },
      { 0xf1520547f3f055f4L,0x69ae26b3006ccf49L,0xe96eec0b33d8d4adL,
        0x00765f0c48a4fc2cL } },
    /* 39 << 147 */
    { { 0xad47e14ea3976c07L,0x82b1f882d905b6b4L,0x7a1b9d7391382bacL,
        0xcc84a82018178290L },
      { 0x1123c6f6b4e845abL,0x63216635b92e3b08L,0x748be745183879fbL,
        0x7f20e1f0a73e9adaL } },
    /* 40 << 147 */
    { { 0x05de3e119224c152L,0x2fa9a474ea8fda4eL,0xf5c8df05f48055ecL,
        0x48bbf43a9e23a599L },
      { 0xf593f034148086dbL,0x0173a87aef0a2b62L,0x90ef01323fbabb6fL,
        0x56ced09a21ade107L } },
    /* 41 << 147 */
    { { 0xcf1ce89273f1d3e0L,0x765236c622424580L,0x0d223937d939d063L,
        0x9a21beda7cb2fe2fL },
      { 0xa559a5711ce3a7fcL,0x7fd6b2551b060dd5L,0x4dfbd210c5afdf1aL,
        0xa74751ce1239368aL } },
    /* 42 << 147 */
    { { 0x93acdd066d9a3eecL,0x7d97f7949832dcfdL,0xdafa9a440cc645caL,
        0x1da27ddfcfee0817L },
      { 0x0c1e631901b8dd49L,0x8267e508d91aeaceL,0x86a2cedc87f43f20L,
        0x7dd0e67007db2f24L } },
    /* 43 << 147 */
    { { 0x8ea1e9739db25177L,0x659cccb8ab8802dfL,0x2bd39c65004940abL,
        0x57676876d9419db5L },
      { 0xd52058a36d6f237cL,0xd9812dcdfb4a9a7bL,0x879890d153bec56eL,
        0x17b7f1517ac5d9d9L } },
    /* 44 << 147 */
    { { 0x2db3f5df1ec6db6cL,0xe9a3b18fafdf29b0L,0xda633d62e63a9ae9L,
        0x0922b16d38d13c8cL },
      { 0xaeb7e2707462c8e6L,0xa98c96d8a01b6984L,0x5586e0d3297c242fL,
        0xbeddd1abff587596L } },
    /* 45 << 147 */
    { { 0x79ac33cec02ea084L,0xe7d067538e02ae2fL,0x05fffd7d94d526b8L,
        0x4590d6555ebc46d0L },
      { 0xfb79c066855f85e6L,0xbb3f0a6d7400ed08L,0x46f4c3cd67fb3683L,
        0x62fc1931d19804cfL } },
    /* 46 << 147 */
    { { 0x0480e772d1b6f356L,0xa5810f2556320242L,0x6cf6c9c364073c03L,
        0x7dfe137b46a6bfbcL },
      { 0xa5633fa0ba59baf8L,0xb703e5db5fd4929aL,0x09eef835d7515518L,
        0x2e596aa8a0e3b067L } },
    /* 47 << 147 */
    { { 0x793831fc8649bb99L,0x91cb00575ba4c1b6L,0x44e93dbd270ec9e8L,
        0xbf2ed01ad139d219L },
      { 0x39697e05c9d68198L,0xf04439cfde2b6894L,0x65b7a04a1e6b8e6dL,
        0xce3e9425ce35ae6dL } },
    /* 48 << 147 */
    { { 0x041e0aff9f102fb3L,0x91b3a87c106ae748L,0xfd969804c426fa5dL,
        0xe624f1cd28f95b76L },
      { 0x6fe28cce34f2ea56L,0xdea55947d230f37cL,0xd5e336f2f92f2742L,
        0x86852e3c1899c751L } },
    /* 49 << 147 */
    { { 0x5ef2a63ba5d1bd04L,0x5f4721a2b6ca2b79L,0xbdb27b7c9f484f78L,
        0x2b07bf5bb085b4edL },
      { 0x96b8ae73501b62abL,0x0b1e003a3ba64e23L,0x43f9ec0093024347L,
        0x3c8c0c7eae180a03L } },
    /* 50 << 147 */
    { { 0x58c722378c0b21d4L,0x9d51a9962b15a1faL,0xf5201743ec755edaL,
        0x0c845fa3933800fbL },
      { 0xb6b66cdb0e82418eL,0x875258e53ae3eeb7L,0xf2c30b1e1a8f2b3eL,
        0xa10b3843250f3328L } },
    /* 51 << 147 */
    { { 0x9f449967c47c53f8L,0x5dfe8c768775e16eL,0xb02813a1336f2194L,
        0x90ad3ad55636498bL },
      { 0x095acf96c7c647e0L,0xc90ef12b1f57c069L,0x52f518781fb85cc1L,
        0x582cfd6725a125adL } },
    /* 52 << 147 */
    { { 0x53b4bfc70d43ffadL,0x143b0b4804dcf047L,0x65d16216d4500bf4L,
        0x960c79109ab1e4cdL },
      { 0x38b7ef7ee1d08c70L,0x64ae69e19806e01eL,0x074681846796b923L,
        0x6480887a70af1e64L } },
    /* 53 << 147 */
    { { 0x4eb2d6fb02384b34L,0xb29337a805be47f3L,0xfec96fc06b744f9dL,
        0xc3de2fb0c8c9afc3L },
      { 0xe8ccc3ebcc6dd0a5L,0x0329a9b971d7de7aL,0x459fbc8ce357c4f9L,
        0x80287f50025fdc97L } },
    /* 54 << 147 */
    { { 0xedf1b0aaa089583dL,0xb1ad1a57fb08add3L,0xd6826d03e1ae76c1L,
        0x3070cd2e541462c8L },
      { 0x7b03c85983e6f4daL,0x5b39a80924bdb487L,0x70017570453bebb7L,
        0xfe4e6206b8ebbfc6L } },
    /* 55 << 147 */
    { { 0xbb8a1899106defe3L,0x6f23dc7a8683287aL,0x2cf0199565d96aedL,
        0x4e4cf7e9dda4ea18L },
      { 0x72ad201fd2d0316bL,0xd645115061de6cd4L,0x12432dbfc84856beL,
        0xdd4dca98d2a8378aL } },
    /* 56 << 147 */
    { { 0xe70af958bf881f9eL,0xd4cd35adc4e58ec4L,0x3889d3d95a531924L,
        0xac657424b4ce15ecL },
      { 0xdbe384caf41e1344L,0x9a1aed235ab8bb08L,0x375a041f8561df1dL,
        0x19f7a238b7685c1cL } },
    /* 57 << 147 */
    { { 0x8ba59933a4ba6317L,0x0c44b6df271f4aa0L,0x51f4e88fbd64e922L,
        0x7279df949095769fL },
      { 0x098c17b6eaf8c8d3L,0xe602ff2c1aa841d1L,0xbe4e49268b63ce81L,
        0x85de277afcc79573L } },
    /* 58 << 147 */
    { { 0x38253d405b8304dbL,0x58c50c3be422af76L,0x7f7ec0d1bf95c27aL,
        0xcb7c3a8c6041df33L },
      { 0xc55595c035364c89L,0xd1a72aa72a6eb1e6L,0x1fa941dedeb98a3dL,
        0x1e9607abeff46690L } },
    /* 59 << 147 */
    { { 0x6633e398ad46a05aL,0xb99e5784b585e241L,0xd63106a4ea558424L,
        0xf0a5f9395df0e501L },
      { 0xba17aaef59dacce3L,0x03dc5a07e907c457L,0xa59f6d63a9800bc3L,
        0x294a3827364e1ef7L } },
    /* 60 << 147 */
    { { 0x741bbab9dd191356L,0xe8fe9161c43954a4L,0x6a711fa965341d90L,
        0x09bd0faaadef2d82L },
      { 0x2112f27e21ffc303L,0xcd2214dd395b69e2L,0xe4b503c98670b06fL,
        0x219a678ac4e13ef4L } },
    /* 61 << 147 */
    { { 0xc4020eff4a993816L,0x00a9f5de1bac14d5L,0xd00fce1feba7c3a4L,
        0x2c6d499314b537abL },
      { 0xe9b2b5406b898739L,0xae53e6e329dbf826L,0x634606c7c8438b2cL,
        0x268a9ee4fabfd429L } },
    /* 62 << 147 */
    { { 0xb0486aae173b5583L,0xf88a2f80bf222673L,0x49c56f760b3178c8L,
        0xeab47059d77d1406L },
      { 0x95035846993b1a7aL,0xd6446e94a9b83efaL,0x1d1a71cec4424fa8L,
        0x8d814c4d3d08b8d2L } },
    /* 63 << 147 */
    { { 0xbc3ed8d27b9374acL,0x8dd2d56d77a3c020L,0x93ada73597efca8dL,
        0x072bb2d037974cd3L },
      { 0xa7c86e7e7bd74e40L,0x7bff56135b52e0edL,0xc8d0bb30053af1f1L,
        0xc5bdb8f9840bcb7dL } },
    /* 64 << 147 */
    { { 0xabdf5f7341690d1cL,0x0e857a78f0edac8cL,0x59f40fcf8238cfb0L,
        0xdcb54f67511d41d2L },
      { 0x3f036ac80e645117L,0xdc4e833e7af5fdccL,0x67d859b23d7bab2cL,
        0x92489b235f8b32bdL } },
    /* 0 << 154 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 154 */
    { { 0xe412aaf7b9e2f9f8L,0x0484c1aa0ff419acL,0x9d944989417bcb90L,
        0x2b73dbe3fe7318caL },
      { 0xb91b71e552dd7b0aL,0xd61f8eea3954afebL,0xaaeab13ca07e3958L,
        0xde44203202a1ff49L } },
    /* 2 << 154 */
    { { 0x8292d96d0b054a0fL,0xa978af8874b9077aL,0x70bd185bfff1d49fL,
        0xbe6d08440279eab1L },
      { 0xa8fffe45b8ed07e9L,0x714824a1cb920e55L,0xcd5c628aaf1bb143L,
        0xd151afcd7637dbb7L } },
    /* 3 << 154 */
    { { 0x83fb0f3762d7ee7cL,0x58c2282f9a3bcb7eL,0x79f77476eac2ca5aL,
        0x7e80c351579a262bL },
      { 0x19e67272edb4f0fcL,0xe142bb311fbbe9feL,0x5c7d7cce95ea6cc1L,
        0x6465a380abfdcf7fL } },
    /* 4 << 154 */
    { { 0xa433bd2e5a26a1d4L,0x1148bb1dd1c2d78cL,0x4aae419e64102515L,
        0xd03b993966489384L },
      { 0xe21d58b1d61a9919L,0x17618c364a0ef3d4L,0x2519020d6fe8c0ddL,
        0x48d837d600b87a75L } },
    /* 5 << 154 */
    { { 0xe6e067ab426c1aa6L,0x431579d2b11d1280L,0xb926943f2ead6552L,
        0x8fd692bf057fed1fL },
      { 0xed11c0ede9a98faeL,0xe2bc967a9bcb2abdL,0x1b388d6668729b8eL,
        0x2144d67c6f74563dL } },
    /* 6 << 154 */
    { { 0xbe51975703fcd3bfL,0x3f9dbd8dc8c7b62fL,0xce91fce6fc476e0eL,
        0x2f140c732715393aL },
      { 0x8a149a94f11da35bL,0xf6a2be5e5367030dL,0xb68c0d820269def3L,
        0x32d588198eecb775L } },
    /* 7 << 154 */
    { { 0xccea6f5332845ab0L,0x792bc0412541c834L,0xd726425fb1336aa7L,
        0x85b1d21e3ddd6256L },
      { 0xd575bfa8d9b1ba0bL,0xd23084e2b778b77aL,0xd44e739944bb1010L,
        0x3d665388a91623fcL } },
    /* 8 << 154 */
    { { 0x5cfd3a693f11fc00L,0x1f2b5d018bc8eadeL,0x5160359ba6b9f7aeL,
        0x1e2601dcfa696463L },
      { 0x7f5ac6d2915f6084L,0x6e387789679176d5L,0x7fb99f4bae26abeeL,
        0x4798a2fcaa409d22L } },
    /* 9 << 154 */
    { { 0x582164f75965615cL,0x2c9dfb600472cbebL,0x36eacc3f2266724fL,
        0x253eb08c5fcb8868L },
      { 0x749a0577760c15b3L,0x71e4ce1e5686b036L,0x47893a8fb710196aL,
        0xe27dfbacdf51c4e8L } },
    /* 10 << 154 */
    { { 0xc9536d6bffb3df08L,0xc95169ce6dde9e09L,0xcb050de7cc085766L,
        0x92fce77e0df088dcL },
      { 0x10c124ca88781592L,0x6429d30bc81030f3L,0x2e37721d09e20c50L,
        0x43e7f9caf3e3d604L } },
    /* 11 << 154 */
    { { 0xa277a87e5b095e01L,0x968bc95183a51a95L,0x3b375d4553aff355L,
        0xb79d7ccee1ebac06L },
      { 0xd929e1a6022995b4L,0x228cf7f428164ff7L,0x7bd129005d3e4608L,
        0xc57ac8732f97ebd8L } },
    /* 12 << 154 */
    { { 0xc192342d86b383b5L,0xe85f303f706b01d5L,0x19e1921388cdcb89L,
        0xe88f19432ce0de2aL },
      { 0xf6fcf8cfe453aeccL,0x0dcd10b89a67b49fL,0xb93d5b4dafece961L,
        0xe232f34ac39d0b53L } },
    /* 13 << 154 */
    { { 0x1b8f6cc330735384L,0xc35c5a82e4f26c08L,0x9e0c933bba98f626L,
        0x498681004c70aed7L },
      { 0x711a3aadb7f26c66L,0x786ea28d7dac506bL,0xd3a7ab1e43935657L,
        0xda7f5c1fd1b69e9eL } },
    /* 14 << 154 */
    { { 0xc08c85e50e6c8579L,0x29d04ad48d991759L,0xbae8f1633a8ccd69L,
        0xade665391790a49cL },
      { 0xf9f5bc8c45915cc1L,0x63461cf04f2b18c3L,0xceb75a9cd236e848L,
        0xac653e3b847ce6c2L } },
    /* 15 << 154 */
    { { 0xb93b3032db088764L,0x567fe1c3a78e5943L,0xba7a7acfe359cb34L,
        0x38f4fbfde2c3827eL },
      { 0x761c36d4c90abad2L,0xac1af4e775027c02L,0x95e6d01cd4715572L,
        0x5b06cf39d621145dL } },
    /* 16 << 154 */
    { { 0x799acd7c64ca2efcL,0x3397a15b4e0bcb6cL,0xb9b10ced0358a26cL,
        0x0a30dbbe4b8ddfaaL },
      { 0xa70e9712e20f6facL,0x87c7f732d11451b0L,0xf0c967b1d5eece8fL,
        0xbc62882aab370e2dL } },
    /* 17 << 154 */
    { { 0x134fb08e59ddb7cbL,0xe937c6633ae8f816L,0x083f73a7802ed184L,
        0xd4badd858cd69f8dL },
      { 0x2d8bfaf5987f389eL,0x5338c0564454b1f2L,0xdce384392f104468L,
        0xffd94d2783c5278bL } },
    /* 18 << 154 */
    { { 0x8740af505628ad08L,0x30a233db8b1284e8L,0xb3982d7357acc8cdL,
        0x211d53d337c5ff03L },
      { 0xb6371f1bf6578d40L,0x7f749beaa80dec53L,0xe6b3f730a9816ec0L,
        0xd26832fdf5423ec6L } },
    /* 19 << 154 */
    { { 0x8012736863e27b64L,0x17b7a4b2d2d21879L,0x7dcced3743cf40d4L,
        0x999bbb8097cf7c4cL },
      { 0x191c84e56bafa0b0L,0x1d08c049917f6b17L,0x02e5fe53f4715c99L,
        0xa92c60850658f1deL } },
    /* 20 << 154 */
    { { 0xe9c0ba8516a010bcL,0x2fd90fbaea4f3e8eL,0x8af183714570a1e5L,
        0xe869e8f77cca9004L },
      { 0xe2c8afb72dd83019L,0xb877995dfd99b386L,0x1e3efc16f5adab87L,
        0x93105fe4aa3b191aL } },
    /* 21 << 154 */
    { { 0x21690dcaae504c31L,0x2d51ead4698f629dL,0x2af3eef1724c9cbfL,
        0xa6181e6081a0d4aaL },
      { 0x580982c7a94f6b05L,0xe8bea90348653ad7L,0x0270614ca608598dL,
        0xa7cae0f03d0d5360L } },
    /* 22 << 154 */
    { { 0x8140768796067f64L,0xab2c270677a62d7dL,0xbe9c1edfae19786bL,
        0xa313f2b2887814ebL },
      { 0xe2bc4c1f08fd3c04L,0x25387129e5a9d032L,0x7b3ced228fbc5030L,
        0xc22bea3badbf1bdcL } },
    /* 23 << 154 */
    { { 0x4f6b6b6d7b1308daL,0x0f2faaafd0e33069L,0xb461990f0d3677c4L,
        0x55c9df430e6a876bL },
      { 0x5ce9aaa4316d252aL,0x7d98a8130e8e5097L,0x047ecd139aa3343eL,
        0x15cc7072939277e1L } },
    /* 24 << 154 */
    { { 0x305165d10a020be7L,0x48560411f66eaf8bL,0x5ff898ddffd2380eL,
        0x7da35f08784b4b11L },
      { 0x50f53e2c38fd05c7L,0x64b3ee8247ada3a5L,0x672ae316678995deL,
        0x74707460dfe96605L } },
    /* 25 << 154 */
    { { 0xb346dc71441e7150L,0xd9505e7a55fd483cL,0xca96e59f94302331L,
        0xcfde701c801930cfL },
      { 0x02fc993673c31e5dL,0x4ef53a558cda0b51L,0xa934e268a269a1f3L,
        0x7ba4e5e07cca8542L } },
    /* 26 << 154 */
    { { 0x4c6408f9a2ae339cL,0xf9ea4cb25a70ba33L,0x3eaa93645cac2af4L,
        0x62686d4695eaea09L },
      { 0x5196e88f3e771722L,0x749518e87108b198L,0x394107c429b25254L,
        0xf9945ac13a315aadL } },
    /* 27 << 154 */
    { { 0xce15c84daab9dbe5L,0xebb54d523940eb15L,0x69b649c7a2fdd11dL,
        0x4e2d17823f6ade80L },
      { 0x0f53ac9c2327f7d8L,0xf6158d6ec79eb564L,0x2903bfc04536f5c1L,
        0x0a25518bfb9e9e07L } },
    /* 28 << 154 */
    { { 0x70cbce8b62a0b0edL,0x92f5dc330abbc9beL,0xbb92b7d3f369c2d6L,
        0x70dd90c879ef83e1L },
      { 0xe0b331537937ab45L,0x3a8d1f74c054af6dL,0x35cf7380b05ebfc4L,
        0xefb8dac258c2cd0cL } },
    /* 29 << 154 */
    { { 0xe7316f997d665d26L,0x59a7ead9800fba6fL,0xfa4d2a2a08a2cb88L,
        0x2e7d3babb441995dL },
      { 0x390988c993046f2bL,0xfd95b86e08869cf5L,0x0185b6be9a76537bL,
        0xa89563bdb6cd3d59L } },
    /* 30 << 154 */
    { { 0xe79a4f63ecb1ad25L,0x1857cec76948504dL,0x03b7b3ada497922fL,
        0x9df2f2e438930f36L },
      { 0x355e4a7a4bb5927cL,0x5ad3fd47636ec349L,0x5400730dc41b19caL,
        0xbfeabac1555afa93L } },
    /* 31 << 154 */
    { { 0xb62320836cca58b7L,0x55faae6b76d0c53eL,0x64ef60e240a8eb5aL,
        0xc68bc678e8f22c94L },
      { 0x5156dc1c10a0416eL,0xac7796445c2037e4L,0xd2e30925c7162aaaL,
        0x7bb5275f2cf21e2fL } },
    /* 32 << 154 */
    { { 0x7722cb400c11e65aL,0xc94a7f5268ff2be5L,0x420085cc8d9f9352L,
        0x4addb986ca4b2544L },
      { 0x3c6ceac006264a47L,0xebc01a03e2b48cccL,0xc430e7abea94fef2L,
        0x973bb6f0bd94aa8aL } },
    /* 33 << 154 */
    { { 0xd60e5feb3225b585L,0x6cbab39c01b56ad1L,0xcb55a9cc37d6d1b4L,
        0xd7288c1efbce1d89L },
      { 0xcb516843162d4b46L,0xf0aca3a615edb910L,0xdb998b5508a6685aL,
        0x16b442e607811873L } },
    /* 34 << 154 */
    { { 0xa9badd09a1a7e0c2L,0x0a9a339b9f813289L,0xabf1793fd4cda45bL,
        0xa9830a12c7378a84L },
      { 0x1ae11c32d28165b1L,0xbfd49acef71bca14L,0x9a3990dffc035476L,
        0x0fd2b1536c32b72aL } },
    /* 35 << 154 */
    { { 0xceece8353541b5aeL,0x2f7429f58256c750L,0x456c347888104f8cL,
        0x8a4355888b23da06L },
      { 0x6b6c14f2d817ce6aL,0x83bf0acbf35ab86aL,0xdadb89ba364b83fdL,
        0x2c8fcf905cfecaf3L } },
    /* 36 << 154 */
    { { 0xa90f77ca20d12c92L,0x2e278e0e69d1739cL,0x29d24b445c1f9e82L,
        0xbf4fb4cb647c59b1L },
      { 0x9c8ea39d90ffd733L,0xe37a1352f14db3fcL,0x3c9164a28f3e1dcaL,
        0x515c16f2aec86440L } },
    /* 37 << 154 */
    { { 0x736fee4c5c483906L,0x2325cabba3f651c7L,0x582324df35b94e45L,
        0xeacedb3a45598c64L },
      { 0x674e1740de9ea8cdL,0x30f2f42389d2b975L,0x330bd76d9c8abe45L,
        0xb97e89f65371c0c4L } },
    /* 38 << 154 */
    { { 0xb1769248b7569543L,0xd29cc9d2d85f4d72L,0x89e1fd0c10a5b6ddL,
        0x501be0aea693a796L },
      { 0xc70965b6e490e600L,0xf518f8af1bb6c5cdL,0xf51d40bb76f6daa2L,
        0x83a83b675ec7849cL } },
    /* 39 << 154 */
    { { 0x0fe0d9756d8aa314L,0x9bf9aed5ea664a8cL,0xef8bb98996fad9aaL,
        0xd07dce3504a0e441L },
      { 0x53bd2a16b3c5eb81L,0x49e29fe2af178b66L,0x62cf7a6224dced32L,
        0xcc111fba0f541e36L } },
    /* 40 << 154 */
    { { 0xc93cd7c1da9dd111L,0x56b625ab28c9c1b4L,0xeff436ae3769f3a2L,
        0xa0d8d46bcbd31a17L },
      { 0x241693fac80dc873L,0x56083f643cd579abL,0x12ee753b33fbd431L,
        0x1bde60add66c283aL } },
    /* 41 << 154 */
    { { 0x0db508dd0243cd83L,0x3b12c1341349307cL,0x8296aa6d61d86bdaL,
        0x1d5c8a4f630adc96L },
      { 0x9d01dc28a30a8ae6L,0xc555a7431dab8168L,0x61fe0d147abe577aL,
        0xe26aa4d8c8c93bb7L } },
    /* 42 << 154 */
    { { 0xfb4b03bfda2bab5bL,0xfbd4908979b4e6c0L,0xda1a010886806aa4L,
        0x281f76aedc078112L },
      { 0x9f662594e0fbd693L,0x1da897b049ec4ee0L,0x20d52a97fc7d1578L,
        0xdbf8d1576b1f4ab4L } },
    /* 43 << 154 */
    { { 0xfc0a59363b97d1e3L,0x00f0f2831aa091b6L,0x505e183e13aadeb0L,
        0xe28041ada55b3f8aL },
      { 0x2e0f76da086c2d23L,0x815b147df2c5ecebL,0x02066c02673ba5f2L,
        0xb85d6a8ace043d4dL } },
    /* 44 << 154 */
    { { 0xd5f023a3113890f6L,0xaa4f9058a9d2491bL,0x6d82393e16d175a3L,
        0x1d1e00b2671e2aedL },
      { 0xd47c4f2840018baeL,0xd08eac837b30838fL,0xa0fde6315dfe910dL,
        0xfc16adf75c66d5c6L } },
    /* 45 << 154 */
    { { 0x0ed2a8a218d8c6b1L,0x67ee6037632b5b07L,0x7eed42e521a89b8dL,
        0xd99942cf33e6da02L },
      { 0x759ec79e39971405L,0x669a92c7174dca4cL,0x85935ed79d1e7c55L,
        0x5f3f9e68a82055c0L } },
    /* 46 << 154 */
    { { 0xab0507c856aa5af3L,0x354cac5d1bd2726fL,0x46e85e16b864816fL,
        0xef2548f6d1840addL },
      { 0xe494ea07c3842f43L,0xa6169c4aedf6c13aL,0x65d9cca3a460e30bL,
        0xa6848e4f31e7dfc3L } },
    /* 47 << 154 */
    { { 0x4309f3155c8109ddL,0x7a4ec14ec5799833L,0xcb768a63a8132b78L,
        0x229106d1b416c77cL },
      { 0x1ca71df6ded02f41L,0xb6365d3ec1a1fc66L,0xf7c432a11431d1faL,
        0x30364500a5654387L } },
    /* 48 << 154 */
    { { 0xc9ed0cf8d5b13b2eL,0xdbd541bbd18d5a28L,0x6b78c887754de9d2L,
        0x7d32fedb54651568L },
      { 0x7f3196800d37c339L,0x22304d1f37d70b76L,0x01b2709e6fb5e555L,
        0x978b0d3efd5d1708L } },
    /* 49 << 154 */
    { { 0x83206b9d96bc118dL,0xb1a4d7bfec7bfc1cL,0x753f98a6b6b41502L,
        0x411391104c5187ceL },
      { 0x56e9e218587a8213L,0x3b39955bad9aefd0L,0x7428b03fb9947cebL,
        0xbbe82668be8bda29L } },
    /* 50 << 154 */
    { { 0x5142e8ba5c4b4c63L,0x90c3e2e3e92ee291L,0x6947a55a8f6a076dL,
        0x9acdeec161964435L },
      { 0x56bc8e4c181dac35L,0x4f4f2c0a7a824372L,0xd1958b99c1033f6bL,
        0xeeaa6604c83ecf98L } },
    /* 51 << 154 */
    { { 0xe43c0b44aca52cb3L,0x1244642675443f14L,0x0d14e885ddcc00b4L,
        0xb0f5f11d6cfe5734L },
      { 0x0e1601641013afcbL,0x4f570ca9ed9f4535L,0xe5162a1273a307adL,
        0x6a4316953321ae54L } },
    /* 52 << 154 */
    { { 0xa6c7b0c55ae301b4L,0x6f5d42b1bd2d3f1dL,0x4eb12c0915c0c94bL,
        0xf1c4038628618c41L },
      { 0x30302333c0f55c25L,0xa5e41426bd1c19f0L,0xd5d4d4d7cfcc66f8L,
        0xcfdf3039449253c5L } },
    /* 53 << 154 */
    { { 0x17b0eb72b30ec0ffL,0xbce593e25e6424f9L,0xa5d829372a73184eL,
        0x23d2857aebe58773L },
      { 0xe3f0f676067e1eacL,0x073ded2d50509d7fL,0xc22af8f0ca405a7eL,
        0x7a4ef5926df6a46cL } },
    /* 54 << 154 */
    { { 0xf9cb017897067006L,0x9ae132af489d2a39L,0xc7c46b356a2da1c1L,
        0x0993353bd95850c9L },
      { 0x6c313a57a25d52efL,0xa6bdb2b293c852c3L,0x27ed916b7e9e296dL,
        0x10b58337c7aeb09bL } },
    /* 55 << 154 */
    { { 0x78800c35ecebe36eL,0xd93e24232234ce8aL,0xe4cf5ceefa95019fL,
        0x21396d3771e13748L },
      { 0xeb0283500c32fdadL,0x3164569761f1652bL,0x9e1c6e0bf6677491L,
        0x4d18f2e574176c12L } },
    /* 56 << 154 */
    { { 0x78d559bf3832d713L,0x04f0b57bb6e00e15L,0xd6c9cb16e80add3aL,
        0xeabfabc55c7b1d70L },
      { 0x4057086698a62cc3L,0x39ef8ff14abb2b1aL,0xadb405480c19959cL,
        0xd61632d7388b1f7cL } },
    /* 57 << 154 */
    { { 0xd1f9b736d73b7d50L,0x652ed78e560bf0aaL,0x58e71e3350e3fc4fL,
        0xbfaf5f4455df1ad1L },
      { 0xefe8893b9106744fL,0xabfbd51e356d1fe9L,0xab03570b9eb1cbafL,
        0x92cfe2e43919012cL } },
    /* 58 << 154 */
    { { 0x7671e5fbb6f7c64dL,0xf040c0396e0a44b7L,0xf430f59362b36088L,
        0xa85b4bc994c7c0acL },
      { 0x07d5c40c16b54fffL,0x47aa73eec53a3788L,0xa63c5b367000d61eL,
        0x04e8f53d91b9f09fL } },
    /* 59 << 154 */
    { { 0x7e48021d87dc6a3dL,0xa2b5516b28ae0f74L,0x84412003705132e2L,
        0xc55f69cfe243d1faL },
      { 0x758c0f716a8f80bdL,0x69ecf887d09b719dL,0x51b100f0a9b45194L,
        0x1fb9ef6690ae0769L } },
    /* 60 << 154 */
    { { 0xfee82fab30fcdfd2L,0xf36185be36a6990bL,0x88f343f63d33027bL,
        0xb775dcbb38ae16c6L },
      { 0xa107b9f085a82e45L,0xaff8b0aede6b9806L,0x3cd3980f0392fad0L,
        0xdd829fc6f3cf7650L } },
    /* 61 << 154 */
    { { 0x177190cc0dc8d031L,0x3e21cd257fc491ebL,0xea0cc90e0d929039L,
        0x5f7e62921dfc37b3L },
      { 0x66dd6ddee23bdd04L,0x70e7a31764fa490aL,0x59c90f8110a03dd8L,
        0x425ee6ce96d58314L } },
    /* 62 << 154 */
    { { 0x868001eb5f896ed1L,0xc4c003f591dad4fdL,0xfb4782b2d9ef80b4L,
        0xb9edb975323e4fc5L },
      { 0xa2ec9b6c53ef4cccL,0x4af8b2caa77922b6L,0x73850e896697874bL,
        0x76e0fd723568523fL } },
    /* 63 << 154 */
    { { 0x64799f46e9c400a6L,0x6c5176e7a9c245deL,0xbd97c80c93503700L,
        0xa92d9ee5ffbe539fL },
      { 0x76003d148376bb3bL,0x2e75cc77ac564679L,0x126af6c73a333970L,
        0xdbfd01336b6604bdL } },
    /* 64 << 154 */
    { { 0x11cf4c2e24424a48L,0x843c73ee37d4471cL,0xb3047fc5617a488bL,
        0xf2a91709e3cf861cL },
      { 0x844444211c3a60f7L,0x74787a3626679148L,0x115fbd0653d9404bL,
        0x70fd33656244cef0L } },
    /* 0 << 161 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 161 */
    { { 0x76695c9b2b574b7fL,0xcca80405c369b6beL,0x1f4bae99e3108dedL,
        0x9e715ce2ea133fceL },
      { 0x60d5205554c2ee1cL,0x56bab3011680742eL,0xa409b5f63fe438b9L,
        0xe3a8e4d08036f7ceL } },
    /* 2 << 161 */
    { { 0xe1d7ec0f247fdfdfL,0xfb9d90e74a23d1dcL,0x7012eb2c190fdc41L,
        0x5c2bbff6ddced48cL },
      { 0x8a93426a68cd7febL,0xb59639626b4854e1L,0x8ac72b8ee772bbd8L,
        0xc10d24d2a6b3040aL } },
    /* 3 << 161 */
    { { 0x8fdfef1694d5f347L,0xf31894902b04af0aL,0x30e3da7a6d2ca633L,
        0x8d002aea4803814aL },
      { 0xc15e311f95a0bfe9L,0x2891ec7e4b4cc50cL,0x0936fed88834df25L,
        0x7e5d7dbf78e00289L } },
    /* 4 << 161 */
    { { 0xb9a92d78fbfcf1b5L,0x17ce4fabe8427d74L,0xbae98ffdac66e74eL,
        0x6d548304145bb5e5L },
      { 0xbf3dc6030992abe1L,0x318cfbdabefdc5c5L,0xbb5fa37d59f8efb8L,
        0x347874a04ef5bef8L } },
    /* 5 << 161 */
    { { 0xdf552b01bf68688bL,0x2fc542cb8f96a57aL,0x5a731b614edb340eL,
        0x5143d103181cf578L },
      { 0x749ab5112cc936b6L,0xbc94c0530dd355c2L,0xa825eff5a3900fa2L,
        0x60a909a3c1dc2b31L } },
    /* 6 << 161 */
    { { 0x59b33c78af5bcab5L,0x0053d789496fbcdfL,0x5a5afe02d7883bc1L,
        0xec9afe78fa66951dL },
      { 0x38f28b83728e56a6L,0x21d0b6ac78cafb9dL,0xd43996bc7042e327L,
        0x606866377c31c145L } },
    /* 7 << 161 */
    { { 0xe1f8d2e63d919304L,0x09cf437c456be82aL,0x6a01dae8f0c21973L,
        0x8bffcda8246d9ef8L },
      { 0x7e03a0d45d853975L,0xc3800ca832533ba3L,0xd77152ccf02ce43cL,
        0xb8bc17a66392089aL } },
    /* 8 << 161 */
    { { 0x6f5fcb614b4558fbL,0x9602597b1f2545aaL,0xfd89ab3fabe5e469L,
        0xf1daeea2fb2e16bcL },
      { 0xe699acd73a12940fL,0x24980f6c4d7c7311L,0x4a5cf975336c8ec6L,
        0x8e180e328c27d3dcL } },
    /* 9 << 161 */
    { { 0xafb66269d36cb503L,0xe98b07d2754fdd67L,0x1e0b425b5a1fe9bfL,
        0xb4ac13e924fc4a85L },
      { 0xef693781c05a9c3fL,0x266c12165c0124dcL,0x7f3184c464ee22e2L,
        0x3f985fb3cdb5f1a9L } },
    /* 10 << 161 */
    { { 0xb258cd5ffc01efaaL,0x861688b10775588eL,0x72184b18fa46eae0L,
        0xd17c9dea5003404aL },
      { 0xa879196692e7bf9eL,0x049c63cb7891ac50L,0x2ed329285d46b33dL,
        0x49d1bfbf0623595aL } },
    /* 11 << 161 */
    { { 0x9f87147036c8e3e9L,0xdec7eb98b20d610dL,0x15b9326f7b151f4eL,
        0xa624c23e04005d02L },
      { 0x89fc2a8ed9cacdedL,0x9eb8defa9a2c3a00L,0x7c5dc2d6e8d7eab7L,
        0x48fa5403eb0a77cfL } },
    /* 12 << 161 */
    { { 0xcc4c31d0bf033733L,0xf37d0072ef211c17L,0x8967fe49ae35b246L,
        0x8c4cbd665cb1aa9bL },
      { 0xab0097db04840da3L,0x3946faec5828733eL,0x96c6531e87d64045L,
        0x893d378083bc0d0eL } },
    /* 13 << 161 */
    { { 0xf833e35553bec0dcL,0xc9ff72802803a655L,0x300ff7aa42b99b53L,
        0x3b48a8db6a7c3f2cL },
      { 0xf78c21d9f617f8aaL,0x23684cb7cbe4d565L,0xf64ae9c87514e9a0L,
        0x4ff5483c8429d8baL } },
    /* 14 << 161 */
    { { 0xdedab3515cb18391L,0xd3126ffc769ae948L,0x6c2f9ba8d3546ad9L,
        0x4567e48a69aabfb7L },
      { 0x6fbe29b0aa284747L,0x3185f0db98af4f2fL,0xf2a958a25b4c14e3L,
        0x106150c527d04855L } },
    /* 15 << 161 */
    { { 0x60a3b4fb68a19ca9L,0x65c5719afac47c70L,0xe228e088973e4cfdL,
        0x122a2429cb63c89fL },
      { 0x39fda97ebaea08f7L,0xe7da5324621c12cbL,0x569c8a51ff9b3c84L,
        0x5ab8bb6d4c3b8d54L } },
    /* 16 << 161 */
    { { 0x4f02ece400e25a95L,0xef9474027ac1732eL,0xecdb65ac51149260L,
        0x6043aa29a9180d51L },
      { 0x07fc92bd852deca0L,0xf333829715237c8dL,0xecfb0e76e84b3f38L,
        0x21f2f5c56b89af17L } },
    /* 17 << 161 */
    { { 0xf7aec2689659963fL,0x67fb5260a0cb213cL,0x5daa0fef66d931b7L,
        0x95457a7e34d309ffL },
      { 0xe7cf1a56c21285b6L,0xcbff9b08244e11b4L,0xd79ee62dc0ecce3dL,
        0xe3f207398267c254L } },
    /* 18 << 161 */
    { { 0xee06dd39037ef2d3L,0x790d1b0fd522f762L,0xf0659106f30c47d0L,
        0xcd83214bb5fdc6b5L },
      { 0xc86216606593b717L,0xb10a6d99fe3fa381L,0xa5c3224cab254244L,
        0xd15287e65854b18eL } },
    /* 19 << 161 */
    { { 0x6bf9594c225806aeL,0x75a97e2157e554f2L,0x0ea199f382b00b16L,
        0xde81a7265389c90fL },
      { 0x8503609e86922afeL,0x6778ad88254b75c3L,0x6bc2ac1bf3e660baL,
        0x7efc1550209c04a4L } },
    /* 20 << 161 */
    { { 0x6e90b6a52528ec51L,0x9196a7c90548389eL,0xf7e285c17b5b5ddeL,
        0x6335a624223d4837L },
      { 0x8acef5af412d19c4L,0xb22808a59783256bL,0x6ea3daaaf53e4b62L,
        0x7ca4c51bfa7bada4L } },
    /* 21 << 161 */
    { { 0x3e40461ee4d3115eL,0x24889b503646fc40L,0x39e0eb1efa26ccf7L,
        0xfcad5d47a82af350L },
      { 0x900375034862b1fdL,0x88e937e81a79283cL,0x16dd07c09a0127fbL,
        0xac62a16839fca31aL } },
    /* 22 << 161 */
    { { 0x26542e2aa294dac9L,0xefab45af2a5dcfe8L,0x6166857de642bbe8L,
        0x3f3ad480ff6290a8L },
      { 0x435d4c2b5f50633fL,0x36da60a784451c8bL,0x00f5e2e4261612e4L,
        0xe43182732d04786aL } },
    /* 23 << 161 */
    { { 0x192bcda52c175edbL,0x74681e0a59a6f637L,0x696df08b2d244985L,
        0xde61a87cfcf577c6L },
      { 0xcbd2ceabf2c9de81L,0x878f06ced36162e8L,0xc4f312e0b3d22955L,
        0x736ed43fe903efeeL } },
    /* 24 << 161 */
    { { 0x2c687134ca9bf60fL,0x2473ea8fbc7da3a5L,0xf54ef685b45fb57eL,
        0x594e84453383cadbL },
      { 0xe1edd3fb4a7df4bbL,0xa783d987c17c2c92L,0x0d498637cf8fcba8L,
        0xdebd801d3acd6e4cL } },
    /* 25 << 161 */
    { { 0x2ade8a7c34d3761eL,0xc591c889d825cd19L,0x3ffd60ba39b42decL,
        0x136d4902fd9674dcL },
      { 0x373a70f8da4842c4L,0x3208c4853f078bfdL,0x3587f871ef608639L,
        0xf990ab0ff04e46edL } },
    /* 26 << 161 */
    { { 0x39d542aba83a8450L,0x634b9198dacb7c65L,0x680cef7882486a05L,
        0xab1d4d7716eaf88bL },
      { 0x5e605279699c7aa5L,0x7e37906f3c40a07fL,0x4ae84ad8fb6926e3L,
        0x236b5f07e2ebc73bL } },
    /* 27 << 161 */
    { { 0xa94e50ab9e0939a5L,0xabeed8102d9e10e2L,0xea8190fb4e6423d3L,
        0xc739d20917acb62cL },
      { 0xae38106e6fdbe8dcL,0x1c6532d763204138L,0x03af879dbb7d0510L,
        0x1d76faf08cd2b1a4L } },
    /* 28 << 161 */
    { { 0x2fcdaf9bd77386ccL,0x30f9f5a4e32d2633L,0xa4fc8189382e7298L,
        0x946923a1588af205L },
      { 0x2c527a79114f2bebL,0xa2ca55d3077762ebL,0xe4b2eb7ccc85e41eL,
        0x4b5938d289346adaL } },
    /* 29 << 161 */
    { { 0x8e94e7414c2084cfL,0x4ef32d29a839ecb4L,0xc5371755802f0897L,
        0xb0274ff1c49ae8a1L },
      { 0xf7716d1c417bff62L,0x6efb0748918f9555L,0x7d3bb9c87aeb1e8dL,
        0xee9bd5e120d51e18L } },
    /* 30 << 161 */
    { { 0xfaf0a1a5d52033b1L,0x7967d3f4b8626432L,0xe837ca4b5574dc0eL,
        0xf7eae2372c11d8ffL },
      { 0xc0f2f1fa87dc4007L,0xf5f1f1538dfb51f7L,0xa64b10ae5bd9ac7fL,
        0xb3c2ba37a2198841L } },
    /* 31 << 161 */
    { { 0x5a7ebac566c1ee7bL,0x59e06f4cdba62ea8L,0xa2ea165e30944ef3L,
        0xfd5c7dfa3e21385bL },
      { 0x4a012c73e3bb110dL,0x16d852194fb2fdf3L,0x1aac7f117cad0594L,
        0xea7f7dbf4b098d9fL } },
    /* 32 << 161 */
    { { 0x88abaa5c7fd181e7L,0x136a0c9fca3ad1ebL,0xe6e5e6c2f394aab5L,
        0x84d697d49349e4a5L },
      { 0x8215578bf76f4b3bL,0x81a1cec612feeb5fL,0x5d336eb73e876bc3L,
        0xe8afdcb5071892caL } },
    /* 33 << 161 */
    { { 0x22f16f6b3da8d94cL,0x28b276c52d150069L,0x49d20441643d3e58L,
        0x3450c84a3da3a7fbL },
      { 0x8f5bf388442ca3e3L,0xca31411c9e615382L,0xbe63e34d7798675fL,
        0x551eb64dd1ea01e1L } },
    /* 34 << 161 */
    { { 0x1738a83b34a00e27L,0xe7591d15bf58ce70L,0xde2ace5a57d806d8L,
        0xe89e8110d0338020L },
      { 0x935ed5de4e25756cL,0x07ef8c2f46d0f00bL,0xa28e5fb4a659592aL,
        0xcb45c6227fa4986aL } },
    /* 35 << 161 */
    { { 0x6b7df06674de493cL,0x4d6bdaef79aa5258L,0xe9709c34e2b255edL,
        0xdba2653a7d0e7443L },
      { 0xeb8da5c8a00eb3e4L,0xe978228e7ab0e45cL,0x3a31bafd9d551a51L,
        0x1de0e9cf403352f5L } },
    /* 36 << 161 */
    { { 0xb94d547823ddd51cL,0x7c215c91130e78e3L,0x556b92e0ed547bceL,
        0x0072da6b909f5c6fL },
      { 0x4ec71b11f0dc846bL,0xd0f3b3b4bf7baaa1L,0x896391c547770705L,
        0x41fe573666732587L } },
    /* 37 << 161 */
    { { 0x02a7e3e34acd3c51L,0x217df736d30407b3L,0x503a31aee47c33cbL,
        0xe31863924912bbb0L },
      { 0x2491a08a75a5df9aL,0x2882f937c09294adL,0xe2576b69979ad9f9L,
        0xf44ddc1526dc1ffcL } },
    /* 38 << 161 */
    { { 0x7dad21d4968268aeL,0x07378e90be9c6fc0L,0x9406a8722b329579L,
        0xb27b5c51761f10aeL },
      { 0xf5dad2f9d04cf60bL,0x3154dff5df950997L,0xaaec9d30d8534a9aL,
        0x4ac722f5ac43f212L } },
    /* 39 << 161 */
    { { 0x722882f446464c70L,0x9b9b52266c3c702eL,0x4e3974bb8325964eL,
        0xd3ceff9daa0c5227L },
      { 0xd530c8f99534dba5L,0xd26e547bbc751878L,0x184a3527ea79b19aL,
        0x8dab921474f1cdc4L } },
    /* 40 << 161 */
    { { 0x708abc8cc051e9f6L,0x75194e9f4be2d9caL,0x031d69c1d6ab5348L,
        0x1785990e78b0e490L },
      { 0xd825f125f6c41f8eL,0x429924ea0fbf2fe6L,0x53c044befb87161eL,
        0xa3bbdf1b0651d153L } },
    /* 41 << 161 */
    { { 0xda660697ec6ecb9cL,0x51b4a5fdddb8c619L,0x80b87520230fbffbL,
        0xa05874308848da9dL },
      { 0x98715939864c2502L,0x2b10cbfbaf973396L,0x2867518409572b5fL,
        0x0a40cdef39adf777L } },
    /* 42 << 161 */
    { { 0x2efa3bb43ead6eefL,0xbd76b425d1b9fe65L,0x95f006cd5e527201L,
        0x00890f3b38a7dc3fL },
      { 0x84ffa0143a7ce6beL,0x3406aaa089541c2eL,0x430542b69559d989L,
        0x9b427b08b53bddd8L } },
    /* 43 << 161 */
    { { 0x2182bd9149639170L,0xb9fb2b423299ae83L,0xbc993d59423b7ea2L,
        0x03e416acc110039eL },
      { 0x90c2269a3ffe24aaL,0x421ea02d1c322c49L,0x40677b1c0ef8fa01L,
        0xa1acd239c59407d4L } },
    /* 44 << 161 */
    { { 0xb8cd4f408f14deccL,0x95e90d8769e16a6bL,0x85dcf163c3c38fd3L,
        0xf4fb87ba0c01f90aL },
      { 0x8274f825dcd0f994L,0x4c685fa52e6bf7d8L,0xc87d88473d928011L,
        0x9add0105f9efa96aL } },
    /* 45 << 161 */
    { { 0xed39152b50db3113L,0x6b523496b794e6b4L,0x6bb241b684630b17L,
        0x6e9f8ae01de3ae08L },
      { 0x97bd7c09d94ce4feL,0xe887b02c9e61057aL,0x853e8febc62c27faL,
        0x3f9d951a01600ed6L } },
    /* 46 << 161 */
    { { 0x3e957b36b57b9742L,0x92bfd61e82b72110L,0x108b450bfdce7ec4L,
        0xd8af107acc29c494L },
      { 0x8d67ff7047688c92L,0x57f4293328b9b681L,0xbbc98ef3aaf8a48dL,
        0x14113b1ae2d549b6L } },
    /* 47 << 161 */
    { { 0x1172b2590b412b3cL,0xaf86ca6f1d42a63eL,0x5f89313583660d24L,
        0xe7bfe9a85a21a441L },
      { 0xecd0aa5b4ee5122eL,0xbb68654c5e4df46eL,0x0c3e820b5e243845L,
        0x042b18955c46bfa5L } },
    /* 48 << 161 */
    { { 0x791b2085894f7f16L,0x42eb80f2b5c353fbL,0x377777f7df8db0d4L,
        0x023c096334c42ef2L },
      { 0xba05eb5ea34cb6d0L,0xffb8b01e55cd1242L,0xeab6ff7d87cd9f24L,
        0x175e94c9ab3c09fcL } },
    /* 49 << 161 */
    { { 0x6dc681407075fd9dL,0x638515664b203c44L,0x3071e924871d1be7L,
        0xe6285b5685ee9cd9L },
      { 0x738dd6294bcf8edcL,0xf3a368134ace75f5L,0x37a09e343cf6feb4L,
        0x4c2eaef72cd0c8afL } },
    /* 50 << 161 */
    { { 0xd945a28b16205f2aL,0xfe9112a7abadde7aL,0x7db6c5ee2bbf97c2L,
        0x3eb84a8fb5b54833L },
      { 0x9732a49f273007d9L,0xe61431c0c6a2e3efL,0x88aa1a0610a101daL,
        0x64b94de3b972cc61L } },
    /* 51 << 161 */
    { { 0xe79eb6aaf8402027L,0xbb1fa5e3ea6e7157L,0x457f33a24ebdbe4bL,
        0xf4e955e07a61b393L },
      { 0x578e2e64698d37cfL,0xbb139e2382ecbb69L,0x268d0291cfe8d05fL,
        0x7dcfef41625fa854L } },
    /* 52 << 161 */
    { { 0xe21d5b8f9c4da5e3L,0xb5e2220910bf3df1L,0xb04dd106437bf2c6L,
        0x807c5d041d055404L },
      { 0x6e9832062c06fd15L,0x773450afed63ea25L,0xc2dae10695c8dca3L,
        0x5323f6bad82229e8L } },
    /* 53 << 161 */
    { { 0x647fabee57c062bbL,0xcd6adee7cd5210acL,0x11b4df3b181f674fL,
        0x4e23bf4ef2a92b48L },
      { 0xeea34e2e84a83d6fL,0xeaa09d519cb197e5L,0x7f36a278845e5008L,
        0x41fa9b521581c0abL } },
    /* 54 << 161 */
    { { 0x58917f6723d1206aL,0xc04601ce11062b8dL,0xdcc60fb6f31f7326L,
        0xc5aeef464b071708L },
      { 0x5364069edc6939ebL,0x44bd15a2034a1052L,0x8177eeb162a307feL,
        0x451ae4e71907ad16L } },
    /* 55 << 161 */
    { { 0x80e4954427eb3193L,0xd788e57aaf88f4c9L,0xf062c60fd944e00aL,
        0x504463e6eb4a609fL },
      { 0x3593ad2074f13c8bL,0xdc7c5a35c50bce88L,0xa6336115b657d1f9L,
        0x18d14e5d591425efL } },
    /* 56 << 161 */
    { { 0x738967251454f76eL,0x52772de4425c87a9L,0xe59e4516c6efb7d6L,
        0xdddb8bf3d76bbc11L },
      { 0x1acbebd9c6fd2066L,0x88c3b5251d7082eaL,0x6a3b3d626d69cea3L,
        0xdbf73dfa8d065405L } },
    /* 57 << 161 */
    { { 0xd659c8d64a7bd06eL,0x678675207bd10bb0L,0x7c4e3be597838647L,
        0x545c7144c5891864L },
      { 0xf64e1031fa78d62cL,0x1f046593fa71692bL,0xd35a9cb771310c47L,
        0x10911b960ea84922L } },
    /* 58 << 161 */
    { { 0x5647310d93a9f5acL,0xa67858616c05eedbL,0x2f5aa7c843950b68L,
        0x57580907a9d03b3aL },
      { 0xd581049b42e15fe3L,0x55dcf9d2916c4e88L,0x87ebfd1327d1a183L,
        0x13aee909f5aaa51eL } },
    /* 59 << 161 */
    { { 0xa651959d3b9fc03eL,0x05c2877298997a74L,0x73e047f4ae2e4a65L,
        0x359e6c45783aa072L },
      { 0x1124e9f07a04b710L,0xd35094de6d2053f2L,0x0d57d9762575dab0L,
        0x822256fc69171229L } },
    /* 60 << 161 */
    { { 0xbd46937a3d19de1cL,0x71feede46f0be84dL,0xca2053667c4dc4b3L,
        0xfbb97d0de3e851cbL },
      { 0x0270b5ea2066e9a4L,0xeade87ff42ae150bL,0x9a7f9e818eb1bafaL,
        0xcb374aaf0eb5f68eL } },
    /* 61 << 161 */
    { { 0xa5841c9ad5525ab2L,0x3eed9ba803e02cd0L,0x29449bca279fca98L,
        0x4990ec0f3f450c92L },
      { 0xa241a8e3becbba58L,0xd0e2487c2eb47817L,0x6db7d4208300837dL,
        0x788728952d7f59efL } },
    /* 62 << 161 */
    { { 0x1b3d50331314fc73L,0x2cf4cd42e710adedL,0x9159bc5d6f4026b7L,
        0x403f947b2e62cc45L },
      { 0x18d6ac7047d97843L,0x69d5faaa0694f7ebL,0x7711535c6932e0f0L,
        0xc85c96166ebd1488L } },
    /* 63 << 161 */
    { { 0x558e3750d3542212L,0x21fe02d702921066L,0x1636a1a246b90554L,
        0x8acf01ed0108cc04L },
      { 0x57a2b16ab4d60d37L,0x3301a33b91f4fdb4L,0x70dc3d3a8e09b548L,
        0x35ae7d07079c0c2fL } },
    /* 64 << 161 */
    { { 0x95792f06978f92ccL,0xb11574d323196752L,0xc3249711b8cfcac1L,
        0x2061c767cf93af67L },
      { 0xeff09a1b2f63dbe7L,0x527776b648091eddL,0xf0fa985e19bba5a9L,
        0xc54f89f366ae3221L } },
    /* 0 << 168 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 168 */
    { { 0xbc5a62846a436476L,0x6fcc231335dbb9cbL,0xa77d2d9f5012ffbfL,
        0xcc25e9f44ae4bd14L },
      { 0xd17fcfc41a5e40c6L,0x7d716a5fff085322L,0x9dcbc50bee3077c4L,
        0xebfe953cdb4a6e61L } },
    /* 2 << 168 */
    { { 0xe7e66f2fd3d777d7L,0x3519dc64cf1a6b09L,0x0df07bebdbf88dcfL,
        0x17b09654acd4e105L },
      { 0xcbd7acd04e70c783L,0xda66e74796b9d577L,0x6d0488a1e3e52f8aL,
        0x3ec0fd116ff71c1bL } },
    /* 3 << 168 */
    { { 0x75474cb6be4f2782L,0x10ef5e6b41c2c0cdL,0x592c6b066a65e29cL,
        0x4d424662d12d0608L },
      { 0xf5280949b1a714feL,0x52697bcc1199f802L,0xc68ba4f8e6a4ff3aL,
        0x25a5380f351849ceL } },
    /* 4 << 168 */
    { { 0x33207f69573ec6f5L,0x7ecc4bbe67bd2e8bL,0xa07acd348ffe2420L,
        0x0a957eb8a13f9cddL },
      { 0x0bc7f95b9ec9c0c5L,0xd82147cc6a8578cdL,0x07a2e7c59e61923cL,
        0x591eb06632e83f25L } },
    /* 5 << 168 */
    { { 0xaaa61588957c94faL,0x6a2bc707364911fbL,0x09771450c4907b19L,
        0x4cc487739694ccc4L },
      { 0x9db6216e50c878acL,0x6e89210c6f3031f1L,0xb711dcbfced0d41eL,
        0xe39bfe3e0fbf9751L } },
    /* 6 << 168 */
    { { 0x18fd7a45764636b5L,0xe437ee86b75d48f3L,0xe323bb1860a80177L,
        0xedc3c8f3bc94c0eaL },
      { 0xd8351164ec8cb0cfL,0xccdd88292472936dL,0xa8db1b8558059756L,
        0x4eda8cf8d55c184aL } },
    /* 7 << 168 */
    { { 0xdfb5727d2923b8cbL,0x6e793e5ce6773d5eL,0x8ecc901ba0641165L,
        0x6077ab26d6da5095L },
      { 0x00669b0c6b127d9dL,0x8140e4e0d63e2e1fL,0x1ad5b03c9641b6a2L,
        0x44299f889baed7b0L } },
    /* 8 << 168 */
    { { 0x1736296d1ea4a056L,0x6f74702cd77811baL,0x5c927548432dd74bL,
        0x9cc73271e7a194abL },
      { 0x0f035eded6328dcaL,0x5292aa3928db755eL,0xb5488385a0192a4aL,
        0x6e7d2fa8dfc6895cL } },
    /* 9 << 168 */
    { { 0xfa912a0a5d8bbec9L,0x7051140a0087edb3L,0x5293672b64865e5bL,
        0x6e8448c9c82c48d5L },
      { 0xeece41cba2c437b3L,0x148967d221ce1ef4L,0xf14391fa6b05c2a5L,
        0x15ff5fc98fed2f1fL } },
    /* 10 << 168 */
    { { 0x18ae5e744557b49fL,0xe33760c63db266b2L,0xd5d830c7b1b249b5L,
        0x24c665b9c5fff531L },
      { 0x6b304406c57df7c0L,0x59706667c3958e89L,0xbf590ff2790a5483L,
        0xbcaea5a55ce77aaaL } },
    /* 11 << 168 */
    { { 0x8578a00280ceb559L,0x3639aadfd8d61946L,0x3fd52d94add3bb00L,
        0x16c27846e09a8ce3L },
      { 0x75cfd6c6294c7967L,0xfb9b7f3759195034L,0xae687a99aa972a86L,
        0x04bdefdbebd2394eL } },
    /* 12 << 168 */
    { { 0x8e245a192f96144dL,0xc740d3483b61e5abL,0x8703710e293ddb25L,
        0xf4bb6ac02bbf8f63L },
      { 0x86396457de3b5805L,0x607022db65d29e63L,0xad0a0cdccc930fe3L,
        0xd9997ebb1626abf6L } },
    /* 13 << 168 */
    { { 0x2d872d172a510565L,0x3e6820790357ba07L,0x49edd962ebfaf203L,
        0x3a13edfbf81eda20L },
      { 0x87b5b5e17a75f2d5L,0xf04de2b8ddfd9511L,0xf29a1569cfc5c5ffL,
        0xa399553207160ed3L } },
    /* 14 << 168 */
    { { 0xb6247469cb2b061bL,0xe75c53512f10fe1eL,0xbaf44963d20e1bf7L,
        0x216cb6ab2d93babfL },
      { 0x7e0b655cf5109e45L,0xdcc712fc6657450dL,0xe06c408ed51fc733L,
        0x85b11f96ed9c0912L } },
    /* 15 << 168 */
    { { 0x954cb91c37365c9bL,0xe0eaa047b2f74fe7L,0x9af74b8615716541L,
        0x4da06207f73dc7bdL },
      { 0xdb0d089ee07890a1L,0x5bf0968173902f91L,0x14e1710ca897f0feL,
        0x191ec9a13605b1c2L } },
    /* 16 << 168 */
    { { 0x271b2e2a0133903bL,0x5b3686f2e495ee32L,0x89bcc9740c991f28L,
        0xadd20cce34f93b8aL },
      { 0x5f5a1768680b65b6L,0x0c453ab8aad41c40L,0xd479630fa7fb4269L,
        0x60039d0152c4e929L } },
    /* 17 << 168 */
    { { 0x0d8d112cff860883L,0xe1dce5c9723c6e29L,0xc19eadae191ad70eL,
        0x4af8194d62ce0e64L },
      { 0xf207bfb0cc81415cL,0x3ab92f3b008495c8L,0xe7250e17fdb9534bL,
        0xba67e9b86c0c1d1cL } },
    /* 18 << 168 */
    { { 0x117ae3ff072c793fL,0x5243e6ea9fb3091eL,0xf93ad51431a59e39L,
        0x8ce9cfb0c93c1891L },
      { 0xbfcbf9011ed08b0eL,0x4d13cf2ab53d687dL,0x25aa82db5d81e4adL,
        0xd12f01f563c3cb41L } },
    /* 19 << 168 */
    { { 0x1e799084f8d1333aL,0x30c96c55653bcd0aL,0x9cf130fd44b5195cL,
        0x4cffc53113c77763L },
      { 0x082287f89430619fL,0x78bb037db08ce0d9L,0x2e69d5123affe8e8L,
        0xe9dbb263ba9ec693L } },
    /* 20 << 168 */
    { { 0x67b66ad862f132b5L,0x70318d2bbeb47184L,0x46c429eaf50a0e98L,
        0xd7e32ebae2b3542cL },
      { 0x625c1ce9e096b4b7L,0x09221351389fd4ddL,0x08dc02d2fb0ee85aL,
        0x98c0ba7d853cd901L } },
    /* 21 << 168 */
    { { 0x88a0cd6d0deb1d99L,0x989e496279a6b90cL,0xf5d19b9524dd89d5L,
        0x189e5230b37cf19eL },
      { 0x84a607b8b0c5fefaL,0xe48450c9d8c7fbd1L,0x178f9b5646479ad7L,
        0x7d6a36c6cbcd2ae5L } },
    /* 22 << 168 */
    { { 0x95a4d51f71ae6516L,0x0363349f566e2171L,0x4d4bb4b0ed1f2fc7L,
        0xde435aaff10fa10cL },
      { 0x711258a9b76e3b6eL,0x9a640eeb2792e0b3L,0x7953ead85fab8617L,
        0xd4b6d248dd64702aL } },
    /* 23 << 168 */
    { { 0x95bbe5282d672209L,0xfcc53cfcb6926b8aL,0x0581419057659f87L,
        0x4836e93b08d25069L },
      { 0xd1eb20066a5ad81eL,0x4bee145aaf0d37f8L,0xd44362add31ce6cbL,
        0xdc03e581936c1060L } },
    /* 24 << 168 */
    { { 0x13cffce916fcb889L,0xed7e6683ac7e709aL,0xb655d0985896e541L,
        0x07124356b92a6204L },
      { 0xa2ae43c8a8f50043L,0xeb39255c68731891L,0xe07be0ad3d9c408bL,
        0x0db7904f0b4f5c3aL } },
    /* 25 << 168 */
    { { 0x7ddc02354d70bb81L,0xe3b323c35347797aL,0x3536cd9d3536deeeL,
        0x579b6894001bfd25L },
      { 0x58ad5301ebe2922eL,0xe0aa2cae92a88d43L,0x24567a3b4409e205L,
        0x3cece61a2258f0cbL } },
    /* 26 << 168 */
    { { 0x8da5cf463babf4f6L,0xb37428d981fff8e6L,0xcda1ff7748495d23L,
        0x98f9208f34f392adL },
      { 0x931f5b375bc88514L,0xd49971becb375921L,0x9dcd4986b5c01fabL,
        0xcc26ec02c1ab1c94L } },
    /* 27 << 168 */
    { { 0x34e8087db4b874d6L,0x224fc2779d0a3761L,0xacc1f2583f7e5159L,
        0xc82d71ec8966d593L },
      { 0x5b1f9f407dcd691aL,0xd8fafdaeba28f416L,0xe8622ae643b6d90fL,
        0xec13fce79ec71d5bL } },
    /* 28 << 168 */
    { { 0x07b6aeb8fd2e8214L,0x813e718e4cbc297aL,0xfac0dfab81fd6931L,
        0xa1fe88213c48ffd7L },
      { 0xd2715c1885e03c08L,0xb6e4418a977c57f0L,0xfaa79ea473418cdeL,
        0x6ab8c25b171e2a89L } },
    /* 29 << 168 */
    { { 0x2800445c4ec7cf05L,0x8e74a7b0b66c6200L,0x081b1177481db950L,
        0x526d051cb89f7c02L },
      { 0x3c8309425c29c905L,0xbfbd9e3e44c15ce5L,0x6055c949a29472e6L,
        0xab0010c7a37c4912L } },
    /* 30 << 168 */
    { { 0xeb8492be5b7d3647L,0x0b4cfd7b1ee31cafL,0x81cfcde24b46304bL,
        0x968df75dc554a5bcL },
      { 0x7ce788068d0e043cL,0x1e896819345ea27cL,0xe040c19c6e287603L,
        0xa581856f138e8eceL } },
    /* 31 << 168 */
    { { 0xe49f6558c354a9d6L,0xc4ad763ac0cfb2d3L,0x4be2143b1b76b8f3L,
        0xa8caae14d0ad0247L },
      { 0xcfe96bd5928b0ae5L,0xcf5051f77724f8e4L,0x9128916fec4af64aL,
        0xc211ff4bcb437bfbL } },
    /* 32 << 168 */
    { { 0xee6e8134bce59c0fL,0x3d068b4cd59f7f86L,0xafa2753c96283457L,
        0x453fe33c1aedcbf0L },
      { 0x781294c8483c0b1aL,0x9e6f51335c2ad1eeL,0x2a77b6ce69383e0bL,
        0xcb5a83abfa9f0142L } },
    /* 33 << 168 */
    { { 0x2318aa983b0e027fL,0xdea716a3c2c68dd5L,0x3f75c46d9f548eb3L,
        0x7164251396120de9L },
      { 0xf733614cdbee488eL,0xdf940026aad077f4L,0xeda9c09894a840cbL,
        0x5108bf0b393be3b9L } },
    /* 34 << 168 */
    { { 0x137c08b039980ceeL,0x2e31bba00839112bL,0x9ec73de2ba614ea3L,
        0xd0bca8d4d17822c0L },
      { 0x5d9f748250b7805dL,0x16035a80298becf6L,0x46571500d7c318e7L,
        0x6bd30919d0ee6956L } },
    /* 35 << 168 */
    { { 0x5c0ad747b2e13320L,0xe7f7f71eda47666dL,0xce322037318a8e8eL,
        0xf15232aee9f84dd6L },
      { 0xc59709c5915a03b7L,0x2e2000f79a3040b4L,0x41955f778398a5a9L,
        0xa8e6620e7086b69eL } },
    /* 36 << 168 */
    { { 0x63acd70e8344224bL,0x966efefcc3145159L,0x406619ecf5e0f955L,
        0xedd0efc9ec6de618L },
      { 0x6fe3e34eb2580ed4L,0x9d8875b54139b95eL,0x85baf0c18e5be187L,
        0x549cefca09553886L } },
    /* 37 << 168 */
    { { 0xc965b2a2ae9ef2ccL,0xd43079fb15afee63L,0x02b8794a076cdb05L,
        0xd0ae7321a0d1a953L },
      { 0x5a8b52812ac5fff0L,0x73437d67cdda362dL,0x1866b2b91a95ff87L,
        0x5ff113980420b3e1L } },
    /* 38 << 168 */
    { { 0x0d43b92c92284adfL,0x814253674da4c4a7L,0xc8093c56df17641aL,
        0xc418f19db5ccd14dL },
      { 0xaad98608506762edL,0xb6f45297ddb2c829L,0xd0e49176d395692aL,
        0xc05b4e273b1073d3L } },
    /* 39 << 168 */
    { { 0xe8ca133be5808e53L,0x6105cd0e06a64b56L,0x89a6466953cf6d7eL,
        0xe281ca2d1bebfea5L },
      { 0x98ee67ac324b25d8L,0x2227631fdca154ecL,0xa242c5a14406e8baL,
        0xced39f0549250026L } },
    /* 40 << 168 */
    { { 0xd256dd83dd77d731L,0x2faa6a0e7414d0c0L,0xa2e0f9283b90f004L,
        0x019bb3ef8719bfd4L },
      { 0x3f4f6109e2d515c2L,0xb50a9907bf88d7a6L,0x8e5fbc2d015ac4deL,
        0x96992421e78a2117L } },
    /* 41 << 168 */
    { { 0x321e608626e53df3L,0x07eb1d15f42b2508L,0x7b5521080ef22bc2L,
        0x9eedb82800f3e571L },
      { 0x556abbaf6f0e883cL,0x8025770b40473eadL,0x2fdab9656ece1cc8L,
        0xba07cf8900ec1adcL } },
    /* 42 << 168 */
    { { 0xefec4deb4be5ad18L,0x16625be8d59fa732L,0xffee542e6808cdf7L,
        0x85c19ef3d7a9f29bL },
      { 0xca4ac1f982dc1ae3L,0xa6c726d1ca5e8f58L,0x0bcc3d5866960eddL,
        0x8e8445d056f94ea8L } },
    /* 43 << 168 */
    { { 0xd4d0177b938e64c9L,0x8d0199f1f9a0288fL,0x9176d55914a226c0L,
        0x13b373eea00aea02L },
      { 0xc63b2d796b629feaL,0x36df7c09a7e0cc42L,0x4628ba4f40bdbc8eL,
        0x7f5b02280de296f2L } },
    /* 44 << 168 */
    { { 0xb05981303c63d73fL,0x55e59f610431550eL,0x6f2e109d6693eb8cL,
        0x3602ba82470b10feL },
      { 0x3acd0af45ec7f357L,0xfa7479f4b071c758L,0xbf47caa0e13652c9L,
        0x6fa139bbf5f5eca9L } },
    /* 45 << 168 */
    { { 0xfa149b848c0e197eL,0xca31714c60ae7755L,0x934ed1af8ccc4241L,
        0x39772769781a024eL },
      { 0x9f07dfb1be24eb34L,0xfa8a9c600a3dac06L,0x08fbbe218e410ce7L,
        0xea55fb96396a9702L } },
    /* 46 << 168 */
    { { 0x4422bc58f18882bbL,0x1ccb7b470ddd0dd7L,0x828580a8f40ea941L,
        0xf9ec97280db78350L },
      { 0x2823b4fd1612f28aL,0x96dc3e2982b26487L,0x1740fdae2497420aL,
        0x3bb39dfa322f1c6fL } },
    /* 47 << 168 */
    { { 0xf32a21e64cb19878L,0xeac040979277c80bL,0x67178d8f13380801L,
        0xfe5e269434bf8872L },
      { 0x8278bad4327129d3L,0xb42a3f9b941c4e5cL,0x04eefb7d39de36f0L,
        0xed2aab7f8d967703L } },
    /* 48 << 168 */
    { { 0xa3283a2c72aa1c89L,0x1969613e2a4d513eL,0x0d4c0347ddd5ea18L,
        0xbbad9ce443cee5feL },
      { 0xe8c050a857313b49L,0x3b91c3ccff09bf31L,0xe6e5ab6d610395cbL,
        0xfc36cde0deb31befL } },
    /* 49 << 168 */
    { { 0x76f806f25d43c8a7L,0x08a64cb263b7c746L,0xb6cdcdab45256a2aL,
        0x640f67ea9bebae90L },
      { 0x682eeeb6cf016971L,0x4d16d56650f59261L,0xdaca66bbf41db99dL,
        0xccdb3da0f8f04d96L } },
    /* 50 << 168 */
    { { 0x7c228caecf41b164L,0x40bef27fedbefa7cL,0x4efdd6c2ecb43685L,
        0x4d0fa367a834a50bL },
      { 0x2ec9c445b87f7ec7L,0xc3663ced23170d0fL,0x189872e4c5b47b29L,
        0xf8047387746d6a13L } },
    /* 51 << 168 */
    { { 0x753837d3b75ac898L,0xaee88a6091959a78L,0xf46b0f6ee6f59621L,
        0x0e92e27110d981c8L },
      { 0x610d0f808d578b6dL,0x962bd7bbb4d9b9deL,0xbe26960d84a0c394L,
        0x142a0c753b5bd996L } },
    /* 52 << 168 */
    { { 0x442bb39a0be95497L,0xce5d2c600f33c9deL,0x1ce0d08c283dc751L,
        0x106ed58879b3c1a8L },
      { 0x4b2e29c67f8ee4d7L,0x7d61e3bb08bbd660L,0x11504dc51e964a3eL,
        0x31544a52c77a957aL } },
    /* 53 << 168 */
    { { 0x1fc4161ecd7d0dacL,0x83733f27370c15c9L,0x224976de853758ccL,
        0x1bbb773047c1ab78L },
      { 0x94a3b69719c89029L,0x031432f037dfc44fL,0xf84593acd88090cbL,
        0x381b51bc65bcfee8L } },
    /* 54 << 168 */
    { { 0x38dac75b10b412b7L,0x6df5c9a1c7e06d08L,0x9c6d80680e08c41cL,
        0x1544e3c5c3600f4fL },
      { 0xf827a48d9c83e0a1L,0xd853922806bcb3c4L,0x149862b36268cf12L,
        0x4829ee566ec4e354L } },
    /* 55 << 168 */
    { { 0x44b2c3bfb712a1f9L,0xe556b78ac90852afL,0x50f6de2e906a13b6L,
        0x1744efd5568a1293L },
      { 0x942ad99e2b5745a1L,0x0f100bd9ca362913L,0xd9b6ad5191e96cdeL,
        0x4aa440bc5a2f88e9L } },
    /* 56 << 168 */
    { { 0x53c4c95657a10070L,0x7d1be72eae6e4872L,0xb704009cd427eda4L,
        0x3e0aa93f5f39b7d8L },
      { 0xdea1ab483153a757L,0x10a070e79ee60eadL,0xd6a6e92de6c916bfL,
        0x02b1e0e6bd7bb216L } },
    /* 57 << 168 */
    { { 0x6efb5f1bb49138a3L,0x11f7a9bee88d2db0L,0x0b9a2b113233df5bL,
        0x0688afda1824fcc5L },
      { 0xcf1ea2a55ff97f9aL,0xe8ad7b154998e602L,0xdb4ae67ea455aad1L,
        0x823ac09074a27ff3L } },
    /* 58 << 168 */
    { { 0x5c4310602573443fL,0x92f9f9ab94258714L,0x1548fe21b1283d2eL,
        0xf86fe50b5c5be5f9L },
      { 0xd20dfc8a520c5fc6L,0x6e721dd953b5e7c5L,0x8ef7eee58f2a8969L,
        0xe894859f62d07bdfL } },
    /* 59 << 168 */
    { { 0xaf2791761cfc6627L,0x94b8cff4483755e9L,0xa5916f700fda4bcbL,
        0x9c5318d047ba65f3L },
      { 0x9e9c8e54636cd7e3L,0x5c64a26154c49da3L,0x04d7ff61690e932cL,
        0x92a357b3c84b0b78L } },
    /* 60 << 168 */
    { { 0x47f6144cc6f3bd8dL,0xdf7b1ee471c19265L,0xa7ea37f13fd5c30fL,
        0xdc2d890b79fa08cfL },
      { 0x9813bced2fd40236L,0xa8a1055f432dde17L,0x70011f477772c727L,
        0x965c130a2e2e802fL } },
    /* 61 << 168 */
    { { 0x31a6aca7f5bd4ac5L,0x83995bded825db6fL,0xcbf20325fe521833L,
        0x8dcd25a10278f4a0L },
      { 0xf1e83d975f2293eaL,0x1717876b52317ad3L,0x0df6216714181928L,
        0x24adfd6e2fe203ceL } },
    /* 62 << 168 */
    { { 0x1d264af0797f25ffL,0x2cb7cc17d22e3da1L,0x10c4b51ae0016a19L,
        0x5956ce8fd82b2a86L },
      { 0xdef0fefca3d4780eL,0x97e693ab6e92b93aL,0x8fa3f4fa20bcc98fL,
        0x4fc004f1f9182867L } },
    /* 63 << 168 */
    { { 0x1a206da393e73961L,0x37d75a901e7db32cL,0xa39f0db10455b815L,
        0x841646e0b69ee770L },
      { 0xadb0aaaa0939f065L,0x5608613b0b147d7aL,0x84ce1a4c470f6875L,
        0x501de5fe7983050eL } },
    /* 64 << 168 */
    { { 0x19915b26c3d8ed98L,0xf451e57a9a66a6e5L,0x2984360730dab6a3L,
        0x1710267c3d1a1ebbL },
      { 0xce4ecfd4e11d88c0L,0x12fc278711ce026aL,0x9801cecd691227deL,
        0x517a92f376ce6daeL } },
    /* 0 << 175 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 175 */
    { { 0x821b0fdf648c48e5L,0x689e6d569f45a433L,0xa5a9dca82e572855L,
        0xb0f07eb78adfb547L },
      { 0x48ecb166552c8d55L,0xfe3fc268ce854171L,0x323af5ebeeee9bc0L,
        0x0666a2a341ae1c80L } },
    /* 2 << 175 */
    { { 0xa06d20bc9ff262fbL,0xcba032fdd075868bL,0x70376026943fd973L,
        0x81c57cbae35c5e02L },
      { 0x1964e700ba871f1bL,0xf03a8c046b265f57L,0xc8ebc9120b950259L,
        0xd2b0ee30ad32ca8bL } },
    /* 3 << 175 */
    { { 0xe01bf0c289c8e719L,0xbce1e20fb2f4cdb0L,0x8c38eeafa1053ca5L,
        0x8c2d85ef7cd633a5L },
      { 0x756953649b53cdb1L,0x5e999741447eb1a5L,0x6d6b2d88dbd88626L,
        0x87eaf04521876357L } },
    /* 4 << 175 */
    { { 0x2c88f1ffdeec441eL,0xab52096bd01b2157L,0x37eee2756c45cf5cL,
        0xa070d24e0520ecaaL },
      { 0x61d15bd1546b9fd3L,0x3276fb742c96db1cL,0xc5c1b041b95b29b7L,
        0xe18008dbbd7d3254L } },
    /* 5 << 175 */
    { { 0xd56ae44f98dfb69aL,0xd5f66b0b609d941cL,0xca6b6d35b91b5245L,
        0x98e3a4e37b3f98a6L },
      { 0x0715dfa6f358c56aL,0x3b02ff2136a66c64L,0x737b1401cb22cbd3L,
        0x9dd15f5b6b8e9624L } },
    /* 6 << 175 */
    { { 0x25f5a71dd360d017L,0x4c0779b529b0ed73L,0xc662fedc9825a018L,
        0xeee8912561d4add0L },
      { 0x1543814d92163d14L,0x79f2376f27370d3cL,0xf80c6963cbe1af7aL,
        0xf2d521bceb9e41f7L } },
    /* 7 << 175 */
    { { 0xe241619fc1805864L,0x6f1d6166b2de204aL,0x13c3f91250e68d0bL,
        0x32eb021dc4a24f5aL },
      { 0x3f1452f50e78c588L,0xa267bf19c9971e98L,0x77a231a7e801c021L,
        0xf363c9b3c2666e80L } },
    /* 8 << 175 */
    { { 0xb8eb0bf0ae309a0aL,0xa9f52f58375b8fbcL,0xb8e4f9481a4993b7L,
        0x50ce578e8f73c292L },
      { 0x2437a4a602e503d6L,0x20cdfc50e4c68ea3L,0xfec5993b3616f348L,
        0x5d96b4c5c0c420dfL } },
    /* 9 << 175 */
    { { 0x6b71cdf0cca0c48aL,0x00e71b54c1aea033L,0x247f5baa69f6d107L,
        0x4e3ec504050c3704L },
      { 0xf2b2be8a7a438e93L,0x240b632da331e01eL,0x61e6655791150675L,
        0x3236413495a99a28L } },
    /* 10 << 175 */
    { { 0x5e5de136d3399e1eL,0xe38bab00fe2f8b75L,0x736126de3a77db29L,
        0x7b0d1865f2aa121eL },
      { 0x5545e45edecf9cdeL,0x9608ebce2318be70L,0xe6596006fa55b0e5L,
        0x0c8c2f41bc4b6ca0L } },
    /* 11 << 175 */
    { { 0xda1c5c7a92025945L,0xb114ba225d3b0775L,0x11cc6888cedb69a0L,
        0x4365bea80f83c772L },
      { 0x006fe80bbda8dbe3L,0x334adcb6c2d3d266L,0x8c92c0841521de1cL,
        0x57873ef978d8f72cL } },
    /* 12 << 175 */
    { { 0xcfb0a7d03b64dcd7L,0xf4c2f1fc558c9d55L,0x110c2db2a0fbc656L,
        0x3cad85caef5b6beaL },
      { 0x7099dd0e4e0b1230L,0xc769b937098a2fcdL,0x9209f5501e1e7407L,
        0x1b47255d1ba7cb47L } },
    /* 13 << 175 */
    { { 0xd8aed0cd2c01b596L,0x1a1a2e1130efcda3L,0xf771f93b36b1a5b5L,
        0x2ea34e3d14fcd251L },
      { 0x6895cb31fd893979L,0x10b1d2c914f556b4L,0x835fdf7e6430bfa8L,
        0x1f4bbef524bf4ba5L } },
    /* 14 << 175 */
    { { 0xbc805aa5d562b5f1L,0x7101b9da35dac658L,0x5b7f211dddc28e5aL,
        0xea89f24cd3d1cd0aL },
      { 0xbaaa9ef57567c80dL,0xe0d1f26d9a60c5eeL,0xc88a044cab36cd64L,
        0xb8e03d021b125de6L } },
    /* 15 << 175 */
    { { 0xda0c10473a707a66L,0x76ddb98f0c692d44L,0xeccae586b15b7254L,
        0xeadc1b51e7e82423L },
      { 0xd6779ff27c3cb698L,0x0e271cb4df6e7da6L,0xeacf34c345900023L,
        0xafd017ad03da2ba5L } },
    /* 16 << 175 */
    { { 0x4926699827c7e6ebL,0x84ffa3726625bc7fL,0xedec924705c9cb15L,
        0xcfad0b908075b84eL },
      { 0x94bed316bc0898d3L,0x02481eec11f92525L,0x19896e1b0d7e59d7L,
        0xa06adb6cf2bb3129L } },
    /* 17 << 175 */
    { { 0x1539228e62a0a690L,0x98ac50b98ae02bdaL,0xaf233c85e5cf21b9L,
        0x943348d3d6a9f599L },
      { 0xf5a2f2d1db363eaaL,0xe917e2c57a8ea96bL,0xc80b56c8bf5c8293L,
        0xcfc1c24fcdbb5c4fL } },
    /* 18 << 175 */
    { { 0x7812dce2fbddf07bL,0xd4af2f9b0186013aL,0x1fadcd166fe8d485L,
        0xc3c2cd95c968f0b7L },
      { 0xdbdd2ef0778bff58L,0x673692048706da34L,0x31cf3a66b8e70e35L,
        0x0b9e5cc5d333801fL } },
    /* 19 << 175 */
    { { 0x1212a811f7177c4aL,0x9e266ec32d379e12L,0xc73828482e8bbbf7L,
        0x3f3f1dc1a973be5fL },
      { 0x534d04de786e727eL,0xfd7a5fbb225497dcL,0x3c03a7fdb63b6320L,
        0xe77f89855dc76e05L } },
    /* 20 << 175 */
    { { 0xe8d14f32265f8b8fL,0xfeaab021b90549c9L,0x7cd36751081ccea6L,
        0x7a0014411f1e8f7aL },
      { 0x2e87b8a21fdfd622L,0xe76138ce8bb4f812L,0x9a5e872271e03be4L,
        0x795e60f3153e0a5fL } },
    /* 21 << 175 */
    { { 0x11d28438d0eb7d4cL,0x147884e14254a845L,0x6795f20f2a8693fbL,
        0x5a10d535ee01bd1aL },
      { 0xe39982c9218c0513L,0x6c23e5be1d4e6ab5L,0x20a8c27f0f424e7cL,
        0x74ae99983bbb486fL } },
    /* 22 << 175 */
    { { 0x3fae61beb90ce3a1L,0xf0f5a1e4571c968bL,0x6b9dded87780d91bL,
        0x10f60ce27597e866L },
      { 0xf268ed02f1eb7d1cL,0xa49b5a466030bf9bL,0xc939c4e7251f8676L,
        0xbdfe5036e2b9928fL } },
    /* 23 << 175 */
    { { 0x5abfbcc2bccf7f43L,0xb22067b628c560afL,0xecf0777104c6a2daL,
        0xa2bf88db8c4ae7dcL },
      { 0x172396f2616675e8L,0x9abbb19c8bfcfbc2L,0x52e26c06e85edd21L,
        0xfca4c4e0a65de52fL } },
    /* 24 << 175 */
    { { 0x255e2d10281d58beL,0x93ec29343614ed6cL,0x36d6cc156dc71abeL,
        0xaa2ad1eff592ae78L },
      { 0x39a82740cc9291fbL,0x6812b80f102600d8L,0x64f4843c50c511d5L,
        0x28f5795e03445793L } },
    /* 25 << 175 */
    { { 0x2c56637229f20b0cL,0xb168ca7a9e24474cL,0xfadd8f80abe37949L,
        0xafa1bea24cd69856L },
      { 0x5ce6ed8046713b88L,0xaf8b5fb34b3bb84dL,0x134e512029d53349L,
        0x1214f4f0cdcedefaL } },
    /* 26 << 175 */
    { { 0xc346821b4bb405b9L,0x753afa86ddd624d6L,0x15fe543cc7c014e3L,
        0x6b3c0c5d43d08964L },
      { 0xc77c8fb0745221aaL,0x3e144fce152995c9L,0x57089907a61b96bcL,
        0xd19a912c5e05c1eeL } },
    /* 27 << 175 */
    { { 0x7bcdc697a6ddd20bL,0xcb07e2292d5090f3L,0x76afc803f089607eL,
        0x9f7a88b9637dae27L },
      { 0x1352d8bd3bd20d78L,0xede1a7805ea79d4cL,0x59a8222bf389e31dL,
        0xed066aa65c09f3d4L } },
    /* 28 << 175 */
    { { 0xade16197684529d3L,0x97bed90496a2a159L,0xdd3da7651b695d68L,
        0xb8fa37e802fecb9eL },
      { 0x1af4311cbc0f7b99L,0x600bdd462a492a7eL,0x6aa9cb3045dc9d16L,
        0xaa494815c0b93019L } },
    /* 29 << 175 */
    { { 0x1211834bba052dd8L,0xcdc0208e86822bf1L,0x515eebd48c8362a0L,
        0x9ea7b9f59b90cf96L },
      { 0x8418fe343a0a5a48L,0x654d3c32331a2db1L,0x22362ddfafde743cL,
        0x617a89e86f6ee3baL } },
    /* 30 << 175 */
    { { 0xed5f3d04b7deb988L,0x31c2c9e6bbc8a6b2L,0x8faa80e181a3f184L,
        0xa718348851ecc548L },
      { 0xe67512d0a3780d0aL,0x9f868036822db54dL,0x6c74490ae555beabL,
        0xe747e666d989d6beL } },
    /* 31 << 175 */
    { { 0xf8346dd6df8cd308L,0xe7ca105f4745cd8eL,0xee059c5831055db8L,
        0x90f4053a18b38aa0L },
      { 0xbb2e7fc341081a21L,0x3602525e45b33a71L,0xff21f2aa2b411945L,
        0xbeaadbd3064ccb11L } },
    /* 32 << 175 */
    { { 0xc35f6950fe94629dL,0x1cbaa9359f860b15L,0x29b4bcd3f24f8f15L,
        0x0ae5b06ad29c8458L },
      { 0xa645c31d1b6c2df1L,0x640b0990d804faccL,0x7a4a7f59122b33e6L,
        0x94bb0b2b7479b828L } },
    /* 33 << 175 */
    { { 0x0567272ac4cd4887L,0x676d6962fc8e4b0bL,0xa712b0208661c0c2L,
        0x660e6aff279454a7L },
      { 0xe12951061cd25bfdL,0x7096885c077496a8L,0xdbc47c923006ab7bL,
        0x498761fa509205f3L } },
    /* 34 << 175 */
    { { 0x5d1eaecae85ecfeeL,0x9fcddeed534f38f5L,0x4d34ec808af32f70L,
        0x476dffc924b3b4e3L },
      { 0xb45cd8698bbcda9fL,0x3b0079e7df684c2dL,0xcaf3eeb5765cd483L,
        0x0b9e25e663945b62L } },
    /* 35 << 175 */
    { { 0xfd73833e06492e0aL,0x4d2937e19507ea57L,0x3e532c2ecf562953L,
        0xe4baa2d481ca80c3L },
      { 0x4699e5c428d22139L,0x69aab9006b1c665aL,0xf6a37330641016acL,
        0x335f14cb5f3b7c71L } },
    /* 36 << 175 */
    { { 0x94a6c868facd904fL,0xb1127cc42ec2bf99L,0x0ccfceb3a4b72d69L,
        0x16b786a355172f5bL },
      { 0x51ebe029e093a729L,0xf57f4a1ec40c4487L,0x8aaf0dd6a8ed5a3dL,
        0x617c51f7811f35d6L } },
    /* 37 << 175 */
    { { 0x18c7ac6211e98d29L,0x71c578c42c904ea8L,0x4626b0ad3c4ef8bdL,
        0x121eb676a390be8bL },
      { 0xcb7249f5154e297dL,0x678ad966c2288ba0L,0x3c2ab06657cc9cbcL,
        0xe32c1d4580c8fbdaL } },
    /* 38 << 175 */
    { { 0xd2f152cbf0b35526L,0xc7f75fd413877dfbL,0x8603feffe83ca4a2L,
        0x6be89bb3cd680589L },
      { 0x5650549e45e1f141L,0x7dab03b8a55ffadcL,0x342edda42dc5d31fL,
        0xa97451ac9af8105aL } },
    /* 39 << 175 */
    { { 0x796e1fe3705b8fd7L,0x6252a7ba02d131b8L,0x3db2ab14086c3099L,
        0xeb763df59db0ce72L },
      { 0xe7b57bab52b62fa5L,0x6076d44988b820bdL,0xc43e1f611b660123L,
        0xc802d40b189eace5L } },
    /* 40 << 175 */
    { { 0x1f2a2a91341309a1L,0x8680be67414db96bL,0x65dd0396c846e288L,
        0x8a1d871eb0bbea85L },
      { 0x623e24088ff931c6L,0x4933ffdae14c5941L,0x72688986b2cbff67L,
        0xe51504d88cf79450L } },
    /* 41 << 175 */
    { { 0x50cd0a3ffeba1168L,0x08d2e0fecd833df8L,0xdbd608270a4370edL,
        0x010cf80066f4f58dL },
      { 0xffa29252144e9656L,0x90b896a29d1e9d61L,0x1802257c81f7b4d3L,
        0xd7758e8b595612a5L } },
    /* 42 << 175 */
    { { 0x751882d8241b4dd2L,0x7dae3003fe177abeL,0x8f4d5dc4ee6fe1cdL,
        0x93a9cd5bb08f625dL },
      { 0xa4d6ee1af91cc442L,0xe05976cd594d172fL,0xfb4064c66e762b2eL,
        0xb2068ad951a0156dL } },
    /* 43 << 175 */
    { { 0x0d2d5b2624f06e82L,0xad70f2768c85a9a9L,0x00ede5d50ed413cbL,
        0x245be28b927064d2L },
      { 0x06eb28252af70d77L,0x472af63052b0592bL,0x493afd98d881d50eL,
        0x56fa76a81189c989L } },
    /* 44 << 175 */
    { { 0x775665d2faa974f7L,0xe395ccdbc3f54effL,0xf0a40e4e3fc83a7fL,
        0xc3b11d224c00087aL },
      { 0xef8d2f06ddb50678L,0x6e41f3156cd5f681L,0x7c9d7a3da1b97891L,
        0x8b297d75a0a41260L } },
    /* 45 << 175 */
    { { 0xca44b65c3806a30aL,0x125c570261a6206eL,0x311842a287003e1eL,
        0xe049a7d04513d726L },
      { 0x8022c2d07b123469L,0x7653393486294393L,0x6a6e84e7892e7bc4L,
        0x7daf8b11db2007feL } },
    /* 46 << 175 */
    { { 0x092d1914923e185cL,0x5ec112373def87c2L,0x38019e9618742a51L,
        0xe05ea79e4808ca10L },
      { 0x1fc8ae26134cbf9bL,0x1405467201b4c1c4L,0x32abf91264051972L,
        0x0edaa9251af62fcaL } },
    /* 47 << 175 */
    { { 0x58fa82e23c47d01aL,0xdb12a452780762c6L,0x16d5a733fdbf4683L,
        0x1d7e85072f798debL },
      { 0x259aa9b99eab12f7L,0xb13e6e4191261397L,0x564706fa32602f2eL,
        0x50daef9c9c2283efL } },
    /* 48 << 175 */
    { { 0x9275f219f07a196eL,0xfc58ebeabb8fcd35L,0x5d1025f1bad69c11L,
        0xcf3641541605c11bL },
      { 0x427bd1172992276cL,0x5545bec56a73cbb3L,0x86855c2f133f3266L,
        0xb3d753d167d9e5b2L } },
    /* 49 << 175 */
    { { 0x2134b384c9fb343bL,0xb572f5d6b0e12b7aL,0x7ee5852f392d24feL,
        0x73559faec4f285f9L },
      { 0x269cb9e77711c525L,0x4badfc52f00d5606L,0xef66d726b465df15L,
        0x83eb59a3aa4a301bL } },
    /* 50 << 175 */
    { { 0xdb406469ed329b12L,0x6eb95cc9d933eb45L,0xe2dabfa46b638bddL,
        0x7a5d0098031df114L },
      { 0xe22d8f3e38dbfaafL,0x2306fd54d79d1ce1L,0xda3245357acb7cceL,
        0xde6fcc1688f61a1eL } },
    /* 51 << 175 */
    { { 0xaf3e4894b730fe5cL,0x7a3e4a7d28adf897L,0x352c0069b160ae0eL,
        0x225cfb67ee52c58aL },
      { 0x12391b7196b2505fL,0x8d811bee3758141dL,0xc941524d8cd82e11L,
        0x0feb26a5bb83a251L } },
    /* 52 << 175 */
    { { 0x60ad066576da8411L,0xe3c033d988d4a968L,0x767b3c05de120078L,
        0xab7da95a9f31e1e8L },
      { 0x7ad9b263b93e7cb7L,0x280f6bc3fd626ea3L,0x746c394562713cadL,
        0xfa2b45993a4edce8L } },
    /* 53 << 175 */
    { { 0x8792d0cb10ab7f93L,0xfa38d031c25a2a86L,0x6914db0b08b028e8L,
        0x75a98aa0383cab40L },
      { 0x462e6b6d6da884bfL,0x2b0f682bd3aa74b1L,0xb3b7995e5cee0a83L,
        0xe99fca2b3cce609aL } },
    /* 54 << 175 */
    { { 0x342c41c945451744L,0xb00d3c24c81be29fL,0xd1e64d86022e8d27L,
        0x404550bebcf67326L },
      { 0xc7c510f0c8aab829L,0xb61ae647a90c605dL,0x582ad9c902db8602L,
        0x732b19ed71cb4397L } },
    /* 55 << 175 */
    { { 0xea097c35265e5369L,0xea7c368f9d5ea687L,0x7fc3b2138fcae7f1L,
        0x641daa3f49c54942L },
      { 0x0696372b404c39a6L,0x5681571687b4b181L,0xa6e156b3fca24eb8L,
        0xf278eeaed078a39cL } },
    /* 56 << 175 */
    { { 0x046566d1ac762dbeL,0x662ef0f6625ed2e8L,0x15499e72650e4764L,
        0x361ccef084edf50eL },
      { 0x2441f6f41f4a2200L,0xf36fff06db730d58L,0xcc18624d3c01edc7L,
        0x4889078f8a77e5bbL } },
    /* 57 << 175 */
    { { 0x02294e3b75f8dd8aL,0x5f6f6057fc4113c5L,0xb5300e0d6f699f18L,
        0x52cce358639dc977L },
      { 0x5dbe59b8328fd50bL,0x81500be639d73c2fL,0x409ac4d796ae313dL,
        0x15205b7b5b16c316L } },
    /* 58 << 175 */
    { { 0xe272300cfc688c09L,0xb412cf39bdf71f2dL,0xe3ab9c44f85b23d4L,
        0x5c14085c7b662694L },
      { 0x24b0b3859956d07bL,0xfa8ea96830b2c82dL,0xd443b2aa6d403b58L,
        0x6da53ecbe7fc8d57L } },
    /* 59 << 175 */
    { { 0x29655314dfdf488fL,0xb418943dadc57e2bL,0xbaf090f16395a287L,
        0x8fdb4fc8d62f5b38L },
      { 0x115653c0371c9db1L,0x6f5e1f3996463359L,0x106aaf1e825e6273L,
        0xba22b7db398cbe1bL } },
    /* 60 << 175 */
    { { 0x3b54530062b6bf7eL,0x495d7d275bb6f993L,0xf558fc5d3f00290bL,
        0xdddbeb3e2cfc2381L },
      { 0xca40217965c79326L,0x376ce4ac33b1973cL,0xd6e65ae49b30749aL,
        0xdf68ee045f54bf5aL } },
    /* 61 << 175 */
    { { 0xa982948d4cfdb41aL,0xddd1d3baf2a7b4b3L,0xf52a6b33581aaba1L,
        0xc3258264894ebf68L },
      { 0x26c32c2784665ac1L,0xda0190eb20119b0eL,0x4a599db7b86745c1L,
        0xf9570f5058964b41L } },
    /* 62 << 175 */
    { { 0xb34d039be0648365L,0x2cd7fde05c5f61e1L,0x76f514a3bc6b08ccL,
        0xc957b50d18a3cabfL },
      { 0x775fc56a2334cd1fL,0x7bfe386467ec91c6L,0x99037daa35ad3a9aL,
        0x17ffe391b7ca5657L } },
    /* 63 << 175 */
    { { 0x19f6d369fef04aefL,0x8030b467d1876f8cL,0xa014be023cd7878fL,
        0x03c22a583358c943L },
      { 0x3c77f0832a257094L,0x47386957d962a04fL,0x768da40c82da3329L,
        0x1507350d458219cfL } },
    /* 64 << 175 */
    { { 0xf460aed34397ee7cL,0xf249e4cc36fbc7feL,0xc42d9da8aab03dfeL,
        0xa3d73ce3435ab9f3L },
      { 0x86dddbc33813a3f3L,0x86d5779ab79c32a3L,0x7c3d9aff028a2c3fL,
        0xc687e71bb1add2bfL } },
    /* 0 << 182 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 182 */
    { { 0x4612a56209b3fed3L,0xf296c17a3579966aL,0xa124a36f07960971L,
        0x6d03b214380c4a05L },
      { 0xcb0746e270f1f268L,0xcc9b47ff9341aea4L,0x1b3662d56d2f59ccL,
        0xa6c65b2dd4b1a15dL } },
    /* 2 << 182 */
    { { 0xf96c113acccb0a4bL,0x24c26bba3615f016L,0x52fe115aeead2f5bL,
        0x85623d260d7aaabbL },
      { 0x50791fd031a2564fL,0x3659974dcd0d59a4L,0x2cffdb747a8b7466L,
        0xcf6b36e5514787b0L } },
    /* 3 << 182 */
    { { 0x8afccd364ab1ccd2L,0x673146351c03ab29L,0x458f36bfd7ff3a32L,
        0x70e9e789fcf71648L },
      { 0xf3764534a6e904cfL,0x2d6130b1f4bdd378L,0xc61c98fb1ca5ce34L,
        0xda11f502a4a684f5L } },
    /* 4 << 182 */
    { { 0x8d9daa41b6223f04L,0x803c9c0e841c3fabL,0x60eee3f9c50b42cfL,
        0xaf4a7a5a77298193L },
      { 0xd379c2e1bf809ad6L,0x903ab4b1f67c0ff2L,0xc779d7ed90f8e637L,
        0x968b0cc02cf3d363L } },
    /* 5 << 182 */
    { { 0xaadfa857acf51940L,0x0c789d1e50156581L,0x5e79cef762cff8f4L,
        0x54cdaba965eb0d49L },
      { 0xdf7a58283321c57eL,0x8571e6e2a21a51a6L,0x0b9b482bc3726e69L,
        0x3bc201e31d92b657L } },
    /* 6 << 182 */
    { { 0x271c58bb8a3b4cf8L,0x269fc422717eb539L,0xe82644e95b381fe1L,
        0x27fb0822cb62982fL },
      { 0xb0acd51c5b5ec726L,0xfd01053dea4eff73L,0x465311dd00b11c80L,
        0xe50a86152ed8460cL } },
    /* 7 << 182 */
    { { 0x3eade5eb7b2243a0L,0xa59ec93377424d11L,0x65a8e1aaf5c7c3b7L,
        0x008399fa0c1db536L },
      { 0x80b20e97fb194a74L,0x2316fb9b43be90dcL,0xb2773b230da4d913L,
        0x945d0671ce973d27L } },
    /* 8 << 182 */
    { { 0x64ca871cb79f82afL,0x31304b022dab52f6L,0x1825ab54928239a7L,
        0x740413b28e4ad736L },
      { 0xc5c5d3fa44071d19L,0x83e438f13f0b2da8L,0xfd759448c70a1981L,
        0x13e0c7ee565ebae3L } },
    /* 9 << 182 */
    { { 0x31b74b0a26bd7c0aL,0x66e0e8e8d280cb56L,0x086795e63d1c83d2L,
        0x59e678da396ecf25L },
      { 0xab3c8d74f015a36eL,0x0d19aed3adc03171L,0xc83b787f5a263686L,
        0x46b94ad09057ed63L } },
    /* 10 << 182 */
    { { 0xfbf783a790979da2L,0xf04dd6a0a335c784L,0x6e3c255487d93c4cL,
        0xe3e6b28947994eb3L },
      { 0x473c06841b74ba16L,0x4e959eb4abe84e1cL,0xdc3bfd517c4a67b7L,
        0xb4e3cb855095bd6eL } },
    /* 11 << 182 */
    { { 0x96fc11f03229fb05L,0x598227e44b36c83aL,0xdc69ad06d46fca66L,
        0x14cc98e5703ad6beL },
      { 0xf0fdd1426b22cd50L,0x9b821fe2f89c1a5dL,0xa3762dca829f9a74L,
        0xf65a584af0c320ccL } },
    /* 12 << 182 */
    { { 0x58f4eaba5568f242L,0x83b0c37b029afc1fL,0x93de2d27994d7dfcL,
        0x0d9a6edbb1679532L },
      { 0x3b83427995f085b0L,0x46ebac98a299355fL,0x0212e489044427f8L,
        0xf9e4ce34a2f37d0eL } },
    /* 13 << 182 */
    { { 0x0fa328d6fdc9e233L,0xd5c8afab51ae732fL,0x85e5955383c00ceeL,
        0x9fce31f987505db4L },
      { 0x33ea5eb67069d066L,0x10e32a39f01c0ce9L,0xf170233c0c4f1a2eL,
        0x8a907760bd4cb366L } },
    /* 14 << 182 */
    { { 0xda59342179bf05e3L,0x7730907ace49a5bdL,0x0dfb8a9709be5c7bL,
        0x6f50c69223eb936eL },
      { 0xc6160551cb18ff1aL,0xfa1d23fd661cc384L,0xfef123077ddec262L,
        0xd1aca960b15af580L } },
    /* 15 << 182 */
    { { 0x7eab8a592ee50fbdL,0xe7f71845be1e7a42L,0x5f46a5116121e573L,
        0xa25dacbf38ff7ebaL },
      { 0xe8aefcc7f58f047cL,0xc343aaa7b538aaceL,0x3e58cdda3c340b1fL,
        0xb0e9867c1fb98ccbL } },
    /* 16 << 182 */
    { { 0x034dd314ef7750f0L,0x2ceaa70522da84d7L,0x4561a254fc0d647bL,
        0x81cf0915bbe01157L },
      { 0x547a3d4e34b798ebL,0xbb5dd6258b1c7544L,0x94fee01bc8194168L,
        0xdb4c25fffaeb010bL } },
    /* 17 << 182 */
    { { 0x1ff217fae4d4a176L,0x8b46e6c2af87f4f5L,0xcf65877589734273L,
        0x73c4390d52746de9L },
      { 0xb5c84899b01c7a06L,0xfa5ffe4dedd9ef63L,0x28a313c5a1a8b2d4L,
        0xadd45f47daf5a33fL } },
    /* 18 << 182 */
    { { 0xc2dc9d131fdb8694L,0xaa5e026c9a90b4d1L,0x5edffd39208cbfa5L,
        0xf095b3fb72a4d6ccL },
      { 0xbfca4e106645fcc1L,0x14b872ac92408c6aL,0x3d9261e1d0b82d2dL,
        0x13e4ecb60294e75bL } },
    /* 19 << 182 */
    { { 0xabd4541c3ac2ab9dL,0x025355b24d5d1531L,0x3d85f67cfb726ab8L,
        0x56e26c826d6fc6bcL },
      { 0xb24608bb495e05a0L,0x840e0978e5afdc5dL,0x2cc543b5248727e2L,
        0xe48146da3bc8c021L } },
    /* 20 << 182 */
    { { 0xa1b36baf530c98b7L,0x04503d7b5acf023bL,0x96bc444921de1503L,
        0xbb8a122fd2a9c89fL },
      { 0x66df99dfd5d4b133L,0x1bb4a13bc97d3e52L,0xdab370f379b318d6L,
        0xfa6c823e9f18552eL } },
    /* 21 << 182 */
    { { 0xe5b27e786388a194L,0x13270523c88ba441L,0x9f309fbf4fecfef5L,
        0x72cd374b10afee60L },
      { 0x16bd0e2e93dfe3afL,0x7e92096a24bc7e8eL,0x144fdf82fec7f0bbL,
        0x5d1d4598e1f765f7L } },
    /* 22 << 182 */
    { { 0xb6b91efc72c67697L,0xc7a2ceafb2487905L,0x4a4c9e637fb24d99L,
        0x7ed373ac4d742089L },
      { 0x3f9e6ae19149ac54L,0x64fd7fef0611efc8L,0x1c38da323d779af6L,
        0x6893691b0a1681f5L } },
    /* 23 << 182 */
    { { 0xbac2997850a0fa72L,0x98d5c82eba55c665L,0xf3e5b58e2d4b76bcL,
        0xfae27d9a90615b32L },
      { 0xb93bc327d49b2500L,0x7d9d4bffbbc213cdL,0xf985fe72d1ee81c4L,
        0x6e2a94d1381f9e48L } },
    /* 24 << 182 */
    { { 0x1f09b22514fb9624L,0x2eba4ff8ca4229d7L,0x5b159dd121dc8c19L,
        0x1e1f968fb1aa553eL },
      { 0x6ea25976c7674d52L,0x98e73adc7b283501L,0x7cfce0e1d39468c2L,
        0x7aad0af908438a62L } },
    /* 25 << 182 */
    { { 0x2291cdd0b2a3dde2L,0x3a625d50f77a0aa4L,0x3be0fba25fbc5a0aL,
        0x67b7598ae794bf46L },
      { 0x3673d805531ad772L,0xf9a9b39203e8479fL,0x142d264c2e16a126L,
        0xc20409ac5a2f6f2cL } },
    /* 26 << 182 */
    { { 0xd9d84438cd43f273L,0xfecc561dbda7be72L,0xc4b113c6241b7ec2L,
        0xfc5bc32b40dba9e3L },
      { 0x70853d39d56bca47L,0x2b9a902da5306217L,0x2bb1836d2017bfd0L,
        0x829ce116cd1c2768L } },
    /* 27 << 182 */
    { { 0x42d5fcf8697097f5L,0xc1fe7be61e936db5L,0xcbc5cdcccb6a81d4L,
        0xab1e4ecbafef5ffaL },
      { 0x3cbbdf76b933c216L,0xdb5808da503607e2L,0x5bdaab7c6bc96246L,
        0x91e5d17c68274629L } },
    /* 28 << 182 */
    { { 0xa3cd09f62eb1db21L,0xbe37048592c3e3e1L,0xeb51fa296aa43da5L,
        0x2c7fa809d726625eL },
      { 0x90c6786ff0ec0e99L,0xd315af3308135cbfL,0xc1b601721504751bL,
        0x88674e2d0e28781aL } },
    /* 29 << 182 */
    { { 0x6aa74055ed74e633L,0xc44e740f7d06ce02L,0x8b40bc5ea33b8d5eL,
        0x42d3539f20f00f14L },
      { 0xd9f1f5cd3307ef15L,0xa9fe4dfbc8599bccL,0x31cb6703efa80b8dL,
        0x4172b46d53bb73feL } },
    /* 30 << 182 */
    { { 0x85a7028020e4c321L,0x999a0d075ac075f3L,0x59a62b627bdb478cL,
        0x9aeb710a573c403bL },
      { 0x1c099614950bb8fcL,0xc1efafab5dc09741L,0x0de58ca57296a74bL,
        0x657116a4f5be2ec4L } },
    /* 31 << 182 */
    { { 0x0ce52f0fcb199b77L,0xdcdc5cb9bcd11438L,0x587a68ff4777327bL,
        0x55d9abb71cc6fbb3L },
      { 0xf1970b829eeb28a9L,0xe1ab4e144ceef00fL,0x184d3fb6f7462893L,
        0x9942a008c8ea54fdL } },
    /* 32 << 182 */
    { { 0x1fee0f771e33b2a3L,0xd4bed81f9f789870L,0x6396feea6ef05b7eL,
        0x9c5d6a012640b62aL },
      { 0x170cfec96834bea4L,0x68d16728e131fecaL,0x4be9c5d600affb4dL,
        0xe34a423c99a6f256L } },
    /* 33 << 182 */
    { { 0x1a254e4a09b9ed61L,0x902bc06630b10207L,0xd2d5ed0162121f53L,
        0x0ba8681130f1b518L },
      { 0x7916c132abe139c9L,0xb3a30fe062c4f337L,0x85d0a769aa5693beL,
        0x2d414379e3c7687bL } },
    /* 34 << 182 */
    { { 0x92b0cb3c94958719L,0xb78aa37b4ec6575dL,0xd035aae14f1bf26aL,
        0x1383992dd31d5108L },
      { 0x53ecc53592bdd6f5L,0xa9925ff608c622caL,0xcaa3146e916d890cL,
        0x8cd0f12eb9c10220L } },
    /* 35 << 182 */
    { { 0xcb6ad82b7e12a730L,0x3f89047cac9485dbL,0x6f926117fea2d970L,
        0x87b0cd9d46a19ecbL },
      { 0x98bb5b0201e45bf6L,0xfc8146202ed7716dL,0x8d6808cf4f5caa95L,
        0x3b57df03082f799eL } },
    /* 36 << 182 */
    { { 0x469e18542df84ca2L,0x00dd62eb64aac069L,0x7d3ee9ce88d9efffL,
        0x9faed6a2bb830ffcL },
      { 0xd073aac1d2d74f58L,0xf69e96b42d44199eL,0x6cb3a3b183ed62caL,
        0x472489fdd799acf8L } },
    /* 37 << 182 */
    { { 0x5f84382db63a36ccL,0x6ba1de8792d5b175L,0x25aab130516101b7L,
        0x6f69c3fc5f039793L },
      { 0xd28439ee89e3da4fL,0x8cb40a0e5e6b2b61L,0xdfa55805e3d6650dL,
        0x2651f6c70be59fd2L } },
    /* 38 << 182 */
    { { 0x290e0044140d01c8L,0x78afa0a462ea488fL,0xc4e3997191eaa932L,
        0x8a9ef3a2fe2e79dcL },
      { 0xdcfae31550705b7eL,0x73324dcad4be3d75L,0x900bdd4303a91415L,
        0xc3ed02ededfdc74dL } },
    /* 39 << 182 */
    { { 0x509bd1d6f22b4a66L,0xfd8ed371b78d264bL,0x562b2d3aa419134fL,
        0x80a2c2747a57a51eL },
      { 0xebba53178c662472L,0xebafedf2a0be71fbL,0x0c5b9c1cb77899c8L,
        0x82448008c4888cb5L } },
    /* 40 << 182 */
    { { 0xb795ea0078401c3bL,0x86776990a85ab971L,0xdd81393b185739daL,
        0x76d0031f58136c97L },
      { 0x6aceaa56641d39d1L,0x918844c739be7ca8L,0xa63993f7e18efc54L,
        0xb53691504af0f30aL } },
    /* 41 << 182 */
    { { 0x9bc2068c3d04af4fL,0xf309dff9a7796ed2L,0x46e9a59d4e15b6a2L,
        0x617aaebac22ef488L },
      { 0xd91a8f90a15cf0cbL,0xc6ce12a4c30fb779L,0xf3b80254b9d0a7ffL,
        0x32a63bf96e9b6fa1L } },
    /* 42 << 182 */
    { { 0x3e1ac837546fe4a8L,0x91ed89a51279c7efL,0x8eb7b88ec73e9deaL,
        0x96d0720518238af0L },
      { 0x56ebf306e96abf80L,0x5088ce2452c4b10fL,0x65293176c979137fL,
        0x824642fb228d300aL } },
    /* 43 << 182 */
    { { 0x968963a87836aea5L,0x2d4c556cfabbfac1L,0xa4c389bbd3f9977aL,
        0x2e8b281899b4ccb6L },
      { 0xc1fd85656cb67df6L,0x0ac57d2aa72d2be8L,0xa51ce6b8b8224eadL,
        0x33f7b468f417d744L } },
    /* 44 << 182 */
    { { 0xcf8c80aff9f0bdf4L,0x0728f880d3222dd6L,0x436188a3653afc12L,
        0x0f8bf1603c7940bbL },
      { 0xdc18c13f424dcd2aL,0x038c184220d3cd1fL,0xed7f86a57b12fd42L,
        0xa75ab77b7aaf1881L } },
    /* 45 << 182 */
    { { 0x5c3d7612df0574e2L,0x2eeeeb6f719414ceL,0x797c577190349fc4L,
        0x0d850f732232eb33L },
      { 0x0a0744f32638c051L,0x739e6278b6e7dbfaL,0xa77f286d659fc5f5L,
        0xb18b7cf19654b0ebL } },
    /* 46 << 182 */
    { { 0x5a2089ac6062e78eL,0x152f1804dfa6fb44L,0xe8a404b4b61e6faaL,
        0x4774d30f08d06ea8L },
      { 0xd7119b913c359648L,0x850b02bd09473ff7L,0x4db6f9a0936b7868L,
        0x84064dd5ae38c3c5L } },
    /* 47 << 182 */
    { { 0x294d6831fe448461L,0xc3c6f44642cd2105L,0xa4412eb03a2fdcaeL,
        0x394c37743d5a9181L },
      { 0x58f190245ca87c4bL,0xba1879db89ad5685L,0x43c55c6a803c2589L,
        0xae1fad20a8249c65L } },
    /* 48 << 182 */
    { { 0x4929e89fe0aff809L,0x19755ec21769a00aL,0x3b6a207bc242f335L,
        0xeca054ef090edab0L },
      { 0x217e9c8bcd9e1c26L,0x917c2ecd35d4ac57L,0xdc869d5dad33911dL,
        0x22d9d8602e828bd7L } },
    /* 49 << 182 */
    { { 0x89262252f38dfaa1L,0x155c96ceeb9cd8d7L,0xb0082b5ded5ebcc4L,
        0x7b6f920317182086L },
      { 0xaefe28aaee92aa6dL,0xbe67090c9aaaa0ebL,0x88c5fbf12f8ef18dL,
        0xbdc8bef1dd1fd65fL } },
    /* 50 << 182 */
    { { 0xfb7052f5a9c7b483L,0x49634258bd6c8a99L,0x1410a747c9f424f8L,
        0xfda0a304e9805723L },
      { 0x1a438bd30879bd30L,0xed09a9d37f6903cbL,0x920878f857e53497L,
        0x87a12968a7fca0edL } },
    /* 51 << 182 */
    { { 0x7c8207cb38590ca1L,0x4cf52db1fae885c2L,0x6cf384c4e8dc711fL,
        0x6fea20ff221dc698L },
      { 0x6af56700a07bb79fL,0xc7da3b5233ca79c6L,0x3a214691d05eb519L,
        0xea94c4f193d4f089L } },
    /* 52 << 182 */
    { { 0x734039d0ba51f002L,0xc45e2042ce206406L,0xc0e75dbb4b3c3d53L,
        0x3a70127255b1b97cL },
      { 0xec856e95d6addb6cL,0xb63fe8c6f283aae1L,0x148fb239405788d1L,
        0x42e7148be0181912L } },
    /* 53 << 182 */
    { { 0x00bddcdd7de07978L,0xac79b6573c2e0a27L,0x94024ba6df1dd3ddL,
        0xcddeb3570bac41adL },
      { 0x51ec3dd7500c4f4bL,0xf00d594fd31c8fbeL,0x6b8c6f43373a3e93L,
        0x891ba3a5fc2b6be9L } },
    /* 54 << 182 */
    { { 0x3928225addd72e36L,0x1e6a63bfcee362c1L,0x317b78f4c5eb404cL,
        0xb882736b67c5e6b3L },
      { 0xb1da56ce1f2f07aaL,0xab3c4fbeff83b633L,0x9cc32f1c0ceeab99L,
        0xf1dead0d1062070eL } },
    /* 55 << 182 */
    { { 0x49ea0d9b8a3e79c4L,0x4e7abe3fec9f16d1L,0x19bda1c65549ade0L,
        0xaae756a5e5885734L },
      { 0xb3cff8cecc2a1aafL,0x812eebfff896ca47L,0x0951b2bb9b2e1123L,
        0x7f245699def6d6a9L } },
    /* 56 << 182 */
    { { 0xa1331e951be7ef41L,0xd1f0c3c39fa1be62L,0xb1d8295e4383e451L,
        0x658d8a849f08bc14L },
      { 0xb0587aef3ba4b85bL,0xb519c587481cbb27L,0x2b975db6040d8f06L,
        0x399f64171691d809L } },
    /* 57 << 182 */
    { { 0x207a0e467c6204fbL,0xe30f142062c3e9d7L,0x6127b782792f8208L,
        0x38f806abb0d3fca9L },
      { 0x382485422ff46c64L,0xc18ffe85926ec166L,0xfd268866c0c133faL,
        0xb7f63f5ab93770e6L } },
    /* 58 << 182 */
    { { 0xd8f1db26b13afb71L,0x5c5627eb32a790deL,0x7f41bc1ddf50b6f8L,
        0x49d4ef1792d4c803L },
      { 0x577f909fe8530065L,0x482cdedee630ff2dL,0x682c8c6a14f54de8L,
        0xe6b5a504b4079343L } },
    /* 59 << 182 */
    { { 0x00d927fce58bde6bL,0x65d85f03f34841f4L,0x265aec022ac001d8L,
        0x1b7856662dfe518dL },
      { 0x76142488c01e6e47L,0x8e8b2044dd5648dcL,0x2c422006b3a340b3L,
        0xa53921133dd67b22L } },
    /* 60 << 182 */
    { { 0xbd08d05ba1567aaaL,0x84a55e4302acbec6L,0x744ffd215d898af0L,
        0x380676226682e78aL },
      { 0xf3696ff2ffd08522L,0x49dd00602bf02466L,0xc9e0d1a559c3e65dL,
        0x29537f560a37fc25L } },
    /* 61 << 182 */
    { { 0x6f6cb9eba5f6b17aL,0xc18543209c55857eL,0x959585c645dacc6eL,
        0xf4e97c94e5f4e930L },
      { 0x966deb5f57d2a492L,0x9825683155d2df12L,0xfdd65534aa457ecaL,
        0x76dbb02103551474L } },
    /* 62 << 182 */
    { { 0x0aeefee909d9b4aaL,0x30fea11a784ca675L,0x56b4b509ff1d381aL,
        0xd1b26fea9fce40daL },
      { 0x4835b91148d22911L,0x6aaac57a8bbe57e8L,0xc888279219d02037L,
        0x301e0aa63ee49afaL } },
    /* 63 << 182 */
    { { 0x1641ce6b00e6b020L,0x846b97deeac7cad8L,0x9b74bfd861aa6886L,
        0xdd95e765b0fa37acL },
      { 0xda0cde52f848a83bL,0xd2cc831d355b3528L,0xc7fd2e035e22238fL,
        0x6d5373faab9a6c34L } },
    /* 64 << 182 */
    { { 0x5dfc2874d8247f13L,0xc211a7a1e3c11f56L,0x7512563fa2503b97L,
        0x124cd9845c007c82L },
      { 0x4f6eb682491cd249L,0xaf4f70a3a683359dL,0x2f1dfe71cc302b62L,
        0x83c474bbe57fbf56L } },
    /* 0 << 189 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 189 */
    { { 0x43af7ab7916a8016L,0xf93d487f532bfb9cL,0xa5f9af3ce2174971L,
        0xd1b9cf1f2d59b4d4L },
      { 0x4a77941844f4eb91L,0x6a131facc226edc5L,0x472ab89780d4bb33L,
        0xb69687a52f6ca1feL } },
    /* 2 << 189 */
    { { 0xffa73ca2fabd066aL,0x494e03a8f9c78bfdL,0xe585a878ff55cfefL,
        0x00770b1fd7053784L },
      { 0xdec4da4a056fe70bL,0xe37395d857bd444fL,0x666250d4685df668L,
        0x0549569ebe6cc583L } },
    /* 3 << 189 */
    { { 0x87629830ab11639eL,0x869dd3baa4488d53L,0x10fe1c0bbaf06eb6L,
        0x990348391687ac37L },
      { 0x384183777f1ffe7bL,0x3334a74c25bd7c57L,0xc57cb7ed7008ba67L,
        0x384c12d0c1e4e12dL } },
    /* 4 << 189 */
    { { 0xf48cdca6db4bdb35L,0x6bc23aec74d913a7L,0x8f0ccd9d12ed94d5L,
        0xe4aabd1286db09e7L },
      { 0x0cbff31a1e948326L,0xcf68c47c17a479a2L,0x3cced8e2ca7686f1L,
        0x15ed1e994eb62669L } },
    /* 5 << 189 */
    { { 0xc373ab4bbdb0c561L,0x150820226a9066a7L,0x330a60c362d31801L,
        0x53d97f09e35bea57L },
      { 0xf204e0069c5dbb92L,0xfb9a8219f831262aL,0x3468ae4142136174L,
        0x0f8fb5bc0e03218eL } },
    /* 6 << 189 */
    { { 0x903374994ad8bba6L,0xdb71e1fbe3ecb618L,0x6955e8743cf2a8adL,
        0x594501f5ed691feeL },
      { 0x7e2baef3d29bd364L,0x5cbd91ac6f766759L,0xaba54aaab2201a96L,
        0x2cfea457cfa392abL } },
    /* 7 << 189 */
    { { 0xa4da416286f8f7daL,0x88d70b86cbc0b934L,0x9df02795acff4f7bL,
        0x0fc80219c65ef81bL },
      { 0x32d457dea299ca0fL,0x97081b350896427bL,0x92d6c30941bab6b4L,
        0x5d5e56f373b8d601L } },
    /* 8 << 189 */
    { { 0xfb3992a4202bde39L,0x2549f5643d6bab98L,0x0b56464287712512L,
        0xd52442b47fde7e50L },
      { 0xa6cefd08a3d3e16eL,0x5b194f0ac83b29bdL,0x6db0edd8906dec8cL,
        0x7a09095902570c1eL } },
    /* 9 << 189 */
    { { 0xf6f74fcc4c41eb53L,0xd07678a95b944a6cL,0xf53bf11db80677eaL,
        0x569a5761bc5900f8L },
      { 0x34e5bba8d3d4de91L,0xc57748048361f73eL,0xd637d3dd59abdbd5L,
        0x64a81bf98772b615L } },
    /* 10 << 189 */
    { { 0x78bb12ea7f3d83abL,0xca22c31c573f9b99L,0x4283c1732aed4c39L,
        0xda054c1d39f32bdbL },
      { 0x2ead717e1da2cbd7L,0x747d67cd62390b41L,0x43739d9c6b9666a6L,
        0xb84e2f228c827b12L } },
    /* 11 << 189 */
    { { 0x0e4ac2b1c0312773L,0x571cfc75e53f068eL,0x6c44df8542bfe41eL,
        0xe7d2edb9627e30bbL },
      { 0x9c2e4fd60dd5cedcL,0xe2d885ef0f7d22d7L,0x44b0b5db1329bcfdL,
        0x006e872fba1c96f6L } },
    /* 12 << 189 */
    { { 0xdbadab5d7e952317L,0xab849ed4c2a5bcaaL,0xe3acbb741e72dbb1L,
        0xbf42c3d35d4b7cb7L },
      { 0xebe967b53d748639L,0x1fe93db5c03af7a1L,0x2ab14596a944ea06L,
        0xfb05a75976655c09L } },
    /* 13 << 189 */
    { { 0x5117890c6f8a532bL,0x2f57781f59430c5bL,0xe70968b379e07b84L,
        0x05df2305e86d7223L },
      { 0x57af0dc531e32933L,0x5473e34a84afc419L,0xa7337a4203d5feb4L,
        0xd85c86021b1c6bd8L } },
    /* 14 << 189 */
    { { 0x25ca1891753008e6L,0x4338ec985f0ff93aL,0xd2ba8557ddd30a7cL,
        0xb4b6536109c51794L },
      { 0xfbb51399d1cbc66eL,0x28853781e53bca50L,0x5b797232fd5a9aaaL,
        0x6249afd75b88c4f3L } },
    /* 15 << 189 */
    { { 0xcc5ab6cbba6918a0L,0x9f824ec18fb65c7dL,0x4796d80b56b18754L,
        0x4c83d37167721520L },
      { 0xd77c373c63b03348L,0x91930e5e54f27457L,0x83f97370af40c03fL,
        0x65b5587234eea661L } },
    /* 16 << 189 */
    { { 0x310695d0eb10175eL,0x79aaa6eacd236aa1L,0xf78539ff3edfff40L,
        0x2369c51702cd6063L },
      { 0x81e43ae55c8631ffL,0x065e8212216a60bdL,0x225cb473e761a5f9L,
        0x695ef860ab6de6faL } },
    /* 17 << 189 */
    { { 0x03536a467d7d98d4L,0xa17d3a6918413673L,0xa6ddcd46295ae303L,
        0x86de0bbd61beae2bL },
      { 0xdd73dfcc7699458eL,0x827deba5b53f88ddL,0x213c376b42a9a11cL,
        0xc854fd7212c73975L } },
    /* 18 << 189 */
    { { 0x1fa9654715ac27ffL,0xcb0dc17bf49b6c9aL,0xa3e44853709dd202L,
        0xd3905c5fcfe2bbeaL },
      { 0xb01e57996c35ce9cL,0x0063e7ac900ef600L,0x8c70b87efffa5cc0L,
        0xebd76d3474230b0cL } },
    /* 19 << 189 */
    { { 0x914eec9eed5f8529L,0x7a65ffd3e8edf477L,0xf0cb206d70c74beeL,
        0x03445ff1d1b02e01L },
      { 0x664ca356e5dbf791L,0xd678d4ae254e69c4L,0x370c9f0f8617386bL,
        0x42af7a0cfdcd985dL } },
    /* 20 << 189 */
    { { 0x8c4b500983c3da54L,0x086a7ec54c8a87c8L,0x9ba0b368aa166c4cL,
        0xa279670fa658ac1cL },
      { 0xc49f49bd5d0544daL,0x28c2232315cb0b41L,0x86293dfaa4834d71L,
        0x283e191dd1e1d63bL } },
    /* 21 << 189 */
    { { 0x0cad6519ca188555L,0x323ce5da0cbd0c5cL,0x6b7d2be138560254L,
        0xb05ed3851696b9b9L },
      { 0x8ce4b5a79ae59f92L,0xabe5ff334f7e61a3L,0xae15a3ccdbfeb302L,
        0x691b1129837fde82L } },
    /* 22 << 189 */
    { { 0xb60b31f32e6d116bL,0xd49e9d11ecab5aa9L,0x3e95f8446787f23dL,
        0x2ab8834fa12f4846L },
      { 0xe70e2ab15b6359ccL,0x7a6349e99322a047L,0xc01e424c6c1e483aL,
        0x424b202792bd5d1bL } },
    /* 23 << 189 */
    { { 0x8a6e6766254e49a3L,0xb8d85d4297e70d58L,0xa859082fb51b3abcL,
        0x2850573be7bb828aL },
      { 0x47cc95b27bfe8021L,0x7c28fe9e5853f12cL,0xe5fb055810c0f389L,
        0xb99a639fdaf0a7e7L } },
    /* 24 << 189 */
    { { 0xa6b9e6c9f60ee3e5L,0xb397af7fa236377fL,0xb7a318ac7da4af71L,
        0xae64b6130a9d39fbL },
      { 0x66ce6c74902b3411L,0xea256a705a199e53L,0x8dcddd89550fb76fL,
        0x9443b47703e70f9cL } },
    /* 25 << 189 */
    { { 0x1787b8a5142113a6L,0xa58b6c61180aec95L,0xcc381420947ff26dL,
        0x22520e8f3d8b8c36L },
      { 0x192ee945ef2cc6efL,0xea52afeee9ca0c7aL,0x5970d794e6e30d93L,
        0x0a325e4257c786acL } },
    /* 26 << 189 */
    { { 0x5e2dddf833ca1226L,0x18e624b9588cb1e3L,0xf3ba597a21809265L,
        0x902477025d575728L },
      { 0x48a5bf7bc1f918dbL,0x17d1efafd6840541L,0x13dfe6fe3e2e754dL,
        0xc471e16a707a531fL } },
    /* 27 << 189 */
    { { 0x79085bbd97d34b48L,0xfa5ba99dc2e9bea9L,0x70b9c9fc6c5a6dc2L,
        0x4e0422134e94c5dbL },
      { 0x4a37b41f25ebb95fL,0x24691010055d79fbL,0xdaff93523f572a8fL,
        0xe63d55b0f327ec2aL } },
    /* 28 << 189 */
    { { 0xc5a86d3cdebd5116L,0xd547fe08a2ddef2aL,0xbabb617f6a149f12L,
        0x14f69a1b8a766128L },
      { 0xb83a147748236f77L,0xd0d81be135711279L,0x706f90675eab1c3aL,
        0x8c4823f116a1ffafL } },
    /* 29 << 189 */
    { { 0xd845c68baff5ea89L,0xa276eaeb6b75eadbL,0x2d0fc819cc230ec1L,
        0xdfad96e8edaaf1f2L },
      { 0x0f25dcbf40868254L,0x53bbe31e5babd7f9L,0x7f8afc48cf804a8dL,
        0x7f4922ef5f9b9a0dL } },
    /* 30 << 189 */
    { { 0x703cbf6dd7422804L,0xe5df61f383349bddL,0x0fa3d8cd77d285adL,
        0xe990f9e52e88e15eL },
      { 0x40ec61f78561d8a6L,0x7fc498a616650305L,0xa3bf5cb48e5beabfL,
        0xfaa5200876ae0350L } },
    /* 31 << 189 */
    { { 0x99e24318e4fc3e72L,0x9241c8ab2079c616L,0xefa5bf389584a258L,
        0xd7b770b51eebb098L },
      { 0x28b714a3e1fc18a7L,0xf0426bd25b83dd9aL,0x956d8972291b28eeL,
        0x8bb8cbde6eb553ffL } },
    /* 32 << 189 */
    { { 0x396cfe2d95298003L,0xcaa66550ad8412fcL,0xf41d021583997dd3L,
        0x7066e35645534587L },
      { 0x0d5b5c3e5b6de0d7L,0x8ead45d0cecd5f26L,0xe2f24e2cd252ae50L,
        0xf71e5d4f815150bfL } },
    /* 33 << 189 */
    { { 0x3872685d54527ce5L,0x59b343ae91fd99eeL,0xd621d0273462cc0cL,
        0xfa42481f8dbfbcf4L },
      { 0xda481a9eaf7ae918L,0xfd5fd37c7c909a18L,0xa5ebb7bf805fb7b7L,
        0xeac65687165200b1L } },
    /* 34 << 189 */
    { { 0x563028667cef9b97L,0x8f662dd6ae3ddb64L,0x90cb4e8760c1aa98L,
        0x33f9fc60986fb3bcL },
      { 0x76f41ecc974593cdL,0xb19501f96e0f01e8L,0x587d903525760dd5L,
        0xa31c971c9391032eL } },
    /* 35 << 189 */
    { { 0x7650e3b195c9a84fL,0xbb83ea9378c66087L,0xda08a04cdfcf1365L,
        0xd23daebaca0b84a4L },
      { 0xf89d395d2ca3bd2bL,0x779e2aaf6e53fc93L,0xc0fc7dc834216082L,
        0x6cd8bdf642a66691L } },
    /* 36 << 189 */
    { { 0x836a2cf30fe014cfL,0xdde5fc220c08373dL,0xc4fa2387cb3b2b54L,
        0x96253732e2aa434aL },
      { 0x4c4f59791d502ce8L,0xf046f5a9b6df40c4L,0xc7d05765ac6b75b5L,
        0xae1cd887b69f3c34L } },
    /* 37 << 189 */
    { { 0xafed4be649b86680L,0x17b75fa514f70463L,0xb12e805190b7c07fL,
        0xe2c8cf2b39a8e99dL },
      { 0x984744c4d5fdb65bL,0xd8b1c012a28942e4L,0x295d019946693fb2L,
        0x5ab3a305a0a3b4faL } },
    /* 38 << 189 */
    { { 0x3c19102326755b3fL,0x75f35df1b6c084deL,0x30640e6663e6286bL,
        0x3b3720ecd2c6c059L },
      { 0x2c821a0f6ea837beL,0x238c4d9384f23bd0L,0xbdc40703390ea4f5L,
        0xcb207d0aae68a2dbL } },
    /* 39 << 189 */
    { { 0x487d18bde25f098fL,0x390180239ab84e10L,0xaa19aa628b7ab4a2L,
        0xcb9cdebe89f08fbdL },
      { 0x26a4c9eb2ca57917L,0xaadfd472da92ce1bL,0x32b592d8daa907dbL,
        0x9bbebacc7d6f995eL } },
    /* 40 << 189 */
    { { 0xa27a4735e1d88c25L,0x339905e19bd66b67L,0xa9bfa0ed62af9942L,
        0xd94dd9e02e2cb83cL },
      { 0x279d8fdaab28e268L,0xf28ab69b51a97518L,0xce9bd2ea9691f33eL,
        0xb9e8b2fe74be3d64L } },
    /* 41 << 189 */
    { { 0x35072fababefa07dL,0x1c2ba05c7b51ba8eL,0x3bb1ec56d32d6bf5L,
        0x326bdfdc5d7bd7dcL },
      { 0x33f4f4f6d95bdcb1L,0x781bfd34453ef338L,0x4d210cad1ef61a66L,
        0x6ae7bb142799bcc7L } },
    /* 42 << 189 */
    { { 0xb105e5ec194f4d6aL,0x204a548052b77f08L,0x13f4e022a328ab98L,
        0xa56863c4b7f9a240L },
      { 0x2780c9a7ce4cf7bdL,0xf98e3f58c497fdf3L,0x635b8bc6f52738fcL,
        0xc5fd89b858937500L } },
    /* 43 << 189 */
    { { 0x5707042875e98a64L,0x66aabaae946f094bL,0x7d2376e806d37944L,
        0x9b31682709319f13L },
      { 0xbbde59a8a77eb79bL,0xb7f35bbbf451fde0L,0xb2f7914e64aa79fdL,
        0x4d2944b39f68a486L } },
    /* 44 << 189 */
    { { 0xbd8a92dec1a7e537L,0x76695e9a4fc930a3L,0x1b75f9ebbcb4153bL,
        0xf5a34d2df6485404L },
      { 0xe09ee96526853a8eL,0x63de85959dbb319aL,0xbbbc1b07da079d6dL,
        0x5956bb3ddfa71b9dL } },
    /* 45 << 189 */
    { { 0x69709306209cbcc3L,0xbe2a08d0e3360429L,0xd377a9fe92a58752L,
        0x37e175ea997bc322L },
      { 0xfe355d4d042ff2e4L,0x4332ef314c4babd3L,0x634429c22314b1afL,
        0xae6e827591a7d5e5L } },
    /* 46 << 189 */
    { { 0x134a39c7250a1476L,0xec9bb64208994f0cL,0x2a9e0ac0d38704cdL,
        0x16490507536a4ad0L },
      { 0xc7f747d27c8dbfebL,0x91e67dd2c0bb24acL,0x2dfc6c8a959eca45L,
        0x78bafaf0c54fefe8L } },
    /* 47 << 189 */
    { { 0xf3eb2d1b5da056f3L,0xda14b6313b89c967L,0x80923b1ccb51f621L,
        0xc3d5fd1f6609791cL },
      { 0x68ad7bef817b1063L,0x3775b686a1f0b00cL,0xb207c9a56c7f0dc1L,
        0xb7c30a7da9b91fffL } },
    /* 48 << 189 */
    { { 0x9274c0908b9f8e8cL,0xa375761024e94ce1L,0x8f2b1f2c4f0f3ec1L,
        0x02e53bb23938d26fL },
      { 0x90a3da2c701e5ae8L,0x60c2eacaa271dccaL,0xc9c08e3931fb2372L,
        0xcaa3245eb838908aL } },
    /* 49 << 189 */
    { { 0x2e168b0ba6a6a275L,0x986a30a30030ef6bL,0x79f768f9170ab683L,
        0x7296fd6fff70981eL },
      { 0xbab6fedf13a323cdL,0xa86ec0dd186e9813L,0xd9f8db04cd56e7d5L,
        0x47b20676aa8b1c96L } },
    /* 50 << 189 */
    { { 0xdff4574ef1fb3b03L,0x41a1f7651051f9fcL,0x35779aee7f289a4eL,
        0x93bd54c911c96180L },
      { 0x1485074a37b95c67L,0x0b01af950865b2f0L,0x43033ffe90ce0b41L,
        0xffd6e34c71504d6fL } },
    /* 51 << 189 */
    { { 0xb380cd601aa946c8L,0x7f7cc73b806b2e19L,0xc17df7d82db88e6dL,
        0x7b767ca2072e5416L },
      { 0xbb42d3ed0ad6134bL,0x5444339f640df8afL,0x7e7c7e7b5bc73112L,
        0xe8f139b4f899dba4L } },
    /* 52 << 189 */
    { { 0xd13b436d43a06bf3L,0xe43f8567773e4863L,0x35555cd556b814d7L,
        0x54af8e53d429ccc8L },
      { 0xc346718f82ae0477L,0x301fb382be02c7a8L,0xcd65b3b2d2a70595L,
        0xcfcff4995aad01d6L } },
    /* 53 << 189 */
    { { 0xd0fcc076589feca8L,0x7b2b93c77c603ed8L,0x2dda7a8c6ddfc3b8L,
        0x678d66e974723d99L },
      { 0x0f7e42156db60b07L,0x40666848c0bfa2f9L,0x70b46b5c8e116cafL,
        0xbd753511fba46d90L } },
    /* 54 << 189 */
    { { 0xe48374cd019d8279L,0x7d40e6e2309b0fc6L,0x226435ee9dec7a42L,
        0x818e79cb4243e7d0L },
      { 0x3d7376d754658634L,0xa40cafeb9f8727acL,0xdc1d09f081f556bcL,
        0x32ca736763223573L } },
    /* 55 << 189 */
    { { 0x92e10f915810a27dL,0x6fb34bad1fdf969fL,0xe5c2b2ff657a067eL,
        0x173c0900382ba37aL },
      { 0xdd5113c886d87c1eL,0x56a2ca9dcaf77294L,0x9f956881666a9821L,
        0xc4bcafc7a3b18c0fL } },
    /* 56 << 189 */
    { { 0xb100f3382b02578bL,0x4716339e64b2c607L,0x92c923ae5b161179L,
        0xada2e4da0df442a0L },
      { 0x4d4b90c547f85474L,0xa378bf79824e3195L,0x4469339d2478a0d4L,
        0x0972e7880c1e69e2L } },
    /* 57 << 189 */
    { { 0x1aedd76172edc384L,0xcabcd9769898d672L,0xd370aa7aba814ca2L,
        0x20fa58dbe88eca9cL },
      { 0x1540ada945a7ab8dL,0x8dcf9860bdca94fcL,0xf0187e2caa9df4f4L,
        0x9a197dc354a49576L } },
    /* 58 << 189 */
    { { 0xb54f5cb2b4a1f341L,0x1439caf0fe32827bL,0x3c1a356dd36783f5L,
        0x284e2f15c56a6e47L },
      { 0xc6abad594dcfaddfL,0xe82993f7082bb2b4L,0x3cb4697223655955L,
        0x8ab06385992551e3L } },
    /* 59 << 189 */
    { { 0xcbd6cb99daa13ab3L,0x01375bbd2dc1333dL,0x638a7f20972c4440L,
        0x150665c624dcb1ccL },
      { 0x4044e12f1ea989c6L,0x204c4eba61012ea3L,0x78b8edaaac2719c1L,
        0x6772643d2ab50d99L } },
    /* 60 << 189 */
    { { 0x94604146606d63deL,0xa876d9b0693aadc8L,0xf7401ffb667044ffL,
        0xab98d73eb599ecb4L },
      { 0xe2b2048fda5cbee3L,0x526e3aa1a2b3da50L,0x4d0885e3b4ad2073L,
        0x916ce3d2644a1a19L } },
    /* 61 << 189 */
    { { 0x952b574796930e8dL,0x2a489fd6b0cf7f5fL,0xbff4b59ba8b3b538L,
        0xba0e03ff6aff1cbeL },
      { 0xfa614adcd56b2285L,0x2305edd450d58e62L,0xb349fdcee36877e9L,
        0x5f808fc243a6103bL } },
    /* 62 << 189 */
    { { 0x66d8404b86493abeL,0x18c92d3d9b08ff7dL,0x6a60ab6b89754762L,
        0xec69fd4c8233dee7L },
      { 0x3244924206beadfaL,0x421caf1ee0df7084L,0x6f89693bd7969339L,
        0xb9a53713fa30a7a9L } },
    /* 63 << 189 */
    { { 0xf89d9bf511556d9aL,0xe4e9c5f0ee8cf993L,0xe5b2a32317ed9a7eL,
        0xd4db392093e80c9eL },
      { 0xae8578641fda3726L,0xe5cb36a3a3e88485L,0xa6b85205f495b9a8L,
        0xc1be010838f3b180L } },
    /* 64 << 189 */
    { { 0x79d0585b36a1f3a8L,0xa3d8f17f913ba5f2L,0x1eaee5d6225acf11L,
        0xd4dfd0a20d32de79L },
      { 0x0cec324b6b3ceff3L,0x3acc6decab447870L,0xabbf7e6db9c759acL,
        0x0d5c1f47a5196938L } },
    /* 0 << 196 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 196 */
    { { 0x781a215745e7ea91L,0x4da3f86dacadfc40L,0xc81d6c7d162cd393L,
        0x2c38a2a1ad6e60fcL },
      { 0x575b25d6f753479dL,0xc914e08ebdec6025L,0xf81cea34492d5547L,
        0x6bbb8bb1fb1b6969L } },
    /* 2 << 196 */
    { { 0x1ee8082c1279504cL,0xa466abb22c92ffb7L,0x4118b26a3e81c7e2L,
        0x1a76cc50fc60e33aL },
      { 0x34998bc25736d7aeL,0x20b39558bd1ef993L,0xd669e2ae5fbf2525L,
        0xbf956ec601cc7626L } },
    /* 3 << 196 */
    { { 0xce817029b0ccbaa5L,0x57ef5bd2279b78a6L,0xc92837474df45d89L,
        0xe86b91a82ec4bfd3L },
      { 0xe5ab4c6dfe565915L,0xe65747167c58a042L,0xe141deda6301c4bcL,
        0x2f95d5618084513aL } },
    /* 4 << 196 */
    { { 0xdc424508eecede3dL,0x11889b35386440d0L,0x7b229f9398de0d77L,
        0x73fced8a300a7447L },
      { 0xf75e1c79e31c8f88L,0x8db20bddbb277e4fL,0x8ded0a702b87c02cL,
        0x166281b54d164c1aL } },
    /* 5 << 196 */
    { { 0x887356cfeedd8e0cL,0x8afab37fe44c012bL,0x0795935fe4aa3eb6L,
        0x9b9efc0cda6dfa57L },
      { 0x0ff0f8aaa8ab0840L,0x0f3a4b63c8561605L,0x2ca911efd5db9315L,
        0xef70e5bac8ded9f8L } },
    /* 6 << 196 */
    { { 0x443d9209a6aae58bL,0x3d0798e8274edda3L,0x5c2d462cc2be3c9aL,
        0xb5488239439882dcL },
      { 0x6391bb41977d4de4L,0x7fd910401e8245c4L,0x1a6d3c713b093dc2L,
        0x423a4e3a7b22fe12L } },
    /* 7 << 196 */
    { { 0xe3156f403a9a04a3L,0x9b32c4e5297d9affL,0x7e0b401e62a89850L,
        0xffbf542ea84ef082L },
      { 0x377cc0e0f990caf5L,0x02704343ec88ea9bL,0x846fd46c63f96a51L,
        0x37f5cebfe9855c47L } },
    /* 8 << 196 */
    { { 0xbd140bd8e6ad29dcL,0x7dca4b106a04da28L,0xa84feafcade05b33L,
        0x44d031f87630aacfL },
      { 0x18af2fa6cdee269cL,0x1e40571b8697a40bL,0xf71d44adf0e5f826L,
        0x2a47ddf9a434cfe6L } },
    /* 9 << 196 */
    { { 0x22b97078ad17cc54L,0x223732dcf2c105b2L,0x25168336e284fae8L,
        0x41b1bb94b356407bL },
      { 0x299e7d7a89933a11L,0x19e13d3cff7dd9f6L,0x9517bd16f23d7ca7L,
        0x9e5e9e341eb978a4L } },
    /* 10 << 196 */
    { { 0x4c222dae5fa3f92fL,0xd5e38e84ed489ca7L,0x3d81aca470ea613dL,
        0xc7bed301be4e88f6L },
      { 0x6fd5a7bf0757d8dbL,0x1472441d7a9181b0L,0x78b787535a90b66fL,
        0xe3fd5e91abdae620L } },
    /* 11 << 196 */
    { { 0xea6a77d884535653L,0x8d241deb81d7e667L,0x1af73798faf4ef1bL,
        0x5e1ae7283e0dae27L },
      { 0x6a67088c2f7450b5L,0x7bccbe06da9cb3c6L,0x520fabab5b808e05L,
        0x84222f68702b247bL } },
    /* 12 << 196 */
    { { 0x2471546ae0bd7ef2L,0x27d310dc656a62a3L,0xb8014ecaad35da30L,
        0xbdfdcd827f35cd7aL },
      { 0xf1e4d51f040ae645L,0x672ffadff42a4d9bL,0x9d8743702d0be1c0L,
        0xcc3671c6c6e55471L } },
    /* 13 << 196 */
    { { 0x39aa705cbb9c9667L,0x8c3e584ac51f661dL,0xe5645b1de570769cL,
        0x81923fdabc97abf4L },
      { 0x51d64f640caac97cL,0x45c17651ff847f4aL,0xc7a6eaf98cbfa2c7L,
        0x6c2ab9f7ba8ab893L } },
    /* 14 << 196 */
    { { 0xbdaa2c7bf435624eL,0xc113e9711d961058L,0xb230f1b0a2021a1cL,
        0x6b34e1ff521a4816L },
      { 0x159dc24d9b874f4dL,0xeaa0f951beaab169L,0x4f38733fb56f4916L,
        0x4ee689dbdc9d3ac7L } },
    /* 15 << 196 */
    { { 0x720254bb7bf8d03bL,0x78b0e6d6d31d7679L,0x848fb878f130d7b0L,
        0xe8e478ecd3ba625aL },
      { 0xb0ce9168100dfefbL,0xfe1463abe5098aa8L,0xf780ac38a11ec558L,
        0x92f15c528e474b9fL } },
    /* 16 << 196 */
    { { 0x3b3892d346410cb1L,0x72097f2203a5a136L,0xdb3a1b8098de068dL,
        0xfb7438e44b1a3890L },
      { 0x8a10d5ea3839d3d9L,0xd9ad034df4bd8126L,0x07d108efd4800261L,
        0x978d98ba9c5d6c52L } },
    /* 17 << 196 */
    { { 0x63ae69e1ecb9ce1cL,0x70d2b43751b28f39L,0xc15696b677f848a2L,
        0x6b6e60f4d8ab4d76L },
      { 0x33a581a4030bf112L,0x9cdb1a6ec5e74a76L,0x6c6f6ec47a950053L,
        0xd47dc472b04ebcffL } },
    /* 18 << 196 */
    { { 0xe85ca76a5e0970dfL,0x74448d9878988af2L,0x5227649b81620019L,
        0x47e2ac62aabc2027L },
      { 0xfea15155fbffedf2L,0xa565c4843b4cb501L,0x4c523be5d830ceceL,
        0x2e2de6bcc321a440L } },
    /* 19 << 196 */
    { { 0xa7d627718d69887dL,0xf9d8ac674e138de4L,0xad3fbc089fcb0a09L,
        0xcaabb0b0bfc3bc9aL },
      { 0x84646bc3b1c20604L,0xf1059ac4d1574260L,0x5c15c6a2eefff298L,
        0x7975ede6f3b0a393L } },
    /* 20 << 196 */
    { { 0x0ea9d35527c2343aL,0xe21c75e44b32e339L,0x1438785ea7fc353aL,
        0x0b8d64bae9a1dd56L },
      { 0xcacf9b6475347c02L,0xf788c83ecaad57aaL,0x90df1ab836ecf2e0L,
        0x4db604a3f45070acL } },
    /* 21 << 196 */
    { { 0xbc76e168b4c4ed93L,0x07177b5e85b65a6cL,0x41e3c27500d21309L,
        0xcc9678e476a48f42L },
      { 0x3a04d197b1c6256fL,0x940920a9b2cc7330L,0x990e4da82523d52fL,
        0x34709b245a59d733L } },
    /* 22 << 196 */
    { { 0x2f0da81c8e745028L,0x32b5f384cd5668abL,0x82744a5aee538e7eL,
        0x1b019babf3eb2516L },
      { 0xccbd28fbd79d735fL,0x0bb54a6e85f90aa2L,0xacf5552f9a69ecafL,
        0xbc51ee85d1f1e30bL } },
    /* 23 << 196 */
    { { 0x12bf8b0bfa25193dL,0x3f0f51b05ba4b3c8L,0xc1b65deb66181f23L,
        0xfeb037f9c0156b03L },
      { 0xdd7a0a8ca9dc59edL,0x20b5c8ea7b57e018L,0x0c3ebc94efaadad5L,
        0x146d05b618758ebaL } },
    /* 24 << 196 */
    { { 0xcb952e4109c7b43cL,0x7f7a0ae31c1b8fb6L,0xbca8a9cf331dfb05L,
        0x4a1db4a1e0db9d7dL },
      { 0x988d36a3e5b9c892L,0x64640e55010ad00eL,0x4c33c7e8c011bffdL,
        0x5d7cf370a0ad217bL } },
    /* 25 << 196 */
    { { 0xbaf8b74a71f3df52L,0x300963bca5995b20L,0x695cf7eed6c27636L,
        0x74d4d3a103ac244eL },
      { 0xddba3bd6c898e5bbL,0x27573a89fe3499f7L,0x666b44154b0a6c98L,
        0xf4f3e8c5aa4ccfaaL } },
    /* 26 << 196 */
    { { 0x5f1368751a5b919bL,0xed8eb5db670d4b04L,0x4cd83d190d0d73bfL,
        0xd2a5c62abdf22579L },
      { 0x8c41be16c2d04c2bL,0x5aa33bc4bf9ad465L,0x36e206465e00d922L,
        0x9df21e7c00b70e17L } },
    /* 27 << 196 */
    { { 0x0601e630d440af4dL,0x4aab0d33963e87dcL,0x2712abdb36d39000L,
        0x856d7e3bf9147e2aL },
      { 0xadc4a96ac8e5d2f4L,0xac3e53362e70c206L,0x1ee7d8386f6f3d0eL,
        0x4674ef20ead72426L } },
    /* 28 << 196 */
    { { 0x3a804dd86af5f580L,0x724a756bd74ea5ceL,0x0c2968d00432d854L,
        0xe3be03f3a4f262feL },
      { 0xe446692ac84c22bbL,0x156b31689647650dL,0x4e06bc39b5d3d62aL,
        0xf99d4fec80eea174L } },
    /* 29 << 196 */
    { { 0x3a2b7ae8c08f1144L,0x35e65bf912dae8d6L,0xfa0af1cfae3892b5L,
        0xa57062dcac408112L },
      { 0xef6a9ec324bf1af9L,0xdda3b4765decd8bcL,0x9314a36c7bed3775L,
        0x9e254b0e60aa296eL } },
    /* 30 << 196 */
    { { 0x8be2de8065b9cf2cL,0x1b110df6cb3b96cfL,0x0f647a1218957e21L,
        0xa1e112384f907766L },
      { 0x751a0d82c5528977L,0x958d87389a4b1260L,0x99087543773658eeL,
        0x18148bbef19f74cfL } },
    /* 31 << 196 */
    { { 0x5f50ef190a19a374L,0xc5bc41606bdd3392L,0x1bdf5e4bb80ad74cL,
        0xc40ec2f7ed7e68c8L },
      { 0xedd7dd6adecef5b8L,0x3d29a1cb896c95a3L,0xfa84c32570ad41d4L,
        0x6a577072c398c177L } },
    /* 32 << 196 */
    { { 0x4f942d017375f2deL,0x968a76088aa1523aL,0x55dc7da6377e5c4cL,
        0xb75fff53282b540eL },
      { 0xfee35c15fd4b6951L,0x6d1d64f6f04ddfaeL,0x320f1769af7c8714L,
        0x2b5f86a4482ba6fdL } },
    /* 33 << 196 */
    { { 0xcf691cb71ab9986bL,0x42913d717377ba6bL,0x120b46011e47bf08L,
        0xfb514e52764b2661L },
      { 0x371c0155a140ae04L,0x94e65b702e186763L,0x5e440f7bd5764306L,
        0x3411dadf7b8a5eebL } },
    /* 34 << 196 */
    { { 0x6c25e519f0e3e158L,0x46ee66d6e8898c80L,0xa0e9d4b1ec4f9b03L,
        0xba48d97c126c1f31L },
      { 0xb9f96818bdbf0928L,0x293ce87d7f51cb48L,0x077a742076f09d38L,
        0xc71cb875edea4c81L } },
    /* 35 << 196 */
    { { 0xfeda750d9ddd1485L,0x987876dc51c10504L,0x4d0253f875ec7922L,
        0xbcc15e39c676b336L },
      { 0x33d533d8b9370740L,0xc5c482dbcb8c88abL,0x1ff3f223c7c08a75L,
        0xccfaf564401b00fdL } },
    /* 36 << 196 */
    { { 0x6ba93d3a6ac9757cL,0xff09b546ec2c92a0L,0x95d3436cc5960be8L,
        0x90b7e8cb69029082L },
      { 0xbdd1e2b9db6b32e5L,0xf4d2e43bfd47ad85L,0x8923251ecb005dbeL,
        0xc21368a0662912e7L } },
    /* 37 << 196 */
    { { 0xc7ce2963062d205cL,0x1e8f812f9542b831L,0x4f8a7915818c322dL,
        0x50073cbafb678809L },
      { 0xed7b52370cb91b3eL,0x22d1fa4160d3fe6bL,0x3de390632d690f75L,
        0x12b2e39ef164ec1fL } },
    /* 38 << 196 */
    { { 0xa28a0d83332f408fL,0xe6d9406c6a054db1L,0x67369b765ddd64e0L,
        0x6d67170702b21c2dL },
      { 0xb9ad3368ac42170fL,0x5e8f5277e5802ffaL,0x1b4468fbd9b4a0a9L,
        0x0daf826996c24331L } },
    /* 39 << 196 */
    { { 0x976c2f23c09ad26dL,0xd47afe8819c68d38L,0x0e96c03bd3d8d84fL,
        0xe05b5fd80932b2feL },
      { 0x13931043347fbbbdL,0xe0fa842fb0ccc752L,0x7295ee0fc75bf745L,
        0xebaae0dcb0aa9d61L } },
    /* 40 << 196 */
    { { 0xb392d49b6355564cL,0x57e2f166887c5a18L,0x88b3a014230a278aL,
        0x088e49084c194449L },
      { 0xc6cd309f43d6af69L,0x394445e3589a7f7eL,0x0610077a031e7c08L,
        0xd05547cca3519f78L } },
    /* 41 << 196 */
    { { 0x0123b543926e26edL,0xcd430b8062d06da6L,0xddb182d00dcd6db5L,
        0x724c9bce8eb6e010L },
      { 0x985a2f0f50a4a597L,0x35f2427f900f2a49L,0xce6136fe13cbf187L,
        0xc893bdee1086c2aaL } },
    /* 42 << 196 */
    { { 0xe2410ccb07eca624L,0xeda92913ddf9afb0L,0x8fc0cfd05bb66033L,
        0x0ab7d29b0509ffc8L },
      { 0xc063b004b3d4f10aL,0xed94a955eb8cf642L,0xacfb2f14a272ac4dL,
        0x10f2c91ac4ebbf0bL } },
    /* 43 << 196 */
    { { 0x73f6e02e06ea04ebL,0xb969e8f88b97ea93L,0xa9b274720cd48657L,
        0xe1a874ec99264937L },
      { 0x34e677a4f794332dL,0x5e67865e5ee2daeaL,0x3fe02b91e6886879L,
        0xe113432f0f9776adL } },
    /* 44 << 196 */
    { { 0x375673066a2c47d1L,0xf66df9b862feb54aL,0xf734ee373e07ce56L,
        0x50c4982d659809fdL },
      { 0xe2fa768f9daf8faaL,0x66088ddc8b9fd7c3L,0xb8265661333683c6L,
        0xe7dacf81dff2a0a7L } },
    /* 45 << 196 */
    { { 0x1e99d6bd5e3da06cL,0xbd50e15cbae05a25L,0x47a0d997802d7b40L,
        0x0a25b51b193ef621L },
      { 0x24d3d4f4148ee5a3L,0x7012618f022a9df0L,0xb3777339f68e648fL,
        0xcdfb557fd7544352L } },
    /* 46 << 196 */
    { { 0x4b0b2d461f912c5fL,0xddaf929a957515d9L,0x29e4bf1f0ae46856L,
        0x158b4c8544e32ab0L },
      { 0x179353987c48d2d2L,0xe4ab63006f2430bcL,0x71dd72840d8b24d4L,
        0xd9303af1fc21d7e4L } },
    /* 47 << 196 */
    { { 0x816c616f450f7f6dL,0x17875d8e3306df19L,0x7ce8d4a5087e86e0L,
        0xa53970ac36251f01L },
      { 0x2037f12cfc98edafL,0xc359a382abf72b6fL,0x06acf1a685130fa6L,
        0x08f45064adfe4344L } },
    /* 48 << 196 */
    { { 0xc01e1f3bdd857b31L,0x92c2263ac9513734L,0x562652d5589327b8L,
        0xa8edd06596a1c164L },
      { 0x2cbf8f9879f8df8dL,0x3d5cf77140847ddeL,0x69b08ee4597c0622L,
        0xfff18c4d8a868f2aL } },
    /* 49 << 196 */
    { { 0x28bca3d2f5ad0686L,0xf7992f892d4eef7bL,0xab10b9cc3977e15dL,
        0x47912ca12db8ef03L },
      { 0x1f3e70e6df27884bL,0xdd9bb81e0e9d8efaL,0x97a83b6f279e27f6L,
        0x47e259fb24daf922L } },
    /* 50 << 196 */
    { { 0x49eb72bc124e71beL,0x01dba0013a6778baL,0x8d02baec3be03050L,
        0xe3571b3c6dd6c8efL },
      { 0x6e1ffbac2cc11ffeL,0x6d725c75f4e2e6f0L,0x96c31b45f2b53a58L,
        0xa0e38dd797f1634bL } },
    /* 51 << 196 */
    { { 0xe8507959143ce001L,0xad9a9f528b49cc63L,0x950fd33d8438b0faL,
        0x2b294c00be0cbdf6L },
      { 0xb2076b47937b00ceL,0x026153a178041498L,0xe958f12de9e53d27L,
        0xf49e1124e8f8fad9L } },
    /* 52 << 196 */
    { { 0xb78a5b742bca0ae1L,0x35180deccccdc3d3L,0x15e4fba5a97e519fL,
        0xe49dac9df5b8340eL },
      { 0xdbd8ed3ae5978024L,0xd181f26aeb105505L,0x3836481829f57098L,
        0xd674fe1f3900171aL } },
    /* 53 << 196 */
    { { 0x5a2ff729f1bd5803L,0x53de7261eda23387L,0x7f1d84c8f0dc417cL,
        0xa65694a75360fa80L },
      { 0x356e451896ed36e6L,0x127a52de406bfd36L,0xb575a98ede925d04L,
        0x35fb44bec0627c4fL } },
    /* 54 << 196 */
    { { 0xc85f2c69471e745aL,0x1c01e1ea6213d79eL,0x95ea99a12f5081f0L,
        0xdb38bd3ec3367864L },
      { 0x0e8cafecd8880436L,0x1d59fd74f9c63d09L,0xe57b0b4f7f875dbbL,
        0xe266c93977084bd7L } },
    /* 55 << 196 */
    { { 0x0e289c5a2fc1f909L,0xece9d22586c4fc40L,0xe0a56fbe5d79b4b3L,
        0x2b96fae7d4489041L },
      { 0x0f66316be23c85e7L,0x2d1a3c78adfef0c2L,0x1aece4ad9fbce9cdL,
        0xccd0f3346c32d32dL } },
    /* 56 << 196 */
    { { 0x958d7a5cfb9ba6ddL,0xa0052032e673275dL,0x514ffd9d7f978d07L,
        0x544bbce9450b76e1L },
      { 0xeaa25d746b5201b6L,0x7528a4ea74d082a5L,0xa08c8d3166609e27L,
        0x5150d1beda7c6fd9L } },
    /* 57 << 196 */
    { { 0x864f5b4c39930618L,0xe71e7f1acebb516eL,0xaeee7fa5ebf1f8acL,
        0x6efcad4a0ea827c6L },
      { 0x6e0f4ecb74e21dd8L,0xc5311600f33a7939L,0xdf62f3c3a4d93fc4L,
        0xd3b627279a18476dL } },
    /* 58 << 196 */
    { { 0x0b54f5e6c0e1256bL,0xe8987efb97ba9afaL,0x4b6ea06441d11c15L,
        0xfed7017e79b79f0fL },
      { 0x5a6bcf9e5bd04e40L,0xf30901538fd3b4bdL,0xa23b5acb82240648L,
        0x61d9a8b1b16cf033L } },
    /* 59 << 196 */
    { { 0x2feb1706c9fbee1eL,0xfaa4cd69d7e07918L,0x28562c58447cba7aL,
        0x727926c4a61a1064L },
      { 0x1b32db7f97ac7effL,0xfd968b22452253ceL,0x69d1842f5cdd3217L,
        0xba7689da26f4007dL } },
    /* 60 << 196 */
    { { 0x16445a64141c8b35L,0xc11c310173c61779L,0xa5aa0d18485300eeL,
        0x531b6de11cc02bf0L },
      { 0xf8b94155c4efeb2cL,0x83632663d015a9c8L,0xc369b3cecba18b7fL,
        0xe11b3ef6c29e0f9bL } },
    /* 61 << 196 */
    { { 0x1a5e9bf2903ca95bL,0x2d9aefc6a50cb332L,0xb5670264b29ce693L,
        0x806d08acab1d7b7eL },
      { 0xcbdfdf28c9107eacL,0xa80862436cdf12acL,0xe7d9c315903d5999L,
        0x4379820bc079d951L } },
    /* 62 << 196 */
    { { 0xe789ecadbf1edf4cL,0xec08681147bc7752L,0xeea2eeb8c2fc8798L,
        0x763183e0e031a96bL },
      { 0xc7daf0b2f9a6bfafL,0x1a2a7ffb4b957cf7L,0xa483c7c8bf2d2e7dL,
        0xf96921fc58ff7f9cL } },
    /* 63 << 196 */
    { { 0x41386185574ee010L,0x62e6a1d82780c649L,0xdec553af60f2516eL,
        0x5b0915377a04eb11L },
      { 0x1b53e9dd67eb90c5L,0xc390a23addfda333L,0xdd4e7c6d480568aaL,
        0xd6c1e8a859ccbe61L } },
    /* 64 << 196 */
    { { 0x1c6fd7a99107901bL,0x5dc4a41ea211d116L,0x597e94e7af1b78a8L,
        0xe72da34d53afcb6aL },
      { 0xbc364db774512c24L,0xc26a8fb9b2811e91L,0xfdd39d7f290469b1L,
        0x8451539220612535L } },
    /* 0 << 203 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 203 */
    { { 0x7fe996a01539cf31L,0x4a3f729a0ded7c6eL,0x86f1f2993016f614L,
        0xc3d44e1886cb9163L },
      { 0x96984531558fa36cL,0x58e8bf05369c89d6L,0x287da114f9ee923fL,
        0x2032e984ec271fbcL } },
    /* 2 << 203 */
    { { 0x91b8579dd39207adL,0x6f62c7250b1fe916L,0x0f1599acd89e01bfL,
        0x8d9bb86d4d1e5843L },
      { 0x348b90d4726e38d1L,0xb824a1ca52a8c6b9L,0x984d9309b1d2f6f4L,
        0xefa485b7431ec12eL } },
    /* 3 << 203 */
    { { 0x24cafa669d616a5cL,0xc1c7445f4c9d0ea8L,0xf733e08590bee7b6L,
        0xa2f3ece3d251d2baL },
      { 0x6e422a4566aeba6cL,0x35e99b1637c1337fL,0x52d0fdf76d4f8d03L,
        0xa043420c79c92672L } },
    /* 4 << 203 */
    { { 0x9972560776ac1925L,0x086449db3442fc58L,0x8dbab9202e311e74L,
        0x29dee69b7ea25561L },
      { 0x5a62b6ee19a7cd6cL,0xba38cc4c0d0dd5a0L,0x779279e5166d0ff1L,
        0x0eef53ccf48b3daeL } },
    /* 5 << 203 */
    { { 0x0463dcaa0f82c6a6L,0x75dfc96d11d7d6d8L,0x61f05e7b6c100d92L,
        0xa118e548e13eabb4L },
      { 0xcc77e3c8dcdf06b5L,0x902d37d66ac25960L,0x967d9993347d7116L,
        0xd28286509ae33561L } },
    /* 6 << 203 */
    { { 0x955b78408c7c6d89L,0xbfa78bc842c2555fL,0x8c56ae3da69c3165L,
        0x72b20e72e33bb1bcL },
      { 0x686870b4d1aa6416L,0xf000040b7db03cddL,0xd25b16a9b0a0fd40L,
        0xeb89e93236815f1fL } },
    /* 7 << 203 */
    { { 0xb3e5e912349b549cL,0x801f788e086c4e74L,0xafb9ea4f0082ae92L,
        0x4e8f27a40d740026L },
      { 0xc4f8285a05f4a6acL,0xefea52970adcd58cL,0x9d5b6ae5c52f8c21L,
        0x92622a7ae97af4ddL } },
    /* 8 << 203 */
    { { 0x39b4393579f34a8aL,0x61acf55f30046435L,0xf0a23fe63f05fdb1L,
        0x7d6baee10c4fa7ffL },
      { 0x253f62b6e2daf735L,0xe370ead82948637bL,0xda57c16ad84e6206L,
        0xf19ffe090dd22ad3L } },
    /* 9 << 203 */
    { { 0x701acab295bf2003L,0x50e4e10a9dff6efcL,0xe637bcf043b95430L,
        0xac45cd3e85050cbcL },
      { 0xc2ebff6480639e4dL,0xe5af1fb53056f603L,0x302791d508b17132L,
        0x87775ac4ed517904L } },
    /* 10 << 203 */
    { { 0xfe64ed1e4263a566L,0x735bbee41d5e8f55L,0x9ac619158294342cL,
        0x0f522e5ad4904935L },
      { 0x2ee883b57c1e11f4L,0x0a2ce30ff0c237f4L,0xf4a7157b8d955086L,
        0x7ec0462e022dc2dbL } },
    /* 11 << 203 */
    { { 0x562fb75bca391b0bL,0x13030aac3bb1efd6L,0x305d9831347f44feL,
        0x9f70c1ad94b2615bL },
      { 0xaaf935f44162ff22L,0x2b20f047a68d160eL,0x30d52a9739222d1bL,
        0x051223b16551642fL } },
    /* 12 << 203 */
    { { 0xae65a5c739620daaL,0x8ef6f93f6f7c078fL,0xb06d52bcb0177db8L,
        0x915cdd0868fdf535L },
      { 0x0070d150c5183222L,0x2b6495cd7817a2aeL,0x3ce476140b194f0bL,
        0x2eec6acf513bfdfbL } },
    /* 13 << 203 */
    { { 0x725dbedef3dbd34dL,0x01c4412a3621fc75L,0x17bd68de3c07f048L,
        0x117df57e62e735ebL },
      { 0xb1596c6db249c407L,0xa878f56ad46c55c4L,0x33385670b8aa0cb4L,
        0xc7faa80e800ec887L } },
    /* 14 << 203 */
    { { 0x2cd2814fd7daf836L,0x877b72b70d616922L,0xea73ca1bdb066012L,
        0xbe336c7bb0d4159dL },
      { 0xb993b07f0f8fcd76L,0x5fdceaba8a593562L,0x716595fbf691ec19L,
        0x51a77f618e68e3c0L } },
    /* 15 << 203 */
    { { 0xe9e4cdfe7a7c18dbL,0x967d35757b4f69b7L,0x6dd350a1a9a434c1L,
        0xb92cdef900c79ba7L },
      { 0x7a762493a6bb0f93L,0x6c18cdc28158ad36L,0xa0bd83e3c529ecfdL,
        0x98363c593962f96dL } },
    /* 16 << 203 */
    { { 0xd80f45a51d63aa7fL,0x8d5eba75b3b32da2L,0x0ef233dfa4708858L,
        0x74c3f4f752161c61L },
      { 0xfa9bfe6be6420de4L,0x96c0c50197dd86d5L,0x28e6827bcfce233bL,
        0x035cc9a958e74d63L } },
    /* 17 << 203 */
    { { 0x9ba64bf47948782dL,0x5e5b7c7280d9ce1aL,0x7b9435dbf51df862L,
        0xe74ab6e8b4dd2421L },
      { 0xb0d704db60954c75L,0xd31c51450b59ae5bL,0xe0ff4660d99ba307L,
        0x1a3800fd986bd82bL } },
    /* 18 << 203 */
    { { 0xe7e06ab7509a0a50L,0xbdf63778e4539885L,0xf888320f16ddb433L,
        0x0f10830418e18998L },
      { 0x27e7ffd6fa834b14L,0x16de9a71c68b9434L,0x53a12e2c4d360436L,
        0x5ad2c9865e110b02L } },
    /* 19 << 203 */
    { { 0x3439443c3cf53e0cL,0xfeae29b01d65a7a3L,0x1e7774f678ad7d78L,
        0x0c79fb016fee368cL },
      { 0xbec71de1e4faf3eeL,0x1a88f3e5263868e8L,0x975d838190e91a8cL,
        0x69c5a65d0f999c60L } },
    /* 20 << 203 */
    { { 0xbd3360d88b884857L,0x0419041331b7c579L,0x40dd9229142cc145L,
        0xb5faab94dad0b2dfL },
      { 0x3e7d792152df4831L,0xcf5bd1ed228bf67dL,0xd8669635c4980085L,
        0x094b89731c71903dL } },
    /* 21 << 203 */
    { { 0x493a7a3dc4abb028L,0x0e1a8facb4ab8e35L,0x26094ca2017aa5f2L,
        0x94fcb8b1021476cbL },
      { 0x57f101f94abf3bcdL,0x1ac2c1252d7f12a8L,0x575259d92e42789cL,
        0xa64a4a4b22471eb3L } },
    /* 22 << 203 */
    { { 0xcc02304de1c00144L,0x6269dfb9754734b2L,0x72e7a183f14fbc81L,
        0xd92a5b1c2a05caa2L },
      { 0xd593492e15efc2fbL,0x1ace7dcad8dd458bL,0x576b4bc8aef2ae81L,
        0x6de6a2db351b397eL } },
    /* 23 << 203 */
    { { 0x73f13b48656cf9abL,0xc18df1c9aee7e01dL,0x30fb5155560355e7L,
        0xd2c9a0ee9ad059d5L },
      { 0xd9f899365e5e0c7cL,0x5d0a2cbdf0a6c9d7L,0x3c2c497d58fa9be9L,
        0xe6c6fcf26ac61a2fL } },
    /* 24 << 203 */
    { { 0xf7ec89e335607bc4L,0x17ca00ca9946bf52L,0xee46be5b180c8bd8L,
        0xd29d5eb0b2873893L },
      { 0x348ac93997487b3cL,0xc18f0cebfeef78ceL,0xfc648dcaf797cce5L,
        0xe2467e0c442148d7L } },
    /* 25 << 203 */
    { { 0x8e201ee7da6dbaf6L,0xc1a93ee4abd0490cL,0xfd0007bf4de7c210L,
        0x02eccb8b083ffce0L },
      { 0xbba82bbb97844c8dL,0xb7ff954c2747a430L,0xb05f058418fb5f29L,
        0x35a29cf5ee7c263fL } },
    /* 26 << 203 */
    { { 0x5fd84efd25282da8L,0xc1fc84c17682db7cL,0x8422b56a4bb291e6L,
        0xce379feb66a56078L },
      { 0x1c3c581ee7f045a0L,0x8f42985d6b3f89acL,0x112839e9a6b2ba59L,
        0x3f0c7269c2a7b29aL } },
    /* 27 << 203 */
    { { 0xecdadb6f79bd3046L,0x669f559b9617ff6eL,0x242bb14d68928ca9L,
        0x28e2b0cbc19cafccL },
      { 0xfb7d895481330593L,0x5c3741fd9fbf8665L,0xaf49e83ac3b93e86L,
        0xd60ecf7d32822548L } },
    /* 28 << 203 */
    { { 0x4bf367597cfb37cdL,0x94b0c7f0db7af2edL,0x2f1bebf6ebf8b461L,
        0x90ebc9c7073e5c18L },
      { 0xe431c7933774e905L,0xb8a4bc2fe03265bbL,0x0bee0825fabb629eL,
        0xbd1481dc84557170L } },
    /* 29 << 203 */
    { { 0xa2257b58e1a010a0L,0x43f5451c4688bb89L,0xb87a5ff091b96371L,
        0x445dd02fde3c7b25L },
      { 0x44c0c08051a0964cL,0xb0c3190e9afdcefaL,0x14cc65ad0044d258L,
        0x8c500b3e374fdd44L } },
    /* 30 << 203 */
    { { 0xed8d840f51b07812L,0xd414a4a276530691L,0x9db9d1381468ef8dL,
        0xfc6b7434292b3870L },
      { 0x80b66797c9d7ad96L,0x81e74eb62a9c1e99L,0x48657d9a9e92f64bL,
        0xf5c600754c851dddL } },
    /* 31 << 203 */
    { { 0x08fa89bed99d5cfeL,0x78b1f26e4db4addfL,0x032371773523ead9L,
        0x0147af5c6a281494L },
      { 0x8db3952a916836b0L,0x0632b102fd365650L,0x3854a8e9ccb3f2f1L,
        0x5048486c586ad427L } },
    /* 32 << 203 */
    { { 0x22de997917a86e18L,0xe2ac2321be029111L,0xbfd3439735cc5a17L,
        0x7a93461f525e13cfL },
      { 0xd433542c5122d6f1L,0x41d2d9de833982c7L,0xe9f1f29a8ec24d27L,
        0x4ae251f3f3b99d58L } },
    /* 33 << 203 */
    { { 0x7234dd2410adb458L,0x0e4b656788379ef5L,0x3007df15748dba5dL,
        0x1485ef0135103772L },
      { 0xe21a9dc929c2382fL,0xcf7e0c246b6c1c8dL,0xf8a7182030550c0aL,
        0xb30e5c0fb797de2eL } },
    /* 34 << 203 */
    { { 0xbe13611903705145L,0xe6d1f720f94aadc7L,0x38ce1872255f5297L,
        0xbbba4793c3143f58L },
      { 0xda5345fe0984e265L,0xe93989d6d895e0d7L,0xb7392b18caab40a3L,
        0x4a58696365e754fcL } },
    /* 35 << 203 */
    { { 0xb3e88445a3afd381L,0xa6cbab0a693ad961L,0x64d51359257d56dcL,
        0xf9e70fccbbde137aL },
      { 0xa33872faadd016b1L,0xd1d263d27344f234L,0xc2d5121024ba41b2L,
        0x8c9c830ce4ab65cbL } },
    /* 36 << 203 */
    { { 0x3b47563c175b4039L,0x53521dfd116b2025L,0xe4f3aa891a9f1ccaL,
        0xcc73485ce7cb1d2bL },
      { 0xa6ca61efbf58fe30L,0x5d50e15d531a2b6aL,0x71cfdb4122611c31L,
        0x0dc1553361e3d46aL } },
    /* 37 << 203 */
    { { 0xb363c60b479074baL,0x2a4d8f4c24cb405dL,0x3d3bee13646b7f0aL,
        0xdfa9194c5571af63L },
      { 0x951a61a7ee76521cL,0x67466ba565eda1f1L,0xe41d33b869ebc7eaL,
        0x8b6c992dd4f4848fL } },
    /* 38 << 203 */
    { { 0x3572faaca5003eaaL,0x01e36500abf54df1L,0x6622f12fac6f3af7L,
        0xb5d7c17f0a8bb122L },
      { 0xd1fc1b99240286b1L,0x519d52cead968edeL,0xcd1e7d0cece28bb4L,
        0x64ffc69993f0b097L } },
    /* 39 << 203 */
    { { 0xb18d51f825af7d81L,0x8d0bb08f19820fb2L,0xe9f45919aa344723L,
        0x558f18ea5f9e0501L },
      { 0x56eff07607cc79dcL,0xf171e880d5fa9783L,0xd5fb41f38be7f1feL,
        0x19a34620d6fe9afcL } },
    /* 40 << 203 */
    { { 0x74c2696b7d8a042aL,0xcf4908c354230dedL,0x98a870d8db32943bL,
        0x181cbe5c52f33e07L },
      { 0x4d9d117293709d8bL,0xb800c2922b2b7939L,0xd5a1fb7aa8920f60L,
        0x8d0a7725bf7df622L } },
    /* 41 << 203 */
    { { 0x83a370cfe9415cf4L,0x9f24d1e162a4ff4dL,0xca33914b0a6ff7cbL,
        0x2576f2d8da1d1aafL },
      { 0xbb2668bdb4793101L,0xb576672cca990b4fL,0xfa165b5fff1d3988L,
        0x273d5b18ba8c9e2cL } },
    /* 42 << 203 */
    { { 0x13594ae5720a5b3fL,0x38c4e04a2e65454cL,0xc5b55d9855d0d903L,
        0xfabeb890f72db301L },
      { 0xe471f1d52f3deaa2L,0x3f8d39f5c5ade08dL,0xe08486a46baf9d1aL,
        0x77c6d30ee5140d3bL } },
    /* 43 << 203 */
    { { 0x828db96ad23d4e09L,0x2de4856d84dcac15L,0x313c7f8ba6ac856dL,
        0x7c9f671cfe7dea98L },
      { 0x4d6c14a5febe9e72L,0x185ac4e66014be55L,0x428099885ed64e23L,
        0xdc9395a1bd6440feL } },
    /* 44 << 203 */
    { { 0x1016908024108055L,0xfe0d9cb038961403L,0xf88e6a48ceb87d29L,
        0x0365ca2f69618944L },
      { 0x1504647e9fb59ec9L,0xb6486b3ba4aadbb7L,0xfe8701af22ef3214L,
        0x4c895bc15f56d985L } },
    /* 45 << 203 */
    { { 0x6fdc6cb62e1e68d2L,0x0689b22b13f07350L,0xba94416b6d62eb1fL,
        0x5a2fcbba98996d72L },
      { 0x2ca2a2e904b2afedL,0x5b62c7640bf61008L,0x30074e5737f4d486L,
        0x4e02be2a31865287L } },
    /* 46 << 203 */
    { { 0x401cfb896842ab16L,0x440fb52d5b2eb304L,0x3245fd38d22eaa61L,
        0x252120e8373f201eL },
      { 0x4d253f5cb2e724c9L,0x9428d6be27e5b5e4L,0x00d4c5986785ee9cL,
        0x0b7fc5f956208d4bL } },
    /* 47 << 203 */
    { { 0x4426665d92310137L,0x75b96cd3fee8da95L,0xaaaac6c3b561c6d8L,
        0x0784a3c53f09e1d9L },
      { 0xac78c064dcac620bL,0x49dd5f02119b8d90L,0xf1f5ebf257e5caf4L,
        0xd8a9fa2d0eb825e2L } },
    /* 48 << 203 */
    { { 0x3553633abfb6a2fdL,0x06533515a0c9ce9aL,0x6decd9e804c71728L,
        0xcbc0df55980b29bdL },
      { 0x17b1b55931826d15L,0xc96ed7d71c5cae17L,0x24f5874088cda83eL,
        0x9e2ee1bc0c69f40fL } },
    /* 49 << 203 */
    { { 0x138ebf0f9e5604edL,0x0577f4c2f229f097L,0x0a44f9759762825fL,
        0x113b8639dd085e55L },
      { 0x4be02fee73acc59eL,0x7829f288ada7a17dL,0x086bd73684fb30d4L,
        0xb2f120eee5338ecaL } },
    /* 50 << 203 */
    { { 0x21701393fb778d2fL,0xd46bc61e6441fd75L,0x466671de135b55bcL,
        0xee1d9cbb51c0f145L },
      { 0x7a7bce676d9ce27cL,0xa8c9b1e026d82b1dL,0x250bee034c87bd6eL,
        0xd6b02f71d3829702L } },
    /* 51 << 203 */
    { { 0xf14b37480e555d98L,0xf795e62a6f775e78L,0xe9a4e4ac8f46de18L,
        0x773bd32ac5ab76efL },
      { 0x4f2dcc685264cae9L,0x453b627ec63a6419L,0xc3aeddd1e441c6d9L,
        0x669500b73027b8f3L } },
    /* 52 << 203 */
    { { 0x06b9341388d601e5L,0x0e996e8776c4483cL,0xe2ff3a6d00eb0c21L,
        0x86ec3a73f4690674L },
      { 0x673d123ee9f82ca7L,0x952c2765bf611d0cL,0x26ed9a683676497dL,
        0x2c9c00499d29cefcL } },
    /* 53 << 203 */
    { { 0x0b8c12fe2ae73af6L,0x555b0ab36455c8e1L,0xd2f49f034804b006L,
        0x408a22bc02e829a0L },
      { 0xde2a59cff2832c53L,0x0133243996a54082L,0x11dc4ab6bbd38f9fL,
        0x0248fd93a24764b5L } },
    /* 54 << 203 */
    { { 0xc7774c121374972aL,0xc735596692764b41L,0x31c10ea523143092L,
        0xe89d9f889070137fL },
      { 0x7d074406a504d91eL,0xc521037970b7aa8cL,0xa67904f8ea799dd8L,
        0x81e6516be7b02c04L } },
    /* 55 << 203 */
    { { 0x18daf05fb08cc6feL,0xfbbd3061f59d49f6L,0x5429b11793a78581L,
        0x795a44651906df65L },
      { 0x643c37e3d51a7866L,0x69b8118d663a17b1L,0x5e3859893e8a2c53L,
        0xbc18c2ea50f007d2L } },
    /* 56 << 203 */
    { { 0x4adec20ab616aa15L,0x99f77e49ea085548L,0x9108c205c01b9a33L,
        0x298fbeb16ef3bcefL },
      { 0xdf1a8d2eefd8ba0eL,0xf0ec9492e9756e7bL,0x4fd333897ff5fbc3L,
        0x122a6bfb03ac8371L } },
    /* 57 << 203 */
    { { 0x7d053c8c90d66732L,0x83f26571f9b2909fL,0x350dd6d066cba4b6L,
        0x8c71c17a40d0d47dL },
      { 0x3bf850534d0be34aL,0x91ae4f59e11bd49fL,0xf8a38b41a22c648fL,
        0xcb96620e58abaaeaL } },
    /* 58 << 203 */
    { { 0xa55cee46a7fabcf5L,0xd16a8b9279c8fbceL,0x26ad700bcbf048bfL,
        0x83b3ce1147bb5f1dL },
      { 0x31a48f466b310318L,0x13a7f78100612ef3L,0xcd840f2aa18db234L,
        0x3be2a7a830611c74L } },
    /* 59 << 203 */
    { { 0xbdf37cb22b1c0447L,0x7f572382fe71722dL,0x085b356625535e86L,
        0xb5b430633f5b9cc2L },
      { 0x7c7cff51dee66228L,0xe29236aeb676fd6eL,0xf0c0105eab0cdb1aL,
        0x0adc9d6e06b52812L } },
    /* 60 << 203 */
    { { 0xc9e6ca97483baf0fL,0x09b063bff9bf5055L,0x8c4c6b2afc5a407fL,
        0xe29cb48799a6f540L },
      { 0x18b72239cb9a2758L,0xa0ae9f108a5ed308L,0x2a2cb6036e402657L,
        0x9c7f52cfaf6f4d14L } },
    /* 61 << 203 */
    { { 0x0ed032e770ca9046L,0xe4b0b1d359cac9e9L,0xd12c87b018462dfdL,
        0xa25a23eebb8860ddL },
      { 0x6c9a8676507fa3d9L,0xc6bb96c4218f325fL,0xe141bbb82386b7b2L,
        0xf86a72d0d4183c77L } },
    /* 62 << 203 */
    { { 0x35537f86aece96b6L,0x83aa1df963f7e1faL,0xa39ab4aa7ac4aaf2L,
        0xb8d0ffa68a202375L },
      { 0xd916df0986514cd8L,0x71f905b311902747L,0x6388c2ee8c744f32L,
        0x6282e1f5a5431096L } },
    /* 63 << 203 */
    { { 0x14bfa7657c388413L,0x95dd04d97b4437aaL,0xdf6ca8493c39d7c3L,
        0x85cb11230c2ddf38L },
      { 0xf7766d86c401529cL,0xe33416a899a4d031L,0x5c507c3fb874ace4L,
        0x0e3a42b6dad6fcb0L } },
    /* 64 << 203 */
    { { 0x402da46047920742L,0xb142d6efb45f94ccL,0xc2d613e876608dd4L,
        0xa2c06cdd5d75d4b5L },
      { 0xa1951bc53c564ff4L,0xe60f126bad1d5ecdL,0xa634e765702135adL,
        0xa5a56a6e8df44695L } },
    /* 0 << 210 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 210 */
    { { 0x234b8c7a9e2207b4L,0x1f724f30f7ee9f62L,0xfa908ca2c58e21b6L,
        0x55587744a74296aeL },
      { 0x7dbe913002911ae1L,0xc20754339d3af02eL,0x505b724b0f3955a1L,
        0x480e1a92caeced66L } },
    /* 2 << 210 */
    { { 0xb20f6128446d9f66L,0xd6e06b14c354b5a1L,0xa72d287d63558aacL,
        0x4819be29ae68a8fdL },
      { 0xb024c324205fbdf2L,0x2fca94e7210927f9L,0x74798be7be658f80L,
        0x618e07f1ef07c046L } },
    /* 3 << 210 */
    { { 0xfba715fcb35a8c3dL,0xc2548193ed1beba8L,0xb956c6dd2ceb663cL,
        0x13d4ddbeaacafe85L },
      { 0x2f8275b530a29cc3L,0x10432e15f51b39efL,0xd6c9277c2509b2d0L,
        0x4ee0d4c3849b946cL } },
    /* 4 << 210 */
    { { 0x547ba94654b01bbcL,0x7c56c36d055d4821L,0x8e93362005575f20L,
        0xaec65be93a621cf4L },
      { 0x820b96df46287937L,0x35cea883733c67e7L,0x30366a3a58cf3e05L,
        0x2580d5652da39773L } },
    /* 5 << 210 */
    { { 0x7717c42fba4417edL,0xb2d66fc7654c1086L,0x07fe918e57503cd8L,
        0xf93851593cacf74fL },
      { 0x157d908163063029L,0x79c84c08659034cfL,0x02976610a8048cb9L,
        0xef82200603e81417L } },
    /* 6 << 210 */
    { { 0x5fb5dd4d22e489c6L,0x9a06d9c281e167e9L,0x83fc248f6b974c90L,
        0xb78cab727110dca6L },
      { 0x73f8f311370ff66aL,0x8c5049eb3b61d20fL,0xaac47edbc8516e05L,
        0x2ceba50d53f0201bL } },
    /* 7 << 210 */
    { { 0x6679dc5e0b93fbc7L,0xf4457919a560bd27L,0x2561bfcab1acadc9L,
        0x338fbb6d46708164L },
      { 0x9f4076218b9cfd27L,0xe806c1e6d3123732L,0xaa1eafc47f24a161L,
        0xbee3f4a168e6650bL } },
    /* 8 << 210 */
    { { 0x453b61815832cd6cL,0xc002e337985e90baL,0x4b33afde6414f686L,
        0xf9ab29e98511fd45L },
      { 0x067f09726fb9a688L,0x7db6e14c7202a1b3L,0x0c15b6e973a881abL,
        0xc8c324e0fad10660L } },
    /* 9 << 210 */
    { { 0xa997a6d287d9f927L,0x62307f24acd2f107L,0xed7b48a59c80a742L,
        0xecd33ae5a7c81e7eL },
      { 0xcf05c763efa00a94L,0x38844b0dd9ee5aa7L,0x02e0b05d214b293fL,
        0x732e776b8a8a510eL } },
    /* 10 << 210 */
    { { 0x784cd9096c929e53L,0xe436e29456a33da2L,0x68eeb727ce9e06d2L,
        0x637890b3fce7e2f0L },
      { 0xc0681a1cc3fde38cL,0x9cb729d976dda134L,0xaa69eb975c333eceL,
        0xe138a68048eed8a6L } },
    /* 11 << 210 */
    { { 0xd53cbd01505dc701L,0x413de3466a64c3d1L,0x91f6cde93170a5bfL,
        0x58ffdfd98489b5faL },
      { 0xcc0b89d75c584a48L,0x74f8ceed167f28deL,0x250fa9f78c878c91L,
        0xeb960a79630adfdbL } },
    /* 12 << 210 */
    { { 0xe43ed412c9489dcbL,0xcec053a5112d084bL,0x0fd4fe42664c7cd2L,
        0x48ee06f482a917f7L },
      { 0xc5de197083cd65f5L,0x3a1765785569c42fL,0xf24508f34f876110L,
        0xf350374b0a415bc4L } },
    /* 13 << 210 */
    { { 0x9c2b11c2c63aa8adL,0x6ac1ae127a51c0ccL,0x75acd0d7e1db428fL,
        0x9e39122719800684L },
      { 0x4f89e9c6b1050426L,0x099d97ccdaf99eeeL,0x27a19ad01ffce97fL,
        0x05fad0573c038d77L } },
    /* 14 << 210 */
    { { 0x96d6c6788597d09cL,0x38f6336c1e1d8b57L,0x1f945bef6330ace7L,
        0x9d627bbb613f9fafL },
      { 0xc0e7f21b19176cb7L,0xf0e09be3bb9db710L,0x16b06011c650133cL,
        0x8629b975f3673d7cL } },
    /* 15 << 210 */
    { { 0x8c8230b267115575L,0x9bfc55b19c9f30c0L,0x132d0e07ce93fd71L,
        0x08e4736e511c5947L },
      { 0xd54a098efe881630L,0x8ec67a8598efa501L,0x72975dc72267db00L,
        0x3d6fc706a338290dL } },
    /* 16 << 210 */
    { { 0x0c89108255ade88bL,0x0525b5014b212e85L,0x9ede010bb61362faL,
        0x52f3d088881eecacL },
      { 0x49957b6ebc6f0ae4L,0x25fe72631659701dL,0x41e9b7f507b76f45L,
        0x5f2ad664bda77d42L } },
    /* 17 << 210 */
    { { 0x5bdcb490a9c418c4L,0xd0e2c38de500a527L,0x0af29f6bca83fadaL,
        0x1f75b1f262273db6L },
      { 0x8454f7519e857e57L,0x3fb816d1b9e79612L,0xbe3040ae6412b5f3L,
        0x99535136843ca984L } },
    /* 18 << 210 */
    { { 0xb26ec8a83257f19dL,0xd32dc622e54dd785L,0x0c52e874f8698ab5L,
        0xf9a60af579183316L },
      { 0x38575d53f7f4496aL,0x33adfd1e3d5cd0deL,0x2133f4a17f502017L,
        0x46c093933e8676f8L } },
    /* 19 << 210 */
    { { 0xca8a5a583fb4c7feL,0x2ad58826328ff257L,0xd926487513b8d08dL,
        0x661ae2b2dc5a845aL },
      { 0xd2dcaa0649a408d3L,0x9ef164f885c21e84L,0x55efaf85b7819b61L,
        0x9488bb1cf504c32aL } },
    /* 20 << 210 */
    { { 0xb571518c9bb777fcL,0xf369c39182415187L,0x2d7c5dd92720284bL,
        0x6feab6344eec41ccL },
      { 0x2522d5db24ecd0beL,0x1fca0d9700338736L,0x7441610520145279L,
        0xf4492e1e0496e925L } },
    /* 21 << 210 */
    { { 0xa62e09fcbc33b547L,0x9434475aae063835L,0x51edd69fa139b769L,
        0x17bbe224e5166a9dL },
      { 0x6ecb0a021b4b6c84L,0x1643949097968c70L,0x75af0456bc8aa671L,
        0xaef056ab3b4411ffL } },
    /* 22 << 210 */
    { { 0x686b771405cef121L,0x5ad6bdf3078f4500L,0x56df858c072e70ebL,
        0xa0fc5e6f254c0917L },
      { 0x1a99de09c15bf9cfL,0x8aeb587ad008aacbL,0xba2d8c53b900d652L,
        0x60eb5d0cad0f69b6L } },
    /* 23 << 210 */
    { { 0x27098ff810b27762L,0x33329ca913264ed3L,0xffceaf40887e3f40L,
        0x854b8284930df9efL },
      { 0xdda913a87d5627beL,0x8eb94d6435e9823bL,0x94c527fd2eb9e9bdL,
        0x18335b1bf57b9f74L } },
    /* 24 << 210 */
    { { 0x3c44dac0d193a526L,0xd0717099e2b2d54fL,0x65624fb4c4c67d11L,
        0x04aa7033bccedad8L },
      { 0x0c522fac31470c52L,0x08eb33ca33b05d54L,0x940e0693b4565e57L,
        0x7e2fd5537be56370L } },
    /* 25 << 210 */
    { { 0xf722793c12e206ffL,0xb57e1f23155d3d02L,0xd68be19394fc6ce3L,
        0xb0f3606c22d4815bL },
      { 0xdaf995a9b62d5741L,0xa7d199803e8f5df5L,0x7bcdb661e4631583L,
        0x013193e35a97dc7eL } },
    /* 26 << 210 */
    { { 0x8210be46fc73494bL,0x508817ee57e10efcL,0x7b6b8da2126f2466L,
        0x2f3b0ec6177bee35L },
      { 0x5ceb71e048db1eefL,0xd989d9c3dc62b6bcL,0x2cc38cb9f78fac92L,
        0xcd2a009f955ba5f4L } },
    /* 27 << 210 */
    { { 0x65a74191453b668eL,0x40e9dc38c081b447L,0x48eb63bf8c3fdf2cL,
        0x7845cf665763071aL },
      { 0x30d9b771787754caL,0x10b3729f8783a05aL,0xf8090b3b6ab570d9L,
        0xc1dfbde1502b3558L } },
    /* 28 << 210 */
    { { 0xa568f5d0be4d36ecL,0x1e9e539328e952feL,0x768113f9eaad6b24L,
        0x2bc798fca8fbede9L },
      { 0x2c787f9baaa9010dL,0x32cbc77a761834caL,0x449e55f7032c25d8L,
        0xe824a5bfca6216ddL } },
    /* 29 << 210 */
    { { 0x3beaec5217ac1130L,0xcc28c64b5e9d1aa8L,0x355d68bf3af8c635L,
        0xcd12e443d3d1adaaL },
      { 0xa456daca6c2030d8L,0x0dfe5bbb62427effL,0xae45325df69e2484L,
        0xfc2a90ab7245c979L } },
    /* 30 << 210 */
    { { 0xc34f38e9a008b446L,0x5e86163daac355e0L,0x61432646d586a2faL,
        0xc68c7c8e3d92e0c3L },
      { 0xbfa8c268020c1dd6L,0x257887418bbcc223L,0xbaf8c9a3ef62642cL,
        0x6d2f1ae5a8c496d2L } },
    /* 31 << 210 */
    { { 0x92d1c80544e57ce4L,0x34cdf4a3aacd2100L,0xd5b89e4d31e9c649L,
        0x558a6e26232cfc85L },
      { 0xb40f3e4acea31a31L,0x346c1e0735c5c924L,0x8ffedd8e3fcede81L,
        0x35269ba33b55d143L } },
    /* 32 << 210 */
    { { 0x0366065a848bdc53L,0xba2af074078554ddL,0x3c755fba19ff3b4dL,
        0x5ea9337235a22cbbL },
      { 0x0e55fe021eb3e23bL,0x2626ecca765dede4L,0x187bf09481f445daL,
        0xba0110179df30578L } },
    /* 33 << 210 */
    { { 0x81148037d72507f2L,0x3a5841fc5db072d0L,0xfd631862bd910aa1L,
        0x17b22d6823881c60L },
      { 0x6fa799cbfcc13359L,0x55c402192d39fc5aL,0xd50bfff69f1f6515L,
        0x575090b52e30fa1aL } },
    /* 34 << 210 */
    { { 0x70343a0b9ba20c27L,0xef34db86749306a5L,0xd7ad61d24ba85f8dL,
        0xe4d24ad87e091a33L },
      { 0xbd6b49b9fc348493L,0x4f11b543299c325dL,0x4574a25455036e93L,
        0x534a623e676b75d9L } },
    /* 35 << 210 */
    { { 0x54aa3d8a7d05afbdL,0x133490097f3f2c90L,0xcd03de0fa94b18aaL,
        0x13123c18855c050dL },
      { 0x747c3cdaf598b5f8L,0x0f7ed9b68644df20L,0x45e010fd08d73585L,
        0x3b0ff430f8cec4afL } },
    /* 36 << 210 */
    { { 0x3745a41fb028a832L,0xcd6d2468c4106172L,0x56c5a9b01eceac6fL,
        0x769c1285e1e6e980L },
      { 0xbd163a36fa113196L,0x206ffc365840c242L,0x12de11479c57ef67L,
        0x5026027303bea885L } },
    /* 37 << 210 */
    { { 0x3099c21b9684d63fL,0x06adb196c7c66691L,0x8464492c3d63b3beL,
        0x86024ef40bd38c15L },
      { 0x226022a210565cbfL,0x2ae6b298c9899033L,0x5564856b262ffa14L,
        0x9472d0e17e038b55L } },
    /* 38 << 210 */
    { { 0x1b17ea07b1dd268fL,0x8340b9d54899352eL,0x4f15940075242992L,
        0xe4392a31e6727e9dL },
      { 0x4df1ef86aef59026L,0xe40671ff950cfee6L,0x7b36d1cdde4dd990L,
        0x25df10a63366ff4bL } },
    /* 39 << 210 */
    { { 0x83fb7e59584ef631L,0xf12dd40091af7b6aL,0x4a5ae41ee26f11c7L,
        0xeb86d5dd96d90445L },
      { 0x028ae37ea355d0a3L,0x3c118ef499260127L,0xb8c7538c76f51bd7L,
        0x66b90aae5fbadc4dL } },
    /* 40 << 210 */
    { { 0x078de9df17dfd0cfL,0x938df6dafe44b17cL,0x4a09616bc40bc950L,
        0x0b507845bc969aacL },
      { 0x23bae09135f7fb82L,0xebc04d379ad29b83L,0x9fa48a5b26a3c5faL,
        0xf67c661cf08f3d8cL } },
    /* 41 << 210 */
    { { 0x21825747b2e9c3a1L,0x3520a82e46c3eb43L,0xe309ae9f9646183dL,
        0xa19c31be26dac288L },
      { 0x3c37018dc76623deL,0x59b9a0fa64b51087L,0xa32f8357f1954f4eL,
        0x24251df41f6da143L } },
    /* 42 << 210 */
    { { 0x825c61cf01fb07d0L,0x69ae93fdf2f0243cL,0xd507c99e0943f7bdL,
        0x5e6dfb09463ee64aL },
      { 0x10a3c32a29afd00bL,0x92179b5fbe8cbadaL,0x7bebad0a7d89f9a6L,
        0x7ba9bbf6d13b3073L } },
    /* 43 << 210 */
    { { 0xfc23c2156481cc75L,0x6a654801feca7532L,0x20785ec00fed841fL,
        0xcb612be925269b21L },
      { 0xe9a9c09b414a0fabL,0x5404c7a76b4fa0ddL,0xde62dae8cb418588L,
        0x2d80afd4c594334eL } },
    /* 44 << 210 */
    { { 0xfe454df195366a44L,0xda7626c3755cf8b2L,0x4446f0ab41397051L,
        0xd178806470eb8b23L },
      { 0xbc7737f1977b040aL,0xbfb3941857590edbL,0xb094b4a8343a7333L,
        0xb15912ceeb91372fL } },
    /* 45 << 210 */
    { { 0x584e1d5e0b56002cL,0x1460ce24aa0cb90fL,0x58f0c1448f7ffcb6L,
        0x56e39f33be0d802eL },
      { 0xb02a6edb529458d0L,0xa0fbae74a730f9d5L,0xd98c0ac51bf69928L,
        0x5c9f888f796f12e9L } },
    /* 46 << 210 */
    { { 0x749207b022e065c8L,0x6e0232a488c61143L,0x27f30808837adda6L,
        0x0b748853d0c215d5L },
      { 0x97bc4008bf076ba7L,0xadae0275f157f4d2L,0x394e5d7a8bcba88bL,
        0xf995ec1423ef50adL } },
    /* 47 << 210 */
    { { 0x6b207f9caa9b60a9L,0xcd7509c152f9979fL,0xe3e8f6dc0834e0adL,
        0x6e2a4165cd5b1314L },
      { 0x073a2db3fd60d975L,0x5ad92ca42c053b7aL,0xceb10220fba97ae8L,
        0xab82f6a0d265e913L } },
    /* 48 << 210 */
    { { 0xc7a755adaa68a13dL,0x56c1336010dd277aL,0xbbcf6411def56183L,
        0xebffe360b863a4e1L },
      { 0x67ff26e5814e8aecL,0x90553561a0804732L,0x407396acad5fe672L,
        0x053a068b11ad53afL } },
    /* 49 << 210 */
    { { 0xb518dd04c652cb95L,0xc818563a57e2b99fL,0x217cf87db96432a7L,
        0x7fdc35be8cc2fdcdL },
      { 0x8c2ef2714effaebfL,0x21879369f427c7c2L,0xd80ebbea5197ba08L,
        0x1b00db45fc6f4c66L } },
    /* 50 << 210 */
    { { 0x99b9d2be3828a5c0L,0xa8855350d24a69e8L,0x2f9196953ceaa821L,
        0x89390c9104296439L },
      { 0xc12b3852c5cf8a0cL,0xdcf234ea73afc431L,0xdddf5568f4adf01bL,
        0x2d04fc761b426097L } },
    /* 51 << 210 */
    { { 0x02a21dd5cb27c5e0L,0x01b842c3a6b2f9b3L,0xefbd483ed8bd7a07L,
        0x0220825ed13a781eL },
      { 0x8aa029a0de802c17L,0xb62fcd6e3a3f0fbfL,0x80558affe9635f48L,
        0xbdc6851d65dbeb2dL } },
    /* 52 << 210 */
    { { 0x99f48286b5412271L,0xa53ef798e242a8a3L,0x41d18606c0371086L,
        0x5df3379cfcb6d1aaL },
      { 0x53f2f5a100a7a13eL,0x3565a6eb2bf51e2aL,0xa2832b52930c5a71L,
        0x66071ec7ee2abfcbL } },
    /* 53 << 210 */
    { { 0x75ce0a563496a532L,0xa316dfbbbe0d69b7L,0x35438d6a353e94fcL,
        0xf53433c11e0ce775L },
      { 0x47ea3e8f22ff3a1dL,0x60ebfba8cd7ccdb6L,0x47c6b6e233c475d0L,
        0xd18637e7b7959fd5L } },
    /* 54 << 210 */
    { { 0x8d7a35cea1ae3404L,0xf15c71d675b832bfL,0x6504741998b9d24bL,
        0x28625a550dcf73f4L },
      { 0x5aa9dce8c7c99478L,0x752d16250bde8d53L,0x7255ecfa93e99ee4L,
        0x1c53bf7122706f48L } },
    /* 55 << 210 */
    { { 0x283354514d478014L,0xd64b05ff3f392c0aL,0x1d9ac89d4fba1661L,
        0x281a0ffb34828cd8L },
      { 0x07abacdd577ed419L,0xa66949f53cfb2c56L,0x38e69105847ebe65L,
        0x8fbbba5a44d6236dL } },
    /* 56 << 210 */
    { { 0x0c85bd64725ef820L,0x4ef9152425a152a7L,0x5237ef0eb019cebfL,
        0x48203f41c9a7724fL },
      { 0x1f61885cc55fc0d4L,0x2c4dd07abcb3daebL,0x9855d5e74b7dafc5L,
        0xd76e6fdf5f3769afL } },
    /* 57 << 210 */
    { { 0xb834df1abb547be6L,0x43056b123e7a9586L,0x7459e0bb4375fc7eL,
        0x5f5f295a9c85fc6bL },
      { 0x3f2d2bb7bb23b709L,0x0b53bd8c955983ceL,0x5aee93dffaf68dccL,
        0x5575770c509f09dcL } },
    /* 58 << 210 */
    { { 0x2bf23c0c40b1b744L,0x524154bb9a5bb913L,0xb0e93d76296bdb2eL,
        0xb3c71f5bda0b2925L },
      { 0x8e77ae7a0c617939L,0x2bfea97e1aca9b0aL,0x8e3317c97897c5a8L,
        0x850ddefb4cee2716L } },
    /* 59 << 210 */
    { { 0x684ceee9107d9186L,0x487084230082c312L,0x5300137c6c556897L,
        0x6d4644017e99bc76L },
      { 0x6b11e1e38808ca2bL,0xedd30eeecca6433eL,0xa9099f60aa072ff0L,
        0x774662ec5830f69dL } },
    /* 60 << 210 */
    { { 0x0770355cf94547d9L,0xb5041edb42967865L,0x169a6274e585a93bL,
        0x06cebf5ed04d6a81L },
      { 0x0a59450f2ebc1791L,0x69fd006e765ac18aL,0x4711ec9ca54f7e7aL,
        0xd72c8d58819c6af9L } },
    /* 61 << 210 */
    { { 0x89c97c6cb5418e15L,0xd520b03ca558a854L,0xe3c24aca0d76773aL,
        0xc4deb5ce67e5110eL },
      { 0x5bb40152cbb04ba4L,0x672563b6de1b628aL,0xaec916aa2e8d9e54L,
        0xa4e8cb473c60ac70L } },
    /* 62 << 210 */
    { { 0x54a03e39452d5064L,0x1e405c2d1e7bb355L,0x2ab2d5df3bbd3ab0L,
        0x0808410edbc9fbd8L },
      { 0x4180ceea27f23f6fL,0x2b965b35ba1d6bebL,0x14f1f010f66d6546L,
        0xefdca6a8f85cfb4aL } },
    /* 63 << 210 */
    { { 0x69e6188e6614c1c0L,0x00bd1531e07cb7f8L,0x1b90f5154bb7ee68L,
        0x8afdf46651abb1f3L },
      { 0xf59a7327b5f34316L,0x43c3c19d64c7bf22L,0xb275733fcdb00a2bL,
        0x0160df79602915baL } },
    /* 64 << 210 */
    { { 0x1ae4ee9a1baea574L,0x0d922f2803ae5168L,0x07df28fdca691124L,
        0x5aad2f318dd457c4L },
      { 0xe0d4f443137384caL,0xd93d424a6620ea8cL,0x21d544d35067797aL,
        0xc8a8cc999d8a15bcL } },
    /* 0 << 217 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 217 */
    { { 0x610f0e26941d80a3L,0x30927879ad36514eL,0xaa2dfd4898f22601L,
        0xbc5b31b788c8b0f6L },
      { 0xb1281f376c841cc8L,0xdae167195a412b84L,0x9ec1f6c8828f210dL,
        0x1935d576e8d92901L } },
    /* 2 << 217 */
    { { 0x47247921af3840f2L,0x348325d2df3fcdfcL,0xef578508c43961bdL,
        0x7d5e8ccd1bd98c29L },
      { 0x59cdba10f8a30164L,0x0757408f7cb8c653L,0xcd7ed73fc3056ef4L,
        0xd28e7cc1fb99cd1bL } },
    /* 3 << 217 */
    { { 0xa8a674946bb62286L,0x8d6ef816e7d87467L,0x3529f938f673b6d5L,
        0xf5c0ee768bbf101bL },
      { 0x3768ed6149fdc949L,0x53b6999ecf405ee0L,0xbf0108a01718e51aL,
        0x38e609ec5181ebd7L } },
    /* 4 << 217 */
    { { 0x82051640d8595159L,0x30e1c706579a3876L,0x091154c60298a67cL,
        0x76d9a9c951132d27L },
      { 0xe41de8b75c661a4dL,0xf24b5e962a6dcbafL,0x1ed4cb0cd714e045L,
        0x605926a40c187c70L } },
    /* 5 << 217 */
    { { 0x97672559f34b1c93L,0xa256be98e0b43506L,0x7fcdd412e1a98eb3L,
        0x7fcfcd84295a061bL },
      { 0xddbac22bcc2386cfL,0x7741adb7928c2556L,0x3a2bb8694e6e1288L,
        0x53ed11da025bb4a1L } },
    /* 6 << 217 */
    { { 0xb114bd674108c8e2L,0x85948c6b3deb8e23L,0x6a9e05d9d0e9434cL,
        0x395060b7b9c4fd70L },
      { 0xa0ccfd1618893751L,0xa941ff60bbf65477L,0x34ada23859423e35L,
        0x4ba7a7d17e570058L } },
    /* 7 << 217 */
    { { 0x3d05d455869ae596L,0x92a1540093368325L,0xbd64ae0a62eb7ffaL,
        0x3f263a7ad34b2c59L },
      { 0xe95eece3a22244e1L,0x39ccef58706fc500L,0x39a88f9322f1d2e6L,
        0x1ec796b36d47c670L } },
    /* 8 << 217 */
    { { 0x1558e0f2aa1ff4afL,0x61f43487390503a4L,0x661647323c4f76f1L,
        0x50d0706e9e13432eL },
      { 0x5f1a87caf5eba0fbL,0x28a95c0f80bda2c5L,0x10d693e012ae6462L,
        0x79871340f45e6ba6L } },
    /* 9 << 217 */
    { { 0x8abf0cad887051c0L,0xd09f571db3c6b540L,0x3fb2e16be30ab25dL,
        0x12e057a7539e8bc4L },
      { 0x6efe71ce733c2597L,0x72fa0df5e71058acL,0x49f14d06ccc037bfL,
        0x9a3ceb03ceb3eb6cL } },
    /* 10 << 217 */
    { { 0x9895e9084195370aL,0xa75007e5927345e7L,0x00b4c212d3850711L,
        0x76e4060ddfee8b34L },
      { 0x15801862184c1d07L,0x234e39c0302f5711L,0x4c0bd3876aa74204L,
        0x0515eddc6f496836L } },
    /* 11 << 217 */
    { { 0xa9fd0cb5c849afbeL,0x041df5bacad5c0aaL,0x9a54af37ddff259eL,
        0xa3f156bf9b550a8eL },
      { 0x4df2d33d7e3298d4L,0x0957a0a065ff0e1aL,0xff7fb43d1e2b3a45L,
        0xb86d386a1a73285aL } },
    /* 12 << 217 */
    { { 0x6e283c4728b18e93L,0x5458b92f4b4132edL,0x7026345eba674332L,
        0xc8e381515c9fc32dL },
      { 0xd6aaf8e158e7b4feL,0x3e77a5c94267253aL,0x6441cba2a0949607L,
        0xfa205185dee20b2eL } },
    /* 13 << 217 */
    { { 0x64f3d576f5b44600L,0xf12125dbef5c8446L,0x1467539b487a0116L,
        0x3aa0fa49f380229aL },
      { 0xcc6586f1d79f36dcL,0xebcf653d1b9a0b42L,0x68af006d9c1df729L,
        0x507e055aa7903ee6L } },
    /* 14 << 217 */
    { { 0xd1b48ef8afd8ac9bL,0xd8920af73b5f6b51L,0x9629e789983339c8L,
        0xbfd2d787fa9248d3L },
      { 0xb50ca3029a078882L,0x1c34f848f5cb0529L,0xb9b015191646a9f8L,
        0xc9e3679e80d53f9dL } },
    /* 15 << 217 */
    { { 0x5a63e8221af3e5f2L,0x05480ad8ff58e3d1L,0x2d241643d6b3626bL,
        0x33b15660c1eda15fL },
      { 0x3e74f8558528e5d6L,0xafb6dc9af63188f4L,0x0cac44cbaeeb1d32L,
        0x50661046a627eff8L } },
    /* 16 << 217 */
    { { 0xadc4b01264b49667L,0xa4bdafa71e05f760L,0x171b28b3f185d27aL,
        0x987e516333425747L },
      { 0x7c42ac4ec3864a65L,0x2dae1bb8bf449c12L,0x680d974306965832L,
        0x6ac1ef017e31d9f4L } },
    /* 17 << 217 */
    { { 0xdef57433579d6ae4L,0xe055b087d5240bf9L,0xe4dbbe6090a5e069L,
        0x2161d5feddb3dc15L },
      { 0x7d303012da297b71L,0x04481034d468046cL,0xaa94d5bb0ac93c6cL,
        0x95bacd45d8d8f53aL } },
    /* 18 << 217 */
    { { 0x790a5d6f3e03e895L,0x27efd50244fa5a81L,0xd9d35230e5998b32L,
        0xb36a0c07f22ade19L },
      { 0x46ec8691f979a2feL,0xa67ba933ced8cb94L,0x00d072452f856ab3L,
        0xadc9ff423c925daeL } },
    /* 19 << 217 */
    { { 0x0e4eaa25563038a5L,0xfef7e89c8a8f6483L,0x50433633ace61af8L,
        0x8a1589e02e1a3515L },
      { 0x99f21e295fdcb1acL,0x8fd2d411c9a466daL,0x55323c6ff56b7f13L,
        0xa016d64a5cff438cL } },
    /* 20 << 217 */
    { { 0x3e3dfcbcdc05b5ccL,0xc1956ca8fc3c70ecL,0x7dbbd169e63f02dfL,
        0x95206689240b87c8L },
      { 0x7bacda5e1aa6d48aL,0x51dcf19f39280f78L,0x1511ae04660abac2L,
        0x3a95adc9d905af53L } },
    /* 21 << 217 */
    { { 0x0c8c4330ea464737L,0x989c09c434fc4b51L,0x1852120de2cf3376L,
        0x5a1cb8a825c04de3L },
      { 0x50486f9875fe7596L,0x8cd78d2e223030b1L,0x524cb8f8cfa1ab11L,
        0xa716ea3f5a15b0b9L } },
    /* 22 << 217 */
    { { 0x7618e95eb902d114L,0x0a1a4146084ebf5dL,0xdfb909e9e3f87683L,
        0xa0b7eee14107410cL },
      { 0xa45a551cf02b0e12L,0xceabbfd29efccb9fL,0xb0d1b6bc740f4e3aL,
        0xfc7372504cbfd0deL } },
    /* 23 << 217 */
    { { 0x3fad2d9e32452b0eL,0xb4e659fef523527dL,0xf0dcd7016c0ff353L,
        0x28f06e2ad67b6f98L },
      { 0x2d0c36ce82a789b4L,0x20e577da49c0d54eL,0x8d1d5c7fae38dd0eL,
        0x72e01399894d9143L } },
    /* 24 << 217 */
    { { 0xf78068563958e055L,0xac35ee405df44aeeL,0x2b47891397c18b8dL,
        0x5396824efa2586cdL },
      { 0x22b37b251b23f8c4L,0xf9ced36ecdecdefaL,0x28c3bee5c2fc39c0L,
        0xa1731fae6d9db32bL } },
    /* 25 << 217 */
    { { 0xa0445fa7bc3e2c91L,0xa1ab695575a4aa72L,0xf0cd61c6bbe0a1c7L,
        0x923c3b690123bc52L },
      { 0x818ad28cafd7c4bcL,0x7c22922428b15b05L,0xecde7efb1f78a4f4L,
        0x550d68e703ef3ab3L } },
    /* 26 << 217 */
    { { 0x0371021dfc5f8c35L,0x4440aa1e0ed2b06eL,0x70c8ede99ba7247dL,
        0x0d2b6ed384f23fdeL },
      { 0xd0119d955ff4478cL,0x66152d27f79c69d5L,0x56d8bea402afd13bL,
        0x035efe5f15bb938aL } },
    /* 27 << 217 */
    { { 0xc5ca7d082ccaa425L,0xc8c69ea6eeee9376L,0xb22cfe59493a2051L,
        0xcb50e618dc7b90fbL },
      { 0x0f6fdf2be05a8705L,0x081f3fe74814df31L,0x6fefe18aeb1e3e76L,
        0x8191005003e06a50L } },
    /* 28 << 217 */
    { { 0x8a801df1db45bfeaL,0x8c7fe1fd7a828cf6L,0x1c1868b58d173cfdL,
        0xe18f0a360dbde1c8L },
      { 0x3b29ed649ac345b6L,0xd56d59569dcd07a5L,0xf4191570c6813a88L,
        0x39033ebceda3af42L } },
    /* 29 << 217 */
    { { 0xdee5591bad5d215dL,0x9cfa11c6afbe5a28L,0x73d0f1e21823c28fL,
        0x75d49925afab1f67L },
      { 0x61c81e2c7c521448L,0xc547be6f4a96edb5L,0xccb9fc594ca368b3L,
        0x175ebe4804fc3303L } },
    /* 30 << 217 */
    { { 0x507620cffce42989L,0xf236e0439abfadb2L,0x381c50c3ab36ab58L,
        0xed4cb73eae22c6a3L },
      { 0xa68a28272158dc4cL,0x1715ac43e9fa53ffL,0xb02fdf73fa266797L,
        0x3079f3c77eefb203L } },
    /* 31 << 217 */
    { { 0x0a41fb947f7545bdL,0x6b9dd022cb923aceL,0x582c7ff53bea2541L,
        0x992f23795ecdbe2dL },
      { 0x821f1670fe17bdcaL,0x521c06f22626bddeL,0x6292748c1864ca0bL,
        0x554d4ece1bc74d8bL } },
    /* 32 << 217 */
    { { 0x745d4f74ea3d4446L,0xa439f17840ad1c7fL,0xc95d951051374e92L,
        0x75870e9f90229008L },
      { 0x3fec98c2c54e7e81L,0xef537ee994b3860bL,0x139dd83440bfc8f6L,
        0x20b513640f114403L } },
    /* 33 << 217 */
    { { 0x4752a49f30b4b4dbL,0xdfbb8b178c3c90e0L,0x60c8915b70f0b16aL,
        0x5e39500040528319L },
      { 0x8a1624c7a641f2e3L,0x3c9925c6bb4ca0dcL,0x2aae6edb2c3152b5L,
        0x8dbac58008b896ffL } },
    /* 34 << 217 */
    { { 0xe0516205e5a36bc8L,0xd77143323295707bL,0x61db680451c3513fL,
        0xf2ee6e20ab552df8L },
      { 0x5ddcfa99353c17f0L,0x65687a2f046d5fd4L,0xef567e9ffd1ccad4L,
        0x7cd5f7dda0238b70L } },
    /* 35 << 217 */
    { { 0x96fba79e92c01197L,0x46a9f2de83b50e70L,0x7efcbbb2fe287169L,
        0xe30d60cb4528d67dL },
      { 0x88fed0cc6cb04d3aL,0x63eb9d0d0221ceb8L,0xc6954e9f748b5813L,
        0xceef2bd85c96e897L } },
    /* 36 << 217 */
    { { 0x99503ae285648f04L,0xeee51f99923e87d7L,0x90908fcab6560cebL,
        0xafad592680e0f6b3L },
      { 0xa50f31f3aea32cf9L,0x7ea17064a74ae92dL,0x0675ccc1cda71d1aL,
        0xd1e3b6301e0a464aL } },
    /* 37 << 217 */
    { { 0xa361f2b72442872dL,0xb21bcd3946e52c97L,0x1405f89c85574630L,
        0x0da7bfbd8e0a96abL },
      { 0x48af06c24220f57bL,0x772a9b126a333e4fL,0x3afc661e6f712eb8L,
        0x29deff6c2eba8817L } },
    /* 38 << 217 */
    { { 0xbab680ded8c69e5aL,0xf8615abbe93daf10L,0x7455ea1dcef6fae6L,
        0xac0a30ea868455fdL },
      { 0xae967b17e47d628aL,0xa6d703e265f1f482L,0x2723a9650bfcc371L,
        0x9b06cc146db4a042L } },
    /* 39 << 217 */
    { { 0xa973d738a77c8b21L,0x9a981f80c008f2edL,0xecc7bbcbaf27cdb3L,
        0x514db964b5cb693aL },
      { 0x24125414e75c93d1L,0xd9308c0e1f00d53cL,0xdb56d155831eba6dL,
        0x29eefc2c672b86f1L } },
    /* 40 << 217 */
    { { 0x332f6ab6dd13b3c9L,0x70e052f6e371f873L,0x05740742125712abL,
        0x4239152db3512100L },
      { 0x98355eaa80b22915L,0xd0e263ecb896f6faL,0x9378a8a6442b4c8fL,
        0x40c2b546f65795bbL } },
    /* 41 << 217 */
    { { 0x0cfa46edd572ead8L,0xb9b4abdb78361300L,0x5fe63ef18c102020L,
        0x1805c84e785a4b54L },
      { 0x147cf487805cb642L,0x87cf50aa487e581fL,0xe942fa5b9eaebcd0L,
        0x06d4fa96d1af71f2L } },
    /* 42 << 217 */
    { { 0x20c1a770c4fc3823L,0xcdffd09e85140885L,0x27ce78ab6b3592e9L,
        0xb8e8c15e8ba82008L },
      { 0x5fe8f3f0fef74187L,0x8e85a3a577ce808dL,0x8447dc69c7395f64L,
        0xae90769f1181b854L } },
    /* 43 << 217 */
    { { 0x54adc101456114c8L,0xe7962b769ca6a9c1L,0x3f0e77fb909410a4L,
        0xe18151cd9e2e44f9L },
      { 0x5e510a0a2cf6e29eL,0x136896abb1836b07L,0x3ad4fdec0fe11010L,
        0x35b36790dbddf038L } },
    /* 44 << 217 */
    { { 0x7c4f5a6875903df9L,0x3e9cb0562f5b7193L,0x745e9452591a4524L,
        0xc406ad441a056e15L },
      { 0x2e93edf2a69e11efL,0xa28b82fd73a1cb88L,0xdc1c9cda1225c3d5L,
        0x86e9a994a5569794L } },
    /* 45 << 217 */
    { { 0xd698506e5b092ddeL,0x076a4c82d1ca8b06L,0x4516033b2ef2bc6fL,
        0x0574c792d78fa65fL },
      { 0xa3b1c3d8735bb362L,0x22fca7a40da54317L,0x3e7ae70960aaebb6L,
        0x42417d54937638c1L } },
    /* 46 << 217 */
    { { 0x32f00a5d1dfe8b0eL,0x8ea5e8e18dcdbdbcL,0x38df57cb6b30ea52L,
        0xd325aa1ce94c30caL },
      { 0x7aa04a9ddce4d256L,0x78e98cd374c7db6bL,0x631475a8443d5c9fL,
        0x34e5c73a7adfbcebL } },
    /* 47 << 217 */
    { { 0x7fb69bab9f1e8828L,0xcadc78bec84149e3L,0xe9424ecc1fe86af8L,
        0x13160cc8bc504ea8L },
      { 0xcb3800784c96a680L,0x006fb9d8845faae5L,0xc6a642771e0e66d1L,
        0x13f77d6e428f526dL } },
    /* 48 << 217 */
    { { 0x9f80fe8c28474530L,0x5649a173db7fec00L,0xdeed5bf4d9cb05caL,
        0x14b1a3a9d7077c41L },
      { 0x4c2ed239096883ecL,0xd550edfe44ae671dL,0xb233e5dcf7b7362aL,
        0x32c158204fd464f2L } },
    /* 49 << 217 */
    { { 0x0ecb18f768880bf9L,0x53468bedaf230a34L,0xe3ba97b9370cd6efL,
        0xf5cdabf43516d77eL },
      { 0x08d78a5611462032L,0x1393fa93d583ccc5L,0x52af7f5d0c1b3514L,
        0xf48cac66188ca043L } },
    /* 50 << 217 */
    { { 0x2524c8dd5461a1d1L,0x6eee810191b6e707L,0x209fece6ca2fe87eL,
        0x50b357279ac56706L },
      { 0x651a6701ec373bb2L,0x881de85b1a4c2e84L,0x4892861dcfdb47d5L,
        0x5ae2e6535cdc4424L } },
    /* 51 << 217 */
    { { 0xc58f4f59a1f90dd9L,0xa5584f85fcf158a4L,0xbde86fb0ab072a7aL,
        0x7c69e25a268bae62L },
      { 0xee3478f344fc7b3eL,0xec1483946b7d3647L,0x2a542ebfe1c8c0caL,
        0x63d1d635161dc0c1L } },
    /* 52 << 217 */
    { { 0x769acdbe57ab9282L,0x9c3389712a119cb9L,0x049e366f125e5b4cL,
        0x3aec68e0f0c8fde4L },
      { 0x9d95b6e5324cefdaL,0x844cce33704014b5L,0x03920a616a6bb216L,
        0xd69d17e3f379db8eL } },
    /* 53 << 217 */
    { { 0x1924ac16c5e386e5L,0x62373a48d64953c3L,0x5b1f7d6447f4e4a4L,
        0xc043b5b5ffa115fdL },
      { 0xb2a2656e87fb16b0L,0xcac56b9bd8cd79a6L,0x544971f6cc19d3afL,
        0xf539244b0fd63db9L } },
    /* 54 << 217 */
    { { 0x0f052d3cfbf4d232L,0x6b3c83667a2a7280L,0xaa6579db48079b9fL,
        0xc5beb93da4d9edcfL },
      { 0x8ad588250f1599a3L,0x3f3a26345f3f640bL,0xda15393a9032fd7cL,
        0x97c10230ac0e7136L } },
    /* 55 << 217 */
    { { 0xfa32ef9f599785eeL,0xe1ed3b286b4c7a65L,0xcee1af272da1dcddL,
        0x4e480c116861e2c2L },
      { 0x35b5ec429c8ad8c3L,0xfd07f6a43fc55f23L,0xab18ead2ea76d444L,
        0xcb8bde1422ba099aL } },
    /* 56 << 217 */
    { { 0x252e6a81c61ae967L,0xaf11042c72a2e1e6L,0xb353902a1a211ef8L,
        0x644d16e0c99a25fcL },
      { 0x637fd6065b67e48aL,0xfa57096351a0b665L,0xaa661c737ee072b8L,
        0xde1eb4fef2e0a727L } },
    /* 57 << 217 */
    { { 0x56096a0c22ed7ee6L,0x31aaf4035825908bL,0xfd5f6ba7bfa02db6L,
        0x85f4f9a9ff798900L },
      { 0xa0997d564a0cd878L,0xdd76909cb1b6982eL,0x874fab15eccf338eL,
        0x5e072b3c4ce82bb1L } },
    /* 58 << 217 */
    { { 0x5dbe883f6dd0d997L,0xa32117f241765fb6L,0x59ca4da37d87fc5eL,
        0xc91002cdb95ec918L },
      { 0xd53bc1236548248fL,0xef10a3736c6d1e0eL,0xafb2d76099d9893fL,
        0xb77c1f1bce0ba0caL } },
    /* 59 << 217 */
    { { 0xabce362ccfb9f6b2L,0xe6e108d235f9be91L,0xb23312907187fa9dL,
        0xdcd1f4fdfc7ddce6L },
      { 0x3a1299919086eb29L,0xb073052053a56d57L,0x9fcdf4cfabd421bdL,
        0x9627127008f3e8e0L } },
    /* 60 << 217 */
    { { 0x951ea7e2401e0217L,0xa4d1d708733f637bL,0xc75170f44f4cd676L,
        0x568279ba832f0b4dL },
      { 0xda4c01f725c17ab7L,0xfcc13028fa30e1b9L,0x4d1d8f71acba57ecL,
        0x0c7971cfef6b3913L } },
    /* 61 << 217 */
    { { 0xdf16e73dc014f166L,0xd5796183f96f2c30L,0xd13ee9f73f70dd7cL,
        0x3f9aa0dddac738c5L },
      { 0xa200c7e4ad021e28L,0x982abae308414fd0L,0x76d16a8cc3779882L,
        0x41563d33e70a6ff5L } },
    /* 62 << 217 */
    { { 0xdbb9656e4b553a17L,0x96af21a0d9c87aa1L,0x2de13a037bd9a625L,
        0x29f8c49bfeb1fec2L },
      { 0x84e2df471a4ce44aL,0x83bb2965548b39eeL,0x38b91cce94d996ebL,
        0x41e0a3cd9441ae0bL } },
    /* 63 << 217 */
    { { 0x720d30d8daa92f34L,0xba58757906f30fbbL,0x24f746764c96ad59L,
        0xf40493f70d33bd5fL },
      { 0x9068c3e9126a7267L,0xa51099df18927490L,0x27452423a9cfe02fL,
        0xcfd035beb8749653L } },
    /* 64 << 217 */
    { { 0x0dd9bc2afda6a4a9L,0xdba0178a0106ae0eL,0x3820c9f54969a4bbL,
        0x5031e9fd99fbc715L },
      { 0x642a030ac193d942L,0xdc3d6ab7454cbb39L,0x507c17b91c8fa77cL,
        0x8465bcc8e3642a95L } },
    /* 0 << 224 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 224 */
    { { 0xe74e265bc25dfad3L,0xd03630b9493f44b6L,0xb3270892bfd6d473L,
        0x5b2d95431c5ee992L },
      { 0xeeb94537a36f7c5fL,0x9befc01d8ab0b81dL,0x483cdb08188b45e5L,
        0x44c753b701e4648bL } },
    /* 2 << 224 */
    { { 0xee43bc87b2411618L,0x08754bd2f07924c4L,0xef2050334ac92557L,
        0x6e7e4fe6ee0387f4L },
      { 0x51f3e2e276961d0eL,0x2b69d41737eac10fL,0x36d0f45f73757a88L,
        0x38b967e52b0c7d35L } },
    /* 3 << 224 */
    { { 0x94ba8fc4b31fa779L,0x8024dc850f13036eL,0xfda2af6382d754b7L,
        0x4a784242ae9ea9aeL },
      { 0x67dd14abf9887947L,0x7f2ecfc4cd555a0aL,0xb37c4244f63a46aaL,
        0xd032cfc1ff71b4b5L } },
    /* 4 << 224 */
    { { 0x0aef84c16b8a6a97L,0xd2e7f3de0b2bca36L,0x721c6c095b174d43L,
        0x5719cf31d52ccc5bL },
      { 0x6c7361f03adf9517L,0x1e264169abe20ff5L,0x01f9d99769eacc0eL,
        0x721eba63c2e635d2L } },
    /* 5 << 224 */
    { { 0x4225e9c825df8bb5L,0x931f721eb5752d7eL,0x3c4ed4750a3b281dL,
        0xcf9276824a4668beL },
      { 0x1b7f358e75b7e90cL,0x06e5c24db7a29b9aL,0x0058967aa167f2c8L,
        0x9f1a6fb9a4ee62d3L } },
    /* 6 << 224 */
    { { 0xca899c4f278291f1L,0x69a90324f4e64c1dL,0x46cc5d428d62916eL,
        0x3c802e65ec1007ccL },
      { 0xdadcf2aa6219cfbbL,0x942870dcd10258b2L,0x77264e68a5e142afL,
        0xf25675e2089cc7a3L } },
    /* 7 << 224 */
    { { 0x177e8a3b7336aa16L,0x5a92cc2dbc5c622cL,0x33a35a2c1789e029L,
        0x6f91306e4e4d5573L },
      { 0xe5a2a581da0a46f5L,0xfb532bed42640bbaL,0x88ff0f114a7b3ae4L,
        0x2223e7b6b8ff7a71L } },
    /* 8 << 224 */
    { { 0x759331335d21d261L,0xa336289acabb1fbdL,0x797db2f3631b3b61L,
        0xc2cedb25d7e6a511L },
      { 0xb8806f3410355332L,0xe5f1fb4a5d0ae37fL,0x57cf26a55d17c5c7L,
        0x82e8df4768c43ec3L } },
    /* 9 << 224 */
    { { 0x70fa23ebf86bd784L,0x711a9dbb51b0ce75L,0x83bb4a9082170008L,
        0x8f096ee9630602dcL },
      { 0x7d275fc97f15e77aL,0x63516a6afe727ec7L,0x6b06827a1dce9d38L,
        0xa01a5382023b31c2L } },
    /* 10 << 224 */
    { { 0x12537433886209b8L,0xb7875fa8c5a11b32L,0xfa63cb99bd61176dL,
        0xebb204ea33378ebbL },
      { 0xf29a29a070c135f6L,0xf53941e9fa29d69fL,0xab97b39a9917da42L,
        0x4677cfea45947ae4L } },
    /* 11 << 224 */
    { { 0xd4668cff0f6dd908L,0x48bb09ed987e0769L,0x794ed2988d64b6fdL,
        0xaf89d530fac845daL },
      { 0x574456492d06e70dL,0xe2a1a8c2079e70a7L,0xd2ef1779f524fc03L,
        0xeaccaaccb137bb1bL } },
    /* 12 << 224 */
    { { 0x34d8ed875d279f42L,0x4dd5344c1cd68904L,0xb558b71d24abd550L,
        0x3728e85040df135eL },
      { 0x9329e2b2cfe86519L,0x48ad17fbac74cde2L,0x2ad61b2230b388b5L,
        0xebcbc1adfaea71e1L } },
    /* 13 << 224 */
    { { 0x50d7b19e35990d9dL,0xb17138e56eb70243L,0xb61618f6aa8ae7e6L,
        0xedee15b0abce12c6L },
      { 0xa99ce250cc7205fcL,0xe438efc969e0d75cL,0x1feb6a105084b390L,
        0x7b3489549c80d42dL } },
    /* 14 << 224 */
    { { 0x67ac89d5e4b68140L,0x34afd23bc9b092afL,0xad65cae9fe1ad661L,
        0x4f402947e02d884cL },
      { 0xd0a48fcc6b1c40c1L,0xf950c9f78961487bL,0xdb1cd811206d1752L,
        0x863b0dede99fd891L } },
    /* 15 << 224 */
    { { 0xd3aad8c2bb2a4515L,0xc93c8cb8797e223cL,0x0f471e4912a77d46L,
        0xa2ac9434600872b6L },
      { 0x6fb1c7ef915f730bL,0x9fb72401d254d363L,0xf521e33a6b44796aL,
        0xb7ed2e8d97c9fafbL } },
    /* 16 << 224 */
    { { 0x60d41128ffb5e7ceL,0xdbd8b542aecb96c2L,0x029ab3dd0b5ca788L,
        0x8b1148a2190eb38cL },
      { 0x59048db869fb1924L,0xcd2149f0b18391a8L,0x6bece5b6fed311b9L,
        0x5edbe9b99ffd29b9L } },
    /* 17 << 224 */
    { { 0x538105561156ded2L,0xf812ce5d721f3e68L,0x50504d407ccdc8cbL,
        0xb559ba08c60fa4fcL },
      { 0x862a83d91d6bd879L,0x2f8f653b836e26baL,0x8587e6dfeb26ca11L,
        0x127bd9058c8aaf7bL } },
    /* 18 << 224 */
    { { 0xe26e690dd67d9902L,0x1a6061f4b58e7e78L,0x960ef741480dd4d1L,
        0x7fd0973675589610L },
      { 0x5a20a1a2855a8b2bL,0x3ed68662355b4e0fL,0xd3786f45e76595b4L,
        0x72a6999d0bdedcfbL } },
    /* 19 << 224 */
    { { 0x4e48e8436a175646L,0xde53c427e05dc02dL,0x9728a4c597d31bc6L,
        0x01a071295bb3bd37L },
      { 0x83c08a98a74a0fccL,0x233e400fbc345df8L,0x9578c5f2cc3e0edbL,
        0x0fe89df2f144a31fL } },
    /* 20 << 224 */
    { { 0x308098a014c5a2ccL,0xeda5a59dba40c0bcL,0x0b10f7e0b718a5aeL,
        0xdaf7da8c5b8ad9baL },
      { 0xddc7128587394cdeL,0x9bdb27cde43458d3L,0xc698d9724bd7c11cL,
        0x2ee97fbc3540be14L } },
    /* 21 << 224 */
    { { 0x2c70499572f98422L,0xfc71fee2ef8661c5L,0x6574e022ce08043eL,
        0x3d17162e5143733cL },
      { 0x3bf0b448730e5b80L,0x56de346a7cf94b5eL,0xfa87a53e6c797797L,
        0xe8b9edfa6487d014L } },
    /* 22 << 224 */
    { { 0x09e743877be60b03L,0x2277ebc3ec8750dbL,0xf1e9d5947aeaa545L,
        0x4156456244c03394L },
      { 0x57943adc4de9f7ecL,0x09dd58f92a220cd5L,0xdf848ec806973808L,
        0xf1d5def1d3950024L } },
    /* 23 << 224 */
    { { 0xd089eba55a8707e5L,0x914046cbb0b90ebeL,0xb01180b263fe6bc2L,
        0x1ffbc9687ede9d83L },
      { 0xe16d336f3c52c09fL,0x32270ecbdf40338dL,0xb55ff5c67eec7039L,
        0xb5ffb31438a63fabL } },
    /* 24 << 224 */
    { { 0x3e9f284fee18ffecL,0x702d97f51d1b4e80L,0x2005ee57214c4da1L,
        0x1c2104132f5ea2f4L },
      { 0xd24a486ca4149949L,0x3869a33923c8e201L,0x00f6e4100149992eL,
        0x54e97b46f0a367ddL } },
    /* 25 << 224 */
    { { 0xd967726ce169de5cL,0xa3e81f936a0fcd03L,0x171faa9ddb1b1733L,
        0x0bbb5e913828e41bL },
      { 0x789a7b2ef0828387L,0x9465cc16fca60b9bL,0xcb58e90aab630d23L,
        0xe7d30293a339d4b4L } },
    /* 26 << 224 */
    { { 0x0bcac95818e75428L,0xd2f1554a9a95900aL,0xc63c2afb03846833L,
        0x703d02206d1e8753L },
      { 0x47f5fe5704a357a2L,0xaafba53ecdc17255L,0x8f94c8eb821af8d5L,
        0x4d9918bc35e37920L } },
    /* 27 << 224 */
    { { 0xc029bd84e32dd067L,0x25982357f77f8962L,0x7af256ca510b7cfbL,
        0xca397f37446925d7L },
      { 0xb3dc7be5e0614e1eL,0x3b64cd27bbc4cc93L,0xbd762df5fb99bbc9L,
        0xc1ef0d4d04d7177fL } },
    /* 28 << 224 */
    { { 0x77b6d3d665e75ed6L,0xbe59c8da53053b45L,0x054d089f54fe92ccL,
        0x2f2327e06fa4758fL },
      { 0x948cf03f5d2b5a01L,0x47544c4c9c23b83eL,0x338590fa6c128d69L,
        0x5724008d76842160L } },
    /* 29 << 224 */
    { { 0x4cbeb18ec4f063e6L,0x507ba0949c2f826cL,0x0e877a6e6f4e49f3L,
        0x050c204034f56868L },
      { 0x8fd667c40f119e25L,0x881dd34d13b47d3fL,0x2a6b636dca8e9a6aL,
        0x67b081fb107ea18cL } },
    /* 30 << 224 */
    { { 0xd3a4636784af55d9L,0x0e709a00d7626b67L,0x135725fa4c6dfc8eL,
        0xbf6328d9133a6e20L },
      { 0xa4b743b4a87031f2L,0x62e90e6713825d07L,0x7004028eb85f3c45L,
        0x0465c50211751be0L } },
    /* 31 << 224 */
    { { 0x4d5d467f8a5ab076L,0x9aa3f414f4fb8a45L,0x9fa0422e5dc1fa84L,
        0x3205c05fd02cfd2bL },
      { 0x3eac28fa078836b6L,0x53bc0189fc3ff573L,0x2c45ef0900b02100L,
        0x61bc02ae34360ef7L } },
    /* 32 << 224 */
    { { 0xeb5593e7532e8d6aL,0x94092904f02a1ee4L,0x379b32e8200496c0L,
        0x46fb6e9e360a27c8L },
      { 0x8a3377ba62005158L,0x1a3266c10de3f191L,0xe60fad96c94d2127L,
        0x41553dd1646302f3L } },
    /* 33 << 224 */
    { { 0x88bf0bfa377e0766L,0x870a24dbe75bf57bL,0xc133cb4979e77976L,
        0x2f14924df43b6f18L },
      { 0xe561dc90aa94cd73L,0x8c420eb2d6eb695dL,0x99e41ba82f04ef79L,
        0x7f427bdf71e6d054L } },
    /* 34 << 224 */
    { { 0x7304bb2510bde8ceL,0x5dbc4325e48b16f8L,0x47d17ab28796db7bL,
        0x8342681794c77832L },
      { 0x6781850e9878ace2L,0x7f747b90019e97aaL,0xa0545c85949f9b08L,
        0xe0a0bbf8244bc083L } },
    /* 35 << 224 */
    { { 0x8cb53666a1f38ea6L,0x9be29ff64989a568L,0xbc5a7f87083a7fcdL,
        0x90d0129c44ca10f6L },
      { 0x1ad274bbd724b7e2L,0xa5290cbdcad5f069L,0x886b1a7c86a4e0a9L,
        0xd2481b5a8d8fb13fL } },
    /* 36 << 224 */
    { { 0x80075fb24f606ac5L,0xf984b5a2bfc10e7fL,0xd3d91aeaf056142fL,
        0x770bee0b4afdc017L },
      { 0x3c42ca886c49c827L,0xb620c4e80aaa3139L,0xac6b512dad87890cL,
        0xaee62df70eb61f92L } },
    /* 37 << 224 */
    { { 0xcf0f37fc21dad9ecL,0xd780d315c52e24c1L,0x0263bcab23a2b699L,
        0xdc8dcd2f9714b577L },
      { 0xeb16eca855622b11L,0x94b3d64901118edfL,0x6bafea64ec66879dL,
        0xc35739c0c4ab9f48L } },
    /* 38 << 224 */
    { { 0x082ccf53f3232370L,0x01b55dd371407825L,0x86e0fe944f7f4038L,
        0x1a623675b04159e9L },
      { 0xf908ca59bc4df337L,0x1b4f1ffe816162ceL,0xb51289522d60e05bL,
        0xb47ca0ebd38cbdf7L } },
    /* 39 << 224 */
    { { 0xdccba22f8ee38219L,0xc94364539fbb36ffL,0x83cecbf58ac12c9dL,
        0x591191b5f4cb1ebfL },
      { 0x693cf383f03c1632L,0xaebd3f9bcb6abacaL,0x1427c1540fa26e7aL,
        0x4f0de89401bf37afL } },
    /* 40 << 224 */
    { { 0x4e497acfd88da2a6L,0x8014a215e5c86482L,0xa627d78fcf94ee40L,
        0x7647708d9ca36aa3L },
      { 0x3d4e8bb187e108c8L,0xacdc3223516f8b28L,0x74e4d4361d955038L,
        0x7e4a198cedd68905L } },
    /* 41 << 224 */
    { { 0x41dc4bdbc4bfbad1L,0xfd1121b185964942L,0xe462eb9c0c0d85ffL,
        0xade1ccb32b012d88L },
      { 0x2eec3503318f2aa3L,0x656b44dadec8a13eL,0x90b7aac8cda13a8cL,
        0xe7f3a5ff214a530fL } },
    /* 42 << 224 */
    { { 0xa0c8062a159060b9L,0xc19f2608d9305873L,0x0d6213c4c9609521L,
        0xde2b91349aec4539L },
      { 0x4a2a6476aeddf0a6L,0x89222dff5cf2e85dL,0xad92a1d3084a0245L,
        0x29644a602138063fL } },
    /* 43 << 224 */
    { { 0x5b57a05bb8164832L,0xecf6620f885ce4d1L,0xde28ed2f045d3b88L,
        0x3eb11759b4502308L },
      { 0xe97f1db24d9f94b8L,0xfa248583eb83f016L,0x63a273b4cda53ba0L,
        0x9692973aa228b7b9L } },
    /* 44 << 224 */
    { { 0x5968cb12b6707cbdL,0x1895ccb45c1a2b4dL,0xff30915737f0b240L,
        0x374d983eb90875c2L },
      { 0x22fc40c6c4e815e7L,0xf2db27be98d18506L,0x2854a948aa9ae62eL,
        0xd614a72279e39df1L } },
    /* 45 << 224 */
    { { 0xebeec551b3501c19L,0xe2b878ebd89cefcaL,0xa0a347576b4cd6bcL,
        0x0159129c70bfdf88L },
      { 0x26fa3e53489502caL,0x7932084f285be050L,0xfe4998f471912b0cL,
        0x3dce0a87c60b88b7L } },
    /* 46 << 224 */
    { { 0x5b93edb0c718ee5cL,0xb93a225fbb075836L,0x87a08c947aa0595cL,
        0x401d2620c31e3249L },
      { 0xbe6928b4dae2cdb9L,0x4b68e1065a226630L,0xdc38c2fcc9d32e4fL,
        0xc51a624526542f89L } },
    /* 47 << 224 */
    { { 0x5fb37c1b1757f3c4L,0xa27d6c0289128aa4L,0x3b74f56f5e629309L,
        0x24b5ad842f7aeef2L },
      { 0x54a962ccbdc89596L,0x6e8bccf8cc2f3d5dL,0x4c1df22c312e9241L,
        0x8ffe6b0dfc30f0dcL } },
    /* 48 << 224 */
    { { 0x670431a2a6ec0fe4L,0x49da0b4235964572L,0xbb12d1b09dda5c39L,
        0x64170fe172d3de51L },
      { 0xea8b2b16a4a2f5d9L,0xde1bad64e590be92L,0xb7f93581f0b9b0b5L,
        0xb007f4dde115d67eL } },
    /* 49 << 224 */
    { { 0xab9d7523415732d4L,0x2951149d905ec0feL,0x94bb2c6374350478L,
        0xe6b63bfde9b1ada4L },
      { 0xd09b4d4b13e8528fL,0x6bed3d25685bf239L,0x83023ad91a14b7ceL,
        0x4bffff63d0505d6bL } },
    /* 50 << 224 */
    { { 0x2ccc180a8bb1cfa0L,0x70c185083a09c912L,0x318c41c25878201cL,
        0xb9f207b164c01149L },
      { 0x89fdd9eec58287d9L,0xdb6fa8db05c43da0L,0xc31354f0311a34a1L,
        0xccfbaddbf1521976L } },
    /* 51 << 224 */
    { { 0xf4175f750c5e8388L,0x7e090ce8a81226cfL,0x5209107eeda6a1abL,
        0xf0a263cb7e5ccefdL },
      { 0x9fe05a3610c704a1L,0x3784d7cacf133aeeL,0x066c311637af86c8L,
        0xbf32ca04d7ebeb8aL } },
    /* 52 << 224 */
    { { 0x0447a950a9b5bab4L,0x3b2f98bd41bb1f1cL,0xd89bbdd759c62f08L,
        0x26bab3703ded069bL },
      { 0xb0db4ca569ea63aeL,0x57b32f329133df68L,0xc79a22d05a17efbeL,
        0x576976a3f8ae3c2dL } },
    /* 53 << 224 */
    { { 0x5754198b9d02d212L,0x9cc9e61e230d0213L,0x7677217992889e33L,
        0xb1246608f5df6cbaL },
      { 0x821766bc8d491280L,0xe148f47096bd3df5L,0xc1e9fc70ed753b73L,
        0x840e40edd6cecfc5L } },
    /* 54 << 224 */
    { { 0x0387467993e2f3a0L,0x462e5abf5b646b64L,0x6fb19edad7ae0e67L,
        0x01e8a27fc3d2dddfL },
      { 0xc9e696394bacfe2dL,0xbc3a134e712e8afbL,0x5d943a868af6d30fL,
        0x65eb5f99443c942cL } },
    /* 55 << 224 */
    { { 0xf50003082339e348L,0xd69b7693eb0d80e6L,0x7b00b43b5b9d220bL,
        0xde0dfc80497bbcf9L },
      { 0xcfe2e3f30c2e851fL,0xef7793d17e91d378L,0x9e43eeac9d266a5bL,
        0x9c81d68b1766c5c1L } },
    /* 56 << 224 */
    { { 0x121db320f6a4d560L,0xcd0a4f03073582a7L,0xbf469f9a6e841041L,
        0x4314f0f65eb2d753L },
      { 0x090210018c498414L,0xf63d00ee859275b7L,0x228fa809f1c0385aL,
        0x44259d51694c3318L } },
    /* 57 << 224 */
    { { 0xb0a5d5fea2ad4eacL,0xbb950010abdedf11L,0x081024ce6264c601L,
        0x6cc7faf2aefb4115L },
      { 0x905112898692a7a4L,0x2bef413560596012L,0xfec5209a0f0becb6L,
        0xad0907a6d1ceb42eL } },
    /* 58 << 224 */
    { { 0x6cde3f21f517372cL,0x9acd4f0926131459L,0xf3629a43491f59d7L,
        0xe944561a41a037ddL },
      { 0x07beeabe826d1b5cL,0x0728a9073a1476cdL,0xa91f41a07d4a1abfL,
        0xdf58ed06a7a119c4L } },
    /* 59 << 224 */
    { { 0x19990669ba701704L,0x8aa3f76b47b67175L,0x8bccff3edd0a6e9aL,
        0x4173fcda24f49029L },
      { 0x2a68891161c18233L,0xdf54b23978b9fa8fL,0x714cf62737596f40L,
        0x2c73ddba24e6a879L } },
    /* 60 << 224 */
    { { 0x1538fd36f2547f19L,0xd85c47300e7e84eeL,0x00799e9f306f5fc0L,
        0xfccc6a3749ce114cL },
      { 0xf9cff5e83fe08120L,0xdf876a1fc2be9f27L,0xe817c72e6939fdb9L,
        0x244a1800d34d0e43L } },
    /* 61 << 224 */
    { { 0x41e83eef78fa7f11L,0xecaa250cba6367e5L,0x9c4203478def6ae6L,
        0x99efb3b1250b9e58L },
      { 0xdaf311ee79b2298cL,0xb49200cf69b6dff3L,0x5c7f17bb559e51f5L,
        0x117d0cbe424be7e9L } },
    /* 62 << 224 */
    { { 0x290a35c436e3af54L,0xd2326cd8e3a643b1L,0xc208b2b33580f9eeL,
        0x2419c6614464a9e0L },
      { 0x87123d3abccb2759L,0x5d36fcf31a77d469L,0x5aafd58a49b07e5aL,
        0xf534595b6b71e237L } },
    /* 63 << 224 */
    { { 0x0f0d31616705039fL,0x7282b08cca701676L,0xb05e8c3e13796941L,
        0x5250012efca06e08L },
      { 0x7eb2341a980c5ea3L,0x92f5aeb1a41defb2L,0x203244e00e62453fL,
        0x7434121896181756L } },
    /* 64 << 224 */
    { { 0x3b0cd36fe12a94abL,0xf364b3b9b5ad7c48L,0x96a7a2a78e768469L,
        0xccc31c7e1bbc7cc5L },
      { 0xe70ad5d0080dbb92L,0xfb201e9256fb0f1fL,0xdfce7a1e29d99f57L,
        0xc12a02b006457da5L } },
    /* 0 << 231 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 231 */
    { { 0xdea72ba62a80f39cL,0xcb2174b168cbe088L,0x9c73ec69d6bd1cc1L,
        0x6a2dbe20f20dcce6L },
      { 0x20a5150beeaae9daL,0xc935e85d9df630daL,0x2147144fa1634cd8L,
        0x5eccb56c44f3af02L } },
    /* 2 << 231 */
    { { 0xf77a79cfc0e2b70aL,0x2569c8bcee8cbae7L,0x392a5dbefadb18fcL,
        0x59bc96b43ce6a0ffL },
      { 0x287f04f48b551005L,0x7efe3aa5a44b2bd8L,0x0e9cb8ed6ac447d7L,
        0x9b4eb10a7783bdd0L } },
    /* 3 << 231 */
    { { 0x793c4880b981d96fL,0xf719d828d56fb2a6L,0x9fcc236f8149057eL,
        0x318c63ecb4d65c2bL },
      { 0x5269c1d75f95c5deL,0x33b3745fd0efd6bcL,0xace344d54ae87c64L,
        0x238809d6dd30ba2cL } },
    /* 4 << 231 */
    { { 0x3cc32acc71192348L,0x545401bf3f17ef60L,0xe209a493cde25b0eL,
        0x5c11886b663abab9L },
      { 0xe61a81b128ec7c90L,0x18b125a675b57f5cL,0x86d1b45afad91696L,
        0xb31a786da4c3f7ffL } },
    /* 5 << 231 */
    { { 0x2fd4cd72f45831d8L,0x85978fa68be40d9fL,0x38106329a9301111L,
        0x1527e4629e5979eeL },
      { 0x97f71c7e76c5fc8aL,0x205fa473f1f33056L,0x7bb9d24ea6546a05L,
        0x0e282a5cf84c4d35L } },
    /* 6 << 231 */
    { { 0x59d2189659471f1fL,0x2e613decf6303573L,0xa799579478bf5a4bL,
        0x20adf6b5bf19fbe5L },
      { 0x3a48c95f1574d34dL,0x95488f0909323cebL,0x450aee7f552df9cfL,
        0xdf016f7a53557500L } },
    /* 7 << 231 */
    { { 0xf2acedc62da8a2a6L,0x03fc8cf82f4a0632L,0xe7ff136b5b82f03aL,
        0xd5841c4d9e88c421L },
      { 0x75a4d66f7eef63f0L,0x92091ade2865c14bL,0x7060474c64fe7ba3L,
        0x4056724cfe30cb3eL } },
    /* 8 << 231 */
    { { 0x38cf4c6f8d9fceb6L,0x11e85f78ab528f38L,0xe2896d2552303b2bL,
        0xf929675aed68c605L },
      { 0xfbd2237410c708a9L,0x4682ca1740d7e5a7L,0x4242b5c59041047fL,
        0xaf5710530f9c6840L } },
    /* 9 << 231 */
    { { 0x713b2bbba56af433L,0x45aaf2ce5e82f947L,0x9882571a106283c7L,
        0x37de12ca9b9c3c3cL },
      { 0xcb463af2bef10529L,0xe18d763dd771236cL,0xb47a69ca62935de3L,
        0x4798e91f9a41e09aL } },
    /* 10 << 231 */
    { { 0x896966978e93edd5L,0x35cdb8e1b7ea4f45L,0x36f8305dfed33d87L,
        0x57623440625642d6L },
      { 0xdfd9b580945dd7d6L,0x965ffcb5731739bcL,0x34588e1f637bf127L,
        0x936c0ba0539d21c7L } },
    /* 11 << 231 */
    { { 0x7083209971640eedL,0x916b19523ff407e3L,0x4cd5888188440bc0L,
        0xd9fcb83dc280e977L },
      { 0x0d3df9dbdf6cda83L,0xc629414e3d55047eL,0xe05738a8c16b84c9L,
        0xf4bdc724e8783570L } },
    /* 12 << 231 */
    { { 0x7d876a599a93a5c9L,0x026be75ca8d12f61L,0xe49900ede9b2aa43L,
        0x44d6dc80b3a68dadL },
      { 0xf96b116b7d23e11bL,0x12791212b6814209L,0x3e2807cf6cc65956L,
        0xcc606ca7f405ffaeL } },
    /* 13 << 231 */
    { { 0x5484b2c55df47226L,0xfbaf90428802da81L,0x84146315087adadcL,
        0x6adbcbc158d593b3L },
      { 0xc1fb389668b97533L,0xa6919aac954cc1b7L,0xf301b2e427a4ddd0L,
        0xa15c16ebdf1a07b1L } },
    /* 14 << 231 */
    { { 0xb36c017dc145a6c7L,0xcca64382968798daL,0xd13b63768d0eff5dL,
        0x06e39e2d2206e681L },
      { 0x1d9dffa43add517aL,0xe670e6c810d95fefL,0x0ecb51abf1c7c7a8L,
        0xf17dff5174945305L } },
    /* 15 << 231 */
    { { 0xf71b09b1b00d9c0fL,0xc719cf629c72c80aL,0x310c5aebe00a49a1L,
        0xd01285e51b33c5e6L },
      { 0x7b23e7c705aa6eb7L,0xf84188b16bc88677L,0x7e034cb564be321aL,
        0x270df734e884323fL } },
    /* 16 << 231 */
    { { 0x218e68f9e5137d20L,0x79588cba0f7e70adL,0xb6d37f5258b86b0aL,
        0xcb281c987cc591feL },
      { 0x30e03fed8fe40e06L,0x394ded95ed9ca793L,0xf1d22cddbcd3a3daL,
        0xcb88cb270c591130L } },
    /* 17 << 231 */
    { { 0x67786ba38ff0cbf4L,0x85738a440565d337L,0x9d3b35ecaf9a667bL,
        0x45a175128f5f540aL },
      { 0xf1ae5171ade5a5baL,0x720e282339869be4L,0x6893f14a5352d84bL,
        0x919a4f15c784dc20L } },
    /* 18 << 231 */
    { { 0x36136612f7ae5a67L,0x11f43d1ceaff0924L,0xcfee088c39449b96L,
        0x3dc4835970c42ff6L },
      { 0x4072683abf208b67L,0x35a7c2bebe15d18fL,0xe61d2748e2c3391bL,
        0x0a4109b139921d95L } },
    /* 19 << 231 */
    { { 0xe2cd131b05545cfcL,0xa898da2c3ae20d7fL,0x501cd84950dc4c61L,
        0x10e287d43374e7f0L },
      { 0x90d6326f38aea879L,0xc48d9af7ef43fa08L,0xf8f4886a6c20f168L,
        0xc5d34a8623ccac4bL } },
    /* 20 << 231 */
    { { 0x72357752b3d7004eL,0x167db0ed817bd377L,0x5d45b3dadfb64d05L,
        0xed4b7fc4f0b414acL },
      { 0xc178941b0bf1dd64L,0x43feac178fe835a5L,0xe1c23a176a014609L,
        0x63255991d5e23bd5L } },
    /* 21 << 231 */
    { { 0xefc76468d7dfec55L,0xb1bc3feec0831696L,0x0996811b5f52433bL,
        0x6b8b6daa799649fcL },
      { 0x6e9f7cb6ab518b64L,0x6a67a00938a3a2abL,0xe55de954928209e2L,
        0x98b6d0a73da81142L } },
    /* 22 << 231 */
    { { 0xdec30331e3f832e8L,0xa9b77f3be50fa9e3L,0x20febc215167c6a6L,
        0x0ce07d1a76fb0f13L },
      { 0x9745deade796f8a3L,0x2cb4eb1fd95deba6L,0x062e7cac4caf2afeL,
        0xf50ce06516ace879L } },
    /* 23 << 231 */
    { { 0xdec8954b1d99d3e7L,0x5287e954a48262c7L,0x1c6fbd17cc3530deL,
        0x6bcbea5053af4211L },
      { 0xe3533bca4dce058dL,0x6fe62e64fc9cdf00L,0xee29fdece8ec4cf9L,
        0x7361797dc8d52f80L } },
    /* 24 << 231 */
    { { 0xb1d858daf4e36023L,0x4a1282ce73e6dee1L,0x6ba8f8bace1d71ccL,
        0xf5b7d6b4cbbd8eb9L },
      { 0x60f8bd505aed382bL,0x47b405193f3a46b1L,0xaed13bb98a997d93L,
        0x6cc2260e4dc6e35dL } },
    /* 25 << 231 */
    { { 0x173bfcddccf915d9L,0xad4525e1c2d46f6eL,0xb7ecec0bcdd2382bL,
        0x01ae8291d2b76c84L },
      { 0x2d1e2a91bec6b980L,0x1b0040be7008a00cL,0x6ac708d77d555120L,
        0xa60175680d745eefL } },
    /* 26 << 231 */
    { { 0x735e35111ed38ef4L,0x7c97f284cebe5a8cL,0xd405931324fecbacL,
        0xf874ca4bde18c42cL },
      { 0x9ab736a8dbb829b6L,0xe914bdde82ff128dL,0x6e949babfd0f362bL,
        0x275824cfffea2e79L } },
    /* 27 << 231 */
    { { 0x81f572458cc52417L,0xed0a90792f274090L,0x98c3372efdd0ba2fL,
        0x49820f413ae99478L },
      { 0x1c47e09fce373d3eL,0x875d79206dd12846L,0x7a9e797315d5bbb1L,
        0x485126566d227962L } },
    /* 28 << 231 */
    { { 0x2c167c88199241e3L,0x98c1df6a7209ca37L,0x09a1583fde89e412L,
        0xc19ed5b9c792de48L },
      { 0xb8dd1b1d74dc0834L,0x9d458529a04456e9L,0x66ef5463ad0ad39dL,
        0x8d7df4a1e641edc5L } },
    /* 29 << 231 */
    { { 0x97815de26bd322e4L,0x0bf6fc83c1f77fb3L,0x493781678b4f7152L,
        0xfdd476efbf0a1712L },
      { 0xe87e1977f2f9883aL,0xdbb2fcbf9ad2d034L,0x5afdd16164e1a4c6L,
        0x0e43f9113e435191L } },
    /* 30 << 231 */
    { { 0xde2d1ee642253804L,0x6def6cebdaf13e57L,0xae09fd4f05423babL,
        0x6f6c17b8ad46e409L },
      { 0x966fa09d6c345cd3L,0x6c8aa1e947abc35dL,0x02991686e015a566L,
        0x39b3aeeecd2f925dL } },
    /* 31 << 231 */
    { { 0xf9cda92a9119c117L,0x7b21ce82f4f833e1L,0x87517bf5e4f99193L,
        0x1b7ddec94eb412f9L },
      { 0x7a30dd576b077498L,0xe060625f0ec44230L,0x0f355dc4b0e5446bL,
        0xdf324d65bbd2df28L } },
    /* 32 << 231 */
    { { 0x28c7eb34649966a5L,0x97587f4f26639e19L,0x0724cc000bce0f38L,
        0x63578add4ae6280aL },
      { 0xf1beaa57c7fd6a1aL,0x83b1a5337b017e35L,0x01c027e3efdf2ed1L,
        0xf373d4ead2d31852L } },
    /* 33 << 231 */
    { { 0xe568acb665b8f5d7L,0xea8ce1b81240a545L,0xb95b0db2555fac44L,
        0x01d18170768333dcL },
      { 0xf938b55eab1798adL,0x73a0d9dd999a7e5bL,0xd2359bb557fd9b51L,
        0x20f1d4fd77fb4e5eL } },
    /* 34 << 231 */
    { { 0xf5efd71f932dc388L,0x40f8681921a37385L,0x05395fb2ff935ef3L,
        0xc2ee43ac1b615e8eL },
      { 0xa3bb6518e82d509aL,0x3a87d5a230b93347L,0xac0a5ad05b130bccL,
        0x91fe8fdd9154d73aL } },
    /* 35 << 231 */
    { { 0x677d7d48deb203a2L,0x4d4108fe8b0168e1L,0x16be4ad1ddc3d24cL,
        0x9b0ea3879865df69L },
      { 0x16daf9324c50ec70L,0xa4799bda478c96a3L,0x4ef24d3f7114d3bbL,
        0x30a3150946e6bbdcL } },
    /* 36 << 231 */
    { { 0x6013718797f3cb4bL,0xf2b66d8f0a29d865L,0x93a4a37a60064a5cL,
        0x7dee9bede8c3cf47L },
      { 0x748833ce0b7ee8b8L,0xc07f2f6d56f89483L,0xd71a40d8d24b406fL,
        0xbe3b2e8febbb7655L } },
    /* 37 << 231 */
    { { 0xa23c2b054a536998L,0xdcaf45b3a9be2e14L,0x515ad15ffe346ad1L,
        0xb9c06a18b7847640L },
      { 0x8552eb06f35bff4aL,0x4fb792e72b7a29f5L,0x1cce2af5a41a38b4L,
        0xde68bd0d02b42414L } },
    /* 38 << 231 */
    { { 0x8124d6e27cd66728L,0x5906d1b455efbaddL,0x7e17855a827f2741L,
        0xab525dfb12c6966cL },
      { 0x065ae99a758e0cd3L,0x0dcb8f5d517318a9L,0x4875664542441f5eL,
        0x03859154d79d535eL } },
    /* 39 << 231 */
    { { 0x99bb28cd8217e4bfL,0xd6aed2e58291e54dL,0x8f9067e31c92a65eL,
        0x120890ea1540b9b5L },
      { 0x227d7c86ec60a215L,0xb6609e85556d8c65L,0xa6a26c3747f8c8a3L,
        0x4c850fe3f1204bdcL } },
    /* 40 << 231 */
    { { 0x25f7e61a42db4eb8L,0xfdf055753d62869dL,0x8b36a74452b31c23L,
        0x83b83c891a5e8d4cL },
      { 0x72d38dd35d9208bfL,0xbeb8873b8cf7b6f4L,0xa3ec5c36cf90bcb6L,
        0x35adda6f9a6d5fe7L } },
    /* 41 << 231 */
    { { 0x7312423df61c68d9L,0xb1c4e10f20bcaf77L,0x4df2850df168ee57L,
        0xed07a4de180985e1L },
      { 0xcb353d6b2fba1f23L,0x00ea9094778cc15eL,0x4967faaa20857170L,
        0x9ff70dbed7153bc4L } },
    /* 42 << 231 */
    { { 0x49eb799459f62fc6L,0x5f459faf3c91862dL,0x1c10f62146d8f2e0L,
        0x7e669c9a252954e7L },
      { 0x4ccf659aa83f6c57L,0xdc2b77ebec0a0a03L,0xcf09ad072cc6b8a2L,
        0x231960fca97aa2d0L } },
    /* 43 << 231 */
    { { 0xc0609130de227de8L,0x40d2691cf1d7ddf1L,0x60349cf4f9a73890L,
        0x3f50005df9968132L },
      { 0xb4be853ef16f44b9L,0x48bf4804799caac5L,0xe6a648763c562849L,
        0x2f4d487f854f283fL } },
    /* 44 << 231 */
    { { 0x64b77e39159484c4L,0xd419d4bd523e1529L,0x1bf9510c143dcf7dL,
        0xa85bea71ed5cb4e1L },
      { 0x73a4cfd2ec715818L,0x88b11d0e67f475f5L,0xbfe170d84d12361cL,
        0x9fc48e6400a0f979L } },
    /* 45 << 231 */
    { { 0x6a8bb2dd65682105L,0xc1362a9c00bd952aL,0xef5b3d89a6013753L,
        0xc87bbacb8fdfa22aL },
      { 0x74fbdfc031bb19e4L,0x7d05802932bfe260L,0x54a4cce4e53da990L,
        0x01acdff6822da672L } },
    /* 46 << 231 */
    { { 0xd2a2d48495597766L,0x5960ac1fd43dc7fdL,0xcf095b6f8d6db685L,
        0x87232088a85618f3L },
      { 0x91497a4834753c7cL,0xf682e372d6353024L,0x7889ceda0c9b271cL,
        0x7126504e18340951L } },
    /* 47 << 231 */
    { { 0xf786b821967c8a60L,0xfce01b37c17f3d99L,0xe23c00a11f2a8575L,
        0x7f56aa1bab6ff8a0L },
      { 0xdb73869dd193dfcbL,0xbec02c94d644733eL,0x283117bcf7b43261L,
        0x920acf5db4108e39L } },
    /* 48 << 231 */
    { { 0x33f1ef5ee49aebb8L,0x9ead51e40fcea2c1L,0x1f800a68f8503f28L,
        0x7881853134a75f67L },
      { 0x1aeb3760b70ffb27L,0x1cca590acb6309e9L,0x8d09f3607170d241L,
        0xbc970b5ba0e0d0f8L } },
    /* 49 << 231 */
    { { 0x2ec93eea31d038a3L,0x3482a0d75153f8a2L,0xedcbe9146641b5d8L,
        0xc086e61be516e387L },
      { 0x038142669b875513L,0x6d37fee337340a4fL,0xcf78515ee5d17ab7L,
        0x0c7cd8304119a759L } },
    /* 50 << 231 */
    { { 0xbd49062b54924618L,0x34c44f4541e7e7a3L,0x0039f3d2706bd0afL,
        0x146cadc60be9a628L },
      { 0x6d5d502057d48746L,0x0ea43f7b82caf4b0L,0x11a089278a064d34L,
        0x30c0ef4095638fa2L } },
    /* 51 << 231 */
    { { 0x4b950c04602a871bL,0xf50cb1ef6a731537L,0xb87a1cd3cbe5e4efL,
        0xb1fc48943dd1c601L },
      { 0xdf402711a516617aL,0x5bdd1d67aaf63c65L,0x020d10626e559bd9L,
        0x4dec26d081ec09fcL } },
    /* 52 << 231 */
    { { 0x7b91fafdeeeeb2bcL,0x56290f9833aaf2c4L,0x57abbd2779c7bf9eL,
        0x568bdee62b1e1ecfL },
      { 0x58f8c80c470f1d01L,0xeecfe3981b9cb76bL,0xc0ffa4de311a0634L,
        0x425fcd130ae99877L } },
    /* 53 << 231 */
    { { 0x1964c681f7bd0748L,0xebcca16f9d920471L,0xa72b40cbab4aa03eL,
        0x4397d6afa05624fcL },
      { 0x372d522ca94fca0aL,0xe1010d603035b9fcL,0x9f1f00cc4f788d44L,
        0xfd00ec756a88b672L } },
    /* 54 << 231 */
    { { 0x537067022983aef7L,0xa5f67b0b9b458edbL,0x10789b907db93ca8L,
        0x885346f0fd27cd55L },
      { 0x3af5b0c82ebb5f15L,0x282e4c4a2a36b2a7L,0x2f9d5d8ba6d88bd4L,
        0x6f016bda9856b7aaL } },
    /* 55 << 231 */
    { { 0x990ae53ea8198c1dL,0x295beceba07e7ac5L,0x576f790f48c2d246L,
        0xe99ab2aee3ea9864L },
      { 0xcf4959f243e2d400L,0xdd1d8fad7a39dfeaL,0xdd6ff9c2fcd7fda0L,
        0x61c25b3eb6ace55eL } },
    /* 56 << 231 */
    { { 0xf94742afb4dcddadL,0xc49cfa2144601959L,0x07b3f1d130c18470L,
        0x2736cb996e6afc82L },
      { 0x401fb234e24a8785L,0x9af8ba40074f51eaL,0xe1acc646a9faed0cL,
        0xd5a5f789c9667008L } },
    /* 57 << 231 */
    { { 0xc643651468c3ab8fL,0x6fa0d734fe8d6b46L,0xe5fccbfcaf7f49c7L,
        0x42c88c53bebcc58cL },
      { 0x7d2e2fede2a0f7f2L,0x694eb76c36a18b26L,0xf0e6ae436b0f657bL,
        0x8a0f625548f1ece7L } },
    /* 58 << 231 */
    { { 0xd594c1688674bfeeL,0xe59ad38dac7d5ebdL,0x080a6b9721645a1eL,
        0xb900f0e1f221b37bL },
      { 0x562dabce04cab97dL,0x5c3087416f472462L,0xa5d87e23c7c4cba8L,
        0x5237fe169b061062L } },
    /* 59 << 231 */
    { { 0xeddfbeb4222021c1L,0xa4fe57d04e7a2a8eL,0x0fbf6bdb2de56c47L,
        0x819588e76fcebc6cL },
      { 0x14196961df041e3aL,0x76a3143740cd4f23L,0x44acd14d8e1a877dL,
        0x227a35c637d7b7deL } },
    /* 60 << 231 */
    { { 0xe1934f1d842a9534L,0x7a2ed2c153ed73e2L,0xcffedd583903924bL,
        0x7c9dbf55b306431dL },
      { 0x61a72f1056e06ab5L,0xb46cf5cc616bc5cbL,0xecf07e10f7c22216L,
        0xa4bddad9d9364b3aL } },
    /* 61 << 231 */
    { { 0x548b95b2da8b1c93L,0xc09a9598a1e1c0cbL,0xedd80ef121d80851L,
        0x4684c439c283f047L },
      { 0x07ca41f387333da3L,0x173ec4deca79a8f4L,0x89ce06f2b4aec6ebL,
        0xfe6b0e9215aaf7f0L } },
    /* 62 << 231 */
    { { 0xdab8876d7c1b9ed3L,0x88aba90fa2606f83L,0xcd21a408bebaf9f6L,
        0x09da66960042a162L },
      { 0x4a9b8b212d66ccf6L,0x34c7490444d5a648L,0xf3fe98e93b0e9564L,
        0xe4a8a352221aa4a5L } },
    /* 63 << 231 */
    { { 0x6278b4b526c2b53eL,0x4ddf26ce1b1708eaL,0x704207af6eb0d845L,
        0x60533de30f5862efL },
      { 0x2b5945dde54393c0L,0x55941df2145ea298L,0xe2b500b6c240f654L,
        0x5a49d8f1cf9f6934L } },
    /* 64 << 231 */
    { { 0xfe8d546827502203L,0x985039d458ade316L,0xefd373f10a687415L,
        0xefccb79143526774L },
      { 0xeef8d46e0f4497d9L,0x4152df711601ab9aL,0x4250cd2fe47b2ad1L,
        0xa2b63fa5fb048180L } },
    /* 0 << 238 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 238 */
    { { 0xd8a6cb6f787d1f1cL,0x427bac943d219a66L,0x51d7d49f383146b0L,
        0x8164b77f7863d781L },
      { 0x1646b0842f9631b8L,0xef5b3aa8849388dfL,0x60536422e58cd383L,
        0xb079d911f43ea3a0L } },
    /* 2 << 238 */
    { { 0x504ac041cb73887eL,0xf878b618c3ce3a33L,0x57ef73d556393e75L,
        0xe4372d2ed276c08cL },
      { 0xfd9bc8940924cf58L,0xfa2a4debaaa317e2L,0xe51edccc79608da5L,
        0xadcc68fa8cd4b960L } },
    /* 3 << 238 */
    { { 0xaa66c201f8e156c7L,0x7c7cf22e1ab2e3feL,0xe479c3930a677d85L,
        0xc0cd340fb87c412bL },
      { 0x2b2bcef4f95ff321L,0x65da11c9b8409952L,0x143a2218eb67eb9cL,
        0x8919ff25e53508e4L } },
    /* 4 << 238 */
    { { 0x6f154f09a9e0eeaeL,0x2246e6feab05a657L,0x4d7c1c811045b85dL,
        0xde99ea37d3bb7432L },
      { 0x058f818763184ff4L,0x2a223421d134bfc3L,0x1560dbed23120320L,
        0x37243c9576a3de9cL } },
    /* 5 << 238 */
    { { 0xb8f3851ad36a81b1L,0xfbc62bfcbdad7ad9L,0xf68215c7561e0f8cL,
        0x894131d11bcf765bL },
      { 0x8da01f9e45c5d736L,0x025de05c7484e0c1L,0x62f4c66c6858b504L,
        0x754b85d6d6dc5f93L } },
    /* 6 << 238 */
    { { 0x5b37cecc822a3de0L,0x422e49b1a98a37c2L,0x3ef53d89be41e927L,
        0x0994dd11f4d5bffaL },
      { 0xa62ea556f7eacca3L,0x37b4e2307c746025L,0xb4291e37a8e14253L,
        0x2bfc9eaa2a2b666cL } },
    /* 7 << 238 */
    { { 0xf604604ac26e5588L,0xf75816ffa7ec3971L,0x859e9ec726a30a6dL,
        0x2ce57b66a1a5b815L },
      { 0xc7aa4df4d65e8ec2L,0xbab6b3bba5d82edeL,0x7a11b25d7b088314L,
        0x501a3891c2c636acL } },
    /* 8 << 238 */
    { { 0x9f116c8fe256b02bL,0x71495693fa5946e0L,0xeb9696ffc335452aL,
        0x01ca59294971162eL },
      { 0xee0a1f50c0f28e72L,0x2baac62c70d8df1aL,0xcf65d297f49110f8L,
        0x041dbb019a45e16aL } },
    /* 9 << 238 */
    { { 0x8db694265e1410c0L,0xb21f3c6aa70d0268L,0x64a3c30ebac0ddacL,
        0xdcebdedc66a2d33aL },
      { 0xc5dcd769a519de21L,0xa692b6a019322c69L,0x454add5b154fca13L,
        0xd2281cf04935eba2L } },
    /* 10 << 238 */
    { { 0xb5f44fe7f2602323L,0x772fb6a65d68a3dbL,0xf519c5d476eec37aL,
        0xbc8e9a15ada6c3f4L },
      { 0x9cd2a2f2f18effeeL,0x9601c1421808ab42L,0x05d110f70480ad18L,
        0x5f7e0721ef6a7f33L } },
    /* 11 << 238 */
    { { 0x1afbeaece6409e21L,0xf6714651317f7967L,0x34cd21ff80124751L,
        0xf85c70ec931d9639L },
      { 0x4e26bef61ca19094L,0xc513f66b0b841b9aL,0xe25507bdb9b41001L,
        0xd77fee9494f49f7cL } },
    /* 12 << 238 */
    { { 0x20b19223d39e1ee4L,0xc8832a2c4e3e6c2cL,0x64a8f43da3a45c34L,
        0x52a05eef21fb291bL },
      { 0x10d3e24ae4b68e38L,0x5289120aee2d8a40L,0x33836b98425b7da8L,
        0x5bd418f3b00c64e1L } },
    /* 13 << 238 */
    { { 0x10e92e5ad511c3f8L,0x17f1301d18b62b7dL,0xf710b02d97f0fcaeL,
        0x8b1030f6bd394477L },
      { 0x49040009e5aab897L,0xfdb23ac1ce75b4d3L,0x7a43d904f2b70e1bL,
        0xdc09e995f94fa56fL } },
    /* 14 << 238 */
    { { 0x9f314e85d075dd65L,0xc0d39ce0b9e26b8dL,0xd3f6778efdc3b678L,
        0xce6573e9fc8497dfL },
      { 0x1f4535f867abaf7aL,0x80706daba47dd948L,0x670ae5bcc059242bL,
        0x3a29bc73cf5f9308L } },
    /* 15 << 238 */
    { { 0xd2f8e2978af2bf74L,0x98dbb4436c48bbecL,0x211a3a96eb448447L,
        0x88ffb2405af4a2c0L },
      { 0x1959dd349cdf9e20L,0xa4d0d839f34627e0L,0xa5cecad3f00057ccL,
        0x22f32ccec5d97b18L } },
    /* 16 << 238 */
    { { 0x31a02241cedc2c97L,0xf0f5489b2b632641L,0xb09091ddcbfb588fL,
        0x5ffd0f385d9478e7L },
      { 0x13f141a1dae35edaL,0xd25563a662f0b26cL,0x80014b171b9dde18L,
        0x9fcf8f817da49b36L } },
    /* 17 << 238 */
    { { 0x68aac84a93519f31L,0xe14c35c1c0b3660aL,0x29f447dd08195bc5L,
        0xc61fbbe610bba62fL },
      { 0xc471624c4ed8621aL,0x8005f67f0950a4c6L,0xdfc3b3e593a2a33eL,
        0x9c3c815e3c1d0e42L } },
    /* 18 << 238 */
    { { 0x1ed1aedb93904766L,0xcd5e0cf6376fd0bcL,0xdd4c337890d03033L,
        0xde39db01d85dca30L },
      { 0x49d01dc2e6fab58bL,0xd16d79406d449f51L,0x3fb6cf8ed20a95e6L,
        0x0b10a596bbeeccb1L } },
    /* 19 << 238 */
    { { 0x06ceaa620005acd3L,0x09db6b2847555053L,0x45d84a857e7d18d7L,
        0x33c28b02229ad33eL },
      { 0x1e5a6b5272e4f34cL,0x81eefbe6b64fa831L,0x4983b84a2aa209aaL,
        0x2077719838d6a8d6L } },
    /* 20 << 238 */
    { { 0xbe99380540096f25L,0x900d4bddec820131L,0x2170cfd32a993f9cL,
        0xa0e3d8942dfe1007L },
      { 0x600d0b5a0e7df109L,0xc904985a47fde3ddL,0x15597a84cb89816aL,
        0x8ac8b027b9dfeb9eL } },
    /* 21 << 238 */
    { { 0x5c9211bc6450a179L,0xd448a70af6333f95L,0xe9c9a964824e1d7fL,
        0xc47d3f3c15750ae4L },
      { 0x959f776badcf9482L,0x00557ffee741ceb3L,0x8b69d3f6353d7898L,
        0x6b4d80d345cfa492L } },
    /* 22 << 238 */
    { { 0xc33ead7830c313daL,0x86f96c3a67eee139L,0x0c6675c708611b15L,
        0xf9ee695d60620c27L },
      { 0xb35d438cd70c9258L,0x1bc2b1e7a5e7a4b1L,0x38d257f8ef92f629L,
        0x090af73a79fd1eb0L } },
    /* 23 << 238 */
    { { 0x96ebd1f0f59342e5L,0xd48693624d053375L,0x7db504e25fab54aaL,
        0x17c0801e6e8e43fbL },
      { 0xd3904d62136b1941L,0x5932b75328a43bd1L,0x551d895eacb35572L,
        0x3f7a8a461a6fdfbeL } },
    /* 24 << 238 */
    { { 0x9e3ea4fdf7a2df83L,0x8b68b26b64524d44L,0x74caeeab126aee21L,
        0x590a00a5915d9e1cL },
      { 0x5ae2a6ab49b90effL,0x74b4cb1e2df4fe51L,0x0306ed1107fcb6edL,
        0x564ebe2e502f5b30L } },
    /* 25 << 238 */
    { { 0x5a09a32e0c89e9baL,0x967f9dfb84f2466dL,0x8b27416c26a1a8a0L,
        0x1c21ef95c3158a18L },
      { 0xa7ee1ad82be23ae9L,0x1f312d044daa1fcfL,0x6782f84344f9c7d7L,
        0xb12ea2bfe19e2681L } },
    /* 26 << 238 */
    { { 0xd2e43cbfd20578afL,0x5566460abb5819b4L,0x86f6c860b658c03cL,
        0xc8d9030962d42d82L },
      { 0x7975a5f3cb883cebL,0xf6f5cf0fdcded5a1L,0x25554fb1d3eb810bL,
        0x3df7536ba596c7c6L } },
    /* 27 << 238 */
    { { 0x255ca13683de31cdL,0x7ac532ee7795eb96L,0xfa9d83a9b12bc235L,
        0x7df5d2314b287a83L },
      { 0xb2eaaaf6b4f19fceL,0x7caabfb01a045f6aL,0x6d1b7f40b1449e6aL,
        0x24ae41da12d22c82L } },
    /* 28 << 238 */
    { { 0xb0f7a0c3c0a9d128L,0x2adc34d3aed0d3bdL,0x4ebf577813e778e6L,
        0xd3b89bd0bb8476baL },
      { 0xe09eb52837413953L,0x952b705cd8ba3471L,0xcaa81ade86a79c09L,
        0xc08eed3d7e0e7b2aL } },
    /* 29 << 238 */
    { { 0x313fb103c80b4196L,0x25449ece88c7ac81L,0xa6cb9ad324f16fa2L,
        0x4602c441728a0c4bL },
      { 0xc3366f885a000a9cL,0x146623e3ef8778bdL,0x184ba0b1f0773fdcL,
        0xe1d115efaecd8d63L } },
    /* 30 << 238 */
    { { 0x420d5473ae165e6cL,0xefe137cd108d8575L,0x15378c576fcff7d9L,
        0x49c48099c1f5b601L },
      { 0x1b0e3aeef68473f1L,0xa78329bbd320720dL,0x385e521bdca54cadL,
        0x478ce06f5c5b8d60L } },
    /* 31 << 238 */
    { { 0x215d7d33ca7c4d4bL,0x773f3ab3a095366cL,0x668e0d117afeeaa1L,
        0x410cd2054878d8a3L },
      { 0x2748fd98b2800646L,0xf118378673a1dbefL,0xecc31bd27567ed3aL,
        0x775210df0ceb3873L } },
    /* 32 << 238 */
    { { 0x2ea0c2bc9a8f42ffL,0x629742404a1c029aL,0x5ee5f5f69e4dd41bL,
        0x5b1bba802e110249L },
      { 0x5ac4eadb78da8016L,0xc29787801809f79fL,0x39d2dbcee3f8c0deL,
        0x7fb4b5fc064d3ba9L } },
    /* 33 << 238 */
    { { 0x038a736dcd481ab4L,0xc4b15c5c396888ebL,0x459a896dd421f36fL,
        0x6058b90f47f54663L },
      { 0x0a5f6771afefebe5L,0x45c97ab2a5b7c2caL,0x6d547af985139ca4L,
        0x6db218dea29d71cbL } },
    /* 34 << 238 */
    { { 0xca6e0e7bfb956184L,0x6682b6e31f660ac6L,0x3959e3968b21bcebL,
        0x0459fd46632cf9c8L },
      { 0xc741250c74f296bbL,0x29b9cacf990dbefaL,0x5065d818fc35bdf7L,
        0xeb8e9e1ba551dc04L } },
    /* 35 << 238 */
    { { 0x4f7d6f7d11befe9eL,0xa88f1fce7478fdeeL,0x39b1e053afa688e3L,
        0x562a0d6ee16847e0L },
      { 0xf6044e4b34c26d14L,0x5ebe87277df61b90L,0xa82a4de46b5e5a39L,
        0xc916b0bafb9d296cL } },
    /* 36 << 238 */
    { { 0x029f1cb22e1dc01eL,0x7699d92efc429483L,0xee0e425a154560f0L,
        0x3f5cdfe6787b6641L },
      { 0x726d87bbe5f6794eL,0x97d7358823aecad2L,0x47f4f5b909ca351cL,
        0xd742ef4b57dc5e3bL } },
    /* 37 << 238 */
    { { 0xccd2209d71411a86L,0x94d576632223e6ceL,0x228a740066c7950cL,
        0x2d00ef6e54dd4e37L },
      { 0x9ea5daf3d60f66beL,0x743c58a58aca724fL,0x1f63840644e38446L,
        0x06314bb092ef6bb0L } },
    /* 38 << 238 */
    { { 0xa7459e7fbb05589dL,0xc3a39592bfa913d7L,0x27dbabeedf07b190L,
        0x1c8a2f33d2ee62ffL },
      { 0x60c8bcb8e31e8d63L,0xea1604d1ce410061L,0x55e8cfee3d7f7a98L,
        0x49efc316ebc64102L } },
    /* 39 << 238 */
    { { 0x04c86d8e41934914L,0x26667c76ab7facd4L,0x319158dba71a8916L,
        0xb802942d114fff43L },
      { 0x5efdef7b8ce544f5L,0xf531c71870e870c1L,0x4b9a5f1b4d92071dL,
        0xbe767cf260cc48b6L } },
    /* 40 << 238 */
    { { 0xbf389d37717381eaL,0xefd9e98406bc5bcbL,0xcc8bc96067ff1110L,
        0xd3414c0bb05612e4L },
      { 0x084e5f05927fad1aL,0x999bd581438e241fL,0x0c917602faa4fab8L,
        0xda0520d295080657L } },
    /* 41 << 238 */
    { { 0x3160f928ce2f1af2L,0x61186d84364f56e4L,0xe36a5fc025fa68f0L,
        0x9e6f66bd774c584bL },
      { 0x2611bba49ecb449aL,0xb1e0b341ec5a0667L,0x336de76d6cddb6c3L,
        0x9668b5b365a18f95L } },
    /* 42 << 238 */
    { { 0x1ff6c81f7c3ec388L,0x53545b0540a8e2d0L,0x990a3cc514ae31d6L,
        0x769b4c26063a2995L },
      { 0xcea238f4039e279fL,0xbfc5cfb9732fb38eL,0x99f5a33c82fa05d8L,
        0x274dc74169c42686L } },
    /* 43 << 238 */
    { { 0x193338ee76af2af7L,0x0488c19f6914ae66L,0x8d197f4e5fc58bf4L,
        0x23de54dff0e61d4bL },
      { 0x547dd09f44a165e1L,0x998780651c2d5471L,0xb2cabfad39b311dbL,
        0x0aed63d94b61a7ebL } },
    /* 44 << 238 */
    { { 0x03713ac5be8110efL,0xaab1917d50f989d3L,0x0d80fe98358fe8b0L,
        0xf6e874c5a7a1f8e3L },
      { 0x05650fd8deb42398L,0xbad3e0851c44de73L,0x5369135f1c27f3c2L,
        0x14bc04f8a7fc74acL } },
    /* 45 << 238 */
    { { 0x18cbf622b5dae291L,0xce2905709356b88cL,0x61bbb44639eba4e6L,
        0xa79c291b980fee37L },
      { 0xd9f1800619960cc6L,0xb0823f410ce98896L,0xf2bc612e1377df6fL,
        0x1c07bdedc0b0e71cL } },
    /* 46 << 238 */
    { { 0xffbf984137211fd5L,0xbd704a6b04a81410L,0x653cd2ee6abf1c67L,
        0x73ab8aa140681621L },
      { 0xc0bae4fd271ada5cL,0xf567cae8c46f189dL,0xd183cb27a5535334L,
        0xcbf133f7e53c530cL } },
    /* 47 << 238 */
    { { 0x32e53f78edd6a17eL,0x6ce6da9aa2194faeL,0xa89b805458cd3586L,
        0x0037febb43b520a5L },
      { 0xbe67a2cf653e2c0bL,0xc07a1ed150301f52L,0xf98b2b60f5ea954fL,
        0xfa6da95d7af6c499L } },
    /* 48 << 238 */
    { { 0x44892091e3889cb1L,0x123fc555d45ae338L,0x2bc4a9ef02a63128L,
        0xb72012c9a1dbb436L },
      { 0x8c75f7b3556a0b46L,0xe4c6f46c5b7608a4L,0xb36abf6838fce20fL,
        0xb5a8e657bf6c21e1L } },
    /* 49 << 238 */
    { { 0x9ceaeefececd5963L,0xe84f200d6105fc29L,0xc28981a98591e346L,
        0x0be4e931207001f1L },
      { 0x31399d9d88616b18L,0x3dac9f55238c626eL,0x0213fca765574274L,
        0xa3560244827aa853L } },
    /* 50 << 238 */
    { { 0x3ffbfeeb1ca99134L,0x0a4b56f6d07a2dacL,0x01795eca75417a6bL,
        0xe2a6dd9c18a5fb22L },
      { 0x13c975868aca0cd8L,0x3c2bb26e7c323c52L,0xa3688caee38319bfL,
        0xe04b44b44c88726aL } },
    /* 51 << 238 */
    { { 0xfed864d0b0a88a4cL,0x3e6cf1526b1fa305L,0x8416b5f000e18e4aL,
        0x3a7603cafa4cd8f2L },
      { 0x8b04d5ff7ec750efL,0xe1867f9b1c1ced05L,0x87ffd0fbdac2f8c1L,
        0xc9ebe42008b3cdcaL } },
    /* 52 << 238 */
    { { 0x5028a4fd029c247eL,0xd6225a43a5ae3e76L,0xfb3fa71cf970817eL,
        0x742168099ab4aef1L },
      { 0xca81ee99a39c2f13L,0xa8336e4286a97827L,0xb75aff99b6489555L,
        0x005b2338e565435cL } },
    /* 53 << 238 */
    { { 0xbaee27bb524bdb34L,0xbf22e1c982e47e71L,0x6ab1d71297491139L,
        0xf420ce062cf4cbffL },
      { 0x9f96a2fcb2b0c86aL,0x42765dd9abeb7335L,0x7c223bb745b7e044L,
        0xce3f92451794e144L } },
    /* 54 << 238 */
    { { 0xa0a15b27f3ee5c4eL,0x1721c5bf54622215L,0x0003fd16ada5a99cL,
        0x8e96dd56dbdccc7bL },
      { 0xd1abdc0b43f83748L,0x71cac4a60f5ce74bL,0xb8539affd46717adL,
        0xeb65c589b99661d9L } },
    /* 55 << 238 */
    { { 0x66b4df3b85e89e17L,0xc94fad666fc30672L,0xfd2aa80f81d90df8L,
        0xed73a163bd8234c1L },
      { 0xe1a2c0b972eb45ddL,0x417e355d902b5ca9L,0xa8f55aaad5128812L,
        0x4826b9343c14cb79L } },
    /* 56 << 238 */
    { { 0xeae495e3394d7a92L,0xcba23153b90faec0L,0xd687c821f6d9d80cL,
        0x951dada28bff3082L },
      { 0x4e74f1f0701708adL,0xa6333cd1dd2134f2L,0xeea276cf04665f7cL,
        0x527257fcae74c17aL } },
    /* 57 << 238 */
    { { 0xeb3fd493e51b53bdL,0xae7807db69ec567eL,0xa50124aa5de15fd0L,
        0x781bfe701336f055L },
      { 0xb5729a74d70a0dfcL,0x89da37f39f50c1a3L,0x6e063297cd8e6c1cL,
        0x17eb6ec1181d0271L } },
    /* 58 << 238 */
    { { 0x36e7251ae4e52a8cL,0x3acfe89b94705324L,0xaa94f06ebc130c3bL,
        0x01b5e44c309ae25aL },
      { 0xb72160f20f61b55bL,0xbef61953e7bbc3f2L,0x96734d7a1bf138a1L,
        0xdaa6186c08c25135L } },
    /* 59 << 238 */
    { { 0xa3b031b2f34534a2L,0x44136619de46f581L,0x4d0ed04b6d379647L,
        0x4879d90dbb2b6735L },
      { 0x8f7e031a590156e0L,0x28428354f42bbc53L,0x1cbed33c5c5b791eL,
        0x175716454cfc5562L } },
    /* 60 << 238 */
    { { 0x8392350a7f76462fL,0x659ce7db0c216ccbL,0xe87a78b7047e35d5L,
        0x307c48616e0862d6L },
      { 0xd444fb86e70741bdL,0x1138a886fea1abe2L,0x4695397d62b79c4fL,
        0x11aaf588003130eeL } },
    /* 61 << 238 */
    { { 0x53bdda6d3a11712bL,0x30c384bd40fba3d2L,0x6303958550ea38beL,
        0x7f110eca3da9738aL },
      { 0xbd701fc65b68c01eL,0xd23f3e8fcc48f38dL,0x6e2557ebf8b9bb65L,
        0x29ceb4b6a3dafc8fL } },
    /* 62 << 238 */
    { { 0x246596864b6b7705L,0x04143a8a4aca2b43L,0x3baed256975e06d8L,
        0x846fb3c93e834249L },
      { 0x7890761e75f6770aL,0x1187920e203c78fdL,0x9b06c3a96b26281fL,
        0x3fe3dccda98215e1L } },
    /* 63 << 238 */
    { { 0x099d7d7a4f33655eL,0x1ba571e6662fb55aL,0x1a0d0147cbc497f0L,
        0xa94218ae2862ff38L },
      { 0x1b0f919b5ce08047L,0x9a3ac37a2baf46cdL,0x76b7a03a8964cc68L,
        0x5aed8c6d4d3e1a40L } },
    /* 64 << 238 */
    { { 0x6607179c7f034ff4L,0xefb8fcd93781eac2L,0xfa57f8a97b022138L,
        0xc5bb9f1d56ab6039L },
      { 0xf9027e24e4d2ab7fL,0x3d67ad7177a9e364L,0xc579e70c1f7f487dL,
        0x7fefc8942a7e6bd0L } },
    /* 0 << 245 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 245 */
    { { 0x2cb91662a45cfd31L,0x09dd56d316f65cfeL,0x983e005d14f3de51L,
        0xb9dc05b0210f64fcL },
      { 0x22790afd885eafe5L,0xbd5213d37444bdecL,0x289dca928987300aL,
        0x69fb2ac2b3960b76L } },
    /* 2 << 245 */
    { { 0xe32748869ae7540fL,0xd73866316131e921L,0x2e3d4fd8f2a360c8L,
        0xb20a59b63d9d41e0L },
      { 0x72b67eae99082a34L,0xfad6aa7d51819470L,0x7c299b9aa2d1d007L,
        0xc1f841e08100bed0L } },
    /* 3 << 245 */
    { { 0x2c1f7d4c43e90ebdL,0x58b781071fc72b07L,0xda8503e1af94f402L,
        0xfbb724b759f244b0L },
      { 0x2fcd2186fcd8755aL,0x7407cdee868482b7L,0x4d62f578349be3d5L,
        0x4a012544dcc6202cL } },
    /* 4 << 245 */
    { { 0xb8a414d2151ffc08L,0xaa79acf0740d6b55L,0xeeab0104cdf472abL,
        0x5014a8c1a3aa5f1dL },
      { 0x8c74340533f13425L,0x2b776b4957eb54d4L,0x3a0cc4ac548a723bL,
        0x65aae6f3c79fe63aL } },
    /* 5 << 245 */
    { { 0xe8b388f2ee5e579cL,0x31cc9373991c03d4L,0x53eed518567bfa7cL,
        0x267e282d67f985edL },
      { 0xc435fd22b4763ea0L,0xead83837e39b7703L,0x806daad5094ba5b4L,
        0xa738a84745842672L } },
    /* 6 << 245 */
    { { 0x99421b429984c4c2L,0x1a3bce27d35c7bbdL,0xe51ae6f63563b09eL,
        0x8e67853b8d9c9fbfL },
      { 0xca8784da6b2100b5L,0xe89a24f798879bbaL,0xe901b45ce286b039L,
        0x23dedbb8f50384bdL } },
    /* 7 << 245 */
    { { 0x4728cbdb5cbf7df2L,0xed274fdf6764329eL,0xc2af1a07642d199aL,
        0x5d66565917a50e7eL },
      { 0x7babf4bcfaa5eb82L,0xd3bcfc6799fe4026L,0xaa5d2648607d9f41L,
        0x7405c071967efac1L } },
    /* 8 << 245 */
    { { 0x79447ef9dfa782a4L,0x6dadc8e174cd9500L,0x0574020edc38f762L,
        0x17596d7ee2ee7a14L },
      { 0x9ef75af79e1f8adcL,0x5ac5f216a4791da0L,0x1583226b7b7b5d80L,
        0x59f3f053a21c26ccL } },
    /* 9 << 245 */
    { { 0xd80e7fdcf95e30d9L,0xecf5041c0a3a3616L,0x50b93b8b03043fa6L,
        0xa31a2aa4ae262ad6L },
      { 0x1468b370d63cd98dL,0xfb89cc65dc07a367L,0x6cf1df6b4d47b59fL,
        0xab451a991b6350feL } },
    /* 10 << 245 */
    { { 0xeb74554d8c124dffL,0x781a8c4d21be0be0L,0xfaacc154e3510068L,
        0x16655d65d6238265L },
      { 0xba46d27b0466134aL,0x1a3f51b93101e283L,0xc08298a9096ec237L,
        0x46248627c69cfb5bL } },
    /* 11 << 245 */
    { { 0xf9e7a5a481a0500fL,0x92db27d5bd2e03e7L,0x3dcce4f682899e3cL,
        0x861f1797f39a39c7L },
      { 0x175b243069dc8961L,0x93d2a88edc67953eL,0xa40f370492d794d6L,
        0x607019f03526eeafL } },
    /* 12 << 245 */
    { { 0xf20e163b22f37d65L,0x70fd00c832cf180aL,0xff1a97d20b17244eL,
        0x9a5a141bacedb33aL },
      { 0xf03dd868cc16bbb4L,0x9b15372da40e44e9L,0xd5ba643615ac397fL,
        0xb1a886d4c821f6b7L } },
    /* 13 << 245 */
    { { 0xbe3aacda4b7b4e21L,0xad9829fe66b56729L,0x78965cefd541cc1aL,
        0x414bfea77d17631eL },
      { 0xf55835d9c64dd621L,0xa0ebf68bef644d93L,0x01d15340c8a40021L,
        0x00ae640d42b99aa0L } },
    /* 14 << 245 */
    { { 0x92321ee26881e64fL,0xaccab5c85267bdd3L,0x0c1f87ea5927647bL,
        0x0093d07e162c6d86L },
      { 0x49868df4389c711dL,0xe68d69aec11e1f37L,0xa40e7aa8b4207246L,
        0x4ae8d126ce832395L } },
    /* 15 << 245 */
    { { 0x5f9b128a86450cc0L,0x88f76293c8ec07e6L,0x0762f293179702b8L,
        0xb56961024910006dL },
      { 0x3951291b35fe0505L,0x70f75a5cce8d7056L,0x4541beaf2eb13369L,
        0x7060a749a643316cL } },
    /* 16 << 245 */
    { { 0xee16abd049c879a5L,0x844874a7a47ac42eL,0xee3f8a203c9c2326L,
        0x99a12054deaed33bL },
      { 0x4814a15b63b333aeL,0xee9f28a59d923fa0L,0x5b0cd25033b1b1efL,
        0x3ccc39b98346d928L } },
    /* 17 << 245 */
    { { 0xf5c1000e002bec95L,0x2ba2f18cf63528c2L,0x8102f6c8cdcec15aL,
        0xab7effcdbb13d14aL },
      { 0x183e0ba2fcd3787cL,0xae70635e2f4a7fc0L,0x473ed37f760bbc96L,
        0xf0ea0acf8a8efb39L } },
    /* 18 << 245 */
    { { 0x63cea36c29b526a9L,0xcdb316139d03f3dbL,0xa3891096d57cca8eL,
        0x646418a9a14a8ffcL },
      { 0x10f8906b8075291fL,0x8221d9412c618bf6L,0x1dc1ae7a8a5da4dfL,
        0xb66b96e38a8cc8bcL } },
    /* 19 << 245 */
    { { 0xe4da7e48fe3551b4L,0xe6891cc9ad9b3827L,0xb266733f6b37b99fL,
        0xfccce911fd5d1219L },
      { 0xe5a47c4b7262b8ccL,0x5d349cafe656af49L,0x7a3a4a287e04e48eL,
        0x7c39a68e80ea7d03L } },
    /* 20 << 245 */
    { { 0xf35d5e32bee0d434L,0x9651f3d90b536161L,0x42634cc972cb370cL,
        0xa7764026406b3457L },
      { 0xec7525bd65d53d80L,0xf44a1bcaadcc8b05L,0x12ef8427da112ddcL,
        0x796a65b320a0f78fL } },
    /* 21 << 245 */
    { { 0x12726e246bd5b0abL,0x9e4414678242fe07L,0x4b52e276de2bea52L,
        0x3a76b6b410422c2cL },
      { 0x71f14945b4e496b9L,0xd20f04b0f36dce4fL,0xa0e57d8d2b310e90L,
        0x59eb773732ec8f38L } },
    /* 22 << 245 */
    { { 0x20a19834aaf6619eL,0x633b94e8691a538eL,0xea1a898592cdf395L,
        0xa3a01c574349b971L },
      { 0x0d65192a30822c59L,0x93a5152da522ae8cL,0x5b09a7a30e1aa4bcL,
        0xdd2588f38d3b97a9L } },
    /* 23 << 245 */
    { { 0xafa1f62a5b62a3a5L,0xbded10e6a9ace9c5L,0x9d03e061bf6e7fb2L,
        0x60c564a84b87177aL },
      { 0x36be1308c22c14c1L,0xeeda57e89425b6bbL,0x5ddaae1436af38c2L,
        0x1695464becdc2911L } },
    /* 24 << 245 */
    { { 0x4b795e1d161e13e7L,0x0f9abc20907e7069L,0xfb3be61854522fe7L,
        0x9e2d0f371938134eL },
      { 0xb8dc7c36d292c6b0L,0xbafbf59cc1e77895L,0x7d0132cd1b6c55f3L,
        0xefa02ed9f609f087L } },
    /* 25 << 245 */
    { { 0x4bfe6aeb03519f9fL,0x248e19a0dab4c075L,0x83ee803d69429f29L,
        0xdbbe31e28190ce56L },
      { 0x3ba735d26b787a5dL,0xfa0211851818070cL,0x9b653000a3683ceeL,
        0xfc3c7907e9517ba2L } },
    /* 26 << 245 */
    { { 0x6521c92f88d94f69L,0x3950e9e87b52da8dL,0xadb817008ee64a88L,
        0x8ccbfa3cf73994feL },
      { 0xb780ab12b048e71eL,0x52879e7be2aeb607L,0xef04b1ed3237554fL,
        0xaeba6a96e1d5a5efL } },
    /* 27 << 245 */
    { { 0xedb58542266f7e93L,0x9a1b80575ea02852L,0x1963c6f25beb3fbdL,
        0xf41833551ad52473L },
      { 0xca772e9e6faed2f4L,0x937eddd03cf8fd1fL,0xb3255376c1d49dacL,
        0x549c2119e670d3ccL } },
    /* 28 << 245 */
    { { 0x10edbf393b6cd199L,0xe947922375644d6aL,0x36cfba92d6e8cc36L,
        0xa37b1d91fe00d80aL },
      { 0x3aadf918deb5ef4aL,0x5bb2ca4dd3893df2L,0xa776000e6569ab8bL,
        0x4fb2308f1cf64905L } },
    /* 29 << 245 */
    { { 0x04da4d09273731c2L,0x1d4a61fe23c05518L,0x201098a30d5206e5L,
        0xd9a7ad4e06430c82L },
      { 0x56df0d0636f7f462L,0x2c067f3d44c81042L,0x01193bc9c453d28eL,
        0xcdf5af5d45ce6e64L } },
    /* 30 << 245 */
    { { 0x9992ce1a0f7d8d12L,0xa7c46a610e5e4542L,0x3fcc0647057802baL,
        0xa78f73d8c7dccbe2L },
      { 0x67f37b94f138dc6dL,0x89330885650a9002L,0xf661caf268aa24c7L,
        0x47732bcdbf73c435L } },
    /* 31 << 245 */
    { { 0xb9ba5f913b04622eL,0x24265f73477d420aL,0x5da6ddb00d44cb89L,
        0x9f8cb8b6151fc40bL },
      { 0x81b6956b9b9f2613L,0x37419206ebb917dfL,0xdb9cfc162bb7a709L,
        0x7a800aa3bacd3fb7L } },
    /* 32 << 245 */
    { { 0xf8ea9359d93f6e1aL,0x729005d43d41c118L,0x4c2934107cb641afL,
        0x6b2b4671895e8e78L },
      { 0x2a1251d05958fad3L,0xb69bc2be78619fe4L,0xd74df34cd911d318L,
        0x5def837815102704L } },
    /* 33 << 245 */
    { { 0xb19ea17a08268482L,0x145911961c37e5d1L,0xe0e12d2e7640df9cL,
        0x8fd6bd4d8c941274L },
      { 0xc3f9f120dcd142b1L,0x106c49ac78dfe6b0L,0x243c8e93cfd9b542L,
        0x6758062d0a2c5fe6L } },
    /* 34 << 245 */
    { { 0xee5a99e815f2f638L,0xb95b008d13979ab6L,0x7fd03105acfcca6aL,
        0x6af914a4e4ced1b3L },
      { 0x8bef3d0fa25f8627L,0x21bae309f9b2f931L,0xe85dee2b2195a839L,
        0x46ad0ad9a3baeb25L } },
    /* 35 << 245 */
    { { 0x6d8e40f8022b62a9L,0x4a6bbabf90b5cd33L,0x53481e6bffa89bb2L,
        0xd674b3b322003cc2L },
      { 0xc71a0a85004a2aa6L,0x86df9697b5404657L,0x407727f4c74e80ccL,
        0x39c13926950a7b08L } },
    /* 36 << 245 */
    { { 0x26bee75ad74472a4L,0xbf7c4ea02eb6f0d6L,0x689a5de5608bea48L,
        0x5b38389229d513f8L },
      { 0x49fee2c2da457cf9L,0x7fc0aee762d523d3L,0x5bf447deb636a46eL,
        0xda3efd988194766eL } },
    /* 37 << 245 */
    { { 0xa77c3ad2d382756dL,0xc0eaa9de0fa55315L,0xe68d0a51b1df90e3L,
        0x0994e8c701d1d8a7L },
      { 0x4f898bc3a91bfed0L,0x1c2a3e46ab6025dfL,0x37bd5c378b269271L,
        0x4e07f5ca8b97f0afL } },
    /* 38 << 245 */
    { { 0xe346b5aa97923d14L,0xa8549f619e0bd9c4L,0x78e59d6b40113a60L,
        0xe3015fb2ed8a0fc6L },
      { 0xfc56a08f8b43288aL,0xcbdb8caecae6c18aL,0xcb147c445f4423dbL,
        0xa6aaa6c910f361c1L } },
    /* 39 << 245 */
    { { 0x6be86c0c7caf702aL,0x2188e83c736f6dacL,0x40b5ed2559ba2af9L,
        0x76211894ab8018c3L },
      { 0x0c1c532ff5b0b048L,0x7503aca9e3200521L,0xb9325d85dfa7eb2dL,
        0xe6c25a002edbb68fL } },
    /* 40 << 245 */
    { { 0xf9ff58678c673c89L,0x4925a046099c7baeL,0x0b3bf59adbb1e1b6L,
        0xc7e9d9f230ae084fL },
      { 0x709823960fa1776fL,0xb2e1b98f624c897bL,0xa9a6407d6c3534d5L,
        0x5e22319ba4dc3f63L } },
    /* 41 << 245 */
    { { 0xc2f0bf3f2431dc01L,0x478f797dc2cfb315L,0x6559f59c3b3ae0c5L,
        0x7e95aa62e18e74a8L },
      { 0xf2a94006d3fce912L,0x7f1b57a2e1bd96ceL,0x55028ad0a3d7b828L,
        0xadae7e924f09fe92L } },
    /* 42 << 245 */
    { { 0x2174c736757b418fL,0xd904ba433661d54dL,0x0281f91263218ecbL,
        0x5fd03ba0c50c8eb6L },
      { 0x29626906896a5aeaL,0xab4d3f27e55ee73fL,0x3db1c43dedfd1991L,
        0x498cc31aa3f9c340L } },
    /* 43 << 245 */
    { { 0xa43bdec14fe75d33L,0x5b067dfb66ae5d4fL,0x84581814464c8239L,
        0x2f10557f503a52eaL },
      { 0x21c4c180a10fbb90L,0x33b191eef79d5e02L,0x6dee3881b499478eL,
        0x27dfef0bbfbd56faL } },
    /* 44 << 245 */
    { { 0x671a3dd728be2d62L,0x06f2f4c2050897ffL,0xd92bdab6b7c4587dL,
        0xd2253a16fd8d5160L },
      { 0x64f6e4aef1c098b1L,0x005a393911ea7255L,0x2ed4eb92dab542e5L,
        0x26920bc150c5e874L } },
    /* 45 << 245 */
    { { 0x93e8f58a5d0bc87cL,0xaa4d313eb2b29b4bL,0x3e175dec01b2096fL,
        0x6c5609721cf31783L },
      { 0x9d41aca273b76f6bL,0xa2454cf55f1d4b12L,0xa561519665b35eeaL,
        0xf241e51670af4fdeL } },
    /* 46 << 245 */
    { { 0x5255e91b65061472L,0x6ef98d2d5bdbb257L,0x0d1d1ab1c74c7b2cL,
        0x9ffb9fdf2e9febdeL },
      { 0x853f3b9f6c50bf24L,0x3d3695946fbd22bdL,0x4d281126bcdad9a9L,
        0x99eb62b6dc46ddc1L } },
    /* 47 << 245 */
    { { 0x5aa8c8b24b10c402L,0x2e79f595473af61dL,0x96153360ce360f37L,
        0x16dffe2266bc29ddL },
      { 0x35536eb11137f9c3L,0xd636ecade2a6a47aL,0x83cdf214b499f840L,
        0x3642c77cd247f18cL } },
    /* 48 << 245 */
    { { 0x4d906a2e916ef527L,0xadeb94d0293dc085L,0x03a078011491da3eL,
        0x177dceae0b84d2ebL },
      { 0x61e5a3c17b691e0cL,0x47d40bd7d172cea3L,0x7d0646ad8ca76bceL,
        0x90b030a9c64d635fL } },
    /* 49 << 245 */
    { { 0x71eca8e797118df2L,0x2cd48f703ac9536bL,0x9ffd991d89fb4d72L,
        0xd49006bcebf781fbL },
      { 0x688af07fd3e60da1L,0x5f74aa46619063b7L,0x44fcbeb3a40d313fL,
        0x0ed5908b326faaa4L } },
    /* 50 << 245 */
    { { 0xe836d537f41ec05dL,0x01eaf207221b0c32L,0x1d6a0bb672f8c904L,
        0xa6ef58b2dfd74641L },
      { 0xbb855ceb811bd6cbL,0x7b1c8b7105408eabL,0xd24d709e4187fb7fL,
        0x283d647d8b30a9beL } },
    /* 51 << 245 */
    { { 0x6d9d3793f9f0d6e6L,0x02fc3ddbb1c06b19L,0x8ff8679394d9abecL,
        0x1f20bba224705873L },
      { 0x74eebc120021b290L,0xd859521e35b6c157L,0x2201aa41431aea79L,
        0x79c1caaf90da1a75L } },
    /* 52 << 245 */
    { { 0xcd6abab76e412a6aL,0x82399139b4c58b05L,0xdf416966a3b55538L,
        0x2b2d546f679882d3L },
      { 0x17425cbcf9145657L,0x3cc6735fe1b8247eL,0x13e50c5657edd04cL,
        0xc87231371b85b7cbL } },
    /* 53 << 245 */
    { { 0x907b5b02dc0ab9d5L,0x5617fb7f4ab23b78L,0x7ae8ff03e8f449cdL,
        0x86d3ff17174e0e22L },
      { 0x22cb7f69bf1e9f8dL,0x12f0abbe0b0c62f0L,0xc8315981537f658cL,
        0x43da2770c467f2b4L } },
    /* 54 << 245 */
    { { 0x3ef9bb815b9e88efL,0xb85263183a8e51f2L,0x2e47cb7ff8d744acL,
        0x63d6dc16510aaa7cL },
      { 0x54da7cdbb40ccc41L,0xdecbe5fd402b2ad9L,0x14c6f15c34c8f225L,
        0x6d8b2342c6559496L } },
    /* 55 << 245 */
    { { 0xa4b7228166fea635L,0x55f5c27f22f248a8L,0x3ced14830959cd01L,
        0xcc6469dbb53bdf42L },
      { 0x2bb2346f1e460645L,0x4d8573c69d7535e7L,0x988cddd549cd2d68L,
        0x785c4a70b9835538L } },
    /* 56 << 245 */
    { { 0xb08337b31f6e396cL,0x6166b21e49a782f3L,0x1ac6198b8ec9b974L,
        0xee2e34460bb44d3dL },
      { 0xdb28374035039dd9L,0x7c708f9529f5c692L,0x8914cce098ddb466L,
        0x8bb1b9f1d446f3cfL } },
    /* 57 << 245 */
    { { 0xa9dea222ee0933a3L,0x2538bd434b26049eL,0x18741acabdcafae2L,
        0xe0f830f716b0f4bbL },
      { 0x0479ec95902caefaL,0x1f858937dcda9e64L,0xe75b4f7b515c4089L,
        0xb78afde42eb91b51L } },
    /* 58 << 245 */
    { { 0x1eebe3e918949935L,0xde8deaa9ba092037L,0xd43cf4ef93609411L,
        0xe0fdb1e4c2d7b76eL },
      { 0x1d3191a54e34b4bdL,0x106d92f19ccc4c26L,0x1a404ef629a2a6d1L,
        0x3338bc9cc598f481L } },
    /* 59 << 245 */
    { { 0x3945e39de3fcbf71L,0x123b082c9c89ab61L,0xc7477f770f9f3c37L,
        0x408c0c7a7dbcc077L },
      { 0x6c4d99f53654f98cL,0x276a007a05299a1aL,0xabd4b8ea23e2d7d0L,
        0xe05a5f3a86017545L } },
    /* 60 << 245 */
    { { 0xde3b885ca11b03cdL,0x46ef07558df5d64eL,0x112a49d6bf3f085dL,
        0xf6ebf441198ff32fL },
      { 0x581c00d87feae481L,0xf2b43827cfde5b2fL,0x3ceb7f8f9b7358f2L,
        0x95761fbd55fe7117L } },
    /* 61 << 245 */
    { { 0x305836fadc04773cL,0x66324504b3c4873cL,0x5d878c1f55b130deL,
        0x96e9b28c8ad49a9bL },
      { 0xd1a707b876d70429L,0xaff33f93aa402e90L,0x733d6256edbfb28fL,
        0x9e421a7ca75d2342L } },
    /* 62 << 245 */
    { { 0xdf86b254c02e49c1L,0x6bb53867b56d308aL,0x771dde4b73f29561L,
        0x96eaf73e8bf28e5fL },
      { 0x9b1ee6be06fbb550L,0xe09fec7797d4a4e8L,0x93bdcd60d5aa84fdL,
        0x3fa8d3a0d457ab9cL } },
    /* 63 << 245 */
    { { 0x315b32b1a0a2e52cL,0xe7e50b2d3bbcb61dL,0x8a55cc0e5e5c6e11L,
        0xc2bfa998961295efL },
      { 0x4a5ab3bb66e996d1L,0x22c42e4f4886a421L,0xa0cdd3644850e0a4L,
        0x7682d38dc64ed713L } },
    /* 64 << 245 */
    { { 0xe31575c2a2c539e4L,0x0bac5dcda756daf9L,0xe917cecf91f55a12L,
        0x1e96433be96f6299L },
      { 0xeec7c71c3700d8fbL,0x9a1d2965dc9b4444L,0x3d2c6970cf74f19cL,
        0x3b444c48ac5e0d6bL } },
    /* 0 << 252 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 << 252 */
    { { 0xe563cefd8ccb854cL,0xf5452cdb65b0c45aL,0xb3c787699c37f743L,
        0x34e9d19295d444abL },
      { 0x2934794652ff26b7L,0x70d6ecfa9b94d642L,0x7d201858fdaffb8fL,
        0xc288719d45dcdc71L } },
    /* 2 << 252 */
    { { 0xc695469d0728a2ebL,0x7b46244ec433d11cL,0x4a8b99baf106c08eL,
        0x7989794f63422083L },
      { 0x82218867d4fc5696L,0x6b021f283c79cdb8L,0x5ff7bbeab26d5049L,
        0xb78611caa7261628L } },
    /* 3 << 252 */
    { { 0x5a75f961531313d7L,0x85a1f4db66dcdc9eL,0xae3026b96460e991L,
        0x7d467bef17ecf7ccL },
      { 0x8a0dbf6705118708L,0x54bfa368f3b2f1c9L,0xa9fc9d5cf2c0e4e0L,
        0xa8c2ad115e93611bL } },
    /* 4 << 252 */
    { { 0x3ef1faf0aa1256bdL,0x0f2245459e4631deL,0x69cb9800de9c2676L,
        0x2601981695782b24L },
      { 0x945c172ca66c0ccdL,0x6c25f635b440719aL,0x917d5dbaa49f681aL,
        0xc0cad047b2dc5df4L } },
    /* 5 << 252 */
    { { 0xd45bcf4c5960ef1cL,0xbabcb16d8c6979d5L,0x8e3be750ae9090d6L,
        0x9481d261ac0eb728L },
      { 0x46b436cd0d6a7d46L,0x6eb1a6a31f976501L,0x5984ffa2dbe1064fL,
        0xe6575fb1f809dc20L } },
    /* 6 << 252 */
    { { 0xf0426d804d974a81L,0x61304f0f97a74be6L,0x2346ff98a9486531L,
        0xa1242ccaf53d781aL },
      { 0x482f03df97355f15L,0xc607ed33bd6058cfL,0x03bc8cd468aefe28L,
        0xa6e7de5a851307e4L } },
    /* 7 << 252 */
    { { 0x2c07df0fc6af7d44L,0x310b251fb15a9188L,0xd42661ced3e15c2fL,
        0x5198fd901b4d8313L },
      { 0x7a6062cdda8368a1L,0x1a905d115e9c2542L,0x1d752b70dae37ceeL,
        0x3ed8c1a516bf84caL } },
    /* 8 << 252 */
    { { 0x5190fb0feecc2f22L,0x3df210f3698d8e60L,0xcce57d3af5f3ce72L,
        0xb2fb6223312b8fc6L },
      { 0x7994700571867c84L,0x141cd92cbe139ebeL,0x415efc9e5de7944eL,
        0xae9ee91945821058L } },
    /* 9 << 252 */
    { { 0xd696e1d95bf363dcL,0x6a1bcfc08251449cL,0xa1b82dffa5fa53e9L,
        0x6c56b5beeef05378L },
      { 0xaf9efe4cc0e74dc3L,0x3d9a7ae9e5c1f1a0L,0x34b385772823c3e5L,
        0x69f297dc41fbabacL } },
    /* 10 << 252 */
    { { 0xf01aff98d74c5a65L,0x979931041951a915L,0x8b211915723096a6L,
        0xf85910c4a769ef1fL },
      { 0x30cefb9e8ddc0eb4L,0xd5957eefbb09607bL,0x2e139c9c2355b499L,
        0x5749531dc1789013L } },
    /* 11 << 252 */
    { { 0x1603ca645475f2d2L,0x57190e0e0a336508L,0x2203b703cea7d558L,
        0xf16eba4dfb5503e3L },
      { 0x62e2ce3db7344a98L,0xebf5b2439a4efa7aL,0x962124551c914064L,
        0xd2c5e31cbe5bbc07L } },
    /* 12 << 252 */
    { { 0x2b5f2f7706c30b28L,0x0931841dbc9823d3L,0xd16fb08badfa6fdbL,
        0x8892bae2d6fd441eL },
      { 0x3fc646302e576983L,0x08c60fb607b05529L,0x32b283b17afc1d4dL,
        0xc9c56965a2f0e37fL } },
    /* 13 << 252 */
    { { 0x8e7191784644e173L,0x4c2a11ecf88b43ffL,0xb13644e67d3ddbb3L,
        0xd4746056c3d8703cL },
      { 0x6611395f55dca667L,0x6359671227c91d73L,0x4ca68a87ea2ff489L,
        0x2864a816337adc1dL } },
    /* 14 << 252 */
    { { 0x8aa830ae224d4f21L,0xda6c122e9f7845dcL,0xb0c61ffcfb240793L,
        0xf4df6842ce8580e9L },
      { 0x94372aaa0a990dc7L,0x42968cd35ce1aa24L,0x177c5ff04df363a5L,
        0xa8c3f73768c4546fL } },
    /* 15 << 252 */
    { { 0xc69750d5bd21c524L,0xbf3b485722a6c4aeL,0xcefcbb98e2883a1dL,
        0x6ffef743ae13f22bL },
      { 0x6316ba605defea01L,0x0a89e6a74ba63810L,0x7f9af1de15ab0e11L,
        0x6247ca15385911c9L } },
    /* 16 << 252 */
    { { 0x6f7b1a6a32f9eaf5L,0x2c440f94acfc13dcL,0x2cf39bc566b18adfL,
        0xb9939fe89f01533fL },
      { 0x031c4553383a6450L,0x16d96ad3f0102087L,0xcbd6fa95501f1360L,
        0x667d3ea065f96c08L } },
    /* 17 << 252 */
    { { 0xa5a7cbfa68a1a680L,0xf131d77942041db7L,0xbefee3acd85d377fL,
        0x6d0ed6b73b62dfa2L },
      { 0xef683f0f1baacfbdL,0xc586c4f2c976cebdL,0x3a4120dc3b163339L,
        0x9ac9b950c79e5c1fL } },
    /* 18 << 252 */
    { { 0xaf1ff35fe294926aL,0x2703bab8a2103168L,0xc645560a658a52bfL,
        0x5ff3ccd9e466fd97L },
      { 0xe62fdc0154867f14L,0x435ef9509cdba39eL,0x2a7bbffd92828accL,
        0xe7538fdbfe763981L } },
    /* 19 << 252 */
    { { 0xedf451738bfe9773L,0xd187fa01471b8b9cL,0x34506c3578fa54dfL,
        0x73cab9fdc2767589L },
      { 0xf8f76c656726f305L,0xea45012d8de332b2L,0xb746f40d87970e03L,
        0xb2b2279a1ba8fbd6L } },
    /* 20 << 252 */
    { { 0x79cdc61021147dbcL,0x738ef6809939a3ccL,0xd66d6ce68101bd8bL,
        0x65612acb09323caaL },
      { 0x6874b37210310a29L,0x3cf30f0a5ee9ecfaL,0x4e1026ad8cfe1df8L,
        0x75a153f7d5989af5L } },
    /* 21 << 252 */
    { { 0xc362ccee8b8e0c49L,0x8adfc0d2b533f3ddL,0xe02ab03ba109572eL,
        0x06efacdcfd3066ecL },
      { 0xf136a8ba3fa28700L,0x48a1e987308cceb9L,0xe8ee7c0368253387L,
        0x47febbe8c2b463c7L } },
    /* 22 << 252 */
    { { 0x485195f239a5c4d3L,0xf42e000ea26241ecL,0x08c64f90cd05368dL,
        0x46fbd381857cdbdbL },
      { 0xf711df8b4c7e16aeL,0x95637e46e4edea42L,0x2df8b206ad171465L,
        0xa31ea8954bccedceL } },
    /* 23 << 252 */
    { { 0x28dbcb7750743bb6L,0x13d12f8ef9cf84b9L,0x39e3d3afc8f7d408L,
        0x5824117feba591d4L },
      { 0xd8ef7c9a1bead2d6L,0x9003a559caf53dd7L,0x33b2365c174cb9a9L,
        0x1149d080adb33afbL } },
    /* 24 << 252 */
    { { 0x55231d00aea9bd3cL,0x07e107c9fdf3f015L,0xf535947dec9d8fceL,
        0x8b64ed8abba349a7L },
      { 0xdd5881fd049301dfL,0xefac9c43e6490fd0L,0xd990285273740a78L,
        0x6eef3724942c326cL } },
    /* 25 << 252 */
    { { 0x5671a6e95cfb3c8cL,0x040aabd20ea29721L,0x24e92ca6eac8da18L,
        0xc34d3d79a31170c3L },
      { 0xf81dd15fb061e416L,0xff7be70e85f80af0L,0xa9faba4bade45cd4L,
        0x42a6ab05505fddd4L } },
    /* 26 << 252 */
    { { 0x17d5821d0a793534L,0x9e094e54ce0ade43L,0xa127fb6dc42cb4d2L,
        0x43865428db12dc99L },
      { 0xb6b1b34759e3bfc1L,0x0b0076a91ec5b810L,0xbf2dd17aa6864982L,
        0x0c45947f9d523c87L } },
    /* 27 << 252 */
    { { 0x9f53372f4c5dd59eL,0x3d0ceaeaca5ce09fL,0xf3ff88e87c0337fbL,
        0xb4fa4593faa022c7L },
      { 0x575240a7d65ea54dL,0xa4ec0a39adb92fb0L,0xc20e737c79429eb1L,
        0xcea931d169addec4L } },
    /* 28 << 252 */
    { { 0x7a29011f3e09f46aL,0x9c36865e0e578a5bL,0x8746ea5171d805f4L,
        0xf024de85e12d3024L },
      { 0xc397b46c15a7f6beL,0x612db6fb1b0580d7L,0xe5342f76f736d087L,
        0x652768538c1e844cL } },
    /* 29 << 252 */
    { { 0xedf48adc113841a5L,0xc21b67e1e5c482f0L,0xe43b0138684a540bL,
        0xc4f2782ba5d4b266L },
      { 0x184e240c397f3664L,0x968e89e70d8788f8L,0xec3eba1a377e18bfL,
        0x4d03cbbc36002652L } },
    /* 30 << 252 */
    { { 0x21eedee71005a953L,0xc178ddf175ba987eL,0xd0d577f6c4ba43f6L,
        0x9486f46c4d6f24fdL },
      { 0x3d33c574c5421895L,0x5be6cb4c842e52abL,0x3809690d9debc9ffL,
        0xe4b1c692a84a5b6fL } },
    /* 31 << 252 */
    { { 0x58b966add7e18b57L,0x7ff0b61e77c94715L,0x0e295883f06add82L,
        0x7c3c04fd65c7f5a4L },
      { 0x4ea9266060223be5L,0x5d843a5789262bfdL,0x35bf4aef36da11c0L,
        0xa6692f14af859eb1L } },
    /* 32 << 252 */
    { { 0xca1fc13ba12fdf41L,0xd798c04b8224f5d2L,0x22f4594e1dd5872bL,
        0xdee12df51bddfda8L },
      { 0x96473ff0ed83420aL,0xf41cf1c78daa27f4L,0x2772cd56aecefd8aL,
        0xd5ddaf184902b47fL } },
    /* 33 << 252 */
    { { 0xff77551fc0798101L,0x8baa01d626946bdaL,0xd0087e47100525f2L,
        0x521d62544c0de308L },
      { 0x4a0f45eb9bbce049L,0x5ee33cbea6c6b96eL,0x9a6af4b7d6a22345L,
        0x0d0d35e738b1b406L } },
    /* 34 << 252 */
    { { 0x9e71252dbbedc29bL,0x3aa70bb6cad1455eL,0xa406fb7a42a1778cL,
        0xd94f9646f0897613L },
      { 0x5256370ff57f66c8L,0x95891e354432f679L,0x75d6423abcb6b3d3L,
        0x79d9ea012367483fL } },
    /* 35 << 252 */
    { { 0x1e36ccc69efb0473L,0x3e64b034dfdc0cecL,0x13bfd326028bb238L,
        0x171e9d96209edd95L },
      { 0xda25838007b22424L,0xe31e97f6d41b8023L,0xdd4ed3907269cecdL,
        0x810fb3c812d5cec6L } },
    /* 36 << 252 */
    { { 0x2f956519babeec88L,0xb0350c52455baf52L,0xa7fb548a48d5abf1L,
        0xcb81bd0cca5e2d9fL },
      { 0xda5ecd39a6d17b19L,0xd2588bab508e5149L,0x1a30cff5c3e23cfdL,
        0x2dd398b4f89f8712L } },
    /* 37 << 252 */
    { { 0x2a9118005b304005L,0xd091be7ad9dece69L,0x147e93daf6cabc89L,
        0x7eac201844935824L },
      { 0xd4aaf2be32f5de9bL,0xe302bc41d9396cd1L,0x3c2794cf2c069d1aL,
        0xf9197eaaa9d433aeL } },
    /* 38 << 252 */
    { { 0x98f822ef4445e8c2L,0xc578360e1383ece8L,0xa5372c1201869457L,
        0x1c6ed00d787d6644L },
      { 0x77fb08cd86531814L,0xeff6ee2663a70db8L,0x980be15380976119L,
        0x534a09bdd69d60c5L } },
    /* 39 << 252 */
    { { 0x71a58b0c759dba20L,0x34d5f06c679c0b40L,0xdc0e7e5fceed2f9fL,
        0xaaa5996e48808edbL },
      { 0x8ca96ff0bcdd88e5L,0x91b02d67c37c2b46L,0xbe4f394895526319L,
        0x4315c7f289be56d1L } },
    /* 40 << 252 */
    { { 0xa312a3c0dc85bba1L,0x3328fa8e431ca797L,0x5438bf1c68fd219aL,
        0x98812c6f85837d74L },
      { 0xe88c4913f8c96d49L,0xcc62e79cc2442acaL,0x4ef3c7d4046655f1L,
        0x04a362eddadab1eaL } },
    /* 41 << 252 */
    { { 0x975e2f3c30a199cfL,0x831e04a9014a165aL,0x1e1d3c53aa126719L,
        0xc42661e01bf707a0L },
      { 0x295b0738aa2da264L,0xb45f5ed865d4ba34L,0x27fb5a129f3938faL,
        0x25fba614cb26f86cL } },
    /* 42 << 252 */
    { { 0x6bd41981cf3c1c4dL,0xd6f9239ca0dedafdL,0x46882526ae55b97fL,
        0x8e6fa99481b628d4L },
      { 0xbdb314dddc0aa158L,0x3534367812ba2a17L,0xac018e8332e2e431L,
        0x43a64e35e65cc63eL } },
    /* 43 << 252 */
    { { 0x887f3a2a0b6603eaL,0xe015426c76b2673fL,0x59dc553027edfe8aL,
        0xea9eacf368d9ebf3L },
      { 0x40301c8ecc3e07caL,0xd8cb9b5b0f57a2e6L,0x542e6b5260ec5864L,
        0xb8791dd617f6affeL } },
    /* 44 << 252 */
    { { 0x6735bd1c798d9993L,0x006d8b25d5da393cL,0x1d675bdb49e6d0d2L,
        0x331d9a108607f99eL },
      { 0x4ff8ab749dc4cd07L,0xa87d4ae164ea3192L,0xdde0d92e41196b5bL,
        0xa15ad47bb2e010ebL } },
    /* 45 << 252 */
    { { 0x23e6003fa5522a75L,0xc6ef3f1b84afa749L,0x9a723f75146d10a3L,
        0x5fa99480119106b0L },
      { 0x01d500dbc0013dbaL,0x10b30ada548edbe0L,0xb2eb046eb04ffc6bL,
        0xa57088f364f25ee2L } },
    /* 46 << 252 */
    { { 0xc0c919c383a068a3L,0x8139559dfbde282fL,0x4e2b5d139fec9a99L,
        0x53bad712fbefa7e6L },
      { 0xa6befe0d2860bd4fL,0x6ea0ae150011bd15L,0xc1ef34632bce3779L,
        0xc09ecb305d742dbbL } },
    /* 47 << 252 */
    { { 0x29526afdf73db19dL,0x7c02c9056a029a40L,0xa778460fde5a48baL,
        0xda05993e77c105f6L },
      { 0xb6d599f9c9ddece9L,0x9f9df6680cfc33caL,0xdcd8ef4fa0aa67a8L,
        0x31277019c3f4d178L } },
    /* 48 << 252 */
    { { 0x98e05abf53e86ae1L,0xc1dc4d903850830dL,0xbd7fd806e06bc33cL,
        0x1ac330d6acf1286fL },
      { 0x28ce2303e1588c1eL,0xdc25e54b1b7e9c19L,0x11e51e494b7149f2L,
        0x551b8391b5c7fa25L } },
    /* 49 << 252 */
    { { 0xa2fc251c1bf69873L,0x099b7b532aec1574L,0x9ff981567c53296aL,
        0xaf3f8d08a2dc60deL },
      { 0x18dd295c59b72d6cL,0x165c9063e75f44fcL,0x9046ee7c427a0c55L,
        0x317ea24dc79ffdb3L } },
    /* 50 << 252 */
    { { 0x6835a3150ef0447dL,0xb2b9c7868068e7c7L,0xe63527140e646af5L,
        0xc5554a91442baaa0L },
      { 0x671febc56d0ba1eaL,0x44f9ef7b0cf649edL,0x4aa0cd610c1dac6bL,
        0x865f3c236e393e68L } },
    /* 51 << 252 */
    { { 0xf6886bcda71dee29L,0x934b0455da44ffaeL,0xda7621c4016d6039L,
        0xf36c41bf3ad35493L },
      { 0x9063135ee5f6ab8dL,0xb0e8eaba47bdc0a8L,0x625306164c737cf3L,
        0x8046423e64f6b6cbL } },
    /* 52 << 252 */
    { { 0x11e50ad77958e3dcL,0x4dab4e16b57234abL,0x6ccfe2c6e0916210L,
        0x4d5dbc3b80f49d40L },
      { 0x2b8ff368ef1b2b1bL,0xf2afb326752fea2aL,0xffa48ea70246e36bL,
        0x3a4bae9b589b7444L } },
    /* 53 << 252 */
    { { 0x80ff984a6ff3efcfL,0x7af53f3056b77b47L,0x1f1c33b09320cae6L,
        0xce1f1c4826fc4ad4L },
      { 0x9cac662bad350ee5L,0xf4c72fffe27a7dbdL,0xd766f986703184e5L,
        0x36d3efd57c5b241eL } },
    /* 54 << 252 */
    { { 0xd4d6e358f7ff5804L,0xa832b3028f5e0bf6L,0x4b3d73f7453d9a22L,
        0xb4dae072df938705L },
      { 0x6bff7b2e92401620L,0x96b8494e9bfa61cdL,0x4bcda341b74dc1e5L,
        0x383fe3d2c19c393dL } },
    /* 55 << 252 */
    { { 0xa375fb70077e8821L,0xea35e04bc17eb9bcL,0x941d21ba7c4dd076L,
        0x916c0a593d0c3d8aL },
      { 0x2c1304e315b2cf47L,0x9233ebf3d0c955c0L,0x77acdd072b2fc935L,
        0xd71b6a7ac04276bfL } },
    /* 56 << 252 */
    { { 0x789ea49bd2ee8d68L,0x89552b460a84a920L,0xe629d5de1a4ea456L,
        0xddfefe8722ddd405L },
      { 0x3d56f6971cdb9e7bL,0x95a861b0a8bf715bL,0xb01248d67896c993L,
        0x3c4e3d9801a3085cL } },
    /* 57 << 252 */
    { { 0x674939e19085b360L,0xae67dea9b589a287L,0xc563856f2bfdcfc9L,
        0x62fa9a80313b685dL },
      { 0x36ff33d97ad501d9L,0xf8bab4dd730ab349L,0x18fd59f3c46ba69dL,
        0x81e08665e65278e9L } },
    /* 58 << 252 */
    { { 0x5a5e803feb8a1e84L,0x5b4eef3547243604L,0x0ee71ee0393d6cdfL,
        0xde4d9deac3a9c6dbL },
      { 0x0c14c37664466b53L,0xc2ce964289e3b45eL,0x6aa8012f54a2de21L,
        0x519759c129b6bc2cL } },
    /* 59 << 252 */
    { { 0x17768527e4667322L,0x09fdfe4dac83b2eaL,0xd422125d04a0d5f5L,
        0x02e8ff962b86b310L },
      { 0xf033628dd7ee97afL,0x778a846c7d72e0e6L,0x06fde613882f63d6L,
        0x9e258b0d8d434f14L } },
    /* 60 << 252 */
    { { 0x5cdda529ccdcd600L,0x37038b38033c4535L,0xd6a1d639391c1d7dL,
        0x4f6489e431d4ce6bL },
      { 0xd1b82f175754e08cL,0x7df268ee75db7bd6L,0x1e4a1202ad14dcfaL,
        0x7ab92ce2ccfb9b77L } },
    /* 61 << 252 */
    { { 0x61388e0323aef997L,0x9981f5bf06440ce3L,0x8d7631dac67d0eddL,
        0xc6ea593fc0a93516L },
      { 0x064a06e0ee841b38L,0x0d1d4f57521ce83fL,0xf7a0e0c370df2613L,
        0x1506cccb84c071abL } },
    /* 62 << 252 */
    { { 0x42a138ec328565e9L,0xe16b4578b8130d16L,0x0628ff2245ba251aL,
        0x016a84ca210e22e8L },
      { 0x8ba14bb494592d43L,0xffee4308785274a5L,0x01fc21ab01354b75L,
        0xc37ce45f7e424674L } },
    /* 63 << 252 */
    { { 0x71e153afa7fe2735L,0x000fcee9c307721fL,0x3b189004805b56e3L,
        0x2f1435aa7f504d9bL },
      { 0xd9aa1ebaa083bd72L,0xf1145036720ccf3dL,0x95b29e274084fa32L,
        0x8862d21301f94f0cL } },
    /* 64 << 252 */
    { { 0x23fc5ddf1510a406L,0x475a78f4c9f0e98dL,0xb6d681c4e72843a0L,
        0xa90af2a44a00c5a6L },
      { 0x95fc6d45a34f4412L,0x60f9c0e2e7f5d703L,0x2bc0642bad110925L,
        0x79abfc10be24a4d5L } },
};

/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Pre-computed table containing multiples of g times powers of 2.
 * Width between powers is 7 bits.
 * Accumulate into the result.
 *
 * r      Resulting point.
 * g      Point to scalar multiply.
 * k      Scalar to multiply by.
 * table  Pre-computed table of points.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_add_only_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 rt[2];
    sp_digit tmp[2 * 4 * 5];
#endif
    sp_point_256* p = NULL;
    sp_digit* negy = NULL;
    int i;
    ecc_recode_256 v[37];
    int err = MP_OKAY;

    (void)g;
    (void)ct;
    (void)heap;


#ifdef WOLFSSL_SP_SMALL_STACK
    rt = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                     DYNAMIC_TYPE_ECC);
    if (rt == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 5, heap,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        negy = tmp;
        p = rt + 1;
    }

    if (err == MP_OKAY) {
        sp_256_ecc_recode_7_4(k, v);

        XMEMCPY(p->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        XMEMCPY(rt->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));

        i = 36;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_65_sm2_4(rt, &table[i * 65], v[i].i);
        }
        else
    #endif
        {
            XMEMCPY(rt->x, table[i * 65 + v[i].i].x, sizeof(table->x));
            XMEMCPY(rt->y, table[i * 65 + v[i].i].y, sizeof(table->y));
        }
        rt->infinity = !v[i].i;
        for (--i; i>=0; i--) {
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_65_sm2_4(p, &table[i * 65], v[i].i);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[i * 65 + v[i].i].x, sizeof(table->x));
                XMEMCPY(p->y, table[i * 65 + v[i].i].y, sizeof(table->y));
            }
            p->infinity = !v[i].i;
            sp_256_sub_sm2_4(negy, p256_sm2_mod, p->y);
            sp_256_norm_4(negy);
            sp_256_cond_copy_sm2_4(p->y, negy, 0 - v[i].neg);
            sp_256_proj_point_add_qz1_sm2_4(rt, rt, p, tmp);
        }
        if (map != 0) {
            sp_256_map_sm2_4(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (tmp != NULL)
#endif
    {
        ForceZero(tmp, sizeof(sp_digit) * 2 * 4 * 5);
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
    #endif
    }
#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(rt, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_sm2_4(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_add_only_sm2_4(r, NULL, p256_sm2_table,
                                      k, map, ct, heap);
}

#ifdef HAVE_INTEL_AVX2
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Pre-computed table containing multiples of g times powers of 2.
 * Width between powers is 7 bits.
 * Accumulate into the result.
 *
 * r      Resulting point.
 * g      Point to scalar multiply.
 * k      Scalar to multiply by.
 * table  Pre-computed table of points.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_add_only_avx2_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 rt[2];
    sp_digit tmp[2 * 4 * 5];
#endif
    sp_point_256* p = NULL;
    sp_digit* negy = NULL;
    int i;
    ecc_recode_256 v[37];
    int err = MP_OKAY;

    (void)g;
    (void)ct;
    (void)heap;


#ifdef WOLFSSL_SP_SMALL_STACK
    rt = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                     DYNAMIC_TYPE_ECC);
    if (rt == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 5, heap,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        negy = tmp;
        p = rt + 1;
    }

    if (err == MP_OKAY) {
        sp_256_ecc_recode_7_4(k, v);

        XMEMCPY(p->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        XMEMCPY(rt->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));

        i = 36;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_65_avx2_sm2_4(rt, &table[i * 65], v[i].i);
        }
        else
    #endif
        {
            XMEMCPY(rt->x, table[i * 65 + v[i].i].x, sizeof(table->x));
            XMEMCPY(rt->y, table[i * 65 + v[i].i].y, sizeof(table->y));
        }
        rt->infinity = !v[i].i;
        for (--i; i>=0; i--) {
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_65_avx2_sm2_4(p, &table[i * 65], v[i].i);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[i * 65 + v[i].i].x, sizeof(table->x));
                XMEMCPY(p->y, table[i * 65 + v[i].i].y, sizeof(table->y));
            }
            p->infinity = !v[i].i;
            sp_256_sub_sm2_4(negy, p256_sm2_mod, p->y);
            sp_256_norm_4(negy);
            sp_256_cond_copy_sm2_4(p->y, negy, 0 - v[i].neg);
            sp_256_proj_point_add_qz1_avx2_sm2_4(rt, rt, p, tmp);
        }
        if (map != 0) {
            sp_256_map_avx2_sm2_4(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (tmp != NULL)
#endif
    {
        ForceZero(tmp, sizeof(sp_digit) * 2 * 4 * 5);
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
    #endif
    }
#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(rt, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_avx2_sm2_4(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_add_only_avx2_sm2_4(r, NULL, p256_sm2_table,
                                      k, map, ct, heap);
}

#endif /* HAVE_INTEL_AVX2 */
#endif /* WOLFSSL_SP_SMALL */
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
    sp_digit k[4];
#endif
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 4, km);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_base_avx2_sm2_4(point, k, map, 1, heap);
        }
        else
#endif
            err = sp_256_ecc_mulmod_base_sm2_4(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_4(point, r);
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
    sp_digit k[4 + 4 * 2 * 6];
#endif
    sp_point_256* addP = NULL;
    sp_digit* tmp = NULL;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(
            sizeof(sp_digit) * (4 + 4 * 2 * 6),
            heap, DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 4;

        sp_256_from_mp(k, 4, km);
        sp_256_point_from_ecc_point_4(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_4(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_4(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_4(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_base_avx2_sm2_4(point, k, 0, 0, heap);
        }
        else
#endif
            err = sp_256_ecc_mulmod_base_sm2_4(point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            sp_256_proj_point_add_avx2_sm2_4(point, point, addP, tmp);
        }
        else
#endif
            sp_256_proj_point_add_sm2_4(point, point, addP, tmp);

        if (map) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                    IS_INTEL_AVX2(cpuid_flags)) {
                sp_256_map_avx2_sm2_4(point, point, tmp);
            }
            else
#endif
                sp_256_map_sm2_4(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_4(point, r);
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
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_add_one_sm2_4(sp_digit* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_from_bin_sm2_bswap(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_from_bin_sm2_movbe(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_256_from_bin(sp_digit* r, int size, const byte* a, int n)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_256_from_bin_sm2_movbe(r, size, a, n);
    }
    else
#endif
    {
        sp_256_from_bin_sm2_bswap(r, size, a, n);
    }
}

/* Generates a scalar that is in the range 1..order-1.
 *
 * rng  Random number generator.
 * k    Scalar value.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
static int sp_256_ecc_gen_k_sm2_4(WC_RNG* rng, sp_digit* k)
{
#ifndef WC_NO_RNG
    int err;
    byte buf[32];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_256_from_bin(k, 4, buf, (int)sizeof(buf));
            if (sp_256_cmp_sm2_4(k, p256_sm2_order2) <= 0) {
                sp_256_add_one_sm2_4(k);
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
    sp_digit k[4];
#endif
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256* infinity = NULL;
#endif
    int err = MP_OKAY;

#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

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
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
        infinity = point + 1;
    #endif

        err = sp_256_ecc_gen_k_sm2_4(rng, k);
    }
    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_base_avx2_sm2_4(point, k, 1, 1, NULL);
       }
        else
#endif
            err = sp_256_ecc_mulmod_base_sm2_4(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_avx2_sm2_4(infinity, point, p256_sm2_order, 1, 1,
                                                                          NULL);
        }
        else
#endif
            err = sp_256_ecc_mulmod_4(infinity, point, p256_sm2_order, 1, 1, NULL);
    }
    if (err == MP_OKAY) {
        if (sp_256_iszero_4(point->x) || sp_256_iszero_4(point->y)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_256_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_4(point, pub);
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
    sp_256_ecc_mulmod_4_ctx mulmod_ctx;
    sp_digit k[4];
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
            err = sp_256_ecc_gen_k_4(rng, ctx->k);
            if (err == MP_OKAY) {
                err = FP_WOULDBLOCK;
                ctx->state = 1;
            }
            break;
        case 1:
            err = sp_256_ecc_mulmod_base_4_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
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
            err = sp_256_ecc_mulmod_4_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      infinity, ctx->point, p256_sm2_order, 1, 1);
            if (err == MP_OKAY) {
                if (sp_256_iszero_4(ctx->point->x) ||
                    sp_256_iszero_4(ctx->point->y)) {
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
                err = sp_256_point_to_ecc_point_4(ctx->point, pub);
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
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_to_bin_bswap_sm2_4(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_256_to_bin_movbe_sm2_4(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 32
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_256_to_bin_4(sp_digit* r, byte* a)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_256_to_bin_movbe_sm2_4(r, a);
    }
    else
#endif
    {
        sp_256_to_bin_bswap_sm2_4(r, a);
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
    sp_digit k[4];
#endif
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

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
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 4, priv);
        sp_256_point_from_ecc_point_4(point, pub);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_avx2_sm2_4(point, point, k, 1, 1, heap);
        }
        else
#endif
            err = sp_256_ecc_mulmod_sm2_4(point, point, k, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_256_to_bin_4(point->x, out);
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
        sp_256_ecc_mulmod_4_ctx mulmod_ctx;
    };
    sp_digit k[4];
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
            sp_256_from_mp(ctx->k, 4, priv);
            sp_256_point_from_ecc_point_4(&ctx->point, pub);
            ctx->state = 1;
            break;
        case 1:
            err = sp_256_ecc_mulmod_sm2_4_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      &ctx->point, &ctx->point, ctx->k, 1, 1, heap);
            if (err == MP_OKAY) {
                sp_256_to_bin_4(ctx->point.x, out);
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
#ifdef HAVE_INTEL_AVX2
#endif /* HAVE_INTEL_AVX2 */
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_256_cond_add_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
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
static void sp_256_mont_mul_order_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_sm2_4(r, a, b);
    sp_256_mont_reduce_order_sm2_4(r, p256_sm2_order, p256_sm2_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_order_sm2_4(sp_digit* r, const sp_digit* a)
{
    sp_256_sqr_sm2_4(r, a);
    sp_256_mont_reduce_order_sm2_4(r, p256_sm2_order, p256_sm2_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P256 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_n_order_sm2_4(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_256_mont_sqr_order_sm2_4(r, a);
    for (i=1; i<n; i++) {
        sp_256_mont_sqr_order_sm2_4(r, r);
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
static void sp_256_mont_inv_order_sm2_4(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 4);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_order_sm2_4(t, t);
        if ((p256_sm2_order_minus_2[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_4(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 4U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 4;
    sp_digit* t3 = td + 4 * 4;
    sp_digit* t4 = td + 6 * 4;
    int i;

    /* t4= a^2 */
    sp_256_mont_sqr_order_sm2_4(t4, a);
    /* t = a^3 = t4* a */
    sp_256_mont_mul_order_sm2_4(t, t4, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_order_sm2_4(t2, t, 2);
    /* t4= a^e = t2 * t4 */
    sp_256_mont_mul_order_sm2_4(t4, t2, t4);
    /* t3= a^f = t2 * t */
    sp_256_mont_mul_order_sm2_4(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_256_mont_sqr_n_order_sm2_4(t2, t3, 4);
    /* t4 = a^fe = t2 * t4 */
    sp_256_mont_mul_order_sm2_4(t4, t2, t4);
    /* t = a^ff = t2 * t3 */
    sp_256_mont_mul_order_sm2_4(t, t2, t3);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_order_sm2_4(t2, t, 8);
    /* t4 = a^fffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_4(t4, t2, t4);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_order_sm2_4(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_order_sm2_4(t2, t, 16);
    /* t4= a^fffffffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_4(t4, t2, t4);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_4(t, t2, t);
    /* t2= a^fffffffe00000000 = t4 ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_4(t4, t4, 32);
    /* t4= a^fffffffeffffffff = t4 * t */
    sp_256_mont_mul_order_sm2_4(t4, t4, t);
    /* t2= a^ffffffff00000000 = t ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_4(t2, t, 32);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_4(t, t2, t);
    /* t4= a^fffffffeffffffff0000000000000000 = t4 ^ 2 ^ 64 */
    sp_256_mont_sqr_n_order_sm2_4(t4, t4, 64);
    /* t2= a^fffffffeffffffffffffffffffffffff = t4 * t2 */
    sp_256_mont_mul_order_sm2_4(t2, t4, t);
    /* t2= a^fffffffeffffffffffffffffffffffff7203d */
    for (i=127; i>=108; i--) {
        sp_256_mont_sqr_order_sm2_4(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_4(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df */
    sp_256_mont_sqr_n_order_sm2_4(t2, t2, 4);
    sp_256_mont_mul_order_sm2_4(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bb */
    for (i=103; i>=48; i--) {
        sp_256_mont_sqr_order_sm2_4(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_4(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf */
    sp_256_mont_sqr_n_order_sm2_4(t2, t2, 4);
    sp_256_mont_mul_order_sm2_4(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412 */
    for (i=43; i>=4; i--) {
        sp_256_mont_sqr_order_sm2_4(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_sm2_4(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54120 */
    sp_256_mont_sqr_n_order_sm2_4(t2, t2, 4);
    /* r = a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121 */
    sp_256_mont_mul_order_sm2_4(r, t2, a);
#endif /* WOLFSSL_SP_SMALL */
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_INTEL_AVX2
#ifdef HAVE_ECC_SIGN
/* Multiply two number mod the order of P256 curve. (r = a * b mod order)
 *
 * r  Result of the multiplication.
 * a  First operand of the multiplication.
 * b  Second operand of the multiplication.
 */
static void sp_256_mont_mul_order_avx2_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_avx2_sm2_4(r, a, b);
    sp_256_mont_reduce_order_avx2_sm2_4(r, p256_sm2_order, p256_sm2_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_order_avx2_sm2_4(sp_digit* r, const sp_digit* a)
{
    sp_256_sqr_avx2_sm2_4(r, a);
    sp_256_mont_reduce_order_avx2_sm2_4(r, p256_sm2_order, p256_sm2_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P256 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_n_order_avx2_sm2_4(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_256_mont_sqr_order_avx2_sm2_4(r, a);
    for (i=1; i<n; i++) {
        sp_256_mont_sqr_order_avx2_sm2_4(r, r);
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
static void sp_256_mont_inv_order_avx2_sm2_4(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 4);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_order_avx2_sm2_4(t, t);
        if ((p256_sm2_order_minus_2[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_avx2_sm2_4(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 4U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 4;
    sp_digit* t3 = td + 4 * 4;
    sp_digit* t4 = td + 6 * 4;
    int i;

    /* t4= a^2 */
    sp_256_mont_sqr_order_avx2_sm2_4(t4, a);
    /* t = a^3 = t4* a */
    sp_256_mont_mul_order_avx2_sm2_4(t, t4, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t, 2);
    /* t4= a^e = t2 * t4 */
    sp_256_mont_mul_order_avx2_sm2_4(t4, t2, t4);
    /* t3= a^f = t2 * t */
    sp_256_mont_mul_order_avx2_sm2_4(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t3, 4);
    /* t4 = a^fe = t2 * t4 */
    sp_256_mont_mul_order_avx2_sm2_4(t4, t2, t4);
    /* t = a^ff = t2 * t3 */
    sp_256_mont_mul_order_avx2_sm2_4(t, t2, t3);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t, 8);
    /* t4 = a^fffe = t2 * t4 */
    sp_256_mont_mul_order_avx2_sm2_4(t4, t2, t4);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_order_avx2_sm2_4(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t, 16);
    /* t4= a^fffffffe = t2 * t4 */
    sp_256_mont_mul_order_avx2_sm2_4(t4, t2, t4);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_order_avx2_sm2_4(t, t2, t);
    /* t2= a^fffffffe00000000 = t4 ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t4, t4, 32);
    /* t4= a^fffffffeffffffff = t4 * t */
    sp_256_mont_mul_order_avx2_sm2_4(t4, t4, t);
    /* t2= a^ffffffff00000000 = t ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t, 32);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_256_mont_mul_order_avx2_sm2_4(t, t2, t);
    /* t4= a^fffffffeffffffff0000000000000000 = t4 ^ 2 ^ 64 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t4, t4, 64);
    /* t2= a^fffffffeffffffffffffffffffffffff = t4 * t2 */
    sp_256_mont_mul_order_avx2_sm2_4(t2, t4, t);
    /* t2= a^fffffffeffffffffffffffffffffffff7203d */
    for (i=127; i>=108; i--) {
        sp_256_mont_sqr_order_avx2_sm2_4(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_avx2_sm2_4(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t2, 4);
    sp_256_mont_mul_order_avx2_sm2_4(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bb */
    for (i=103; i>=48; i--) {
        sp_256_mont_sqr_order_avx2_sm2_4(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_avx2_sm2_4(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t2, 4);
    sp_256_mont_mul_order_avx2_sm2_4(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412 */
    for (i=43; i>=4; i--) {
        sp_256_mont_sqr_order_avx2_sm2_4(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_avx2_sm2_4(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54120 */
    sp_256_mont_sqr_n_order_avx2_sm2_4(t2, t2, 4);
    /* r = a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121 */
    sp_256_mont_mul_order_avx2_sm2_4(r, t2, a);
#endif /* WOLFSSL_SP_SMALL */
}
#endif /* HAVE_ECC_SIGN */

#endif /* HAVE_INTEL_AVX2 */
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
    sp_digit d[4 * 10*4];
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    (void)heap;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8 * 2 * 4, heap,
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
        e = d + 0 * 4;
        x = d + 2 * 4;
        k = d + 4 * 4;
        r = d + 6 * 4;
        tmp = d + 8 * 4;
        s = e;
        xInv = x;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_bin(e, 4, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_256_from_mp(x, 4, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_256_ecc_gen_k_sm2_4(rng, k);
        }
        else {
            sp_256_from_mp(k, 4, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_256_ecc_mulmod_base_avx2_sm2_4(point, k, 1, 1, heap);
            else
#endif
                err = sp_256_ecc_mulmod_base_sm2_4(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = (point->x + e) mod order */
            c = sp_256_add_sm2_4(r, point->x, e);
            sp_256_cond_sub_sm2_4(r, r, p256_sm2_order, 0L - (sp_digit)c);
            c = sp_256_cmp_sm2_4(r, p256_sm2_order);
            sp_256_cond_sub_sm2_4(r, r, p256_sm2_order, 0L - (sp_digit)(c >= 0));

            /* Try again if r == 0 */
            if (sp_256_iszero_4(r)) {
                continue;
            }

            /* Try again if r + k == 0 */
            c = sp_256_add_sm2_4(s, k, r);
            sp_256_cond_sub_sm2_4(s, s, p256_sm2_order, 0L - (sp_digit)c);
            c = sp_256_cmp_sm2_4(s, p256_sm2_order);
            sp_256_cond_sub_sm2_4(s, s, p256_sm2_order, 0L - (sp_digit)(c >= 0));
            if (sp_256_iszero_4(s)) {
                continue;
            }

            /* Conv x to Montgomery form (mod order) */
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_256_mul_avx2_sm2_4(x, x, p256_sm2_norm_order);
            else
#endif
                sp_256_mul_sm2_4(x, x, p256_sm2_norm_order);
            err = sp_256_mod_sm2_4(x, x, p256_sm2_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_4(x);

            /* s = k - r * x */
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_256_mont_mul_order_avx2_sm2_4(s, x, r);
            else
#endif
                sp_256_mont_mul_order_sm2_4(s, x, r);
        }
        if (err == MP_OKAY) {
            sp_256_norm_4(s);
            c = sp_256_sub_sm2_4(s, k, s);
            sp_256_cond_add_sm2_4(s, s, p256_sm2_order, c);
            sp_256_norm_4(s);

            /* xInv = 1/(x+1) mod order */
            sp_256_add_sm2_4(x, x, p256_sm2_norm_order);

#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_256_mont_inv_order_avx2_sm2_4(xInv, x, tmp);
            else
#endif
                sp_256_mont_inv_order_sm2_4(xInv, x, tmp);
            sp_256_norm_4(xInv);

            /* s = s * (x+1)^-1 mod order */
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_256_mont_mul_order_avx2_sm2_4(s, s, xInv);
            else
#endif
                sp_256_mont_mul_order_sm2_4(s, s, xInv);
            sp_256_norm_4(s);

            c = sp_256_cmp_sm2_4(s, p256_sm2_order);
            sp_256_cond_sub_sm2_4(s, s, p256_sm2_order,
                0L - (sp_digit)(c >= 0));
            sp_256_norm_4(s);

            /* Check that signature is usable. */
            if (sp_256_iszero_4(s) == 0) {
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
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 4);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
    if (point != NULL) {
        XFREE(point, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 4U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 4U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 4U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 4U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 4U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 4U * 2U * 4U);
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
    sp_digit d[8*4 * 7];
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 20 * 4, heap,
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
        e   = d + 0 * 4;
        r   = d + 2 * 4;
        s   = d + 4 * 4;
        tmp = d + 6 * 4;
        p2 = p1 + 1;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_mp(r, 4, rm);
        sp_256_from_mp(s, 4, sm);
        sp_256_from_mp(p2->x, 4, pX);
        sp_256_from_mp(p2->y, 4, pY);
        sp_256_from_mp(p2->z, 4, pZ);


        if (sp_256_iszero_4(r) ||
            sp_256_iszero_4(s) ||
            (sp_256_cmp_sm2_4(r, p256_sm2_order) >= 0) ||
            (sp_256_cmp_sm2_4(s, p256_sm2_order) >= 0)) {
            *res = 0;
            done = 1;
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        carry = sp_256_add_sm2_4(e, r, s);
        sp_256_norm_4(e);
        if (carry || sp_256_cmp_sm2_4(e, p256_sm2_order) >= 0) {
            sp_256_sub_sm2_4(e, e, p256_sm2_order);            sp_256_norm_4(e);
        }

        if (sp_256_iszero_4(e)) {
           *res = 0;
           done = 1;
        }
    }
    if ((err == MP_OKAY) && (!done)) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_256_ecc_mulmod_base_avx2_sm2_4(p1, s, 0, 0, heap);
        else
#endif
            err = sp_256_ecc_mulmod_base_sm2_4(p1, s, 0, 0, heap);
    }
    if ((err == MP_OKAY) && (!done)) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            err = sp_256_ecc_mulmod_avx2_sm2_4(p2, p2, e, 0, 0, heap);
        }
        else
#endif
        {
            err = sp_256_ecc_mulmod_sm2_4(p2, p2, e, 0, 0, heap);
        }
    }

    if ((err == MP_OKAY) && (!done)) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_256_proj_point_add_avx2_sm2_4(p1, p1, p2, tmp);
            if (sp_256_iszero_4(p1->z)) {
                if (sp_256_iszero_4(p1->x) && sp_256_iszero_4(p1->y)) {
                    sp_256_proj_point_dbl_avx2_sm2_4(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    XMEMCPY(p1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
                }
            }
        }
        else
#endif
        {
            sp_256_proj_point_add_sm2_4(p1, p1, p2, tmp);
            if (sp_256_iszero_4(p1->z)) {
                if (sp_256_iszero_4(p1->x) && sp_256_iszero_4(p1->y)) {
                    sp_256_proj_point_dbl_sm2_4(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    XMEMCPY(p1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
                }
            }
        }

        /* z' = z'.z' */
        sp_256_mont_sqr_sm2_4(p1->z, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        XMEMSET(p1->x + 4, 0, 4U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_4(p1->x, p256_sm2_mod, p256_sm2_mp_mod);
        /* (r - e + n*order).z'.z' mod prime == (s.G + t.Q)->x' */
        /* Load e, subtract from r. */
        sp_256_from_bin(e, 4, hash, (int)hashLen);
        if (sp_256_cmp_sm2_4(r, e) < 0) {
            (void)sp_256_add_sm2_4(r, r, p256_sm2_order);
        }
        sp_256_sub_sm2_4(e, r, e);
        sp_256_norm_4(e);
        /* x' == (r - e).z'.z' mod prime */
        sp_256_mont_mul_sm2_4(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        *res = (int)(sp_256_cmp_sm2_4(p1->x, s) == 0);
        if (*res == 0) {
            carry = sp_256_add_sm2_4(e, e, p256_sm2_order);
            if (!carry && sp_256_cmp_sm2_4(e, p256_sm2_mod) < 0) {
                /* x' == (r - e + order).z'.z' mod prime */
                sp_256_mont_mul_sm2_4(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
                *res = (int)(sp_256_cmp_sm2_4(p1->x, s) == 0);
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
static int sp_256_ecc_is_point_sm2_4(const sp_point_256* point,
    void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t1 = NULL;
#else
    sp_digit t1[4 * 4];
#endif
    sp_digit* t2 = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t1 = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 4, heap, DYNAMIC_TYPE_ECC);
    if (t1 == NULL)
        err = MEMORY_E;
#endif
    (void)heap;

    if (err == MP_OKAY) {
        t2 = t1 + 2 * 4;

        /* y^2 - x^3 - a.x = b */
        sp_256_sqr_sm2_4(t1, point->y);
        (void)sp_256_mod_sm2_4(t1, t1, p256_sm2_mod);
        sp_256_sqr_sm2_4(t2, point->x);
        (void)sp_256_mod_sm2_4(t2, t2, p256_sm2_mod);
        sp_256_mul_sm2_4(t2, t2, point->x);
        (void)sp_256_mod_sm2_4(t2, t2, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(t1, t1, t2, p256_sm2_mod);

        /* y^2 - x^3 + 3.x = b, when a = -3  */
        sp_256_mont_add_sm2_4(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_4(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_4(t1, t1, point->x, p256_sm2_mod);


        if (sp_256_cmp_sm2_4(t1, p256_sm2_b) != 0) {
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
        sp_256_from_mp(pub->x, 4, pX);
        sp_256_from_mp(pub->y, 4, pY);
        sp_256_from_bin(pub->z, 4, one, (int)sizeof(one));

        err = sp_256_ecc_is_point_sm2_4(pub, NULL);
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
    sp_digit priv[4];
    sp_point_256 pub[2];
#endif
    sp_point_256* p = NULL;
    const byte one[1] = { 1 };
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif


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
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4, heap,
                                  DYNAMIC_TYPE_ECC);
        if (priv == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        p = pub + 1;

        sp_256_from_mp(pub->x, 4, pX);
        sp_256_from_mp(pub->y, 4, pY);
        sp_256_from_bin(pub->z, 4, one, (int)sizeof(one));
        if (privm)
            sp_256_from_mp(priv, 4, privm);

        /* Check point at infinitiy. */
        if ((sp_256_iszero_4(pub->x) != 0) &&
            (sp_256_iszero_4(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    /* Check range of X and Y */
    if ((err == MP_OKAY) &&
            ((sp_256_cmp_sm2_4(pub->x, p256_sm2_mod) >= 0) ||
             (sp_256_cmp_sm2_4(pub->y, p256_sm2_mod) >= 0))) {
        err = ECC_OUT_OF_RANGE_E;
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_256_ecc_is_point_sm2_4(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            err = sp_256_ecc_mulmod_avx2_sm2_4(p, pub, p256_sm2_order, 1, 1, heap);
        }
        else
#endif
            err = sp_256_ecc_mulmod_sm2_4(p, pub, p256_sm2_order, 1, 1, heap);
    }
    /* Check result is infinity */
    if ((err == MP_OKAY) && ((sp_256_iszero_4(p->x) == 0) ||
                             (sp_256_iszero_4(p->y) == 0))) {
        err = ECC_INF_E;
    }

    if (privm) {
        if (err == MP_OKAY) {
            /* Base * private = point */
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                    IS_INTEL_AVX2(cpuid_flags)) {
                err = sp_256_ecc_mulmod_base_avx2_sm2_4(p, priv, 1, 1, heap);
            }
            else
#endif
                err = sp_256_ecc_mulmod_base_sm2_4(p, priv, 1, 1, heap);
        }
        /* Check result is public key */
        if ((err == MP_OKAY) &&
                ((sp_256_cmp_sm2_4(p->x, pub->x) != 0) ||
                 (sp_256_cmp_sm2_4(p->y, pub->y) != 0))) {
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
    sp_digit tmp[2 * 4 * 6];
    sp_point_256 p[2];
#endif
    sp_point_256* q = NULL;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * 2, NULL,
                                         DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 6, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        q = p + 1;

        sp_256_from_mp(p->x, 4, pX);
        sp_256_from_mp(p->y, 4, pY);
        sp_256_from_mp(p->z, 4, pZ);
        sp_256_from_mp(q->x, 4, qX);
        sp_256_from_mp(q->y, 4, qY);
        sp_256_from_mp(q->z, 4, qZ);
        p->infinity = sp_256_iszero_4(p->x) &
                      sp_256_iszero_4(p->y);
        q->infinity = sp_256_iszero_4(q->x) &
                      sp_256_iszero_4(q->y);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            sp_256_proj_point_add_avx2_sm2_4(p, p, q, tmp);
        }
        else
#endif
            sp_256_proj_point_add_sm2_4(p, p, q, tmp);
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
    sp_digit tmp[2 * 4 * 2];
    sp_point_256 p[1];
#endif
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256), NULL,
                                         DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 2, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 4, pX);
        sp_256_from_mp(p->y, 4, pY);
        sp_256_from_mp(p->z, 4, pZ);
        p->infinity = sp_256_iszero_4(p->x) &
                      sp_256_iszero_4(p->y);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            sp_256_proj_point_dbl_avx2_sm2_4(p, p, tmp);
        }
        else
#endif
            sp_256_proj_point_dbl_sm2_4(p, p, tmp);
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
    sp_digit tmp[2 * 4 * 5];
    sp_point_256 p[1];
#endif
    int err = MP_OKAY;

#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256), NULL,
                                         DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4 * 5, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 4, pX);
        sp_256_from_mp(p->y, 4, pY);
        sp_256_from_mp(p->z, 4, pZ);
        p->infinity = sp_256_iszero_4(p->x) &
                      sp_256_iszero_4(p->y);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            sp_256_map_avx2_sm2_4(p, p, tmp);
        }
        else
#endif
            sp_256_map_sm2_4(p, p, tmp);
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
static int sp_256_mont_sqrt_sm2_4(sp_digit* y)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t = NULL;
#else
    sp_digit t[2 * 4];
#endif
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4, NULL, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            int i;

            XMEMCPY(t, y, sizeof(sp_digit) * 4);
            for (i=252; i>=0; i--) {
                sp_256_mont_sqr_avx2_sm2_4(t, t, p256_sm2_mod, p256_sm2_mp_mod);
                if (p256_sm2_sqrt_power[i / 64] & ((sp_digit)1 << (i % 64)))
                    sp_256_mont_mul_avx2_sm2_4(t, t, y, p256_sm2_mod, p256_sm2_mp_mod);
            }
            XMEMCPY(y, t, sizeof(sp_digit) * 4);
        }
        else
#endif
        {
            int i;

            XMEMCPY(t, y, sizeof(sp_digit) * 4);
            for (i=252; i>=0; i--) {
                sp_256_mont_sqr_sm2_4(t, t, p256_sm2_mod, p256_sm2_mp_mod);
                if (p256_sm2_sqrt_power[i / 64] & ((sp_digit)1 << (i % 64)))
                    sp_256_mont_mul_sm2_4(t, t, y, p256_sm2_mod, p256_sm2_mp_mod);
            }
            XMEMCPY(y, t, sizeof(sp_digit) * 4);
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
    sp_digit x[4 * 4];
#endif
    sp_digit* y = NULL;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    x = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 4, NULL, DYNAMIC_TYPE_ECC);
    if (x == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        y = x + 2 * 4;

        sp_256_from_mp(x, 4, xm);
        err = sp_256_mod_mul_norm_sm2_4(x, x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags) &&
                IS_INTEL_AVX2(cpuid_flags)) {
            sp_256_mont_sqr_avx2_sm2_4(y, x, p256_sm2_mod, p256_sm2_mp_mod);
            sp_256_mont_mul_avx2_sm2_4(y, y, x, p256_sm2_mod, p256_sm2_mp_mod);
        }
        else
#endif
        {
            sp_256_mont_sqr_sm2_4(y, x, p256_sm2_mod, p256_sm2_mp_mod);
            sp_256_mont_mul_sm2_4(y, y, x, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = x^3 - 3x */
        sp_256_mont_sub_sm2_4(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(y, y, x, p256_sm2_mod);
        /* y = x^3 - 3x + b */
        err = sp_256_mod_mul_norm_sm2_4(x, p256_sm2_b, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        sp_256_mont_add_sm2_4(y, y, x, p256_sm2_mod);
        /* y = sqrt(x^3 - 3x + b) */
        err = sp_256_mont_sqrt_sm2_4(y);
    }
    if (err == MP_OKAY) {
        XMEMSET(y + 4, 0, 4U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_4(y, p256_sm2_mod, p256_sm2_mp_mod);
        if ((((word32)y[0] ^ (word32)odd) & 1U) != 0U) {
            sp_256_mont_sub_sm2_4(y, p256_sm2_mod, y, p256_sm2_mod);
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
#endif /* WOLFSSL_SP_X86_64_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
