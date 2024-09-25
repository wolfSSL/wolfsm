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

#ifdef WOLFSSL_SP_ARM_THUMB_ASM
#define SP_PRINT_NUM(var, name, total, words, bits)         \
    do {                                                    \
        int ii;                                             \
        fprintf(stderr, name "=0x");                        \
        for (ii = (((bits) + 31) / 32) - 1; ii >= 0; ii--)  \
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
    sp_digit x[2 * 8];
    /* Y ordinate of point. */
    sp_digit y[2 * 8];
    /* Z ordinate of point. */
    sp_digit z[2 * 8];
    /* Indicates point is at infinity. */
    int infinity;
} sp_point_256;

/* The modulus (prime) of the curve SM2 P256. */
static const sp_digit p256_sm2_mod[8] = {
    0xffffffff,0xffffffff,0x00000000,0xffffffff,0xffffffff,0xffffffff,
    0xffffffff,0xfffffffe
};
/* The Montgomery normalizer for modulus of the curve P256. */
static const sp_digit p256_sm2_norm_mod[8] = {
    0x00000001,0x00000000,0xffffffff,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000001
};
/* The Montgomery multiplier for modulus of the curve P256. */
static const sp_digit p256_sm2_mp_mod = 0x00000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P256. */
static const sp_digit p256_sm2_order[8] = {
    0x39d54123,0x53bbf409,0x21c6052b,0x7203df6b,0xffffffff,0xffffffff,
    0xffffffff,0xfffffffe
};
#endif
/* The order of the curve P256 minus 2. */
static const sp_digit p256_sm2_order2[8] = {
    0x39d54121,0x53bbf409,0x21c6052b,0x7203df6b,0xffffffff,0xffffffff,
    0xffffffff,0xfffffffe
};
#if defined(HAVE_ECC_SIGN)
/* The Montgomery normalizer for order of the curve P256. */
static const sp_digit p256_sm2_norm_order[8] = {
    0xc62abedd,0xac440bf6,0xde39fad4,0x8dfc2094,0x00000000,0x00000000,
    0x00000000,0x00000001
};
#endif
#if defined(HAVE_ECC_SIGN)
/* The Montgomery multiplier for order of the curve P256. */
static const sp_digit p256_sm2_mp_order = 0x72350975;
#endif
/* The base point of curve P256. */
static const sp_point_256 p256_sm2_base = {
    /* X ordinate */
    {
        0x334c74c7,0x715a4589,0xf2660be1,0x8fe30bbf,0x6a39c994,0x5f990446,
        0x1f198119,0x32c4ae2c,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Y ordinate */
    {
        0x2139f0a0,0x02df32e5,0xc62a4740,0xd0a9877c,0x6b692153,0x59bdcee3,
        0xf4f6779c,0xbc3736a2,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Z ordinate */
    {
        0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
        0x00000000,0x00000000,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* infinity */
    0
};
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p256_sm2_b[8] = {
    0x4d940e93,0xddbcbd41,0x15ab8f92,0xf39789f5,0xcf6509a7,0x4d5a9e4b,
    0x9d9f5e34,0x28e9fa9e
};
#endif

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_256_mul_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit t[8 * 2];
    sp_digit* tmp = t;
    __asm__ __volatile__ (
        "movs	r3, #0\n\t"
        "movs	r4, #0\n\t"
        "mov	r8, r3\n\t"
        "mov	r11, %[tmp]\n\t"
        "mov	r9, %[a]\n\t"
        "mov	r10, %[b]\n\t"
        "movs	r6, #32\n\t"
        "add	r6, r6, r9\n\t"
        "mov	r12, r6\n\t"
        "\n"
    "L_sp_256_mul_sm2_8_words_%=:\n\t"
        "movs	%[tmp], #0\n\t"
        "movs	r5, #0\n\t"
        "movs	r6, #28\n\t"
        "mov	%[a], r8\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[a], %[a], r6\n\t"
#else
        "sub	%[a], %[a], r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs	r6, r6\n\t"
#else
        "sbc	r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r6, r6\n\t"
#else
        "mvn	r6, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	%[a], %[a], r6\n\t"
#elif defined(__clang__)
        "ands	%[a], r6\n\t"
#else
        "and	%[a], r6\n\t"
#endif
        "mov	%[b], r8\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[b], %[b], %[a]\n\t"
#else
        "sub	%[b], %[b], %[a]\n\t"
#endif
        "add	%[a], %[a], r9\n\t"
        "add	%[b], %[b], r10\n\t"
        "\n"
    "L_sp_256_mul_sm2_8_mul_%=:\n\t"
        "# Multiply Start\n\t"
        "ldrh	r6, [%[a]]\n\t"
        "ldrh	r7, [%[b]]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r7, r6, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r6\n\t"
#else
        "mul	r7, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r7\n\t"
#else
        "add	r3, r3, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, %[tmp]\n\t"
#elif defined(__clang__)
        "adcs	r4, %[tmp]\n\t"
#else
        "adc	r4, %[tmp]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[tmp]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[tmp]\n\t"
#else
        "adc	r5, %[tmp]\n\t"
#endif
        "ldr	r7, [%[b]]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r7, #16\n\t"
#else
        "lsr	r7, r7, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #16\n\t"
#else
        "lsr	r7, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #16\n\t"
#else
        "lsl	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[tmp]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[tmp]\n\t"
#else
        "adc	r5, %[tmp]\n\t"
#endif
        "ldr	r6, [%[a]]\n\t"
        "ldr	r7, [%[b]]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r6, #16\n\t"
#else
        "lsr	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r7, #16\n\t"
#else
        "lsr	r7, r7, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r7, r6, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r6\n\t"
#else
        "mul	r7, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r7\n\t"
#else
        "add	r4, r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[tmp]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[tmp]\n\t"
#else
        "adc	r5, %[tmp]\n\t"
#endif
        "ldrh	r7, [%[b]]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #16\n\t"
#else
        "lsr	r7, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #16\n\t"
#else
        "lsl	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[tmp]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[tmp]\n\t"
#else
        "adc	r5, %[tmp]\n\t"
#endif
        "# Multiply Done\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #4\n\t"
#else
        "add	%[a], %[a], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[b], %[b], #4\n\t"
#else
        "sub	%[b], %[b], #4\n\t"
#endif
        "cmp	%[a], r12\n\t"
        "beq	L_sp_256_mul_sm2_8_done_mul_%=\n\t"
        "mov	r6, r8\n\t"
        "add	r6, r6, r9\n\t"
        "cmp	%[a], r6\n\t"
        "ble	L_sp_256_mul_sm2_8_mul_%=\n\t"
        "\n"
    "L_sp_256_mul_sm2_8_done_mul_%=:\n\t"
        "mov	%[tmp], r11\n\t"
        "mov	r7, r8\n\t"
        "str	r3, [%[tmp], r7]\n\t"
        "movs	r3, r4\n\t"
        "movs	r4, r5\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r7, r7, #4\n\t"
#else
        "add	r7, r7, #4\n\t"
#endif
        "mov	r8, r7\n\t"
        "movs	r6, #56\n\t"
        "cmp	r7, r6\n\t"
        "ble	L_sp_256_mul_sm2_8_words_%=\n\t"
        "str	r3, [%[tmp], r7]\n\t"
        "mov	%[a], r9\n\t"
        "mov	%[b], r10\n\t"
        : [a] "+l" (a), [b] "+l" (b), [tmp] "+l" (tmp)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "cc"
    );

    XMEMCPY(r, t, sizeof(t));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_sm2_8(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "movs	r3, #0\n\t"
        "movs	r4, #0\n\t"
        "movs	r5, #0\n\t"
        "mov	r8, r3\n\t"
        "mov	r11, %[r]\n\t"
        "movs	r6, #0x40\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "negs	r6, r6\n\t"
#else
        "neg	r6, r6\n\t"
#endif
        "add	sp, sp, r6\n\t"
        "mov	r10, sp\n\t"
        "mov	r9, %[a]\n\t"
        "\n"
    "L_sp_256_sqr_sm2_8_words_%=:\n\t"
        "movs	%[r], #0\n\t"
        "movs	r6, #28\n\t"
        "mov	%[a], r8\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[a], %[a], r6\n\t"
#else
        "sub	%[a], %[a], r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs	r6, r6\n\t"
#else
        "sbc	r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r6, r6\n\t"
#else
        "mvn	r6, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	%[a], %[a], r6\n\t"
#elif defined(__clang__)
        "ands	%[a], r6\n\t"
#else
        "and	%[a], r6\n\t"
#endif
        "mov	r2, r8\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r2, r2, %[a]\n\t"
#else
        "sub	r2, r2, %[a]\n\t"
#endif
        "add	%[a], %[a], r9\n\t"
        "add	r2, r2, r9\n\t"
        "\n"
    "L_sp_256_sqr_sm2_8_mul_%=:\n\t"
        "cmp	r2, %[a]\n\t"
        "beq	L_sp_256_sqr_sm2_8_sqr_%=\n\t"
        "# Multiply * 2: Start\n\t"
        "ldrh	r6, [%[a]]\n\t"
        "ldrh	r7, [r2]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r7, r6, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r6\n\t"
#else
        "mul	r7, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r7\n\t"
#else
        "add	r3, r3, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r4, %[r]\n\t"
#else
        "adc	r4, %[r]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r7\n\t"
#else
        "add	r3, r3, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r4, %[r]\n\t"
#else
        "adc	r4, %[r]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "ldr	r7, [r2]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r7, #16\n\t"
#else
        "lsr	r7, r7, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #16\n\t"
#else
        "lsr	r7, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #16\n\t"
#else
        "lsl	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "ldr	r6, [%[a]]\n\t"
        "ldr	r7, [r2]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r6, #16\n\t"
#else
        "lsr	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r7, #16\n\t"
#else
        "lsr	r7, r7, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r7, r6, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r6\n\t"
#else
        "mul	r7, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r7\n\t"
#else
        "add	r4, r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r7\n\t"
#else
        "add	r4, r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "ldrh	r7, [r2]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #16\n\t"
#else
        "lsr	r7, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #16\n\t"
#else
        "lsl	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "# Multiply * 2: Done\n\t"
        "bal	L_sp_256_sqr_sm2_8_done_sqr_%=\n\t"
        "\n"
    "L_sp_256_sqr_sm2_8_sqr_%=:\n\t"
        "mov	r12, r2\n\t"
        "ldr	r2, [%[a]]\n\t"
        "# Square: Start\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r2, #16\n\t"
#else
        "lsr	r7, r2, #16\n\t"
#endif
        "uxth	r6, r2\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r6, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r6\n\t"
#else
        "mul	r6, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r7, r7, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r7\n\t"
#else
        "mul	r7, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r2, #16\n\t"
#else
        "lsr	r7, r2, #16\n\t"
#endif
        "uxth	r6, r2\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #15\n\t"
#else
        "lsr	r7, r6, #15\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #17\n\t"
#else
        "lsl	r6, r6, #17\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "# Square: Done\n\t"
        "mov	r2, r12\n\t"
        "\n"
    "L_sp_256_sqr_sm2_8_done_sqr_%=:\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #4\n\t"
#else
        "add	%[a], %[a], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r2, r2, #4\n\t"
#else
        "sub	r2, r2, #4\n\t"
#endif
        "movs	r6, #32\n\t"
        "add	r6, r6, r9\n\t"
        "cmp	%[a], r6\n\t"
        "beq	L_sp_256_sqr_sm2_8_done_mul_%=\n\t"
        "cmp	%[a], r2\n\t"
        "bgt	L_sp_256_sqr_sm2_8_done_mul_%=\n\t"
        "mov	r7, r8\n\t"
        "add	r7, r7, r9\n\t"
        "cmp	%[a], r7\n\t"
        "ble	L_sp_256_sqr_sm2_8_mul_%=\n\t"
        "\n"
    "L_sp_256_sqr_sm2_8_done_mul_%=:\n\t"
        "mov	%[r], r10\n\t"
        "mov	r7, r8\n\t"
        "str	r3, [%[r], r7]\n\t"
        "movs	r3, r4\n\t"
        "movs	r4, r5\n\t"
        "movs	r5, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r7, r7, #4\n\t"
#else
        "add	r7, r7, #4\n\t"
#endif
        "mov	r8, r7\n\t"
        "movs	r6, #56\n\t"
        "cmp	r7, r6\n\t"
        "ble	L_sp_256_sqr_sm2_8_words_%=\n\t"
        "mov	%[a], r9\n\t"
        "str	r3, [%[r], r7]\n\t"
        "mov	%[r], r11\n\t"
        "mov	%[a], r10\n\t"
        "movs	r3, #60\n\t"
        "\n"
    "L_sp_256_sqr_sm2_8_store_%=:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, #4\n\t"
#else
        "sub	r3, r3, #4\n\t"
#endif
        "bge	L_sp_256_sqr_sm2_8_store_%=\n\t"
        "movs	r6, #0x40\n\t"
        "add	sp, sp, r6\n\t"
        : [r] "+l" (r), [a] "+l" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "cc"
    );
}

#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_256_add_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "movs	r6, %[a]\n\t"
        "movs	r7, #0\n\t"
        "movs	r3, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r6, r6, #32\n\t"
#else
        "add	r6, r6, #32\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r7, r7, #1\n\t"
#else
        "sub	r7, r7, #1\n\t"
#endif
        "\n"
    "L_sp_256_add_sm2_8_word_%=:\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r7\n\t"
#else
        "add	r3, r3, r7\n\t"
#endif
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r5\n\t"
#elif defined(__clang__)
        "adcs	r4, r5\n\t"
#else
        "adc	r4, r5\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "movs	r3, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "adcs	r3, r3\n\t"
#else
        "adc	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #4\n\t"
#else
        "add	%[a], %[a], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[b], %[b], #4\n\t"
#else
        "add	%[b], %[b], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[r], %[r], #4\n\t"
#else
        "add	%[r], %[r], #4\n\t"
#endif
        "cmp	%[a], r6\n\t"
        "bne	L_sp_256_add_sm2_8_word_%=\n\t"
        "movs	%[r], r3\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "cc"
    );
    return (uint32_t)(size_t)r;
}

#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_256_add_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "movs	%[r], #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	%[r], %[r], %[r]\n\t"
#elif defined(__clang__)
        "adcs	%[r], %[r]\n\t"
#else
        "adc	%[r], %[r]\n\t"
#endif
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "cc"
    );
    return (uint32_t)(size_t)r;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_256_sub_in_place_sm2_8(sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "movs	r7, %[a]\n\t"
        "movs	r2, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r7, r7, #32\n\t"
#else
        "add	r7, r7, #32\n\t"
#endif
        "\n"
    "L_sp_256_sub_in_place_sm2_8_words_%=:\n\t"
        "movs	r5, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r2\n\t"
#else
        "sub	r5, r5, r2\n\t"
#endif
        "ldr	r3, [%[a]]\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "ldr	r6, [%[b], #4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
        "str	r3, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r2\n\t"
#elif defined(__clang__)
        "sbcs	r2, r2\n\t"
#else
        "sbc	r2, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #8\n\t"
#else
        "add	%[a], %[a], #8\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[b], %[b], #8\n\t"
#else
        "add	%[b], %[b], #8\n\t"
#endif
        "cmp	%[a], r7\n\t"
        "bne	L_sp_256_sub_in_place_sm2_8_words_%=\n\t"
        "movs	%[a], r2\n\t"
        : [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "cc"
    );
    return (uint32_t)(size_t)a;
}

#else
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_256_sub_in_place_sm2_8(sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldm	%[b]!, {r4, r5}\n\t"
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r2, r2, r4\n\t"
#else
        "sub	r2, r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
        "stm	%[a]!, {r2, r3}\n\t"
        "ldm	%[b]!, {r4, r5}\n\t"
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "sbcs	r2, r4\n\t"
#else
        "sbc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
        "stm	%[a]!, {r2, r3}\n\t"
        "ldm	%[b]!, {r4, r5}\n\t"
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "sbcs	r2, r4\n\t"
#else
        "sbc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
        "stm	%[a]!, {r2, r3}\n\t"
        "ldm	%[b]!, {r4, r5}\n\t"
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "sbcs	r2, r4\n\t"
#else
        "sbc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
        "stm	%[a]!, {r2, r3}\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	%[a], %[a], %[a]\n\t"
#elif defined(__clang__)
        "sbcs	%[a], %[a]\n\t"
#else
        "sbc	%[a], %[a]\n\t"
#endif
        : [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r2", "r3", "r4", "r5", "cc"
    );
    return (uint32_t)(size_t)a;
}

#endif /* WOLFSSL_SP_SMALL */
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
SP_NOINLINE static sp_digit sp_256_cond_sub_sm2_8(sp_digit* r,
        const sp_digit* a, const sp_digit* b, sp_digit m)
{
    __asm__ __volatile__ (
        "movs	r4, #0\n\t"
        "movs	r5, #32\n\t"
        "mov	r8, r5\n\t"
        "movs	r7, #0\n\t"
        "\n"
    "L_sp_256_cond_sub_sm2_8_words_%=:\n\t"
        "ldr	r6, [%[b], r7]\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, %[m]\n\t"
#elif defined(__clang__)
        "ands	r6, %[m]\n\t"
#else
        "and	r6, %[m]\n\t"
#endif
        "movs	r5, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r4\n\t"
#else
        "sub	r5, r5, r4\n\t"
#endif
        "ldr	r5, [%[a], r7]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r4\n\t"
#elif defined(__clang__)
        "sbcs	r4, r4\n\t"
#else
        "sbc	r4, r4\n\t"
#endif
        "str	r5, [%[r], r7]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r7, r7, #4\n\t"
#else
        "add	r7, r7, #4\n\t"
#endif
        "cmp	r7, r8\n\t"
        "blt	L_sp_256_cond_sub_sm2_8_words_%=\n\t"
        "movs	%[r], r4\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b), [m] "+l" (m)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "cc"
    );
    return (uint32_t)(size_t)r;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
SP_NOINLINE static void sp_256_mul_d_sm2_8(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "movs	r6, #32\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r6, r6, %[a]\n\t"
#else
        "add	r6, r6, %[a]\n\t"
#endif
        "mov	r8, %[r]\n\t"
        "mov	r9, r6\n\t"
        "movs	r3, #0\n\t"
        "movs	r4, #0\n\t"
        "\n"
    "L_sp_256_mul_d_sm2_8_%=:\n\t"
        "movs	%[r], #0\n\t"
        "movs	r5, #0\n\t"
        "# A[] * B\n\t"
        "ldrh	r6, [%[a]]\n\t"
        "uxth	r7, %[b]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r7, r6, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r6\n\t"
#else
        "mul	r7, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r7\n\t"
#else
        "add	r3, r3, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r4, %[r]\n\t"
#else
        "adc	r4, %[r]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, %[b], #16\n\t"
#else
        "lsr	r7, %[b], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #16\n\t"
#else
        "lsr	r7, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #16\n\t"
#else
        "lsl	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "ldr	r6, [%[a]]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r6, #16\n\t"
#else
        "lsr	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, %[b], #16\n\t"
#else
        "lsr	r7, %[b], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r7, r6, r7\n\t"
#elif defined(__clang__)
        "muls	r7, r6\n\t"
#else
        "mul	r7, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r7\n\t"
#else
        "add	r4, r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "uxth	r7, %[b]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r7, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r7\n\t"
#else
        "mul	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r7, r6, #16\n\t"
#else
        "lsr	r7, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #16\n\t"
#else
        "lsl	r6, r6, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, %[r]\n\t"
#elif defined(__clang__)
        "adcs	r5, %[r]\n\t"
#else
        "adc	r5, %[r]\n\t"
#endif
        "# A[] * B - Done\n\t"
        "mov	%[r], r8\n\t"
        "str	r3, [%[r]]\n\t"
        "movs	r3, r4\n\t"
        "movs	r4, r5\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[r], %[r], #4\n\t"
#else
        "add	%[r], %[r], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #4\n\t"
#else
        "add	%[a], %[a], #4\n\t"
#endif
        "mov	r8, %[r]\n\t"
        "cmp	%[a], r9\n\t"
        "blt	L_sp_256_mul_d_sm2_8_%=\n\t"
        "str	r3, [%[r]]\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "cc"
    );
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 *
 * Note that this is an approximate div. It may give an answer 1 larger.
 */
SP_NOINLINE static sp_digit div_256_word_8(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    __asm__ __volatile__ (
        "movs	r3, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, %[div], #1\n\t"
#else
        "lsr	r5, %[div], #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, #1\n\t"
#else
        "add	r5, r5, #1\n\t"
#endif
        "mov	r8, %[d0]\n\t"
        "mov	r9, %[d1]\n\t"
        "# Do top 32\n\t"
        "movs	r6, r5\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r6, r6, %[d1]\n\t"
#else
        "sub	r6, r6, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs	r6, r6\n\t"
#else
        "sbc	r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r3\n\t"
#else
        "add	r3, r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, r6\n\t"
#else
        "sub	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r5\n\t"
#elif defined(__clang__)
        "ands	r6, r5\n\t"
#else
        "and	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[d1], %[d1], r6\n\t"
#else
        "sub	%[d1], %[d1], r6\n\t"
#endif
        "movs	r4, #29\n\t"
        "\n"
    "L_div_256_word_8_loop_%=:\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d0], %[d0], #1\n\t"
#else
        "lsl	%[d0], %[d0], #1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	%[d1], %[d1], %[d1]\n\t"
#elif defined(__clang__)
        "adcs	%[d1], %[d1]\n\t"
#else
        "adc	%[d1], %[d1]\n\t"
#endif
        "movs	r6, r5\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r6, r6, %[d1]\n\t"
#else
        "sub	r6, r6, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs	r6, r6\n\t"
#else
        "sbc	r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r3\n\t"
#else
        "add	r3, r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, r6\n\t"
#else
        "sub	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r5\n\t"
#elif defined(__clang__)
        "ands	r6, r5\n\t"
#else
        "and	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[d1], %[d1], r6\n\t"
#else
        "sub	%[d1], %[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, #1\n\t"
#else
        "sub	r4, r4, #1\n\t"
#endif
        "bpl	L_div_256_word_8_loop_%=\n\t"
        "movs	r7, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r3\n\t"
#else
        "add	r3, r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, #1\n\t"
#else
        "add	r3, r3, #1\n\t"
#endif
        "# r * div - Start\n\t"
        "uxth	%[d1], r3\n\t"
        "uxth	r4, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r4, %[d1], r4\n\t"
#elif defined(__clang__)
        "muls	r4, %[d1]\n\t"
#else
        "mul	r4, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[div], #16\n\t"
#else
        "lsr	r6, %[div], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, %[d1], #16\n\t"
#else
        "lsr	r5, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	%[d1], r3, #16\n\t"
#else
        "lsr	%[d1], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, %[d1], r6\n\t"
#elif defined(__clang__)
        "muls	r6, %[d1]\n\t"
#else
        "mul	r6, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
        "uxth	r6, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[d1], #16\n\t"
#else
        "lsr	r6, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs	r5, r6\n\t"
#else
        "adc	r5, r6\n\t"
#endif
        "# r * div - Done\n\t"
        "mov	%[d1], r8\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[d1], %[d1], r4\n\t"
#else
        "sub	%[d1], %[d1], r4\n\t"
#endif
        "movs	r4, %[d1]\n\t"
        "mov	%[d1], r9\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	%[d1], %[d1], r5\n\t"
#elif defined(__clang__)
        "sbcs	%[d1], r5\n\t"
#else
        "sbc	%[d1], r5\n\t"
#endif
        "movs	r5, %[d1]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
        "# r * div - Start\n\t"
        "uxth	%[d1], r3\n\t"
        "uxth	r4, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r4, %[d1], r4\n\t"
#elif defined(__clang__)
        "muls	r4, %[d1]\n\t"
#else
        "mul	r4, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[div], #16\n\t"
#else
        "lsr	r6, %[div], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, %[d1], #16\n\t"
#else
        "lsr	r5, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	%[d1], r3, #16\n\t"
#else
        "lsr	%[d1], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, %[d1], r6\n\t"
#elif defined(__clang__)
        "muls	r6, %[d1]\n\t"
#else
        "mul	r6, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
        "uxth	r6, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[d1], #16\n\t"
#else
        "lsr	r6, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs	r5, r6\n\t"
#else
        "adc	r5, r6\n\t"
#endif
        "# r * div - Done\n\t"
        "mov	%[d1], r8\n\t"
        "mov	r6, r9\n\t"
#ifdef WOLFSSL_KEIL
        "subs	r4, %[d1], r4\n\t"
#else
#ifdef __clang__
        "subs	r4, %[d1], r4\n\t"
#else
        "sub	r4, %[d1], r4\n\t"
#endif
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r5\n\t"
#elif defined(__clang__)
        "sbcs	r6, r5\n\t"
#else
        "sbc	r6, r5\n\t"
#endif
        "movs	r5, r6\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
        "# r * div - Start\n\t"
        "uxth	%[d1], r3\n\t"
        "uxth	r4, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r4, %[d1], r4\n\t"
#elif defined(__clang__)
        "muls	r4, %[d1]\n\t"
#else
        "mul	r4, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[div], #16\n\t"
#else
        "lsr	r6, %[div], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, %[d1], #16\n\t"
#else
        "lsr	r5, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	%[d1], r3, #16\n\t"
#else
        "lsr	%[d1], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, %[d1], r6\n\t"
#elif defined(__clang__)
        "muls	r6, %[d1]\n\t"
#else
        "mul	r6, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
        "uxth	r6, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[d1], #16\n\t"
#else
        "lsr	r6, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs	r5, r6\n\t"
#else
        "adc	r5, r6\n\t"
#endif
        "# r * div - Done\n\t"
        "mov	%[d1], r8\n\t"
        "mov	r6, r9\n\t"
#ifdef WOLFSSL_KEIL
        "subs	r4, %[d1], r4\n\t"
#else
#ifdef __clang__
        "subs	r4, %[d1], r4\n\t"
#else
        "sub	r4, %[d1], r4\n\t"
#endif
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r5\n\t"
#elif defined(__clang__)
        "sbcs	r6, r5\n\t"
#else
        "sbc	r6, r5\n\t"
#endif
        "movs	r5, r6\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
        "# r * div - Start\n\t"
        "uxth	%[d1], r3\n\t"
        "uxth	r4, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r4, %[d1], r4\n\t"
#elif defined(__clang__)
        "muls	r4, %[d1]\n\t"
#else
        "mul	r4, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[div], #16\n\t"
#else
        "lsr	r6, %[div], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, %[d1], #16\n\t"
#else
        "lsr	r5, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	%[d1], r3, #16\n\t"
#else
        "lsr	%[d1], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, %[d1], r6\n\t"
#elif defined(__clang__)
        "muls	r6, %[d1]\n\t"
#else
        "mul	r6, %[d1]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
        "uxth	r6, %[div]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	%[d1], r6, %[d1]\n\t"
#elif defined(__clang__)
        "muls	%[d1], r6\n\t"
#else
        "mul	%[d1], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[d1], #16\n\t"
#else
        "lsr	r6, %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d1], %[d1], #16\n\t"
#else
        "lsl	%[d1], %[d1], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, %[d1]\n\t"
#else
        "add	r4, r4, %[d1]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs	r5, r6\n\t"
#else
        "adc	r5, r6\n\t"
#endif
        "# r * div - Done\n\t"
        "mov	%[d1], r8\n\t"
        "mov	r6, r9\n\t"
#ifdef WOLFSSL_KEIL
        "subs	r4, %[d1], r4\n\t"
#else
#ifdef __clang__
        "subs	r4, %[d1], r4\n\t"
#else
        "sub	r4, %[d1], r4\n\t"
#endif
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r5\n\t"
#elif defined(__clang__)
        "sbcs	r6, r5\n\t"
#else
        "sbc	r6, r5\n\t"
#endif
        "movs	r5, r6\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
        "movs	r6, %[div]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r6, r6, r4\n\t"
#else
        "sub	r6, r6, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs	r6, r6\n\t"
#else
        "sbc	r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, r6\n\t"
#else
        "sub	r3, r3, r6\n\t"
#endif
        "movs	%[d1], r3\n\t"
        : [d1] "+l" (d1), [d0] "+l" (d0), [div] "+l" (div)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "cc"
    );
    return (uint32_t)(size_t)d1;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_256_mask_8(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<8; i++) {
        r[i] = a[i] & m;
    }
#else
    r[0] = a[0] & m;
    r[1] = a[1] & m;
    r[2] = a[2] & m;
    r[3] = a[3] & m;
    r[4] = a[4] & m;
    r[5] = a[5] & m;
    r[6] = a[6] & m;
    r[7] = a[7] & m;
#endif
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
SP_NOINLINE static sp_int32 sp_256_cmp_sm2_8(const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "movs	r2, #0\n\t"
        "movs	r3, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r3, r3\n\t"
#else
        "mvn	r3, r3\n\t"
#endif
        "movs	r6, #28\n\t"
        "\n"
    "L_sp_256_cmp_sm2_8_words_%=:\n\t"
        "ldr	r7, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r7, r7, r3\n\t"
#elif defined(__clang__)
        "ands	r7, r3\n\t"
#else
        "and	r7, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	r5, r5, r3\n\t"
#elif defined(__clang__)
        "ands	r5, r3\n\t"
#else
        "and	r5, r3\n\t"
#endif
        "movs	r4, r7\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r7, r7, r5\n\t"
#else
        "sub	r7, r7, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "sbcs	r7, r7\n\t"
#else
        "sbc	r7, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r2, r2, r7\n\t"
#else
        "add	r2, r2, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r7, r7\n\t"
#else
        "mvn	r7, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	r3, r3, r7\n\t"
#elif defined(__clang__)
        "ands	r3, r7\n\t"
#else
        "and	r3, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r4\n\t"
#else
        "sub	r5, r5, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "sbcs	r7, r7\n\t"
#else
        "sbc	r7, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r2, r2, r7\n\t"
#else
        "sub	r2, r2, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r7, r7\n\t"
#else
        "mvn	r7, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	r3, r3, r7\n\t"
#elif defined(__clang__)
        "ands	r3, r7\n\t"
#else
        "and	r3, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r6, r6, #4\n\t"
#else
        "sub	r6, r6, #4\n\t"
#endif
        "bge	L_sp_256_cmp_sm2_8_words_%=\n\t"
        "movs	%[a], r2\n\t"
        : [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "cc"
    );
    return (uint32_t)(size_t)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_256_div_sm2_8(const sp_digit* a, const sp_digit* d,
        sp_digit* m, sp_digit* r)
{
    sp_digit t1[16], t2[9];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[7];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 8);
    r1 = sp_256_cmp_sm2_8(&t1[8], d) >= 0;
    sp_256_cond_sub_sm2_8(&t1[8], &t1[8], d, (sp_digit)0 - r1);
    for (i = 7; i >= 0; i--) {
        volatile sp_digit mask = (sp_digit)0 - (t1[8 + i] == div);
        sp_digit hi = t1[8 + i] + mask;
        r1 = div_256_word_8(hi, t1[8 + i - 1], div);
        r1 |= mask;

        sp_256_mul_d_sm2_8(t2, d, r1);
        t1[8 + i] += sp_256_sub_in_place_sm2_8(&t1[i], t2);
        t1[8 + i] -= t2[8];
        sp_256_mask_8(t2, d, t1[8 + i]);
        t1[8 + i] += sp_256_add_sm2_8(&t1[i], &t1[i], t2);
        sp_256_mask_8(t2, d, t1[8 + i]);
        t1[8 + i] += sp_256_add_sm2_8(&t1[i], &t1[i], t2);
    }

    r1 = sp_256_cmp_sm2_8(t1, d) >= 0;
    sp_256_cond_sub_sm2_8(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_256_mod_sm2_8(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    int ret;
    ret = sp_256_div_sm2_8(a, m, NULL, r);
    return ret;
}

/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mod_mul_norm_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_256_mul_sm2_8(r, a, p256_sm2_norm_mod);
    return sp_256_mod_sm2_8(r, r, m);
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_256_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 32
    int i;
    sp_digit j = (sp_digit)0 - (sp_digit)a->used;
    int o = 0;

    for (i = 0; i < size; i++) {
        sp_digit mask = (sp_digit)0 - (j >> 31);
        r[i] = a->dp[o] & mask;
        j++;
        o += (int)(j >> 31);
    }
#elif DIGIT_BIT > 32
    unsigned int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < (unsigned int)a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffff;
        s = 32U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 32U) <= (word32)DIGIT_BIT) {
            s += 32U;
            r[j] &= 0xffffffff;
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
        if (s + DIGIT_BIT >= 32) {
            r[j] &= 0xffffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 32 - s;
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
static void sp_256_point_from_ecc_point_8(sp_point_256* p,
        const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_256_from_mp(p->x, 8, pm->x);
    sp_256_from_mp(p->y, 8, pm->y);
    sp_256_from_mp(p->z, 8, pm->z);
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
#if DIGIT_BIT == 32
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 8);
        r->used = 8;
        mp_clamp(r);
#elif DIGIT_BIT < 32
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 8; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 32) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 32 - s;
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 8; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 32 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 32 - s;
            }
            else {
                s += 32;
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
static int sp_256_point_to_ecc_point_8(const sp_point_256* p, ecc_point* pm)
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

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_256_mont_reduce_sm2_8(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    (void)mp;
    (void)m;

    __asm__ __volatile__ (
        "movs	r2, #0\n\t"
        "movs	r1, #0\n\t"
        "# i = 0\n\t"
        "mov	r8, r2\n\t"
        "\n"
    "L_sp_256_mont_reduce_8_mod_%=:\n\t"
        "movs	r4, #0\n\t"
        "# mu = a[i] * 1 (mp) = a[i]\n\t"
        "ldr	r3, [%[a]]\n\t"
        "# a[i+0] += -1 * mu\n\t"
        "movs	r5, r3\n\t"
        "str	r4, [%[a]]\n\t"
        "# a[i+1] += -1 * mu\n\t"
        "ldr	r6, [%[a], #4]\n\t"
        "movs	r4, r3\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r3\n\t"
#else
        "sub	r5, r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "sbcs	r4, r2\n\t"
#else
        "sbc	r4, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "adcs	r4, r2\n\t"
#else
        "adc	r4, r2\n\t"
#endif
        "str	r5, [%[a], #4]\n\t"
        "# a[i+2] += 0 * mu\n\t"
        "ldr	r6, [%[a], #8]\n\t"
        "movs	r5, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r2\n\t"
#elif defined(__clang__)
        "adcs	r5, r2\n\t"
#else
        "adc	r5, r2\n\t"
#endif
        "str	r4, [%[a], #8]\n\t"
        "# a[i+3] += -1 * mu\n\t"
        "ldr	r6, [%[a], #12]\n\t"
        "movs	r4, r3\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r3\n\t"
#else
        "sub	r5, r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "sbcs	r4, r2\n\t"
#else
        "sbc	r4, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "adcs	r4, r2\n\t"
#else
        "adc	r4, r2\n\t"
#endif
        "str	r5, [%[a], #12]\n\t"
        "# a[i+4] += -1 * mu\n\t"
        "ldr	r6, [%[a], #16]\n\t"
        "movs	r5, r3\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r3\n\t"
#else
        "sub	r4, r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r2\n\t"
#elif defined(__clang__)
        "sbcs	r5, r2\n\t"
#else
        "sbc	r5, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r2\n\t"
#elif defined(__clang__)
        "adcs	r5, r2\n\t"
#else
        "adc	r5, r2\n\t"
#endif
        "str	r4, [%[a], #16]\n\t"
        "# a[i+5] += -1 * mu\n\t"
        "ldr	r6, [%[a], #20]\n\t"
        "movs	r4, r3\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r3\n\t"
#else
        "sub	r5, r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "sbcs	r4, r2\n\t"
#else
        "sbc	r4, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "adcs	r4, r2\n\t"
#else
        "adc	r4, r2\n\t"
#endif
        "str	r5, [%[a], #20]\n\t"
        "# a[i+6] += -1 * mu\n\t"
        "ldr	r6, [%[a], #24]\n\t"
        "movs	r5, r3\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r3\n\t"
#else
        "sub	r4, r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r2\n\t"
#elif defined(__clang__)
        "sbcs	r5, r2\n\t"
#else
        "sbc	r5, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r2\n\t"
#elif defined(__clang__)
        "adcs	r5, r2\n\t"
#else
        "adc	r5, r2\n\t"
#endif
        "str	r4, [%[a], #24]\n\t"
        "# a[i+7] += -2 * mu\n\t"
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r7, [%[a], #32]\n\t"
#ifdef WOLFSSL_KEIL
        "adds	r4, r1, r3\n\t"
#else
    #ifdef __clang__
        "adds	r4, r1, r3\n\t"
    #else
        "add	r4, r1, r3\n\t"
    #endif
#endif
        "movs	r1, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r3\n\t"
#else
        "sub	r5, r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "sbcs	r4, r2\n\t"
#else
        "sbc	r4, r2\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "sbcs	r1, r2\n\t"
#else
        "sbc	r1, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r3\n\t"
#else
        "sub	r5, r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r2\n\t"
#elif defined(__clang__)
        "sbcs	r4, r2\n\t"
#else
        "sbc	r4, r2\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "sbcs	r1, r2\n\t"
#else
        "sbc	r1, r2\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r6\n\t"
#else
        "add	r5, r5, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r5, [%[a], #28]\n\t"
        "str	r4, [%[a], #32]\n\t"
        "# i += 1\n\t"
        "movs	r6, #4\n\t"
        "add	r8, r8, r6\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #4\n\t"
#else
        "add	%[a], %[a], #4\n\t"
#endif
        "movs	r6, #32\n\t"
        "cmp	r8, r6\n\t"
        "blt	L_sp_256_mont_reduce_8_mod_%=\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[a], %[a], #32\n\t"
#else
        "sub	%[a], %[a], #32\n\t"
#endif
        "movs	r3, r1\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r1, r1, #1\n\t"
#else
        "sub	r1, r1, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r1, r1\n\t"
#else
        "mvn	r1, r1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "subs	r3, r1, r3\n\t"
#else
#ifdef __clang__
        "subs	r3, r1, r3\n\t"
#else
        "sub	r3, r1, r3\n\t"
#endif
#endif
        "ldr	r5, [%[a], #32]\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "ldr	r6, [%[a], #40]\n\t"
        "ldr	r7, [%[a], #44]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r1\n\t"
#else
        "sub	r5, r5, r1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r1\n\t"
#elif defined(__clang__)
        "sbcs	r4, r1\n\t"
#else
        "sbc	r4, r1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r2\n\t"
#elif defined(__clang__)
        "sbcs	r6, r2\n\t"
#else
        "sbc	r6, r2\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r7, r7, r1\n\t"
#elif defined(__clang__)
        "sbcs	r7, r1\n\t"
#else
        "sbc	r7, r1\n\t"
#endif
        "str	r5, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
        "str	r6, [%[a], #8]\n\t"
        "str	r7, [%[a], #12]\n\t"
        "ldr	r5, [%[a], #48]\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "ldr	r6, [%[a], #56]\n\t"
        "ldr	r7, [%[a], #60]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r1\n\t"
#elif defined(__clang__)
        "sbcs	r5, r1\n\t"
#else
        "sbc	r5, r1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r1\n\t"
#elif defined(__clang__)
        "sbcs	r4, r1\n\t"
#else
        "sbc	r4, r1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r1\n\t"
#elif defined(__clang__)
        "sbcs	r6, r1\n\t"
#else
        "sbc	r6, r1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r7, r7, r3\n\t"
#elif defined(__clang__)
        "sbcs	r7, r3\n\t"
#else
        "sbc	r7, r3\n\t"
#endif
        "str	r5, [%[a], #16]\n\t"
        "str	r4, [%[a], #20]\n\t"
        "str	r6, [%[a], #24]\n\t"
        "str	r7, [%[a], #28]\n\t"
        : [a] "+l" (a)
        :
        : "memory", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "cc"
    );
}

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_256_mont_reduce_order_sm2_8(sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    __asm__ __volatile__ (
        "movs	r7, #0\n\t"
        "mov	r8, %[mp]\n\t"
        "mov	r12, r7\n\t"
        "mov	lr, %[m]\n\t"
        "mov	r9, %[a]\n\t"
        "mov	r11, %[a]\n\t"
        "movs	r5, #28\n\t"
        "movs	r6, #32\n\t"
        "add	r9, r9, r5\n\t"
        "add	r11, r11, r6\n\t"
        "\n"
    "L_sp_256_mont_reduce_order_8_mod_%=:\n\t"
        "movs	r7, #0\n\t"
        "movs	r4, #0\n\t"
        "# a[i] += m[0] * mu\n\t"
        "ldm	%[m]!, {%[mp]}\n\t"
        "ldm	%[a]!, {r3}\n\t"
        "# mu = a[i] * mp\n\t"
        "mov	r5, r8\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r5, r3, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r3\n\t"
#else
        "mul	r5, r3\n\t"
#endif
        "mov	r10, r5\n\t"
        "# Multiply m[0] and mu - Start\n\t"
        "mov	r5, r10\n\t"
        "uxth	r6, %[mp]\n\t"
        "uxth	r5, r5\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r5, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r5\n\t"
#else
        "mul	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[mp], #16\n\t"
#else
        "lsr	r6, %[mp], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r5, r6, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r6\n\t"
#else
        "mul	r5, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r5, #16\n\t"
#else
        "lsr	r6, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r5, r5, #16\n\t"
#else
        "lsl	r5, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "mov	r5, r10\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[mp], #16\n\t"
#else
        "lsr	r6, %[mp], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r5, #16\n\t"
#else
        "lsr	r5, r5, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, r5, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r5\n\t"
#else
        "mul	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
        "uxth	r6, %[mp]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r5, r6, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r6\n\t"
#else
        "mul	r5, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r5, #16\n\t"
#else
        "lsr	r6, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r5, r5, #16\n\t"
#else
        "lsl	r5, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "# Multiply m[0] and mu - Done\n\t"
        "\n"
    "L_sp_256_mont_reduce_order_8_word_%=:\n\t"
        "# a[i+j] += m[j] * mu\n\t"
        "ldr	r3, [%[a]]\n\t"
        "ldm	%[m]!, {%[mp]}\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r4\n\t"
#else
        "add	r3, r3, r4\n\t"
#endif
        "movs	r4, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
        "# Multiply m[j] and mu - Start\n\t"
        "mov	r5, r10\n\t"
        "uxth	r6, %[mp]\n\t"
        "uxth	r5, r5\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r5, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r5\n\t"
#else
        "mul	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "adcs	r4, r7\n\t"
#else
        "adc	r4, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[mp], #16\n\t"
#else
        "lsr	r6, %[mp], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r5, r6, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r6\n\t"
#else
        "mul	r5, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r5, #16\n\t"
#else
        "lsr	r6, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r5, r5, #16\n\t"
#else
        "lsl	r5, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "mov	r5, r10\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[mp], #16\n\t"
#else
        "lsr	r6, %[mp], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r5, #16\n\t"
#else
        "lsr	r5, r5, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, r5, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r5\n\t"
#else
        "mul	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
        "uxth	r6, %[mp]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r5, r6, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r6\n\t"
#else
        "mul	r5, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r5, #16\n\t"
#else
        "lsr	r6, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r5, r5, #16\n\t"
#else
        "lsl	r5, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r5\n\t"
#else
        "add	r3, r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
        "# Multiply m[j] and mu - Done\n\t"
        "stm	%[a]!, {r3}\n\t"
        "cmp	%[a], r9\n\t"
        "blt	L_sp_256_mont_reduce_order_8_word_%=\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "ldr	%[mp], [%[m]]\n\t"
        "mov	r3, r12\n\t"
        "# Multiply m[7] and mu - Start\n\t"
        "mov	r5, r10\n\t"
        "uxth	r6, %[mp]\n\t"
        "uxth	r5, r5\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r6, r5, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r5\n\t"
#else
        "mul	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r7\n\t"
#elif defined(__clang__)
        "adcs	r3, r7\n\t"
#else
        "adc	r3, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[mp], #16\n\t"
#else
        "lsr	r6, %[mp], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r5, r6, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r6\n\t"
#else
        "mul	r5, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r5, #16\n\t"
#else
        "lsr	r6, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r5, r5, #16\n\t"
#else
        "lsl	r5, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r5\n\t"
#else
        "add	r4, r4, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r6\n\t"
#elif defined(__clang__)
        "adcs	r3, r6\n\t"
#else
        "adc	r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
        "mov	r5, r10\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, %[mp], #16\n\t"
#else
        "lsr	r6, %[mp], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r5, #16\n\t"
#else
        "lsr	r5, r5, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls	r6, r5, r6\n\t"
#elif defined(__clang__)
        "muls	r6, r5\n\t"
#else
        "mul	r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, r6\n\t"
#else
        "add	r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
        "uxth	r6, %[mp]\n\t"
#ifdef WOLFSSL_KEIL
        "muls	r5, r6, r5\n\t"
#elif defined(__clang__)
        "muls	r5, r6\n\t"
#else
        "mul	r5, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r5, #16\n\t"
#else
        "lsr	r6, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r5, r5, #16\n\t"
#else
        "lsl	r5, r5, #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r5\n\t"
#else
        "add	r4, r4, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r6\n\t"
#elif defined(__clang__)
        "adcs	r3, r6\n\t"
#else
        "adc	r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
        "# Multiply m[7] and mu - Done\n\t"
        "ldr	r5, [%[a]]\n\t"
        "ldr	r6, [%[a], #4]\n\t"
        "movs	%[mp], #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r4\n\t"
#else
        "add	r5, r5, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r6, r6, r3\n\t"
#elif defined(__clang__)
        "adcs	r6, r3\n\t"
#else
        "adc	r6, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, %[mp]\n\t"
#elif defined(__clang__)
        "adcs	r7, %[mp]\n\t"
#else
        "adc	r7, %[mp]\n\t"
#endif
        "stm	%[a]!, {r5, r6}\n\t"
        "# i += 1\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[a], %[a], #4\n\t"
#else
        "sub	%[a], %[a], #4\n\t"
#endif
        "movs	r3, #28\n\t"
        "mov	r9, %[a]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[a], %[a], r3\n\t"
#else
        "sub	%[a], %[a], r3\n\t"
#endif
        "mov	r12, r7\n\t"
        "mov	%[m], lr\n\t"
        "cmp	r11, %[a]\n\t"
        "bgt	L_sp_256_mont_reduce_order_8_mod_%=\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "negs	r7, r7\n\t"
#else
        "neg	r7, r7\n\t"
#endif
        "# Subtract masked modulus\n\t"
        "movs	r4, #32\n\t"
        "movs	%[mp], #0\n\t"
        "movs	r3, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	%[a], %[a], r4\n\t"
#else
        "sub	%[a], %[a], r4\n\t"
#endif
#ifndef WOLFSSL_SP_LARGE_CODE
        "\n"
    "L_sp_256_mont_reduce_order_8_sub_mask_%=:\n\t"
        "ldm	%[m]!, {r6}\n\t"
        "movs	r5, #0\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, %[mp]\n\t"
#else
        "sub	r5, r5, %[mp]\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	%[mp], %[mp], %[mp]\n\t"
#elif defined(__clang__)
        "sbcs	%[mp], %[mp]\n\t"
#else
        "sbc	%[mp], %[mp]\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r3, r3, #4\n\t"
#else
        "add	r3, r3, #4\n\t"
#endif
        "cmp	r3, r4\n\t"
        "blt	L_sp_256_mont_reduce_order_8_sub_mask_%=\n\t"
#else /* WOLFSSL_SP_LARGE_CODE */
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r6\n\t"
#else
        "sub	r5, r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
        "ldm	%[m]!, {r6}\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, r7\n\t"
#elif defined(__clang__)
        "ands	r6, r7\n\t"
#else
        "and	r6, r7\n\t"
#endif
        "ldr	r5, [%[a], r4]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "stm	%[a]!, {r5}\n\t"
#endif /* WOLFSSL_SP_LARGE_CODE */
        : [a] "+l" (a), [m] "+l" (m), [mp] "+l" (mp)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "cc"
    );
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
SP_NOINLINE static void sp_256_mont_mul_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_256_mul_sm2_8(r, a, b);
    sp_256_mont_reduce_sm2_8(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_256_mont_sqr_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_256_sqr_sm2_8(r, a);
    sp_256_mont_reduce_sm2_8(r, m, mp);
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
SP_NOINLINE static void sp_256_mont_sqr_n_sm2_8(sp_digit* r,
    const sp_digit* a, int n, const sp_digit* m, sp_digit mp)
{
    sp_256_mont_sqr_sm2_8(r, a, m, mp);
    for (; n > 1; n--) {
        sp_256_mont_sqr_sm2_8(r, r, m, mp);
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
static void sp_256_mont_inv_sm2_8(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 8);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_sm2_8(t, t, p256_sm2_mod, p256_sm2_mp_mod);
        if (p256_sm2_mod_minus_2[i / 32] & ((sp_digit)1 << (i % 32)))
            sp_256_mont_mul_sm2_8(t, t, a, p256_sm2_mod, p256_sm2_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 8);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 8;
    sp_digit* t3 = td + 4 * 8;
    sp_digit* t4 = td + 6 * 8;
    /* 0x2 */
    sp_256_mont_sqr_sm2_8(t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0x3 */
    sp_256_mont_mul_sm2_8(t2, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xc */
    sp_256_mont_sqr_n_sm2_8(t1, t2, 2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xd */
    sp_256_mont_mul_sm2_8(t3, t1, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf */
    sp_256_mont_mul_sm2_8(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xf0 */
    sp_256_mont_sqr_n_sm2_8(t1, t2, 4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfd */
    sp_256_mont_mul_sm2_8(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff */
    sp_256_mont_mul_sm2_8(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xff00 */
    sp_256_mont_sqr_n_sm2_8(t1, t2, 8, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffd */
    sp_256_mont_mul_sm2_8(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff */
    sp_256_mont_mul_sm2_8(t2, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffff0000 */
    sp_256_mont_sqr_n_sm2_8(t1, t2, 16, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffd */
    sp_256_mont_mul_sm2_8(t3, t3, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe */
    sp_256_mont_mul_sm2_8(t2, t3, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xffffffff */
    sp_256_mont_mul_sm2_8(t4, t2, a, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffe00000000 */
    sp_256_mont_sqr_n_sm2_8(t2, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff */
    sp_256_mont_mul_sm2_8(t2, t4, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffff00000000 */
    sp_256_mont_sqr_n_sm2_8(t1, t2, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff */
    sp_256_mont_mul_sm2_8(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_8(t1, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_8(r, t4, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffff00000000 */
    sp_256_mont_sqr_n_sm2_8(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff */
    sp_256_mont_mul_sm2_8(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff0000000000000000 */
    sp_256_mont_sqr_n_sm2_8(r, r, 64, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff */
    sp_256_mont_mul_sm2_8(r, r, t4, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff00000000 */
    sp_256_mont_sqr_n_sm2_8(r, r, 32, p256_sm2_mod, p256_sm2_mp_mod);
    /* 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd */
    sp_256_mont_mul_sm2_8(r, r, t3, p256_sm2_mod, p256_sm2_mp_mod);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_256_norm_8(a)

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_256_map_sm2_8(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*8;
    sp_int32 n;

    sp_256_mont_inv_sm2_8(t1, p->z, t + 2*8);

    sp_256_mont_sqr_sm2_8(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    /* x /= z^2 */
    sp_256_mont_mul_sm2_8(r->x, p->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->x + 8, 0, sizeof(sp_digit) * 8U);
    sp_256_mont_reduce_sm2_8(r->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_256_cmp_sm2_8(r->x, p256_sm2_mod);
    sp_256_cond_sub_sm2_8(r->x, r->x, p256_sm2_mod, (sp_digit)~(n >> 31));
    sp_256_norm_8(r->x);

    /* y /= z^3 */
    sp_256_mont_mul_sm2_8(r->y, p->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMSET(r->y + 8, 0, sizeof(sp_digit) * 8U);
    sp_256_mont_reduce_sm2_8(r->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_256_cmp_sm2_8(r->y, p256_sm2_mod);
    sp_256_cond_sub_sm2_8(r->y, r->y, p256_sm2_mod, (sp_digit)~(n >> 31));
    sp_256_norm_8(r->y);

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
SP_NOINLINE static void sp_256_mont_add_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m)
{
    (void)m;
    __asm__ __volatile__ (
        "movs	r3, #0\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[a], #4]\n\t"
        "ldr	r6, [%[b]]\n\t"
        "ldr	r7, [%[b], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r6\n\t"
#else
        "add	r4, r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[a], #12]\n\t"
        "ldr	r6, [%[b], #8]\n\t"
        "ldr	r7, [%[b], #12]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[a], #20]\n\t"
        "ldr	r6, [%[b], #16]\n\t"
        "ldr	r7, [%[b], #20]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
        "mov	r8, r4\n\t"
        "mov	r9, r5\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[a], #28]\n\t"
        "ldr	r6, [%[b], #24]\n\t"
        "ldr	r7, [%[b], #28]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
        "mov	r10, r4\n\t"
        "mov	r11, r5\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "adcs	r3, r3\n\t"
#else
        "adc	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, #1\n\t"
#else
        "sub	r3, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r3, r3\n\t"
#else
        "mvn	r3, r3\n\t"
#endif
        "movs	r7, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r3, #1\n\t"
#else
        "lsl	r6, r3, #1\n\t"
#endif
        "ldr	r4, [%[r]]\n\t"
        "ldr	r5, [%[r], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r3\n\t"
#else
        "sub	r4, r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "sbcs	r5, r3\n\t"
#else
        "sbc	r5, r3\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        "ldr	r4, [%[r], #8]\n\t"
        "ldr	r5, [%[r], #12]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r7\n\t"
#elif defined(__clang__)
        "sbcs	r4, r7\n\t"
#else
        "sbc	r4, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "sbcs	r5, r3\n\t"
#else
        "sbc	r5, r3\n\t"
#endif
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "mov	r4, r8\n\t"
        "mov	r5, r9\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "sbcs	r4, r3\n\t"
#else
        "sbc	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "sbcs	r5, r3\n\t"
#else
        "sbc	r5, r3\n\t"
#endif
        "str	r4, [%[r], #16]\n\t"
        "str	r5, [%[r], #20]\n\t"
        "mov	r4, r10\n\t"
        "mov	r5, r11\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "sbcs	r4, r3\n\t"
#else
        "sbc	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "sbcs	r5, r6\n\t"
#else
        "sbc	r5, r6\n\t"
#endif
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
    );
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montgomery form.
 * m   Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_dbl_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    (void)m;
    __asm__ __volatile__ (
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[a], #4]\n\t"
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r7, [%[a], #12]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r4\n\t"
#else
        "add	r4, r4, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r5\n\t"
#elif defined(__clang__)
        "adcs	r5, r5\n\t"
#else
        "adc	r5, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "adcs	r6, r6\n\t"
#else
        "adc	r6, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        "str	r6, [%[r], #8]\n\t"
        "str	r7, [%[r], #12]\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[a], #20]\n\t"
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r7, [%[a], #28]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r4\n\t"
#elif defined(__clang__)
        "adcs	r4, r4\n\t"
#else
        "adc	r4, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r5\n\t"
#elif defined(__clang__)
        "adcs	r5, r5\n\t"
#else
        "adc	r5, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "adcs	r6, r6\n\t"
#else
        "adc	r6, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
        "mov	r8, r4\n\t"
        "mov	r9, r5\n\t"
        "mov	r10, r6\n\t"
        "mov	r11, r7\n\t"
        "movs	r3, #0\n\t"
        "movs	r7, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "adcs	r3, r3\n\t"
#else
        "adc	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, #1\n\t"
#else
        "sub	r3, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r3, r3\n\t"
#else
        "mvn	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r2, r3, #1\n\t"
#else
        "lsl	r2, r3, #1\n\t"
#endif
        "ldr	r4, [%[r]]\n\t"
        "ldr	r5, [%[r], #4]\n\t"
        "ldr	r6, [%[r], #8]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r3\n\t"
#else
        "sub	r4, r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "sbcs	r5, r3\n\t"
#else
        "sbc	r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r7\n\t"
#elif defined(__clang__)
        "sbcs	r6, r7\n\t"
#else
        "sbc	r6, r7\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        "str	r6, [%[r], #8]\n\t"
        "ldr	r4, [%[r], #12]\n\t"
        "mov	r5, r8\n\t"
        "mov	r6, r9\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "sbcs	r4, r3\n\t"
#else
        "sbc	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "sbcs	r5, r3\n\t"
#else
        "sbc	r5, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r6, r6, r3\n\t"
#elif defined(__clang__)
        "sbcs	r6, r3\n\t"
#else
        "sbc	r6, r3\n\t"
#endif
        "str	r4, [%[r], #12]\n\t"
        "str	r5, [%[r], #16]\n\t"
        "str	r6, [%[r], #20]\n\t"
        "mov	r4, r10\n\t"
        "mov	r5, r11\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "sbcs	r4, r3\n\t"
#else
        "sbc	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r2\n\t"
#elif defined(__clang__)
        "sbcs	r5, r2\n\t"
#else
        "sbc	r5, r2\n\t"
#endif
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
        : [r] "+l" (r), [a] "+l" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
    );
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montgomery form.
 * m   Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_tpl_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    (void)m;
    __asm__ __volatile__ (
        "ldr	r6, [%[a]]\n\t"
        "ldr	r7, [%[a], #4]\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[a], #12]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r6, r6, r6\n\t"
#else
        "add	r6, r6, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r7\n\t"
#elif defined(__clang__)
        "adcs	r7, r7\n\t"
#else
        "adc	r7, r7\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r4\n\t"
#elif defined(__clang__)
        "adcs	r4, r4\n\t"
#else
        "adc	r4, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r5\n\t"
#elif defined(__clang__)
        "adcs	r5, r5\n\t"
#else
        "adc	r5, r5\n\t"
#endif
        "mov	r8, r4\n\t"
        "mov	r9, r5\n\t"
        "ldr	r2, [%[a], #16]\n\t"
        "ldr	r3, [%[a], #20]\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[a], #28]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r2\n\t"
#elif defined(__clang__)
        "adcs	r2, r2\n\t"
#else
        "adc	r2, r2\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "adcs	r3, r3\n\t"
#else
        "adc	r3, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r4\n\t"
#elif defined(__clang__)
        "adcs	r4, r4\n\t"
#else
        "adc	r4, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r5\n\t"
#elif defined(__clang__)
        "adcs	r5, r5\n\t"
#else
        "adc	r5, r5\n\t"
#endif
        "mov	r10, r2\n\t"
        "mov	r11, r3\n\t"
        "mov	r12, r4\n\t"
        "mov	lr, r5\n\t"
        "movs	r3, #0\n\t"
        "movs	r5, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "adcs	r3, r3\n\t"
#else
        "adc	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, #1\n\t"
#else
        "sub	r3, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r3, r3\n\t"
#else
        "mvn	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r4, r3, #1\n\t"
#else
        "lsl	r4, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r6, r6, r3\n\t"
#else
        "sub	r6, r6, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r7, r7, r3\n\t"
#elif defined(__clang__)
        "sbcs	r7, r3\n\t"
#else
        "sbc	r7, r3\n\t"
#endif
        "mov	r2, r8\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r5\n\t"
#elif defined(__clang__)
        "sbcs	r2, r5\n\t"
#else
        "sbc	r2, r5\n\t"
#endif
        "mov	r8, r2\n\t"
        "mov	r2, r9\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "mov	r9, r2\n\t"
        "mov	r2, r10\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "mov	r10, r2\n\t"
        "mov	r2, r11\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "mov	r11, r2\n\t"
        "mov	r2, r12\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "mov	r12, r2\n\t"
        "mov	r2, lr\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "sbcs	r2, r4\n\t"
#else
        "sbc	r2, r4\n\t"
#endif
        "mov	lr, r2\n\t"
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r6, r6, r2\n\t"
#else
        "add	r6, r6, r2\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r7, r7, r3\n\t"
#elif defined(__clang__)
        "adcs	r7, r3\n\t"
#else
        "adc	r7, r3\n\t"
#endif
        "ldr	r2, [%[a], #8]\n\t"
        "ldr	r3, [%[a], #12]\n\t"
        "mov	r4, r8\n\t"
        "mov	r5, r9\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "adcs	r2, r4\n\t"
#else
        "adc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
        "mov	r8, r2\n\t"
        "mov	r9, r3\n\t"
        "ldr	r2, [%[a], #16]\n\t"
        "ldr	r3, [%[a], #20]\n\t"
        "mov	r4, r10\n\t"
        "mov	r5, r11\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "adcs	r2, r4\n\t"
#else
        "adc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
        "mov	r10, r2\n\t"
        "mov	r11, r3\n\t"
        "ldr	r2, [%[a], #24]\n\t"
        "ldr	r3, [%[a], #28]\n\t"
        "mov	r4, r12\n\t"
        "mov	r5, lr\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "adcs	r2, r4\n\t"
#else
        "adc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
        "mov	r12, r2\n\t"
        "mov	lr, r3\n\t"
        "movs	r3, #0\n\t"
        "movs	r5, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "adcs	r3, r3\n\t"
#else
        "adc	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, #1\n\t"
#else
        "sub	r3, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "mvns	r3, r3\n\t"
#else
        "mvn	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r4, r3, #1\n\t"
#else
        "lsl	r4, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r6, r6, r3\n\t"
#else
        "sub	r6, r6, r3\n\t"
#endif
        "str	r6, [%[r]]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r7, r7, r3\n\t"
#elif defined(__clang__)
        "sbcs	r7, r3\n\t"
#else
        "sbc	r7, r3\n\t"
#endif
        "str	r7, [%[r], #4]\n\t"
        "mov	r2, r8\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r5\n\t"
#elif defined(__clang__)
        "sbcs	r2, r5\n\t"
#else
        "sbc	r2, r5\n\t"
#endif
        "str	r2, [%[r], #8]\n\t"
        "mov	r2, r9\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "str	r2, [%[r], #12]\n\t"
        "mov	r2, r10\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "str	r2, [%[r], #16]\n\t"
        "mov	r2, r11\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "str	r2, [%[r], #20]\n\t"
        "mov	r2, r12\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r3\n\t"
#elif defined(__clang__)
        "sbcs	r2, r3\n\t"
#else
        "sbc	r2, r3\n\t"
#endif
        "str	r2, [%[r], #24]\n\t"
        "mov	r2, lr\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "sbcs	r2, r4\n\t"
#else
        "sbc	r2, r4\n\t"
#endif
        "str	r2, [%[r], #28]\n\t"
        : [r] "+l" (r), [a] "+l" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "cc"
    );
}

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_sub_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m)
{
    (void)m;
    __asm__ __volatile__ (
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[a], #4]\n\t"
        "ldr	r6, [%[b]]\n\t"
        "ldr	r7, [%[b], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r6\n\t"
#else
        "sub	r4, r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "sbcs	r5, r7\n\t"
#else
        "sbc	r5, r7\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[a], #12]\n\t"
        "ldr	r6, [%[b], #8]\n\t"
        "ldr	r7, [%[b], #12]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "sbcs	r5, r7\n\t"
#else
        "sbc	r5, r7\n\t"
#endif
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[a], #20]\n\t"
        "ldr	r6, [%[b], #16]\n\t"
        "ldr	r7, [%[b], #20]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "sbcs	r5, r7\n\t"
#else
        "sbc	r5, r7\n\t"
#endif
        "mov	r8, r4\n\t"
        "mov	r9, r5\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[a], #28]\n\t"
        "ldr	r6, [%[b], #24]\n\t"
        "ldr	r7, [%[b], #28]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "sbcs	r5, r7\n\t"
#else
        "sbc	r5, r7\n\t"
#endif
        "mov	r10, r4\n\t"
        "mov	r11, r5\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "sbcs	r3, r3\n\t"
#else
        "sbc	r3, r3\n\t"
#endif
        "movs	r6, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r7, r3, #1\n\t"
#else
        "lsl	r7, r3, #1\n\t"
#endif
        "ldr	r4, [%[r]]\n\t"
        "ldr	r5, [%[r], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r4, r4, r3\n\t"
#else
        "add	r4, r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "adcs	r5, r3\n\t"
#else
        "adc	r5, r3\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        "ldr	r4, [%[r], #8]\n\t"
        "ldr	r5, [%[r], #12]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "adcs	r4, r6\n\t"
#else
        "adc	r4, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "adcs	r5, r3\n\t"
#else
        "adc	r5, r3\n\t"
#endif
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "mov	r4, r8\n\t"
        "mov	r5, r9\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "adcs	r4, r3\n\t"
#else
        "adc	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r3\n\t"
#elif defined(__clang__)
        "adcs	r5, r3\n\t"
#else
        "adc	r5, r3\n\t"
#endif
        "str	r4, [%[r], #16]\n\t"
        "str	r5, [%[r], #20]\n\t"
        "mov	r4, r10\n\t"
        "mov	r5, r11\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "adcs	r4, r3\n\t"
#else
        "adc	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs	r5, r7\n\t"
#else
        "adc	r5, r7\n\t"
#endif
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
    );
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_div2_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    (void)m;
    __asm__ __volatile__ (
        "ldr	r6, [%[a]]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #31\n\t"
#else
        "lsl	r6, r6, #31\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r6, r6, #31\n\t"
#else
        "lsr	r6, r6, #31\n\t"
#endif
        "movs	r4, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r6\n\t"
#else
        "sub	r4, r4, r6\n\t"
#endif
        "movs	r6, #0\n\t"
        "movs	r5, r4\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, #1\n\t"
#else
        "sub	r5, r5, #1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands	r5, r5, r4\n\t"
#elif defined(__clang__)
        "ands	r5, r4\n\t"
#else
        "and	r5, r4\n\t"
#endif
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r2, r2, r4\n\t"
#else
        "add	r2, r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r4\n\t"
#elif defined(__clang__)
        "adcs	r3, r4\n\t"
#else
        "adc	r3, r4\n\t"
#endif
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #4]\n\t"
        "ldr	r2, [%[a], #8]\n\t"
        "ldr	r3, [%[a], #12]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r6\n\t"
#elif defined(__clang__)
        "adcs	r2, r6\n\t"
#else
        "adc	r2, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r4\n\t"
#elif defined(__clang__)
        "adcs	r3, r4\n\t"
#else
        "adc	r3, r4\n\t"
#endif
        "str	r2, [%[r], #8]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "ldr	r2, [%[a], #16]\n\t"
        "ldr	r3, [%[a], #20]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "adcs	r2, r4\n\t"
#else
        "adc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r4\n\t"
#elif defined(__clang__)
        "adcs	r3, r4\n\t"
#else
        "adc	r3, r4\n\t"
#endif
        "str	r2, [%[r], #16]\n\t"
        "str	r3, [%[r], #20]\n\t"
        "ldr	r2, [%[a], #24]\n\t"
        "ldr	r3, [%[a], #28]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r2, r2, r4\n\t"
#elif defined(__clang__)
        "adcs	r2, r4\n\t"
#else
        "adc	r2, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "adcs	r3, r5\n\t"
#else
        "adc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs	r6, r6, r6\n\t"
#elif defined(__clang__)
        "adcs	r6, r6\n\t"
#else
        "adc	r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r6, r6, #31\n\t"
#else
        "lsl	r6, r6, #31\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r4, r2, #1\n\t"
#else
        "lsr	r4, r2, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r2, r2, #31\n\t"
#else
        "lsl	r2, r2, #31\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r3, #1\n\t"
#else
        "lsr	r5, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r3, r3, #31\n\t"
#else
        "lsl	r3, r3, #31\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "orrs	r4, r3\n\t"
#else
        "orr	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "orrs	r5, r6\n\t"
#else
        "orr	r5, r6\n\t"
#endif
        "movs	r6, r2\n\t"
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
        "ldr	r2, [%[r], #16]\n\t"
        "ldr	r3, [%[r], #20]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r4, r2, #1\n\t"
#else
        "lsr	r4, r2, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r2, r2, #31\n\t"
#else
        "lsl	r2, r2, #31\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r3, #1\n\t"
#else
        "lsr	r5, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r3, r3, #31\n\t"
#else
        "lsl	r3, r3, #31\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "orrs	r4, r3\n\t"
#else
        "orr	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "orrs	r5, r6\n\t"
#else
        "orr	r5, r6\n\t"
#endif
        "movs	r6, r2\n\t"
        "str	r4, [%[r], #16]\n\t"
        "str	r5, [%[r], #20]\n\t"
        "ldr	r2, [%[r], #8]\n\t"
        "ldr	r3, [%[r], #12]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r4, r2, #1\n\t"
#else
        "lsr	r4, r2, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r2, r2, #31\n\t"
#else
        "lsl	r2, r2, #31\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r3, #1\n\t"
#else
        "lsr	r5, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r3, r3, #31\n\t"
#else
        "lsl	r3, r3, #31\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "orrs	r4, r3\n\t"
#else
        "orr	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "orrs	r5, r6\n\t"
#else
        "orr	r5, r6\n\t"
#endif
        "movs	r6, r2\n\t"
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #4]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r4, r2, #1\n\t"
#else
        "lsr	r4, r2, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r3, #1\n\t"
#else
        "lsr	r5, r3, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	r3, r3, #31\n\t"
#else
        "lsl	r3, r3, #31\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r4, r4, r3\n\t"
#elif defined(__clang__)
        "orrs	r4, r3\n\t"
#else
        "orr	r4, r3\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "orrs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "orrs	r5, r6\n\t"
#else
        "orr	r5, r6\n\t"
#endif
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
        : [r] "+l" (r), [a] "+l" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "cc"
    );
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_sm2_8(sp_point_256* r, const sp_point_256* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*8;
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
    sp_256_mont_sqr_sm2_8(t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = Y * Z */
    sp_256_mont_mul_sm2_8(z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    /* Z = 2Z */
    sp_256_mont_dbl_sm2_8(z, z, p256_sm2_mod);
    /* T2 = X - T1 */
    sp_256_mont_sub_sm2_8(t2, p->x, t1, p256_sm2_mod);
    /* T1 = X + T1 */
    sp_256_mont_add_sm2_8(t1, p->x, t1, p256_sm2_mod);
    /* T2 = T1 * T2 */
    sp_256_mont_mul_sm2_8(t2, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
    /* T1 = 3T2 */
    sp_256_mont_tpl_sm2_8(t1, t2, p256_sm2_mod);
    /* Y = 2Y */
    sp_256_mont_dbl_sm2_8(y, p->y, p256_sm2_mod);
    /* Y = Y * Y */
    sp_256_mont_sqr_sm2_8(y, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = Y * Y */
    sp_256_mont_sqr_sm2_8(t2, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* T2 = T2/2 */
    sp_256_mont_div2_sm2_8(t2, t2, p256_sm2_mod);
    /* Y = Y * X */
    sp_256_mont_mul_sm2_8(y, y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = T1 * T1 */
    sp_256_mont_sqr_sm2_8(x, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_8(x, x, y, p256_sm2_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_8(x, x, y, p256_sm2_mod);
    /* Y = Y - X */
    sp_256_mont_sub_sm2_8(y, y, x, p256_sm2_mod);
    /* Y = Y * T1 */
    sp_256_mont_mul_sm2_8(y, y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* Y = Y - T2 */
    sp_256_mont_sub_sm2_8(y, y, t2, p256_sm2_mod);
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_dbl_8_ctx {
    int state;
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
} sp_256_proj_point_dbl_8_ctx;

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_dbl_sm2_8_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
        const sp_point_256* p, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_dbl_8_ctx* ctx = (sp_256_proj_point_dbl_sm2_8_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_proj_point_dbl_8_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0:
        ctx->t1 = t;
        ctx->t2 = t + 2*8;
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
        sp_256_mont_sqr_sm2_8(ctx->t1, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        /* Z = Y * Z */
        sp_256_mont_mul_sm2_8(ctx->z, p->y, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        /* Z = 2Z */
        sp_256_mont_dbl_sm2_8(ctx->z, ctx->z, p256_sm2_mod);
        ctx->state = 4;
        break;
    case 4:
        /* T2 = X - T1 */
        sp_256_mont_sub_sm2_8(ctx->t2, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 5;
        break;
    case 5:
        /* T1 = X + T1 */
        sp_256_mont_add_sm2_8(ctx->t1, p->x, ctx->t1, p256_sm2_mod);
        ctx->state = 6;
        break;
    case 6:
        /* T2 = T1 * T2 */
        sp_256_mont_mul_sm2_8(ctx->t2, ctx->t1, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* T1 = 3T2 */
        sp_256_mont_tpl_sm2_8(ctx->t1, ctx->t2, p256_sm2_mod);
        ctx->state = 8;
        break;
    case 8:
        /* Y = 2Y */
        sp_256_mont_dbl_sm2_8(ctx->y, p->y, p256_sm2_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Y = Y * Y */
        sp_256_mont_sqr_sm2_8(ctx->y, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 10;
        break;
    case 10:
        /* T2 = Y * Y */
        sp_256_mont_sqr_sm2_8(ctx->t2, ctx->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 11;
        break;
    case 11:
        /* T2 = T2/2 */
        sp_256_mont_div2_sm2_8(ctx->t2, ctx->t2, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* Y = Y * X */
        sp_256_mont_mul_sm2_8(ctx->y, ctx->y, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        /* X = T1 * T1 */
        sp_256_mont_sqr_sm2_8(ctx->x, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        /* X = X - Y */
        sp_256_mont_sub_sm2_8(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 15;
        break;
    case 15:
        /* X = X - Y */
        sp_256_mont_sub_sm2_8(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 16;
        break;
    case 16:
        /* Y = Y - X */
        sp_256_mont_sub_sm2_8(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
        ctx->state = 17;
        break;
    case 17:
        /* Y = Y * T1 */
        sp_256_mont_mul_sm2_8(ctx->y, ctx->y, ctx->t1, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        /* Y = Y - T2 */
        sp_256_mont_sub_sm2_8(ctx->y, ctx->y, ctx->t2, p256_sm2_mod);
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
static int sp_256_cmp_equal_8(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
            (a[3] ^ b[3]) | (a[4] ^ b[4]) | (a[5] ^ b[5]) |
            (a[6] ^ b[6]) | (a[7] ^ b[7])) == 0;
}

/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_256_iszero_8(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7]) == 0;
}


/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_sm2_8(sp_point_256* r,
        const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t6 = t;
    sp_digit* t1 = t + 2*8;
    sp_digit* t2 = t + 4*8;
    sp_digit* t3 = t + 6*8;
    sp_digit* t4 = t + 8*8;
    sp_digit* t5 = t + 10*8;

    /* U1 = X1*Z2^2 */
    sp_256_mont_sqr_sm2_8(t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t3, t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t1, t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_8(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_256_mont_mul_sm2_8(t3, t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_8(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    /* Check double */
    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_8(t2, t1) &
            sp_256_cmp_equal_8(t4, t3)) {
        sp_256_proj_point_dbl_sm2_8(r, p, t);
    }
    else {
        sp_digit* x = t6;
        sp_digit* y = t1;
        sp_digit* z = t2;

        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_8(t2, t2, t1, p256_sm2_mod);
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_8(t4, t4, t3, p256_sm2_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_8(t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(y, t1, t5, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(t5, t5, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_8(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(z, z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_8(x, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_8(x, x, t5, p256_sm2_mod);
        sp_256_mont_mul_sm2_8(t5, t5, t3, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_8(t3, y, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(x, x, t3, p256_sm2_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_8(y, y, x, p256_sm2_mod);
        sp_256_mont_mul_sm2_8(y, y, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_8(y, y, t5, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 8; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 8; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 8; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_256_proj_point_add_8_ctx {
    int state;
    sp_256_proj_point_dbl_8_ctx dbl_ctx;
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
} sp_256_proj_point_add_8_ctx;

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static int sp_256_proj_point_add_sm2_8_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_add_8_ctx* ctx = (sp_256_proj_point_add_sm2_8_ctx*)sp_ctx->data;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_256* a = p;
        p = q;
        q = a;
    }

    typedef char ctx_size_test[sizeof(sp_256_proj_point_add_8_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    switch (ctx->state) {
    case 0: /* INIT */
        ctx->t6 = t;
        ctx->t1 = t + 2*8;
        ctx->t2 = t + 4*8;
        ctx->t3 = t + 6*8;
        ctx->t4 = t + 8*8;
        ctx->t5 = t + 10*8;
        ctx->x = ctx->t6;
        ctx->y = ctx->t1;
        ctx->z = ctx->t2;

        ctx->state = 1;
        break;
    case 1:
        /* U1 = X1*Z2^2 */
        sp_256_mont_sqr_sm2_8(ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 2;
        break;
    case 2:
        sp_256_mont_mul_sm2_8(ctx->t3, ctx->t1, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 3;
        break;
    case 3:
        sp_256_mont_mul_sm2_8(ctx->t1, ctx->t1, p->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 4;
        break;
    case 4:
        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_sm2_8(ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 5;
        break;
    case 5:
        sp_256_mont_mul_sm2_8(ctx->t4, ctx->t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 6;
        break;
    case 6:
        sp_256_mont_mul_sm2_8(ctx->t2, ctx->t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 7;
        break;
    case 7:
        /* S1 = Y1*Z2^3 */
        sp_256_mont_mul_sm2_8(ctx->t3, ctx->t3, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 8;
        break;
    case 8:
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_sm2_8(ctx->t4, ctx->t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 9;
        break;
    case 9:
        /* Check double */
        if ((~p->infinity) & (~q->infinity) &
                sp_256_cmp_equal_8(ctx->t2, ctx->t1) &
                sp_256_cmp_equal_8(ctx->t4, ctx->t3)) {
            XMEMSET(&ctx->dbl_ctx, 0, sizeof(ctx->dbl_ctx));
            sp_256_proj_point_dbl_sm2_8(r, p, t);
            ctx->state = 25;
        }
        else {
            ctx->state = 10;
        }
        break;
    case 10:
        /* H = U2 - U1 */
        sp_256_mont_sub_sm2_8(ctx->t2, ctx->t2, ctx->t1, p256_sm2_mod);
        ctx->state = 11;
        break;
    case 11:
        /* R = S2 - S1 */
        sp_256_mont_sub_sm2_8(ctx->t4, ctx->t4, ctx->t3, p256_sm2_mod);
        ctx->state = 12;
        break;
    case 12:
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_sm2_8(ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 13;
        break;
    case 13:
        sp_256_mont_mul_sm2_8(ctx->y, ctx->t1, ctx->t5, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 14;
        break;
    case 14:
        sp_256_mont_mul_sm2_8(ctx->t5, ctx->t5, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 15;
        break;
    case 15:
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_sm2_8(ctx->z, p->z, ctx->t2, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 16;
        break;
    case 16:
        sp_256_mont_mul_sm2_8(ctx->z, ctx->z, q->z, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 17;
        break;
    case 17:
        sp_256_mont_sqr_sm2_8(ctx->x, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 18;
        break;
    case 18:
        sp_256_mont_sub_sm2_8(ctx->x, ctx->x, ctx->t5, p256_sm2_mod);
        ctx->state = 19;
        break;
    case 19:
        sp_256_mont_mul_sm2_8(ctx->t5, ctx->t5, ctx->t3, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 20;
        break;
    case 20:
        sp_256_mont_dbl_sm2_8(ctx->t3, ctx->y, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(ctx->x, ctx->x, ctx->t3, p256_sm2_mod);
        ctx->state = 21;
        break;
    case 21:
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_8(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
        ctx->state = 22;
        break;
    case 22:
        sp_256_mont_mul_sm2_8(ctx->y, ctx->y, ctx->t4, p256_sm2_mod, p256_sm2_mp_mod);
        ctx->state = 23;
        break;
    case 23:
        sp_256_mont_sub_sm2_8(ctx->y, ctx->y, ctx->t5, p256_sm2_mod);
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

            for (i = 0; i < 8; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (ctx->x[i] & maskt);
            }
            for (i = 0; i < 8; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (ctx->y[i] & maskt);
            }
            for (i = 0; i < 8; i++) {
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

#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible point that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entries to access
 * idx    Index of entry to retrieve.
 */
static void sp_256_get_point_16_sm2_8(sp_point_256* r, const sp_point_256* table,
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
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    r->z[4] = 0;
    r->z[5] = 0;
    r->z[6] = 0;
    r->z[7] = 0;
    for (i = 1; i < 16; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->x[7] |= mask & table[i].x[7];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
        r->z[4] |= mask & table[i].z[4];
        r->z[5] |= mask & table[i].z[5];
        r->z[6] |= mask & table[i].z[6];
        r->z[7] |= mask & table[i].z[7];
    }
}
#endif /* !WC_NO_CACHE_RESISTANT */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Fast implementation that generates a pre-computation table.
 * 4 bits of window (no sliding!).
 * Uses add and double for calculating table.
 * 256 doubles.
 * 76 adds.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_fast_sm2_8(sp_point_256* r, const sp_point_256* g, const sp_digit* k,
        int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* t = NULL;
    sp_digit* tmp = NULL;
#else
    sp_point_256 t[16 + 1];
    sp_digit tmp[2 * 8 * 6];
#endif
    sp_point_256* rt = NULL;
#ifndef WC_NO_CACHE_RESISTANT
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* p = NULL;
#else
    sp_point_256 p[1];
#endif
#endif /* !WC_NO_CACHE_RESISTANT */
    sp_digit n;
    int i;
    int c;
    int y;
    int err = MP_OKAY;

    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_point_256*)XMALLOC(sizeof(sp_point_256) * (16 + 1),
        heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    #ifndef WC_NO_CACHE_RESISTANT
    if (err == MP_OKAY) {
        p = (sp_point_256*)XMALLOC(sizeof(sp_point_256),
            heap, DYNAMIC_TYPE_ECC);
        if (p == NULL)
            err = MEMORY_E;
    }
    #endif
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 6, heap,
                                DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        rt = t + 16;

        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        (void)sp_256_mod_mul_norm_sm2_8(t[1].x, g->x, p256_sm2_mod);
        (void)sp_256_mod_mul_norm_sm2_8(t[1].y, g->y, p256_sm2_mod);
        (void)sp_256_mod_mul_norm_sm2_8(t[1].z, g->z, p256_sm2_mod);
        t[1].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[ 2], &t[ 1], tmp);
        t[ 2].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[ 3], &t[ 2], &t[ 1], tmp);
        t[ 3].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[ 4], &t[ 2], tmp);
        t[ 4].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[ 5], &t[ 3], &t[ 2], tmp);
        t[ 5].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[ 6], &t[ 3], tmp);
        t[ 6].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[ 7], &t[ 4], &t[ 3], tmp);
        t[ 7].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[ 8], &t[ 4], tmp);
        t[ 8].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[ 9], &t[ 5], &t[ 4], tmp);
        t[ 9].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[10], &t[ 5], tmp);
        t[10].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[11], &t[ 6], &t[ 5], tmp);
        t[11].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[12], &t[ 6], tmp);
        t[12].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[13], &t[ 7], &t[ 6], tmp);
        t[13].infinity = 0;
        sp_256_proj_point_dbl_sm2_8(&t[14], &t[ 7], tmp);
        t[14].infinity = 0;
        sp_256_proj_point_add_sm2_8(&t[15], &t[ 8], &t[ 7], tmp);
        t[15].infinity = 0;

        i = 6;
        n = k[i+1] << 0;
        c = 28;
        y = (int)(n >> 28);
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_point_16_sm2_8(rt, t, y);
            rt->infinity = !y;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[y], sizeof(sp_point_256));
        }
        n <<= 4;
        for (; i>=0 || c>=4; ) {
            if (c < 4) {
                n |= k[i--];
                c += 32;
            }
            y = (n >> 28) & 0xf;
            n <<= 4;
            c -= 4;

            sp_256_proj_point_dbl_sm2_8(rt, rt, tmp);
            sp_256_proj_point_dbl_sm2_8(rt, rt, tmp);
            sp_256_proj_point_dbl_sm2_8(rt, rt, tmp);
            sp_256_proj_point_dbl_sm2_8(rt, rt, tmp);

    #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_point_16_sm2_8(p, t, y);
                p->infinity = !y;
                sp_256_proj_point_add_sm2_8(rt, rt, p, tmp);
            }
            else
    #endif
            {
                sp_256_proj_point_add_sm2_8(rt, rt, &t[y], tmp);
            }
        }

        if (map != 0) {
            sp_256_map_sm2_8(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_256));
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (tmp != NULL)
#endif
    {
        ForceZero(tmp, sizeof(sp_digit) * 2 * 8 * 6);
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
    #endif
    }
#ifndef WC_NO_CACHE_RESISTANT
#ifdef WOLFSSL_SP_SMALL_STACK
    if (p != NULL)
#endif
    {
        ForceZero(p, sizeof(sp_point_256));
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(p, heap, DYNAMIC_TYPE_ECC);
    #endif
    }
#endif /* !WC_NO_CACHE_RESISTANT */
#ifdef WOLFSSL_SP_SMALL_STACK
    if (t != NULL)
#endif
    {
        ForceZero(t, sizeof(sp_point_256) * 17);
    #ifdef WOLFSSL_SP_SMALL_STACK
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    #endif
    }

    return err;
}

#ifdef FP_ECC
/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_sm2_8(sp_point_256* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*8;
    sp_digit* b = t + 4*8;
    sp_digit* t1 = t + 6*8;
    sp_digit* t2 = t + 8*8;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_8(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_8(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_8(w, w, p256_sm2_mod, p256_sm2_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_sm2_8(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_8(t1, t1, w, p256_sm2_mod);
        sp_256_mont_tpl_sm2_8(a, t1, p256_sm2_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_sm2_8(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
        /* X = A^2 - 2B */
        sp_256_mont_sqr_sm2_8(x, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_dbl_sm2_8(t2, b, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(x, x, t2, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_sub_sm2_8(t2, b, x, p256_sm2_mod);
        sp_256_mont_dbl_sm2_8(b, t2, p256_sm2_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_sm2_8(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
        /* t1 = Y^4 */
        sp_256_mont_sqr_sm2_8(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_256_mont_mul_sm2_8(w, w, t1, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_mul_sm2_8(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_8(y, y, t1, p256_sm2_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_256_mont_sqr_sm2_8(t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_8(t1, t1, w, p256_sm2_mod);
    sp_256_mont_tpl_sm2_8(a, t1, p256_sm2_mod);
    /* B = X*Y^2 */
    sp_256_mont_sqr_sm2_8(t1, y, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(b, t1, x, p256_sm2_mod, p256_sm2_mp_mod);
    /* X = A^2 - 2B */
    sp_256_mont_sqr_sm2_8(x, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_dbl_sm2_8(t2, b, p256_sm2_mod);
    sp_256_mont_sub_sm2_8(x, x, t2, p256_sm2_mod);
    /* B = 2.(B - X) */
    sp_256_mont_sub_sm2_8(t2, b, x, p256_sm2_mod);
    sp_256_mont_dbl_sm2_8(b, t2, p256_sm2_mod);
    /* Z = Z*Y */
    sp_256_mont_mul_sm2_8(z, z, y, p256_sm2_mod, p256_sm2_mp_mod);
    /* t1 = Y^4 */
    sp_256_mont_sqr_sm2_8(t1, t1, p256_sm2_mod, p256_sm2_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_256_mont_mul_sm2_8(y, b, a, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sub_sm2_8(y, y, t1, p256_sm2_mod);
#endif /* WOLFSSL_SP_SMALL */
    /* Y = Y/2 */
    sp_256_mont_div2_sm2_8(y, y, p256_sm2_mod);
}

/* Convert the projective point to affine.
 * Ordinates are in Montgomery form.
 *
 * a  Point to convert.
 * t  Temporary data.
 */
static void sp_256_proj_to_affine_sm2_8(sp_point_256* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 8;
    sp_digit* tmp = t + 4 * 8;

    sp_256_mont_inv_sm2_8(t1, a->z, tmp);

    sp_256_mont_sqr_sm2_8(t2, t1, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t1, t2, t1, p256_sm2_mod, p256_sm2_mp_mod);

    sp_256_mont_mul_sm2_8(a->x, a->x, t2, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(a->y, a->y, t1, p256_sm2_mod, p256_sm2_mp_mod);
    XMEMCPY(a->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
}

#endif /* FP_ECC */
/* A table entry for pre-computed points. */
typedef struct sp_table_entry_256 {
    sp_digit x[8];
    sp_digit y[8];
} sp_table_entry_256;

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
static void sp_256_proj_point_add_qz1_sm2_8(sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*8;
    sp_digit* t6 = t + 4*8;
    sp_digit* t1 = t + 6*8;
    sp_digit* t4 = t + 8*8;
    sp_digit* t5 = t + 10*8;

    /* Calculate values to subtract from P->x and P->y. */
    /* U2 = X2*Z1^2 */
    sp_256_mont_sqr_sm2_8(t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t4, t2, p->z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_mul_sm2_8(t2, t2, q->x, p256_sm2_mod, p256_sm2_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_256_mont_mul_sm2_8(t4, t4, q->y, p256_sm2_mod, p256_sm2_mp_mod);

    if ((~p->infinity) & (~q->infinity) &
            sp_256_cmp_equal_8(p->x, t2) &
            sp_256_cmp_equal_8(p->y, t4)) {
        sp_256_proj_point_dbl_sm2_8(r, p, t);
    }
    else {
        sp_digit* x = t2;
        sp_digit* y = t3;
        sp_digit* z = t6;

        /* H = U2 - X1 */
        sp_256_mont_sub_sm2_8(t2, t2, p->x, p256_sm2_mod);
        /* R = S2 - Y1 */
        sp_256_mont_sub_sm2_8(t4, t4, p->y, p256_sm2_mod);
        /* Z3 = H*Z1 */
        sp_256_mont_mul_sm2_8(z, p->z, t2, p256_sm2_mod, p256_sm2_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_256_mont_sqr_sm2_8(t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(t3, p->x, t1, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(t1, t1, t2, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sqr_sm2_8(t2, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_8(t2, t2, t1, p256_sm2_mod);
        sp_256_mont_dbl_sm2_8(t5, t3, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(x, t2, t5, p256_sm2_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_sub_sm2_8(t3, t3, x, p256_sm2_mod);
        sp_256_mont_mul_sm2_8(t3, t3, t4, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_mul_sm2_8(t1, t1, p->y, p256_sm2_mod, p256_sm2_mp_mod);
        sp_256_mont_sub_sm2_8(y, t3, t1, p256_sm2_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 8; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 8; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 8; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

#ifdef WOLFSSL_SP_SMALL
#ifdef FP_ECC
/* Generate the pre-computed table of points for the base point.
 *
 * width = 4
 * 16 entries
 * 64 bits between
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temporary data.
 * heap  Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_sm2_8(const sp_point_256* a,
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

        err = sp_256_mod_mul_norm_sm2_8(t->x, a->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_8(t->y, a->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_8(t->z, a->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_sm2_8(t, tmp);

        XMEMCPY(s1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s1->infinity = 0;
        XMEMCPY(s2->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        s2->infinity = 0;

        /* table[0] = {0, 0, infinity} */
        XMEMSET(&table[0], 0, sizeof(sp_table_entry_256));
        /* table[1] = Affine version of 'a' in Montgomery form */
        XMEMCPY(table[1].x, t->x, sizeof(table->x));
        XMEMCPY(table[1].y, t->y, sizeof(table->y));

        for (i=1; i<4; i++) {
            sp_256_proj_point_dbl_n_sm2_8(t, 64, tmp);
            sp_256_proj_to_affine_sm2_8(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<4; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_sm2_8(t, s1, s2, tmp);
                sp_256_proj_to_affine_sm2_8(t, tmp);
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
static void sp_256_get_entry_16_sm2_8(sp_point_256* r,
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
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
    for (i = 1; i < 16; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->x[7] |= mask & table[i].x[7];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
    }
}
#endif /* !WC_NO_CACHE_RESISTANT */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^64, ...
 * Pre-generated: products of all combinations of above.
 * 4 doubles and adds (with qz=1)
 *
 * r      Resulting point.
 * k      Scalar to multiply by.
 * table  Pre-computed table.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_stripe_sm2_8(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* t = NULL;
#else
    sp_point_256 rt[2];
    sp_digit t[2 * 8 * 6];
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
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 6, heap,
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
        x = 63;
        for (j=0; j<4; j++) {
            y |= (int)(((k[x / 32] >> (x % 32)) & 1) << j);
            x += 64;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_16_sm2_8(rt, table, y);
        } else
    #endif
        {
            XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        }
        rt->infinity = !y;
        for (i=62; i>=0; i--) {
            y = 0;
            x = i;
            for (j=0; j<4; j++) {
                y |= (int)(((k[x / 32] >> (x % 32)) & 1) << j);
                x += 64;
            }

            sp_256_proj_point_dbl_sm2_8(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_16_sm2_8(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_256_proj_point_add_qz1_sm2_8(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_sm2_8(r, rt, t);
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
    sp_digit x[8];
    /* Y ordinate of point that table was generated from. */
    sp_digit y[8];
    /* Precomputation table for point. */
    sp_table_entry_256 table[16];
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

        if (sp_256_cmp_equal_8(g->x, sp_cache_256[i].x) &
                           sp_256_cmp_equal_8(g->y, sp_cache_256[i].y)) {
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
static int sp_256_ecc_mulmod_sm2_8(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_fast_sm2_8(r, g, k, map, ct, heap);
#else
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp;
#else
    sp_digit tmp[2 * 8 * 6];
#endif
    sp_cache_256_t* cache;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 6, heap, DYNAMIC_TYPE_ECC);
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
            sp_256_gen_stripe_table_sm2_8(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_fast_sm2_8(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_8(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif
    return err;
#endif
}

#else
#ifdef FP_ECC
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
static int sp_256_gen_stripe_table_sm2_8(const sp_point_256* a,
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

        err = sp_256_mod_mul_norm_sm2_8(t->x, a->x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_8(t->y, a->y, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_sm2_8(t->z, a->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_sm2_8(t, tmp);

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
            sp_256_proj_point_dbl_n_sm2_8(t, 32, tmp);
            sp_256_proj_to_affine_sm2_8(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_sm2_8(t, s1, s2, tmp);
                sp_256_proj_to_affine_sm2_8(t, tmp);
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
static void sp_256_get_entry_256_sm2_8(sp_point_256* r,
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
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
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
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
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
static int sp_256_ecc_mulmod_stripe_sm2_8(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_point_256* rt = NULL;
    sp_digit* t = NULL;
#else
    sp_point_256 rt[2];
    sp_digit t[2 * 8 * 6];
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
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 6, heap,
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
            y |= (int)(((k[x / 32] >> (x % 32)) & 1) << j);
            x += 32;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_256_sm2_8(rt, table, y);
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
                y |= (int)(((k[x / 32] >> (x % 32)) & 1) << j);
                x += 32;
            }

            sp_256_proj_point_dbl_sm2_8(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_256_sm2_8(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_256_proj_point_add_qz1_sm2_8(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_sm2_8(r, rt, t);
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
    sp_digit x[8];
    /* Y ordinate of point that table was generated from. */
    sp_digit y[8];
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

        if (sp_256_cmp_equal_8(g->x, sp_cache_256[i].x) &
                           sp_256_cmp_equal_8(g->y, sp_cache_256[i].y)) {
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
static int sp_256_ecc_mulmod_sm2_8(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_fast_sm2_8(r, g, k, map, ct, heap);
#else
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* tmp;
#else
    sp_digit tmp[2 * 8 * 6];
#endif
    sp_cache_256_t* cache;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 6, heap, DYNAMIC_TYPE_ECC);
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
            sp_256_gen_stripe_table_sm2_8(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_fast_sm2_8(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_8(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif
    return err;
#endif
}

#endif /* WOLFSSL_SP_SMALL */
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
    sp_digit k[8];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 8, km);
        sp_256_point_from_ecc_point_8(point, gm);

            err = sp_256_ecc_mulmod_sm2_8(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_8(point, r);
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
    sp_digit k[8 + 8 * 2 * 6];
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
            sizeof(sp_digit) * (8 + 8 * 2 * 6), heap,
            DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 8;

        sp_256_from_mp(k, 8, km);
        sp_256_point_from_ecc_point_8(point, gm);
        sp_256_point_from_ecc_point_8(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_8(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_8(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_8(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_sm2_8(point, point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_8(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_8(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_8(point, r);
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    XFREE(k, heap, DYNAMIC_TYPE_ECC);
    XFREE(point, heap, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Striping precomputation table.
 * 4 points combined into a table of 16 points.
 * Distance of 64 between points.
 */
static const sp_table_entry_256 p256_sm2_table[16] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0xf418029e,0x61328990,0xdca6c050,0x3e7981ed,0xac24c3c3,0xd6a1ed99,
        0xe1c13b05,0x91167a5e },
      { 0x3c2d0ddd,0xc1354e59,0x8d3295fa,0xc1f5e578,0x6e2a48f8,0x8d4cfb06,
        0x81d735bd,0x63cd65d4 } },
    /* 2 */
    { { 0xbad830d2,0x4b33e020,0x590dffb3,0x5c101f9e,0xbc80ecb0,0xcd0e0498,
        0x52aa293e,0x302787f8 },
      { 0x220f8fc8,0xbfd64ced,0xbe0ee377,0xcf5cebe0,0x8913b128,0xdc03a038,
        0xfde23279,0x4b096971 } },
    /* 3 */
    { { 0x39a0d9dc,0xb4ee84e2,0x061edfa5,0xf7d229cc,0xd4cf33d0,0x9765b24b,
        0x13329f59,0x511c69f1 },
      { 0xa07ae316,0x41095bb7,0x387f0e5a,0x3a4650f1,0x99827e4a,0x4624421c,
        0x04b4243a,0x7b1e8144 } },
    /* 4 */
    { { 0x8a914b50,0x7b9f561a,0x9154d377,0x2bf7130e,0x519b4c35,0x6800f696,
        0x568b4c56,0xc9e65040 },
      { 0x6d98a331,0x30706e00,0xe211ce1e,0x781a12f6,0x40562e5f,0x1fff9e3d,
        0x8c166747,0x6356cf46 } },
    /* 5 */
    { { 0x897518d9,0x96c4e4f3,0x66f75b0d,0x3825d80c,0x07f7ceb5,0xfa0bd6c0,
        0xa303ef24,0x5c01af69 },
      { 0x6bfcbc92,0xdd75cf9e,0x248dceae,0x8bfe4a53,0x95373421,0x519362c6,
        0x168ccb86,0x6f350880 } },
    /* 6 */
    { { 0xcf13b772,0xfa95c510,0xd95aca7c,0xa9b3fc90,0x4cb1a435,0x8e6e7790,
        0x8754e6a0,0x840b63d9 },
      { 0x33196bd2,0xcfa67981,0xef85911f,0x15ab0561,0xfbd94af6,0x504d9402,
        0xfcc90fb5,0x063173d3 } },
    /* 7 */
    { { 0x11fa5996,0x6d58e50e,0xcce6427b,0x5a7db9ba,0x95291d18,0x7d30d5aa,
        0xcd354763,0x9e69e861 },
      { 0x706bd6f9,0x2d0cbca9,0xaf3bda5f,0x63cc64b0,0x06d6cc0d,0x09cc5dbf,
        0x81e50b6b,0x533ba1aa } },
    /* 8 */
    { { 0x202bde39,0xfb3992a4,0x3d6bab98,0x2549f564,0x87712512,0x0b564642,
        0x7fde7e50,0xd52442b4 },
      { 0xa3d3e16e,0xa6cefd08,0xc83b29bd,0x5b194f0a,0x906dec8c,0x6db0edd8,
        0x02570c1e,0x7a090959 } },
    /* 9 */
    { { 0xbfab3d26,0x04d6ce6d,0x668edf18,0xf2aa223b,0xf06250ba,0xeb899557,
        0x4940d66d,0xef6bba07 },
      { 0xb78ca345,0xb483763b,0x3f08ff72,0x15867b4f,0x5bca92b2,0x91225b72,
        0x498804db,0xccead663 } },
    /* 10 */
    { { 0x487bdc21,0xd7aef5e8,0x858c0310,0x626fbd75,0x08d1054f,0x8cd9250d,
        0xd0831265,0x25a65ab1 },
      { 0xfec04e2c,0x4d0ac007,0x8ddf0f4c,0x859f4355,0x031dd8a0,0xb1d58e0b,
        0x9618799d,0x9df8ab40 } },
    /* 11 */
    { { 0x43d44adf,0x4cfcca55,0x6bf2e90e,0x6ed6f695,0x1f8b275d,0xff878d62,
        0x846471f5,0x4ac00774 },
      { 0xd59b5eaa,0xe8f08905,0xc904e73a,0xf961eb4f,0x8419c14c,0x51282943,
        0x94e41d6e,0x591e7dcf } },
    /* 12 */
    { { 0x805f0ed8,0x7254de6e,0x05ad4708,0xe0ad1d79,0xa339058e,0xf3212455,
        0x834b8957,0xf176c2f9 },
      { 0x9162ff84,0x6a42a692,0xeaa628e8,0x7af37ab5,0x0da655e1,0xe6605aa8,
        0x9bce77b6,0x840eabd9 } },
    /* 13 */
    { { 0xb891bf80,0x15e2a820,0x3dcfd53c,0xf218d7d6,0xc354f5d6,0x0b3fbb91,
        0x60ec6c0b,0xd2907e20 },
      { 0x4a8c701a,0x2ba584dd,0x9f829e57,0x1edfa8b2,0xf33ce835,0x482e8e37,
        0x75b06197,0x4f8b7581 } },
    /* 14 */
    { { 0x48e761ab,0xc1f039f8,0xa4db0990,0xb75d923c,0x85ba216c,0xfe8fffc1,
        0x64667cdc,0x5f193c87 },
      { 0x78ed1f3c,0xdce2f35c,0x77a90887,0x82cbb59e,0x521fca71,0x0c6bb634,
        0x8d79141f,0xbf0b44e8 } },
    /* 15 */
    { { 0xc6fe11e5,0xc424f15d,0x19a25ef3,0x1e866a49,0xdbb31334,0x419ace92,
        0x2408a903,0x1bd3b441 },
      { 0xcad2225b,0x1bb62300,0xcf204b84,0x44db4cab,0xcd229aa6,0x9fcf0afa,
        0xcc492384,0x38d13bed } },
};

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^64, ...
 * Pre-generated: products of all combinations of above.
 * 4 doubles and adds (with qz=1)
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_sm2_8(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_8(r, &p256_sm2_base, p256_sm2_table,
                                      k, map, ct, heap);
}

#else
/* Striping precomputation table.
 * 8 points combined into a table of 256 points.
 * Distance of 32 between points.
 */
static const sp_table_entry_256 p256_sm2_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0xf418029e,0x61328990,0xdca6c050,0x3e7981ed,0xac24c3c3,0xd6a1ed99,
        0xe1c13b05,0x91167a5e },
      { 0x3c2d0ddd,0xc1354e59,0x8d3295fa,0xc1f5e578,0x6e2a48f8,0x8d4cfb06,
        0x81d735bd,0x63cd65d4 } },
    /* 2 */
    { { 0x0cf4efe5,0xecb8f92d,0x960e2d22,0x88c47214,0x6059f079,0xca9549ef,
        0x7016da7c,0xd0a3774a },
      { 0x1d001cab,0xd51c95f6,0xa3feeec1,0x2d744def,0x0afedf2b,0xb7c20cc2,
        0x71d144a5,0xbf16c5f1 } },
    /* 3 */
    { { 0xad9c635e,0x6684ea0b,0x85246e15,0x48a44a56,0x56bb6373,0x16926cc4,
        0x43efef8e,0xb9966ebd },
      { 0x350e7f7d,0xace57f14,0xa25bdfd6,0x5c026c95,0x9ed4a592,0xf30be375,
        0x51234a24,0x74dde4e5 } },
    /* 4 */
    { { 0xbad830d2,0x4b33e020,0x590dffb3,0x5c101f9e,0xbc80ecb0,0xcd0e0498,
        0x52aa293e,0x302787f8 },
      { 0x220f8fc8,0xbfd64ced,0xbe0ee377,0xcf5cebe0,0x8913b128,0xdc03a038,
        0xfde23279,0x4b096971 } },
    /* 5 */
    { { 0x39a0d9dc,0xb4ee84e2,0x061edfa5,0xf7d229cc,0xd4cf33d0,0x9765b24b,
        0x13329f59,0x511c69f1 },
      { 0xa07ae316,0x41095bb7,0x387f0e5a,0x3a4650f1,0x99827e4a,0x4624421c,
        0x04b4243a,0x7b1e8144 } },
    /* 6 */
    { { 0xf8f2bc34,0x5de17662,0x171ae6a1,0x88408716,0x4c7cbaa0,0xc65b6470,
        0xbdce2e60,0xb56909fc },
      { 0x3e73ddb0,0x465dcb39,0x5d5e0850,0x5cca771f,0x86717cfb,0x96fe1e14,
        0xc1dcd4fb,0xfda13692 } },
    /* 7 */
    { { 0x043f38e8,0xd50c47aa,0x59faf190,0x5397eb91,0xb03d00cb,0xa9d1027e,
        0xa59a818f,0x1d04d612 },
      { 0x0328d2b3,0x59cddc86,0x87d68132,0x06f881e8,0xbf180493,0x42914fc4,
        0x0820fcbe,0xd6a600a8 } },
    /* 8 */
    { { 0x1abd31f0,0x4599b894,0x9a1da7d3,0xdb34198d,0xa0f0217d,0xa8b89523,
        0xe56b884e,0x2014cc43 },
      { 0x49efd4ee,0x6fb94f88,0x287f4ae0,0xf1b81710,0x99fd2deb,0x89d38a9a,
        0x72b67a53,0x8179277a } },
    /* 9 */
    { { 0x8e4b53df,0xa752f195,0x8bc1f19c,0x15b855b9,0xb75b2028,0xd3bcd58f,
        0x49b7651b,0x3e7e2841 },
      { 0x0b47b1aa,0x69a8e4cb,0x9750b86a,0xc3b27c7b,0x3f1415ed,0x65dc9f78,
        0x468ba56a,0xbaab4dbc } },
    /* 10 */
    { { 0xdf4f7cb3,0x33fe09ba,0x53cfe07a,0xbedb9815,0x586f167d,0x35e0c4fa,
        0x0821eb4c,0xdd4c37c9 },
      { 0xa0e9402a,0x2365240c,0x7f049720,0x694b0362,0x9b7723d8,0x1c60260d,
        0x52f8e305,0xe488f0af } },
    /* 11 */
    { { 0xeec04411,0x7bb89930,0x15b89af4,0xd659c71a,0xb64883ce,0xbe21fc69,
        0x02ad1648,0xfcdd9de0 },
      { 0x799d29fe,0x072b555d,0x971489ef,0x2c517a58,0xf45a0f68,0xdbdcc979,
        0x3cd08b95,0xb268b83f } },
    /* 12 */
    { { 0x36aed763,0x676c1049,0xd4a079be,0x8c871299,0xda194f33,0xdfafad16,
        0xc5d4925c,0x2ab29161 },
      { 0x1970c4f8,0x2264761c,0x8312b03a,0xc768d934,0x5b580022,0x187f2050,
        0xd13363c0,0x16406b19 } },
    /* 13 */
    { { 0x8f11a1b7,0x534a8d42,0xdeee83a5,0x938477f1,0xf25c6bd3,0xd77237f6,
        0x40e6ca87,0x46ef1395 },
      { 0x79dbd954,0x0830e760,0xa3a9aa6d,0xe22981b6,0xcc1aa064,0x07719e76,
        0xd044478c,0x6c909a3a } },
    /* 14 */
    { { 0x3ab4c047,0x3cd09dbd,0xc51725dd,0x8c857820,0x818a00d8,0xa0cefbac,
        0xd93d5fed,0x6bf4b678 },
      { 0x9c1c77f8,0xb7b8b764,0x3bb210ae,0xd3c82db5,0x19f40ce0,0x27f5ec75,
        0x60a39f9c,0x1c742c6d } },
    /* 15 */
    { { 0x608acdd0,0x7923d806,0x4dbe6185,0x119764c5,0x44c14789,0x58284940,
        0xebe015b9,0xba5f5971 },
      { 0x73d216f3,0x1bc235a2,0x0360f260,0x99624ba0,0xc1aaed49,0x4c8b3eef,
        0x7cde415a,0xa302e8b7 } },
    /* 16 */
    { { 0x8a914b50,0x7b9f561a,0x9154d377,0x2bf7130e,0x519b4c35,0x6800f696,
        0x568b4c56,0xc9e65040 },
      { 0x6d98a331,0x30706e00,0xe211ce1e,0x781a12f6,0x40562e5f,0x1fff9e3d,
        0x8c166747,0x6356cf46 } },
    /* 17 */
    { { 0x897518d9,0x96c4e4f3,0x66f75b0d,0x3825d80c,0x07f7ceb5,0xfa0bd6c0,
        0xa303ef24,0x5c01af69 },
      { 0x6bfcbc92,0xdd75cf9e,0x248dceae,0x8bfe4a53,0x95373421,0x519362c6,
        0x168ccb86,0x6f350880 } },
    /* 18 */
    { { 0x442e4248,0xe61cabbf,0x5ee1ab7a,0x24194cea,0x9bacbbb0,0x21b5f531,
        0xabc8abde,0x7d554b80 },
      { 0x7268ca65,0xaeb6a612,0xfe9b7a84,0x3c6f7c15,0x63559133,0x5be8a9ff,
        0x11efe081,0x9d17778c } },
    /* 19 */
    { { 0x2d347f7f,0x65f2b753,0x3a25167a,0x2f70c2b3,0xeafb45ac,0xad9c7fb5,
        0x1c3961be,0x9fcd997c },
      { 0x337ca7dd,0x25b72ce3,0x5a88b6bd,0x255e90d5,0x38834ffe,0x7b1d4dc8,
        0xf241c0db,0x0cb91039 } },
    /* 20 */
    { { 0xcf13b772,0xfa95c510,0xd95aca7c,0xa9b3fc90,0x4cb1a435,0x8e6e7790,
        0x8754e6a0,0x840b63d9 },
      { 0x33196bd2,0xcfa67981,0xef85911f,0x15ab0561,0xfbd94af6,0x504d9402,
        0xfcc90fb5,0x063173d3 } },
    /* 21 */
    { { 0x11fa5996,0x6d58e50e,0xcce6427b,0x5a7db9ba,0x95291d18,0x7d30d5aa,
        0xcd354763,0x9e69e861 },
      { 0x706bd6f9,0x2d0cbca9,0xaf3bda5f,0x63cc64b0,0x06d6cc0d,0x09cc5dbf,
        0x81e50b6b,0x533ba1aa } },
    /* 22 */
    { { 0x25a4c565,0xa5f72c24,0xd3f80897,0xc864130a,0xfb50c4d9,0x40f41882,
        0x5551ed50,0x499c1499 },
      { 0x61ee4b05,0x32404d88,0xd2729bef,0x4a3f1953,0xedbfb28b,0xff878e9a,
        0xe81b4dec,0xca18c856 } },
    /* 23 */
    { { 0x1b87826e,0x8ca4c14e,0xce8326da,0xe4b2b873,0xb0192797,0x5e0b6c47,
        0xbed322e4,0xa95e1b9e },
      { 0x4f98438b,0x94bba8c0,0x6afd2a09,0x8e5301b7,0x9a746186,0xe12fa56a,
        0x3aa68ad0,0x31b5268e } },
    /* 24 */
    { { 0xe0b8f9c6,0x2f67b871,0xe6ce880f,0x101bde96,0x2d8b362f,0x07f08fb2,
        0x3f1daf42,0xe8cfc641 },
      { 0x68742a60,0xe0883246,0xa244b370,0xeb54979d,0x02887b39,0x34cd326d,
        0x7fe7906e,0x68fd6b64 } },
    /* 25 */
    { { 0x0774bf91,0x47c92174,0x90aaeb2e,0x6879e682,0x289b5af5,0xd66bc8cf,
        0x35d21c7d,0xdc9ead34 },
      { 0x5400fd22,0xe55439d9,0x6df86577,0xb4d1200a,0x5cd5bfed,0x79f85271,
        0xa33fd89e,0xf1e74dd8 } },
    /* 26 */
    { { 0x8eadd7c7,0x5d1de787,0x6c9cf945,0x26883aae,0x469c63d2,0xf4c8d3ee,
        0x549fe13b,0x7e163562 },
      { 0x8a1e5a2d,0x6c24e7f8,0xbf1a43d2,0x7f5550a5,0xf268f8dd,0xc3fc954e,
        0x91f23634,0x2b0d6771 } },
    /* 27 */
    { { 0xbaef1d85,0xff22a87b,0xac4393ac,0xcf774cf7,0x574b1d81,0x1cdda137,
        0xc004fd6a,0xcda8f0db },
      { 0x6a5c7738,0x711e9d09,0xfca4584f,0x7189aaab,0x15b9c75c,0xeb8edd27,
        0x78db0ed1,0x0532d2b7 } },
    /* 28 */
    { { 0x7e93d304,0x46c2fd01,0xb6455b42,0x6df3f991,0x5a3146eb,0xad3fff98,
        0xc12c3c15,0x9dbadcfa },
      { 0x48adf57d,0x87a15d62,0xe7f0ad3e,0x9c0ee760,0xf115bb26,0x7ddcf16f,
        0x877423fc,0xee787b98 } },
    /* 29 */
    { { 0xa35b2fe6,0xcfd9c9cd,0x58c7b139,0xc46ffcfa,0x8f28ce21,0xdbafc873,
        0xe79837df,0x4798d018 },
      { 0xadf63b8c,0x5bbe3e66,0xfd7aa8fe,0xbc5d673e,0x133e5359,0x0e5bb7fb,
        0x9dab3fc8,0x645aa53c } },
    /* 30 */
    { { 0xd26b8292,0x84e4b573,0x343e5186,0x0d52bf00,0xb574a3b6,0x783f1d8c,
        0xd76a9e25,0xdbe3f8ec },
      { 0x99b642b8,0xd57dce03,0x770f5a79,0x5113181a,0xcdafa422,0x2b59683e,
        0x61a0aea7,0x9a73de8a } },
    /* 31 */
    { { 0x67ef03fc,0x1367e4a2,0x421bbfd0,0x5b1dd688,0x8e233f88,0xa6789acb,
        0xb9050c32,0xbcc0ad09 },
      { 0x2256ea88,0xcd5e81a8,0xc2083a41,0x2c801344,0x030d6300,0x02992221,
        0x22ac59e7,0x561e5935 } },
    /* 32 */
    { { 0x24424a48,0x11cf4c2e,0x37d4471c,0x843c73ee,0x617a488b,0xb3047fc5,
        0xe3cf861c,0xf2a91709 },
      { 0x1c3a60f7,0x84444421,0x26679148,0x74787a36,0x53d9404b,0x115fbd06,
        0x6244cef0,0x70fd3365 } },
    /* 33 */
    { { 0x1350a8ac,0x825ad1a9,0x55da889e,0xa9527d44,0x84df2c5e,0xa957f05c,
        0x9ff131fc,0x5061719a },
      { 0xa296a530,0xecdda998,0xdf7b5a9f,0x4f5af589,0xc84869a1,0xc2d1d040,
        0x6417fd96,0x8401cc8a } },
    /* 34 */
    { { 0x29853c8c,0xc89b8d31,0x5864b1c5,0x54dec399,0xf2c2b191,0x32c4b3a4,
        0xf08412b7,0x4b4b9bee },
      { 0x97ac6061,0x1a7cee6a,0x5b2c2c33,0x73038ff3,0xa903a0f6,0xa11ffda5,
        0xec43aa54,0xd8a0fa39 } },
    /* 35 */
    { { 0xb6c18ad6,0x7f2ca2f3,0x757eed8f,0xfc2c34c4,0xaadaca59,0xbdbf5e28,
        0x6fac786f,0x979a3f6a },
      { 0x50a130bc,0xe7df10cc,0x4323bd8d,0x6a3f62db,0x8d207c46,0xfc590a10,
        0x2e98c829,0x66a7b059 } },
    /* 36 */
    { { 0xdff39f50,0x96b69deb,0x4ebcd6d4,0x2a3d865f,0x823455cb,0x6ffadbd9,
        0x764ffb30,0xb1f617cd },
      { 0xe8cb5759,0x01ed713c,0x09a6e01a,0x31c4b25c,0x77d99e5e,0x3a4272ec,
        0xf4661c86,0x49ee3010 } },
    /* 37 */
    { { 0x612270de,0x4b4671bb,0xddf060ca,0x0cc60112,0x3aee95dd,0xd6fb8500,
        0xc2448f2d,0x120d05ee },
      { 0x1070c2ba,0xacb71342,0x2ac04adb,0x6eb1f759,0x05519c65,0x6f41914b,
        0x3b4a997e,0xaf69c419 } },
    /* 38 */
    { { 0xc4b11a5b,0xcad8c59a,0x57bdb1fd,0x05d68942,0xdb66574d,0x22d7b638,
        0x30dfab7c,0xd060d0a9 },
      { 0xe0c8e41d,0x5edc0102,0x4a22e5c2,0xe4718293,0xd280fd21,0x9d5a138c,
        0xdfd6b471,0xe47ed3fc } },
    /* 39 */
    { { 0xce30e491,0x5f0fe174,0x4081468a,0xb664382e,0x5ae38ff1,0x8e14c714,
        0x5ea3103f,0x21b63d38 },
      { 0x312036e2,0xafa86cca,0x22b39fe3,0x1fbf7bb4,0xee1061f2,0x59f85460,
        0x28092e57,0x86565def } },
    /* 40 */
    { { 0xa2d0b7ff,0x593a7870,0x60786676,0x286a76e5,0x14e51639,0x00016a4a,
        0x1ba83628,0x176e05d8 },
      { 0xccd7f1c9,0x86eb39ca,0x32f77ef2,0x89dbbf0e,0xc7fa33f0,0x7e6ff400,
        0x406df605,0x1a174b70 } },
    /* 41 */
    { { 0x4d69fcde,0x78ac0d1a,0x910960ad,0x5aedf5e6,0x92339353,0x67103e79,
        0x391534e1,0x0adf982c },
      { 0xdbf326a6,0xe98fd8b7,0x530e4fa6,0x3f71664f,0xd05ba2a9,0x7772c027,
        0xdb678aa1,0x5ecf1ee5 } },
    /* 42 */
    { { 0x924bd676,0x3ae88e90,0x5ddf5faa,0xc7e2a614,0xff44bde9,0x0c01b5a7,
        0xf664d896,0x9b16db80 },
      { 0x5c63dee2,0xd7f4bb3c,0x013c90b9,0x1e57e0cf,0xd59a92ed,0xe6a403dc,
        0x4c61c564,0x90151508 } },
    /* 43 */
    { { 0x222ca5cb,0xc0736835,0x528a8c2b,0x4b7bbc44,0x9091a70e,0xf2e9a9b5,
        0xca8c8302,0x02bdce5a },
      { 0x0c61cf3d,0x3290d35a,0x3401929e,0x13e152c4,0x0264664f,0xacb5ad50,
        0x947dea41,0xc8f83b90 } },
    /* 44 */
    { { 0x2325b5b4,0x79752997,0xdc8f28b8,0xda8348e5,0x4c23c663,0xf8bbb6ff,
        0x2182c92c,0x6a870887 },
      { 0xb800dd46,0xf145c17d,0x3f52f048,0x5eaac872,0x5859b9fc,0xda05888a,
        0x888790be,0x3a66e9ca } },
    /* 45 */
    { { 0x59f902b6,0x774596be,0x1c4919f3,0xc6eb3cf3,0x457c9558,0x9e379b34,
        0x554ccc9c,0x3c86aee9 },
      { 0xd9efa09a,0x3fb79ed8,0xb1a68c0d,0x1098633e,0x6b7fd4c8,0x6e8bb88e,
        0xa4c7dab8,0x0a7fccc0 } },
    /* 46 */
    { { 0x3309ddff,0x20538c6d,0x0ea5b0f2,0x80206f3a,0xb7910256,0x333fba72,
        0xab78861b,0xf80eb58a },
      { 0xb58fc705,0x58a07ab3,0xfb3578ff,0x043d1acb,0xf7eb90f5,0xcb923acc,
        0x1cb26eeb,0x251a6cf8 } },
    /* 47 */
    { { 0x850afc51,0xb58affe3,0xfb637b74,0xdc8a487e,0x57fe16b9,0x946c07b3,
        0x8d8272fa,0x2483b880 },
      { 0x1c79f6ac,0xc402687a,0xb9468ce8,0x90ef68aa,0x7a8e900f,0x077aacb6,
        0x0a82e5ee,0x47e3cd8e } },
    /* 48 */
    { { 0x47c08a1a,0x015385c6,0xb0a4c2b7,0x928d3e73,0xa745f557,0x95f60e9c,
        0xa969f6ba,0x6584670e },
      { 0x190948d2,0xc0d92f36,0xebbe384d,0x9d79c98d,0x971fa585,0x6bcc8320,
        0x36f0ceaf,0x7793c296 } },
    /* 49 */
    { { 0x6d970f51,0xf055669b,0x8d88c22d,0xe83b3c59,0x9685ba68,0x624f33f0,
        0x4a34d05e,0x9a1653a5 },
      { 0xfe134e8c,0x4e89dd5b,0xafd7e22b,0x9cda5eed,0xf2866223,0x49d8322b,
        0x8a8abfe8,0x1b43287c } },
    /* 50 */
    { { 0xdaef42de,0xcddc091f,0x43e9d6ba,0x6c113097,0x80a805af,0x3b8b1706,
        0xada919f3,0x82209792 },
      { 0x99d0b57a,0x3204559f,0xb3befc8c,0x6c27cac3,0x0abe5d44,0xa6378ef4,
        0x85374d49,0x1afa934b } },
    /* 51 */
    { { 0x73c2d262,0xf3c24004,0xc41da1fb,0x3a9f060d,0xeb52f63b,0x44a96fff,
        0x601e3c94,0xa466df13 },
      { 0x24901485,0x09ae8d8b,0xd80ac885,0xcaf436b3,0x050ed93f,0xca82f159,
        0x908c085e,0x4be695fe } },
    /* 52 */
    { { 0x344fdb3e,0xfe2e00fa,0xabeb75b9,0x5604750d,0x7f7ef79b,0xe9eba9b0,
        0xf574a15d,0x2ac3e192 },
      { 0xa5cde112,0x98b0dd56,0x93f7edda,0xddbf00ed,0xc533a370,0xb27f899e,
        0x81609f90,0x2002df2f } },
    /* 53 */
    { { 0xbc8978a6,0x74455f35,0xa66eb954,0x1d50ccce,0x9c4d0818,0xdfa4cbd8,
        0x3511ff8e,0xb52e8f30 },
      { 0xa2efeb7a,0xe6cf2b7f,0x5d526232,0x5822341e,0xd59b88e4,0x0e06413b,
        0xfaa28034,0xcf119b2b } },
    /* 54 */
    { { 0x789f943c,0x5492280a,0x71d42ef1,0xfd788b4b,0xd0dfdfc9,0x5a521b47,
        0xaf6d1a20,0x9bd24038 },
      { 0xdf050a75,0x7adad554,0x0353da85,0x72f639f2,0x988e6b4b,0x58658887,
        0x2e9d0b65,0x6ff2c2be } },
    /* 55 */
    { { 0x7aff0b43,0x51822eb4,0x5a15a720,0x9f92df89,0x32b4b00a,0xe368c221,
        0x140ced6b,0x036951e3 },
      { 0x65bea331,0x8f15ea35,0x3ce5c920,0xbf0324bb,0xc8884ef7,0xda95e3bf,
        0x27c9bcbf,0xd72c7e13 } },
    /* 56 */
    { { 0xeeee6b16,0x7f01fa97,0x40ed83fc,0xcce129d0,0x3fce79a6,0xc93919f1,
        0x96e09e84,0x8dafd0de },
      { 0xfc60c529,0xd65d9049,0x55fdb769,0x5843b710,0xa1a2cfd1,0xa6f973e6,
        0x970fa22d,0x9f0dcab7 } },
    /* 57 */
    { { 0x728aadf3,0xf9020cfd,0xc070b46f,0x376d8f28,0x31f9a432,0x24a02f31,
        0x4c77bb48,0xa9a6c13f },
      { 0xab369b55,0xe4de5c45,0x4f5ac90d,0x6cc8cb04,0x7c80e815,0x131852e1,
        0x0f679300,0x8504f355 } },
    /* 58 */
    { { 0x3a22cc5d,0xb4d3fbe5,0xdaa6bdcc,0x612067c7,0x6301480f,0x2919eb5b,
        0x6f5bafae,0x4238725e },
      { 0xd8ae2dfe,0x25af69a2,0x3dedbd09,0x992c6c3f,0xa4ffcf12,0x232e6f43,
        0x7b9206d5,0xe0ff2634 } },
    /* 59 */
    { { 0x5f6a97eb,0x23398e1c,0xa12e0bc9,0xfeec3b49,0xc1afaf63,0x2db029d0,
        0xf6b1ad9d,0xcaf10eee },
      { 0xa8f02497,0x87154e4d,0x712c4b88,0xae1a98e1,0x4ebe9643,0xf627d241,
        0x2861505f,0xca4c47ed } },
    /* 60 */
    { { 0xcee1f8df,0x35ff1959,0xeba36ac5,0xfae13dc3,0x8f4a0d4a,0x5a426de7,
        0x606db796,0x5019e48a },
      { 0x1628aa47,0xdc814132,0x5a5e065d,0x75ff8570,0x8065b511,0x89891988,
        0x513cc426,0x7880810a } },
    /* 61 */
    { { 0xab8bbe28,0xb6dc4dc0,0x0846ba34,0x5dbe49e5,0xe93bfba7,0x1abeba8c,
        0xaa1021ff,0x71c0d8d2 },
      { 0xbba1651d,0xce2cc527,0x183a2ae4,0xd328e4c8,0x6c221e0a,0x7836996d,
        0x758e1436,0x1a3181c9 } },
    /* 62 */
    { { 0x9224e28e,0x7bc381f1,0x366bb0d8,0x8b125f05,0x7e8cafd8,0xcfefc04f,
        0x063afd7c,0x5bd73477 },
      { 0x0a245316,0xccd169ab,0x9104f04f,0xac7c8832,0x3ac7762f,0xb1a61164,
        0xf0b315d8,0x4c80bb71 } },
    /* 63 */
    { { 0x63b9249e,0x07c7831a,0xbbbda95e,0xe5e0f45b,0xdf4517e8,0x9d1b6c0f,
        0x69bd1d79,0xd01cde06 },
      { 0xea498130,0x36dd69a7,0x8451ab5e,0xdaa65193,0xe4ad3ded,0x88a3cded,
        0xffc9f1b0,0x32c2a71b } },
    /* 64 */
    { { 0x202bde39,0xfb3992a4,0x3d6bab98,0x2549f564,0x87712512,0x0b564642,
        0x7fde7e50,0xd52442b4 },
      { 0xa3d3e16e,0xa6cefd08,0xc83b29bd,0x5b194f0a,0x906dec8c,0x6db0edd8,
        0x02570c1e,0x7a090959 } },
    /* 65 */
    { { 0xbfab3d26,0x04d6ce6d,0x668edf18,0xf2aa223b,0xf06250ba,0xeb899557,
        0x4940d66d,0xef6bba07 },
      { 0xb78ca345,0xb483763b,0x3f08ff72,0x15867b4f,0x5bca92b2,0x91225b72,
        0x498804db,0xccead663 } },
    /* 66 */
    { { 0x58d49df0,0x233c13fb,0x5003f43d,0x3d25550f,0x8472130f,0xf6f920a2,
        0x142c3def,0x3b9507a3 },
      { 0x697ac7d4,0x8108608f,0xbb84db98,0xfe1cfd90,0xd61853b9,0xcf2ac224,
        0x6ae3b38c,0xac6fe44c } },
    /* 67 */
    { { 0xa42c8ed7,0x9b4d14a7,0xc988a847,0x1ec02af9,0x33dca61f,0x3a6fcf6e,
        0x72852f91,0x31d28b00 },
      { 0x6eefcf6a,0xcc689bf6,0xc1c5002c,0x835e6f24,0x636c179f,0x716fa507,
        0x62bb7883,0x2ec87a6a } },
    /* 68 */
    { { 0x487bdc21,0xd7aef5e8,0x858c0310,0x626fbd75,0x08d1054f,0x8cd9250d,
        0xd0831265,0x25a65ab1 },
      { 0xfec04e2c,0x4d0ac007,0x8ddf0f4c,0x859f4355,0x031dd8a0,0xb1d58e0b,
        0x9618799d,0x9df8ab40 } },
    /* 69 */
    { { 0x43d44adf,0x4cfcca55,0x6bf2e90e,0x6ed6f695,0x1f8b275d,0xff878d62,
        0x846471f5,0x4ac00774 },
      { 0xd59b5eaa,0xe8f08905,0xc904e73a,0xf961eb4f,0x8419c14c,0x51282943,
        0x94e41d6e,0x591e7dcf } },
    /* 70 */
    { { 0xf2bad284,0xdcd90e7f,0x855fe1aa,0x6a6b30f3,0x8c15c1e8,0x8561f904,
        0x74d14887,0x3e06e031 },
      { 0xe6db2203,0x777a67b2,0xd2e66bd5,0x58db5e94,0xb65cf7b0,0x28df0d59,
        0xc6260357,0x2dab3a07 } },
    /* 71 */
    { { 0xd2792b23,0xcf33c73c,0x4a6613a4,0x1f2cfc95,0xc22cb6f3,0x1174a86a,
        0x17f30cba,0x4ae01cb0 },
      { 0xbad7d330,0x8b07c15e,0x3b414fc5,0x53295cb4,0x9201c68e,0x555022e1,
        0x92ad8ccf,0x07bce7c2 } },
    /* 72 */
    { { 0xcf71938f,0x955fec91,0x3cc010db,0x6176f044,0xd5c81390,0x5cbfa71c,
        0x724141fa,0x78040891 },
      { 0x4211fcc4,0x9d20f9f2,0x69d45611,0xf5a0c968,0x93bb5005,0xfbafd81b,
        0x0e95095c,0x7b9d8d7b } },
    /* 73 */
    { { 0x565cb6c4,0x3ba07473,0x7f738e87,0xf2fc4313,0x893003e9,0x0edefd71,
        0xce48b45b,0xce96d07b },
      { 0x45a3e43e,0x9d181f96,0xe6e75f80,0x4d1c0992,0xecf10bab,0x3651ec38,
        0x179d4a8b,0x60fa83fc } },
    /* 74 */
    { { 0xdb2f8c7c,0x965fea09,0xf767bafd,0xc0541081,0x2c0c2017,0x67da4ff0,
        0xe428da08,0x472c556a },
      { 0x7c717933,0xb85cb20a,0x0dddf8a0,0x88d4477c,0x88b0ba37,0xc36017df,
        0x2c6162d5,0x3412b136 } },
    /* 75 */
    { { 0x7a26cf67,0x602133f0,0x0f3ed6c4,0x231fa345,0x2f7819be,0xa8183f39,
        0xcc40e1b9,0xf403ddb0 },
      { 0xfd14746e,0x623111d8,0xfc2a4978,0x4ed1d1b7,0x50bde2be,0x4bc2ae2e,
        0xdd66148d,0x42cc90f7 } },
    /* 76 */
    { { 0x5471c5c7,0x2ce4232d,0x35c69a9d,0x90c84c6f,0xefed117e,0x57b5a756,
        0xdee73305,0x89a7a62a },
      { 0x1e5add63,0x1e9e8ce2,0x977005b0,0x47e20b3f,0xf61dc977,0xde442f5d,
        0xdafd1699,0xe8222d95 } },
    /* 77 */
    { { 0xfb21173f,0x13f16ab6,0x13b23320,0x7d650562,0x803dc588,0xfd35f369,
        0xb6c26025,0x1ff1996a },
      { 0x7e49ae4b,0x5932441c,0xc1d4d2b3,0xe58d8cad,0x701f9a86,0xfc26aeae,
        0x3826d2cb,0xf3043fe5 } },
    /* 78 */
    { { 0xbeb74735,0xd27c6070,0x3b016809,0x662f4962,0xffffa491,0xf2f821c4,
        0x8de08a68,0xe80d0d2a },
      { 0x5152be84,0x06478378,0x4d940804,0xe65b70a6,0x3f729581,0x5b390ac9,
        0x13b0a068,0xb39a11e4 } },
    /* 79 */
    { { 0xedc47a03,0xbe943e88,0x8163d1eb,0xdb040044,0x402cfc25,0x7673179c,
        0x858ea0ad,0xa7842fb6 },
      { 0xc3a823a2,0x69497369,0xebda0548,0x8af3d54f,0x6b2363f4,0x8975de55,
        0x707aa586,0x5e931dec } },
    /* 80 */
    { { 0x805f0ed8,0x7254de6e,0x05ad4708,0xe0ad1d79,0xa339058e,0xf3212455,
        0x834b8957,0xf176c2f9 },
      { 0x9162ff84,0x6a42a692,0xeaa628e8,0x7af37ab5,0x0da655e1,0xe6605aa8,
        0x9bce77b6,0x840eabd9 } },
    /* 81 */
    { { 0xb891bf80,0x15e2a820,0x3dcfd53c,0xf218d7d6,0xc354f5d6,0x0b3fbb91,
        0x60ec6c0b,0xd2907e20 },
      { 0x4a8c701a,0x2ba584dd,0x9f829e57,0x1edfa8b2,0xf33ce835,0x482e8e37,
        0x75b06197,0x4f8b7581 } },
    /* 82 */
    { { 0xbfbe555a,0x2be95107,0x77b3851c,0x9b76fb7e,0x318b7f27,0xbeb03148,
        0x80fde126,0x425194eb },
      { 0x2996474b,0x489a386a,0xcd1ed314,0x318df1af,0x807c380c,0xe01451dc,
        0x2a38be26,0xc0dfbdab } },
    /* 83 */
    { { 0x4043ce80,0xcc5a05bc,0x28e09c50,0x4101c7dc,0x1ab5ee6b,0xcec16f69,
        0x3f02fbec,0x6e0539e0 },
      { 0x57b36485,0xdc36e66a,0xe5c8d145,0x07d55262,0x104068af,0xae754a39,
        0x1c470491,0xc47aefb7 } },
    /* 84 */
    { { 0x48e761ab,0xc1f039f8,0xa4db0990,0xb75d923c,0x85ba216c,0xfe8fffc1,
        0x64667cdc,0x5f193c87 },
      { 0x78ed1f3c,0xdce2f35c,0x77a90887,0x82cbb59e,0x521fca71,0x0c6bb634,
        0x8d79141f,0xbf0b44e8 } },
    /* 85 */
    { { 0xc6fe11e5,0xc424f15d,0x19a25ef3,0x1e866a49,0xdbb31334,0x419ace92,
        0x2408a903,0x1bd3b441 },
      { 0xcad2225b,0x1bb62300,0xcf204b84,0x44db4cab,0xcd229aa6,0x9fcf0afa,
        0xcc492384,0x38d13bed } },
    /* 86 */
    { { 0x5e4fb378,0x7bd9a114,0xa1c8e94d,0x56be5ae6,0x2fa18b0a,0x9322de41,
        0x5aaf8696,0x983fb47e },
      { 0x28cde8ea,0xd32e6249,0x2bf0d003,0xc235267d,0x0571b4e8,0xfbc55e89,
        0xbd605049,0xd119056f } },
    /* 87 */
    { { 0xe5729482,0x9b16c659,0xf29b3b86,0x4b02be67,0xceedf6f3,0x36702e4b,
        0x6c023e01,0xf518950b },
      { 0xc01c7886,0xb2b536f0,0x093b1218,0x99704f46,0x77b68364,0x500ac8e0,
        0x9231e9c5,0x65f72478 } },
    /* 88 */
    { { 0xcbb602b5,0xb3ff545b,0xbd8413ab,0x566e5114,0x4b5d352a,0xe9aefd98,
        0x0f457ed2,0x5bae49a8 },
      { 0xf11d8800,0x07e4695b,0xfd4ec25d,0x01ac54b6,0xd2b70671,0xd6644e6e,
        0x1d8605d4,0x28bb3e5e } },
    /* 89 */
    { { 0x69044ab8,0xe7b1887e,0x5cb4f30b,0x933044b3,0xdd7b9891,0x7aa537a5,
        0xf19f3221,0x42072798 },
      { 0xc51f50d8,0x6b8297e3,0xeef90e53,0x5b21edfc,0xfe5c7059,0xcb57951e,
        0xfab581be,0x6d2d15fb } },
    /* 90 */
    { { 0x5d33b0b6,0x690e6f83,0x95d73cc3,0xbb452cdb,0x37cfebf4,0x62ebea7c,
        0x3193c9ce,0x9035b627 },
      { 0x40f4d7b7,0x5c45279e,0x28f329ba,0x799d6753,0x35fc993d,0x07bc499f,
        0x009a4c1d,0x7d579db8 } },
    /* 91 */
    { { 0x9cbe4314,0x26eee57d,0xa8584f9a,0xb5ebf1aa,0x8db21946,0xdfe924e8,
        0x6de2ed08,0x7c2f8c18 },
      { 0x62204329,0x72a56c88,0xfd970ace,0x0e5af12d,0xc3273716,0x391a62ec,
        0x8e9208f7,0x11796fed } },
    /* 92 */
    { { 0x64c0138c,0xd9c1d014,0x1ac403c5,0x0f1bc4c4,0x537f20f3,0xede9cc66,
        0xf1d4067e,0x0814c5e4 },
      { 0x8e58bd95,0xee04e423,0xfc9a7231,0xcd262e86,0xbb8fdf12,0x8a2c8b6c,
        0x81698dd0,0x772a46b0 } },
    /* 93 */
    { { 0xbb35551e,0xbb5ba56d,0x663c3ba9,0x07c04bf5,0xc13f92fa,0x2658e49e,
        0x4b0528a6,0xd8002bf0 },
      { 0x6e19feae,0xe5a5a44f,0xd32f85bd,0x5182c831,0x2f326a5d,0x7391563e,
        0x1043c6ab,0xc04b58b3 } },
    /* 94 */
    { { 0xd98d1a35,0x77cb1957,0xd2dae5ee,0x75fa1798,0xddb024c1,0x21387bf6,
        0x057d7f35,0xb3706b48 },
      { 0x0d7e2ad4,0xf2cedf39,0x25ab3e0a,0x09b70778,0x925ec8be,0x67f4ebfd,
        0xdfca4b5f,0x6ffb26ed } },
    /* 95 */
    { { 0xbae85738,0xf9524628,0xdd316b90,0x8699f4ea,0x1c6ed782,0xd8d0f110,
        0x7e60fbe1,0x4175889e },
      { 0xcc11b1cd,0xaaff3def,0x0e5e9428,0x87177ff8,0x0292d76e,0xd1cec679,
        0x87323f56,0xdbbabaaf } },
    /* 96 */
    { { 0xafe9099f,0x862696e9,0x407a925c,0x4f695f15,0x2dae1f95,0x8701f30a,
        0xf45e4cb1,0xf984c561 },
      { 0x6ebb4441,0x4fafee1c,0xfa59ad45,0xfbf96f53,0x20ba55c7,0xa530b86e,
        0x90e0423d,0x6efa587b } },
    /* 97 */
    { { 0xb7bdf0b3,0xbe355bfe,0x806394fc,0xf1d290fe,0x56c8e8f1,0xf517a086,
        0x09b301f3,0x32756a1d },
      { 0x93704c72,0x0e7e1fb3,0xd2c711e9,0x5a3ebaa1,0x936ec599,0xaea7952e,
        0x46521036,0x4493678e } },
    /* 98 */
    { { 0x525ca4c6,0xe4161f6d,0xb4c96eae,0x1b969ac1,0xc70338db,0xf9975658,
        0xa08ddf12,0xa064cc6e },
      { 0x1c73ca8e,0xdb438c3e,0xc825e7b0,0x0eeac3f1,0x4659f59a,0x874903d9,
        0x0d98731c,0x2270c0c1 } },
    /* 99 */
    { { 0xa16a8f1d,0x0c821bcb,0x8748f6a5,0xb559c2e9,0xe8991a9a,0xd7ad00ec,
        0x98fa2758,0x56cc2caf },
      { 0xb185924f,0x69a09406,0x008daf7a,0xd56e1870,0x682b81d1,0x1a307168,
        0xa6a712d0,0xb51075f6 } },
    /* 100 */
    { { 0x82da577d,0x7bf7375f,0x2dda1fa8,0xf191d584,0x0a9fbd96,0x06a73740,
        0xadc73390,0xa81aa04b },
      { 0x0627446c,0x7e77b3ac,0xb8bc08b7,0x4e662186,0xdfa62560,0x8315b1bd,
        0x619678d3,0x912ba4fd } },
    /* 101 */
    { { 0xe21bda2f,0xaa6244e7,0xcea4ad07,0x82aec7d7,0x92f8a4ae,0xa391e63f,
        0xeda9032f,0x0811b0a9 },
      { 0x0c1e7599,0xbb8c7293,0x5c36a1cb,0x02a31865,0x641883c6,0xbe014f1a,
        0x116d0352,0x98c6cb62 } },
    /* 102 */
    { { 0xa1df225b,0x331d9e52,0x7fefdd9c,0x133b0ae9,0x29f9af11,0xc003f65e,
        0xddf01433,0xad884879 },
      { 0xa4af26ff,0x7261e2f6,0x1f6ff193,0x57e94b62,0x1aca40cf,0x4640a4d4,
        0x3c5cd73b,0xbb2ca6ef } },
    /* 103 */
    { { 0x4664d8b9,0xfbdb73cb,0x32302861,0x403c2412,0x06b814c6,0x9000ce62,
        0xcd3aa1fd,0x28ad9c95 },
      { 0x1d012d1d,0xfc458583,0x5f8eef3a,0x4d784c38,0xce859d46,0x15d7456c,
        0x8fdd537c,0x2002b79d } },
    /* 104 */
    { { 0x58ff29ca,0x269a8e83,0x7d4a65f9,0xb49c4f76,0x40457f21,0x758233f9,
        0x91ca479c,0x149755a4 },
      { 0x40cdad3b,0x9f204823,0x0edf5d42,0x52efa201,0x6843c0a9,0xe0cf812a,
        0x5ee13b47,0x3e9b4d51 } },
    /* 105 */
    { { 0x1851bb43,0x58725c44,0xb1d5f4c5,0xd6ab9afd,0x4561ed22,0xcc47d6ce,
        0x44fbe7f1,0x36e92579 },
      { 0x78e47086,0x9dd595f7,0x0cd23532,0xb90420e4,0x8bd666e8,0x4eec937e,
        0x0c851ae6,0x5fda90a9 } },
    /* 106 */
    { { 0xfe3ece65,0xecd87e43,0x2e511f19,0x2c4a07ed,0x2bc895e4,0x0cef0a33,
        0x81b1b783,0x5a4e679c },
      { 0xf35bef34,0xff577167,0x7e9a98ac,0xfd949a88,0x82e42034,0xecd9b69a,
        0xe0a3249a,0x3960b999 } },
    /* 107 */
    { { 0x341a4ca7,0xb0634531,0x653c48ea,0xa97b2f74,0xe05211b9,0xfe7fcd35,
        0x2fa897ff,0x3abfb61a },
      { 0xb67a9b8f,0xc4665714,0xd4f1f720,0x77c3f374,0x79e90128,0xea8882f8,
        0xd100d209,0x2a201265 } },
    /* 108 */
    { { 0xbfd9fe05,0xf4c15d09,0x3764454a,0xbfd5269f,0x5fbcee9e,0x757375b9,
        0x30499a3d,0xd6487246 },
      { 0x0dd0e3df,0xd4aeea19,0x99b2c184,0xdba477f3,0x476f6787,0xffa9671c,
        0x32d1cbed,0x404358f2 } },
    /* 109 */
    { { 0x45ba70a1,0x88096568,0xd7c02846,0xc1025d8e,0x10e79c61,0x10070d7a,
        0xcc51d71d,0xda5545e6 },
      { 0xd36071a4,0x86100592,0x2cb84b66,0x7ccf96bd,0x9f09a3ae,0x8c04ec14,
        0xf07c45fb,0x90263635 } },
    /* 110 */
    { { 0x15a02c24,0x6c021a6f,0xb345c3eb,0xd8fd90d6,0x6346cb58,0x4deeb0f8,
        0x28c63a00,0x8e319f99 },
      { 0x3fbe9596,0xae65c88f,0x2c57f362,0xcd441226,0x77874cb4,0xb491d9b3,
        0xca29eff4,0x1a6cc217 } },
    /* 111 */
    { { 0x82b02298,0x81a498d3,0x70c81c1f,0x71934d19,0xd06009e1,0xab24b353,
        0x2a10368b,0x270bad31 },
      { 0x1acf8d51,0x4a58be03,0x96fe90ff,0xe9f0519e,0x6a2cbad7,0xf74b1373,
        0xd0501451,0x558377b9 } },
    /* 112 */
    { { 0x61f8c84b,0x0f7acf31,0x6e47a311,0xa5a72c1e,0x4373f8c6,0x16c2690e,
        0x59d03954,0xc05d2da1 },
      { 0x2c7e9247,0x70230c54,0xce9531dd,0xc29d9317,0x90f1f78e,0x9683a0ef,
        0x5053755d,0x7dd05c85 } },
    /* 113 */
    { { 0xd935116f,0x369f32c2,0x28550a73,0xf776c2e9,0xc5d579b6,0x7e449b09,
        0x217a7ade,0x2caffed8 },
      { 0x17ca913f,0xacfec3fb,0x299bdfe4,0x1b592631,0xa8bbbc6e,0x58016260,
        0xa90f5edc,0x6ab392fc } },
    /* 114 */
    { { 0x0ccceecb,0x904d2c9d,0xd0705967,0x89102f9f,0x8813ef3c,0xd12f4193,
        0xf7fe5335,0x2ec8a831 },
      { 0x736d8979,0xb60e1674,0xb00549a6,0x9115936b,0xa64085eb,0xdf4f2d15,
        0x0f72a207,0x4517fa55 } },
    /* 115 */
    { { 0xb807c6e6,0x269664b9,0xae45a4c6,0x31ef23b4,0xe3791c14,0xe2076e09,
        0x7a383887,0xb8c4f567 },
      { 0xbc149a92,0xa831e21c,0xd3a787be,0xa4e6c3c3,0xc3ffd766,0x0eb26c57,
        0x7796e8bc,0xa9f8c4f6 } },
    /* 116 */
    { { 0xc2df4bf3,0xecefcd0b,0xaca2333b,0xf34c21e5,0xdd23fb04,0xbf4bc9d7,
        0xaefa8ac8,0x8188fc44 },
      { 0x8d27e4ff,0x8f98a930,0x56de5282,0x176f524b,0x653ba693,0xac357342,
        0xc7917bc3,0x1184e8d4 } },
    /* 117 */
    { { 0x3ec27426,0x819f080c,0x314f618d,0x1bf33d34,0x05605882,0x59d87c26,
        0xbe748ebc,0x614c5091 },
      { 0x6b12648e,0xbbec1bcb,0xb1ead712,0x84575ab0,0x727f376d,0x0d567c95,
        0xd689b2d7,0xf7138698 } },
    /* 118 */
    { { 0x002936dd,0x58a15b85,0x85ff129e,0x32db35c5,0x2c76679f,0x1c85d85f,
        0x820975d3,0x1c4e12bd },
      { 0x7a93eaa8,0x8fc04964,0x63676744,0xf3aba428,0x104c293f,0x07fa73fa,
        0x988d3071,0x90c82500 } },
    /* 119 */
    { { 0xdbff4eff,0x4c8af557,0x97c3fa17,0xc63c072d,0x10949630,0x5f7276b4,
        0x2ea82545,0x34db1d0e },
      { 0xe950c2ce,0x5282e7da,0xccc61dd3,0xc0584105,0xcb48882e,0xcd364e40,
        0xc46717d9,0x62e3bc4e } },
    /* 120 */
    { { 0xf4d76e8d,0xdc9ad306,0xb922a0be,0x37e687dc,0xdffb5453,0xd06acfe9,
        0x16391951,0xc8525290 },
      { 0xcc8601a9,0x34de48cf,0x58b73373,0xc4f078b7,0x28bd9fff,0x2a3cc096,
        0xefd134d6,0x5bec709b } },
    /* 121 */
    { { 0xf4d0a639,0x4e44abad,0xfe612ba5,0xbb4c9910,0x30e58c0c,0xab2e5b41,
        0x3e800e9a,0x9a6a2fa5 },
      { 0x2ca0d01c,0xf5cc5788,0x89a25d59,0x3f8412a1,0x453fbaa7,0x4ba569e0,
        0xe0629ab6,0x9e33bd82 } },
    /* 122 */
    { { 0x61613f97,0xd4fe957c,0xf35694cb,0xb86e9ddf,0xa0a7f9c2,0x65700b9a,
        0xa789f4ac,0x349a4dbf },
      { 0x483553c7,0x836b7cf8,0xe07dff25,0xe41f0e55,0x848bb8e4,0xe71ca712,
        0xc00a7fa8,0x625b33bc } },
    /* 123 */
    { { 0xc7068002,0xbf41f45a,0x78affb63,0x9f4b862f,0xff3207fb,0x523f30d1,
        0x7212b4e2,0xaf653430 },
      { 0xbd9269e3,0x595b18f6,0x5bbb73b4,0x0ddc252a,0x2381044d,0xb59634a8,
        0xc4df1aab,0x72550c74 } },
    /* 124 */
    { { 0x4997b745,0x0f4ead41,0x80ab7698,0xab3e46c5,0x85719bf1,0xe010d55a,
        0xe7304bd3,0x0fe9667b },
      { 0x44eae3c6,0x8e112a0a,0x8a4808a7,0xd30ce0f5,0x5c32d57d,0x3fac7831,
        0xc95d0e1c,0x1e4b2152 } },
    /* 125 */
    { { 0x64a0b46c,0x9c6b8858,0xec200e69,0x6a3c1253,0xa74942ce,0xdb0e573f,
        0x257dd452,0x1ef64607 },
      { 0x89b9b886,0xb3efd2e5,0x4ef3df9b,0x2046de87,0x110a57e0,0x4b837cee,
        0x79f3139c,0xc8b42744 } },
    /* 126 */
    { { 0xecd31b38,0xfd57f4de,0x946b43e6,0x5064631b,0x3f27e71a,0x5f75a0e8,
        0x8539cdb4,0xb98d159a },
      { 0x46fc3042,0x941caf07,0x862ec3fd,0xb0e4e23f,0xfdc6a175,0x637e2cb2,
        0x3589c36f,0x52425584 } },
    /* 127 */
    { { 0x63fb7688,0xb80bee0f,0x16ad1233,0x4b03dd04,0xdeab742f,0xb2aa0667,
        0x7d622028,0x3af71b2d },
      { 0x725b4531,0x4caa50b4,0x08af5e89,0xbb4342ec,0x3c77438a,0x2b61fa9d,
        0xdb0af575,0x01d25439 } },
    /* 128 */
    { { 0xc25dfad3,0xe74e265b,0x493f44b6,0xd03630b9,0xbfd6d473,0xb3270892,
        0x1c5ee992,0x5b2d9543 },
      { 0xa36f7c5f,0xeeb94537,0x8ab0b81d,0x9befc01d,0x188b45e5,0x483cdb08,
        0x01e4648b,0x44c753b7 } },
    /* 129 */
    { { 0x924195ac,0x779ee42d,0x0cec6c21,0x44ccd6a0,0x211bd343,0x1a0df86e,
        0xa7fc826e,0x2f73a627 },
      { 0xdd4b2fac,0x179c9d7c,0x65a3f70b,0xe09df4b3,0x63270b3d,0x169b58ea,
        0x57217f02,0x5934a0a0 } },
    /* 130 */
    { { 0xf471c90d,0x488905bf,0x30de94b7,0x2fe5dcf5,0x8218ea8f,0xef436698,
        0x79e5558f,0x986125e8 },
      { 0x2ce9c497,0x2e59c17a,0x1ddab4b1,0x8131f0e2,0x20035218,0x408daea7,
        0xd40469e4,0xcd71798e } },
    /* 131 */
    { { 0x0fe2e160,0x3c3fd652,0x05bcf84f,0x569f8123,0x5151f451,0x022bf0e9,
        0xac2845ec,0x054574f4 },
      { 0xd524a547,0xbb17853d,0x33d6e7b0,0xbf1b6f27,0xd4d10a83,0x5d71af25,
        0xe8ae37e7,0xd4cfa938 } },
    /* 132 */
    { { 0x843e3cb6,0xda39e364,0x61812528,0xf259a38d,0x57862e0a,0x94912e51,
        0x2e978c13,0x8142ba4a },
      { 0x244620d5,0xb8348db9,0xa46c8074,0xe67f9053,0xa1e6346e,0x21ab9bff,
        0x64f1b73d,0x04415770 } },
    /* 133 */
    { { 0x74019e33,0xd4355d58,0x18e26d25,0xdb1c1b22,0xea91876f,0x9a39a7d6,
        0xef2d83fb,0xc1d29df0 },
      { 0x9cfaf04f,0xf2378120,0xc33a65ee,0x5ca4b4bb,0xc5364c6b,0x529e4d14,
        0x0b9c3666,0x9cd549d0 } },
    /* 134 */
    { { 0x0d561bbc,0x7dacb824,0x753ced32,0x7c7c2fd1,0xf3afb037,0xd9774757,
        0x0d6e3a55,0x213fe371 },
      { 0x50d4f212,0xa6d3d8d5,0x98665a38,0x674c0a81,0x4f2a518a,0x112e0ed5,
        0x8f902353,0x1b995abf } },
    /* 135 */
    { { 0x0f049d2f,0xa06b8d22,0xeea425af,0x415763b2,0x8051b012,0x027b304b,
        0xef51bae0,0xb8cdb43f },
      { 0xd7109f5c,0x492e11fe,0x7298d02f,0x0b57be5d,0x634f9a12,0xeeda24c4,
        0x1592d326,0x0b0aab29 } },
    /* 136 */
    { { 0x1d0ad6b2,0xa4a48c8d,0xde384635,0x3b996e4b,0x19b7e324,0x09d5a0fe,
        0xefac055b,0x5847aae5 },
      { 0xa0c3770e,0xf6b1627f,0x6fc34e82,0x37cb2670,0x6c0ede62,0xfdcb37fb,
        0x2a34e059,0x4e41298d } },
    /* 137 */
    { { 0x9a3b63ad,0x84b04e36,0xbc323063,0x8353ab53,0xc0045b9a,0x06987eca,
        0x46f45828,0xb461ba88 },
      { 0xe5943ccc,0xd37ef067,0xcdc4de91,0xe5d36625,0x024ac769,0x4f72a9d3,
        0x3c8e2b9d,0x0ad61f17 } },
    /* 138 */
    { { 0xb5c95125,0x5114fdc8,0xc9341981,0x57637b86,0x39b74fc0,0xb66786bd,
        0x230b7e41,0xc9e138be },
      { 0xde050283,0x0bc6d5fe,0xd609a03e,0xa7c743a3,0xb1ae24f0,0x1233df12,
        0x57db9668,0xb2ea42ec } },
    /* 139 */
    { { 0x1363c862,0x9f9b8840,0x39a4b717,0x9a850b30,0xf87a216d,0xaeffb727,
        0xb3d99a0c,0x754cb279 },
      { 0xbade742c,0x046e6946,0x3b3ea466,0x05669a4f,0x23aa2b1c,0xc64392ba,
        0xfd714fe1,0xa218279d } },
    /* 140 */
    { { 0x235b46aa,0x4203d984,0xe219d5a2,0xb35f0c71,0x3c5ba535,0x93a429b2,
        0x9111aaca,0x7eefbb77 },
      { 0xc45d8760,0x67b99023,0x3ce39388,0xa0f78654,0xdbf34ec0,0xaafb1901,
        0x2dced638,0x49498c8b } },
    /* 141 */
    { { 0x99e4ef46,0x94f5cc8a,0x0ef0d4b1,0x3321e667,0xffb89f14,0xdb2d0224,
        0x9d069a20,0x9bf74803 },
      { 0x4f1c1f1e,0xa64d6b13,0x2162dd15,0x1ab10285,0xa7742325,0x7c7f6a09,
        0xc823efc1,0xc5a9082d } },
    /* 142 */
    { { 0x3d087141,0x393fb679,0xfbdb7ff5,0xe872932d,0x4ba6c9d3,0x21bff1a2,
        0x97ad760b,0x3193dea2 },
      { 0x10c7e145,0x0ae5a741,0xb18493bf,0x9e7cf429,0xc871111e,0xa0a3bfa1,
        0xda10cf39,0x322f34ea } },
    /* 143 */
    { { 0xee32db92,0x482375dc,0x416f8eb4,0xa7e02d01,0x004ba196,0x224fb2c1,
        0xc6488715,0x165f5f16 },
      { 0xd1125e78,0x4cad71bf,0x37d5cc46,0xf7a1b1f4,0xefd065af,0xb54a9fe1,
        0xdbfbe5e7,0x3a954eb0 } },
    /* 144 */
    { { 0xff76620a,0x45f4a643,0x18233034,0xdb839133,0xaebce0ab,0xb777abee,
        0xb961e3d8,0xe610ded6 },
      { 0xd7bc0322,0x848f85dd,0x05bcf887,0x64dec64f,0x85d3ed98,0x32f43df0,
        0x0af94bf8,0x2e150e9a } },
    /* 145 */
    { { 0xc7de998e,0x5890c658,0x3509373d,0xc418a43a,0x7d290312,0x04661baf,
        0xd4f3762a,0x87a24bda },
      { 0xcaf8e73a,0x3a46493d,0xa475ba0d,0x694bce49,0x1fa35fe6,0x9af7566e,
        0xd7bc94ac,0x3ee19601 } },
    /* 146 */
    { { 0xdfb0faec,0x5bf209ee,0x8a6ec977,0x514ea871,0xd04a9727,0x95b71f0e,
        0xdb496313,0x4650bc76 },
      { 0x58184292,0x22cc758d,0xec9aceab,0x152d43f9,0x091f0bb7,0x4b47606e,
        0x1b7d4e79,0x6da270ef } },
    /* 147 */
    { { 0x935c7726,0x4ee7022b,0xd1af2fac,0x2f7e7bb7,0xfdf9e72f,0x55a2f594,
        0x14b8b2d8,0xedf46a30 },
      { 0xcdc3292f,0xe5fba600,0x58c6f6a4,0x04b54a3a,0xb023369e,0x1263dc16,
        0xbfc3a1ad,0x0ac721dd } },
    /* 148 */
    { { 0x27351b84,0xe62e1d91,0x4dba475b,0x5c99d239,0x567c9219,0x6cafe0d0,
        0x5418e29b,0x8db1ed2a },
      { 0xe729b5e4,0x36d4e136,0xed502494,0x0c714c79,0xf4809507,0x20d538d3,
        0xb0b20279,0xc187d5fb } },
    /* 149 */
    { { 0x51ad0a16,0x68ca10ce,0x679b7804,0x3150db24,0xbb25aa04,0x0e9496a5,
        0xac090e22,0x71237e21 },
      { 0x8454f658,0xd3911b2b,0x99498743,0xb4cc8be3,0xe6a6a08e,0x3eec8fba,
        0x89d40596,0x32302505 } },
    /* 150 */
    { { 0xad144097,0xe898b046,0x24c88b1a,0xc5ca6ff8,0x8cf479ae,0x9d01b59b,
        0x92115900,0x5ecd93aa },
      { 0x61716de7,0xf4b4b1d8,0x58d641b5,0x187b1e07,0xca3f3a12,0x3c6948c5,
        0xee7e1518,0x3841240c } },
    /* 151 */
    { { 0x69f16249,0x7d5bc16a,0xdddb1510,0xaa932350,0x76d23cc9,0xe5df5104,
        0xbb0900eb,0x2f2a1306 },
      { 0x699413cc,0x9fdf3047,0x26394d94,0x71f3cd30,0x59396461,0xad22fa8c,
        0x469fbffa,0x6c6253bc } },
    /* 152 */
    { { 0x1e33c180,0xb79fbc3e,0x615e3e38,0x754fb963,0x37111e5e,0xa3a40838,
        0x49f757bb,0xd8780e04 },
      { 0xe545fb38,0xbb941a11,0x55d54231,0x227ba21b,0xcfcc068d,0x5d80da73,
        0xe600e277,0xd3b0557b } },
    /* 153 */
    { { 0x595a7415,0x286524f5,0x657a5920,0x1e8dcdfc,0x1477845c,0x04d7efa9,
        0x17d2b3ba,0x86bd1af7 },
      { 0x06b56786,0x08e833c7,0x028130b2,0xff007b61,0x6e05001d,0xfcafe082,
        0x37fe292a,0x41556b55 } },
    /* 154 */
    { { 0x0baaa8ff,0xfddd3819,0x45bc51be,0xd916d17b,0x6a86f8a9,0xf981a07a,
        0xb2c36491,0x23111568 },
      { 0xda2059ab,0x51628fa0,0xa2f34fea,0x62537ee8,0x30d7894c,0xf34ce38a,
        0x967e567b,0xc464b9dd } },
    /* 155 */
    { { 0x6fd5fc85,0x0e4e5592,0x9d5e3741,0xcccec5e9,0xf835d025,0x3c297ade,
        0x1250825c,0x40e40ff8 },
      { 0x1953cfa2,0xd4120ecf,0x05e32613,0x295c5b64,0xee8fe373,0x0eb531c0,
        0x7ea315fc,0x5c4d2470 } },
    /* 156 */
    { { 0x918fd269,0x73543946,0x7c10b8ee,0x61cd97dd,0x5fcf9bb7,0x5f88e781,
        0x4cc5a4a7,0xce83e70e },
      { 0x7d845599,0x4891847f,0xe052a4ac,0xb1a2b373,0xf6932c5d,0x6996b90e,
        0x81227964,0x4e53f370 } },
    /* 157 */
    { { 0x55856253,0x2135b8eb,0x47b465f5,0xba19ee8b,0x1b8090ac,0x8e2b91a1,
        0x7857ed6a,0xf80bb6bf },
      { 0x73d12c59,0x0a813661,0xc74599e6,0xa75a8e11,0xcda2a2df,0xad08ee3e,
        0xc87ac463,0x70d54102 } },
    /* 158 */
    { { 0x49af46ff,0x6736584f,0x2f98bce9,0x096d00ef,0x4e133b91,0x77f01942,
        0x5f3904eb,0xd10b349e },
      { 0x80429c3b,0x96131a13,0xf0fabf71,0x479ab882,0x78a64ffe,0x40a22cde,
        0x1952c3cf,0x165920d3 } },
    /* 159 */
    { { 0xfc086dd0,0xab5f1c1a,0x12956035,0x07063e85,0xc5a58ddc,0xfe92b742,
        0x0cd4d60f,0xa58aeb14 },
      { 0xef78f77a,0x975f3323,0x66687342,0xf31f2912,0x6a031ece,0xd92b874a,
        0x554dab9a,0xf1b36156 } },
    /* 160 */
    { { 0x4396accc,0x2ce9fa74,0xf00e49e8,0xef9c4a79,0xe6694bee,0x9c32ee8d,
        0x0e8f785c,0x6fba4bbe },
      { 0x78a65c2c,0x65fa8e03,0x18cb8f40,0x7ac38e69,0x6b188e1a,0x24f743ab,
        0x56eb3ec8,0xc39006b4 } },
    /* 161 */
    { { 0x732d3604,0x519ba583,0x0b6b3459,0x9bfeb481,0x120f4fc5,0x1897d0c9,
        0x4a7b2350,0xde080cba },
      { 0xa7d2b287,0xb8bd8414,0x3f4fd647,0x8a78b72b,0x45bb0427,0xbfa1061d,
        0x75940cf8,0xe6f95dae } },
    /* 162 */
    { { 0xf0bade5d,0x1cb29b49,0x43f806b8,0x742025f6,0xbc73ee16,0x890214ea,
        0x4e9357a8,0xcbbacf13 },
      { 0xd4970cf8,0x71b32714,0x433f00da,0xec4f8e50,0x178913cd,0xa92b3b9d,
        0x630520e3,0x892fad97 } },
    /* 163 */
    { { 0x02648f13,0x5fa5194f,0x27b6be01,0x169f296c,0x5709091b,0x7971c34d,
        0x01ca703e,0xc4390edc },
      { 0xf36dac3a,0xba5e8745,0x8cd0c336,0x25a85d73,0x1fd290ae,0x25af152f,
        0xccc50dc4,0x9fa06153 } },
    /* 164 */
    { { 0x61604b75,0x4ada778c,0x9e803317,0x61e46463,0xa5819084,0xbc7f3a0a,
        0xf3616fee,0xb4f2a6ba },
      { 0x540da7f8,0x482bafb8,0xf4d6225a,0x9fd559cf,0xa1c5e50e,0xa0f1d758,
        0xe872b407,0x35c216e7 } },
    /* 165 */
    { { 0x04a1c7e2,0xace013fc,0xa946f3ff,0xc6990d5c,0x783d06ac,0x71dbec40,
        0x43eb15b4,0xe30a6d85 },
      { 0x94673fea,0xdfed7d42,0x7c17e5f0,0xf3191fb4,0xbde2e1b0,0x091f8e0b,
        0xd38b269d,0xe4ef3600 } },
    /* 166 */
    { { 0xa4f41f17,0xae114bc7,0xcfa30c21,0x9279e404,0x0f5c1e5c,0xfa5eb205,
        0xb881c925,0x18722e9f },
      { 0xbc23bf33,0xff8d7a37,0xa01c1056,0x1d5cc75d,0x879bed47,0x38b6e7ed,
        0x8eca3e56,0x1aae4f6e } },
    /* 167 */
    { { 0x690e1ed5,0x60a4895b,0x39da8dc3,0x391a0d0c,0x5f566fa4,0xfa6239a0,
        0xdd56c22d,0x5d1bd75b },
      { 0xfdab28fc,0x3024adae,0x80d52bcc,0xcb81fe0a,0xdebbfdb1,0x0b8947a6,
        0xa0b673a1,0x727d4cc2 } },
    /* 168 */
    { { 0x661e7a89,0xfa39ed48,0xffaf4d15,0xbbabf22c,0x694fb83e,0x25e4c308,
        0xabd08906,0x1082cd04 },
      { 0xdfcf1eee,0x6fa4dfce,0x7ce8427f,0xb1f0e4df,0x73533d4c,0xa6d9bcbf,
        0x973e175f,0x1cc91dfd } },
    /* 169 */
    { { 0xa0d41758,0xf8ec2fc5,0x7783739c,0xae5419e3,0xa3526559,0x1654d7dd,
        0xefd85eef,0x75dde554 },
      { 0x71da8cba,0x8760accb,0x91e56cf0,0x485d4ba1,0x81d8f13a,0x81e62034,
        0x8522fcfd,0xf4b5c1eb } },
    /* 170 */
    { { 0x50dd7082,0x4c3973ce,0x708c6f26,0x2bae6a23,0x65af6483,0x2f88f446,
        0xe21be208,0x25a78b5e },
      { 0x908c8150,0xe66c29cc,0x98fd5ffb,0x9829b616,0xadc66028,0xc04624bc,
        0x1a199b00,0x505f9561 } },
    /* 171 */
    { { 0x59dabf11,0xd523f418,0xbc4d2d5b,0x570f20ac,0xf790e997,0xd2ce247c,
        0xd574992a,0x85fa298e },
      { 0x4b273bd3,0x62eed5f3,0x765f65a5,0xfe8b6af9,0x03f38d8a,0xfb2f462a,
        0x057a67be,0x5f6122f4 } },
    /* 172 */
    { { 0x5b5100cc,0x124d731e,0x39d4313f,0x4f7860a7,0x1120c638,0x3d829330,
        0xc64e5ad0,0x0b9786d4 },
      { 0x23985e90,0xaca427c0,0xc889b882,0xdbc70c00,0x61d4f290,0xa292ff81,
        0x5b2dda0d,0x970f1f5a } },
    /* 173 */
    { { 0xfb1d91cf,0xcd1ff2c3,0x19aa012e,0x6d278412,0x229e18ee,0xc9d1cbd6,
        0xa80f4762,0xa815433e },
      { 0x8e920554,0x83ed4b4f,0xd0aa369b,0x1d3f0c45,0xf7a905b0,0x17275152,
        0x1ab9a60c,0xf1a03dd3 } },
    /* 174 */
    { { 0x48c26023,0x92c10eda,0xaf3927c8,0xb2227c50,0x68916b9d,0x1cbe20e7,
        0xa602f95a,0xcfd53e67 },
      { 0xa0130dd5,0x3cdc9993,0xe4cbe0fa,0x9bb6f3cb,0x8aa67f6e,0x4d2daa7e,
        0xa206ba18,0xf626df7e } },
    /* 175 */
    { { 0x56c08f54,0xff053d4a,0xdfd00c53,0x8cb873cb,0x8cca3d25,0xb49844d1,
        0xe113ea68,0x58257196 },
      { 0xd26f6bdf,0xa0e29282,0x66135148,0x7621dc6c,0x148a385a,0x057dbc3f,
        0x9b26e1b0,0x49badc07 } },
    /* 176 */
    { { 0xc47731af,0x353b2df7,0x7b9a1f37,0x767106a5,0x76a16fa4,0xd5fe65f7,
        0x1c39003f,0x4d65eb8d },
      { 0x0e6d9389,0x7d1702fb,0x49099879,0xbf49d246,0x4e4d0c8e,0xa84e2ff3,
        0x44f06e64,0xbdbc3773 } },
    /* 177 */
    { { 0x40209fea,0x150219e0,0x6286c965,0x56e604b3,0x48a4e72c,0xf118efad,
        0x294b0883,0xc6f889c8 },
      { 0x8e7e0c57,0xe4c8d164,0x23d600ab,0xa92c6a2a,0xfedb4278,0x24dd2751,
        0xd93e34ca,0xffd8a7e1 } },
    /* 178 */
    { { 0x160722af,0x2d2627ed,0x28bf0d0f,0x3c8b8102,0x8ec4d61c,0x6eaf4d9c,
        0x2c17f2cc,0x1b4baff5 },
      { 0xb4594092,0x4f5a3e23,0x7d829bf5,0x14b4a245,0x5a5a4222,0xfa5ee05e,
        0xec0fe001,0x03a0d850 } },
    /* 179 */
    { { 0x69ade883,0x9a31d6c6,0xd7fab9b5,0x9d49c856,0x0c61b5ac,0x578ab41a,
        0x332350de,0x7e4f2902 },
      { 0x196ac4bb,0x719bd4ed,0xafcea98d,0x71c88e05,0xac85a02c,0x5b441bbe,
        0xfa018e8e,0x4132c66d } },
    /* 180 */
    { { 0xbd80c757,0x86242d5c,0x3966b1a6,0xd3423fed,0x92e7fcf4,0x5d0ad4d6,
        0x4a79f3f0,0x545bb52a },
      { 0x2037745a,0xa1222634,0x5c9a47cc,0xb58d29fe,0x2140baad,0xccda9827,
        0x76c769a3,0x603e39d3 } },
    /* 181 */
    { { 0x67c3d4aa,0xae9a6ec3,0x08bef96f,0x444f55d1,0xd664d0a8,0x50996abe,
        0x608613aa,0xa44601dd },
      { 0xba37b00a,0x076256f9,0xea4489ca,0x9d9f730a,0x8f356781,0xe8e1af33,
        0x1b0c9ac2,0x9da72c5c } },
    /* 182 */
    { { 0x8056721f,0xa5480cd2,0xcd67f6a3,0xf8ba48e4,0xdfdbf0a9,0xc8dc6652,
        0xb7e1edac,0x3d7064af },
      { 0xa309625e,0x4454ea36,0x896c1810,0x026a0223,0x87e52615,0xe9f50011,
        0x3c3d703b,0xf7a1b253 } },
    /* 183 */
    { { 0x6194a9a7,0xf4adfac6,0xec1c3185,0x31a944e7,0x40a0ea46,0xfde9ce81,
        0xabf635c5,0x16a7b783 },
      { 0x87106be1,0xcf49d624,0xbaeedd58,0xf1108156,0x65e3b59a,0x53bfdc63,
        0xc0a7c900,0x89acded0 } },
    /* 184 */
    { { 0x9c0c7c04,0xa6eb380b,0x9f01cc9c,0x23007cac,0x285b6c6e,0xc4ddfb2f,
        0x4d2fe7ad,0xbcdc7f51 },
      { 0x4a8963d2,0x42bc6534,0x27b55dd7,0x2fa0bd5e,0xd8e79874,0x7e493fb2,
        0xc84bf937,0x17108a6c } },
    /* 185 */
    { { 0xa0ae33b0,0x8f8d2e9c,0x0e3cd053,0x403cc766,0x20587996,0xf7816585,
        0x69c8fab6,0x0f662d56 },
      { 0xd4e35be1,0xfae35eac,0x6ab0035d,0x5ff47201,0xc783bcd4,0x4cdb6ea1,
        0x5247a9d5,0x3ad2e46a } },
    /* 186 */
    { { 0x962b769b,0xf066bef1,0xba79d9f3,0x1834fec5,0xcfe70b11,0x0c3d474b,
        0x181455de,0xff3146e6 },
      { 0xe9fda5a1,0x90b4292f,0x29e22976,0x100d540c,0xaa2df711,0x041186a3,
        0xf3bc2117,0xcfd8a211 } },
    /* 187 */
    { { 0xa4e1e3f9,0xabaa164c,0x5076c4ec,0x0ffc5d4c,0x29715425,0x8d6a7646,
        0xd9ecd358,0xd50913ea },
      { 0x37f9e5ba,0xa39841d1,0xa756c925,0x6a90abfc,0x335855ad,0xd29c4f84,
        0x90bee210,0x3a8a3ffe } },
    /* 188 */
    { { 0x82775465,0x20529ea2,0x05de46b0,0x96bd3965,0x6fe0203d,0xeafdf757,
        0xb849e1dc,0x033709f7 },
      { 0x7440bc88,0xd990f262,0x562bda86,0x19fd98da,0x1b3ab664,0x6f609080,
        0xee05d54c,0xe39bc8f9 } },
    /* 189 */
    { { 0xb7fee211,0xba63d7d0,0xcc72f995,0xe5cfd677,0x3df5863d,0x5e64ab10,
        0xdc863619,0x2e6ad6bd },
      { 0xdeffbe49,0xf91e115f,0xbb1c3c09,0x154edfcd,0x0be68cfd,0x5fbc8d3b,
        0xb13bc1ec,0xdc5630bc } },
    /* 190 */
    { { 0xa9924c34,0x85f93624,0x2e11428f,0x8478bfd7,0x47f9defd,0x8149f857,
        0xf509f993,0x0610508b },
      { 0x513724ea,0x419ebe1f,0x725c8b24,0xcff020a1,0xa72bddfb,0x94f36584,
        0xbbec1038,0xaec05fd5 } },
    /* 191 */
    { { 0x9b77bf82,0xebfcb170,0xbabca0c3,0x19147831,0xdd409ac7,0x33fee22d,
        0x511f8112,0xc370cff2 },
      { 0x4151c5be,0xe023d298,0x2ef5ec6f,0xf1097e8b,0x3a09fbcb,0x7907a2bd,
        0xbbfa1899,0x7e8f0a83 } },
    /* 192 */
    { { 0xda638608,0xcc2f2cf4,0xe7b68ac0,0xb2144397,0xdb95ff63,0x7f18bf77,
        0x39846917,0xd0bf3e2a },
      { 0xa7315aff,0x4105e86e,0x2f3bf9e5,0x65a0a552,0x92351199,0x3109f61c,
        0xc464d33a,0xf0119421 } },
    /* 193 */
    { { 0x6fb23d10,0x051330e5,0x8ea63c77,0x96026edb,0xe9cbfade,0xf3541172,
        0x873c8b97,0xea56376a },
      { 0x44d8110b,0x7f40793d,0xc6beed1d,0x0779b1ec,0xf5b721c4,0x6c03806e,
        0x4203d666,0xd2827a00 } },
    /* 194 */
    { { 0x3c0f3250,0xe63eca28,0x0fa8aef9,0xb430c96d,0x68c00b3c,0xc9b9cb9f,
        0xc38645f9,0xefba8043 },
      { 0x13d1e454,0xbe5e077b,0xd2ee51af,0x994033d5,0x3c3aa41b,0x3790fdae,
        0x6458b246,0x66714c6e } },
    /* 195 */
    { { 0x924fb9f6,0x8ee9f742,0xec8a9cb8,0xac369983,0xb0a4f49b,0x04285109,
        0x4c550017,0xca5a01f0 },
      { 0x6442c569,0xc36d0e51,0x207a07e4,0xc58b3059,0x3bc85b18,0xa9755fd7,
        0xcc2190b3,0xda0e7c16 } },
    /* 196 */
    { { 0xd0bf8406,0xc1b13cf6,0x0af68e16,0x48d0f360,0x839ca656,0x1c054718,
        0x5a41a48f,0x0ae2237a },
      { 0x11f0d902,0xefdc6797,0x419ea87c,0x13ac5bd1,0x6f0677cf,0xe069d8cd,
        0x3016d453,0x42b06a0b } },
    /* 197 */
    { { 0x6f4e1f14,0xdb427c88,0x0ace79d8,0x0b5ab225,0xd8c06c52,0x6326177f,
        0x31c37cd9,0x99a08f02 },
      { 0x13aa5906,0xa81d31ab,0x4dd755b0,0x001f4759,0x9c8da586,0x8b56793f,
        0xcec64d25,0xb99c3583 } },
    /* 198 */
    { { 0x6ae869dd,0xfdd184fa,0x44d4becb,0xa3bf5ff6,0xa0bb9801,0xf1763825,
        0xfabf79ac,0xca93f5ab },
      { 0x0ab2c9c7,0xba7dfd23,0x2e90ea27,0x46430857,0x37bc97d5,0x96923173,
        0x1c2b8297,0x955dca02 } },
    /* 199 */
    { { 0xb2e176c2,0xccb8f40e,0x074758c0,0x384a64e1,0xd2422f90,0x62cc8b9b,
        0x8d32e31a,0x0462a779 },
      { 0x53aa56f7,0x683e1ec5,0x67bcf05d,0xb40bb0ba,0xb09ea3bf,0x12f21d32,
        0x9bb58b02,0x7b5c0a3c } },
    /* 200 */
    { { 0x19486bf4,0x7f6b288e,0x221d922e,0x40ba6178,0xdc3358f7,0xd1bef20d,
        0xa3730105,0xebea60f6 },
      { 0x1762e27f,0xeeb79c28,0x39fa2505,0x7659eac5,0x4487bd90,0xf495d602,
        0xff797c5b,0x7b6d4af5 } },
    /* 201 */
    { { 0xbacaa0eb,0x2202cbf8,0x796b8656,0x84547e98,0x81e01a8a,0xb66b87a9,
        0x933d78ee,0x2755125c },
      { 0xed33f8cb,0x684555d4,0xe2e677f8,0xf1de0cad,0x51a1e9ff,0x0ee5ad53,
        0xf98ad35f,0xb34315b3 } },
    /* 202 */
    { { 0x131cd75d,0x7a64eb13,0xcb0e3be2,0x91f74f35,0x2399ddf3,0xe4145003,
        0x0dffe5a0,0x371b8671 },
      { 0x682d0f80,0x769c13f4,0xa5dbd72e,0x24381abc,0xdb9a531c,0xe21a333c,
        0x73f60abd,0xaeddc99c } },
    /* 203 */
    { { 0xb5f2259c,0x5cf49e69,0x044a6413,0xb0498616,0x55d0a46e,0x510e2451,
        0x6e27da21,0xd83c7ca1 },
      { 0x635891b5,0x07bde6d2,0x9ebf3102,0xdf518788,0x8c069792,0x0a99d520,
        0xcdf92014,0x47202f65 } },
    /* 204 */
    { { 0x2f443a32,0xcdb47bff,0xd8e7a6c0,0x9023bc64,0x62a9e45d,0xf6b48ca5,
        0xfd7737dc,0x3ad3dfce },
      { 0x4b805be2,0x3782fced,0xeb1b5ad7,0x3c062ece,0x0059b736,0x3f59fe86,
        0xa36c46ae,0xf7cedd0b } },
    /* 205 */
    { { 0x433b78c5,0xbb15e367,0x9ff6a006,0xa2371907,0x15bc7d71,0x8f3d622d,
        0xfa1fc090,0x525c2ed4 },
      { 0xe68d4b0f,0x93a3073a,0x10fe1959,0xdf19b8c2,0xe47ac5a5,0x28faba36,
        0x18a7ae11,0x2da6d62b } },
    /* 206 */
    { { 0x5629d133,0xa489b3bb,0xad127129,0xf9f09b94,0x7082982e,0x53b7fedf,
        0x8d2beb9d,0xc5573373 },
      { 0x5cb75589,0x847a38e5,0x5f665eef,0xcb7bbdb0,0xae3c259b,0x641fdfc9,
        0x57705d8c,0x80e34ca1 } },
    /* 207 */
    { { 0x001ef72f,0x609c29f6,0x678789b2,0x60ffe037,0xfde15530,0x700ceefc,
        0x2aa8ac3a,0x98199469 },
      { 0x41ca3125,0xc39aa064,0xbc0c9a94,0x3e9f504e,0xff861068,0x2c613728,
        0xa442d6f3,0x5951fcb4 } },
    /* 208 */
    { { 0xb97e8fce,0x7e9b2251,0xae42fa93,0xa5d521c5,0x7a79f665,0x5c73d3e3,
        0x1e7c1843,0x929a5916 },
      { 0x2453f77a,0x308733ba,0x808bd44e,0x20191c84,0x24b263b2,0x17f9f06c,
        0x27503ac8,0xfffdcd9a } },
    /* 209 */
    { { 0xfa2e3d35,0x97845355,0x2deaba0a,0x2f9fa6fc,0xea11a38a,0x82884be4,
        0xfc779866,0x38ceee09 },
      { 0x565550ee,0x91f38305,0xc2090b67,0x037d2469,0x5bb97c29,0x612d5589,
        0x3ffce185,0x45a8c6a7 } },
    /* 210 */
    { { 0x948986b4,0x43e991af,0x22500ec1,0x0c39d148,0x9e7de923,0xd93c272b,
        0x9690f4de,0x219e1386 },
      { 0xaa62b42b,0xbc0282bc,0x84e8bc91,0x78d26196,0x478144e3,0x143930f4,
        0xcc913d8a,0x5ec12735 } },
    /* 211 */
    { { 0x92dd1b0d,0x00e8510f,0xcbc479cc,0x8fa55634,0xde583ebc,0x6585d80a,
        0xdb09af4f,0x3500e41c },
      { 0x8edc1c6b,0x79791727,0x69973edf,0xaa6de3b5,0x13ac36f2,0x03c5e9cd,
        0x6c77a697,0xc274afcc } },
    /* 212 */
    { { 0x3c423efc,0x998788ad,0xb7ff9bf0,0x22c6a751,0x8fe82e4e,0x7a11b0cd,
        0x0c8c45f9,0x7538db2b },
      { 0x56d33e22,0x964e5fa8,0xbb0e5708,0x319d22e3,0xc57dfa92,0xc67e4321,
        0xfa2e0a03,0x465b5b2e } },
    /* 213 */
    { { 0x1248e296,0xaf90b237,0xe125ba03,0xf7e7ff34,0x7b58f21a,0x673bf50e,
        0x2a5646a0,0x9613120d },
      { 0x35fa20a4,0xed2a3ec5,0x815b674f,0xffc2f510,0x0917c28c,0x217b49a8,
        0x63e90143,0x5febff8d } },
    /* 214 */
    { { 0x883048a7,0xe180bad9,0xde2fb311,0xedf0d76f,0x42f10918,0xf22f60ff,
        0x017e4056,0xd9a441c6 },
      { 0x4c2ad962,0x1b5b00eb,0x9ccf4c87,0x0e301d8e,0x45f8f97f,0x557f614d,
        0xe0f1e478,0x6cc18f2e } },
    /* 215 */
    { { 0xf78b96ab,0x48cc01d7,0xb47e0f8e,0x1ea8bdeb,0xeffb8a4b,0xadca92ff,
        0x77438be4,0xe998d32e },
      { 0xd4e6087e,0x09942eb0,0x6b241876,0x3fbc2255,0xacbc1c48,0xaa2ec237,
        0x5732e76d,0x9aecd930 } },
    /* 216 */
    { { 0x958b5d43,0x5667d9b8,0xe1eb773b,0x07bf1898,0xbf548b86,0x851a6cd8,
        0x42d6b46d,0x242d8422 },
      { 0x7b655c2f,0xd50ba08d,0xcdf7c978,0x2278910d,0x306b780f,0x9d5bfd7b,
        0x6e301873,0x6ca437e0 } },
    /* 217 */
    { { 0xf9feae4e,0xd7c265cc,0x997592a0,0xbdd4bd75,0xe86249e4,0x518ae1d2,
        0xccb06028,0x5909fa1b },
      { 0x5746eb81,0x7a2f9659,0xdc812fff,0x409d2993,0xb0abaf4f,0x031ad114,
        0xe531fc8f,0xe0a7eced } },
    /* 218 */
    { { 0x201217cc,0xdd20de76,0x553cec6e,0xc9a48c60,0xcf672846,0xbde5f1df,
        0x003693df,0x957ce106 },
      { 0x067c0809,0x02592916,0x03a61c6f,0x2bcf52dc,0x7e8aa527,0x8acdfba6,
        0xb7284b11,0xdad8f454 } },
    /* 219 */
    { { 0x6aa83bd4,0x442f3af8,0x8338a645,0x415a0e0f,0x9690dd50,0x87689c92,
        0x862826f0,0x7a127cc0 },
      { 0x93e33b5a,0x48290cb1,0xab75c410,0x124d399f,0xe0a845c4,0x1653bdac,
        0x72cec15a,0x2cd18196 } },
    /* 220 */
    { { 0x676a8a56,0x8f4023c9,0x78d282d5,0x0c90e99c,0xfc6d6b1c,0xe4bea5a6,
        0xa89ce402,0x6cf1b326 },
      { 0x1046702d,0x066b1dd2,0x252ac152,0x5fb766ca,0xd24182b6,0x6c678ab5,
        0x8b18042c,0x9fc95746 } },
    /* 221 */
    { { 0x387f9611,0x49efcb21,0x88404b43,0xff2d2507,0x1c7526c6,0x55590cd9,
        0x58e86a73,0x90a22fc3 },
      { 0x9ce2f640,0x6f7bdc00,0x04d6346a,0x92fbae71,0x907d181c,0x3bffa7bc,
        0x9268de9e,0x6b54f6c0 } },
    /* 222 */
    { { 0xf91e135d,0xf96e2d45,0x47f90eda,0x54b7f889,0xfb73b229,0x336da15d,
        0x0d211b78,0x4d971d02 },
      { 0x50ff0147,0x1974c3fc,0x86c808cc,0x1b14505c,0x6c112d67,0xce66ab02,
        0x0c0231fe,0x69fafa32 } },
    /* 223 */
    { { 0x05a94617,0x8d851956,0x0c5f7fee,0xbe07ec98,0x907711f8,0xe0ccb082,
        0x3b82b814,0xc6709cbe },
      { 0xdf8014a0,0x3da1bae0,0x0b547f76,0x3f78beb2,0x94a0cc36,0x98d0b7fd,
        0x2b2e7ce1,0xb87de651 } },
    /* 224 */
    { { 0xc3219f63,0x33a41222,0x4a847636,0x070730db,0x482146e7,0x49f5cdda,
        0x8f7e8088,0x0f3b01a2 },
      { 0x24ed5675,0xd50d3c70,0xd12ebd84,0x7e56578f,0x36e5ebd6,0xae574c6a,
        0x311490bf,0x3a6a7004 } },
    /* 225 */
    { { 0x9dc3afa7,0x94e7397e,0xf1475d2b,0x4a2bf9aa,0xbb1ad3e0,0xc8b14f38,
        0x3493e504,0x65657f7c },
      { 0x4162798f,0x3342a58d,0x47f1f764,0x446a208f,0x3c10275a,0x11795deb,
        0x270c97a0,0x62e54572 } },
    /* 226 */
    { { 0x3fd3001a,0x199537c0,0x95687faa,0x292d8736,0x0ed75bf6,0x63e19958,
        0x37bbe563,0xfad9dbb0 },
      { 0x6330d6f7,0x8a324881,0x7ac23a2c,0x03b5f10a,0xbc4e295d,0x3a939dbc,
        0xb1b12f19,0xa3e6119a } },
    /* 227 */
    { { 0xb42823a4,0xfb67cecd,0x73f43db3,0x26ecf068,0x52f1c5fa,0xfb86e108,
        0xb8185042,0x74ba5c89 },
      { 0x8c74b8af,0xa5f58428,0xa1dbf80a,0x33716f67,0x223854cb,0x172190af,
        0x676ccaca,0xbffbbbc4 } },
    /* 228 */
    { { 0xe28b90c5,0xf662064e,0xf79d0be9,0x563d7e97,0x56becae0,0x34330aca,
        0xb6b1e3de,0x7c64d2be },
      { 0x31b53678,0x8dc53abe,0x650da609,0x34608a9f,0x16f66c18,0x4f1b089c,
        0xbf5c6c4f,0xd0a9d4ca } },
    /* 229 */
    { { 0x8dd922a9,0x1f631e85,0x8691bd15,0xa5394eac,0xc8860f68,0xd77571b3,
        0xe7d234bd,0x06bad558 },
      { 0x69d6c786,0x29962727,0x1dd44649,0x5f02f385,0xb0303874,0xf0b87128,
        0x260f67db,0x1184eb38 } },
    /* 230 */
    { { 0xf646a2d8,0x4fbc2176,0xfcaf9f98,0xb59a9d2d,0xe398fd97,0x63d4394b,
        0x94480bdd,0x026ff9bc },
      { 0xb25eb68f,0x31cb2a85,0x1ed33abc,0x3700d8ab,0xcc504287,0x653c3e89,
        0xf1f78624,0xf81ba865 } },
    /* 231 */
    { { 0xec2b7ab7,0x19aeb2d4,0x5a60f91e,0xfae73e76,0xe7a33ad4,0x59ebf10d,
        0xdfaf022d,0x731217a1 },
      { 0x3e5c73d5,0x44feb342,0x12420333,0x7b46a628,0xca063263,0x8dbf2725,
        0x9ceee3a8,0x2f19658b } },
    /* 232 */
    { { 0xee1aa4ef,0x1b0eeb8b,0x53f8bc25,0x881f09db,0xebe31aa5,0xde19ed0f,
        0xb421079e,0xc1205040 },
      { 0x7f9fbb19,0x6abe613d,0x4c02f1ae,0x480eb33f,0xbc78a4aa,0x98272198,
        0x0060c59f,0x73bd74b9 } },
    /* 233 */
    { { 0xb7f909a1,0x26f7d0f0,0x7e4c5a48,0xffc76b17,0x88442ea1,0x793ea04b,
        0x3936ad3b,0xe389c45d },
      { 0x843ffd3c,0xcef076b6,0x43e56892,0x364ac1ec,0xdad106e5,0xbfc58bb0,
        0x64b886ac,0xaed22ac2 } },
    /* 234 */
    { { 0x869ae3dd,0xe31334cc,0x98110bae,0x52b64143,0xbb8dd6cc,0x256fe087,
        0x519dd12c,0x29f73d4c },
      { 0xe2b5be53,0x3fece3d3,0xbd5f8344,0x55687bee,0x010be101,0x257f6456,
        0xb9ab6eff,0x38390f01 } },
    /* 235 */
    { { 0x0cdf4b26,0xd67ae41b,0x7e774fa6,0x84236c0a,0x95d979c5,0xbbdc69a0,
        0x3605d2dc,0xd5bc7358 },
      { 0x79a77475,0xde384dd3,0x02a480f7,0x9f094f5a,0x0beeea56,0x2e77bf03,
        0x865158ba,0xa6a6adcb } },
    /* 236 */
    { { 0x155cbb33,0xd7d7c70d,0x9ea44142,0x47823ae6,0xdc91a3d7,0x47e9c5ad,
        0x75312c3a,0x5ce9047c },
      { 0x14696568,0x70e98cc5,0x641ab644,0x9a2efc99,0x21dafe31,0x47efa05a,
        0x5ac5b71f,0x2cefaab2 } },
    /* 237 */
    { { 0x7bccf3ca,0xb12db204,0x77e8fa88,0x15dfed52,0x824a58ae,0xe981a650,
        0xb8628bc9,0xe47a22d5 },
      { 0x688432d8,0xb7965f01,0xedacb523,0xcc3015bb,0x8a53ba8e,0x4d8c847e,
        0xbeea6f3b,0x19601827 } },
    /* 238 */
    { { 0x1feb5071,0xfff32328,0xf54a0cf7,0xd16cd02d,0x138f89bf,0xeb6f98ed,
        0x7ff7d3b8,0x53164715 },
      { 0xc992b998,0x01d104ef,0x3b19571e,0x5a7c4cb2,0x5b93dc12,0xa872e737,
        0x74954891,0x22e7a9db } },
    /* 239 */
    { { 0x0283ccdf,0x9f6198e8,0xf78cd2c6,0x8b0eaeb9,0x78604294,0x0d9fecea,
        0xe9b26934,0xd0ac75fe },
      { 0x36fdf44f,0xba2ccb4a,0x90828426,0x828b5123,0x631013ac,0x1b76b83c,
        0x69874176,0xf8d1bf63 } },
    /* 240 */
    { { 0x33c6d17c,0x1e601505,0x0c76fbcb,0xec3d5b60,0x00604f65,0x23ebbee1,
        0x5644050b,0x12959cbc },
      { 0xf023a933,0xea58df49,0x920421e2,0x58b9cc89,0xc0979200,0xf2b13f1b,
        0x9af1622a,0x1aac8e32 } },
    /* 241 */
    { { 0x54e44471,0x56d3c867,0xd60f959e,0x16cfa79c,0x3800aa6d,0xe1a0a9b3,
        0x63cf5cb5,0x03478573 },
      { 0x281c0625,0x5d93f256,0xc6e710c4,0x4eda2ed5,0x1fa7caf8,0x76d99846,
        0x1b6c2e3b,0x5fbd4e1b } },
    /* 242 */
    { { 0x2628bd27,0xdeee9c0e,0x6f8d8926,0x5ed1edc9,0xba6c6702,0x4bbc7968,
        0xc47b97e8,0x71c11b59 },
      { 0xd93fdd98,0x269af35c,0xad98d80f,0x250f63e7,0x4a878b4d,0x9640ec91,
        0x05eb0c5d,0xd994d23b } },
    /* 243 */
    { { 0xe2eb6f86,0x0349852c,0xaff1aad5,0xb7e3620f,0xb9a9359d,0x0f8a633c,
        0x0b99e076,0xc89a7027 },
      { 0x6661ebad,0x18555323,0xda88f0ba,0x85ec6e68,0xdb0f4d37,0xa8542f32,
        0x82ee8616,0x04e03ee0 } },
    /* 244 */
    { { 0x86460df0,0xaa463c26,0xefd5e793,0x08b775cf,0x8409d3d9,0x14e17975,
        0x737a958d,0xe68e9468 },
      { 0xca015c8b,0x6519e649,0xa35c7b2a,0xd6310f75,0xcab343f8,0xf1faec99,
        0x32f77af7,0x1b23979c } },
    /* 245 */
    { { 0x2b5e0c0c,0x3526d420,0x528c897f,0x99db2bd9,0x26bfcd02,0xb64d880d,
        0xef2ecd27,0xdd78c263 },
      { 0x95822826,0xa0b35078,0xacf21c03,0x5ea1c0e5,0xdbe7e601,0x3d5b1d01,
        0x8d9215b4,0x139c073f } },
    /* 246 */
    { { 0x670e8ca9,0xbd9222c7,0xa4b03512,0x381bd976,0x6946fc83,0x9c5d3aca,
        0xa6f3316d,0x5a13dc71 },
      { 0x0f25e97b,0xbcbf2364,0x6fe55b35,0xdd741a0b,0x85cdaace,0x748a7707,
        0x77211b82,0x02d9d814 } },
    /* 247 */
    { { 0x83eca061,0x766514ee,0xca7faa4c,0x38df097c,0xc850fc7d,0x88886165,
        0x7c80986b,0x5f4fcb7a },
      { 0xc8612b88,0x58c498cb,0xd0029d39,0xa26ed74a,0x11118e41,0xed010aa4,
        0x0808e5f4,0x01239ca9 } },
    /* 248 */
    { { 0x771f2025,0x8b41551b,0x1dad7187,0x8931e6f0,0x84d1d187,0x633b0ba5,
        0x1fb4ec83,0x80176026 },
      { 0xa3fed11f,0x0a1740c3,0x0e31c6ca,0x49dcada1,0xd1079e1b,0xb96f0bd6,
        0x5035edf5,0xd325b1ba } },
    /* 249 */
    { { 0x45614b0c,0x9ecca10c,0x0f520a05,0x65d4b71b,0x496af3b3,0xc875ce5b,
        0x089ec25b,0x1993daac },
      { 0x9b44405f,0x6c27531e,0xe8327055,0x7166a016,0x66a45d43,0xba7ed055,
        0x3d3531a0,0x1da832bb } },
    /* 250 */
    { { 0xb92d1d40,0x8b4e0e7a,0x2c66c63b,0x8692417a,0x8735ec72,0xcf340c58,
        0xb5f78949,0xb5856961 },
      { 0xb1715164,0xd10a0b91,0xbd2dabfa,0x864c17c7,0xa94db101,0x480dd9f7,
        0x8f038493,0xa7dff882 } },
    /* 251 */
    { { 0xedf73f04,0xd39c5bbd,0x724545d9,0x3a8fea08,0x74f7306a,0xca683587,
        0xb97ef241,0x7094aeb4 },
      { 0xd72ebf79,0x06623559,0xfa95a003,0xde24a91d,0xa716a892,0x34e73d4e,
        0xddc9453f,0xf0477a2c } },
    /* 252 */
    { { 0x1fb80211,0xa032471c,0x629f78ed,0x47c322b5,0xb4d34838,0x92a62b56,
        0x8e88c984,0x2400e424 },
      { 0xd3dbc9d8,0xaf924289,0x74a08df6,0x257c14a6,0x6a095105,0x95902016,
        0x8bfdd383,0xf5ac5452 } },
    /* 253 */
    { { 0x42980d58,0xfb37e5ba,0x75657f91,0x2c031e61,0x4483bd4d,0xf9e45e92,
        0x64132fbb,0x43b13ea6 },
      { 0xd6665e37,0xddf081a4,0xa715ddd6,0x93f75def,0x2b039528,0x4c76d8fa,
        0x839aeab0,0x4ee3a221 } },
    /* 254 */
    { { 0x3a6ef7ba,0x97ff049d,0xf217b134,0xbcc779d5,0x850cc2ab,0xea153370,
        0xea78cbef,0x93967c32 },
      { 0xc18605ea,0xdb72faa2,0x5e16939c,0xddee2f6f,0xeae0e4f8,0xf53bf342,
        0xfddc580f,0x14e25972 } },
    /* 255 */
    { { 0x950d7f94,0x0854dcd8,0x3ea3b4d6,0x07006a66,0xdf8b5b2f,0xa91fa63f,
        0x060c2f4a,0xaad30b11 },
      { 0x4254ba5d,0x1a30c016,0xc5847aea,0x31450eaa,0xd49eab3c,0x41c6740c,
        0xb97d5888,0xbcc984ef } },
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
static int sp_256_ecc_mulmod_base_sm2_8(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_8(r, &p256_sm2_base, p256_sm2_table,
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
    sp_digit k[8];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    point = (sp_point_256*)XMALLOC(sizeof(sp_point_256), heap,
                                         DYNAMIC_TYPE_ECC);
    if (point == NULL)
        err = MEMORY_E;
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 8, km);

            err = sp_256_ecc_mulmod_base_sm2_8(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_8(point, r);
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
    sp_digit k[8 + 8 * 2 * 6];
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
            sizeof(sp_digit) * (8 + 8 * 2 * 6),
            heap, DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        addP = point + 1;
        tmp = k + 8;

        sp_256_from_mp(k, 8, km);
        sp_256_point_from_ecc_point_8(addP, am);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_8(addP->x, addP->x, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_8(addP->y, addP->y, p256_sm2_mod);
    }
    if ((err == MP_OKAY) && (!inMont)) {
        err = sp_256_mod_mul_norm_sm2_8(addP->z, addP->z, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_8(point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_8(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_8(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_8(point, r);
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
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_add_one_sm2_8(sp_digit* a)
{
    __asm__ __volatile__ (
        "movs	r2, #1\n\t"
        "ldr	r1, [%[a]]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r1, r1, r2\n\t"
#else
        "add	r1, r1, r2\n\t"
#endif
        "movs	r2, #0\n\t"
        "str	r1, [%[a]]\n\t"
        "ldr	r1, [%[a], #4]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #4]\n\t"
        "ldr	r1, [%[a], #8]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #8]\n\t"
        "ldr	r1, [%[a], #12]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #12]\n\t"
        "ldr	r1, [%[a], #16]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #16]\n\t"
        "ldr	r1, [%[a], #20]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #20]\n\t"
        "ldr	r1, [%[a], #24]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #24]\n\t"
        "ldr	r1, [%[a], #28]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r1, r1, r2\n\t"
#elif defined(__clang__)
        "adcs	r1, r2\n\t"
#else
        "adc	r1, r2\n\t"
#endif
        "str	r1, [%[a], #28]\n\t"
        : [a] "+l" (a)
        :
        : "memory", "r1", "r2", "cc"
    );
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
    int j;
    byte* d;

    for (i = n - 1,j = 0; i >= 3; i -= 4) {
        r[j]  = ((sp_digit)a[i - 0] <<  0) |
                ((sp_digit)a[i - 1] <<  8) |
                ((sp_digit)a[i - 2] << 16) |
                ((sp_digit)a[i - 3] << 24);
        j++;
    }

    if (i >= 0) {
        r[j] = 0;

        d = (byte*)r;
        switch (i) {
            case 2: d[n - 1 - 2] = a[2]; //fallthrough
            case 1: d[n - 1 - 1] = a[1]; //fallthrough
            case 0: d[n - 1 - 0] = a[0]; //fallthrough
        }
        j++;
    }

    for (; j < size; j++) {
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
static int sp_256_ecc_gen_k_sm2_8(WC_RNG* rng, sp_digit* k)
{
#ifndef WC_NO_RNG
    int err;
    byte buf[32];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_256_from_bin(k, 8, buf, (int)sizeof(buf));
            if (sp_256_cmp_sm2_8(k, p256_sm2_order2) <= 0) {
                sp_256_add_one_sm2_8(k);
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
    sp_digit k[8];
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
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
        infinity = point + 1;
    #endif

        err = sp_256_ecc_gen_k_sm2_8(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_8(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_8(infinity, point, p256_sm2_order, 1, 1, NULL);
    }
    if (err == MP_OKAY) {
        if (sp_256_iszero_8(point->x) || sp_256_iszero_8(point->y)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_256_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_8(point, pub);
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
    sp_256_ecc_mulmod_8_ctx mulmod_ctx;
    sp_digit k[8];
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
            err = sp_256_ecc_gen_k_8(rng, ctx->k);
            if (err == MP_OKAY) {
                err = FP_WOULDBLOCK;
                ctx->state = 1;
            }
            break;
        case 1:
            err = sp_256_ecc_mulmod_base_8_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
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
            err = sp_256_ecc_mulmod_8_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      infinity, ctx->point, p256_sm2_order, 1, 1);
            if (err == MP_OKAY) {
                if (sp_256_iszero_8(ctx->point->x) ||
                    sp_256_iszero_8(ctx->point->y)) {
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
                err = sp_256_point_to_ecc_point_8(ctx->point, pub);
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
static void sp_256_to_bin_8(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 7; i >= 0; i--) {
        a[j++] = r[i] >> 24;
        a[j++] = r[i] >> 16;
        a[j++] = r[i] >> 8;
        a[j++] = r[i] >> 0;
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
    sp_digit k[8];
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
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8, heap,
                               DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 8, priv);
        sp_256_point_from_ecc_point_8(point, pub);
            err = sp_256_ecc_mulmod_sm2_8(point, point, k, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_256_to_bin_8(point->x, out);
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
        sp_256_ecc_mulmod_8_ctx mulmod_ctx;
    };
    sp_digit k[8];
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
            sp_256_from_mp(ctx->k, 8, priv);
            sp_256_point_from_ecc_point_8(&ctx->point, pub);
            ctx->state = 1;
            break;
        case 1:
            err = sp_256_ecc_mulmod_sm2_8_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
                      &ctx->point, &ctx->point, ctx->k, 1, 1, heap);
            if (err == MP_OKAY) {
                sp_256_to_bin_8(ctx->point.x, out);
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
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_256_sub_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "movs	r6, %[a]\n\t"
        "movs	r3, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r6, r6, #32\n\t"
#else
        "add	r6, r6, #32\n\t"
#endif
        "\n"
    "L_sp_256_sub_sm2_8_word_%=:\n\t"
        "movs	r5, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, r3\n\t"
#else
        "sub	r5, r5, r3\n\t"
#endif
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r5\n\t"
#elif defined(__clang__)
        "sbcs	r4, r5\n\t"
#else
        "sbc	r4, r5\n\t"
#endif
        "str	r4, [%[r]]\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r3\n\t"
#elif defined(__clang__)
        "sbcs	r3, r3\n\t"
#else
        "sbc	r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[a], %[a], #4\n\t"
#else
        "add	%[a], %[a], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[b], %[b], #4\n\t"
#else
        "add	%[b], %[b], #4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	%[r], %[r], #4\n\t"
#else
        "add	%[r], %[r], #4\n\t"
#endif
        "cmp	%[a], r6\n\t"
        "bne	L_sp_256_sub_sm2_8_word_%=\n\t"
        "movs	%[r], r3\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "cc"
    );
    return (uint32_t)(size_t)r;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_256_sub_sm2_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r3, r3, r5\n\t"
#else
        "sub	r3, r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "ldm	%[a]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	r3, r3, r5\n\t"
#elif defined(__clang__)
        "sbcs	r3, r5\n\t"
#else
        "sbc	r3, r5\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs	r4, r4, r6\n\t"
#elif defined(__clang__)
        "sbcs	r4, r6\n\t"
#else
        "sbc	r4, r6\n\t"
#endif
        "stm	%[r]!, {r3, r4}\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs	%[r], %[r], %[r]\n\t"
#elif defined(__clang__)
        "sbcs	%[r], %[r]\n\t"
#else
        "sbc	%[r], %[r]\n\t"
#endif
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "cc"
    );
    return (uint32_t)(size_t)r;
}

#endif /* WOLFSSL_SP_SMALL */
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
SP_NOINLINE static sp_digit sp_256_cond_add_sm2_8(sp_digit* r,
        const sp_digit* a, const sp_digit* b, sp_digit m)
{
    __asm__ __volatile__ (
        "movs	r4, #0\n\t"
        "movs	r5, #32\n\t"
        "mov	r8, r5\n\t"
        "movs	r7, #0\n\t"
        "\n"
    "L_sp_256_cond_add_sm2_8_words_%=:\n\t"
        "ldr	r6, [%[b], r7]\n\t"
#ifdef WOLFSSL_KEIL
        "ands	r6, r6, %[m]\n\t"
#elif defined(__clang__)
        "ands	r6, %[m]\n\t"
#else
        "and	r6, %[m]\n\t"
#endif
        "movs	r5, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r5, r5, #1\n\t"
#else
        "sub	r5, r5, #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r5, r5, r4\n\t"
#else
        "add	r5, r5, r4\n\t"
#endif
        "ldr	r5, [%[a], r7]\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs	r5, r6\n\t"
#else
        "adc	r5, r6\n\t"
#endif
        "movs	r4, #0\n\t"
#ifdef WOLFSSL_KEIL
        "adcs	r4, r4, r4\n\t"
#elif defined(__clang__)
        "adcs	r4, r4\n\t"
#else
        "adc	r4, r4\n\t"
#endif
        "str	r5, [%[r], r7]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds	r7, r7, #4\n\t"
#else
        "add	r7, r7, #4\n\t"
#endif
        "cmp	r7, r8\n\t"
        "blt	L_sp_256_cond_add_sm2_8_words_%=\n\t"
        "movs	%[r], r4\n\t"
        : [r] "+l" (r), [a] "+l" (a), [b] "+l" (b), [m] "+l" (m)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "cc"
    );
    return (uint32_t)(size_t)r;
}

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
static void sp_256_mont_mul_order_sm2_8(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_sm2_8(r, a, b);
    sp_256_mont_reduce_order_sm2_8(r, p256_sm2_order, p256_sm2_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_order_sm2_8(sp_digit* r, const sp_digit* a)
{
    sp_256_sqr_sm2_8(r, a);
    sp_256_mont_reduce_order_sm2_8(r, p256_sm2_order, p256_sm2_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P256 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_n_order_sm2_8(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_256_mont_sqr_order_sm2_8(r, a);
    for (i=1; i<n; i++) {
        sp_256_mont_sqr_order_sm2_8(r, r);
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
static void sp_256_mont_inv_order_sm2_8(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 8);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_order_sm2_8(t, t);
        if ((p256_sm2_order_minus_2[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_8(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 8U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 8;
    sp_digit* t3 = td + 4 * 8;
    sp_digit* t4 = td + 6 * 8;
    int i;

    /* t4= a^2 */
    sp_256_mont_sqr_order_sm2_8(t4, a);
    /* t = a^3 = t4* a */
    sp_256_mont_mul_order_sm2_8(t, t4, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_order_sm2_8(t2, t, 2);
    /* t4= a^e = t2 * t4 */
    sp_256_mont_mul_order_sm2_8(t4, t2, t4);
    /* t3= a^f = t2 * t */
    sp_256_mont_mul_order_sm2_8(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_256_mont_sqr_n_order_sm2_8(t2, t3, 4);
    /* t4 = a^fe = t2 * t4 */
    sp_256_mont_mul_order_sm2_8(t4, t2, t4);
    /* t = a^ff = t2 * t3 */
    sp_256_mont_mul_order_sm2_8(t, t2, t3);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_order_sm2_8(t2, t, 8);
    /* t4 = a^fffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_8(t4, t2, t4);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_order_sm2_8(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_order_sm2_8(t2, t, 16);
    /* t4= a^fffffffe = t2 * t4 */
    sp_256_mont_mul_order_sm2_8(t4, t2, t4);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_8(t, t2, t);
    /* t2= a^fffffffe00000000 = t4 ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_8(t4, t4, 32);
    /* t4= a^fffffffeffffffff = t4 * t */
    sp_256_mont_mul_order_sm2_8(t4, t4, t);
    /* t2= a^ffffffff00000000 = t ^ 2 ^ 32 */
    sp_256_mont_sqr_n_order_sm2_8(t2, t, 32);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_256_mont_mul_order_sm2_8(t, t2, t);
    /* t4= a^fffffffeffffffff0000000000000000 = t4 ^ 2 ^ 64 */
    sp_256_mont_sqr_n_order_sm2_8(t4, t4, 64);
    /* t2= a^fffffffeffffffffffffffffffffffff = t4 * t2 */
    sp_256_mont_mul_order_sm2_8(t2, t4, t);
    /* t2= a^fffffffeffffffffffffffffffffffff7203d */
    for (i=127; i>=108; i--) {
        sp_256_mont_sqr_order_sm2_8(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_8(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df */
    sp_256_mont_sqr_n_order_sm2_8(t2, t2, 4);
    sp_256_mont_mul_order_sm2_8(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bb */
    for (i=103; i>=48; i--) {
        sp_256_mont_sqr_order_sm2_8(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_8(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf */
    sp_256_mont_sqr_n_order_sm2_8(t2, t2, 4);
    sp_256_mont_mul_order_sm2_8(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412 */
    for (i=43; i>=4; i--) {
        sp_256_mont_sqr_order_sm2_8(t2, t2);
        if (((sp_digit)p256_sm2_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_256_mont_mul_order_sm2_8(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54120 */
    sp_256_mont_sqr_n_order_sm2_8(t2, t2, 4);
    /* r = a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121 */
    sp_256_mont_mul_order_sm2_8(r, t2, a);
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
    sp_digit d[4 * 10*8];
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
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8 * 2 * 8, heap,
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
        e = d + 0 * 8;
        x = d + 2 * 8;
        k = d + 4 * 8;
        r = d + 6 * 8;
        tmp = d + 8 * 8;
        s = e;
        xInv = x;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_bin(e, 8, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_256_from_mp(x, 8, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_256_ecc_gen_k_sm2_8(rng, k);
        }
        else {
            sp_256_from_mp(k, 8, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
                err = sp_256_ecc_mulmod_base_sm2_8(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = (point->x + e) mod order */
            c = sp_256_add_sm2_8(r, point->x, e);
            sp_256_cond_sub_sm2_8(r, r, p256_sm2_order, 0L - (sp_digit)c);
            c = sp_256_cmp_sm2_8(r, p256_sm2_order);
            sp_256_cond_sub_sm2_8(r, r, p256_sm2_order, 0L - (sp_digit)(c >= 0));

            /* Try again if r == 0 */
            if (sp_256_iszero_8(r)) {
                continue;
            }

            /* Try again if r + k == 0 */
            c = sp_256_add_sm2_8(s, k, r);
            sp_256_cond_sub_sm2_8(s, s, p256_sm2_order, 0L - (sp_digit)c);
            c = sp_256_cmp_sm2_8(s, p256_sm2_order);
            sp_256_cond_sub_sm2_8(s, s, p256_sm2_order, 0L - (sp_digit)(c >= 0));
            if (sp_256_iszero_8(s)) {
                continue;
            }

            /* Conv x to Montgomery form (mod order) */
                sp_256_mul_sm2_8(x, x, p256_sm2_norm_order);
            err = sp_256_mod_sm2_8(x, x, p256_sm2_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_8(x);

            /* s = k - r * x */
                sp_256_mont_mul_order_sm2_8(s, x, r);
        }
        if (err == MP_OKAY) {
            sp_256_norm_8(s);
            c = sp_256_sub_sm2_8(s, k, s);
            sp_256_cond_add_sm2_8(s, s, p256_sm2_order, c);
            sp_256_norm_8(s);

            /* xInv = 1/(x+1) mod order */
            sp_256_add_sm2_8(x, x, p256_sm2_norm_order);

                sp_256_mont_inv_order_sm2_8(xInv, x, tmp);
            sp_256_norm_8(xInv);

            /* s = s * (x+1)^-1 mod order */
                sp_256_mont_mul_order_sm2_8(s, s, xInv);
            sp_256_norm_8(s);

            c = sp_256_cmp_sm2_8(s, p256_sm2_order);
            sp_256_cond_sub_sm2_8(s, s, p256_sm2_order,
                0L - (sp_digit)(c >= 0));
            sp_256_norm_8(s);

            /* Check that signature is usable. */
            if (sp_256_iszero_8(s) == 0) {
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
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 8);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
    if (point != NULL) {
        XFREE(point, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 8U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 8U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 8U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 8U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 8U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 4U * 2U * 8U);
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
    sp_digit d[8*8 * 7];
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
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 20 * 8, heap,
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
        e   = d + 0 * 8;
        r   = d + 2 * 8;
        s   = d + 4 * 8;
        tmp = d + 6 * 8;
        p2 = p1 + 1;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_mp(r, 8, rm);
        sp_256_from_mp(s, 8, sm);
        sp_256_from_mp(p2->x, 8, pX);
        sp_256_from_mp(p2->y, 8, pY);
        sp_256_from_mp(p2->z, 8, pZ);


        if (sp_256_iszero_8(r) ||
            sp_256_iszero_8(s) ||
            (sp_256_cmp_sm2_8(r, p256_sm2_order) >= 0) ||
            (sp_256_cmp_sm2_8(s, p256_sm2_order) >= 0)) {
            *res = 0;
            done = 1;
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        carry = sp_256_add_sm2_8(e, r, s);
        sp_256_norm_8(e);
        if (carry || sp_256_cmp_sm2_8(e, p256_sm2_order) >= 0) {
            sp_256_sub_sm2_8(e, e, p256_sm2_order);            sp_256_norm_8(e);
        }

        if (sp_256_iszero_8(e)) {
           *res = 0;
           done = 1;
        }
    }
    if ((err == MP_OKAY) && (!done)) {
            err = sp_256_ecc_mulmod_base_sm2_8(p1, s, 0, 0, heap);
    }
    if ((err == MP_OKAY) && (!done)) {
        {
            err = sp_256_ecc_mulmod_sm2_8(p2, p2, e, 0, 0, heap);
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        {
            sp_256_proj_point_add_sm2_8(p1, p1, p2, tmp);
            if (sp_256_iszero_8(p1->z)) {
                if (sp_256_iszero_8(p1->x) && sp_256_iszero_8(p1->y)) {
                    sp_256_proj_point_dbl_sm2_8(p1, p2, tmp);
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
                    XMEMCPY(p1->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
                }
            }
        }

        /* z' = z'.z' */
        sp_256_mont_sqr_sm2_8(p1->z, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        XMEMSET(p1->x + 8, 0, 8U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_8(p1->x, p256_sm2_mod, p256_sm2_mp_mod);
        /* (r - e + n*order).z'.z' mod prime == (s.G + t.Q)->x' */
        /* Load e, subtract from r. */
        sp_256_from_bin(e, 8, hash, (int)hashLen);
        if (sp_256_cmp_sm2_8(r, e) < 0) {
            (void)sp_256_add_sm2_8(r, r, p256_sm2_order);
        }
        sp_256_sub_sm2_8(e, r, e);
        sp_256_norm_8(e);
        /* x' == (r - e).z'.z' mod prime */
        sp_256_mont_mul_sm2_8(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
        *res = (int)(sp_256_cmp_sm2_8(p1->x, s) == 0);
        if (*res == 0) {
            carry = sp_256_add_sm2_8(e, e, p256_sm2_order);
            if (!carry && sp_256_cmp_sm2_8(e, p256_sm2_mod) < 0) {
                /* x' == (r - e + order).z'.z' mod prime */
                sp_256_mont_mul_sm2_8(s, e, p1->z, p256_sm2_mod, p256_sm2_mp_mod);
                *res = (int)(sp_256_cmp_sm2_8(p1->x, s) == 0);
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
static int sp_256_ecc_is_point_sm2_8(const sp_point_256* point,
    void* heap)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t1 = NULL;
#else
    sp_digit t1[8 * 4];
#endif
    sp_digit* t2 = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t1 = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8 * 4, heap, DYNAMIC_TYPE_ECC);
    if (t1 == NULL)
        err = MEMORY_E;
#endif
    (void)heap;

    if (err == MP_OKAY) {
        t2 = t1 + 2 * 8;

        /* y^2 - x^3 - a.x = b */
        sp_256_sqr_sm2_8(t1, point->y);
        (void)sp_256_mod_sm2_8(t1, t1, p256_sm2_mod);
        sp_256_sqr_sm2_8(t2, point->x);
        (void)sp_256_mod_sm2_8(t2, t2, p256_sm2_mod);
        sp_256_mul_sm2_8(t2, t2, point->x);
        (void)sp_256_mod_sm2_8(t2, t2, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(t1, t1, t2, p256_sm2_mod);

        /* y^2 - x^3 + 3.x = b, when a = -3  */
        sp_256_mont_add_sm2_8(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_8(t1, t1, point->x, p256_sm2_mod);
        sp_256_mont_add_sm2_8(t1, t1, point->x, p256_sm2_mod);


        if (sp_256_cmp_sm2_8(t1, p256_sm2_b) != 0) {
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
        sp_256_from_mp(pub->x, 8, pX);
        sp_256_from_mp(pub->y, 8, pY);
        sp_256_from_bin(pub->z, 8, one, (int)sizeof(one));

        err = sp_256_ecc_is_point_sm2_8(pub, NULL);
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
    sp_digit priv[8];
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
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 8, heap,
                                  DYNAMIC_TYPE_ECC);
        if (priv == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        p = pub + 1;

        sp_256_from_mp(pub->x, 8, pX);
        sp_256_from_mp(pub->y, 8, pY);
        sp_256_from_bin(pub->z, 8, one, (int)sizeof(one));
        if (privm)
            sp_256_from_mp(priv, 8, privm);

        /* Check point at infinitiy. */
        if ((sp_256_iszero_8(pub->x) != 0) &&
            (sp_256_iszero_8(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    /* Check range of X and Y */
    if ((err == MP_OKAY) &&
            ((sp_256_cmp_sm2_8(pub->x, p256_sm2_mod) >= 0) ||
             (sp_256_cmp_sm2_8(pub->y, p256_sm2_mod) >= 0))) {
        err = ECC_OUT_OF_RANGE_E;
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_256_ecc_is_point_sm2_8(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
            err = sp_256_ecc_mulmod_sm2_8(p, pub, p256_sm2_order, 1, 1, heap);
    }
    /* Check result is infinity */
    if ((err == MP_OKAY) && ((sp_256_iszero_8(p->x) == 0) ||
                             (sp_256_iszero_8(p->y) == 0))) {
        err = ECC_INF_E;
    }

    if (privm) {
        if (err == MP_OKAY) {
            /* Base * private = point */
                err = sp_256_ecc_mulmod_base_sm2_8(p, priv, 1, 1, heap);
        }
        /* Check result is public key */
        if ((err == MP_OKAY) &&
                ((sp_256_cmp_sm2_8(p->x, pub->x) != 0) ||
                 (sp_256_cmp_sm2_8(p->y, pub->y) != 0))) {
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
    sp_digit tmp[2 * 8 * 6];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 6, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        q = p + 1;

        sp_256_from_mp(p->x, 8, pX);
        sp_256_from_mp(p->y, 8, pY);
        sp_256_from_mp(p->z, 8, pZ);
        sp_256_from_mp(q->x, 8, qX);
        sp_256_from_mp(q->y, 8, qY);
        sp_256_from_mp(q->z, 8, qZ);
        p->infinity = sp_256_iszero_8(p->x) &
                      sp_256_iszero_8(p->y);
        q->infinity = sp_256_iszero_8(q->x) &
                      sp_256_iszero_8(q->y);

            sp_256_proj_point_add_sm2_8(p, p, q, tmp);
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
    sp_digit tmp[2 * 8 * 2];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 2, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 8, pX);
        sp_256_from_mp(p->y, 8, pY);
        sp_256_from_mp(p->z, 8, pZ);
        p->infinity = sp_256_iszero_8(p->x) &
                      sp_256_iszero_8(p->y);

            sp_256_proj_point_dbl_sm2_8(p, p, tmp);
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
    sp_digit tmp[2 * 8 * 5];
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
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8 * 5, NULL,
                                 DYNAMIC_TYPE_ECC);
        if (tmp == NULL)
            err = MEMORY_E;
    }
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 8, pX);
        sp_256_from_mp(p->y, 8, pY);
        sp_256_from_mp(p->z, 8, pZ);
        p->infinity = sp_256_iszero_8(p->x) &
                      sp_256_iszero_8(p->y);

            sp_256_map_sm2_8(p, p, tmp);
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
static int sp_256_mont_sqrt_sm2_8(sp_digit* y)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t = NULL;
#else
    sp_digit t[2 * 8];
#endif
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 8, NULL, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {

        {
            int i;

            XMEMCPY(t, y, sizeof(sp_digit) * 8);
            for (i=252; i>=0; i--) {
                sp_256_mont_sqr_sm2_8(t, t, p256_sm2_mod, p256_sm2_mp_mod);
                if (p256_sm2_sqrt_power[i / 32] & ((sp_digit)1 << (i % 32)))
                    sp_256_mont_mul_sm2_8(t, t, y, p256_sm2_mod, p256_sm2_mp_mod);
            }
            XMEMCPY(y, t, sizeof(sp_digit) * 8);
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
    sp_digit x[4 * 8];
#endif
    sp_digit* y = NULL;
    int err = MP_OKAY;

#ifdef WOLFSSL_SP_SMALL_STACK
    x = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 8, NULL, DYNAMIC_TYPE_ECC);
    if (x == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        y = x + 2 * 8;

        sp_256_from_mp(x, 8, xm);
        err = sp_256_mod_mul_norm_sm2_8(x, x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
        {
            sp_256_mont_sqr_sm2_8(y, x, p256_sm2_mod, p256_sm2_mp_mod);
            sp_256_mont_mul_sm2_8(y, y, x, p256_sm2_mod, p256_sm2_mp_mod);
        }
        /* y = x^3 - 3x */
        sp_256_mont_sub_sm2_8(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(y, y, x, p256_sm2_mod);
        sp_256_mont_sub_sm2_8(y, y, x, p256_sm2_mod);
        /* y = x^3 - 3x + b */
        err = sp_256_mod_mul_norm_sm2_8(x, p256_sm2_b, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        sp_256_mont_add_sm2_8(y, y, x, p256_sm2_mod);
        /* y = sqrt(x^3 - 3x + b) */
        err = sp_256_mont_sqrt_sm2_8(y);
    }
    if (err == MP_OKAY) {
        XMEMSET(y + 8, 0, 8U * sizeof(sp_digit));
        sp_256_mont_reduce_sm2_8(y, p256_sm2_mod, p256_sm2_mp_mod);
        if ((((word32)y[0] ^ (word32)odd) & 1U) != 0U) {
            sp_256_mont_sub_sm2_8(y, p256_sm2_mod, y, p256_sm2_mod);
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
#endif /* WOLFSSL_SP_ARM_THUMB_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
