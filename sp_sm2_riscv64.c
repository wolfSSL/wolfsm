/* sp.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_SP_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(WOLFSSL_HAVE_SP_ECC)

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

#if defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) && !defined(WOLFSSL_SP_ASM) && \
        !defined(DEBUG_VECTOR_REGISTER_ACCESS)
    /* force off unneeded vector register save/restore. */
    #undef SAVE_VECTOR_REGISTERS
    #define SAVE_VECTOR_REGISTERS(fail_clause) SAVE_NO_VECTOR_REGISTERS(fail_clause)
    #undef SAVE_VECTOR_REGISTERS2
    #define SAVE_VECTOR_REGISTERS2() SAVE_NO_VECTOR_REGISTERS2()
    #undef RESTORE_VECTOR_REGISTERS
    #define RESTORE_VECTOR_REGISTERS() RESTORE_NO_VECTOR_REGISTERS()
#endif

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif

#ifdef WOLFSSL_SP_SMALL_STACK
    #define SP_DECL_VAR(TYPE, NAME, CNT)                                \
        TYPE* NAME = NULL
    #define SP_ALLOC_VAR(TYPE, NAME, CNT, HEAP, DT)                     \
        if (err == MP_OKAY) {                                           \
            (NAME) = (TYPE*)XMALLOC(sizeof(TYPE) * (CNT), (HEAP), DT);  \
            if ((NAME) == NULL) {                                       \
                err = MEMORY_E;                                         \
            }                                                           \
        }

    #define SP_VAR_OK(NAME)          ((NAME) != NULL)

    #define SP_FREE_VAR(NAME, HEAP, DT)                                 \
        XFREE(NAME, (HEAP), DT)
    #define SP_ZEROFREE_VAR(TYPE, NAME, CNT, HEAP, DT)                  \
        do {                                                            \
            if ((NAME) != NULL) {                                       \
                ForceZero(NAME, sizeof(TYPE) * (CNT));                  \
            }                                                           \
            SP_FREE_VAR(NAME, HEAP, DT);                                \
        } while (0)
    #define SP_ZEROFREE_VAR_ALT(TYPE, NAME, FZ_NAME, CNT, HEAP, DT)     \
        do {                                                            \
            if ((FZ_NAME) != NULL) {                                    \
                ForceZero(FZ_NAME, sizeof(TYPE) * (CNT));               \
            }                                                           \
            SP_FREE_VAR(NAME, HEAP, DT);                                \
        } while (0)
#else
    #define SP_DECL_VAR(TYPE, NAME, CNT)                                \
        TYPE NAME[CNT]
    #define SP_ALLOC_VAR(TYPE, NAME, CNT, HEAP, DT)                     \
        WC_DO_NOTHING
    #define SP_VAR_OK(NAME)          (1)
    #define SP_FREE_VAR(NAME, HEAP, DT)                                 \
        WC_DO_NOTHING
    #define SP_ZEROFREE_VAR(TYPE, NAME, CNT, HEAP, DT)                  \
        do {                                                            \
            if ((NAME) != NULL) {                                       \
                ForceZero(NAME, sizeof(TYPE) * (CNT));                  \
            }                                                           \
        } while (0)
    #define SP_ZEROFREE_VAR_ALT(TYPE, NAME, FZ_NAME, CNT, HEAP, DT)     \
        do {                                                            \
            if ((FZ_NAME) != NULL) {                                    \
                ForceZero(FZ_NAME, sizeof(TYPE) * (CNT));               \
            }                                                           \
        } while (0)
#endif

/* Variables too large to place on the stack of a constrained environment.
 * The Linux kernel stack is only a few pages and the ECC window tables are
 * many kilobytes, so allocate those from the heap there as well. */
#if defined(WOLFSSL_SP_SMALL_STACK) || defined(WOLFSSL_SMALL_STACK) || \
    defined(WOLFSSL_LINUXKM)
    #define SP_DECL_VAR_LARGE(TYPE, NAME, CNT)                          \
        TYPE* NAME = NULL
    #define SP_ALLOC_VAR_LARGE(TYPE, NAME, CNT, HEAP, DT)               \
        if (err == MP_OKAY) {                                           \
            (NAME) = (TYPE*)XMALLOC(sizeof(TYPE) * (CNT), (HEAP), DT);  \
            if ((NAME) == NULL) {                                       \
                err = MEMORY_E;                                         \
            }                                                           \
        }
    #define SP_FREE_VAR_LARGE(NAME, HEAP, DT)                           \
        XFREE(NAME, (HEAP), DT)
#else
    #define SP_DECL_VAR_LARGE(TYPE, NAME, CNT)                          \
        TYPE NAME[CNT]
    #define SP_ALLOC_VAR_LARGE(TYPE, NAME, CNT, HEAP, DT)               \
        WC_DO_NOTHING
    #define SP_FREE_VAR_LARGE(NAME, HEAP, DT)                           \
        WC_DO_NOTHING
#endif

#ifdef WOLFSSL_SP_RISCV64_ASM
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
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p256_sm2_b[4] = {
    0xddbcbd414d940e93L,0xf39789f515ab8f92L,0x4d5a9e4bcf6509a7L,
    0x28e9fa9e9d9f5e34L
};
#endif

/* Multiply a and b into r. (r = a * b)
 *
 * @param [out] r  A single precision integer.
 * @param [in]  a  A single precision integer.
 * @param [in]  b  A single precision integer.
 */
static void sp_256_mul_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        /* Load both operands */
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 24(%[a])\n\t"
        "ld      t4, 0(%[b])\n\t"
        "ld      t5, 8(%[b])\n\t"
        "ld      t6, 16(%[b])\n\t"
        "ld      a3, 24(%[b])\n\t"
        "li      a4, 0\n\t"
        "li      a5, 0\n\t"
        "mul     a7, t0, t4\n\t"
        "mulhu   s1, t0, t4\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s2, a4, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s3, a5, s1\n\t"
        "add     a5, a5, s2\n\t"
        "sltu    s2, a5, s2\n\t"
        "add     a6, s3, s2\n\t"
        "sd      a4, 0(%[r])\n\t"
        "mul     a7, t0, t5\n\t"
        "mulhu   s1, t0, t5\n\t"
        "add     a5, a5, a7\n\t"
        "sltu    s2, a5, a7\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s3, a6, s1\n\t"
        "add     a6, a6, s2\n\t"
        "sltu    s2, a6, s2\n\t"
        "add     a4, s3, s2\n\t"
        "mul     a7, t1, t4\n\t"
        "mulhu   s1, t1, t4\n\t"
        "add     a5, a5, a7\n\t"
        "sltu    s2, a5, a7\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s3, a6, s1\n\t"
        "add     a6, a6, s2\n\t"
        "sltu    s2, a6, s2\n\t"
        "add     a4, a4, s3\n\t"
        "add     a4, a4, s2\n\t"
        "sd      a5, 8(%[r])\n\t"
        "mul     a7, t0, t6\n\t"
        "mulhu   s1, t0, t6\n\t"
        "add     a6, a6, a7\n\t"
        "sltu    s2, a6, a7\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    s3, a4, s1\n\t"
        "add     a4, a4, s2\n\t"
        "sltu    s2, a4, s2\n\t"
        "add     a5, s3, s2\n\t"
        "mul     a7, t1, t5\n\t"
        "mulhu   s1, t1, t5\n\t"
        "add     a6, a6, a7\n\t"
        "sltu    s2, a6, a7\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    s3, a4, s1\n\t"
        "add     a4, a4, s2\n\t"
        "sltu    s2, a4, s2\n\t"
        "add     a5, a5, s3\n\t"
        "add     a5, a5, s2\n\t"
        "mul     a7, t2, t4\n\t"
        "mulhu   s1, t2, t4\n\t"
        "add     a6, a6, a7\n\t"
        "sltu    s2, a6, a7\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    s3, a4, s1\n\t"
        "add     a4, a4, s2\n\t"
        "sltu    s2, a4, s2\n\t"
        "add     a5, a5, s3\n\t"
        "add     a5, a5, s2\n\t"
        "sd      a6, 16(%[r])\n\t"
        "mul     a7, t0, a3\n\t"
        "mulhu   s1, t0, a3\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s2, a4, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s3, a5, s1\n\t"
        "add     a5, a5, s2\n\t"
        "sltu    s2, a5, s2\n\t"
        "add     a6, s3, s2\n\t"
        "mul     a7, t1, t6\n\t"
        "mulhu   s1, t1, t6\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s2, a4, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s3, a5, s1\n\t"
        "add     a5, a5, s2\n\t"
        "sltu    s2, a5, s2\n\t"
        "add     a6, a6, s3\n\t"
        "add     a6, a6, s2\n\t"
        "mul     a7, t2, t5\n\t"
        "mulhu   s1, t2, t5\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s2, a4, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s3, a5, s1\n\t"
        "add     a5, a5, s2\n\t"
        "sltu    s2, a5, s2\n\t"
        "add     a6, a6, s3\n\t"
        "add     a6, a6, s2\n\t"
        "mul     a7, t3, t4\n\t"
        "mulhu   s1, t3, t4\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s2, a4, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s3, a5, s1\n\t"
        "add     a5, a5, s2\n\t"
        "sltu    s2, a5, s2\n\t"
        "add     a6, a6, s3\n\t"
        "add     a6, a6, s2\n\t"
        "sd      a4, 24(%[r])\n\t"
        "mul     a7, t1, a3\n\t"
        "mulhu   s1, t1, a3\n\t"
        "add     a5, a5, a7\n\t"
        "sltu    s2, a5, a7\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s3, a6, s1\n\t"
        "add     a6, a6, s2\n\t"
        "sltu    s2, a6, s2\n\t"
        "add     a4, s3, s2\n\t"
        "mul     a7, t2, t6\n\t"
        "mulhu   s1, t2, t6\n\t"
        "add     a5, a5, a7\n\t"
        "sltu    s2, a5, a7\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s3, a6, s1\n\t"
        "add     a6, a6, s2\n\t"
        "sltu    s2, a6, s2\n\t"
        "add     a4, a4, s3\n\t"
        "add     a4, a4, s2\n\t"
        "mul     a7, t3, t5\n\t"
        "mulhu   s1, t3, t5\n\t"
        "add     a5, a5, a7\n\t"
        "sltu    s2, a5, a7\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s3, a6, s1\n\t"
        "add     a6, a6, s2\n\t"
        "sltu    s2, a6, s2\n\t"
        "add     a4, a4, s3\n\t"
        "add     a4, a4, s2\n\t"
        "sd      a5, 32(%[r])\n\t"
        "mul     a7, t2, a3\n\t"
        "mulhu   s1, t2, a3\n\t"
        "add     a6, a6, a7\n\t"
        "sltu    s2, a6, a7\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    s3, a4, s1\n\t"
        "add     a4, a4, s2\n\t"
        "sltu    s2, a4, s2\n\t"
        "add     a5, s3, s2\n\t"
        "mul     a7, t3, t6\n\t"
        "mulhu   s1, t3, t6\n\t"
        "add     a6, a6, a7\n\t"
        "sltu    s2, a6, a7\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    s3, a4, s1\n\t"
        "add     a4, a4, s2\n\t"
        "sltu    s2, a4, s2\n\t"
        "add     a5, a5, s3\n\t"
        "add     a5, a5, s2\n\t"
        "sd      a6, 40(%[r])\n\t"
        "mul     a7, t3, a3\n\t"
        "mulhu   s1, t3, a3\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s2, a4, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s3, a5, s1\n\t"
        "add     a5, a5, s2\n\t"
        "sltu    s2, a5, s2\n\t"
        "add     a6, s3, s2\n\t"
        "sd      a4, 48(%[r])\n\t"
        "sd      a5, 56(%[r])\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a3", "a4", "a5",
            "a6", "a7", "s1", "s2", "s3"
    );
}

/* Square a and put result in r. (r = a * a)
 *
 * @param [out] r  A single precision integer.
 * @param [in]  a  A single precision integer.
 */
static void sp_256_sqr_sm2_4(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        /* Load the operand */
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 24(%[a])\n\t"
        "li      a2, 0\n\t"
        "li      a3, 0\n\t"
        "li      t4, 0\n\t"
        "li      t5, 0\n\t"
        "li      t6, 0\n\t"
        /* Double the cross terms */
        "srli    a6, t5, 63\n\t"
        "slli    t6, t6, 1\n\t"
        "or      t6, t6, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    t5, t5, 1\n\t"
        "or      t5, t5, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Diagonal square */
        "mul     a4, t0, t0\n\t"
        "mulhu   a5, t0, t0\n\t"
        "add     t4, t4, a4\n\t"
        "sltu    a6, t4, a4\n\t"
        "add     t5, t5, a5\n\t"
        "sltu    a7, t5, a5\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        /* Carry from the previous column */
        "add     t4, t4, a2\n\t"
        "sltu    a6, t4, a2\n\t"
        "add     t5, t5, a3\n\t"
        "sltu    a7, t5, a3\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        "sd      t4, 0(%[r])\n\t"
        "mul     t4, t0, t1\n\t"
        "mulhu   a2, t0, t1\n\t"
        "li      a3, 0\n\t"
        /* Double the cross terms */
        "srli    a6, a2, 63\n\t"
        "slli    a3, a3, 1\n\t"
        "or      a3, a3, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    a2, a2, 1\n\t"
        "or      a2, a2, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Carry from the previous column */
        "add     t4, t4, t5\n\t"
        "sltu    a6, t4, t5\n\t"
        "add     a2, a2, t6\n\t"
        "sltu    a7, a2, t6\n\t"
        "add     a2, a2, a6\n\t"
        "sltu    a6, a2, a6\n\t"
        "add     a3, a3, a7\n\t"
        "add     a3, a3, a6\n\t"
        "sd      t4, 8(%[r])\n\t"
        "mul     t4, t0, t2\n\t"
        "mulhu   t5, t0, t2\n\t"
        "li      t6, 0\n\t"
        /* Double the cross terms */
        "srli    a6, t5, 63\n\t"
        "slli    t6, t6, 1\n\t"
        "or      t6, t6, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    t5, t5, 1\n\t"
        "or      t5, t5, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Diagonal square */
        "mul     a4, t1, t1\n\t"
        "mulhu   a5, t1, t1\n\t"
        "add     t4, t4, a4\n\t"
        "sltu    a6, t4, a4\n\t"
        "add     t5, t5, a5\n\t"
        "sltu    a7, t5, a5\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        /* Carry from the previous column */
        "add     t4, t4, a2\n\t"
        "sltu    a6, t4, a2\n\t"
        "add     t5, t5, a3\n\t"
        "sltu    a7, t5, a3\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        "sd      t4, 16(%[r])\n\t"
        "mul     t4, t0, t3\n\t"
        "mulhu   a2, t0, t3\n\t"
        "li      a3, 0\n\t"
        "mul     a4, t1, t2\n\t"
        "mulhu   a5, t1, t2\n\t"
        "add     t4, t4, a4\n\t"
        "sltu    a6, t4, a4\n\t"
        "add     a2, a2, a5\n\t"
        "sltu    a7, a2, a5\n\t"
        "add     a2, a2, a6\n\t"
        "sltu    a6, a2, a6\n\t"
        "add     a3, a3, a7\n\t"
        "add     a3, a3, a6\n\t"
        /* Double the cross terms */
        "srli    a6, a2, 63\n\t"
        "slli    a3, a3, 1\n\t"
        "or      a3, a3, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    a2, a2, 1\n\t"
        "or      a2, a2, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Carry from the previous column */
        "add     t4, t4, t5\n\t"
        "sltu    a6, t4, t5\n\t"
        "add     a2, a2, t6\n\t"
        "sltu    a7, a2, t6\n\t"
        "add     a2, a2, a6\n\t"
        "sltu    a6, a2, a6\n\t"
        "add     a3, a3, a7\n\t"
        "add     a3, a3, a6\n\t"
        "sd      t4, 24(%[r])\n\t"
        "mul     t4, t1, t3\n\t"
        "mulhu   t5, t1, t3\n\t"
        "li      t6, 0\n\t"
        /* Double the cross terms */
        "srli    a6, t5, 63\n\t"
        "slli    t6, t6, 1\n\t"
        "or      t6, t6, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    t5, t5, 1\n\t"
        "or      t5, t5, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Diagonal square */
        "mul     a4, t2, t2\n\t"
        "mulhu   a5, t2, t2\n\t"
        "add     t4, t4, a4\n\t"
        "sltu    a6, t4, a4\n\t"
        "add     t5, t5, a5\n\t"
        "sltu    a7, t5, a5\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        /* Carry from the previous column */
        "add     t4, t4, a2\n\t"
        "sltu    a6, t4, a2\n\t"
        "add     t5, t5, a3\n\t"
        "sltu    a7, t5, a3\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        "sd      t4, 32(%[r])\n\t"
        "mul     t4, t2, t3\n\t"
        "mulhu   a2, t2, t3\n\t"
        "li      a3, 0\n\t"
        /* Double the cross terms */
        "srli    a6, a2, 63\n\t"
        "slli    a3, a3, 1\n\t"
        "or      a3, a3, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    a2, a2, 1\n\t"
        "or      a2, a2, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Carry from the previous column */
        "add     t4, t4, t5\n\t"
        "sltu    a6, t4, t5\n\t"
        "add     a2, a2, t6\n\t"
        "sltu    a7, a2, t6\n\t"
        "add     a2, a2, a6\n\t"
        "sltu    a6, a2, a6\n\t"
        "add     a3, a3, a7\n\t"
        "add     a3, a3, a6\n\t"
        "sd      t4, 40(%[r])\n\t"
        "li      t4, 0\n\t"
        "li      t5, 0\n\t"
        "li      t6, 0\n\t"
        /* Double the cross terms */
        "srli    a6, t5, 63\n\t"
        "slli    t6, t6, 1\n\t"
        "or      t6, t6, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    t5, t5, 1\n\t"
        "or      t5, t5, a6\n\t"
        "slli    t4, t4, 1\n\t"
        /* Diagonal square */
        "mul     a4, t3, t3\n\t"
        "mulhu   a5, t3, t3\n\t"
        "add     t4, t4, a4\n\t"
        "sltu    a6, t4, a4\n\t"
        "add     t5, t5, a5\n\t"
        "sltu    a7, t5, a5\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        /* Carry from the previous column */
        "add     t4, t4, a2\n\t"
        "sltu    a6, t4, a2\n\t"
        "add     t5, t5, a3\n\t"
        "sltu    a7, t5, a3\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    a6, t5, a6\n\t"
        "add     t6, t6, a7\n\t"
        "add     t6, t6, a6\n\t"
        "sd      t4, 48(%[r])\n\t"
        "sd      t5, 56(%[r])\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a2", "a3", "a4",
            "a5", "a6", "a7"
    );
}

/* Add b to a into r. (r = a + b)
 *
 * @param [out] r  A single precision integer.
 * @param [in]  a  A single precision integer.
 * @param [in]  b  A single precision integer.
 */
static sp_digit sp_256_add_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    __asm__ __volatile__ (
        "ld      t1, 0(%[a])\n\t"
        "ld      t2, 0(%[b])\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t0, t3, t1\n\t"
        "sd      t3, 0(%[r])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 8(%[b])\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t4, t3, t1\n\t"
        "add     t3, t3, t0\n\t"
        "sltu    t0, t3, t0\n\t"
        "or      t0, t0, t4\n\t"
        "sd      t3, 8(%[r])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "ld      t2, 16(%[b])\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t4, t3, t1\n\t"
        "add     t3, t3, t0\n\t"
        "sltu    t0, t3, t0\n\t"
        "or      t0, t0, t4\n\t"
        "sd      t3, 16(%[r])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "ld      t2, 24(%[b])\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t4, t3, t1\n\t"
        "add     t3, t3, t0\n\t"
        "sltu    t0, t3, t0\n\t"
        "or      t0, t0, t4\n\t"
        "sd      t3, 24(%[r])\n\t"
        "mv      %[r], t0\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );
    return (word64)(size_t)r;
}

/* Sub b from a into r. (r = a - b)
 *
 * @param [out] r  A single precision integer.
 * @param [in]  a  A single precision integer.
 * @param [in]  b  A single precision integer.
 */
static sp_digit sp_256_sub_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    __asm__ __volatile__ (
        "ld      t1, 0(%[a])\n\t"
        "ld      t2, 0(%[b])\n\t"
        "sltu    t0, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sd      t3, 0(%[r])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 8(%[b])\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 8(%[r])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "ld      t2, 16(%[b])\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 16(%[r])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "ld      t2, 24(%[b])\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 24(%[r])\n\t"
        "sub     %[r], zero, t0\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5"
    );
    return (word64)(size_t)r;
}

/* Sub b from a into a. (a -= b)
 *
 * @param [in] a  A single precision integer.
 * @param [in] b  A single precision integer.
 */
static sp_digit sp_256_sub_in_place_sm2_4(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ld      t1, 0(%[a])\n\t"
        "ld      t2, 0(%[b])\n\t"
        "sltu    t0, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sd      t3, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 8(%[b])\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 8(%[a])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "ld      t2, 16(%[b])\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 16(%[a])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "ld      t2, 24(%[b])\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 24(%[a])\n\t"
        "sub     %[a], zero, t0\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5"
    );
    return (word64)(size_t)a;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * @param [out] r  A single precision number representing condition subtract
 *                 result.
 * @param [in]  a  A single precision number to subtract from.
 * @param [in]  b  A single precision number to subtract.
 * @param [in]  m  Mask value to apply.
 */
static sp_digit sp_256_cond_sub_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* b, sp_digit m)
{
    __asm__ __volatile__ (
        "ld      t1, 0(%[a])\n\t"
        "ld      t2, 0(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "sltu    t0, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sd      t3, 0(%[r])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 8(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 8(%[r])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "ld      t2, 16(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 16(%[r])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "ld      t2, 24(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "sltu    t4, t1, t2\n\t"
        "sub     t3, t1, t2\n\t"
        "sltu    t5, t3, t0\n\t"
        "sub     t3, t3, t0\n\t"
        "or      t0, t4, t5\n\t"
        "sd      t3, 24(%[r])\n\t"
        "sub     %[r], zero, t0\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b), [m] "+r" (m)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5"
    );
    return (word64)(size_t)r;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * @param [out] r  A single precision integer.
 * @param [in]  a  A single precision integer.
 * @param [in]  b  A single precision digit.
 */
static void sp_256_mul_d_sm2_4(sp_digit* r, const sp_digit* a, sp_digit b)
{
    __asm__ __volatile__ (
        "li      t0, 0\n\t"
        "ld      t1, 0(%[a])\n\t"
        "mul     t2, t1, %[b]\n\t"
        "mulhu   t3, t1, %[b]\n\t"
        "add     t2, t2, t0\n\t"
        "sltu    t4, t2, t0\n\t"
        "add     t3, t3, t4\n\t"
        "sd      t2, 0(%[r])\n\t"
        "mv      t0, t3\n\t"
        "ld      t1, 8(%[a])\n\t"
        "mul     t2, t1, %[b]\n\t"
        "mulhu   t3, t1, %[b]\n\t"
        "add     t2, t2, t0\n\t"
        "sltu    t4, t2, t0\n\t"
        "add     t3, t3, t4\n\t"
        "sd      t2, 8(%[r])\n\t"
        "mv      t0, t3\n\t"
        "ld      t1, 16(%[a])\n\t"
        "mul     t2, t1, %[b]\n\t"
        "mulhu   t3, t1, %[b]\n\t"
        "add     t2, t2, t0\n\t"
        "sltu    t4, t2, t0\n\t"
        "add     t3, t3, t4\n\t"
        "sd      t2, 16(%[r])\n\t"
        "mv      t0, t3\n\t"
        "ld      t1, 24(%[a])\n\t"
        "mul     t2, t1, %[b]\n\t"
        "mulhu   t3, t1, %[b]\n\t"
        "add     t2, t2, t0\n\t"
        "sltu    t4, t2, t0\n\t"
        "add     t3, t3, t4\n\t"
        "sd      t2, 24(%[r])\n\t"
        "mv      t0, t3\n\t"
        "sd      t0, 32(%[r])\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has highest bit set.
 *
 * @param [in] d1   The high order half of the number to divide.
 * @param [in] d0   The low order half of the number to divide.
 * @param [in] div  The divisor.
 *
 * @return  The result of the division.
 */
static sp_digit div_256_word_4(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        /* Divisor to estimate with - high half plus one. */
        "srli    t5, %[div], 32\n\t"
        "addi    t2, t5, 1\n\t"
        /* Estimate the top 32 bits of the quotient. */
        "divu    t0, %[d1], t2\n\t"
        "slli    t4, %[div], 32\n\t"
        "slli    t3, t0, 32\n\t"
        "mul     t1, %[div], t3\n\t"
        "mulhu   t0, %[div], t3\n\t"
        "sltu    a4, %[d0], t1\n\t"
        "sub     %[d0], %[d0], t1\n\t"
        "sub     %[d1], %[d1], t0\n\t"
        "sub     %[d1], %[d1], a4\n\t"
        /* Correct the estimate when the remainder is still too large. */
        "sltu    t6, %[d1], t2\n\t"
        "xori    t6, t6, 1\n\t"
        "slli    a3, t6, 32\n\t"
        "sub     t6, zero, t6\n\t"
        "and     t4, t4, t6\n\t"
        "and     t5, t5, t6\n\t"
        "sltu    a4, %[d0], t4\n\t"
        "sub     %[d0], %[d0], t4\n\t"
        "sub     %[d1], %[d1], t5\n\t"
        "sub     %[d1], %[d1], a4\n\t"
        "add     t3, t3, a3\n\t"
        /* Next 32 bits of the quotient from the top of the remainder. */
        "srli    t0, %[d0], 32\n\t"
        "slli    t1, %[d1], 32\n\t"
        "or      t0, t0, t1\n\t"
        "divu    t0, t0, t2\n\t"
        "add     t3, t3, t0\n\t"
        "mul     t1, %[div], t0\n\t"
        "mulhu   t0, %[div], t0\n\t"
        "sltu    a4, %[d0], t1\n\t"
        "sub     %[d0], %[d0], t1\n\t"
        "sub     %[d1], %[d1], t0\n\t"
        "sub     %[d1], %[d1], a4\n\t"
        /* Next 32 bits of the quotient from the top of the remainder. */
        "srli    t0, %[d0], 32\n\t"
        "slli    t1, %[d1], 32\n\t"
        "or      t0, t0, t1\n\t"
        "divu    t0, t0, t2\n\t"
        "add     t3, t3, t0\n\t"
        "mul     t1, %[div], t0\n\t"
        "mulhu   t0, %[div], t0\n\t"
        "sltu    a4, %[d0], t1\n\t"
        "sub     %[d0], %[d0], t1\n\t"
        "sub     %[d1], %[d1], t0\n\t"
        "sub     %[d1], %[d1], a4\n\t"
        /* Remainder now fits in a word - finish with a plain divide. */
        "divu    t0, %[d0], %[div]\n\t"
        "add     %[d1], t3, t0\n\t"
        : [d1] "+r" (d1), [d0] "+r" (d0), [div] "+r" (div)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a3", "a4"
    );
    return (word64)(size_t)d1;
}

/* AND m into each word of a and store in r.
 *
 * @param [out] r  A single precision integer.
 * @param [in]  a  A single precision integer.
 * @param [in]  m  Mask to AND against each digit.
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

/* Compare a with b in constant time.
 *
 * @param [in] a  A single precision integer.
 * @param [in] b  A single precision integer.
 *
 * @return  -ve, 0 or +ve if a is less than, equal to or greater than b
 *          respectively.
 */
static sp_int64 sp_256_cmp_sm2_4(const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "li      t1, 0\n\t"
        "li      t0, -1\n\t"
        "ld      t2, 24(%[a])\n\t"
        "ld      t3, 24(%[b])\n\t"
        "sltu    t4, t2, t3\n\t"
        "sub     t4, zero, t4\n\t"
        "and     t4, t4, t0\n\t"
        "or      t1, t1, t4\n\t"
        "xor     t5, t2, t3\n\t"
        "sltiu   t5, t5, 1\n\t"
        "sub     t5, zero, t5\n\t"
        "and     t0, t0, t5\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 16(%[b])\n\t"
        "sltu    t4, t2, t3\n\t"
        "sub     t4, zero, t4\n\t"
        "and     t4, t4, t0\n\t"
        "or      t1, t1, t4\n\t"
        "xor     t5, t2, t3\n\t"
        "sltiu   t5, t5, 1\n\t"
        "sub     t5, zero, t5\n\t"
        "and     t0, t0, t5\n\t"
        "ld      t2, 8(%[a])\n\t"
        "ld      t3, 8(%[b])\n\t"
        "sltu    t4, t2, t3\n\t"
        "sub     t4, zero, t4\n\t"
        "and     t4, t4, t0\n\t"
        "or      t1, t1, t4\n\t"
        "xor     t5, t2, t3\n\t"
        "sltiu   t5, t5, 1\n\t"
        "sub     t5, zero, t5\n\t"
        "and     t0, t0, t5\n\t"
        "ld      t2, 0(%[a])\n\t"
        "ld      t3, 0(%[b])\n\t"
        "sltu    t4, t2, t3\n\t"
        "sub     t4, zero, t4\n\t"
        "and     t4, t4, t0\n\t"
        "or      t1, t1, t4\n\t"
        "xor     t5, t2, t3\n\t"
        "sltiu   t5, t5, 1\n\t"
        "sub     t5, zero, t5\n\t"
        "and     t0, t0, t5\n\t"
        "sltiu   %[a], t0, 1\n\t"
        "or      %[a], %[a], t1\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5"
    );
    return (word64)(size_t)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * @param [in]  a  Number to be divided.
 * @param [in]  d  Number to divide with.
 * @param [in]  m  Multiplier result.
 * @param [out] r  Remainder from the division.
 *
 * @return  MP_OKAY indicating success.
 */
static WC_INLINE int sp_256_div_sm2_4(const sp_digit* a, const sp_digit* d,
        sp_digit* m, sp_digit* r)
{
    sp_digit t1[8], t2[5];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[3];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 4);
    r1 = sp_256_cmp_sm2_4(&t1[4], d) >= 0;
    sp_256_cond_sub_sm2_4(&t1[4], &t1[4], d, (sp_digit)0 - r1);
    for (i = 3; i >= 0; i--) {
        volatile sp_digit mask = (sp_digit)0 - (t1[4 + i] == div);
        sp_digit hi = t1[4 + i] + mask;
        r1 = div_256_word_4(hi, t1[4 + i - 1], div);
        r1 |= mask;

        sp_256_mul_d_sm2_4(t2, d, r1);
        t1[4 + i] += sp_256_sub_in_place_sm2_4(&t1[i], t2);
        t1[4 + i] -= t2[4];
        sp_256_mask_4(t2, d, t1[4 + i]);
        t1[4 + i] += sp_256_add_sm2_4(&t1[i], &t1[i], t2);
        sp_256_mask_4(t2, d, t1[4 + i]);
        t1[4 + i] += sp_256_add_sm2_4(&t1[i], &t1[i], t2);
    }

    r1 = sp_256_cmp_sm2_4(t1, d) >= 0;
    sp_256_cond_sub_sm2_4(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * @param [out] r  A single precision number that is the reduced result.
 * @param [in]  a  A single precision number that is to be reduced.
 * @param [in]  m  A single precision number that is the modulus to reduce with.
 *
 * @return  MP_OKAY indicating success.
 */
static WC_INLINE int sp_256_mod_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_256_div_sm2_4(a, m, NULL, r);
}

/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * @param [out] r  The resulting Montgomery form number.
 * @param [in]  a  The number to convert.
 * @param [in]  m  The modulus (prime).
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_mod_mul_norm_sm2_4(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_256_mul_sm2_4(r, a, p256_sm2_norm_mod);
    return sp_256_mod_sm2_4(r, r, m);
}

/* Convert an mp_int to an array of sp_digit.
 *
 * @param [out] r     A single precision integer.
 * @param [in]  size  Maximum number of bytes to convert
 * @param [in]  a     A multi-precision integer.
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
    int o = 0;
    word32 s = 0;
    /* Digit holder and mask are full mp_digit width (the type of a->dp[]) so
     * the wide-digit split shifts below are not truncated when DIGIT_BIT is
     * wider than the sp word (e.g. sp_c32.c over a 64-bit mp_digit). */
    mp_digit d;
    /* mask = all ones while the read index is a valid digit (index < a->used),
     * else zero. It is recomputed at the end of each iteration and reused: it
     * zeros the digit at or after a->used, and negated (-mask is 0 or 1) it
     * advances the read index only while another digit remains, so o never
     * reads past the last valid digit. The first digit is always valid, so mask
     * starts as all ones and no pre-loop calculation is needed. */
    mp_digit mask = (mp_digit)0 - 1;

    r[0] = 0;
    /* Loop a fixed number of times (bounded by the output size, not by
     * a->used) so a secret value is converted in constant time. */
    for (i = 0; j < size; i++) {
        d = a->dp[o] & mask;
        r[j] |= (sp_digit)(d << s);
        r[j] &= 0xffffffffffffffffl;
        s = 64U - s;
        if (j + 1 >= size) {
            break;
        }
        r[++j] = (sp_digit)(d >> s);
        while ((s + 64U) <= (word32)DIGIT_BIT) {
            s += 64U;
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                r[++j] = (sp_digit)(d >> s);
            }
            else {
                r[++j] = (sp_digit)0;
            }
        }
        s = (word32)DIGIT_BIT - s;
        /* Recompute mask for the next read index, then advance o by -mask
         * (0 or 1) so it only moves while another digit remains. */
        mask = (mp_digit)0 - (((mp_digit)(i + 1U) - (mp_digit)(unsigned int)a->used) >>
            (sizeof(mp_digit) * 8 - 1));
        o += (int)((mp_digit)0 - mask);
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
        r[j] |= ((sp_uint64)a->dp[i]) << s;
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
 * @param [out] p   Point of type sp_point_256 (result).
 * @param [in]  pm  Point of type ecc_point.
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
 * @param [in]  a  A single precision integer.
 * @param [out] r  A multi-precision integer.
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
            r->dp[j] |= (mp_digit)((sp_uint64)a[i] << s);
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
            r->dp[j] |= ((sp_uint64)a[i]) << s;
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
 * @param [in] p   Point of type sp_point_256.
 * @param [in] pm  Point of type ecc_point (result).
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when allocation of memory in ecc_point fails.
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

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * @param [out] r   Result of multiplication.
 * @param [in]  a   First number to multiply in Montgomery form.
 * @param [in]  b   Second number to multiply in Montgomery form.
 * @param [in]  m   Modulus (prime).  SM2 only - not read.
 * @param [in]  mp  Montgomery multiplier.  Must be 1 - not read.
 */
static SP_NOINLINE void sp_256_mont_mul_sm2_4(sp_digit* r_p,
    const sp_digit* a_p, const sp_digit* b_p, const sp_digit* m_p,
    sp_digit mp_p)
{
    register sp_digit* r __asm__ ("a0") = (sp_digit*)r_p;
    register const sp_digit* a __asm__ ("a1") = (const sp_digit*)a_p;
    register const sp_digit* b __asm__ ("a2") = (const sp_digit*)b_p;
    register const sp_digit* m __asm__ ("a3") = (const sp_digit*)m_p;
    register sp_digit mp __asm__ ("a4") = (sp_digit)mp_p;

    __asm__ __volatile__ (
        /* Load a - its argument register is a working register after this */
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 24(%[a])\n\t"
        /* Iteration 0: t += a * b[0] */
        "ld      a5, 0(%[b])\n\t"
        /* t is zero - a plain multiply */
        "mul     a1, t0, a5\n\t"
        "mulhu   s1, t0, a5\n\t"
        "mul     a6, t1, a5\n\t"
        "mulhu   a7, t1, a5\n\t"
        "add     t4, a6, s1\n\t"
        "sltu    s1, t4, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t2, a5\n\t"
        "mulhu   a7, t2, a5\n\t"
        "add     t5, a6, s1\n\t"
        "sltu    s1, t5, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t3, a5\n\t"
        "mulhu   a7, t3, a5\n\t"
        "add     t6, a6, s1\n\t"
        "sltu    s1, t6, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mv      a4, s1\n\t"
        "li      a5, 0\n\t"
        /* Reduce: mu = t[0]; A = mu << 32, B = mu >> 32 */
        "slli    s2, a1, 32\n\t"
        "srli    s3, a1, 32\n\t"
        /* Word 0: -mu cancels t[0]; keep only the carry */
        "sltu    s1, zero, a1\n\t"
        "mv      s5, s1\n\t"
        /* Word 1: mu - A */
        "sltu    a6, a1, s2\n\t"
        "sub     s4, a1, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    a6, t4, s4\n\t"
        "add     t4, t4, s1\n\t"
        "sltu    a7, t4, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 2: -B */
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    a6, t5, s4\n\t"
        "add     t5, t5, s1\n\t"
        "sltu    a7, t5, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 3: -A */
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 4: mu - B - cannot borrow out */
        "sub     s4, a1, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     a4, a4, s4\n\t"
        "sltu    a6, a4, s4\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    a7, a4, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Carry into word 5 */
        "add     a5, a5, s1\n\t"
        /* Iteration 1: t += a * b[1] */
        "ld      a1, 8(%[b])\n\t"
        "mul     a6, t0, a1\n\t"
        "mulhu   a7, t0, a1\n\t"
        "add     t4, t4, a6\n\t"
        "sltu    s1, t4, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t1, a1\n\t"
        "mulhu   a7, t1, a1\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    s1, t5, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t2, a1\n\t"
        "mulhu   a7, t2, a1\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     t6, t6, a6\n\t"
        "sltu    s1, t6, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t3, a1\n\t"
        "mulhu   a7, t3, a1\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     a4, a4, a6\n\t"
        "sltu    s1, a4, a6\n\t"
        "add     s1, s1, a7\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    s1, a5, s1\n\t"
        "mv      a1, s1\n\t"
        /* Reduce: mu = t[0]; A = mu << 32, B = mu >> 32 */
        "slli    s2, t4, 32\n\t"
        "srli    s3, t4, 32\n\t"
        /* Word 0: -mu cancels t[0]; keep only the carry */
        "sltu    s1, zero, t4\n\t"
        "mv      s5, s1\n\t"
        /* Word 1: mu - A */
        "sltu    a6, t4, s2\n\t"
        "sub     s4, t4, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    a6, t5, s4\n\t"
        "add     t5, t5, s1\n\t"
        "sltu    a7, t5, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 2: -B */
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 3: -A */
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a4, a4, s4\n\t"
        "sltu    a6, a4, s4\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    a7, a4, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 4: mu - B - cannot borrow out */
        "sub     s4, t4, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     a5, a5, s4\n\t"
        "sltu    a6, a5, s4\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    a7, a5, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Carry into word 5 */
        "add     a1, a1, s1\n\t"
        /* Iteration 2: t += a * b[2] */
        "ld      t4, 16(%[b])\n\t"
        "mul     a6, t0, t4\n\t"
        "mulhu   a7, t0, t4\n\t"
        "add     t5, t5, a6\n\t"
        "sltu    s1, t5, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t1, t4\n\t"
        "mulhu   a7, t1, t4\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     t6, t6, a6\n\t"
        "sltu    s1, t6, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t2, t4\n\t"
        "mulhu   a7, t2, t4\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     a4, a4, a6\n\t"
        "sltu    s1, a4, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t3, t4\n\t"
        "mulhu   a7, t3, t4\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     a5, a5, a6\n\t"
        "sltu    s1, a5, a6\n\t"
        "add     s1, s1, a7\n\t"
        "add     a1, a1, s1\n\t"
        "sltu    s1, a1, s1\n\t"
        "mv      t4, s1\n\t"
        /* Reduce: mu = t[0]; A = mu << 32, B = mu >> 32 */
        "slli    s2, t5, 32\n\t"
        "srli    s3, t5, 32\n\t"
        /* Word 0: -mu cancels t[0]; keep only the carry */
        "sltu    s1, zero, t5\n\t"
        "mv      s5, s1\n\t"
        /* Word 1: mu - A */
        "sltu    a6, t5, s2\n\t"
        "sub     s4, t5, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 2: -B */
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a4, a4, s4\n\t"
        "sltu    a6, a4, s4\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    a7, a4, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 3: -A */
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a5, a5, s4\n\t"
        "sltu    a6, a5, s4\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    a7, a5, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 4: mu - B - cannot borrow out */
        "sub     s4, t5, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     a1, a1, s4\n\t"
        "sltu    a6, a1, s4\n\t"
        "add     a1, a1, s1\n\t"
        "sltu    a7, a1, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Carry into word 5 */
        "add     t4, t4, s1\n\t"
        /* Iteration 3: t += a * b[3] */
        "ld      t5, 24(%[b])\n\t"
        "mul     a6, t0, t5\n\t"
        "mulhu   a7, t0, t5\n\t"
        "add     t6, t6, a6\n\t"
        "sltu    s1, t6, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t1, t5\n\t"
        "mulhu   a7, t1, t5\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     a4, a4, a6\n\t"
        "sltu    s1, a4, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t2, t5\n\t"
        "mulhu   a7, t2, t5\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     a5, a5, a6\n\t"
        "sltu    s1, a5, a6\n\t"
        "add     s1, s1, a7\n\t"
        "mul     a6, t3, t5\n\t"
        "mulhu   a7, t3, t5\n\t"
        "add     a6, a6, s1\n\t"
        "sltu    s1, a6, s1\n\t"
        "add     a7, a7, s1\n\t"
        "add     a1, a1, a6\n\t"
        "sltu    s1, a1, a6\n\t"
        "add     s1, s1, a7\n\t"
        "add     t4, t4, s1\n\t"
        "sltu    s1, t4, s1\n\t"
        "mv      t5, s1\n\t"
        /* Reduce: mu = t[0]; A = mu << 32, B = mu >> 32 */
        "slli    s2, t6, 32\n\t"
        "srli    s3, t6, 32\n\t"
        /* Word 0: -mu cancels t[0]; keep only the carry */
        "sltu    s1, zero, t6\n\t"
        "mv      s5, s1\n\t"
        /* Word 1: mu - A */
        "sltu    a6, t6, s2\n\t"
        "sub     s4, t6, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a4, a4, s4\n\t"
        "sltu    a6, a4, s4\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    a7, a4, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 2: -B */
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a5, a5, s4\n\t"
        "sltu    a6, a5, s4\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    a7, a5, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 3: -A */
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a1, a1, s4\n\t"
        "sltu    a6, a1, s4\n\t"
        "add     a1, a1, s1\n\t"
        "sltu    a7, a1, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Word 4: mu - B - cannot borrow out */
        "sub     s4, t6, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    a6, t4, s4\n\t"
        "add     t4, t4, s1\n\t"
        "sltu    a7, t4, s1\n\t"
        "or      s1, a6, a7\n\t"
        /* Carry into word 5 */
        "add     t5, t5, s1\n\t"
        /* t stays below 2m, so one conditional subtract fully reduces it. */
        /* Compute t - m in a's registers - dead now - keeping the borrow. */
        "li      s5, 0\n\t"
        "ld      s3, 0(%[m])\n\t"
        "sltu    a6, a4, s3\n\t"
        "sub     s4, a4, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "mv      t0, s4\n\t"
        "ld      s3, 8(%[m])\n\t"
        "sltu    a6, a5, s3\n\t"
        "sub     s4, a5, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "mv      t1, s4\n\t"
        "ld      s3, 16(%[m])\n\t"
        "sltu    a6, a1, s3\n\t"
        "sub     s4, a1, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "mv      t2, s4\n\t"
        "ld      s3, 24(%[m])\n\t"
        "sltu    a6, t4, s3\n\t"
        "sub     s4, t4, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "mv      t3, s4\n\t"
        /* Take the subtracted value when t overflowed or did not borrow */
        "xori    s5, s5, 1\n\t"
        "sltu    a6, zero, t5\n\t"
        "or      s5, s5, a6\n\t"
        "sub     s5, zero, s5\n\t"
        "xor     s4, a4, t0\n\t"
        "and     s4, s4, s5\n\t"
        "xor     s4, a4, s4\n\t"
        "sd      s4, 0(%[r])\n\t"
        "xor     s4, a5, t1\n\t"
        "and     s4, s4, s5\n\t"
        "xor     s4, a5, s4\n\t"
        "sd      s4, 8(%[r])\n\t"
        "xor     s4, a1, t2\n\t"
        "and     s4, s4, s5\n\t"
        "xor     s4, a1, s4\n\t"
        "sd      s4, 16(%[r])\n\t"
        "xor     s4, t4, t3\n\t"
        "and     s4, s4, s5\n\t"
        "xor     s4, t4, s4\n\t"
        "sd      s4, 24(%[r])\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b), [m] "+r" (m),
          [mp] "+r" (mp)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a5", "a6", "a7",
            "s1", "s2", "s3", "s4", "s5"
    );
}

/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * @param [out] r   Result of squaring.
 * @param [in]  a   Number to square in Montgomery form.
 * @param [in]  m   Modulus (prime).
 * @param [in]  mp  Montgomery multiplier.  Must be 1 - not read.
 */
static SP_NOINLINE void sp_256_mont_sqr_sm2_4(sp_digit* r_p,
    const sp_digit* a_p, const sp_digit* m_p, sp_digit mp_p)
{
    register sp_digit* r __asm__ ("a0") = (sp_digit*)r_p;
    register const sp_digit* a __asm__ ("a1") = (const sp_digit*)a_p;
    register const sp_digit* m __asm__ ("a2") = (const sp_digit*)m_p;
    register sp_digit mp __asm__ ("a3") = (sp_digit)mp_p;

    __asm__ __volatile__ (
        /* Load a - its argument register is a working register after this */
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 24(%[a])\n\t"
        /* Off-diagonal products a[i]*a[j], i < j - in position order so */
        /* each opens at most one new word, written directly */
        "mul     a1, t0, t1\n\t"
        "mulhu   t4, t0, t1\n\t"
        "mul     a6, t0, t2\n\t"
        "mulhu   t5, t0, t2\n\t"
        "mul     a3, t0, t3\n\t"
        "mulhu   t6, t0, t3\n\t"
        "add     t4, t4, a6\n\t"
        "sltu    s1, t4, a6\n\t"
        "add     t5, t5, s1\n\t"
        "mul     a7, t1, t2\n\t"
        "mulhu   a4, t1, t2\n\t"
        "add     t5, t5, a3\n\t"
        "sltu    s1, t5, a3\n\t"
        "add     t6, t6, s1\n\t"
        "add     t5, t5, a7\n\t"
        "sltu    s1, t5, a7\n\t"
        "add     a4, a4, s1\n\t"
        "add     t6, t6, a4\n\t"
        "sltu    a3, t6, a4\n\t"
        "mul     a6, t1, t3\n\t"
        "mulhu   a7, t1, t3\n\t"
        "add     t6, t6, a6\n\t"
        "sltu    s1, t6, a6\n\t"
        "add     a7, a7, s1\n\t"
        "add     a3, a3, a7\n\t"
        "sltu    a4, a3, a7\n\t"
        "mul     a6, t2, t3\n\t"
        "mulhu   a7, t2, t3\n\t"
        "add     a3, a3, a6\n\t"
        "sltu    s1, a3, a6\n\t"
        "add     a7, a7, s1\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    a5, a4, a7\n\t"
        /* Twice the off-diagonal sum plus the diagonals, in one sweep */
        /* Word 0: low word of a[0]*a[0], over the dying operand */
        "mulhu   a6, t0, t0\n\t"
        "mul     t0, t0, t0\n\t"
        /* Word 1: nothing shifts in, no carry in */
        "srli    a7, a1, 63\n\t"
        "slli    a1, a1, 1\n\t"
        "add     a1, a1, a6\n\t"
        "sltu    s1, a1, a6\n\t"
        "srli    a6, t4, 63\n\t"
        "slli    t4, t4, 1\n\t"
        "or      t4, t4, a7\n\t"
        "mul     a7, t1, t1\n\t"
        "mulhu   t1, t1, t1\n\t"
        "add     a7, a7, s1\n\t"
        "add     t4, t4, a7\n\t"
        "sltu    s1, t4, a7\n\t"
        "srli    a7, t5, 63\n\t"
        "slli    t5, t5, 1\n\t"
        "or      t5, t5, a6\n\t"
        "add     t1, t1, s1\n\t"
        "add     t5, t5, t1\n\t"
        "sltu    s1, t5, t1\n\t"
        "srli    a6, t6, 63\n\t"
        "slli    t6, t6, 1\n\t"
        "or      t6, t6, a7\n\t"
        "mul     a7, t2, t2\n\t"
        "mulhu   t2, t2, t2\n\t"
        "add     a7, a7, s1\n\t"
        "add     t6, t6, a7\n\t"
        "sltu    s1, t6, a7\n\t"
        "srli    a7, a3, 63\n\t"
        "slli    a3, a3, 1\n\t"
        "or      a3, a3, a6\n\t"
        "add     t2, t2, s1\n\t"
        "add     a3, a3, t2\n\t"
        "sltu    s1, a3, t2\n\t"
        "srli    a6, a4, 63\n\t"
        "slli    a4, a4, 1\n\t"
        "or      a4, a4, a7\n\t"
        "mul     a7, t3, t3\n\t"
        "mulhu   t3, t3, t3\n\t"
        "add     a7, a7, s1\n\t"
        "add     a4, a4, a7\n\t"
        "sltu    s1, a4, a7\n\t"
        "slli    a5, a5, 1\n\t"
        "or      a5, a5, a6\n\t"
        "add     t3, t3, s1\n\t"
        "add     a5, a5, t3\n\t"
        /* Reduce in place - multiply-free, see mont_red_sm2_shift */
        "li      s6, 0\n\t"
        "slli    s2, t0, 32\n\t"
        "srli    s3, t0, 32\n\t"
        "sltu    s1, zero, t0\n\t"
        "mv      s5, s1\n\t"
        "sltu    a6, t0, s2\n\t"
        "sub     s4, t0, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a1, a1, s4\n\t"
        "sltu    a6, a1, s4\n\t"
        "add     a1, a1, s1\n\t"
        "sltu    a7, a1, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    a6, t4, s4\n\t"
        "add     t4, t4, s1\n\t"
        "sltu    a7, t4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    a6, t5, s4\n\t"
        "add     t5, t5, s1\n\t"
        "sltu    a7, t5, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sub     s4, t0, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        "add     t6, t6, s6\n\t"
        "sltu    a7, t6, s6\n\t"
        "add     s6, s1, a7\n\t"
        "slli    s2, a1, 32\n\t"
        "srli    s3, a1, 32\n\t"
        "sltu    s1, zero, a1\n\t"
        "mv      s5, s1\n\t"
        "sltu    a6, a1, s2\n\t"
        "sub     s4, a1, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    a6, t4, s4\n\t"
        "add     t4, t4, s1\n\t"
        "sltu    a7, t4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    a6, t5, s4\n\t"
        "add     t5, t5, s1\n\t"
        "sltu    a7, t5, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sub     s4, a1, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     a3, a3, s4\n\t"
        "sltu    a6, a3, s4\n\t"
        "add     a3, a3, s1\n\t"
        "sltu    a7, a3, s1\n\t"
        "or      s1, a6, a7\n\t"
        "add     a3, a3, s6\n\t"
        "sltu    a7, a3, s6\n\t"
        "add     s6, s1, a7\n\t"
        "slli    s2, t4, 32\n\t"
        "srli    s3, t4, 32\n\t"
        "sltu    s1, zero, t4\n\t"
        "mv      s5, s1\n\t"
        "sltu    a6, t4, s2\n\t"
        "sub     s4, t4, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    a6, t5, s4\n\t"
        "add     t5, t5, s1\n\t"
        "sltu    a7, t5, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a3, a3, s4\n\t"
        "sltu    a6, a3, s4\n\t"
        "add     a3, a3, s1\n\t"
        "sltu    a7, a3, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sub     s4, t4, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     a4, a4, s4\n\t"
        "sltu    a6, a4, s4\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    a7, a4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "add     a4, a4, s6\n\t"
        "sltu    a7, a4, s6\n\t"
        "add     s6, s1, a7\n\t"
        "slli    s2, t5, 32\n\t"
        "srli    s3, t5, 32\n\t"
        "sltu    s1, zero, t5\n\t"
        "mv      s5, s1\n\t"
        "sltu    a6, t5, s2\n\t"
        "sub     s4, t5, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    a6, t6, s4\n\t"
        "add     t6, t6, s1\n\t"
        "sltu    a7, t6, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s3\n\t"
        "sub     s4, zero, s3\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a3, a3, s4\n\t"
        "sltu    a6, a3, s4\n\t"
        "add     a3, a3, s1\n\t"
        "sltu    a7, a3, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sltu    a6, zero, s2\n\t"
        "sub     s4, zero, s2\n\t"
        "sltu    a7, s4, s5\n\t"
        "sub     s4, s4, s5\n\t"
        "or      s5, a6, a7\n\t"
        "add     a4, a4, s4\n\t"
        "sltu    a6, a4, s4\n\t"
        "add     a4, a4, s1\n\t"
        "sltu    a7, a4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sub     s4, t5, s3\n\t"
        "sub     s4, s4, s5\n\t"
        "add     a5, a5, s4\n\t"
        "sltu    a6, a5, s4\n\t"
        "add     a5, a5, s1\n\t"
        "sltu    a7, a5, s1\n\t"
        "or      s1, a6, a7\n\t"
        "add     a5, a5, s6\n\t"
        "sltu    a7, a5, s6\n\t"
        "add     s6, s1, a7\n\t"
        /* Subtract the modulus when the accumulation overflowed */
        "sub     s2, zero, s6\n\t"
        "li      s1, 0\n\t"
        "ld      s3, 0(%[m])\n\t"
        "and     s3, s3, s2\n\t"
        "sltu    a6, t6, s3\n\t"
        "sub     s4, t6, s3\n\t"
        "sltu    a7, s4, s1\n\t"
        "sub     s4, s4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sd      s4, 0(%[r])\n\t"
        "ld      s3, 8(%[m])\n\t"
        "and     s3, s3, s2\n\t"
        "sltu    a6, a3, s3\n\t"
        "sub     s4, a3, s3\n\t"
        "sltu    a7, s4, s1\n\t"
        "sub     s4, s4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sd      s4, 8(%[r])\n\t"
        "ld      s3, 16(%[m])\n\t"
        "and     s3, s3, s2\n\t"
        "sltu    a6, a4, s3\n\t"
        "sub     s4, a4, s3\n\t"
        "sltu    a7, s4, s1\n\t"
        "sub     s4, s4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sd      s4, 16(%[r])\n\t"
        "ld      s3, 24(%[m])\n\t"
        "and     s3, s3, s2\n\t"
        "sltu    a6, a5, s3\n\t"
        "sub     s4, a5, s3\n\t"
        "sltu    a7, s4, s1\n\t"
        "sub     s4, s4, s1\n\t"
        "or      s1, a6, a7\n\t"
        "sd      s4, 24(%[r])\n\t"
        : [r] "+r" (r), [a] "+r" (a), [m] "+r" (m), [mp] "+r" (mp)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a4", "a5", "a6",
            "a7", "s1", "s2", "s3", "s4", "s5", "s6"
    );
}

#if !defined(WOLFSSL_SP_SMALL)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * @param [out] r   Result of squaring.
 * @param [in]  a   Number to square in Montgomery form.
 * @param [in]  n   Number of times to square.
 * @param [in]  m   Modulus (prime).
 * @param [in]  mp  Montgomery multiplier.
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
 * @param [in] a  Array of sp_digit to normalize.
 */
#define sp_256_norm_4(a)

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * @param [in, out] a   A single precision number to reduce in place.
 * @param [in]      m   The single precision number representing the modulus.
 * @param [in]      mp  The digit representing the negative inverse of
 *                      m mod 2^n.
 */
static SP_NOINLINE void sp_256_mont_reduce_sm2_4(sp_digit* a, const sp_digit* m,
    sp_digit mp)
{
    __asm__ __volatile__ (
        /* Load the value to reduce */
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 24(%[a])\n\t"
        "ld      t4, 32(%[a])\n\t"
        "ld      t5, 40(%[a])\n\t"
        "ld      t6, 48(%[a])\n\t"
        "ld      a3, 56(%[a])\n\t"
        "li      s3, 0\n\t"
        /* mu = t[0] (mp == 1); A = mu << 32, B = mu >> 32 */
        "mv      a4, t0\n\t"
        "slli    a5, a4, 32\n\t"
        "srli    a6, a4, 32\n\t"
        /* Word 0: -mu cancels t[0] exactly; keep only the carry */
        "sltu    s2, zero, a4\n\t"
        "mv      s1, s2\n\t"
        /* Word 1: mu - A */
        "sltu    s4, a4, a5\n\t"
        "sub     a7, a4, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t1, t1, a7\n\t"
        "sltu    s4, t1, a7\n\t"
        "add     t1, t1, s2\n\t"
        "sltu    s5, t1, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 2: -B */
        "sltu    s4, zero, a6\n\t"
        "sub     a7, zero, a6\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t2, t2, a7\n\t"
        "sltu    s4, t2, a7\n\t"
        "add     t2, t2, s2\n\t"
        "sltu    s5, t2, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 3: -A */
        "sltu    s4, zero, a5\n\t"
        "sub     a7, zero, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t3, t3, a7\n\t"
        "sltu    s4, t3, a7\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s5, t3, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 4: mu - B, the top word of mu*m - cannot borrow out */
        "sub     a7, a4, a6\n\t"
        "sub     a7, a7, s1\n\t"
        "add     t4, t4, a7\n\t"
        "sltu    s4, t4, a7\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s5, t4, s2\n\t"
        "or      s2, s4, s5\n\t"
        "add     t4, t4, s3\n\t"
        "sltu    s5, t4, s3\n\t"
        "add     s3, s2, s5\n\t"
        /* mu = t[1] (mp == 1); A = mu << 32, B = mu >> 32 */
        "mv      a4, t1\n\t"
        "slli    a5, a4, 32\n\t"
        "srli    a6, a4, 32\n\t"
        /* Word 1: -mu cancels t[1] exactly; keep only the carry */
        "sltu    s2, zero, a4\n\t"
        "mv      s1, s2\n\t"
        /* Word 2: mu - A */
        "sltu    s4, a4, a5\n\t"
        "sub     a7, a4, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t2, t2, a7\n\t"
        "sltu    s4, t2, a7\n\t"
        "add     t2, t2, s2\n\t"
        "sltu    s5, t2, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 3: -B */
        "sltu    s4, zero, a6\n\t"
        "sub     a7, zero, a6\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t3, t3, a7\n\t"
        "sltu    s4, t3, a7\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s5, t3, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 4: -A */
        "sltu    s4, zero, a5\n\t"
        "sub     a7, zero, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t4, t4, a7\n\t"
        "sltu    s4, t4, a7\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s5, t4, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 5: mu - B, the top word of mu*m - cannot borrow out */
        "sub     a7, a4, a6\n\t"
        "sub     a7, a7, s1\n\t"
        "add     t5, t5, a7\n\t"
        "sltu    s4, t5, a7\n\t"
        "add     t5, t5, s2\n\t"
        "sltu    s5, t5, s2\n\t"
        "or      s2, s4, s5\n\t"
        "add     t5, t5, s3\n\t"
        "sltu    s5, t5, s3\n\t"
        "add     s3, s2, s5\n\t"
        /* mu = t[2] (mp == 1); A = mu << 32, B = mu >> 32 */
        "mv      a4, t2\n\t"
        "slli    a5, a4, 32\n\t"
        "srli    a6, a4, 32\n\t"
        /* Word 2: -mu cancels t[2] exactly; keep only the carry */
        "sltu    s2, zero, a4\n\t"
        "mv      s1, s2\n\t"
        /* Word 3: mu - A */
        "sltu    s4, a4, a5\n\t"
        "sub     a7, a4, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t3, t3, a7\n\t"
        "sltu    s4, t3, a7\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s5, t3, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 4: -B */
        "sltu    s4, zero, a6\n\t"
        "sub     a7, zero, a6\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t4, t4, a7\n\t"
        "sltu    s4, t4, a7\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s5, t4, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 5: -A */
        "sltu    s4, zero, a5\n\t"
        "sub     a7, zero, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t5, t5, a7\n\t"
        "sltu    s4, t5, a7\n\t"
        "add     t5, t5, s2\n\t"
        "sltu    s5, t5, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 6: mu - B, the top word of mu*m - cannot borrow out */
        "sub     a7, a4, a6\n\t"
        "sub     a7, a7, s1\n\t"
        "add     t6, t6, a7\n\t"
        "sltu    s4, t6, a7\n\t"
        "add     t6, t6, s2\n\t"
        "sltu    s5, t6, s2\n\t"
        "or      s2, s4, s5\n\t"
        "add     t6, t6, s3\n\t"
        "sltu    s5, t6, s3\n\t"
        "add     s3, s2, s5\n\t"
        /* mu = t[3] (mp == 1); A = mu << 32, B = mu >> 32 */
        "mv      a4, t3\n\t"
        "slli    a5, a4, 32\n\t"
        "srli    a6, a4, 32\n\t"
        /* Word 3: -mu cancels t[3] exactly; keep only the carry */
        "sltu    s2, zero, a4\n\t"
        "mv      s1, s2\n\t"
        /* Word 4: mu - A */
        "sltu    s4, a4, a5\n\t"
        "sub     a7, a4, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t4, t4, a7\n\t"
        "sltu    s4, t4, a7\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s5, t4, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 5: -B */
        "sltu    s4, zero, a6\n\t"
        "sub     a7, zero, a6\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t5, t5, a7\n\t"
        "sltu    s4, t5, a7\n\t"
        "add     t5, t5, s2\n\t"
        "sltu    s5, t5, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 6: -A */
        "sltu    s4, zero, a5\n\t"
        "sub     a7, zero, a5\n\t"
        "sltu    s5, a7, s1\n\t"
        "sub     a7, a7, s1\n\t"
        "or      s1, s4, s5\n\t"
        "add     t6, t6, a7\n\t"
        "sltu    s4, t6, a7\n\t"
        "add     t6, t6, s2\n\t"
        "sltu    s5, t6, s2\n\t"
        "or      s2, s4, s5\n\t"
        /* Word 7: mu - B, the top word of mu*m - cannot borrow out */
        "sub     a7, a4, a6\n\t"
        "sub     a7, a7, s1\n\t"
        "add     a3, a3, a7\n\t"
        "sltu    s4, a3, a7\n\t"
        "add     a3, a3, s2\n\t"
        "sltu    s5, a3, s2\n\t"
        "or      s2, s4, s5\n\t"
        "add     a3, a3, s3\n\t"
        "sltu    s5, a3, s3\n\t"
        "add     s3, s2, s5\n\t"
        /* Subtract the modulus when the accumulation overflowed */
        "sub     a4, zero, s3\n\t"
        "li      s2, 0\n\t"
        "ld      a6, 0(%[m])\n\t"
        "and     a6, a6, a4\n\t"
        "sltu    s4, t4, a6\n\t"
        "sub     a7, t4, a6\n\t"
        "sltu    s5, a7, s2\n\t"
        "sub     a7, a7, s2\n\t"
        "or      s2, s4, s5\n\t"
        "sd      a7, 0(%[a])\n\t"
        "ld      a6, 8(%[m])\n\t"
        "and     a6, a6, a4\n\t"
        "sltu    s4, t5, a6\n\t"
        "sub     a7, t5, a6\n\t"
        "sltu    s5, a7, s2\n\t"
        "sub     a7, a7, s2\n\t"
        "or      s2, s4, s5\n\t"
        "sd      a7, 8(%[a])\n\t"
        "ld      a6, 16(%[m])\n\t"
        "and     a6, a6, a4\n\t"
        "sltu    s4, t6, a6\n\t"
        "sub     a7, t6, a6\n\t"
        "sltu    s5, a7, s2\n\t"
        "sub     a7, a7, s2\n\t"
        "or      s2, s4, s5\n\t"
        "sd      a7, 16(%[a])\n\t"
        "ld      a6, 24(%[m])\n\t"
        "and     a6, a6, a4\n\t"
        "sltu    s4, a3, a6\n\t"
        "sub     a7, a3, a6\n\t"
        "sltu    s5, a7, s2\n\t"
        "sub     a7, a7, s2\n\t"
        "or      s2, s4, s5\n\t"
        "sd      a7, 24(%[a])\n\t"
        : [a] "+r" (a), [m] "+r" (m), [mp] "+r" (mp)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a3", "a4", "a5",
            "a6", "a7", "s1", "s2", "s3", "s4", "s5"
    );
}

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * @param [in, out] a   A single precision number to reduce in place.
 * @param [in]      m   The single precision number representing the modulus.
 * @param [in]      mp  The digit representing the negative inverse of
 *                      m mod 2^n.
 */
static SP_NOINLINE void sp_256_mont_reduce_order_sm2_4(sp_digit* a_p,
    const sp_digit* m_p, sp_digit mp_p)
{
    register sp_digit* a __asm__ ("a0") = (sp_digit*)a_p;
    register const sp_digit* m __asm__ ("a1") = (const sp_digit*)m_p;
    register sp_digit mp __asm__ ("a2") = (sp_digit)mp_p;

    __asm__ __volatile__ (
        /* Load the value to reduce */
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 16(%[a])\n\t"
        "ld      t3, 24(%[a])\n\t"
        "ld      t4, 32(%[a])\n\t"
        "ld      t5, 40(%[a])\n\t"
        "ld      t6, 48(%[a])\n\t"
        "ld      a3, 56(%[a])\n\t"
        /* Load the modulus - the pointer is dead once it is in registers */
        "ld      a4, 0(%[m])\n\t"
        "ld      a5, 8(%[m])\n\t"
        "ld      a6, 16(%[m])\n\t"
        "ld      a7, 24(%[m])\n\t"
        "li      s3, 0\n\t"
        "mul     s1, t0, %[mp]\n\t"
        "li      s2, 0\n\t"
        "mul     s4, s1, a4\n\t"
        "mulhu   s5, s1, a4\n\t"
        "add     t0, t0, s4\n\t"
        "sltu    s6, t0, s4\n\t"
        "add     t0, t0, s2\n\t"
        "sltu    s7, t0, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a5\n\t"
        "mulhu   s5, s1, a5\n\t"
        "add     t1, t1, s4\n\t"
        "sltu    s6, t1, s4\n\t"
        "add     t1, t1, s2\n\t"
        "sltu    s7, t1, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a6\n\t"
        "mulhu   s5, s1, a6\n\t"
        "add     t2, t2, s4\n\t"
        "sltu    s6, t2, s4\n\t"
        "add     t2, t2, s2\n\t"
        "sltu    s7, t2, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a7\n\t"
        "mulhu   s5, s1, a7\n\t"
        "add     t3, t3, s4\n\t"
        "sltu    s6, t3, s4\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s7, t3, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s6, t4, s2\n\t"
        "add     t4, t4, s3\n\t"
        "sltu    s7, t4, s3\n\t"
        "add     s3, s6, s7\n\t"
        "mul     s1, t1, %[mp]\n\t"
        "li      s2, 0\n\t"
        "mul     s4, s1, a4\n\t"
        "mulhu   s5, s1, a4\n\t"
        "add     t1, t1, s4\n\t"
        "sltu    s6, t1, s4\n\t"
        "add     t1, t1, s2\n\t"
        "sltu    s7, t1, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a5\n\t"
        "mulhu   s5, s1, a5\n\t"
        "add     t2, t2, s4\n\t"
        "sltu    s6, t2, s4\n\t"
        "add     t2, t2, s2\n\t"
        "sltu    s7, t2, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a6\n\t"
        "mulhu   s5, s1, a6\n\t"
        "add     t3, t3, s4\n\t"
        "sltu    s6, t3, s4\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s7, t3, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a7\n\t"
        "mulhu   s5, s1, a7\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    s6, t4, s4\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s7, t4, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "add     t5, t5, s2\n\t"
        "sltu    s6, t5, s2\n\t"
        "add     t5, t5, s3\n\t"
        "sltu    s7, t5, s3\n\t"
        "add     s3, s6, s7\n\t"
        "mul     s1, t2, %[mp]\n\t"
        "li      s2, 0\n\t"
        "mul     s4, s1, a4\n\t"
        "mulhu   s5, s1, a4\n\t"
        "add     t2, t2, s4\n\t"
        "sltu    s6, t2, s4\n\t"
        "add     t2, t2, s2\n\t"
        "sltu    s7, t2, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a5\n\t"
        "mulhu   s5, s1, a5\n\t"
        "add     t3, t3, s4\n\t"
        "sltu    s6, t3, s4\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s7, t3, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a6\n\t"
        "mulhu   s5, s1, a6\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    s6, t4, s4\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s7, t4, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a7\n\t"
        "mulhu   s5, s1, a7\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    s6, t5, s4\n\t"
        "add     t5, t5, s2\n\t"
        "sltu    s7, t5, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "add     t6, t6, s2\n\t"
        "sltu    s6, t6, s2\n\t"
        "add     t6, t6, s3\n\t"
        "sltu    s7, t6, s3\n\t"
        "add     s3, s6, s7\n\t"
        "mul     s1, t3, %[mp]\n\t"
        "li      s2, 0\n\t"
        "mul     s4, s1, a4\n\t"
        "mulhu   s5, s1, a4\n\t"
        "add     t3, t3, s4\n\t"
        "sltu    s6, t3, s4\n\t"
        "add     t3, t3, s2\n\t"
        "sltu    s7, t3, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a5\n\t"
        "mulhu   s5, s1, a5\n\t"
        "add     t4, t4, s4\n\t"
        "sltu    s6, t4, s4\n\t"
        "add     t4, t4, s2\n\t"
        "sltu    s7, t4, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a6\n\t"
        "mulhu   s5, s1, a6\n\t"
        "add     t5, t5, s4\n\t"
        "sltu    s6, t5, s4\n\t"
        "add     t5, t5, s2\n\t"
        "sltu    s7, t5, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "mul     s4, s1, a7\n\t"
        "mulhu   s5, s1, a7\n\t"
        "add     t6, t6, s4\n\t"
        "sltu    s6, t6, s4\n\t"
        "add     t6, t6, s2\n\t"
        "sltu    s7, t6, s2\n\t"
        "add     s2, s5, s6\n\t"
        "add     s2, s2, s7\n\t"
        "add     a3, a3, s2\n\t"
        "sltu    s6, a3, s2\n\t"
        "add     a3, a3, s3\n\t"
        "sltu    s7, a3, s3\n\t"
        "add     s3, s6, s7\n\t"
        /* Subtract the modulus when the accumulation overflowed */
        "sub     s1, zero, s3\n\t"
        "li      s2, 0\n\t"
        "and     s5, a4, s1\n\t"
        "sltu    s6, t4, s5\n\t"
        "sub     s4, t4, s5\n\t"
        "sltu    s7, s4, s2\n\t"
        "sub     s4, s4, s2\n\t"
        "or      s2, s6, s7\n\t"
        "sd      s4, 0(%[a])\n\t"
        "and     s5, a5, s1\n\t"
        "sltu    s6, t5, s5\n\t"
        "sub     s4, t5, s5\n\t"
        "sltu    s7, s4, s2\n\t"
        "sub     s4, s4, s2\n\t"
        "or      s2, s6, s7\n\t"
        "sd      s4, 8(%[a])\n\t"
        "and     s5, a6, s1\n\t"
        "sltu    s6, t6, s5\n\t"
        "sub     s4, t6, s5\n\t"
        "sltu    s7, s4, s2\n\t"
        "sub     s4, s4, s2\n\t"
        "or      s2, s6, s7\n\t"
        "sd      s4, 16(%[a])\n\t"
        "and     s5, a7, s1\n\t"
        "sltu    s6, a3, s5\n\t"
        "sub     s4, a3, s5\n\t"
        "sltu    s7, s4, s2\n\t"
        "sub     s4, s4, s2\n\t"
        "or      s2, s6, s7\n\t"
        "sd      s4, 24(%[a])\n\t"
        : [a] "+r" (a), [m] "+r" (m), [mp] "+r" (mp)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a3", "a4", "a5",
            "a6", "a7", "s1", "s2", "s3", "s4", "s5", "s6", "s7"
    );
}

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * @param [out] r  Resulting affine coordinate point.
 * @param [in]  p  Montgomery form projective coordinate point.
 * @param [out] t  Temporary ordinate data.
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

/* Add two Montgomery form numbers (r = a + b % m).
 *
 * @param [out] r  Result of addition.
 * @param [in]  a  First number to add in Montgomery form.
 * @param [in]  b  Second number to add in Montgomery form.
 * @param [in]  m  Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_add_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* b, const sp_digit* m)
{
    sp_digit o;

    o = sp_256_add_sm2_4(r, a, b);
    sp_256_cond_sub_sm2_4(r, r, m, 0 - o);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * @param [out] r  Result of doubling.
 * @param [in]  a  Number to double in Montgomery form.
 * @param [in]  m  Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_dbl_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* m)
{
    sp_digit o;

    o = sp_256_add_sm2_4(r, a, a);
    sp_256_cond_sub_sm2_4(r, r, m, 0 - o);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * @param [out] r  Result of tripling.
 * @param [in]  a  Number to triple in Montgomery form.
 * @param [in]  m  Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_tpl_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* m)
{
    sp_digit o;

    o = sp_256_add_sm2_4(r, a, a);
    sp_256_cond_sub_sm2_4(r, r, m, 0 - o);
    o = sp_256_add_sm2_4(r, r, a);
    sp_256_cond_sub_sm2_4(r, r, m, 0 - o);
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * @param [out] r  A single precision number representing conditional add
 *                 result.
 * @param [in]  a  A single precision number to add with.
 * @param [in]  b  A single precision number to add.
 * @param [in]  m  Mask value to apply.
 */
static sp_digit sp_256_cond_add_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* b, sp_digit m)
{
    __asm__ __volatile__ (
        "ld      t1, 0(%[a])\n\t"
        "ld      t2, 0(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t0, t3, t1\n\t"
        "sd      t3, 0(%[r])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "ld      t2, 8(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t4, t3, t1\n\t"
        "add     t3, t3, t0\n\t"
        "sltu    t0, t3, t0\n\t"
        "or      t0, t0, t4\n\t"
        "sd      t3, 8(%[r])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "ld      t2, 16(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t4, t3, t1\n\t"
        "add     t3, t3, t0\n\t"
        "sltu    t0, t3, t0\n\t"
        "or      t0, t0, t4\n\t"
        "sd      t3, 16(%[r])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "ld      t2, 24(%[b])\n\t"
        "and     t2, t2, %[m]\n\t"
        "add     t3, t1, t2\n\t"
        "sltu    t4, t3, t1\n\t"
        "add     t3, t3, t0\n\t"
        "sltu    t0, t3, t0\n\t"
        "or      t0, t0, t4\n\t"
        "sd      t3, 24(%[r])\n\t"
        "mv      %[r], t0\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b), [m] "+r" (m)
        :
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );
    return (word64)(size_t)r;
}

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * @param [out] r  Result of subtration.
 * @param [in]  a  Number to subtract from in Montgomery form.
 * @param [in]  b  Number to subtract with in Montgomery form.
 * @param [in]  m  Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_sub_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* b, const sp_digit* m)
{
    sp_digit o;

    o = sp_256_sub_sm2_4(r, a, b);
    sp_256_cond_add_sm2_4(r, r, m, o);
}

/* Shift number right one bit.
 * Bottom bit is lost.
 *
 * @param [out] r  Result of shift.
 * @param [in]  a  Number to shift.
 */
static void sp_256_rshift1_sm2_4(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "ld      t0, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "srli    t2, t0, 1\n\t"
        "slli    t1, t1, 63\n\t"
        "or      t2, t2, t1\n\t"
        "sd      t2, 0(%[r])\n\t"
        "ld      t0, 8(%[a])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "srli    t2, t0, 1\n\t"
        "slli    t1, t1, 63\n\t"
        "or      t2, t2, t1\n\t"
        "sd      t2, 8(%[r])\n\t"
        "ld      t0, 16(%[a])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "srli    t2, t0, 1\n\t"
        "slli    t1, t1, 63\n\t"
        "or      t2, t2, t1\n\t"
        "sd      t2, 16(%[r])\n\t"
        "ld      t0, 24(%[a])\n\t"
        "srli    t2, t0, 1\n\t"
        "sd      t2, 24(%[r])\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "t0", "t1", "t2"
    );
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * @param [out] r  Result of division by 2.
 * @param [in]  a  Number to divide.
 * @param [in]  m  Modulus (prime).
 */
SP_NOINLINE static void sp_256_mont_div2_sm2_4(sp_digit* r, const sp_digit* a,
    const sp_digit* m)
{
    sp_digit o;

    o = sp_256_cond_add_sm2_4(r, a, m, 0 - (a[0] & 1));
    sp_256_rshift1_sm2_4(r, r);
    r[3] |= o << 63;
}

/* Double the Montgomery form projective point p.
 *
 * @param [out] r  Result of doubling point.
 * @param [in]  p  Point to double.
 * @param [out] t  Temporary ordinate data.
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
    /* X = X - Y */
    sp_256_mont_sub_sm2_4(x, x, y, p256_sm2_mod);
    /* X = X - Y */
    sp_256_mont_sub_sm2_4(x, x, y, p256_sm2_mod);
    /* Y = Y - X */
    sp_256_mont_sub_sm2_4(y, y, x, p256_sm2_mod);
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
 * Non-blocking version.  Call repeatedly until it does not return
 * FP_WOULDBLOCK.  State is saved and restored through sp_ctx.
 *
 * @param [in, out] sp_ctx  Context to save state in for non-blocking calls.
 * @param [out]     r       Result of doubling point.
 * @param [in]      p       Point to double.
 * @param [out]     t       Temporary ordinate data.
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
        /* X = X - Y */
        sp_256_mont_sub_sm2_4(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 15;
        break;
    case 15:
        /* X = X - Y */
        sp_256_mont_sub_sm2_4(ctx->x, ctx->x, ctx->y, p256_sm2_mod);
        ctx->state = 16;
        break;
    case 16:
        /* Y = Y - X */
        sp_256_mont_sub_sm2_4(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
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
        FALL_THROUGH;
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
 * @param [in] a  First number to compare.
 * @param [in] b  Second number to compare.
 *
 * @return  1 when equal and 0 otherwise.
 */
static int sp_256_cmp_equal_4(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
            (a[3] ^ b[3])) == 0;
}

/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * @param [in] a  Number to check.
 *
 * @return  1 when the number is zero and 0 otherwise.
 */
static int sp_256_iszero_4(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}


/* Add two Montgomery form projective points.
 *
 * @param [out] r  Result of addition.
 * @param [in]  p  First point to add.
 * @param [in]  q  Second point to add.
 * @param [out] t  Temporary ordinate data.
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
        sp_256_mont_dbl_sm2_4(t3, y, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(x, x, t3, p256_sm2_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_4(y, y, x, p256_sm2_mod);
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
 * Non-blocking version.  Call repeatedly until it does not return
 * FP_WOULDBLOCK.  State is saved and restored through sp_ctx.
 *
 * @param [in, out] sp_ctx  Context to save state in for non-blocking calls.
 * @param [out]     r       Result of addition.
 * @param [in]      p       First point to add.
 * @param [in]      q       Second point to add.
 * @param [out]     t       Temporary ordinate data.
 */
static int sp_256_proj_point_add_sm2_4_nb(sp_ecc_ctx_t* sp_ctx, sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    int err = FP_WOULDBLOCK;
    sp_256_proj_point_add_4_ctx* ctx = (sp_256_proj_point_add_sm2_4_ctx*)sp_ctx->data;

    typedef char ctx_size_test[sizeof(sp_256_proj_point_add_4_ctx) >= sizeof(*sp_ctx) ? -1 : 1];
    (void)sizeof(ctx_size_test);

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_256* a = p;
        p = q;
        q = a;
    }

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
        sp_256_mont_dbl_sm2_4(ctx->t3, ctx->y, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(ctx->x, ctx->x, ctx->t3, p256_sm2_mod);
        ctx->state = 21;
        break;
    case 21:
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_sm2_4(ctx->y, ctx->y, ctx->x, p256_sm2_mod);
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

#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible point that could be being copied.
 *
 * @param [out] r      Point to copy into.
 * @param [in]  table  Table - start of the entries to access
 * @param [in]  idx    Index of entry to retrieve.
 */
static void sp_256_get_point_16_sm2_4(sp_point_256* r, const sp_point_256* table,
    int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    for (i = 1; i < 16; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
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
 * @param [out] r     Resulting point.
 * @param [in]  g     Point to multiply.
 * @param [in]  k     Scalar to multiply by.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  ct    Constant time required.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_fast_sm2_4(sp_point_256* r, const sp_point_256* g, const sp_digit* k,
        int map, int ct, void* heap)
{
    SP_DECL_VAR(sp_point_256, t, 16 + 1);
    SP_DECL_VAR(sp_digit, tmp, 2 * 4 * 6);
    sp_point_256* rt = NULL;
#ifndef WC_NO_CACHE_RESISTANT
    SP_DECL_VAR(sp_point_256, p, 1);
#endif /* !WC_NO_CACHE_RESISTANT */
    sp_digit n;
    int i;
    int c;
    int y;
    int err = MP_OKAY;

    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;

    SP_ALLOC_VAR(sp_point_256, t, 16 + 1, heap, DYNAMIC_TYPE_ECC);
#ifndef WC_NO_CACHE_RESISTANT
    SP_ALLOC_VAR(sp_point_256, p, 1, heap, DYNAMIC_TYPE_ECC);
#endif
    SP_ALLOC_VAR(sp_digit, tmp, 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);

    if (err == MP_OKAY) {
        rt = t + 16;

        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        (void)sp_256_mod_mul_norm_sm2_4(t[1].x, g->x, p256_sm2_mod);
        (void)sp_256_mod_mul_norm_sm2_4(t[1].y, g->y, p256_sm2_mod);
        (void)sp_256_mod_mul_norm_sm2_4(t[1].z, g->z, p256_sm2_mod);
        t[1].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[ 2], &t[ 1], tmp);
        t[ 2].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[ 3], &t[ 2], &t[ 1], tmp);
        t[ 3].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[ 4], &t[ 2], tmp);
        t[ 4].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[ 5], &t[ 3], &t[ 2], tmp);
        t[ 5].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[ 6], &t[ 3], tmp);
        t[ 6].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[ 7], &t[ 4], &t[ 3], tmp);
        t[ 7].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[ 8], &t[ 4], tmp);
        t[ 8].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[ 9], &t[ 5], &t[ 4], tmp);
        t[ 9].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[10], &t[ 5], tmp);
        t[10].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[11], &t[ 6], &t[ 5], tmp);
        t[11].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[12], &t[ 6], tmp);
        t[12].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[13], &t[ 7], &t[ 6], tmp);
        t[13].infinity = 0;
        sp_256_proj_point_dbl_sm2_4(&t[14], &t[ 7], tmp);
        t[14].infinity = 0;
        sp_256_proj_point_add_sm2_4(&t[15], &t[ 8], &t[ 7], tmp);
        t[15].infinity = 0;

        i = 2;
        n = (sp_uint64)k[i+1] << 0;
        c = 60;
        y = (int)(n >> 60);
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_point_16_sm2_4(rt, t, y);
            rt->infinity = !y;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[y], sizeof(sp_point_256));
        }
        n = (sp_uint64)n << (4);
        for (; i>=0 || c>=4; ) {
            if (c < 4) {
                n |= k[i--];
                c += 64;
            }
            y = (n >> 60) & 0xf;
            n = (sp_uint64)n << 4;
            c -= 4;

            sp_256_proj_point_dbl_sm2_4(rt, rt, tmp);
            sp_256_proj_point_dbl_sm2_4(rt, rt, tmp);
            sp_256_proj_point_dbl_sm2_4(rt, rt, tmp);
            sp_256_proj_point_dbl_sm2_4(rt, rt, tmp);

    #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_point_16_sm2_4(p, t, y);
                p->infinity = !y;
                sp_256_proj_point_add_sm2_4(rt, rt, p, tmp);
            }
            else
    #endif
            {
                sp_256_proj_point_add_sm2_4(rt, rt, &t[y], tmp);
            }
        }

        if (map != 0) {
            sp_256_map_sm2_4(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_256));
        }
    }

    SP_ZEROFREE_VAR(sp_digit, tmp, 2 * 4 * 6, heap,
        DYNAMIC_TYPE_ECC);
#ifndef WC_NO_CACHE_RESISTANT
    SP_ZEROFREE_VAR(sp_point_256, p, 1, heap, DYNAMIC_TYPE_ECC);
#endif /* !WC_NO_CACHE_RESISTANT */
    SP_ZEROFREE_VAR(sp_point_256, t, 16 + 1, heap, DYNAMIC_TYPE_ECC);

    return err;
}

#ifdef FP_ECC
/* Double the Montgomery form projective point p a number of times.
 *
 * @param [in, out] p  Point to double and result.
 * @param [in]      i  Number of times to double.
 * @param [out]     t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_sm2_4(sp_point_256* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*4;
    sp_digit* b = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* t2 = t + 8*4;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i - 1;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_256_mont_dbl_sm2_4(y, y, p256_sm2_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_sm2_4(w, z, p256_sm2_mod, p256_sm2_mp_mod);
    sp_256_mont_sqr_sm2_4(w, w, p256_sm2_mod, p256_sm2_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (n > 0)
#else
    while (n >= 0)
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
        sp_256_mont_dbl_sm2_4(t2, b, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(x, x, t2, p256_sm2_mod);
        /* B = 2.(B - X) */
        sp_256_mont_sub_sm2_4(t2, b, x, p256_sm2_mod);
        sp_256_mont_dbl_sm2_4(b, t2, p256_sm2_mod);
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
        n = n - 1;
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
    sp_256_mont_dbl_sm2_4(t2, b, p256_sm2_mod);
    sp_256_mont_sub_sm2_4(x, x, t2, p256_sm2_mod);
    /* B = 2.(B - X) */
    sp_256_mont_sub_sm2_4(t2, b, x, p256_sm2_mod);
    sp_256_mont_dbl_sm2_4(b, t2, p256_sm2_mod);
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

/* Convert the projective point to affine.
 * Ordinates are in Montgomery form.
 *
 * @param [in, out] a  Point to convert.
 * @param [out]     t  Temporary data.
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

#endif /* FP_ECC */
/* A table entry for pre-computed points. */
typedef struct sp_table_entry_256 {
    sp_digit x[4];
    sp_digit y[4];
} sp_table_entry_256;

#ifdef FP_ECC
#endif /* FP_ECC */
/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * @param [out] r  Result of addition.
 * @param [in]  p  First point to add.
 * @param [in]  q  Second point to add.
 * @param [out] t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_qz1_sm2_4(sp_point_256* r,
    const sp_point_256* p, const sp_point_256* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*4;
    sp_digit* t6 = t + 4*4;
    sp_digit* t1 = t + 6*4;
    sp_digit* t4 = t + 8*4;
    sp_digit* t5 = t + 10*4;

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
        sp_256_mont_dbl_sm2_4(t5, t3, p256_sm2_mod);
        sp_256_mont_sub_sm2_4(x, t2, t5, p256_sm2_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_sub_sm2_4(t3, t3, x, p256_sm2_mod);
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

#ifdef WOLFSSL_SP_SMALL
#ifdef FP_ECC
/* Generate the pre-computed table of points for the base point.
 *
 * width = 4
 * 16 entries
 * 64 bits between
 *
 * @param [in]  a      The base point.
 * @param [out] table  Place to store generated point data.
 * @param [out] tmp    Temporary data.
 * @param [in]  heap   Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_sm2_4(const sp_point_256* a,
        sp_table_entry_256* table, sp_digit* tmp, void* heap)
{
    SP_DECL_VAR(sp_point_256, t, 3);
    sp_point_256* s1 = NULL;
    sp_point_256* s2 = NULL;
    int i;
    int j;
    int err = MP_OKAY;

    (void)heap;

    SP_ALLOC_VAR(sp_point_256, t, 3, heap, DYNAMIC_TYPE_ECC);
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

        for (i=1; i<4; i++) {
            sp_256_proj_point_dbl_n_sm2_4(t, 64, tmp);
            sp_256_proj_to_affine_sm2_4(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<4; i++) {
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

    SP_FREE_VAR(t, heap, DYNAMIC_TYPE_ECC);

    return err;
}

#endif /* FP_ECC */
#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible entry that could be being copied.
 *
 * @param [out] r      Point to copy into.
 * @param [in]  table  Table - start of the entries to access
 * @param [in]  idx    Index of entry to retrieve.
 */
static void sp_256_get_entry_16_sm2_4(sp_point_256* r,
    const sp_table_entry_256* table, int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    for (i = 1; i < 16; i++) {
        sp_digit gte = (sp_digit)((((sp_uint64)i - (sp_uint64)idx) >> 63) - 1);
        sp_digit lte = (sp_digit)((((sp_uint64)idx - (sp_uint64)i) >> 63) - 1);
        mask = gte & lte;
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
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
 * @param [out] r      Resulting point.
 * @param [in]  g      Point to multiply.
 * @param [in]  table  Pre-computed table.
 * @param [in]  k      Scalar to multiply by.
 * @param [in]  map    Indicates whether to convert result to affine.
 * @param [in]  ct     Constant time required.
 * @param [in]  heap   Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_stripe_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
    SP_DECL_VAR(sp_point_256, rt, 2);
    SP_DECL_VAR(sp_digit, t, 2 * 4 * 6);
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


    SP_ALLOC_VAR(sp_point_256, rt, 2, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, t, 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        p = rt + 1;

        XMEMCPY(p->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        XMEMCPY(rt->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));

        y = 0;
        x = 63;
        for (j=0; j<4; j++) {
            y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
            x += 64;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_16_sm2_4(rt, table, y);
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
                y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
                x += 64;
            }

            sp_256_proj_point_dbl_sm2_4(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_16_sm2_4(p, table, y);
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

    SP_FREE_VAR(rt, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(t, heap, DYNAMIC_TYPE_ECC);

    return err;
}

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
    sp_table_entry_256 table[16];
    /* Count of entries in table. */
    word32 cnt;
    /* Point and table set in entry. */
    int set;
} sp_cache_256_t;

/* Cache of tables. */
static THREAD_LS_T sp_cache_256_t sp_cache_256[FP_ENTRIES];
/* Index of last entry in cache. */
static THREAD_LS_T int sp_cache_256_last = -1;
/* Cache has been initialized. */
static THREAD_LS_T int sp_cache_256_inited = 0;

#if !defined(SINGLE_THREADED) && !defined(HAVE_THREAD_LS)
    #ifndef WOLFSSL_MUTEX_INITIALIZER
    static wolfSSL_Atomic_Uint initCacheMutex_256 = 0;
    #endif
    static wolfSSL_Mutex sp_cache_256_lock WOLFSSL_MUTEX_INITIALIZER_CLAUSE(sp_cache_256_lock);
#endif

/* Get the cache entry for the point.
 *
 * @param [in]  g      Point scalar multiplying.
 * @param [out] cache  Cache table to use.
 */
static void sp_ecc_get_cache_256(const sp_point_256* g, sp_cache_256_t** cache)
{
    int i;
    int j;
    word32 least;

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
 * @param [out] r     Resulting point.
 * @param [in]  g     Point to multiply.
 * @param [in]  k     Scalar to multiply by.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  ct    Constant time required.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_fast_sm2_4(r, g, k, map, ct, heap);
#else
    SP_DECL_VAR(sp_digit, tmp, 2 * 4 * 6);
    sp_cache_256_t* cache;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_digit, tmp, 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);
#if !defined(SINGLE_THREADED) && !defined(HAVE_THREAD_LS)
    if (err == MP_OKAY) {
    #ifndef WOLFSSL_MUTEX_INITIALIZER
        /* Lazy initialization of mutex - one atomic with three states:
         *   0 = uninitialized, 1 = initialization in progress,
         *   2 = initialized.
         */
        if (WOLFSSL_ATOMIC_LOAD(initCacheMutex_256) != 2) {
            unsigned int expected_then_actual;

            for (;;) {
                expected_then_actual = 0;
                if (wolfSSL_Atomic_Uint_CompareExchange(
                        &initCacheMutex_256, &expected_then_actual,
                        1) == 1) {
                    /* Won race - initialize mutex. On failure, reset state
                     * to 0 so that a later call retries. */
                    err = wc_InitMutex(&sp_cache_256_lock);
                    WOLFSSL_ATOMIC_STORE(initCacheMutex_256,
                        (err == 0) ? 2U : 0U);
                    break;
                }
                if (expected_then_actual == 2) {
                    /* Another thread completed initialization. */
                    break;
                }
                /* Initialization in progress in another thread. */
                WC_RELAX_LONG_LOOP();
            }
        }
    #endif
        if ((err == MP_OKAY) && (wc_LockMutex(&sp_cache_256_lock) != 0)) {
            err = BAD_MUTEX_E;
        }
    }
#endif /* !SINGLE_THREADED && !HAVE_THREAD_LS */

    if (err == MP_OKAY) {
        sp_ecc_get_cache_256(g, &cache);
        if (cache->cnt == 2)
            sp_256_gen_stripe_table_sm2_4(g, cache->table, tmp, heap);

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_fast_sm2_4(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_4(r, g, cache->table, k,
                    map, ct, heap);
        }
#if !defined(SINGLE_THREADED) && !defined(HAVE_THREAD_LS)
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* !SINGLE_THREADED && !HAVE_THREAD_LS */
    }

    SP_FREE_VAR(tmp, heap, DYNAMIC_TYPE_ECC);
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
 * @param [in]  a      The base point.
 * @param [out] table  Place to store generated point data.
 * @param [out] tmp    Temporary data.
 * @param [in]  heap   Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_sm2_4(const sp_point_256* a,
        sp_table_entry_256* table, sp_digit* tmp, void* heap)
{
    SP_DECL_VAR(sp_point_256, t, 3);
    sp_point_256* s1 = NULL;
    sp_point_256* s2 = NULL;
    int i;
    int j;
    int err = MP_OKAY;

    (void)heap;

    SP_ALLOC_VAR(sp_point_256, t, 3, heap, DYNAMIC_TYPE_ECC);
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

        for (i=1; i<8; i++) {
            sp_256_proj_point_dbl_n_sm2_4(t, 32, tmp);
            sp_256_proj_to_affine_sm2_4(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
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

    SP_FREE_VAR(t, heap, DYNAMIC_TYPE_ECC);

    return err;
}

#endif /* FP_ECC */
#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible entry that could be being copied.
 *
 * @param [out] r      Point to copy into.
 * @param [in]  table  Table - start of the entries to access
 * @param [in]  idx    Index of entry to retrieve.
 */
static void sp_256_get_entry_256_sm2_4(sp_point_256* r,
    const sp_table_entry_256* table, int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    for (i = 1; i < 256; i++) {
        sp_digit gte = (sp_digit)((((sp_uint64)i - (sp_uint64)idx) >> 63) - 1);
        sp_digit lte = (sp_digit)((((sp_uint64)idx - (sp_uint64)i) >> 63) - 1);
        mask = gte & lte;
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
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
 * @param [out] r      Resulting point.
 * @param [in]  g      Point to multiply.
 * @param [in]  table  Pre-computed table.
 * @param [in]  k      Scalar to multiply by.
 * @param [in]  map    Indicates whether to convert result to affine.
 * @param [in]  ct     Constant time required.
 * @param [in]  heap   Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_stripe_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_table_entry_256* table, const sp_digit* k, int map,
        int ct, void* heap)
{
    SP_DECL_VAR(sp_point_256, rt, 2);
    SP_DECL_VAR(sp_digit, t, 2 * 4 * 6);
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


    SP_ALLOC_VAR(sp_point_256, rt, 2, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, t, 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        p = rt + 1;

        XMEMCPY(p->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));
        XMEMCPY(rt->z, p256_sm2_norm_mod, sizeof(p256_sm2_norm_mod));

        y = 0;
        x = 31;
        for (j=0; j<8; j++) {
            y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
            x += 32;
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_256_get_entry_256_sm2_4(rt, table, y);
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
                y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
                x += 32;
            }

            sp_256_proj_point_dbl_sm2_4(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_256_get_entry_256_sm2_4(p, table, y);
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

    SP_FREE_VAR(rt, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(t, heap, DYNAMIC_TYPE_ECC);

    return err;
}

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
    sp_table_entry_256 table[256];
    /* Count of entries in table. */
    word32 cnt;
    /* Point and table set in entry. */
    int set;
} sp_cache_256_t;

/* Cache of tables. */
static THREAD_LS_T sp_cache_256_t sp_cache_256[FP_ENTRIES];
/* Index of last entry in cache. */
static THREAD_LS_T int sp_cache_256_last = -1;
/* Cache has been initialized. */
static THREAD_LS_T int sp_cache_256_inited = 0;

#if !defined(SINGLE_THREADED) && !defined(HAVE_THREAD_LS)
    #ifndef WOLFSSL_MUTEX_INITIALIZER
    static wolfSSL_Atomic_Uint initCacheMutex_256 = 0;
    #endif
    static wolfSSL_Mutex sp_cache_256_lock WOLFSSL_MUTEX_INITIALIZER_CLAUSE(sp_cache_256_lock);
#endif

/* Get the cache entry for the point.
 *
 * @param [in]  g      Point scalar multiplying.
 * @param [out] cache  Cache table to use.
 */
static void sp_ecc_get_cache_256(const sp_point_256* g, sp_cache_256_t** cache)
{
    int i;
    int j;
    word32 least;

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
 * @param [out] r     Resulting point.
 * @param [in]  g     Point to multiply.
 * @param [in]  k     Scalar to multiply by.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  ct    Constant time required.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_sm2_4(sp_point_256* r, const sp_point_256* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_fast_sm2_4(r, g, k, map, ct, heap);
#else
    SP_DECL_VAR(sp_digit, tmp, 2 * 4 * 6);
    sp_cache_256_t* cache;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_digit, tmp, 2 * 4 * 6, heap, DYNAMIC_TYPE_ECC);
#if !defined(SINGLE_THREADED) && !defined(HAVE_THREAD_LS)
    if (err == MP_OKAY) {
    #ifndef WOLFSSL_MUTEX_INITIALIZER
        /* Lazy initialization of mutex - one atomic with three states:
         *   0 = uninitialized, 1 = initialization in progress,
         *   2 = initialized.
         */
        if (WOLFSSL_ATOMIC_LOAD(initCacheMutex_256) != 2) {
            unsigned int expected_then_actual;

            for (;;) {
                expected_then_actual = 0;
                if (wolfSSL_Atomic_Uint_CompareExchange(
                        &initCacheMutex_256, &expected_then_actual,
                        1) == 1) {
                    /* Won race - initialize mutex. On failure, reset state
                     * to 0 so that a later call retries. */
                    err = wc_InitMutex(&sp_cache_256_lock);
                    WOLFSSL_ATOMIC_STORE(initCacheMutex_256,
                        (err == 0) ? 2U : 0U);
                    break;
                }
                if (expected_then_actual == 2) {
                    /* Another thread completed initialization. */
                    break;
                }
                /* Initialization in progress in another thread. */
                WC_RELAX_LONG_LOOP();
            }
        }
    #endif
        if ((err == MP_OKAY) && (wc_LockMutex(&sp_cache_256_lock) != 0)) {
            err = BAD_MUTEX_E;
        }
    }
#endif /* !SINGLE_THREADED && !HAVE_THREAD_LS */

    if (err == MP_OKAY) {
        sp_ecc_get_cache_256(g, &cache);
        if (cache->cnt == 2)
            sp_256_gen_stripe_table_sm2_4(g, cache->table, tmp, heap);

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_fast_sm2_4(r, g, k, map, ct, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_sm2_4(r, g, cache->table, k,
                    map, ct, heap);
        }
#if !defined(SINGLE_THREADED) && !defined(HAVE_THREAD_LS)
        wc_UnLockMutex(&sp_cache_256_lock);
#endif /* !SINGLE_THREADED && !HAVE_THREAD_LS */
    }

    SP_FREE_VAR(tmp, heap, DYNAMIC_TYPE_ECC);
    return err;
#endif
}

#endif /* WOLFSSL_SP_SMALL */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * @param [in]  km    Scalar to multiply by.
 * @param [in]  gm    Point to multiply.
 * @param [out] r     Resulting point.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
int sp_ecc_mulmod_sm2_256(const mp_int* km, const ecc_point* gm, ecc_point* r,
        int map, void* heap)
{
    SP_DECL_VAR(sp_point_256, point, 1);
    SP_DECL_VAR(sp_digit, k, 4);
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_point_256, point, 1, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, k, 4, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_256_from_mp(k, 4, km);
        sp_256_point_from_ecc_point_4(point, gm);

            err = sp_256_ecc_mulmod_sm2_4(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_4(point, r);
    }

    SP_FREE_VAR(k, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(point, heap, DYNAMIC_TYPE_ECC);

    return err;
}

/* Multiply the point by the scalar, add point a and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * @param [in]  km      Scalar to multiply by.
 * @param [in]  gm      Point to multiply.
 * @param [in]  am      Point to add to scalar multiply result.
 * @param [in]  inMont  Point to add is in montgomery form.
 * @param [out] r       Resulting point.
 * @param [in]  map     Indicates whether to convert result to affine.
 * @param [in]  heap    Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
int sp_ecc_mulmod_add_sm2_256(const mp_int* km, const ecc_point* gm,
    const ecc_point* am, int inMont, ecc_point* r, int map, void* heap)
{
    SP_DECL_VAR(sp_point_256, point, 2);
    SP_DECL_VAR(sp_digit, k, 4 + 4 * 2 * 6);
    sp_point_256* addP = NULL;
    sp_digit* tmp = NULL;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_point_256, point, 2, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, k, 4 + 4 * 2 * 6, heap, DYNAMIC_TYPE_ECC);
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
            err = sp_256_ecc_mulmod_sm2_4(point, point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_4(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_4(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_4(point, r);
    }

    SP_FREE_VAR(k, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(point, heap, DYNAMIC_TYPE_ECC);

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Striping precomputation table.
 * 4 points combined into a table of 16 points.
 * Distance of 64 between points.
 */
static const sp_table_entry_256 p256_sm2_table[16] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x61328990f418029eL,0x3e7981eddca6c050L,0xd6a1ed99ac24c3c3L,
        0x91167a5ee1c13b05L },
      { 0xc1354e593c2d0dddL,0xc1f5e5788d3295faL,0x8d4cfb066e2a48f8L,
        0x63cd65d481d735bdL } },
    /* 2 */
    { { 0x4b33e020bad830d2L,0x5c101f9e590dffb3L,0xcd0e0498bc80ecb0L,
        0x302787f852aa293eL },
      { 0xbfd64ced220f8fc8L,0xcf5cebe0be0ee377L,0xdc03a0388913b128L,
        0x4b096971fde23279L } },
    /* 3 */
    { { 0xb4ee84e239a0d9dcL,0xf7d229cc061edfa5L,0x9765b24bd4cf33d0L,
        0x511c69f113329f59L },
      { 0x41095bb7a07ae316L,0x3a4650f1387f0e5aL,0x4624421c99827e4aL,
        0x7b1e814404b4243aL } },
    /* 4 */
    { { 0x7b9f561a8a914b50L,0x2bf7130e9154d377L,0x6800f696519b4c35L,
        0xc9e65040568b4c56L },
      { 0x30706e006d98a331L,0x781a12f6e211ce1eL,0x1fff9e3d40562e5fL,
        0x6356cf468c166747L } },
    /* 5 */
    { { 0x96c4e4f3897518d9L,0x3825d80c66f75b0dL,0xfa0bd6c007f7ceb5L,
        0x5c01af69a303ef24L },
      { 0xdd75cf9e6bfcbc92L,0x8bfe4a53248dceaeL,0x519362c695373421L,
        0x6f350880168ccb86L } },
    /* 6 */
    { { 0xfa95c510cf13b772L,0xa9b3fc90d95aca7cL,0x8e6e77904cb1a435L,
        0x840b63d98754e6a0L },
      { 0xcfa6798133196bd2L,0x15ab0561ef85911fL,0x504d9402fbd94af6L,
        0x063173d3fcc90fb5L } },
    /* 7 */
    { { 0x6d58e50e11fa5996L,0x5a7db9bacce6427bL,0x7d30d5aa95291d18L,
        0x9e69e861cd354763L },
      { 0x2d0cbca9706bd6f9L,0x63cc64b0af3bda5fL,0x09cc5dbf06d6cc0dL,
        0x533ba1aa81e50b6bL } },
    /* 8 */
    { { 0xfb3992a4202bde39L,0x2549f5643d6bab98L,0x0b56464287712512L,
        0xd52442b47fde7e50L },
      { 0xa6cefd08a3d3e16eL,0x5b194f0ac83b29bdL,0x6db0edd8906dec8cL,
        0x7a09095902570c1eL } },
    /* 9 */
    { { 0x04d6ce6dbfab3d26L,0xf2aa223b668edf18L,0xeb899557f06250baL,
        0xef6bba074940d66dL },
      { 0xb483763bb78ca345L,0x15867b4f3f08ff72L,0x91225b725bca92b2L,
        0xccead663498804dbL } },
    /* 10 */
    { { 0xd7aef5e8487bdc21L,0x626fbd75858c0310L,0x8cd9250d08d1054fL,
        0x25a65ab1d0831265L },
      { 0x4d0ac007fec04e2cL,0x859f43558ddf0f4cL,0xb1d58e0b031dd8a0L,
        0x9df8ab409618799dL } },
    /* 11 */
    { { 0x4cfcca5543d44adfL,0x6ed6f6956bf2e90eL,0xff878d621f8b275dL,
        0x4ac00774846471f5L },
      { 0xe8f08905d59b5eaaL,0xf961eb4fc904e73aL,0x512829438419c14cL,
        0x591e7dcf94e41d6eL } },
    /* 12 */
    { { 0x7254de6e805f0ed8L,0xe0ad1d7905ad4708L,0xf3212455a339058eL,
        0xf176c2f9834b8957L },
      { 0x6a42a6929162ff84L,0x7af37ab5eaa628e8L,0xe6605aa80da655e1L,
        0x840eabd99bce77b6L } },
    /* 13 */
    { { 0x15e2a820b891bf80L,0xf218d7d63dcfd53cL,0x0b3fbb91c354f5d6L,
        0xd2907e2060ec6c0bL },
      { 0x2ba584dd4a8c701aL,0x1edfa8b29f829e57L,0x482e8e37f33ce835L,
        0x4f8b758175b06197L } },
    /* 14 */
    { { 0xc1f039f848e761abL,0xb75d923ca4db0990L,0xfe8fffc185ba216cL,
        0x5f193c8764667cdcL },
      { 0xdce2f35c78ed1f3cL,0x82cbb59e77a90887L,0x0c6bb634521fca71L,
        0xbf0b44e88d79141fL } },
    /* 15 */
    { { 0xc424f15dc6fe11e5L,0x1e866a4919a25ef3L,0x419ace92dbb31334L,
        0x1bd3b4412408a903L },
      { 0x1bb62300cad2225bL,0x44db4cabcf204b84L,0x9fcf0afacd229aa6L,
        0x38d13bedcc492384L } },
};

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^64, ...
 * Pre-generated: products of all combinations of above.
 * 4 doubles and adds (with qz=1)
 *
 * @param [out] r     Resulting point.
 * @param [in]  k     Scalar to multiply by.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  ct    Constant time required.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_base_sm2_4(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_4(r, &p256_sm2_base, p256_sm2_table,
                                      k, map, ct, heap);
}

#else
/* Striping precomputation table.
 * 8 points combined into a table of 256 points.
 * Distance of 32 between points.
 */
static const sp_table_entry_256 p256_sm2_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x61328990f418029eL,0x3e7981eddca6c050L,0xd6a1ed99ac24c3c3L,
        0x91167a5ee1c13b05L },
      { 0xc1354e593c2d0dddL,0xc1f5e5788d3295faL,0x8d4cfb066e2a48f8L,
        0x63cd65d481d735bdL } },
    /* 2 */
    { { 0xecb8f92d0cf4efe5L,0x88c47214960e2d22L,0xca9549ef6059f079L,
        0xd0a3774a7016da7cL },
      { 0xd51c95f61d001cabL,0x2d744defa3feeec1L,0xb7c20cc20afedf2bL,
        0xbf16c5f171d144a5L } },
    /* 3 */
    { { 0x6684ea0bad9c635eL,0x48a44a5685246e15L,0x16926cc456bb6373L,
        0xb9966ebd43efef8eL },
      { 0xace57f14350e7f7dL,0x5c026c95a25bdfd6L,0xf30be3759ed4a592L,
        0x74dde4e551234a24L } },
    /* 4 */
    { { 0x4b33e020bad830d2L,0x5c101f9e590dffb3L,0xcd0e0498bc80ecb0L,
        0x302787f852aa293eL },
      { 0xbfd64ced220f8fc8L,0xcf5cebe0be0ee377L,0xdc03a0388913b128L,
        0x4b096971fde23279L } },
    /* 5 */
    { { 0xb4ee84e239a0d9dcL,0xf7d229cc061edfa5L,0x9765b24bd4cf33d0L,
        0x511c69f113329f59L },
      { 0x41095bb7a07ae316L,0x3a4650f1387f0e5aL,0x4624421c99827e4aL,
        0x7b1e814404b4243aL } },
    /* 6 */
    { { 0x5de17662f8f2bc34L,0x88408716171ae6a1L,0xc65b64704c7cbaa0L,
        0xb56909fcbdce2e60L },
      { 0x465dcb393e73ddb0L,0x5cca771f5d5e0850L,0x96fe1e1486717cfbL,
        0xfda13692c1dcd4fbL } },
    /* 7 */
    { { 0xd50c47aa043f38e8L,0x5397eb9159faf190L,0xa9d1027eb03d00cbL,
        0x1d04d612a59a818fL },
      { 0x59cddc860328d2b3L,0x06f881e887d68132L,0x42914fc4bf180493L,
        0xd6a600a80820fcbeL } },
    /* 8 */
    { { 0x4599b8941abd31f0L,0xdb34198d9a1da7d3L,0xa8b89523a0f0217dL,
        0x2014cc43e56b884eL },
      { 0x6fb94f8849efd4eeL,0xf1b81710287f4ae0L,0x89d38a9a99fd2debL,
        0x8179277a72b67a53L } },
    /* 9 */
    { { 0xa752f1958e4b53dfL,0x15b855b98bc1f19cL,0xd3bcd58fb75b2028L,
        0x3e7e284149b7651bL },
      { 0x69a8e4cb0b47b1aaL,0xc3b27c7b9750b86aL,0x65dc9f783f1415edL,
        0xbaab4dbc468ba56aL } },
    /* 10 */
    { { 0x33fe09badf4f7cb3L,0xbedb981553cfe07aL,0x35e0c4fa586f167dL,
        0xdd4c37c90821eb4cL },
      { 0x2365240ca0e9402aL,0x694b03627f049720L,0x1c60260d9b7723d8L,
        0xe488f0af52f8e305L } },
    /* 11 */
    { { 0x7bb89930eec04411L,0xd659c71a15b89af4L,0xbe21fc69b64883ceL,
        0xfcdd9de002ad1648L },
      { 0x072b555d799d29feL,0x2c517a58971489efL,0xdbdcc979f45a0f68L,
        0xb268b83f3cd08b95L } },
    /* 12 */
    { { 0x676c104936aed763L,0x8c871299d4a079beL,0xdfafad16da194f33L,
        0x2ab29161c5d4925cL },
      { 0x2264761c1970c4f8L,0xc768d9348312b03aL,0x187f20505b580022L,
        0x16406b19d13363c0L } },
    /* 13 */
    { { 0x534a8d428f11a1b7L,0x938477f1deee83a5L,0xd77237f6f25c6bd3L,
        0x46ef139540e6ca87L },
      { 0x0830e76079dbd954L,0xe22981b6a3a9aa6dL,0x07719e76cc1aa064L,
        0x6c909a3ad044478cL } },
    /* 14 */
    { { 0x3cd09dbd3ab4c047L,0x8c857820c51725ddL,0xa0cefbac818a00d8L,
        0x6bf4b678d93d5fedL },
      { 0xb7b8b7649c1c77f8L,0xd3c82db53bb210aeL,0x27f5ec7519f40ce0L,
        0x1c742c6d60a39f9cL } },
    /* 15 */
    { { 0x7923d806608acdd0L,0x119764c54dbe6185L,0x5828494044c14789L,
        0xba5f5971ebe015b9L },
      { 0x1bc235a273d216f3L,0x99624ba00360f260L,0x4c8b3eefc1aaed49L,
        0xa302e8b77cde415aL } },
    /* 16 */
    { { 0x7b9f561a8a914b50L,0x2bf7130e9154d377L,0x6800f696519b4c35L,
        0xc9e65040568b4c56L },
      { 0x30706e006d98a331L,0x781a12f6e211ce1eL,0x1fff9e3d40562e5fL,
        0x6356cf468c166747L } },
    /* 17 */
    { { 0x96c4e4f3897518d9L,0x3825d80c66f75b0dL,0xfa0bd6c007f7ceb5L,
        0x5c01af69a303ef24L },
      { 0xdd75cf9e6bfcbc92L,0x8bfe4a53248dceaeL,0x519362c695373421L,
        0x6f350880168ccb86L } },
    /* 18 */
    { { 0xe61cabbf442e4248L,0x24194cea5ee1ab7aL,0x21b5f5319bacbbb0L,
        0x7d554b80abc8abdeL },
      { 0xaeb6a6127268ca65L,0x3c6f7c15fe9b7a84L,0x5be8a9ff63559133L,
        0x9d17778c11efe081L } },
    /* 19 */
    { { 0x65f2b7532d347f7fL,0x2f70c2b33a25167aL,0xad9c7fb5eafb45acL,
        0x9fcd997c1c3961beL },
      { 0x25b72ce3337ca7ddL,0x255e90d55a88b6bdL,0x7b1d4dc838834ffeL,
        0x0cb91039f241c0dbL } },
    /* 20 */
    { { 0xfa95c510cf13b772L,0xa9b3fc90d95aca7cL,0x8e6e77904cb1a435L,
        0x840b63d98754e6a0L },
      { 0xcfa6798133196bd2L,0x15ab0561ef85911fL,0x504d9402fbd94af6L,
        0x063173d3fcc90fb5L } },
    /* 21 */
    { { 0x6d58e50e11fa5996L,0x5a7db9bacce6427bL,0x7d30d5aa95291d18L,
        0x9e69e861cd354763L },
      { 0x2d0cbca9706bd6f9L,0x63cc64b0af3bda5fL,0x09cc5dbf06d6cc0dL,
        0x533ba1aa81e50b6bL } },
    /* 22 */
    { { 0xa5f72c2425a4c565L,0xc864130ad3f80897L,0x40f41882fb50c4d9L,
        0x499c14995551ed50L },
      { 0x32404d8861ee4b05L,0x4a3f1953d2729befL,0xff878e9aedbfb28bL,
        0xca18c856e81b4decL } },
    /* 23 */
    { { 0x8ca4c14e1b87826eL,0xe4b2b873ce8326daL,0x5e0b6c47b0192797L,
        0xa95e1b9ebed322e4L },
      { 0x94bba8c04f98438bL,0x8e5301b76afd2a09L,0xe12fa56a9a746186L,
        0x31b5268e3aa68ad0L } },
    /* 24 */
    { { 0x2f67b871e0b8f9c6L,0x101bde96e6ce880fL,0x07f08fb22d8b362fL,
        0xe8cfc6413f1daf42L },
      { 0xe088324668742a60L,0xeb54979da244b370L,0x34cd326d02887b39L,
        0x68fd6b647fe7906eL } },
    /* 25 */
    { { 0x47c921740774bf91L,0x6879e68290aaeb2eL,0xd66bc8cf289b5af5L,
        0xdc9ead3435d21c7dL },
      { 0xe55439d95400fd22L,0xb4d1200a6df86577L,0x79f852715cd5bfedL,
        0xf1e74dd8a33fd89eL } },
    /* 26 */
    { { 0x5d1de7878eadd7c7L,0x26883aae6c9cf945L,0xf4c8d3ee469c63d2L,
        0x7e163562549fe13bL },
      { 0x6c24e7f88a1e5a2dL,0x7f5550a5bf1a43d2L,0xc3fc954ef268f8ddL,
        0x2b0d677191f23634L } },
    /* 27 */
    { { 0xff22a87bbaef1d85L,0xcf774cf7ac4393acL,0x1cdda137574b1d81L,
        0xcda8f0dbc004fd6aL },
      { 0x711e9d096a5c7738L,0x7189aaabfca4584fL,0xeb8edd2715b9c75cL,
        0x0532d2b778db0ed1L } },
    /* 28 */
    { { 0x46c2fd017e93d304L,0x6df3f991b6455b42L,0xad3fff985a3146ebL,
        0x9dbadcfac12c3c15L },
      { 0x87a15d6248adf57dL,0x9c0ee760e7f0ad3eL,0x7ddcf16ff115bb26L,
        0xee787b98877423fcL } },
    /* 29 */
    { { 0xcfd9c9cda35b2fe6L,0xc46ffcfa58c7b139L,0xdbafc8738f28ce21L,
        0x4798d018e79837dfL },
      { 0x5bbe3e66adf63b8cL,0xbc5d673efd7aa8feL,0x0e5bb7fb133e5359L,
        0x645aa53c9dab3fc8L } },
    /* 30 */
    { { 0x84e4b573d26b8292L,0x0d52bf00343e5186L,0x783f1d8cb574a3b6L,
        0xdbe3f8ecd76a9e25L },
      { 0xd57dce0399b642b8L,0x5113181a770f5a79L,0x2b59683ecdafa422L,
        0x9a73de8a61a0aea7L } },
    /* 31 */
    { { 0x1367e4a267ef03fcL,0x5b1dd688421bbfd0L,0xa6789acb8e233f88L,
        0xbcc0ad09b9050c32L },
      { 0xcd5e81a82256ea88L,0x2c801344c2083a41L,0x02992221030d6300L,
        0x561e593522ac59e7L } },
    /* 32 */
    { { 0x11cf4c2e24424a48L,0x843c73ee37d4471cL,0xb3047fc5617a488bL,
        0xf2a91709e3cf861cL },
      { 0x844444211c3a60f7L,0x74787a3626679148L,0x115fbd0653d9404bL,
        0x70fd33656244cef0L } },
    /* 33 */
    { { 0x825ad1a91350a8acL,0xa9527d4455da889eL,0xa957f05c84df2c5eL,
        0x5061719a9ff131fcL },
      { 0xecdda998a296a530L,0x4f5af589df7b5a9fL,0xc2d1d040c84869a1L,
        0x8401cc8a6417fd96L } },
    /* 34 */
    { { 0xc89b8d3129853c8cL,0x54dec3995864b1c5L,0x32c4b3a4f2c2b191L,
        0x4b4b9beef08412b7L },
      { 0x1a7cee6a97ac6061L,0x73038ff35b2c2c33L,0xa11ffda5a903a0f6L,
        0xd8a0fa39ec43aa54L } },
    /* 35 */
    { { 0x7f2ca2f3b6c18ad6L,0xfc2c34c4757eed8fL,0xbdbf5e28aadaca59L,
        0x979a3f6a6fac786fL },
      { 0xe7df10cc50a130bcL,0x6a3f62db4323bd8dL,0xfc590a108d207c46L,
        0x66a7b0592e98c829L } },
    /* 36 */
    { { 0x96b69debdff39f50L,0x2a3d865f4ebcd6d4L,0x6ffadbd9823455cbL,
        0xb1f617cd764ffb30L },
      { 0x01ed713ce8cb5759L,0x31c4b25c09a6e01aL,0x3a4272ec77d99e5eL,
        0x49ee3010f4661c86L } },
    /* 37 */
    { { 0x4b4671bb612270deL,0x0cc60112ddf060caL,0xd6fb85003aee95ddL,
        0x120d05eec2448f2dL },
      { 0xacb713421070c2baL,0x6eb1f7592ac04adbL,0x6f41914b05519c65L,
        0xaf69c4193b4a997eL } },
    /* 38 */
    { { 0xcad8c59ac4b11a5bL,0x05d6894257bdb1fdL,0x22d7b638db66574dL,
        0xd060d0a930dfab7cL },
      { 0x5edc0102e0c8e41dL,0xe47182934a22e5c2L,0x9d5a138cd280fd21L,
        0xe47ed3fcdfd6b471L } },
    /* 39 */
    { { 0x5f0fe174ce30e491L,0xb664382e4081468aL,0x8e14c7145ae38ff1L,
        0x21b63d385ea3103fL },
      { 0xafa86cca312036e2L,0x1fbf7bb422b39fe3L,0x59f85460ee1061f2L,
        0x86565def28092e57L } },
    /* 40 */
    { { 0x593a7870a2d0b7ffL,0x286a76e560786676L,0x00016a4a14e51639L,
        0x176e05d81ba83628L },
      { 0x86eb39caccd7f1c9L,0x89dbbf0e32f77ef2L,0x7e6ff400c7fa33f0L,
        0x1a174b70406df605L } },
    /* 41 */
    { { 0x78ac0d1a4d69fcdeL,0x5aedf5e6910960adL,0x67103e7992339353L,
        0x0adf982c391534e1L },
      { 0xe98fd8b7dbf326a6L,0x3f71664f530e4fa6L,0x7772c027d05ba2a9L,
        0x5ecf1ee5db678aa1L } },
    /* 42 */
    { { 0x3ae88e90924bd676L,0xc7e2a6145ddf5faaL,0x0c01b5a7ff44bde9L,
        0x9b16db80f664d896L },
      { 0xd7f4bb3c5c63dee2L,0x1e57e0cf013c90b9L,0xe6a403dcd59a92edL,
        0x901515084c61c564L } },
    /* 43 */
    { { 0xc0736835222ca5cbL,0x4b7bbc44528a8c2bL,0xf2e9a9b59091a70eL,
        0x02bdce5aca8c8302L },
      { 0x3290d35a0c61cf3dL,0x13e152c43401929eL,0xacb5ad500264664fL,
        0xc8f83b90947dea41L } },
    /* 44 */
    { { 0x797529972325b5b4L,0xda8348e5dc8f28b8L,0xf8bbb6ff4c23c663L,
        0x6a8708872182c92cL },
      { 0xf145c17db800dd46L,0x5eaac8723f52f048L,0xda05888a5859b9fcL,
        0x3a66e9ca888790beL } },
    /* 45 */
    { { 0x774596be59f902b6L,0xc6eb3cf31c4919f3L,0x9e379b34457c9558L,
        0x3c86aee9554ccc9cL },
      { 0x3fb79ed8d9efa09aL,0x1098633eb1a68c0dL,0x6e8bb88e6b7fd4c8L,
        0x0a7fccc0a4c7dab8L } },
    /* 46 */
    { { 0x20538c6d3309ddffL,0x80206f3a0ea5b0f2L,0x333fba72b7910256L,
        0xf80eb58aab78861bL },
      { 0x58a07ab3b58fc705L,0x043d1acbfb3578ffL,0xcb923accf7eb90f5L,
        0x251a6cf81cb26eebL } },
    /* 47 */
    { { 0xb58affe3850afc51L,0xdc8a487efb637b74L,0x946c07b357fe16b9L,
        0x2483b8808d8272faL },
      { 0xc402687a1c79f6acL,0x90ef68aab9468ce8L,0x077aacb67a8e900fL,
        0x47e3cd8e0a82e5eeL } },
    /* 48 */
    { { 0x015385c647c08a1aL,0x928d3e73b0a4c2b7L,0x95f60e9ca745f557L,
        0x6584670ea969f6baL },
      { 0xc0d92f36190948d2L,0x9d79c98debbe384dL,0x6bcc8320971fa585L,
        0x7793c29636f0ceafL } },
    /* 49 */
    { { 0xf055669b6d970f51L,0xe83b3c598d88c22dL,0x624f33f09685ba68L,
        0x9a1653a54a34d05eL },
      { 0x4e89dd5bfe134e8cL,0x9cda5eedafd7e22bL,0x49d8322bf2866223L,
        0x1b43287c8a8abfe8L } },
    /* 50 */
    { { 0xcddc091fdaef42deL,0x6c11309743e9d6baL,0x3b8b170680a805afL,
        0x82209792ada919f3L },
      { 0x3204559f99d0b57aL,0x6c27cac3b3befc8cL,0xa6378ef40abe5d44L,
        0x1afa934b85374d49L } },
    /* 51 */
    { { 0xf3c2400473c2d262L,0x3a9f060dc41da1fbL,0x44a96fffeb52f63bL,
        0xa466df13601e3c94L },
      { 0x09ae8d8b24901485L,0xcaf436b3d80ac885L,0xca82f159050ed93fL,
        0x4be695fe908c085eL } },
    /* 52 */
    { { 0xfe2e00fa344fdb3eL,0x5604750dabeb75b9L,0xe9eba9b07f7ef79bL,
        0x2ac3e192f574a15dL },
      { 0x98b0dd56a5cde112L,0xddbf00ed93f7eddaL,0xb27f899ec533a370L,
        0x2002df2f81609f90L } },
    /* 53 */
    { { 0x74455f35bc8978a6L,0x1d50cccea66eb954L,0xdfa4cbd89c4d0818L,
        0xb52e8f303511ff8eL },
      { 0xe6cf2b7fa2efeb7aL,0x5822341e5d526232L,0x0e06413bd59b88e4L,
        0xcf119b2bfaa28034L } },
    /* 54 */
    { { 0x5492280a789f943cL,0xfd788b4b71d42ef1L,0x5a521b47d0dfdfc9L,
        0x9bd24038af6d1a20L },
      { 0x7adad554df050a75L,0x72f639f20353da85L,0x58658887988e6b4bL,
        0x6ff2c2be2e9d0b65L } },
    /* 55 */
    { { 0x51822eb47aff0b43L,0x9f92df895a15a720L,0xe368c22132b4b00aL,
        0x036951e3140ced6bL },
      { 0x8f15ea3565bea331L,0xbf0324bb3ce5c920L,0xda95e3bfc8884ef7L,
        0xd72c7e1327c9bcbfL } },
    /* 56 */
    { { 0x7f01fa97eeee6b16L,0xcce129d040ed83fcL,0xc93919f13fce79a6L,
        0x8dafd0de96e09e84L },
      { 0xd65d9049fc60c529L,0x5843b71055fdb769L,0xa6f973e6a1a2cfd1L,
        0x9f0dcab7970fa22dL } },
    /* 57 */
    { { 0xf9020cfd728aadf3L,0x376d8f28c070b46fL,0x24a02f3131f9a432L,
        0xa9a6c13f4c77bb48L },
      { 0xe4de5c45ab369b55L,0x6cc8cb044f5ac90dL,0x131852e17c80e815L,
        0x8504f3550f679300L } },
    /* 58 */
    { { 0xb4d3fbe53a22cc5dL,0x612067c7daa6bdccL,0x2919eb5b6301480fL,
        0x4238725e6f5bafaeL },
      { 0x25af69a2d8ae2dfeL,0x992c6c3f3dedbd09L,0x232e6f43a4ffcf12L,
        0xe0ff26347b9206d5L } },
    /* 59 */
    { { 0x23398e1c5f6a97ebL,0xfeec3b49a12e0bc9L,0x2db029d0c1afaf63L,
        0xcaf10eeef6b1ad9dL },
      { 0x87154e4da8f02497L,0xae1a98e1712c4b88L,0xf627d2414ebe9643L,
        0xca4c47ed2861505fL } },
    /* 60 */
    { { 0x35ff1959cee1f8dfL,0xfae13dc3eba36ac5L,0x5a426de78f4a0d4aL,
        0x5019e48a606db796L },
      { 0xdc8141321628aa47L,0x75ff85705a5e065dL,0x898919888065b511L,
        0x7880810a513cc426L } },
    /* 61 */
    { { 0xb6dc4dc0ab8bbe28L,0x5dbe49e50846ba34L,0x1abeba8ce93bfba7L,
        0x71c0d8d2aa1021ffL },
      { 0xce2cc527bba1651dL,0xd328e4c8183a2ae4L,0x7836996d6c221e0aL,
        0x1a3181c9758e1436L } },
    /* 62 */
    { { 0x7bc381f19224e28eL,0x8b125f05366bb0d8L,0xcfefc04f7e8cafd8L,
        0x5bd73477063afd7cL },
      { 0xccd169ab0a245316L,0xac7c88329104f04fL,0xb1a611643ac7762fL,
        0x4c80bb71f0b315d8L } },
    /* 63 */
    { { 0x07c7831a63b9249eL,0xe5e0f45bbbbda95eL,0x9d1b6c0fdf4517e8L,
        0xd01cde0669bd1d79L },
      { 0x36dd69a7ea498130L,0xdaa651938451ab5eL,0x88a3cdede4ad3dedL,
        0x32c2a71bffc9f1b0L } },
    /* 64 */
    { { 0xfb3992a4202bde39L,0x2549f5643d6bab98L,0x0b56464287712512L,
        0xd52442b47fde7e50L },
      { 0xa6cefd08a3d3e16eL,0x5b194f0ac83b29bdL,0x6db0edd8906dec8cL,
        0x7a09095902570c1eL } },
    /* 65 */
    { { 0x04d6ce6dbfab3d26L,0xf2aa223b668edf18L,0xeb899557f06250baL,
        0xef6bba074940d66dL },
      { 0xb483763bb78ca345L,0x15867b4f3f08ff72L,0x91225b725bca92b2L,
        0xccead663498804dbL } },
    /* 66 */
    { { 0x233c13fb58d49df0L,0x3d25550f5003f43dL,0xf6f920a28472130fL,
        0x3b9507a3142c3defL },
      { 0x8108608f697ac7d4L,0xfe1cfd90bb84db98L,0xcf2ac224d61853b9L,
        0xac6fe44c6ae3b38cL } },
    /* 67 */
    { { 0x9b4d14a7a42c8ed7L,0x1ec02af9c988a847L,0x3a6fcf6e33dca61fL,
        0x31d28b0072852f91L },
      { 0xcc689bf66eefcf6aL,0x835e6f24c1c5002cL,0x716fa507636c179fL,
        0x2ec87a6a62bb7883L } },
    /* 68 */
    { { 0xd7aef5e8487bdc21L,0x626fbd75858c0310L,0x8cd9250d08d1054fL,
        0x25a65ab1d0831265L },
      { 0x4d0ac007fec04e2cL,0x859f43558ddf0f4cL,0xb1d58e0b031dd8a0L,
        0x9df8ab409618799dL } },
    /* 69 */
    { { 0x4cfcca5543d44adfL,0x6ed6f6956bf2e90eL,0xff878d621f8b275dL,
        0x4ac00774846471f5L },
      { 0xe8f08905d59b5eaaL,0xf961eb4fc904e73aL,0x512829438419c14cL,
        0x591e7dcf94e41d6eL } },
    /* 70 */
    { { 0xdcd90e7ff2bad284L,0x6a6b30f3855fe1aaL,0x8561f9048c15c1e8L,
        0x3e06e03174d14887L },
      { 0x777a67b2e6db2203L,0x58db5e94d2e66bd5L,0x28df0d59b65cf7b0L,
        0x2dab3a07c6260357L } },
    /* 71 */
    { { 0xcf33c73cd2792b23L,0x1f2cfc954a6613a4L,0x1174a86ac22cb6f3L,
        0x4ae01cb017f30cbaL },
      { 0x8b07c15ebad7d330L,0x53295cb43b414fc5L,0x555022e19201c68eL,
        0x07bce7c292ad8ccfL } },
    /* 72 */
    { { 0x955fec91cf71938fL,0x6176f0443cc010dbL,0x5cbfa71cd5c81390L,
        0x78040891724141faL },
      { 0x9d20f9f24211fcc4L,0xf5a0c96869d45611L,0xfbafd81b93bb5005L,
        0x7b9d8d7b0e95095cL } },
    /* 73 */
    { { 0x3ba07473565cb6c4L,0xf2fc43137f738e87L,0x0edefd71893003e9L,
        0xce96d07bce48b45bL },
      { 0x9d181f9645a3e43eL,0x4d1c0992e6e75f80L,0x3651ec38ecf10babL,
        0x60fa83fc179d4a8bL } },
    /* 74 */
    { { 0x965fea09db2f8c7cL,0xc0541081f767bafdL,0x67da4ff02c0c2017L,
        0x472c556ae428da08L },
      { 0xb85cb20a7c717933L,0x88d4477c0dddf8a0L,0xc36017df88b0ba37L,
        0x3412b1362c6162d5L } },
    /* 75 */
    { { 0x602133f07a26cf67L,0x231fa3450f3ed6c4L,0xa8183f392f7819beL,
        0xf403ddb0cc40e1b9L },
      { 0x623111d8fd14746eL,0x4ed1d1b7fc2a4978L,0x4bc2ae2e50bde2beL,
        0x42cc90f7dd66148dL } },
    /* 76 */
    { { 0x2ce4232d5471c5c7L,0x90c84c6f35c69a9dL,0x57b5a756efed117eL,
        0x89a7a62adee73305L },
      { 0x1e9e8ce21e5add63L,0x47e20b3f977005b0L,0xde442f5df61dc977L,
        0xe8222d95dafd1699L } },
    /* 77 */
    { { 0x13f16ab6fb21173fL,0x7d65056213b23320L,0xfd35f369803dc588L,
        0x1ff1996ab6c26025L },
      { 0x5932441c7e49ae4bL,0xe58d8cadc1d4d2b3L,0xfc26aeae701f9a86L,
        0xf3043fe53826d2cbL } },
    /* 78 */
    { { 0xd27c6070beb74735L,0x662f49623b016809L,0xf2f821c4ffffa491L,
        0xe80d0d2a8de08a68L },
      { 0x064783785152be84L,0xe65b70a64d940804L,0x5b390ac93f729581L,
        0xb39a11e413b0a068L } },
    /* 79 */
    { { 0xbe943e88edc47a03L,0xdb0400448163d1ebL,0x7673179c402cfc25L,
        0xa7842fb6858ea0adL },
      { 0x69497369c3a823a2L,0x8af3d54febda0548L,0x8975de556b2363f4L,
        0x5e931dec707aa586L } },
    /* 80 */
    { { 0x7254de6e805f0ed8L,0xe0ad1d7905ad4708L,0xf3212455a339058eL,
        0xf176c2f9834b8957L },
      { 0x6a42a6929162ff84L,0x7af37ab5eaa628e8L,0xe6605aa80da655e1L,
        0x840eabd99bce77b6L } },
    /* 81 */
    { { 0x15e2a820b891bf80L,0xf218d7d63dcfd53cL,0x0b3fbb91c354f5d6L,
        0xd2907e2060ec6c0bL },
      { 0x2ba584dd4a8c701aL,0x1edfa8b29f829e57L,0x482e8e37f33ce835L,
        0x4f8b758175b06197L } },
    /* 82 */
    { { 0x2be95107bfbe555aL,0x9b76fb7e77b3851cL,0xbeb03148318b7f27L,
        0x425194eb80fde126L },
      { 0x489a386a2996474bL,0x318df1afcd1ed314L,0xe01451dc807c380cL,
        0xc0dfbdab2a38be26L } },
    /* 83 */
    { { 0xcc5a05bc4043ce80L,0x4101c7dc28e09c50L,0xcec16f691ab5ee6bL,
        0x6e0539e03f02fbecL },
      { 0xdc36e66a57b36485L,0x07d55262e5c8d145L,0xae754a39104068afL,
        0xc47aefb71c470491L } },
    /* 84 */
    { { 0xc1f039f848e761abL,0xb75d923ca4db0990L,0xfe8fffc185ba216cL,
        0x5f193c8764667cdcL },
      { 0xdce2f35c78ed1f3cL,0x82cbb59e77a90887L,0x0c6bb634521fca71L,
        0xbf0b44e88d79141fL } },
    /* 85 */
    { { 0xc424f15dc6fe11e5L,0x1e866a4919a25ef3L,0x419ace92dbb31334L,
        0x1bd3b4412408a903L },
      { 0x1bb62300cad2225bL,0x44db4cabcf204b84L,0x9fcf0afacd229aa6L,
        0x38d13bedcc492384L } },
    /* 86 */
    { { 0x7bd9a1145e4fb378L,0x56be5ae6a1c8e94dL,0x9322de412fa18b0aL,
        0x983fb47e5aaf8696L },
      { 0xd32e624928cde8eaL,0xc235267d2bf0d003L,0xfbc55e890571b4e8L,
        0xd119056fbd605049L } },
    /* 87 */
    { { 0x9b16c659e5729482L,0x4b02be67f29b3b86L,0x36702e4bceedf6f3L,
        0xf518950b6c023e01L },
      { 0xb2b536f0c01c7886L,0x99704f46093b1218L,0x500ac8e077b68364L,
        0x65f724789231e9c5L } },
    /* 88 */
    { { 0xb3ff545bcbb602b5L,0x566e5114bd8413abL,0xe9aefd984b5d352aL,
        0x5bae49a80f457ed2L },
      { 0x07e4695bf11d8800L,0x01ac54b6fd4ec25dL,0xd6644e6ed2b70671L,
        0x28bb3e5e1d8605d4L } },
    /* 89 */
    { { 0xe7b1887e69044ab8L,0x933044b35cb4f30bL,0x7aa537a5dd7b9891L,
        0x42072798f19f3221L },
      { 0x6b8297e3c51f50d8L,0x5b21edfceef90e53L,0xcb57951efe5c7059L,
        0x6d2d15fbfab581beL } },
    /* 90 */
    { { 0x690e6f835d33b0b6L,0xbb452cdb95d73cc3L,0x62ebea7c37cfebf4L,
        0x9035b6273193c9ceL },
      { 0x5c45279e40f4d7b7L,0x799d675328f329baL,0x07bc499f35fc993dL,
        0x7d579db8009a4c1dL } },
    /* 91 */
    { { 0x26eee57d9cbe4314L,0xb5ebf1aaa8584f9aL,0xdfe924e88db21946L,
        0x7c2f8c186de2ed08L },
      { 0x72a56c8862204329L,0x0e5af12dfd970aceL,0x391a62ecc3273716L,
        0x11796fed8e9208f7L } },
    /* 92 */
    { { 0xd9c1d01464c0138cL,0x0f1bc4c41ac403c5L,0xede9cc66537f20f3L,
        0x0814c5e4f1d4067eL },
      { 0xee04e4238e58bd95L,0xcd262e86fc9a7231L,0x8a2c8b6cbb8fdf12L,
        0x772a46b081698dd0L } },
    /* 93 */
    { { 0xbb5ba56dbb35551eL,0x07c04bf5663c3ba9L,0x2658e49ec13f92faL,
        0xd8002bf04b0528a6L },
      { 0xe5a5a44f6e19feaeL,0x5182c831d32f85bdL,0x7391563e2f326a5dL,
        0xc04b58b31043c6abL } },
    /* 94 */
    { { 0x77cb1957d98d1a35L,0x75fa1798d2dae5eeL,0x21387bf6ddb024c1L,
        0xb3706b48057d7f35L },
      { 0xf2cedf390d7e2ad4L,0x09b7077825ab3e0aL,0x67f4ebfd925ec8beL,
        0x6ffb26eddfca4b5fL } },
    /* 95 */
    { { 0xf9524628bae85738L,0x8699f4eadd316b90L,0xd8d0f1101c6ed782L,
        0x4175889e7e60fbe1L },
      { 0xaaff3defcc11b1cdL,0x87177ff80e5e9428L,0xd1cec6790292d76eL,
        0xdbbabaaf87323f56L } },
    /* 96 */
    { { 0x862696e9afe9099fL,0x4f695f15407a925cL,0x8701f30a2dae1f95L,
        0xf984c561f45e4cb1L },
      { 0x4fafee1c6ebb4441L,0xfbf96f53fa59ad45L,0xa530b86e20ba55c7L,
        0x6efa587b90e0423dL } },
    /* 97 */
    { { 0xbe355bfeb7bdf0b3L,0xf1d290fe806394fcL,0xf517a08656c8e8f1L,
        0x32756a1d09b301f3L },
      { 0x0e7e1fb393704c72L,0x5a3ebaa1d2c711e9L,0xaea7952e936ec599L,
        0x4493678e46521036L } },
    /* 98 */
    { { 0xe4161f6d525ca4c6L,0x1b969ac1b4c96eaeL,0xf9975658c70338dbL,
        0xa064cc6ea08ddf12L },
      { 0xdb438c3e1c73ca8eL,0x0eeac3f1c825e7b0L,0x874903d94659f59aL,
        0x2270c0c10d98731cL } },
    /* 99 */
    { { 0x0c821bcba16a8f1dL,0xb559c2e98748f6a5L,0xd7ad00ece8991a9aL,
        0x56cc2caf98fa2758L },
      { 0x69a09406b185924fL,0xd56e1870008daf7aL,0x1a307168682b81d1L,
        0xb51075f6a6a712d0L } },
    /* 100 */
    { { 0x7bf7375f82da577dL,0xf191d5842dda1fa8L,0x06a737400a9fbd96L,
        0xa81aa04badc73390L },
      { 0x7e77b3ac0627446cL,0x4e662186b8bc08b7L,0x8315b1bddfa62560L,
        0x912ba4fd619678d3L } },
    /* 101 */
    { { 0xaa6244e7e21bda2fL,0x82aec7d7cea4ad07L,0xa391e63f92f8a4aeL,
        0x0811b0a9eda9032fL },
      { 0xbb8c72930c1e7599L,0x02a318655c36a1cbL,0xbe014f1a641883c6L,
        0x98c6cb62116d0352L } },
    /* 102 */
    { { 0x331d9e52a1df225bL,0x133b0ae97fefdd9cL,0xc003f65e29f9af11L,
        0xad884879ddf01433L },
      { 0x7261e2f6a4af26ffL,0x57e94b621f6ff193L,0x4640a4d41aca40cfL,
        0xbb2ca6ef3c5cd73bL } },
    /* 103 */
    { { 0xfbdb73cb4664d8b9L,0x403c241232302861L,0x9000ce6206b814c6L,
        0x28ad9c95cd3aa1fdL },
      { 0xfc4585831d012d1dL,0x4d784c385f8eef3aL,0x15d7456cce859d46L,
        0x2002b79d8fdd537cL } },
    /* 104 */
    { { 0x269a8e8358ff29caL,0xb49c4f767d4a65f9L,0x758233f940457f21L,
        0x149755a491ca479cL },
      { 0x9f20482340cdad3bL,0x52efa2010edf5d42L,0xe0cf812a6843c0a9L,
        0x3e9b4d515ee13b47L } },
    /* 105 */
    { { 0x58725c441851bb43L,0xd6ab9afdb1d5f4c5L,0xcc47d6ce4561ed22L,
        0x36e9257944fbe7f1L },
      { 0x9dd595f778e47086L,0xb90420e40cd23532L,0x4eec937e8bd666e8L,
        0x5fda90a90c851ae6L } },
    /* 106 */
    { { 0xecd87e43fe3ece65L,0x2c4a07ed2e511f19L,0x0cef0a332bc895e4L,
        0x5a4e679c81b1b783L },
      { 0xff577167f35bef34L,0xfd949a887e9a98acL,0xecd9b69a82e42034L,
        0x3960b999e0a3249aL } },
    /* 107 */
    { { 0xb0634531341a4ca7L,0xa97b2f74653c48eaL,0xfe7fcd35e05211b9L,
        0x3abfb61a2fa897ffL },
      { 0xc4665714b67a9b8fL,0x77c3f374d4f1f720L,0xea8882f879e90128L,
        0x2a201265d100d209L } },
    /* 108 */
    { { 0xf4c15d09bfd9fe05L,0xbfd5269f3764454aL,0x757375b95fbcee9eL,
        0xd648724630499a3dL },
      { 0xd4aeea190dd0e3dfL,0xdba477f399b2c184L,0xffa9671c476f6787L,
        0x404358f232d1cbedL } },
    /* 109 */
    { { 0x8809656845ba70a1L,0xc1025d8ed7c02846L,0x10070d7a10e79c61L,
        0xda5545e6cc51d71dL },
      { 0x86100592d36071a4L,0x7ccf96bd2cb84b66L,0x8c04ec149f09a3aeL,
        0x90263635f07c45fbL } },
    /* 110 */
    { { 0x6c021a6f15a02c24L,0xd8fd90d6b345c3ebL,0x4deeb0f86346cb58L,
        0x8e319f9928c63a00L },
      { 0xae65c88f3fbe9596L,0xcd4412262c57f362L,0xb491d9b377874cb4L,
        0x1a6cc217ca29eff4L } },
    /* 111 */
    { { 0x81a498d382b02298L,0x71934d1970c81c1fL,0xab24b353d06009e1L,
        0x270bad312a10368bL },
      { 0x4a58be031acf8d51L,0xe9f0519e96fe90ffL,0xf74b13736a2cbad7L,
        0x558377b9d0501451L } },
    /* 112 */
    { { 0x0f7acf3161f8c84bL,0xa5a72c1e6e47a311L,0x16c2690e4373f8c6L,
        0xc05d2da159d03954L },
      { 0x70230c542c7e9247L,0xc29d9317ce9531ddL,0x9683a0ef90f1f78eL,
        0x7dd05c855053755dL } },
    /* 113 */
    { { 0x369f32c2d935116fL,0xf776c2e928550a73L,0x7e449b09c5d579b6L,
        0x2caffed8217a7adeL },
      { 0xacfec3fb17ca913fL,0x1b592631299bdfe4L,0x58016260a8bbbc6eL,
        0x6ab392fca90f5edcL } },
    /* 114 */
    { { 0x904d2c9d0ccceecbL,0x89102f9fd0705967L,0xd12f41938813ef3cL,
        0x2ec8a831f7fe5335L },
      { 0xb60e1674736d8979L,0x9115936bb00549a6L,0xdf4f2d15a64085ebL,
        0x4517fa550f72a207L } },
    /* 115 */
    { { 0x269664b9b807c6e6L,0x31ef23b4ae45a4c6L,0xe2076e09e3791c14L,
        0xb8c4f5677a383887L },
      { 0xa831e21cbc149a92L,0xa4e6c3c3d3a787beL,0x0eb26c57c3ffd766L,
        0xa9f8c4f67796e8bcL } },
    /* 116 */
    { { 0xecefcd0bc2df4bf3L,0xf34c21e5aca2333bL,0xbf4bc9d7dd23fb04L,
        0x8188fc44aefa8ac8L },
      { 0x8f98a9308d27e4ffL,0x176f524b56de5282L,0xac357342653ba693L,
        0x1184e8d4c7917bc3L } },
    /* 117 */
    { { 0x819f080c3ec27426L,0x1bf33d34314f618dL,0x59d87c2605605882L,
        0x614c5091be748ebcL },
      { 0xbbec1bcb6b12648eL,0x84575ab0b1ead712L,0x0d567c95727f376dL,
        0xf7138698d689b2d7L } },
    /* 118 */
    { { 0x58a15b85002936ddL,0x32db35c585ff129eL,0x1c85d85f2c76679fL,
        0x1c4e12bd820975d3L },
      { 0x8fc049647a93eaa8L,0xf3aba42863676744L,0x07fa73fa104c293fL,
        0x90c82500988d3071L } },
    /* 119 */
    { { 0x4c8af557dbff4effL,0xc63c072d97c3fa17L,0x5f7276b410949630L,
        0x34db1d0e2ea82545L },
      { 0x5282e7dae950c2ceL,0xc0584105ccc61dd3L,0xcd364e40cb48882eL,
        0x62e3bc4ec46717d9L } },
    /* 120 */
    { { 0xdc9ad306f4d76e8dL,0x37e687dcb922a0beL,0xd06acfe9dffb5453L,
        0xc852529016391951L },
      { 0x34de48cfcc8601a9L,0xc4f078b758b73373L,0x2a3cc09628bd9fffL,
        0x5bec709befd134d6L } },
    /* 121 */
    { { 0x4e44abadf4d0a639L,0xbb4c9910fe612ba5L,0xab2e5b4130e58c0cL,
        0x9a6a2fa53e800e9aL },
      { 0xf5cc57882ca0d01cL,0x3f8412a189a25d59L,0x4ba569e0453fbaa7L,
        0x9e33bd82e0629ab6L } },
    /* 122 */
    { { 0xd4fe957c61613f97L,0xb86e9ddff35694cbL,0x65700b9aa0a7f9c2L,
        0x349a4dbfa789f4acL },
      { 0x836b7cf8483553c7L,0xe41f0e55e07dff25L,0xe71ca712848bb8e4L,
        0x625b33bcc00a7fa8L } },
    /* 123 */
    { { 0xbf41f45ac7068002L,0x9f4b862f78affb63L,0x523f30d1ff3207fbL,
        0xaf6534307212b4e2L },
      { 0x595b18f6bd9269e3L,0x0ddc252a5bbb73b4L,0xb59634a82381044dL,
        0x72550c74c4df1aabL } },
    /* 124 */
    { { 0x0f4ead414997b745L,0xab3e46c580ab7698L,0xe010d55a85719bf1L,
        0x0fe9667be7304bd3L },
      { 0x8e112a0a44eae3c6L,0xd30ce0f58a4808a7L,0x3fac78315c32d57dL,
        0x1e4b2152c95d0e1cL } },
    /* 125 */
    { { 0x9c6b885864a0b46cL,0x6a3c1253ec200e69L,0xdb0e573fa74942ceL,
        0x1ef64607257dd452L },
      { 0xb3efd2e589b9b886L,0x2046de874ef3df9bL,0x4b837cee110a57e0L,
        0xc8b4274479f3139cL } },
    /* 126 */
    { { 0xfd57f4deecd31b38L,0x5064631b946b43e6L,0x5f75a0e83f27e71aL,
        0xb98d159a8539cdb4L },
      { 0x941caf0746fc3042L,0xb0e4e23f862ec3fdL,0x637e2cb2fdc6a175L,
        0x524255843589c36fL } },
    /* 127 */
    { { 0xb80bee0f63fb7688L,0x4b03dd0416ad1233L,0xb2aa0667deab742fL,
        0x3af71b2d7d622028L },
      { 0x4caa50b4725b4531L,0xbb4342ec08af5e89L,0x2b61fa9d3c77438aL,
        0x01d25439db0af575L } },
    /* 128 */
    { { 0xe74e265bc25dfad3L,0xd03630b9493f44b6L,0xb3270892bfd6d473L,
        0x5b2d95431c5ee992L },
      { 0xeeb94537a36f7c5fL,0x9befc01d8ab0b81dL,0x483cdb08188b45e5L,
        0x44c753b701e4648bL } },
    /* 129 */
    { { 0x779ee42d924195acL,0x44ccd6a00cec6c21L,0x1a0df86e211bd343L,
        0x2f73a627a7fc826eL },
      { 0x179c9d7cdd4b2facL,0xe09df4b365a3f70bL,0x169b58ea63270b3dL,
        0x5934a0a057217f02L } },
    /* 130 */
    { { 0x488905bff471c90dL,0x2fe5dcf530de94b7L,0xef4366988218ea8fL,
        0x986125e879e5558fL },
      { 0x2e59c17a2ce9c497L,0x8131f0e21ddab4b1L,0x408daea720035218L,
        0xcd71798ed40469e4L } },
    /* 131 */
    { { 0x3c3fd6520fe2e160L,0x569f812305bcf84fL,0x022bf0e95151f451L,
        0x054574f4ac2845ecL },
      { 0xbb17853dd524a547L,0xbf1b6f2733d6e7b0L,0x5d71af25d4d10a83L,
        0xd4cfa938e8ae37e7L } },
    /* 132 */
    { { 0xda39e364843e3cb6L,0xf259a38d61812528L,0x94912e5157862e0aL,
        0x8142ba4a2e978c13L },
      { 0xb8348db9244620d5L,0xe67f9053a46c8074L,0x21ab9bffa1e6346eL,
        0x0441577064f1b73dL } },
    /* 133 */
    { { 0xd4355d5874019e33L,0xdb1c1b2218e26d25L,0x9a39a7d6ea91876fL,
        0xc1d29df0ef2d83fbL },
      { 0xf23781209cfaf04fL,0x5ca4b4bbc33a65eeL,0x529e4d14c5364c6bL,
        0x9cd549d00b9c3666L } },
    /* 134 */
    { { 0x7dacb8240d561bbcL,0x7c7c2fd1753ced32L,0xd9774757f3afb037L,
        0x213fe3710d6e3a55L },
      { 0xa6d3d8d550d4f212L,0x674c0a8198665a38L,0x112e0ed54f2a518aL,
        0x1b995abf8f902353L } },
    /* 135 */
    { { 0xa06b8d220f049d2fL,0x415763b2eea425afL,0x027b304b8051b012L,
        0xb8cdb43fef51bae0L },
      { 0x492e11fed7109f5cL,0x0b57be5d7298d02fL,0xeeda24c4634f9a12L,
        0x0b0aab291592d326L } },
    /* 136 */
    { { 0xa4a48c8d1d0ad6b2L,0x3b996e4bde384635L,0x09d5a0fe19b7e324L,
        0x5847aae5efac055bL },
      { 0xf6b1627fa0c3770eL,0x37cb26706fc34e82L,0xfdcb37fb6c0ede62L,
        0x4e41298d2a34e059L } },
    /* 137 */
    { { 0x84b04e369a3b63adL,0x8353ab53bc323063L,0x06987ecac0045b9aL,
        0xb461ba8846f45828L },
      { 0xd37ef067e5943cccL,0xe5d36625cdc4de91L,0x4f72a9d3024ac769L,
        0x0ad61f173c8e2b9dL } },
    /* 138 */
    { { 0x5114fdc8b5c95125L,0x57637b86c9341981L,0xb66786bd39b74fc0L,
        0xc9e138be230b7e41L },
      { 0x0bc6d5fede050283L,0xa7c743a3d609a03eL,0x1233df12b1ae24f0L,
        0xb2ea42ec57db9668L } },
    /* 139 */
    { { 0x9f9b88401363c862L,0x9a850b3039a4b717L,0xaeffb727f87a216dL,
        0x754cb279b3d99a0cL },
      { 0x046e6946bade742cL,0x05669a4f3b3ea466L,0xc64392ba23aa2b1cL,
        0xa218279dfd714fe1L } },
    /* 140 */
    { { 0x4203d984235b46aaL,0xb35f0c71e219d5a2L,0x93a429b23c5ba535L,
        0x7eefbb779111aacaL },
      { 0x67b99023c45d8760L,0xa0f786543ce39388L,0xaafb1901dbf34ec0L,
        0x49498c8b2dced638L } },
    /* 141 */
    { { 0x94f5cc8a99e4ef46L,0x3321e6670ef0d4b1L,0xdb2d0224ffb89f14L,
        0x9bf748039d069a20L },
      { 0xa64d6b134f1c1f1eL,0x1ab102852162dd15L,0x7c7f6a09a7742325L,
        0xc5a9082dc823efc1L } },
    /* 142 */
    { { 0x393fb6793d087141L,0xe872932dfbdb7ff5L,0x21bff1a24ba6c9d3L,
        0x3193dea297ad760bL },
      { 0x0ae5a74110c7e145L,0x9e7cf429b18493bfL,0xa0a3bfa1c871111eL,
        0x322f34eada10cf39L } },
    /* 143 */
    { { 0x482375dcee32db92L,0xa7e02d01416f8eb4L,0x224fb2c1004ba196L,
        0x165f5f16c6488715L },
      { 0x4cad71bfd1125e78L,0xf7a1b1f437d5cc46L,0xb54a9fe1efd065afL,
        0x3a954eb0dbfbe5e7L } },
    /* 144 */
    { { 0x45f4a643ff76620aL,0xdb83913318233034L,0xb777abeeaebce0abL,
        0xe610ded6b961e3d8L },
      { 0x848f85ddd7bc0322L,0x64dec64f05bcf887L,0x32f43df085d3ed98L,
        0x2e150e9a0af94bf8L } },
    /* 145 */
    { { 0x5890c658c7de998eL,0xc418a43a3509373dL,0x04661baf7d290312L,
        0x87a24bdad4f3762aL },
      { 0x3a46493dcaf8e73aL,0x694bce49a475ba0dL,0x9af7566e1fa35fe6L,
        0x3ee19601d7bc94acL } },
    /* 146 */
    { { 0x5bf209eedfb0faecL,0x514ea8718a6ec977L,0x95b71f0ed04a9727L,
        0x4650bc76db496313L },
      { 0x22cc758d58184292L,0x152d43f9ec9aceabL,0x4b47606e091f0bb7L,
        0x6da270ef1b7d4e79L } },
    /* 147 */
    { { 0x4ee7022b935c7726L,0x2f7e7bb7d1af2facL,0x55a2f594fdf9e72fL,
        0xedf46a3014b8b2d8L },
      { 0xe5fba600cdc3292fL,0x04b54a3a58c6f6a4L,0x1263dc16b023369eL,
        0x0ac721ddbfc3a1adL } },
    /* 148 */
    { { 0xe62e1d9127351b84L,0x5c99d2394dba475bL,0x6cafe0d0567c9219L,
        0x8db1ed2a5418e29bL },
      { 0x36d4e136e729b5e4L,0x0c714c79ed502494L,0x20d538d3f4809507L,
        0xc187d5fbb0b20279L } },
    /* 149 */
    { { 0x68ca10ce51ad0a16L,0x3150db24679b7804L,0x0e9496a5bb25aa04L,
        0x71237e21ac090e22L },
      { 0xd3911b2b8454f658L,0xb4cc8be399498743L,0x3eec8fbae6a6a08eL,
        0x3230250589d40596L } },
    /* 150 */
    { { 0xe898b046ad144097L,0xc5ca6ff824c88b1aL,0x9d01b59b8cf479aeL,
        0x5ecd93aa92115900L },
      { 0xf4b4b1d861716de7L,0x187b1e0758d641b5L,0x3c6948c5ca3f3a12L,
        0x3841240cee7e1518L } },
    /* 151 */
    { { 0x7d5bc16a69f16249L,0xaa932350dddb1510L,0xe5df510476d23cc9L,
        0x2f2a1306bb0900ebL },
      { 0x9fdf3047699413ccL,0x71f3cd3026394d94L,0xad22fa8c59396461L,
        0x6c6253bc469fbffaL } },
    /* 152 */
    { { 0xb79fbc3e1e33c180L,0x754fb963615e3e38L,0xa3a4083837111e5eL,
        0xd8780e0449f757bbL },
      { 0xbb941a11e545fb38L,0x227ba21b55d54231L,0x5d80da73cfcc068dL,
        0xd3b0557be600e277L } },
    /* 153 */
    { { 0x286524f5595a7415L,0x1e8dcdfc657a5920L,0x04d7efa91477845cL,
        0x86bd1af717d2b3baL },
      { 0x08e833c706b56786L,0xff007b61028130b2L,0xfcafe0826e05001dL,
        0x41556b5537fe292aL } },
    /* 154 */
    { { 0xfddd38190baaa8ffL,0xd916d17b45bc51beL,0xf981a07a6a86f8a9L,
        0x23111568b2c36491L },
      { 0x51628fa0da2059abL,0x62537ee8a2f34feaL,0xf34ce38a30d7894cL,
        0xc464b9dd967e567bL } },
    /* 155 */
    { { 0x0e4e55926fd5fc85L,0xcccec5e99d5e3741L,0x3c297adef835d025L,
        0x40e40ff81250825cL },
      { 0xd4120ecf1953cfa2L,0x295c5b6405e32613L,0x0eb531c0ee8fe373L,
        0x5c4d24707ea315fcL } },
    /* 156 */
    { { 0x73543946918fd269L,0x61cd97dd7c10b8eeL,0x5f88e7815fcf9bb7L,
        0xce83e70e4cc5a4a7L },
      { 0x4891847f7d845599L,0xb1a2b373e052a4acL,0x6996b90ef6932c5dL,
        0x4e53f37081227964L } },
    /* 157 */
    { { 0x2135b8eb55856253L,0xba19ee8b47b465f5L,0x8e2b91a11b8090acL,
        0xf80bb6bf7857ed6aL },
      { 0x0a81366173d12c59L,0xa75a8e11c74599e6L,0xad08ee3ecda2a2dfL,
        0x70d54102c87ac463L } },
    /* 158 */
    { { 0x6736584f49af46ffL,0x096d00ef2f98bce9L,0x77f019424e133b91L,
        0xd10b349e5f3904ebL },
      { 0x96131a1380429c3bL,0x479ab882f0fabf71L,0x40a22cde78a64ffeL,
        0x165920d31952c3cfL } },
    /* 159 */
    { { 0xab5f1c1afc086dd0L,0x07063e8512956035L,0xfe92b742c5a58ddcL,
        0xa58aeb140cd4d60fL },
      { 0x975f3323ef78f77aL,0xf31f291266687342L,0xd92b874a6a031eceL,
        0xf1b36156554dab9aL } },
    /* 160 */
    { { 0x2ce9fa744396acccL,0xef9c4a79f00e49e8L,0x9c32ee8de6694beeL,
        0x6fba4bbe0e8f785cL },
      { 0x65fa8e0378a65c2cL,0x7ac38e6918cb8f40L,0x24f743ab6b188e1aL,
        0xc39006b456eb3ec8L } },
    /* 161 */
    { { 0x519ba583732d3604L,0x9bfeb4810b6b3459L,0x1897d0c9120f4fc5L,
        0xde080cba4a7b2350L },
      { 0xb8bd8414a7d2b287L,0x8a78b72b3f4fd647L,0xbfa1061d45bb0427L,
        0xe6f95dae75940cf8L } },
    /* 162 */
    { { 0x1cb29b49f0bade5dL,0x742025f643f806b8L,0x890214eabc73ee16L,
        0xcbbacf134e9357a8L },
      { 0x71b32714d4970cf8L,0xec4f8e50433f00daL,0xa92b3b9d178913cdL,
        0x892fad97630520e3L } },
    /* 163 */
    { { 0x5fa5194f02648f13L,0x169f296c27b6be01L,0x7971c34d5709091bL,
        0xc4390edc01ca703eL },
      { 0xba5e8745f36dac3aL,0x25a85d738cd0c336L,0x25af152f1fd290aeL,
        0x9fa06153ccc50dc4L } },
    /* 164 */
    { { 0x4ada778c61604b75L,0x61e464639e803317L,0xbc7f3a0aa5819084L,
        0xb4f2a6baf3616feeL },
      { 0x482bafb8540da7f8L,0x9fd559cff4d6225aL,0xa0f1d758a1c5e50eL,
        0x35c216e7e872b407L } },
    /* 165 */
    { { 0xace013fc04a1c7e2L,0xc6990d5ca946f3ffL,0x71dbec40783d06acL,
        0xe30a6d8543eb15b4L },
      { 0xdfed7d4294673feaL,0xf3191fb47c17e5f0L,0x091f8e0bbde2e1b0L,
        0xe4ef3600d38b269dL } },
    /* 166 */
    { { 0xae114bc7a4f41f17L,0x9279e404cfa30c21L,0xfa5eb2050f5c1e5cL,
        0x18722e9fb881c925L },
      { 0xff8d7a37bc23bf33L,0x1d5cc75da01c1056L,0x38b6e7ed879bed47L,
        0x1aae4f6e8eca3e56L } },
    /* 167 */
    { { 0x60a4895b690e1ed5L,0x391a0d0c39da8dc3L,0xfa6239a05f566fa4L,
        0x5d1bd75bdd56c22dL },
      { 0x3024adaefdab28fcL,0xcb81fe0a80d52bccL,0x0b8947a6debbfdb1L,
        0x727d4cc2a0b673a1L } },
    /* 168 */
    { { 0xfa39ed48661e7a89L,0xbbabf22cffaf4d15L,0x25e4c308694fb83eL,
        0x1082cd04abd08906L },
      { 0x6fa4dfcedfcf1eeeL,0xb1f0e4df7ce8427fL,0xa6d9bcbf73533d4cL,
        0x1cc91dfd973e175fL } },
    /* 169 */
    { { 0xf8ec2fc5a0d41758L,0xae5419e37783739cL,0x1654d7dda3526559L,
        0x75dde554efd85eefL },
      { 0x8760accb71da8cbaL,0x485d4ba191e56cf0L,0x81e6203481d8f13aL,
        0xf4b5c1eb8522fcfdL } },
    /* 170 */
    { { 0x4c3973ce50dd7082L,0x2bae6a23708c6f26L,0x2f88f44665af6483L,
        0x25a78b5ee21be208L },
      { 0xe66c29cc908c8150L,0x9829b61698fd5ffbL,0xc04624bcadc66028L,
        0x505f95611a199b00L } },
    /* 171 */
    { { 0xd523f41859dabf11L,0x570f20acbc4d2d5bL,0xd2ce247cf790e997L,
        0x85fa298ed574992aL },
      { 0x62eed5f34b273bd3L,0xfe8b6af9765f65a5L,0xfb2f462a03f38d8aL,
        0x5f6122f4057a67beL } },
    /* 172 */
    { { 0x124d731e5b5100ccL,0x4f7860a739d4313fL,0x3d8293301120c638L,
        0x0b9786d4c64e5ad0L },
      { 0xaca427c023985e90L,0xdbc70c00c889b882L,0xa292ff8161d4f290L,
        0x970f1f5a5b2dda0dL } },
    /* 173 */
    { { 0xcd1ff2c3fb1d91cfL,0x6d27841219aa012eL,0xc9d1cbd6229e18eeL,
        0xa815433ea80f4762L },
      { 0x83ed4b4f8e920554L,0x1d3f0c45d0aa369bL,0x17275152f7a905b0L,
        0xf1a03dd31ab9a60cL } },
    /* 174 */
    { { 0x92c10eda48c26023L,0xb2227c50af3927c8L,0x1cbe20e768916b9dL,
        0xcfd53e67a602f95aL },
      { 0x3cdc9993a0130dd5L,0x9bb6f3cbe4cbe0faL,0x4d2daa7e8aa67f6eL,
        0xf626df7ea206ba18L } },
    /* 175 */
    { { 0xff053d4a56c08f54L,0x8cb873cbdfd00c53L,0xb49844d18cca3d25L,
        0x58257196e113ea68L },
      { 0xa0e29282d26f6bdfL,0x7621dc6c66135148L,0x057dbc3f148a385aL,
        0x49badc079b26e1b0L } },
    /* 176 */
    { { 0x353b2df7c47731afL,0x767106a57b9a1f37L,0xd5fe65f776a16fa4L,
        0x4d65eb8d1c39003fL },
      { 0x7d1702fb0e6d9389L,0xbf49d24649099879L,0xa84e2ff34e4d0c8eL,
        0xbdbc377344f06e64L } },
    /* 177 */
    { { 0x150219e040209feaL,0x56e604b36286c965L,0xf118efad48a4e72cL,
        0xc6f889c8294b0883L },
      { 0xe4c8d1648e7e0c57L,0xa92c6a2a23d600abL,0x24dd2751fedb4278L,
        0xffd8a7e1d93e34caL } },
    /* 178 */
    { { 0x2d2627ed160722afL,0x3c8b810228bf0d0fL,0x6eaf4d9c8ec4d61cL,
        0x1b4baff52c17f2ccL },
      { 0x4f5a3e23b4594092L,0x14b4a2457d829bf5L,0xfa5ee05e5a5a4222L,
        0x03a0d850ec0fe001L } },
    /* 179 */
    { { 0x9a31d6c669ade883L,0x9d49c856d7fab9b5L,0x578ab41a0c61b5acL,
        0x7e4f2902332350deL },
      { 0x719bd4ed196ac4bbL,0x71c88e05afcea98dL,0x5b441bbeac85a02cL,
        0x4132c66dfa018e8eL } },
    /* 180 */
    { { 0x86242d5cbd80c757L,0xd3423fed3966b1a6L,0x5d0ad4d692e7fcf4L,
        0x545bb52a4a79f3f0L },
      { 0xa12226342037745aL,0xb58d29fe5c9a47ccL,0xccda98272140baadL,
        0x603e39d376c769a3L } },
    /* 181 */
    { { 0xae9a6ec367c3d4aaL,0x444f55d108bef96fL,0x50996abed664d0a8L,
        0xa44601dd608613aaL },
      { 0x076256f9ba37b00aL,0x9d9f730aea4489caL,0xe8e1af338f356781L,
        0x9da72c5c1b0c9ac2L } },
    /* 182 */
    { { 0xa5480cd28056721fL,0xf8ba48e4cd67f6a3L,0xc8dc6652dfdbf0a9L,
        0x3d7064afb7e1edacL },
      { 0x4454ea36a309625eL,0x026a0223896c1810L,0xe9f5001187e52615L,
        0xf7a1b2533c3d703bL } },
    /* 183 */
    { { 0xf4adfac66194a9a7L,0x31a944e7ec1c3185L,0xfde9ce8140a0ea46L,
        0x16a7b783abf635c5L },
      { 0xcf49d62487106be1L,0xf1108156baeedd58L,0x53bfdc6365e3b59aL,
        0x89acded0c0a7c900L } },
    /* 184 */
    { { 0xa6eb380b9c0c7c04L,0x23007cac9f01cc9cL,0xc4ddfb2f285b6c6eL,
        0xbcdc7f514d2fe7adL },
      { 0x42bc65344a8963d2L,0x2fa0bd5e27b55dd7L,0x7e493fb2d8e79874L,
        0x17108a6cc84bf937L } },
    /* 185 */
    { { 0x8f8d2e9ca0ae33b0L,0x403cc7660e3cd053L,0xf781658520587996L,
        0x0f662d5669c8fab6L },
      { 0xfae35eacd4e35be1L,0x5ff472016ab0035dL,0x4cdb6ea1c783bcd4L,
        0x3ad2e46a5247a9d5L } },
    /* 186 */
    { { 0xf066bef1962b769bL,0x1834fec5ba79d9f3L,0x0c3d474bcfe70b11L,
        0xff3146e6181455deL },
      { 0x90b4292fe9fda5a1L,0x100d540c29e22976L,0x041186a3aa2df711L,
        0xcfd8a211f3bc2117L } },
    /* 187 */
    { { 0xabaa164ca4e1e3f9L,0x0ffc5d4c5076c4ecL,0x8d6a764629715425L,
        0xd50913ead9ecd358L },
      { 0xa39841d137f9e5baL,0x6a90abfca756c925L,0xd29c4f84335855adL,
        0x3a8a3ffe90bee210L } },
    /* 188 */
    { { 0x20529ea282775465L,0x96bd396505de46b0L,0xeafdf7576fe0203dL,
        0x033709f7b849e1dcL },
      { 0xd990f2627440bc88L,0x19fd98da562bda86L,0x6f6090801b3ab664L,
        0xe39bc8f9ee05d54cL } },
    /* 189 */
    { { 0xba63d7d0b7fee211L,0xe5cfd677cc72f995L,0x5e64ab103df5863dL,
        0x2e6ad6bddc863619L },
      { 0xf91e115fdeffbe49L,0x154edfcdbb1c3c09L,0x5fbc8d3b0be68cfdL,
        0xdc5630bcb13bc1ecL } },
    /* 190 */
    { { 0x85f93624a9924c34L,0x8478bfd72e11428fL,0x8149f85747f9defdL,
        0x0610508bf509f993L },
      { 0x419ebe1f513724eaL,0xcff020a1725c8b24L,0x94f36584a72bddfbL,
        0xaec05fd5bbec1038L } },
    /* 191 */
    { { 0xebfcb1709b77bf82L,0x19147831babca0c3L,0x33fee22ddd409ac7L,
        0xc370cff2511f8112L },
      { 0xe023d2984151c5beL,0xf1097e8b2ef5ec6fL,0x7907a2bd3a09fbcbL,
        0x7e8f0a83bbfa1899L } },
    /* 192 */
    { { 0xcc2f2cf4da638608L,0xb2144397e7b68ac0L,0x7f18bf77db95ff63L,
        0xd0bf3e2a39846917L },
      { 0x4105e86ea7315affL,0x65a0a5522f3bf9e5L,0x3109f61c92351199L,
        0xf0119421c464d33aL } },
    /* 193 */
    { { 0x051330e56fb23d10L,0x96026edb8ea63c77L,0xf3541172e9cbfadeL,
        0xea56376a873c8b97L },
      { 0x7f40793d44d8110bL,0x0779b1ecc6beed1dL,0x6c03806ef5b721c4L,
        0xd2827a004203d666L } },
    /* 194 */
    { { 0xe63eca283c0f3250L,0xb430c96d0fa8aef9L,0xc9b9cb9f68c00b3cL,
        0xefba8043c38645f9L },
      { 0xbe5e077b13d1e454L,0x994033d5d2ee51afL,0x3790fdae3c3aa41bL,
        0x66714c6e6458b246L } },
    /* 195 */
    { { 0x8ee9f742924fb9f6L,0xac369983ec8a9cb8L,0x04285109b0a4f49bL,
        0xca5a01f04c550017L },
      { 0xc36d0e516442c569L,0xc58b3059207a07e4L,0xa9755fd73bc85b18L,
        0xda0e7c16cc2190b3L } },
    /* 196 */
    { { 0xc1b13cf6d0bf8406L,0x48d0f3600af68e16L,0x1c054718839ca656L,
        0x0ae2237a5a41a48fL },
      { 0xefdc679711f0d902L,0x13ac5bd1419ea87cL,0xe069d8cd6f0677cfL,
        0x42b06a0b3016d453L } },
    /* 197 */
    { { 0xdb427c886f4e1f14L,0x0b5ab2250ace79d8L,0x6326177fd8c06c52L,
        0x99a08f0231c37cd9L },
      { 0xa81d31ab13aa5906L,0x001f47594dd755b0L,0x8b56793f9c8da586L,
        0xb99c3583cec64d25L } },
    /* 198 */
    { { 0xfdd184fa6ae869ddL,0xa3bf5ff644d4becbL,0xf1763825a0bb9801L,
        0xca93f5abfabf79acL },
      { 0xba7dfd230ab2c9c7L,0x464308572e90ea27L,0x9692317337bc97d5L,
        0x955dca021c2b8297L } },
    /* 199 */
    { { 0xccb8f40eb2e176c2L,0x384a64e1074758c0L,0x62cc8b9bd2422f90L,
        0x0462a7798d32e31aL },
      { 0x683e1ec553aa56f7L,0xb40bb0ba67bcf05dL,0x12f21d32b09ea3bfL,
        0x7b5c0a3c9bb58b02L } },
    /* 200 */
    { { 0x7f6b288e19486bf4L,0x40ba6178221d922eL,0xd1bef20ddc3358f7L,
        0xebea60f6a3730105L },
      { 0xeeb79c281762e27fL,0x7659eac539fa2505L,0xf495d6024487bd90L,
        0x7b6d4af5ff797c5bL } },
    /* 201 */
    { { 0x2202cbf8bacaa0ebL,0x84547e98796b8656L,0xb66b87a981e01a8aL,
        0x2755125c933d78eeL },
      { 0x684555d4ed33f8cbL,0xf1de0cade2e677f8L,0x0ee5ad5351a1e9ffL,
        0xb34315b3f98ad35fL } },
    /* 202 */
    { { 0x7a64eb13131cd75dL,0x91f74f35cb0e3be2L,0xe41450032399ddf3L,
        0x371b86710dffe5a0L },
      { 0x769c13f4682d0f80L,0x24381abca5dbd72eL,0xe21a333cdb9a531cL,
        0xaeddc99c73f60abdL } },
    /* 203 */
    { { 0x5cf49e69b5f2259cL,0xb0498616044a6413L,0x510e245155d0a46eL,
        0xd83c7ca16e27da21L },
      { 0x07bde6d2635891b5L,0xdf5187889ebf3102L,0x0a99d5208c069792L,
        0x47202f65cdf92014L } },
    /* 204 */
    { { 0xcdb47bff2f443a32L,0x9023bc64d8e7a6c0L,0xf6b48ca562a9e45dL,
        0x3ad3dfcefd7737dcL },
      { 0x3782fced4b805be2L,0x3c062eceeb1b5ad7L,0x3f59fe860059b736L,
        0xf7cedd0ba36c46aeL } },
    /* 205 */
    { { 0xbb15e367433b78c5L,0xa23719079ff6a006L,0x8f3d622d15bc7d71L,
        0x525c2ed4fa1fc090L },
      { 0x93a3073ae68d4b0fL,0xdf19b8c210fe1959L,0x28faba36e47ac5a5L,
        0x2da6d62b18a7ae11L } },
    /* 206 */
    { { 0xa489b3bb5629d133L,0xf9f09b94ad127129L,0x53b7fedf7082982eL,
        0xc55733738d2beb9dL },
      { 0x847a38e55cb75589L,0xcb7bbdb05f665eefL,0x641fdfc9ae3c259bL,
        0x80e34ca157705d8cL } },
    /* 207 */
    { { 0x609c29f6001ef72fL,0x60ffe037678789b2L,0x700ceefcfde15530L,
        0x981994692aa8ac3aL },
      { 0xc39aa06441ca3125L,0x3e9f504ebc0c9a94L,0x2c613728ff861068L,
        0x5951fcb4a442d6f3L } },
    /* 208 */
    { { 0x7e9b2251b97e8fceL,0xa5d521c5ae42fa93L,0x5c73d3e37a79f665L,
        0x929a59161e7c1843L },
      { 0x308733ba2453f77aL,0x20191c84808bd44eL,0x17f9f06c24b263b2L,
        0xfffdcd9a27503ac8L } },
    /* 209 */
    { { 0x97845355fa2e3d35L,0x2f9fa6fc2deaba0aL,0x82884be4ea11a38aL,
        0x38ceee09fc779866L },
      { 0x91f38305565550eeL,0x037d2469c2090b67L,0x612d55895bb97c29L,
        0x45a8c6a73ffce185L } },
    /* 210 */
    { { 0x43e991af948986b4L,0x0c39d14822500ec1L,0xd93c272b9e7de923L,
        0x219e13869690f4deL },
      { 0xbc0282bcaa62b42bL,0x78d2619684e8bc91L,0x143930f4478144e3L,
        0x5ec12735cc913d8aL } },
    /* 211 */
    { { 0x00e8510f92dd1b0dL,0x8fa55634cbc479ccL,0x6585d80ade583ebcL,
        0x3500e41cdb09af4fL },
      { 0x797917278edc1c6bL,0xaa6de3b569973edfL,0x03c5e9cd13ac36f2L,
        0xc274afcc6c77a697L } },
    /* 212 */
    { { 0x998788ad3c423efcL,0x22c6a751b7ff9bf0L,0x7a11b0cd8fe82e4eL,
        0x7538db2b0c8c45f9L },
      { 0x964e5fa856d33e22L,0x319d22e3bb0e5708L,0xc67e4321c57dfa92L,
        0x465b5b2efa2e0a03L } },
    /* 213 */
    { { 0xaf90b2371248e296L,0xf7e7ff34e125ba03L,0x673bf50e7b58f21aL,
        0x9613120d2a5646a0L },
      { 0xed2a3ec535fa20a4L,0xffc2f510815b674fL,0x217b49a80917c28cL,
        0x5febff8d63e90143L } },
    /* 214 */
    { { 0xe180bad9883048a7L,0xedf0d76fde2fb311L,0xf22f60ff42f10918L,
        0xd9a441c6017e4056L },
      { 0x1b5b00eb4c2ad962L,0x0e301d8e9ccf4c87L,0x557f614d45f8f97fL,
        0x6cc18f2ee0f1e478L } },
    /* 215 */
    { { 0x48cc01d7f78b96abL,0x1ea8bdebb47e0f8eL,0xadca92ffeffb8a4bL,
        0xe998d32e77438be4L },
      { 0x09942eb0d4e6087eL,0x3fbc22556b241876L,0xaa2ec237acbc1c48L,
        0x9aecd9305732e76dL } },
    /* 216 */
    { { 0x5667d9b8958b5d43L,0x07bf1898e1eb773bL,0x851a6cd8bf548b86L,
        0x242d842242d6b46dL },
      { 0xd50ba08d7b655c2fL,0x2278910dcdf7c978L,0x9d5bfd7b306b780fL,
        0x6ca437e06e301873L } },
    /* 217 */
    { { 0xd7c265ccf9feae4eL,0xbdd4bd75997592a0L,0x518ae1d2e86249e4L,
        0x5909fa1bccb06028L },
      { 0x7a2f96595746eb81L,0x409d2993dc812fffL,0x031ad114b0abaf4fL,
        0xe0a7ecede531fc8fL } },
    /* 218 */
    { { 0xdd20de76201217ccL,0xc9a48c60553cec6eL,0xbde5f1dfcf672846L,
        0x957ce106003693dfL },
      { 0x02592916067c0809L,0x2bcf52dc03a61c6fL,0x8acdfba67e8aa527L,
        0xdad8f454b7284b11L } },
    /* 219 */
    { { 0x442f3af86aa83bd4L,0x415a0e0f8338a645L,0x87689c929690dd50L,
        0x7a127cc0862826f0L },
      { 0x48290cb193e33b5aL,0x124d399fab75c410L,0x1653bdace0a845c4L,
        0x2cd1819672cec15aL } },
    /* 220 */
    { { 0x8f4023c9676a8a56L,0x0c90e99c78d282d5L,0xe4bea5a6fc6d6b1cL,
        0x6cf1b326a89ce402L },
      { 0x066b1dd21046702dL,0x5fb766ca252ac152L,0x6c678ab5d24182b6L,
        0x9fc957468b18042cL } },
    /* 221 */
    { { 0x49efcb21387f9611L,0xff2d250788404b43L,0x55590cd91c7526c6L,
        0x90a22fc358e86a73L },
      { 0x6f7bdc009ce2f640L,0x92fbae7104d6346aL,0x3bffa7bc907d181cL,
        0x6b54f6c09268de9eL } },
    /* 222 */
    { { 0xf96e2d45f91e135dL,0x54b7f88947f90edaL,0x336da15dfb73b229L,
        0x4d971d020d211b78L },
      { 0x1974c3fc50ff0147L,0x1b14505c86c808ccL,0xce66ab026c112d67L,
        0x69fafa320c0231feL } },
    /* 223 */
    { { 0x8d85195605a94617L,0xbe07ec980c5f7feeL,0xe0ccb082907711f8L,
        0xc6709cbe3b82b814L },
      { 0x3da1bae0df8014a0L,0x3f78beb20b547f76L,0x98d0b7fd94a0cc36L,
        0xb87de6512b2e7ce1L } },
    /* 224 */
    { { 0x33a41222c3219f63L,0x070730db4a847636L,0x49f5cdda482146e7L,
        0x0f3b01a28f7e8088L },
      { 0xd50d3c7024ed5675L,0x7e56578fd12ebd84L,0xae574c6a36e5ebd6L,
        0x3a6a7004311490bfL } },
    /* 225 */
    { { 0x94e7397e9dc3afa7L,0x4a2bf9aaf1475d2bL,0xc8b14f38bb1ad3e0L,
        0x65657f7c3493e504L },
      { 0x3342a58d4162798fL,0x446a208f47f1f764L,0x11795deb3c10275aL,
        0x62e54572270c97a0L } },
    /* 226 */
    { { 0x199537c03fd3001aL,0x292d873695687faaL,0x63e199580ed75bf6L,
        0xfad9dbb037bbe563L },
      { 0x8a3248816330d6f7L,0x03b5f10a7ac23a2cL,0x3a939dbcbc4e295dL,
        0xa3e6119ab1b12f19L } },
    /* 227 */
    { { 0xfb67cecdb42823a4L,0x26ecf06873f43db3L,0xfb86e10852f1c5faL,
        0x74ba5c89b8185042L },
      { 0xa5f584288c74b8afL,0x33716f67a1dbf80aL,0x172190af223854cbL,
        0xbffbbbc4676ccacaL } },
    /* 228 */
    { { 0xf662064ee28b90c5L,0x563d7e97f79d0be9L,0x34330aca56becae0L,
        0x7c64d2beb6b1e3deL },
      { 0x8dc53abe31b53678L,0x34608a9f650da609L,0x4f1b089c16f66c18L,
        0xd0a9d4cabf5c6c4fL } },
    /* 229 */
    { { 0x1f631e858dd922a9L,0xa5394eac8691bd15L,0xd77571b3c8860f68L,
        0x06bad558e7d234bdL },
      { 0x2996272769d6c786L,0x5f02f3851dd44649L,0xf0b87128b0303874L,
        0x1184eb38260f67dbL } },
    /* 230 */
    { { 0x4fbc2176f646a2d8L,0xb59a9d2dfcaf9f98L,0x63d4394be398fd97L,
        0x026ff9bc94480bddL },
      { 0x31cb2a85b25eb68fL,0x3700d8ab1ed33abcL,0x653c3e89cc504287L,
        0xf81ba865f1f78624L } },
    /* 231 */
    { { 0x19aeb2d4ec2b7ab7L,0xfae73e765a60f91eL,0x59ebf10de7a33ad4L,
        0x731217a1dfaf022dL },
      { 0x44feb3423e5c73d5L,0x7b46a62812420333L,0x8dbf2725ca063263L,
        0x2f19658b9ceee3a8L } },
    /* 232 */
    { { 0x1b0eeb8bee1aa4efL,0x881f09db53f8bc25L,0xde19ed0febe31aa5L,
        0xc1205040b421079eL },
      { 0x6abe613d7f9fbb19L,0x480eb33f4c02f1aeL,0x98272198bc78a4aaL,
        0x73bd74b90060c59fL } },
    /* 233 */
    { { 0x26f7d0f0b7f909a1L,0xffc76b177e4c5a48L,0x793ea04b88442ea1L,
        0xe389c45d3936ad3bL },
      { 0xcef076b6843ffd3cL,0x364ac1ec43e56892L,0xbfc58bb0dad106e5L,
        0xaed22ac264b886acL } },
    /* 234 */
    { { 0xe31334cc869ae3ddL,0x52b6414398110baeL,0x256fe087bb8dd6ccL,
        0x29f73d4c519dd12cL },
      { 0x3fece3d3e2b5be53L,0x55687beebd5f8344L,0x257f6456010be101L,
        0x38390f01b9ab6effL } },
    /* 235 */
    { { 0xd67ae41b0cdf4b26L,0x84236c0a7e774fa6L,0xbbdc69a095d979c5L,
        0xd5bc73583605d2dcL },
      { 0xde384dd379a77475L,0x9f094f5a02a480f7L,0x2e77bf030beeea56L,
        0xa6a6adcb865158baL } },
    /* 236 */
    { { 0xd7d7c70d155cbb33L,0x47823ae69ea44142L,0x47e9c5addc91a3d7L,
        0x5ce9047c75312c3aL },
      { 0x70e98cc514696568L,0x9a2efc99641ab644L,0x47efa05a21dafe31L,
        0x2cefaab25ac5b71fL } },
    /* 237 */
    { { 0xb12db2047bccf3caL,0x15dfed5277e8fa88L,0xe981a650824a58aeL,
        0xe47a22d5b8628bc9L },
      { 0xb7965f01688432d8L,0xcc3015bbedacb523L,0x4d8c847e8a53ba8eL,
        0x19601827beea6f3bL } },
    /* 238 */
    { { 0xfff323281feb5071L,0xd16cd02df54a0cf7L,0xeb6f98ed138f89bfL,
        0x531647157ff7d3b8L },
      { 0x01d104efc992b998L,0x5a7c4cb23b19571eL,0xa872e7375b93dc12L,
        0x22e7a9db74954891L } },
    /* 239 */
    { { 0x9f6198e80283ccdfL,0x8b0eaeb9f78cd2c6L,0x0d9fecea78604294L,
        0xd0ac75fee9b26934L },
      { 0xba2ccb4a36fdf44fL,0x828b512390828426L,0x1b76b83c631013acL,
        0xf8d1bf6369874176L } },
    /* 240 */
    { { 0x1e60150533c6d17cL,0xec3d5b600c76fbcbL,0x23ebbee100604f65L,
        0x12959cbc5644050bL },
      { 0xea58df49f023a933L,0x58b9cc89920421e2L,0xf2b13f1bc0979200L,
        0x1aac8e329af1622aL } },
    /* 241 */
    { { 0x56d3c86754e44471L,0x16cfa79cd60f959eL,0xe1a0a9b33800aa6dL,
        0x0347857363cf5cb5L },
      { 0x5d93f256281c0625L,0x4eda2ed5c6e710c4L,0x76d998461fa7caf8L,
        0x5fbd4e1b1b6c2e3bL } },
    /* 242 */
    { { 0xdeee9c0e2628bd27L,0x5ed1edc96f8d8926L,0x4bbc7968ba6c6702L,
        0x71c11b59c47b97e8L },
      { 0x269af35cd93fdd98L,0x250f63e7ad98d80fL,0x9640ec914a878b4dL,
        0xd994d23b05eb0c5dL } },
    /* 243 */
    { { 0x0349852ce2eb6f86L,0xb7e3620faff1aad5L,0x0f8a633cb9a9359dL,
        0xc89a70270b99e076L },
      { 0x185553236661ebadL,0x85ec6e68da88f0baL,0xa8542f32db0f4d37L,
        0x04e03ee082ee8616L } },
    /* 244 */
    { { 0xaa463c2686460df0L,0x08b775cfefd5e793L,0x14e179758409d3d9L,
        0xe68e9468737a958dL },
      { 0x6519e649ca015c8bL,0xd6310f75a35c7b2aL,0xf1faec99cab343f8L,
        0x1b23979c32f77af7L } },
    /* 245 */
    { { 0x3526d4202b5e0c0cL,0x99db2bd9528c897fL,0xb64d880d26bfcd02L,
        0xdd78c263ef2ecd27L },
      { 0xa0b3507895822826L,0x5ea1c0e5acf21c03L,0x3d5b1d01dbe7e601L,
        0x139c073f8d9215b4L } },
    /* 246 */
    { { 0xbd9222c7670e8ca9L,0x381bd976a4b03512L,0x9c5d3aca6946fc83L,
        0x5a13dc71a6f3316dL },
      { 0xbcbf23640f25e97bL,0xdd741a0b6fe55b35L,0x748a770785cdaaceL,
        0x02d9d81477211b82L } },
    /* 247 */
    { { 0x766514ee83eca061L,0x38df097cca7faa4cL,0x88886165c850fc7dL,
        0x5f4fcb7a7c80986bL },
      { 0x58c498cbc8612b88L,0xa26ed74ad0029d39L,0xed010aa411118e41L,
        0x01239ca90808e5f4L } },
    /* 248 */
    { { 0x8b41551b771f2025L,0x8931e6f01dad7187L,0x633b0ba584d1d187L,
        0x801760261fb4ec83L },
      { 0x0a1740c3a3fed11fL,0x49dcada10e31c6caL,0xb96f0bd6d1079e1bL,
        0xd325b1ba5035edf5L } },
    /* 249 */
    { { 0x9ecca10c45614b0cL,0x65d4b71b0f520a05L,0xc875ce5b496af3b3L,
        0x1993daac089ec25bL },
      { 0x6c27531e9b44405fL,0x7166a016e8327055L,0xba7ed05566a45d43L,
        0x1da832bb3d3531a0L } },
    /* 250 */
    { { 0x8b4e0e7ab92d1d40L,0x8692417a2c66c63bL,0xcf340c588735ec72L,
        0xb5856961b5f78949L },
      { 0xd10a0b91b1715164L,0x864c17c7bd2dabfaL,0x480dd9f7a94db101L,
        0xa7dff8828f038493L } },
    /* 251 */
    { { 0xd39c5bbdedf73f04L,0x3a8fea08724545d9L,0xca68358774f7306aL,
        0x7094aeb4b97ef241L },
      { 0x06623559d72ebf79L,0xde24a91dfa95a003L,0x34e73d4ea716a892L,
        0xf0477a2cddc9453fL } },
    /* 252 */
    { { 0xa032471c1fb80211L,0x47c322b5629f78edL,0x92a62b56b4d34838L,
        0x2400e4248e88c984L },
      { 0xaf924289d3dbc9d8L,0x257c14a674a08df6L,0x959020166a095105L,
        0xf5ac54528bfdd383L } },
    /* 253 */
    { { 0xfb37e5ba42980d58L,0x2c031e6175657f91L,0xf9e45e924483bd4dL,
        0x43b13ea664132fbbL },
      { 0xddf081a4d6665e37L,0x93f75defa715ddd6L,0x4c76d8fa2b039528L,
        0x4ee3a221839aeab0L } },
    /* 254 */
    { { 0x97ff049d3a6ef7baL,0xbcc779d5f217b134L,0xea153370850cc2abL,
        0x93967c32ea78cbefL },
      { 0xdb72faa2c18605eaL,0xddee2f6f5e16939cL,0xf53bf342eae0e4f8L,
        0x14e25972fddc580fL } },
    /* 255 */
    { { 0x0854dcd8950d7f94L,0x07006a663ea3b4d6L,0xa91fa63fdf8b5b2fL,
        0xaad30b11060c2f4aL },
      { 0x1a30c0164254ba5dL,0x31450eaac5847aeaL,0x41c6740cd49eab3cL,
        0xbcc984efb97d5888L } },
};

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^32, ...
 * Pre-generated: products of all combinations of above.
 * 8 doubles and adds (with qz=1)
 *
 * @param [out] r     Resulting point.
 * @param [in]  k     Scalar to multiply by.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  ct    Constant time required.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
static int sp_256_ecc_mulmod_base_sm2_4(sp_point_256* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_256_ecc_mulmod_stripe_sm2_4(r, &p256_sm2_base, p256_sm2_table,
                                      k, map, ct, heap);
}

#endif

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * @param [in]  km    Scalar to multiply by.
 * @param [out] r     Resulting point.
 * @param [in]  map   Indicates whether to convert result to affine.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
int sp_ecc_mulmod_base_sm2_256(const mp_int* km, ecc_point* r, int map, void* heap)
{
    SP_DECL_VAR(sp_point_256, point, 1);
    SP_DECL_VAR(sp_digit, k, 4);
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_point_256, point, 1, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, k, 4, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_256_from_mp(k, 4, km);

            err = sp_256_ecc_mulmod_base_sm2_4(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_4(point, r);
    }

    SP_FREE_VAR(k, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(point, heap, DYNAMIC_TYPE_ECC);

    return err;
}

/* Multiply the base point of P256 by the scalar, add point a and return
 * the result. If map is true then convert result to affine coordinates.
 *
 * @param [in]  km      Scalar to multiply by.
 * @param [in]  am      Point to add to scalar multiply result.
 * @param [in]  inMont  Point to add is in montgomery form.
 * @param [out] r       Resulting point.
 * @param [in]  map     Indicates whether to convert result to affine.
 * @param [in]  heap    Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  MEMORY_E when memory allocation fails.
 */
int sp_ecc_mulmod_base_add_sm2_256(const mp_int* km, const ecc_point* am,
        int inMont, ecc_point* r, int map, void* heap)
{
    SP_DECL_VAR(sp_point_256, point, 2);
    SP_DECL_VAR(sp_digit, k, 4 + 4 * 2 * 6);
    sp_point_256* addP = NULL;
    sp_digit* tmp = NULL;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_point_256, point, 2, NULL, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, k, 4 + 4 * 2 * 6, NULL, DYNAMIC_TYPE_ECC);
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
            err = sp_256_ecc_mulmod_base_sm2_4(point, k, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            sp_256_proj_point_add_sm2_4(point, point, addP, tmp);

        if (map) {
                sp_256_map_sm2_4(point, point, tmp);
        }

        err = sp_256_point_to_ecc_point_4(point, r);
    }

    SP_FREE_VAR(k, NULL, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(point, NULL, DYNAMIC_TYPE_ECC);

    return err;
}

#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                                        defined(HAVE_ECC_VERIFY)
#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN | HAVE_ECC_SIGN | HAVE_ECC_VERIFY */
#ifndef WC_NO_RNG
/* Add 1 to a. (a = a + 1)
 *
 * @param [in, out] a  A single precision integer.
 */
static void sp_256_add_one_sm2_4(sp_digit* a)
{
    __asm__ __volatile__ (
        "li      t0, 1\n\t"
        "ld      t1, 0(%[a])\n\t"
        "add     t2, t1, t0\n\t"
        "sltu    t0, t2, t0\n\t"
        "sd      t2, 0(%[a])\n\t"
        "ld      t1, 8(%[a])\n\t"
        "add     t2, t1, t0\n\t"
        "sltu    t0, t2, t0\n\t"
        "sd      t2, 8(%[a])\n\t"
        "ld      t1, 16(%[a])\n\t"
        "add     t2, t1, t0\n\t"
        "sltu    t0, t2, t0\n\t"
        "sd      t2, 16(%[a])\n\t"
        "ld      t1, 24(%[a])\n\t"
        "add     t2, t1, t0\n\t"
        "sltu    t0, t2, t0\n\t"
        "sd      t2, 24(%[a])\n\t"
        : [a] "+r" (a)
        :
        : "memory", "t0", "t1", "t2"
    );
}

#endif
/* Read big endian unsigned byte array into r.
 *
 * @param [out] r     A single precision integer.
 * @param [in]  size  Maximum number of bytes to convert
 * @param [in]  a     Byte array.
 * @param [in]  n     Number of bytes in array to read.
 */
static void sp_256_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i;
    int j;
    byte* d;

    j = 0;
    for (i = n - 1; i >= 7; i -= 8) {
        r[j]  = ((sp_uint64)a[i - 0] <<  0) |
                ((sp_uint64)a[i - 1] <<  8) |
                ((sp_uint64)a[i - 2] << 16) |
                ((sp_uint64)a[i - 3] << 24) |
                ((sp_uint64)a[i - 4] << 32) |
                ((sp_uint64)a[i - 5] << 40) |
                ((sp_uint64)a[i - 6] << 48) |
                ((sp_uint64)a[i - 7] << 56);
        j++;
    }

    if (i >= 0) {
        r[j] = 0;

        d = (byte*)(r + j);
#ifdef BIG_ENDIAN_ORDER
        switch (i) {
            case 6: d[1] = *(a++); FALL_THROUGH;
            case 5: d[2] = *(a++); FALL_THROUGH;
            case 4: d[3] = *(a++); FALL_THROUGH;
            case 3: d[4] = *(a++); FALL_THROUGH;
            case 2: d[5] = *(a++); FALL_THROUGH;
            case 1: d[6] = *(a++); FALL_THROUGH;
            case 0: d[7] = *a    ;
        }
#else
        switch (i) {
            case 6: d[i-6] = a[6]; FALL_THROUGH;
            case 5: d[i-5] = a[5]; FALL_THROUGH;
            case 4: d[i-4] = a[4]; FALL_THROUGH;
            case 3: d[i-3] = a[3]; FALL_THROUGH;
            case 2: d[i-2] = a[2]; FALL_THROUGH;
            case 1: d[i-1] = a[1]; FALL_THROUGH;
            case 0: d[i-0] = a[0];
        }
#endif
        j++;
    }

    for (; j < size; j++) {
        r[j] = 0;
    }
}

/* Generates a scalar that is in the range 1..order-1.
 *
 * @param [in] rng  Random number generator.
 * @param [in] k    Scalar value.
 *
 * @return  MP_OKAY on success.
 * @return  RNG failures.
 * @return  MEMORY_E when memory allocation fails.
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
 * @param [in]  rng   Random number generator.
 * @param [out] priv  Generated private value.
 * @param [out] pub   Generated public point.
 * @param [in]  heap  Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  ECC_INF_E when the point does not have the correct order.
 * @return  RNG failures.
 * @return  MEMORY_E when memory allocation fails.
 */
int sp_ecc_make_key_sm2_256(WC_RNG* rng, mp_int* priv, ecc_point* pub, void* heap)
{
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    SP_DECL_VAR(sp_point_256, point, 2);
#else
    SP_DECL_VAR(sp_point_256, point, 1);
#endif
    SP_DECL_VAR(sp_digit, k, 4);
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256* infinity = NULL;
#endif
    int err = MP_OKAY;


    (void)heap;

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    SP_ALLOC_VAR(sp_point_256, point, 2, heap, DYNAMIC_TYPE_ECC);
#else
    SP_ALLOC_VAR(sp_point_256, point, 1, heap, DYNAMIC_TYPE_ECC);
#endif
    SP_ALLOC_VAR(sp_digit, k, 4, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
    #ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
        infinity = point + 1;
    #endif

        err = sp_256_ecc_gen_k_sm2_4(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_sm2_4(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_sm2_4(infinity, point, p256_sm2_order, 1, 1, NULL);
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

    SP_FREE_VAR(k, heap, DYNAMIC_TYPE_ECC);
    /* point is not sensitive, so no need to zeroize */
    SP_FREE_VAR(point, heap, DYNAMIC_TYPE_ECC);

    return err;
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_ecc_key_gen_256_ctx {
    int state;
    sp_256_ecc_mulmod_sm2_4_ctx mulmod_ctx;
    sp_digit k[4];
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_256  point[2];
#else
    sp_point_256 point[1];
#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN */
} sp_ecc_key_gen_256_ctx;

/* Makes a random EC key pair.
 *
 * Non-blocking version.  Call repeatedly until it does not return
 * FP_WOULDBLOCK.  State is saved and restored through sp_ctx.
 *
 * @param [in, out] sp_ctx  Context to save state in for non-blocking calls.
 * @param [in]      rng     Random number generator.
 * @param [out]     priv    Generated private value.
 * @param [out]     pub     Generated public point.
 * @param [in]      heap    Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  FP_WOULDBLOCK while more work remains.
 * @return  ECC_INF_E when the point does not have the correct order.
 * @return  RNG failures.
 * @return  MEMORY_E when memory allocation fails.
 */
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
            err = sp_256_ecc_gen_k_sm2_4(rng, ctx->k);
            if (err == MP_OKAY) {
                err = FP_WOULDBLOCK;
                ctx->state = 1;
            }
            break;
        case 1:
            err = sp_256_ecc_mulmod_base_sm2_4_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
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
            err = sp_256_ecc_mulmod_sm2_4_nb((sp_ecc_ctx_t*)&ctx->mulmod_ctx,
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
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 32
 *
 * @param [in, out] r  A single precision integer.
 * @param [out]     a  Byte array.
 */
static void sp_256_to_bin_4(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 3; i >= 0; i--) {
        a[j++] = r[i] >> 56;
        a[j++] = r[i] >> 48;
        a[j++] = r[i] >> 40;
        a[j++] = r[i] >> 32;
        a[j++] = r[i] >> 24;
        a[j++] = r[i] >> 16;
        a[j++] = r[i] >> 8;
        a[j++] = r[i] >> 0;
    }
}

/* Multiply the point by the scalar and serialize the X ordinate.
 * The number is 0 padded to maximum size on output.
 *
 * @param [in]      priv    Scalar to multiply the point by.
 * @param [in]      pub     Point to multiply.
 * @param [out]     out     Buffer to hold X ordinate.
 * @param [in, out] outLen  On entry, size of the buffer in bytes.
 *                          On exit, length of data in buffer in bytes.
 * @param [in]      heap    Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  BUFFER_E when the buffer is too small for output size.
 * @return  MEMORY_E when memory allocation fails.
 */
int sp_ecc_secret_gen_sm2_256(const mp_int* priv, const ecc_point* pub, byte* out,
                          word32* outLen, void* heap)
{
    SP_DECL_VAR(sp_point_256, point, 1);
    SP_DECL_VAR(sp_digit, k, 4);
    int err = MP_OKAY;

    if (*outLen < 32U) {
        err = BUFFER_E;
    }

    SP_ALLOC_VAR(sp_point_256, point, 1, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, k, 4, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_256_from_mp(k, 4, priv);
        sp_256_point_from_ecc_point_4(point, pub);
            err = sp_256_ecc_mulmod_sm2_4(point, point, k, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_256_to_bin_4(point->x, out);
        *outLen = 32;
    }

    SP_FREE_VAR(k, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(point, heap, DYNAMIC_TYPE_ECC);

    return err;
}

#ifdef WOLFSSL_SP_NONBLOCK
typedef struct sp_ecc_sec_gen_256_ctx {
    int state;
    union {
        sp_256_ecc_mulmod_sm2_4_ctx mulmod_ctx;
    };
    sp_digit k[4];
    sp_point_256 point;
} sp_ecc_sec_gen_256_ctx;

/* Multiply the point by the scalar and serialize the X ordinate.
 * The number is 0 padded to maximum size on output.
 *
 * Non-blocking version.  Call repeatedly until it does not return
 * FP_WOULDBLOCK.  State is saved and restored through sp_ctx.
 *
 * @param [in, out] sp_ctx  Context to save state in for non-blocking calls.
 * @param [in]      priv    Scalar to multiply the point by.
 * @param [in]      pub     Point to multiply.
 * @param [out]     out     Buffer to hold X ordinate.
 * @param [in, out] outLen  On entry, size of the buffer in bytes.
 *                          On exit, length of data in buffer in bytes.
 * @param [in]      heap    Heap to use for allocation.
 *
 * @return  MP_OKAY on success.
 * @return  FP_WOULDBLOCK while more work remains.
 * @return  BUFFER_E when the buffer is too small for output size.
 * @return  MEMORY_E when memory allocation fails.
 */
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
 * @param [out] r  Result of the multiplication.
 * @param [in]  a  First operand of the multiplication.
 * @param [in]  b  Second operand of the multiplication.
 */
static void sp_256_mont_mul_order_sm2_4(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_sm2_4(r, a, b);
    sp_256_mont_reduce_order_sm2_4(r, p256_sm2_order, p256_sm2_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * @param [out] r  Result of the squaring.
 * @param [in]  a  Number to square.
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
 * @param [out] r  Result of the squaring.
 * @param [in]  a  Number to square.
 * @param [in]  n  Number of times to square.
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
                sp_256_mul_sm2_4(x, x, p256_sm2_norm_order);
            err = sp_256_mod_sm2_4(x, x, p256_sm2_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_4(x);

            /* s = k - r * x */
                sp_256_mont_mul_order_sm2_4(s, x, r);
        }
        if (err == MP_OKAY) {
            sp_256_norm_4(s);
            c = sp_256_sub_sm2_4(s, k, s);
            sp_256_cond_add_sm2_4(s, s, p256_sm2_order, c);
            sp_256_norm_4(s);

            /* xInv = 1/(x+1) mod order */
            sp_256_add_sm2_4(x, x, p256_sm2_norm_order);

                sp_256_mont_inv_order_sm2_4(xInv, x, tmp);
            sp_256_norm_4(xInv);

            /* s = s * (x+1)^-1 mod order */
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
            err = sp_256_ecc_mulmod_base_sm2_4(p1, s, 0, 0, heap);
    }
    if ((err == MP_OKAY) && (!done)) {
        {
            err = sp_256_ecc_mulmod_sm2_4(p2, p2, e, 0, 0, heap);
        }
    }

    if ((err == MP_OKAY) && (!done)) {
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

/* Check that the x and y ordinates are a valid point on the curve.
 *
 * @param [in] point  EC point.
 * @param [in] heap   Heap to use if dynamically allocating.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  MP_VAL when the point is not on the curve.
 */
static int sp_256_ecc_is_point_sm2_4(const sp_point_256* point,
    void* heap)
{
    SP_DECL_VAR(sp_digit, t1, 4 * 4);
    sp_digit* t2 = NULL;
    int err = MP_OKAY;

    (void)heap;

    SP_ALLOC_VAR(sp_digit, t1, 4 * 4, heap, DYNAMIC_TYPE_ECC);
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

    SP_FREE_VAR(t1, heap, DYNAMIC_TYPE_ECC);

    return err;
}

/* Check that the x and y ordinates are a valid point on the curve.
 *
 * @param [in] pX  X ordinate of EC point.
 * @param [in] pY  Y ordinate of EC point.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  MP_VAL when the point is not on the curve.
 */
int sp_ecc_is_point_sm2_256(const mp_int* pX, const mp_int* pY)
{
    SP_DECL_VAR(sp_point_256, pub, 1);
    const byte one[1] = { 1 };
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_point_256, pub, 1, NULL, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_256_from_mp(pub->x, 4, pX);
        sp_256_from_mp(pub->y, 4, pY);
        sp_256_from_bin(pub->z, 4, one, (int)sizeof(one));

        err = sp_256_ecc_is_point_sm2_4(pub, NULL);
    }

    SP_FREE_VAR(pub, NULL, DYNAMIC_TYPE_ECC);

    return err;
}

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
/* Check that the private scalar generates the EC point (px, py), the point is
 * on the curve and the point has the correct order.
 *
 * @param [in] pX     X ordinate of EC point.
 * @param [in] pY     Y ordinate of EC point.
 * @param [in] privm  Private scalar that generates EC point.
 * @param [in] heap   Heap to use for allocation.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  MP_VAL when the point is not on the curve.
 * @return  ECC_INF_E when the point does not have the correct order.
 * @return  ECC_PRIV_KEY_E when the private scalar doesn't generate the EC
 *          point.
 */
int sp_ecc_check_key_sm2_256(const mp_int* pX, const mp_int* pY,
    const mp_int* privm, void* heap)
{
    SP_DECL_VAR(sp_digit, priv, 4);
    SP_DECL_VAR(sp_point_256, pub, 2);
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

    SP_ALLOC_VAR(sp_digit, priv, 4, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_point_256, pub, 2, heap, DYNAMIC_TYPE_ECC);
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
                err = sp_256_ecc_mulmod_base_sm2_4(p, priv, 1, 1, heap);
        }
        /* Check result is public key */
        if ((err == MP_OKAY) &&
                ((sp_256_cmp_sm2_4(p->x, pub->x) != 0) ||
                 (sp_256_cmp_sm2_4(p->y, pub->y) != 0))) {
            err = ECC_PRIV_KEY_E;
        }
    }

    SP_FREE_VAR(pub, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(priv, heap, DYNAMIC_TYPE_ECC);

    return err;
}
#endif
#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
/* Add two projective EC points together.
 * (pX, pY, pZ) + (qX, qY, qZ) = (rX, rY, rZ)
 *
 * @param [in]  pX  First EC point's X ordinate.
 * @param [in]  pY  First EC point's Y ordinate.
 * @param [in]  pZ  First EC point's Z ordinate.
 * @param [in]  qX  Second EC point's X ordinate.
 * @param [in]  qY  Second EC point's Y ordinate.
 * @param [in]  qZ  Second EC point's Z ordinate.
 * @param [out] rX  Resultant EC point's X ordinate.
 * @param [out] rY  Resultant EC point's Y ordinate.
 * @param [out] rZ  Resultant EC point's Z ordinate.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int sp_ecc_proj_add_point_sm2_256(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* qX, mp_int* qY, mp_int* qZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
    SP_DECL_VAR(sp_digit, tmp, 2 * 4 * 6);
    SP_DECL_VAR(sp_point_256, p, 2);
    sp_point_256* q = NULL;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_digit, tmp, 2 * 4 * 6, NULL, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_point_256, p, 2, NULL, DYNAMIC_TYPE_ECC);
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

    SP_FREE_VAR(p, NULL, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(tmp, NULL, DYNAMIC_TYPE_ECC);

    return err;
}

/* Double a projective EC point.
 * (pX, pY, pZ) + (pX, pY, pZ) = (rX, rY, rZ)
 *
 * @param [in]  pX  EC point's X ordinate.
 * @param [in]  pY  EC point's Y ordinate.
 * @param [in]  pZ  EC point's Z ordinate.
 * @param [out] rX  Resultant EC point's X ordinate.
 * @param [out] rY  Resultant EC point's Y ordinate.
 * @param [out] rZ  Resultant EC point's Z ordinate.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int sp_ecc_proj_dbl_point_sm2_256(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
    SP_DECL_VAR(sp_digit, tmp, 2 * 4 * 2);
    SP_DECL_VAR(sp_point_256, p, 1);
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_digit, tmp, 2 * 4 * 2, NULL, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_point_256, p, 1, NULL, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 4, pX);
        sp_256_from_mp(p->y, 4, pY);
        sp_256_from_mp(p->z, 4, pZ);
        p->infinity = sp_256_iszero_4(p->x) &
                      sp_256_iszero_4(p->y);

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

    SP_FREE_VAR(p, NULL, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(tmp, NULL, DYNAMIC_TYPE_ECC);

    return err;
}

/* Map a projective EC point to affine in place.
 * pZ will be one.
 *
 * @param [in] pX  EC point's X ordinate.
 * @param [in] pY  EC point's Y ordinate.
 * @param [in] pZ  EC point's Z ordinate.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int sp_ecc_map_sm2_256(mp_int* pX, mp_int* pY, mp_int* pZ)
{
    SP_DECL_VAR(sp_digit, tmp, 2 * 4 * 5);
    SP_DECL_VAR(sp_point_256, p, 1);
    int err = MP_OKAY;


    SP_ALLOC_VAR(sp_digit, tmp, 2 * 4 * 5, NULL, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_point_256, p, 1, NULL, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 4, pX);
        sp_256_from_mp(p->y, 4, pY);
        sp_256_from_mp(p->z, 4, pZ);
        p->infinity = sp_256_iszero_4(p->x) &
                      sp_256_iszero_4(p->y);

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

    SP_FREE_VAR(p, NULL, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(tmp, NULL, DYNAMIC_TYPE_ECC);

    return err;
}
#endif /* WOLFSSL_PUBLIC_ECC_ADD_DBL */
#ifdef HAVE_COMP_KEY
/* Square root power for the P256 curve. */
static const word64 p256_sm2_sqrt_power[4] = {
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

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 4, NULL, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {

        {
            int i;

            XMEMCPY(t, y, sizeof(sp_digit) * 4);
            for (i=252; i>=0; i--) {
                sp_256_mont_sqr_sm2_4(t, t, p256_sm2_mod, p256_sm2_mp_mod);
                if (p256_sm2_sqrt_power[i / 64] & ((sp_uint64)1 << (i % 64)))
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
 * @param [in]  xm   X ordinate.
 * @param [in]  odd  Whether the Y ordinate is odd.
 * @param [out] ym   Calculated Y ordinate.
 *
 * @return  MP_OKAY otherwise.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int sp_ecc_uncompress_sm2_256(mp_int* xm, int odd, mp_int* ym)
{
    SP_DECL_VAR(sp_digit, x, 4 * 4);
    sp_digit* y = NULL;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_digit, x, 4 * 4, NULL, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        y = x + 2 * 4;

        sp_256_from_mp(x, 4, xm);
        err = sp_256_mod_mul_norm_sm2_4(x, x, p256_sm2_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
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

    SP_FREE_VAR(x, NULL, DYNAMIC_TYPE_ECC);

    return err;
}
#endif
#endif /* WOLFSSL_SP_SM2 */
#endif /* WOLFSSL_HAVE_SP_ECC */
#endif /* WOLFSSL_SP_RISCV64_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
