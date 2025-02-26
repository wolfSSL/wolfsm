/* sm3.c
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

/* For more info on the algorithm, see:
 *   https://datatracker.ietf.org/doc/html/draft-oscca-cfrg-sm3-02
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SM3

#include <wolfssl/wolfcrypt/sm3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP)
    #if defined(__GNUC__) && ((__GNUC__ < 4) || \
                              (__GNUC__ == 4 && __GNUC_MINOR__ <= 8))
        #undef  NO_AVX2_SUPPORT
        #define NO_AVX2_SUPPORT
    #endif
    #if defined(__clang__) && ((__clang_major__ < 3) || \
                               (__clang_major__ == 3 && __clang_minor__ <= 5))
        #define NO_AVX2_SUPPORT
    #elif defined(__clang__) && defined(NO_AVX2_SUPPORT)
        #undef NO_AVX2_SUPPORT
    #endif

    #define HAVE_INTEL_AVX1
    #ifndef NO_AVX2_SUPPORT
        #define HAVE_INTEL_AVX2
    #endif
#else
    #undef HAVE_INTEL_AVX1
    #undef HAVE_INTEL_AVX2
#endif /* WOLFSSL_X86_64_BUILD && USE_INTEL_SPEEDUP */

#if defined(HAVE_INTEL_AVX2)
    #define HAVE_INTEL_RORX
#endif

/******************************************************************************/

/* To support different implementations at the same time, replace these
 * functions with ones that vector off to the appropriate implementation.
 *
 * Have SM3_COMPRESS call the function in a global function pointer if the
 * choice can be made up front.
 * Same for SM3_COMPRESS_LEN if available.
 */

/* Compression process applied to one block. Block's endian has been fixed. */
typedef void (*SM3_COMPRESS_FUNC)(wc_Sm3* sm3, const word32* block);
/* Compression process applied to one or more blocks. Data big-endian. */
typedef void (*SM3_COMPRESS_LEN_FUNC)(wc_Sm3* sm3, const byte* data,
    word32 len);

/* Prototype for platforms where it is the default implementation. */
static void sm3_compress_c(wc_Sm3* sm3, const word32* block);
static void sm3_compress_len_c(wc_Sm3* sm3, const byte* data, word32 len);


#ifdef USE_INTEL_SPEEDUP

/* C and x64 assembly implementations available. */

/* Compression process function that is changed depending on CPUs capabilities.
 * Default is C implementation.
 */
SM3_COMPRESS_FUNC     sm3_compress_func     = &sm3_compress_c;
/* Compression process with length function that is changed depending on CPUs
 * capabilities. Default is C implementation.
 */
SM3_COMPRESS_LEN_FUNC sm3_compress_len_func = &sm3_compress_len_c;

/* Prototype of assembly functions. */
extern void sm3_compress_avx1_rorx(wc_Sm3* sm3, const word32* block);
extern void sm3_compress_len_avx1_rorx(wc_Sm3* sm3, const byte* data,
    word32 len);
extern void sm3_compress_avx1(wc_Sm3* sm3, const word32* block);
extern void sm3_compress_len_avx1(wc_Sm3* sm3, const byte* data, word32 len);

/* Sets the compression process functions based on CPU information.
 */
static void sm3_set_compress_x64(void)
{
    /* Boolean indicating choice of compression functions made. */
    static int compress_funcs_set = 0;
    /* Intel CPU Id flags. */
    static int intel_cpuid_flags;

    /* Only set functions once. */
    if (!compress_funcs_set) {
        /* Get CPU Id flags. */
        intel_cpuid_flags = cpuid_get_flags();
    #ifdef HAVE_INTEL_AVX1
        /* Use AVX1 assembly implementation if flags say AVX1 available. */
        if (IS_INTEL_AVX1(intel_cpuid_flags)) {
            if (IS_INTEL_BMI2(intel_cpuid_flags) &&
                    IS_INTEL_BMI1(intel_cpuid_flags)) {
                sm3_compress_func = &sm3_compress_avx1_rorx;
                sm3_compress_len_func = &sm3_compress_len_avx1_rorx;
            }
            else {
                sm3_compress_func = &sm3_compress_avx1;
                sm3_compress_len_func = &sm3_compress_len_avx1;
            }
        }
    #endif
        /* Compression functions set - don't set again. */
        compress_funcs_set = 1;
    }
}

/* Set the compression functions to use. */
#define SM3_SET_COMPRESS()                  sm3_set_compress_x64()
/* Compression process for a block uses function pointer. */
#define SM3_COMPRESS(sm3, block)            (*sm3_compress_func)(sm3, block)
/* Compression process with length uses function pointer. */
#define SM3_COMPRESS_LEN(sm3, data, len)    \
    (*sm3_compress_len_func)(sm3, data, len)
/* Only use C implementation of final process. */
#define sm3_final(sm3)                      sm3_final_c(sm3)

#else

/* Only C implementation compiled in. */

/* No global function pointers to set. */
#define SM3_SET_COMPRESS()
/* Only use C implementation of compression process. */
#define SM3_COMPRESS(sm3, block)            sm3_compress_c(sm3, block)
/* Only use C implementation of multi-block compression process. */
#define SM3_COMPRESS_LEN(sm3, data, len)    sm3_compress_len_c(sm3, data, len)
/* Only use C implementation of final process. */
#define sm3_final(sm3)                      sm3_final_c(sm3)

#endif

/******************************************************************************/

/* To replace C implementation use #ifdef around this code.
 * Also around prototypes.
 */

/* Reverse block size worth of 32-bit words.
 *
 * @param [out] out  Output buffer to write to.
 * @param [in]  in   Buffer to reverse.
 */
#define BSWAP32_16(out, in) \
    ByteReverseWords((word32*)(out), (const word32*)(in), WC_SM3_BLOCK_SIZE)

/* Reverse digest size worth of 32-bit words.
 *
 * @param [out] out  Output buffer to write to.
 * @param [in]  in   Buffer to reverse.
 */
#define BSWAP32_8(out, in) \
    ByteReverseWords((word32*)(out), (const word32*)(in), WC_SM3_DIGEST_SIZE)

#if !(defined(WOLFSSL_X86_64_BUILD) || defined(WOLFSSL_X86_BUILD))
/* Permutation function within the compression function.
 *
 * @param [in] x  Value to use.
 * @return  Permutated result.
 */
#define P0(x)       ((x) ^ rotlFixed((x),  9) ^ rotlFixed((x), 17))
/* Permutation function within the message expansion.
 *
 * @param [in] x  Value to use.
 * @return  Permutated result.
 */
#define P1(x)       ((x) ^ rotlFixed((x), 15) ^ rotlFixed((x), 23))
#else
/* These are faster when you don't have 3 argument rotate instructions. */

/* Permutation function within the compression function.
 *
 * @param [in] x  Value to use.
 * @return  Permutated result.
 */
#define P0(x)       ((x) ^ rotlFixed((x) ^ rotlFixed((x), 8), 9))
/* Permutation function within the message expansion.
 *
 * @param [in] x  Value to use.
 * @return  Permutated result.
 */
#define P1(x)       ((x) ^ rotlFixed((x) ^ rotlFixed((x), 8), 15))
#endif

/* Calculates w based on previous values and j.
 *
 * @param [in] w  Array of 32-bit values.
 * @param [in] j  Index into array to use.
 * @return  New 32-bit value to be placed into array.
 */
#define W(w, j)     P1((w)[(j)-16] ^ (w)[(j)-9] ^ rotlFixed((w)[(j)-3], 15)) ^ \
                    rotlFixed((w)[(j)-13], 7) ^ (w)[(j)-6]

#ifdef SM3_STANDARD
/* Boolean function FF.
 *
 * Original function as described in standard.
 *
 * @param [in] x  First value.
 * @param [in] y  Second value.
 * @param [in] z  Third value.
 * @param [in] j  Iteration count.
 * @return  32-bit value that is the FF calculation.
 */
#define FF(x, y, z, j)  (((j) < 16) ? ((x) ^ (y) ^ (z)) : \
                                      (((x) & (y)) | ((x) & (z)) | ((y) & (z))))
#else
/* Boolean function FF.
 *
 * Equivalent to standard but fewer operations.
 *
 * @param [in] x  First value.
 * @param [in] y  Second value.
 * @param [in] z  Third value.
 * @param [in] j  Iteration count.
 * @return  32-bit value that is the FF calculation.
 */
#define FF(x, y, z, j)  (((j) < 16) ? ((x) ^ (y) ^ (z)) : \
                                      ((((y) ^ (x)) & ((y) ^ (z))) ^ (y)))
#endif /* SM3_STANDARD */

/* Boolean function GG.
 *
 * @param [in] x  First value.
 * @param [in] y  Second value.
 * @param [in] z  Third value.
 * @param [in] j  Iteration count.
 * @return  32-bit value that is the GG calculation.
 */
#define GG(x, y, z, j)  (((j) < 16) ? ((x) ^ (y) ^ (z)) : \
                                      (((x) & (y)) | ((~(x)) & (z))))
/* Alternative that is no faster: ((((y) ^ (z)) & (x)) ^ (z))) */

/* Unrolled loop when not small. */
#ifndef WOLFSSL_SM3_SMALL

/* A-H values for iteration i. */
#define A(i)    v[(0-(i)) & 7]
#define B(i)    v[(1-(i)) & 7]
#define C(i)    v[(2-(i)) & 7]
#define D(i)    v[(3-(i)) & 7]
#define E(i)    v[(4-(i)) & 7]
#define F(i)    v[(5-(i)) & 7]
#define G(i)    v[(6-(i)) & 7]
#define H(i)    v[(7-(i)) & 7]

/* An iteration of merged message expansion and compression function.
 * Loop unrolled by 8 so that registers are not rotated around.
 *
 * Call when: i + j < 12
 *
 * @param [in] i  Index of unrolled 8 iterations.
 * @param [in] j  Index of iteration - multiple of 8.
 */
#define SM3_ITER_INIT(i, j)                                             \
    ss2 = rotlFixed(A(i), 12);                                          \
    ss1 = rotlFixed((ss2 + E(i) + SM3_T[(j)+(i)]), 7);                  \
    ss2 ^= ss1;                                                         \
    ss1 += w[(j)+(i)];                                                  \
    ss2 += w[(j)+(i)] ^ w[(j)+(i)+4];                                   \
    tt1 = FF(A(i), B(i), C(i), (j)+(i)) + D(i) + ss2;                   \
    tt2 = GG(E(i), F(i), G(i), (j)+(i)) + H(i) + ss1;                   \
    B(i) = rotlFixed(B(i), 9);                                          \
    F(i) = rotlFixed(F(i), 19);                                         \
    H(i) = tt1;                                                         \
    D(i) = P0(tt2)

/* An iteration of merged message expansion and compression function.
 * Loop unrolled by 8 so that registers are not rotated around.
 *
 * Call when: i + j >= 12
 *
 * @param [in] i  Index of unrolled 8 iterations.
 * @param [in] j  Index of iteration - multiple of 8.
 */
#define SM3_ITER(i, j)                                                  \
    w[(j)+(i)+4] = W(w, (j)+(i)+4);                                     \
    ss2 = rotlFixed(A(i), 12);                                          \
    ss1 = rotlFixed((ss2 + E(i) + SM3_T[(j)+(i)]), 7);                  \
    ss2 ^= ss1;                                                         \
    ss1 += w[(j)+(i)];                                                  \
    ss2 += w[(j)+(i)] ^ w[(j)+(i)+4];                                   \
    tt1 = FF(A(i), B(i), C(i), (j)+(i)) + D(i) + ss2;                   \
    tt2 = GG(E(i), F(i), G(i), (j)+(i)) + H(i) + ss1;                   \
    B(i) = rotlFixed(B(i), 9);                                          \
    F(i) = rotlFixed(F(i), 19);                                         \
    H(i) = tt1;                                                         \
    D(i) = P0(tt2)

#endif /* !WOLFSSL_SM3_SMALL */

#ifdef SM3_PREPROCESSOR_CALC_T
/* Rotate left by r. */
#define ROTL(v, r) (((word32)(v) << (r)) | ((word32)(v) >> (32 - (r))))
/* First table value - rotated by 0. */
#define T_00_00(i)  0x79cc4519
/* Table value calculation for iterations: 1 - 16. */
#define T_01_15(i)  ROTL(0x79cc4519, (i))
/* Table value calculation for iterations: 16 - 63. */
#define T_16_63(i)  ROTL(0x7a879d8a, (i))
/* Table value for iteration 32 - rotated by 0. */
#define T_32_32(i)  0x7a879d8a

/* Constants for each iteration. */
static const FLASH_QUALIFIER word32 SM3_T[64] = {
    T_00_00( 0), T_01_15( 1), T_01_15( 2), T_01_15( 3),
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM3)
    T_01_15( 4), T_01_15( 5), T_01_15( 6), T_01_15( 7),
    T_01_15( 8), T_01_15( 9), T_01_15(10), T_01_15(11),
    T_01_15(12), T_01_15(13), T_01_15(14), T_01_15(15),
#endif
    T_16_63(16), T_16_63(17), T_16_63(18), T_16_63(19),
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM3)
    T_16_63(20), T_16_63(21), T_16_63(22), T_16_63(23),
    T_16_63(24), T_16_63(25), T_16_63(26), T_16_63(27),
    T_16_63(28), T_16_63(29), T_16_63(30), T_16_63(31),
    T_32_32( 0), T_16_63( 1), T_16_63( 2), T_16_63( 3),
    T_16_63( 4), T_16_63( 5), T_16_63( 6), T_16_63( 7),
    T_16_63( 8), T_16_63( 9), T_16_63(10), T_16_63(11),
    T_16_63(12), T_16_63(13), T_16_63(14), T_16_63(15),
    T_16_63(16), T_16_63(17), T_16_63(18), T_16_63(19),
    T_16_63(20), T_16_63(21), T_16_63(22), T_16_63(23),
    T_16_63(24), T_16_63(25), T_16_63(26), T_16_63(27),
    T_16_63(28), T_16_63(29), T_16_63(30), T_16_63(31),
#endif
};
#else
/* Constants for each iteration. */
static const FLASH_QUALIFIER word32 SM3_T[64] = {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM3)
    0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
    0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
#endif
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM3)
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53,
    0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4,
    0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5
#endif
};
#endif


/* Compression process applied to a block of data and current values.
 *
 * 32-bit words are in appropriate order for CPU.
 *
 * @param [in, out] sm3    SM3 hash object.
 * @param [in]      block  Block of data that is 512 bits (64 byte) long.
 */
static void sm3_compress_c(wc_Sm3* sm3, const word32* block)
{
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM3)

#ifdef WOLFSSL_SM3_SMALL
#ifndef WOLFSSL_SMALL_STACK
    word32 w[68];
#else
    word32* w = sm3->w;
#endif
    word32 v[8];
    int j;

    /* Copy in first 16 32-bit words. */
    XMEMCPY(w, block, WC_SM3_BLOCK_SIZE);

    /* Copy values into temporary. */
    v[0] = sm3->v[0];
    v[1] = sm3->v[1];
    v[2] = sm3->v[2];
    v[3] = sm3->v[3];
    v[4] = sm3->v[4];
    v[5] = sm3->v[5];
    v[6] = sm3->v[6];
    v[7] = sm3->v[7];

    /* Do 64 iterations of the compression process. */
    for (j = 0; j < 64; j++) {
        word32 ss1;
        word32 ss2;
        word32 tt1;
        word32 tt2;

        /* Need 4 ahead of the expanded message value. */
        if ((j + 4) >= 16) {
            w[j+4] = W(w, j+4);
        }
        /* Compression function. */
        ss1 = rotlFixed((rotlFixed(v[0], 12) + v[4] + SM3_T[j]), 7);
        ss2 = ss1 ^ rotlFixed(v[0], 12);
        tt1 = FF(v[0], v[1], v[2], j) + v[3] + ss2 + (w[j] ^ w[j+4]);
        tt2 = GG(v[4], v[5], v[6], j) + v[7] + ss1 + w[j];
        v[3] = v[2];
        v[2] = rotlFixed(v[1], 9);
        v[1] = v[0];
        v[0] = tt1;
        v[7] = v[6];
        v[6] = rotlFixed(v[5], 19);
        v[5] = v[4];
        v[4] = P0(tt2);
    }

    /* XOR result into current values. */
    sm3->v[0] ^= v[0];
    sm3->v[1] ^= v[1];
    sm3->v[2] ^= v[2];
    sm3->v[3] ^= v[3];
    sm3->v[4] ^= v[4];
    sm3->v[5] ^= v[5];
    sm3->v[6] ^= v[6];
    sm3->v[7] ^= v[7];
#else
#ifndef WOLFSSL_SMALL_STACK
    word32 w[68];
#else
    word32* w = sm3->w;
#endif
    word32 v[8];
    word32 ss1;
    word32 ss2;
    word32 tt1;
    word32 tt2;
    int j;

    /* Copy in first 16 32-bit words. */
    XMEMCPY(w, block, WC_SM3_BLOCK_SIZE);

    /* Copy values into temporary. */
    v[0] = sm3->v[0];
    v[1] = sm3->v[1];
    v[2] = sm3->v[2];
    v[3] = sm3->v[3];
    v[4] = sm3->v[4];
    v[5] = sm3->v[5];
    v[6] = sm3->v[6];
    v[7] = sm3->v[7];

    /* First 8 iterations of the compression process. */
    SM3_ITER_INIT(0, 0); SM3_ITER_INIT(1, 0);
    SM3_ITER_INIT(2, 0); SM3_ITER_INIT(3, 0);
    SM3_ITER_INIT(4, 0); SM3_ITER_INIT(5, 0);
    SM3_ITER_INIT(6, 0); SM3_ITER_INIT(7, 0);
    /* Next 8 iterations of the compression process.
     * Last 4 iterations need to to calculate expansion values.
     */
    SM3_ITER_INIT(0, 8); SM3_ITER_INIT(1, 8);
    SM3_ITER_INIT(2, 8); SM3_ITER_INIT(3, 8);
    SM3_ITER(4, 8); SM3_ITER(5, 8); SM3_ITER(6, 8); SM3_ITER(7, 8);
    /* Remaining iterations of the compression process.
     * Different FF and GG operations.
     */
    for (j = 16; j < 64; j += 8) {
        SM3_ITER(0, j); SM3_ITER(1, j); SM3_ITER(2, j); SM3_ITER(3, j);
        SM3_ITER(4, j); SM3_ITER(5, j); SM3_ITER(6, j); SM3_ITER(7, j);
    }

    /* XOR result into current values. */
    sm3->v[0] ^= v[0];
    sm3->v[1] ^= v[1];
    sm3->v[2] ^= v[2];
    sm3->v[3] ^= v[3];
    sm3->v[4] ^= v[4];
    sm3->v[5] ^= v[5];
    sm3->v[6] ^= v[6];
    sm3->v[7] ^= v[7];
#endif

#else

    word32 w[WC_SM3_BLOCK_SIZE / 4];
    word32 v[8];
    word32* wt;
    word32* vt = v;

    /* Use passed in buffer if aligned. */
    if (((size_t)block & 0x3) == 0) {
        wt = (word32*)block;
    }
    /* Copy into aligned buffer. */
    else {
        XMEMCPY(w, block, WC_SM3_BLOCK_SIZE);
        wt = w;
    }

    /* Copy values into temporary. */
    v[0] = sm3->v[3];
    v[1] = sm3->v[2];
    v[2] = sm3->v[1];
    v[3] = sm3->v[0];
    v[4] = sm3->v[7];
    v[5] = sm3->v[6];
    v[6] = sm3->v[5];
    v[7] = sm3->v[4];

    /* Do 64 iterations of the compression process. */
    __asm__ volatile (
        "LD1	{v8.16b-v11.16b}, [%[w]], #64\n\t"
        "LD1	{v0.16b, v1.16b}, [%[v]]\n\t"
        "LD1	{v3.16b}, [%[t]]\n\t"

        /* Compression function. */
        "MOV	v12.16b, v8.16b\n\t"
        "MOV	v13.16b, v9.16b\n\t"
        "MOV	v14.16b, v10.16b\n\t"
        "MOV	v15.16b, v11.16b\n\t"
        "MOV	x4, #3\n\t"
    "2:\n\t"
        "EOR	v6.16b, v13.16b, v12.16b\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #4\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[0], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[0]\n\t"
        /* Vm=v4[0], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v12.S[0]\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #8\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[1], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[1]\n\t"
        /* Vm=v4[1], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v12.S[1]\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #12\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[2], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[2]\n\t"
        /* Vm=v4[2], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v12.S[2]\n\t"

        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v3.4s\n\t"
        /* Vm=v6[3], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[3]\n\t"
        /* Vm=v4[3], Vn=ss1, V d=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v12.S[3]\n\t"

        "SUBS	x4, x4, #1\n\t"
        "MOV	v12.16B, v13.16B\n\t"
        "SHL	v4.4S, v3.4S, #4\n\t"
        "MOV	v13.16B, v14.16B\n\t"
        "SRI	v4.4S, v3.4S, #28\n\t"
        "MOV	v14.16B, v15.16B\n\t"
        "MOV	v3.16B, v4.16B\n\t"
        "BNE	2b\n\t"

        /* W[-13] */
        "EXT	v4.16b, v8.16b, v9.16b, #12\n\t"
        /* W[-9] */
        "EXT	v5.16b, v9.16b, v10.16b, #12\n\t"
        /* W[-6] */
        "EXT	v6.16b, v10.16b, v11.16b, #8\n\t"
        /* Vd=W-16=v8, Vn=W-9=v5, Vm=W-4=v11 */
        "SM3PARTW1	v8.4S, v5.4S, v11.4S\n\t"
        /* Vd=v8, Vn=W-6=v6, Vm=W-13=v4 */
        "SM3PARTW2	v8.4S, v6.4S, v4.4S\n\t"

        /* Compression function. */
        "EOR	v6.16b, v8.16b, v11.16b\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #4\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[0], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[0]\n\t"
        /* Vm=v11[0], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v11.S[0]\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #8\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[1], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[1]\n\t"
        /* Vm=v11[1], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v11.S[1]\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #12\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[2], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[2]\n\t"
        /* Vm=v11[2], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v11.S[2]\n\t"

        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v3.4s\n\t"
        /* Vm=v6[3], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1A	v0.4S, v2.4S, v6.S[3]\n\t"
        /* Vm=v11[3], Vn=ss1, V d=[v[7],v[6],v[5],v[4]] */
        "SM3TT2A	v1.4S, v2.4S, v11.S[3]\n\t"

        "MOV	x4, #3\n\t"
        "LD1	{v3.16b}, [%[t2]]\n\t"
    "1:\n\t"
        /* W[-13] */
        "EXT	v4.16b, v9.16b, v10.16b, #12\n\t"
        /* W[-9] */
        "EXT	v5.16b, v10.16b, v11.16b, #12\n\t"
        /* W[-6] */
        "EXT	v6.16b, v11.16b, v8.16b, #8\n\t"
        /* Vd=W-16=v9, Vn=W-9=v5, Vm=W-4=v8 */
        "SM3PARTW1	v9.4S, v5.4S, v8.4S\n\t"
        /* Vd=v9, Vn=W-6=v6, Vm=W-13=v4 */
        "SM3PARTW2	v9.4S, v6.4S, v4.4S\n\t"

        /* W[-13] */
        "EXT	v4.16b, v10.16b, v11.16b, #12\n\t"
        /* W[-9] */
        "EXT	v5.16b, v11.16b, v8.16b, #12\n\t"
        /* W[-6] */
        "EXT	v6.16b, v8.16b, v9.16b, #8\n\t"
        /* Vd=W-16=v10, Vn=W-9=v5, Vm=W-4=v9 */
        "SM3PARTW1	v10.4S, v5.4S, v9.4S\n\t"
        /* Vd=v10, Vn=W-6=v6, Vm=W-13=v4 */
        "SM3PARTW2	v10.4S, v6.4S, v4.4S\n\t"

        /* W[-13] */
        "EXT	v4.16b, v11.16b, v8.16b, #12\n\t"
        /* W[-9] */
        "EXT	v5.16b, v8.16b, v9.16b, #12\n\t"
        /* W[-6] */
        "EXT	v6.16b, v9.16b, v10.16b, #8\n\t"
        /* Vd=W-16=v11, Vn=W-9=v5, Vm=W-4=v10 */
        "SM3PARTW1	v11.4S, v5.4S, v10.4S\n\t"
        /* Vd=v11, Vn=W-6=v6, Vm=W-13=v4 */
        "SM3PARTW2	v11.4S, v6.4S, v4.4S\n\t"

        "MOV	v12.16B, v8.16B\n\t"
        /* W[-13] */
        "EXT	v4.16b, v8.16b, v9.16b, #12\n\t"
        /* W[-9] */
        "EXT	v5.16b, v9.16b, v10.16b, #12\n\t"
        /* W[-6] */
        "EXT	v6.16b, v10.16b, v11.16b, #8\n\t"
        /* Vd=W-16=v8, Vn=W-9=v5, Vm=W-4=v11 */
        "SM3PARTW1	v8.4S, v5.4S, v11.4S\n\t"
        /* Vd=v8, Vn=W-6=v6, Vm=W-13=v4 */
        "SM3PARTW2	v8.4S, v6.4S, v4.4S\n\t"

        "MOV	x5, #4\n\t"
        "MOV	v13.16B, v9.16B\n\t"
        "MOV	v14.16B, v10.16B\n\t"
        "MOV	v15.16B, v11.16B\n\t"
        "MOV	v4.16B, v8.16B\n\t"
    "3:\n\t"
        "EOR	v6.16b, v13.16b, v12.16b\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #4\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[0], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1B	v0.4S, v2.4S, v6.S[0]\n\t"
        /* Vm=v12[0], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2B	v1.4S, v2.4S, v12.S[0]\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #8\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[1], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1B	v0.4S, v2.4S, v6.S[1]\n\t"
        /* Vm=v12[1], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2B	v1.4S, v2.4S, v12.S[1]\n\t"

        "EXT	v7.16b, v7.16b, v3.16b, #12\n\t"
        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v7.4s\n\t"
        /* Vm=v6[2], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1B	v0.4S, v2.4S, v6.S[2]\n\t"
        /* Vm=v12[2], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2B	v1.4S, v2.4S, v12.S[2]\n\t"

        /* Vm[3]=v[4], Vn[3]=v[0], Vd=v2, Va[3]=SM3_T[j] */
        "SM3SS1	v2.4S, v0.4s, v1.4s, v3.4s\n\t"
        /* Vm=v6[3], Vn=ss1, Vd=[v[3],v[2],v[1],v[0]] */
        "SM3TT1B	v0.4S, v2.4S, v6.S[3]\n\t"
        /* Vm=v12[3], Vn=ss1, Vd=[v[7],v[6],v[5],v[4]] */
        "SM3TT2B	v1.4S, v2.4S, v12.S[3]\n\t"

        "SUBS	x5, x5, #1\n\t"
        "MOV	v12.16B, v13.16B\n\t"
        "SHL	v7.4S, v3.4S, #4\n\t"
        "MOV	v13.16B, v14.16B\n\t"
        "SRI	v7.4S, v3.4S, #28\n\t"
        "MOV	v14.16B, v15.16B\n\t"
        "MOV	v3.16B, v7.16B\n\t"
        "MOV	v15.16B, v4.16B\n\t"
        "BNE	3b\n\t"

        "SUBS	x4, x4, #1\n\t"
        "BNE	1b\n\t"

        /* Store result of hash. */
        "ST1	{v0.16b, v1.16b}, [%[v]]\n\t"
        :
        : [w] "r" (wt), [v] "r" (vt), [t] "r" (SM3_T), [t2] "r" (SM3_T + 4)
        : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "x4", "x5"
    );

    /* XOR result into current values. */
    sm3->v[0] ^= v[3];
    sm3->v[1] ^= v[2];
    sm3->v[2] ^= v[1];
    sm3->v[3] ^= v[0];
    sm3->v[4] ^= v[7];
    sm3->v[5] ^= v[6];
    sm3->v[6] ^= v[5];
    sm3->v[7] ^= v[4];

#endif
}

/* Compression process applied to a multiplie blocks of data and current values.
 *
 * @param [in, out] sm3   SM3 hash object.
 * @param [in]      data  Data to compress as a byte array.
 * @param [in]      len   Number of bytes of data.
 */
static void sm3_compress_len_c(wc_Sm3* sm3, const byte* data, word32 len)
{
    do {
        /* Compress one block at a time. */
#ifdef LITTLE_ENDIAN_ORDER
        word32* buffer = sm3->buffer;
        /* Convert big-endian bytes to little-endian 32-bit words. */
        BSWAP32_16(buffer, data);
        /* Process block of data. */
        SM3_COMPRESS(sm3, buffer);
#else
        /* Process block of data. */
        SM3_COMPRESS(sm3, (word32*)data);
#endif
        /* Move over processed data. */
        data += WC_SM3_BLOCK_SIZE;
        len -= WC_SM3_BLOCK_SIZE;
    }
    while (len > 0);
}

/* Finalize last block of hash.
 *
 * @param [in, out] sm3  SM4 hash object.
 * @return  0 on success.
 */
static void sm3_final_c(wc_Sm3* sm3)
{
    /* Convert length in bytes to length in bits and store in buffer. */
    sm3->buffer[14] = (sm3->hiLen << 3) | (sm3->loLen >> (32 - 3));
    sm3->buffer[15] = (sm3->loLen << 3);

    /* Process last block. */
    SM3_COMPRESS(sm3, sm3->buffer);
    /* No data unprocessed. */
    sm3->buffLen = 0;
}

/******************************************************************************/

/* Initialize the state of the hash.
 *
 * @param [in] sm3  SM3 hash object.
 */
static WC_INLINE void sm3_init(wc_Sm3* sm3)
{
    SM3_SET_COMPRESS();

    /* Set IV into values. */
    sm3->v[0] = 0x7380166f;
    sm3->v[1] = 0x4914b2b9;
    sm3->v[2] = 0x172442d7;
    sm3->v[3] = 0xda8a0600;
    sm3->v[4] = 0xa96f30bc;
    sm3->v[5] = 0x163138aa;
    sm3->v[6] = 0xe38dee4d;
    sm3->v[7] = 0xb0fb0e4e;

    /* No cached message data. */
    sm3->buffLen = 0;
    /* No message data seen. */
    sm3->loLen = 0;
    sm3->hiLen = 0;
}

/* Initialize the SM3 hash object.
 *
 * @param [in, out] sm3    SM3 hash object.
 * @param [in]      heap   Dynamic memory hint.
 * @param [in]      devId  Device ID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm3 is NULL.
 */
int wc_InitSm3(wc_Sm3* sm3, void* heap, int devId)
{
    int ret = 0;

    /* No device support yet. */
    (void)devId;

    /* Validate parameters. */
    if (sm3 == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Initialize hash state. */
        sm3_init(sm3);

        sm3->heap = heap;
    #ifdef WOLFSSL_HASH_FLAGS
        sm3->flags = 0;
    #endif
    }

    return ret;
}

/* Increase the number of bytes in the message being hashed.
 *
 * @param [in, out] sm3  SM3 hash object.
 * @param [in]      len  Number of new bytes of message.
 */
static WC_INLINE void sm3_add_to_len(wc_Sm3* sm3, word32 len)
{
    sm3->loLen += len;
    /* Detect overflow. */
    if (sm3->loLen < len) {
        sm3->hiLen++;
    }
}

/* Buffer message bytes.
 *
 * Processes the block if filled.
 *
 * @param [in, out] sm3   SM3 hash object.
 * @param [in]      data  Message data.
 * @param [in]      len   Length of message data not processed yet.
 * @param [out]     used  Number of bytes used.
 */
static WC_INLINE void sm3_buffer_msg_bytes(wc_Sm3* sm3, const byte* data,
    word32 len, word32* used)
{
    word32 add = min(len, WC_SM3_BLOCK_SIZE - sm3->buffLen);
    unsigned char* buffer = (unsigned char*)sm3->buffer;

    /* Put in bytes in big-endian order. */
    XMEMCPY(buffer + sm3->buffLen, data, add);

    /* Update count of bytes buffered. */
    sm3->buffLen += add;
    /* Check for full block. */
    if (sm3->buffLen == WC_SM3_BLOCK_SIZE) {
    #ifdef LITTLE_ENDIAN_ORDER
        /* Convert big-endian bytes to little-endian 32-bit words. */
        BSWAP32_16(buffer, buffer);
    #endif
        /* Process block of data. */
        SM3_COMPRESS(sm3, sm3->buffer);
        /* No more cached data. */
        sm3->buffLen = 0;
    }

    *used = add;
}

/* Update the hash with more message data.
 *
 * @param [in, out] sm3   SM3 hash object.
 * @param [in]      data  Message data.
 * @param [in]      len   Number of bytes in message data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm3 is NULL or len > 0 and data is NULL.
 * @return  BAD_COND_E when internal state invalid.
 */
int wc_Sm3Update(wc_Sm3* sm3, const byte* data, word32 len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm3 == NULL) || ((len > 0) && (data == NULL))) {
        ret = BAD_FUNC_ARG;
    }

#ifdef DEBUG_WOLFSSL
    /* Check internal state - buffer length is a valid value. */
    if ((ret == 0) && (sm3->buffLen >= WC_SM3_BLOCK_SIZE)) {
        ret = BAD_COND_E;
    }
#endif

    if ((ret == 0) && (len > 0)) {
        /* Always add to length. */
        sm3_add_to_len(sm3, len);

        /* Check for unprocessed data. */
        if (sm3->buffLen > 0) {
            word32 used = 0;

            /* Add to existing message bytes. */
            sm3_buffer_msg_bytes(sm3, data, len, &used);
            len -= used;
            data += used;
        }
    }
    if ((ret == 0) && (len >= WC_SM3_BLOCK_SIZE)) {
        /* Mask out bits that are not a multiple of 64. */
        word32 l = len & (word32)(~(WC_SM3_BLOCK_SIZE - 1));

        /* Compress complete blocks of data. */
        SM3_COMPRESS_LEN(sm3, data, l);
        data += l;
        len -= l;
    }

    if ((ret == 0) && (len > 0)) {
        /* Store unprocessed data less than a block. */
        XMEMCPY(sm3->buffer, data, len);
        sm3->buffLen = len;
    }

    return ret;
}

/* Last block with data to be hashed.
 *
 * @param [in, out] sm3   SM3 hash object.
 */
static WC_INLINE void sm3_last_data_block(wc_Sm3* sm3)
{
    byte* buffer8 = (byte*)sm3->buffer;

    /* Fill rest of block with 0s. */
    XMEMSET(buffer8 + sm3->buffLen, 0, WC_SM3_BLOCK_SIZE - sm3->buffLen);

#ifdef LITTLE_ENDIAN_ORDER
    /* Convert big-endian bytes to little-endian 32-bit words. */
    BSWAP32_16(sm3->buffer, sm3->buffer);
#endif
    /* Process last data block. */
    SM3_COMPRESS(sm3, sm3->buffer);

    /* No data unprocessed. */
    sm3->buffLen = 0;
}

/* Hash last block.
 *
 * @param [in, out] sm3   SM3 hash object.
 * @return  0 on success.
 */
static WC_INLINE void sm3_last_block(wc_Sm3* sm3)
{
    byte* buffer8 = (byte*)sm3->buffer;

    /* Fill rest of block with 0s except 64-bits of length. */
    XMEMSET(buffer8 + sm3->buffLen, 0, WC_SM3_PAD_SIZE - sm3->buffLen);

#ifdef LITTLE_ENDIAN_ORDER
    /* Reverse as many words as had data in them. (Reverse of 0 is 0). */
    ByteReverseWords(sm3->buffer, sm3->buffer,
        (sm3->buffLen + 3) & (word32)(~3));
#endif
    /* Hash last block. */
    sm3_final(sm3);
}

/* Get raw hash.
 *
 * @param [in, out] sm3   SM3 hash object.
 * @param [out]     hash  Final hash value.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm3 or hash is NULL.
 */
int wc_Sm3FinalRaw(wc_Sm3* sm3, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm3 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
    #ifdef LITTLE_ENDIAN_ORDER
        /* Convert little-endian 32-bit words to big-endian bytes. */
        BSWAP32_8(hash, sm3->v);
    #else
        XMEMCPY(hash, sm3->v, WC_SM3_DIGEST_SIZE);
    #endif
    }

    return ret;
}

/* Finalize hash.
 *
 * Initializes the state once final hash produced.
 *
 * @param [in, out] sm3   SM3 hash object.
 * @param [out]     hash  Final hash value.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm3 or hash is NULL.
 */
int wc_Sm3Final(wc_Sm3* sm3, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm3 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        byte* buffer8 = (byte*)sm3->buffer;

        /* Append a "1" bit to end of message. */
        buffer8[sm3->buffLen++] = 0x80;
        if (sm3->buffLen > WC_SM3_PAD_SIZE) {
            /* Hash the last data block.
             * l + 1 > 448 bits so need to do this block first. */
            sm3_last_data_block(sm3);
        }
    }
    if (ret == 0) {
        /* Hash the last block. Data length added to end. */
        sm3_last_block(sm3);
        /* Get the hash. */
    #ifdef LITTLE_ENDIAN_ORDER
        /* Convert little-endian 32-bit words to big-endian bytes. */
        BSWAP32_8(hash, sm3->v);
    #else
        XMEMCPY(hash, sm3->v, WC_SM3_DIGEST_SIZE);
    #endif

        /* Initialize hash state. */
        sm3_init(sm3);
    }

    return ret;
}

/* Dispose of any dynamically allocated data in object.
 *
 * @param [in, out] sm3  SM3 hash object.
 */
void wc_Sm3Free(wc_Sm3* sm3)
{
    (void)sm3;
}

/* Copy the SM3 hash object.
 *
 * Assumes src and dst are valid pointers.
 *
 * @param [in]      src  SM3 hash object to copy.
 * @param [in, out] dst  SM3 hash object to copy into.
 */
static void sm3_copy(const wc_Sm3* src, wc_Sm3* dst)
{
    XMEMCPY(dst, src, sizeof(wc_Sm3));
#ifdef WOLFSSL_HASH_FLAGS
    /* Mark destination as a copy. */
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif
}

/* Get the final hash for the message data seen.
 *
 * More message data can be added to this object.
 *
 * @param [in]  sm3   SM3 hash object.
 * @param [out] hash  Final hash value for message data up to this point.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm3 or hash is NULL.
 */
int wc_Sm3GetHash(wc_Sm3* sm3, byte* hash)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    wc_Sm3* sm3Copy;
#else
    wc_Sm3  sm3Copy[1];
#endif

    /* Validate parameters. */
    if ((sm3 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    #ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        /* Allocate a SM3 hash object to do final on. */
        sm3Copy = (wc_Sm3*)XMALLOC(sizeof(wc_Sm3), sm3->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (sm3Copy == NULL) {
            ret = MEMORY_E;
        }
    }
    #endif
    if (ret == 0) {
        /* Get a copy of the hash object. */
        sm3_copy(sm3, sm3Copy);
        /* Calculate final hash value. */
        ret = wc_Sm3Final(sm3Copy, hash);
        /* Dispose of hash object. */
        wc_Sm3Free(sm3Copy);

    #ifdef WOLFSSL_SMALL_STACK
        /* Free the SM3 hash object that was the copy. */
        XFREE(sm3Copy, sm3->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }

    return ret;
}

/* Copy the SM3 hash object.
 *
 * @param [in]      src  SM3 hash object to copy.
 * @param [in, out] dst  SM3 hash object to copy into.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Sm3Copy(const wc_Sm3* src, wc_Sm3* dst)
{
    int ret = 0;

    /* Validate parameters. */
    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sm3_copy(src, dst);
    }

    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
/* Set the flags of the SM3 hash object.
 *
 * @param [in, out] sm3    SM3 hash object.
 * @param [in]      flags  Flags to set.
 * @return  0 on success.
 */
int wc_Sm3SetFlags(wc_Sm3* sm3, word32 flags)
{
    if (sm3 != NULL) {
        sm3->flags = flags;
    }
    return 0;
}

/* Get the flags of the SM3 hash object.
 *
 * @param [in]  sm3    SM3 hash object.
 * @param [out] flags  Flags from hash object.
 * @return  0 on success.
 */
int wc_Sm3GetFlags(const wc_Sm3* sm3, word32* flags)
{
    if ((sm3 != NULL) && (flags != NULL)) {
        *flags = sm3->flags;
    }
    return 0;
}
#endif

#endif /* WOLFSSL_SM3 */

