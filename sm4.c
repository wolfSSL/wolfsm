/* sm4.c
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
 *  https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_SM4

#include <wolfssl/wolfcrypt/sm4.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif


#ifdef LITTLE_ENDIAN_ORDER

/* Load unsigned 32-bit word from big-endian byte array.
 *
 * @param [in] b  Byte array with big-endian data.
 * @return  Unsigned 32-bit word.
 */
#define LOAD_U32_BE(b, v0, v1, v2, v3)  \
    XMEMCPY(&v0, b +  0, sizeof(v0));   \
    XMEMCPY(&v1, b +  4, sizeof(v1));   \
    XMEMCPY(&v2, b +  8, sizeof(v2));   \
    XMEMCPY(&v3, b + 12, sizeof(v3));   \
    v0 = ByteReverseWord32(v0);         \
    v1 = ByteReverseWord32(v1);         \
    v2 = ByteReverseWord32(v2);         \
    v3 = ByteReverseWord32(v3)

/* Store unsigned 32-bit word as big-endian byte array.
 *
 * @param [in]  v  Unsigned 32-bit value.
 * @param [out] b  Byte array to hold big-endian data.
 */
#define STORE_U32_BE(v0, v1, v2, v3, b) \
    v0 = ByteReverseWord32(v0);         \
    v1 = ByteReverseWord32(v1);         \
    v2 = ByteReverseWord32(v2);         \
    v3 = ByteReverseWord32(v3);         \
    XMEMCPY(b +  0, &v3, sizeof(v3));   \
    XMEMCPY(b +  4, &v2, sizeof(v2));   \
    XMEMCPY(b +  8, &v1, sizeof(v1));   \
    XMEMCPY(b + 12, &v0, sizeof(v0))

#else

/* Load unsigned 32-bit word from big-endian byte array.
 *
 * @param [in] b  Byte array with big-endian data.
 * @return  Unsigned 32-bit word.
 */
#define LOAD_U32_BE(b, v0, v1, v2, v3)  \
    XMEMCPY(&v0, b +  0, sizeof(v0));   \
    XMEMCPY(&v1, b +  4, sizeof(v1));   \
    XMEMCPY(&v2, b +  8, sizeof(v2));   \
    XMEMCPY(&v3, b + 12, sizeof(v3))

/* Store unsigned 32-bit word as big-endian byte array.
 *
 * @param [in]  v  Unsigned 32-bit value.
 * @param [out] b  Byte array to hold big-endian data.
 */
#define STORE_U32_BE(v0, v1, v2, v3, b) \
    XMEMCPY(b +  0, &v3, sizeof(v3));   \
    XMEMCPY(b +  4, &v2, sizeof(v2));   \
    XMEMCPY(b +  8, &v1, sizeof(v1));   \
    XMEMCPY(b + 12, &v0, sizeof(v0))

#endif


/* Constant key values used in creating key schedule. */
static word32 sm4_ck[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

/* Family key values used in creating key schedule. */
static word32 sm4_fk[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};


#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM4)

/* S-box used in nonlinear transformation tau. */
static byte sm4_sbox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

#ifndef WOLFSSL_SM4_SMALL

/* S-boxes used in nonlinear transformation tau.
 * Linear transformation applied to each byte.
 *
 * Generated using script: ruby scripts/sm4/tables.rb
 */
static const word32 sm4_sbox_0[256] = {
    0xd55b5b8e, 0x924242d0, 0xeaa7a74d, 0xfdfbfb06, 0xcf3333fc, 0xe2878765,
    0x3df4f4c9, 0xb5dede6b, 0x1658584e, 0xb4dada6e, 0x14505044, 0xc10b0bca,
    0x28a0a088, 0xf8efef17, 0x2cb0b09c, 0x05141411, 0x2bacac87, 0x669d9dfb,
    0x986a6af2, 0x77d9d9ae, 0x2aa8a882, 0xbcfafa46, 0x04101014, 0xc00f0fcf,
    0xa8aaaa02, 0x45111154, 0x134c4c5f, 0x269898be, 0x4825256d, 0x841a1a9e,
    0x0618181e, 0x9b6666fd, 0x9e7272ec, 0x4309094a, 0x51414110, 0xf7d3d324,
    0x934646d5, 0xecbfbf53, 0x9a6262f8, 0x7be9e992, 0x33ccccff, 0x55515104,
    0x0b2c2c27, 0x420d0d4f, 0xeeb7b759, 0xcc3f3ff3, 0xaeb2b21c, 0x638989ea,
    0xe7939374, 0xb1cece7f, 0x1c70706c, 0xaba6a60d, 0xca2727ed, 0x08202028,
    0xeba3a348, 0x975656c1, 0x82020280, 0xdc7f7fa3, 0x965252c4, 0xf9ebeb12,
    0x74d5d5a1, 0x8d3e3eb3, 0x3ffcfcc3, 0xa49a9a3e, 0x461d1d5b, 0x071c1c1b,
    0xa59e9e3b, 0xfff3f30c, 0xf0cfcf3f, 0x72cdcdbf, 0x175c5c4b, 0xb8eaea52,
    0x810e0e8f, 0x5865653d, 0x3cf0f0cc, 0x1964647d, 0xe59b9b7e, 0x87161691,
    0x4e3d3d73, 0xaaa2a208, 0x69a1a1c8, 0x6aadadc7, 0x83060685, 0xb0caca7a,
    0x70c5c5b5, 0x659191f4, 0xd96b6bb2, 0x892e2ea7, 0xfbe3e318, 0xe8afaf47,
    0x0f3c3c33, 0x4a2d2d67, 0x71c1c1b0, 0x5759590e, 0x9f7676e9, 0x35d4d4e1,
    0x1e787866, 0x249090b4, 0x0e383836, 0x5f797926, 0x628d8def, 0x59616138,
    0xd2474795, 0xa08a8a2a, 0x259494b1, 0x228888aa, 0x7df1f18c, 0x3bececd7,
    0x01040405, 0x218484a5, 0x79e1e198, 0x851e1e9b, 0xd7535384, 0x00000000,
    0x4719195e, 0x565d5d0b, 0x9d7e7ee3, 0xd04f4f9f, 0x279c9cbb, 0x5349491a,
    0x4d31317c, 0x36d8d8ee, 0x0208080a, 0xe49f9f7b, 0xa2828220, 0xc71313d4,
    0xcb2323e8, 0x9c7a7ae6, 0xe9abab42, 0xbdfefe43, 0x882a2aa2, 0xd14b4b9a,
    0x41010140, 0xc41f1fdb, 0x38e0e0d8, 0xb7d6d661, 0xa18e8e2f, 0xf4dfdf2b,
    0xf1cbcb3a, 0xcd3b3bf6, 0xfae7e71d, 0x608585e5, 0x15545441, 0xa3868625,
    0xe3838360, 0xacbaba16, 0x5c757529, 0xa6929234, 0x996e6ef7, 0x34d0d0e4,
    0x1a686872, 0x54555501, 0xafb6b619, 0x914e4edf, 0x32c8c8fa, 0x30c0c0f0,
    0xf6d7d721, 0x8e3232bc, 0xb3c6c675, 0xe08f8f6f, 0x1d747469, 0xf5dbdb2e,
    0xe18b8b6a, 0x2eb8b896, 0x800a0a8a, 0x679999fe, 0xc92b2be2, 0x618181e0,
    0xc30303c0, 0x29a4a48d, 0x238c8caf, 0xa9aeae07, 0x0d343439, 0x524d4d1f,
    0x4f393976, 0x6ebdbdd3, 0xd6575781, 0xd86f6fb7, 0x37dcdceb, 0x44151551,
    0xdd7b7ba6, 0xfef7f709, 0x8c3a3ab6, 0x2fbcbc93, 0x030c0c0f, 0xfcffff03,
    0x6ba9a9c2, 0x73c9c9ba, 0x6cb5b5d9, 0x6db1b1dc, 0x5a6d6d37, 0x50454515,
    0x8f3636b9, 0x1b6c6c77, 0xadbebe13, 0x904a4ada, 0xb9eeee57, 0xde7777a9,
    0xbef2f24c, 0x7efdfd83, 0x11444455, 0xda6767bd, 0x5d71712c, 0x40050545,
    0x1f7c7c63, 0x10404050, 0x5b696932, 0xdb6363b8, 0x0a282822, 0xc20707c5,
    0x31c4c4f5, 0x8a2222a8, 0xa7969631, 0xce3737f9, 0x7aeded97, 0xbff6f649,
    0x2db4b499, 0x75d1d1a4, 0xd3434390, 0x1248485a, 0xbae2e258, 0xe6979771,
    0xb6d2d264, 0xb2c2c270, 0x8b2626ad, 0x68a5a5cd, 0x955e5ecb, 0x4b292962,
    0x0c30303c, 0x945a5ace, 0x76ddddab, 0x7ff9f986, 0x649595f1, 0xbbe6e65d,
    0xf2c7c735, 0x0924242d, 0xc61717d1, 0x6fb9b9d6, 0xc51b1bde, 0x86121294,
    0x18606078, 0xf3c3c330, 0x7cf5f589, 0xefb3b35c, 0x3ae8e8d2, 0xdf7373ac,
    0x4c353579, 0x208080a0, 0x78e5e59d, 0xedbbbb56, 0x5e7d7d23, 0x3ef8f8c6,
    0xd45f5f8b, 0xc82f2fe7, 0x39e4e4dd, 0x49212168,
};
static const word32 sm4_sbox_1[256] = {
    0x5b5b8ed5, 0x4242d092, 0xa7a74dea, 0xfbfb06fd, 0x3333fccf, 0x878765e2,
    0xf4f4c93d, 0xdede6bb5, 0x58584e16, 0xdada6eb4, 0x50504414, 0x0b0bcac1,
    0xa0a08828, 0xefef17f8, 0xb0b09c2c, 0x14141105, 0xacac872b, 0x9d9dfb66,
    0x6a6af298, 0xd9d9ae77, 0xa8a8822a, 0xfafa46bc, 0x10101404, 0x0f0fcfc0,
    0xaaaa02a8, 0x11115445, 0x4c4c5f13, 0x9898be26, 0x25256d48, 0x1a1a9e84,
    0x18181e06, 0x6666fd9b, 0x7272ec9e, 0x09094a43, 0x41411051, 0xd3d324f7,
    0x4646d593, 0xbfbf53ec, 0x6262f89a, 0xe9e9927b, 0xccccff33, 0x51510455,
    0x2c2c270b, 0x0d0d4f42, 0xb7b759ee, 0x3f3ff3cc, 0xb2b21cae, 0x8989ea63,
    0x939374e7, 0xcece7fb1, 0x70706c1c, 0xa6a60dab, 0x2727edca, 0x20202808,
    0xa3a348eb, 0x5656c197, 0x02028082, 0x7f7fa3dc, 0x5252c496, 0xebeb12f9,
    0xd5d5a174, 0x3e3eb38d, 0xfcfcc33f, 0x9a9a3ea4, 0x1d1d5b46, 0x1c1c1b07,
    0x9e9e3ba5, 0xf3f30cff, 0xcfcf3ff0, 0xcdcdbf72, 0x5c5c4b17, 0xeaea52b8,
    0x0e0e8f81, 0x65653d58, 0xf0f0cc3c, 0x64647d19, 0x9b9b7ee5, 0x16169187,
    0x3d3d734e, 0xa2a208aa, 0xa1a1c869, 0xadadc76a, 0x06068583, 0xcaca7ab0,
    0xc5c5b570, 0x9191f465, 0x6b6bb2d9, 0x2e2ea789, 0xe3e318fb, 0xafaf47e8,
    0x3c3c330f, 0x2d2d674a, 0xc1c1b071, 0x59590e57, 0x7676e99f, 0xd4d4e135,
    0x7878661e, 0x9090b424, 0x3838360e, 0x7979265f, 0x8d8def62, 0x61613859,
    0x474795d2, 0x8a8a2aa0, 0x9494b125, 0x8888aa22, 0xf1f18c7d, 0xececd73b,
    0x04040501, 0x8484a521, 0xe1e19879, 0x1e1e9b85, 0x535384d7, 0x00000000,
    0x19195e47, 0x5d5d0b56, 0x7e7ee39d, 0x4f4f9fd0, 0x9c9cbb27, 0x49491a53,
    0x31317c4d, 0xd8d8ee36, 0x08080a02, 0x9f9f7be4, 0x828220a2, 0x1313d4c7,
    0x2323e8cb, 0x7a7ae69c, 0xabab42e9, 0xfefe43bd, 0x2a2aa288, 0x4b4b9ad1,
    0x01014041, 0x1f1fdbc4, 0xe0e0d838, 0xd6d661b7, 0x8e8e2fa1, 0xdfdf2bf4,
    0xcbcb3af1, 0x3b3bf6cd, 0xe7e71dfa, 0x8585e560, 0x54544115, 0x868625a3,
    0x838360e3, 0xbaba16ac, 0x7575295c, 0x929234a6, 0x6e6ef799, 0xd0d0e434,
    0x6868721a, 0x55550154, 0xb6b619af, 0x4e4edf91, 0xc8c8fa32, 0xc0c0f030,
    0xd7d721f6, 0x3232bc8e, 0xc6c675b3, 0x8f8f6fe0, 0x7474691d, 0xdbdb2ef5,
    0x8b8b6ae1, 0xb8b8962e, 0x0a0a8a80, 0x9999fe67, 0x2b2be2c9, 0x8181e061,
    0x0303c0c3, 0xa4a48d29, 0x8c8caf23, 0xaeae07a9, 0x3434390d, 0x4d4d1f52,
    0x3939764f, 0xbdbdd36e, 0x575781d6, 0x6f6fb7d8, 0xdcdceb37, 0x15155144,
    0x7b7ba6dd, 0xf7f709fe, 0x3a3ab68c, 0xbcbc932f, 0x0c0c0f03, 0xffff03fc,
    0xa9a9c26b, 0xc9c9ba73, 0xb5b5d96c, 0xb1b1dc6d, 0x6d6d375a, 0x45451550,
    0x3636b98f, 0x6c6c771b, 0xbebe13ad, 0x4a4ada90, 0xeeee57b9, 0x7777a9de,
    0xf2f24cbe, 0xfdfd837e, 0x44445511, 0x6767bdda, 0x71712c5d, 0x05054540,
    0x7c7c631f, 0x40405010, 0x6969325b, 0x6363b8db, 0x2828220a, 0x0707c5c2,
    0xc4c4f531, 0x2222a88a, 0x969631a7, 0x3737f9ce, 0xeded977a, 0xf6f649bf,
    0xb4b4992d, 0xd1d1a475, 0x434390d3, 0x48485a12, 0xe2e258ba, 0x979771e6,
    0xd2d264b6, 0xc2c270b2, 0x2626ad8b, 0xa5a5cd68, 0x5e5ecb95, 0x2929624b,
    0x30303c0c, 0x5a5ace94, 0xddddab76, 0xf9f9867f, 0x9595f164, 0xe6e65dbb,
    0xc7c735f2, 0x24242d09, 0x1717d1c6, 0xb9b9d66f, 0x1b1bdec5, 0x12129486,
    0x60607818, 0xc3c330f3, 0xf5f5897c, 0xb3b35cef, 0xe8e8d23a, 0x7373acdf,
    0x3535794c, 0x8080a020, 0xe5e59d78, 0xbbbb56ed, 0x7d7d235e, 0xf8f8c63e,
    0x5f5f8bd4, 0x2f2fe7c8, 0xe4e4dd39, 0x21216849,
};
static const word32 sm4_sbox_2[256] = {
    0x5b8ed55b, 0x42d09242, 0xa74deaa7, 0xfb06fdfb, 0x33fccf33, 0x8765e287,
    0xf4c93df4, 0xde6bb5de, 0x584e1658, 0xda6eb4da, 0x50441450, 0x0bcac10b,
    0xa08828a0, 0xef17f8ef, 0xb09c2cb0, 0x14110514, 0xac872bac, 0x9dfb669d,
    0x6af2986a, 0xd9ae77d9, 0xa8822aa8, 0xfa46bcfa, 0x10140410, 0x0fcfc00f,
    0xaa02a8aa, 0x11544511, 0x4c5f134c, 0x98be2698, 0x256d4825, 0x1a9e841a,
    0x181e0618, 0x66fd9b66, 0x72ec9e72, 0x094a4309, 0x41105141, 0xd324f7d3,
    0x46d59346, 0xbf53ecbf, 0x62f89a62, 0xe9927be9, 0xccff33cc, 0x51045551,
    0x2c270b2c, 0x0d4f420d, 0xb759eeb7, 0x3ff3cc3f, 0xb21caeb2, 0x89ea6389,
    0x9374e793, 0xce7fb1ce, 0x706c1c70, 0xa60daba6, 0x27edca27, 0x20280820,
    0xa348eba3, 0x56c19756, 0x02808202, 0x7fa3dc7f, 0x52c49652, 0xeb12f9eb,
    0xd5a174d5, 0x3eb38d3e, 0xfcc33ffc, 0x9a3ea49a, 0x1d5b461d, 0x1c1b071c,
    0x9e3ba59e, 0xf30cfff3, 0xcf3ff0cf, 0xcdbf72cd, 0x5c4b175c, 0xea52b8ea,
    0x0e8f810e, 0x653d5865, 0xf0cc3cf0, 0x647d1964, 0x9b7ee59b, 0x16918716,
    0x3d734e3d, 0xa208aaa2, 0xa1c869a1, 0xadc76aad, 0x06858306, 0xca7ab0ca,
    0xc5b570c5, 0x91f46591, 0x6bb2d96b, 0x2ea7892e, 0xe318fbe3, 0xaf47e8af,
    0x3c330f3c, 0x2d674a2d, 0xc1b071c1, 0x590e5759, 0x76e99f76, 0xd4e135d4,
    0x78661e78, 0x90b42490, 0x38360e38, 0x79265f79, 0x8def628d, 0x61385961,
    0x4795d247, 0x8a2aa08a, 0x94b12594, 0x88aa2288, 0xf18c7df1, 0xecd73bec,
    0x04050104, 0x84a52184, 0xe19879e1, 0x1e9b851e, 0x5384d753, 0x00000000,
    0x195e4719, 0x5d0b565d, 0x7ee39d7e, 0x4f9fd04f, 0x9cbb279c, 0x491a5349,
    0x317c4d31, 0xd8ee36d8, 0x080a0208, 0x9f7be49f, 0x8220a282, 0x13d4c713,
    0x23e8cb23, 0x7ae69c7a, 0xab42e9ab, 0xfe43bdfe, 0x2aa2882a, 0x4b9ad14b,
    0x01404101, 0x1fdbc41f, 0xe0d838e0, 0xd661b7d6, 0x8e2fa18e, 0xdf2bf4df,
    0xcb3af1cb, 0x3bf6cd3b, 0xe71dfae7, 0x85e56085, 0x54411554, 0x8625a386,
    0x8360e383, 0xba16acba, 0x75295c75, 0x9234a692, 0x6ef7996e, 0xd0e434d0,
    0x68721a68, 0x55015455, 0xb619afb6, 0x4edf914e, 0xc8fa32c8, 0xc0f030c0,
    0xd721f6d7, 0x32bc8e32, 0xc675b3c6, 0x8f6fe08f, 0x74691d74, 0xdb2ef5db,
    0x8b6ae18b, 0xb8962eb8, 0x0a8a800a, 0x99fe6799, 0x2be2c92b, 0x81e06181,
    0x03c0c303, 0xa48d29a4, 0x8caf238c, 0xae07a9ae, 0x34390d34, 0x4d1f524d,
    0x39764f39, 0xbdd36ebd, 0x5781d657, 0x6fb7d86f, 0xdceb37dc, 0x15514415,
    0x7ba6dd7b, 0xf709fef7, 0x3ab68c3a, 0xbc932fbc, 0x0c0f030c, 0xff03fcff,
    0xa9c26ba9, 0xc9ba73c9, 0xb5d96cb5, 0xb1dc6db1, 0x6d375a6d, 0x45155045,
    0x36b98f36, 0x6c771b6c, 0xbe13adbe, 0x4ada904a, 0xee57b9ee, 0x77a9de77,
    0xf24cbef2, 0xfd837efd, 0x44551144, 0x67bdda67, 0x712c5d71, 0x05454005,
    0x7c631f7c, 0x40501040, 0x69325b69, 0x63b8db63, 0x28220a28, 0x07c5c207,
    0xc4f531c4, 0x22a88a22, 0x9631a796, 0x37f9ce37, 0xed977aed, 0xf649bff6,
    0xb4992db4, 0xd1a475d1, 0x4390d343, 0x485a1248, 0xe258bae2, 0x9771e697,
    0xd264b6d2, 0xc270b2c2, 0x26ad8b26, 0xa5cd68a5, 0x5ecb955e, 0x29624b29,
    0x303c0c30, 0x5ace945a, 0xddab76dd, 0xf9867ff9, 0x95f16495, 0xe65dbbe6,
    0xc735f2c7, 0x242d0924, 0x17d1c617, 0xb9d66fb9, 0x1bdec51b, 0x12948612,
    0x60781860, 0xc330f3c3, 0xf5897cf5, 0xb35cefb3, 0xe8d23ae8, 0x73acdf73,
    0x35794c35, 0x80a02080, 0xe59d78e5, 0xbb56edbb, 0x7d235e7d, 0xf8c63ef8,
    0x5f8bd45f, 0x2fe7c82f, 0xe4dd39e4, 0x21684921,
};
static const word32 sm4_sbox_3[256] = {
    0x8ed55b5b, 0xd0924242, 0x4deaa7a7, 0x06fdfbfb, 0xfccf3333, 0x65e28787,
    0xc93df4f4, 0x6bb5dede, 0x4e165858, 0x6eb4dada, 0x44145050, 0xcac10b0b,
    0x8828a0a0, 0x17f8efef, 0x9c2cb0b0, 0x11051414, 0x872bacac, 0xfb669d9d,
    0xf2986a6a, 0xae77d9d9, 0x822aa8a8, 0x46bcfafa, 0x14041010, 0xcfc00f0f,
    0x02a8aaaa, 0x54451111, 0x5f134c4c, 0xbe269898, 0x6d482525, 0x9e841a1a,
    0x1e061818, 0xfd9b6666, 0xec9e7272, 0x4a430909, 0x10514141, 0x24f7d3d3,
    0xd5934646, 0x53ecbfbf, 0xf89a6262, 0x927be9e9, 0xff33cccc, 0x04555151,
    0x270b2c2c, 0x4f420d0d, 0x59eeb7b7, 0xf3cc3f3f, 0x1caeb2b2, 0xea638989,
    0x74e79393, 0x7fb1cece, 0x6c1c7070, 0x0daba6a6, 0xedca2727, 0x28082020,
    0x48eba3a3, 0xc1975656, 0x80820202, 0xa3dc7f7f, 0xc4965252, 0x12f9ebeb,
    0xa174d5d5, 0xb38d3e3e, 0xc33ffcfc, 0x3ea49a9a, 0x5b461d1d, 0x1b071c1c,
    0x3ba59e9e, 0x0cfff3f3, 0x3ff0cfcf, 0xbf72cdcd, 0x4b175c5c, 0x52b8eaea,
    0x8f810e0e, 0x3d586565, 0xcc3cf0f0, 0x7d196464, 0x7ee59b9b, 0x91871616,
    0x734e3d3d, 0x08aaa2a2, 0xc869a1a1, 0xc76aadad, 0x85830606, 0x7ab0caca,
    0xb570c5c5, 0xf4659191, 0xb2d96b6b, 0xa7892e2e, 0x18fbe3e3, 0x47e8afaf,
    0x330f3c3c, 0x674a2d2d, 0xb071c1c1, 0x0e575959, 0xe99f7676, 0xe135d4d4,
    0x661e7878, 0xb4249090, 0x360e3838, 0x265f7979, 0xef628d8d, 0x38596161,
    0x95d24747, 0x2aa08a8a, 0xb1259494, 0xaa228888, 0x8c7df1f1, 0xd73becec,
    0x05010404, 0xa5218484, 0x9879e1e1, 0x9b851e1e, 0x84d75353, 0x00000000,
    0x5e471919, 0x0b565d5d, 0xe39d7e7e, 0x9fd04f4f, 0xbb279c9c, 0x1a534949,
    0x7c4d3131, 0xee36d8d8, 0x0a020808, 0x7be49f9f, 0x20a28282, 0xd4c71313,
    0xe8cb2323, 0xe69c7a7a, 0x42e9abab, 0x43bdfefe, 0xa2882a2a, 0x9ad14b4b,
    0x40410101, 0xdbc41f1f, 0xd838e0e0, 0x61b7d6d6, 0x2fa18e8e, 0x2bf4dfdf,
    0x3af1cbcb, 0xf6cd3b3b, 0x1dfae7e7, 0xe5608585, 0x41155454, 0x25a38686,
    0x60e38383, 0x16acbaba, 0x295c7575, 0x34a69292, 0xf7996e6e, 0xe434d0d0,
    0x721a6868, 0x01545555, 0x19afb6b6, 0xdf914e4e, 0xfa32c8c8, 0xf030c0c0,
    0x21f6d7d7, 0xbc8e3232, 0x75b3c6c6, 0x6fe08f8f, 0x691d7474, 0x2ef5dbdb,
    0x6ae18b8b, 0x962eb8b8, 0x8a800a0a, 0xfe679999, 0xe2c92b2b, 0xe0618181,
    0xc0c30303, 0x8d29a4a4, 0xaf238c8c, 0x07a9aeae, 0x390d3434, 0x1f524d4d,
    0x764f3939, 0xd36ebdbd, 0x81d65757, 0xb7d86f6f, 0xeb37dcdc, 0x51441515,
    0xa6dd7b7b, 0x09fef7f7, 0xb68c3a3a, 0x932fbcbc, 0x0f030c0c, 0x03fcffff,
    0xc26ba9a9, 0xba73c9c9, 0xd96cb5b5, 0xdc6db1b1, 0x375a6d6d, 0x15504545,
    0xb98f3636, 0x771b6c6c, 0x13adbebe, 0xda904a4a, 0x57b9eeee, 0xa9de7777,
    0x4cbef2f2, 0x837efdfd, 0x55114444, 0xbdda6767, 0x2c5d7171, 0x45400505,
    0x631f7c7c, 0x50104040, 0x325b6969, 0xb8db6363, 0x220a2828, 0xc5c20707,
    0xf531c4c4, 0xa88a2222, 0x31a79696, 0xf9ce3737, 0x977aeded, 0x49bff6f6,
    0x992db4b4, 0xa475d1d1, 0x90d34343, 0x5a124848, 0x58bae2e2, 0x71e69797,
    0x64b6d2d2, 0x70b2c2c2, 0xad8b2626, 0xcd68a5a5, 0xcb955e5e, 0x624b2929,
    0x3c0c3030, 0xce945a5a, 0xab76dddd, 0x867ff9f9, 0xf1649595, 0x5dbbe6e6,
    0x35f2c7c7, 0x2d092424, 0xd1c61717, 0xd66fb9b9, 0xdec51b1b, 0x94861212,
    0x78186060, 0x30f3c3c3, 0x897cf5f5, 0x5cefb3b3, 0xd23ae8e8, 0xacdf7373,
    0x794c3535, 0xa0208080, 0x9d78e5e5, 0x56edbbbb, 0x235e7d7d, 0xc63ef8f8,
    0x8bd45f5f, 0xe7c82f2f, 0xdd39e4e4, 0x68492121,
};

/* Linear transformation of nonlinear transformation tau.
 *
 * Each S-box value has had the linear transformation applied.
 *
 * @param [in] x  Unsigned 32-bit value to transform.
 * @return  Unsigned 32-bit bit value.
 */
static WC_INLINE word32 sm4_t(word32 x)
{
    return sm4_sbox_3[(byte)(x >> 24)] ^
           sm4_sbox_2[(byte)(x >> 16)] ^
           sm4_sbox_1[(byte)(x >>  8)] ^
           sm4_sbox_0[(byte)(x >>  0)];
}

#else

/* Linear transformation of nonlinear transformation tau.
 *
 * @param [in] x  Unsigned 32-bit value to transform.
 * @return  Unsigned 32-bit bit value.
 */
static word32 sm4_t(word32 x)
{
    word32 t;

    /* Nonlinear transformation. */
    t  = ((word32)sm4_sbox[(byte)(x >> 24)]) << 24;
    t |= ((word32)sm4_sbox[(byte)(x >> 16)]) << 16;
    t |= ((word32)sm4_sbox[(byte)(x >>  8)]) <<  8;
    t |=          sm4_sbox[(byte) x       ]       ;

    /* Linear transformation. */
    return t ^ rotlFixed(t, 2) ^ rotlFixed(t, 10) ^ rotlFixed(t, 18) ^
        rotlFixed(t, 24);
}

#endif

#endif /* !__aarch64__ || !WOLFSSL_ARMASM_CRYPTO_SM4 */

/* Key schedule calculation.
 *
 * @param [in]  key  Array of bytes representing key.
 * @param [out] ks   Array of unsigned 32-bit values that are the key schedule.
 */
static void sm4_key_schedule(const byte* key, word32* ks)
{
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM4)
#ifndef WOLFSSL_SMALL_STACK
    word32 k[36];
    word32 t;
    word32 x;
    int i;

    /* Load key into words. */
    LOAD_U32_BE(key, k[0], k[1], k[2], k[3]);
    k[0] ^= sm4_fk[0];
    k[1] ^= sm4_fk[1];
    k[2] ^= sm4_fk[2];
    k[3] ^= sm4_fk[3];

    /* Calculate each word of key schedule. */
    for (i = 0; i < SM4_KEY_SCHEDULE; ++i) {
        x = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ sm4_ck[i];

        /* Nonlinear operation tau */
        t = ((word32)sm4_sbox[(byte)(x >> 24)]) << 24 |
            ((word32)sm4_sbox[(byte)(x >> 16)]) << 16 |
            ((word32)sm4_sbox[(byte)(x >>  8)]) <<  8 |
            ((word32)sm4_sbox[(byte)(x      )])       ;

        /* Linear operation L' */
        k[i+4] = k[i] ^ (t ^ rotlFixed(t, 13) ^ rotlFixed(t, 23));
        ks[i] = k[i + 4];
    }
#else
    word32 k[8];
    word32 t;
    word32 x;
    int i;

    /* Load key into words. */
    LOAD_U32_BE(key, k[0], k[1], k[2], k[3]);
    k[0] ^= sm4_fk[0];
    k[1] ^= sm4_fk[1];
    k[2] ^= sm4_fk[2];
    k[3] ^= sm4_fk[3];

    /* Calculate first 4 words of key schedule using k. */
    for (i = 0; i < 4; ++i) {
        x = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ sm4_ck[i];

        /* Nonlinear operation tau */
        t = ((word32)sm4_sbox[(byte)(x >> 24)]) << 24 |
            ((word32)sm4_sbox[(byte)(x >> 16)]) << 16 |
            ((word32)sm4_sbox[(byte)(x >>  8)]) <<  8 |
            ((word32)sm4_sbox[(byte)(x      )])       ;

        /* Linear operation L' */
        k[i + 4] = k[i] ^ (t ^ rotlFixed(t, 13) ^ rotlFixed(t, 23));
        ks[i] = k[i + 4];
    }
    /* Calculate remaining words of key schedule without k. */
    for (; i < SM4_KEY_SCHEDULE; ++i) {
        x = ks[i - 3] ^ ks[i - 2] ^ ks[i - 1] ^ sm4_ck[i];

        /* Nonlinear operation tau */
        t = ((word32)sm4_sbox[(byte)(x >> 24)]) << 24 |
            ((word32)sm4_sbox[(byte)(x >> 16)]) << 16 |
            ((word32)sm4_sbox[(byte)(x >>  8)]) <<  8 |
            ((word32)sm4_sbox[(byte)(x      )])       ;

        /* Linear operation L' */
        ks[i] = ks[i - 4] ^ (t ^ rotlFixed(t, 13) ^ rotlFixed(t, 23));
    }
#endif
#else
    word32* ck = sm4_ck;

    __asm__ volatile (
        "LD1	{v0.16b}, [%[key]]\n\t"
        "LD1	{v9.16b}, [%[fk]]\n\t"
        "REV32	v0.16B, v0.16B\n\t"
        "LD1	{v1.4S-v4.4S}, [%[ck]], #64\n\t"
        "EOR	v0.16B, v0.16B, v9.16B\n\t"
        "LD1	{v5.4S-v8.4S}, [%[ck]]\n\t"

        "SM4EKEY	v1.4S, v0.4S, v1.4S\n\t"
        "SM4EKEY	v2.4S, v1.4S, v2.4S\n\t"
        "SM4EKEY	v3.4S, v2.4S, v3.4S\n\t"
        "SM4EKEY	v4.4S, v3.4S, v4.4S\n\t"
        "SM4EKEY	v5.4S, v4.4S, v5.4S\n\t"
        "SM4EKEY	v6.4S, v5.4S, v6.4S\n\t"
        "SM4EKEY	v7.4S, v6.4S, v7.4S\n\t"
        "SM4EKEY	v8.4S, v7.4S, v8.4S\n\t"

        "ST4	{v1.S-v4.S}[0], [%[ks]], #16\n\t"
        "ST4	{v5.S-v8.S}[0], [%[ks]], #16\n\t"
        "ST4	{v1.S-v4.S}[1], [%[ks]], #16\n\t"
        "ST4	{v5.S-v8.S}[1], [%[ks]], #16\n\t"
        "ST4	{v1.S-v4.S}[2], [%[ks]], #16\n\t"
        "ST4	{v5.S-v8.S}[2], [%[ks]], #16\n\t"
        "ST4	{v1.S-v4.S}[3], [%[ks]], #16\n\t"
        "ST4	{v5.S-v8.S}[3], [%[ks]], #16\n\t"
        : [ks] "+r" (ks), [ck] "+r" (ck)
        : [key] "r" (key), [fk] "r" (sm4_fk)
        : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8",
          "v9"
    );
#endif
}

/* Round operation.
 *
 * Assumes x0, x1, x2, x3 are the current state.
 * Assumes ks is the key schedule.
 *
 * @param [in] k0  Index into key schedule for first word.
 * @param [in] k1  Index into key schedule for second word.
 * @param [in] k2  Index into key schedule for third word.
 * @param [in] k3  Index into key schedule for fourth word.
 */
#define SM4_ROUNDS(k0, k1, k2, k3)          \
        x0 ^= sm4_t(x1 ^ x2 ^ x3 ^ ks[k0]); \
        x1 ^= sm4_t(x0 ^ x2 ^ x3 ^ ks[k1]); \
        x2 ^= sm4_t(x0 ^ x1 ^ x3 ^ ks[k2]); \
        x3 ^= sm4_t(x0 ^ x1 ^ x2 ^ ks[k3])

/* Encrypt a block of data using SM4 algorithm.
 *
 * @param [in]  ks   Key schedule.
 * @param [in]  in   Block to encrypt.
 * @param [out] out  Encrypted block.
 */
static void sm4_encrypt(const word32* ks, const byte* in, byte* out)
{
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM4)
    word32 x0, x1, x2, x3;
    /* Load block. */
    LOAD_U32_BE(in, x0, x1, x2, x3);

    /* Encrypt block. */
    SM4_ROUNDS( 0,  1,  2,  3);
    SM4_ROUNDS( 4,  5,  6,  7);
    SM4_ROUNDS( 8,  9, 10, 11);
    SM4_ROUNDS(12, 13, 14, 15);
    SM4_ROUNDS(16, 17, 18, 19);
    SM4_ROUNDS(20, 21, 22, 23);
    SM4_ROUNDS(24, 25, 26, 27);
    SM4_ROUNDS(28, 29, 30, 31);

    /* Store encrypted block. */
    STORE_U32_BE(x0, x1, x2, x3, out);
#else
    __asm__ volatile (
        "LD1	{v0.16b}, [%[in]]\n\t"
        "LD4	{v1.S-v4.S}[0], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[0], [%[ks]], #16\n\t"
        "LD4	{v1.S-v4.S}[1], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[1], [%[ks]], #16\n\t"
        "REV32	v0.16B, v0.16B\n\t"
        "LD4	{v1.S-v4.S}[2], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[2], [%[ks]], #16\n\t"
        "LD4	{v1.S-v4.S}[3], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[3], [%[ks]], #16\n\t"

        "SM4E	v0.4S, v1.4S\n\t"
        "SM4E	v0.4S, v2.4S\n\t"
        "SM4E	v0.4S, v3.4S\n\t"
        "SM4E	v0.4S, v4.4S\n\t"
        "SM4E	v0.4S, v5.4S\n\t"
        "SM4E	v0.4S, v6.4S\n\t"
        "SM4E	v0.4S, v7.4S\n\t"
        "SM4E	v0.4S, v8.4S\n\t"

        "REV64	v0.16B, v0.16B\n\t"
        "EXT	v0.16B, v0.16B, v0.16B, #8\n\t"
        "ST1	{v0.16b}, [%[out]]\n\t"

        : [ks] "+r" (ks), [out] "+r" (out)
        : [in] "r" (in)
        : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"
    );
#endif
}

#if defined(WOLFSSL_SM4_ECB) || defined(WOLFSSL_SM4_CBC)
/* Decrypt a block of data using SM4 algorithm.
 *
 * @param [in]  ks   Key schedule.
 * @param [in]  in   Block to decrypt.
 * @param [out] out  Decrypted block.
 */
static void sm4_decrypt(const word32* ks, const byte* in, byte* out)
{
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM_CRYPTO_SM4)
    word32 x0, x1, x2, x3;

    /* Load block. */
    LOAD_U32_BE(in, x0, x1, x2, x3);

    /* Decrypt block. */
    SM4_ROUNDS(31, 30, 29, 28);
    SM4_ROUNDS(27, 26, 25, 24);
    SM4_ROUNDS(23, 22, 21, 20);
    SM4_ROUNDS(19, 18, 17, 16);
    SM4_ROUNDS(15, 14, 13, 12);
    SM4_ROUNDS(11, 10,  9,  8);
    SM4_ROUNDS( 7,  6,  5,  4);
    SM4_ROUNDS( 3,  2,  1,  0);

    /* Store decrypted block. */
    STORE_U32_BE(x0, x1, x2, x3, out);
#else
    __asm__ volatile (
        "LD1	{v0.16b}, [%[in]]\n\t"
        "LD4	{v1.S-v4.S}[3], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[3], [%[ks]], #16\n\t"
        "LD4	{v1.S-v4.S}[2], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[2], [%[ks]], #16\n\t"
        "REV32	v0.16B, v0.16B\n\t"
        "LD4	{v1.S-v4.S}[1], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[1], [%[ks]], #16\n\t"
        "LD4	{v1.S-v4.S}[0], [%[ks]], #16\n\t"
        "LD4	{v5.S-v8.S}[0], [%[ks]], #16\n\t"

        "SM4E	v0.4S, v8.4S\n\t"
        "SM4E	v0.4S, v7.4S\n\t"
        "SM4E	v0.4S, v6.4S\n\t"
        "SM4E	v0.4S, v5.4S\n\t"
        "SM4E	v0.4S, v4.4S\n\t"
        "SM4E	v0.4S, v3.4S\n\t"
        "SM4E	v0.4S, v2.4S\n\t"
        "SM4E	v0.4S, v1.4S\n\t"

        "REV64	v0.16B, v0.16B\n\t"
        "EXT	v0.16B, v0.16B, v0.16B, #8\n\t"
        "ST1	{v0.16b}, [%[out]]\n\t"

        : [ks] "+r" (ks)
        : [in] "r" (in), [out] "r" (out)
        : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"
    );
#endif
}
#endif


/* Initialize the SM4 algorithm object.
 *
 * @param [in, out] sm4    SM4 algorithm object.
 * @param [in]      heap   Heap hint for dynamic memory allocation.
 * @param [in]      devId  Device identifier.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4 is NULL.
 */
int wc_Sm4Init(wc_Sm4* sm4, void* heap, int devId)
{
    int ret = 0;

    /* No device support yet. */
    (void)devId;

    /* Validate parameters. */
    if (sm4 == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set all fields to zero including bit fields. */
        XMEMSET(sm4, 0, sizeof(*sm4));

        /* Cache heap hint to use with any dynamic allocations. */
        sm4->heap = heap;
    }

    return ret;
}

/* Dispose of SM4 algorithm object.
 *
 * Zeroize sensitive data in object.
 *
 * @param [in, out] sm4  SM4 algorithm object.
 */
void wc_Sm4Free(wc_Sm4* sm4)
{
    /* Check we have something to work with. */
    if (sm4 != NULL) {
        /* Must zeroize key schedule. */
        ForceZero(sm4->ks, sizeof(sm4->ks));
    #if defined(WOLFSSL_SM4_CTR)
        /* For CBC, tmp is cipher text - no need to zeroize. */
        /* For CTR, tmp is encrypted counter that must be zeroized. */
        ForceZero(sm4->tmp, sizeof(sm4->tmp));
    #endif
    }
}

/* Set the key.
 *
 * @param [in, out] sm4  SM4 algorithm object.
 * @param [in]      key  Array of bytes representing key.
 */
static void sm4_set_key(wc_Sm4* sm4, const byte* key)
{
    /* Create key schedule. */
    sm4_key_schedule(key, sm4->ks);
    /* Mark key as having been set. */
    sm4->keySet = 1;
}

#if defined(WOLFSSL_SM4_ECB) || defined(WOLFSSL_SM4_CBC) || \
    defined(WOLFSSL_SM4_CTR) || defined(WOLFSSL_SM4_CCM)
/* Set the key.
 *
 * @param [in, out] sm4  SM4 algorithm object.
 * @param [in]      key  Array of bytes representing key.
 * @param [in]      len  Length of key. Must be SM4_KEY_SIZE.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4 or key is NULL.
 * @return  BAD_FUNC_ARG when len is not SM4_KEY_SIZE.
 */
int wc_Sm4SetKey(wc_Sm4* sm4, const byte* key, word32 len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (key == NULL) || (len != SM4_KEY_SIZE)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sm4_set_key(sm4, key);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR) || \
    defined(WOLFSSL_SM4_GCM)
/* Set the IV.
 *
 * @param [in, out] sm4  SM4 algorithm object.
 * @param [in]      iv   Array of bytes representing IV. May be NULL.
 */
static void sm4_set_iv(wc_Sm4* sm4, const byte* iv)
{
    /* Set IV. */
    XMEMCPY(sm4->iv, iv, SM4_IV_SIZE);
#ifdef WOLFSSL_SM4_CTR
    /* Unused count of encrypted counter for CTR mode. */
    sm4->unused = 0;
#endif
    sm4->ivSet = 1;
}
#endif

#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR)
/* Set the IV.
 *
 * @param [in, out] sm4  SM4 algorithm object.
 * @param [in]      iv   Array of bytes representing IV. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4 or iv is NULL.
 */
int wc_Sm4SetIV(wc_Sm4* sm4, const byte* iv)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (iv == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sm4_set_iv(sm4, iv);
    }

    return ret;
}
#endif

#ifdef WOLFSSL_SM4_ECB

/* Encrypt bytes using SM4-ECB.
 *
 * Length of input must be a multiple of the block size.
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [out] out  Byte array in which to place encrypted data.
 * @param [in]  in   Array of bytes to encrypt.
 * @param [in]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, out or in is NULL.
 * @return  BAD_FUNC_ARG when sz is not a multiple of SM4_BLOCK_SIZE.
 * @return  MISSING_KEY when a key has not been set.
 */
int wc_Sm4EcbEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (in == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Can only work on multiples of block size of bytes. */
    if ((ret == 0) && ((sz & (SM4_BLOCK_SIZE - 1)) != 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key has been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }

    if (ret == 0) {
        /* Encrypt all bytes. */
        while (sz > 0) {
            /* Encrypt a block. */
            sm4_encrypt(sm4->ks, in, out);
            /* Move on to next block. */
            in += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
            sz -= SM4_BLOCK_SIZE;
        }
    }

    return ret;
}

/* Decrypt bytes using SM4-ECB.
 *
 * Length of input must be a multiple of the block size.
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [out] out  Byte array in which to place decrypted data.
 * @param [in]  in   Array of bytes to decrypt.
 * @param [in]  sz   Number of bytes to decrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, out or in is NULL.
 * @return  BAD_FUNC_ARG when sz is not a multiple of SM4_BLOCK_SIZE.
 * @return  MISSING_KEY when a key has not been set.
 */
int wc_Sm4EcbDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
{

    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (in == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Can only work on multiples of block size of bytes. */
    if ((ret == 0) && ((sz & (SM4_BLOCK_SIZE - 1)) != 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key has been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }

    if (ret == 0) {
       /* Decrypt all bytes. */
        while (sz > 0) {
            /* Decrypt a block. */
            sm4_decrypt(sm4->ks, in, out);
            /* Move on to next block. */
            in += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
            sz -= SM4_BLOCK_SIZE;
        }
    }

    return ret;
}

#endif /* WOLFSSL_SM4_ECB */

#ifdef WOLFSSL_SM4_CBC

/* Encrypt bytes using SM4-CBC.
 *
 * Length of input must be a multiple of the block size.
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [out] out  Byte array in which to place encrypted data.
 * @param [in]  in   Array of bytes to encrypt.
 * @param [in]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, out or in is NULL.
 * @return  BAD_FUNC_ARG when sz is not a multiple of SM4_BLOCK_SIZE.
 * @return  MISSING_KEY when a key has not been set.
 * @return  MISSING_IV when an IV has not been set.
 */
int wc_Sm4CbcEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (in == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Can only work on multiples of block size of bytes. */
    if ((ret == 0) && ((sz & (SM4_BLOCK_SIZE - 1)) != 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key and IV have been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }
    if ((ret == 0) && (!sm4->ivSet)) {
        ret = MISSING_IV;
    }

    if (ret == 0) {
        /* Encrypt all bytes. */
        while (sz > 0) {
            /* XOR next block into IV. */
            xorbuf(sm4->iv, in, SM4_BLOCK_SIZE);
            /* Encrypt IV XORed with block. */
            sm4_encrypt(sm4->ks, sm4->iv, sm4->iv);
            /* Use output block as next IV. */
            XMEMCPY(out, sm4->iv, SM4_BLOCK_SIZE);

            /* Move on to next block. */
            in += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
            sz -= SM4_BLOCK_SIZE;
        }
    }

    return ret;
}

/* Decrypt bytes using SM4-CBC.
 *
 * Length of input must be a multiple of the block size.
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [out] out  Byte array in which to place decrypted data.
 * @param [in]  in   Array of bytes to decrypt.
 * @param [in]  sz   Number of bytes to decrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, out or in is NULL.
 * @return  MISSING_KEY when a key has not been set.
 * @return  MISSING_IV when an IV has not been set.
 */
int wc_Sm4CbcDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (in == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Can only work on multiples of block size of bytes. */
    if ((ret == 0) && ((sz & (SM4_BLOCK_SIZE - 1)) != 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key and IV have been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }
    if ((ret == 0) && (!sm4->ivSet)) {
        ret = MISSING_IV;
    }

    if (ret == 0) {
    #ifndef WOLFSSL_SM4_SMALL
        if (in != out) {
            while (sz > 0) {
                /* Decrypt next block. */
                sm4_decrypt(sm4->ks, in, sm4->tmp);
                /* XOR decrypted block with IV to create output. */
                xorbufout(out, sm4->tmp, sm4->iv, SM4_BLOCK_SIZE);
                /* This encrypted block is the IV for next decryption. */
                XMEMCPY(sm4->iv, in, SM4_BLOCK_SIZE);

                /* Move on to next block. */
                in += SM4_BLOCK_SIZE;
                out += SM4_BLOCK_SIZE;
                sz -= SM4_BLOCK_SIZE;
            }
        }
        else
    #endif
        {
            while (sz > 0) {
                /* Cache encrypted block as it is next IV. */
                XMEMCPY(sm4->tmp, in, SM4_BLOCK_SIZE);
                /* Decrypt next block. */
                sm4_decrypt(sm4->ks, sm4->tmp, out);
                /* XOR decrypted block with IV to create output. */
                xorbuf(out, sm4->iv, SM4_BLOCK_SIZE);
                /* Cached encrypted block is next IV. */
                XMEMCPY(sm4->iv, sm4->tmp, SM4_BLOCK_SIZE);

                /* Move on to next block. */
                in += SM4_BLOCK_SIZE;
                out += SM4_BLOCK_SIZE;
                sz -= SM4_BLOCK_SIZE;
            }
        }
    }

    return ret;
}

#endif /* WOLFSSL_SM4_CBC */

#ifdef WOLFSSL_SM4_CTR

/* Increment IV in big-endian representation.
 *
 * @param [in, out] counter  Counter value to increment.
 */
static WC_INLINE void sm4_increment_counter(byte* counter)
{
    int i;

    /* Big-endian number. */
    for (i = SM4_BLOCK_SIZE - 1; i >= 0; i--) {
        /* Increment byte and check for carry. */
        if ((++counter[i]) != 0) {
            /* No carry - done. */
            break;
        }
    }
}

/* Encrypt bytes using SM4-CTR.
 *
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [out] out  Byte array in which to place encrypted data.
 * @param [in]  in   Array of bytes to encrypt.
 * @param [in]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, out or in is NULL.
 * @return  MISSING_KEY when a key has not been set.
 * @return  MISSING_IV when an IV has not been set.
 */
int wc_Sm4CtrEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || (in == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key and IV have been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }
    if ((ret == 0) && (!sm4->ivSet)) {
        ret = MISSING_IV;
    }

    /* Continue if no error and bytes to encrypt. */
    if ((ret == 0) && (sz > 0)) {
        /* Check for unused bytes from previous encrypted counter. */
        if (sm4->unused != 0) {
            /* Calculate maximum length that can be encrypted. */
            word32 len = min(sm4->unused, sz);

            /* XOR the encrypted counter with input into output. */
            xorbufout(out, in, sm4->tmp + SM4_BLOCK_SIZE - sm4->unused, len);

            /* Move over processed data. */
            in += len;
            out += len;
            sz -= len;
            /* Some or all unused bytes used up. */
            sm4->unused -= (byte)len;
        }

        /* Do blocks at a time - only get here when there are no unused bytes.
         */
        while (sz >= SM4_BLOCK_SIZE) {
            /* Encrypt the current IV into temporary buffer in object. */
            sm4_encrypt(sm4->ks, sm4->iv, sm4->tmp);
            /* XOR the encrypted IV with next block into output. */
            xorbufout(out, in, sm4->tmp, SM4_BLOCK_SIZE);
            /* Increment counter for next block. */
            sm4_increment_counter(sm4->iv);

            /* Move on to next block. */
            in += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
            sz -= SM4_BLOCK_SIZE;
        }

        /* Check for less than a block of data that needing to be encrypted. */
        if (sz > 0) {
            /* Encrypt the current IV into temporary buffer in object. */
            sm4_encrypt(sm4->ks, sm4->iv, sm4->tmp);
            /* Increment counter for next block. */
            sm4_increment_counter(sm4->iv);
            /* XOR the encrypted IV with remaining data into output. */
            xorbufout(out, in, sm4->tmp, sz);
            /* Record number of unused encrypted IV bytes. */
            sm4->unused = (byte)(SM4_BLOCK_SIZE - sz);
        }
    }

    return ret;
}

#endif /* WOLFSSL_SM4_CTR */

#ifdef WOLFSSL_SM4_GCM
/* Calculate the value of H for the GMAC operation.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [in]  iv   Initial IV.
 */
static void sm4_gcm_calc_h(wc_Sm4* sm4, byte* iv)
{
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)
    word32* pt = (word32*)sm4->gcm.H;
#endif

    /* Encrypt all zeros IV to create hash key for GCM. */
    sm4_encrypt(sm4->ks, iv, sm4->gcm.H);
#if !defined(__aarch64__) || !defined(WOLFSSL_ARMASM)
    #if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
        /* Generate table from hash key. */
        GenerateM0(&sm4->gcm);
    #endif /* GCM_TABLE */
#else
    /* Reverse the bits of H for use in assembly. */
    __asm__ volatile (
        "LD1 {v0.16b}, [%[h]] \n"
        "RBIT v0.16b, v0.16b \n"
        "ST1 {v0.16b}, [%[out]] \n"
        : [out] "=r" (pt)
        : [h] "0" (pt)
        : "cc", "memory", "v0"
    );
#endif
}

/* Increment counter for GCM.
 *
 * @param [in, out] counter  4-byte big endian number.
 */
static WC_INLINE void sm4_increment_gcm_counter(byte* counter)
{
    int i;

    /* Big-endian number in last 4 bytes. */
    for (i = SM4_BLOCK_SIZE - 1; i >= SM4_BLOCK_SIZE - CTR_SZ; i--) {
        /* Increment byte and check for carry. */
        if ((++counter[i]) != 0) {
            /* No carry - done. */
            break;
        }
    }
}

/* Encrypt bytes using SM4-GCM implementation in C.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place encrypted data.
 * @param [in]  in       Array of bytes to encrypt.
 * @param [in]  sz       Number of bytes to encrypt.
 * @param [in]  nonce    Array of bytes holding nonce.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag calculated using GCM.
 * @param [in]  tagSz    Length of authentication tag to calculate in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 */
static void sm4_gcm_encrypt_c(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    word32 blocks = sz / SM4_BLOCK_SIZE;
    word32 partial = sz % SM4_BLOCK_SIZE;
    byte* c = out;
    ALIGN16 byte counter[SM4_BLOCK_SIZE];
    ALIGN16 byte encCounter[SM4_BLOCK_SIZE];

    /* Check for 12 bytes of nonce to use as is with 4 bytes of counter. */
    if (nonceSz == GCM_NONCE_MID_SZ) {
        /* Counter is nonce with bottom 4 bytes set to: 0x00,0x00,0x00,0x01. */
        XMEMCPY(counter, nonce, nonceSz);
        XMEMSET(counter + GCM_NONCE_MID_SZ, 0, CTR_SZ - 1);
        counter[SM4_BLOCK_SIZE - 1] = 1;
    }
    else {
        /* Counter is GHASH of nonce. */
        GHASH(&sm4->gcm, NULL, 0, nonce, nonceSz, counter, SM4_BLOCK_SIZE);
#ifdef WOLFSSL_ARMASM
        GMULT(counter, sm4->gcm.H);
#endif
    }
    /* Encrypt the initial counter for GMAC. */
    sm4_encrypt(sm4->ks, counter, encCounter);

#if defined(WOLFSSL_SM4_ECB)
    /* Encrypting multiple blocks at a time can be faster. */
    if ((c != in) && (blocks > 0)) {
        /* Set the counters for a multiple of block size into the output. */
        while (blocks--) {
            /* Increment last 4 bytes of big-endian counter. */
            sm4_increment_gcm_counter(counter);
            /* Copy into output. */
            XMEMCPY(c, counter, SM4_BLOCK_SIZE);
            /* Move output position past this block. */
            c += SM4_BLOCK_SIZE;
        }

        /* Reset number of blocks. */
        blocks = sz / SM4_BLOCK_SIZE;
        /* Encrypt the counters. */
        wc_Sm4EcbEncrypt(sm4, out, out, SM4_BLOCK_SIZE * blocks);
        /* XOR in the plaintext to create cipher text. */
        xorbuf(out, in, SM4_BLOCK_SIZE * blocks);
        /* Step over handled plaintext */
        in += SM4_BLOCK_SIZE * blocks;
    }
    else
#endif /* HAVE_SM4_ECB */
    {
        ALIGN32 byte scratch[SM4_BLOCK_SIZE];

        /* For each full block of data, encrypt. */
        while (blocks--) {
            /* Increment last 4 bytes of big-endian counter. */
            sm4_increment_gcm_counter(counter);
            /* Encrypt the counter into scratch. */
            sm4_encrypt(sm4->ks, counter, scratch);
            /* XOR encryted counter with plaintext into output. */
            xorbufout(c, scratch, in, SM4_BLOCK_SIZE);
            /* Move plaintext and cipher text position past this block. */
            in += SM4_BLOCK_SIZE;
            c += SM4_BLOCK_SIZE;
        }
    }

    if (partial != 0) {
        /* Increment last 4 bytes of big-endian counter. */
        sm4_increment_gcm_counter(counter);
        /* Encrypt the last counter. */
        sm4_encrypt(sm4->ks, counter, counter);
        /* XOR encryted counter with partial block plaintext into output. */
        xorbufout(c, counter, in, partial);
    }

    /* Calculate GHASH on additional authentication data and cipher text. */
#ifndef WOLFSSL_ARMASM
    GHASH(&sm4->gcm, aad, aadSz, out, sz, tag, tagSz);
#else
    GHASH(&sm4->gcm, aad, aadSz, out, sz, counter, SM4_BLOCK_SIZE);
    GMULT(counter, sm4->gcm.H);
    XMEMCPY(tag, counter, tagSz);
#endif
    /* XOR the encrypted initial counter into tag. */
    xorbuf(tag, encCounter, tagSz);
}

/* Decrypt bytes using SM4-GCM implementation in C.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place decrypted data.
 * @param [in]  in       Array of bytes to decrypt.
 * @param [in]  sz       Number of bytes to decrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [in]  tag      Authentication tag calculated using GCM.
 * @param [in]  tagSz    Length of authentication tag to calculate in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 * @return  0 on success.
 * @return  SM4_GCM_AUTH_E when authentication tag calculated does not match
 *          the one passed in.
 */
static int sm4_gcm_decrypt_c(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret;
    word32 blocks = sz / SM4_BLOCK_SIZE;
    word32 partial = sz % SM4_BLOCK_SIZE;
    byte* p = out;
    ALIGN16 byte counter[SM4_BLOCK_SIZE];
    ALIGN16 byte calcTag[SM4_BLOCK_SIZE];
    ALIGN16 byte scratch[SM4_BLOCK_SIZE];
    sword32 res;

    if (nonceSz == GCM_NONCE_MID_SZ) {
        /* Counter is nonce with bottom 4 bytes set to: 0x00,0x00,0x00,0x01. */
        XMEMCPY(counter, nonce, nonceSz);
        XMEMSET(counter + GCM_NONCE_MID_SZ, 0, CTR_SZ - 1);
        counter[SM4_BLOCK_SIZE - 1] = 1;
    }
    else {
        /* Counter is GHASH of nonce. */
        GHASH(&sm4->gcm, NULL, 0, nonce, nonceSz, counter, SM4_BLOCK_SIZE);
#ifdef WOLFSSL_ARMASM
        GMULT(counter, sm4->gcm.H);
#endif
    }

    /* Calculate GHASH on additional authentication data and cipher text. */
#ifndef WOLFSSL_ARMASM
    GHASH(&sm4->gcm, aad, aadSz, in, sz, calcTag, sizeof(calcTag));
#else
    GHASH(&sm4->gcm, aad, aadSz, in, sz, calcTag, SM4_BLOCK_SIZE);
    GMULT(calcTag, sm4->gcm.H);
#endif
    /* Encrypt the initial counter. */
    sm4_encrypt(sm4->ks, counter, scratch);
    /* XOR the encrypted initial counter into calculated tag. */
    xorbuf(calcTag, scratch, sizeof(calcTag));
#ifdef WC_SM4_GCM_DEC_AUTH_EARLY
    /* Compare tag and calculated tag in constant time. */
    res = ConstantCompare(tag, calcTag, tagSz);
    /* Create mask based on comparison result in constant time */
    res = 0 - (sword32)(((word32)(0 - res)) >> 31U);
    /* Mask error code to get return value. */
    ret = res & SM4_GCM_AUTH_E;
    /* Decrypt data when no error. */
    if (ret == 0)
#endif
    {
    #if defined(WOLFSSL_SM4_ECB)
        if ((in != p) && (blocks > 0)) {
            /* Set the counters for a multiple of block size into the output. */
            while (blocks--) {
                /* Increment last 4 bytes of big-endian counter. */
                sm4_increment_gcm_counter(counter);
                /* Copy into output. */
                XMEMCPY(p, counter, SM4_BLOCK_SIZE);
                /* Move output position past this block. */
                p += SM4_BLOCK_SIZE;
            }

            /* Reset number of blocks. */
            blocks = sz / SM4_BLOCK_SIZE;
            /* Encrypt the counters. */
            wc_Sm4EcbEncrypt(sm4, out, out, SM4_BLOCK_SIZE * blocks);
            /* XOR in the plaintext to create cipher text. */
            xorbuf(out, in, SM4_BLOCK_SIZE * blocks);
            /* Step over handled plaintext */
            in += SM4_BLOCK_SIZE * blocks;
        }
        else
    #endif /* WOLFSSL_SM4_ECB */
        {
            while (blocks--) {
                /* Increment last 4 bytes of big-endian counter. */
                sm4_increment_gcm_counter(counter);
                /* Encrypt the counter into scratch. */
                sm4_encrypt(sm4->ks, counter, scratch);
                /* XOR encryted counter with cipher text into output. */
                xorbufout(p, scratch, in, SM4_BLOCK_SIZE);
                /* Move plaintext and cipher text position past this block. */
                p += SM4_BLOCK_SIZE;
                in += SM4_BLOCK_SIZE;
            }
        }

        if (partial != 0) {
            /* Increment last 4 bytes of big-endian counter. */
            sm4_increment_gcm_counter(counter);
            /* Encrypt the last counter. */
            sm4_encrypt(sm4->ks, counter, counter);
            /* XOR encryted counter with partial block cipher text into output.
             */
            xorbufout(p, counter, in, partial);
        }

    #ifndef WC_SM4_GCM_DEC_AUTH_EARLY
        /* Compare tag and calculated tag in constant time. */
        res = ConstantCompare(tag, calcTag, (int)tagSz);
        /* Create mask based on comparison result in constant time */
        res = 0 - (sword32)(((word32)(0 - res)) >> 31U);
        /* Mask error code to get return value. */
        ret = res & SM4_GCM_AUTH_E;
    #endif
    }
    return ret;
}

/* Set the SM4-GCM key.
 *
 * Calculates key based table here.
 *
 * @param [in, out] sm4  SM4 algorithm object.
 * @param [in]      key  Array of bytes representing key.
 * @param [in]      len  Length of key. Must be SM4_KEY_SIZE.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4 or key is NULL.
 * @return  BAD_FUNC_ARG when len is not SM4_KEY_SIZE.
 */
int wc_Sm4GcmSetKey(wc_Sm4* sm4, const byte* key, word32 len)
{
    int ret = 0;
    byte iv[SM4_BLOCK_SIZE];

    /* Validate parameters. */
    if ((sm4 == NULL) || (key == NULL) || (len != SM4_KEY_SIZE)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set key. */
        sm4_set_key(sm4, key);
        /* Reset IV to all zeros. */
        XMEMSET(iv, 0, sizeof(iv));
        /* Set IV. */
        sm4_set_iv(sm4, iv);
        /* Calculate H for GMAC operation */
        sm4_gcm_calc_h(sm4, iv);
    }

    return ret;
}

/* Encrypt bytes using SM4-GCM.
 *
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place encrypted data.
 * @param [in]  in       Array of bytes to encrypt.
 * @param [in]  sz       Number of bytes to encrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag calculated using GCM.
 * @param [in]  tagSz    Length of authentication tag to calculate in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, in, out, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when authentication tag data length is less than
 *          WOLFSSL_MIN_AUTH_TAG_SZ or is more than SM4_BLOCK_SIZE.
 * @return  BAD_FUNC_ARG when nonce length is 0.
 * @return  MISSING_KEY when a key has not been set.
 */
int wc_Sm4GcmEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz, const byte* aad,
    word32 aadSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || ((sz != 0) && ((in == NULL) || (out == NULL))) ||
            (nonce == NULL) || (tag == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((tagSz < WOLFSSL_MIN_AUTH_TAG_SZ) || (tagSz > SM4_BLOCK_SIZE)) {
        ret = BAD_FUNC_ARG;
    }
    if (nonceSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key has been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }

    if (ret == 0) {
    #ifdef OPENSSL_EXTRA
        sm4->nonceSz = (int)nonceSz;
    #endif
        /* Perform encryption using C implementation. */
        sm4_gcm_encrypt_c(sm4, out, in, sz, nonce, nonceSz, tag, tagSz, aad,
            aadSz);
    }

    return ret;
}

/* Decrypt bytes using SM4-GCM.
 *
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place decrypted data.
 * @param [in]  in       Array of bytes to decrypt.
 * @param [in]  sz       Number of bytes to decrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [in]  tag      Authentication tag to compare against calculated.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, in, out, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when authentication tag data length is less than
 *          WOLFSSL_MIN_AUTH_TAG_SZ or is more than SM4_BLOCK_SIZE.
 * @return  BAD_FUNC_ARG when nonce length is 0.
 * @return  MISSING_KEY when a key has not been set.
 * @return  SM4_GCM_AUTH_E when authentication tag calculated does not match
 *          the one passed in.
 */
int wc_Sm4GcmDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || ((sz != 0) && ((in == NULL) || (out == NULL))) ||
            (nonce == NULL) || (tag == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((tagSz < WOLFSSL_MIN_AUTH_TAG_SZ) || (tagSz > SM4_BLOCK_SIZE)) {
        ret = BAD_FUNC_ARG;
    }
    if (nonceSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key has been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }

    if (ret == 0) {
    #ifdef OPENSSL_EXTRA
        sm4->nonceSz = (int)nonceSz;
    #endif
        /* Perform decryption using C implementation. */
        ret = sm4_gcm_decrypt_c(sm4, out, in, sz, nonce, nonceSz, tag, tagSz,
            aad, aadSz);
    }

    return ret;
}

#endif /* WOLFSSL_SM4_GCM */

#ifdef WOLFSSL_SM4_CCM

/* Roll up data.
 *
 * Encrypt each block XORed into out.
 *
 * @param [in]      sm4  SM4 algorithm object.
 * @param [in]      in   Data to roll up.
 * @param [in]      sz   Length in bytes of data.
 * @param [in, out] out  Block XORed into and encrypted.
 */
static void sm4_ccm_roll_x(wc_Sm4* sm4, const byte* in, word32 sz, byte* out)
{
    /* XOR in each block and encrypt each result. */
    while (sz >= SM4_BLOCK_SIZE) {
        /* XOR in next block. */
        xorbuf(out, in, SM4_BLOCK_SIZE);
        /* Move on past block. */
        in += SM4_BLOCK_SIZE;
        sz -= SM4_BLOCK_SIZE;
        /* Encrypt into self. */
        sm4_encrypt(sm4->ks, out, out);
    }

    /* XOR in a block of data and encrypt result. */
    if (sz > 0) {
        /* XOR in partial block. */
        xorbuf(out, in, sz);
        /* Encrypt into self. */
        sm4_encrypt(sm4->ks, out, out);
    }
}

/* Roll up additional authentication data (AAD).
 *
 * First block has length plus ant AAD XORed in before being encrypted.
 *
 * @param [in]  sm4  SM4 algorithm object.
 * @param [in]  in   Additional authentication data to roll up.
 * @param [in]  sz   Length in bytes of data.
 * @param [out] out  Block XORed into and encrypted.
 */
static void sm4_ccm_roll_aad(wc_Sm4* sm4, const byte* in, word32 sz, byte* out)
{
    word32 aadLenSz;
    word32 remainder;

    /* XOR length at start of block. */
    if (sz <= 0xFEFF) {
        /* Two bytes used to represent length. */
        aadLenSz = 2;
        out[0] ^= ((sz & 0xFF00) >> 8);
        out[1] ^=  (sz & 0x00FF);
    }
    else {
        /* Four bytes used to represent length plus two unique bytes. */
        aadLenSz = 6;
        out[0] ^= 0xFF;
        out[1] ^= 0xFE;
        out[2] ^= (byte)((sz & 0xFF000000) >> 24);
        out[3] ^= (byte)((sz & 0x00FF0000) >> 16);
        out[4] ^= (byte)((sz & 0x0000FF00) >>  8);
        out[5] ^= (byte) (sz & 0x000000FF);
    }

    /* Calculate number of input bytes required to make up the block. */
    remainder = SM4_BLOCK_SIZE - aadLenSz;
    /* Check how much AAD available. */
    if (sz >= remainder) {
        /* XOR up to block into out. */
        xorbuf(out + aadLenSz, in, remainder);
        /* Move past data. */
        sz -= remainder;
        in += remainder;
    }
    else {
        /* XOR in AAD available. */
        xorbuf(out + aadLenSz, in, sz);
        /* All AAD used. */
        sz = 0;
    }
    /* Encrypt into self. */
    sm4_encrypt(sm4->ks, out, out);

    if (sz > 0) {
        /* Roll up any remaining AAD. */
        sm4_ccm_roll_x(sm4, in, sz, out);
    }
}

/* Last bytes incremented as a big-endian number.
 *
 * Bytes not the nonce and length are incremented.
 *
 * @param [in, out] b      IV block.
 * @param [in]      ctrSz  Length of counter.
 */
static WC_INLINE void sm4_ccm_ctr_inc(byte* b, word32 ctrSz)
{
    word32 i;

    /* Only last bytes that make up counter. */
    for (i = 0; i < ctrSz; i++) {
        /* Increment byte and check for carry. */
        if ((++b[SM4_BLOCK_SIZE - 1 - i]) != 0) {
            /* No carry - done. */
            break;
        }
    }
}

/* Encipher bytes using SM4-CCM.
 *
 * @param [in]       sm4    SM4 algorithm object.
 * @param [out]      out    Byte array in which to place encrypted data.
 * @param [in]       in     Array of bytes to encrypt.
 * @param [in]       sz     Number of bytes to encrypt.
 * @param [in, out]  b      IV block.
 * @param [in]       ctrSz  Number of counter bytes in IV block.
 */
static WC_INLINE void sm4_ccm_crypt(wc_Sm4* sm4, byte* out, const byte* in,
    word32 sz, byte* b, byte ctrSz)
{
    ALIGN16 byte a[SM4_BLOCK_SIZE];

    /* Nonce and length have been set and counter 0 except for last byte. */

    /* Set counter to 1. */
    b[SM4_BLOCK_SIZE - 1] = 1;
    /* Encrypting full blocks at a time. */
    while (sz >= SM4_BLOCK_SIZE) {
        /* Encrypt counter. */
        sm4_encrypt(sm4->ks, b, a);
        /* XOR in plaintext. */
        xorbuf(a, in, SM4_BLOCK_SIZE);
        /* Copy cipher text out. */
        XMEMCPY(out, a, SM4_BLOCK_SIZE);

        /* Increment counter for next block. */
        sm4_ccm_ctr_inc(b, ctrSz);
        /* Move over block. */
        sz -= SM4_BLOCK_SIZE;
        in += SM4_BLOCK_SIZE;
        out += SM4_BLOCK_SIZE;
    }
    if (sz > 0) {
        /* Encrypt counter. */
        sm4_encrypt(sm4->ks, b, a);
        /* XOR in remaining plaintext. */
        xorbuf(a, in, sz);
        /* Copy cipher text out. */
        XMEMCPY(out, a, sz);
    }
}

/* Calculate authentication tag for SM4-CCM.
 *
 * @param [in]       sm4    SM4 algorithm object.
 * @param [in]       plain  Array of bytes to encrypt.
 * @param [in]       sz     Number of bytes to encrypt.
 * @param [in]       aad    Additional authentication data. May be NULL.
 * @param [in]       aadSz  Length of additional authentication data in bytes.
 * @param [in, out]  b      IV block.
 * @param [in]       ctrSz  Number of counter bytes in IV block.
 * @param [out]      tag    Authentication tag calculated using CCM.
 * @param [in]       tagSz  Length of authentication tag to calculate in bytes.
 */
static WC_INLINE void sm4_ccm_calc_auth_tag(wc_Sm4* sm4, const byte* plain,
    word32 sz, const byte* aad, word32 aadSz, byte* b, byte ctrSz,
    byte* tag, word32 tagSz)
{
    ALIGN16 byte a[SM4_BLOCK_SIZE];
    byte t[SM4_BLOCK_SIZE];
    word32 i;

    /* Nonce is in place. */

    /* Set first byte to length and flags. */
    b[0] = (byte)((((aad != NULL) && (aadSz > 0)) ? 0x40 : 0x00) +
                  (8 * (((byte)tagSz - 2) / 2)) + (ctrSz - 1));
    /* Set the counter bytes to length of data - 4 bytes of length only. */
    for (i = 0; i < ctrSz && i < sizeof(word32); i++) {
        b[SM4_BLOCK_SIZE - 1 - i] = (byte)(sz >> (8 * i));
    }
    /* Set remaining counter bytes to 0. */
    for (; i < ctrSz; i++) {
        b[SM4_BLOCK_SIZE - 1 - i] = 0x00;
    }
    /* Encrypt block into authentication tag block. */
    sm4_encrypt(sm4->ks, b, a);

    if ((aad != NULL) && (aadSz > 0)) {
        /* Roll up any AAD. */
        sm4_ccm_roll_aad(sm4, aad, aadSz, a);
    }
    if (sz > 0) {
        /* Roll up any plaintext. */
        sm4_ccm_roll_x(sm4, plain, sz, a);
    }

    /* Nonce remains in place. */
    /* Set first byte to counter size - 1. */
    b[0] = ctrSz - 1;
    /* Set counter to 0. */
    for (i = 0; i < ctrSz; i++) {
        b[SM4_BLOCK_SIZE - 1 - i] = 0;
    }
    /* Encrypt block into authentication tag block. */
    sm4_encrypt(sm4->ks, b, t);
    /* XOR in other authentication tag data. */
    xorbufout(tag, t, a, tagSz);
}

/* Encrypt bytes using SM4-CCM implementation in C.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place encrypted data.
 * @param [in]  in       Array of bytes to encrypt.
 * @param [in]  sz       Number of bytes to encrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag calculated using CCM.
 * @param [in]  tagSz    Length of authentication tag to calculate in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 */
static void sm4_ccm_encrypt_c(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz, const byte* aad,
    word32 aadSz)
{
    ALIGN16 byte b[SM4_BLOCK_SIZE];
    byte ctrSz;

    /* Calculate length of counter. */
    ctrSz = SM4_BLOCK_SIZE - 1 - (byte)nonceSz;
    /* Copy nonce in after length byte. */
    XMEMCPY(b + 1, nonce, nonceSz);

    /* Calculate authentication tag. */
    sm4_ccm_calc_auth_tag(sm4, in, sz, aad, aadSz, b, ctrSz, tag, tagSz);
    /* b is left with first byte counter size - 1 and counter part set to zero.
     */

    if (sz > 0) {
        /* Encrypt plaintext to cipher text. */
        sm4_ccm_crypt(sm4, out, in, sz, b, ctrSz);
    }
}

/* Decrypt bytes using SM4-CCM implementation in C.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place decrypted data.
 * @param [in]  in       Array of bytes to decrypt.
 * @param [in]  sz       Number of bytes to decrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [in]  tag      Authentication tag calculated using GCM.
 * @param [in]  tagSz    Length of authentication tag to calculate in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 * @return  0 on success.
 * @return  SM4_CCM_AUTH_E when authentication tag calculated does not match
 *          the one passed in.
 */
static int sm4_ccm_decrypt_c(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    ALIGN16 byte b[SM4_BLOCK_SIZE];
    ALIGN16 byte t[SM4_BLOCK_SIZE];
    byte ctrSz;
    word32 i;
    int ret = 0;

    /* Calculate length of counter. */
    ctrSz = SM4_BLOCK_SIZE - 1 - (byte)nonceSz;
    /* Copy nonce in after length byte. */
    XMEMCPY(b + 1, nonce, nonceSz);

    /* Set length byte to counter size - 1. */
    b[0] = ctrSz - 1;
    /* Set all bytes but least significant of counter to 0. */
    for (i = 1; i < ctrSz; i++) {
        b[SM4_BLOCK_SIZE - 1 - i] = 0;
    }
    if (sz > 0) {
        /* Decrypt cipher text to plaintext. */
        sm4_ccm_crypt(sm4, out, in, sz, b, ctrSz);
        /* b still has nonce in place. */
    }

    /* Calculate authentication tag. */
    sm4_ccm_calc_auth_tag(sm4, out, sz, aad, aadSz, b, ctrSz, t, tagSz);

    /* Compare calculated tag with passed in tag. */
    if (ConstantCompare(t, tag, (int)tagSz) != 0) {
        /* Set CCM authentication error return. */
        ret = SM4_CCM_AUTH_E;
    }

    return ret;
}

/* Encrypt bytes using SM4-CCM.
 *
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place encrypted data.
 * @param [in]  in       Array of bytes to encrypt.
 * @param [in]  sz       Number of bytes to encrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag calculated using CCM.
 * @param [in]  tagSz    Length of authentication tag to calculate in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, in, out, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when authentication tag data length is less than
 *          4 or is more than SM4_BLOCK_SIZE or an odd value.
 * @return  BAD_FUNC_ARG when nonce length is less than CCM_NONCE_MIN_SZ or
 *          greater than CCM_NONCE_MAX_SZ.
 * @return  MISSING_KEY when a key has not been set.
 */
int wc_Sm4CcmEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz, const byte* aad,
    word32 aadSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || ((sz != 0) && ((in == NULL) || (out == NULL))) ||
            (nonce == NULL) || (tag == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Tag size is even number 4..16. */
    if ((tagSz < 4) || (tagSz > SM4_BLOCK_SIZE) || ((tagSz & 1) == 1)) {
        ret = BAD_FUNC_ARG;
    }
    /* Nonce must be within supported range. */
    if ((nonceSz < CCM_NONCE_MIN_SZ) || (nonceSz > CCM_NONCE_MAX_SZ)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key has been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }

    if (ret == 0) {
    #ifdef OPENSSL_EXTRA
        sm4->nonceSz = (int)nonceSz;
    #endif
        /* Perform encryption using C implementation. */
        sm4_ccm_encrypt_c(sm4, out, in, sz, nonce, nonceSz, tag, tagSz, aad,
            aadSz);
    }

    return ret;
}

/* Decrypt bytes using SM4-CCM.
 *
 * Assumes out is at least sz bytes long.
 *
 * @param [in]  sm4      SM4 algorithm object.
 * @param [out] out      Byte array in which to place decrypted data.
 * @param [in]  in       Array of bytes to decrypt.
 * @param [in]  sz       Number of bytes to decrypt.
 * @param [in]  nonce    Array of bytes holding initialization vector.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [in]  tag      Authentication tag to compare against calculated.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 *                       Must be no more than SM4_BLOCK_SIZE.
 * @param [in]  aad      Additional authentication data. May be NULL.
 * @param [in]  aadSz    Length of additional authentication data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sm4, in, out, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when authentication tag data length is less than
 *          4 or is more than SM4_BLOCK_SIZE or an odd value.
 * @return  BAD_FUNC_ARG when nonce length is less than CCM_NONCE_MIN_SZ or
 *          greater than CCM_NONCE_MAX_SZ.
 * @return  MISSING_KEY when a key has not been set.
 * @return  SM4_CCM_AUTH_E when authentication tag calculated does not match
 *          the one passed in.
 */
int wc_Sm4CcmDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sm4 == NULL) || ((sz != 0) && ((in == NULL) || (out == NULL))) ||
            (nonce == NULL) || (tag == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Tag size is even number 4..16. */
    if ((tagSz < 4) || (tagSz > SM4_BLOCK_SIZE) || ((tagSz & 1) == 1)) {
        ret = BAD_FUNC_ARG;
    }
    /* Nonce must be within supported range. */
    if ((nonceSz < CCM_NONCE_MIN_SZ) || (nonceSz > CCM_NONCE_MAX_SZ)) {
        ret = BAD_FUNC_ARG;
    }

    /* Ensure a key has been set. */
    if ((ret == 0) && (!sm4->keySet)) {
        ret = MISSING_KEY;
    }

    if (ret == 0) {
    #ifdef OPENSSL_EXTRA
        sm4->nonceSz = (int)nonceSz;
    #endif
        /* Perform decryption using C implementation. */
        ret = sm4_ccm_decrypt_c(sm4, out, in, sz, nonce, nonceSz, tag, tagSz,
            aad, aadSz);
    }

    return ret;
}

#endif

#endif /* WOLFSSL_SM4 */

