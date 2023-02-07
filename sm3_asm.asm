; /* sm3_asm
;  *
;  * Copyright (C) 2006-2022 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 2 of the License, or
;  * (at your option) any later version.
;  *
;  * wolfSSL is distributed in the hope that it will be useful,
;  * but WITHOUT ANY WARRANTY; without even the implied warranty of
;  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  * GNU General Public License for more details.
;  *
;  * You should have received a copy of the GNU General Public License
;  * along with this program; if not, write to the Free Software
;  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
;  */
IF @Version LT 1200
; AVX2 instructions not recognized by old versions of MASM
IFNDEF NO_AVX2_SUPPORT
NO_AVX2_SUPPORT = 1
ENDIF
; MOVBE instruction not recognized by old versions of MASM
IFNDEF NO_MOVBE_SUPPORT
NO_MOVBE_SUPPORT = 1
ENDIF
ENDIF

IFNDEF HAVE_INTEL_AVX1
HAVE_INTEL_AVX1 = 1
ENDIF
IFNDEF NO_AVX2_SUPPORT
HAVE_INTEL_AVX2 = 1
ENDIF

IFNDEF _WIN64
_WIN64 = 1
ENDIF

IFDEF WOLFSSL_X86_64_BUILD
IFDEF HAVE_INTEL_AVX1
_DATA SEGMENT
ALIGN 16
L_SM3_AVX1_t DWORD 2043430169,4086860338,3878753381,3462539467,2630111639,965255983,1930511966,3861023932,3427080569,2559193843,823420391,1646840782,3293681564,2292395833,289824371,579648742,2643098247,991229199,1982458398,3964916796,3634866297,2974765299,1654563303,3309126606,2323285917,351604539,703209078,1406418156,2812836312,1330705329,2661410658,1027854021,2055708042,4111416084,3927864873,3560762451,2826557607,1358147919,2716295838,1137624381,2275248762,255530229,511060458,1022120916,2044241832,4088483664,3882000033,3469032771,2643098247,991229199,1982458398,3964916796,3634866297,2974765299,1654563303,3309126606,2323285917,351604539,703209078,1406418156,2812836312,1330705329,2661410658,1027854021
ptr_L_SM3_AVX1_t QWORD L_SM3_AVX1_t
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_SM3_AVX1_flip_mask QWORD 289644378169868803, 868365760874482187
ptr_L_SM3_AVX1_flip_mask QWORD L_SM3_AVX1_flip_mask
_DATA ENDS
_text SEGMENT READONLY PARA
sm3_compress_avx1 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        mov	rdi, rcx
        sub	rsp, 272
        lea	rax, QWORD PTR [rdi+32]
        vmovdqa	xmm11, ptr_L_SM3_AVX1_flip_mask
        mov	r8, [rdi]
        mov	r9, [rdi+4]
        mov	r10, [rdi+8]
        mov	r11, [rdi+12]
        mov	r12, [rdi+16]
        mov	r13, [rdi+20]
        mov	r14, [rdi+24]
        mov	r15, [rdi+28]
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rax]
        vmovdqu	xmm1, OWORD PTR [rax+16]
        vmovdqu	xmm2, OWORD PTR [rax+32]
        vmovdqu	xmm3, OWORD PTR [rax+48]
        ; x_to_w: 0
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm1
        vmovdqu	OWORD PTR [rsp+32], xmm2
        vmovdqu	OWORD PTR [rsp+48], xmm3
        ; msg_sched: 0-3
        ; iter_0: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_0: 1 - 1
        mov	rax, [rsp+16]
        add	rdx, rcx
        mov	rbx, [rsp]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_0: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_0: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_0: 6 - 7
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+8]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_1: 1 - 2
        mov	rax, [rsp+20]
        add	rdx, rcx
        mov	rbx, [rsp+4]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_1: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_1: 6 - 6
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_1: 7 - 7
        xorl	r10d, ebx
        ; iter_2: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+16]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	rax, [rsp+24]
        add	rdx, rcx
        mov	rbx, [rsp+8]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_2: 5 - 5
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_2: 6 - 6
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+24]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_3: 1 - 1
        mov	rax, [rsp+28]
        add	rdx, rcx
        mov	rbx, [rsp+12]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_3: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_3: 6 - 6
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        ; iter_3: 7 - 7
        xorl	r8d, ebx
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+32]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_4: 1 - 1
        mov	rax, [rsp+32]
        add	rdx, rcx
        mov	rbx, [rsp+16]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_4: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_4: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_4: 6 - 7
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+40]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_5: 1 - 2
        mov	rax, [rsp+36]
        add	rdx, rcx
        mov	rbx, [rsp+20]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_5: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_5: 6 - 6
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_5: 7 - 7
        xorl	r14d, ebx
        ; iter_6: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+48]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	rax, [rsp+40]
        add	rdx, rcx
        mov	rbx, [rsp+24]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_6: 5 - 5
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_6: 6 - 6
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+56]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_7: 1 - 1
        mov	rax, [rsp+44]
        add	rdx, rcx
        mov	rbx, [rsp+28]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_7: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_7: 6 - 6
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        ; iter_7: 7 - 7
        xorl	r12d, ebx
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+64]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_8: 1 - 1
        mov	rax, [rsp+48]
        add	rdx, rcx
        mov	rbx, [rsp+32]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_8: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_8: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_8: 6 - 7
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+72]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_9: 1 - 2
        mov	rax, [rsp+52]
        add	rdx, rcx
        mov	rbx, [rsp+36]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_9: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_9: 6 - 6
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_9: 7 - 7
        xorl	r10d, ebx
        ; iter_10: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+80]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	rax, [rsp+56]
        add	rdx, rcx
        mov	rbx, [rsp+40]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_10: 5 - 5
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_10: 6 - 6
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+88]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_11: 1 - 1
        mov	rax, [rsp+60]
        add	rdx, rcx
        mov	rbx, [rsp+44]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_11: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_11: 6 - 6
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        ; iter_11: 7 - 7
        xorl	r8d, ebx
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+96]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_12: 1 - 1
        mov	rax, [rsp+64]
        add	rdx, rcx
        mov	rbx, [rsp+48]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_12: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_12: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_12: 6 - 7
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+104]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_13: 1 - 2
        mov	rax, [rsp+68]
        add	rdx, rcx
        mov	rbx, [rsp+52]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_13: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_13: 6 - 6
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_13: 7 - 7
        xorl	r14d, ebx
        ; iter_14: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+112]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	rax, [rsp+72]
        add	rdx, rcx
        mov	rbx, [rsp+56]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_14: 5 - 5
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_14: 6 - 6
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+120]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_15: 1 - 1
        mov	rax, [rsp+76]
        add	rdx, rcx
        mov	rbx, [rsp+60]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_15: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_15: 6 - 6
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        ; iter_15: 7 - 7
        xorl	r12d, ebx
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+128]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_16: 1 - 1
        mov	rax, [rsp+80]
        add	rdx, rcx
        mov	rbx, [rsp+64]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_16: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_16: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_16: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+136]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_17: 1 - 2
        mov	rax, [rsp+84]
        add	rdx, rcx
        mov	rbx, [rsp+68]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_17: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_17: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_17: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_18: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+144]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        mov	rax, [rsp+88]
        add	rdx, rcx
        mov	rbx, [rsp+72]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_18: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_18: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+152]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_19: 1 - 1
        mov	rax, [rsp+92]
        add	rdx, rcx
        mov	rbx, [rsp+76]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_19: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_19: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_19: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+160]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_20: 1 - 1
        mov	rax, [rsp+96]
        add	rdx, rcx
        mov	rbx, [rsp+80]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_20: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_20: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_20: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+168]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_21: 1 - 2
        mov	rax, [rsp+100]
        add	rdx, rcx
        mov	rbx, [rsp+84]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_21: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_21: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_21: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_22: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+176]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        mov	rax, [rsp+104]
        add	rdx, rcx
        mov	rbx, [rsp+88]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_22: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_22: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+184]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_23: 1 - 1
        mov	rax, [rsp+108]
        add	rdx, rcx
        mov	rbx, [rsp+92]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_23: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_23: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_23: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+192]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_24: 1 - 1
        mov	rax, [rsp+112]
        add	rdx, rcx
        mov	rbx, [rsp+96]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_24: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_24: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_24: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+200]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_25: 1 - 2
        mov	rax, [rsp+116]
        add	rdx, rcx
        mov	rbx, [rsp+100]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_25: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_25: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_25: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_26: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+208]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        mov	rax, [rsp+120]
        add	rdx, rcx
        mov	rbx, [rsp+104]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_26: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_26: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+216]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_27: 1 - 1
        mov	rax, [rsp+124]
        add	rdx, rcx
        mov	rbx, [rsp+108]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_27: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_27: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_27: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+224]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_28: 1 - 1
        mov	rax, [rsp+128]
        add	rdx, rcx
        mov	rbx, [rsp+112]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_28: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_28: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_28: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+232]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_29: 1 - 2
        mov	rax, [rsp+132]
        add	rdx, rcx
        mov	rbx, [rsp+116]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_29: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_29: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_29: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_30: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+240]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        mov	rax, [rsp+136]
        add	rdx, rcx
        mov	rbx, [rsp+120]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_30: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_30: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+248]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_31: 1 - 1
        mov	rax, [rsp+140]
        add	rdx, rcx
        mov	rbx, [rsp+124]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_31: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_31: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_31: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+256]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_32: 1 - 1
        mov	rax, [rsp+144]
        add	rdx, rcx
        mov	rbx, [rsp+128]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_32: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_32: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_32: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+264]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_33: 1 - 2
        mov	rax, [rsp+148]
        add	rdx, rcx
        mov	rbx, [rsp+132]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_33: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_33: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_33: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_34: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+272]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        mov	rax, [rsp+152]
        add	rdx, rcx
        mov	rbx, [rsp+136]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_34: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_34: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+280]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_35: 1 - 1
        mov	rax, [rsp+156]
        add	rdx, rcx
        mov	rbx, [rsp+140]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_35: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_35: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_35: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+288]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_36: 1 - 1
        mov	rax, [rsp+160]
        add	rdx, rcx
        mov	rbx, [rsp+144]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_36: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_36: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_36: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+296]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_37: 1 - 2
        mov	rax, [rsp+164]
        add	rdx, rcx
        mov	rbx, [rsp+148]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_37: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_37: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_37: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_38: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+304]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        mov	rax, [rsp+168]
        add	rdx, rcx
        mov	rbx, [rsp+152]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_38: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_38: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+312]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_39: 1 - 1
        mov	rax, [rsp+172]
        add	rdx, rcx
        mov	rbx, [rsp+156]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_39: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_39: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_39: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+320]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_40: 1 - 1
        mov	rax, [rsp+176]
        add	rdx, rcx
        mov	rbx, [rsp+160]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_40: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_40: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_40: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+328]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_41: 1 - 2
        mov	rax, [rsp+180]
        add	rdx, rcx
        mov	rbx, [rsp+164]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_41: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_41: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_41: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_42: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+336]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        mov	rax, [rsp+184]
        add	rdx, rcx
        mov	rbx, [rsp+168]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_42: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_42: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+344]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_43: 1 - 1
        mov	rax, [rsp+188]
        add	rdx, rcx
        mov	rbx, [rsp+172]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_43: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_43: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_43: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+352]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_44: 1 - 1
        mov	rax, [rsp+192]
        add	rdx, rcx
        mov	rbx, [rsp+176]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_44: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_44: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_44: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+360]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_45: 1 - 2
        mov	rax, [rsp+196]
        add	rdx, rcx
        mov	rbx, [rsp+180]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_45: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_45: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_45: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_46: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+368]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        mov	rax, [rsp+200]
        add	rdx, rcx
        mov	rbx, [rsp+184]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_46: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_46: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+376]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_47: 1 - 1
        mov	rax, [rsp+204]
        add	rdx, rcx
        mov	rbx, [rsp+188]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_47: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_47: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_47: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+384]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_48: 1 - 1
        mov	rax, [rsp+208]
        add	rdx, rcx
        mov	rbx, [rsp+192]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_48: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_48: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_48: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+392]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_49: 1 - 2
        mov	rax, [rsp+212]
        add	rdx, rcx
        mov	rbx, [rsp+196]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_49: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_49: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_49: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_50: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+400]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        mov	rax, [rsp+216]
        add	rdx, rcx
        mov	rbx, [rsp+200]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_50: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_50: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+408]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_51: 1 - 1
        mov	rax, [rsp+220]
        add	rdx, rcx
        mov	rbx, [rsp+204]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_51: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_51: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_51: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+416]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        mov	rax, [rsp+224]
        add	rdx, rcx
        mov	rbx, [rsp+208]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        ; iter_53: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+424]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        mov	rax, [rsp+228]
        add	rdx, rcx
        mov	rbx, [rsp+212]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_54: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+432]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        mov	rax, [rsp+232]
        add	rdx, rcx
        mov	rbx, [rsp+216]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        ; iter_55: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+440]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        mov	rax, [rsp+236]
        add	rdx, rcx
        mov	rbx, [rsp+220]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+448]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        mov	rax, [rsp+240]
        add	rdx, rcx
        mov	rbx, [rsp+224]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        ; iter_57: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+456]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        mov	rax, [rsp+244]
        add	rdx, rcx
        mov	rbx, [rsp+228]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_58: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+464]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        mov	rax, [rsp+248]
        add	rdx, rcx
        mov	rbx, [rsp+232]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        ; iter_59: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+472]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        mov	rax, [rsp+252]
        add	rdx, rcx
        mov	rbx, [rsp+236]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; iter_60: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+480]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        mov	rax, [rsp+256]
        add	rdx, rcx
        mov	rbx, [rsp+240]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        ; iter_61: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+488]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        mov	rax, [rsp+260]
        add	rdx, rcx
        mov	rbx, [rsp+244]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_62: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+496]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        mov	rax, [rsp+264]
        add	rdx, rcx
        mov	rbx, [rsp+248]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        ; iter_63: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+504]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        mov	rax, [rsp+268]
        add	rdx, rcx
        mov	rbx, [rsp+252]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        xorl	[rdi], r8d
        xorl	[rdi+4], r9d
        xorl	[rdi+8], r10d
        xorl	[rdi+12], r11d
        xorl	[rdi+16], r12d
        xorl	[rdi+20], r13d
        xorl	[rdi+24], r14d
        xorl	[rdi+28], r15d
        xor	rax, rax
        vzeroupper
        add	rsp, 272
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
sm3_compress_avx1 ENDP
_text ENDS
_text SEGMENT READONLY PARA
sm3_compress_len_avx1 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rbp
        push	rsi
        mov	rdi, rcx
        mov	rbp, rdx
        mov	rsi, r8
        sub	rsp, 272
        vmovdqa	xmm11, ptr_L_SM3_AVX1_flip_mask
        mov	r8, [rdi]
        mov	r9, [rdi+4]
        mov	r10, [rdi+8]
        mov	r11, [rdi+12]
        mov	r12, [rdi+16]
        mov	r13, [rdi+20]
        mov	r14, [rdi+24]
        mov	r15, [rdi+28]
        ; Start of loop processing a block
L_SM3_AVX1len_start:
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rbp]
        vmovdqu	xmm1, OWORD PTR [rbp+16]
        vpshufb	xmm0, xmm0, xmm11
        vpshufb	xmm1, xmm1, xmm11
        vmovdqu	xmm2, OWORD PTR [rbp+32]
        vmovdqu	xmm3, OWORD PTR [rbp+48]
        vpshufb	xmm2, xmm2, xmm11
        vpshufb	xmm3, xmm3, xmm11
        ; x_to_w: 0
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm1
        vmovdqu	OWORD PTR [rsp+32], xmm2
        vmovdqu	OWORD PTR [rsp+48], xmm3
        ; msg_sched: 0-3
        ; iter_0: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_0: 1 - 1
        mov	rax, [rsp+16]
        add	rdx, rcx
        mov	rbx, [rsp]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_0: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_0: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_0: 6 - 7
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+8]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_1: 1 - 2
        mov	rax, [rsp+20]
        add	rdx, rcx
        mov	rbx, [rsp+4]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_1: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_1: 6 - 6
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_1: 7 - 7
        xorl	r10d, ebx
        ; iter_2: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+16]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	rax, [rsp+24]
        add	rdx, rcx
        mov	rbx, [rsp+8]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_2: 5 - 5
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_2: 6 - 6
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+24]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_3: 1 - 1
        mov	rax, [rsp+28]
        add	rdx, rcx
        mov	rbx, [rsp+12]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_3: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_3: 6 - 6
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        ; iter_3: 7 - 7
        xorl	r8d, ebx
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+32]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_4: 1 - 1
        mov	rax, [rsp+32]
        add	rdx, rcx
        mov	rbx, [rsp+16]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_4: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_4: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_4: 6 - 7
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+40]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_5: 1 - 2
        mov	rax, [rsp+36]
        add	rdx, rcx
        mov	rbx, [rsp+20]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_5: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_5: 6 - 6
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_5: 7 - 7
        xorl	r14d, ebx
        ; iter_6: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+48]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	rax, [rsp+40]
        add	rdx, rcx
        mov	rbx, [rsp+24]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_6: 5 - 5
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_6: 6 - 6
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+56]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_7: 1 - 1
        mov	rax, [rsp+44]
        add	rdx, rcx
        mov	rbx, [rsp+28]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_7: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_7: 6 - 6
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        ; iter_7: 7 - 7
        xorl	r12d, ebx
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+64]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_8: 1 - 1
        mov	rax, [rsp+48]
        add	rdx, rcx
        mov	rbx, [rsp+32]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_8: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_8: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_8: 6 - 7
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+72]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_9: 1 - 2
        mov	rax, [rsp+52]
        add	rdx, rcx
        mov	rbx, [rsp+36]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_9: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_9: 6 - 6
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_9: 7 - 7
        xorl	r10d, ebx
        ; iter_10: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+80]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	rax, [rsp+56]
        add	rdx, rcx
        mov	rbx, [rsp+40]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_10: 5 - 5
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_10: 6 - 6
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+88]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_11: 1 - 1
        mov	rax, [rsp+60]
        add	rdx, rcx
        mov	rbx, [rsp+44]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_11: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_11: 6 - 6
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        ; iter_11: 7 - 7
        xorl	r8d, ebx
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+96]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_12: 1 - 1
        mov	rax, [rsp+64]
        add	rdx, rcx
        mov	rbx, [rsp+48]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_12: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_12: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_12: 6 - 7
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+104]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_13: 1 - 2
        mov	rax, [rsp+68]
        add	rdx, rcx
        mov	rbx, [rsp+52]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_13: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_13: 6 - 6
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_13: 7 - 7
        xorl	r14d, ebx
        ; iter_14: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+112]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	rax, [rsp+72]
        add	rdx, rcx
        mov	rbx, [rsp+56]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_14: 5 - 5
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_14: 6 - 6
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+120]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_15: 1 - 1
        mov	rax, [rsp+76]
        add	rdx, rcx
        mov	rbx, [rsp+60]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_15: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_15: 6 - 6
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        ; iter_15: 7 - 7
        xorl	r12d, ebx
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+128]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_16: 1 - 1
        mov	rax, [rsp+80]
        add	rdx, rcx
        mov	rbx, [rsp+64]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_16: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_16: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_16: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+136]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_17: 1 - 2
        mov	rax, [rsp+84]
        add	rdx, rcx
        mov	rbx, [rsp+68]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_17: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_17: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_17: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_18: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+144]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        mov	rax, [rsp+88]
        add	rdx, rcx
        mov	rbx, [rsp+72]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_18: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_18: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+152]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_19: 1 - 1
        mov	rax, [rsp+92]
        add	rdx, rcx
        mov	rbx, [rsp+76]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_19: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_19: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_19: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+160]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_20: 1 - 1
        mov	rax, [rsp+96]
        add	rdx, rcx
        mov	rbx, [rsp+80]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_20: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_20: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_20: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+168]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_21: 1 - 2
        mov	rax, [rsp+100]
        add	rdx, rcx
        mov	rbx, [rsp+84]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_21: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_21: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_21: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_22: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+176]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        mov	rax, [rsp+104]
        add	rdx, rcx
        mov	rbx, [rsp+88]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_22: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_22: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+184]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_23: 1 - 1
        mov	rax, [rsp+108]
        add	rdx, rcx
        mov	rbx, [rsp+92]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_23: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_23: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_23: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+192]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_24: 1 - 1
        mov	rax, [rsp+112]
        add	rdx, rcx
        mov	rbx, [rsp+96]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_24: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_24: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_24: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+200]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_25: 1 - 2
        mov	rax, [rsp+116]
        add	rdx, rcx
        mov	rbx, [rsp+100]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_25: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_25: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_25: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_26: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+208]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        mov	rax, [rsp+120]
        add	rdx, rcx
        mov	rbx, [rsp+104]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_26: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_26: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+216]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_27: 1 - 1
        mov	rax, [rsp+124]
        add	rdx, rcx
        mov	rbx, [rsp+108]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_27: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_27: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_27: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+224]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_28: 1 - 1
        mov	rax, [rsp+128]
        add	rdx, rcx
        mov	rbx, [rsp+112]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_28: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_28: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_28: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+232]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_29: 1 - 2
        mov	rax, [rsp+132]
        add	rdx, rcx
        mov	rbx, [rsp+116]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_29: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_29: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_29: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_30: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+240]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        mov	rax, [rsp+136]
        add	rdx, rcx
        mov	rbx, [rsp+120]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_30: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_30: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+248]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_31: 1 - 1
        mov	rax, [rsp+140]
        add	rdx, rcx
        mov	rbx, [rsp+124]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_31: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_31: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_31: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+256]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_32: 1 - 1
        mov	rax, [rsp+144]
        add	rdx, rcx
        mov	rbx, [rsp+128]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_32: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_32: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_32: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+264]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_33: 1 - 2
        mov	rax, [rsp+148]
        add	rdx, rcx
        mov	rbx, [rsp+132]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_33: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_33: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_33: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_34: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+272]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        mov	rax, [rsp+152]
        add	rdx, rcx
        mov	rbx, [rsp+136]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_34: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_34: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+280]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_35: 1 - 1
        mov	rax, [rsp+156]
        add	rdx, rcx
        mov	rbx, [rsp+140]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_35: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_35: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_35: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+288]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_36: 1 - 1
        mov	rax, [rsp+160]
        add	rdx, rcx
        mov	rbx, [rsp+144]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_36: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_36: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_36: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+296]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_37: 1 - 2
        mov	rax, [rsp+164]
        add	rdx, rcx
        mov	rbx, [rsp+148]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_37: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_37: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_37: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_38: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+304]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        mov	rax, [rsp+168]
        add	rdx, rcx
        mov	rbx, [rsp+152]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_38: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_38: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+312]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_39: 1 - 1
        mov	rax, [rsp+172]
        add	rdx, rcx
        mov	rbx, [rsp+156]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_39: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_39: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_39: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+320]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_40: 1 - 1
        mov	rax, [rsp+176]
        add	rdx, rcx
        mov	rbx, [rsp+160]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_40: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_40: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_40: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+328]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_41: 1 - 2
        mov	rax, [rsp+180]
        add	rdx, rcx
        mov	rbx, [rsp+164]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_41: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_41: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_41: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_42: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+336]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        mov	rax, [rsp+184]
        add	rdx, rcx
        mov	rbx, [rsp+168]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_42: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_42: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+344]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_43: 1 - 1
        mov	rax, [rsp+188]
        add	rdx, rcx
        mov	rbx, [rsp+172]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_43: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_43: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_43: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+352]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_44: 1 - 1
        mov	rax, [rsp+192]
        add	rdx, rcx
        mov	rbx, [rsp+176]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_44: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_44: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_44: 6 - 7
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+360]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_45: 1 - 2
        mov	rax, [rsp+196]
        add	rdx, rcx
        mov	rbx, [rsp+180]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_45: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_45: 6 - 6
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_45: 7 - 7
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_46: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+368]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        mov	rax, [rsp+200]
        add	rdx, rcx
        mov	rbx, [rsp+184]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_46: 5 - 5
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_46: 6 - 6
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+376]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_47: 1 - 1
        mov	rax, [rsp+204]
        add	rdx, rcx
        mov	rbx, [rsp+188]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_47: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_47: 6 - 6
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        ; iter_47: 7 - 7
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+384]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_48: 1 - 1
        mov	rax, [rsp+208]
        add	rdx, rcx
        mov	rbx, [rsp+192]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_48: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_48: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_48: 6 - 7
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+392]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_49: 1 - 2
        mov	rax, [rsp+212]
        add	rdx, rcx
        mov	rbx, [rsp+196]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_49: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_49: 6 - 6
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_49: 7 - 7
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_50: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+400]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        mov	rax, [rsp+216]
        add	rdx, rcx
        mov	rbx, [rsp+200]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_50: 5 - 5
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_50: 6 - 6
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_t+408]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_51: 1 - 1
        mov	rax, [rsp+220]
        add	rdx, rcx
        mov	rbx, [rsp+204]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_51: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_51: 6 - 6
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        ; iter_51: 7 - 7
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+416]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        mov	rax, [rsp+224]
        add	rdx, rcx
        mov	rbx, [rsp+208]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        ; iter_53: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+424]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        mov	rax, [rsp+228]
        add	rdx, rcx
        mov	rbx, [rsp+212]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_54: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+432]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        mov	rax, [rsp+232]
        add	rdx, rcx
        mov	rbx, [rsp+216]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        ; iter_55: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+440]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        mov	rax, [rsp+236]
        add	rdx, rcx
        mov	rbx, [rsp+220]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+448]
        mov	rcx, r8
        add	rdx, r12
        roll	ecx, 0xc
        mov	rax, [rsp+240]
        add	rdx, rcx
        mov	rbx, [rsp+224]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        add	rcx, r11
        mov	r11, r13
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        xorl	r11d, r14d
        and	r15, rbx
        and	r11, r12
        xorl	r15d, r9d
        xorl	r11d, r14d
        add	r15, rcx
        add	r11, rdx
        mov	rbx, r11
        roll	r11d, 0x8
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        roll	r11d, 0x9
        xorl	r11d, ebx
        ; iter_57: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+456]
        mov	rcx, r15
        add	rdx, r11
        roll	ecx, 0xc
        mov	rax, [rsp+244]
        add	rdx, rcx
        mov	rbx, [rsp+228]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        add	rcx, r10
        mov	r10, r12
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        xorl	r10d, r13d
        and	r14, rbx
        and	r10, r11
        xorl	r14d, r8d
        xorl	r10d, r13d
        add	r14, rcx
        add	r10, rdx
        mov	rbx, r10
        roll	r10d, 0x8
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        roll	r10d, 0x9
        xorl	r10d, ebx
        ; iter_58: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+464]
        mov	rcx, r14
        add	rdx, r10
        roll	ecx, 0xc
        mov	rax, [rsp+248]
        add	rdx, rcx
        mov	rbx, [rsp+232]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        add	rcx, r9
        mov	r9, r11
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        xorl	r9d, r12d
        and	r13, rbx
        and	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r12d
        add	r13, rcx
        add	r9, rdx
        mov	rbx, r9
        roll	r9d, 0x8
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        roll	r9d, 0x9
        xorl	r9d, ebx
        ; iter_59: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+472]
        mov	rcx, r13
        add	rdx, r9
        roll	ecx, 0xc
        mov	rax, [rsp+252]
        add	rdx, rcx
        mov	rbx, [rsp+236]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        add	rcx, r8
        mov	r8, r10
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        xorl	r8d, r11d
        and	r12, rbx
        and	r8, r9
        xorl	r12d, r14d
        xorl	r8d, r11d
        add	r12, rcx
        add	r8, rdx
        mov	rbx, r8
        roll	r8d, 0x8
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        roll	r8d, 0x9
        xorl	r8d, ebx
        ; iter_60: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+480]
        mov	rcx, r12
        add	rdx, r8
        roll	ecx, 0xc
        mov	rax, [rsp+256]
        add	rdx, rcx
        mov	rbx, [rsp+240]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r15, r9
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        xorl	r15d, r10d
        and	r11, rbx
        and	r15, r8
        xorl	r11d, r13d
        xorl	r15d, r10d
        add	r11, rcx
        add	r15, rdx
        mov	rbx, r15
        roll	r15d, 0x8
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        roll	r15d, 0x9
        xorl	r15d, ebx
        ; iter_61: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+488]
        mov	rcx, r11
        add	rdx, r15
        roll	ecx, 0xc
        mov	rax, [rsp+260]
        add	rdx, rcx
        mov	rbx, [rsp+244]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r14, r8
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        xorl	r14d, r9d
        and	r10, rbx
        and	r14, r15
        xorl	r10d, r12d
        xorl	r14d, r9d
        add	r10, rcx
        add	r14, rdx
        mov	rbx, r14
        roll	r14d, 0x8
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        roll	r14d, 0x9
        xorl	r14d, ebx
        ; iter_62: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+496]
        mov	rcx, r10
        add	rdx, r14
        roll	ecx, 0xc
        mov	rax, [rsp+264]
        add	rdx, rcx
        mov	rbx, [rsp+248]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r13, r15
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        xorl	r13d, r8d
        and	r9, rbx
        and	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r8d
        add	r9, rcx
        add	r13, rdx
        mov	rbx, r13
        roll	r13d, 0x8
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        roll	r13d, 0x9
        xorl	r13d, ebx
        ; iter_63: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_t+504]
        mov	rcx, r9
        add	rdx, r13
        roll	ecx, 0xc
        mov	rax, [rsp+268]
        add	rdx, rcx
        mov	rbx, [rsp+252]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r12, r14
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        xorl	r12d, r15d
        and	r8, rbx
        and	r12, r13
        xorl	r8d, r10d
        xorl	r12d, r15d
        add	r8, rcx
        add	r12, rdx
        mov	rbx, r12
        roll	r12d, 0x8
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        roll	r12d, 0x9
        xorl	r12d, ebx
        xorl	r8d, [rdi]
        xorl	r9d, [rdi+4]
        xorl	r10d, [rdi+8]
        xorl	r11d, [rdi+12]
        xorl	r12d, [rdi+16]
        xorl	r13d, [rdi+20]
        xorl	r14d, [rdi+24]
        xorl	r15d, [rdi+28]
        add	rbp, 64
        subl	esi, 0x40
        mov	[rdi], r8
        mov	[rdi+4], r9
        mov	[rdi+8], r10
        mov	[rdi+12], r11
        mov	[rdi+16], r12
        mov	[rdi+20], r13
        mov	[rdi+24], r14
        mov	[rdi+28], r15
        jnz	L_SM3_AVX1len_start
        xor	rax, rax
        vzeroupper
        add	rsp, 272
        pop	rsi
        pop	rbp
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
sm3_compress_len_avx1 ENDP
_text ENDS
_DATA SEGMENT
ALIGN 16
L_SM3_AVX1_RORX_t DWORD 2043430169,4086860338,3878753381,3462539467,2630111639,965255983,1930511966,3861023932,3427080569,2559193843,823420391,1646840782,3293681564,2292395833,289824371,579648742,2643098247,991229199,1982458398,3964916796,3634866297,2974765299,1654563303,3309126606,2323285917,351604539,703209078,1406418156,2812836312,1330705329,2661410658,1027854021,2055708042,4111416084,3927864873,3560762451,2826557607,1358147919,2716295838,1137624381,2275248762,255530229,511060458,1022120916,2044241832,4088483664,3882000033,3469032771,2643098247,991229199,1982458398,3964916796,3634866297,2974765299,1654563303,3309126606,2323285917,351604539,703209078,1406418156,2812836312,1330705329,2661410658,1027854021
ptr_L_SM3_AVX1_RORX_t QWORD L_SM3_AVX1_RORX_t
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_SM3_AVX1_RORX_flip_mask QWORD 289644378169868803, 868365760874482187
ptr_L_SM3_AVX1_RORX_flip_mask QWORD L_SM3_AVX1_RORX_flip_mask
_DATA ENDS
_text SEGMENT READONLY PARA
sm3_compress_avx1_rorx PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        mov	rdi, rcx
        sub	rsp, 272
        lea	rax, QWORD PTR [rdi+32]
        vmovdqa	xmm11, ptr_L_SM3_AVX1_RORX_flip_mask
        mov	r8, [rdi]
        mov	r9, [rdi+4]
        mov	r10, [rdi+8]
        mov	r11, [rdi+12]
        mov	r12, [rdi+16]
        mov	r13, [rdi+20]
        mov	r14, [rdi+24]
        mov	r15, [rdi+28]
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rax]
        vmovdqu	xmm1, OWORD PTR [rax+16]
        vmovdqu	xmm2, OWORD PTR [rax+32]
        vmovdqu	xmm3, OWORD PTR [rax+48]
        ; x_to_w: 0
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm1
        vmovdqu	OWORD PTR [rsp+32], xmm2
        vmovdqu	OWORD PTR [rsp+48], xmm3
        ; msg_sched: 0-3
        ; iter_0: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_0: 1 - 1
        mov	rax, [rsp+16]
        add	rdx, rcx
        mov	rbx, [rsp]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_0: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_0: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15, rcx
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_0: 6 - 7
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+8]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_1: 1 - 2
        mov	rax, [rsp+20]
        add	rdx, rcx
        mov	rbx, [rsp+4]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_1: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14, rcx
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_1: 6 - 6
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        xorl	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_1: 7 - 7
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_2: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+16]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	rax, [rsp+24]
        add	rdx, rcx
        mov	rbx, [rsp+8]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_2: 5 - 5
        add	r13, rcx
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_2: 6 - 6
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        xorl	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+24]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_3: 1 - 1
        mov	rax, [rsp+28]
        add	rdx, rcx
        mov	rbx, [rsp+12]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_3: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12, rcx
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_3: 6 - 6
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        xorl	r8d, ebx
        ; iter_3: 7 - 7
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+32]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_4: 1 - 1
        mov	rax, [rsp+32]
        add	rdx, rcx
        mov	rbx, [rsp+16]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_4: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_4: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11, rcx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_4: 6 - 7
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+40]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_5: 1 - 2
        mov	rax, [rsp+36]
        add	rdx, rcx
        mov	rbx, [rsp+20]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_5: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10, rcx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_5: 6 - 6
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_5: 7 - 7
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_6: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+48]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	rax, [rsp+40]
        add	rdx, rcx
        mov	rbx, [rsp+24]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_6: 5 - 5
        add	r9, rcx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_6: 6 - 6
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+56]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_7: 1 - 1
        mov	rax, [rsp+44]
        add	rdx, rcx
        mov	rbx, [rsp+28]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_7: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8, rcx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_7: 6 - 6
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        ; iter_7: 7 - 7
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+64]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_8: 1 - 1
        mov	rax, [rsp+48]
        add	rdx, rcx
        mov	rbx, [rsp+32]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_8: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_8: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15, rcx
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_8: 6 - 7
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+72]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_9: 1 - 2
        mov	rax, [rsp+52]
        add	rdx, rcx
        mov	rbx, [rsp+36]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_9: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14, rcx
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_9: 6 - 6
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        xorl	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_9: 7 - 7
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_10: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+80]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	rax, [rsp+56]
        add	rdx, rcx
        mov	rbx, [rsp+40]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_10: 5 - 5
        add	r13, rcx
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_10: 6 - 6
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        xorl	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+88]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_11: 1 - 1
        mov	rax, [rsp+60]
        add	rdx, rcx
        mov	rbx, [rsp+44]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_11: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12, rcx
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_11: 6 - 6
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        xorl	r8d, ebx
        ; iter_11: 7 - 7
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+96]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_12: 1 - 1
        mov	rax, [rsp+64]
        add	rdx, rcx
        mov	rbx, [rsp+48]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_12: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_12: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11, rcx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_12: 6 - 7
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+104]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_13: 1 - 2
        mov	rax, [rsp+68]
        add	rdx, rcx
        mov	rbx, [rsp+52]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_13: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10, rcx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_13: 6 - 6
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_13: 7 - 7
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_14: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+112]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	rax, [rsp+72]
        add	rdx, rcx
        mov	rbx, [rsp+56]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_14: 5 - 5
        add	r9, rcx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_14: 6 - 6
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+120]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_15: 1 - 1
        mov	rax, [rsp+76]
        add	rdx, rcx
        mov	rbx, [rsp+60]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_15: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8, rcx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_15: 6 - 6
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        ; iter_15: 7 - 7
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+128]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+80]
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_16: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+64]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_16: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_16: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_16: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+136]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+84]
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_17: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+68]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_17: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_17: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_17: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_18: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+144]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+88]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+72]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_18: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_18: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+152]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+92]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_19: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+76]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_19: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_19: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_19: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+160]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+96]
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_20: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+80]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_20: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_20: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_20: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+168]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+100]
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_21: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+84]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_21: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_21: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_21: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_22: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+176]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+104]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+88]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_22: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_22: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+184]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+108]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_23: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+92]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_23: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_23: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_23: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+192]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+112]
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_24: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+96]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_24: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_24: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_24: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+200]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+116]
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_25: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+100]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_25: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_25: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_25: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_26: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+208]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+120]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+104]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_26: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_26: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+216]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+124]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_27: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+108]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_27: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_27: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_27: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+224]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+128]
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_28: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+112]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_28: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_28: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_28: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+232]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+132]
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_29: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+116]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_29: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_29: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_29: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_30: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+240]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+136]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+120]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_30: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_30: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+248]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+140]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_31: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+124]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_31: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_31: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_31: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+256]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+144]
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_32: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+128]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_32: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_32: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_32: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+264]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+148]
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_33: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+132]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_33: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_33: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_33: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_34: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+272]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+152]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+136]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_34: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_34: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+280]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+156]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_35: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+140]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_35: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_35: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_35: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+288]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+160]
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_36: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+144]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_36: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_36: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_36: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+296]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+164]
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_37: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+148]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_37: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_37: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_37: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_38: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+304]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+168]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+152]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_38: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_38: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+312]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+172]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_39: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+156]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_39: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_39: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_39: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+320]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+176]
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_40: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+160]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_40: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_40: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_40: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+328]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+180]
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_41: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+164]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_41: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_41: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_41: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_42: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+336]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+184]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+168]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_42: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_42: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+344]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+188]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_43: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+172]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_43: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_43: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_43: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+352]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+192]
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_44: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+176]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_44: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_44: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_44: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+360]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+196]
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_45: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+180]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_45: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_45: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_45: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_46: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+368]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+200]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+184]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_46: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_46: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+376]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+204]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_47: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+188]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_47: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_47: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_47: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+384]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+208]
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_48: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+192]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_48: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_48: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_48: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+392]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+212]
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_49: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+196]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_49: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_49: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_49: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_50: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+400]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+216]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+200]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_50: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_50: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+408]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+220]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_51: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+204]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_51: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_51: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_51: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+416]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+224]
        add	rdx, rcx
        mov	rbx, [rsp+208]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        ; iter_53: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+424]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+228]
        add	rdx, rcx
        mov	rbx, [rsp+212]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_54: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+432]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+232]
        add	rdx, rcx
        mov	rbx, [rsp+216]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        ; iter_55: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+440]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+236]
        add	rdx, rcx
        mov	rbx, [rsp+220]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+448]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+240]
        add	rdx, rcx
        mov	rbx, [rsp+224]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        ; iter_57: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+456]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+244]
        add	rdx, rcx
        mov	rbx, [rsp+228]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_58: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+464]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+248]
        add	rdx, rcx
        mov	rbx, [rsp+232]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        ; iter_59: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+472]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+252]
        add	rdx, rcx
        mov	rbx, [rsp+236]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; iter_60: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+480]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+256]
        add	rdx, rcx
        mov	rbx, [rsp+240]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        ; iter_61: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+488]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+260]
        add	rdx, rcx
        mov	rbx, [rsp+244]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_62: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+496]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+264]
        add	rdx, rcx
        mov	rbx, [rsp+248]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        ; iter_63: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+504]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+268]
        add	rdx, rcx
        mov	rbx, [rsp+252]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        xorl	[rdi], r8d
        xorl	[rdi+4], r9d
        xorl	[rdi+8], r10d
        xorl	[rdi+12], r11d
        xorl	[rdi+16], r12d
        xorl	[rdi+20], r13d
        xorl	[rdi+24], r14d
        xorl	[rdi+28], r15d
        xor	rax, rax
        vzeroupper
        add	rsp, 272
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
sm3_compress_avx1_rorx ENDP
_text ENDS
_text SEGMENT READONLY PARA
sm3_compress_len_avx1_rorx PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rbp
        push	rsi
        mov	rdi, rcx
        mov	rbp, rdx
        mov	rsi, r8
        sub	rsp, 272
        vmovdqa	xmm11, ptr_L_SM3_AVX1_RORX_flip_mask
        mov	r8, [rdi]
        mov	r9, [rdi+4]
        mov	r10, [rdi+8]
        mov	r11, [rdi+12]
        mov	r12, [rdi+16]
        mov	r13, [rdi+20]
        mov	r14, [rdi+24]
        mov	r15, [rdi+28]
        ; Start of loop processing a block
L_SM3_AVX1_RORXlen_start:
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rbp]
        vmovdqu	xmm1, OWORD PTR [rbp+16]
        vpshufb	xmm0, xmm0, xmm11
        vpshufb	xmm1, xmm1, xmm11
        vmovdqu	xmm2, OWORD PTR [rbp+32]
        vmovdqu	xmm3, OWORD PTR [rbp+48]
        vpshufb	xmm2, xmm2, xmm11
        vpshufb	xmm3, xmm3, xmm11
        ; x_to_w: 0
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm1
        vmovdqu	OWORD PTR [rsp+32], xmm2
        vmovdqu	OWORD PTR [rsp+48], xmm3
        ; msg_sched: 0-3
        ; iter_0: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_0: 1 - 1
        mov	rax, [rsp+16]
        add	rdx, rcx
        mov	rbx, [rsp]
        roll	edx, 0x7
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_0: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_0: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15, rcx
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_0: 6 - 7
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+8]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_1: 1 - 2
        mov	rax, [rsp+20]
        add	rdx, rcx
        mov	rbx, [rsp+4]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_1: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14, rcx
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_1: 6 - 6
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        xorl	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_1: 7 - 7
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_2: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+16]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	rax, [rsp+24]
        add	rdx, rcx
        mov	rbx, [rsp+8]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_2: 5 - 5
        add	r13, rcx
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_2: 6 - 6
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        xorl	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+24]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_3: 1 - 1
        mov	rax, [rsp+28]
        add	rdx, rcx
        mov	rbx, [rsp+12]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_3: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12, rcx
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_3: 6 - 6
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        xorl	r8d, ebx
        ; iter_3: 7 - 7
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+32]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_4: 1 - 1
        mov	rax, [rsp+32]
        add	rdx, rcx
        mov	rbx, [rsp+16]
        roll	edx, 0x7
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_4: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_4: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11, rcx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_4: 6 - 7
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+40]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_5: 1 - 2
        mov	rax, [rsp+36]
        add	rdx, rcx
        mov	rbx, [rsp+20]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_5: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10, rcx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_5: 6 - 6
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_5: 7 - 7
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_6: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+48]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	rax, [rsp+40]
        add	rdx, rcx
        mov	rbx, [rsp+24]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_6: 5 - 5
        add	r9, rcx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_6: 6 - 6
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+56]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_7: 1 - 1
        mov	rax, [rsp+44]
        add	rdx, rcx
        mov	rbx, [rsp+28]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_7: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8, rcx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_7: 6 - 6
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        ; iter_7: 7 - 7
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+64]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_8: 1 - 1
        mov	rax, [rsp+48]
        add	rdx, rcx
        mov	rbx, [rsp+32]
        roll	edx, 0x7
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_8: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_8: 3 - 3
        add	rdx, r15
        add	rcx, r11
        mov	r15, r8
        mov	r11, r12
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xorl	r15d, r9d
        xorl	r11d, r13d
        xorl	r15d, r10d
        xorl	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15, rcx
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_8: 6 - 7
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+72]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_9: 1 - 2
        mov	rax, [rsp+52]
        add	rdx, rcx
        mov	rbx, [rsp+36]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_9: 3 - 3
        add	rdx, r14
        add	rcx, r10
        mov	r14, r15
        mov	r10, r11
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xorl	r14d, r8d
        xorl	r10d, r12d
        xorl	r14d, r9d
        xorl	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14, rcx
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_9: 6 - 6
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        xorl	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_9: 7 - 7
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_10: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+80]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	rax, [rsp+56]
        add	rdx, rcx
        mov	rbx, [rsp+40]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	rdx, r13
        add	rcx, r9
        mov	r13, r14
        mov	r9, r10
        xorl	r13d, r15d
        xorl	r9d, r11d
        xorl	r13d, r8d
        xorl	r9d, r12d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_10: 5 - 5
        add	r13, rcx
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_10: 6 - 6
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        xorl	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+88]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_11: 1 - 1
        mov	rax, [rsp+60]
        add	rdx, rcx
        mov	rbx, [rsp+44]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_11: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	rdx, r12
        add	rcx, r8
        mov	r12, r13
        mov	r8, r9
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xorl	r12d, r14d
        xorl	r8d, r10d
        xorl	r12d, r15d
        xorl	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12, rcx
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_11: 6 - 6
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        xorl	r8d, ebx
        ; iter_11: 7 - 7
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+96]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_12: 1 - 1
        mov	rax, [rsp+64]
        add	rdx, rcx
        mov	rbx, [rsp+48]
        roll	edx, 0x7
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_12: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_12: 3 - 3
        add	rdx, r11
        add	rcx, r15
        mov	r11, r12
        mov	r15, r8
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xorl	r11d, r13d
        xorl	r15d, r9d
        xorl	r11d, r14d
        xorl	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11, rcx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_12: 6 - 7
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+104]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_13: 1 - 2
        mov	rax, [rsp+68]
        add	rdx, rcx
        mov	rbx, [rsp+52]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_13: 3 - 3
        add	rdx, r10
        add	rcx, r14
        mov	r10, r11
        mov	r14, r15
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xorl	r10d, r12d
        xorl	r14d, r8d
        xorl	r10d, r13d
        xorl	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10, rcx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_13: 6 - 6
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_13: 7 - 7
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_14: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+112]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	rax, [rsp+72]
        add	rdx, rcx
        mov	rbx, [rsp+56]
        roll	edx, 0x7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	rdx, r9
        add	rcx, r13
        mov	r9, r10
        mov	r13, r14
        xorl	r9d, r11d
        xorl	r13d, r15d
        xorl	r9d, r12d
        xorl	r13d, r8d
        vpshufd	xmm4, xmm8, 0x0
        ; iter_14: 5 - 5
        add	r9, rcx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_14: 6 - 6
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+120]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_15: 1 - 1
        mov	rax, [rsp+76]
        add	rdx, rcx
        mov	rbx, [rsp+60]
        roll	edx, 0x7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_15: 2 - 2
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	rdx, r8
        add	rcx, r12
        mov	r8, r9
        mov	r12, r13
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xorl	r8d, r10d
        xorl	r12d, r14d
        xorl	r8d, r11d
        xorl	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8, rcx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_15: 6 - 6
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        ; iter_15: 7 - 7
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+128]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+80]
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_16: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+64]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_16: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_16: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_16: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+136]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+84]
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_17: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+68]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_17: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_17: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_17: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_18: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+144]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+88]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+72]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_18: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_18: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+152]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+92]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_19: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+76]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_19: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_19: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_19: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+160]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+96]
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_20: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+80]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_20: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_20: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_20: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+168]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+100]
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_21: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+84]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_21: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_21: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_21: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_22: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+176]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+104]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+88]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_22: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_22: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+184]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+108]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_23: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+92]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_23: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_23: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_23: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+192]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+112]
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_24: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+96]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_24: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_24: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_24: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+200]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+116]
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_25: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+100]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_25: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_25: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_25: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_26: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+208]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+120]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+104]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_26: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_26: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+216]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+124]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_27: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+108]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_27: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_27: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_27: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+224]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+128]
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_28: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+112]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_28: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_28: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_28: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+232]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+132]
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_29: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+116]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_29: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_29: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_29: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_30: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+240]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+136]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+120]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_30: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_30: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+248]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+140]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_31: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+124]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_31: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_31: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_31: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+256]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+144]
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_32: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+128]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_32: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_32: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_32: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+264]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+148]
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_33: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+132]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_33: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_33: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_33: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_34: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+272]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+152]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+136]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_34: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_34: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+280]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+156]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_35: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+140]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_35: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_35: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_35: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+288]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+160]
        vpalignr	xmm5, xmm2, xmm1, 0xc
        ; iter_36: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+144]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 0x8
        ; iter_36: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_36: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 0xc
        ; iter_36: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+296]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+164]
        vpshufd	xmm4, xmm0, 0xf9
        ; iter_37: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+148]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_37: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_37: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_37: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_38: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+304]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+168]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+152]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_38: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_38: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+312]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+172]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_39: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+156]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_39: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 0xc0
        ; iter_39: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_39: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+320]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+176]
        vpalignr	xmm5, xmm3, xmm2, 0xc
        ; iter_40: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+160]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 0x8
        ; iter_40: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_40: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 0xc
        ; iter_40: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+328]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+180]
        vpshufd	xmm4, xmm1, 0xf9
        ; iter_41: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+164]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_41: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_41: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_41: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_42: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+336]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+184]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+168]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_42: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_42: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+344]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+188]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_43: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+172]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_43: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 0xc0
        ; iter_43: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_43: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+352]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+192]
        vpalignr	xmm5, xmm0, xmm3, 0xc
        ; iter_44: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+176]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 0x8
        ; iter_44: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_44: 3 - 3
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 0xc
        ; iter_44: 6 - 7
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+360]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+196]
        vpshufd	xmm4, xmm2, 0xf9
        ; iter_45: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+180]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_45: 3 - 3
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_45: 6 - 6
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_45: 7 - 7
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_46: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+368]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+200]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+184]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        vpshufd	xmm4, xmm8, 0x0
        ; iter_46: 5 - 5
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_46: 6 - 6
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+376]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+204]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_47: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+188]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_47: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 0xc0
        ; iter_47: 6 - 6
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        ; iter_47: 7 - 7
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+384]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+208]
        vpalignr	xmm5, xmm1, xmm0, 0xc
        ; iter_48: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+192]
        roll	edx, 0x7
        xorl	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 0x8
        ; iter_48: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 0x19
        ; iter_48: 3 - 3
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 0xc
        ; iter_48: 6 - 7
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+392]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+212]
        vpshufd	xmm4, xmm3, 0xf9
        ; iter_49: 1 - 2
        add	rdx, rcx
        mov	rbx, [rsp+196]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_49: 3 - 3
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 0x11
        ; iter_49: 6 - 6
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 0x9
        ; iter_49: 7 - 7
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_50: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+400]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+216]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+200]
        roll	edx, 0x7
        xorl	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        vpshufd	xmm4, xmm8, 0x0
        ; iter_50: 5 - 5
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 0x11
        ; iter_50: 6 - 6
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+408]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+220]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 0x11
        ; iter_51: 1 - 1
        add	rdx, rcx
        mov	rbx, [rsp+204]
        roll	edx, 0x7
        xorl	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 0x9
        ; iter_51: 2 - 2
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 0xc0
        ; iter_51: 6 - 6
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        ; iter_51: 7 - 7
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+416]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+224]
        add	rdx, rcx
        mov	rbx, [rsp+208]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        ; iter_53: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+424]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+228]
        add	rdx, rcx
        mov	rbx, [rsp+212]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_54: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+432]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+232]
        add	rdx, rcx
        mov	rbx, [rsp+216]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        ; iter_55: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+440]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+236]
        add	rdx, rcx
        mov	rbx, [rsp+220]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+448]
        rorxl	ecx, r8d, 0x14
        add	rdx, r12
        mov	rax, [rsp+240]
        add	rdx, rcx
        mov	rbx, [rsp+224]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r15
        add	rcx, r11
        mov	r15, r9
        mov	rbx, r9
        xorl	r15d, r8d
        xorl	ebx, r10d
        andn	r11, r12, r14
        and	r15, rbx
        mov	rbx, r12
        xorl	r15d, r9d
        and	rbx, r13
        add	r15, rcx
        orl	r11d, ebx
        add	r11, rdx
        rorxl	ebx, r11d, 0xf
        rorxl	eax, r11d, 0x17
        roll	r9d, 0x9
        xorl	r11d, ebx
        roll	r13d, 0x13
        xorl	r11d, eax
        ; iter_57: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+456]
        rorxl	ecx, r15d, 0x14
        add	rdx, r11
        mov	rax, [rsp+244]
        add	rdx, rcx
        mov	rbx, [rsp+228]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r14
        add	rcx, r10
        mov	r14, r8
        mov	rbx, r8
        xorl	r14d, r15d
        xorl	ebx, r9d
        andn	r10, r11, r13
        and	r14, rbx
        mov	rbx, r11
        xorl	r14d, r8d
        and	rbx, r12
        add	r14, rcx
        orl	r10d, ebx
        add	r10, rdx
        rorxl	ebx, r10d, 0xf
        rorxl	eax, r10d, 0x17
        roll	r8d, 0x9
        xorl	r10d, ebx
        roll	r12d, 0x13
        xorl	r10d, eax
        ; iter_58: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+464]
        rorxl	ecx, r14d, 0x14
        add	rdx, r10
        mov	rax, [rsp+248]
        add	rdx, rcx
        mov	rbx, [rsp+232]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r13
        add	rcx, r9
        mov	r13, r15
        mov	rbx, r15
        xorl	r13d, r14d
        xorl	ebx, r8d
        andn	r9, r10, r12
        and	r13, rbx
        mov	rbx, r10
        xorl	r13d, r15d
        and	rbx, r11
        add	r13, rcx
        orl	r9d, ebx
        add	r9, rdx
        rorxl	ebx, r9d, 0xf
        rorxl	eax, r9d, 0x17
        roll	r15d, 0x9
        xorl	r9d, ebx
        roll	r11d, 0x13
        xorl	r9d, eax
        ; iter_59: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+472]
        rorxl	ecx, r13d, 0x14
        add	rdx, r9
        mov	rax, [rsp+252]
        add	rdx, rcx
        mov	rbx, [rsp+236]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r12
        add	rcx, r8
        mov	r12, r14
        mov	rbx, r14
        xorl	r12d, r13d
        xorl	ebx, r15d
        andn	r8, r9, r11
        and	r12, rbx
        mov	rbx, r9
        xorl	r12d, r14d
        and	rbx, r10
        add	r12, rcx
        orl	r8d, ebx
        add	r8, rdx
        rorxl	ebx, r8d, 0xf
        rorxl	eax, r8d, 0x17
        roll	r14d, 0x9
        xorl	r8d, ebx
        roll	r10d, 0x13
        xorl	r8d, eax
        ; iter_60: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+480]
        rorxl	ecx, r12d, 0x14
        add	rdx, r8
        mov	rax, [rsp+256]
        add	rdx, rcx
        mov	rbx, [rsp+240]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r11
        add	rcx, r15
        mov	r11, r13
        mov	rbx, r13
        xorl	r11d, r12d
        xorl	ebx, r14d
        andn	r15, r8, r10
        and	r11, rbx
        mov	rbx, r8
        xorl	r11d, r13d
        and	rbx, r9
        add	r11, rcx
        orl	r15d, ebx
        add	r15, rdx
        rorxl	ebx, r15d, 0xf
        rorxl	eax, r15d, 0x17
        roll	r13d, 0x9
        xorl	r15d, ebx
        roll	r9d, 0x13
        xorl	r15d, eax
        ; iter_61: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+488]
        rorxl	ecx, r11d, 0x14
        add	rdx, r15
        mov	rax, [rsp+260]
        add	rdx, rcx
        mov	rbx, [rsp+244]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r10
        add	rcx, r14
        mov	r10, r12
        mov	rbx, r12
        xorl	r10d, r11d
        xorl	ebx, r13d
        andn	r14, r15, r9
        and	r10, rbx
        mov	rbx, r15
        xorl	r10d, r12d
        and	rbx, r8
        add	r10, rcx
        orl	r14d, ebx
        add	r14, rdx
        rorxl	ebx, r14d, 0xf
        rorxl	eax, r14d, 0x17
        roll	r12d, 0x9
        xorl	r14d, ebx
        roll	r8d, 0x13
        xorl	r14d, eax
        ; iter_62: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+496]
        rorxl	ecx, r10d, 0x14
        add	rdx, r14
        mov	rax, [rsp+264]
        add	rdx, rcx
        mov	rbx, [rsp+248]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r9
        add	rcx, r13
        mov	r9, r11
        mov	rbx, r11
        xorl	r9d, r10d
        xorl	ebx, r12d
        andn	r13, r14, r8
        and	r9, rbx
        mov	rbx, r14
        xorl	r9d, r11d
        and	rbx, r15
        add	r9, rcx
        orl	r13d, ebx
        add	r13, rdx
        rorxl	ebx, r13d, 0xf
        rorxl	eax, r13d, 0x17
        roll	r11d, 0x9
        xorl	r13d, ebx
        roll	r15d, 0x13
        xorl	r13d, eax
        ; iter_63: 0 - 7
        mov	rdx, [ptr_L_SM3_AVX1_RORX_t+504]
        rorxl	ecx, r9d, 0x14
        add	rdx, r13
        mov	rax, [rsp+268]
        add	rdx, rcx
        mov	rbx, [rsp+252]
        roll	edx, 0x7
        xorl	ecx, edx
        xorl	eax, ebx
        add	rdx, rbx
        add	rcx, rax
        add	rdx, r8
        add	rcx, r12
        mov	r8, r10
        mov	rbx, r10
        xorl	r8d, r9d
        xorl	ebx, r11d
        andn	r12, r13, r15
        and	r8, rbx
        mov	rbx, r13
        xorl	r8d, r10d
        and	rbx, r14
        add	r8, rcx
        orl	r12d, ebx
        add	r12, rdx
        rorxl	ebx, r12d, 0xf
        rorxl	eax, r12d, 0x17
        roll	r10d, 0x9
        xorl	r12d, ebx
        roll	r14d, 0x13
        xorl	r12d, eax
        xorl	r8d, [rdi]
        xorl	r9d, [rdi+4]
        xorl	r10d, [rdi+8]
        xorl	r11d, [rdi+12]
        xorl	r12d, [rdi+16]
        xorl	r13d, [rdi+20]
        xorl	r14d, [rdi+24]
        xorl	r15d, [rdi+28]
        add	rbp, 64
        subl	esi, 0x40
        mov	[rdi], r8
        mov	[rdi+4], r9
        mov	[rdi+8], r10
        mov	[rdi+12], r11
        mov	[rdi+16], r12
        mov	[rdi+20], r13
        mov	[rdi+24], r14
        mov	[rdi+28], r15
        jnz	L_SM3_AVX1_RORXlen_start
        xor	rax, rax
        vzeroupper
        add	rsp, 272
        pop	rsi
        pop	rbp
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
sm3_compress_len_avx1_rorx ENDP
_text ENDS
ENDIF
ENDIF
END
