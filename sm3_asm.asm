; /* sm3_asm.asm */
; /*
;  * Copyright (C) 2006-2024 wolfSSL Inc.
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

IFDEF WOLFSSL_SM3
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
        vmovdqa	xmm11, OWORD PTR L_SM3_AVX1_flip_mask
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
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
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_0: 1 - 1
        mov	eax, DWORD PTR [rsp+16]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_0: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_0: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_0: 6 - 7
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+8]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_1: 1 - 2
        mov	eax, DWORD PTR [rsp+20]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+4]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_1: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_1: 6 - 6
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_1: 7 - 7
        xor	r10d, ebx
        ; iter_2: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+16]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	eax, DWORD PTR [rsp+24]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+8]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_2: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_2: 6 - 6
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+24]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_3: 1 - 1
        mov	eax, DWORD PTR [rsp+28]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+12]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_3: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_3: 6 - 6
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        ; iter_3: 7 - 7
        xor	r8d, ebx
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+32]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_4: 1 - 1
        mov	eax, DWORD PTR [rsp+32]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+16]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_4: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_4: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_4: 6 - 7
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+40]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm0, 249
        ; iter_5: 1 - 2
        mov	eax, DWORD PTR [rsp+36]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+20]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_5: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_5: 6 - 6
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_5: 7 - 7
        xor	r14d, ebx
        ; iter_6: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+48]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	eax, DWORD PTR [rsp+40]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+24]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_6: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_6: 6 - 6
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+56]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_7: 1 - 1
        mov	eax, DWORD PTR [rsp+44]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+28]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_7: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_7: 6 - 6
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        ; iter_7: 7 - 7
        xor	r12d, ebx
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+64]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_8: 1 - 1
        mov	eax, DWORD PTR [rsp+48]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+32]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_8: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_8: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_8: 6 - 7
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+72]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm1, 249
        ; iter_9: 1 - 2
        mov	eax, DWORD PTR [rsp+52]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+36]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_9: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_9: 6 - 6
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_9: 7 - 7
        xor	r10d, ebx
        ; iter_10: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+80]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	eax, DWORD PTR [rsp+56]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+40]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_10: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_10: 6 - 6
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+88]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_11: 1 - 1
        mov	eax, DWORD PTR [rsp+60]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+44]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_11: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_11: 6 - 6
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        ; iter_11: 7 - 7
        xor	r8d, ebx
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+96]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_12: 1 - 1
        mov	eax, DWORD PTR [rsp+64]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+48]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_12: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_12: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_12: 6 - 7
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+104]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm2, 249
        ; iter_13: 1 - 2
        mov	eax, DWORD PTR [rsp+68]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+52]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_13: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_13: 6 - 6
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_13: 7 - 7
        xor	r14d, ebx
        ; iter_14: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+112]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	eax, DWORD PTR [rsp+72]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+56]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_14: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_14: 6 - 6
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+120]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_15: 1 - 1
        mov	eax, DWORD PTR [rsp+76]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+60]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_15: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_15: 6 - 6
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        ; iter_15: 7 - 7
        xor	r12d, ebx
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+128]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_16: 1 - 1
        mov	eax, DWORD PTR [rsp+80]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+64]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_16: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_16: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_16: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+136]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_17: 1 - 2
        mov	eax, DWORD PTR [rsp+84]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+68]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_17: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_17: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_17: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_18: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+144]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        mov	eax, DWORD PTR [rsp+88]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+72]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_18: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_18: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+152]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_19: 1 - 1
        mov	eax, DWORD PTR [rsp+92]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+76]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_19: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_19: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_19: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+160]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_20: 1 - 1
        mov	eax, DWORD PTR [rsp+96]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+80]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_20: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_20: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_20: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+168]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm0, 249
        ; iter_21: 1 - 2
        mov	eax, DWORD PTR [rsp+100]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+84]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_21: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_21: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_21: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_22: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+176]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        mov	eax, DWORD PTR [rsp+104]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+88]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_22: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_22: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+184]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_23: 1 - 1
        mov	eax, DWORD PTR [rsp+108]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+92]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_23: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_23: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_23: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+192]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_24: 1 - 1
        mov	eax, DWORD PTR [rsp+112]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+96]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_24: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_24: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_24: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+200]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm1, 249
        ; iter_25: 1 - 2
        mov	eax, DWORD PTR [rsp+116]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+100]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_25: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_25: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_25: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_26: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+208]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        mov	eax, DWORD PTR [rsp+120]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+104]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_26: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_26: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+216]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_27: 1 - 1
        mov	eax, DWORD PTR [rsp+124]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+108]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_27: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_27: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_27: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+224]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_28: 1 - 1
        mov	eax, DWORD PTR [rsp+128]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+112]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_28: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_28: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_28: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+232]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm2, 249
        ; iter_29: 1 - 2
        mov	eax, DWORD PTR [rsp+132]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+116]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_29: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_29: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_29: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_30: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+240]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        mov	eax, DWORD PTR [rsp+136]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+120]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_30: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_30: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+248]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_31: 1 - 1
        mov	eax, DWORD PTR [rsp+140]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+124]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_31: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_31: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_31: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+256]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_32: 1 - 1
        mov	eax, DWORD PTR [rsp+144]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+128]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_32: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_32: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_32: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+264]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_33: 1 - 2
        mov	eax, DWORD PTR [rsp+148]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+132]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_33: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_33: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_33: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_34: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+272]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        mov	eax, DWORD PTR [rsp+152]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+136]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_34: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_34: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+280]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_35: 1 - 1
        mov	eax, DWORD PTR [rsp+156]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+140]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_35: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_35: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_35: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+288]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_36: 1 - 1
        mov	eax, DWORD PTR [rsp+160]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+144]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_36: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_36: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_36: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+296]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm0, 249
        ; iter_37: 1 - 2
        mov	eax, DWORD PTR [rsp+164]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+148]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_37: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_37: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_37: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_38: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+304]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        mov	eax, DWORD PTR [rsp+168]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+152]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_38: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_38: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+312]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_39: 1 - 1
        mov	eax, DWORD PTR [rsp+172]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+156]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_39: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_39: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_39: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+320]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_40: 1 - 1
        mov	eax, DWORD PTR [rsp+176]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+160]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_40: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_40: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_40: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+328]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm1, 249
        ; iter_41: 1 - 2
        mov	eax, DWORD PTR [rsp+180]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+164]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_41: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_41: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_41: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_42: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+336]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        mov	eax, DWORD PTR [rsp+184]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+168]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_42: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_42: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+344]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_43: 1 - 1
        mov	eax, DWORD PTR [rsp+188]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+172]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_43: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_43: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_43: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+352]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_44: 1 - 1
        mov	eax, DWORD PTR [rsp+192]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+176]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_44: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_44: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_44: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+360]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm2, 249
        ; iter_45: 1 - 2
        mov	eax, DWORD PTR [rsp+196]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+180]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_45: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_45: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_45: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_46: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+368]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        mov	eax, DWORD PTR [rsp+200]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+184]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_46: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_46: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+376]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_47: 1 - 1
        mov	eax, DWORD PTR [rsp+204]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+188]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_47: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_47: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_47: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+384]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_48: 1 - 1
        mov	eax, DWORD PTR [rsp+208]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+192]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_48: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_48: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_48: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+392]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_49: 1 - 2
        mov	eax, DWORD PTR [rsp+212]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+196]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_49: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_49: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_49: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_50: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+400]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        mov	eax, DWORD PTR [rsp+216]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+200]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_50: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_50: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+408]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_51: 1 - 1
        mov	eax, DWORD PTR [rsp+220]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+204]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_51: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_51: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_51: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+416]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+224]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+208]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        ; iter_53: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+424]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+228]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+212]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_54: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+432]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+232]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+216]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        ; iter_55: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+440]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+236]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+220]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+448]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+240]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+224]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        ; iter_57: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+456]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+244]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+228]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_58: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+464]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+248]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+232]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        ; iter_59: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+472]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+252]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+236]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; iter_60: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+480]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+256]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+240]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        ; iter_61: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+488]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+260]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+244]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_62: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+496]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+264]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+248]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        ; iter_63: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+504]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+268]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+252]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        xor	DWORD PTR [rdi], r8d
        xor	DWORD PTR [rdi+4], r9d
        xor	DWORD PTR [rdi+8], r10d
        xor	DWORD PTR [rdi+12], r11d
        xor	DWORD PTR [rdi+16], r12d
        xor	DWORD PTR [rdi+20], r13d
        xor	DWORD PTR [rdi+24], r14d
        xor	DWORD PTR [rdi+28], r15d
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
        vmovdqa	xmm11, OWORD PTR L_SM3_AVX1_flip_mask
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
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
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_0: 1 - 1
        mov	eax, DWORD PTR [rsp+16]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_0: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_0: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_0: 6 - 7
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+8]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_1: 1 - 2
        mov	eax, DWORD PTR [rsp+20]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+4]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_1: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_1: 6 - 6
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_1: 7 - 7
        xor	r10d, ebx
        ; iter_2: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+16]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	eax, DWORD PTR [rsp+24]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+8]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_2: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_2: 6 - 6
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+24]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_3: 1 - 1
        mov	eax, DWORD PTR [rsp+28]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+12]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_3: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_3: 6 - 6
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        ; iter_3: 7 - 7
        xor	r8d, ebx
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+32]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_4: 1 - 1
        mov	eax, DWORD PTR [rsp+32]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+16]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_4: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_4: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_4: 6 - 7
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+40]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm0, 249
        ; iter_5: 1 - 2
        mov	eax, DWORD PTR [rsp+36]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+20]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_5: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_5: 6 - 6
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_5: 7 - 7
        xor	r14d, ebx
        ; iter_6: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+48]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	eax, DWORD PTR [rsp+40]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+24]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_6: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_6: 6 - 6
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+56]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_7: 1 - 1
        mov	eax, DWORD PTR [rsp+44]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+28]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_7: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_7: 6 - 6
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        ; iter_7: 7 - 7
        xor	r12d, ebx
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+64]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_8: 1 - 1
        mov	eax, DWORD PTR [rsp+48]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+32]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_8: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_8: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_8: 6 - 7
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+72]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm1, 249
        ; iter_9: 1 - 2
        mov	eax, DWORD PTR [rsp+52]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+36]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_9: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_9: 6 - 6
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_9: 7 - 7
        xor	r10d, ebx
        ; iter_10: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+80]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	eax, DWORD PTR [rsp+56]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+40]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_10: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_10: 6 - 6
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+88]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_11: 1 - 1
        mov	eax, DWORD PTR [rsp+60]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+44]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_11: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_11: 6 - 6
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        ; iter_11: 7 - 7
        xor	r8d, ebx
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+96]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_12: 1 - 1
        mov	eax, DWORD PTR [rsp+64]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+48]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_12: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_12: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_12: 6 - 7
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+104]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm2, 249
        ; iter_13: 1 - 2
        mov	eax, DWORD PTR [rsp+68]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+52]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_13: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_13: 6 - 6
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_13: 7 - 7
        xor	r14d, ebx
        ; iter_14: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+112]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	eax, DWORD PTR [rsp+72]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+56]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_14: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_14: 6 - 6
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+120]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_15: 1 - 1
        mov	eax, DWORD PTR [rsp+76]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+60]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_15: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_15: 6 - 6
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        ; iter_15: 7 - 7
        xor	r12d, ebx
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+128]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_16: 1 - 1
        mov	eax, DWORD PTR [rsp+80]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+64]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_16: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_16: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_16: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+136]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_17: 1 - 2
        mov	eax, DWORD PTR [rsp+84]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+68]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_17: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_17: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_17: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_18: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+144]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        mov	eax, DWORD PTR [rsp+88]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+72]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_18: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_18: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+152]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_19: 1 - 1
        mov	eax, DWORD PTR [rsp+92]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+76]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_19: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_19: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_19: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+160]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_20: 1 - 1
        mov	eax, DWORD PTR [rsp+96]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+80]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_20: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_20: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_20: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+168]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm0, 249
        ; iter_21: 1 - 2
        mov	eax, DWORD PTR [rsp+100]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+84]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_21: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_21: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_21: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_22: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+176]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        mov	eax, DWORD PTR [rsp+104]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+88]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_22: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_22: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+184]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_23: 1 - 1
        mov	eax, DWORD PTR [rsp+108]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+92]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_23: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_23: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_23: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+192]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_24: 1 - 1
        mov	eax, DWORD PTR [rsp+112]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+96]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_24: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_24: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_24: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+200]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm1, 249
        ; iter_25: 1 - 2
        mov	eax, DWORD PTR [rsp+116]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+100]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_25: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_25: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_25: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_26: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+208]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        mov	eax, DWORD PTR [rsp+120]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+104]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_26: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_26: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+216]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_27: 1 - 1
        mov	eax, DWORD PTR [rsp+124]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+108]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_27: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_27: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_27: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+224]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_28: 1 - 1
        mov	eax, DWORD PTR [rsp+128]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+112]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_28: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_28: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_28: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+232]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm2, 249
        ; iter_29: 1 - 2
        mov	eax, DWORD PTR [rsp+132]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+116]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_29: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_29: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_29: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_30: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+240]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        mov	eax, DWORD PTR [rsp+136]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+120]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_30: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_30: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+248]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_31: 1 - 1
        mov	eax, DWORD PTR [rsp+140]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+124]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_31: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_31: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_31: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+256]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_32: 1 - 1
        mov	eax, DWORD PTR [rsp+144]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+128]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_32: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_32: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_32: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+264]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_33: 1 - 2
        mov	eax, DWORD PTR [rsp+148]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+132]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_33: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_33: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_33: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_34: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+272]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        mov	eax, DWORD PTR [rsp+152]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+136]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_34: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_34: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+280]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_35: 1 - 1
        mov	eax, DWORD PTR [rsp+156]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+140]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_35: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_35: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_35: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+288]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_36: 1 - 1
        mov	eax, DWORD PTR [rsp+160]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+144]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_36: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_36: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_36: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+296]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm0, 249
        ; iter_37: 1 - 2
        mov	eax, DWORD PTR [rsp+164]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+148]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_37: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_37: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_37: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_38: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+304]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        mov	eax, DWORD PTR [rsp+168]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+152]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_38: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_38: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+312]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_39: 1 - 1
        mov	eax, DWORD PTR [rsp+172]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+156]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_39: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_39: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_39: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+320]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_40: 1 - 1
        mov	eax, DWORD PTR [rsp+176]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+160]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_40: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_40: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_40: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+328]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm1, 249
        ; iter_41: 1 - 2
        mov	eax, DWORD PTR [rsp+180]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+164]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_41: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_41: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_41: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_42: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+336]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        mov	eax, DWORD PTR [rsp+184]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+168]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_42: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_42: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+344]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_43: 1 - 1
        mov	eax, DWORD PTR [rsp+188]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+172]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_43: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_43: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_43: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+352]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_44: 1 - 1
        mov	eax, DWORD PTR [rsp+192]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+176]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_44: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_44: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_44: 6 - 7
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+360]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        vpshufd	xmm4, xmm2, 249
        ; iter_45: 1 - 2
        mov	eax, DWORD PTR [rsp+196]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+180]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_45: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_45: 6 - 6
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_45: 7 - 7
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_46: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+368]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        mov	eax, DWORD PTR [rsp+200]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+184]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_46: 5 - 5
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_46: 6 - 6
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+376]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_47: 1 - 1
        mov	eax, DWORD PTR [rsp+204]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+188]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_47: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_47: 6 - 6
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        ; iter_47: 7 - 7
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+384]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_48: 1 - 1
        mov	eax, DWORD PTR [rsp+208]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+192]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_48: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_48: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_48: 6 - 7
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+392]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        vpshufd	xmm4, xmm3, 249
        ; iter_49: 1 - 2
        mov	eax, DWORD PTR [rsp+212]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+196]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_49: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_49: 6 - 6
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_49: 7 - 7
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_50: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+400]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        mov	eax, DWORD PTR [rsp+216]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+200]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_50: 5 - 5
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_50: 6 - 6
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+408]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_51: 1 - 1
        mov	eax, DWORD PTR [rsp+220]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+204]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_51: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_51: 6 - 6
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        ; iter_51: 7 - 7
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+416]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+224]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+208]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        ; iter_53: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+424]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+228]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+212]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_54: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+432]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+232]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+216]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        ; iter_55: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+440]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+236]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+220]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+448]
        mov	ecx, r8d
        add	edx, r12d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+240]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+224]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        add	ecx, r11d
        mov	r11d, r13d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        xor	r11d, r14d
        and	r15d, ebx
        and	r11d, r12d
        xor	r15d, r9d
        xor	r11d, r14d
        add	r15d, ecx
        add	r11d, edx
        mov	ebx, r11d
        rol	r11d, 8
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        rol	r11d, 9
        xor	r11d, ebx
        ; iter_57: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+456]
        mov	ecx, r15d
        add	edx, r11d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+244]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+228]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        add	ecx, r10d
        mov	r10d, r12d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        xor	r10d, r13d
        and	r14d, ebx
        and	r10d, r11d
        xor	r14d, r8d
        xor	r10d, r13d
        add	r14d, ecx
        add	r10d, edx
        mov	ebx, r10d
        rol	r10d, 8
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        rol	r10d, 9
        xor	r10d, ebx
        ; iter_58: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+464]
        mov	ecx, r14d
        add	edx, r10d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+248]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+232]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        add	ecx, r9d
        mov	r9d, r11d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        xor	r9d, r12d
        and	r13d, ebx
        and	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r12d
        add	r13d, ecx
        add	r9d, edx
        mov	ebx, r9d
        rol	r9d, 8
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        rol	r9d, 9
        xor	r9d, ebx
        ; iter_59: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+472]
        mov	ecx, r13d
        add	edx, r9d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+252]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+236]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        add	ecx, r8d
        mov	r8d, r10d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        xor	r8d, r11d
        and	r12d, ebx
        and	r8d, r9d
        xor	r12d, r14d
        xor	r8d, r11d
        add	r12d, ecx
        add	r8d, edx
        mov	ebx, r8d
        rol	r8d, 8
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        rol	r8d, 9
        xor	r8d, ebx
        ; iter_60: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+480]
        mov	ecx, r12d
        add	edx, r8d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+256]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+240]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r15d, r9d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        xor	r15d, r10d
        and	r11d, ebx
        and	r15d, r8d
        xor	r11d, r13d
        xor	r15d, r10d
        add	r11d, ecx
        add	r15d, edx
        mov	ebx, r15d
        rol	r15d, 8
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        rol	r15d, 9
        xor	r15d, ebx
        ; iter_61: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+488]
        mov	ecx, r11d
        add	edx, r15d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+260]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+244]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r14d, r8d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        xor	r14d, r9d
        and	r10d, ebx
        and	r14d, r15d
        xor	r10d, r12d
        xor	r14d, r9d
        add	r10d, ecx
        add	r14d, edx
        mov	ebx, r14d
        rol	r14d, 8
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        rol	r14d, 9
        xor	r14d, ebx
        ; iter_62: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+496]
        mov	ecx, r10d
        add	edx, r14d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+264]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+248]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r13d, r15d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        xor	r13d, r8d
        and	r9d, ebx
        and	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r8d
        add	r9d, ecx
        add	r13d, edx
        mov	ebx, r13d
        rol	r13d, 8
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        rol	r13d, 9
        xor	r13d, ebx
        ; iter_63: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_t+504]
        mov	ecx, r9d
        add	edx, r13d
        rol	ecx, 12
        mov	eax, DWORD PTR [rsp+268]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+252]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r12d, r14d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        xor	r12d, r15d
        and	r8d, ebx
        and	r12d, r13d
        xor	r8d, r10d
        xor	r12d, r15d
        add	r8d, ecx
        add	r12d, edx
        mov	ebx, r12d
        rol	r12d, 8
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        rol	r12d, 9
        xor	r12d, ebx
        xor	r8d, DWORD PTR [rdi]
        xor	r9d, DWORD PTR [rdi+4]
        xor	r10d, DWORD PTR [rdi+8]
        xor	r11d, DWORD PTR [rdi+12]
        xor	r12d, DWORD PTR [rdi+16]
        xor	r13d, DWORD PTR [rdi+20]
        xor	r14d, DWORD PTR [rdi+24]
        xor	r15d, DWORD PTR [rdi+28]
        add	rbp, 64
        sub	esi, 64
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
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
        vmovdqa	xmm11, OWORD PTR L_SM3_AVX1_RORX_flip_mask
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
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
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t]
        rorx	ecx, r8d, 20
        add	edx, r12d
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_0: 1 - 1
        mov	eax, DWORD PTR [rsp+16]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_0: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_0: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        rorx	ebx, r11d, 15
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_0: 6 - 7
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+8]
        rorx	ecx, r15d, 20
        add	edx, r11d
        vpshufd	xmm4, xmm3, 249
        ; iter_1: 1 - 2
        mov	eax, DWORD PTR [rsp+20]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+4]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_1: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        rorx	ebx, r10d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_1: 6 - 6
        rorx	eax, r10d, 23
        rol	r8d, 9
        xor	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_1: 7 - 7
        rol	r12d, 19
        xor	r10d, eax
        ; iter_2: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+16]
        rorx	ecx, r14d, 20
        add	edx, r10d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	eax, DWORD PTR [rsp+24]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+8]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_2: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        rorx	ebx, r9d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_2: 6 - 6
        rorx	eax, r9d, 23
        rol	r15d, 9
        xor	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+24]
        rorx	ecx, r13d, 20
        add	edx, r9d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_3: 1 - 1
        mov	eax, DWORD PTR [rsp+28]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+12]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_3: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        rorx	ebx, r8d, 15
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_3: 6 - 6
        rorx	eax, r8d, 23
        rol	r14d, 9
        xor	r8d, ebx
        ; iter_3: 7 - 7
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+32]
        rorx	ecx, r12d, 20
        add	edx, r8d
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_4: 1 - 1
        mov	eax, DWORD PTR [rsp+32]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+16]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_4: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_4: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        rorx	ebx, r15d, 15
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_4: 6 - 7
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+40]
        rorx	ecx, r11d, 20
        add	edx, r15d
        vpshufd	xmm4, xmm0, 249
        ; iter_5: 1 - 2
        mov	eax, DWORD PTR [rsp+36]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+20]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_5: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        rorx	ebx, r14d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_5: 6 - 6
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_5: 7 - 7
        rol	r8d, 19
        xor	r14d, eax
        ; iter_6: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+48]
        rorx	ecx, r10d, 20
        add	edx, r14d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	eax, DWORD PTR [rsp+40]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+24]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_6: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        rorx	ebx, r13d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_6: 6 - 6
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+56]
        rorx	ecx, r9d, 20
        add	edx, r13d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_7: 1 - 1
        mov	eax, DWORD PTR [rsp+44]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+28]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_7: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        rorx	ebx, r12d, 15
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_7: 6 - 6
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        ; iter_7: 7 - 7
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+64]
        rorx	ecx, r8d, 20
        add	edx, r12d
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_8: 1 - 1
        mov	eax, DWORD PTR [rsp+48]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+32]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_8: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_8: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        rorx	ebx, r11d, 15
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_8: 6 - 7
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+72]
        rorx	ecx, r15d, 20
        add	edx, r11d
        vpshufd	xmm4, xmm1, 249
        ; iter_9: 1 - 2
        mov	eax, DWORD PTR [rsp+52]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+36]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_9: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        rorx	ebx, r10d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_9: 6 - 6
        rorx	eax, r10d, 23
        rol	r8d, 9
        xor	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_9: 7 - 7
        rol	r12d, 19
        xor	r10d, eax
        ; iter_10: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+80]
        rorx	ecx, r14d, 20
        add	edx, r10d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	eax, DWORD PTR [rsp+56]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+40]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_10: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        rorx	ebx, r9d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_10: 6 - 6
        rorx	eax, r9d, 23
        rol	r15d, 9
        xor	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+88]
        rorx	ecx, r13d, 20
        add	edx, r9d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_11: 1 - 1
        mov	eax, DWORD PTR [rsp+60]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+44]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_11: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        rorx	ebx, r8d, 15
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_11: 6 - 6
        rorx	eax, r8d, 23
        rol	r14d, 9
        xor	r8d, ebx
        ; iter_11: 7 - 7
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+96]
        rorx	ecx, r12d, 20
        add	edx, r8d
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_12: 1 - 1
        mov	eax, DWORD PTR [rsp+64]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+48]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_12: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_12: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        rorx	ebx, r15d, 15
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_12: 6 - 7
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+104]
        rorx	ecx, r11d, 20
        add	edx, r15d
        vpshufd	xmm4, xmm2, 249
        ; iter_13: 1 - 2
        mov	eax, DWORD PTR [rsp+68]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+52]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_13: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        rorx	ebx, r14d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_13: 6 - 6
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_13: 7 - 7
        rol	r8d, 19
        xor	r14d, eax
        ; iter_14: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+112]
        rorx	ecx, r10d, 20
        add	edx, r14d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	eax, DWORD PTR [rsp+72]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+56]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_14: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        rorx	ebx, r13d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_14: 6 - 6
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+120]
        rorx	ecx, r9d, 20
        add	edx, r13d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_15: 1 - 1
        mov	eax, DWORD PTR [rsp+76]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+60]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_15: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        rorx	ebx, r12d, 15
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_15: 6 - 6
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        ; iter_15: 7 - 7
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+128]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+80]
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_16: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+64]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_16: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_16: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_16: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+136]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+84]
        vpshufd	xmm4, xmm3, 249
        ; iter_17: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+68]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_17: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_17: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_17: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_18: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+144]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+88]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+72]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_18: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_18: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+152]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+92]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_19: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+76]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_19: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_19: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_19: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+160]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+96]
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_20: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+80]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_20: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_20: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_20: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+168]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+100]
        vpshufd	xmm4, xmm0, 249
        ; iter_21: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+84]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_21: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_21: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_21: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_22: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+176]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+104]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+88]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_22: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_22: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+184]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+108]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_23: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+92]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_23: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_23: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_23: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+192]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+112]
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_24: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+96]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_24: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_24: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_24: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+200]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+116]
        vpshufd	xmm4, xmm1, 249
        ; iter_25: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+100]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_25: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_25: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_25: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_26: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+208]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+120]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+104]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_26: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_26: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+216]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+124]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_27: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+108]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_27: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_27: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_27: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+224]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+128]
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_28: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+112]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_28: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_28: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_28: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+232]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+132]
        vpshufd	xmm4, xmm2, 249
        ; iter_29: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+116]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_29: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_29: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_29: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_30: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+240]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+136]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+120]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_30: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_30: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+248]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+140]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_31: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+124]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_31: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_31: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_31: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+256]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+144]
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_32: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+128]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_32: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_32: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_32: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+264]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+148]
        vpshufd	xmm4, xmm3, 249
        ; iter_33: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+132]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_33: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_33: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_33: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_34: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+272]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+152]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+136]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_34: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_34: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+280]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+156]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_35: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+140]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_35: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_35: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_35: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+288]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+160]
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_36: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+144]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_36: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_36: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_36: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+296]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+164]
        vpshufd	xmm4, xmm0, 249
        ; iter_37: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+148]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_37: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_37: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_37: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_38: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+304]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+168]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+152]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_38: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_38: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+312]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+172]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_39: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+156]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_39: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_39: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_39: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+320]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+176]
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_40: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+160]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_40: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_40: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_40: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+328]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+180]
        vpshufd	xmm4, xmm1, 249
        ; iter_41: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+164]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_41: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_41: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_41: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_42: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+336]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+184]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+168]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_42: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_42: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+344]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+188]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_43: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+172]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_43: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_43: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_43: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+352]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+192]
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_44: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+176]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_44: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_44: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_44: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+360]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+196]
        vpshufd	xmm4, xmm2, 249
        ; iter_45: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+180]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_45: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_45: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_45: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_46: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+368]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+200]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+184]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_46: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_46: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+376]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+204]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_47: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+188]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_47: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_47: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_47: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+384]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+208]
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_48: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+192]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_48: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_48: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_48: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+392]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+212]
        vpshufd	xmm4, xmm3, 249
        ; iter_49: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+196]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_49: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_49: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_49: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_50: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+400]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+216]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+200]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_50: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_50: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+408]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+220]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_51: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+204]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_51: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_51: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_51: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+416]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+224]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+208]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        ; iter_53: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+424]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+228]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+212]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_54: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+432]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+232]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+216]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        ; iter_55: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+440]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+236]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+220]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+448]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+240]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+224]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        ; iter_57: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+456]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+244]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+228]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_58: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+464]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+248]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+232]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        ; iter_59: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+472]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+252]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+236]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; iter_60: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+480]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+256]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+240]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        ; iter_61: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+488]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+260]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+244]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_62: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+496]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+264]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+248]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        ; iter_63: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+504]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+268]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+252]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        xor	DWORD PTR [rdi], r8d
        xor	DWORD PTR [rdi+4], r9d
        xor	DWORD PTR [rdi+8], r10d
        xor	DWORD PTR [rdi+12], r11d
        xor	DWORD PTR [rdi+16], r12d
        xor	DWORD PTR [rdi+20], r13d
        xor	DWORD PTR [rdi+24], r14d
        xor	DWORD PTR [rdi+28], r15d
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
        vmovdqa	xmm11, OWORD PTR L_SM3_AVX1_RORX_flip_mask
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
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
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t]
        rorx	ecx, r8d, 20
        add	edx, r12d
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_0: 1 - 1
        mov	eax, DWORD PTR [rsp+16]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp]
        rol	edx, 7
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_0: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_0: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_0: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_0: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        rorx	ebx, r11d, 15
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_0: 6 - 7
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_1: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+8]
        rorx	ecx, r15d, 20
        add	edx, r11d
        vpshufd	xmm4, xmm3, 249
        ; iter_1: 1 - 2
        mov	eax, DWORD PTR [rsp+20]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+4]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_1: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_1: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_1: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        rorx	ebx, r10d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_1: 6 - 6
        rorx	eax, r10d, 23
        rol	r8d, 9
        xor	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_1: 7 - 7
        rol	r12d, 19
        xor	r10d, eax
        ; iter_2: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+16]
        rorx	ecx, r14d, 20
        add	edx, r10d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_2: 1 - 1
        mov	eax, DWORD PTR [rsp+24]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+8]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_2: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_2: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_2: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        rorx	ebx, r9d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_2: 6 - 6
        rorx	eax, r9d, 23
        rol	r15d, 9
        xor	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_2: 7 - 7
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_3: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+24]
        rorx	ecx, r13d, 20
        add	edx, r9d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_3: 1 - 1
        mov	eax, DWORD PTR [rsp+28]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+12]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_3: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_3: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_3: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_3: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        rorx	ebx, r8d, 15
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_3: 6 - 6
        rorx	eax, r8d, 23
        rol	r14d, 9
        xor	r8d, ebx
        ; iter_3: 7 - 7
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; iter_4: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+32]
        rorx	ecx, r12d, 20
        add	edx, r8d
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_4: 1 - 1
        mov	eax, DWORD PTR [rsp+32]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+16]
        rol	edx, 7
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_4: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_4: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_4: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_4: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        rorx	ebx, r15d, 15
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_4: 6 - 7
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_5: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+40]
        rorx	ecx, r11d, 20
        add	edx, r15d
        vpshufd	xmm4, xmm0, 249
        ; iter_5: 1 - 2
        mov	eax, DWORD PTR [rsp+36]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+20]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_5: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_5: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_5: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        rorx	ebx, r14d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_5: 6 - 6
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_5: 7 - 7
        rol	r8d, 19
        xor	r14d, eax
        ; iter_6: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+48]
        rorx	ecx, r10d, 20
        add	edx, r14d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_6: 1 - 1
        mov	eax, DWORD PTR [rsp+40]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+24]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_6: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_6: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_6: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        rorx	ebx, r13d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_6: 6 - 6
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_6: 7 - 7
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_7: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+56]
        rorx	ecx, r9d, 20
        add	edx, r13d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_7: 1 - 1
        mov	eax, DWORD PTR [rsp+44]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+28]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_7: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_7: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_7: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_7: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        rorx	ebx, r12d, 15
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_7: 6 - 6
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        ; iter_7: 7 - 7
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 4-7
        ; x2_to_w: 16
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm1
        ; msg_sched: 8-11
        ; iter_8: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+64]
        rorx	ecx, r8d, 20
        add	edx, r12d
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_8: 1 - 1
        mov	eax, DWORD PTR [rsp+48]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+32]
        rol	edx, 7
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_8: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_8: 3 - 3
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r8d
        mov	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_8: 4 - 4
        xor	r15d, r9d
        xor	r11d, r13d
        xor	r15d, r10d
        xor	r11d, r14d
        vpxor	xmm9, xmm4, xmm9
        ; iter_8: 5 - 5
        add	r15d, ecx
        add	r11d, edx
        rorx	ebx, r11d, 15
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_8: 6 - 7
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_9: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+72]
        rorx	ecx, r15d, 20
        add	edx, r11d
        vpshufd	xmm4, xmm1, 249
        ; iter_9: 1 - 2
        mov	eax, DWORD PTR [rsp+52]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+36]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_9: 3 - 3
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r15d
        mov	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_9: 4 - 4
        xor	r14d, r8d
        xor	r10d, r12d
        xor	r14d, r9d
        xor	r10d, r13d
        vpxor	xmm4, xmm10, xmm4
        ; iter_9: 5 - 5
        add	r14d, ecx
        add	r10d, edx
        rorx	ebx, r10d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_9: 6 - 6
        rorx	eax, r10d, 23
        rol	r8d, 9
        xor	r10d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_9: 7 - 7
        rol	r12d, 19
        xor	r10d, eax
        ; iter_10: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+80]
        rorx	ecx, r14d, 20
        add	edx, r10d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_10: 1 - 1
        mov	eax, DWORD PTR [rsp+56]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+40]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_10: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_10: 3 - 4
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r14d
        mov	r9d, r10d
        xor	r13d, r15d
        xor	r9d, r11d
        xor	r13d, r8d
        xor	r9d, r12d
        vpshufd	xmm4, xmm8, 0
        ; iter_10: 5 - 5
        add	r13d, ecx
        add	r9d, edx
        rorx	ebx, r9d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_10: 6 - 6
        rorx	eax, r9d, 23
        rol	r15d, 9
        xor	r9d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_10: 7 - 7
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_11: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+88]
        rorx	ecx, r13d, 20
        add	edx, r9d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_11: 1 - 1
        mov	eax, DWORD PTR [rsp+60]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+44]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_11: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_11: 3 - 3
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r13d
        mov	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_11: 4 - 4
        xor	r12d, r14d
        xor	r8d, r10d
        xor	r12d, r15d
        xor	r8d, r11d
        vpxor	xmm10, xmm5, xmm10
        ; iter_11: 5 - 5
        add	r12d, ecx
        add	r8d, edx
        rorx	ebx, r8d, 15
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_11: 6 - 6
        rorx	eax, r8d, 23
        rol	r14d, 9
        xor	r8d, ebx
        ; iter_11: 7 - 7
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; iter_12: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+96]
        rorx	ecx, r12d, 20
        add	edx, r8d
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_12: 1 - 1
        mov	eax, DWORD PTR [rsp+64]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+48]
        rol	edx, 7
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_12: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_12: 3 - 3
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r12d
        mov	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_12: 4 - 4
        xor	r11d, r13d
        xor	r15d, r9d
        xor	r11d, r14d
        xor	r15d, r10d
        vpxor	xmm9, xmm4, xmm9
        ; iter_12: 5 - 5
        add	r11d, ecx
        add	r15d, edx
        rorx	ebx, r15d, 15
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_12: 6 - 7
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_13: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+104]
        rorx	ecx, r11d, 20
        add	edx, r15d
        vpshufd	xmm4, xmm2, 249
        ; iter_13: 1 - 2
        mov	eax, DWORD PTR [rsp+68]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+52]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_13: 3 - 3
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r11d
        mov	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_13: 4 - 4
        xor	r10d, r12d
        xor	r14d, r8d
        xor	r10d, r13d
        xor	r14d, r9d
        vpxor	xmm4, xmm10, xmm4
        ; iter_13: 5 - 5
        add	r10d, ecx
        add	r14d, edx
        rorx	ebx, r14d, 15
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_13: 6 - 6
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_13: 7 - 7
        rol	r8d, 19
        xor	r14d, eax
        ; iter_14: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+112]
        rorx	ecx, r10d, 20
        add	edx, r14d
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_14: 1 - 1
        mov	eax, DWORD PTR [rsp+72]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+56]
        rol	edx, 7
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_14: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpxor	xmm8, xmm4, xmm8
        ; iter_14: 3 - 4
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r10d
        mov	r13d, r14d
        xor	r9d, r11d
        xor	r13d, r15d
        xor	r9d, r12d
        xor	r13d, r8d
        vpshufd	xmm4, xmm8, 0
        ; iter_14: 5 - 5
        add	r9d, ecx
        add	r13d, edx
        rorx	ebx, r13d, 15
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_14: 6 - 6
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        vpor	xmm4, xmm5, xmm4
        ; iter_14: 7 - 7
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_15: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+120]
        rorx	ecx, r9d, 20
        add	edx, r13d
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_15: 1 - 1
        mov	eax, DWORD PTR [rsp+76]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+60]
        rol	edx, 7
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_15: 2 - 2
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_15: 3 - 3
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r9d
        mov	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_15: 4 - 4
        xor	r8d, r10d
        xor	r12d, r14d
        xor	r8d, r11d
        xor	r12d, r15d
        vpxor	xmm10, xmm5, xmm10
        ; iter_15: 5 - 5
        add	r8d, ecx
        add	r12d, edx
        rorx	ebx, r12d, 15
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_15: 6 - 6
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        ; iter_15: 7 - 7
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 12-15
        ; x2_to_w: 24
        vmovdqu	OWORD PTR [rsp+96], xmm2
        vmovdqu	OWORD PTR [rsp+112], xmm3
        ; msg_sched: 16-19
        ; iter_16: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+128]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+80]
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_16: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+64]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_16: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_16: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_16: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_16: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_16: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_17: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+136]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+84]
        vpshufd	xmm4, xmm3, 249
        ; iter_17: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+68]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_17: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_17: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_17: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_17: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_17: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_18: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+144]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+88]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_18: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+72]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_18: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_18: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_18: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_18: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_18: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_19: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+152]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+92]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_19: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+76]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_19: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_19: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_19: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_19: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_19: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_19: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 16-19
        ; msg_sched: 20-23
        ; iter_20: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+160]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+96]
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_20: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+80]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_20: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_20: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_20: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_20: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_20: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_21: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+168]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+100]
        vpshufd	xmm4, xmm0, 249
        ; iter_21: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+84]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_21: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_21: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_21: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_21: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_21: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_22: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+176]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+104]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_22: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+88]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_22: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_22: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_22: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_22: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_22: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_23: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+184]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+108]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_23: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+92]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_23: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_23: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_23: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_23: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_23: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_23: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 20-23
        ; x2_to_w: 32
        vmovdqu	OWORD PTR [rsp+128], xmm0
        vmovdqu	OWORD PTR [rsp+144], xmm1
        ; msg_sched: 24-27
        ; iter_24: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+192]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+112]
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_24: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+96]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_24: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_24: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_24: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_24: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_24: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_25: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+200]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+116]
        vpshufd	xmm4, xmm1, 249
        ; iter_25: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+100]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_25: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_25: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_25: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_25: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_25: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_26: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+208]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+120]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_26: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+104]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_26: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_26: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_26: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_26: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_26: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_27: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+216]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+124]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_27: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+108]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_27: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_27: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_27: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_27: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_27: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_27: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 24-27
        ; msg_sched: 28-31
        ; iter_28: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+224]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+128]
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_28: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+112]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_28: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_28: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_28: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_28: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_28: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_29: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+232]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+132]
        vpshufd	xmm4, xmm2, 249
        ; iter_29: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+116]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_29: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_29: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_29: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_29: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_29: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_30: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+240]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+136]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_30: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+120]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_30: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_30: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_30: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_30: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_30: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_31: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+248]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+140]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_31: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+124]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_31: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_31: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_31: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_31: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_31: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_31: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 28-31
        ; x2_to_w: 40
        vmovdqu	OWORD PTR [rsp+160], xmm2
        vmovdqu	OWORD PTR [rsp+176], xmm3
        ; msg_sched: 32-35
        ; iter_32: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+256]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+144]
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_32: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+128]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_32: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_32: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_32: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_32: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_32: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_33: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+264]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+148]
        vpshufd	xmm4, xmm3, 249
        ; iter_33: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+132]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_33: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_33: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_33: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_33: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_33: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_34: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+272]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+152]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_34: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+136]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_34: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_34: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_34: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_34: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_34: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_35: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+280]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+156]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_35: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+140]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_35: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_35: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_35: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_35: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_35: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_35: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 32-35
        ; msg_sched: 36-39
        ; iter_36: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+288]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+160]
        vpalignr	xmm5, xmm2, xmm1, 12
        ; iter_36: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+144]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm0, xmm3, 8
        ; iter_36: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_36: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_36: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_36: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm3, xmm2, 12
        ; iter_36: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm1, xmm10
        ; iter_37: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+296]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+164]
        vpshufd	xmm4, xmm0, 249
        ; iter_37: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+148]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_37: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_37: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_37: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_37: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_37: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_38: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+304]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+168]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_38: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+152]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_38: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_38: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_38: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_38: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_38: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_39: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+312]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+172]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_39: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+156]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_39: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_39: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_39: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_39: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm1, xmm8, xmm10, 192
        ; iter_39: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_39: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 36-39
        ; x2_to_w: 48
        vmovdqu	OWORD PTR [rsp+192], xmm0
        vmovdqu	OWORD PTR [rsp+208], xmm1
        ; msg_sched: 40-43
        ; iter_40: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+320]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+176]
        vpalignr	xmm5, xmm3, xmm2, 12
        ; iter_40: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+160]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm1, xmm0, 8
        ; iter_40: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_40: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_40: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_40: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm0, xmm3, 12
        ; iter_40: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm2, xmm10
        ; iter_41: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+328]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+180]
        vpshufd	xmm4, xmm1, 249
        ; iter_41: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+164]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_41: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_41: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_41: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_41: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_41: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_42: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+336]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+184]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_42: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+168]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_42: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_42: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_42: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_42: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_42: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_43: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+344]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+188]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_43: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+172]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_43: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_43: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_43: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_43: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm2, xmm8, xmm10, 192
        ; iter_43: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_43: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 40-43
        ; msg_sched: 44-47
        ; iter_44: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+352]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+192]
        vpalignr	xmm5, xmm0, xmm3, 12
        ; iter_44: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+176]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm2, xmm1, 8
        ; iter_44: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_44: 3 - 3
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        vpor	xmm9, xmm8, xmm9
        ; iter_44: 4 - 4
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        vpxor	xmm9, xmm4, xmm9
        ; iter_44: 5 - 5
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        vpalignr	xmm10, xmm1, xmm0, 12
        ; iter_44: 6 - 7
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        vpxor	xmm10, xmm3, xmm10
        ; iter_45: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+360]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+196]
        vpshufd	xmm4, xmm2, 249
        ; iter_45: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+180]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_45: 3 - 3
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        vpor	xmm4, xmm5, xmm4
        ; iter_45: 4 - 4
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        vpxor	xmm4, xmm10, xmm4
        ; iter_45: 5 - 5
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_45: 6 - 6
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_45: 7 - 7
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_46: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+368]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+200]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_46: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+184]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_46: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        vpxor	xmm8, xmm4, xmm8
        ; iter_46: 3 - 4
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        vpshufd	xmm4, xmm8, 0
        ; iter_46: 5 - 5
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_46: 6 - 6
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_46: 7 - 7
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_47: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+376]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+204]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_47: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+188]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_47: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_47: 3 - 3
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_47: 4 - 4
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        vpxor	xmm10, xmm5, xmm10
        ; iter_47: 5 - 5
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        vpblendw	xmm3, xmm8, xmm10, 192
        ; iter_47: 6 - 6
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        ; iter_47: 7 - 7
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; msg_sched done: 44-47
        ; x2_to_w: 56
        vmovdqu	OWORD PTR [rsp+224], xmm2
        vmovdqu	OWORD PTR [rsp+240], xmm3
        ; msg_sched: 48-51
        ; iter_48: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+384]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+208]
        vpalignr	xmm5, xmm1, xmm0, 12
        ; iter_48: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+192]
        rol	edx, 7
        xor	ecx, edx
        vpalignr	xmm4, xmm3, xmm2, 8
        ; iter_48: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        vpslld	xmm8, xmm5, 7
        vpsrld	xmm9, xmm5, 25
        ; iter_48: 3 - 3
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        vpor	xmm9, xmm8, xmm9
        ; iter_48: 4 - 4
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        vpxor	xmm9, xmm4, xmm9
        ; iter_48: 5 - 5
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        vpalignr	xmm10, xmm2, xmm1, 12
        ; iter_48: 6 - 7
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        vpxor	xmm10, xmm0, xmm10
        ; iter_49: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+392]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+212]
        vpshufd	xmm4, xmm3, 249
        ; iter_49: 1 - 2
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+196]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_49: 3 - 3
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        vpor	xmm4, xmm5, xmm4
        ; iter_49: 4 - 4
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        vpxor	xmm4, xmm10, xmm4
        ; iter_49: 5 - 5
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        vpslld	xmm8, xmm4, 15
        vpsrld	xmm7, xmm4, 17
        ; iter_49: 6 - 6
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        vpslld	xmm6, xmm4, 23
        vpsrld	xmm5, xmm4, 9
        ; iter_49: 7 - 7
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_50: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+400]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+216]
        vpor	xmm8, xmm7, xmm8
        vpor	xmm6, xmm5, xmm6
        ; iter_50: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+200]
        rol	edx, 7
        xor	ecx, edx
        vpxor	xmm8, xmm6, xmm8
        vpxor	xmm4, xmm9, xmm4
        ; iter_50: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        vpxor	xmm8, xmm4, xmm8
        ; iter_50: 3 - 4
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        vpshufd	xmm4, xmm8, 0
        ; iter_50: 5 - 5
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        vpslld	xmm5, xmm4, 15
        vpsrld	xmm4, xmm4, 17
        ; iter_50: 6 - 6
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        vpor	xmm4, xmm5, xmm4
        ; iter_50: 7 - 7
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        vpxor	xmm10, xmm4, xmm10
        ; iter_51: 0 - 0
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+408]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+220]
        vpslld	xmm7, xmm10, 15
        vpsrld	xmm6, xmm10, 17
        ; iter_51: 1 - 1
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+204]
        rol	edx, 7
        xor	ecx, edx
        vpslld	xmm5, xmm10, 23
        vpsrld	xmm4, xmm10, 9
        ; iter_51: 2 - 2
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        vpor	xmm7, xmm6, xmm7
        vpor	xmm5, xmm4, xmm5
        ; iter_51: 3 - 3
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        vpxor	xmm10, xmm7, xmm10
        vpxor	xmm5, xmm9, xmm5
        ; iter_51: 4 - 4
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        vpxor	xmm10, xmm5, xmm10
        ; iter_51: 5 - 5
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        vpblendw	xmm0, xmm8, xmm10, 192
        ; iter_51: 6 - 6
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        ; iter_51: 7 - 7
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; msg_sched done: 48-51
        ; iter_52: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+416]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+224]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+208]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        ; iter_53: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+424]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+228]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+212]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_54: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+432]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+232]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+216]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        ; iter_55: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+440]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+236]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+220]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        ; x0_to_w: 64
        vmovdqu	OWORD PTR [rsp+256], xmm0
        ; iter_56: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+448]
        rorx	ecx, r8d, 20
        add	edx, r12d
        mov	eax, DWORD PTR [rsp+240]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+224]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r15d
        add	ecx, r11d
        mov	r15d, r9d
        mov	ebx, r9d
        xor	r15d, r8d
        xor	ebx, r10d
        andn	r11, r12, r14
        and	r15d, ebx
        mov	ebx, r12d
        xor	r15d, r9d
        and	ebx, r13d
        add	r15d, ecx
        or	r11d, ebx
        add	r11d, edx
        rorx	ebx, r11d, 15
        rorx	eax, r11d, 23
        rol	r9d, 9
        xor	r11d, ebx
        rol	r13d, 19
        xor	r11d, eax
        ; iter_57: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+456]
        rorx	ecx, r15d, 20
        add	edx, r11d
        mov	eax, DWORD PTR [rsp+244]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+228]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r14d
        add	ecx, r10d
        mov	r14d, r8d
        mov	ebx, r8d
        xor	r14d, r15d
        xor	ebx, r9d
        andn	r10, r11, r13
        and	r14d, ebx
        mov	ebx, r11d
        xor	r14d, r8d
        and	ebx, r12d
        add	r14d, ecx
        or	r10d, ebx
        add	r10d, edx
        rorx	ebx, r10d, 15
        rorx	eax, r10d, 23
        rol	r8d, 9
        xor	r10d, ebx
        rol	r12d, 19
        xor	r10d, eax
        ; iter_58: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+464]
        rorx	ecx, r14d, 20
        add	edx, r10d
        mov	eax, DWORD PTR [rsp+248]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+232]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r13d
        add	ecx, r9d
        mov	r13d, r15d
        mov	ebx, r15d
        xor	r13d, r14d
        xor	ebx, r8d
        andn	r9, r10, r12
        and	r13d, ebx
        mov	ebx, r10d
        xor	r13d, r15d
        and	ebx, r11d
        add	r13d, ecx
        or	r9d, ebx
        add	r9d, edx
        rorx	ebx, r9d, 15
        rorx	eax, r9d, 23
        rol	r15d, 9
        xor	r9d, ebx
        rol	r11d, 19
        xor	r9d, eax
        ; iter_59: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+472]
        rorx	ecx, r13d, 20
        add	edx, r9d
        mov	eax, DWORD PTR [rsp+252]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+236]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r12d
        add	ecx, r8d
        mov	r12d, r14d
        mov	ebx, r14d
        xor	r12d, r13d
        xor	ebx, r15d
        andn	r8, r9, r11
        and	r12d, ebx
        mov	ebx, r9d
        xor	r12d, r14d
        and	ebx, r10d
        add	r12d, ecx
        or	r8d, ebx
        add	r8d, edx
        rorx	ebx, r8d, 15
        rorx	eax, r8d, 23
        rol	r14d, 9
        xor	r8d, ebx
        rol	r10d, 19
        xor	r8d, eax
        ; iter_60: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+480]
        rorx	ecx, r12d, 20
        add	edx, r8d
        mov	eax, DWORD PTR [rsp+256]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+240]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r11d
        add	ecx, r15d
        mov	r11d, r13d
        mov	ebx, r13d
        xor	r11d, r12d
        xor	ebx, r14d
        andn	r15, r8, r10
        and	r11d, ebx
        mov	ebx, r8d
        xor	r11d, r13d
        and	ebx, r9d
        add	r11d, ecx
        or	r15d, ebx
        add	r15d, edx
        rorx	ebx, r15d, 15
        rorx	eax, r15d, 23
        rol	r13d, 9
        xor	r15d, ebx
        rol	r9d, 19
        xor	r15d, eax
        ; iter_61: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+488]
        rorx	ecx, r11d, 20
        add	edx, r15d
        mov	eax, DWORD PTR [rsp+260]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+244]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r10d
        add	ecx, r14d
        mov	r10d, r12d
        mov	ebx, r12d
        xor	r10d, r11d
        xor	ebx, r13d
        andn	r14, r15, r9
        and	r10d, ebx
        mov	ebx, r15d
        xor	r10d, r12d
        and	ebx, r8d
        add	r10d, ecx
        or	r14d, ebx
        add	r14d, edx
        rorx	ebx, r14d, 15
        rorx	eax, r14d, 23
        rol	r12d, 9
        xor	r14d, ebx
        rol	r8d, 19
        xor	r14d, eax
        ; iter_62: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+496]
        rorx	ecx, r10d, 20
        add	edx, r14d
        mov	eax, DWORD PTR [rsp+264]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+248]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r9d
        add	ecx, r13d
        mov	r9d, r11d
        mov	ebx, r11d
        xor	r9d, r10d
        xor	ebx, r12d
        andn	r13, r14, r8
        and	r9d, ebx
        mov	ebx, r14d
        xor	r9d, r11d
        and	ebx, r15d
        add	r9d, ecx
        or	r13d, ebx
        add	r13d, edx
        rorx	ebx, r13d, 15
        rorx	eax, r13d, 23
        rol	r11d, 9
        xor	r13d, ebx
        rol	r15d, 19
        xor	r13d, eax
        ; iter_63: 0 - 7
        mov	edx, DWORD PTR [ptr_L_SM3_AVX1_RORX_t+504]
        rorx	ecx, r9d, 20
        add	edx, r13d
        mov	eax, DWORD PTR [rsp+268]
        add	edx, ecx
        mov	ebx, DWORD PTR [rsp+252]
        rol	edx, 7
        xor	ecx, edx
        xor	eax, ebx
        add	edx, ebx
        add	ecx, eax
        add	edx, r8d
        add	ecx, r12d
        mov	r8d, r10d
        mov	ebx, r10d
        xor	r8d, r9d
        xor	ebx, r11d
        andn	r12, r13, r15
        and	r8d, ebx
        mov	ebx, r13d
        xor	r8d, r10d
        and	ebx, r14d
        add	r8d, ecx
        or	r12d, ebx
        add	r12d, edx
        rorx	ebx, r12d, 15
        rorx	eax, r12d, 23
        rol	r10d, 9
        xor	r12d, ebx
        rol	r14d, 19
        xor	r12d, eax
        xor	r8d, DWORD PTR [rdi]
        xor	r9d, DWORD PTR [rdi+4]
        xor	r10d, DWORD PTR [rdi+8]
        xor	r11d, DWORD PTR [rdi+12]
        xor	r12d, DWORD PTR [rdi+16]
        xor	r13d, DWORD PTR [rdi+20]
        xor	r14d, DWORD PTR [rdi+24]
        xor	r15d, DWORD PTR [rdi+28]
        add	rbp, 64
        sub	esi, 64
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
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
ENDIF
END
