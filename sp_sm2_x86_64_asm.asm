; /* sp_sm2_x86_64_asm.asm */
; /*
;  * Copyright (C) 2006-2026 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 3 of the License, or
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

IFDEF WOLFSSL_SP_SM2
; /* Multiply a and b into r. (r = a * b)
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  A single precision integer.
;  * @param [in]  b  A single precision integer.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mul_sm2_4 PROC
        push	r12
        mov	r9, rdx
        sub	rsp, 32
        ; A[0] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9]
        xor	r12, r12
        mov	QWORD PTR [rsp], rax
        mov	r11, rdx
        ; A[0] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9]
        xor	r10, r10
        add	r11, rax
        adc	r12, rdx
        adc	r10, 0
        ; A[1] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9+8]
        add	r11, rax
        adc	r12, rdx
        adc	r10, 0
        mov	QWORD PTR [rsp+8], r11
        ; A[0] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9]
        xor	r11, r11
        add	r12, rax
        adc	r10, rdx
        adc	r11, 0
        ; A[1] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9+8]
        add	r12, rax
        adc	r10, rdx
        adc	r11, 0
        ; A[2] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9+16]
        add	r12, rax
        adc	r10, rdx
        adc	r11, 0
        mov	QWORD PTR [rsp+16], r12
        ; A[0] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ; A[1] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9+8]
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ; A[2] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9+16]
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ; A[3] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9+24]
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        mov	QWORD PTR [rsp+24], r10
        ; A[1] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9+8]
        xor	r10, r10
        add	r11, rax
        adc	r12, rdx
        adc	r10, 0
        ; A[2] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9+16]
        add	r11, rax
        adc	r12, rdx
        adc	r10, 0
        ; A[3] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9+24]
        add	r11, rax
        adc	r12, rdx
        adc	r10, 0
        mov	QWORD PTR [rcx+32], r11
        ; A[2] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9+16]
        xor	r11, r11
        add	r12, rax
        adc	r10, rdx
        adc	r11, 0
        ; A[3] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9+24]
        add	r12, rax
        adc	r10, rdx
        adc	r11, 0
        mov	QWORD PTR [rcx+40], r12
        ; A[3] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9+24]
        add	r10, rax
        adc	r11, rdx
        mov	QWORD PTR [rcx+48], r10
        mov	QWORD PTR [rcx+56], r11
        mov	rax, QWORD PTR [rsp]
        mov	rdx, QWORD PTR [rsp+8]
        mov	r10, QWORD PTR [rsp+16]
        mov	r11, QWORD PTR [rsp+24]
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], rdx
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        add	rsp, 32
        pop	r12
        ret
sp_256_mul_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Multiply a and b into r. (r = a * b)
;  *
;  * @param [out] r  Result of multiplication.
;  * @param [in]  a  First number to multiply.
;  * @param [in]  b  Second number to multiply.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mul_avx2_sm2_4 PROC
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rbp, r8
        mov	rax, rdx
        mov	rdx, QWORD PTR [rax]
        mov	r14, QWORD PTR [rbp+8]
        ; A[0] * B[0]
        mulx	r9, r8, QWORD PTR [rbp]
        xor	rbx, rbx
        ; A[0] * B[1]
        mulx	r10, rdi, r14
        adcx	r9, rdi
        ; A[0] * B[2]
        mulx	r11, rdi, QWORD PTR [rbp+16]
        adcx	r10, rdi
        ; A[0] * B[3]
        mulx	r12, rdi, QWORD PTR [rbp+24]
        adcx	r11, rdi
        mov	rdx, QWORD PTR [rax+8]
        adcx	r12, rbx
        ; A[1] * B[0]
        mulx	rsi, rdi, QWORD PTR [rbp]
        xor	rbx, rbx
        adcx	r9, rdi
        ; A[1] * B[1]
        mulx	r15, rdi, r14
        adox	r10, rsi
        adcx	r10, rdi
        ; A[1] * B[2]
        mulx	rsi, rdi, QWORD PTR [rbp+16]
        adox	r11, r15
        adcx	r11, rdi
        ; A[1] * B[3]
        mulx	r13, rdi, QWORD PTR [rbp+24]
        adox	r12, rsi
        adcx	r12, rdi
        adox	r13, rbx
        mov	rdx, QWORD PTR [rax+16]
        adcx	r13, rbx
        ; A[2] * B[0]
        mulx	rsi, rdi, QWORD PTR [rbp]
        xor	rbx, rbx
        adcx	r10, rdi
        ; A[2] * B[1]
        mulx	r15, rdi, r14
        adox	r11, rsi
        adcx	r11, rdi
        ; A[2] * B[2]
        mulx	rsi, rdi, QWORD PTR [rbp+16]
        adox	r12, r15
        adcx	r12, rdi
        ; A[2] * B[3]
        mulx	r14, rdi, QWORD PTR [rbp+24]
        adox	r13, rsi
        adcx	r13, rdi
        adox	r14, rbx
        mov	rdx, QWORD PTR [rax+24]
        adcx	r14, rbx
        ; A[3] * B[0]
        mulx	rsi, rdi, QWORD PTR [rbp]
        xor	rbx, rbx
        adcx	r11, rdi
        ; A[3] * B[1]
        mulx	r15, rdi, QWORD PTR [rbp+8]
        adox	r12, rsi
        adcx	r12, rdi
        ; A[3] * B[2]
        mulx	rsi, rdi, QWORD PTR [rbp+16]
        adox	r13, r15
        adcx	r13, rdi
        ; A[3] * B[3]
        mulx	r15, rdi, QWORD PTR [rbp+24]
        adox	r14, rsi
        adcx	r14, rdi
        adox	r15, rbx
        adcx	r15, rbx
        mov	QWORD PTR [rcx], r8
        mov	QWORD PTR [rcx+8], r9
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        mov	QWORD PTR [rcx+32], r12
        mov	QWORD PTR [rcx+40], r13
        mov	QWORD PTR [rcx+48], r14
        mov	QWORD PTR [rcx+56], r15
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        ret
sp_256_mul_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
; /* Square a and put result in r. (r = a * a)
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  A single precision integer.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_sqr_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        mov	r8, rdx
        sub	rsp, 32
        ; A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        xor	r11, r11
        mov	QWORD PTR [rsp], rax
        mov	r10, rdx
        ; A[0] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8]
        xor	r9, r9
        add	r10, rax
        adc	r11, rdx
        adc	r9, 0
        add	r10, rax
        adc	r11, rdx
        adc	r9, 0
        mov	QWORD PTR [rsp+8], r10
        ; A[0] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8]
        xor	r10, r10
        add	r11, rax
        adc	r9, rdx
        adc	r10, 0
        add	r11, rax
        adc	r9, rdx
        adc	r10, 0
        ; A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r11, rax
        adc	r9, rdx
        adc	r10, 0
        mov	QWORD PTR [rsp+16], r11
        ; A[0] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r8]
        xor	r11, r11
        add	r9, rax
        adc	r10, rdx
        adc	r11, 0
        add	r9, rax
        adc	r10, rdx
        adc	r11, 0
        ; A[1] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+8]
        add	r9, rax
        adc	r10, rdx
        adc	r11, 0
        add	r9, rax
        adc	r10, rdx
        adc	r11, 0
        mov	QWORD PTR [rsp+24], r9
        ; A[1] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r8+8]
        xor	r9, r9
        add	r10, rax
        adc	r11, rdx
        adc	r9, 0
        add	r10, rax
        adc	r11, rdx
        adc	r9, 0
        ; A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r10, rax
        adc	r11, rdx
        adc	r9, 0
        mov	QWORD PTR [rcx+32], r10
        ; A[2] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r8+16]
        xor	r10, r10
        add	r11, rax
        adc	r9, rdx
        adc	r10, 0
        add	r11, rax
        adc	r9, rdx
        adc	r10, 0
        mov	QWORD PTR [rcx+40], r11
        ; A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	r9, rax
        adc	r10, rdx
        mov	QWORD PTR [rcx+48], r9
        mov	QWORD PTR [rcx+56], r10
        mov	rax, QWORD PTR [rsp]
        mov	rdx, QWORD PTR [rsp+8]
        mov	r12, QWORD PTR [rsp+16]
        mov	r13, QWORD PTR [rsp+24]
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], rdx
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        add	rsp, 32
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_sqr_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Square a and put result in r. (r = a * a)
;  *
;  * @param [out] r  Result of squaring.
;  * @param [in]  a  Number to square in Montgomery form.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_sqr_avx2_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rax, rdx
        xor	r8, r8
        mov	rdx, QWORD PTR [rax]
        mov	rsi, QWORD PTR [rax+8]
        mov	rbx, QWORD PTR [rax+16]
        mov	r15, QWORD PTR [rax+24]
        ; A[0] * A[1]
        mulx	r10, r9, rsi
        ; A[0] * A[2]
        mulx	r11, r8, rbx
        adox	r10, r8
        ; A[0] * A[3]
        mulx	r12, r8, r15
        mov	rdx, rsi
        adox	r11, r8
        ; A[1] * A[2]
        mulx	rdi, r8, rbx
        mov	rdx, r15
        adcx	r11, r8
        ; A[1] * A[3]
        mulx	r13, r8, rsi
        mov	r15, 0
        adox	r12, rdi
        adcx	r12, r8
        ; A[2] * A[3]
        mulx	r14, r8, rbx
        adox	r13, r15
        adcx	r13, r8
        adox	r14, r15
        adcx	r14, r15
        ; Double with Carry Flag
        xor	r15, r15
        ; A[0] * A[0]
        mov	rdx, QWORD PTR [rax]
        mulx	rdi, r8, rdx
        adcx	r9, r9
        adcx	r10, r10
        adox	r9, rdi
        ; A[1] * A[1]
        mov	rdx, QWORD PTR [rax+8]
        mulx	rbx, rsi, rdx
        adcx	r11, r11
        adox	r10, rsi
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rax+16]
        mulx	rsi, rdi, rdx
        adcx	r12, r12
        adox	r11, rbx
        adcx	r13, r13
        adox	r12, rdi
        adcx	r14, r14
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rax+24]
        mulx	rbx, rdi, rdx
        adox	r13, rsi
        adcx	r15, r15
        adox	r14, rdi
        adox	r15, rbx
        mov	QWORD PTR [rcx], r8
        mov	QWORD PTR [rcx+8], r9
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        mov	QWORD PTR [rcx+32], r12
        mov	QWORD PTR [rcx+40], r13
        mov	QWORD PTR [rcx+48], r14
        mov	QWORD PTR [rcx+56], r15
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_sqr_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
; /* Add b to a into r. (r = a + b)
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  A single precision integer.
;  * @param [in]  b  A single precision integer.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_add_sm2_4 PROC
        push	r12
        xor	rax, rax
        mov	r9, QWORD PTR [rdx]
        mov	r10, QWORD PTR [rdx+8]
        mov	r11, QWORD PTR [rdx+16]
        mov	r12, QWORD PTR [rdx+24]
        add	r9, QWORD PTR [r8]
        adc	r10, QWORD PTR [r8+8]
        adc	r11, QWORD PTR [r8+16]
        adc	r12, QWORD PTR [r8+24]
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        adc	rax, 0
        pop	r12
        ret
sp_256_add_sm2_4 ENDP
_TEXT ENDS
; /* Sub b from a into r. (r = a - b)
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  A single precision integer.
;  * @param [in]  b  A single precision integer.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_sub_sm2_4 PROC
        push	r12
        xor	rax, rax
        mov	r9, QWORD PTR [rdx]
        mov	r10, QWORD PTR [rdx+8]
        mov	r11, QWORD PTR [rdx+16]
        mov	r12, QWORD PTR [rdx+24]
        sub	r9, QWORD PTR [r8]
        sbb	r10, QWORD PTR [r8+8]
        sbb	r11, QWORD PTR [r8+16]
        sbb	r12, QWORD PTR [r8+24]
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        sbb	rax, rax
        pop	r12
        ret
sp_256_sub_sm2_4 ENDP
_TEXT ENDS
; /* Sub b from a into a. (a -= b)
;  *
;  * @param [in, out] a  A single precision integer and result.
;  * @param [in]      b  A single precision integer.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_sub_in_place_sm2_4 PROC
        mov	r8, QWORD PTR [rdx]
        mov	r9, QWORD PTR [rdx+8]
        mov	r10, QWORD PTR [rdx+16]
        mov	r11, QWORD PTR [rdx+24]
        sub	QWORD PTR [rcx], r8
        sbb	QWORD PTR [rcx+8], r9
        sbb	QWORD PTR [rcx+16], r10
        sbb	QWORD PTR [rcx+24], r11
        sbb	rax, rax
        ret
sp_256_sub_in_place_sm2_4 ENDP
_TEXT ENDS
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * @param [out] r  A single precision number representing condition subtract
;  *                 result.
;  * @param [in]  a  A single precision number to subtract from.
;  * @param [in]  b  A single precision number to subtract.
;  * @param [in]  m  Mask value to apply.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_cond_sub_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r14, QWORD PTR [r8]
        mov	r15, QWORD PTR [r8+8]
        mov	rdi, QWORD PTR [r8+16]
        mov	rsi, QWORD PTR [r8+24]
        and	r14, r9
        and	r15, r9
        and	rdi, r9
        and	rsi, r9
        mov	r10, QWORD PTR [rdx]
        mov	r11, QWORD PTR [rdx+8]
        mov	r12, QWORD PTR [rdx+16]
        mov	r13, QWORD PTR [rdx+24]
        sub	r10, r14
        sbb	r11, r15
        sbb	r12, rdi
        sbb	r13, rsi
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        sbb	rax, rax
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_cond_sub_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * @param [out] r  A single precision number representing condition subtract
;  *                 result.
;  * @param [in]  a  A single precision number to subtract from.
;  * @param [in]  b  A single precision number to subtract.
;  * @param [in]  m  Mask value to apply.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_cond_sub_avx2_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r14, QWORD PTR [r8]
        mov	r15, QWORD PTR [r8+8]
        mov	rdi, QWORD PTR [r8+16]
        mov	rsi, QWORD PTR [r8+24]
        and	r14, r9
        and	r15, r9
        and	rdi, r9
        and	rsi, r9
        mov	r10, QWORD PTR [rdx]
        mov	r11, QWORD PTR [rdx+8]
        mov	r12, QWORD PTR [rdx+16]
        mov	r13, QWORD PTR [rdx+24]
        sub	r10, r14
        sbb	r11, r15
        sbb	r12, rdi
        sbb	r13, rsi
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        sbb	rax, rax
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_cond_sub_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  A single precision integer.
;  * @param [in]  b  A single precision digit.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mul_d_sm2_4 PROC
        push	r12
        mov	r9, rdx
        ; A[0] * B
        mov	rax, r8
        xor	r12, r12
        mul	QWORD PTR [r9]
        mov	r10, rax
        mov	r11, rdx
        mov	QWORD PTR [rcx], r10
        ; A[1] * B
        mov	rax, r8
        xor	r10, r10
        mul	QWORD PTR [r9+8]
        add	r11, rax
        mov	QWORD PTR [rcx+8], r11
        adc	r12, rdx
        adc	r10, 0
        ; A[2] * B
        mov	rax, r8
        xor	r11, r11
        mul	QWORD PTR [r9+16]
        add	r12, rax
        mov	QWORD PTR [rcx+16], r12
        adc	r10, rdx
        adc	r11, 0
        ; A[3] * B
        mov	rax, r8
        mul	QWORD PTR [r9+24]
        add	r10, rax
        adc	r11, rdx
        mov	QWORD PTR [rcx+24], r10
        mov	QWORD PTR [rcx+32], r11
        pop	r12
        ret
sp_256_mul_d_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  A single precision integer.
;  * @param [in]  b  A single precision digit.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mul_d_avx2_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, rdx
        ; A[0] * B
        mov	rdx, r8
        xor	r13, r13
        mulx	r12, r11, QWORD PTR [rax]
        mov	QWORD PTR [rcx], r11
        ; A[1] * B
        mulx	r10, r9, QWORD PTR [rax+8]
        mov	r11, r13
        adcx	r12, r9
        adox	r11, r10
        mov	QWORD PTR [rcx+8], r12
        ; A[2] * B
        mulx	r10, r9, QWORD PTR [rax+16]
        mov	r12, r13
        adcx	r11, r9
        adox	r12, r10
        mov	QWORD PTR [rcx+16], r11
        ; A[3] * B
        mulx	r10, r9, QWORD PTR [rax+24]
        mov	r11, r13
        adcx	r12, r9
        adox	r11, r10
        adcx	r11, r13
        mov	QWORD PTR [rcx+24], r12
        mov	QWORD PTR [rcx+32], r11
        pop	r13
        pop	r12
        ret
sp_256_mul_d_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
IFDEF _WIN64
; /* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
;  *
;  * @param [in] d1   The high order half of the number to divide.
;  * @param [in] d0   The low order half of the number to divide.
;  * @param [in] div  The dividend.
;  *
;  * @return  The result of the division.
;  */
_TEXT SEGMENT READONLY PARA
div_256_word_asm_4 PROC
        mov	r9, rdx
        mov	rax, r9
        mov	rdx, rcx
        div	r8
        ret
div_256_word_asm_4 ENDP
_TEXT ENDS
ENDIF
; /* Compare a with b in constant time.
;  *
;  * @param [in] a  A single precision integer.
;  * @param [in] b  A single precision integer.
;  *
;  * @return  -ve, 0 or +ve if a is less than, equal to or greater than b
;  *          respectively.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_cmp_sm2_4 PROC
        push	r12
        xor	r9, r9
        mov	r8, -1
        mov	rax, -1
        mov	r10, 1
        mov	r11, QWORD PTR [rcx+24]
        mov	r12, QWORD PTR [rdx+24]
        and	r11, r8
        and	r12, r8
        sub	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        mov	r11, QWORD PTR [rcx+16]
        mov	r12, QWORD PTR [rdx+16]
        and	r11, r8
        and	r12, r8
        sub	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        mov	r11, QWORD PTR [rcx+8]
        mov	r12, QWORD PTR [rdx+8]
        and	r11, r8
        and	r12, r8
        sub	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        mov	r11, QWORD PTR [rcx]
        mov	r12, QWORD PTR [rdx]
        and	r11, r8
        and	r12, r8
        sub	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        xor	rax, r8
        pop	r12
        ret
sp_256_cmp_sm2_4 ENDP
_TEXT ENDS
; /* Conditionally copy a into r using the mask m.
;  * m is -1 to copy and 0 when not.
;  *
;  * @param [out] r  A single precision number to copy over.
;  * @param [in]  a  A single precision number to copy.
;  * @param [in]  m  Mask value to apply.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_cond_copy_sm2_4 PROC
        mov	rax, QWORD PTR [rcx]
        mov	r9, QWORD PTR [rcx+8]
        mov	r10, QWORD PTR [rcx+16]
        mov	r11, QWORD PTR [rcx+24]
        xor	rax, QWORD PTR [rdx]
        xor	r9, QWORD PTR [rdx+8]
        xor	r10, QWORD PTR [rdx+16]
        xor	r11, QWORD PTR [rdx+24]
        and	rax, r8
        and	r9, r8
        and	r10, r8
        and	r11, r8
        xor	QWORD PTR [rcx], rax
        xor	QWORD PTR [rcx+8], r9
        xor	QWORD PTR [rcx+16], r10
        xor	QWORD PTR [rcx+24], r11
        ret
sp_256_cond_copy_sm2_4 ENDP
_TEXT ENDS
; /* Multiply two Montgomery form numbers mod the modulus (prime).
;  * (r = a * b mod m)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply in Montgomery form.
;  * b   Second number to multiply in Montgomery form.
;  * m   Modulus (prime).
;  * mp  Montgomery multiplier.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_mul_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r10, rdx
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r10]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r10]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r10+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r10]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r10+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r10]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r10+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r10+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r10+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r10+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        ; Start Reduction
        ; mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64
        ;    + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128
        ;    + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192
        ; mu = a[0..3]
        mov	rdx, r14
        ;   + (a[0..0] * 2) << 192
        add	rdx, r11
        mov	r8, r13
        add	rdx, r11
        ;   + a[0..1) << 128
        add	r8, r11
        mov	r10, r12
        adc	rdx, r12
        ;   + a[0..2] << 64
        add	r10, r11
        mov	rax, r11
        adc	r8, r12
        adc	rdx, r13
        ;   a[0..2] << 32
        shl	r11, 32
        shld	r13, r12, 32
        shld	r12, rax, 32
        ;   - (a[0..1] * 2) << 32 << 128
        sub	r8, r11
        sbb	rdx, r12
        sub	r8, r11
        sbb	rdx, r12
        ;   - a[0..2] << 32 << 64
        sub	r10, r11
        sbb	r8, r12
        sbb	rdx, r13
        ;   - (a[0..0] * 4) << 32 << 192
        mov	r13, r11
        shl	r13, 2
        sub	rdx, r13
        ; a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu
        ;   a += mu << 256
        xor	r11, r11
        add	r15, rax
        adc	rdi, r10
        adc	rsi, r8
        adc	rbx, rdx
        sbb	r11, 0
        ;   a += mu << 64
        add	r14, r8
        adc	r15, rdx
        adc	rdi, 0
        adc	rsi, 0
        adc	rbx, 0
        sbb	r11, 0
        ; mu <<= 32
        mov	r9, rdx
        shld	rdx, r8, 32
        shld	r8, r10, 32
        shld	r10, rax, 32
        shr	r9, 32
        shl	rax, 32
        ;   a -= (mu << 32) << 64
        sub	r14, r8
        sbb	r15, rdx
        sbb	rdi, r9
        sbb	rsi, 0
        sbb	rbx, 0
        adc	r11, 0
        ;   a -= (mu << 32) << 192
        sub	r14, rax
        sbb	r15, r10
        sbb	rdi, r8
        sbb	rsi, rdx
        sbb	rbx, r9
        adc	r11, 0
        mov	rax, 18446744069414584320
        mov	r10, 18446744069414584319
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        and	rax, r11
        ;  m[2] = -1 & mask = mask
        and	r10, r11
        sub	r15, r11
        sbb	rdi, rax
        sbb	rsi, r11
        sbb	rbx, r10
        mov	QWORD PTR [rcx], r15
        mov	QWORD PTR [rcx+8], rdi
        mov	QWORD PTR [rcx+16], rsi
        mov	QWORD PTR [rcx+24], rbx
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_mont_mul_sm2_4 ENDP
_TEXT ENDS
; /* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
;  *
;  * r   Result of squaring.
;  * a   Number to square in Montgomery form.
;  * m   Modulus (prime).
;  * mp  Montgomery multiplier.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_sqr_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r8, rdx
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	r10, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r11, rbx
        adc	r12, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r13, rbx
        adc	r14, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	r15, rbx
        adc	rdi, rax
        adc	rsi, rdx
        ; Start Reduction
        ; mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64
        ;    + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128
        ;    + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192
        ; mu = a[0..3]
        mov	rdx, r13
        ;   + (a[0..0] * 2) << 192
        add	rdx, r10
        mov	rbx, r12
        add	rdx, r10
        ;   + a[0..1) << 128
        add	rbx, r10
        mov	r8, r11
        adc	rdx, r11
        ;   + a[0..2] << 64
        add	r8, r10
        mov	rax, r10
        adc	rbx, r11
        adc	rdx, r12
        ;   a[0..2] << 32
        shl	r10, 32
        shld	r12, r11, 32
        shld	r11, rax, 32
        ;   - (a[0..1] * 2) << 32 << 128
        sub	rbx, r10
        sbb	rdx, r11
        sub	rbx, r10
        sbb	rdx, r11
        ;   - a[0..2] << 32 << 64
        sub	r8, r10
        sbb	rbx, r11
        sbb	rdx, r12
        ;   - (a[0..0] * 4) << 32 << 192
        mov	r12, r10
        shl	r12, 2
        sub	rdx, r12
        ; a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu
        ;   a += mu << 256
        xor	r10, r10
        add	r14, rax
        adc	r15, r8
        adc	rdi, rbx
        adc	rsi, rdx
        sbb	r10, 0
        ;   a += mu << 64
        add	r13, rbx
        adc	r14, rdx
        adc	r15, 0
        adc	rdi, 0
        adc	rsi, 0
        sbb	r10, 0
        ; mu <<= 32
        mov	r9, rdx
        shld	rdx, rbx, 32
        shld	rbx, r8, 32
        shld	r8, rax, 32
        shr	r9, 32
        shl	rax, 32
        ;   a -= (mu << 32) << 64
        sub	r13, rbx
        sbb	r14, rdx
        sbb	r15, r9
        sbb	rdi, 0
        sbb	rsi, 0
        adc	r10, 0
        ;   a -= (mu << 32) << 192
        sub	r13, rax
        sbb	r14, r8
        sbb	r15, rbx
        sbb	rdi, rdx
        sbb	rsi, r9
        adc	r10, 0
        mov	rax, 18446744069414584320
        mov	r8, 18446744069414584319
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        and	rax, r10
        ;  m[2] = -1 & mask = mask
        and	r8, r10
        sub	r14, r10
        sbb	r15, rax
        sbb	rdi, r10
        sbb	rsi, r8
        mov	QWORD PTR [rcx], r14
        mov	QWORD PTR [rcx+8], r15
        mov	QWORD PTR [rcx+16], rdi
        mov	QWORD PTR [rcx+24], rsi
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_mont_sqr_sm2_4 ENDP
_TEXT ENDS
; /* Reduce the number back to 256 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_reduce_sm2_4 PROC
        push	rbx
        push	rsi
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        mov	r8, rcx
        mov	r9, QWORD PTR [r8]
        mov	r10, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [r8+16]
        mov	r12, QWORD PTR [r8+24]
        mov	r13, QWORD PTR [r8+32]
        mov	r14, QWORD PTR [r8+40]
        mov	r15, QWORD PTR [r8+48]
        mov	rdi, QWORD PTR [r8+56]
        ; Start Reduction
        ; mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64
        ;    + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128
        ;    + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192
        ; mu = a[0..3]
        mov	rdx, r12
        ;   + (a[0..0] * 2) << 192
        add	rdx, r9
        mov	rcx, r11
        add	rdx, r9
        ;   + a[0..1) << 128
        add	rcx, r9
        mov	rbx, r10
        adc	rdx, r10
        ;   + a[0..2] << 64
        add	rbx, r9
        mov	rax, r9
        adc	rcx, r10
        adc	rdx, r11
        ;   a[0..2] << 32
        shl	r9, 32
        shld	r11, r10, 32
        shld	r10, rax, 32
        ;   - (a[0..1] * 2) << 32 << 128
        sub	rcx, r9
        sbb	rdx, r10
        sub	rcx, r9
        sbb	rdx, r10
        ;   - a[0..2] << 32 << 64
        sub	rbx, r9
        sbb	rcx, r10
        sbb	rdx, r11
        ;   - (a[0..0] * 4) << 32 << 192
        mov	r11, r9
        shl	r11, 2
        sub	rdx, r11
        ; a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu
        ;   a += mu << 256
        xor	r9, r9
        add	r13, rax
        adc	r14, rbx
        adc	r15, rcx
        adc	rdi, rdx
        sbb	r9, 0
        ;   a += mu << 64
        add	r12, rcx
        adc	r13, rdx
        adc	r14, 0
        adc	r15, 0
        adc	rdi, 0
        sbb	r9, 0
        ; mu <<= 32
        mov	rsi, rdx
        shld	rdx, rcx, 32
        shld	rcx, rbx, 32
        shld	rbx, rax, 32
        shr	rsi, 32
        shl	rax, 32
        ;   a -= (mu << 32) << 64
        sub	r12, rcx
        sbb	r13, rdx
        sbb	r14, rsi
        sbb	r15, 0
        sbb	rdi, 0
        adc	r9, 0
        ;   a -= (mu << 32) << 192
        sub	r12, rax
        sbb	r13, rbx
        sbb	r14, rcx
        sbb	r15, rdx
        sbb	rdi, rsi
        adc	r9, 0
        mov	rax, 18446744069414584320
        mov	rbx, 18446744069414584319
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        and	rax, r9
        ;  m[2] = -1 & mask = mask
        and	rbx, r9
        sub	r13, r9
        sbb	r14, rax
        sbb	r15, r9
        sbb	rdi, rbx
        mov	QWORD PTR [r8], r13
        mov	QWORD PTR [r8+8], r14
        mov	QWORD PTR [r8+16], r15
        mov	QWORD PTR [r8+24], rdi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rsi
        pop	rbx
        ret
sp_256_mont_reduce_sm2_4 ENDP
_TEXT ENDS
; /* Reduce the number back to 256 bits using Montgomery reduction.
;  *
;  * @param [in, out] a   A single precision number to reduce in place.
;  * @param [in]      m   The single precision number representing the modulus.
;  * @param [in]      mp  The digit representing the negative inverse of
;  *                      m mod 2^n.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_reduce_order_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r9, rdx
        ; i = 0
        xor	rdi, rdi
        mov	r10, 4
        mov	r15, rcx
L_mont_loop_4:
        ; mu = a[i] * mp
        mov	r14, QWORD PTR [r15]
        imul	r14, r8
        ; a[i+0] += m[0] * mu
        mov	rax, QWORD PTR [r9]
        mov	r12, QWORD PTR [r9+8]
        mul	r14
        mov	rsi, QWORD PTR [r15]
        add	rsi, rax
        mov	r11, rdx
        mov	QWORD PTR [r15], rsi
        adc	r11, 0
        ; a[i+1] += m[1] * mu
        mov	rax, r12
        mul	r14
        mov	r12, QWORD PTR [r9+16]
        mov	rsi, QWORD PTR [r15+8]
        add	rax, r11
        mov	r13, rdx
        adc	r13, 0
        add	rsi, rax
        mov	QWORD PTR [r15+8], rsi
        adc	r13, 0
        ; a[i+2] += m[2] * mu
        mov	rax, r12
        mul	r14
        mov	r12, QWORD PTR [r9+24]
        mov	rsi, QWORD PTR [r15+16]
        add	rax, r13
        mov	r11, rdx
        adc	r11, 0
        add	rsi, rax
        mov	QWORD PTR [r15+16], rsi
        adc	r11, 0
        ; a[i+3] += m[3] * mu
        mov	rax, r12
        mul	r14
        mov	rsi, QWORD PTR [r15+24]
        add	rax, r11
        adc	rdx, rdi
        mov	rdi, 0
        adc	rdi, 0
        add	rsi, rax
        mov	QWORD PTR [r15+24], rsi
        adc	QWORD PTR [r15+32], rdx
        adc	rdi, 0
        ; i += 1
        add	r15, 8
        dec	r10
        jnz	L_mont_loop_4
        xor	rax, rax
        mov	rdx, QWORD PTR [rcx+32]
        mov	r10, QWORD PTR [rcx+40]
        mov	rsi, QWORD PTR [rcx+48]
        mov	r11, QWORD PTR [rcx+56]
        sub	rax, rdi
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        mov	r14, QWORD PTR [r9+16]
        mov	r15, QWORD PTR [r9+24]
        and	r12, rax
        and	r13, rax
        and	r14, rax
        and	r15, rax
        sub	rdx, r12
        sbb	r10, r13
        sbb	rsi, r14
        sbb	r11, r15
        mov	QWORD PTR [rcx], rdx
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], rsi
        mov	QWORD PTR [rcx+24], r11
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_mont_reduce_order_sm2_4 ENDP
_TEXT ENDS
; /* Add two Montgomery form numbers (r = a + b % m).
;  *
;  * r   Result of addition.
;  * a   First number to add in Montgomery form.
;  * b   Second number to add in Montgomery form.
;  * m   Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_add_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, QWORD PTR [rdx]
        mov	r9, QWORD PTR [rdx+8]
        mov	r10, QWORD PTR [rdx+16]
        mov	r11, QWORD PTR [rdx+24]
        add	rax, QWORD PTR [r8]
        mov	r12, 18446744069414584320
        adc	r9, QWORD PTR [r8+8]
        mov	r13, 18446744069414584319
        adc	r10, QWORD PTR [r8+16]
        adc	r11, QWORD PTR [r8+24]
        sbb	rdx, rdx
        and	r12, rdx
        and	r13, rdx
        sub	rax, rdx
        sbb	r9, r12
        sbb	r10, rdx
        sbb	r11, r13
        adc	rdx, 0
        and	r12, rdx
        and	r13, rdx
        sub	rax, rdx
        sbb	r9, r12
        mov	QWORD PTR [rcx], rax
        sbb	r10, rdx
        mov	QWORD PTR [rcx+8], r9
        sbb	r11, r13
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        pop	r13
        pop	r12
        ret
sp_256_mont_add_sm2_4 ENDP
_TEXT ENDS
; /* Double a Montgomery form number (r = a + a % m).
;  *
;  * r   Result of doubling.
;  * a   Number to double in Montgomery form.
;  * m   Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_dbl_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        add	rax, rax
        mov	r11, 18446744069414584320
        adc	r8, r8
        mov	r12, 18446744069414584319
        adc	r9, r9
        mov	r13, r10
        adc	r10, r10
        sar	r13, 63
        and	r11, r13
        and	r12, r13
        sub	rax, r13
        sbb	r8, r11
        sbb	r9, r13
        sbb	r10, r12
        adc	r13, 0
        and	r11, r13
        and	r12, r13
        sub	rax, r13
        sbb	r8, r11
        mov	QWORD PTR [rcx], rax
        sbb	r9, r13
        mov	QWORD PTR [rcx+8], r8
        sbb	r10, r12
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        pop	r13
        pop	r12
        ret
sp_256_mont_dbl_sm2_4 ENDP
_TEXT ENDS
; /* Triple a Montgomery form number (r = a + a + a % m).
;  *
;  * r   Result of Tripling.
;  * a   Number to triple in Montgomery form.
;  * m   Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_tpl_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        add	rax, rax
        mov	r11, 18446744069414584320
        adc	r8, r8
        mov	r12, 18446744069414584319
        adc	r9, r9
        adc	r10, r10
        sbb	r13, r13
        and	r11, r13
        and	r12, r13
        sub	rax, r13
        sbb	r8, r11
        sbb	r9, r13
        sbb	r10, r12
        adc	r13, 0
        and	r11, r13
        and	r12, r13
        sub	rax, r13
        sbb	r8, r11
        sbb	r9, r13
        sbb	r10, r12
        add	rax, QWORD PTR [rdx]
        mov	r11, 18446744069414584320
        adc	r8, QWORD PTR [rdx+8]
        mov	r12, 18446744069414584319
        adc	r9, QWORD PTR [rdx+16]
        adc	r10, QWORD PTR [rdx+24]
        sbb	r13, 0
        and	r11, r13
        and	r12, r13
        sub	rax, r13
        sbb	r8, r11
        sbb	r9, r13
        sbb	r10, r12
        adc	r13, 0
        and	r11, r13
        and	r12, r13
        sub	rax, r13
        sbb	r8, r11
        mov	QWORD PTR [rcx], rax
        sbb	r9, r13
        mov	QWORD PTR [rcx+8], r8
        sbb	r10, r12
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        pop	r13
        pop	r12
        ret
sp_256_mont_tpl_sm2_4 ENDP
_TEXT ENDS
; /* Subtract two Montgomery form numbers (r = a - b % m).
;  *
;  * r   Result of subtration.
;  * a   Number to subtract from in Montgomery form.
;  * b   Number to subtract with in Montgomery form.
;  * m   Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_sub_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, QWORD PTR [rdx]
        mov	r9, QWORD PTR [rdx+8]
        mov	r10, QWORD PTR [rdx+16]
        mov	r11, QWORD PTR [rdx+24]
        sub	rax, QWORD PTR [r8]
        mov	r12, 18446744069414584320
        sbb	r9, QWORD PTR [r8+8]
        mov	r13, 18446744069414584319
        sbb	r10, QWORD PTR [r8+16]
        sbb	r11, QWORD PTR [r8+24]
        sbb	rdx, rdx
        and	r12, rdx
        and	r13, rdx
        add	rax, rdx
        adc	r9, r12
        adc	r10, rdx
        adc	r11, r13
        adc	rdx, 0
        and	r12, rdx
        and	r13, rdx
        add	rax, rdx
        adc	r9, r12
        mov	QWORD PTR [rcx], rax
        adc	r10, rdx
        mov	QWORD PTR [rcx+8], r9
        adc	r11, r13
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        pop	r13
        pop	r12
        ret
sp_256_mont_sub_sm2_4 ENDP
_TEXT ENDS
; /* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
;  *
;  * @param [out] r  Result of division by 2.
;  * @param [in]  a  Number to divide.
;  * @param [in]  m  Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_div2_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        mov	r11, 18446744069414584320
        mov	r12, 18446744069414584319
        mov	r13, rax
        and	r13, 1
        neg	r13
        and	r11, r13
        and	r12, r13
        add	rax, r13
        adc	r8, r11
        adc	r9, r13
        adc	r10, r12
        mov	r13, 0
        adc	r13, 0
        shrd	rax, r8, 1
        shrd	r8, r9, 1
        shrd	r9, r10, 1
        shrd	r10, r13, 1
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        pop	r13
        pop	r12
        ret
sp_256_mont_div2_sm2_4 ENDP
_TEXT ENDS
; /* Two Montgomery numbers, subtract double second from first (r = a - 2.b % m).
;  *
;  * r   Result of subtration.
;  * a   Number to subtract from in Montgomery form.
;  * b   Number to double and subtract with in Montgomery form.
;  * m   Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_rsb_sub_dbl_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rax, QWORD PTR [rdx]
        mov	r9, QWORD PTR [rdx+8]
        mov	r10, QWORD PTR [rdx+16]
        mov	r11, QWORD PTR [rdx+24]
        mov	r12, QWORD PTR [r8]
        mov	r13, QWORD PTR [r8+8]
        mov	r14, QWORD PTR [r8+16]
        mov	r15, QWORD PTR [r8+24]
        add	r12, r12
        mov	rdi, 18446744069414584320
        adc	r13, r13
        mov	rsi, 18446744069414584319
        adc	r14, r14
        adc	r15, r15
        sbb	rdx, rdx
        and	rdi, rdx
        and	rsi, rdx
        sub	r12, rdx
        sbb	r13, rdi
        sbb	r14, rdx
        sbb	r15, rsi
        adc	rdx, 0
        and	rdi, rdx
        and	rsi, rdx
        sub	r12, rdx
        sbb	r13, rdi
        sbb	r14, rdx
        sbb	r15, rsi
        sub	rax, r12
        mov	rdi, 18446744069414584320
        sbb	r9, r13
        mov	rsi, 18446744069414584319
        sbb	r10, r14
        sbb	r11, r15
        sbb	rdx, 0
        and	rdi, rdx
        and	rsi, rdx
        add	rax, rdx
        adc	r9, rdi
        adc	r10, rdx
        adc	r11, rsi
        adc	rdx, 0
        and	rdi, rdx
        and	rsi, rdx
        add	rax, rdx
        adc	r9, rdi
        mov	QWORD PTR [rcx], rax
        adc	r10, rdx
        mov	QWORD PTR [rcx+8], r9
        adc	r11, rsi
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        mov	r12, QWORD PTR [r8]
        mov	r13, QWORD PTR [r8+8]
        mov	r14, QWORD PTR [r8+16]
        mov	r15, QWORD PTR [r8+24]
        sub	r12, rax
        mov	rdi, 18446744069414584320
        sbb	r13, r9
        mov	rsi, 18446744069414584319
        sbb	r14, r10
        sbb	r15, r11
        sbb	rdx, rdx
        and	rdi, rdx
        and	rsi, rdx
        add	r12, rdx
        adc	r13, rdi
        adc	r14, rdx
        adc	r15, rsi
        adc	rdx, 0
        and	rdi, rdx
        and	rsi, rdx
        add	r12, rdx
        adc	r13, rdi
        mov	QWORD PTR [r8], r12
        adc	r14, rdx
        mov	QWORD PTR [r8+8], r13
        adc	r15, rsi
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_mont_rsb_sub_dbl_sm2_4 ENDP
_TEXT ENDS
IFNDEF WC_NO_CACHE_RESISTANT
; /* Touch each possible point that could be being copied.
;  *
;  * @param [out] r      Point to copy into.
;  * @param [in]  table  Table - start of the entries to access
;  * @param [in]  idx    Index of point to retrieve.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_get_point_33_sm2_4 PROC
        sub	rsp, 168
        movdqu	OWORD PTR [rsp+8], xmm6
        movdqu	OWORD PTR [rsp+24], xmm7
        movdqu	OWORD PTR [rsp+40], xmm8
        movdqu	OWORD PTR [rsp+56], xmm9
        movdqu	OWORD PTR [rsp+72], xmm10
        movdqu	OWORD PTR [rsp+88], xmm11
        movdqu	OWORD PTR [rsp+104], xmm12
        movdqu	OWORD PTR [rsp+120], xmm13
        movdqu	OWORD PTR [rsp+136], xmm14
        movdqu	OWORD PTR [rsp+152], xmm15
        mov	rax, 1
        vmovd	xmm13, r8d
        add	rdx, 200
        movd	xmm15, eax
        mov	rax, 32
        pshufd	xmm15, xmm15, 0
        pshufd	xmm13, xmm13, 0
        pxor	xmm14, xmm14
        pxor	xmm0, xmm0
        pxor	xmm1, xmm1
        pxor	xmm2, xmm2
        pxor	xmm3, xmm3
        pxor	xmm4, xmm4
        pxor	xmm5, xmm5
        movdqa	xmm14, xmm15
L_256_get_point_33_sm2_4_start_1:
        movdqa	xmm12, xmm14
        paddd	xmm14, xmm15
        pcmpeqd	xmm12, xmm13
        movdqu	xmm6, OWORD PTR [rdx]
        movdqu	xmm7, OWORD PTR [rdx+16]
        movdqu	xmm8, OWORD PTR [rdx+64]
        movdqu	xmm9, OWORD PTR [rdx+80]
        movdqu	xmm10, OWORD PTR [rdx+128]
        movdqu	xmm11, OWORD PTR [rdx+144]
        add	rdx, 200
        pand	xmm6, xmm12
        pand	xmm7, xmm12
        pand	xmm8, xmm12
        pand	xmm9, xmm12
        pand	xmm10, xmm12
        pand	xmm11, xmm12
        por	xmm0, xmm6
        por	xmm1, xmm7
        por	xmm2, xmm8
        por	xmm3, xmm9
        por	xmm4, xmm10
        por	xmm5, xmm11
        dec	rax
        jnz	L_256_get_point_33_sm2_4_start_1
        movdqu	OWORD PTR [rcx], xmm0
        movdqu	OWORD PTR [rcx+16], xmm1
        movdqu	OWORD PTR [rcx+64], xmm2
        movdqu	OWORD PTR [rcx+80], xmm3
        movdqu	OWORD PTR [rcx+128], xmm4
        movdqu	OWORD PTR [rcx+144], xmm5
        movdqu	xmm6, OWORD PTR [rsp+8]
        movdqu	xmm7, OWORD PTR [rsp+24]
        movdqu	xmm8, OWORD PTR [rsp+40]
        movdqu	xmm9, OWORD PTR [rsp+56]
        movdqu	xmm10, OWORD PTR [rsp+72]
        movdqu	xmm11, OWORD PTR [rsp+88]
        movdqu	xmm12, OWORD PTR [rsp+104]
        movdqu	xmm13, OWORD PTR [rsp+120]
        movdqu	xmm14, OWORD PTR [rsp+136]
        movdqu	xmm15, OWORD PTR [rsp+152]
        add	rsp, 168
        ret
sp_256_get_point_33_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Touch each possible point that could be being copied.
;  *
;  * @param [out] r      Point to copy into.
;  * @param [in]  table  Table - start of the entries to access
;  * @param [in]  idx    Index of point to retrieve.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_get_point_33_avx2_sm2_4 PROC
        sub	rsp, 72
        vmovdqu	OWORD PTR [rsp+8], xmm6
        vmovdqu	OWORD PTR [rsp+24], xmm7
        vmovdqu	OWORD PTR [rsp+40], xmm8
        vmovdqu	OWORD PTR [rsp+56], xmm9
        mov	rax, 1
        vmovd	xmm7, r8d
        add	rdx, 200
        vmovd	xmm9, eax
        mov	rax, 32
        vpxor	ymm8, ymm8, ymm8
        vpermd	ymm7, ymm8, ymm7
        vpermd	ymm9, ymm8, ymm9
        vpxor	ymm0, ymm0, ymm0
        vpxor	ymm1, ymm1, ymm1
        vpxor	ymm2, ymm2, ymm2
        vmovdqa	ymm8, ymm9
L_256_get_point_33_avx2_sm2_4_start:
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm3, YMMWORD PTR [rdx]
        vmovupd	ymm4, YMMWORD PTR [rdx+64]
        vmovupd	ymm5, YMMWORD PTR [rdx+128]
        add	rdx, 200
        vpand	ymm3, ymm3, ymm6
        vpand	ymm4, ymm4, ymm6
        vpand	ymm5, ymm5, ymm6
        vpor	ymm0, ymm0, ymm3
        vpor	ymm1, ymm1, ymm4
        vpor	ymm2, ymm2, ymm5
        dec	rax
        jnz	L_256_get_point_33_avx2_sm2_4_start
        vmovupd	YMMWORD PTR [rcx], ymm0
        vmovupd	YMMWORD PTR [rcx+64], ymm1
        vmovupd	YMMWORD PTR [rcx+128], ymm2
        vmovdqu	xmm6, OWORD PTR [rsp+8]
        vmovdqu	xmm7, OWORD PTR [rsp+24]
        vmovdqu	xmm8, OWORD PTR [rsp+40]
        vmovdqu	xmm9, OWORD PTR [rsp+56]
        add	rsp, 72
        ret
sp_256_get_point_33_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
ENDIF
IFDEF HAVE_INTEL_AVX2
; /* Multiply two Montgomery form numbers mod the modulus (prime).
;  * (r = a * b mod m)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply in Montgomery form.
;  * b   Second number to multiply in Montgomery form.
;  * m   Modulus (prime).
;  * mp  Montgomery multiplier.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_mul_avx2_sm2_4 PROC
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rbp, r8
        mov	rax, rdx
        mov	rdx, QWORD PTR [rax]
        mov	r14, QWORD PTR [rbp+8]
        ; A[0] * B[0]
        mulx	r9, r8, QWORD PTR [rbp]
        xor	rbx, rbx
        ; A[0] * B[1]
        mulx	r10, rdi, r14
        adcx	r9, rdi
        ; A[0] * B[2]
        mulx	r11, rdi, QWORD PTR [rbp+16]
        adcx	r10, rdi
        ; A[0] * B[3]
        mulx	r12, rdi, QWORD PTR [rbp+24]
        adcx	r11, rdi
        mov	rdx, QWORD PTR [rax+8]
        adcx	r12, rbx
        ; A[1] * B[0]
        mulx	rsi, rdi, QWORD PTR [rbp]
        xor	rbx, rbx
        adcx	r9, rdi
        ; A[1] * B[1]
        mulx	r15, rdi, r14
        adox	r10, rsi
        adcx	r10, rdi
        ; A[1] * B[2]
        mulx	rsi, rdi, QWORD PTR [rbp+16]
        adox	r11, r15
        adcx	r11, rdi
        ; A[1] * B[3]
        mulx	r13, rdi, QWORD PTR [rbp+24]
        adox	r12, rsi
        adcx	r12, rdi
        adox	r13, rbx
        mov	rdx, QWORD PTR [rax+16]
        adcx	r13, rbx
        ; A[2] * B[0]
        mulx	rsi, rdi, QWORD PTR [rbp]
        xor	rbx, rbx
        adcx	r10, rdi
        ; A[2] * B[1]
        mulx	r15, rdi, r14
        adox	r11, rsi
        adcx	r11, rdi
        ; A[2] * B[2]
        mulx	rsi, rdi, QWORD PTR [rbp+16]
        adox	r12, r15
        adcx	r12, rdi
        ; A[2] * B[3]
        mulx	r14, rdi, QWORD PTR [rbp+24]
        adox	r13, rsi
        adcx	r13, rdi
        adox	r14, rbx
        mov	rdx, QWORD PTR [rax+24]
        adcx	r14, rbx
        ; A[3] * B[0]
        mulx	rsi, rdi, QWORD PTR [rbp]
        xor	rbx, rbx
        adcx	r11, rdi
        ; A[3] * B[1]
        mulx	r15, rdi, QWORD PTR [rbp+8]
        adox	r12, rsi
        adcx	r12, rdi
        ; A[3] * B[2]
        mulx	rsi, rdi, QWORD PTR [rbp+16]
        adox	r13, r15
        adcx	r13, rdi
        ; A[3] * B[3]
        mulx	r15, rdi, QWORD PTR [rbp+24]
        adox	r14, rsi
        adcx	r14, rdi
        adox	r15, rbx
        adcx	r15, rbx
        ; Start Reduction
        ; mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64
        ;    + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128
        ;    + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192
        ; mu = a[0..3]
        mov	rdx, r11
        ;   + (a[0..0] * 2) << 192
        add	rdx, r8
        mov	rbp, r10
        add	rdx, r8
        ;   + a[0..1) << 128
        add	rbp, r8
        mov	rax, r9
        adc	rdx, r9
        ;   + a[0..2] << 64
        add	rax, r8
        mov	rax, r8
        adc	rbp, r9
        adc	rdx, r10
        ;   a[0..2] << 32
        shl	r8, 32
        shld	r10, r9, 32
        shld	r9, rax, 32
        ;   - (a[0..1] * 2) << 32 << 128
        sub	rbp, r8
        sbb	rdx, r9
        sub	rbp, r8
        sbb	rdx, r9
        ;   - a[0..2] << 32 << 64
        sub	rax, r8
        sbb	rbp, r9
        sbb	rdx, r10
        ;   - (a[0..0] * 4) << 32 << 192
        mov	r10, r8
        shl	r10, 2
        sub	rdx, r10
        ; a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu
        ;   a += mu << 256
        xor	r8, r8
        add	r12, rax
        adc	r13, rax
        adc	r14, rbp
        adc	r15, rdx
        sbb	r8, 0
        ;   a += mu << 64
        add	r11, rbp
        adc	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        sbb	r8, 0
        ; mu <<= 32
        mov	rsi, rdx
        shld	rdx, rbp, 32
        shld	rbp, rax, 32
        shld	rax, rax, 32
        shr	rsi, 32
        shl	rax, 32
        ;   a -= (mu << 32) << 64
        sub	r11, rbp
        sbb	r12, rdx
        sbb	r13, rsi
        sbb	r14, 0
        sbb	r15, 0
        adc	r8, 0
        ;   a -= (mu << 32) << 192
        sub	r11, rax
        sbb	r12, rax
        sbb	r13, rbp
        sbb	r14, rdx
        sbb	r15, rsi
        adc	r8, 0
        mov	rax, 18446744069414584320
        mov	rax, 18446744069414584319
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        and	rax, r8
        ;  m[2] = -1 & mask = mask
        and	rax, r8
        sub	r12, r8
        sbb	r13, rax
        sbb	r14, r8
        sbb	r15, rax
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        ret
sp_256_mont_mul_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
; /* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
;  *
;  * r   Result of squaring.
;  * a   Number to square in Montgomery form.
;  * m   Modulus (prime).
;  * mp  Montgomery multiplier.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_sqr_avx2_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rax, rdx
        xor	r8, r8
        mov	rdx, QWORD PTR [rax]
        mov	rsi, QWORD PTR [rax+8]
        mov	rbx, QWORD PTR [rax+16]
        mov	r15, QWORD PTR [rax+24]
        ; A[0] * A[1]
        mulx	r10, r9, rsi
        ; A[0] * A[2]
        mulx	r11, r8, rbx
        adox	r10, r8
        ; A[0] * A[3]
        mulx	r12, r8, r15
        mov	rdx, rsi
        adox	r11, r8
        ; A[1] * A[2]
        mulx	rdi, r8, rbx
        mov	rdx, r15
        adcx	r11, r8
        ; A[1] * A[3]
        mulx	r13, r8, rsi
        mov	r15, 0
        adox	r12, rdi
        adcx	r12, r8
        ; A[2] * A[3]
        mulx	r14, r8, rbx
        adox	r13, r15
        adcx	r13, r8
        adox	r14, r15
        adcx	r14, r15
        ; Double with Carry Flag
        xor	r15, r15
        ; A[0] * A[0]
        mov	rdx, QWORD PTR [rax]
        mulx	rdi, r8, rdx
        adcx	r9, r9
        adcx	r10, r10
        adox	r9, rdi
        ; A[1] * A[1]
        mov	rdx, QWORD PTR [rax+8]
        mulx	rbx, rsi, rdx
        adcx	r11, r11
        adox	r10, rsi
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rax+16]
        mulx	rsi, rdi, rdx
        adcx	r12, r12
        adox	r11, rbx
        adcx	r13, r13
        adox	r12, rdi
        adcx	r14, r14
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rax+24]
        mulx	rbx, rdi, rdx
        adox	r13, rsi
        adcx	r15, r15
        adox	r14, rdi
        adox	r15, rbx
        ; Start Reduction
        ; mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64
        ;    + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128
        ;    + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192
        ; mu = a[0..3]
        mov	rdx, r11
        ;   + (a[0..0] * 2) << 192
        add	rdx, r8
        mov	rsi, r10
        add	rdx, r8
        ;   + a[0..1) << 128
        add	rsi, r8
        mov	rax, r9
        adc	rdx, r9
        ;   + a[0..2] << 64
        add	rax, r8
        mov	rax, r8
        adc	rsi, r9
        adc	rdx, r10
        ;   a[0..2] << 32
        shl	r8, 32
        shld	r10, r9, 32
        shld	r9, rax, 32
        ;   - (a[0..1] * 2) << 32 << 128
        sub	rsi, r8
        sbb	rdx, r9
        sub	rsi, r8
        sbb	rdx, r9
        ;   - a[0..2] << 32 << 64
        sub	rax, r8
        sbb	rsi, r9
        sbb	rdx, r10
        ;   - (a[0..0] * 4) << 32 << 192
        mov	r10, r8
        shl	r10, 2
        sub	rdx, r10
        ; a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu
        ;   a += mu << 256
        xor	r8, r8
        add	r12, rax
        adc	r13, rax
        adc	r14, rsi
        adc	r15, rdx
        sbb	r8, 0
        ;   a += mu << 64
        add	r11, rsi
        adc	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        sbb	r8, 0
        ; mu <<= 32
        mov	rbx, rdx
        shld	rdx, rsi, 32
        shld	rsi, rax, 32
        shld	rax, rax, 32
        shr	rbx, 32
        shl	rax, 32
        ;   a -= (mu << 32) << 64
        sub	r11, rsi
        sbb	r12, rdx
        sbb	r13, rbx
        sbb	r14, 0
        sbb	r15, 0
        adc	r8, 0
        ;   a -= (mu << 32) << 192
        sub	r11, rax
        sbb	r12, rax
        sbb	r13, rsi
        sbb	r14, rdx
        sbb	r15, rbx
        adc	r8, 0
        mov	rax, 18446744069414584320
        mov	rax, 18446744069414584319
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        and	rax, r8
        ;  m[2] = -1 & mask = mask
        and	rax, r8
        sub	r12, r8
        sbb	r13, rax
        sbb	r14, r8
        sbb	r15, rax
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_mont_sqr_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
; /* Reduce the number back to 256 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_reduce_order_avx2_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rax, rcx
        mov	r10, rdx
        mov	r11, r8
        mov	r14, QWORD PTR [rax]
        mov	r15, QWORD PTR [rax+8]
        mov	rdi, QWORD PTR [rax+16]
        mov	rsi, QWORD PTR [rax+24]
        xor	r13, r13
        xor	r12, r12
        ; a[0-4] += m[0-3] * mu = m[0-3] * (a[0] * mp)
        mov	rbx, QWORD PTR [rax+32]
        ;   mu = a[0] * mp
        mov	rdx, r14
        mulx	rcx, rdx, r11
        ;   a[0] += m[0] * mu
        mulx	r9, r8, QWORD PTR [r10]
        adcx	r14, r8
        ;   a[1] += m[1] * mu
        mulx	rcx, r8, QWORD PTR [r10+8]
        adox	r15, r9
        adcx	r15, r8
        ;   a[2] += m[2] * mu
        mulx	r9, r8, QWORD PTR [r10+16]
        adox	rdi, rcx
        adcx	rdi, r8
        ;   a[3] += m[3] * mu
        mulx	rcx, r8, QWORD PTR [r10+24]
        adox	rsi, r9
        adcx	rsi, r8
        ;   a[4] += carry
        adox	rbx, rcx
        adcx	rbx, r12
        ;   carry
        adox	r13, r12
        adcx	r13, r12
        ; a[1-5] += m[0-3] * mu = m[0-3] * (a[1] * mp)
        mov	r14, QWORD PTR [rax+40]
        ;   mu = a[1] * mp
        mov	rdx, r15
        mulx	rcx, rdx, r11
        ;   a[1] += m[0] * mu
        mulx	r9, r8, QWORD PTR [r10]
        adcx	r15, r8
        ;   a[2] += m[1] * mu
        mulx	rcx, r8, QWORD PTR [r10+8]
        adox	rdi, r9
        adcx	rdi, r8
        ;   a[3] += m[2] * mu
        mulx	r9, r8, QWORD PTR [r10+16]
        adox	rsi, rcx
        adcx	rsi, r8
        ;   a[4] += m[3] * mu
        mulx	rcx, r8, QWORD PTR [r10+24]
        adox	rbx, r9
        adcx	rbx, r8
        ;   a[5] += carry
        adox	r14, rcx
        adcx	r14, r13
        mov	r13, r12
        ;   carry
        adox	r13, r12
        adcx	r13, r12
        ; a[2-6] += m[0-3] * mu = m[0-3] * (a[2] * mp)
        mov	r15, QWORD PTR [rax+48]
        ;   mu = a[2] * mp
        mov	rdx, rdi
        mulx	rcx, rdx, r11
        ;   a[2] += m[0] * mu
        mulx	r9, r8, QWORD PTR [r10]
        adcx	rdi, r8
        ;   a[3] += m[1] * mu
        mulx	rcx, r8, QWORD PTR [r10+8]
        adox	rsi, r9
        adcx	rsi, r8
        ;   a[4] += m[2] * mu
        mulx	r9, r8, QWORD PTR [r10+16]
        adox	rbx, rcx
        adcx	rbx, r8
        ;   a[5] += m[3] * mu
        mulx	rcx, r8, QWORD PTR [r10+24]
        adox	r14, r9
        adcx	r14, r8
        ;   a[6] += carry
        adox	r15, rcx
        adcx	r15, r13
        mov	r13, r12
        ;   carry
        adox	r13, r12
        adcx	r13, r12
        ; a[3-7] += m[0-3] * mu = m[0-3] * (a[3] * mp)
        mov	rdi, QWORD PTR [rax+56]
        ;   mu = a[3] * mp
        mov	rdx, rsi
        mulx	rcx, rdx, r11
        ;   a[3] += m[0] * mu
        mulx	r9, r8, QWORD PTR [r10]
        adcx	rsi, r8
        ;   a[4] += m[1] * mu
        mulx	rcx, r8, QWORD PTR [r10+8]
        adox	rbx, r9
        adcx	rbx, r8
        ;   a[5] += m[2] * mu
        mulx	r9, r8, QWORD PTR [r10+16]
        adox	r14, rcx
        adcx	r14, r8
        ;   a[6] += m[3] * mu
        mulx	rcx, r8, QWORD PTR [r10+24]
        adox	r15, r9
        adcx	r15, r8
        ;   a[7] += carry
        adox	rdi, rcx
        adcx	rdi, r13
        mov	r13, r12
        ;   carry
        adox	r13, r12
        adcx	r13, r12
        ; Subtract mod if carry
        neg	r13
        mov	r8, 6033684446255071523
        mov	r9, 8215655796475036971
        mov	rdx, 18446744069414584319
        and	r8, r13
        and	r9, r13
        and	rdx, r13
        sub	rbx, r8
        sbb	r14, r9
        sbb	r15, r13
        sbb	rdi, rdx
        mov	QWORD PTR [rax], rbx
        mov	QWORD PTR [rax+8], r14
        mov	QWORD PTR [rax+16], r15
        mov	QWORD PTR [rax+24], rdi
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_mont_reduce_order_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
; /* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
;  *
;  * @param [out] r  Result of division by 2.
;  * @param [in]  a  Number to divide.
;  * @param [in]  m  Modulus (prime).
;  */
_TEXT SEGMENT READONLY PARA
sp_256_mont_div2_avx2_sm2_4 PROC
        push	r12
        push	r13
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        mov	r11, 18446744069414584320
        mov	r12, 18446744069414584319
        mov	r13, rax
        and	r13, 1
        neg	r13
        and	r11, r13
        and	r12, r13
        add	rax, r13
        adc	r8, r11
        adc	r9, r13
        adc	r10, r12
        mov	r13, 0
        adc	r13, 0
        shrd	rax, r8, 1
        shrd	r8, r9, 1
        shrd	r9, r10, 1
        shrd	r10, r13, 1
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        pop	r13
        pop	r12
        ret
sp_256_mont_div2_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
IFNDEF WC_NO_CACHE_RESISTANT
; /* Touch each possible entry that could be being copied.
;  *
;  * @param [out] r      Point to copy into.
;  * @param [in]  table  Table - start of the entries to access
;  * @param [in]  idx    Index of entry to retrieve.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_get_entry_64_sm2_4 PROC
        sub	rsp, 104
        movdqu	OWORD PTR [rsp+8], xmm6
        movdqu	OWORD PTR [rsp+24], xmm7
        movdqu	OWORD PTR [rsp+40], xmm8
        movdqu	OWORD PTR [rsp+56], xmm9
        movdqu	OWORD PTR [rsp+72], xmm10
        movdqu	OWORD PTR [rsp+88], xmm11
        ; From entry 1
        mov	rax, 1
        movd	xmm9, r8d
        add	rdx, 64
        movd	xmm11, eax
        mov	rax, 63
        pshufd	xmm11, xmm11, 0
        pshufd	xmm9, xmm9, 0
        pxor	xmm10, xmm10
        pxor	xmm0, xmm0
        pxor	xmm1, xmm1
        pxor	xmm2, xmm2
        pxor	xmm3, xmm3
        movdqa	xmm10, xmm11
L_256_get_entry_64_sm2_4_start_0:
        movdqa	xmm8, xmm10
        paddd	xmm10, xmm11
        pcmpeqd	xmm8, xmm9
        movdqu	xmm4, OWORD PTR [rdx]
        movdqu	xmm5, OWORD PTR [rdx+16]
        movdqu	xmm6, OWORD PTR [rdx+32]
        movdqu	xmm7, OWORD PTR [rdx+48]
        add	rdx, 64
        pand	xmm4, xmm8
        pand	xmm5, xmm8
        pand	xmm6, xmm8
        pand	xmm7, xmm8
        por	xmm0, xmm4
        por	xmm1, xmm5
        por	xmm2, xmm6
        por	xmm3, xmm7
        dec	rax
        jnz	L_256_get_entry_64_sm2_4_start_0
        movdqu	OWORD PTR [rcx], xmm0
        movdqu	OWORD PTR [rcx+16], xmm1
        movdqu	OWORD PTR [rcx+64], xmm2
        movdqu	OWORD PTR [rcx+80], xmm3
        movdqu	xmm6, OWORD PTR [rsp+8]
        movdqu	xmm7, OWORD PTR [rsp+24]
        movdqu	xmm8, OWORD PTR [rsp+40]
        movdqu	xmm9, OWORD PTR [rsp+56]
        movdqu	xmm10, OWORD PTR [rsp+72]
        movdqu	xmm11, OWORD PTR [rsp+88]
        add	rsp, 104
        ret
sp_256_get_entry_64_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Touch each possible entry that could be being copied.
;  *
;  * @param [out] r      Point to copy into.
;  * @param [in]  table  Table - start of the entries to access
;  * @param [in]  idx    Index of entry to retrieve.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_get_entry_64_avx2_sm2_4 PROC
        sub	rsp, 40
        vmovdqu	OWORD PTR [rsp+8], xmm6
        vmovdqu	OWORD PTR [rsp+24], xmm7
        mov	rax, 1
        vmovd	xmm5, r8d
        add	rdx, 64
        vmovd	xmm7, eax
        mov	rax, 64
        vpxor	ymm6, ymm6, ymm6
        vpermd	ymm5, ymm6, ymm5
        vpermd	ymm7, ymm6, ymm7
        vpxor	ymm0, ymm0, ymm0
        vpxor	ymm1, ymm1, ymm1
        vmovdqa	ymm6, ymm7
L_256_get_entry_64_avx2_sm2_4_start:
        vpcmpeqd	ymm4, ymm6, ymm5
        vpaddd	ymm6, ymm6, ymm7
        vmovupd	ymm2, YMMWORD PTR [rdx]
        vmovupd	ymm3, YMMWORD PTR [rdx+32]
        add	rdx, 64
        vpand	ymm2, ymm2, ymm4
        vpand	ymm3, ymm3, ymm4
        vpor	ymm0, ymm0, ymm2
        vpor	ymm1, ymm1, ymm3
        dec	rax
        jnz	L_256_get_entry_64_avx2_sm2_4_start
        vmovupd	YMMWORD PTR [rcx], ymm0
        vmovupd	YMMWORD PTR [rcx+64], ymm1
        vmovdqu	xmm6, OWORD PTR [rsp+8]
        vmovdqu	xmm7, OWORD PTR [rsp+24]
        add	rsp, 40
        ret
sp_256_get_entry_64_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
ENDIF
IFNDEF WC_NO_CACHE_RESISTANT
; /* Touch each possible entry that could be being copied.
;  *
;  * @param [out] r      Point to copy into.
;  * @param [in]  table  Table - start of the entries to access
;  * @param [in]  idx    Index of entry to retrieve.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_get_entry_65_sm2_4 PROC
        sub	rsp, 104
        movdqu	OWORD PTR [rsp+8], xmm6
        movdqu	OWORD PTR [rsp+24], xmm7
        movdqu	OWORD PTR [rsp+40], xmm8
        movdqu	OWORD PTR [rsp+56], xmm9
        movdqu	OWORD PTR [rsp+72], xmm10
        movdqu	OWORD PTR [rsp+88], xmm11
        ; From entry 1
        mov	rax, 1
        movd	xmm9, r8d
        add	rdx, 64
        movd	xmm11, eax
        mov	rax, 64
        pshufd	xmm11, xmm11, 0
        pshufd	xmm9, xmm9, 0
        pxor	xmm10, xmm10
        pxor	xmm0, xmm0
        pxor	xmm1, xmm1
        pxor	xmm2, xmm2
        pxor	xmm3, xmm3
        movdqa	xmm10, xmm11
L_256_get_entry_65_sm2_4_start_0:
        movdqa	xmm8, xmm10
        paddd	xmm10, xmm11
        pcmpeqd	xmm8, xmm9
        movdqu	xmm4, OWORD PTR [rdx]
        movdqu	xmm5, OWORD PTR [rdx+16]
        movdqu	xmm6, OWORD PTR [rdx+32]
        movdqu	xmm7, OWORD PTR [rdx+48]
        add	rdx, 64
        pand	xmm4, xmm8
        pand	xmm5, xmm8
        pand	xmm6, xmm8
        pand	xmm7, xmm8
        por	xmm0, xmm4
        por	xmm1, xmm5
        por	xmm2, xmm6
        por	xmm3, xmm7
        dec	rax
        jnz	L_256_get_entry_65_sm2_4_start_0
        movdqu	OWORD PTR [rcx], xmm0
        movdqu	OWORD PTR [rcx+16], xmm1
        movdqu	OWORD PTR [rcx+64], xmm2
        movdqu	OWORD PTR [rcx+80], xmm3
        movdqu	xmm6, OWORD PTR [rsp+8]
        movdqu	xmm7, OWORD PTR [rsp+24]
        movdqu	xmm8, OWORD PTR [rsp+40]
        movdqu	xmm9, OWORD PTR [rsp+56]
        movdqu	xmm10, OWORD PTR [rsp+72]
        movdqu	xmm11, OWORD PTR [rsp+88]
        add	rsp, 104
        ret
sp_256_get_entry_65_sm2_4 ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX2
; /* Touch each possible entry that could be being copied.
;  *
;  * @param [out] r      Point to copy into.
;  * @param [in]  table  Table - start of the entries to access
;  * @param [in]  idx    Index of entry to retrieve.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_get_entry_65_avx2_sm2_4 PROC
        sub	rsp, 40
        vmovdqu	OWORD PTR [rsp+8], xmm6
        vmovdqu	OWORD PTR [rsp+24], xmm7
        mov	rax, 1
        vmovd	xmm5, r8d
        add	rdx, 64
        vmovd	xmm7, eax
        mov	rax, 65
        vpxor	ymm6, ymm6, ymm6
        vpermd	ymm5, ymm6, ymm5
        vpermd	ymm7, ymm6, ymm7
        vpxor	ymm0, ymm0, ymm0
        vpxor	ymm1, ymm1, ymm1
        vmovdqa	ymm6, ymm7
L_256_get_entry_65_avx2_sm2_4_start:
        vpcmpeqd	ymm4, ymm6, ymm5
        vpaddd	ymm6, ymm6, ymm7
        vmovupd	ymm2, YMMWORD PTR [rdx]
        vmovupd	ymm3, YMMWORD PTR [rdx+32]
        add	rdx, 64
        vpand	ymm2, ymm2, ymm4
        vpand	ymm3, ymm3, ymm4
        vpor	ymm0, ymm0, ymm2
        vpor	ymm1, ymm1, ymm3
        dec	rax
        jnz	L_256_get_entry_65_avx2_sm2_4_start
        vmovupd	YMMWORD PTR [rcx], ymm0
        vmovupd	YMMWORD PTR [rcx+64], ymm1
        vmovdqu	xmm6, OWORD PTR [rsp+8]
        vmovdqu	xmm7, OWORD PTR [rsp+24]
        add	rsp, 40
        ret
sp_256_get_entry_65_avx2_sm2_4 ENDP
_TEXT ENDS
ENDIF
ENDIF
; /* Add 1 to a. (a = a + 1)
;  *
;  * @param [in, out] a  A single precision integer.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_add_one_sm2_4 PROC
        add	QWORD PTR [rcx], 1
        adc	QWORD PTR [rcx+8], 0
        adc	QWORD PTR [rcx+16], 0
        adc	QWORD PTR [rcx+24], 0
        ret
sp_256_add_one_sm2_4 ENDP
_TEXT ENDS
; /* Read big endian unsigned byte array into r.
;  * Uses the bswap instruction.
;  *
;  * @param [out] r     A single precision integer.
;  * @param [in]  size  Maximum number of bytes to convert
;  * @param [in]  a     Byte array.
;  * @param [in]  n     Number of bytes in array to read.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_from_bin_sm2_bswap PROC
        push	r12
        push	r13
        mov	r11, r8
        mov	r12, rcx
        add	r11, r9
        add	r12, 32
        xor	r13, r13
        jmp	L_256_from_bin_sm2_bswap_64_end
L_256_from_bin_sm2_bswap_64_start:
        sub	r11, 64
        mov	rax, QWORD PTR [r11+56]
        mov	r10, QWORD PTR [r11+48]
        bswap	rax
        bswap	r10
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r10
        mov	rax, QWORD PTR [r11+40]
        mov	r10, QWORD PTR [r11+32]
        bswap	rax
        bswap	r10
        mov	QWORD PTR [rcx+16], rax
        mov	QWORD PTR [rcx+24], r10
        mov	rax, QWORD PTR [r11+24]
        mov	r10, QWORD PTR [r11+16]
        bswap	rax
        bswap	r10
        mov	QWORD PTR [rcx+32], rax
        mov	QWORD PTR [rcx+40], r10
        mov	rax, QWORD PTR [r11+8]
        mov	r10, QWORD PTR [r11]
        bswap	rax
        bswap	r10
        mov	QWORD PTR [rcx+48], rax
        mov	QWORD PTR [rcx+56], r10
        add	rcx, 64
        sub	r9, 64
L_256_from_bin_sm2_bswap_64_end:
        cmp	r9, 63
        jg	L_256_from_bin_sm2_bswap_64_start
        jmp	L_256_from_bin_sm2_bswap_8_end
L_256_from_bin_sm2_bswap_8_start:
        sub	r11, 8
        mov	rax, QWORD PTR [r11]
        bswap	rax
        mov	QWORD PTR [rcx], rax
        add	rcx, 8
        sub	r9, 8
L_256_from_bin_sm2_bswap_8_end:
        cmp	r9, 7
        jg	L_256_from_bin_sm2_bswap_8_start
        cmp	r9, r13
        je	L_256_from_bin_sm2_bswap_hi_end
        mov	r10, r13
        mov	rax, r13
L_256_from_bin_sm2_bswap_hi_start:
        mov	al, BYTE PTR [r8]
        shl	r10, 8
        inc	r8
        add	r10, rax
        dec	r9
        jg	L_256_from_bin_sm2_bswap_hi_start
        mov	QWORD PTR [rcx], r10
        add	rcx, 8
L_256_from_bin_sm2_bswap_hi_end:
        cmp	rcx, r12
        jge	L_256_from_bin_sm2_bswap_zero_end
L_256_from_bin_sm2_bswap_zero_start:
        mov	QWORD PTR [rcx], r13
        add	rcx, 8
        cmp	rcx, r12
        jl	L_256_from_bin_sm2_bswap_zero_start
L_256_from_bin_sm2_bswap_zero_end:
        pop	r13
        pop	r12
        ret
sp_256_from_bin_sm2_bswap ENDP
_TEXT ENDS
IFNDEF NO_MOVBE_SUPPORT
; /* Read big endian unsigned byte array into r.
;  * Uses the movbe instruction which is an optional instruction.
;  *
;  * @param [out] r     A single precision integer.
;  * @param [in]  size  Maximum number of bytes to convert
;  * @param [in]  a     Byte array.
;  * @param [in]  n     Number of bytes in array to read.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_from_bin_sm2_movbe PROC
        push	r12
        mov	r11, r8
        mov	r12, rcx
        add	r11, r9
        add	r12, 32
        jmp	L_256_from_bin_sm2_movbe_64_end
L_256_from_bin_sm2_movbe_64_start:
        sub	r11, 64
        movbe	rax, QWORD PTR [r11+56]
        movbe	r10, QWORD PTR [r11+48]
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r10
        movbe	rax, QWORD PTR [r11+40]
        movbe	r10, QWORD PTR [r11+32]
        mov	QWORD PTR [rcx+16], rax
        mov	QWORD PTR [rcx+24], r10
        movbe	rax, QWORD PTR [r11+24]
        movbe	r10, QWORD PTR [r11+16]
        mov	QWORD PTR [rcx+32], rax
        mov	QWORD PTR [rcx+40], r10
        movbe	rax, QWORD PTR [r11+8]
        movbe	r10, QWORD PTR [r11]
        mov	QWORD PTR [rcx+48], rax
        mov	QWORD PTR [rcx+56], r10
        add	rcx, 64
        sub	r9, 64
L_256_from_bin_sm2_movbe_64_end:
        cmp	r9, 63
        jg	L_256_from_bin_sm2_movbe_64_start
        jmp	L_256_from_bin_sm2_movbe_8_end
L_256_from_bin_sm2_movbe_8_start:
        sub	r11, 8
        movbe	rax, QWORD PTR [r11]
        mov	QWORD PTR [rcx], rax
        add	rcx, 8
        sub	r9, 8
L_256_from_bin_sm2_movbe_8_end:
        cmp	r9, 7
        jg	L_256_from_bin_sm2_movbe_8_start
        cmp	r9, 0
        je	L_256_from_bin_sm2_movbe_hi_end
        mov	r10, 0
        mov	rax, 0
L_256_from_binsm2__movbe_hi_start:
        mov	al, BYTE PTR [r8]
        shl	r10, 8
        inc	r8
        add	r10, rax
        dec	r9
        jg	L_256_from_binsm2__movbe_hi_start
        mov	QWORD PTR [rcx], r10
        add	rcx, 8
L_256_from_bin_sm2_movbe_hi_end:
        cmp	rcx, r12
        jge	L_256_from_bin_sm2_movbe_zero_end
L_256_from_bin_sm2_movbe_zero_start:
        mov	QWORD PTR [rcx], 0
        add	rcx, 8
        cmp	rcx, r12
        jl	L_256_from_bin_sm2_movbe_zero_start
L_256_from_bin_sm2_movbe_zero_end:
        pop	r12
        ret
sp_256_from_bin_sm2_movbe ENDP
_TEXT ENDS
ENDIF
; /* Write r as big endian to byte array.
;  * Fixed length number of bytes written: 32
;  * Uses the bswap instruction.
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  Byte array.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_to_bin_bswap_sm2_4 PROC
        mov	rax, QWORD PTR [rcx+24]
        mov	r8, QWORD PTR [rcx+16]
        bswap	rax
        bswap	r8
        mov	QWORD PTR [rdx], rax
        mov	QWORD PTR [rdx+8], r8
        mov	rax, QWORD PTR [rcx+8]
        mov	r8, QWORD PTR [rcx]
        bswap	rax
        bswap	r8
        mov	QWORD PTR [rdx+16], rax
        mov	QWORD PTR [rdx+24], r8
        ret
sp_256_to_bin_bswap_sm2_4 ENDP
_TEXT ENDS
IFNDEF NO_MOVBE_SUPPORT
; /* Write r as big endian to byte array.
;  * Fixed length number of bytes written: 32
;  * Uses the movbe instruction which is optional.
;  *
;  * @param [out] r  A single precision integer.
;  * @param [in]  a  Byte array.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_to_bin_movbe_sm2_4 PROC
        movbe	rax, QWORD PTR [rcx+24]
        movbe	r8, QWORD PTR [rcx+16]
        mov	QWORD PTR [rdx], rax
        mov	QWORD PTR [rdx+8], r8
        movbe	rax, QWORD PTR [rcx+8]
        movbe	r8, QWORD PTR [rcx]
        mov	QWORD PTR [rdx+16], rax
        mov	QWORD PTR [rdx+24], r8
        ret
sp_256_to_bin_movbe_sm2_4 ENDP
_TEXT ENDS
ENDIF
; /* Conditionally add a and b using the mask m.
;  * m is -1 to add and 0 when not.
;  *
;  * @param [out] r  A single precision number representing conditional add
;  *                 result.
;  * @param [in]  a  A single precision number to add with.
;  * @param [in]  b  A single precision number to add.
;  * @param [in]  m  Mask value to apply.
;  */
_TEXT SEGMENT READONLY PARA
sp_256_cond_add_sm2_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rax, 0
        mov	r14, QWORD PTR [r8]
        mov	r15, QWORD PTR [r8+8]
        mov	rdi, QWORD PTR [r8+16]
        mov	rsi, QWORD PTR [r8+24]
        and	r14, r9
        and	r15, r9
        and	rdi, r9
        and	rsi, r9
        mov	r10, QWORD PTR [rdx]
        mov	r11, QWORD PTR [rdx+8]
        mov	r12, QWORD PTR [rdx+16]
        mov	r13, QWORD PTR [rdx+24]
        add	r10, r14
        adc	r11, r15
        adc	r12, rdi
        adc	r13, rsi
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        adc	rax, 0
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sp_256_cond_add_sm2_4 ENDP
_TEXT ENDS
ENDIF
END
