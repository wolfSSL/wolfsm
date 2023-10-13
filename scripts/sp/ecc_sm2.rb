# ecc_sm2.rb
#
# Copyright (C) 2006-2023 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# Implementation by Sean Parkinson

require_relative("./sm2_table.rb")

module Ecc_SM2
  def sp_ecc_curve_sm2_p256(words)
    @modulus=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    @mp_mod = calc_rho(@modulus, @bits)
    @order=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    @mp_order=calc_rho(@order, @bits)
    @base_x=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    @base_y=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    @param_a=-3
    @param_b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

    norm = (1 << 256) - @modulus
    norm_order = (1 << 256) - @order

    puts "/* The modulus (prime) of the curve SM2 P#{@total}. */"
    decl_num("mod", @modulus)
    puts "/* The Montgomery normalizer for modulus of the curve P#{@total}. */"
    decl_num("norm_mod", norm)
    puts "/* The Montgomery multiplier for modulus of the curve P#{@total}. */"
    printf "static const sp_digit #{@cname}_mp_mod = 0x%0#{@bits/4}x;\n", @mp_mod
    puts "#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \\"
    puts "                                            defined(HAVE_ECC_VERIFY)"
    puts "/* The order of the curve P#{@total}. */"
    decl_num("order", @order)
    puts "#endif"
    puts "/* The order of the curve P#{@total} minus 2. */"
    decl_num("order2", @order-2)
    puts "#if defined(HAVE_ECC_SIGN)"
    puts "/* The Montgomery normalizer for order of the curve P#{@total}. */"
    decl_num("norm_order", norm_order)
    puts "#endif"
    puts "#if defined(HAVE_ECC_SIGN)"
    puts "/* The Montgomery multiplier for order of the curve P#{@total}. */"
    printf "static const sp_digit #{@cname}_mp_order = 0x%0#{@bits/4}x", @mp_order & ((1 << @bits) - 1)
    print "L" if @size == 64
    puts ";"
    puts "#endif"
    if @bits != @size or @use_base
      puts "#ifdef WOLFSSL_SP_SMALL" if @use_base.eql? "small"
      puts "/* The base point of curve P#{@total}. */"
      decl_point("base", @base_x, @base_y, 1)
      puts "#endif /* WOLFSSL_SP_SMALL */" if @use_base.eql? "small"
    end
    puts "#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)"
    decl_num("b", @param_b)
    puts "#endif"
    puts
  end

  def sp_ecc_sign_sm2(words, total)
    from_mp(@words)
    from_bin(@words)
    to_mp(@words)
    if not @add.include?(words)
      puts "#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)"
      add(words)
      puts "#endif"
    end
    puts "#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)"
    sub(words)
    puts "#endif"
    if not @mul.include?(words)
      puts "#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)"
      mul(words)
      if @cpus.length > 0
        puts "#ifdef HAVE_INTEL_AVX2"
        mul(words, "avx2")
        puts "#endif /* HAVE_INTEL_AVX2 */"
      end
      puts "#endif"
    end
    if @mod_func == nil or not @mod_func.include?(words)
      puts "#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)"
      mod(words, @words)
      puts "#endif"
    end
    sub_cond(words)
    add_cond(words)
    cmp(words)
    puts "#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)"
    tcnt = mont_inv_order()
    if @cpus.length > 0
      puts "#ifdef HAVE_INTEL_AVX2"
      mont_inv_order("avx2")
      puts "#endif /* HAVE_INTEL_AVX2 */"
    end
    puts "#endif /* HAVE_ECC_SIGN || HAVE_ECC_VERIFY */"

    puts <<EOF
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
int sp_ecc_sign_#{@namef}#{total}(const byte* hash, word32 hashLen, WC_RNG* rng,
    const mp_int* priv, mp_int* rm, mp_int* sm, mp_int* km, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
    sp_point_#{@total}* point = NULL;
#else
    sp_digit d[#{tcnt} * 10*#{@words}];
    sp_point_#{@total} point[1];
#endif
    sp_digit* e = NULL;
    sp_digit* x = NULL;
    sp_digit* k = NULL;
    sp_digit* r = NULL;
    sp_digit* tmp = NULL;
    sp_digit* s = NULL;
    sp_digit* xInv = NULL;
    int err = MP_OKAY;
    #{@stype} c;
    int i;
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
EOF
    end
    puts <<EOF

    (void)heap;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * #{tcnt + 4} * 2 * #{@words}, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        point = (sp_point_#{@total}*)XMALLOC(sizeof(sp_point_#{@total}), heap,
            DYNAMIC_TYPE_ECC);
        if (point == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        e = d + 0 * #{@words};
        x = d + 2 * #{@words};
        k = d + 4 * #{@words};
        r = d + 6 * #{@words};
        tmp = d + 8 * #{@words};
        s = e;
        xInv = x;

        if (hashLen > #{@total / 8}U) {
            hashLen = #{@total / 8}U;
        }

        sp_#{@total}_from_bin(e, #{@words}, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_#{@total}_from_mp(x, #{@words}, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_#{@total}_ecc_gen_k_#{@namef}#{@words}(rng, k);
        }
        else {
            sp_#{@total}_from_mp(k, #{@words}, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_#{@total}_ecc_mulmod_base_avx2_#{@namef}#{@words}(point, k, 1, 1, heap);
            else
#endif
EOF
    end
    puts <<EOF
                err = sp_#{@total}_ecc_mulmod_base_#{@namef}#{@words}(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = (point->x + e) mod order */
EOF
    if @bits != @size
      puts <<EOF
            sp_#{@total}_add_#{@namef}#{@words}(r, point->x, e);
            sp_#{@total}_norm_#{@words}(r);
            c = sp_#{@total}_cmp_#{@namef}#{@words}(r, #{@cname}_order);
            sp_#{@total}_cond_sub_#{@namef}#{@words}(r, r, #{@cname}_order, 0L - (sp_digit)(c >= 0));
            sp_#{@total}_norm_#{@words}(r);
EOF
    else
      puts <<EOF
            c = sp_#{@total}_add_#{@namef}#{@words}(r, point->x, e);
            sp_#{@total}_cond_sub_#{@namef}#{@words}(r, r, #{@cname}_order, 0L - (sp_digit)c);
            c = sp_#{@total}_cmp_#{@namef}#{@words}(r, #{@cname}_order);
            sp_#{@total}_cond_sub_#{@namef}#{@words}(r, r, #{@cname}_order, 0L - (sp_digit)(c >= 0));
EOF
    end
puts <<EOF

            /* Try again if r == 0 */
            if (sp_#{@total}_iszero_#{@words}(r)) {
                continue;
            }

            /* Try again if r + k == 0 */
EOF
    if @bits != @size
      puts <<EOF
            sp_#{@total}_add_#{@namef}#{@words}(s, k, r);
            sp_#{@total}_norm_#{@words}(s);
            c += sp_#{@total}_cmp_#{@namef}#{@words}(s, #{@cname}_order);
            sp_#{@total}_cond_sub_#{@namef}#{@words}(s, s, #{@cname}_order, 0L - (sp_digit)(c >= 0));
            sp_#{@total}_norm_#{@words}(s);
EOF
    else
      puts <<EOF
            c = sp_#{@total}_add_#{@namef}#{@words}(s, k, r);
            sp_#{@total}_cond_sub_#{@namef}#{@words}(s, s, #{@cname}_order, 0L - (sp_digit)c);
            c = sp_#{@total}_cmp_#{@namef}#{@words}(s, #{@cname}_order);
            sp_#{@total}_cond_sub_#{@namef}#{@words}(s, s, #{@cname}_order, 0L - (sp_digit)(c >= 0));
EOF
    end
puts <<EOF
            if (sp_#{@total}_iszero_#{@words}(s)) {
                continue;
            }

            /* Conv x to Montgomery form (mod order) */
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_#{@total}_mul_avx2_#{@namef}#{@words}(x, x, #{@cname}_norm_order);
            else
#endif
EOF
    end
    puts <<EOF
                sp_#{@total}_mul_#{@namef}#{@words}(x, x, #{@cname}_norm_order);
            err = sp_#{@total}_mod_#{@namef}#{@words}(x, x, #{@cname}_order);
        }
        if (err == MP_OKAY) {
            sp_#{@total}_norm_#{@words}(x);

            /* s = k - r * x */
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_#{@total}_mont_mul_order_avx2_#{@namef}#{@words}(s, x, r);
            else
#endif
EOF
    end
    puts <<EOF
                sp_#{@total}_mont_mul_order_#{@namef}#{@words}(s, x, r);
        }
        if (err == MP_OKAY) {
            sp_#{@total}_norm_#{@words}(s);
EOF
    if @bits != @size
      puts <<EOF
            sp_#{@total}_sub_#{@namef}#{@words}(s, k, s);
            sp_#{@total}_cond_add_#{@namef}#{@words}(s, s, #{@cname}_order, s[#{@words-1}] >> #{@hibits});
EOF
    else
      puts <<EOF
            c = sp_#{@total}_sub_#{@namef}#{@words}(s, k, s);
            sp_#{@total}_cond_add_#{@namef}#{@words}(s, s, #{@cname}_order, c);
EOF
    end
    puts <<EOF
            sp_#{@total}_norm_#{@words}(s);

            /* xInv = 1/(x+1) mod order */
            sp_#{@total}_add_#{@namef}#{@words}(x, x, #{@cname}_norm_order);
EOF
            if @size != @bits
              puts <<EOF
            sp_#{@total}_norm_#{@words}(x);
            x[#{@words-1}] &= (((sp_digit)1) << #{@bits}) - 1;
EOF
            end
    puts <<EOF
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_#{@total}_mont_inv_order_avx2_#{@namef}#{@words}(xInv, x, tmp);
            else
#endif
EOF
    end
    puts <<EOF
                sp_#{@total}_mont_inv_order_#{@namef}#{@words}(xInv, x, tmp);
            sp_#{@total}_norm_#{@words}(xInv);

            /* s = s * (x+1)^-1 mod order */
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                sp_#{@total}_mont_mul_order_avx2_#{@namef}#{@words}(s, s, xInv);
            else
#endif
EOF
    end
    puts <<EOF
                sp_#{@total}_mont_mul_order_#{@namef}#{@words}(s, s, xInv);
            sp_#{@total}_norm_#{@words}(s);

            /* Check that signature is usable. */
            if (sp_#{@total}_iszero_#{@words}(s) == 0) {
                break;
            }
        }
    }

    if (i == 0) {
        err = RNG_FAILURE_E;
    }

    if (err == MP_OKAY) {
        err = sp_#{@total}_to_mp(r, rm);
    }
    if (err == MP_OKAY) {
        err = sp_#{@total}_to_mp(s, sm);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * #{@words});
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
    if (point != NULL) {
        XFREE(point, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * #{@words}U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * #{@words}U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * #{@words}U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * #{@words}U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * #{@words}U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * #{tcnt}U * 2U * #{@words}U);
#endif

    return err;
}
#endif /* HAVE_ECC_SIGN */

EOF
  end

  def sp_ecc_verify_sm2(words, total)
    mod_norm(words)
    tcnt = point_add() + 1

    puts <<EOF
#ifdef HAVE_ECC_VERIFY
int sp_ecc_verify_#{@namef}#{total}(const byte* hash, word32 hashLen, const mp_int* pX,
    const mp_int* pY, const mp_int* pZ, const mp_int* rm, const mp_int* sm,
    int* res, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
    sp_point_#{@total}* p1 = NULL;
#else
    sp_digit d[8*#{@words} * #{tcnt}];
    sp_point_#{@total} p1[2];
#endif
    sp_digit* e = NULL;
    sp_digit* r = NULL;
    sp_digit* s = NULL;
    sp_digit* tmp = NULL;
    sp_point_#{@total}* p2 = NULL;
    sp_digit carry;
    int err = MP_OKAY;
    int done = 0;
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
EOF
    end
    puts <<EOF

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * #{6+2*tcnt} * #{@words}, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        p1 = (sp_point_#{@total}*)XMALLOC(sizeof(sp_point_#{@total}) * 2, heap,
            DYNAMIC_TYPE_ECC);
        if (p1 == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        e   = d + 0 * #{@words};
        r   = d + 2 * #{@words};
        s   = d + 4 * #{@words};
        tmp = d + 6 * #{@words};
        p2 = p1 + 1;

        if (hashLen > #{@total / 8}U) {
            hashLen = #{@total / 8}U;
        }

        sp_#{@total}_from_mp(r, #{@words}, rm);
        sp_#{@total}_from_mp(s, #{@words}, sm);
        sp_#{@total}_from_mp(p2->x, #{@words}, pX);
        sp_#{@total}_from_mp(p2->y, #{@words}, pY);
        sp_#{@total}_from_mp(p2->z, #{@words}, pZ);


        if (sp_#{@total}_iszero_#{@words}(r) ||
            sp_#{@total}_iszero_#{@words}(s) ||
            (sp_#{@total}_cmp_#{@namef}#{@words}(r, #{@cname}_order) >= 0) ||
            (sp_#{@total}_cmp_#{@namef}#{@words}(s, #{@cname}_order) >= 0)) {
            *res = 0;
            done = 1;
        }
    }

    if ((err == MP_OKAY) && (!done)) {
        carry = sp_#{@total}_add_#{@namef}#{@words}(e, r, s);
        sp_#{@total}_norm_#{@words}(e);
        if (carry || sp_#{@total}_cmp_#{@namef}#{@words}(e, #{@cname}_order) >= 0) {
            sp_#{@total}_sub_#{@namef}#{@words}(e, e, #{@cname}_order);            sp_#{@total}_norm_#{@words}(e);
        }

        if (sp_#{@total}_iszero_#{@words}(e)) {
           *res = 0;
           done = 1;
        }
    }
    if ((err == MP_OKAY) && (!done)) {
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_#{@total}_ecc_mulmod_base_avx2_#{@namef}#{@words}(p1, s, 0, 0, heap);
        else
#endif
EOF
    end
    puts <<EOF
            err = sp_#{@total}_ecc_mulmod_base_#{@namef}#{@words}(p1, s, 0, 0, heap);
    }
    if ((err == MP_OKAY) && (!done)) {
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            err = sp_#{@total}_ecc_mulmod_avx2_#{@namef}#{@words}(p2, p2, e, 0, 0, heap);
        }
        else
#endif
EOF
    end
    puts <<EOF
        {
            err = sp_#{@total}_ecc_mulmod_#{@namef}#{@words}(p2, p2, e, 0, 0, heap);
        }
    }

    if ((err == MP_OKAY) && (!done)) {
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_#{@total}_proj_point_add_avx2_#{@namef}#{@words}(p1, p1, p2, tmp);
            if (sp_#{@total}_iszero_#{@words}(p1->z)) {
                if (sp_#{@total}_iszero_#{@words}(p1->x) && sp_#{@total}_iszero_#{@words}(p1->y)) {
                    sp_#{@total}_proj_point_dbl_avx2_#{@namef}#{@words}(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
EOF
    0.upto(@words-1) do |i|
      puts "                    p1->x[#{i}] = 0;"
    end
    puts "                    XMEMCPY(p1->z, #{@cname}_norm_mod, sizeof(#{@cname}_norm_mod));"
    puts <<EOF
                }
            }
        }
        else
#endif
EOF
    end
    puts <<EOF
        {
            sp_#{@total}_proj_point_add_#{@namef}#{@words}(p1, p1, p2, tmp);
            if (sp_#{@total}_iszero_#{@words}(p1->z)) {
                if (sp_#{@total}_iszero_#{@words}(p1->x) && sp_#{@total}_iszero_#{@words}(p1->y)) {
                    sp_#{@total}_proj_point_dbl_#{@namef}#{@words}(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
EOF
    0.upto(@words-1) do |i|
      puts "                    p1->x[#{i}] = 0;"
    end
    puts "                    XMEMCPY(p1->z, #{@cname}_norm_mod, sizeof(#{@cname}_norm_mod));"
    puts <<EOF
                }
            }
        }

        /* z' = z'.z' */
        sp_#{@total}_mont_sqr_#{@namef}#{@words}(p1->z, p1->z, #{@cname}_mod, #{@cname}_mp_mod);
        XMEMSET(p1->x + #{@words}, 0, #{@words}U * sizeof(sp_digit));
        sp_#{@total}_mont_reduce_#{@namef}#{@words}(p1->x, #{@cname}_mod, #{@cname}_mp_mod);
        /* (r - e + n*order).z'.z' mod prime == (s.G + t.Q)->x' */
        /* Load e, subtract from r. */
        sp_#{@total}_from_bin(e, #{@words}, hash, (int)hashLen);
        if (sp_#{@total}_cmp_#{@namef}#{@words}(r, e) < 0) {
            carry = sp_#{@total}_add_#{@namef}#{@words}(r, r, #{@cname}_order);
        }
        sp_#{@total}_sub_#{@namef}#{@words}(e, r, e);
        sp_#{@total}_norm_#{@words}(e);
        /* x' == (r - e).z'.z' mod prime */
        sp_#{@total}_mont_mul_#{@namef}#{@words}(s, e, p1->z, #{@cname}_mod, #{@cname}_mp_mod);
        *res = (int)(sp_#{@total}_cmp_#{@namef}#{@words}(p1->x, s) == 0);
        if (*res == 0) {
            carry = sp_#{@total}_add_#{@namef}#{@words}(e, e, #{@cname}_order);
            if (!carry && sp_#{@total}_cmp_#{@namef}#{@words}(e, #{@cname}_mod) < 0) {
                /* x' == (r - e + order).z'.z' mod prime */
                sp_#{@total}_mont_mul_#{@namef}#{@words}(s, e, p1->z, #{@cname}_mod, #{@cname}_mp_mod);
                *res = (int)(sp_#{@total}_cmp_#{@namef}#{@words}(p1->x, s) == 0);
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

EOF
  end

  def sqrt_y_ct_sm2(words, total, sqrt_power)
    puts <<EOF
/* Find the square root of a number mod the prime of the curve.
 *
 * y  The number to operate on and the result.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
static int sp_#{total}_mont_sqrt_#{@namef}#{words}(sp_digit* y)
{
#ifdef WOLFSSL_SP_SMALL_STACK
    sp_digit* t = NULL;
#else
    sp_digit t[2 * #{@words}];
#endif
    int err = MP_OKAY;
EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
EOF
    end
    puts <<EOF

#ifdef WOLFSSL_SP_SMALL_STACK
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * #{@words}, NULL, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {

EOF
    if @cpus.length > 0
      puts <<EOF
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
EOF
      sqrt_y_ct(@cpus[0] + "_", sqrt_power)
      puts <<EOF
        }
        else
#endif
EOF
    end
    puts <<EOF
        {
EOF
      sqrt_y_ct("", sqrt_power)
    puts <<EOF
        }
    }

#ifdef WOLFSSL_SP_SMALL_STACK
    if (t != NULL)
        XFREE(t, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

EOF
  end
end

