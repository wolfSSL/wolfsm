# modinv_sm2.rb
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

module ModInv_SM2
  def mont_inv_order_ct_sm2_p256(cpu="")
    tcnt = 4
    v = cpu + @words.to_s + @name
    return tcnt if @mont_inv_order_func != nil and @mont_inv_order_func.include?(v)
    @mont_inv_order_func = [] if @mont_inv_order_func == nil
    @mont_inv_order_func << v

    mul(@words, cpu)
    sqr(@words, cpu)
    mont_red(@words, @total, false, false, cpu)

    cpu += "_" if not cpu.eql? "" and cpu[-1] != "_"

    if cpu.eql? ""
      order2 = @order-2
      puts "#ifdef WOLFSSL_SP_SMALL"
      puts "/* Order-2 for the SM2 P256 curve. */"
      puts "static const uint#{@size}_t #{@cname}_order_minus_2[#{@total/@size}] = {"
      print "    "
      0.upto((@total/@size) - 1) do |i|
        printf "0x%0#{@size/4}xU", ((order2 >> (i * @size)) & ((1 << @size) - 1))
        print "," if i != (@total/@size) - 1
        print "\n    " if (((@size / 4) + 3) * (i + 2) + 4) % 80 < (@size / 4) + 3
      end
      puts
      puts "};"
      puts "#else"
      puts "#ifdef HAVE_ECC_SIGN"
      puts "/* The low half of the order-2 of the SM2 P256 curve. */"
      puts "static const uint#{@size}_t #{@cname}_order_low[#{@total/@size/2}] = {"
      print "    "
      0.upto((@total/@size/2) - 1) do |i|
        printf "0x%0#{@size/4}xU", ((order2 >> (i * @size)) & ((1 << @size) - 1))
        print "," if i != (@total/@size/2) - 1
        print "\n    " if (((@size / 4) + 3) * (i + 2) + 4) % 80 < (@size / 4) + 3
      end
      puts
      puts "};"
      puts "#endif /* HAVE_ECC_SIGN */"
      puts "#endif /* WOLFSSL_SP_SMALL */"
      puts
    end

    puts "#ifdef HAVE_ECC_SIGN"
    mont_mul_order(@words, @total, cpu)
    mont_sqr_order(@words, @total, cpu)
    ifndefc("WOLFSSL_SP_SMALL")
    mont_sqr_order_n(@words, cpu)
    endifc("!WOLFSSL_SP_SMALL")

    puts <<EOF
/* Invert the number, in Montgomery form, modulo the order of the P#{@total} curve.
 * (r = 1 / a mod order)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_#{@total}_mont_inv_order_#{cpu}#{@namef}#{@words}(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * #{@words});
    for (i=254; i>=0; i--) {
        sp_#{@total}_mont_sqr_order_#{cpu}#{@namef}#{@words}(t, t);
        if ((#{@cname}_order_minus_2[i / #{@size}] & ((sp_int_digit)1 << (i % #{@size}))) != 0) {
            sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * #{@words}U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * #{@words};
    sp_digit* t3 = td + 4 * #{@words};
    sp_digit* t4 = td + 6 * #{@words};
    int i;

    /* t4= a^2 */
    sp_#{@total}_mont_sqr_order_#{cpu}#{@namef}#{@words}(t4, a);
    /* t = a^3 = t4* a */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t, t4, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t, 2);
    /* t4= a^e = t2 * t4 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t4, t2, t4);
    /* t3= a^f = t2 * t */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t3, 4);
    /* t4 = a^fe = t2 * t4 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t4, t2, t4);
    /* t = a^ff = t2 * t3 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t, t2, t3);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t, 8);
    /* t4 = a^fffe = t2 * t4 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t4, t2, t4);
    /* t = a^ffff = t2 * t */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t, 16);
    /* t4= a^fffffffe = t2 * t4 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t4, t2, t4);
    /* t = a^ffffffff = t2 * t */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t, t2, t);
    /* t2= a^fffffffe00000000 = t4 ^ 2 ^ 32 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t4, t4, 32);
    /* t4= a^fffffffeffffffff = t4 * t */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t4, t4, t);
    /* t2= a^ffffffff00000000 = t ^ 2 ^ 32 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t, 32);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t, t2, t);
    /* t4= a^fffffffeffffffff0000000000000000 = t4 ^ 2 ^ 64 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t4, t4, 64);
    /* t2= a^fffffffeffffffffffffffffffffffff = t4 * t2 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t2, t4, t);
    /* t2= a^fffffffeffffffffffffffffffffffff7203d */
    for (i=127; i>=108; i--) {
        sp_#{@total}_mont_sqr_order_#{cpu}#{@namef}#{@words}(t2, t2);
        if (((sp_digit)#{@cname}_order_low[i / #{@size}] & ((sp_int_digit)1 << (i % #{@size}))) != 0) {
            sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t2, 4);
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bb */
    for (i=103; i>=48; i--) {
        sp_#{@total}_mont_sqr_order_#{cpu}#{@namef}#{@words}(t2, t2);
        if (((sp_digit)#{@cname}_order_low[i / #{@size}] & ((sp_int_digit)1 << (i % #{@size}))) != 0) {
            sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t2, 4);
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t2, t2, t3);
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412 */
    for (i=43; i>=4; i--) {
        sp_#{@total}_mont_sqr_order_#{cpu}#{@namef}#{@words}(t2, t2);
        if (((sp_digit)#{@cname}_order_low[i / #{@size}] & ((sp_int_digit)1 << (i % #{@size}))) != 0) {
            sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(t2, t2, a);
        }
    }
    /* t2= a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54120 */
    sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(t2, t2, 4);
    /* r = a^fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121 */
    sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(r, t2, a);
#endif /* WOLFSSL_SP_SMALL */
}
#endif /* HAVE_ECC_SIGN */

EOF

    return tcnt
  end

  def mont_inv_ct_sm2_p256(cpu="")
    cpu += "_" if not cpu.eql? "" and cpu[-1] != "_"
    v = cpu + @words.to_s + @name
    tcnt = 4
    return tcnt if @mont_inv_func != nil and @mont_inv_func.include?(v)
    @mont_inv_func = [] if @mont_inv_func == nil
    @mont_inv_func << v

    mont_mul(@words, @total, true, true, cpu)
    mont_sqr(@words, @total, true, true, cpu)
    puts "#if !defined(WOLFSSL_SP_SMALL)"
    mont_sqr_n(@words, cpu)
    puts "#endif /* !WOLFSSL_SP_SMALL */"
    if cpu.eql? ""
      puts "#ifdef WOLFSSL_SP_SMALL"
      mod2 = @modulus - 2
      puts "/* Mod-2 for the SM2 P256 curve. */"
      puts "static const uint#{@size}_t #{@cname}_mod_minus_2#{cpu}[#{@total/@size}] = {"
      print "    "
      0.upto((@total/@size) - 1) do |i|
        printf "0x%0#{@size/4}xU", ((mod2 >> (i * @size)) & ((1 << @size) - 1))
        print "," if i != (@total/@size) - 1
        print "\n    " if (((@size / 4) + 3) * (i + 2) + 4) % 80 < (@size / 4) + 3
      end
      puts
      puts "};"
      puts "#endif /* !WOLFSSL_SP_SMALL */"
    end
    puts

    puts <<EOF
/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P#{@total} curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_#{@total}_mont_inv_#{cpu}#{@namef}#{@words}(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * #{@words});
    for (i=254; i>=0; i--) {
        sp_#{@total}_mont_sqr_#{cpu}#{@namef}#{@words}(t, t, #{@cname}_mod, #{@cname}_mp_mod);
        if (#{@cname}_mod_minus_2[i / #{@size}] & ((sp_digit)1 << (i % #{@size})))
            sp_#{@total}_mont_mul_#{cpu}#{@namef}#{@words}(t, t, a, #{@cname}_mod, #{@cname}_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * #{@words});
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * #{@words};
    sp_digit* t3 = td + 4 * #{@words};
    sp_digit* t4 = td + 6 * #{@words};
EOF

    p256_mod_minus_2 = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd
    vals = [
     [ 0x2, 1 ],
     [ 0x3, 2 ],
     [ 0xc, 1 ],
     [ 0xd, 3 ],
     [ 0xf, 2 ],
     [ 0xf0, 1 ],
     [ 0xfd, 3 ],
     [ 0xff, 2 ],
     [ 0xff00, 1 ],
     [ 0xfffd, 3 ],
     [ 0xffff, 2 ],
     [ 0xffff0000, 1 ],
     [ 0xfffffffd, 3 ],
     [ 0xfffffffe, 2 ],
     [ 0xffffffff, 4 ],
     [ 0xfffffffe00000000, 2 ],
     [ 0xfffffffeffffffff, 2 ],
     [ 0xfffffffeffffffff00000000, 1 ],
     [ 0xfffffffeffffffffffffffff, -1 ],
     [ 0xfffffffeffffffffffffffff00000000, 1 ],
     [ 0xfffffffeffffffffffffffffffffffff, -1 ],
     [ 0xfffffffeffffffffffffffffffffffff00000000, -1 ],
     [ 0xfffffffeffffffffffffffffffffffffffffffff, -1 ],
     [ 0xfffffffeffffffffffffffffffffffffffffffff0000000000000000, -1 ],
     [ 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff, -1 ],
     [ 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffff00000000, -1 ],
     [ 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffd, -1 ],
    ]
    write_mont_inv_ct(vals, cpu)

    puts <<EOF
#endif /* WOLFSSL_SP_SMALL */
}

EOF

    return tcnt
  end
end

require_relative "x86_64/modinv_sm2.rb"

