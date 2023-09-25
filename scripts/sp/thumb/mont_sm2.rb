# mont_sm2.rb
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

module MontArmThumb_SM2

  def mont_add_sm2()
    @r = use_param(0)
    @a = use_param(1)
    @b = use_param(2)
    #@m = use_param(3)

    o = use_reg(32)
    a = [ use_reg(32), use_reg(32) ]
    b = [ use_reg(32), use_reg(32) ]
    m = [ -1, -1, -1, 0, 0, 0, 1, -1 ]
    m7 = b[0]
    zero = b[1]
    rh = use_regs(4, 32)

    puts "    (void)m;"

    asm()

    i_mov(o, 0)
    # 0-1
    i_ldr(a[0], @a[0])
    i_ldr(a[1], @a[1])
    i_ldr(b[0], @b[0])
    i_ldr(b[1], @b[1])
    i_add(a[0], b[0])
    i_adc(a[1], b[1])
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])
    # 2-3
    i_ldr(a[0], @a[2])
    i_ldr(a[1], @a[3])
    i_ldr(b[0], @b[2])
    i_ldr(b[1], @b[3])
    i_adc(a[0], b[0])
    i_adc(a[1], b[1])
    i_str(a[0], @r[2])
    i_str(a[1], @r[3])
    # 4-5
    i_ldr(a[0], @a[4])
    i_ldr(a[1], @a[5])
    i_ldr(b[0], @b[4])
    i_ldr(b[1], @b[5])
    i_adc(a[0], b[0])
    i_adc(a[1], b[1])
    i_mov(rh[0], a[0])
    i_mov(rh[1], a[1])
    # 6-7
    i_ldr(a[0], @a[6])
    i_ldr(a[1], @a[7])
    i_ldr(b[0], @b[6])
    i_ldr(b[1], @b[7])
    i_adc(a[0], b[0])
    i_adc(a[1], b[1])
    i_mov(rh[2], a[0])
    i_mov(rh[3], a[1])

    # o is overflow, m7 is 7th word of modulus (-2 on overflow, 0 not)
    i_adc(o, o)
    i_sub(o, 1)
    i_mvn(o, o)
    i_mov(zero, 0)
    i_lsl(m7, o, 1)

    # Subtract mod (when no overflow 'o' and 'm7' are 0)
    # m = fffffffe ffffffff ffffffff ffffffff
    #     ffffffff 00000000 ffffffff ffffffff
    i_ldr(a[0], @r[0])
    i_ldr(a[1], @r[1])
    i_sub(a[0], o)
    i_sbc(a[1], o)
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])
    i_ldr(a[0], @r[2])
    i_ldr(a[1], @r[3])
    i_sbc(a[0], zero)
    i_sbc(a[1], o)
    i_str(a[0], @r[2])
    i_str(a[1], @r[3])
    i_mov(a[0], rh[0])
    i_mov(a[1], rh[1])
    i_sbc(a[0], o)
    i_sbc(a[1], o)
    i_str(a[0], @r[4])
    i_str(a[1], @r[5])
    i_mov(a[0], rh[2])
    i_mov(a[1], rh[3])
    i_sbc(a[0], o)
    i_sbc(a[1], m7)
    i_str(a[0], @r[6])
    i_str(a[1], @r[7])

    end_asm()
  end

  def mont_dbl_sm2()
    @r = use_param(0)
    @a = use_param(1)
    #@m = use_param(2)

    m7 = use_reg(32)
    o = use_reg(32)
    a = use_regs(4, 32)
    m = [ -1, -1, -1, 0, 0, 0, 1, -1 ]
    zero = a[3]
    rh = use_regs(4, 32)

    puts "    (void)m;"

    asm()

    # 0-3
    i_ldr(a[0], @a[0])
    i_ldr(a[1], @a[1])
    i_ldr(a[2], @a[2])
    i_ldr(a[3], @a[3])
    i_add(a[0], a[0])
    i_adc(a[1], a[1])
    i_adc(a[2], a[2])
    i_adc(a[3], a[3])
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])
    i_str(a[2], @r[2])
    i_str(a[3], @r[3])
    # 4-5
    i_ldr(a[0], @a[4])
    i_ldr(a[1], @a[5])
    i_ldr(a[2], @a[6])
    i_ldr(a[3], @a[7])
    i_adc(a[0], a[0])
    i_adc(a[1], a[1])
    i_adc(a[2], a[2])
    i_adc(a[3], a[3])
    i_mov(rh[0], a[0])
    i_mov(rh[1], a[1])
    i_mov(rh[2], a[2])
    i_mov(rh[3], a[3])

    i_mov(o, 0)
    i_mov(zero, 0)
    i_adc(o, o)
    i_sub(o, 1)
    i_mvn(o, o)
    i_lsl(m7, o, 1)

    i_ldr(a[0], @r[0])
    i_ldr(a[1], @r[1])
    i_ldr(a[2], @r[2])
    i_sub(a[0], o)
    i_sbc(a[1], o)
    i_sbc(a[2], zero)
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])
    i_str(a[2], @r[2])
    i_ldr(a[0], @r[3])
    i_mov(a[1], rh[0])
    i_mov(a[2], rh[1])
    i_sbc(a[0], o)
    i_sbc(a[1], o)
    i_sbc(a[2], o)
    i_str(a[0], @r[3])
    i_str(a[1], @r[4])
    i_str(a[2], @r[5])
    i_mov(a[0], rh[2])
    i_mov(a[1], rh[3])
    i_sbc(a[0], o)
    i_sbc(a[1], m7)
    i_str(a[0], @r[6])
    i_str(a[1], @r[7])

    end_asm()
  end

    def mont_tpl_sm2()
    @r = use_param(0)
    @a = use_param(1)
    #@m = use_param(2)

    a = use_regs(4, 32)
    b = a[2..3]
    m = [ -1, -1, -1, 0, 0, 0, 1, -1 ]
    o = a[1]
    m7 = a[2]
    zero = a[3]
    rh = use_regs(8, 32)

    puts "    (void)m;"

    asm()

    # 0-3
    i_ldr(rh[0], @a[0])
    i_ldr(rh[1], @a[1])
    i_ldr(a[2], @a[2])
    i_ldr(a[3], @a[3])
    i_add(rh[0], rh[0])
    i_adc(rh[1], rh[1])
    i_adc(a[2], a[2])
    i_adc(a[3], a[3])
    i_mov(rh[2], a[2])
    i_mov(rh[3], a[3])
    # 4-7
    i_ldr(a[0], @a[4])
    i_ldr(a[1], @a[5])
    i_ldr(a[2], @a[6])
    i_ldr(a[3], @a[7])
    i_adc(a[0], a[0])
    i_adc(a[1], a[1])
    i_adc(a[2], a[2])
    i_adc(a[3], a[3])
    i_mov(rh[4], a[0])
    i_mov(rh[5], a[1])
    i_mov(rh[6], a[2])
    i_mov(rh[7], a[3])

    i_mov(o, 0)
    i_mov(zero, 0)
    i_adc(o, o)
    i_sub(o, 1)
    i_mvn(o, o)
    i_lsl(m7, o, 1)

    i_sub(rh[0], o)
    i_sbc(rh[1], o)
    i_mov(a[0], rh[2])
    i_sbc(a[0], zero)
    i_mov(rh[2], a[0])
    i_mov(a[0], rh[3])
    i_sbc(a[0], o)
    i_mov(rh[3], a[0])
    i_mov(a[0], rh[4])
    i_sbc(a[0], o)
    i_mov(rh[4], a[0])
    i_mov(a[0], rh[5])
    i_sbc(a[0], o)
    i_mov(rh[5], a[0])
    i_mov(a[0], rh[6])
    i_sbc(a[0], o)
    i_mov(rh[6], a[0])
    i_mov(a[0], rh[7])
    i_sbc(a[0], m7)
    i_mov(rh[7], a[0])

    # 0-1
    i_ldr(a[0], @a[0])
    i_ldr(a[1], @a[1])
    i_add(rh[0], a[0])
    i_adc(rh[1], a[1])
    # 2-3
    i_ldr(a[0], @a[2])
    i_ldr(a[1], @a[3])
    i_mov(b[0], rh[2])
    i_mov(b[1], rh[3])
    i_adc(a[0], b[0])
    i_adc(a[1], b[1])
    i_mov(rh[2], a[0])
    i_mov(rh[3], a[1])
    # 4-5
    i_ldr(a[0], @a[4])
    i_ldr(a[1], @a[5])
    i_mov(b[0], rh[4])
    i_mov(b[1], rh[5])
    i_adc(a[0], b[0])
    i_adc(a[1], b[1])
    i_mov(rh[4], a[0])
    i_mov(rh[5], a[1])
    # 6-7
    i_ldr(a[0], @a[6])
    i_ldr(a[1], @a[7])
    i_mov(b[0], rh[6])
    i_mov(b[1], rh[7])
    i_adc(a[0], b[0])
    i_adc(a[1], b[1])
    i_mov(rh[6], a[0])
    i_mov(rh[7], a[1])

    i_mov(o, 0)
    i_mov(zero, 0)
    i_adc(o, o)
    i_sub(o, 1)
    i_mvn(o, o)
    i_lsl(m7, o, 1)

    i_sub(rh[0], o)
    i_str(rh[0], @r[0])
    i_sbc(rh[1], o)
    i_str(rh[1], @r[1])
    i_mov(a[0], rh[2])
    i_sbc(a[0], zero)
    i_str(a[0], @r[2])
    i_mov(a[0], rh[3])
    i_sbc(a[0], o)
    i_str(a[0], @r[3])
    i_mov(a[0], rh[4])
    i_sbc(a[0], o)
    i_str(a[0], @r[4])
    i_mov(a[0], rh[5])
    i_sbc(a[0], o)
    i_str(a[0], @r[5])
    i_mov(a[0], rh[6])
    i_sbc(a[0], o)
    i_str(a[0], @r[6])
    i_mov(a[0], rh[7])
    i_sbc(a[0], m7)
    i_str(a[0], @r[7])

    end_asm()
  end

  def mont_sub_sm2()
    @r = use_param(0)
    @a = use_param(1)
    @b = use_param(2)
    #@m = use_param(3)

    o = use_reg(32)
    a = use_regs(2, 32)
    b = use_regs(2, 32)
    m = [-1, -1, -1, 0, 0, 0, 1, -1]
    zero = b[0]
    m7 = b[1]
    rh = use_regs(4, 32)

    puts "    (void)m;"

    asm()

    # 0-1
    i_ldr(a[0], @a[0])
    i_ldr(a[1], @a[1])
    i_ldr(b[0], @b[0])
    i_ldr(b[1], @b[1])
    i_sub(a[0], b[0])
    i_sbc(a[1], b[1])
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])
    # 2-3
    i_ldr(a[0], @a[2])
    i_ldr(a[1], @a[3])
    i_ldr(b[0], @b[2])
    i_ldr(b[1], @b[3])
    i_sbc(a[0], b[0])
    i_sbc(a[1], b[1])
    i_str(a[0], @r[2])
    i_str(a[1], @r[3])
    # 4-5
    i_ldr(a[0], @a[4])
    i_ldr(a[1], @a[5])
    i_ldr(b[0], @b[4])
    i_ldr(b[1], @b[5])
    i_sbc(a[0], b[0])
    i_sbc(a[1], b[1])
    i_mov(rh[0], a[0])
    i_mov(rh[1], a[1])
    # 6-7
    i_ldr(a[0], @a[6])
    i_ldr(a[1], @a[7])
    i_ldr(b[0], @b[6])
    i_ldr(b[1], @b[7])
    i_sbc(a[0], b[0])
    i_sbc(a[1], b[1])
    i_mov(rh[2], a[0])
    i_mov(rh[3], a[1])

    i_sbc(o, o)
    i_mov(zero, 0)
    i_lsl(m7, o, 1)

    # Add mod (when no underlow, values are 0)
    # m = fffffffe ffffffff ffffffff ffffffff
    #     ffffffff 00000000 ffffffff ffffffff
    i_ldr(a[0], @r[0])
    i_ldr(a[1], @r[1])
    i_add(a[0], o)
    i_adc(a[1], o)
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])
    i_ldr(a[0], @r[2])
    i_ldr(a[1], @r[3])
    i_adc(a[0], zero)
    i_adc(a[1], o)
    i_str(a[0], @r[2])
    i_str(a[1], @r[3])
    i_mov(a[0], rh[0])
    i_mov(a[1], rh[1])
    i_adc(a[0], o)
    i_adc(a[1], o)
    i_str(a[0], @r[4])
    i_str(a[1], @r[5])
    i_mov(a[0], rh[2])
    i_mov(a[1], rh[3])
    i_adc(a[0], o)
    i_adc(a[1], m7)
    i_str(a[0], @r[6])
    i_str(a[1], @r[7])

    end_asm()
  end

  def mont_div2_sm2()
    @r = use_param(0)
    @a = use_param(1)

    a = use_regs(2, 32)
    l = use_regs(2, 32)
    o = use_reg(32)
    mask = l[0]
    m = l[1]
    zero = o

    puts "    (void)m;"

    asm()

    i_ldr(o, @a[0])
    i_lsl(o, o, 31)
    i_lsr(o, o, 31)
    i_mov(mask, 0)
    i_sub(mask, o)
    i_mov(zero, 0)

    # m = fffffffe or 0
    i_mov(m, mask)
    i_sub(m, 1)
    i_and(m, mask)

    # m = fffffffe ffffffff ffffffff ffffffff
    #     ffffffff 00000000 ffffffff ffffffff
    i_ldr(a[0], @a[0])
    i_ldr(a[1], @a[1])
    i_add(a[0], mask)
    i_adc(a[1], mask)
    i_str(a[0], @r[0])
    i_str(a[1], @r[1])

    i_ldr(a[0], @a[2])
    i_ldr(a[1], @a[3])
    i_adc(a[0], zero)
    i_adc(a[1], mask)
    i_str(a[0], @r[2])
    i_str(a[1], @r[3])

    i_ldr(a[0], @a[4])
    i_ldr(a[1], @a[5])
    i_adc(a[0], mask)
    i_adc(a[1], mask)
    i_str(a[0], @r[4])
    i_str(a[1], @r[5])

    i_ldr(a[0], @a[6])
    i_ldr(a[1], @a[7])
    i_adc(a[0], mask)
    i_adc(a[1], m)

    # o is same register as zero
    i_adc(o, o)
    # Shift up to OR into top word as top bit
    i_lsl(o, o, 31)

    i_lsr(l[0], a[0], 1)
    i_lsl(a[0], a[0], 31)
    i_lsr(l[1], a[1], 1)
    i_lsl(a[1], a[1], 31)
    i_orr(l[0], a[1])
    i_orr(l[1], o)
    i_mov(o, a[0])
    i_str(l[0], @r[6])
    i_str(l[1], @r[7])

    i_ldr(a[0], @r[4])
    i_ldr(a[1], @r[5])
    i_lsr(l[0], a[0], 1)
    i_lsl(a[0], a[0], 31)
    i_lsr(l[1], a[1], 1)
    i_lsl(a[1], a[1], 31)
    i_orr(l[0], a[1])
    i_orr(l[1], o)
    i_mov(o, a[0])
    i_str(l[0], @r[4])
    i_str(l[1], @r[5])

    i_ldr(a[0], @r[2])
    i_ldr(a[1], @r[3])
    i_lsr(l[0], a[0], 1)
    i_lsl(a[0], a[0], 31)
    i_lsr(l[1], a[1], 1)
    i_lsl(a[1], a[1], 31)
    i_orr(l[0], a[1])
    i_orr(l[1], o)
    i_mov(o, a[0])
    i_str(l[0], @r[2])
    i_str(l[1], @r[3])

    i_ldr(a[0], @r[0])
    i_ldr(a[1], @r[1])
    i_lsr(l[0], a[0], 1)
    #i_lsl(a[0], a[0], 31)
    i_lsr(l[1], a[1], 1)
    i_lsl(a[1], a[1], 31)
    i_orr(l[0], a[1])
    i_orr(l[1], o)
    #i_mov(o, a[0])
    i_str(l[0], @r[0])
    i_str(l[1], @r[1])

    end_asm()
  end

  def mont_red_sm2(words, total)
    puts <<EOF
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
EOF
    ni_static_func(void, "sp_#{@total}_mont_reduce_#{@namef}#{words}",
                   ["sp_digit*"      , "a" , 1, 32],
                   ["const sp_digit*", "m" , 0, 32],
                   ["sp_digit"       , "mp", 0, 32]
                   )
    puts <<EOF
    (void)mp;
    (void)m;

EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{2*words}, #{2*total});
SP_PRINT_NUM(m, "m", #{@total}, #{words}, #{total});
EOF
    end

    @a = use_param(0)

    ca = use_reg(32)
    zr = use_reg(32)
    mu = use_reg(32)
    t = use_regs(2, 32)
    m0 = use_reg(32)
    m1 = use_reg(32)
    ii = use_reg(32)
    m = [-1, -1, 0, -1, -1, -1, -1, -2]

    start_mod = add_label("L_sp_#{@total}_mont_reduce_#{words}_mod")

    asm()

    # Set zero to 0
    i_mov(zr, 0)
    i_mov(ca, 0)
    puti "# i = 0"
    i_mov(ii, zr)

    set_label(start_mod)
    # Set low previous product to 0
    i_mov(t[0], 0)
    puti "# mu = a[i] * 1 (mp) = a[i]"
    i_ldr(mu, @a[0])

    0.upto(words - 2) do |j|
        puti "# a[i+#{j}] += #{m[j]} * mu"
        i_ldr(m0, @a[j]) if j != 0
        if m[j] == 0
            i_mov(t[1], 0)
            i_add(t[0], m0)
            i_adc(t[1], zr)
        elsif m[j] == -1
            if j == 0
                i_mov(t[1], mu)
            else
                i_mov(t[1], mu)
                i_sub(t[0], mu)
                i_sbc(t[1], zr)
                i_add(t[0], m0)
                i_adc(t[1], zr)
            end
        end
        i_str(t[0], @a[j])
        t = t.rotate
    end

    puti "# a[i+#{words-1}] += #{m[words-1]} * mu"
    i_ldr(m0, @a[words - 1])
    i_ldr(m1, @a[words])
    i_add(t[1], ca, mu)
    i_mov(ca, 0)
    i_adc(ca, zr)
    i_sub(t[0], mu)
    i_sbc(t[1], zr)
    i_sbc(ca, zr)
    i_sub(t[0], mu)
    i_sbc(t[1], zr)
    i_sbc(ca, zr)
    i_add(t[0], m0)
    i_adc(t[1], m1)
    i_adc(ca, zr)
    i_str(t[0], @a[words - 1])
    i_str(t[1], @a[words])
    puti "# i += 1"
    i_mov(m0, 4)
    i_add(ii, m0)
    i_add(@a, 4)
    i_mov(m0, words * 4)
    i_cmp(ii, m0)
    i_blt(start_mod)

    o = ca
    zero = zr
    m7 = mu
    a = [ t[0], t[1], m0, m1 ]

    i_sub(@a, 8 * 4)

    # o is overflow, m7 is 7th word of modulus (1 on overflow, 0 not)
    i_mov(m7, o)
    i_sub(o, 1)
    i_mvn(o, o)
    i_sub(m7, o, m7)

    # Subtract mod (when no overflow values are 0)
    i_ldr(a[0], @a[8])
    i_ldr(a[1], @a[9])
    i_ldr(a[2], @a[10])
    i_ldr(a[3], @a[11])
    i_sub(a[0], o)
    i_sbc(a[1], o)
    i_sbc(a[2], zero)
    i_sbc(a[3], o)
    i_str(a[0], @a[0])
    i_str(a[1], @a[1])
    i_str(a[2], @a[2])
    i_str(a[3], @a[3])
    i_ldr(a[0], @a[12])
    i_ldr(a[1], @a[13])
    i_ldr(a[2], @a[14])
    i_ldr(a[3], @a[15])
    i_sbc(a[0], o)
    i_sbc(a[1], o)
    i_sbc(a[2], o)
    i_sbc(a[3], m7)
    i_str(a[0], @a[4])
    i_str(a[1], @a[5])
    i_str(a[2], @a[6])
    i_str(a[3], @a[7])

    end_asm()
    if false
      puts <<EOF
SP_PRINT_NUM(a, "rr", #{@total}, #{words}, #{total});
EOF
    end
    end_func()
  end
end

