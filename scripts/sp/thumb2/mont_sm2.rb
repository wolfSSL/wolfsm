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

module MontThumb2_SM2

  def add_red_sm2(a, o, t, single=false)
    m = [o, o, 0, o, o, o, o, -2]

    rsb(o, o, 0)
    subs(a[0], a[0], m[0])
    1.upto(@words-2) do |i|
      sbcs(a[i], a[i], m[i])
    end
    sbcs(a[7], a[7], o, LSL_Thumb2.new(1))
    if single
      rsb(o, o, 0)
      sbc(o, o, 0)
    else
      sbc(t, t, t)

      i_sub(o, o, t)
      subs(a[0], a[0], m[0])
      1.upto(@words-2) do |i|
        sbcs(a[i], a[i], m[i])
      end
      sbc(a[7], a[7], o, LSL_Thumb2.new(1))
    end
  end

  def sub_red_sm2(a, o, t)
    m = [o, o, 0, o, o, o, o, -2]

    adds(a[0], a[0], m[0])
    1.upto(@words-2) do |i|
      adcs(a[i], a[i], m[i])
    end
    adcs(a[7], a[7], o, LSL_Thumb2.new(1))
    adc(o, o, 0)

    adds(a[0], a[0], m[0])
    1.upto(@words-2) do |i|
      adcs(a[i], a[i], m[i])
    end
    adc(a[7], a[7], o, LSL_Thumb2.new(1))
  end

  def mont_add_sm2()
    @r = use_param(0)
    @a = use_param(1)
    @b = use_param(2)

    b = [ use_reg(r3), use_reg(r4) ]
    a = [ use_reg(r5), use_reg(r6), use_reg(r7), use_reg(r8),
          use_reg(r9), use_reg(r10), use_reg(r11), use_reg(r12) ]
    o = use_reg(32)

    asm()

    mov(o, 0)
    ldm(@a, a)
    0.step(@words-1, 2) do |j|
      ldmia(@b, b)
      0.upto(1) do |i|
        adds(a[j+i], a[j+i], b[i]) if i + j == 0
        adcs(a[j+i], a[j+i], b[i]) if i + j != 0
      end
    end
    adc(o, o, 0)

    add_red_sm2(a, o, @b)

    stm(@r, a)

    end_asm()
  end

  def mont_dbl_sm2()
    @r = use_param(0)
    @a = use_param(1)

    a = [ use_reg(r4), use_reg(r5), use_reg(r6), use_reg(r7),
          use_reg(r8), use_reg(r9), use_reg(r10), use_reg(r11) ]
    o = use_reg(32)

    asm()

    mov(o, 0)
    ldm(@a, a)
    adds(a[0], a[0], a[0])
    1.upto(@words-1) do |i|
      adcs(a[i], a[i], a[i])
    end
    adc(o, o, 0)

    add_red_sm2(a, o, @a)

    stm(@r, a)

    end_asm()
  end

  def mont_tpl_sm2()
    @r = use_param(0)
    @a = use_param(1)

    a = [ use_reg(r4), use_reg(r5), use_reg(r6), use_reg(r7),
          use_reg(r8), use_reg(r9), use_reg(r10), use_reg(r11) ]
    t = [ use_reg(r2), use_reg(r3) ]
    o = use_reg(32)

    asm()

    mov(o, 0)
    ldm(@a, a)
    adds(a[0], a[0], a[0])
    1.upto(@words-1) do |i|
      adcs(a[i], a[i], a[i])
    end
    adc(o, o, 0)

    add_red_sm2(a, o, t[0])

    0.step(@words-1, 2) do |j|
      ldmia(@a, t)
      0.upto(1) do |i|
        adds(a[j+i], a[j+i], t[i]) if i + j == 0
        adcs(a[j+i], a[j+i], t[i]) if i + j != 0
      end
    end
    adc(o, o, 0)

    add_red_sm2(a, o, t[0])

    stm(@r, a)

    end_asm()
  end

  def mont_sub_sm2()
    @r = use_param(0)
    @a = use_param(1)
    @b = use_param(2)

    b = [ use_reg(r3), use_reg(r4) ]
    a = [ use_reg(r5), use_reg(r6), use_reg(r7), use_reg(r8),
          use_reg(r9), use_reg(r10), use_reg(r11), use_reg(r12) ]
    o = use_reg(32)

    asm()

    mov(o, 0)
    ldm(@a, a)
    0.step(@words-1, 2) do |j|
      ldmia(@b, b)
      0.upto(1) do |i|
        subs(a[j+i], a[j+i], b[i]) if i + j == 0
        sbcs(a[j+i], a[j+i], b[i]) if i + j != 0
      end
    end
    sbc(o, o, 0)

    sub_red_sm2(a, o, @b)

    stm(@r, a)

    end_asm()
  end

  def mont_div2_sm2(words, cpu, debug)
    puts <<EOF
/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
EOF
    static_func(void, "sp_#{@total}_mont_div2_#{@namef}#{words}",
                ["sp_digit*"      , "r", 1, 32],
                ["const sp_digit*", "a", 1, 32],
                ["const sp_digit*", "m", 1, 32]
                )

    @r = use_param(0)
    @a = use_param(1)
    @m = use_param(2)

    a = [ use_reg(r4), use_reg(r5), use_reg(r6), use_reg(r7) ]
    l = [ use_reg(r8), use_reg(r9), use_reg(r10), use_reg(r11) ]
    o = use_reg(32)
    mask = l[0]

    if debug
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{words}, #{total});
SP_PRINT_NUM(m, "m", #{@total}, #{words}, #{total});
EOF
    end

    asm()

    ldm(@a, a)
    i_and(o, a[0], 1)
    rsb(mask, o, 0)

    # m = fffffffe ffffffff ffffffff ffffffff
    #     ffffffff 00000000 ffffffff ffffffff
    adds(a[0], a[0], mask)
    adcs(a[1], a[1], mask)
    adcs(a[2], a[2], 0)
    adcs(a[3], a[3], mask)
    stm(@r, a)

    ldrd(a[0], a[1], @a[4])
    ldrd(a[2], a[3], @a[6])
    # m = fffffffe ffffffff ffffffff ffffffff
    #     ffffffff 00000000 ffffffff ffffffff
    adcs(a[0], a[0], mask)
    adcs(a[1], a[1], mask)
    adcs(a[2], a[2], mask)
    adcs(a[3], a[3], mask, LSL_Thumb2.new(1))
    mov(o, 0)
    adc( o   , o   , 0)

    lsr(l[0], a[0], 1)
    lsr(l[1], a[1], 1)
    lsr(l[2], a[2], 1)
    lsr(l[3], a[3], 1)
    orr(l[0], l[0], a[1], LSL_Thumb2.new(31))
    orr(l[1], l[1], a[2], LSL_Thumb2.new(31))
    orr(l[2], l[2], a[3], LSL_Thumb2.new(31))
    orr(l[3], l[3], o   , LSL_Thumb2.new(31))
    mov(o, a[0])
    strd(l[0], l[1], @r[4])
    strd(l[2], l[3], @r[6])

    ldm(@r, a)
    lsr(l[0], a[0], 1)
    lsr(l[1], a[1], 1)
    lsr(l[2], a[2], 1)
    lsr(l[3], a[3], 1)
    orr(l[0], l[0], a[1], LSL_Thumb2.new(31))
    orr(l[1], l[1], a[2], LSL_Thumb2.new(31))
    orr(l[2], l[2], a[3], LSL_Thumb2.new(31))
    orr(l[3], l[3], o   , LSL_Thumb2.new(31))
    stm(@r, l)

    end_asm()

    if debug
      puts <<EOF
SP_PRINT_NUM(r, "rd2", #{@total}, #{words}, #{total});
EOF
    end

    end_func
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
    sp_ni_static_func(void, "sp_#{@total}_mont_reduce_#{@namef}#{words}",
                      ["sp_digit*"      , "a" , 1, 32],
                      ["const sp_digit*", "m" , 0, 32],
                      ["sp_digit"       , "mp", 0, 32]
                      )

    @a = use_param(0)

    a = [ use_reg(r1), use_reg(r2), use_reg(r3), use_reg(r4),
          use_reg(r5), use_reg(r6), use_reg(r7), use_reg(r8),
          use_reg(r9), use_reg(r10), use_reg(r11), use_reg(r12),
          use_reg(lr) ]

    stack = use_stack(17, 32)
    rsp = stack[16]

    debug = false

    if debug
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{2*words}, #{2*total});
SP_PRINT_NUM(m, "m", #{@total}, #{words}, #{total});

EOF
    end

    asm()

    str(@a, rsp)

    mov(lr, stack)
    ldm(@a.postAdd, a[0..7])
    stm(lr.postAdd, a[0..7])
    ldm(@a, a[0..7])
    stm(lr, a[0..7])

    r = do_mont_red_sm2(words, stack, stack, a[0], a[1], r12)

    ldr(@a, rsp)
    stm(@a, r)

    end_asm()

    if debug
      puts <<EOF

SP_PRINT_NUM(a, "rr", #{@total}, #{words}, #{total});
fprintf(stderr, "mp=%d\\n", mp);
EOF
    end
    puts <<EOF
}

EOF
  end

  def mont_mul_sm2_umaal(words)
    puts <<EOF
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
EOF
    sp_ni_static_func(void, "sp_#{@total}_mont_mul_#{@namef}#{@words}",
                ["sp_digit*"      , "r" , 1, 32],
                ["const sp_digit*", "a" , 1, 32],
                ["const sp_digit*", "b" , 1, 32],
                ["const sp_digit*", "m" , 0, 32],
                ["sp_digit"       , "mp", 0, 32]
                )

    @r = use_param(0)
    @a = use_param(1)
    @b = use_param(2)

    ar = [ @r, @a, @b, use_reg(r3) ] * 2
    br = [ use_reg(r4), use_reg(r5), use_reg(r6), r4 ]
    rr = [ use_reg(r10), use_reg(r11), use_reg(r12),
           use_reg(r7), use_reg(r8), use_reg(r9), r10, r11 ]

    t = ar[0..3] + br[0..2] + rr[3..7] + rr[2..2]

    b = use_reg(lr)
    r = b

    rs = use_stack(19, 32)
    ts = stack[16]
    rsp = stack[17]
    as = stack[18]

    debug = false

    if debug
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(b, "b", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(m, "m", #{@total}, #{@words}, #{@total});

EOF
    end

    asm()

    strd(@r, @a, rsp)
    mov(b, @b)

    (tt, rr8) = do_mul_fast_8_umaal(@a, ar, b, br, rr, t, rs, ts, as)

    mov(tt, rr8)

    rr = t[3..10]
    i_add(r, rs, 8 * 4)
    stm(r, rr[0..7])

    r = do_mont_red_sm2(words, rs, rs, @a, @b, t[12])

    # Store result
    ldr(@r, rsp)
    stm(@r, r)

    end_asm()

    if debug
      puts <<EOF

SP_PRINT_NUM(r, "rm", #{@total}, #{@words}, #{@total});
fprintf(stderr, "c=0x%x\\n", (unsigned int)b);
EOF
    end

    end_func()
  end

  def mont_mul_sm2_umlal(words)
    puts <<EOF
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
EOF
    sp_ni_static_func(void, "sp_#{@total}_mont_mul_#{@namef}#{@words}",
                ["sp_digit*"      , "r" , 1, 32],
                ["const sp_digit*", "a" , 1, 32],
                ["const sp_digit*", "b" , 1, 32],
                ["const sp_digit*", "m" , 0, 32],
                ["sp_digit"       , "mp", 0, 32]
                )

    @r = use_param(0)
    @a = use_param(1)
    @b = use_param(2)

    rr = [ use_reg(r3), use_reg(r4), use_reg(r5), use_reg(r6),
           use_reg(r7), use_reg(r8), use_reg(r9), use_reg(r10) ] * 2
    hi = use_reg(r11)
    ar = use_reg(r12)
    br = use_reg(lr)
    zero = @r

    stack = use_stack(17, 32)
    rsp = stack[16]

    debug = false

    if debug
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(b, "b", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(m, "m", #{@total}, #{@words}, #{@total});

EOF
    end

    asm()

    str(@r, rsp)

    do_mul_fast_8_umlal(@a, ar, @b, br, rr, hi, zero, stack)

    # Store top 8 words of result on stack
    i_add(br, sp, 8 * 4)
    stm(br, rr[0..7])

    r = do_mont_red_sm2(words, stack, stack, @a, @b, r12)

    # Store result
    ldr(@r, rsp)
    stm(@r, r[0..7])

    end_asm()

    if debug
      puts <<EOF

SP_PRINT_NUM(r, "rm", #{@total}, #{@words}, #{@total});
fprintf(stderr, "c=0x%x\\n", (unsigned int)b);
EOF
    end

    end_func()
  end

  def mont_mul_sm2(words)
    puts "#ifdef WOLFSSL_SP_NO_UMAAL"
    mont_mul_sm2_umlal(words)
    puts "#else"
    mont_mul_sm2_umaal(words)
    puts "#endif"
  end

  def mont_sqr_sm2_umaal(words)
    puts <<EOF
/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
EOF
    sp_ni_static_func(void, "sp_#{@total}_mont_sqr_#{@namef}#{@words}",
                ["sp_digit*"      , "r" , 1, 32],
                ["const sp_digit*", "a" , 1, 32],
                ["const sp_digit*", "m" , 0, 32],
                ["sp_digit"       , "mp", 0, 32]
                )

    @r = use_param(0)
    @a = use_param(1)

    t = [ @r, @a, use_reg(r2), use_reg(r3), use_reg(r4), use_reg(r5),
          use_reg(r6), use_reg(r7), use_reg(r8), use_reg(r9), use_reg(r10),
          use_reg(r11), use_reg(r12) ]
    zero = use_reg(lr)

    ar = t[0..7]
    tr = t[8..12]
    rs = use_stack(17, 32)
    rsp = rs[16]

    rr = tr[1..4] + [ tr[0] ] + ar[0..7]
    # r0 | r12, r11, r10, r3, r4, r8, r9, r7

    debug = false

    if debug
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(m, "m", #{@total}, #{@words}, #{@total});

EOF
    end

    asm()

    str(@r, rsp)

    ldm(@a, ar[0..7])

    do_sqr_fast_8_umaal(ar, tr, rr, zero, rs)
    r = zero
    mov(r, sp)
    i_add(r, r, 7 * 4)
    stm(r.postAdd, rr[5..5] + rr[3..3])
    stm(r.postAdd, rr[2..2])
    stm(r.postAdd, rr[1..1])
    stm(r.postAdd, rr[8..9] + rr[4..4] + rr[0..0])
    stm(r.postAdd, rr[12..12])

    r = do_mont_red_sm2(words, sp, sp, @a, t[2], t[12])

    # Store result
    ldr(@r, rsp)
    stm(@r, r[0..7])

    end_asm()

    if debug
      puts <<EOF

SP_PRINT_NUM(r, "rs", #{@total}, #{@words}, #{@total});
EOF
    end

    end_func()
  end

  def mont_sqr_sm2_umlal(words)
    puts <<EOF
/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
EOF
    sp_ni_static_func(void, "sp_#{@total}_mont_sqr_#{@namef}#{@words}",
                ["sp_digit*"      , "r" , 1, 32],
                ["const sp_digit*", "a" , 1, 32],
                ["const sp_digit*", "m" , 0, 32],
                ["sp_digit"       , "mp", 0, 32]
                )

    @r = use_param(0)
    @a = use_param(1)

    c = use_reg(r2)
    rr = [ use_reg(r3), use_reg(r4), use_reg(r5), use_reg(r6),
           use_reg(r7), use_reg(r8), use_reg(r9), use_reg(r10) ] * 2
    hi = use_reg(r11)
    ar = use_reg(r12)
    br = use_reg(lr)
    zero = @r

    stack = use_stack(17, 32)
    rsp = stack[16]

    debug = false

    if debug
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(m, "m", #{@total}, #{@words}, #{@total});

EOF
    end

    asm()

    str(@r, rsp)

    do_sqr_fast_8_umlal(@a, ar, br, rr, hi, zero, stack)

    i_add(br, stack, 8 * 4)
    stm(br, rr[0..7])

    r = do_mont_red_sm2(words, stack, stack, @a, c, r12)

    # Store result
    ldr(@r, rsp)
    stm(@r, r[0..7])

    end_asm()

    if debug
      puts <<EOF

SP_PRINT_NUM(r, "rs", #{@total}, #{@words}, #{@total});
EOF
    end

    end_func()
  end

  def mont_sqr_sm2(words)
    puts "#ifdef WOLFSSL_SP_NO_UMAAL"
    mont_sqr_sm2_umlal(words)
    puts "#else"
    mont_sqr_sm2_umaal(words)
    puts "#endif"
  end

  def do_mont_red_sm2(words, tmp, out, t1, t2, t3)
    c = lr
    t = [r5, r6, r7, r8, r9, r10, r11, r12]
    r = [r0, r1, r2, r3, r4] + t
    m = [c, c, 0, c, c, c, c, -2]
    p = r0

    commenta "Start Reduction"
    ldm(out, t[0..7])
    mov(r[3], t[6])
    mov(r[4], t[7])

    # mu = a[0..7] * mp
    # mp = 0xfffffffc00000001fffffffe00000000ffffffff000000010000000000000001
    # mp = 1 + (1 << 64) - (1 << 96) + (1 << 128) - (2 << 160) + (2 << 192) -
    #      (4 << 224)
    commenta "mu = a[0..7] + a[0..5] << 64 - a[0..4] << 96"
    commenta "   + a[0..3] << 128 - (a[0..2] * 2) << 160"
    commenta "   + (a[0..1] * 2) << 192 - (a[0..0] * 4) << 224"

    commenta "   - (a[0..0] * 4) << (7 * 32)"
    i_sub( t[7], t[7], t[0], LSL_Thumb2.new(2))
    commenta "   + (a[0..1] * 2) << (6 * 32)"
    adds(t[6], t[6], t[0], LSL_Thumb2.new(1))
    mov(r[2], t[5])
    adc( t[7], t[7], t[1], LSL_Thumb2.new(1))
    i_add( t[7], t[7], t[0], LSR_Thumb2.new(31))
    commenta "   - (a[0..2] * 2) << (5 * 32)"
    subs(t[5], t[5], t[0], LSL_Thumb2.new(1))
    sbcs(t[6], t[6], t[1], LSL_Thumb2.new(1))
    sbc( t[7], t[7], t[2], LSL_Thumb2.new(1))
    subs(t[6], t[6], t[0], LSR_Thumb2.new(31))
    mov(r[1], t[4])
    sbc( t[7], t[7], t[1], LSR_Thumb2.new(31))
    commenta "   + a[0..3] << (4 * 32)"
    adds(t[4], t[4], t[0])
    adcs(t[5], t[5], t[1])
    adcs(t[6], t[6], t[2])
    mov(r[0], t[3])
    adc( t[7], t[7], t[3])
    commenta "   - a[0..4] << (3 * 32)"
    subs(t[3], t[3], t[0])
    sbcs(t[4], t[4], t[1])
    sbcs(t[5], t[5], t[2])
    sbcs(t[6], t[6], r[0])
    mov(c, t[2])
    sbc( t[7], t[7], r[1])
    commenta "   + a[0..5] << (2 * 32)"
    adds(t[2], t[2], t[0])
    adcs(t[3], t[3], t[1])
    adcs(t[4], t[4], c)
    adcs(t[5], t[5], r[0])
    adcs(t[6], t[6], r[1])
    adc( t[7], t[7], r[2])

    commenta "a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu"

    commenta "a[0]   =              = t[0]"
    commenta "a[1]   =              = t[1]"
    commenta "a[2]  +=         t[0] = t[2]"
    commenta "a[3]  +=         t[1] = t[3] + t[0]"
    commenta "a[4]  +=         t[2] = t[4] + t[1]"
    commenta "a[5]  +=         t[3] = t[5] + t[2]"
    commenta "a[6]  +=         t[4] = t[6] + t[3]"
    commenta "a[7]  +=         t[5] = t[7] + t[4] + t[0]"
    adds(   c,    c, t[0])
    adcs(r[0], r[0], t[1])
    adcs(r[1], r[1], t[2])
    adcs(r[2], r[2], t[3])
    adcs(r[3], r[3], t[4])
    adcs(r[4], r[4], t[5])
    # Store out[3..7]
    i_add(c, out, 3 * 4)
    stm(c, r[0..4])

    commenta "a[8]  +=  t[0] + t[6] = r[0] + t[5] + t[1]"
    commenta "a[9]  +=  t[1] + t[7] = r[1] + t[6] + t[2]"
    commenta "a[10] +=  t[2]        = r[2] + t[7] + t[3]"
    commenta "a[11] +=  t[3]        = r[3] +        t[4]"
    # Load out[8..11]
    i_add(r[0], out, 8 * 4)
    ldm(r[0], r[1..4])
    adcs(r[1], r[1], t[0])
    adcs(r[2], r[2], t[1])
    adcs(r[3], r[3], t[2])
    adcs(r[4], r[4], t[3])
    mov(c, 0)
    adc(c, c, 0)
    adds(r[1], r[1], t[6])
    adcs(r[2], r[2], t[7])
    adcs(r[3], r[3], 0)
    adcs(r[4], r[4], 0)
    adc(c, c, 0)
    # Store out[8..11]
    stm(r[0], r[1..4])

    commenta "a[12] +=  t[4]        = r[4] +        t[5]"
    commenta "a[13] +=  t[5]        = r[5] +        t[6]"
    commenta "a[14] +=  t[6]        = r[6] +        t[7]"
    commenta "a[15] +=  t[7]        = r[7]"
    # Load out[11..15]
    i_add(r[0], out, 12 * 4)
    ldm(r[0], r[1..4])
    adds(c, c, -1)
    adcs(r[1], r[1], t[4])
    adcs(r[2], r[2], t[5])
    adcs(r[3], r[3], t[6])
    adcs(r[4], r[4], t[7])
    mov(c, 0)
    adc(c, c, 0)
    # Store out[11..15] and carry
    stm(r[0], r[1..4])
    str(c, out[1])

    commenta "a[3]  += -t[0]        = t[3]"
    commenta "a[4]  += -t[1]        = t[4]"
    commenta "a[5]  += -t[2]        = t[5]"
    commenta "a[6]  += -t[3]        = t[6]"
    # Load out[3..6]
    i_add(r[0], out, 3 * 4)
    ldm(r[0], r[0..3])
    subs(r[0], r[0], t[0])
    sbcs(r[1], r[1], t[1])
    sbcs(r[2], r[2], t[2])
    sbcs(r[3], r[3], t[3])
    # out[3..6] not needed

    commenta "a[7]  += -t[4] - t[0] = t[7]"
    commenta "a[8]  += -t[5] - t[1] = r[0]"
    commenta "a[9]  += -t[6] - t[2] = r[1]"
    commenta "a[10] += -t[7] - t[3] = r[2]"
    # Load out[7..10]
    i_add(r[0], out, 7 * 4)
    ldm(r[0], r[0..3])
    sbcs(r[0], r[0], t[4])
    sbcs(r[1], r[1], t[5])
    sbcs(r[2], r[2], t[6])
    sbcs(r[3], r[3], t[7])
    mov(c, 0)
    sbc(c, c, 0)
    subs(r[0], r[0], t[0])
    sbcs(r[1], r[1], t[1])
    sbcs(r[2], r[2], t[2])
    sbcs(r[3], r[3], t[3])
    sbc(c, c, 0)
    # out[7] not needed, out[8..10] kept in regs

    commenta "a[11] +=       - t[4] = r[3]"
    commenta "a[12] +=       - t[5] = r[4]"
    commenta "a[13] +=       - t[6] = r[5]"
    commenta "a[14] +=       - t[7] = r[6]"
    commenta "a[15] +=              = r[7]"
    # Load out[11..15]
    i_add(r[0], out, 11 * 4)
    ldm(r[0], r[4..8])
    rsb(c, c, 0)
    subs(r[4], r[4], c)
    sbcs(r[5], r[5], 0)
    sbcs(r[6], r[6], 0)
    sbcs(r[7], r[7], 0)
    sbcs(r[8], r[8], 0)
    mov(c, 0)
    sbc(c, c, 0)
    subs(r[4], r[4], t[4])
    sbcs(r[5], r[5], t[5])
    sbcs(r[6], r[6], t[6])
    sbcs(r[7], r[7], t[7])
    sbcs(r[8], r[8], 0)
    ldr(r[0], out[1])
    sbc(c, c, 0)
    i_add(c, c, r[0])
    # out[11..15] kept in regs

    r = r[1..-1]
    commenta "mask m and sub from result if overflow"
    rsb(c, c, 0)
    subs(r[0], r[0], m[0])
    sbcs(r[1], r[1], m[1])
    sbcs(r[2], r[2], m[2])
    sbcs(r[3], r[3], m[3])
    sbcs(r[4], r[4], m[4])
    sbcs(r[5], r[5], m[5])
    sbcs(r[6], r[6], m[6])
    sbc( r[7], r[7], c, LSL_Thumb2.new(1))

    r[0..7]
  end
end

