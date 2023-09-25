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

module MontX86_64_SM2
  def add_red_sm2(r, ar, mr, o, twice=true)
    andq(o, mr[1])
    andq(o, mr[3])
    subq(o, ar[0])
    sbbq(mr[1], ar[1])
    sbbq(o, ar[2])
    sbbq(mr[3], ar[3])
    adcq(0, o)

    if twice
      andq(o, mr[1])
      andq(o, mr[3])
      subq(o, ar[0])
      sbbq(mr[1], ar[1])
      movq(ar[0], r[0]) if r
      sbbq(o, ar[2])
      movq(ar[1], r[1]) if r
      sbbq(mr[3], ar[3])
      movq(ar[2], r[2]) if r
      movq(ar[3], r[3]) if r
    end
  end

  def sub_red_sm2(r, ar, mr, o, twice=true)
    andq(o, mr[1])
    andq(o, mr[3])
    addq(o, ar[0])
    adcq(mr[1], ar[1])
    adcq(o, ar[2])
    adcq(mr[3], ar[3])
    adcq(0, o)

    if twice
      andq(o, mr[1])
      andq(o, mr[3])
      addq(o, ar[0])
      adcq(mr[1], ar[1])
      movq(ar[0], r[0]) if r
      adcq(o, ar[2])
      movq(ar[1], r[1]) if r
      adcq(mr[3], ar[3])
      movq(ar[2], r[2]) if r
      movq(ar[3], r[3]) if r
    end
  end

  def mont_add_sm2()
    puta "\
/* Add two Montgomery form numbers (r = a + b % m).
 *
 * r   Result of addition.
 * a   First number to add in Montgomery form.
 * b   Second number to add in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_add_#{@namef}#{@words}",
                ["sp_digit*", "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["const sp_digit*", "b", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    b = use_param(2)
    a = use_param(1)
    r = use_param(0)
    ar = use_regs(4, 64)
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = a

    asm()

    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end

    addq(b[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    adcq(b[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(b[2], ar[2])
    adcq(b[3], ar[3])
    sbbq(o, o)

    add_red_sm2(r, ar, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_dbl_sm2()
    puta "\
/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_dbl_#{@namef}#{@words}",
                ["sp_digit*", "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    a = use_param(1)
    r = use_param(0)
    ar = use_regs(4, 64)
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = use_reg(64)

    asm()

    # Load a
    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end

    # Double a
    addq(ar[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    adcq(ar[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(ar[2], ar[2])
    movq(ar[3], o)
    adcq(ar[3], ar[3])
    sarq(63, o)

    add_red_sm2(r, ar, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_tpl_sm2()
    puta "\
/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_tpl_#{@namef}#{@words}",
                ["sp_digit*", "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    a = use_param(1)
    r = use_param(0)
    ar = use_regs(4, 64)
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = use_reg(64)

    asm()

    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end
    addq(ar[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    adcq(ar[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(ar[2], ar[2])
    adcq(ar[3], ar[3])
    sbbq(o, o)

    add_red_sm2(nil, ar, mr, o)

    addq(a[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    adcq(a[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(a[2], ar[2])
    adcq(a[3], ar[3])
    sbbq(0, o)

    add_red_sm2(r, ar, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_sub_sm2()
    puta "\
/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_sub_#{@namef}#{@words}",
                ["sp_digit*", "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["const sp_digit*", "b", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    b = use_param(2)
    a = use_param(1)
    r = use_param(0)
    ar = [use_reg(64), use_reg(64), use_reg(64), use_reg(64)]
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = a

    asm()

    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end

    subq(b[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    sbbq(b[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    sbbq(b[2], ar[2])
    sbbq(b[3], ar[3])
    sbbq(o, o)

    sub_red_sm2(r, ar, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_rsb_sub_dbl_sm2()
    puta "\
/* Two Montgomery numbers, subtract double second from first (r = a - 2.b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to double and subtract with in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_rsb_sub_dbl_#{@namef}#{@words}",
                ["sp_digit*"      , "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["sp_digit*"      , "b", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    (r, a, b) = use_params(3)
    ar = use_regs(4, 64)
    br = use_regs(4, 64)
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = a

    asm()

    # Load a
    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end
    # Load b
    0.upto(@words-1) do |i|
      movq(b[i], br[i])
    end

    # Double b
    addq(br[0], br[0])
      movq(0xffffffff00000000, mr[1])
    adcq(br[1], br[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(br[2], br[2])
    adcq(br[3], br[3])
    sbbq(o, o)

    add_red_sm2(nil, br, mr, o)

    # Subtract 2.b from a
    subq(br[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    sbbq(br[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    sbbq(br[2], ar[2])
    sbbq(br[3], ar[3])
    sbbq(0, o)

    sub_red_sm2(r, ar, mr, o)

    # Load b
    0.upto(@words-1) do |i|
      movq(b[i], br[i])
    end

    # Subtract a - 2.b from b
    subq(ar[0], br[0])
      movq(0xffffffff00000000, mr[1])
    sbbq(ar[1], br[1])
      movq(0xfffffffeffffffff, mr[3])
    sbbq(ar[2], br[2])
    sbbq(ar[3], br[3])
    sbbq(o, o)

    sub_red_sm2(b, br, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_sub_dbl_sm2()
    puta "\
/* Two Montgomery numbers, subtract double second from first (r = a - 2.b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to double and subtract with in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_sub_dbl_#{@namef}#{@words}",
                ["sp_digit*", "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["const sp_digit*", "b", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    b = use_param(2)
    a = use_param(1)
    r = use_param(0)
    ar = use_regs(4, 64)
    br = use_regs(4, 64)
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = b

    asm()

    # Load a
    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end
    # Load b
    0.upto(@words-1) do |i|
      movq(b[i], br[i])
    end

    # Double b
    addq(br[0], br[0])
      movq(0xffffffff00000000, mr[1])
    adcq(br[1], br[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(br[2], br[2])
    adcq(br[3], br[3])
    sbbq(o, o)

    add_red_sm2(nil, br, mr, o)

    # Subtract 2.b from a
    subq(br[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    sbbq(br[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    sbbq(br[2], ar[2])
    sbbq(br[3], ar[3])
    sbbq(o, o)

    sub_red_sm2(r, ar, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_dbl_sub_sm2()
    puta "\
/* Two Montgomery numbers, subtract second from first and double.
 * (r = 2.(a - b) % m).
 *
 * b must have came from a mont_sub operation.
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */"
    static_func(void, "sp_#{@total}_mont_dbl_sub_#{@namef}#{@words}",
                ["sp_digit*", "r", 1, 64],
                ["const sp_digit*", "a", 1, 64],
                ["const sp_digit*", "b", 1, 64],
                ["const sp_digit*", "m", 0, 64])

    b = use_param(2)
    a = use_param(1)
    r = use_param(0)
    ar = use_regs(4, 64)
    mr = [-1, use_reg(64), 0, use_reg(64)]
    o = b

    asm()

    # Load a
    0.upto(@words-1) do |i|
      movq(a[i], ar[i])
    end

    # Subtract b from a
    subq(b[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    sbbq(b[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    sbbq(b[2], ar[2])
    sbbq(b[3], ar[3])
    sbbq(o, o)

    # Note that b must have been the result of a mont_sub operation!
    sub_red_sm2(nil, ar, mr, o)

    # Double result
    addq(ar[0], ar[0])
      movq(0xffffffff00000000, mr[1])
    adcq(ar[1], ar[1])
      movq(0xfffffffeffffffff, mr[3])
    adcq(ar[2], ar[2])
    adcq(ar[3], ar[3])
    sbbq(o, o)

    add_red_sm2(r, ar, mr, o)

    end_asm(true)
    end_func()
  end

  def mont_div2_sm2()
    a = use_param(1)
    r = use_param(0)

    ar = use_regs(4, 64)
    mr = [ -1, use_reg(64), 0, use_reg(64) ]
    o = use_reg(64)
    mask = o

    asm()

    movq(a[0], ar[0])
    movq(a[1], ar[1])
    movq(a[2], ar[2])
    movq(a[3], ar[3])
    movq(0xffffffff00000000, mr[1])
    movq(0xfffffffeffffffff, mr[3])
    movq(ar[0], mask)
    andq(1, mask)
    negq(mask)

    andq(mask, mr[1])
    andq(mask, mr[3])
    addq(mask, ar[0])
    adcq(mr[1], ar[1])
    adcq(mask, ar[2])
    adcq(mr[3], ar[3])
    movq(0, o)
    adcq(0, o)

    shrdq(1, ar[1], ar[0])
    shrdq(1, ar[2], ar[1])
    shrdq(1, ar[3], ar[2])
    shrdq(1, o, ar[3])
    movq(ar[0], r[0])
    movq(ar[1], r[1])
    movq(ar[2], r[2])
    movq(ar[3], r[3])

    end_asm(true)
    end_func()
  end

  def mont_red_avx2_sm2(words, total)
    ifdefa("HAVE_INTEL_AVX2")
    puta "\
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */"
    ni_static_func(void, "sp_#{@total}_mont_reduce_order_avx2_#{@namef}#{words}",
                   ["sp_digit*", "a" , 1, 64],
                   ["const sp_digit*", "m" , 1, 64],
                   ["sp_digit" , "mp", 1, 64])

    m0 = use_reg(r8)
    m1 = use_reg(r9)
    m2 = use_reg(rcx)
    mu = use_reg(rdx)
    (a, m, mp) = use_params(3)
    zero = use_reg(64)
    ca = use_reg(64)

    sa = use_regs(words+1, 64)
    sm = [m0, m1, ca, mu]

    asm()
    movq(a[0], sa[0])
    movq(a[1], sa[1])
    movq(a[2], sa[2])
    movq(a[3], sa[3])
    xorq(ca, ca)
    xorq(zero, zero)

    0.upto(words-1) do |i|
      commenta "a[#{i}-#{i+4}] += m[0-3] * mu = m[0-3] * (a[#{i}] * mp)"
      movq(a[4 + i], sa[4])
      commenta "  mu = a[#{i}] * mp"
      movq(sa[0], mu)
      mulxq(mp, mu, m2)
      commenta "  a[#{i + 0}] += m[0] * mu"
      mulx(m[0], m0, m1)
      adcxq(m0, sa[0])
      commenta "  a[#{i + 1}] += m[1] * mu"
      mulx(m[1], m0, m2)
      adoxq(m1, sa[1])
      adcxq(m0, sa[1])
      commenta "  a[#{i + 2}] += m[2] * mu"
      mulx(m[2], m0, m1)
      adoxq(m2, sa[2])
      adcxq(m0, sa[2])
      commenta "  a[#{i + 3}] += m[3] * mu"
      mulx(m[3], m0, m2)
      adoxq(m1, sa[3])
      adcxq(m0, sa[3])
      commenta "  a[#{i + 4}] += carry"
      adoxq(m2, sa[4])
      if i == 0
        adcxq(zero, sa[4])
      else
        adcxq(ca, sa[4])
        movq(zero, ca)
      end
      commenta "  carry"
      adoxq(zero, ca)
      adcxq(zero, ca)

      sa = sa.rotate
    end

    commenta "Subtract mod if carry"
    negq(ca)
    movq(@order[0..63], sm[0])
    movq(@order[64..127], sm[1])
    #movq(@order[128..191], sm[2]) # sm[2] = ca
    movq(@order[192..255], sm[3])
    andq(ca, sm[0])
    andq(ca, sm[1])
    #movq(ca, sm[2])
    andq(ca, sm[3])
    subq(sm[0], sa[0])
    sbbq(sm[1], sa[1])
    sbbq(sm[2], sa[2])
    sbbq(sm[3], sa[3])
    movq(sa[0], a[0])
    movq(sa[1], a[1])
    movq(sa[2], a[2])
    movq(sa[3], a[3])

    end_asm(true)
    end_func()
    endifa "HAVE_INTEL_AVX2"
  end

  def mont_red_sm2(words, total)
    puta "\
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */"
    ni_static_func(void, "sp_#{@total}_mont_reduce_#{@namef}#{words}",
                   ["sp_digit*", "a" , 1, 64],
                   ["const sp_digit*", "m" , 1, 64],
                   ["sp_digit" , "mp", 1, 64])

    t0 = use_reg(rax)
    t1 = use_reg(rbx)
    t2 = use_reg(rcx)
    t3 = use_reg(rdx)
    t4 = use_reg(rsi)
    a = use_param(0)
    ar = use_regs(words * 2, 64)

    asm()

    0.upto(words*2-1) do |i|
      movq(a[i], ar[i])
    end

    do_mont_red_sm2(words, ar, t2, t1, t4, a, t0, true)

    end_asm(true)
    end_func()
  end

  def mont_mul_sm2(words)
    puta "\
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */"
    ni_static_func(void, "sp_#{@total}_mont_mul_#{@namef}#{@words}",
                   ["sp_digit*", "r" , 1, 64],
                   ["const sp_digit*", "a" , 2, 64],
                   ["const sp_digit*", "b" , 2, 64],
                   ["const sp_digit*", "m" , 2, 64],
                   ["sp_digit" , "mp", 0, 64])

    m0 = use_reg(rax)
    m1 = use_reg(rdx)
    (r, a, b, m) = use_params(4)
    out = use_regs(words * 2, 64)
    t0 = out[6]
    t1 = out[7]
    t2 = out[5]

    asm()
    o = []
    c = []
    0.upto(words * 2 - 1) do |k|
      0.upto(words - 1) do |i|
        j = k - i
        next if j < 0
        next if j >= words
        mul_op(i, j, a, b, c, o, out)
      end
    end

    do_mont_red_sm2(words, out, b, a, m, r, m0, true)

    end_asm(true)
    end_func
  end

  def mont_mul_avx2_sm2(words)
    ifdefa("HAVE_INTEL_AVX2")
    puta "\
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */"
    ni_static_func(void, "sp_#{@total}_mont_mul_avx2_#{@namef}#{@words}",
                   ["sp_digit*", "r" , 1, 64],
                   ["const sp_digit*", "a" , 2, 64],
                   ["const sp_digit*", "b" , 2, 64],
                   ["const sp_digit*", "m" , 0, 64],
                   ["sp_digit" , "mp", 0, 64])

    (rr, b, a, m, r, m0, m1) = do_mul_avx2_4()

    do_mont_red_sm2(words, rr, b, a, m, r, m0, true)

    end_asm(true)
    end_func()
    endifa("HAVE_INTEL_AVX2")
  end

  def mont_sqr_sm2(words)
    puta "\
/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */"
    ni_static_func(void, "sp_#{@total}_mont_sqr_#{@namef}#{@words}",
                   ["sp_digit*", "r" , 1, 64],
                   ["const sp_digit*", "a" , 2, 64],
                   ["const sp_digit*", "m" , 0, 64],
                   ["sp_digit" , "mp", 0, 64])

    m0 = use_reg(rax)
    m1 = use_reg(rdx)
    (r, a) = use_params(2)
    m = use_reg(64)
    out = use_regs(8, 64)
    t = out[7]
    mp = use_reg(64)

    asm()
    o = []
    c = []
    sqr_op(0, 1, a, c, o, out)
    sqr_op(0, 2, a, c, o, out)
    sqr_op(0, 3, a, c, o, out)
    sqr_op(1, 2, a, c, o, out)
    sqr_op(1, 3, a, c, o, out)
    sqr_op(2, 3, a, c, o, out)

    commenta "Double"
    xorq(t, t)
    addq(out[1], out[1])
    2.upto(2*words-2) do |i|
      adcq(out[i], out[i])
    end
    adcq(0, out[2*words-1])

    out2 = [ rax, rdx, rax, rdx, rax, rdx, rax, rdx ]
    o2 = [ nil, nil, nil, nil, nil, nil, nil, nil ]
    c2 = []
    sqr_op(0, 0, a, c2, o2, out2)
    movq(rax, out[0])
    movq(rdx, mp)
    sqr_op(1, 1, a, c2, o2, out2)
    addq(mp, out[1])
    adcq(rax, out[2])
    adcq(0, rdx)
    movq(rdx, mp)
    sqr_op(2, 2, a, c2, o2, out2)
    addq(mp, out[3])
    adcq(rax, out[4])
    adcq(0, rdx)
    movq(rdx, mp)
    sqr_op(3, 3, a, c2, o2, out2)
    addq(mp, out[5])
    adcq(rax, out[6])
    adcq(rdx, out[7])

    do_mont_red_sm2(words, out, mp, a, m, r, m0, true)

    end_asm(true)
    end_func()
  end

  def mont_sqr_avx2_sm2(words)
    ifdefa("HAVE_INTEL_AVX2")
    puta "\
/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */"
    ni_static_func(void, "sp_#{@total}_mont_sqr_avx2_#{@namef}#{@words}",
                   ["sp_digit*", "r" , 1, 64],
                   ["const sp_digit*", "a" , 2, 64],
                   ["const sp_digit*", "m" , 0, 64],
                   ["sp_digit" , "mp", 0, 64])

    (rr, mxo, r, a, m0, m1) = do_sqr_avx2_4()

    do_mont_red_sm2(words, rr, mxo[1][0], a, mxo[1][1], r, m0, true)

    end_asm(true)
    end_func
    endifa("HAVE_INTEL_AVX2")
  end

  def do_mont_red_sm2(words, rr, reg, ap, mp, r, t0, xor)
    t = [ rax, ap, reg, rdx, mp ]
    m = [-1, t[0], -1, t[1]]
    a = rr
    c = a[0]

    # mod = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    #     = 1 << 256 - 1 << 224 - 1 << 96 + 1 << 64 - 1
    commenta "Start Reduction"
    # mu = a[0..3] * mp
    # mp = 1 + (1 << 64) - (1 << 96) + (1 << 128) - (2 << 160) + (2 << 192) -
    #      (4 << 224)

    commenta "mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64"
    commenta "   + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128"
    commenta "   + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192"

    commenta "mu = a[0..3]"
    movq(rr[3], t[3])
    commenta "  + (a[0..0] * 2) << 192"
    addq(a[0], t[3])
    movq(rr[2], t[2])
    addq(a[0], t[3])
    commenta "  + a[0..1) << 128"
    addq(a[0], t[2])
    movq(rr[1], t[1])
    adcq(a[1], t[3])
    commenta "  + a[0..2] << 64"
    addq(a[0], t[1])
    movq(rr[0], t[0])
    adcq(a[1], t[2])
    adcq(a[2], t[3])
    commenta "  a[0..2] << 32"
    shlq(32, a[0])
    shldq(32, a[1], a[2])
    shldq(32, t[0], a[1])
    commenta "  - (a[0..1] * 2) << 32 << 128"
    subq(a[0], t[2])
    sbbq(a[1], t[3])
    subq(a[0], t[2])
    sbbq(a[1], t[3])
    commenta "  - a[0..2] << 32 << 64"
    subq(a[0], t[1])
    sbbq(a[1], t[2])
    sbbq(a[2], t[3])
    commenta "  - (a[0..0] * 4) << 32 << 192"
    movq(a[0], a[2])
    shlq(2, a[2])
    subq(a[2], t[3])

    # a += mu * m
    # a += mu * ((1 << 256) - (1 << 224) - (1 << 96) + (1 << 64) - 1)
    commenta "a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu"
    commenta "  a += mu << 256"
    xorq(c, c) if xor
    addq(t[0], a[4])
    adcq(t[1], a[5])
    adcq(t[2], a[6])
    movq(0, c) if not xor
    adcq(t[3], a[7])
    sbbq(0, c)
    commenta "  a += mu << 64"
    #addq(t[0], a[1])
    #adcq(t[1], a[2])
    addq(t[2], a[3])
    adcq(t[3], a[4])
    adcq(0, a[5])
    adcq(0, a[6])
    adcq(0, a[7])
    sbbq(0, c)
    commenta "mu <<= 32"
    movq(t[3], t[4])
    shldq(32, t[2], t[3])
    shldq(32, t[1], t[2])
    shldq(32, t[0], t[1])
    shrq(32, t[4])
    shlq(32, t[0])
    commenta "  a -= (mu << 32) << 64"
    #subq(t[0], a[1])
    #sbbq(t[1], a[2])
    subq(t[2], a[3])
    sbbq(t[3], a[4])
    sbbq(t[4], a[5])
    sbbq(0, a[6])
    sbbq(0, a[7])
    adcq(0, c)
    commenta "  a -= (mu << 32) << 192"
    subq(t[0], a[3])
    sbbq(t[1], a[4])
    sbbq(t[2], a[5])
    sbbq(t[3], a[6])
    sbbq(t[4], a[7])
    adcq(0, c)

    movq(0xffffffff00000000, m[1])
    movq(0xfffffffeffffffff, m[3])
    commenta "mask m and sub from result if overflow"
    commenta " m[0] = -1 & mask = mask"
    andq(c, m[1])
    commenta " m[2] = -1 & mask = mask"
    andq(c, m[3])
    subq(c, a[4])
    sbbq(m[1], a[5])
    sbbq(c, a[6])
    sbbq(m[3], a[7])
    movq(a[4], r[0])
    movq(a[5], r[1])
    movq(a[6], r[2])
    movq(a[7], r[3])
  end
end

