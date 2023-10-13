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

module MontArm64_SM2

  def add_red_sm2(r, a, m, o, twice=true, shift=false)
    # m = fffffffeffffffff ffffffffffffffff
    #     ffffffff00000000 ffffffffffffffff
    # Conditional reduction
    puti "asr       #{o}, #{o}, #1"                  if shift
    puti "subs      #{a[0]}, #{a[0]}, #{o}"
    puti "lsl       #{m[1]}, #{o}, 32"
    puti "sbcs      #{a[1]}, #{a[1]}, #{m[1]}"
    puti "and       #{m[3]}, #{o}, #0xfffffffeffffffff"
    puti "sbcs      #{a[2]}, #{a[2]}, #{o}"
    puti "sbcs      #{a[3]}, #{a[3]}, #{m[3]}"
    puti "sbc       #{m[3]}, xzr, xzr"
    puti "sub       #{o}, #{o}, #{m[3]}"

    if twice
      # Conditional reduction
      puti "subs    #{a[0]}, #{a[0]}, #{o}"
      puti "lsl     #{m[1]}, #{o}, 32"
      puti "sbcs    #{a[1]}, #{a[1]}, #{m[1]}"
      puti "and     #{m[3]}, #{o}, #0xfffffffeffffffff"
      puti "sbcs    #{a[2]}, #{a[2]}, #{o}"
      puti "stp     #{a[0]}, #{a[1]}, [#{r},#{0*8}]" if r
      puti "sbc     #{a[3]}, #{a[3]}, #{m[3]}"
      puti "stp     #{a[2]}, #{a[3]}, [#{r},#{2*8}]" if r
    end
  end

  def sub_red_sm2(r, a, m, o, shift=false)
    # m = fffffffeffffffff ffffffffffffffff
    #     ffffffff00000000 ffffffffffffffff
    puti "asr       #{o}, #{o}, #1"                  if shift
    # Conditional reduction
    puti "adds      #{a[0]}, #{a[0]}, #{o}"
    puti "lsl       #{m[1]}, #{o}, 32"
    puti "adcs      #{a[1]}, #{a[1]}, #{m[1]}"
    puti "and       #{m[3]}, #{o}, #0xfffffffeffffffff"
    puti "adcs      #{a[2]}, #{a[2]}, #{o}"
    puti "adcs      #{a[3]}, #{a[3]}, #{m[3]}"
    puti "adc       #{o}, #{o}, xzr"

    # Conditional reduction
    puti "adds      #{a[0]}, #{a[0]}, #{o}"
    puti "lsl       #{m[1]}, #{o}, 32"
    puti "adcs      #{a[1]}, #{a[1]}, #{m[1]}"
    puti "and       #{m[3]}, #{o}, #0xfffffffeffffffff"
    puti "adcs      #{a[2]}, #{a[2]}, #{o}"
    puti "stp       #{a[0]}, #{a[1]}, [#{r},#{0*8}]" if r
    puti "adc       #{a[3]}, #{a[3]}, #{m[3]}"
    puti "stp       #{a[2]}, #{a[3]}, [#{r},#{2*8}]" if r
  end

  def mont_add_sm2()
    a = ["x4", "x5", "x6", "x7"]
    b = ["x8", "x9", "x10", "x11"]
    m = ["$-1", "x12", "$0", "x13"]
    o = "x14"
    regs = a + b + [m[1], m[3], o]
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a], 0]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a], 16]"
    puti "ldp   #{b[0]}, #{b[1]}, [%[b], 0]"
    puti "ldp   #{b[2]}, #{b[3]}, [%[b], 16]"

    puti "adds  #{a[0]}, #{a[0]}, #{b[0]}"
    puti "adcs  #{a[1]}, #{a[1]}, #{b[1]}"
    puti "adcs  #{a[2]}, #{a[2]}, #{b[2]}"
    puti "adcs  #{a[3]}, #{a[3]}, #{b[3]}"
    puti "csetm #{o}, cs"

    add_red_sm2("%[r]", a, m, o)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );

    (void)m;
EOF
  end

  def mont_dbl_sm2()
    a = ["x3", "x4", "x5", "x6"]
    m = ["$-1", "x7", "$0", "x8"]
    r = ["x9", "x10", "x11", "x12"]
    o = "x13"
    regs = a + [m[1], m[3], o] + r
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a]]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a],16]"

    puti "lsl   #{r[0]}, #{a[0]}, #1"
    puti "extr  #{r[1]}, #{a[1]}, #{a[0]}, #63"
    puti "extr  #{r[2]}, #{a[2]}, #{a[1]}, #63"
    puti "asr   #{o}, #{a[3]}, #63"
    puti "extr  #{r[3]}, #{a[3]}, #{a[2]}, #63"

    add_red_sm2("%[r]", r, m, o)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", #{regs}, "cc"
    );

    (void)m;
EOF
  end

  def mont_tpl_sm2()
    a = ["x9", "x10", "x11", "x12"]
    r = ["x3", "x4", "x5", "x6"]
    m = ["$-1", "x7", "$0", "x8"]
    o = "x13"
    regs = a + r + [m[1], m[3], o]
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a]]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a], 16]"

    # Double
    puti "lsl   #{r[0]}, #{a[0]}, #1"
    puti "extr  #{r[1]}, #{a[1]}, #{a[0]}, #63"
    puti "extr  #{r[2]}, #{a[2]}, #{a[1]}, #63"
    puti "asr   #{o}, #{a[3]}, #63"
    puti "extr  #{r[3]}, #{a[3]}, #{a[2]}, #63"

    add_red_sm2(nil, r, m, o, false)

    # Add
    puti "adds  #{r[0]}, #{r[0]}, #{a[0]}"
    puti "adcs  #{r[1]}, #{r[1]}, #{a[1]}"
    puti "adcs  #{r[2]}, #{r[2]}, #{a[2]}"
    puti "adcs  #{r[3]}, #{r[3]}, #{a[3]}"
    puti "adc   #{o}, #{o}, xzr"
    puti "neg   #{o}, #{o}"

    add_red_sm2("%[r]", r, m, o, true, true)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", #{regs}, "cc"
    );

    (void)m;
EOF
  end

  def mont_sub_sm2()
    a = ["x4", "x5", "x6", "x7"]
    b = ["x8", "x9", "x10", "x11"]
    m = ["$-1", "x12", "$0", "x13"]
    o = "x14"
    regs = a + b + [m[1], m[3], o]
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a], 0]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a], 16]"
    puti "ldp   #{b[0]}, #{b[1]}, [%[b], 0]"
    puti "ldp   #{b[2]}, #{b[3]}, [%[b], 16]"

    puti "subs  #{a[0]}, #{a[0]}, #{b[0]}"
    puti "sbcs  #{a[1]}, #{a[1]}, #{b[1]}"
    puti "sbcs  #{a[2]}, #{a[2]}, #{b[2]}"
    puti "sbcs  #{a[3]}, #{a[3]}, #{b[3]}"
    puti "sbc   #{o}, xzr, xzr"

    sub_red_sm2("%[r]", a, m, o)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );

    (void)m;
EOF
  end

  def mont_rsb_sub_dbl_sm2(cpu)
    a = ["x4", "x5", "x6", "x7"]
    b = ["x8", "x9", "x10", "x11"]
    r = ["x15", "x16", "x17", "x19"]
    m = ["$-1", "x12", "$0", "x13"]
    o = "x14"
    regs = a + b + [m[1], m[3], o] + r
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
/* Double number and subtract (r = (a - 2.b) % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_#{@total}_mont_rsb_sub_dbl_#{@namef}#{@words}(sp_digit* r, const sp_digit* a,
        sp_digit* b, const sp_digit* m)
{
    __asm__ __volatile__ (
EOF
    puti "ldp   #{b[0]}, #{b[1]}, [%[b]]"
    puti "ldp   #{b[2]}, #{b[3]}, [%[b],16]"

    # Double
    puti "lsl   #{r[0]}, #{b[0]}, #1"
    puti "extr  #{r[1]}, #{b[1]}, #{b[0]}, #63"
    puti "extr  #{r[2]}, #{b[2]}, #{b[1]}, #63"
    puti "asr   #{o}, #{b[3]}, #63"
    puti "extr  #{r[3]}, #{b[3]}, #{b[2]}, #63"

    puti "ldp   #{a[0]}, #{a[1]}, [%[a]]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a],16]"

    add_red_sm2(nil, r, m, o, false)

    # Subtract double
    puti "subs  #{r[0]}, #{a[0]}, #{r[0]}"
    puti "sbcs  #{r[1]}, #{a[1]}, #{r[1]}"
    puti "sbcs  #{r[2]}, #{a[2]}, #{r[2]}"
    puti "sbcs  #{r[3]}, #{a[3]}, #{r[3]}"
    puti "sbc   #{o}, xzr, #{o}"

    sub_red_sm2("%[r]", r, m, o, true)

    # Reverse subtract
    puti "subs  #{r[0]}, #{b[0]}, #{r[0]}"
    puti "sbcs  #{r[1]}, #{b[1]}, #{r[1]}"
    puti "sbcs  #{r[2]}, #{b[2]}, #{r[2]}"
    puti "sbcs  #{r[3]}, #{b[3]}, #{r[3]}"
    puti "sbc   #{o}, xzr, xzr"

    sub_red_sm2("%[b]", r, m, o)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );

    (void)m;
}

EOF
  end

  def mont_sub_dbl_sm2(cpu)
    a = ["x4", "x5", "x6", "x7"]
    b = ["x8", "x9", "x10", "x11"]
    m = ["$-1", "x12", "$0", "x13"]
    o = "x14"
    regs = a + b + [m[1], m[3], o]
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
/* Double number and subtract (r = (a - 2.b) % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_#{@total}_mont_sub_dbl_#{@namef}#{@words}(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[b]]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[b],16]"

    # Double
    puti "lsl   #{b[0]}, #{a[0]}, #1"
    puti "extr  #{b[1]}, #{a[1]}, #{a[0]}, #63"
    puti "extr  #{b[2]}, #{a[2]}, #{a[1]}, #63"
    puti "asr   #{o}, #{a[3]}, #63"
    puti "extr  #{b[3]}, #{a[3]}, #{a[2]}, #63"

    puti "ldp   #{a[0]}, #{a[1]}, [%[a]]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a],16]"

    add_red_sm2(nil, b, m, o, false)

    # Subtract double
    puti "subs  #{a[0]}, #{a[0]}, #{b[0]}"
    puti "sbcs  #{a[1]}, #{a[1]}, #{b[1]}"
    puti "sbcs  #{a[2]}, #{a[2]}, #{b[2]}"
    puti "sbcs  #{a[3]}, #{a[3]}, #{b[3]}"
    puti "sbc   #{o}, xzr, #{o}"

    sub_red_sm2("%[r]", a, m, o, true)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );

    (void)m;
}

EOF
  end

  def mont_dbl_sub_sm2(cpu)
    a = ["x4", "x5", "x6", "x7"]
    b = ["x8", "x9", "x10", "x11"]
    o = "x14"
    m = ["$-1", "x12", "$0", "x13"]
    regs = a + b + [m[1], [3], o]
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
/* Subtract two Montgomery form numbers and double (r = 2.(a - b) % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_#{@total}_mont_dbl_sub_#{@namef}#{@words}(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a], 0]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a], 16]"
    puti "ldp   #{b[0]}, #{b[1]}, [%[b], 0]"
    puti "ldp   #{b[2]}, #{b[3]}, [%[b], 16]"

    # Sub
    puti "subs  #{a[0]}, #{a[0]}, #{b[0]}"
    puti "sbcs  #{a[1]}, #{a[1]}, #{b[1]}"
    puti "sbcs  #{a[2]}, #{a[2]}, #{b[2]}"
    puti "sbcs  #{a[3]}, #{a[3]}, #{b[3]}"
    puti "sbc   #{o}, xzr, xzr"

    sub_red_sm2(nil, a, m, o)

    # Double
    puti "lsl   #{b[0]}, #{a[0]}, #1"
    puti "extr  #{b[1]}, #{a[1]}, #{a[0]}, #63"
    puti "extr  #{b[2]}, #{a[2]}, #{a[1]}, #63"
    puti "asr   #{o}, #{a[3]}, #63"
    puti "extr  #{b[3]}, #{a[3]}, #{a[2]}, #63"

    add_red_sm2("%[r]", b, m, o)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );

    (void)m;
}

EOF
  end

  def mont_add_sub_sm2(cpu)
    a = ["x4", "x5", "x6", "x7"]
    b = ["x8", "x9", "x10", "x11"]
    m = ["$-1", "x12", "$0", "x13"]
    o = "x19"
    ra = ["x14", "x15", "x16", "x17"]
    rs = a
    regs = a + b + [m[1], m[3], o] + ra
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * ra  Result of addition.
 * rs  Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_#{@total}_mont_add_sub_#{@namef}#{@words}(sp_digit* ra, sp_digit* rs, const sp_digit* a,
        const sp_digit* b, const sp_digit* m)
{
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a], 0]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a], 16]"
    puti "ldp   #{b[0]}, #{b[1]}, [%[b], 0]"
    puti "ldp   #{b[2]}, #{b[3]}, [%[b], 16]"

    # Add
    puti "adds  #{ra[0]}, #{a[0]}, #{b[0]}"
    puti "adcs  #{ra[1]}, #{a[1]}, #{b[1]}"
    puti "adcs  #{ra[2]}, #{a[2]}, #{b[2]}"
    puti "adcs  #{ra[3]}, #{a[3]}, #{b[3]}"
    puti "csetm #{o}, cs"

    add_red_sm2("%[ra]", ra, m, o)

    # Sub
    puti "subs  #{rs[0]}, #{a[0]}, #{b[0]}"
    puti "sbcs  #{rs[1]}, #{a[1]}, #{b[1]}"
    puti "sbcs  #{rs[2]}, #{a[2]}, #{b[2]}"
    puti "sbcs  #{rs[3]}, #{a[3]}, #{b[3]}"
    puti "sbc   #{o}, xzr, xzr"

    sub_red_sm2("%[rs]", rs, m, o)

    puts <<EOF
        :
        : [ra] "r" (ra), [rs] "r" (rs), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );

    (void)m;
}

EOF
  end

  def mont_div2_sm2(words, cpu="")
    total = @total * words / @words

    a = [ "x3", "x4", "x5", "x6" ]
    mask = "x8"
    m = [ "$-1", "x7", "$0", mask ]
    o = "x9"
    zr = "xzr"
    regs = a + [m[1], o, mask]
    regs = "\"" + regs.join("\", \"") + "\""

    puts <<EOF
    __asm__ __volatile__ (
EOF
    puti "ldp   #{a[0]}, #{a[1]}, [%[a], #{0 * 8}]"
    puti "ldp   #{a[2]}, #{a[3]}, [%[a], #{2 * 8}]"
    puti "sbfx  #{mask}, #{a[0]}, 0, 1"
    # m = fffffffeffffffff ffffffffffffffff
    #     ffffffff00000000 ffffffffffffffff
    puti "adds      #{a[0]}, #{a[0]}, #{mask}"
    puti "lsl       #{m[1]}, #{mask}, 32"
    puti "adcs      #{a[1]}, #{a[1]}, #{m[1]}"
    puti "adcs      #{a[2]}, #{a[2]}, #{mask}"
    puti "and       #{m[3]}, #{mask}, #0xfffffffeffffffff"
    puti "extr      #{a[0]}, #{a[1]}, #{a[0]}, 1"
    puti "adcs      #{a[3]}, #{a[3]}, #{m[3]}"
    puti "extr  #{a[1]}, #{a[2]}, #{a[1]}, 1"
    puti "adc   #{o}, xzr, xzr"
    puti "extr  #{a[2]}, #{a[3]}, #{a[2]}, 1"
    puti "extr  #{a[3]}, #{o}, #{a[3]}, 1"
    puti "stp   #{a[0]}, #{a[1]}, [%[r], #{0 * 8}]"
    puti "stp   #{a[2]}, #{a[3]}, [%[r], #{2 * 8}]"
    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [m] "r" (m)
        : "memory", #{regs}, "cc"
    );
EOF
  end

  def mont_red_sm2(words, total)
    puts <<EOF
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_#{@total}_mont_reduce_#{@namef}#{words}(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{2*total}, #{2*words});
SP_PRINT_NUM(m, "m", #{total}, #{words});

EOF
    end
    puts <<EOF
    __asm__ __volatile__ (
EOF

    t = []
    0.upto(2*words-1) do |i|
      t[i] = "x#{i+3}"
    end
    out = []
    0.upto(2*words-1) do |i|
      out[i] = "x#{i+10}"
    end
    t += ["x19", "x20"]
    a = []
    0.upto(2*words-1) do |i|
      a[i] = "[%[a], #{i*8}]"
    end

    regs = out + t
    regs = "\"" + regs.join("\", \"") + "\""

    0.step(2*words-2, 2) do |i|
      puti "ldp #{out[i+0]}, #{out[i+1]}, #{a[i]}"
    end
    puti "mov   #{t[0]}, #{out[0]}"

    do_mont_red_sm2(words, "%[a]", out, t)

    puts <<EOF
        :
        : [a] "r" (a), [m] "r" (m), [mp] "r" (mp)
        : "memory", #{regs}, "cc"
    );
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "rr", #{total}, #{words});
EOF
    end
    puts <<EOF
}
EOF
  end

  def do_mont_red_order_sm2(words, res, ar, mr, mp, tr, do_store=true)
    do_mont_red_order_4(words, res, ar, mr, mp, tr, do_store)
  end

  # Generic Montgomery Reduction for order.
  # mont_mul and mont_sqr have the reduction built in.
  def mont_red_order_sm2(words, total, name="")
    puts <<EOF
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_#{@total}_mont_reduce#{name}_#{@namef}#{words}(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{2*words}, #{2*total});
SP_PRINT_NUM(m, "m", #{@total}, #{words}, #{total});
EOF
    end
    puts <<EOF
    __asm__ __volatile__ (
EOF
    t = [ "x3", "x4", "x5", "x6" ]
    ar = [ ]
    0.upto(7) do |i|
      ar[i] = "x#{i+7}"
    end
    mr = [ ]
    n = 15
    0.upto(3) do |i|
      n += 1 if i + n == 18
      mr[i] = "x#{i+n}"
    end
    regs = ar + mr + t
    regs = "\"" + regs.join("\", \"") + "\""

    puti "ldp   #{ar[0]}, #{ar[1]}, [%[a], #{0 * 8}]"
    puti "ldp   #{ar[2]}, #{ar[3]}, [%[a], #{2 * 8}]"
    puti "ldp   #{ar[4]}, #{ar[5]}, [%[a], #{4 * 8}]"
    puti "ldp   #{ar[6]}, #{ar[7]}, [%[a], #{6 * 8}]"
    # Load order
    puti "ldp   #{mr[0]}, #{mr[1]}, [%[m], #{0 * 8}]"
    #puti "ldp   #{mr[2]}, #{mr[3]}, [%[m], #{2 * 8}]"
    puti "mov #{mr[2]}, 0xffffffffffffffff"
    puti "mov #{mr[3]}, 0xffffffffefffffff"

    do_mont_red_order_sm2(words, "%[a]", ar, mr, "%[mp]", t)

    puts <<EOF
        :
        : [a] "r" (a), [m] "r" (m), [mp] "r" (mp)
        : "memory", #{regs}, "cc"
    );
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "rr", #{@total}, #{words}, #{total});
EOF
    end
    puts <<EOF
}

EOF
  end

  def mont_mul_sm2(words)
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
static void sp_#{@total}_mont_mul_#{@namef}#{@words}(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    (void)m;
    (void)mp;

EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(b, "b", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(m, "m", #{@total}, #{@words}, #{@total});
EOF
    end
    puts <<EOF
    __asm__ __volatile__ (
EOF

    regs, out, t = do_mul_fast_4(words, true)

    do_mont_red_sm2(words, "%[r]", out, t)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", #{regs}, "cc"
    );
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(r, "rm", #{@total}, #{@words}, #{@total});
EOF
    end
    puts <<EOF
}

EOF
  end

  def mont_mul_order_sm2(cpu)
    puts <<EOF
/* Multiply two number mod the order of P#{@total} curve. (r = a * b mod order)
 *
 * r  Result of the multiplication.
 * a  First operand of the multiplication.
 * b  Second operand of the multiplication.
 */
static void sp_#{@total}_mont_mul_order_#{cpu}#{@namef}#{@words}(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(b, "b", #{@total}, #{@words}, #{@total});
SP_PRINT_NUM(#{@cname}_order, "m", #{@total}, #{@words}, #{@total});

EOF
    end
    puts <<EOF
    __asm__ __volatile__ (
EOF

    regs, out, t = do_mul_fast_4(@words, true, true)

    mr = t[2..5]
    tr = t[0..1] + t[6..-1]

    puti "ldp   #{mr[0]}, #{mr[1]}, [%[m], #{0 * 8}]"
    #puti "ldp   #{mr[2]}, #{mr[3]}, [%[m], #{2 * 8}]"
    puti "mov #{mr[2]}, 0xffffffffffffffff"
    puti "mov #{mr[3]}, 0xfffffffeffffffff"

    do_mont_red_order_sm2(@words, "%[r]", out, mr, "%[mp]", tr)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (#{@cname}_order),
          [mp] "r" (#{@cname}_mp_order)
        : "memory", #{regs}, "cc"
    );
EOF
    if false
      puts <<EOF

SP_PRINT_NUM(r, "rm", #{@total}, #{@words}, #{@total});
EOF
    end
    puts <<EOF
}

EOF
  end

  def mont_sqr_sm2(words)
    puts <<EOF
/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
static void sp_#{@total}_mont_sqr_#{@namef}#{@words}(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    (void)m;
    (void)mp;

EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{words}, #{@total});
SP_PRINT_NUM(m, "m", #{@total}, #{words}, #{@total});
EOF
    end
    puts <<EOF
    __asm__ __volatile__ (
EOF

    regs, out, t = do_sqr_fast_4(words, true)

    do_mont_red_sm2(words, "%[r]", out, t)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", #{regs}, "cc"
    );
EOF
    if false
      puts <<EOF
SP_PRINT_NUM(r, "rs", #{@total}, #{words}, #{@total});
EOF
    end
    puts <<EOF
}

EOF
  end

  def do_mont_sqr_order_sm2(cpu, load_store=true)
    regs, out, t = do_sqr_fast_4(@words, true, true, load_store)

    mr = t[2..5]
    tr = t[0..1] + t[6..-1]

    puti "ldp   #{mr[0]}, #{mr[1]}, [%[m], #{0 * 8}]"
    #puti "ldp   #{mr[2]}, #{mr[3]}, [%[m], #{2 * 8}]"
    puti "mov #{mr[2]}, 0xffffffffffffffff"
    puti "mov #{mr[3]}, 0xfffffffeffffffff"

    do_mont_red_order_sm2(@words, "%[r]", out, mr, "%[mp]", tr, load_store)

    regs
  end

  def mont_sqr_order_sm2(cpu)
    puts <<EOF
/* Square number mod the order of P#{@total} curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_#{@total}_mont_sqr_order_#{cpu}#{@namef}#{@words}(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
EOF

    regs = do_mont_sqr_order_sm2(cpu)

    puts <<EOF
        :
        : [r] "r" (r), [a] "r" (a), [m] "r" (#{@cname}_order),
          [mp] "r" (#{@cname}_mp_order)
        : "memory", #{regs}, "cc"
    );
}

EOF
  end

  def mont_sqr_order_n_sm2(words, cpu="")
    puts <<EOF
/* Square number mod the order of P#{@total} curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_#{@total}_mont_sqr_n_order_#{cpu}#{@namef}#{@words}(sp_digit* r, const sp_digit* a, int n)
{

    __asm__ __volatile__ (
EOF
    puti "ldp   x12, x13, [%[a], 0]"
    puti "ldp   x14, x15, [%[a], 16]"
    puti "1:"
    regs = do_mont_sqr_order_sm2(cpu, false)
    puti "subs  %w[n], %w[n], #1"
    puti "b.ne  1b"
    puti "stp   x12, x13, [%[r], 0]"
    puti "stp   x14, x15, [%[r], 16]"
    puts <<EOF
        : [n] "+r" (n)
        : [r] "r" (r), [a] "r" (a), [m] "r" (#{@cname}_order),
          [mp] "r" (#{@cname}_mp_order)
        : "memory", #{regs}, "cc"
    );
}
EOF
  end

  def do_mont_red_sm2(words, r, a, t)
    m = ["$-1", t[5], "$-1", t[6]]
    mu = t[0..4]
    s = t[4..6]
    c = t[6]

    # mp = 0xfffffffc00000001fffffffe00000000ffffffff000000010000000000000001
    # mp = 1 + (1 << 64) - (1 << 96) + (1 << 128) - (2 << 160) + (2 << 192) -
    #      (4 << 224)
    # mu = mp * a[0..3]
    puti "# mu = a[0..3] + a[0..2] << 64 - a[0..2] << 32 << 64"
    puti "#    + a[0..1] << 128 - (a[0..1] * 2) << 32 << 128"
    puti "#    + (a[0..0] * 2) << 192 - (a[0..0] * 4) << 32 << 192"

    puti "# Start Reduction"
    puti "# mu = a[0..3]"
    # mu[0] = a[0]
    puti "#    + (a[0..0] * 2) << 192"
    puti "add   #{mu[3]}, #{a[3]}, #{a[0]}"
    puti "add   #{mu[3]}, #{mu[3]}, #{a[0]}"
    puti "#    + a[0..1] << 128"
    puti "adds  #{mu[2]}, #{a[2]}, #{a[0]}"
    puti "adc   #{mu[3]}, #{mu[3]}, #{a[1]}"
    puti "#    + a[0..2] << 64"
    puti "adds  #{mu[1]}, #{a[1]}, #{a[0]}"
    puti "adcs  #{mu[2]}, #{mu[2]}, #{a[1]}"
    puti "adc   #{mu[3]}, #{mu[3]}, #{a[2]}"
    puti "#    a[0..2] << 32"
    puti "lsl   #{s[0]}, #{a[0]}, #32"
    puti "extr  #{s[1]}, #{a[1]}, #{a[0]}, #32"
    puti "extr  #{s[2]}, #{a[2]}, #{a[1]}, #32"
    puti "#    - a[0..2] << 32 << 64"
    puti "subs  #{mu[1]}, #{mu[1]}, #{s[0]}"
    puti "sbcs  #{mu[2]}, #{mu[2]}, #{s[1]}"
    puti "sbc   #{mu[3]}, #{mu[3]}, #{s[2]}"
    puti "#    - (a[0..1] * 2) << 32 << 128"
    puti "subs  #{mu[2]}, #{mu[2]}, #{s[0]}"
    puti "sbc   #{mu[3]}, #{mu[3]}, #{s[1]}"
    puti "subs  #{mu[2]}, #{mu[2]}, #{s[0]}"
    puti "sbc   #{mu[3]}, #{mu[3]}, #{s[1]}"
    puti "#    - (a[0..0] * 4) << 32 << 192"
    puti "lsl   #{s[0]}, #{s[0]}, #2"
    puti "sub   #{mu[3]}, #{mu[3]}, #{s[0]}"

    # a += mu * m
    # a += mu * ((1 << 256) - (1 << 224) - (1 << 96) + (1 << 64) - 1)
    puti "# a += (mu << 256) - (mu << 224) - (mu << 96) + (mu << 64) - mu"
    puti "#   a += mu << 256"
    puti "adds  #{a[4]}, #{a[4]}, #{a[0]}"
    puti "adcs  #{a[5]}, #{a[5]}, #{mu[1]}"
    puti "adcs  #{a[6]}, #{a[6]}, #{mu[2]}"
    puti "adcs  #{a[7]}, #{a[7]}, #{mu[3]}"
    puti "adc   #{c}, xzr, xzr"
    puti "#   a += mu << 64"
    puti "adds  #{a[1]}, #{a[1]}, #{a[0]}"
    puti "adcs  #{a[2]}, #{a[2]}, #{mu[1]}"
    puti "adcs  #{a[3]}, #{a[3]}, #{mu[2]}"
    puti "adcs  #{a[4]}, #{a[4]}, #{mu[3]}"
    puti "adcs  #{a[5]}, #{a[5]}, xzr"
    puti "adcs  #{a[6]}, #{a[6]}, xzr"
    puti "adcs  #{a[7]}, #{a[7]}, xzr"
    puti "adc   #{c}, #{c}, xzr"
    puti "# mu <<= 32"
    puti "lsl   #{mu[0]}, #{a[0]}, #32"
    puti "lsr   #{mu[4]}, #{mu[3]}, #32"
    puti "extr  #{mu[3]}, #{mu[3]}, #{mu[2]}, #32"
    puti "extr  #{mu[2]}, #{mu[2]}, #{mu[1]}, #32"
    puti "extr  #{mu[1]}, #{mu[1]}, #{a[0]}, #32"
    puti "#   a -= (mu << 32) << 64"
    puti "subs  #{a[1]}, #{a[1]}, #{mu[0]}"
    puti "sbcs  #{a[2]}, #{a[2]}, #{mu[1]}"
    puti "sbcs  #{a[3]}, #{a[3]}, #{mu[2]}"
    puti "sbcs  #{a[4]}, #{a[4]}, #{mu[3]}"
    puti "sbcs  #{a[5]}, #{a[5]}, #{mu[4]}"
    puti "sbcs  #{a[6]}, #{a[6]}, xzr"
    puti "sbcs  #{a[7]}, #{a[7]}, xzr"
    puti "sbc   #{c}, #{c}, xzr"
    puti "#   a -= (mu << 32) << 192"
    puti "subs  #{a[3]}, #{a[3]}, #{mu[0]}"
    puti "sbcs  #{a[4]}, #{a[4]}, #{mu[1]}"
    puti "sbcs  #{a[5]}, #{a[5]}, #{mu[2]}"
    puti "sbcs  #{a[6]}, #{a[6]}, #{mu[3]}"
    puti "sbcs  #{a[7]}, #{a[7]}, #{mu[4]}"
    puti "sbc   #{c}, #{c}, xzr"
    puti "neg   #{c}, #{c}"

    puti "# mask m and sub from result if overflow"
    puti "#  m[0] = -1 & mask = mask"
    puti "lsl   #{m[1]}, #{c}, 32"
    puti "subs  #{a[4]}, #{a[4]}, #{c}"
    puti "sbcs  #{a[5]}, #{a[5]}, #{m[1]}"
    puti "sbcs  #{a[6]}, #{a[6]}, #{c}"
    puti "stp   #{a[4]}, #{a[5]}, [#{r}, #{0*8}]"
    puti "#  m[2] = -1 & mask = mask"
    puti "and   #{m[3]}, #{c}, 0xfffffffeffffffff"
    puti "sbc   #{a[7]}, #{a[7]}, #{m[3]}"
    puti "stp   #{a[6]}, #{a[7]}, [#{r}, #{2*8}]"
  end

  def do_mont_red_sm2_one_word(words, r, a, t)
    m = ["$-1", t[5], "$-1", t[6]]
    c = t[1..4]
    t = t[0]

    puti "# Start Reduction"
    0.upto(3) do |i|
        puti "#   += a[#{i}] * mod"

        puti "adds      #{a[i+1]}, #{a[i+1]}, #{a[i]}"
        puti "adcs      #{a[i+2]}, #{a[i+2]}, xzr"
        puti "adcs      #{a[i+3]}, #{a[i+3]}, xzr"
        puti "lsr       #{t}, #{a[i]}, 32"
        puti "adcs      #{a[i+4]}, #{a[i+4]}, #{a[i]}"
        puti "lsl       #{a[i]}, #{a[i]}, 32"
        puti "adc       #{c[i]}, xzr, xzr"

        puti "subs      #{a[i+1]}, #{a[i+1]}, #{a[i]}"
        puti "sbcs      #{a[i+2]}, #{a[i+2]}, #{t}"
        puti "sbcs      #{a[i+3]}, #{a[i+3]}, #{a[i]}"
        puti "sbcs      #{a[i+4]}, #{a[i+4]}, #{t}"
        puti "sbc       #{c[i]}, #{c[i]}, xzr"
    end
    puti "#   Add carries"
    puti "adds  #{a[5]}, #{a[5]}, #{c[0]}"
    puti "adcs  #{a[6]}, #{a[6]}, #{c[1]}"
    puti "adcs  #{a[7]}, #{a[7]}, #{c[2]}"
    puti "adc   #{c[3]}, #{c[3]}, xzr"
    puti "neg   #{c[3]}, #{c[3]}"

    puti "# mask m and sub from result if overflow"
    puti "#  m[0] = -1 & mask = mask"
    puti "lsl   #{m[1]}, #{c[3]}, 32"
    puti "#  m[2] = -1 & mask = mask"
    puti "and   #{m[3]}, #{c[3]}, 0xfffffffeffffffff"
    puti "subs  #{a[4]}, #{a[4]}, #{c[3]}"
    puti "sbcs  #{a[5]}, #{a[5]}, #{m[1]}"
    puti "sbcs  #{a[6]}, #{a[6]}, #{c[3]}"
    puti "stp   #{a[4]}, #{a[5]}, [#{r}, #{0*8}]"
    puti "sbc   #{a[7]}, #{a[7]}, #{m[3]}"
    puti "stp   #{a[6]}, #{a[7]}, [#{r}, #{2*8}]"
  end
end

