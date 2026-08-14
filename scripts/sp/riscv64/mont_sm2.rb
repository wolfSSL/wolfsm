# mont_sm2.rb
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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


# RISC-V 64 SM2 field reduction.
#
# p = 2^256 - 2^224 - 2^96 + 2^64 - 1, so
#   mu*m = mu<<256 - mu<<224 - mu<<96 + mu<<64 - mu
# and every partial product is a shift.  p256_sm2_mp_mod is 1, so mu is just
# t[i].  The reduction therefore needs no multiply at all - 16 of them go.
#
# With A = mu << 32 and B = mu >> 32 the positive part is mu at words 1 and 4;
# the negative part is mu at word 0, A at words 1 and 3, and B at words 2 and 4.
# So V = mu*m is
#   v0 = -mu    v1 = mu - A    v2 = -B    v3 = -A    v4 = mu - B
# each less the running borrow.  V is built and added to t in ONE pass, the
# word formed and consumed immediately, so there is a single carry chain with
# the subtraction's borrow running alongside it - splitting them into separate
# chains is what made an earlier shaped P-256 attempt lose.
#
# Word i is zero by construction (t[i] + (-mu) == 0 since mu == t[i]), so only
# its carry out matters, and that is just "was t[i] non-zero".
module MontRiscv64_SM2
  def mont_red_sm2_shift(words, total, name="")
    puts <<EOF
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * @param [in, out] a   A single precision number to reduce in place.
 * @param [in]      m   The single precision number representing the modulus.
 * @param [in]      mp  The digit representing the negative inverse of
 *                      m mod 2^n.
 */
EOF
    sp_ni_static_func(void, "sp_#{@total}_mont_reduce#{name}_#{@namef}#{words}",
            ["sp_digit*"      , "a", 1, 64],
            ["const sp_digit*", "m", 1, 64],
            ["sp_digit"       , "mp", 1, 64]
            )

    a  = use_param(0)
    m  = use_param(1)
    mp = use_param(2)

    av = use_regs(2 * words, 64)
    mu = use_reg(64)
    aa = use_reg(64)
    bb = use_reg(64)
    v  = use_reg(64)
    bw = use_reg(64)
    cy = use_reg(64)
    ca = use_reg(64)
    c1 = use_reg(64)
    c2 = use_reg(64)

    # t[k] += v + cy, carry out in cy
    addw = lambda do |k|
      i_add(av[k], av[k], v)
      sltu(c1, av[k], v)
      i_add(av[k], av[k], cy)
      sltu(c2, av[k], cy)
      or_(cy, c1, c2)
    end
    # v = x - y - bw, new borrow in bw
    subb = lambda do |x, y|
      sltu(c1, x, y)
      i_sub(v, x, y)
      sltu(c2, v, bw)
      i_sub(v, v, bw)
      or_(bw, c1, c2)
    end

    asm()

    commenta("Load the value to reduce")
    0.upto(2 * words - 1) do |i|
      ld(av[i], a[i * 8])
    end

    li(ca, 0)
    0.upto(words - 1) do |i|
      commenta("mu = t[#{i}] (mp == 1); A = mu << 32, B = mu >> 32")
      mv(mu, av[i])
      slli(aa, mu, 32)
      srli(bb, mu, 32)

      commenta("Word #{i}: -mu cancels t[#{i}] exactly; keep only the carry")
      sltu(cy, zero, mu)
      mv(bw, cy)

      commenta("Word #{i + 1}: mu - A")
      subb.call(mu, aa)
      addw.call(i + 1)

      commenta("Word #{i + 2}: -B")
      subb.call(zero, bb)
      addw.call(i + 2)

      commenta("Word #{i + 3}: -A")
      subb.call(zero, aa)
      addw.call(i + 3)

      commenta("Word #{i + 4}: mu - B, the top word of mu*m - cannot borrow out")
      i_sub(v, mu, bb)
      i_sub(v, v, bw)
      addw.call(i + words)
      i_add(av[i + words], av[i + words], ca)
      sltu(c2, av[i + words], ca)
      i_add(ca, cy, c2)
    end

    commenta("Subtract the modulus when the accumulation overflowed")
    i_sub(mu, zero, ca)
    li(cy, 0)
    0.upto(words-1) do |j|
      ld(bb, m[j * 8])
      and_(bb, bb, mu)
      sltu(c1, av[words+j], bb)
      i_sub(v, av[words+j], bb)
      sltu(c2, v, cy)
      i_sub(v, v, cy)
      or_(cy, c1, c2)
      sd(v, a[j * 8])
    end

    end_asm()

    end_func()
  end


  # Fused SM2 Montgomery multiply (CIOS).  The reduction of the low word runs
  # inside the multiply loop, so only n+2 words of state are live instead of
  # the full 2n product - it never reaches memory, and there is one call
  # instead of two.
  #
  # The state rotates rather than shifts: t[k] is st[(base+k) % 6], base
  # advancing each round.  The reduction is the same multiply-free form as
  # mont_red_sm2_shift; V's five words land on t[0..4] and the carry on t[5].
  # mu is t[0] itself (mp == 1) and t[0] is never written - -mu cancels it - so
  # mu needs no register, and b[i] lives in t[5], dead until the row ends.
  def mont_mul_sm2_cios(words, total)
    puts <<EOF
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * @param [out] r   Result of multiplication.
 * @param [in]  a   First number to multiply in Montgomery form.
 * @param [in]  b   Second number to multiply in Montgomery form.
 * @param [in]  m   Modulus (prime).  SM2 only - not read.
 * @param [in]  mp  Montgomery multiplier.  Must be 1 - not read.
 */
EOF
    c_asm.pin_params = true
    sp_ni_static_func(void, "sp_#{@total}_mont_mul_#{@namef}#{words}",
            ["sp_digit*"      , "r", 1, 64],
            ["const sp_digit*", "a", 1, 64],
            ["const sp_digit*", "b", 1, 64],
            ["const sp_digit*", "m", 1, 64],
            ["sp_digit"       , "mp", 1, 64]
            )

    r = use_param(0)
    a = use_param(1)
    b = use_param(2)
    m = use_param(3)

    av = use_regs(words, 64)
    free_reg(a)
    ns = words + 2
    st = use_regs(ns, 64)
    lo = use_reg(64)
    hi = use_reg(64)
    cc = use_reg(64)
    aa = use_reg(64)
    bb = use_reg(64)
    v  = use_reg(64)
    bw = use_reg(64)

    base = 0
    tt = lambda { |k| st[(base + k) % ns] }
    addw = lambda do |k|
      i_add(tt.call(k), tt.call(k), v)
      sltu(lo, tt.call(k), v)
      i_add(tt.call(k), tt.call(k), cc)
      sltu(hi, tt.call(k), cc)
      or_(cc, lo, hi)
    end
    subb = lambda do |x, y|
      sltu(lo, x, y)
      i_sub(v, x, y)
      sltu(hi, v, bw)
      i_sub(v, v, bw)
      or_(bw, lo, hi)
    end

    asm()

    commenta("Load a - its argument register is a working register after this")
    0.upto(words - 1) do |i|
      ld(av[i], a[i * 8])
    end

    0.upto(words - 1) do |i|
      bi = tt.call(words + 1)
      commenta("Iteration #{i}: t += a * b[#{i}]")
      ld(bi, b[i * 8])
      if i == 0
        commenta("t is zero - a plain multiply")
        i_mul(tt.call(0), av[0], bi)
        mulhu(cc, av[0], bi)
        1.upto(words - 1) do |j|
          i_mul(lo, av[j], bi)
          mulhu(hi, av[j], bi)
          i_add(tt.call(j), lo, cc)
          sltu(cc, tt.call(j), lo)
          i_add(cc, cc, hi)
        end
        mv(tt.call(words), cc)
        li(tt.call(words + 1), 0)
      else
        i_mul(lo, av[0], bi)
        mulhu(hi, av[0], bi)
        i_add(tt.call(0), tt.call(0), lo)
        sltu(cc, tt.call(0), lo)
        i_add(cc, cc, hi)
        1.upto(words - 1) do |j|
          i_mul(lo, av[j], bi)
          mulhu(hi, av[j], bi)
          i_add(lo, lo, cc)
          sltu(cc, lo, cc)
          i_add(hi, hi, cc)
          i_add(tt.call(j), tt.call(j), lo)
          sltu(cc, tt.call(j), lo)
          i_add(cc, cc, hi)
        end
        i_add(tt.call(words), tt.call(words), cc)
        sltu(cc, tt.call(words), cc)
        mv(tt.call(words + 1), cc)
      end

      commenta("Reduce: mu = t[0]; A = mu << 32, B = mu >> 32")
      mu = tt.call(0)
      slli(aa, mu, 32)
      srli(bb, mu, 32)
      commenta("Word 0: -mu cancels t[0]; keep only the carry")
      sltu(cc, zero, mu)
      mv(bw, cc)
      commenta("Word 1: mu - A")
      subb.call(mu, aa)
      addw.call(1)
      commenta("Word 2: -B")
      subb.call(zero, bb)
      addw.call(2)
      commenta("Word 3: -A")
      subb.call(zero, aa)
      addw.call(3)
      commenta("Word 4: mu - B - cannot borrow out")
      i_sub(v, mu, bb)
      i_sub(v, v, bw)
      addw.call(4)
      commenta("Carry into word 5")
      i_add(tt.call(5), tt.call(5), cc)

      base = (base + 1) % ns
    end
    commenta("t stays below 2m, so one conditional subtract fully reduces it.")
    commenta("Compute t - m in a's registers - dead now - keeping the borrow.")
    res = (0...words).map { |k| tt.call(k) }
    li(bw, 0)
    0.upto(words - 1) do |j|
      ld(bb, m[j * 8])
      sltu(lo, res[j], bb)
      i_sub(v, res[j], bb)
      sltu(hi, v, bw)
      i_sub(v, v, bw)
      or_(bw, lo, hi)
      mv(av[j], v)
    end

    commenta("Take the subtracted value when t overflowed or did not borrow")
    xori(bw, bw, 1)
    sltu(lo, zero, tt.call(words))
    or_(bw, bw, lo)
    i_sub(bw, zero, bw)
    0.upto(words - 1) do |j|
      xor_(v, res[j], av[j])
      and_(v, v, bw)
      xor_(v, res[j], v)
      sd(v, r[j * 8])
    end


    end_asm()

    end_func()
  end


  # Fused SM2 Montgomery square (Comba).  The off-diagonal products a[i]*a[j],
  # i < j, are computed once and the sum doubled - 10 products where the fused
  # multiply would do 16 - and the 8-word product is held in registers and
  # reduced in place, so it never reaches memory and there is one call.
  #
  # Squaring phase is the same shape as the P-256 one: products in position
  # order so each opens at most one new word (written directly, never zeroed),
  # then one sweep doing 2*s[k] + the diagonal word landing there + carry.
  # Word 0 lands in a[0]'s register - the a[0]*a[0] diagonal is that operand's
  # last use.  The reduction is mont_red_sm2_shift's multiply-free form.
  def mont_sqr_sm2_comba(words, total)
    puts <<EOF
/* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
 *
 * @param [out] r   Result of squaring.
 * @param [in]  a   Number to square in Montgomery form.
 * @param [in]  m   Modulus (prime).
 * @param [in]  mp  Montgomery multiplier.  Must be 1 - not read.
 */
EOF
    c_asm.pin_params = true
    sp_ni_static_func(void, "sp_#{@total}_mont_sqr_#{@namef}#{words}",
            ["sp_digit*"      , "r", 1, 64],
            ["const sp_digit*", "a", 1, 64],
            ["const sp_digit*", "m", 1, 64],
            ["sp_digit"       , "mp", 1, 64]
            )

    r = use_param(0)
    a = use_param(1)
    m = use_param(2)

    av = use_regs(words, 64)
    free_reg(a)
    ph = use_regs(2 * words - 1, 64)
    lo = use_reg(64)
    hi = use_reg(64)
    cc = use_reg(64)
    aa = use_reg(64)
    bb = use_reg(64)
    v  = use_reg(64)
    bw = use_reg(64)
    ca = use_reg(64)

    t = [av[0]] + ph
    top = 2 * words - 1

    addw = lambda do |k|
      i_add(t[k], t[k], v)
      sltu(lo, t[k], v)
      i_add(t[k], t[k], cc)
      sltu(hi, t[k], cc)
      or_(cc, lo, hi)
    end
    subb = lambda do |x, y|
      sltu(lo, x, y)
      i_sub(v, x, y)
      sltu(hi, v, bw)
      i_sub(v, v, bw)
      or_(bw, lo, hi)
    end

    asm()

    commenta("Load a - its argument register is a working register after this")
    0.upto(words - 1) { |i| ld(av[i], a[i * 8]) }

    commenta("Off-diagonal products a[i]*a[j], i < j - in position order so")
    commenta("each opens at most one new word, written directly")
    i_mul(t[1], av[0], av[1])
    mulhu(t[2], av[0], av[1])
    i_mul(lo, av[0], av[2])
    mulhu(t[3], av[0], av[2])
    i_mul(t[5], av[0], av[3])
    mulhu(t[4], av[0], av[3])
    i_add(t[2], t[2], lo)
    sltu(cc, t[2], lo)
    i_add(t[3], t[3], cc)
    i_mul(hi, av[1], av[2])
    mulhu(t[6], av[1], av[2])
    i_add(t[3], t[3], t[5])
    sltu(cc, t[3], t[5])
    i_add(t[4], t[4], cc)
    i_add(t[3], t[3], hi)
    sltu(cc, t[3], hi)
    i_add(t[6], t[6], cc)
    i_add(t[4], t[4], t[6])
    sltu(t[5], t[4], t[6])
    i_mul(lo, av[1], av[3])
    mulhu(hi, av[1], av[3])
    i_add(t[4], t[4], lo)
    sltu(cc, t[4], lo)
    i_add(hi, hi, cc)
    i_add(t[5], t[5], hi)
    sltu(t[6], t[5], hi)
    i_mul(lo, av[2], av[3])
    mulhu(hi, av[2], av[3])
    i_add(t[5], t[5], lo)
    sltu(cc, t[5], lo)
    i_add(hi, hi, cc)
    i_add(t[6], t[6], hi)
    sltu(t[7], t[6], hi)

    commenta("Twice the off-diagonal sum plus the diagonals, in one sweep")
    commenta("Word 0: low word of a[0]*a[0], over the dying operand")
    mulhu(lo, av[0], av[0])
    i_mul(t[0], av[0], av[0])
    commenta("Word 1: nothing shifts in, no carry in")
    srli(hi, t[1], 63)
    slli(t[1], t[1], 1)
    i_add(t[1], t[1], lo)
    sltu(cc, t[1], lo)
    pb = hi
    nb = lo
    2.upto(top) do |k|
      d = k / 2
      srli(nb, t[k], 63) if k < top
      slli(t[k], t[k], 1)
      or_(t[k], t[k], pb)
      if k.even?
        i_mul(pb, av[d], av[d])
        mulhu(av[d], av[d], av[d])
        i_add(pb, pb, cc)
        i_add(t[k], t[k], pb)
        sltu(cc, t[k], pb) if k < top
      else
        i_add(av[d], av[d], cc)
        i_add(t[k], t[k], av[d])
        sltu(cc, t[k], av[d]) if k < top
      end
      pb, nb = nb, pb
    end

    commenta("Reduce in place - multiply-free, see mont_red_sm2_shift")
    li(ca, 0)
    0.upto(words - 1) do |i|
      mu = t[i]
      slli(aa, mu, 32)
      srli(bb, mu, 32)
      sltu(cc, zero, mu)
      mv(bw, cc)
      subb.call(mu, aa)
      addw.call(i + 1)
      subb.call(zero, bb)
      addw.call(i + 2)
      subb.call(zero, aa)
      addw.call(i + 3)
      i_sub(v, mu, bb)
      i_sub(v, v, bw)
      addw.call(i + words)
      i_add(t[i + words], t[i + words], ca)
      sltu(hi, t[i + words], ca)
      i_add(ca, cc, hi)
    end

    commenta("Subtract the modulus when the accumulation overflowed")
    i_sub(aa, zero, ca)
    li(cc, 0)
    0.upto(words - 1) do |j|
      ld(bb, m[j * 8])
      and_(bb, bb, aa)
      sltu(lo, t[words + j], bb)
      i_sub(v, t[words + j], bb)
      sltu(hi, v, cc)
      i_sub(v, v, cc)
      or_(cc, lo, hi)
      sd(v, r[j * 8])
    end

    end_asm()

    end_func()
  end

  def mont_sqr(words, total=@total, mp1=false, check_mp=false, cpu="")
    if @total == 256 and words == 4 and cpu == "" and sm2Curve()
      v = "#{cpu}#{words}"
      return if @mont_sqr_func != nil and @mont_sqr_func.include?(v)
      @mont_sqr_func = [] if @mont_sqr_func == nil
      @mont_sqr_func << v
      mont_sqr_sm2_comba(words, total)
      return
    end
    super
  end

  def mont_mul(words, total=@total, mp1=false, check_mp=false, cpu="")
    if @total == 256 and words == 4 and cpu == "" and sm2Curve()
      v = "#{cpu}#{words}"
      return if @mont_mul_func != nil and @mont_mul_func.include?(v)
      @mont_mul_func = [] if @mont_mul_func == nil
      @mont_mul_func << v
      mont_mul_sm2_cios(words, total)
      return
    end
    super
  end

  # Route only the SM2 field reduction here; the order has no such shape.
  def mont_red(words, total, mp1, check_mp, cpu="")
    if @total == 256 and words == 4 and cpu == "" and sm2Curve()
      v = cpu + words.to_s
      return if @mont_red_func != nil and @mont_red_func.include?(v)
      @mont_red_func = [] if @mont_red_func == nil
      @mont_red_func << v

      mont_red_sm2_shift(words, total)
      mont_red_unrolled(words, total, "_order")
      return
    end
    super
  end
end
