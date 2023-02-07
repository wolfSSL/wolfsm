# sm3_avx1.rb
#
# Copyright (C) 2006-2020 wolfSSL Inc.
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


class SM3_ASM_X86_64_AVX1
  include X86_64

  def initialize(att_asm, msvc_asm)
    super(att_asm, msvc_asm)
    @func_impl = "avx1"
    @label_pre = "L_SM3_AVX1"
  end

  def load_digest(digest, s)
    0.upto(7) do |i|
      movl(digest[i], s[i])
    end
  end

  def store_xor_digest(digest, s)
    0.upto(7) do |i|
      xorl(s[i], digest[i])
    end
  end

  def xor_digest(digest, s)
    0.upto(7) do |i|
      xorl(digest[i], s[i])
    end
  end

  def store_digest(digest, s)
    0.upto(7) do |i|
      movl(s[i], digest[i])
    end
  end

  def buffer_to_x(x, buffer, flip_mask=nil)
    commenta("X0, X1, X2, X3 = W[0..15]")
    vmovdqu(buffer[0], x[0])
    vmovdqu(buffer[2], x[1])
    vpshufb(flip_mask, x[0], x[0]) if flip_mask
    vpshufb(flip_mask, x[1], x[1]) if flip_mask
    vmovdqu(buffer[4], x[2])
    vmovdqu(buffer[6], x[3])
    vpshufb(flip_mask, x[2], x[2]) if flip_mask
    vpshufb(flip_mask, x[3], x[3]) if flip_mask
  end

  def x_to_w(w, i, x)
    commenta("x_to_w: #{i*4}")
    vmovdqu(x[0], w[i*4+0])
    vmovdqu(x[1], w[i*4+4])
    vmovdqu(x[2], w[i*4+8])
    vmovdqu(x[3], w[i*4+12])
  end
  def x2_to_w(w, i, x)
    commenta("x2_to_w: #{i*4}")
    vmovdqu(x[2], w[i*4])
    vmovdqu(x[3], w[i*4+4])
  end
  def x0_to_w(w, i, x)
    commenta("x0_to_w: #{i*4}")
    vmovdqu(x[0], w[i*4])
  end

  def iter_00_15_step(s, w, i, l, c, n)
    ss1 = l[0]
    ss2 = l[1]
    tmp1 = tt1 = l[2]
    tmp2 = tt2 = l[3]

    commenta("iter_#{i}: #{c} - #{c+n-1}")
    0.upto(n-1) do
      case c
      when 0
        # ss1 = T[i]
        movl(@t[i], ss1)
        # ss2 = a
        movl(s[0], ss2)
        # ss1 = T[i] + e
        addl(s[4], ss1)
        # ss2 = rotl(a, 12)
        roll(12, ss2)
      when 1
        # tmp1 = w[i+4]
        movl(w[i+4], tmp1)
        # ss1 = T[i] + e + rotl(a, 12)
        addl(ss2, ss1)
        # tmp2 = w[i]
        movl(w[i], tmp2)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7)
        roll(7, ss1)
      when 2
        # ss2 = rotl(a, 12) ^ ss1
        xorl(ss1, ss2)
        # tmp1 = w[i+4] ^ w[i]
        xorl(tmp2, tmp1)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7) + w[i]
        addl(tmp2, ss1)
        # ss2 = (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i])
        addl(tmp1, ss2)
      when 3
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7) + w[i] + h
        addl(s[7], ss1)
        # ss2 = (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i]) + d
        addl(s[3], ss2)
        # tt1 = a
        movl(s[0], s[7])
        # d = e
        movl(s[4], s[3])
      when 4
        # tt1 = a ^ b
        xorl(s[1], s[7])
        # d = e ^ f
        xorl(s[5], s[3])
        # tt1 = a ^ b ^ c
        xorl(s[2], s[7])
        # d = e ^ f ^ g
        xorl(s[6], s[3])
      when 5
        # tt1 += ss2 => tt1 += (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i]) + d
        addl(ss2, s[7])
        # tt2 += ss1 => tt2 += rotl(T[i] + e + rotl(a, 12), 7) + w[i] + h
        addl(ss1, s[3])
        # tt2 = d
        movl(s[3], tt2)
        # d = rotl(tt2, 8)
        roll(8, s[3])
      when 6
        # b = rotl(b, 9)
        roll(9, s[1])
        # d = rotl(tt2, 8) ^ tt2
        xorl(tt2, s[3])
        # f = rotl(f, 19)
        roll(19, s[5])
        # d = rotl(rotl(tt2, 8) ^ d), 9)
        roll(9, s[3])
      when 7
        # d = rotl(rotl(tt2, 8) ^ d), 9) ^ d
        xorl(tt2, s[3])
        c = -1
      end
      c += 1
    end
    c
  end
  def iter_16_63_step(s, w, i, l, c, n)
    ss1 = l[0]
    ss2 = l[1]
    tmp1 = tt1 = l[2]
    tmp2 = tt2 = l[3]

    commenta("iter_#{i}: #{c} - #{c+n-1}")
    0.upto(n-1) do
      case c
      when 0
        # ss1 = T[i]
        movl(@t[i], ss1)
        # ss2 = a
        movl(s[0], ss2)
        # ss1 = T[i] + e
        addl(s[4], ss1)
        # ss2 = rotl(a, 12)
        roll(12, ss2)
      when 1
        # tmp1 = w[i+4]
        movl(w[i+4], tmp1)
        # ss1 = T[i] + e + rotl(a, 12)
        addl(ss2, ss1)
        # tmp2 = w[i]
        movl(w[i], tmp2)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7)
        roll(7, ss1)
      when 2
        # ss2 = rotl(a, 12) ^ ss1
        xorl(ss1, ss2)
        # tmp1 = w[i+4] ^ w[i]
        xorl(tmp2, tmp1)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7) + w[i]
        addl(tmp2, ss1)
        # ss2 = (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i])
        addl(tmp1, ss2)
      when 3
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7) + w[i] + h
        addl(s[7], ss1)
        # ss2 = (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i]) + d
        addl(s[3], ss2)
        # tt2 = f
        movl(s[5], s[3])
        # tt1 = b
        movl(s[1], s[7])
      when 4
        # tmp3 = b
        movl(s[1], tt2)
        # tt1 = b ^ a
        xorl(s[0], s[7])
        # tmp3 = b ^ c
        xorl(s[2], tt2)
        # tt2 = f ^ g
        xorl(s[6], s[3])
      when 5
        # tt1 = (b ^ a) & (b ^ c)
        andl(tt2, s[7])
        # tt2 = (f ^ g) & e
        andl(s[4], s[3])
        # tt1 = ((b ^ a) & (b ^ c)) ^ b
        xorl(s[1], s[7])
        # tt2 = ((f ^ g) & e) ^ g
        xorl(s[6], s[3])
      when 6
        # tt1 += ss2 => tt1 += (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i]) + d
        addl(ss2, s[7])
        # tt2 += ss1 => tt2 += rotl(T[i] + e + rotl(a, 12), 7) + w[i] + h
        addl(ss1, s[3])
        # d = tt2
        movl(s[3], tt2)
        # d = rotl(tt2, 8)
        roll(8, s[3])
      when 7
        # b = rotl(b, 9)
        roll(9, s[1])
        # d = rotl(tt2, 8) ^ tt2
        xorl(tt2, s[3])
        # f = rotl(f, 19)
        roll(19, s[5])
        # d = rotl(rotl(tt2, 8) ^ d), 9)
        roll(9, s[3])
        # d = rotl(rotl(tt2, 8) ^ d), 9) ^ d
        xorl(tt2, s[3])
        c = -1
      end
      c += 1
    end
    c
  end

  def msg_sched_4(x, s, w, i, l, tx, step)
    commenta("msg_sched: #{i}-#{i+3}")
      c = 0
      c = step.call(s, w, i, l, c, 1)
    vpalignr(12, x[0], x[1], tx[1])   # XTMP1 = W[-13]
      c = step.call(s, w, i, l, c, 1)
    vpalignr(8, x[2], x[3], tx[0])    # XTMP0 = W[-6]
      c = step.call(s, w, i, l, c, 1)
    vpslld(7, tx[1], tx[4])           # XTMP4 = W[-13] << 7
    vpsrld(25, tx[1], tx[5])          # XTMP5 = W[-13] >> (32-7)
      c = step.call(s, w, i, l, c, 1)
    vpor(tx[5], tx[4], tx[5])         # XTMP5 |= XTMP4
      c = step.call(s, w, i, l, c, 1)
    vpxor(tx[5], tx[0], tx[5])        # XTMP5 ^= XTMP0                KEEP XTMP5
      c = step.call(s, w, i, l, c, 1)
    vpalignr(12, x[1], x[2], tx[6])   # XTMP6 = W[-9]
      c = step.call(s, w, i, l, c, 2)
    vpxor(tx[6], x[0], tx[6])         # XTMP6 ^= W[-16]               KEEP XTMP6
      s.rotate!(-1)
      c = step.call(s, w, i+1, l, c, 1)
    vpshufd(0b11111001, x[3], tx[0])  # XTMP0 = W[-3] {CCBA}
      c = step.call(s, w, i+1, l, c, 2)
    vpslld(15, tx[0], tx[1])          # XTMP1 = W[-3] << 15
    vpsrld(17, tx[0], tx[0])          # XTMP0 = W[-3] >> (32-15)
      c = step.call(s, w, i+1, l, c, 1)
    vpor(tx[0], tx[1], tx[0])         # XTMP0 |= XTMP1
      c = step.call(s, w, i+1, l, c, 1)
    vpxor(tx[0], tx[6], tx[0])        # XTMP0 ^= XTMP6                USE XTMP6
      c = step.call(s, w, i+1, l, c, 1)
                                      # P1(XTMP1)
    vpslld(15, tx[0], tx[4])          # XTMP4 = XTMP0 << 15
    vpsrld(17, tx[0], tx[3])          # XTMP3 = XTMP0 >> (32-15)
      c = step.call(s, w, i+1, l, c, 1)
    vpslld(23, tx[0], tx[2])          # XTMP2 = XTMP0 << 23
    vpsrld(9, tx[0], tx[1])           # XTMP1 = XTMP0 >> (32-23)
      c = step.call(s, w, i+1, l, c, 1)
      s.rotate!(-1)
      c = step.call(s, w, i+2, l, c, 1)
    vpor(tx[4], tx[3], tx[4])         # XTMP4 |= XTMP3
    vpor(tx[2], tx[1], tx[2])         # XTMP2 |= XTMP1
      c = step.call(s, w, i+2, l, c, 1)
    vpxor(tx[4], tx[2], tx[4])        # XTMP4 ^= XTMP2
    vpxor(tx[0], tx[5], tx[0])        # XTMP0 ^= XTMP5                USE XTMP5
      c = step.call(s, w, i+2, l, c, 1)
    vpxor(tx[4], tx[0], tx[4])        # XTMP4 ^= XTMP0
      c = step.call(s, w, i+2, l, c, 2)
                                      # Use XTMP4[0] and redo
    vpshufd(0b00000000, tx[4], tx[0]) # XTMP0 = W[-3] {DDDD}
      c = step.call(s, w, i+2, l, c, 1)
    vpslld(15, tx[0], tx[1])          # XTMP1 = W[-3] << 15
    vpsrld(17, tx[0], tx[0])          # XTMP0 = W[-3] >> (32-15)
      c = step.call(s, w, i+2, l, c, 1)
    vpor(tx[0], tx[1], tx[0])         # XTMP0 |= XTMP1
      c = step.call(s, w, i+2, l, c, 1)
      s.rotate!(-1)
    vpxor(tx[6], tx[0], tx[6])        # XTMP6 ^= XTMP0                USE XTMP6
      c = step.call(s, w, i+3, l, c, 1)
                                      # P1(XTMP6)
    vpslld(15, tx[6], tx[3])          # XTMP3 = XTMP6 << 15
    vpsrld(17, tx[6], tx[2])          # XTMP2 = XTMP6 >> (32-15)
      c = step.call(s, w, i+3, l, c, 1)
    vpslld(23, tx[6], tx[1])          # XTMP1 = XTMP6 << 23
    vpsrld(9, tx[6], tx[0])           # XTMP0 = XTMP6 >> (32-23)
      c = step.call(s, w, i+3, l, c, 1)
    vpor(tx[3], tx[2], tx[3])         # XTMP3 |= XTMP2
    vpor(tx[1], tx[0], tx[1])         # XTMP1 |= XTMP0
      c = step.call(s, w, i+3, l, c, 1)
    vpxor(tx[6], tx[3], tx[6])        # XTMP6 ^= XTMP3
    vpxor(tx[1], tx[5], tx[1])        # XTMP1 ^= XTMP5                USE XTMP5
      c = step.call(s, w, i+3, l, c, 1)
    vpxor(tx[6], tx[1], tx[6])        # XTMP6 ^= XTMP1
      c = step.call(s, w, i+3, l, c, 1)
                                             # Combine
    vpblendw(0b11000000, tx[6], tx[4], x[0]) # X[0] = XTMP4[0..2] | XTMP6[3]
      c = step.call(s, w, i+3, l, c, 1)
      c = step.call(s, w, i+3, l, c, 1)
    commenta("msg_sched done: #{i}-#{i+3}")
      s.rotate!(-1)
  end

  def transform_block_4(w, s, l, x, tx)
    # First 16 words in W - changed to little endian
    x_to_w(w, 0, x)
    # First 16 iterations.
    0.upto(3) do |j|
      # 4 iterations performed. 4 words of W calculated.
      msg_sched_4(x, s, w, j*4, l, tx, method(:iter_00_15_step))
      x.rotate!
      x2_to_w(w, j+3, x) if j == 1 or j == 3
    end
    # Next 32 iterations.
    1.upto(2) do |i|
      # Next 16 words in W
      0.upto(3) do |j|
        # 4 iterations performed. 4 words of W calculated.
        msg_sched_4(x, s, w, i*16+j*4, l, tx, method(:iter_16_63_step))
        x.rotate!
        x2_to_w(w, i*4+j+3, x) if j == 1 or j == 3
      end
    end

    msg_sched_4(x, s, w, 3*16, l, tx, method(:iter_16_63_step))
    4.upto(15) do |j|
      x0_to_w(w, 4*4, x) if j == 8
      c = 0
      c = iter_16_63_step(s, w, 3*16+j, l, c, 8)
      s.rotate!(-1)
    end
  end

  # Doesn't work
  def msg_sched_3(x, s, w, i, l, tx, step)
    commenta("msg_sched: #{i}-#{i+3}")
      c = 0
      c = step.call(s, w, i, l, c, 1)
    if i % 4 == 0
      vpalignr(12, x[0], x[1], tx[1])   # XTMP1 = W[-13]
      vpalignr(8, x[2], x[3], tx[0])    # XTMP0 = W[-6]
    elsif i % 4 == 3
      vpalignr(8, x[1], x[2], tx[1])    # XTMP1 = W[-13]
      vpshufd(0b11111001, x[3], tx[0])  # XTMP0 = W[-6]
    elsif i % 4 == 2
      vpshufd(0b11111001, x[1], tx[1])  # XTMP1 = W[-13]
      vmovdqa(x[3], tx[0])              # XTMP0 = W[-6]
    elsif i % 4 == 1
      vmovdqa(x[1], tx[1])              # XTMP0 = W[-13]
      vpalignr(12, x[2], x[3], tx[0])   # XTMP0 = W[-6]
    end
      c = step.call(s, w, i, l, c, 2)
    vpslld(7, tx[1], tx[4])           # XTMP4 = W[-13] << 7
    vpsrld(25, tx[1], tx[5])          # XTMP5 = W[-13] >> (32-7)
      c = step.call(s, w, i, l, c, 1)
    vpor(tx[5], tx[4], tx[5])         # XTMP5 |= XTMP4
      c = step.call(s, w, i, l, c, 1)
    vpxor(tx[5], tx[0], tx[5])        # XTMP5 ^= XTMP0                KEEP XTMP5
      c = step.call(s, w, i, l, c, 1)
    if i % 4 == 0
      vpalignr(12, x[1], x[2], tx[6])   # XTMP6 = W[-9]
    elsif i % 4 == 3
      vpalignr(8, x[2], x[3], tx[6])    # XTMP6 = W[-9]
    elsif i % 4 == 2
      vpshufd(0b11111001, x[2], tx[6])  # XTMP6 = W[-9]
    elsif i % 4 == 1
                                        # XTMP6 = W[-9] = x[2]
    end
      c = step.call(s, w, i, l, c, 2)
    if i % 4 == 0
      vpxor(tx[6], x[0], tx[6])          # XTMP6 ^= W[-16]            KEEP XTMP6
      s.rotate!(-1)
      c = step.call(s, w, i+1, l, c, 1)
      c = step.call(s, w, i+1, l, c, 1)
      vpshufd(0b11111001, x[3], tx[0])   # XTMP0 = W[-3] {CCBA}
    elsif i % 4 == 3
      vpalignr(12, x[0], x[1], tx[2])    # XTMP6 = W[-16]
      s.rotate!(-1)
      c = step.call(s, w, i+1, l, c, 1)
      c = step.call(s, w, i+1, l, c, 1)
      vpxor(tx[6], tx[2], tx[6])         # XTMP6 ^= W[-16]            KEEP XTMP6
      vmovdqa(x[0], tx[0])               # XTMP0 = W[-3] {CCBA}
    elsif i % 4 == 2
      vpalignr(8, x[0], x[1], tx[2])     # XTMP6 = W[-16]
      s.rotate!(-1)
      c = step.call(s, w, i+1, l, c, 1)
      c = step.call(s, w, i+1, l, c, 1)
      vpxor(tx[6], tx[2], tx[6])         # XTMP6 ^= W[-16]            KEEP XTMP6
      vpalignr(12, x[3], x[0], tx[0])    # XTMP0 = W[-3]
    elsif i % 4 == 1
      vpshufd(0b11111001, x[0], tx[2])   # XTMP6 = W[-16]
      s.rotate!(-1)
      c = step.call(s, w, i+1, l, c, 1)
      c = step.call(s, w, i+1, l, c, 1)
      vpxor(x[2], tx[2], tx[6])          # XTMP6 ^= W[-16]            KEEP XTMP6
      vpalignr(8, x[3], x[0], tx[0])     # XTMP0 = W[-3]
    end
      c = step.call(s, w, i+1, l, c, 2)
    vpslld(15, tx[0], tx[1])          # XTMP1 = W[-3] << 15
    vpsrld(17, tx[0], tx[0])          # XTMP0 = W[-3] >> (32-15)
      c = step.call(s, w, i+1, l, c, 1)
    vpor(tx[0], tx[1], tx[0])         # XTMP0 |= XTMP1
      c = step.call(s, w, i+1, l, c, 1)
    vpxor(tx[0], tx[6], tx[0])        # XTMP0 ^= XTMP6                USE XTMP6
      c = step.call(s, w, i+1, l, c, 1)
                                      # P1(XTMP1)
    vpslld(15, tx[0], tx[4])          # XTMP4 = XTMP0 << 15
    vpsrld(17, tx[0], tx[3])          # XTMP3 = XTMP0 >> (32-15)
      c = step.call(s, w, i+1, l, c, 1)
      s.rotate!(-1)
      c = step.call(s, w, i+2, l, c, 1)
    vpslld(23, tx[0], tx[2])          # XTMP2 = XTMP0 << 23
    vpsrld(9, tx[0], tx[1])           # XTMP1 = XTMP0 >> (32-23)
      c = step.call(s, w, i+2, l, c, 1)
    vpor(tx[4], tx[3], tx[4])         # XTMP4 |= XTMP3
    vpor(tx[2], tx[1], tx[2])         # XTMP2 |= XTMP1
      c = step.call(s, w, i+2, l, c, 1)
    vpxor(tx[4], tx[2], tx[4])        # XTMP4 ^= XTMP2
    vpxor(tx[0], tx[5], tx[0])        # XTMP0 ^= XTMP5                USE XTMP5
      c = step.call(s, w, i+2, l, c, 1)
    vpxor(tx[4], tx[0], tx[4])        # XTMP4 ^= XTMP0
      c = step.call(s, w, i+2, l, c, 1)
    if i % 4 == 0
      vpblendw(0b00111111, tx[4], x[0], x[0]) # X[0] replace bottom 3 words
      c = step.call(s, w, i+2, l, c, 1)
      c = step.call(s, w, i+2, l, c, 1)
      c = step.call(s, w, i+2, l, c, 1)
    elsif i % 4 == 3
      vpshufd(0b00111001, tx[4], tx[4])  # XTMP4 {A0CB}               KEEP XTMP4
      c = step.call(s, w, i+2, l, c, 1)
      c = step.call(s, w, i+2, l, c, 1)
      vpblendw(0b11000000, tx[4], x[0], x[0]) # X[0] replace top word
      vpblendw(0b00001111, tx[4], x[1], x[1]) # X[1] replace bottom 2 words
      c = step.call(s, w, i+2, l, c, 1)
    elsif i % 4 == 2
      vpshufd(0b01001110, tx[4], tx[4])  # XTMP4 {BA0C}               KEEP XTMP4
      c = step.call(s, w, i+2, l, c, 1)
      c = step.call(s, w, i+2, l, c, 1)
      vpblendw(0b11110000, tx[4], x[0], x[0]) # X[0] replace top 2 words
      vpblendw(0b00000011, tx[4], x[1], x[1]) # X[1] replace bottom word
      c = step.call(s, w, i+2, l, c, 1)
    elsif i % 4 == 1
      vpshufd(0b10010011, tx[4], tx[4])  # XTMP4 {CBA0}               KEEP XTMP4
      c = step.call(s, w, i+2, l, c, 1)
      c = step.call(s, w, i+2, l, c, 1)
      vpblendw(0b11111100, tx[4], x[0], x[0]) # X[0] replace top 3 words
      c = step.call(s, w, i+2, l, c, 1)
    end
    commenta("msg_sched done: #{i}-#{i+2}")
      s.rotate!(-1)
  end

  # Doesn't work
  def transform_block_3(w, s, l, x, tx)
    # First 16 words in W - changed to little endian
    x_to_w(w, 0, x)
    # First 12 iterations.
    0.upto(3) do |j|
      # 3 iterations performed. 3 words of W calculated.
      msg_sched_3(x, s, w, j*3, l, tx, method(:iter_00_15_step))
      x.rotate! if j == 1 or j == 2 or j == 3
      x2_to_w(w, 4, x) if j == 2
    end
    # Next 4 iterations.
    msg_sched_4(x, s, w, 12, l, tx, method(:iter_00_15_step))
    x.rotate!
    x2_to_w(w, 6, x)
    wi = 8
    done4 = 0
    # Next 36 iterations.
    0.upto(11) do |j|
      # 3 iterations performed. 3 words of W calculated.
      msg_sched_3(x, s, w, 16+j*3, l, tx, method(:iter_16_63_step))
      if ((j + 1) * 3) / 4 != done4
        x0_to_w(w, wi, x)
        wi += 1
        x.rotate!
        done4 += 1
      end
    end

    0.upto(11) do |j|
      x0_to_w(w, 16, x) if j == 8
      c = 0
      c = iter_16_63_step(s, w, 52+j, l, c, 8)
      s.rotate!(-1)
    end
  end

  def transform_block(w, s, l, x, tx)
    transform_block_4(w, s, l, x, tx)
  end

  def write_transform()
    @t = constanta(@label_pre + "_t", 32,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
        0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
        0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
        0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
        0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
        0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
        0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53,
        0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
        0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4,
        0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
        0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
        0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
        0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5
    )

    @flip = constanta(@label_pre + "_flip_mask", 64,
                      0x0405060700010203, 0x0c0d0e0f08090a0b)

    static_func(["int", 32], "sm3_compress_" + @func_impl,
                ["wc_Sm3*", "sm3", 1, 64],
               )

    # offset (bytes)
    #      0  digest - 32
    #     32  buffer - 64
    #     96  bufLen -  4
    #    100  loLen  -  4
    #    104  hiLen  -  4
    #    108  heap   -  8 (ptr)
    l = [ use_reg(rdx), use_reg(rcx), use_reg(rax), use_reg(rbx) ]
    s = [ use_reg(r8) , use_reg(r9) , use_reg(r10), use_reg(r11),
          use_reg(r12), use_reg(r13), use_reg(r14), use_reg(r15) ]
    @ctx = use_param(0)
    digest = @ctx.get(32)
    buffer = l[2]


    x = [ xmm0, xmm1, xmm2, xmm3 ]
    tx = [ xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10 ]
    flip_mask = xmm11

    stack = use_stack(68, 32)
    w = stack.get(32)

    ctx = @label_pre + "_transform"

    asm()

    leaq(@ctx[4], buffer)
    vmovdqa(@flip, flip_mask)
    load_digest(digest, s)

    buffer_to_x(x, buffer)

    transform_block(w, s, l, x, tx)

    store_xor_digest(digest, s)

    # return 0
    xorq(rax, rax)

    vzeroupper()

    end_asm()
    end_func()
  end

  def write_transform_len()
    static_func(["int", 32], "sm3_compress_len_" + @func_impl,
                ["wc_Sm3*", "sm3", 1, 64],
                ["const byte*", "data", 1, 64],
                ["word32", "len", 1, 32],
               )

    loop_start = add_label(@label_pre + "len_start")

    # offset (bytes)
    #      0  digest - 32
    #     32  buffer - 64
    #     96  bufLen -  4
    #    100  loLen  -  4
    #    104  hiLen  -  4
    #    108  heap   -  8 (ptr)
    l = [ use_reg(rdx), use_reg(rcx), use_reg(rax), use_reg(rbx) ]
    s = [ use_reg(r8) , use_reg(r9) , use_reg(r10), use_reg(r11),
          use_reg(r12), use_reg(r13), use_reg(r14), use_reg(r15) ]
    @ctx = use_param(0)
    buffer = use_param(1, rbp)
    @len = use_param(2)
    digest = @ctx.get(32)


    x = [ xmm0, xmm1, xmm2, xmm3 ]
    tx = [ xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10 ]
    flip_mask = xmm11

    stack = use_stack(68, 32)
    w = stack.get(32)

    ctx = @label_pre + "transform_len"

    asm()

    vmovdqa(@flip, flip_mask)
    load_digest(digest, s)

    commenta("Start of loop processing a block")
    set_label(loop_start)

    buffer_to_x(x, buffer, flip_mask)

    transform_block(w, s, l, x, tx)

    xor_digest(digest, s)

    addq(64, buffer)
    subl(64, @len)

    store_digest(digest, s)

    jnz(loop_start)

    # return 0
    xorq(rax, rax)

    vzeroupper()

    end_asm()
    end_func()
  end

  def write()
    write_transform()
    write_transform_len()
  end
end

