# sm3_avx1_rorx.rb
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


class SM3_ASM_X86_64_AVX1_RORX <SM3_ASM_X86_64_AVX1
  def initialize(att_asm, msvc_asm)
    super(att_asm, msvc_asm)
    @func_impl = "avx1_rorx"
    @label_pre = "L_SM3_AVX1_RORX"
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
        # ss2 = rotl(a, 12)
        rorxl(32-12, s[0], ss2)
        # ss1 = T[i] + e
        addl(s[4], ss1)
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
        # tt2 = rotl(d, 17)
        rorxl(32-17, s[3], tt2)
      when 6
        # tt1 = rotl(d, 9)
        rorxl(32-9, s[3], tt1)
        # b = rotl(b, 9)
        roll(9, s[1])
        # d ^= rotl(d, 17)
        xorl(tt2, s[3])
      when 7
        # f = rotl(f, 19)
        roll(19, s[5])
        # d ^= rotl(d, 17) ^ rotl(d, 9)
        xorl(tt1, s[3])
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
        # ss2 = rotl(a, 12)
        rorxl(32-12, s[0], ss2)
        # ss1 = T[i] + e
        addl(s[4], ss1)
        # tmp1 = w[i+4]
        movl(w[i+4], tmp1)
      when 1
        # ss1 = T[i] + e + rotl(a, 12)
        addl(ss2, ss1)
        # tmp2 = w[i]
        movl(w[i], tmp2)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7)
        roll(7, ss1)
        # ss2 = rotl(a, 12) ^ ss1
        xorl(ss1, ss2)
      when 2
        # tmp1 = w[i+4] ^ w[i]
        xorl(tmp2, tmp1)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7) + w[i]
        addl(tmp2, ss1)
        # ss2 = (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i])
        addl(tmp1, ss2)
        # ss1 = rotl(T[i] + e + rotl(a, 12), 7) + w[i] + h
        addl(s[7], ss1)
      when 3
        # ss2 = (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i]) + d
        addl(s[3], ss2)
        # tt1 = b
        movl(s[1], s[7])
        # tmp3 = b
        movl(s[1], tt2)
        # tt1 = b ^ a
        xorl(s[0], s[7])
      when 4
        # tt2 = b ^ c
        xorl(s[2], tt2)
        # tt2 = (~e) ^ g
        andn(s[6], s[4], s[3])
        # tt1 = (b ^ a) & (b ^ c)
        andl(tt2, s[7])
        # tt2 = e
        movl(s[4], tt2)
      when 5
        # tt1 = ((b ^ a) & (b ^ c)) ^ b
        xorl(s[1], s[7])
        # tt2 = e & f
        andl(s[5], tt2)
        # tt1 += ss2 => tt1 += (rotl(a, 12) ^ ss1) + (w[i+4] ^ w[i]) + d
        addl(ss2, s[7])
        # tt2 = (e & f) | ((~e) ^ g)
        orl(tt2, s[3])
      when 6
        # tt2 += ss1 => tt2 += rotl(T[i] + e + rotl(a, 12), 7) + w[i] + h
        addl(ss1, s[3])
        # tt2 = rotl(d, 17)
        rorxl(32-17, s[3], tt2)
        # tt1 = rotl(d, 9)
        rorxl(32-9, s[3], tt1)
        # b = rotl(b, 9)
        roll(9, s[1])
      when 7
        # d ^= rotl(d, 17)
        xorl(tt2, s[3])
        # f = rotl(f, 19)
        roll(19, s[5])
        # d ^= rotl(d, 17) ^ rotl(d, 9)
        xorl(tt1, s[3])
        c = -1
      end
      c += 1
    end
    c
  end
end
