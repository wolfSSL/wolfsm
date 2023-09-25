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

module ModInvX86_64_SM2
  # Parameter 'a' must contain registers r8-15
  # Requires rbp
  def do_mont_red_order_sm2_p256(words, a, reg, r1, r2, r3, res, xor)
    mv = []
    0.upto(words-1) do |i|
      mv[i] = (@order >> (i * 64)) & ((1 << 64) - 1)
    end
    t = [ r3, rbx, nil, rbp ]
    mr = [ reg, r1 ]
    mu = rdx
    c = a[0]
    zero = t[3]
    mp = t[1]
    mn = t[0]

    commenta "Start Reduction"
    movq(@mp_order, mp)

    0.upto(3) do |i|
      commenta " A[#{i+0}]"
      movq(mp, mu)
      imulq(a[i+0], mu)
      movq(mv[0], mn)
      xorq(zero, zero)
      mulxq(mn, mr[0], mr[1])
      movq(mv[1], mn)
      adcxq(mr[0], a[i+0])
      adoxq(mr[1], a[i+1])
      mulxq(mn, mr[0], mr[1])
      movq(mv[2], mn)
      adcxq(mr[0], a[i+1])
      adoxq(mr[1], a[i+2])
      mulxq(mn, mr[0], mr[1])
      movq(mv[3], mn)
      adcxq(mr[0], a[i+2])
      adoxq(mr[1], a[i+3])
      mulxq(mn, mr[0], mr[1])
      adcxq(mr[0], a[i+3])
      adoxq(mr[1], a[i+4])
      if i == 0
        adcxq(zero, a[i+4])
      else
        adcxq(c, a[i+4])
      end
      movq(zero, c)
      commenta "  carry"
      adoxq(zero, c)
      adcxq(zero, c)
    end

    negq(c)
    # Load up modulus and mask for conditional subtract
    # t[2] = 0xffffffff = c
    movq(mv[0], t[0])
    movq(mv[1], t[1])
    andq(c, t[0])
    movq(mv[3], t[3])
    andq(c, t[1])
    andq(c, t[3])
    # Subtract and store
    subq(t[0], a[4])
    sbbq(t[1], a[5])
    movq(a[4], res[0])
    sbbq(   c, a[6])
    movq(a[5], res[1])
    sbbq(t[3], a[7])
    movq(a[6], res[2])
    movq(a[7], res[3])
  end
end

