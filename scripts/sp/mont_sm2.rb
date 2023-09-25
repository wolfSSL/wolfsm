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

module MontC_SM2
  def mont_red_sm2_256(words, total)
    over = @bits - (total % @bits)
    himask = (1 << (total % @bits)) - 1
    hibits = total % @bits

    if false
      norm(words*2, @total)
      to_bin_size(words, total)
      to_bin_size(2*words, 2*total)
    end
    cmp(words)
    sub_cond(words)
    mul_add(words, 256)
    norm(words, @total)
    mont_shift(words, over, total)

    puts <<EOF
/* Reduce the number back to #{@total} bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_#{@total}_mont_reduce_#{@namef}#{words}(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

EOF
    if false
      puts <<EOF
SP_PRINT_NUM(a, "a", #{@total}, #{2*words}, #{2*total});
SP_PRINT_NUM(m, "m", #{@total}, #{words}, #{total});
SP_PRINT_VAL(mp, "mp");

EOF
    end
    puts <<EOF
    if (mp != 1) {
        for (i=0; i<#{words-1}; i++) {
            mu = (a[i] * mp) & #{@mask};
            sp_#{@total}_mul_add_#{@namef}#{words}(a+i, m, mu);
            a[i+1] += a[i] >> #{@bits};
        }
        mu = (a[i] * mp) & 0x#{himask.to_s(16)}L;
        sp_#{@total}_mul_add_#{@namef}#{words}(a+i, m, mu);
        a[i+1] += a[i] >> #{@bits};
        a[i] &= #{@mask};
    }
    else {
        for (i=0; i<#{words-1}; i++) {
            mu = a[i] & #{@mask};
            sp_#{@total}_mul_add_#{@namef}#{words}(a+i, #{@cname}_mod, mu);
            a[i+1] += a[i] >> #{@bits};
        }
        mu = a[i] & 0x#{himask.to_s(16)}L;
        sp_#{@total}_mul_add_#{@namef}#{words}(a+i, #{@cname}_mod, mu);
        a[i+1] += a[i] >> #{@bits};
        a[i] &= #{@mask};
    }

    sp_#{@total}_mont_shift_#{words}(a, a);
    sp_#{@total}_cond_sub_#{@namef}#{words}(a, a, m, 0 - (((a[#{words-1}] >> #{hibits}) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_#{@total}_norm_#{words}(a);
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
end

require_relative "x86_64/mont_sm2.rb"
require_relative "arm64/mont_sm2.rb"
require_relative "arm32/mont_sm2.rb"
require_relative "thumb2/mont_sm2.rb"
require_relative "thumb/mont_sm2.rb"

