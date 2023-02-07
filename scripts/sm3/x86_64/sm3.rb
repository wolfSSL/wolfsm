# sm3.rb
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

require_relative "../../../../scripts/asm/x86_64/x86_64.rb"
require_relative "./sm3_avx1.rb"
require_relative "./sm3_avx1_rorx.rb"

class SM3_ASM_X86_64
  include X86_64

  def initialize(att_asm, msvc_asm)
    @avx1 = SM3_ASM_X86_64_AVX1.new(att_asm, msvc_asm)
    @avx1_rorx = SM3_ASM_X86_64_AVX1_RORX.new(att_asm, msvc_asm)
  end

  def write()
    @avx1.ifdefa("WOLFSSL_X86_64_BUILD")
    @avx1.ifdefa("HAVE_INTEL_AVX1")
    @avx1.write
    @avx1_rorx.write
    @avx1.endifa("HAVE_INTEL_AVX1")
    @avx1.endifa("WOLFSSL_X86_64_BUILD")
  end
end

