# sm3.rb
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

require_relative "./x86_64/sm3.rb"

class SM3
  def header_asm(name)
    @asm.header_asm(name)
  end
  def trailer_asm()
    @asm.trailer_asm()
  end
end

class SM3_X86_64 <SM3
  include X86_64

  def initialize(att_asm, msvc_asm)
    @att_asm = ATT_X86_64_Asm.new(att_asm)
    @msvc_asm = MSVC_X86_64_Asm.new(msvc_asm)
  end

  def write()
    @sm3 = SM3_ASM_X86_64.new(@att_asm, @msvc_asm)
    @sm3.write()
  end
end

case ARGV[0]
when "x86_64"
  att_asm = File.open(ARGV[1] + ".S", "w")
  msvc_asm = File.open(ARGV[1] + ".asm", "w")
  x86_64 = SM3_X86_64.new(att_asm, msvc_asm)
  x86_64.header_asm(ARGV[1])
  x86_64.write()
  x86_64.trailer_asm()
  att_asm.close
  msvc_asm.close
else
  STDERR.puts "Bad target: #{ARGV[0]}"
  STDERR.puts "Specify a target: x86_64 arm32"
  exit 1
end

