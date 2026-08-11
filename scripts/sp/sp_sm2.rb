# sp_sm2.rb
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

require_relative "../../../scripts/sp/sp_impl.rb"
require_relative "./base_sm2.rb"
require_relative "./mod_sm2.rb"
require_relative "./modinv_sm2.rb"
require_relative "./mont_sm2.rb"
require_relative "./riscv64/mont_sm2.rb"
require_relative "./ecc_sm2.rb"

class SinglePrecision_SM2 <SinglePrecision
  include FileC_SM2
  include Ecc_SM2
end

class SinglePrecisionC_SM2 <SinglePrecisionC
  include FileC_SM2
  include ModMulNormC_SM2
  include ModInv_SM2
  include MontC_SM2
  include Ecc_SM2
end

class SinglePrecisionX86_64_SM2 <SinglePrecisionX86_64
  include FileC_SM2
  include ModInv_SM2
  include ModInvX86_64_SM2
  include MontX86_64_SM2
  include Ecc_SM2

  # WC_ASM_ATT_HIDDEN is defined in wolfssl/wolfcrypt/visibility.h, which only
  # gained it after v5.9.2.  wolfSSL's own generated assembly ships alongside
  # that header so it is always in step, but wolfsm is built against several
  # wolfSSL releases - the CI matrix includes v5.9.2-stable - and there the
  # macro is undefined and its name reaches the assembler, which reports
  # "invalid character '(' in mnemonic".  Emit a no-op fallback after the
  # includes so the output assembles against either.
  def header_asm(name)
    super(name)
    att.puta "#ifndef WC_ASM_ATT_HIDDEN"
    att.puta "#define WC_ASM_ATT_HIDDEN(name)"
    att.puta "#endif"
    att.puta ""
  end
end

class SinglePrecisionArm32_SM2 <SinglePrecisionArm32
  include FileC_SM2
  include ModInv_SM2
  include MontArm32_SM2
  include Ecc_SM2
end

class SinglePrecisionThumb2_SM2 <SinglePrecisionThumb2
  include FileC_SM2
  include ModInv_SM2
  include MontThumb2_SM2
  include Ecc_SM2
end

class SinglePrecisionArmThumb_SM2 <SinglePrecisionArmThumb
  include FileC_SM2
  include ModInv_SM2
  include MontArmThumb_SM2
  include Ecc_SM2
end

class SinglePrecisionRiscv64_SM2 <SinglePrecisionRiscv64
  include FileC_SM2
  include ModInv_SM2
  include MontRiscv64_SM2
  include Ecc_SM2
end

class SinglePrecisionArm64_SM2 <SinglePrecisionArm64
  include FileC_SM2
  include ModInv_SM2
  include MontArm64_SM2
  include Ecc_SM2
end


def generate_sm2(platform, out_file)
  case platform
    when "32"
      sp32 = SinglePrecisionC_SM2.new(32)
      sp32.header("sp.c")
      sp32.ifndef("WOLFSSL_SP_ASM")
      sp32.ifs("SP_WORD_SIZE == 32")
      sp32.write_num_macro()
      sp32.write_addr()
      sp32.ifdef("WOLFSSL_HAVE_SP_ECC")
      # Best speed
      sp32.write_ecc(256, 32, 9, true, "SM2")
      sp32.endif("WOLFSSL_HAVE_SP_ECC")
      sp32.endif("SP_WORD_SIZE == 32")
      sp32.endif("!WOLFSSL_SP_ASM")
      sp32.trailer()
    when "64"
      sp64 = SinglePrecisionC_SM2.new(64)
      sp64.header("sp.c")
      sp64.ifndef("WOLFSSL_SP_ASM")
      sp64.ifs("SP_WORD_SIZE == 64")
      sp64.write_num_macro()
      sp64.write_addr()
      sp64.ifdef("WOLFSSL_HAVE_SP_ECC")
      # 256 / 5 = 51.2, 2^52 * 5 => 2^56
      sp64.write_ecc(256, 64, 5, true, "SM2")
      sp64.endif("WOLFSSL_HAVE_SP_ECC")
      sp64.endif("SP_WORD_SIZE == 64")
      sp64.endif("!WOLFSSL_SP_ASM")
      sp64.trailer()
    when "x86_64"
      x86_64 = SinglePrecisionX86_64_SM2.new(64, out_file)
      x86_64.header("sp.c")
      x86_64.header_asm(out_file)
      x86_64.att.ifdefa("WOLFSSL_SP_X86_64_ASM")
      x86_64.ifdefc("WOLFSSL_SP_X86_64_ASM")
      x86_64.write_num_macro()
      x86_64.write_addr()
      x86_64.ifdefc("WOLFSSL_HAVE_SP_ECC")
      x86_64.write_ecc(256, 64, 4, true, "SM2")
      x86_64.endifc("WOLFSSL_HAVE_SP_ECC")
      x86_64.endifc("WOLFSSL_SP_X86_64_ASM")
      x86_64.att.endifa("WOLFSSL_SP_X86_64_ASM")
      x86_64.trailer_asm()
      x86_64.trailer()
    when "ARM32"
      asm = SinglePrecisionArm32_SM2.new(32, out_file)
      asm.header("sp.c")
      asm.ifdef("WOLFSSL_SP_ARM32_ASM")
      asm.write_num_macro()
      asm.write_addr()
      asm.ifdef("WOLFSSL_HAVE_SP_ECC")
      asm.write_ecc(256, 32, 8, true, "SM2")
      asm.endif("WOLFSSL_HAVE_SP_ECC")
      asm.endif("WOLFSSL_SP_ARM32_ASM")
      asm.trailer()
    when "Thumb2"
      asm = SinglePrecisionThumb2_SM2.new(32, out_file)
      asm.header("sp.c")
      asm.ifdef("WOLFSSL_SP_ARM_CORTEX_M_ASM")
      asm.write_num_macro()
      asm.write_addr()
      asm.ifdef("WOLFSSL_HAVE_SP_ECC")
      asm.write_ecc(256, 32, 8, true, "SM2")
      asm.endif("WOLFSSL_HAVE_SP_ECC")
      asm.endif("WOLFSSL_SP_ARM_CORTEX_M_ASM")
      asm.trailer()
    when "ARM_Thumb"
      gcc_file = File.open(out_file + ".c", "w")
      thumb = SinglePrecisionArmThumb_SM2.new(32, gcc_file)
      thumb.header("sp.c")
      thumb.ifdef("WOLFSSL_SP_ARM_THUMB_ASM")
      thumb.write_num_macro()
      thumb.write_addr()
      thumb.ifdef("WOLFSSL_HAVE_SP_ECC")
      thumb.write_ecc(256, 32, 8, true, "SM2")
      thumb.endif("WOLFSSL_HAVE_SP_ECC")
      thumb.endif("WOLFSSL_SP_ARM_THUMB_ASM")
      thumb.trailer()
      gcc_file.close
    when "ARM64"
      arm64 = SinglePrecisionArm64_SM2.new(64)
      arm64.header("sp.c")
      arm64.ifdef("WOLFSSL_SP_ARM64_ASM")
      arm64.write_num_macro()
      arm64.write_addr()
      arm64.ifdef("WOLFSSL_HAVE_SP_ECC")
      arm64.write_ecc(256, 64, 4, true, "SM2")
      arm64.endif("WOLFSSL_HAVE_SP_ECC")
      arm64.endif("WOLFSSL_SP_ARM64_ASM")
      arm64.trailer()
    when "RISCV64"
      rv = SinglePrecisionRiscv64_SM2.new(64, out_file)
      rv.header("sp.c")
      rv.ifdef("WOLFSSL_SP_RISCV64_ASM")
      rv.write_num_macro()
      rv.write_addr()
      rv.ifdef("WOLFSSL_HAVE_SP_ECC")
      rv.write_ecc(256, 64, 4, true, "SM2")
      rv.endif("WOLFSSL_HAVE_SP_ECC")
      rv.endif("WOLFSSL_SP_RISCV64_ASM")
      rv.trailer()
    else
      STDERR.puts "Bad target: #{platform}"
      STDERR.puts "Specify a target: 32 64 x86_64 ARM32 Thumb2 ARM_Thumb Cortex-M ARM64 RISCV64"
      exit 1
  end
end

if ARGV.length > 2
  STDERR.puts "Specify a target: 32 64 x86_64 ARM32 ARM_Thumb Cortex-M ARM64"
  exit 1
end

generate_sm2(ARGV[0], ARGV[1])

