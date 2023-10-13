#!/bin/sh

# Current directory is: wolfsm/scripts

OUT_DIR=..
if [ $# -eq 1 ]; then
    OUT_DIR=$1
fi

echo "C32..."
ruby sp/sp_sm2.rb 32 >$OUT_DIR/sp_sm2_c32.c
echo "C64..."
ruby sp/sp_sm2.rb 64 >$OUT_DIR/sp_sm2_c64.c
echo "arm32..."
ruby sp/sp_sm2.rb ARM32 $OUT_DIR/sp_sm2_arm32
echo "arm thumb..."
ruby sp/sp_sm2.rb ARM_Thumb $OUT_DIR/sp_sm2_armthumb
echo "Cortex-M..."
ruby sp/sp_sm2.rb Thumb2 $OUT_DIR/sp_sm2_cortexm
echo "arm64..."
ruby sp/sp_sm2.rb ARM64 >$OUT_DIR/sp_sm2_arm64.c
echo "x86_64..."
ruby sp/sp_sm2.rb x86_64 $OUT_DIR/sp_sm2_x86_64_asm >$OUT_DIR/sp_sm2_x86_64.c
echo "Done"

