#!/bin/sh

if [ ! -d "../scripts/asm" ]; then
   echo "'scripts' repository needs to be checked out next to wolfsm"
   return 1
fi

echo -n "Generating x86_64 assembly files ... "
ruby ./scripts/sm3/sm3.rb x86_64 sm3_asm
echo "Done"
echo "Generating SP files ... "
cd scripts
./gen-sp-sm2.sh
echo "Done"

