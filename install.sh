#!/bin/sh

if [ $# -gt 1 ]
then
    echo "Usage: $0 [>path to wolfssl>]"
    return 1;
fi

WOLFSSL_DIR=../wolfssl
if [ $# -eq 1 ]
then
    WOLFSSL_DIR=$1
fi
if [ ! -d $WOLFSSL_DIR ]
then
    echo "Directory not found: $WOLFSSL_DIR"
    return 1
fi
if [ ! -f $WOLFSSL_DIR/wolfssl/wolfcrypt/sm3.h ]
then
    echo "Could not confirm directory is 'wolfssl': $WOLFSSL_DIR"
    echo "Failed to find file: sm3.h"
    return 1
fi

echo -n "Copying files into $WOLFSSL_DIR ... "
cp sm2.h               $WOLFSSL_DIR/wolfssl/wolfcrypt/
cp sm2.c               $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_c32.c        $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_c64.c        $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_x86_64.c     $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_x86_64_asm.S $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_arm32.c      $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_cortexm.c    $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_armthumb.c   $WOLFSSL_DIR/wolfcrypt/src/
cp sp_sm2_arm64.c      $WOLFSSL_DIR/wolfcrypt/src/

cp sm3.h               $WOLFSSL_DIR/wolfssl/wolfcrypt/
cp sm3.c               $WOLFSSL_DIR/wolfcrypt/src/
cp sm3_asm.S           $WOLFSSL_DIR/wolfcrypt/src/

cp sm4.h               $WOLFSSL_DIR/wolfssl/wolfcrypt/
cp sm4.c               $WOLFSSL_DIR/wolfcrypt/src/

cp certs_test_sm.h     $WOLFSSL_DIR/wolfssl/
echo "Done"
