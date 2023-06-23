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

check_file() {
    echo "$1 $WOLFSSL_DIR/$2/$1"
    diff $1 $WOLFSSL_DIR/$2/$1
    if [ "$?" = "0" ]; then
        echo "    SAME"
    fi
}

echo "Diffing files with those in wolfssl ... "
check_file sm2.h wolfssl/wolfcrypt
check_file sm2.c wolfcrypt/src
check_file sm3.h wolfssl/wolfcrypt
check_file sm3.c wolfcrypt/src
check_file sm3_asm.S wolfcrypt/src
check_file sm4.h wolfssl/wolfcrypt
check_file sm4.c wolfcrypt/src
echo "Done"

