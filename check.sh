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

echo "Diffing files with those in wolfssl ... "
echo "sm3.h $WOLFSSL_DIR/wolfssl/wolfcrypt/sm3.h"
diff sm3.h $WOLFSSL_DIR/wolfssl/wolfcrypt/sm3.h
if [ "$?" = "0" ]; then
    echo "    SAME"
fi
echo "sm3.c $WOLFSSL_DIR/wolfcrypt/src/sm3.c"
diff sm3.c $WOLFSSL_DIR/wolfcrypt/src/sm3.c
if [ "$?" = "0" ]; then
    echo "    SAME"
fi
echo "sm3_asm.S $WOLFSSL_DIR/wolfcrypt/src/sm3_asm.S"
diff sm3_asm.S $WOLFSSL_DIR/wolfcrypt/src/sm3_asm.S
if [ "$?" = "0" ]; then
    echo "    SAME"
fi
echo "sm4.h $WOLFSSL_DIR/wolfssl/wolfcrypt/sm4.h"
diff sm4.h $WOLFSSL_DIR/wolfssl/wolfcrypt/sm4.h
if [ "$?" = "0" ]; then
    echo "    SAME"
fi
echo "sm4.c $WOLFSSL_DIR/wolfcrypt/src/sm4.c"
diff sm4.c $WOLFSSL_DIR/wolfcrypt/src/sm4.c
if [ "$?" = "0" ]; then
    echo "    SAME"
fi
echo "Done"

