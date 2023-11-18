# wolfSSL SM Algorithms

This repository contains the implementations of the Chinese Nation Standard's
cryptographic algorithms known as ShangMi (SM).

Support includes:
* SM3 - Hash Function
* SM4 - Cipher
* SM2 - ECDH key agreement and a signature scheme using the specified 256-bit elliptic curve.

The code must be installed into wolfSSL in order to be used.

Note that the test and build configuration code is already in wolfSSL.

## Get wolfsm from GitHub

Clone this repository from GitHub:

```
git clone https://github.com/wolfssl/wolfsm.git
```

## Get wolfSSL from GitHub

wolfSSL is needed to build and test the SM algorithm implementations.
Checkout the wolfSSL repository from GitHub beside wolfsm:

```
<install-dir>
├── wolfsm
└── wolfssl
```

```
cd .. # To directory containing wolfsm
git clone https://github.com/wolfssl/wolfssl.git
```

## Install SM code into wolfSSL

To install the SM code into wolfSSL, use the install script:

```bash
cd wolfsm
./install.sh
```

If you have wolfssl installed in a different directory, such as `wolfssl-username`:

```bash
cd wolfsm
./install.sh ../wolfssl-$USER
```

The following file will be placed in wolfssl/wolfssl:
* certs_test_sm.h

The following files will be placed in wolfssl/wolfssl/wolfcrypt:
* sm2.h
* sm3.h
* sm4.h

The following files will be placed in wolfssl/wolfcrypt/src:
* sm2.c
* sp_sm2_arm32.c      (Assembly optimised SM2 for ARM 32-bit)
* sp_sm2_arm64.c      (Assembly optimised SM2 for Aarch64)
* sp_sm2_armthumb.c   (Assembly optimised SM2 for ARM Thumb)
* sp_sm2_c32.c        (C only optimised SM2 for 32-bit CPUs)
* sp_sm2_c64.c        (C only optimised SM2 for 64-bit CPUs)
* sp_sm2_cortexm.c    (Assembly optimised SM2 for ARM Thumb2)
* sp_sm2_x86_64_asm.S (Assembly optimised SM2 for Intel x64)
* sp_sm2_x86_64.c     (C calling assembly optimised SM2 for Intel x64)
* sm3.c
* sm3_asm.S           (Assembly optimised SM2 for Intel x64)
* sm4.c

## Build wolfSSL

Once the files have been installed, you can build SM algorithms into wolfSSL.

Choose which algorithms you require on the configure line:
* --enable-sm3
* --enable-sm4-ecb
* --enable-sm4-cbc
* --enable-sm4-ctr
* --enable-sm4-gcm
* --enable-sm4-ccm
* --enable-sm2

For example, to include SM3, SM4-GCM and SM2:

```
cd ../wolfssl
./autogen.sh
./configure --enable-sm3 --enable-sm4-gcm --enable-sm2
make
sudo make install
```

### Optimised SM2

To use optimised implementations of SM2 you can either use C only code or C code
with the faster assembly code.

For C code only: --enable-sp
For C and assembly code: --enable-sp --enable-sp-asm

Optimised C code is available for 32 and 64 bit CPUs.

Assmembly code is available for the following platforms:
* Intel x64
* Aarch64
* ARM 32-bit
* ARM Thumb2
* ARM Thumb

## Testing Algorithms

To test that the SM ciphers are working use the following command:

```
make test
```

To benchmark the algorithms enabled:

```
./wolfcrypt/benchmark/benchmark
```

To benchmark specific algorithms, add to the command line the option/s matching
the algorithm/s:
* SM2: -sm2
* SM3: -sm3
* SM4: -sm4 or
  * SM4-CBC: -sm4-cbc
  * SM4-GCM: -sm4-gcm
  * SM4-CCM: -sm4-ccm

## Testing TLS

SM ciphers are able to be used with TLSv1.2 and TLSv1.3.

Note: SM2, SM3 and at least one SM4 cipher must be built in order for SM
ciphers suite to work. All algorithms must be SM.

The cipher suites added are:
  - ECDHE-ECDSA-SM4-CBC-SM3 (TLSv1.2, --enable-sm2 --enable-sm3 --enable-sm4-cbc)
  - ECDHE-ECDSA-SM4-GCM-SM3 (TLSv1.2, --enable-sm2 --enable-sm3 --enable-sm4-gcm)
  - ECDHE-ECDSA-SM4-CCM-SM3 (TLSv1.2, --enable-sm2 --enable-sm3 --enable-sm4-ccm)
  - TLS13-SM4-GCM-SM3 (TLSv1.3, --enable-sm2 --enable-sm3 --enable-sm4-gcm)
  - TLS13-SM4-CCM-SM3 (TLSv1.3, --enable-sm2 --enable-sm3 --enable-sm4-ccm)

### Example of using SM cipher suites with TLSv1.2

An example of testing TLSv1.2 with "ECDHE-ECDSA-SM4-CBC-SM3" cipher suite:

```
./examples/server/server -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3 \
    -c ./certs/sm2/server-sm2.pem -k ./certs/sm2/server-sm2-priv.pem \
    -A ./certs/sm2/client-sm2.pem -V &
./examples/client/client -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3 \
    -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem \
    -A ./certs/sm2/root-sm2.pem -C
```

The output using the commands above will be:

```
SSL version is TLSv1.2
SSL cipher suite is TLS_ECDHE_ECDSA_WITH_SM4_CBC_SM3
SSL curve name is SM2P256V1
SSL version is TLSv1.2
SSL cipher suite is TLS_ECDHE_ECDSA_WITH_SM4_CBC_SM3
SSL curve name is SM2P256V1
Client message: hello wolfssl!
I hear you fa shizzle!
```

### Example of using SM cipher suites with TLSv1.3

An example of testing TLSv1.3 with "TLS13-SM4-GCM-SM3" cipher suite:

```
./examples/server/server -v 4 -l TLS13-SM4-GCM-SM3 \
    -c ./certs/sm2/server-sm2.pem -k ./certs/sm2/server-sm2-priv.pem \
    -A ./certs/sm2/client-sm2.pem -V &
./examples/client/client -v 4 -l TLS13-SM4-GCM-SM3 \
    -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem \
    -A ./certs/sm2/root-sm2.pem -C
```

The output using the commands above will be:

```
SSL version is TLSv1.3
SSL cipher suite is TLS_SM4_GCM_SM3
SSL curve name is SM2P256V1
SSL version is TLSv1.3
SSL cipher suite is TLS_SM4_GCM_SM3
SSL curve name is SM2P256V1
Client message: hello wolfssl!
I hear you fa shizzle!
```

# Development

## Regenerating assembly code

### Get scripts repository

The scripts to generate the assembly code have a dependency on the scripts
repository.

Note: You will need ruby installed to run the scripts.

Checkout the scripts repository from GitHub beside wolfsm:

```
<install-dir>
├── wolfsm
├── wolfssl
└── scripts
```

```
cd .. # To directory containing wolfsm
git clone https://github.com/wolfssl/scripts.git
```

### Regenerate

Now regenerate the assembly code using the gen-asm.sh script:

```
cd wolfsm
./gen-asm.sh
```

## Checking against install

You can check whether the code is different from what is already installed:

```
./check.sh
```

A list of files that would be copied and there difference will be shown.
There are no difference if the line is:

```
    SAME
```

## Reinstall

If the wolfsm files are more up to date then those in wolfSSL, install all the files with:

```
./install.sh
```

## Modifying SM implementations in wolfSSL

You may have modified installed wolfsm files in place in wolfSSL.

You will have to manually copy back each file you have modified.

See "Checking against install" as to which files need to be copied.

## Need Help?

Please reach out to support@wolfssl.com for technical support. If you're
interested in commercial licensing, FIPS operating environment additions,
consulting services, or other business engagements, please reach out to
facts@wolfssl.com.

