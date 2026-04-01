# AES-128 ConfigMgr CryptDeriveKey Hashcat Module

This repo contains the module and OpenCL code that implements an AES-128 key derivation for ConfigMgr media variable files. This key derivation is based completely on the documented steps at [https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks).The code has recently been updated to work with Hashcat 6.2.5. In order to use it, you will need to compile Hashcat to obtain a .so/.dll/.dylib library of `module_19850.c`. The OpenCL code is dynamically compiled by Hashcat during module initialisation. 

## Instructions

1. Clone the Hashcat source repository. Remember, this code base was developed with 6.2.5 in mind, but it will likely work with the latest version unless there has been a recent breaking change to the code base
2. Copy `module_19850.c` into src/modules/ folder of the main Hashcat code base
3. Copy `m19850_a0-pure.cl`, `m19850_a1-pure.cl` and `m19850_a3-pure.cl` into the OpenCL/ folder of the main Hashcat code base
4. Follow the compilation instructions in Hashcat's BUILD.md. I would very highly recommend using the WSL option if you are compiling on Windows, as I had the best results with that. 


## Author Credit 

Copyright (C) 2022 Christopher Panayi, MWR CyberSec


## AES-256 variant

This repository now also includes an AES-256 variant of the ConfigMgr CryptDeriveKey module based on the same Microsoft CryptDeriveKey remarks:

- Module file: `module_code/module_19851.c`
- OpenCL files: `opencl_code/m19851_a0-pure.cl`, `opencl_code/m19851_a1-pure.cl`, `opencl_code/m19851_a3-pure.cl`

The AES-256 implementation follows the documented derivation for key sizes larger than the hash output by using both the ipad and opad SHA-1 transforms, then taking the first 32 bytes of the concatenated result.
