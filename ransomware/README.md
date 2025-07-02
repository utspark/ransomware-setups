# Ransomware Simulator

This is a academic ransomware simulator that is basic and provides a first step insight into the behavior of ransomwares. This has been updated and modified from CryptSky[https://github.com/deadPix3l/CryptSky/tree/master] but been modified to add more functionality and lifecycle for ransomware programs.

This python module depends on PyCryptodome package and needs to be installed with `pip3 install pycryptodome`

The ransomware can be run using `./main.py [args]`

Supported arguments:
```
-p, --path : Directory path to recursively encrypt/decrypt
-d, --decrypt : Run decryption stage
-a, --algo    : Crypto algorithms to use [AES, Salsa20, ChaCha20]
-m, --mode    : AES mode to use, to be used with -a AES [ECB, CBC, CTR, OFB, CFB]
```
