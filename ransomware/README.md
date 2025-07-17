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

command to generate base x25519 key to be used in payload.py and decryptor.py
```
openssl genpkey -algorithm X25519 -out x25519_priv.pem
openssl pkey -in x25519_priv.pem -pubout -out x25519_pub.pem
```
Hexvalues:
`EMBEDDED_PRIV = openssl pkey -in x25519_priv.pem -outform DER | tail -c 32 | hexdump -ve '1/1 "%.2x"'`
`EMBEDDED_PUB = openssl pkey -in x25519_priv.pem -pubout -outform DER | tail -c 32 | hexdump -ve '1/1 "%.2x"'`

