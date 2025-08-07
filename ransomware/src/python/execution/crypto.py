#!/usr/bin/python3
import os
from hashlib import sha256
from Crypto.Cipher import AES,Salsa20,ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization

# --- Generate x25519 Key Pair ---
def derive_x25519_keypair():
    entropy = os.urandom(32)
    digest = sha256(entropy).digest()
    priv_key = X25519PrivateKey.from_private_bytes(digest)
    pub_key = priv_key.public_key()
    return priv_key, pub_key, digest

# --- ECDH Shared Key ---
def generate_shared_key(priv, pub):
    return priv.exchange(pub)

# --- SHA Key Derivation Function ---
def derive_symmetric_key(shared_key, bits=256):
    hashed = sha256(shared_key).digest()
    if int(bits) == 128:
        return hashed[:16]
    elif int(bits) == 192:
        return hashed[:24]
    elif int(bits) == 256:
        return hashed
    else:
        raise ValueError("Symmetric keys must be 128, 192, or 256 bits")

def public_bytes(pubkey):
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def private_bytes(privkey):
    return privkey.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

def privateKey(bytes_val):
    return X25519PrivateKey.from_private_bytes(bytes_val)

def publicKey(bytes_val):
    return X25519PublicKey.from_public_bytes(bytes_val)

# --- Generate Session Keys and Asymmetric Keys ---
def key_gen(asym, sym, mode, master_pub):
    mPub = X25519PublicKey.from_public_bytes(bytes.fromhex(master_pub))
    
    aPriv, aPub, _ = derive_x25519_keypair()
    bPriv, bPub, _ = derive_x25519_keypair()
    
    shared1 = generate_shared_key(aPriv, mPub)
    
    cipher1, iv_bytes, padding = get_sym_cipher(sym, mode, shared1, 256)
    
    #key1 = derive_symmetric_key(shared1, bits=256)
    #ctr_bytes = os.urandom(16)
    #ctr = Counter.new(128, initial_value=int.from_bytes(ctr_bytes, "big"))
    #cipher1 = AES.new(key1, AES.MODE_CTR, counter=ctr)
    bPriv_bytes = private_bytes(bPriv)
    secret1 = encrypt_data(bPriv_bytes, cipher1.encrypt, needPad=padding)
    
    aPub_bytes = public_bytes(aPub)

    return bPub, iv_bytes, secret1, aPub_bytes

# --- Symmetric Encryption of Data --- 
#def encrypt_data2(data, cipher, fraction=100, blocksize=16, needPad=False, needUnpad=False):
#    if fraction < 100 and len(data) > 50*1024:

def encrypt_data(data, cipher, blocksize=16, needPad=False, needUnpad=False):
    if needPad:
        data = pad(data, blocksize)
    ct = cipher(data)
    if needUnpad:
        ct = unpad(ct, blocksize)
    return ct

# --- Create Cipher Object based on Symmetric Algo ---
def get_sym_cipher(algo, aes_mode, shared, keylen, iv=os.urandom(16)):

    mode = getattr(AES, f"MODE_{aes_mode.upper()}")
    padding = False or (mode in (AES.MODE_ECB, AES.MODE_CBC))

    if algo == 'AES':
        key = derive_symmetric_key(shared, bits=keylen)
        if mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
            cipher = AES.new(key, mode, iv=iv)
        elif mode == AES.MODE_CTR:
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key, mode, counter=ctr)
        else:
            cipher = AES.new(key, mode)
    elif algo == 'Salsa20':
        key = derive_symmetric_key(shared, bits=keylen)
        cipher = Salsa20.new(key=key, nonce=iv[:8])
    elif algo == 'ChaCha20':
        key = derive_symmetric_key(shared, bits=256)
        cipher = ChaCha20.new(key=key, nonce=iv)
    return cipher, iv, padding
