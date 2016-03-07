'''
AES encryption and decryption
'''
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import os
from struct import pack
# encrypt message with AES
# ---------------------------------------------------
BLOCK_SIZE = 16
# generate a random secret key
# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
# Since out content is JSON, use white space as padding and run trim() to strip it.
PADDING = ' '
# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

iv = Random.new().read( AES.block_size )

def encrypt(message):
    aes_key = Random.new().read(BLOCK_SIZE)
    iv = Random.new().read(AES.block_size)
    # create a cipher object using the random secret
    cipher = AES.new(aes_key, mode=AES.MODE_CBC, IV=iv)
    encrypted = cipher.encrypt(pad(message))
    return (aes_key, iv, encrypted)

def decrypt(aes_key, iv, encrypted):
    cipher = AES.new(aes_key, mode=AES.MODE_CBC, IV=iv)
    return cipher.decrypt(encrypted).rstrip(PADDING)

if __name__ == "__main__":
    message = 'I have a dream.'
    aes_key, iv, encrypted = encrypt(message)
    print decrypt(aes_key, iv, encrypted)
