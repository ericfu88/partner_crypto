'''
 Encrypts a message
'''
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import aes
import base64

def asHex(bytes):
    return ':'.join(x.encode('hex') for x in bytes)

def encrypt(senderPrivateKeyFile, receiverPublicKeyFile, message, base64Encode=False):

    # encrypt message with AES
    # ---------------------------------------------------
    (aes_key, iv, aes_encrypted_message) = aes.encrypt(message)
    # print 'aes-key:' + asHex(aes_key)
    # print 'iv:', asHex(iv)
    # print 'aes_encrypted_message-' + str(len(aes_encrypted_message)) + ':', asHex(aes_encrypted_message)
    # sign the aes key and IV with public key of receiver
    # ---------------------------------------------------
    receiverPubKeyObj = RSA.importKey(open(receiverPublicKeyFile).read())
    cipher = PKCS1_OAEP.new(receiverPubKeyObj)
    encrypted_aes_key = cipher.encrypt(aes_key + iv)

    # hash the combined encrypted aes_key and encrypted message
    # ---------------------------------------------------
    combined_aes_key_and_message = b''.join([encrypted_aes_key, aes_encrypted_message])
    sha1_hash = SHA256.new(combined_aes_key_and_message)

    # sign the hash with private key of sender
    # ---------------------------------------------------
    senderPrivateKeyObj = RSA.importKey(open(senderPrivateKeyFile).read())
    signer = PKCS1_v1_5.new(senderPrivateKeyObj)
    signed_hash = signer.sign(sha1_hash)

    # returned the whole blob
    # ---------------------------------------------------
    encrypted = b''.join([signed_hash, combined_aes_key_and_message])
    if base64Encode:
        encrypted = base64.b64encode(encrypted)
    return encrypted

def decrypt(receiverPrivateKeyFile, senderPublicKeyFile, encrypted, base64Decode=False):
    if base64Decode:
        encrypted = base64.b64decode(encrypted)

    # base64 decode the object First
    signature = encrypted[:128]
    signed_body = encrypted[128:]
    encrypted_aes_key = encrypted[128:256]
    aes_encrypted_message = encrypted[256:]

    # Verifies the signed hash
    senderPublicKeyObj = RSA.importKey(open(senderPublicKeyFile).read())
    sha1_hash = SHA256.new(signed_body)
    verifier = PKCS1_v1_5.new(senderPublicKeyObj)
    if not verifier.verify(sha1_hash, signature):
        return None

    # decrypt to get the AES key
    # ---------------------------------------------------
    receiverPrivateKeyObj = RSA.importKey(open(receiverPrivateKeyFile).read())
    cipher = PKCS1_OAEP.new(receiverPrivateKeyObj)
    aes_key_and_iv = cipher.decrypt(encrypted_aes_key)
    aes_key = aes_key_and_iv[:16]
    iv = aes_key_and_iv[16:]

    # decrypt the message with AES key and iv
    # ---------------------------------------------------
    message = aes.decrypt(aes_key, iv, aes_encrypted_message)

    return message

if __name__ == "__main__":
    # message = "But in late 2014, the family that had run the paper for five generations found an eager buyer: private equity-run newspaper chain New Media Investment Group, which has been snapping up similar assets nationwide."
    message = 'Instances of the Decipher class are used to decrypt data. The class can be used in one of two ways.'
    senderPrivateKeyFile = '../sampleKeys/sender_private.pem'
    receiverPublicKeyFile = '../sampleKeys/receiver_public.pem'

    encodeWithBase64 = True

    encrypted = encrypt(senderPrivateKeyFile, receiverPublicKeyFile, message, encodeWithBase64)
    if encodeWithBase64:
        with open('../sampleKeys/encrypted.b64', 'w') as f:
            f.write(encrypted)
    else:
        with open('../sampleKeys/encrypted.bin', 'wb') as f:
            f.write(encrypted)

    receiverPrivateKeyFile = '../sampleKeys/receiver_private.pem'
    senderPublicKeyFile = '../sampleKeys/sender_public.pem'

    decrypted = decrypt(receiverPrivateKeyFile, senderPublicKeyFile, encrypted, encodeWithBase64)
    if (decrypted == message):
        print 'success'
    else:
        print 'failed'
