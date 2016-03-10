import sys

def generate_RSA(bits=1024):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    return private_key, public_key

'''
 generates two files:
 public.pem
 private.key
'''
if __name__ == '__main__':
    prefix = sys.argv[1]
    private_key, public_key = generate_RSA()
    with open(prefix + '_private.pem', 'w') as f:
        f.write(private_key)
    with open(prefix + '_public.pem', 'w') as f:
        f.write(public_key)
