# Xealth Crypto Library

This is the crypto library used to secure and authenticate communication between partners.

* Step 1. Generate a random AES key.
* Step 2. AES encrypt the body of the message.
* Step 3. Sign the AES key using Receiver’s public RSA key.
* Step 4. Generate a SHA-1 hash over the signed AES key and the AES encrypted body
* Step 5. Sign the SHA-1 hash using Sender(partner)’s private RSA key.
* Step 6. Sends the message body by joining the following:
  * Signed SHA-1 hash
  * Signed AES key
  * AES encrypted body

# How to use

* Generate a pair of RSA keys:

```
cd python
pip install -r requirements.txt
python generateRSA.py ../sampleKeys/receiver
python generateRSA.py ../sampleKeys/sender
```

* Encrypt a message:

```
python encrypt.py
```
This generates a file called `samplkeKeys/encrypted.b64`.

* Decrypt the message:

```
cd node
npm install
node decrypt.js
```
