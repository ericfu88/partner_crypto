const fs = require('fs');
const crypto = require('crypto');
const constants = require('constants');
const uuid = require('uuid');

const aes_algo = 'aes-128-cbc';

function printCiphers() {
  const ciphers = crypto.getCiphers();
  console.log(ciphers);
}


function pad(str, length, ch) {
  var size_to_pad = length - str.length % length;
  for (var i = 0; i < size_to_pad; i++) {
    str = str + ch;
  }
  return str;
}

function encrypt(senderPrivateKeyFile, receiverPublicKeyFile, message, base64Encode) {
  // pad message with space
  message = pad(message, 16, ' ');

  // encrypt message with AES
  // ---------------------------------------------------
  var aes_key = uuid.v4(null, new Buffer(16));
  var iv = uuid.v4(null, new Buffer(16));

  // console.log('aes_key=' + aes_key.toString('hex'));
  // console.log('iv=' + iv.toString('hex'));

  const cipher = crypto.createCipheriv(aes_algo, aes_key, iv);
  cipher.setAutoPadding(false);
  var aes_encrypted_message = cipher.update(message, 'utf8', 'binary');
  aes_encrypted_message += cipher.final('binary');

  // sign the aes key with public key of receiver
  // ---------------------------------------------------
  var receiverPubKey = fs.readFileSync(receiverPublicKeyFile).toString();
  var aes_key_and_iv = Buffer.concat([aes_key, iv]);
  var encrypted_aes_key = crypto.publicEncrypt({
    key: receiverPubKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING
  }, aes_key_and_iv);

  // hash the combined encrypted aes_key and encrypted message
  // ---------------------------------------------------
  var combined_aes_key_and_message = Buffer.concat([new Buffer(encrypted_aes_key, 'binary'), new Buffer(aes_encrypted_message, 'binary')]);
  const sign = crypto.createSign('RSA-SHA256');
  sign.write(combined_aes_key_and_message);
  sign.end();
  var senderPrivateKey = fs.readFileSync(senderPrivateKeyFile).toString();
  var signature = sign.sign(senderPrivateKey, 'binary');

  // returned the whole blob
  // ---------------------------------------------------
  var encrypted = Buffer.concat([new Buffer(signature, 'binary'), combined_aes_key_and_message]);
  if (base64Encode) {
    encrypted = encrypted.toString('base64');
  }
  return encrypted;
}


function decrypt(receiverPrivateKeyFile, senderPublicKeyFile, encrypted, isBase64Encoded) {
  var buffer = encrypted;
  if (isBase64Encoded) {
    buffer = new Buffer(encrypted, 'base64');
  }

  var signature = buffer.slice(0, 128);
  var signed_body = buffer.slice(128);
  var encrypted_aes_key = buffer.slice(128, 256);
  var aes_encrypted_message = buffer.slice(256);

  // verify the signed hash
  // ---------------------------------------------------
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(signed_body);

  const senderPublicKey = fs.readFileSync(senderPublicKeyFile).toString();
  if (! verifier.verify(senderPublicKey, signature)) {
    return null;
  }

  // decrypt to get the AES key
  // ---------------------------------------------------
  const receiverPrivateKey = fs.readFileSync(receiverPrivateKeyFile).toString();
  var aes_key_and_iv = crypto.privateDecrypt({
    key: receiverPrivateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING
  }, encrypted_aes_key);

  var aes_key = aes_key_and_iv.slice(0, 16);
  var iv = aes_key_and_iv.slice(16);

  // console.log('aes_key=' + aes_key.toString('hex'));
  // console.log('iv=' + iv.toString('hex'));
  // console.log('aes_encrypted_message=' + aes_encrypted_message.toString('hex'));

  // decrypt the message with AES key
  // ---------------------------------------------------
  const decipher = crypto.createDecipheriv(aes_algo, aes_key, iv);
  decipher.setAutoPadding(false);
  var decrypted = decipher.update(aes_encrypted_message, 'binary', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted.trim();
}


///////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////
const senderPrivateKeyFile = '../sampleKeys/sender_private.pem';
const senderPublicKeyFile = '../sampleKeys/sender_public.pem';
const receiverPublicKeyFile = '../sampleKeys/receiver_public.pem';
const receiverPrivateKeyFile = '../sampleKeys/receiver_private.pem';
/**
 * Tests encryption and decryption all using node.js code
 */
function testEncryptDecypt() {
  const base64Encode = true;
  const message = "Hello world";
  const encrypted = encrypt(senderPrivateKeyFile, receiverPublicKeyFile, message, base64Encode);
  // console.log(encrypted);
  const decrypted = decrypt(receiverPrivateKeyFile, senderPublicKeyFile, encrypted, base64Encode);
  console.log('"' + decrypted + '"');
  console.log(decrypted === message);
}

/**
 * Tests decryption of a python encoded blob
 */
function testDecrypt() {
  const encrypted = fs.readFileSync('../sampleKeys/encrypted.b64').toString();
  var decrypted = decrypt(receiverPrivateKeyFile, senderPublicKeyFile, encrypted, true);
  console.log('"' + decrypted + '"');
}

// printCiphers();
// testEncryptDecypt();
testDecrypt();
