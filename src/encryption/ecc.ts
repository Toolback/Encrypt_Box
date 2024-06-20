// ECC (Elliptic Curve Cryptography) encryption implementation

import crypto from 'crypto';

export const encryptWithECC = (content: string): string => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1', // Use the curve secp256k1
  });
  const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(content));
  return `${encrypted.toString('hex')}:${privateKey.export({ type: 'pkcs8', format: 'pem' })}`; // Return encrypted content and private key
};

export const decryptWithECC = (encryptedContent: string): string => {
  const [encrypted, privateKey] = encryptedContent.split(':');
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encrypted, 'hex'));
  return decrypted.toString('utf8');
};