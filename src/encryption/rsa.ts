// RSA (Rivest–Shamir–Adleman) encryption implementation

import crypto from 'crypto';

export const encryptWithRSA = (content: string): string => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048, // 2048-bit key
  });
  const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(content));
  return `${encrypted.toString('hex')}:${privateKey.export({ type: 'pkcs1', format: 'pem' })}`; // Return encrypted content and private key
};

export const decryptWithRSA = (encryptedContent: string): string => {
  const [encrypted, privateKey] = encryptedContent.split(':');
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encrypted, 'hex'));
  return decrypted.toString('utf8');
};