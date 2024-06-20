// GOST encryption implementation

const gostCrypto = require('gost-crypto');

export const encryptWithGOST = (content: string): string => {
  const key = gostCrypto.random(32); // Generate a random key
  const iv = gostCrypto.random(8); // Generate a random IV
  const cipher = gostCrypto.cipher.init({
    name: 'GOST 28147',
    mode: 'CTR',
    key: key,
    iv: iv
  });
  const encrypted = cipher.update(Buffer.from(content)).concat(cipher.final());
  return `${iv.toString('hex')}:${encrypted.toString('hex')}:${key.toString('hex')}`; // Return IV, encrypted content, and key
};

export const decryptWithGOST = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = gostCrypto.cipher.init({
    name: 'GOST 28147',
    mode: 'CTR',
    key: Buffer.from(key, 'hex'),
    iv: Buffer.from(iv, 'hex')
  });
  const decrypted = decipher.update(Buffer.from(encrypted, 'hex')).concat(decipher.final());
  return decrypted.toString('utf8');
};