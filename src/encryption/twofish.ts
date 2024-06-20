// Twofish encryption implementation

import crypto from 'crypto';
const Twofish = require('twofish');

export const encryptWithTwofish = (content: string): string => {
  const key = crypto.randomBytes(32); // Generate a random key
  const twofish = new Twofish();
  const encrypted = twofish.encrypt(key, Buffer.from(content));
  return `${encrypted.toString('hex')}:${key.toString('hex')}`; // Return encrypted content and key
};

export const decryptWithTwofish = (encryptedContent: string): string => {
  const [encrypted, key] = encryptedContent.split(':');
  const twofish = new Twofish();
  const decrypted = twofish.decrypt(Buffer.from(key, 'hex'), Buffer.from(encrypted, 'hex'));
  return decrypted.toString('utf8');
};