// Serpent encryption implementation
import crypto from 'crypto';
const serpent = require('serpent');

export const encryptWithSerpent = (content: string): string => {
  const key = crypto.randomBytes(32); // Generate a random key
  const iv = crypto.randomBytes(16); // Generate a random IV
  const cipher = serpent.encrypt(key, iv, Buffer.from(content));
  return `${iv.toString('hex')}:${cipher.toString('hex')}:${key.toString('hex')}`; // Return IV, encrypted content, and key
};

export const decryptWithSerpent = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = serpent.decrypt(Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'), Buffer.from(encrypted, 'hex'));
  return decipher.toString('utf8');
};