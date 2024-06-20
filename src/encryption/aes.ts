// AES (Advanced Encryption Standard) encryption implementation using aes-256-cbc

import crypto from 'crypto';

export const encryptWithAES = (content: string): string => {
  const key = crypto.randomBytes(32); // Generate a random 256-bit key
  const iv = crypto.randomBytes(16);  // Generate a random 128-bit IV (AES uses a 16-byte block size)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}:${key.toString('hex')}`; // Return IV, encrypted content, and key
};

export const decryptWithAES = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};