// Blowfish encryption implementation

import crypto from 'crypto';

export const encryptWithBlowfish = (content: string): string => {
  const key = crypto.randomBytes(32); // Generate a random key
  const iv = crypto.randomBytes(8); // Generate a random IV (Blowfish uses an 8-byte block size)
  const cipher = crypto.createCipheriv('bf-cbc', key, iv); // Use Blowfish with CBC mode
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}:${key.toString('hex')}`; // Return IV, encrypted content, and key
};

export const decryptWithBlowfish = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = crypto.createDecipheriv('bf-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};