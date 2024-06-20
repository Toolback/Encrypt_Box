// Camellia encryption implementation

import crypto from 'crypto';

export const encryptWithCamellia = (content: string): string => {
  const key = crypto.randomBytes(32); // Generate a random key
  const iv = crypto.randomBytes(16); // Generate a random IV
  const cipher = crypto.createCipheriv('camellia-256-cbc', key, iv);
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}:${key.toString('hex')}`; // Return IV, encrypted content, and key
};

export const decryptWithCamellia = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = crypto.createDecipheriv('camellia-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};