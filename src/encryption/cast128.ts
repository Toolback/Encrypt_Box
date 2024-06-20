// CAST-128 encryption implementation

import crypto from 'crypto';

export const encryptWithCAST128 = (content: string): string => {
  const key = crypto.randomBytes(16); // Generate a random key (CAST-128 uses a 16-byte key)
  const iv = crypto.randomBytes(8); // Generate a random IV (CAST-128 uses an 8-byte block size)
  const cipher = crypto.createCipheriv('cast5-cbc', key, iv); // Use CAST-128 with CBC mode
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}:${key.toString('hex')}`; // Return IV, encrypted content, and key
};

export const decryptWithCAST128 = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = crypto.createDecipheriv('cast5-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};