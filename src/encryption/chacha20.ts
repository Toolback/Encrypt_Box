// ChaCha20 encryption implementation

import crypto from 'crypto';
export const encryptWithChaCha20 = (content: string): string => {
  const key = crypto.randomBytes(32); // Generate a random 256-bit key
  const iv = crypto.randomBytes(12);  // Generate a random 96-bit nonce (ChaCha20 uses a 12-byte nonce)
  const cipher = crypto.createCipheriv('chacha20', key, iv);
  let encrypted = cipher.update(content, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}:${key.toString('hex')}`; // Return nonce, encrypted content, and key
};

export const decryptWithChaCha20 = (encryptedContent: string): string => {
  const [iv, encrypted, key] = encryptedContent.split(':');
  const decipher = crypto.createDecipheriv('chacha20', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};