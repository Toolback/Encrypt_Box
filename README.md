# Encryption Project
This project implements various encryption algorithms in Node.js using TypeScript. The project structure is organized to keep each encryption algorithm in its own file for better modularity and maintainability.

## Run Script
first install packages
``` shell
npm install
```

then for hardcoded value, run
``` shell
npx ts-node main.ts
```

or 
``` shell
npx ts-node main.ts "Your String to Encrypt"
```

## Project structure

encryption-project/  
│  
├── src/  
│   └── encryption/  
│       ├── aes.ts        # AES encryption implementation  
│       ├── rsa.ts        # RSA encryption implementation  
│       ├── chacha20.ts   # ChaCha20 encryption implementation  
│       ├── blowfish.ts   # Blowfish encryption implementation  
│       ├── twofish.ts    # Twofish encryption implementation  
│       ├── camellia.ts   # Camellia encryption implementation  
│       ├── seed.ts       # SEED encryption implementation  
│       ├── serpent.ts    # Serpent encryption implementation  
│       ├── ecc.ts        # ECC (Elliptic Curve Cryptography) encryption implementation  
│       ├── idea.ts       # IDEA encryption implementation  
│       ├── cast128.ts    # CAST-128 encryption implementation  
│       ├── gost.ts       # GOST encryption implementation  
├── main.ts               # Run the program with a hardcoded value or the one given as the first argument  
├── package.json          # Project configuration and dependencies  
├── tsconfig.json         # TypeScript configuration      
  
## Encryption Models

### AES (Advanced Encryption Standard)
- **Description**: AES is a symmetric encryption algorithm widely used across the globe. It is known for its speed and security. AES uses a block size of 128 bits and supports key sizes of 128, 192, and 256 bits.
- **Usage**: Suitable for encrypting large amounts of data quickly, such as file encryption and secure data transmission.

### RSA (Rivest-Shamir-Adleman)
- **Description**: RSA is an asymmetric encryption algorithm used for secure data transmission. It is based on the mathematical difficulty of factoring large prime numbers. RSA uses a pair of keys: a public key for encryption and a private key for decryption.
- **Usage**: Commonly used for securing sensitive data, digital signatures, and secure key exchanges.

### ChaCha20
- **Description**: ChaCha20 is a stream cipher designed to provide better security than older ciphers like RC4. It uses a 256-bit key and a 96-bit nonce. ChaCha20 is known for its speed and efficiency on software platforms.
- **Usage**: Suitable for secure data encryption in software applications, including secure communications.

### Blowfish
- **Description**: Blowfish is a symmetric-key block cipher designed to be fast and secure. It uses a variable-length key, from 32 bits to 448 bits, making it flexible for different security needs.
- **Usage**: Often used for file encryption and secure data storage.

### Twofish
- **Description**: Twofish is a symmetric key block cipher with a block size of 128 bits and key sizes up to 256 bits. It is known for its high speed and flexibility in key scheduling.
- **Usage**: Suitable for encrypting data in applications where high performance is required.

### Camellia
- **Description**: Camellia is a symmetric key block cipher with a block size of 128 bits and key sizes of 128, 192, and 256 bits. It offers a high level of security and performance.
- **Usage**: Often used in secure data storage and transmission.

### SEED
- **Description**: SEED is a symmetric key block cipher developed by the Korean Information Security Agency. It uses a block size of 128 bits and supports a 128-bit key.
- **Usage**: Commonly used in Korean financial and government applications.

### Serpent
- **Description**: Serpent is a symmetric key block cipher that was a finalist in the Advanced Encryption Standard (AES) contest. It uses a block size of 128 bits and supports key sizes of 128, 192, and 256 bits.
- **Usage**: Suitable for applications requiring a high level of security.

### ECC (Elliptic Curve Cryptography)
- **Description**: ECC is an asymmetric encryption algorithm based on elliptic curve theory. It provides the same level of security as RSA but with smaller key sizes, making it more efficient.
- **Usage**: Commonly used in mobile devices and other environments where computational power and battery life are limited.

### IDEA (International Data Encryption Algorithm)
- **Description**: IDEA is a symmetric key block cipher that uses a 128-bit key and operates on 64-bit blocks. It is known for its simplicity and security.
- **Usage**: Often used in secure data storage and transmission.

### CAST-128
- **Description**: CAST-128 is a symmetric key block cipher with a block size of 64 bits and key sizes ranging from 40 to 128 bits. It is designed for high security and efficiency.
- **Usage**: Suitable for secure data encryption in various applications.

### GOST
- **Description**: GOST is a symmetric key block cipher that was developed in the former Soviet Union. It uses a block size of 64 bits and a 256-bit key.
- **Usage**: Commonly used in Russian encryption standards and applications.