import { encryptWithAES, decryptWithAES } from "./src/encryption/aes";
import { encryptWithChaCha20, decryptWithChaCha20 } from "./src/encryption/chacha20";
import { encryptWithRSA, decryptWithRSA } from "./src/encryption/rsa";
import { encryptWithBlowfish, decryptWithBlowfish } from "./src/encryption/blowfish";
import { encryptWithTwofish, decryptWithTwofish } from "./src/encryption/twofish";
import { encryptWithCamellia, decryptWithCamellia } from "./src/encryption/camellia";
import { encryptWithSEED, decryptWithSEED } from "./src/encryption/seed";
import { encryptWithSerpent, decryptWithSerpent } from "./src/encryption/serpent";
import { encryptWithECC, decryptWithECC } from "./src/encryption/ecc";
import { encryptWithIDEA, decryptWithIDEA } from "./src/encryption/idea";
import { encryptWithCAST128, decryptWithCAST128 } from "./src/encryption/cast128";
import { encryptWithGOST, decryptWithGOST } from "./src/encryption/gost";

const main = () => {
  const contentToEncrypt = process.argv[2] || "Place Content Here";
  
  console.log("|-------------------------------------------------|")
  const encryptedAES = encryptWithAES(contentToEncrypt);
  console.log("Encryption with AES Model: ", encryptedAES);
  console.log("Decryption with AES Model: ", decryptWithAES(encryptedAES));
  console.log("|-------------------------------------------------|")
  const encryptedRSA = encryptWithRSA(contentToEncrypt);
  console.log("Encryption with RSA Model: ", encryptedRSA);
  console.log("Decryption with RSA Model: ", decryptWithRSA(encryptedRSA));
  console.log("|-------------------------------------------------|")

  const encryptedCamellia = encryptWithCamellia(contentToEncrypt);
  console.log("Encryption with Camellia Model: ", encryptedCamellia);
  console.log("Decryption with Camellia Model: ", decryptWithCamellia(encryptedCamellia));
  console.log("|-------------------------------------------------|")

  // ################################################################
  // WIP
  // ################################################################

  // const encryptedChaCha20 = encryptWithChaCha20(contentToEncrypt);
  // console.log("Encryption with ChaCha20 Model: ", encryptedChaCha20);
  // console.log("Decryption with ChaCha20 Model: ", decryptWithChaCha20(encryptedChaCha20));
  // console.log("|-------------------------------------------------|")

  // const encryptedBlowfish = encryptWithBlowfish(contentToEncrypt);
  // console.log("Encryption with Blowfish Model: ", encryptedBlowfish);
  // console.log("Decryption with Blowfish Model: ", decryptWithBlowfish(encryptedBlowfish));
  // console.log("|-------------------------------------------------|")

  // const encryptedTwofish = encryptWithTwofish(contentToEncrypt);
  // console.log("Encryption with Twofish Model: ", encryptedTwofish);
  // console.log("Decryption with Twofish Model: ", decryptWithTwofish(encryptedTwofish));

  // console.log("|-------------------------------------------------|")

  // const encryptedSEED = encryptWithSEED(contentToEncrypt);
  // console.log("Encryption with SEED Model: ", encryptedSEED);
  // console.log("Decryption with SEED Model: ", decryptWithSEED(encryptedSEED));
  // console.log("|-------------------------------------------------|")

  // const encryptedSerpent = encryptWithSerpent(contentToEncrypt);
  // console.log("Encryption with Serpent Model: ", encryptedSerpent);
  // console.log("Decryption with Serpent Model: ", decryptWithSerpent(encryptedSerpent));
  // console.log("|-------------------------------------------------|")

  // const encryptedECC = encryptWithECC(contentToEncrypt);
  // console.log("Encryption with ECC Model: ", encryptedECC);
  // console.log("Decryption with ECC Model: ", decryptWithECC(encryptedECC));
  // console.log("|-------------------------------------------------|")

  // const encryptedIDEA = encryptWithIDEA(contentToEncrypt);
  // console.log("Encryption with IDEA Model: ", encryptedIDEA);
  // console.log("Decryption with IDEA Model: ", decryptWithIDEA(encryptedIDEA));
  // console.log("|-------------------------------------------------|")

  // const encryptedCAST128 = encryptWithCAST128(contentToEncrypt);
  // console.log("Encryption with CAST-128 Model: ", encryptedCAST128);
  // console.log("Decryption with CAST-128 Model: ", decryptWithCAST128(encryptedCAST128));
  // console.log("|-------------------------------------------------|")

  // const encryptedGOST = encryptWithGOST(contentToEncrypt);
  // console.log("Encryption with GOST Model: ", encryptedGOST);
  // console.log("Decryption with GOST Model: ", decryptWithGOST(encryptedGOST));
};

main();