import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  try {
    const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
          hash: { name: "SHA-256" },
        },
        true, // extractable
        ["encrypt", "decrypt"] // key usages
    );

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  } catch (error) {
    console.error("Error generating RSA key pair:", error);
    throw error;
  }
}


// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  try {
    const exportedKey = await crypto.subtle.exportKey("spki", key);
    const exportedAsString = arrayBufferToBase64(exportedKey);
    return exportedAsString;
  } catch (error) {
    console.error("Error exporting public key:", error);
    throw error;
  }
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
    key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key) {
    return null; // Return null if the key is null
  }

  try {
    const exportedKey = await crypto.subtle.exportKey("pkcs8", key);
    const exportedAsString = arrayBufferToBase64(exportedKey);
    return exportedAsString;
  } catch (error) {
    console.error("Error exporting private key:", error);
    throw error;
  }
}

// Import a base64 string public key to its native format
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  try {
    // Decode the Base64 string to ArrayBuffer
    const arrayBuffer = base64ToArrayBuffer(strKey);

    // Import the ArrayBuffer as a CryptoKey
    const publicKey = await crypto.subtle.importKey(
        "spki",
        arrayBuffer,
        {
          name: "RSA-OAEP",
          hash: { name: "SHA-256" },
        },
        true,
        ["encrypt"]
    );

    return publicKey;
  } catch (error) {
    console.error("Error importing public key:", error);
    throw error;
  }
}


// Import a base64 string private key to its native format
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  try {
    // Decode the Base64 string to ArrayBuffer
    const arrayBuffer = base64ToArrayBuffer(strKey);

    // Import the ArrayBuffer as a CryptoKey
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        arrayBuffer,
        {
          name: "RSA-OAEP",
          hash: { name: "SHA-256" },
        },
        true,
        ["decrypt"]
    );

    return privateKey;
  } catch (error) {
    console.error("Error importing private key:", error);
    throw error;
  }
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
    b64Data: string,
    strPublicKey: string
): Promise<string> {
  try {
    // Convert Base64 public key to CryptoKey
    const publicKey = await importPubKey(strPublicKey);

    // Decode the Base64 data to ArrayBuffer
    const data = base64ToArrayBuffer(b64Data);

    // Encrypt the data with the public key
    const encryptedData = await crypto.subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        publicKey,
        data
    );

    // Convert the encrypted data to Base64
    const encryptedBase64 = arrayBufferToBase64(encryptedData);

    return encryptedBase64;
  } catch (error) {
    console.error("Error encrypting message:", error);
    throw error;
  }
}

// Decrypts a message using an RSA private key





export async function rsaDecrypt(
    data: string,
    privateKey: webcrypto.CryptoKey
): Promise<string> {
  try {
    // Decode the Base64 data to ArrayBuffer
    const encryptedData = base64ToArrayBuffer(data);

    // Decrypt the data with the private key
    const decryptedData = await crypto.subtle.decrypt(
        {
          name: "RSA-OAEP"
        },
        privateKey,
        encryptedData
    );

    // Convert the decrypted data to a string using TextDecoder with UTF-8
    const decryptedBase64 = arrayBufferToBase64(decryptedData);

    return decryptedBase64;
  } catch (error) {
    console.error("Error decrypting message:", error);
    throw error;
  }
}


// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  try {
    // Generate a random 256-bit (32 bytes) key
    const key = await crypto.subtle.generateKey(
        {
          name: "AES-CBC",
          length: 256 // Use 256 bits key size for AES
        },
        true, // Make the key extractable
        ["encrypt", "decrypt"] // Key can be used for both encryption and decryption
    );

    return key;
  } catch (error) {
    console.error("Error creating random symmetric key:", error);
    throw error;
  }
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  try {
    // Export the symmetric key
    const exportedKey = await crypto.subtle.exportKey("raw", key);

    // Convert the exported key data to a Base64 string
    const exportedBase64 = arrayBufferToBase64(exportedKey);

    return exportedBase64;
  } catch (error) {
    console.error("Error exporting symmetric key:", error);
    throw error;
  }
}

// Import a base64 string format to its crypto native format
export async function symEncrypt(
    key: webcrypto.CryptoKey,
    data: string
): Promise<string> {
  try {
    // Generate a random initialization vector (IV)
    const iv = crypto.getRandomValues(new Uint8Array(16)); // 16 bytes for AES-CBC IV

    // Convert the string data to a Uint8Array using TextEncoder
    const encodedData = new TextEncoder().encode(data);

    // Encrypt the data with the symmetric key and the generated IV
    const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-CBC",
          iv: iv, // Include the IV in the encryption parameters
        },
        key,
        encodedData
    );

    // Combine the IV and the encrypted data into a single buffer
    const combinedBuffer = new Uint8Array(iv.length + encryptedData.byteLength);
    combinedBuffer.set(iv);
    combinedBuffer.set(new Uint8Array(encryptedData), iv.length);

    // Convert the combined buffer to a Base64 string
    const encryptedBase64 = arrayBufferToBase64(combinedBuffer.buffer);

    return encryptedBase64;
  } catch (error) {
    console.error("Error encrypting message:", error);
    throw error;
  }
}


// Encrypt a message using a symmetric key

export async function importSymKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  try {
    // Convert the Base64 string to ArrayBuffer
    const arrayBuffer = base64ToArrayBuffer(strKey);

    // Import the ArrayBuffer as a CryptoKey
    const symmetricKey = await crypto.subtle.importKey(
        "raw",
        arrayBuffer,
        {
          name: "AES-CBC"
        },
        true, // Make the key extractable
        ["encrypt", "decrypt"] // Key can be used for both encryption and decryption
    );

    return symmetricKey;
  } catch (error) {
    console.error("Error importing symmetric key:", error);
    throw error;
  }
}


// Decrypt a message using a symmetric key
export async function symDecrypt(
    strKey: string,
    encryptedData: string
): Promise<string> {
  try {
    // Import the symmetric key from Base64 string to CryptoKey
    const symmetricKey = await importSymKey(strKey);

    // Decode the Base64 encrypted data to ArrayBuffer
    const arrayBuffer = base64ToArrayBuffer(encryptedData);

    // Extract the IV (first 16 bytes) from the combined buffer
    const iv = arrayBuffer.slice(0, 16);

    // Extract the encrypted data (after the IV) from the combined buffer
    const encryptedBytes = arrayBuffer.slice(16);

    // Decrypt the data with the symmetric key and the extracted IV
    const decryptedData = await crypto.subtle.decrypt(
        {
          name: "AES-CBC",
          iv: iv, // Include the IV in the decryption parameters
        },
        symmetricKey,
        encryptedBytes
    );

    // Convert the decrypted data ArrayBuffer to a string using TextDecoder
    const decryptedString = new TextDecoder().decode(decryptedData);

    return decryptedString;
  } catch (error) {
    console.error("Error decrypting message:", error);
    throw error;
  }
}
