/**
 * AES encryption/decryption using WebCrypto.
 *
 * This module provides cross-platform AES-CTR operations that work identically
 * in Node.js 18+ and browsers using the WebCrypto API (crypto.subtle).
 */

// ============================================================================
// Mutex - async lock utility for stream cipher state protection
// ============================================================================

class Mutex {
  private current: Promise<void> = Promise.resolve();

  lock(): Promise<() => void> {
    let resolveLock!: () => void;
    const p = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    // Caller gets a promise that resolves when the current outstanding lock resolves.
    const unlockP = this.current.then(() => resolveLock);

    // Don't allow the next request until the new promise is done.
    this.current = p;

    return unlockP;
  }
}

// ============================================================================
// Constants
// ============================================================================

const blockLength = 16;
const keyParams128 = { name: 'AES-CTR', length: 128 };
const keyParams256 = { name: 'AES-CTR', length: 256 };

// ============================================================================
// Helper functions
// ============================================================================

const incrementCounter = (counter: Buffer, blockCount: number) => {
  const ivLength = counter.length;
  const numberLength = 6;
  const counterOffset = ivLength - numberLength;
  const currentCounter = counter.readUIntBE(counterOffset, numberLength);
  counter.writeUIntBE(currentCounter + blockCount, counterOffset, numberLength);
};

// ============================================================================
// AES-CTR Stream Ciphers
// ============================================================================

/**
 * Create an AES-128-CTR stream cipher.
 *
 * This cipher maintains internal state for streaming encryption/decryption.
 * It handles partial blocks correctly by tracking the internal offset.
 *
 * @param key - 16-byte AES-128 key
 * @returns Object with encrypt and decrypt methods
 */
export const makeAes128CtrKey = (key: Buffer) => {
  const counter = Buffer.alloc(blockLength);
  const cryptParams = { ...keyParams128, length: 64, counter };
  // when AES-CTR is used in stream mode, it will leave unused
  // encryption bytes from the block in the cache. webcrypto does not
  // seem to provide an api to support this but we can achieve it by
  // prepending padding to the input and then removing from the beggining of
  // the output and not incrementing our counter for the partial block
  let internalOffset = 0;
  // Copy to a Uint8Array backed by an ArrayBuffer (avoids SharedArrayBuffer typing issues)
  const rawKey = Uint8Array.from(key);
  const iKeyP = globalThis.crypto.subtle.importKey('raw', rawKey, keyParams128, false, [
    'encrypt',
    'decrypt',
  ]);
  const mutex = new Mutex();

  const crypt = async (input: Buffer): Promise<Buffer> => {
    const iKey = await iKeyP;
    const unlock = await mutex.lock();
    try {
      const paddedInput = Buffer.concat([Buffer.alloc(internalOffset), input]);
      const paddedOutput = Buffer.from(
        // this is a symetric cipher so encryption is the same
        // as decryption
        await globalThis.crypto.subtle.encrypt(cryptParams, iKey, paddedInput)
      );
      const output = paddedOutput.subarray(internalOffset);
      // floor instead of ceil because we track the offset
      const blockCount = Math.floor(paddedInput.length / blockLength);
      internalOffset = paddedInput.length % blockLength;
      incrementCounter(counter, blockCount);
      return output;
    } finally {
      unlock();
    }
  };
  return {
    encrypt(plaintext: Buffer) {
      return crypt(plaintext);
    },
    decrypt(ciphertext: Buffer) {
      return crypt(ciphertext);
    },
  };
};

/**
 * Create an AES-256-CTR stream cipher.
 *
 * This cipher maintains internal state for streaming encryption/decryption.
 * It handles partial blocks correctly by tracking the internal offset.
 *
 * @param key - 32-byte AES-256 key
 * @returns Object with encrypt and decrypt methods
 */
export const makeAes256CtrKey = (key: Buffer) => {
  const counter = Buffer.alloc(blockLength);
  const cryptParams = { ...keyParams256, length: 64, counter };
  let internalOffset = 0;
  // Copy to a Uint8Array backed by an ArrayBuffer (avoids SharedArrayBuffer typing issues)
  const rawKey = Uint8Array.from(key);
  const iKeyP = globalThis.crypto.subtle.importKey('raw', rawKey, keyParams256, false, [
    'encrypt',
    'decrypt',
  ]);
  const mutex = new Mutex();

  const crypt = async (input: Buffer): Promise<Buffer> => {
    const iKey = await iKeyP;
    const unlock = await mutex.lock();
    try {
      const paddedInput = Buffer.concat([Buffer.alloc(internalOffset), input]);
      const paddedOutput = Buffer.from(
        await globalThis.crypto.subtle.encrypt(cryptParams, iKey, paddedInput)
      );
      const output = paddedOutput.subarray(internalOffset);
      const blockCount = Math.floor(paddedInput.length / blockLength);
      internalOffset = paddedInput.length % blockLength;
      incrementCounter(counter, blockCount);
      return output;
    } finally {
      unlock();
    }
  };

  return {
    encrypt(plaintext: Buffer) {
      return crypt(plaintext);
    },
    decrypt(ciphertext: Buffer) {
      return crypt(ciphertext);
    },
  };
};

// ============================================================================
// One-shot AES-256-CTR XOR
// ============================================================================

/**
 * One-shot AES-256-CTR encryption/decryption (XOR operation).
 *
 * This is a stateless operation - it encrypts/decrypts data with the given
 * key and IV without maintaining any state between calls.
 *
 * @param key - 32-byte AES-256 key
 * @param iv - 16-byte initialization vector (counter)
 * @param data - Data to encrypt/decrypt
 * @returns Encrypted/decrypted data
 */
export async function aes256CtrXor(key: Buffer, iv: Buffer, data: Buffer): Promise<Buffer> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    Uint8Array.from(key),
    { name: 'AES-CTR' },
    false,
    ['encrypt', 'decrypt']
  );
  const result = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-CTR',
      counter: Uint8Array.from(iv),
      length: 64,
    },
    cryptoKey,
    Uint8Array.from(data)
  );
  return Buffer.from(result);
}
