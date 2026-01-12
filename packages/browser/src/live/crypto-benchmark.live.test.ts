/**
 * Benchmark comparing SubtleCrypto vs pure JS crypto performance.
 *
 * This test measures the actual throughput difference between:
 * - webcryptoCrypto (SubtleCrypto - hardware accelerated)
 * - pureJsCrypto (@noble libraries)
 */

import { describe, it, expect } from 'vitest';
import { gcm } from '@noble/ciphers/aes';
import { sha256 } from '@noble/hashes/sha256';
import { p256 } from '@noble/curves/p256';

describe('Crypto Performance Benchmark', () => {
  it('benchmarks AES-GCM encryption (the TLS hot path)', async () => {
    // Test data - 1KB chunks (typical TLS record size)
    const testData = new Uint8Array(1024);
    crypto.getRandomValues(testData);

    // Generate a test key
    const keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);

    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    const iterations = 100;

    // Benchmark SubtleCrypto
    console.log('\n--- AES-256-GCM Encryption Benchmark ---');

    const subtleKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);

    const subtleStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const testIv = new Uint8Array(12);
      testIv.set(iv);
      testIv[11] = i % 256;
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: testIv }, subtleKey, testData);
    }
    const subtleEnd = performance.now();
    const subtleTime = subtleEnd - subtleStart;
    const subtleThroughput = (iterations * 1024) / (subtleTime / 1000) / 1024;

    console.log(`SubtleCrypto: ${subtleTime.toFixed(2)}ms for ${iterations} iterations`);
    console.log(`SubtleCrypto throughput: ${subtleThroughput.toFixed(2)} KB/s`);

    // Benchmark @noble/ciphers
    const nobleStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const testIv = new Uint8Array(12);
      testIv.set(iv);
      testIv[11] = i % 256;
      const cipher = gcm(keyBytes, testIv);
      cipher.encrypt(testData);
    }
    const nobleEnd = performance.now();
    const nobleTime = nobleEnd - nobleStart;
    const nobleThroughput = (iterations * 1024) / (nobleTime / 1000) / 1024;

    console.log(`@noble/ciphers: ${nobleTime.toFixed(2)}ms for ${iterations} iterations`);
    console.log(`@noble/ciphers throughput: ${nobleThroughput.toFixed(2)} KB/s`);

    const speedup = nobleTime / subtleTime;
    console.log(`\nSubtleCrypto is ${speedup.toFixed(2)}x faster than pure JS`);

    expect(subtleTime).toBeLessThan(nobleTime);
  }, 30000);

  it('benchmarks SHA-256 hashing', async () => {
    const testData = new Uint8Array(1024);
    crypto.getRandomValues(testData);

    const iterations = 1000;

    console.log('\n--- SHA-256 Hashing Benchmark ---');

    // SubtleCrypto SHA-256
    const subtleStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await crypto.subtle.digest('SHA-256', testData);
    }
    const subtleEnd = performance.now();
    const subtleTime = subtleEnd - subtleStart;

    console.log(`SubtleCrypto SHA-256: ${subtleTime.toFixed(2)}ms for ${iterations} iterations`);

    // @noble/hashes SHA-256
    const nobleStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      sha256(testData);
    }
    const nobleEnd = performance.now();
    const nobleTime = nobleEnd - nobleStart;

    console.log(`@noble/hashes SHA-256: ${nobleTime.toFixed(2)}ms for ${iterations} iterations`);

    const speedup = nobleTime / subtleTime;
    console.log(`\nSubtleCrypto is ${speedup.toFixed(2)}x faster than pure JS`);
  }, 30000);

  it('benchmarks ECDH key exchange (P-256)', async () => {
    const iterations = 50;

    console.log('\n--- ECDH P-256 Key Exchange Benchmark ---');

    // SubtleCrypto ECDH
    const subtleStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveBits',
      ]);
      const peerKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
      );
      await crypto.subtle.deriveBits(
        { name: 'ECDH', public: peerKeyPair.publicKey },
        keyPair.privateKey,
        256
      );
    }
    const subtleEnd = performance.now();
    const subtleTime = subtleEnd - subtleStart;

    console.log(`SubtleCrypto ECDH: ${subtleTime.toFixed(2)}ms for ${iterations} iterations`);
    console.log(`SubtleCrypto: ${(subtleTime / iterations).toFixed(2)}ms per key exchange`);

    // @noble/curves ECDH (P-256)
    const nobleStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const privKey = p256.utils.randomPrivateKey();
      const peerPrivKey = p256.utils.randomPrivateKey();
      const peerPubKey = p256.getPublicKey(peerPrivKey);
      p256.getSharedSecret(privKey, peerPubKey);
    }
    const nobleEnd = performance.now();
    const nobleTime = nobleEnd - nobleStart;

    console.log(`@noble/curves ECDH: ${nobleTime.toFixed(2)}ms for ${iterations} iterations`);
    console.log(`@noble/curves: ${(nobleTime / iterations).toFixed(2)}ms per key exchange`);

    const speedup = nobleTime / subtleTime;
    console.log(`\nSubtleCrypto is ${speedup.toFixed(2)}x faster than pure JS`);
  }, 60000);

  it('benchmarks full TLS-like encryption workflow', async () => {
    // Simulate a TLS data transfer: encrypt many 16KB records
    const recordSize = 16 * 1024; // 16KB TLS record
    const totalData = 1024 * 1024; // 1MB total
    const records = totalData / recordSize;

    const testData = new Uint8Array(recordSize);
    crypto.getRandomValues(testData);

    const keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);

    console.log('\n--- TLS Record Encryption Simulation (1MB data) ---');

    // SubtleCrypto
    const subtleKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
      'encrypt',
    ]);

    const subtleStart = performance.now();
    for (let i = 0; i < records; i++) {
      const iv = new Uint8Array(12);
      iv[11] = i % 256;
      iv[10] = Math.floor(i / 256) % 256;
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, subtleKey, testData);
    }
    const subtleEnd = performance.now();
    const subtleTime = subtleEnd - subtleStart;
    const subtleThroughput = totalData / (subtleTime / 1000) / 1024 / 1024; // MB/s

    console.log(`SubtleCrypto: ${subtleTime.toFixed(2)}ms for 1MB`);
    console.log(`SubtleCrypto throughput: ${subtleThroughput.toFixed(2)} MB/s`);

    // @noble/ciphers
    const nobleStart = performance.now();
    for (let i = 0; i < records; i++) {
      const iv = new Uint8Array(12);
      iv[11] = i % 256;
      iv[10] = Math.floor(i / 256) % 256;
      const cipher = gcm(keyBytes, iv);
      cipher.encrypt(testData);
    }
    const nobleEnd = performance.now();
    const nobleTime = nobleEnd - nobleStart;
    const nobleThroughput = totalData / (nobleTime / 1000) / 1024 / 1024;

    console.log(`@noble/ciphers: ${nobleTime.toFixed(2)}ms for 1MB`);
    console.log(`@noble/ciphers throughput: ${nobleThroughput.toFixed(2)} MB/s`);

    const speedup = nobleTime / subtleTime;
    console.log(`\nSubtleCrypto is ${speedup.toFixed(2)}x faster than pure JS`);

    // Calculate time to transfer 2MB consensus
    const consensusSize = 2 * 1024 * 1024;
    const subtleConsensusTime = consensusSize / (subtleThroughput * 1024 * 1024);
    const nobleConsensusTime = consensusSize / (nobleThroughput * 1024 * 1024);

    console.log(`\n--- Estimated 2MB Consensus Download (crypto only) ---`);
    console.log(`SubtleCrypto: ${subtleConsensusTime.toFixed(2)}s`);
    console.log(`@noble/ciphers: ${nobleConsensusTime.toFixed(2)}s`);
  }, 60000);
});
