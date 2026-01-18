/**
 * Browser tests for microdescriptor parsing and SHA256 hashing.
 *
 * These tests verify that the hash computation works correctly in the browser
 * environment, using the same test fixtures as Tor's test_microdesc.c.
 */

import { describe, it, expect } from 'vitest';
import { sha256 } from 'tor-crypto';
import { parseMicrodescriptorBatch, parseMicrodescriptor } from 'tor/directory-client';

// Test vectors from Tor's test_microdesc.c
const test_md1 = `onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMjlHH/daN43cSVRaHBwgUfnszzAhg98EvivJ9Qxfv51mvQUxPjQ07es
gV/3n8fyh3Kqr/ehi9jxkdgSRfSnmF7giaHL1SLZ29kA7KtST+pBvmTpDtHa3ykX
Xorc7hJvIyTZoc1HU+5XSynj3gsBE5IGK1ZRzrNS688LnuZMVp1tAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key AppBt6CSeb1kKid/36ototmFA24ddfW5JpjWPLuoJgs=
`;

const test_md3_noannotation = `onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMH3340d4ENNGrqx7UxT+lB7x6DNUKOdPEOn4teceE11xlMyZ9TPv41c
qj2fRZzfxlc88G/tmiaHshmdtEpklZ740OFqaaJVj4LjPMKFNE+J7Xc1142BE9Ci
KgsbjGYe2RY261aADRWLetJ8T9QDMm+JngL4288hc8pq1uB/3TAbAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key AppBt6CSeb1kKid/36ototmFA24ddfW5JpjWPLuoJgs=
p accept 1-700,800-1000
family nodeX nodeY nodeZ
`;

// Expected hashes from Tor's test code (SHA256 of exact microdescriptor bytes)
const expected_hash_md1 = 'WyuXS18qtToOiPGV2I3959TyuAn2f1QcNT+Q+neOtFk';
const expected_hash_md3 = 'MobrhyPBXBr3w1TMgyTY8OhGDiDOSenQykU+haX5Tk8';

describe('Browser SHA256', () => {
  it('computes correct hash for "hello world"', () => {
    const hash = sha256(Buffer.from('hello world'));
    const hashHex = hash.toString('hex');
    expect(hashHex).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  it('matches Tor test_md1 hash', () => {
    const hash = sha256(Buffer.from(test_md1));
    const hashB64 = hash.toString('base64').replace(/=+$/, '');
    expect(hashB64).toBe(expected_hash_md1);
  });

  it('matches Tor test_md3 hash', () => {
    const hash = sha256(Buffer.from(test_md3_noannotation));
    const hashB64 = hash.toString('base64').replace(/=+$/, '');
    expect(hashB64).toBe(expected_hash_md3);
  });
});

describe('Browser parseMicrodescriptorBatch', () => {
  it('matches all digests from Tor fixtures', () => {
    // Note: No extra newline between microdescriptors - each ends with its own \n
    // and the next starts immediately with "onion-key"
    const batchContent = test_md1 + test_md3_noannotation;
    const digests = [expected_hash_md1, expected_hash_md3];
    const parsed = parseMicrodescriptorBatch(batchContent, digests);

    expect(parsed.size).toBe(2);
    expect(parsed.has(expected_hash_md1)).toBe(true);
    expect(parsed.has(expected_hash_md3)).toBe(true);
  });

  it('correctly parses ntor-onion-key', () => {
    const parsed = parseMicrodescriptor(test_md1);
    expect(parsed.ntorOnionKey).toBeDefined();
    expect(parsed.ntorOnionKey?.length).toBe(32);

    // Verify the key value
    const expectedKey = Buffer.from('AppBt6CSeb1kKid/36ototmFA24ddfW5JpjWPLuoJgs=', 'base64');
    expect(parsed.ntorOnionKey?.equals(expectedKey)).toBe(true);
  });

  it('correctly parses exit policy', () => {
    const parsed = parseMicrodescriptor(test_md3_noannotation);
    expect(parsed.exitPolicy).toBeDefined();
    expect(parsed.exitPolicy?.type).toBe('accept');
    expect(parsed.exitPolicy?.ports).toHaveLength(2);
    expect(parsed.exitPolicy?.ports[0]).toEqual({ start: 1, end: 700 });
    expect(parsed.exitPolicy?.ports[1]).toEqual({ start: 800, end: 1000 });
  });

  it('returns empty map when no digests match', () => {
    const batchContent = test_md1;
    const digests = ['nonexistent123'];
    const parsed = parseMicrodescriptorBatch(batchContent, digests);
    expect(parsed.size).toBe(0);
  });

  it('handles empty content', () => {
    const parsed = parseMicrodescriptorBatch('', ['someDigest']);
    expect(parsed.size).toBe(0);
  });
});

describe('Browser microdescriptor batch fixture', () => {
  // Real microdescriptor batch content (same as Node.js tests)
  const fixtureContent = `onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOgdQrJK9xsVSgU+liwaewJ01Yb0JCnjcqIdUVVLOZqRxBxHVSPqCWu0
kha6kruYTlZ+IJn22CFQf66wElHPn5sGgoxH+9Gq60jg2AjM+SQYD5KKaR1F4QhH
n8KKooMmXNw/2y7S+bWJA29oHhk9Ae9NcbyBeP5rt1zzxEiPJWgRAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key MgElDVaws27q/J+WXzqCw3/4Uf8S15xaWJPkFOKwzVk=
id ed25519 J5lkRqyL6qW+CpN3E4RIlgJZeLgwjtmOOrjZvVhuwLQ
p accept 1-65535

onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK/ZMpOCy4HP+sRdQEVDjbgfYUXQ0Kc5aMh/Af/WWUJld8lldngjn1hn
j1V5GUWGKSIe/jRneUxeNK1m8Nos2iO/GDcBoikXUMGecm8taEq/Cav0B6nrtiXq
hOQL4zv0i9e42pxOa1kEnRfSXyNM4xXuDeulf9CDy/JGZSRB23GdAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key XR9xSwVxJtM0ARX1CQbukCEL04eMjTGMKjg1YDci+Ug=
id ed25519 J5lkRqyL6qW+CpN3E4RIlgJZeLgwjtmOOrjZvVhuwLQ
p accept 1-65535

onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK7a/D6rLoA19po+9iBU7lAqfr8LvQ6ERDVzmCBTUj8CADEzpdGJHIRy
HYUesaiWV5kEFqlCNuhR02Hue146iyvo/ZT/4tyqGY9JbTt0SfI89Mxj/HaAJ9x+
IbRoSlF5UvTSMkvSftMWU0AubImi7FNIOK2y7wjyn1EK78Ykujj5AgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key pnoI8ITWNoHu+JC2c5G5S+5ovwHqY0Gq2YJbwvdLLmo=
id ed25519 J5lkRqyL6qW+CpN3E4RIlgJZeLgwjtmOOrjZvVhuwLQ
p accept 1-65535
`;

  // Pre-computed hashes for the fixture content (computed by sha256 of each microdesc)
  const fixtureDigest1 = '1XMiEDRAOF6AkZ6M1CHcIY30JLwClPLvIUxxMz7ao24';
  const fixtureDigest2 = 'giMvntY8fQPfWON7f7WH5Lu3jHR75mZ5XJP4K5GfYJA';
  const fixtureDigest3 = '2WCxuJF5noUzWogjORwoFneY4Uc0NnKWs8YpY9Aa1bg';

  it('matches all fixture digests', () => {
    const digests = [fixtureDigest1, fixtureDigest2, fixtureDigest3];
    const parsed = parseMicrodescriptorBatch(fixtureContent, digests);

    expect(parsed.size).toBe(3);
    expect(parsed.has(fixtureDigest1)).toBe(true);
    expect(parsed.has(fixtureDigest2)).toBe(true);
    expect(parsed.has(fixtureDigest3)).toBe(true);
  });

  it('parses ed25519 identity from fixture', () => {
    const digests = [fixtureDigest1];
    const parsed = parseMicrodescriptorBatch(fixtureContent, digests);

    const md = parsed.get(fixtureDigest1);
    expect(md).toBeDefined();
    expect(md?.ed25519Identity).toBeDefined();
    expect(md?.ed25519Identity?.length).toBe(32);
  });

  it('parses ntor-onion-key from fixture', () => {
    const digests = [fixtureDigest1];
    const parsed = parseMicrodescriptorBatch(fixtureContent, digests);

    const md = parsed.get(fixtureDigest1);
    expect(md).toBeDefined();
    expect(md?.ntorOnionKey).toBeDefined();
    expect(md?.ntorOnionKey?.length).toBe(32);
  });
});
