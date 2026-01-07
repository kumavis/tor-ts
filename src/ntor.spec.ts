import test from 'ava';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { KDF_RFC5869, NtorParams } from './ntor.ts';

// fn expand(b: &[u8]) -> SecretBuf {
//   let t_key = b"ntor-curve25519-sha256-1:key_extract";
//   let m_expand = b"ntor-curve25519-sha256-1:key_expand";
//   Ntor1Kdf::new(&t_key[..], &m_expand[..])
//       .derive(b, 100)
//       .unwrap()
// }

// let expect = hex!(
//   "5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6
//    c02a4f8d622a6cfdf9b7c7edd3832e2760ded1eac309b76f8d
//    66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3
//    961be9fdb9f93197ea8e5977180801926d3321fa21513e59ac"
// );
// assert_eq!(&expand(&b"Tor"[..])[..], &expect[..]);

// let brunner_quote = b"AN ALARMING ITEM TO FIND ON YOUR CREDIT-RATING STATEMENT";
// let expect = hex!(
//   "a2aa9b50da7e481d30463adb8f233ff06e9571a0ca6ab6df0f
//    b206fa34e5bc78d063fc291501beec53b36e5a0e434561200c
//    5f8bd13e0f88b3459600b4dc21d69363e2895321c06184879d
//    94b18f078411be70b767c7fc40679a9440a0c95ea83a23efbf"
// );
// assert_eq!(&expand(&brunner_quote[..])[..], &expect[..]);

test('KDF_RFC5869', t => {
  const keySeed1 = Buffer.from(hmac(sha256, Buffer.from(NtorParams.t_key, 'utf-8'), Buffer.from('Tor')))
  const result1 = KDF_RFC5869(keySeed1, 100)
  t.is(result1.toString('hex'), '5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6c02a4f8d622a6cfdf9b7c7edd3832e2760ded1eac309b76f8d66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3961be9fdb9f93197ea8e5977180801926d3321fa21513e59ac', 'KDF_RFC5869 result1 does not match')
  const brunnerQuote = Buffer.from('AN ALARMING ITEM TO FIND ON YOUR CREDIT-RATING STATEMENT')
  const keySeed2 = Buffer.from(hmac(sha256, Buffer.from(NtorParams.t_key, 'utf-8'), brunnerQuote))
  const result2 = KDF_RFC5869(keySeed2, 100)
  t.is(result2.toString('hex'), 'a2aa9b50da7e481d30463adb8f233ff06e9571a0ca6ab6df0fb206fa34e5bc78d063fc291501beec53b36e5a0e434561200c5f8bd13e0f88b3459600b4dc21d69363e2895321c06184879d94b18f078411be70b767c7fc40679a9440a0c95ea83a23efbf', 'KDF_RFC5869 result2 does not match')
})