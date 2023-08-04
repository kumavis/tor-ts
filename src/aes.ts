import { Mutex } from "./util"

const blockLength = 16
const keyParams = { name: 'AES-CTR', length: 128 }

const incrementCounter = (counter, blockCount: number) => {
  const ivLength = counter.length
  const numberLength = 6
  const counterOffset = ivLength - numberLength
  const currentCounter = counter.readUIntBE(counterOffset, numberLength)
  counter.writeUIntBE(currentCounter + blockCount, counterOffset, numberLength)
}

export const makeAes128CtrKey = async (key: Buffer) => {
  const counter = Buffer.alloc(blockLength)
  const cryptParams = { ...keyParams, length: 64, counter }
  // when AES-CTR is used in stream mode, it will leave unused
  // encryption bytes from the block in the cache. webcrypto does not
  // seem to provide an api to support this but we can achieve it by
  // prepending padding to the input and then removing from the beggining of
  // the output and not incrementing our counter for the partial block
  let internalOffset = 0
  const iKey = await crypto.subtle.importKey('raw', key, keyParams, false, ['encrypt', 'decrypt'])
  const mutex = new Mutex()
  
  const crypt = async (input: Buffer): Promise<Buffer> => {
    const unlock = await mutex.lock()
    try {
      const paddedInput = Buffer.concat([
        Buffer.alloc(internalOffset),
        input,
      ])
      const paddedOutput = Buffer.from(
        // this is a symetric cipher so encryption is the same
        // as decryption
        await crypto.subtle.encrypt(cryptParams, iKey, paddedInput)
      )
      const output = paddedOutput.subarray(internalOffset)
      // floor instead of ceil because we track the offset
      const blockCount = Math.floor(paddedInput.length / blockLength)
      internalOffset = paddedInput.length % blockLength
      incrementCounter(counter, blockCount)
      return output
    } finally {
      unlock()
    }
  }
  return {
    encrypt (plaintext: Buffer) {
      return crypt(plaintext)
    },
    decrypt (ciphertext: Buffer) {
      return crypt(ciphertext)
    },
  }
}
