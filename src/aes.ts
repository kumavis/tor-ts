
export const makeAes128CtrKey = async (key: Buffer) => {
  const blockLength = 16
  const keyParams = { name: 'AES-CTR', length: 128 }
  const counter = Buffer.alloc(16)
  const cryptParams = { ...keyParams, length: 64, counter }
  // when AES-CTR is used in stream mode, it will leave unused
  // encryption bytes from the block in the cache. webcrypto does not
  // seem to provide an api to support this but we can achieve it by
  // prepending padding to the input and removing from the beggining of
  // the output
  let internalOffset = 0
  const iKey = await crypto.subtle.importKey('raw', key, keyParams, false, ['encrypt', 'decrypt'])
  
  const incrementCounter = (blockCount: number) => {
    const ivLength = counter.length
    const numberLength = 6
    const counterOffset = ivLength - numberLength
    const currentCounter = counter.readUIntBE(counterOffset, numberLength)
    counter.writeUIntBE(currentCounter + blockCount, counterOffset, numberLength)
  }
  const crypt = async (input: Buffer): Promise<Buffer> => {
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
    const blockCount = Math.floor(paddedInput.length / blockLength)
    internalOffset = paddedInput.length % blockLength
    incrementCounter(blockCount)
    return output
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