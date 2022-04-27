from js import palisade_pke

plaintextModulus = 65537
sigma = 3.2
depth = 2

# Instantiate the crypto context
cryptoContext = palisade_pke.GenCryptoContextBFVrns(plaintextModulus, palisade_pke.SecurityLevel.HEStd_128_classic, sigma, 0, depth, 0, palisade_pke.MODE.OPTIMIZED)

# Enable features that you wish to use
cryptoContext.Enable(palisade_pke.PKESchemeFeature.ENCRYPTION)
cryptoContext.Enable(palisade_pke.PKESchemeFeature.SHE)

# Generate a public/private key pair
keyPair = cryptoContext.KeyGen()

print(keyPair.secretKey.GetKeyTag())
print(keyPair.secretKey.GetCryptoParameters())
print(dir(keyPair.secretKey))


# Generate the relinearization key
cryptoContext.EvalMultKeyGen(keyPair.secretKey)


# Generate the rotation evaluation keys
cryptoContext.EvalAtIndexKeyGen(keyPair.secretKey, [1, 2, -1, -2])



'''
Traceback (most recent call last):
  File "<console>", line 1, in <module>
  File "http://localhost:8000/palisade/palisade_pke.js", line 4723, in __emval_as
  File "http://localhost:8000/palisade/palisade_pke.js", line 4501, in Object.toWireType
  File "http://localhost:8000/palisade/palisade_pke.js", line 4487, in checkAssertions
JsException: TypeError: Cannot convert "undefined" to int'''

'''
  // Generate the rotation evaluation keys
  cryptoContext.EvalAtIndexKeyGen(keyPair.secretKey, [1, 2, -1, -2]);


  // Sample Program: Step 3: Encryption
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays
  // First plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
  // in JS)
  const vectorOfInts1 = palisade_pke.MakeVectorInt64Clipped(
	[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] );
  //"Plaintext" type is switched to string
  const plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1);
  // Second plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
  // in JS)
  const vectorOfInts2 = palisade_pke.MakeVectorInt64Clipped(
	  [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12] );
  //"Plaintext" type is switched to string
  const plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2);
  // Third plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
  // in JS)
  const vectorOfInts3 = palisade_pke.MakeVectorInt64Clipped(
	  [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12] );
  //"Plaintext" type is switched to string
  const plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3);
  // The encoded vectors are encrypted
  const ciphertext1 = cryptoContext.Encrypt(keyPair.publicKey, plaintext1);
  const ciphertext2 = cryptoContext.Encrypt(keyPair.publicKey, plaintext2);
  const ciphertext3 = cryptoContext.Encrypt(keyPair.publicKey, plaintext3);
  // Sample Program: Step 4: Evaluation
  // all "auto" types become "any"
  // Homomorphic additions
  const ciphertextAdd12 = cryptoContext.EvalAddCipherCipher(ciphertext1, ciphertext2);
  const ciphertextAddResult = cryptoContext.EvalAddCipherCipher(ciphertextAdd12, ciphertext3);
  // Homomorphic multiplications
  const ciphertextMul12 = cryptoContext.EvalMultCipherCipher(ciphertext1, ciphertext2);
  const ciphertextMultResult = cryptoContext.EvalMultCipherCipher(ciphertextMul12, ciphertext3);
  // Homomorphic rotations
  const ciphertextRot1 = cryptoContext.EvalAtIndex(ciphertext1, 1);
  const ciphertextRot2 = cryptoContext.EvalAtIndex(ciphertext1, 2);
  const ciphertextRot3 = cryptoContext.EvalAtIndex(ciphertext1, -1);
  const ciphertextRot4 = cryptoContext.EvalAtIndex(ciphertext1, -2);
  // Sample Program: Step 5: Decryption
  // Decrypt the result of additions
  // Plaintext => any
  let plaintextAddResult = cryptoContext.Decrypt(keyPair.secretKey, ciphertextAddResult);
  // Decrypt the result of multiplications
  // Plaintext => any
  let plaintextMultResult = cryptoContext.Decrypt(keyPair.secretKey, ciphertextMultResult);
  // Decrypt the result of rotations
  //"Plaintext" => "implicit, emscripten will handle"
  let plaintextRot1 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot1);
  let plaintextRot2 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot2);
  let plaintextRot3 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot3);
  let plaintextRot4 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot4);

  plaintextRot1.SetLength(vectorOfInts1.size());
  plaintextRot2.SetLength(vectorOfInts1.size());
  plaintextRot3.SetLength(vectorOfInts1.size());
  plaintextRot4.SetLength(vectorOfInts1.size());

  console.log(`Plaintext #1: ${plaintext1}`);
  console.log(`Plaintext #2: ${plaintext2}`);
  console.log(`Plaintext #3: ${plaintext3}`);
  // Output results
  console.log('\nResults of homomorphic computations');
  console.log(`#1 + #2 + #3: ${plaintextAddResult}`);
  console.log(`#1 * #2 * #3: ${plaintextMultResult}`);
  console.log(`Left rotation of #1 by 1: ${plaintextRot1}`);
  console.log(`Left rotation of #1 by 2: ${plaintextRot2}`);
  console.log(`Right rotation of #1 by 1: ${plaintextRot3}`);
  console.log(`Right rotation of #1 by 2: ${plaintextRot4}`);
  cryptoContext.delete();
  return 0;

'''
