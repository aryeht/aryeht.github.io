import sys
sys.version
import pandas as pd
import numpy as np
from pyodide import to_js

from js import createCrypto, palisade_pke
cryptoContext = createCrypto()

# Enable features that you wish to use
cryptoContext.Enable(palisade_pke.PKESchemeFeature.ENCRYPTION)
cryptoContext.Enable(palisade_pke.PKESchemeFeature.SHE)

# Generate a public/private key pair
keyPair = cryptoContext.KeyGen()

print('keyPair.secretKey.GetKeyTag():')
print(keyPair.secretKey.GetKeyTag())
print('keyPair.secretKey.GetCryptoParameters():')
print(keyPair.secretKey.GetCryptoParameters())
print('keyPair.secretKey.GetCryptoContext():')
print(keyPair.secretKey.GetCryptoContext())

print('keyPair.secretKey.GetCryptoParameters():')
print(keyPair.secretKey.GetCryptoParameters())

# Generate the relinearization key
cryptoContext.EvalMultKeyGen()

# Generate the rotation evaluation keys
cryptoContext.EvalAtIndexKeyGen([1, 2, -1, -2])

vectorOfInts1 = cryptoContext.MakeVectorInt64Clipped([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)

vectorOfInts2 = cryptoContext.MakeVectorInt64Clipped([3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12])
plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2)

vectorOfInts3 = cryptoContext.MakeVectorInt64Clipped([1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12])
plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3)

# The encoded vectors are encrypted
ciphertext1 = cryptoContext.Encrypt(plaintext1)
ciphertext2 = cryptoContext.Encrypt(plaintext2)
ciphertext3 = cryptoContext.Encrypt(plaintext3)

print('end encryption')


# Step 4: Evaluation

# Homomorphic additions
ciphertextAdd12 = cryptoContext.EvalAddCipherCipher(ciphertext1, ciphertext2)
ciphertextAddResult = cryptoContext.EvalAddCipherCipher(ciphertextAdd12, ciphertext3)
print('additions end evaluation')

# Homomorphic multiplications
ciphertextMul12 = cryptoContext.EvalMultCipherCipher(ciphertext1, ciphertext2)
ciphertextMultResult = cryptoContext.EvalMultCipherCipher(ciphertextMul12, ciphertext3)
print('multiplications end evaluation')

# Homomorphic rotations
ciphertextRot1 = cryptoContext.EvalAtIndex(ciphertext1, 1)
ciphertextRot2 = cryptoContext.EvalAtIndex(ciphertext1, 2)
ciphertextRot3 = cryptoContext.EvalAtIndex(ciphertext1, -1)
ciphertextRot4 = cryptoContext.EvalAtIndex(ciphertext1, -2)

print('end evaluation')


# Step 5: Decryption

# Decrypt the result of additions
plaintextAddResult = cryptoContext.Decrypt(ciphertextAddResult)

# Decrypt the result of multiplications
plaintextMultResult = cryptoContext.Decrypt(ciphertextMultResult)

# Decrypt the result of rotations
plaintextRot1 = cryptoContext.Decrypt(ciphertextRot1)
plaintextRot2 = cryptoContext.Decrypt(ciphertextRot2)
plaintextRot3 = cryptoContext.Decrypt(ciphertextRot3)
plaintextRot4 = cryptoContext.Decrypt(ciphertextRot4)

print(f"Plaintext #1: {plaintext1}")
print(dir(plaintext1))
print(type(plaintext1))
#print(plaintext1.GetPackedValue())
#print(plaintext1.GetCoefPackedValue())
#print(plaintext1.GetLength())
#print(plaintext1.GetLogPrecision())
#print(plaintext1.GetRealPackedValue())


print(f"Plaintext #2: {plaintext2}")
print(f"Plaintext #3: {plaintext3}")

print('Results of homomorphic computations')
print(f"#1 + #2 + #3: {plaintextAddResult}");
print(f"#1 * #2 * #3: {plaintextMultResult}");
print(f"Left rotation of #1 by 1: {plaintextRot1}")
print(f"Left rotation of #1 by 2: {plaintextRot2}")
print(f"Right rotation of #1 by 1: {plaintextRot3}")
print(f"Right rotation of #1 by 2: {plaintextRot4}")

cryptoContext.delete()
