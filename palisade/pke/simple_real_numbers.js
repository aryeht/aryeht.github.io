function getVectorDouble(arr) {
  let vec = new module.VectorDouble();
  for (let i of arr) vec.push_back(i);
  return vec;
}

async function main() {
  const factory = require('../../../lib/palisade_pke')
  module = await factory()
  // Step 1: Setup CryptoContext
  const multDepth = 1;
  const scaleFactorBits = 50;
  const batchSize = 8;
  const securityLevel = module.SecurityLevel.HEStd_128_classic;

  const cc = new module.GenCryptoContextCKKS(multDepth, scaleFactorBits, batchSize, securityLevel);

  console.log(`CKKS scheme is using ring dimension ${cc.GetRingDimension()}\n`)

  cc.Enable(module.PKESchemeFeature.ENCRYPTION);
  cc.Enable(module.PKESchemeFeature.SHE);

  // Step 2: Key Generation
  const keys = cc.KeyGen();
  cc.EvalMultKeyGen(keys.secretKey);
  cc.EvalAtIndexKeyGen(keys.secretKey, [1, -2]);

  // Step 3: Encoding and encryption of targets
  const x1 = new module.VectorDouble([0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]);
  const x2 = new module.VectorDouble([5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]);

  const ptxt1 = cc.MakeCKKSPackedPlaintext(x1);
  const ptxt2 = cc.MakeCKKSPackedPlaintext(x2);

  console.log(`Input x1: ${ptxt1}`);
  console.log(`Input x2: ${ptxt2}`);

  const c1 = cc.Encrypt(keys.publicKey, ptxt1);
  const c2 = cc.Encrypt(keys.publicKey, ptxt2);

  // Step 4: Evaluation
  // note that overloads hve been replaced with separate methods here
  const cAdd = cc.EvalAddCipherCipher(c1, c2);
  const cSub = cc.EvalSubCipherCipher(c1, c2);
  const cScalar = cc.EvalMultCipherConstant(c1, 4.0);
  const cMul = cc.EvalMultCipherCipher(c1, c2);

  const cRot1 = cc.EvalAtIndex(c1, 1);
  const cRot2 = cc.EvalAtIndex(c1, -2);

  // Step 5: Decryption and output
  let result;
  console.log('Results of homomorphic computations');
  result = cc.Decrypt(keys.secretKey, cAdd);
  result.SetLength(batchSize);
  console.log(`x1 + x2 = ${result} Estimated precision in bits ${result.GetLogPrecision()}`)

  result = cc.Decrypt(keys.secretKey, cSub);
  result.SetLength(batchSize);
  console.log(`x1 - x2 = ${result}`);

  result = cc.Decrypt(keys.secretKey, cScalar);
  result.SetLength(batchSize);
  console.log(`4 * x1 = ${result}`);

  result = cc.Decrypt(keys.secretKey, cMul);
  result.SetLength(batchSize);
  console.log(`x1 * x2 = ${result}`);

  result = cc.Decrypt(keys.secretKey, cRot1);
  result.SetLength(batchSize);
  console.log('\nIn rotations, very small outputs (~10^-10 here) correspond to 0\'s:\n')
  console.log(`x1 rotate by 1 = ${result}`)

  result = cc.Decrypt(keys.secretKey, cRot2);
  result.SetLength(batchSize);
  console.log(`x1 rotate by -2 = ${result}`)

  return 0;
}
main().then(exitCode => console.log(exitCode));
