class myCrypto {
    constructor() {
        const plaintextModulus = 65537
        const sigma = 3.2
        const depth = 2

        this.cryptoContext = palisade_pke.GenCryptoContextBFVrns(plaintextModulus, palisade_pke.SecurityLevel.HEStd_128_classic, sigma, 0, depth, 0, palisade_pke.MODE.OPTIMIZED)
        console.log("cryptoContext:" + this.cryptoContext)
    }
    _toJs(v) {
        let res = null;
        try { res = v.toJs(); }
        catch (e) { res = v; }
        return res;
    }
    MakeVectorInt64Clipped(vec) {
        return palisade_pke.MakeVectorInt64Clipped(this._toJs(vec));
    }
    Enable(v) {
        this.cryptoContext.Enable(v);
    }
    KeyGen() {
        this.keyPair = this.cryptoContext.KeyGen();
        return this.keyPair;
    }
    EvalMultKeyGen() {
        this.cryptoContext.EvalMultKeyGen(this.keyPair.secretKey)
    }
    EvalAtIndexKeyGen(vec) {
        this.cryptoContext.EvalAtIndexKeyGen(this.keyPair.secretKey, this._toJs(vec))
    }
    MakePackedPlaintext(v) {
        return this.cryptoContext.MakePackedPlaintext(v);
    }
    Encrypt(plaintext) {
        return this.cryptoContext.Encrypt(this.keyPair.publicKey, plaintext);
    }
    EvalAddCipherCipher(ciphertext1, ciphertext2) {
        return this.cryptoContext.EvalAddCipherCipher(ciphertext1, ciphertext2);
    }
    EvalMultCipherCipher(ciphertext1, ciphertext2) {
        return this.cryptoContext.EvalMultCipherCipher(ciphertext1, ciphertext2);
    }
    EvalAtIndex(ciphertext, idx) {
        return this.cryptoContext.EvalAtIndex(ciphertext, idx);
    }
    Decrypt(ciphertext) {
        let plaintext = this.cryptoContext.Decrypt(this.keyPair.secretKey, ciphertext);
        console.log("plaintext len=" + plaintext.GetLength() + "value:" + plaintext.GetPackedValue());
        return plaintext;
    }
    SerializeCryptoContextToBuffer() {
        return palisade_pke.SerializeCryptoContextToBuffer(this.cryptoContext, palisade_pke.SerType.JSON);
    }
    DeserializeCryptoContextFromBuffer(cryptoContextBuffer) {
        return palisade_pke.DeserializeCryptoContextFromBuffer(cryptoContextBuffer, palisade_pke.SerType.JSON);
    }
    Equals(cc) {
        return cc.$$.ptr === this.cryptoContext.$$.ptr;
    }
    set(cc) {
        this.cryptoContext = cc;
        console.log("cryptoContext updated!");
    }
    delete() {
        this.cryptoContext.delete();
        this.cryptoContext = null;
        console.log("cryptoContext deleted!");
    }
};
