const crypto = require('crypto');


function modExp(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % mod;
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}


function secureRandomBigInt(max) {
    const byteLen = Math.ceil(max.toString(2).length / 8);
    let r;
    do {
        const buf = crypto.randomBytes(byteLen);
        r = BigInt('0x' + buf.toString('hex'));
        r = r % (max - 2n) + 2n;
    } while (r < 2n || r >= max);
    return r;
}


function deriveKey(sharedSecret, bits) {
    const secretHex = sharedSecret.toString(16).padStart(64, '0');
    const hash = crypto.createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest();

    if (bits === 10) {
        
        const byte0 = hash[0];
        const byte1 = hash[1];
        const combined = (byte0 << 8) | byte1;
        return (combined >>> 6).toString(2).padStart(10, '0');
    } else if (bits === 128) {
        
        return hash.slice(0, 16).toString('hex');
    }
    throw new Error('Unsupported key size');
}

module.exports = { modExp, secureRandomBigInt, deriveKey };