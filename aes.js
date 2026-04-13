const crypto = require('crypto');


function processAES(textHex, keyHex, mode) {
    const keyBuf = Buffer.from(keyHex, 'hex'); 

    const logs = {
        original: textHex,
        key: keyHex,
        mode,
        algorithm: 'AES-128-CBC',
    };

    if (mode === 'encrypt') {
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', keyBuf, iv);
        cipher.setAutoPadding(true);

        const inputBuf = Buffer.from(textHex, 'hex');
        const encrypted = Buffer.concat([cipher.update(inputBuf), cipher.final()]);

        logs.iv = iv.toString('hex');
        logs.final = encrypted.toString('hex');
        logs.ivPlusEncrypted = iv.toString('hex') + ':' + encrypted.toString('hex');
        logs.steps = [
            { label: 'Алгоритм', value: 'AES-128-CBC' },
            { label: 'Ключ (hex)', value: keyHex },
            { label: 'IV (випадковий)', value: iv.toString('hex') },
            { label: 'Вхід (hex)', value: textHex },
            { label: 'Зашифровано (hex)', value: encrypted.toString('hex') },
        ];
    } else {
        
        const parts = textHex.split(':');
        if (parts.length !== 2) {
            throw new Error('Для дешифрування AES потрібен формат: IV:шифротекст (hex)');
        }
        const iv = Buffer.from(parts[0], 'hex');
        const encryptedBuf = Buffer.from(parts[1], 'hex');

        const decipher = crypto.createDecipheriv('aes-128-cbc', keyBuf, iv);
        decipher.setAutoPadding(true);
        const decrypted = Buffer.concat([decipher.update(encryptedBuf), decipher.final()]);

        logs.iv = parts[0];
        logs.final = decrypted.toString('hex');
        logs.steps = [
            { label: 'Алгоритм', value: 'AES-128-CBC' },
            { label: 'Ключ (hex)', value: keyHex },
            { label: 'IV', value: parts[0] },
            { label: 'Зашифровано (hex)', value: parts[1] },
            { label: 'Розшифровано (hex)', value: decrypted.toString('hex') },
        ];
    }

    return logs;
}

module.exports = { processAES };