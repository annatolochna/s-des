
function modExp(base, exp, mod) {
    let result = 1n;
    base = BigInt(base) % BigInt(mod);
    exp = BigInt(exp);
    const p = BigInt(mod);
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % p;
        exp = exp / 2n;
        base = (base * base) % p;
    }
    return result;
}


async function deriveKeyFromSecret(sharedSecret, algorithm) {
    
    const secretHex = sharedSecret.toString(16).padStart(64, '0');
    const secretBytes = hexToBytes(secretHex);

    const hashBuf = await crypto.subtle.digest('SHA-256', secretBytes);
    const hashArr = new Uint8Array(hashBuf);

    if (algorithm === 'sdes') {
        
        const combined = (hashArr[0] << 8) | hashArr[1];
        return (combined >>> 6).toString(2).padStart(10, '0');
    } else {
        
        return Array.from(hashArr.slice(0, 16))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}


let currentMode = 'encrypt';
let currentAlgorithm = 'sdes';
let currentStepsData = null;
let currentSessionId = null;  


document.querySelectorAll('input[name="algorithm"]').forEach(radio => {
    radio.addEventListener('change', () => {
        currentAlgorithm = radio.value;

        
        document.getElementById('algo-sdes-card').classList.toggle('active', currentAlgorithm === 'sdes');
        document.getElementById('algo-aes-card').classList.toggle('active', currentAlgorithm === 'aes');

        
        document.getElementById('algo-hint-sdes').style.display = currentAlgorithm === 'sdes' ? 'block' : 'none';
        document.getElementById('algo-hint-aes').style.display = currentAlgorithm === 'aes' ? 'block' : 'none';

        
        document.getElementById('algo-tag-label').textContent = currentAlgorithm === 'sdes' ? 'S-DES' : 'AES-128-CBC';
        updateMessageFieldHint();

        
        resetToStep1();
    });
});

function updateMessageFieldHint() {
    const isSdes = currentAlgorithm === 'sdes';
    document.getElementById('label-message').innerHTML =
        isSdes
            ? 'Відкритий текст <span id="label-hint" class="field-hint">(8 біт: символи 0 та 1)</span>'
            : 'Вхідні дані <span id="label-hint" class="field-hint">(hex-рядок, парна кількість символів)</span>';
    document.getElementById('message').placeholder = isSdes ? '11010000' : '48656c6c6f21';

    const decRow = document.getElementById('res-dec-row');
    if (decRow) decRow.style.display = isSdes ? 'flex' : 'none';

    const submitLabel = document.getElementById('btn-submit-label');
    if (submitLabel) {
        submitLabel.textContent = currentMode === 'encrypt'
            ? 'Зашифрувати та відправити'
            : 'Розшифрувати та відправити';
    }
}

function resetToStep1() {
    document.getElementById('dh-result').style.display = 'none';
    document.getElementById('sdes-section').classList.add('disabled');
    document.getElementById('key').value = '';
    document.getElementById('quick-result').style.display = 'none';
    document.getElementById('sdes-visualizer').style.display = 'none';
    document.getElementById('aes-visualizer').style.display = 'none';
    currentSessionId = null;

   
    document.getElementById('key-bits-label').textContent =
        currentAlgorithm === 'sdes' ? '(10 біт, KDF)' : '(128 біт, KDF → SHA-256)';
}


document.getElementById('btn-dh').addEventListener('click', async () => {
    const p = document.getElementById('dh-p').value;
    const g = document.getElementById('dh-g').value;
    const a = document.getElementById('dh-a').value;

    if (!p || !g || !a) { alert('Заповніть всі поля DH'); return; }

    const btn = document.getElementById('btn-dh');
    btn.textContent = '⌛ Обчислення...';
    btn.disabled = true;

    try {
        
        const A = modExp(g, a, p);

       
        const response = await fetch('/api/dh-exchange', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ p, g, A: A.toString(), algorithm: currentAlgorithm }),
        });
        const data = await response.json();

        if (!response.ok) { alert('Помилка DH: ' + data.error); return; }

        const B = BigInt(data.B);

        
        const K = modExp(B, a, p);

        
        const derivedKey = await deriveKeyFromSecret(K, currentAlgorithm);

        
        currentSessionId = data.sessionId;

        
        document.getElementById('res-A').textContent = A.toString();
        document.getElementById('res-B').textContent = B.toString();
        document.getElementById('res-K').textContent = K.toString();
        document.getElementById('res-derived-key').textContent = derivedKey;
        document.getElementById('key-bits-label').textContent =
            currentAlgorithm === 'sdes' ? '(10 біт, KDF)' : '(128 біт hex, KDF)';
        document.getElementById('dh-result').style.display = 'block';

        
        document.getElementById('key').value = derivedKey;
        document.getElementById('sdes-section').classList.remove('disabled');

    } catch (err) {
        console.error(err);
        alert('Критична помилка мережі або обчислень');
    } finally {
        btn.innerHTML = '<span class="btn-icon">⇌</span> Згенерувати спільний ключ';
        btn.disabled = false;
    }
});


function setMode(mode) {
    currentMode = mode;
    document.getElementById('btn-encrypt').classList.toggle('active', mode === 'encrypt');
    document.getElementById('btn-decrypt').classList.toggle('active', mode === 'decrypt');
    updateMessageFieldHint();
    document.getElementById('quick-result').style.display = 'none';
    document.getElementById('sdes-visualizer').style.display = 'none';
    document.getElementById('aes-visualizer').style.display = 'none';
}

document.getElementById('btn-encrypt').addEventListener('click', () => setMode('encrypt'));
document.getElementById('btn-decrypt').addEventListener('click', () => setMode('decrypt'));


document.getElementById('message').addEventListener('input', (e) => {
    if (currentAlgorithm === 'sdes') {
        e.target.value = e.target.value.replace(/[^01]/g, '');
    } else {
        
        e.target.value = e.target.value.replace(/[^0-9a-fA-F:]/g, '').toLowerCase();
    }
});


document.getElementById('btn-submit').addEventListener('click', async (e) => {
    e.preventDefault();

    const messageVal = document.getElementById('message').value.trim();
    const emailVal = document.getElementById('email').value.trim();

    
    if (currentAlgorithm === 'sdes' && !/^[01]{8}$/.test(messageVal)) {
        alert('S-DES: введіть рівно 8 біт (символи 0 та 1)'); return;
    }
    if (currentAlgorithm === 'aes') {
        if (messageVal.length === 0) {
            alert('AES: введіть повідомлення'); return;
        }
        if (currentMode === 'decrypt') {
            const parts = messageVal.split(':');
            if (parts.length !== 2 || parts[0].length % 2 !== 0 || parts[1].length % 2 !== 0) {
                alert('AES дешифрування: введіть у форматі IV:шифротекст (обидві частини hex, парна кількість символів)'); return;
            }
        } else {
            if (messageVal.length % 2 !== 0) {
                alert('AES: hex-рядок має містити парну кількість символів'); return;
            }
        }
    }
    if (!currentSessionId) {
        alert('Спочатку виконайте обмін ключами (Крок 1)'); return;
    }

    const btn = document.getElementById('btn-submit');
    btn.disabled = true;
    btn.textContent = '⌛ Обробка...';

    document.getElementById('quick-result').style.display = 'none';
    document.getElementById('sdes-visualizer').style.display = 'none';
    document.getElementById('aes-visualizer').style.display = 'none';

    try {
        
        const response = await fetch('/api/process', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: messageVal,
                sessionId: currentSessionId,
                email: emailVal,
                mode: currentMode,
                algorithm: currentAlgorithm,
            }),
        });
        const result = await response.json();

        if (!response.ok) { alert('Помилка сервера: ' + result.error); return; }

        document.getElementById('message').value = '';
        document.getElementById('email').value = '';

        currentStepsData = result.steps;

        
        const output = currentAlgorithm === 'sdes'
            ? currentStepsData.final
            : (currentStepsData.ivPlusEncrypted || currentStepsData.final);
        document.getElementById('res-output').textContent = output;

        if (currentAlgorithm === 'sdes') {
            document.getElementById('res-dec').textContent = parseInt(currentStepsData.final, 2);
            document.getElementById('res-dec-row').style.display = 'flex';
        } else {
            document.getElementById('res-dec-row').style.display = 'none';
        }

        document.getElementById('quick-result').style.display = 'block';
        document.getElementById('btn-show-steps').style.display = 'inline-flex';

    } catch (err) {
        console.error(err);
        alert('Критична помилка мережі');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">✉</span> <span id="btn-submit-label">${currentMode === 'encrypt' ? 'Зашифрувати та відправити' : 'Розшифрувати та відправити'}</span>`;
    }
});

function buildKeyGenHtml(key, kg) {
    return `<div>Ключ: <span class="micro-highlight">${key}</span></div>
            <div>P10: <span class="micro-highlight">${kg.p10}</span></div>
            <div>Зсув LS-1: L=${kg.shift1.L5}, R=${kg.shift1.R5} → <b>K1</b></div>
            <div>Зсув LS-2: L=${kg.shift2.L5}, R=${kg.shift2.R5} → <b>K2</b></div>`;
}
function buildIPHtml(ip) {
    return `<div>Таблиця IP до входу <span class="micro-highlight">${ip.before}</span></div>`;
}
function buildFkHtml(fk) {
    const d = fk.details;
    return `<div>Підключ: ${fk.keyUsed}</div>
            <div>XOR: ${d.epR} ⊕ ${d.subkey} = ${d.xored}</div>
            <div>S0: ${d.s0In} → ${d.s0Res}, S1: ${d.s1In} → ${d.s1Res}</div>
            <div>Нове L = L ⊕ P4 = ${d.newL}</div>`;
}

function showStep(stepId, valueId, value, microId, microHtml) {
    if (valueId) document.getElementById(valueId).textContent = value;
    if (microId && microHtml) document.getElementById(microId).innerHTML = microHtml;
    document.getElementById(stepId).classList.add('active');
}

document.getElementById('btn-show-steps').addEventListener('click', () => {
    const steps = currentStepsData;
    document.getElementById('btn-show-steps').style.display = 'none';

    if (currentAlgorithm === 'sdes') {
        document.getElementById('sdes-visualizer').style.display = 'block';
        document.querySelectorAll('#sdes-visualizer .step-block').forEach(el => el.classList.remove('active'));

        let delay = 200;
        setTimeout(() => showStep('step-keys', 'val-keys', `K1=${steps.K1}, K2=${steps.K2}`, 'micro-keys', buildKeyGenHtml(steps.key, steps.keyGen)), delay); delay += 1000;
        setTimeout(() => showStep('step-1', 'val-ip', steps.IP.after, 'micro-ip', buildIPHtml(steps.IP)), delay); delay += 800;
        setTimeout(() => showStep('step-2', 'val-fk1', steps.FK1.result, 'micro-fk1', buildFkHtml(steps.FK1)), delay); delay += 1200;
        setTimeout(() => showStep('step-3', 'val-sw', steps.SW.after, 'micro-sw', '<div>Міняємо місцями ліву та праву половини.</div>'), delay); delay += 800;
        setTimeout(() => showStep('step-4', 'val-fk2', steps.FK2.result, 'micro-fk2', buildFkHtml(steps.FK2)), delay); delay += 1200;
        setTimeout(() => showStep('step-5', 'val-final', steps.final, 'micro-final', '<div>Зворотна перестановка IP⁻¹.</div>'), delay);

    } else {
       
        const vis = document.getElementById('aes-visualizer');
        vis.style.display = 'block';
        const container = document.getElementById('aes-steps-container');
        container.innerHTML = '';
        steps.steps.forEach((step, i) => {
            setTimeout(() => {
                const div = document.createElement('div');
                div.className = 'aes-step';
                div.innerHTML = `<span class="aes-step-label">${step.label}</span>
                                 <span class="aes-step-value">${step.value}</span>`;
                container.appendChild(div);
            }, i * 300);
        });
    }
});


updateMessageFieldHint();