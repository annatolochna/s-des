let currentMode = 'encrypt';
const form = document.getElementById('crypto-form');
const btnEncrypt = document.getElementById('btn-encrypt');
const btnDecrypt = document.getElementById('btn-decrypt');
const messageInput = document.getElementById('message');
const keyInput = document.getElementById('key');
const btnShowSteps = document.getElementById('btn-show-steps');
let currentStepsData = null; 
if (btnEncrypt && btnDecrypt) {
    btnEncrypt.addEventListener('click', () => setMode('encrypt'));
    btnDecrypt.addEventListener('click', () => setMode('decrypt'));
}
function restrictToBinary(event) {
    event.target.value = event.target.value.replace(/[^01]/g, '');
}
if (messageInput && keyInput) {
    messageInput.addEventListener('input', restrictToBinary);
    keyInput.addEventListener('input', restrictToBinary);
}
function setMode(mode) {
    currentMode = mode;
    const isEncrypt = mode === 'encrypt';
    btnEncrypt.classList.toggle('active', isEncrypt);
    btnDecrypt.classList.toggle('active', !isEncrypt);
    document.getElementById('label-message').innerText = isEncrypt ? 'Відкритий текст (8 біт):' : 'Шифротекст (8 біт):';
    document.getElementById('btn-submit').innerText = isEncrypt ? 'Зашифрувати та відправити' : 'Розшифрувати та відправити';
    document.getElementById('quick-result').style.display = 'none';
    document.getElementById('visualizer').style.display = 'none';
}
function buildKeyGenHtml(key, kg) {
    return `
        <div>Початковий 10-бітний ключ: <span class="micro-highlight">${key}</span></div>
        <div>Перестановка <b>P10</b> (3,5,2,7,4,10,1,9,8,6): <span class="micro-highlight">${kg.p10}</span></div>
        <div>Розбиття: L0=<span class="micro-highlight">${kg.split1.L5}</span>, R0=<span class="micro-highlight">${kg.split1.R5}</span></div>
        <div>Зсув ліворуч (LS-1): L1=<span class="micro-highlight">${kg.shift1.L5}</span>, R1=<span class="micro-highlight">${kg.shift1.R5}</span></div>
        <div>Перестановка <b>P8</b> &rarr; <b>K1</b>.</div><br>
        <div>Зсув ліворуч (LS-2) від L1, R1: L2=<span class="micro-highlight">${kg.shift2.L5}</span>, R2=<span class="micro-highlight">${kg.shift2.R5}</span></div>
        <div>Перестановка <b>P8</b> &rarr; <b>K2</b>.</div>
    `;
}
function buildIPHtml(ip) { return `<div>Таблиця <b>IP</b> (2,6,3,1,4,8,5,7) до входу <span class="micro-highlight">${ip.before}</span>.</div>`; }
function buildFkHtml(fk) {
    const d = fk.details;
    return `
        <div>Підключ: <span class="micro-highlight">${fk.keyUsed}</span></div>
        <div>Розбиття: L = <span class="micro-highlight">${d.L}</span>, R = <span class="micro-highlight">${d.R}</span></div>
        <div>Розширення <b>E/P</b> для R: <span class="micro-highlight">${d.epR}</span></div>
        <div><b>XOR</b> з підключем: <span class="micro-highlight">${d.epR}</span> &oplus; <span class="micro-highlight">${d.subkey}</span> = <span class="micro-highlight">${d.xored}</span></div>
        <div>Матриця <b>S0</b> для <span class="micro-highlight">${d.s0In}</span> &rarr; <span class="micro-highlight">${d.s0Res}</span></div>
        <div>Матриця <b>S1</b> для <span class="micro-highlight">${d.s1In}</span> &rarr; <span class="micro-highlight">${d.s1Res}</span></div>
        <div>Перестановка <b>P4</b>: <span class="micro-highlight">${d.p4Res}</span></div>
        <div>Остаточний <b>XOR</b>: L &oplus; P4 = <span class="micro-highlight">${d.newL}</span></div>
    `;
}
function buildSWHtml(sw) { return `<div>Міняємо місцями L та R.</div>`; }
function buildFinalIPHtml(inv) { return `<div>Зворотна перестановка <b>IP⁻¹</b> (4,1,3,5,7,2,8,6).</div>`; }
function showStep(stepId, valueId, value, microHtmlContainerId, microHtml) {
    const stepBlock = document.getElementById(stepId);
    if (valueId && value) document.getElementById(valueId).innerText = value;
    if (microHtmlContainerId && microHtml) document.getElementById(microHtmlContainerId).innerHTML = microHtml;
    stepBlock.classList.add('active');
}
if (btnShowSteps) {
    btnShowSteps.addEventListener('click', () => {
        if (!currentStepsData) return;
        btnShowSteps.style.display = 'none'; 
        const vis = document.getElementById('visualizer');
        vis.style.display = 'block';
        document.querySelectorAll('.step-block').forEach(el => el.classList.remove('active'));
        const steps = currentStepsData;
        let delay = 300; 
        setTimeout(() => showStep('step-keys', 'val-keys', `K1 = ${steps.K1}, K2 = ${steps.K2}`, 'micro-keys', buildKeyGenHtml(steps.key, steps.keyGen)), delay);
        delay += 1200;
        setTimeout(() => showStep('step-1', 'val-ip', steps.IP.after, 'micro-ip', buildIPHtml(steps.IP)), delay);
        delay += 1000;
        setTimeout(() => showStep('step-2', 'val-fk1', steps.FK1.result, 'micro-fk1', buildFkHtml(steps.FK1)), delay);
        delay += 2500;
        setTimeout(() => showStep('step-3', 'val-sw', steps.SW.after, 'micro-sw', buildSWHtml(steps.SW)), delay);
        delay += 1000;
        setTimeout(() => showStep('step-4', 'val-fk2', steps.FK2.result, 'micro-fk2', buildFkHtml(steps.FK2)), delay);
        delay += 2500;
        setTimeout(() => {
            showStep('step-5', 'val-final', steps.final, 'micro-final', buildFinalIPHtml(steps.IP_INV));
        }, delay);
    });
}
if (form) {
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        document.getElementById('quick-result').style.display = 'none';
        document.getElementById('visualizer').style.display = 'none';
        const messageVal = messageInput.value.trim();
        const keyVal = keyInput.value.trim();
        const emailVal = document.getElementById('email').value.trim();
        if (!/^[01]{8}$/.test(messageVal)) { alert("Помилка: Повідомлення має містити 8 біт."); return; }
        if (!/^[01]{10}$/.test(keyVal)) { alert("Помилка: Ключ має містити 10 біт."); return; }
        const data = { message: messageVal, key: keyVal, email: emailVal, mode: currentMode };
        try {
            const response = await fetch('/api/process', { 
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (response.ok) {
                form.reset(); 
                currentStepsData = result.steps;
                const finalBinary = currentStepsData.final;
                const finalDecimal = parseInt(finalBinary, 2);
                document.getElementById('res-bin').innerText = finalBinary;
                document.getElementById('res-dec').innerText = finalDecimal;
                const quickPanel = document.getElementById('quick-result');
                quickPanel.style.display = 'block';
                btnShowSteps.style.display = 'inline-block'; 
            } else {
                alert(`Помилка сервера: ${result.error}`);
            }
        } catch (error) {
            console.error('Помилка мережі:', error);
            alert('Виникла критична помилка мережі. Перевірте, чи запущено сервер.');
        }
    });
}