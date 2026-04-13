require('dotenv').config();
const Koa = require('koa');
const serve = require('koa-static');
const bodyParser = require('koa-bodyparser');
const nodemailer = require('nodemailer');
const path = require('path');
const encryptSDES = require('./sdes');
const { processAES } = require('./aes');
const { modExp, secureRandomBigInt, deriveKey } = require('./dh');

const app = new Koa();
app.use(bodyParser());


const dhSessions = new Map();

function cleanupOldSessions() {
    const now = Date.now();
    for (const [id, session] of dhSessions) {
        if (now - session.createdAt > 5 * 60 * 1000) dhSessions.delete(id);
    }
}


app.use(async (ctx, next) => {
    ctx.set('X-Content-Type-Options', 'nosniff');
    ctx.set('X-Frame-Options', 'DENY');
    await next();
});


app.use(async (ctx, next) => {
    if (ctx.method !== 'POST' || ctx.path !== '/api/dh-exchange') return next();

    const { p, g, A, algorithm } = ctx.request.body;

    if (!p || !g || !A || !algorithm) {
        ctx.status = 400;
        ctx.body = { error: "Відсутні обов'язкові параметри DH" };
        return;
    }
    if (!['sdes', 'aes'].includes(algorithm)) {
        ctx.status = 400;
        ctx.body = { error: 'Невідомий алгоритм' };
        return;
    }

    try {
        const pBig = BigInt(p);
        const gBig = BigInt(g);
        const ABig = BigInt(A);

        if (ABig < 2n || ABig >= pBig - 1n) {
            ctx.status = 400;
            ctx.body = { error: 'Некоректне значення публічного ключа A' };
            return;
        }

        
        const b = secureRandomBigInt(pBig - 1n);

        const B = modExp(gBig, b, pBig);
        const K = modExp(ABig, b, pBig);

        
        const keyBits = algorithm === 'sdes' ? 10 : 128;
        const derivedKey = deriveKey(K, keyBits);

        cleanupOldSessions();
        const sessionId = require('crypto').randomBytes(16).toString('hex');
        dhSessions.set(sessionId, {
            derivedKey,
            algorithm,
            createdAt: Date.now(),
        });

        
        ctx.status = 200;
        ctx.body = {
            B: B.toString(),
            sessionId,
        };
    } catch (error) {
        console.error('DH error:', error);
        ctx.status = 500;
        ctx.body = { error: 'Помилка при обчисленні DH на сервері' };
    }
});


app.use(async (ctx, next) => {
    if (ctx.method !== 'POST' || ctx.path !== '/api/process') return next();

    const { message, sessionId, email, mode, algorithm } = ctx.request.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!message || !sessionId || !email || !mode || !algorithm) {
        ctx.status = 400; ctx.body = { error: "Всі поля обов'язкові" }; return;
    }
    if (!emailRegex.test(email)) {
        ctx.status = 400; ctx.body = { error: 'Некоректний формат email' }; return;
    }
    if (!['sdes', 'aes'].includes(algorithm)) {
        ctx.status = 400; ctx.body = { error: 'Невідомий алгоритм' }; return;
    }
    if (!['encrypt', 'decrypt'].includes(mode)) {
        ctx.status = 400; ctx.body = { error: 'Невідомий режим' }; return;
    }

    
    const session = dhSessions.get(sessionId);
    if (!session) {
        ctx.status = 401;
        ctx.body = { error: 'Сесія не знайдена або застаріла. Повторіть обмін ключами.' };
        return;
    }
    if (session.algorithm !== algorithm) {
        ctx.status = 400;
        ctx.body = { error: 'Алгоритм не збігається з поточною сесією' };
        return;
    }

    if (algorithm === 'sdes' && !/^[01]{8}$/.test(message)) {
        ctx.status = 400; ctx.body = { error: 'S-DES: повідомлення має бути рівно 8 біт (0/1)' }; return;
    }

    try {
        let processSteps;

        if (algorithm === 'sdes') {
            processSteps = encryptSDES(message, session.derivedKey, mode);
            processSteps.algorithm = 'S-DES';
        } else {
            processSteps = processAES(message, session.derivedKey, mode);
        }

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });

        const isEncrypt = mode === 'encrypt';
        const algoLabel = algorithm === 'sdes' ? 'S-DES' : 'AES-128-CBC';
        const emailSubject = isEncrypt
            ? `Зашифроване повідомлення (${algoLabel})`
            : `Розшифроване повідомлення (${algoLabel})`;
        const resultText = algorithm === 'sdes'
            ? processSteps.final
            : (processSteps.ivPlusEncrypted || processSteps.final);
        const emailText = isEncrypt
            ? `Вам надійшло таємне повідомлення!\n\nАлгоритм: ${algoLabel}\nРезультат: ${resultText}`
            : `Ваше повідомлення розшифровано.\n\nАлгоритм: ${algoLabel}\nРезультат (hex): ${processSteps.final}`;

        await transporter.sendMail({
            from: process.env.SMTP_USER, to: email, subject: emailSubject, text: emailText,
        });

        ctx.status = 200;
        ctx.body = { success: true, steps: processSteps };
    } catch (error) {
        console.error('Process error:', error.message);
        ctx.status = 500;
        ctx.body = { error: `Помилка: ${error.message}` };
    }
});

app.use(serve(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Гібридний сервер запущено! http://localhost:${PORT}`);
});