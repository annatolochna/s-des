require('dotenv').config();
const Koa = require('koa');
const serve = require('koa-static');
const bodyParser = require('koa-bodyparser');
const nodemailer = require('nodemailer');
const path = require('path');
const encryptSDES = require('./sdes');
const app = new Koa();
app.use(bodyParser());
app.use(async (ctx, next) => {
    if (ctx.method === 'POST' && ctx.path === '/api/process') {
        const { message, key, email, mode } = ctx.request.body;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const bits8Regex = /^[01]{8}$/;
        const bits10Regex = /^[01]{10}$/; 
        if (!message || !key || !email || !mode) {
            ctx.status = 400;
            ctx.body = { error: "Всі поля обов'язкові для заповнення" };
            return;
        }
        if (!emailRegex.test(email)) {
            ctx.status = 400;
            ctx.body = { error: "Некоректний формат email" };
            return;
        }
        if (!bits8Regex.test(message)) {
            ctx.status = 400;
            ctx.body = { error: "Повідомлення має містити рівно 8 біт" };
            return;
        }
        if (!bits10Regex.test(key)) {
            ctx.status = 400;
            ctx.body = { error: "Ключ має містити рівно 10 біт" };
            return;
        }
        try {
            const processSteps = encryptSDES(message, key, mode);
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });
            const isEncrypt = mode === 'encrypt';
            const emailSubject = isEncrypt 
                ? 'Зашифроване повідомлення (S-DES)' 
                : 'Розшифроване повідомлення (S-DES)';
            const emailText = isEncrypt 
                ? `Вам надійшло таємне повідомлення!\n\nЗашифрований текст: ${processSteps.final}\n\nВикористайте свій секретний 10-бітний ключ на нашому сервісі, щоб розшифрувати його.`
                : `Ваше повідомлення було успішно розшифровано.\n\nОригінальний текст: ${processSteps.final}\n\nДякуємо за використання сервісу!`;
            const mailOptions = {
                from: process.env.SMTP_USER,
                to: email,
                subject: emailSubject,
                text: emailText
            };
            await transporter.sendMail(mailOptions);
            ctx.status = 200;
            ctx.body = { success: true, steps: processSteps };
        } catch (error) {
            console.error("Помилка:", error);
            ctx.status = 500;
            ctx.body = { error: "Помилка сервера при обробці або відправленні листа" };
        }
    } else {
        await next();
    }
});
app.use(serve(path.join(__dirname, 'public')));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер успішно запущено! Відкрий: http://localhost:${PORT}`);
});