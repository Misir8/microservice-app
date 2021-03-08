import {createTransport} from "nodemailer";
import {config} from "dotenv";

config();
const {NODEMAILER_MAIL, NODEMAILER_PASSWORD, NODEMAILER_HOST, NODEMAILER_PORT, NODEMAILER_SECURE} = process.env;

const transporter = createTransport({
    host: NODEMAILER_HOST,
    port: Number(NODEMAILER_PORT),
    secure: NODEMAILER_SECURE as unknown as boolean, // true for 465, false for other ports
    auth: {
        user: NODEMAILER_MAIL, // generated ethereal user
        pass: NODEMAILER_PASSWORD, // generated ethereal password
    },
});

export const sendEmail = async (email: string, subject: string, text: string, html: string): Promise<string> => {
    const info = await transporter.sendMail({
        from: `"Misir Asgarov 👻" ${NODEMAILER_MAIL}`, // sender address
        to: email, // list of receivers
        subject, // Subject line
        text, // plain text body
        html, // html body
    });
    return info.messageId;
}
