import { Injectable } from "@nestjs/common";
import * as nodemailer from 'nodemailer'
import * as dotenv from 'dotenv'
dotenv.config()

@Injectable()
export class MailerService{
    private transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.E_PASS
        }
    })


    async sendOtp(email: string, otp: string){
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP Code is ${otp}`
        };

        return this.transporter.sendMail(mailOptions)
    }
}