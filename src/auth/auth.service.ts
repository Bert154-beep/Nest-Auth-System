import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RegisterDto } from './dto/register-dto';
import { loginDto } from './dto/login-dto';
import { User } from './Entities/user.entity';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { MailerService } from 'src/config/mailer.service';
import { randomInt } from 'crypto';
import { sendOtpDto } from './dto/send-otp-dto';

@Injectable()
export class AuthService {

    constructor(@InjectRepository(User) private UsersRepo: Repository<User>, private jwt: JwtService, private config: ConfigService, private mailerService: MailerService) { }

    async signup(dto: RegisterDto) {
        try {
            const { email, userName, password } = dto

            const existingUser = await this.UsersRepo.findOneBy({ email })

            if (existingUser) {
                throw new ForbiddenException('User Already Exists!')
            }

            const hashedPassword = await bcrypt.hash(password, 10)

            const newUser = this.UsersRepo.create({
                email,
                userName,
                password: hashedPassword
            })

            await this.UsersRepo.save(newUser)


            return {
                message: "User Created!"
            }


        } catch (error) {
            console.error('Signup error:', error);
            throw new ForbiddenException('Signup failed.');
        }
    }

    async signin(dto: loginDto) {
        try {
            const { email, password } = dto

            const user = await this.UsersRepo.findOneBy({ email })

            if (!user) {
                throw new ForbiddenException("User Does Not Exists!")
            }

            const isMatch = await bcrypt.compare(password, user.password)

            if (!isMatch) {
                throw new ForbiddenException("Invalid Credentials!")
            }

            const tokens = await this.signtoken(user.id, user.email)
            await this.updateRefreshToken(user.id, tokens.refresh_token)

            return {
                message: "User Signed In!",
                tokens
            }


        } catch (error) {
            console.log("Sign In Error: ", error)
            throw new BadRequestException("Sign In Failed!")
        }
    }

    async signtoken(
        userId: number,
        email: string
    ): Promise<{ access_token: string, refresh_token: string }> {
        const payload = {
            sub: userId,
            email
        }

        const secret = this.config.get('JWT_SECRET')!

        const token = await this.jwt.signAsync(
            payload,
            {
                expiresIn: '15m',
                secret: secret
            }
        )

        const refreshToken = await this.jwt.signAsync(
            payload,
            {
                expiresIn: '7d',
                secret: secret
            }
        )

        return {
            access_token: token,
            refresh_token: refreshToken
        }
    }

    async updateRefreshToken(userId: number, refreshToken: string) {
        const hashedToken = await bcrypt.hash(refreshToken, 10)
        await this.UsersRepo.update(userId, { hashedRefreshToken: hashedToken })
    }

    async sendOtp(dto: sendOtpDto) {
        try {
            const { email } = dto
            const user = await this.UsersRepo.findOneBy({ email })

            if (!user) {
                throw new NotFoundException("Invalid Credentials!")
            }

            const otp = randomInt(100000, 999999).toString()
            const expires = new Date(Date.now() + 5 * 60 * 1000)

            user.otp = otp
            user.otpExpires = expires

            await this.UsersRepo.save(user)

            await this.mailerService.sendOtp(email, otp)

            return {
                message: "OTP SENT!"
            }

        } catch (error) {
            console.log("Send-OTP Error: ", error)
            throw new BadRequestException("Send OTP Failed!")
        }
    }

    async resetPassword(dto: ResetPasswordDto) {
        try {
            const { otp, newPassword } = dto

            const user = await this.UsersRepo.findOne({
                where: { otp }
            })

            if (!user || !user.otpExpires || new Date() > user.otpExpires) {
                throw new BadRequestException('Invalid Or Expired OTP')
            }

            if (user.password === newPassword) {
                return {
                    error: "Do not Repeat Your Old Password!"
                }
            }
            user.password = await bcrypt.hash(newPassword, 10)
            user.otp = null
            user.otpExpires = null
            await this.UsersRepo.save(user)

            return {
                message: "Password Reset Successful!"
            }
        } catch (error) {
            console.log('Reset Password Error: ', error)
            throw new BadRequestException("Reset Password Failed!")
        }
    }
}

