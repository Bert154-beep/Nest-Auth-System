import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { RegisterDto } from './dto/register-dto';
import { AuthService } from './auth.service';
import { loginDto } from './dto/login-dto';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { sendOtpDto } from './dto/send-otp-dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('signup')
    signup(@Body() dto: RegisterDto){
        return this.authService.signup(dto)
    }

    @Post('signin')
    signin(@Body() dto: loginDto){
        return this.authService.signin(dto)
    }

    @Post('sendOtp')
    sendOtp(@Body() dto: sendOtpDto){
        return this.authService.sendOtp(dto)
    }

    @Post('resetPassword')
    resetPassword(@Body() dto: ResetPasswordDto){
        return this.authService.resetPassword(dto)
    }

}
