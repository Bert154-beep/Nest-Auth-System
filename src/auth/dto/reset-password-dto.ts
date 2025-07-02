import { IsEmail, IsOptional, IsString, MinLength } from "class-validator";

export class ResetPasswordDto{
    @IsString()
    otp: string


    @IsString()
    @MinLength(6)
    newPassword: string
}