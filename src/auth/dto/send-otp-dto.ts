import { IsEmail, IsNotEmpty } from "class-validator";

export class sendOtpDto{
    @IsEmail()
    @IsNotEmpty()
    email: string
}