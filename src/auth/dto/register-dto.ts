import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class RegisterDto {

    @IsEmail()
    @IsString()
    @IsNotEmpty()
    email: string

    @IsString()
    userName: string

    @IsString()
    @IsNotEmpty()
    password: string


}