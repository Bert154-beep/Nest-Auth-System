import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './Entities/user.entity';
import { JwtStrategy } from './strategy/jwt.strategy';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { MailerService } from 'src/config/mailer.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule.register({})

],
  providers: [AuthService, JwtStrategy, JwtService, MailerService],
  controllers: [AuthController]
})
export class AuthModule {}
