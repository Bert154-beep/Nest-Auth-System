import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, ExtractJwt } from "passport-jwt";
import { Repository } from "typeorm";
import { User } from "../Entities/user.entity";
import { InjectRepository } from "@nestjs/typeorm";

@Injectable()
export class JwtStrategy extends PassportStrategy(
    Strategy,
    'jwt'
){
    constructor(private config: ConfigService, @InjectRepository(User) private userRepo: Repository<User>){
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.get<string>('JWT_SECRET')!
        })
    }

    async validate(payload: {sub: number, email: string}){
        const user = await this.userRepo.findOne({
            where: {id: payload.sub},
            select: {
                id: true,
                email: true,
                userName: true
            }
        })

        return user
    }
}