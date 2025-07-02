import {TypeOrmModuleOptions} from '@nestjs/typeorm'
import * as dotenv from 'dotenv'
import { User } from 'src/auth/Entities/user.entity'
dotenv.config()

export const TypeOrmConfig: TypeOrmModuleOptions = {
    type: 'postgres',
    host: process.env.DB_HOST,
    port: 5432,
    username: process.env.USER_NAME,
    password: process.env.PASSWORD,
    database: process.env.DB_NAME,
    entities: [User],
    synchronize: true
}