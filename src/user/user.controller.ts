import { Controller, Get, UseGuards } from '@nestjs/common';
import { getUser } from 'src/auth/decorators/get-user-decorator';
import { User } from 'src/auth/Entities/user.entity';
import { JWTGuard } from 'src/auth/guards/jwt.guard';

@UseGuards(JWTGuard)
@Controller('user')
export class UserController {
    @Get('getUser')
    getUser(@getUser() user: User){
        return user;
    }
}
