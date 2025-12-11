import { Body, Controller, Post, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private auth: AuthService) { }
    
    @Post('register')
    register(@Body() body) {
        return this.auth.register(body);
    }

    @Post('login')
    login(@Body() body) {
        return this.auth.login(body.email, body.password);
    }

    @UseGuards(JwtAuthGuard)
    @Post('profile')
    profile(@Request() req) {
        return req.user;
    }
}
