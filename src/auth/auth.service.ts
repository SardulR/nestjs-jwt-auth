import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
    ) { }
    
    //REGISTER USER
    async register(data: { email: string; password: string }) {
    const hashed = await bcrypt.hash(data.password, 10);

    try {
        const user = await this.prisma.user.create({
        data: {
            email: data.email,
            password: hashed,
        },
        });

        // Do NOT return the password hash
        const { password, ...safeUser } = user;
        return safeUser;
    } catch (err) {
        // Prisma unique constraint error
        if (err.code === 'P2002') {
        throw new ConflictException('Email is already registered');
        }
        throw err;
    }
    }

    // VALIDATE USER (EMAIL + PASSWORD)
    async validateUser(email: string, password: string) {
        const user = await this.prisma.user.findUnique({ where: { email } });
        if (!user) return null;

        const isMatch = await bcrypt.compare(password, user.password);
        return isMatch ? user : null;
    }

    // LOGIN + RETURN JWT
    async login(email: string, password: string) {
        const user = await this.validateUser(email, password);
        if (!user) throw new UnauthorizedException('Invalid credentials');

        const payload = { sub: user.id, email: user.email };
        const token = this.jwt.sign(payload);

        return { access_token: token };
    }

}
