import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

interface JwtPayload {
  sub: string;
  email: string;
  iat?: number;
  exp?: number;
}

interface ValidatedUser {
  userId: string;
  email: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get<string>('JWT_SECRET'),
      ignoreExpiration: false,
    });
  }

  /**
   * Validate JWT payload and return user information
   * @param payload - Decoded JWT payload
   * @returns User information extracted from payload
   */
  validate(payload: JwtPayload): ValidatedUser {
    return {
      userId: payload.sub,
      email: payload.email,
    };
  }
}
