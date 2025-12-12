import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * JWT Authentication Guard
 * Validates JWT tokens from request headers
 * Protects routes that require authentication
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
