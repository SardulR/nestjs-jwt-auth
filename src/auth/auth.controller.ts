import {
  Body,
  Controller,
  Post,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService, AuthResponse } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

interface RegisterRequest {
  email: string;
  password: string;
}

interface LoginRequest {
  email: string;
  password: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Register a new user
   * @param body - Registration credentials
   * @returns Newly created user object
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() body: RegisterRequest) {
    return this.authService.register(body);
  }

  /**
   * Login user and return JWT token
   * @param body - Login credentials
   * @returns Object containing JWT access token
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: LoginRequest): Promise<AuthResponse> {
    return this.authService.login(body.email, body.password);
  }

  /**
   * Get authenticated user profile
   * @param req - Express request object with user data
   * @returns User profile information
   */
  @UseGuards(JwtAuthGuard)
  @Post('profile')
  async profile(@Request() req: any) {
    return req.user;
  }
}
