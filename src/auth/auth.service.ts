import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';

export interface RegisterDto {
  email: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
}

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = 10;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  /**
   * Register a new user with email and password
   * @param data - Registration data containing email and password
   * @returns User object without password hash
   * @throws ConflictException if email already exists
   * @throws BadRequestException if input is invalid
   */
  async register(data: RegisterDto) {
    this.validateInput(data);

    const hashedPassword = await bcrypt.hash(
      data.password,
      this.SALT_ROUNDS,
    );

    try {
      const user = await this.prisma.user.create({
        data: {
          email: data.email.toLowerCase(),
          password: hashedPassword,
        },
      });

      // Return user without password hash
      return this.sanitizeUser(user);
    } catch (error) {
      this.handlePrismaError(error);
    }
  }

  /**
   * Validate user credentials
   * @param email - User email
   * @param password - User password
   * @returns User object if credentials are valid, null otherwise
   */
  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    return isPasswordValid ? user : null;
  }

  /**
   * Authenticate user and return JWT token
   * @param email - User email
   * @param password - User password
   * @returns Object containing access token
   * @throws UnauthorizedException if credentials are invalid
   */
  async login(email: string, password: string): Promise<AuthResponse> {
    const user = await this.validateUser(email, password);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const payload = { sub: user.id, email: user.email };
    const access_token = this.jwt.sign(payload);

    return { access_token };
  }

  /**
   * Remove sensitive fields from user object
   * @param user - User object with password
   * @returns User object without password
   */
  private sanitizeUser(user: any) {
    const { password, ...safeUser } = user;
    return safeUser;
  }

  /**
   * Validate user input
   * @param data - User registration data
   * @throws BadRequestException if validation fails
   */
  private validateInput(data: RegisterDto): void {
    if (!data.email || !data.password) {
      throw new BadRequestException('Email and password are required');
    }

    if (data.password.length < 6) {
      throw new BadRequestException('Password must be at least 6 characters');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      throw new BadRequestException('Invalid email format');
    }
  }

  /**
   * Handle Prisma-specific errors
   * @param error - Error from Prisma
   * @throws ConflictException for unique constraint violations
   * @throws Error for other errors
   */
  private handlePrismaError(error: any): void {
    if (error.code === 'P2002') {
      throw new ConflictException(
        'Email is already registered. Please use a different email.',
      );
    }
    throw error;
  }
}
