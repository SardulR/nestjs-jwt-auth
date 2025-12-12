# NestJS JWT Authentication API

A production-ready JWT authentication backend built with NestJS, Prisma ORM, and PostgreSQL.

## 📋 Features

- ✅ User registration with email validation
- ✅ User login with JWT token generation
- ✅ Protected routes with JWT authentication guard
- ✅ Password hashing with bcrypt (10 salt rounds)
- ✅ Comprehensive error handling
- ✅ Input validation
- ✅ Professional TypeScript types
- ✅ Full test coverage with Jest
- ✅ Prisma ORM for database management

## 🛠️ Tech Stack

- **Runtime**: Node.js (v24+)
- **Framework**: NestJS 11.x
- **Database**: PostgreSQL
- **ORM**: Prisma 5.x
- **Authentication**: Passport.js + JWT
- **Password Hashing**: bcrypt
- **Testing**: Jest
- **Language**: TypeScript

## 📦 Prerequisites

- Node.js v18 or higher
- npm or yarn
- PostgreSQL database
- Git

## 🚀 Installation

1. **Clone the repository**

```bash
git clone <repository-url>
cd nestjs-jwt-auth
```

2. **Install dependencies**

```bash
npm install
```

3. **Configure environment variables**

Create a `.env` file in the root directory:

```env
# Database Configuration
DATABASE_URL="postgresql://user:password@localhost:5432/nestjs_jwt_auth?schema=public"

# JWT Configuration
JWT_SECRET="your-super-secret-key-change-this-in-production"
JWT_EXPIRES_IN="1h"
```

4. **Generate Prisma Client**

```bash
npx prisma generate
```

5. **Run database migrations (optional)**

```bash
npx prisma db push
```

## 📂 Project Structure

```
src/
├── auth/                          # Authentication module
│   ├── auth.controller.ts         # Auth routes
│   ├── auth.service.ts            # Auth business logic
│   ├── auth.module.ts             # Auth module definition
│   ├── jwt.strategy.ts            # JWT Passport strategy
│   └── jwt-auth.guard.ts          # Route protection guard
├── prisma/                        # Database module
│   ├── prisma.service.ts          # Prisma client wrapper
│   └── prisma.module.ts           # Prisma module definition
├── app.controller.ts              # Root controller
├── app.service.ts                 # Root service
├── app.module.ts                  # Root module
└── main.ts                        # Application entry point

prisma/
└── schema.prisma                  # Database schema

test/
└── jest-e2e.json                  # E2E test configuration
```

## 🔌 API Endpoints

### 1. Register User

**POST** `/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response (201 Created):**
```json
{
  "id": "uuid-here",
  "email": "user@example.com",
  "createdAt": "2025-12-12T13:00:00Z"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid email format or password too short
- `409 Conflict` - Email already registered

### 2. Login

**POST** `/auth/login`

Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Responses:**
- `401 Unauthorized` - Invalid email or password

### 3. Get User Profile

**POST** `/auth/profile`

Retrieve authenticated user's profile information.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "userId": "uuid-here",
  "email": "user@example.com"
}
```

**Error Responses:**
- `401 Unauthorized` - Missing or invalid token

## 🧪 Testing

### Run all tests

```bash
npm run test
```

### Run tests in watch mode

```bash
npm run test:watch
```

### Run tests with coverage report

```bash
npm run test:cov
```

### Run E2E tests

```bash
npm run test:e2e
```

## 🏃 Running the Application

### Development mode (with hot reload)

```bash
npm run start:dev
```

The server will be available at `http://localhost:3000`

### Production mode

First build the application:

```bash
npm run build
```

Then run the compiled code:

```bash
npm run start:prod
```

## 🔒 Security Features

- **Password Hashing**: Passwords are hashed using bcrypt with 10 salt rounds
- **JWT Tokens**: Secure token-based authentication
- **Input Validation**: Email format and password length validation
- **Protected Routes**: JWT guard on sensitive endpoints
- **Error Handling**: Sanitized error messages to prevent information leakage
- **CORS**: Configure as needed in production

## 📝 Input Validation Rules

### Registration

- **Email**: Must be valid email format (user@domain.com)
- **Password**: Minimum 6 characters

### Login

- **Email**: Valid email format
- **Password**: Any non-empty string

## 🗄️ Database Schema

### User Model

```prisma
model User {
  id        String   @id @default(uuid())
  email     String   @unique
  password  String
  createdAt DateTime @default(now())
}
```

## 🔧 Configuration

### JWT Configuration

Edit `src/auth/auth.module.ts` to modify JWT settings:

```typescript
JwtModule.registerAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    secret: config.get<string>('JWT_SECRET'),
    signOptions: { expiresIn: '1h' }, // Modify token expiration here
  }),
})
```

### Password Hashing

Modify salt rounds in `src/auth/auth.service.ts`:

```typescript
private readonly SALT_ROUNDS = 10; // Increase for more security (slower)
```

## 📊 Database Commands

```bash
# Generate Prisma Client
npx prisma generate

# View database in Prisma Studio
npx prisma studio

# Create a migration
npx prisma migrate dev --name migration_name

# Apply migrations
npx prisma db push

# Reset database (removes all data)
npx prisma db push --force-reset
```

## 🐛 Troubleshooting

### Port 3000 already in use

```bash
# Windows - Find and kill process on port 3000
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# macOS/Linux
lsof -i :3000
kill -9 <PID>
```

### Prisma Client not initialized

```bash
npx prisma generate
```

### Database connection failed

Check your `DATABASE_URL` in `.env` file and ensure PostgreSQL is running.

## 📚 Documentation

- [NestJS Documentation](https://docs.nestjs.com)
- [Prisma Documentation](https://www.prisma.io/docs)
- [JWT.io](https://jwt.io)
- [Passport.js Documentation](http://www.passportjs.org/)

## 🤝 Contributing

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Commit your changes (`git commit -m 'Add amazing feature'`)
3. Push to the branch (`git push origin feature/amazing-feature`)
4. Open a Pull Request

## 📄 License

This project is licensed under the UNLICENSED license.

## ✨ Next Steps

- [ ] Add email verification on registration
- [ ] Implement password reset functionality
- [ ] Add user profile update endpoint
- [ ] Implement refresh token mechanism
- [ ] Add rate limiting
- [ ] Implement API documentation with Swagger/OpenAPI
- [ ] Add role-based access control (RBAC)
- [ ] Implement two-factor authentication (2FA)

## 📞 Support

For issues and questions, please create an issue in the repository or contact the development team.

---

**Last Updated**: December 12, 2025
**Node Version**: v24.11.1
**NestJS Version**: 11.x
**Prisma Version**: 5.22.0
