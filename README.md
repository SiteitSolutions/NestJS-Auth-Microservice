# NestJS Auth Microservice

An **enterprise-grade authentication and authorization microservice** built with **NestJS**, **PassportJS**, and **MongoDB**. This microservice provides comprehensive user authentication, session management, role-based access control (RBAC), and advanced security features.

---

## 🚀 **Key Features**

### Authentication & Authorization
- **Local authentication** with email/password
- **JWT-based access and refresh tokens** with automatic rotation
- **Session management** with device tracking and multi-device support
- **Role-Based Access Control (RBAC)** with decorators
- **Account security** with lockout protection and login attempt tracking

### Security Features
- **Advanced session validation** - tokens are invalidated when sessions are revoked
- **Token blacklisting** with Redis for instant invalidation
- **Refresh token rotation** for enhanced security
- **Rate limiting** and DDoS protection
- **Security headers** with Helmet.js
- **Input validation** and sanitization
- **Password complexity** requirements with bcrypt hashing

### Session Management
- **Multi-device session tracking** with device information
- **Session revocation** - logout from all devices or specific sessions
- **Session analytics** - last used timestamps and device details
- **Automatic cleanup** of expired sessions

### Developer Experience
- **Comprehensive Swagger documentation** (development only)
- **TypeScript interfaces** for type safety
- **Detailed logging** with Winston
- **Docker support** with multi-service setup
- **Environment-based configuration**

---

## 📚 **Documentation**

- **[Security Guide](docs/SECURITY.md)** - Security features and best practices
- **[Session Management](docs/SESSION_MANAGEMENT.md)** - Session handling and device management
- **[API Consumer Guide](docs/API_CONSUMER_GUIDE.md)** - How to integrate with other services
- **[Orchestration Usage](docs/ORCHESTRATION_USAGE_GUIDE.md)** - Using with orchestration APIs
- **[Practical Examples](docs/PRACTICAL_EXAMPLES.md)** - Real-world usage examples

---

## 🛠️ **Technologies**

- **NestJS 10+** - Modern Node.js framework
- **PassportJS** - Authentication middleware
- **JWT** - Secure token-based authentication
- **MongoDB** - Document database with Mongoose ODM
- **Redis** - Caching and session management
- **Winston** - Structured logging
- **Helmet** - Security headers
- **class-validator** - Input validation

---

## 🚦 **Getting Started**

### **Prerequisites**

- [Node.js](https://nodejs.org/) v18+
- [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/)
- [Git](https://git-scm.com/)

### **Quick Start**

```bash
# 1. Clone the repository
git clone <repository-url>
cd nestjs-auth-microservice

# 2. Copy environment template
cp .env.example .env

# 3. Edit environment variables (see below)
nano .env

# 4. Start all services with Docker
docker-compose up -d --build

# 5. Verify services are running
curl http://localhost:3000/auth/health
```

The microservice will be available at `http://localhost:3000` with:
- **API Documentation**: `http://localhost:3000/api` (development only)
- **MongoDB**: `localhost:27017`
- **Redis**: `localhost:6379`

---

## ⚙️ **Environment Configuration**

Create a `.env` file based on `.env.example`:

```bash
# Database Configuration
MONGO_URI=mongodb://root:password@localhost:27017/nestdb?authSource=admin

# Redis Configuration (for caching and token blacklisting)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_TTL=900000  # 15 minutes in milliseconds

# JWT Configuration - CHANGE THESE IN PRODUCTION!
JWT_SECRET=your-super-secret-jwt-key-here-make-it-long-and-random
REFRESH_TOKEN_SECRET=your-super-secret-refresh-token-key-here-make-it-different-from-jwt

# Application Configuration
PORT=3000
NODE_ENV=development

# Security Configuration
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_TIME=900000  # 15 minutes in milliseconds

# Rate Limiting
RATE_LIMIT_TTL=60000  # 1 minute
RATE_LIMIT_MAX=100    # requests per minute

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Session Security
REQUIRE_SESSION_ID=false  # Set to true for stricter session validation
```

---

## 🔌 **API Endpoints**

### Authentication Endpoints

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/auth/login` | User login with email/password | 3/min |
| `POST` | `/auth/register` | Create new user account | 5/min |
| `POST` | `/auth/logout` | Logout current session | - |
| `POST` | `/auth/refresh` | Refresh access token | - |
| `GET` | `/auth/profile` | Get current user profile | - |

### Session Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/auth/sessions` | List all user sessions | ✅ |
| `POST` | `/auth/logout-all` | Logout from all devices | ✅ |
| `POST` | `/auth/logout-others` | Logout from other devices | ✅ |
| `POST` | `/auth/revoke-session` | Revoke specific session | ✅ |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `PATCH` | `/users/:id` | Update user profile | ✅ |
| `DELETE` | `/users/:id` | Soft delete user | ✅ (Admin) |

---

## 📖 **Usage Examples**

### **User Registration**

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "givenName": "John",
    "familyName": "Doe"
  }'
```

**Response:**
```json
{
  "_id": "65a1b2c3d4e5f6789abc0123",
  "email": "user@example.com",
  "givenName": "John",
  "familyName": "Doe",
  "roles": ["USER"],
  "isActive": true,
  "createdAt": "2023-12-01T10:30:00.000Z"
}
```

### **User Login with Device Tracking**

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: mobile-app-v1.0" \
  -H "User-Agent: MyApp/1.0 (iOS 15.0; iPhone 13)" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### **Access Protected Resource**

```bash
curl -X GET http://localhost:3000/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### **Session Management**

```bash
# Get all active sessions
curl -X GET http://localhost:3000/auth/sessions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Logout from all devices
curl -X POST http://localhost:3000/auth/logout-all \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Logout from other devices (keep current session)
curl -X POST http://localhost:3000/auth/logout-others \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### **Token Refresh with Rotation**

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Authorization: Bearer YOUR_REFRESH_TOKEN"
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 🔒 **Security Features**

### **Rate Limiting**
- Login attempts: **3 per minute**
- Registration: **5 per minute**
- Global API: **100 requests per minute**

### **Account Protection**
- Account lockout after **5 failed attempts**
- Lockout duration: **15 minutes**
- Progressive lockout for repeat offenders

### **Session Security**
- Automatic session validation on each request
- Session revocation enforcement
- Device tracking and management
- Refresh token rotation

### **JWT Security**
- Separate secrets for access and refresh tokens
- Token blacklisting with Redis
- Short-lived access tokens (30 minutes)
- Long-lived refresh tokens (7 days)

---

## 📊 **API Documentation**

### **Swagger UI** (Development Only)
- **URL**: `http://localhost:3000/api`
- **Features**: Interactive API testing, request/response schemas, authentication

### **Production Documentation**
- Swagger is automatically disabled in production
- Use this README and docs folder for production reference

---

## 🛡️ **Role-Based Access Control (RBAC)**

### **Available Roles**
- `USER` - Standard user permissions
- `MODERATOR` - Elevated permissions for content management
- `ADMIN` - Full system access

### **Using Roles in Controllers**

```typescript
import { Roles } from './decorators/role.decorator';
import { UserRole } from './enums/user-role.enum';

@Patch(':id')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
async updateUser(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
  return this.usersService.updateUser(id, updateUserDto);
}
```

---

## 🚀 **Production Deployment**

### **Environment Variables for Production**

```bash
NODE_ENV=production
REQUIRE_SESSION_ID=true  # Stricter session validation
LOG_LEVEL=warn          # Reduce log verbosity
```

### **Security Checklist**
- ✅ Change all default JWT secrets
- ✅ Use strong database passwords
- ✅ Configure Redis with authentication
- ✅ Set up proper CORS origins
- ✅ Enable stricter session validation
- ✅ Use HTTPS in production
- ✅ Configure proper logging levels

---

## 🤝 **Contributing**

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 **License**

This project is licensed under the MIT License. See `LICENSE` for details.

---

## 🆘 **Support**

- **Documentation**: Check the `docs/` folder for detailed guides
- **Issues**: Open an issue on GitHub
- **Security**: Report security issues privately

Built with ❤️ using NestJS, MongoDB, and Redis.
