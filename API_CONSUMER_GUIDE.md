# API Consumer Guide - Using the Auth Microservice

This guide explains how to integrate and consume the NestJS Auth Microservice from your main application or orchestration API.

## 🏗️ **Architecture Overview**

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   Frontend App      │    │  Orchestration API   │    │  Auth Microservice  │
│  (React/Vue/etc)    │    │   (Main Backend)     │    │  (This Service)     │
├─────────────────────┤    ├──────────────────────┤    ├─────────────────────┤
│ • User Interface    │◄──►│ • Business Logic     │◄──►│ • Authentication    │
│ • Token Storage     │    │ • API Gateway        │    │ • User Management   │
│ • HTTP Client       │    │ • Service Mesh       │    │ • Session Tracking  │
│ • Route Protection  │    │ • Request Routing    │    │ • Security Logging  │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
```

## 🚀 **Integration Patterns**

### Pattern 1: Direct Client Integration

```typescript
// Frontend directly calls Auth Microservice
const authResponse = await fetch('http://auth-service:3000/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

### Pattern 2: Orchestration API Proxy (Recommended)

```typescript
// Frontend calls main API, which proxies to Auth Microservice
const authResponse = await fetch('http://main-api:4000/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

## 📋 **Available API Endpoints**

### Authentication Endpoints

- `POST /auth/register` - Register new user
- `POST /auth/login` - User login with credentials
- `POST /auth/logout` - Logout current session
- `POST /auth/refresh` - Refresh access token
- `GET /auth/profile` - Get current user profile

### Session Management Endpoints

- `GET /auth/sessions` - Get all user sessions
- `POST /auth/logout-all` - Logout from all devices
- `POST /auth/logout-others` - Logout from other devices
- `POST /auth/revoke-session` - Revoke specific session

### User Management Endpoints

- `PATCH /users/:id` - Update user profile
- `DELETE /users/:id` - Soft delete user

## 💼 **Orchestration API Integration Example**

Here's how your main API would integrate with this auth microservice:

### 1. **Environment Configuration**

```typescript
// main-api/.env
AUTH_SERVICE_URL=http://auth-microservice:3000
AUTH_SERVICE_TIMEOUT=5000
JWT_SECRET=same-secret-as-auth-service
```

### 2. **Auth Service Client**

```typescript
// main-api/src/services/auth.service.ts
import { Injectable, HttpService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthServiceClient {
  private readonly baseUrl: string;

  constructor(
    private httpService: HttpService,
    private configService: ConfigService,
  ) {
    this.baseUrl = this.configService.get('AUTH_SERVICE_URL');
  }

  async registerUser(userData: RegisterDto) {
    const response = await this.httpService
      .post(`${this.baseUrl}/auth/register`, userData)
      .toPromise();
    return response.data;
  }

  async loginUser(credentials: LoginDto, deviceInfo?: any) {
    const response = await this.httpService
      .post(`${this.baseUrl}/auth/login`, credentials, {
        headers: {
          'X-Device-ID': deviceInfo?.deviceId,
          'User-Agent': deviceInfo?.userAgent,
          'X-Forwarded-For': deviceInfo?.ipAddress,
        },
      })
      .toPromise();
    return response.data;
  }

  async refreshToken(refreshToken: string) {
    const response = await this.httpService
      .post(
        `${this.baseUrl}/auth/refresh`,
        {},
        {
          headers: {
            Authorization: `Bearer ${refreshToken}`,
          },
        },
      )
      .toPromise();
    return response.data;
  }

  async validateToken(accessToken: string) {
    try {
      const response = await this.httpService
        .get(`${this.baseUrl}/auth/profile`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        })
        .toPromise();
      return response.data;
    } catch (error) {
      return null;
    }
  }

  async getUserSessions(accessToken: string) {
    const response = await this.httpService
      .get(`${this.baseUrl}/auth/sessions`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })
      .toPromise();
    return response.data;
  }

  async logoutUser(accessToken: string) {
    const response = await this.httpService
      .post(
        `${this.baseUrl}/auth/logout`,
        {},
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      )
      .toPromise();
    return response.data;
  }

  async logoutAllDevices(accessToken: string) {
    const response = await this.httpService
      .post(
        `${this.baseUrl}/auth/logout-all`,
        {},
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      )
      .toPromise();
    return response.data;
  }
}
```

### 3. **Auth Controller (Proxy Layer)**

```typescript
// main-api/src/controllers/auth.controller.ts
@Controller('api/auth')
export class AuthController {
  constructor(private authServiceClient: AuthServiceClient) {}

  @Post('register')
  async register(@Body() userData: RegisterDto) {
    try {
      const result = await this.authServiceClient.registerUser(userData);
      return {
        success: true,
        data: result,
        message: 'User registered successfully',
      };
    } catch (error) {
      throw new BadRequestException('Registration failed');
    }
  }

  @Post('login')
  async login(@Body() credentials: LoginDto, @Req() req: Request) {
    try {
      const deviceInfo = {
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip,
        deviceId: req.get('X-Device-ID'),
      };

      const result = await this.authServiceClient.loginUser(
        credentials,
        deviceInfo,
      );

      return {
        success: true,
        data: {
          user: result.user,
          tokens: {
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
          },
        },
        message: 'Login successful',
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  @Post('refresh')
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    try {
      const result = await this.authServiceClient.refreshToken(refreshToken);
      return {
        success: true,
        data: result,
        message: 'Token refreshed successfully',
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  async getSessions(@Req() req: Request) {
    const token = req.headers.authorization?.split(' ')[1];
    const sessions = await this.authServiceClient.getUserSessions(token);

    return {
      success: true,
      data: sessions,
      message: 'Sessions retrieved successfully',
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() req: Request) {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authServiceClient.logoutUser(token);

    return {
      success: true,
      message: 'Logged out successfully',
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  async logoutAll(@Req() req: Request) {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authServiceClient.logoutAllDevices(token);

    return {
      success: true,
      message: 'Logged out from all devices',
    };
  }
}
```

### 4. **JWT Guard for Main API**

```typescript
// main-api/src/guards/jwt.guard.ts
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private authServiceClient: AuthServiceClient,
    private jwtService: JwtService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      // Option 1: Validate with auth microservice
      const user = await this.authServiceClient.validateToken(token);

      // Option 2: Validate locally (faster, but requires shared secret)
      // const payload = this.jwtService.verify(token);
      // const user = await this.userService.findById(payload.sub);

      if (!user) {
        throw new UnauthorizedException('Invalid token');
      }

      request.user = user;
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
```

## 🌐 **Frontend Integration Examples**

### React Example with Axios

```typescript
// frontend/src/services/authService.ts
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:4000';

class AuthService {
  private api = axios.create({
    baseURL: `${API_BASE_URL}/api`,
  });

  constructor() {
    // Add token to requests automatically
    this.api.interceptors.request.use((config) => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Handle token refresh automatically
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          const refreshed = await this.refreshToken();
          if (refreshed) {
            return this.api.request(error.config);
          } else {
            this.logout();
          }
        }
        return Promise.reject(error);
      },
    );
  }

  async register(userData: RegisterDto) {
    const response = await this.api.post('/auth/register', userData);
    return response.data;
  }

  async login(email: string, password: string) {
    const response = await this.api.post('/auth/login', { email, password });
    const { accessToken, refreshToken } = response.data.data.tokens;

    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);

    return response.data;
  }

  async refreshToken() {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      const response = await this.api.post('/auth/refresh', { refreshToken });

      const { accessToken, refreshToken: newRefreshToken } = response.data.data;
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', newRefreshToken);

      return true;
    } catch (error) {
      return false;
    }
  }

  async getSessions() {
    const response = await this.api.get('/auth/sessions');
    return response.data.data;
  }

  async logout() {
    try {
      await this.api.post('/auth/logout');
    } finally {
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      window.location.href = '/login';
    }
  }

  async logoutAllDevices() {
    await this.api.post('/auth/logout-all');
    this.logout();
  }

  isAuthenticated() {
    return !!localStorage.getItem('accessToken');
  }
}

export default new AuthService();
```

### React Hook for Authentication

```typescript
// frontend/src/hooks/useAuth.ts
import { useState, useEffect, useContext, createContext } from 'react';
import authService from '../services/authService';

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  sessions: Session[];
  getSessions: () => Promise<void>;
  logoutAllDevices: () => Promise<void>;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in
    if (authService.isAuthenticated()) {
      loadUserProfile();
    } else {
      setIsLoading(false);
    }
  }, []);

  const loadUserProfile = async () => {
    try {
      const profile = await authService.getProfile();
      setUser(profile.data);
    } catch (error) {
      authService.logout();
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    const response = await authService.login(email, password);
    setUser(response.data.user);
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    setSessions([]);
  };

  const getSessions = async () => {
    const sessionData = await authService.getSessions();
    setSessions(sessionData);
  };

  const logoutAllDevices = async () => {
    await authService.logoutAllDevices();
    setUser(null);
    setSessions([]);
  };

  return (
    <AuthContext.Provider value={{
      user,
      login,
      logout,
      sessions,
      getSessions,
      logoutAllDevices,
      isLoading
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

## 🔐 **Security Considerations**

### 1. **Token Storage**

```typescript
// ❌ Don't store in localStorage (XSS vulnerable)
localStorage.setItem('accessToken', token);

// ✅ Use secure httpOnly cookies (recommended)
// Set in backend:
res.cookie('accessToken', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 30 * 60 * 1000, // 30 minutes
});

// ✅ Or use memory storage with refresh pattern
class TokenManager {
  private accessToken: string | null = null;

  setToken(token: string) {
    this.accessToken = token;
  }

  getToken() {
    return this.accessToken;
  }
}
```

### 2. **Network Security**

```typescript
// Always use HTTPS in production
const API_BASE_URL =
  process.env.NODE_ENV === 'production'
    ? 'https://api.yourdomain.com'
    : 'http://localhost:4000';

// Add timeout and retry logic
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  retry: 3,
});
```

### 3. **Error Handling**

```typescript
try {
  const result = await authService.login(email, password);
  // Handle success
} catch (error) {
  if (error.response?.status === 429) {
    // Rate limit exceeded
    showError('Too many attempts. Please try again later.');
  } else if (error.response?.status === 401) {
    // Invalid credentials
    showError('Invalid email or password.');
  } else {
    // Generic error
    showError('Login failed. Please try again.');
  }
}
```

## 📊 **Monitoring and Analytics**

### 1. **Track Authentication Events**

```typescript
// In your main API
@Post('login')
async login(@Body() credentials: LoginDto, @Req() req: Request) {
  try {
    const result = await this.authServiceClient.loginUser(credentials);

    // Track successful login
    this.analyticsService.track('user_login', {
      userId: result.user.id,
      timestamp: new Date(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    return result;
  } catch (error) {
    // Track failed login
    this.analyticsService.track('login_failed', {
      email: credentials.email,
      timestamp: new Date(),
      ipAddress: req.ip,
      reason: error.message
    });

    throw error;
  }
}
```

### 2. **Session Analytics**

```typescript
// Track session activity
@UseGuards(JwtAuthGuard)
@Get('sessions')
async getSessions(@Req() req: Request) {
  const sessions = await this.authServiceClient.getUserSessions(token);

  // Track session access
  this.analyticsService.track('sessions_viewed', {
    userId: req.user.id,
    sessionCount: sessions.length,
    timestamp: new Date()
  });

  return sessions;
}
```

## 🚀 **Deployment Considerations**

### 1. **Docker Compose (Development)**

```yaml
version: '3.8'
services:
  main-api:
    build: ./main-api
    ports:
      - '4000:4000'
    environment:
      - AUTH_SERVICE_URL=http://auth-service:3000
    depends_on:
      - auth-service

  auth-service:
    build: ./auth-microservice
    ports:
      - '3000:3000'
    environment:
      - MONGO_URI=mongodb://mongo:27017/authdb
      - REDIS_HOST=redis
    depends_on:
      - mongo
      - redis

  mongo:
    image: mongo:6.0
    ports:
      - '27017:27017'

  redis:
    image: redis:latest
    ports:
      - '6379:6379'
```

### 2. **Kubernetes (Production)**

```yaml
# auth-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
        - name: auth-service
          image: your-registry/auth-service:latest
          ports:
            - containerPort: 3000
          env:
            - name: MONGO_URI
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: mongo-uri
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: jwt-secret
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
spec:
  selector:
    app: auth-service
  ports:
    - port: 3000
      targetPort: 3000
  type: ClusterIP
```

This comprehensive guide shows exactly how your orchestration API can consume and integrate with the auth microservice, providing a complete authentication solution for your application architecture! 🚀
