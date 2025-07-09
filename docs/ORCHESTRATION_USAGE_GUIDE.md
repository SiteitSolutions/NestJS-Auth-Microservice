# How to Use This Auth Microservice - Orchestration API Guide

This guide explains how a consumer application (like an orchestration API) would integrate with and use this NestJS Authentication Microservice.

## 🏗️ **Architecture & Integration Patterns**

### Overview

Your authentication microservice is designed to work as a standalone service that other applications can consume. Here are the main integration patterns:

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   Frontend App      │    │  Orchestration API   │    │  Auth Microservice  │
│  (React/Vue/etc)    │    │   (Main Backend)     │    │  (This Service)     │
├─────────────────────┤    ├──────────────────────┤    ├─────────────────────┤
│ • UI Components     │◄──►│ • Business Logic     │◄──►│ • User Auth         │
│ • Token Storage     │    │ • API Gateway        │    │ • Session Mgmt      │
│ • HTTP Requests     │    │ • Service Mesh       │    │ • Security Features │
│ • Route Guards      │    │ • Request Proxying   │    │ • Token Validation  │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
```

## 🚀 **Quick Start: Orchestration API Setup**

### 1. **Install Required Dependencies**

```bash
npm install @nestjs/axios @nestjs/jwt @nestjs/config
```

### 2. **Environment Configuration**

```typescript
// orchestration-api/.env
AUTH_SERVICE_URL=http://localhost:3000
AUTH_SERVICE_TIMEOUT=5000
JWT_SECRET=your-super-secret-jwt-key-here
ALLOWED_ORIGINS=http://localhost:3001,http://localhost:3002
```

### 3. **Create Auth Service Client**

```typescript
// src/services/auth-client.service.ts
import { Injectable, HttpException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class AuthClientService {
  private readonly authServiceUrl: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.authServiceUrl = this.configService.get<string>('AUTH_SERVICE_URL');
  }

  // User Registration
  async registerUser(userData: any) {
    try {
      const response = await firstValueFrom(
        this.httpService.post(`${this.authServiceUrl}/auth/register`, userData),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Registration failed',
        error.response?.status || 500,
      );
    }
  }

  // User Login
  async loginUser(credentials: any, deviceInfo?: any) {
    try {
      const headers: any = {};
      if (deviceInfo) {
        headers['X-Device-ID'] = deviceInfo.deviceId;
        headers['User-Agent'] = deviceInfo.userAgent;
        headers['X-Forwarded-For'] = deviceInfo.ipAddress;
      }

      const response = await firstValueFrom(
        this.httpService.post(
          `${this.authServiceUrl}/auth/login`,
          credentials,
          { headers },
        ),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Login failed',
        error.response?.status || 401,
      );
    }
  }

  // Token Refresh
  async refreshToken(refreshToken: string, deviceInfo?: any) {
    try {
      const headers: any = {
        Authorization: `Bearer ${refreshToken}`,
      };
      if (deviceInfo?.userAgent) {
        headers['User-Agent'] = deviceInfo.userAgent;
      }

      const response = await firstValueFrom(
        this.httpService.post(
          `${this.authServiceUrl}/auth/refresh`,
          {},
          { headers },
        ),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Token refresh failed',
        error.response?.status || 401,
      );
    }
  }

  // Validate Token & Get User Profile
  async validateToken(accessToken: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.get(`${this.authServiceUrl}/auth/profile`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        }),
      );
      return response.data;
    } catch (error) {
      return null; // Token is invalid
    }
  }

  // Logout User
  async logoutUser(accessToken: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.post(
          `${this.authServiceUrl}/auth/logout`,
          {},
          { headers: { Authorization: `Bearer ${accessToken}` } },
        ),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Logout failed',
        error.response?.status || 400,
      );
    }
  }

  // Get User Sessions
  async getUserSessions(accessToken: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.get(`${this.authServiceUrl}/auth/sessions`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Failed to get sessions',
        error.response?.status || 400,
      );
    }
  }

  // Logout from all devices
  async logoutAllDevices(accessToken: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.post(
          `${this.authServiceUrl}/auth/logout-all`,
          {},
          { headers: { Authorization: `Bearer ${accessToken}` } },
        ),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Logout all failed',
        error.response?.status || 400,
      );
    }
  }

  // Revoke specific session
  async revokeSession(accessToken: string, sessionId: string) {
    try {
      const response = await firstValueFrom(
        this.httpService.post(
          `${this.authServiceUrl}/auth/revoke-session`,
          { sessionId },
          { headers: { Authorization: `Bearer ${accessToken}` } },
        ),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(
        error.response?.data || 'Session revocation failed',
        error.response?.status || 400,
      );
    }
  }
}
```

## 🛡️ **Auth Guard for Your Orchestration API**

```typescript
// src/guards/auth.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthClientService } from '../services/auth-client.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly authClientService: AuthClientService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Authentication token is required');
    }

    try {
      const user = await this.authClientService.validateToken(token);
      if (!user) {
        throw new UnauthorizedException('Invalid token');
      }

      // Attach user to request object
      request.user = user;
      return true;
    } catch (error) {
      throw new UnauthorizedException('Authentication failed');
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
```

## 🎮 **Controller Examples (Proxy Pattern)**

```typescript
// src/controllers/auth.controller.ts
import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import { AuthClientService } from '../services/auth-client.service';
import { AuthGuard } from '../guards/auth.guard';
import { Request } from 'express';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authClientService: AuthClientService) {}

  @Post('register')
  @HttpCode(201)
  async register(@Body() userData: any) {
    const result = await this.authClientService.registerUser(userData);
    return {
      success: true,
      data: result,
      message: 'User registered successfully',
    };
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body() credentials: any, @Req() req: Request) {
    const deviceInfo = {
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip,
      deviceId: req.get('X-Device-ID') || 'unknown',
    };

    const result = await this.authClientService.loginUser(
      credentials,
      deviceInfo,
    );

    return {
      success: true,
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      },
      message: 'Login successful',
    };
  }

  @Post('refresh')
  @HttpCode(200)
  async refreshToken(
    @Body() body: { refreshToken: string },
    @Req() req: Request,
  ) {
    const deviceInfo = {
      userAgent: req.get('User-Agent'),
    };

    const result = await this.authClientService.refreshToken(
      body.refreshToken,
      deviceInfo,
    );

    return {
      success: true,
      data: result,
      message: 'Token refreshed successfully',
    };
  }

  @UseGuards(AuthGuard)
  @Get('profile')
  async getProfile(@Req() req: any) {
    return {
      success: true,
      data: req.user,
      message: 'Profile retrieved successfully',
    };
  }

  @UseGuards(AuthGuard)
  @Post('logout')
  @HttpCode(200)
  async logout(@Req() req: Request) {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authClientService.logoutUser(token);

    return {
      success: true,
      message: 'Logged out successfully',
    };
  }

  @UseGuards(AuthGuard)
  @Get('sessions')
  async getSessions(@Req() req: Request) {
    const token = req.headers.authorization?.split(' ')[1];
    const sessions = await this.authClientService.getUserSessions(token);

    return {
      success: true,
      data: sessions,
      message: 'Sessions retrieved successfully',
    };
  }

  @UseGuards(AuthGuard)
  @Post('logout-all')
  @HttpCode(200)
  async logoutAll(@Req() req: Request) {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authClientService.logoutAllDevices(token);

    return {
      success: true,
      message: 'Logged out from all devices successfully',
    };
  }

  @UseGuards(AuthGuard)
  @Post('revoke-session')
  @HttpCode(200)
  async revokeSession(
    @Body() body: { sessionId: string },
    @Req() req: Request,
  ) {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authClientService.revokeSession(token, body.sessionId);

    return {
      success: true,
      message: 'Session revoked successfully',
    };
  }
}
```

## 📱 **Frontend Integration Examples**

### React/TypeScript Example

```typescript
// frontend/src/services/authService.ts
class AuthService {
  private readonly baseURL = 'http://your-orchestration-api:4000/api';

  async login(email: string, password: string) {
    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': this.getDeviceId(),
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data = await response.json();

    // Store tokens securely
    localStorage.setItem('accessToken', data.data.accessToken);
    localStorage.setItem('refreshToken', data.data.refreshToken);

    return data;
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(`${this.baseURL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      // Refresh failed, redirect to login
      this.logout();
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    localStorage.setItem('accessToken', data.data.accessToken);
    localStorage.setItem('refreshToken', data.data.refreshToken);

    return data;
  }

  async logout() {
    const token = localStorage.getItem('accessToken');

    if (token) {
      try {
        await fetch(`${this.baseURL}/auth/logout`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } catch (error) {
        console.error('Logout request failed:', error);
      }
    }

    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  }

  async getProfile() {
    const token = localStorage.getItem('accessToken');

    const response = await fetch(`${this.baseURL}/auth/profile`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        // Try to refresh token
        await this.refreshToken();
        return this.getProfile(); // Retry with new token
      }
      throw new Error('Failed to get profile');
    }

    return response.json();
  }

  private getDeviceId(): string {
    let deviceId = localStorage.getItem('deviceId');
    if (!deviceId) {
      deviceId = 'web-' + Math.random().toString(36).substr(2, 9);
      localStorage.setItem('deviceId', deviceId);
    }
    return deviceId;
  }
}

export const authService = new AuthService();
```

### React Hook for Authentication

```typescript
// frontend/src/hooks/useAuth.ts
import { useState, useEffect, createContext, useContext } from 'react';
import { authService } from '../services/authService';

interface User {
  _id: string;
  email: string;
  givenName: string;
  familyName: string;
  roles: string[];
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        try {
          const profileResponse = await authService.getProfile();
          setUser(profileResponse.data);
        } catch (error) {
          console.error('Failed to get profile:', error);
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
        }
      }
      setLoading(false);
    };

    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    const response = await authService.login(email, password);
    setUser(response.data.user);
  };

  const logout = () => {
    authService.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

## 🔄 **HTTP Request Examples**

### 1. User Registration

```bash
POST http://your-orchestration-api:4000/api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "givenName": "John",
  "familyName": "Doe"
}
```

### 2. User Login with Device Tracking

```bash
POST http://your-orchestration-api:4000/api/auth/login
Content-Type: application/json
X-Device-ID: mobile-app-ios-v1.0
User-Agent: MyApp/1.0 (iOS 15.0; iPhone 13)

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

### 3. Access Protected Resources

```bash
GET http://your-orchestration-api:4000/api/auth/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 4. Session Management

```bash
# Get all sessions
GET http://your-orchestration-api:4000/api/auth/sessions
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Logout from all devices
POST http://your-orchestration-api:4000/api/auth/logout-all
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Revoke specific session
POST http://your-orchestration-api:4000/api/auth/revoke-session
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "sessionId": "session_abc123"
}
```

## 🚦 **Best Practices**

### 1. **Token Storage**

- **Frontend**: Use secure HTTP-only cookies or localStorage with XSS protection
- **Mobile**: Use secure keychain/keystore
- **Server**: Never store tokens in logs or databases

### 2. **Error Handling**

```typescript
// Implement proper error handling with retry logic
const makeAuthenticatedRequest = async (
  url: string,
  options: RequestInit = {},
) => {
  let token = localStorage.getItem('accessToken');

  const makeRequest = async () => {
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${token}`,
      },
    });
  };

  let response = await makeRequest();

  if (response.status === 401) {
    // Try to refresh token
    try {
      await authService.refreshToken();
      token = localStorage.getItem('accessToken');
      response = await makeRequest();
    } catch (error) {
      // Refresh failed, redirect to login
      authService.logout();
      window.location.href = '/login';
      throw new Error('Authentication failed');
    }
  }

  return response;
};
```

### 3. **Security Considerations**

- Always use HTTPS in production
- Implement proper CORS settings
- Use short-lived access tokens (15-30 minutes)
- Implement refresh token rotation
- Log authentication events for monitoring
- Rate limit authentication endpoints

### 4. **Monitoring & Observability**

```typescript
// Add logging to your auth client
import { Logger } from '@nestjs/common';

@Injectable()
export class AuthClientService {
  private readonly logger = new Logger(AuthClientService.name);

  async loginUser(credentials: any, deviceInfo?: any) {
    this.logger.log(`Login attempt for user: ${credentials.email}`);

    try {
      const result = await this.performLogin(credentials, deviceInfo);
      this.logger.log(`Login successful for user: ${credentials.email}`);
      return result;
    } catch (error) {
      this.logger.error(
        `Login failed for user: ${credentials.email}`,
        error.stack,
      );
      throw error;
    }
  }
}
```

## 🔧 **Environment-Specific Configurations**

### Development

```typescript
// .env.development
AUTH_SERVICE_URL=http://localhost:3000
AUTH_SERVICE_TIMEOUT=5000
LOG_LEVEL=debug
```

### Production

```typescript
// .env.production
AUTH_SERVICE_URL=https://auth-service.yourcompany.com
AUTH_SERVICE_TIMEOUT=3000
LOG_LEVEL=warn
ENABLE_REQUEST_LOGGING=false
```

This guide provides everything you need to integrate your NestJS auth microservice with an orchestration API. The microservice handles all authentication complexity while your main API focuses on business logic and acts as a clean proxy layer for your frontend applications.
