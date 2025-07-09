# Practical Usage Examples - Auth Microservice Integration

This document provides real-world examples of how to consume the auth microservice with actual HTTP requests and responses.

## 🔄 **Complete Authentication Flow**

### 1. **User Registration**

```bash
POST http://auth-service:3000/auth/register
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "givenName": "John",
  "familyName": "Doe",
  "roles": ["USER"]
}
```

**Response (201 Created):**

```json
{
  "_id": "65a1b2c3d4e5f6789abc0123",
  "email": "john.doe@example.com",
  "givenName": "John",
  "familyName": "Doe",
  "roles": ["USER"],
  "isActive": true,
  "emailVerified": false,
  "createdAt": "2023-12-01T10:30:00.000Z",
  "updatedAt": "2023-12-01T10:30:00.000Z"
}
```

### 2. **User Login**

```bash
POST http://auth-service:3000/auth/login
Content-Type: application/json
X-Device-ID: mobile-app-v1.0
User-Agent: MyApp/1.0 (iOS 15.0; iPhone 13)

{
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

**Response (201 Created):**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NWExYjJjM2Q0ZTVmNjc4OWFiYzAxMjMiLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiaWF0IjoxNzAzMTYzMDAwLCJleHAiOjE3MDMxNjQ4MDB9.signature",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NWExYjJjM2Q0ZTVmNjc4OWFiYzAxMjMiLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwic2Vzc2lvbklkIjoic2Vzc2lvbl8xMjMiLCJpYXQiOjE3MDMxNjMwMDAsImV4cCI6MTcwMzc2NzgwMH0.signature"
}
```

### 3. **Access Protected Resource**

```bash
GET http://auth-service:3000/auth/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**

```json
{
  "_id": "65a1b2c3d4e5f6789abc0123",
  "email": "john.doe@example.com",
  "givenName": "John",
  "familyName": "Doe",
  "roles": ["USER"],
  "isActive": true,
  "lastLoginAt": "2023-12-01T10:30:00.000Z"
}
```

### 4. **Token Refresh with Rotation**

```bash
POST http://auth-service:3000/auth/refresh
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...(refresh_token)
User-Agent: MyApp/1.0 (iOS 15.0; iPhone 13)
```

**Response (201 Created):**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.NEW_ACCESS_TOKEN.signature",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.NEW_REFRESH_TOKEN.signature"
}
```

## 📱 **Session Management Examples**

### 1. **View Active Sessions**

```bash
GET http://auth-service:3000/auth/sessions
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**

```json
[
  {
    "id": "session_123",
    "deviceName": "Mobile Device",
    "deviceId": "mobile-app-v1.0",
    "userAgent": "MyApp/1.0 (iOS 15.0; iPhone 13)",
    "ipAddress": "192.168.1.100",
    "location": "New York, US",
    "lastUsedAt": "2023-12-01T10:30:00.000Z",
    "expiresAt": "2023-12-08T10:30:00.000Z"
  },
  {
    "id": "session_456",
    "deviceName": "Desktop",
    "deviceId": "web-browser-chrome",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "ipAddress": "192.168.1.101",
    "lastUsedAt": "2023-12-01T09:15:00.000Z",
    "expiresAt": "2023-12-08T09:15:00.000Z"
  }
]
```

### 2. **Logout from All Devices**

```bash
POST http://auth-service:3000/auth/logout-all
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (201 Created):**

```json
{
  "message": "Logged out from all devices successfully"
}
```

### 3. **Logout from Other Devices**

```bash
POST http://auth-service:3000/auth/logout-others
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (201 Created):**

```json
{
  "message": "Logged out from other devices successfully"
}
```

### 4. **Revoke Specific Session**

```bash
POST http://auth-service:3000/auth/revoke-session
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "sessionId": "session_456"
}
```

**Response (201 Created):**

```json
{
  "message": "Session revoked successfully"
}
```

## 🏗️ **Orchestration API Implementation**

### Express.js Example

```javascript
// main-api/routes/auth.js
const express = require('express');
const axios = require('axios');
const router = express.Router();

const AUTH_SERVICE_URL =
  process.env.AUTH_SERVICE_URL || 'http://localhost:3000';

// Proxy login request
router.post('/login', async (req, res) => {
  try {
    const response = await axios.post(
      `${AUTH_SERVICE_URL}/auth/login`,
      req.body,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': req.headers['x-device-id'],
          'User-Agent': req.headers['user-agent'],
          'X-Forwarded-For': req.ip,
        },
      },
    );

    // Transform response to match your API format
    res.json({
      success: true,
      data: {
        user: response.data.user,
        tokens: {
          accessToken: response.data.accessToken,
          refreshToken: response.data.refreshToken,
        },
      },
      message: 'Login successful',
    });
  } catch (error) {
    if (error.response?.status === 401) {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        error: 'INVALID_CREDENTIALS',
      });
    } else if (error.response?.status === 429) {
      res.status(429).json({
        success: false,
        message: 'Too many attempts. Please try again later.',
        error: 'RATE_LIMIT_EXCEEDED',
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Authentication service error',
        error: 'SERVICE_ERROR',
      });
    }
  }
});

// Middleware to validate tokens
const validateToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const response = await axios.get(`${AUTH_SERVICE_URL}/auth/profile`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    req.user = response.data;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Protected route example
router.get('/profile', validateToken, (req, res) => {
  res.json({
    success: true,
    data: req.user,
    message: 'Profile retrieved successfully',
  });
});

module.exports = router;
```

### NestJS Orchestration Example

```typescript
// main-api/src/auth/auth.controller.ts
@Controller('api/auth')
export class AuthController {
  constructor(private readonly httpService: HttpService) {}

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    try {
      const response = await this.httpService
        .post(`${process.env.AUTH_SERVICE_URL}/auth/login`, loginDto, {
          headers: {
            'X-Device-ID': req.headers['x-device-id'],
            'User-Agent': req.headers['user-agent'],
            'X-Forwarded-For': req.ip,
          },
        })
        .toPromise();

      // Set secure cookies for tokens
      res.cookie('accessToken', response.data.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000, // 30 minutes
      });

      res.cookie('refreshToken', response.data.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return res.json({
        success: true,
        data: { user: response.data.user },
        message: 'Login successful',
      });
    } catch (error) {
      if (error.response?.status === 401) {
        throw new UnauthorizedException('Invalid credentials');
      }
      throw new BadRequestException('Login failed');
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  async getSessions(@Req() req: Request) {
    const token =
      req.cookies.accessToken || req.headers.authorization?.split(' ')[1];

    const response = await this.httpService
      .get(`${process.env.AUTH_SERVICE_URL}/auth/sessions`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })
      .toPromise();

    return {
      success: true,
      data: response.data,
      message: 'Sessions retrieved successfully',
    };
  }
}
```

## 🌐 **Frontend Integration Patterns**

### React with Context API

```jsx
// AuthContext.jsx
import React, { createContext, useContext, useReducer, useEffect } from 'react';

const AuthContext = createContext();

const authReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        loading: false,
      };
    case 'LOGOUT':
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        sessions: [],
      };
    case 'SET_SESSIONS':
      return {
        ...state,
        sessions: action.payload,
      };
    default:
      return state;
  }
};

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, {
    isAuthenticated: false,
    user: null,
    sessions: [],
    loading: true,
  });

  const login = async (email, password) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': getDeviceId(),
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (data.success) {
        dispatch({ type: 'LOGIN_SUCCESS', payload: data.data });
        return { success: true };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      return { success: false, message: 'Network error' };
    }
  };

  const getSessions = async () => {
    try {
      const response = await fetch('/api/auth/sessions', {
        credentials: 'include',
      });
      const data = await response.json();

      if (data.success) {
        dispatch({ type: 'SET_SESSIONS', payload: data.data });
      }
    } catch (error) {
      console.error('Failed to fetch sessions:', error);
    }
  };

  const logoutAllDevices = async () => {
    try {
      await fetch('/api/auth/logout-all', {
        method: 'POST',
        credentials: 'include',
      });
      dispatch({ type: 'LOGOUT' });
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
        getSessions,
        logoutAllDevices,
      }}
    >
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

// Helper function to generate/retrieve device ID
const getDeviceId = () => {
  let deviceId = localStorage.getItem('deviceId');
  if (!deviceId) {
    deviceId = 'device_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('deviceId', deviceId);
  }
  return deviceId;
};
```

### Vue.js with Pinia Store

```javascript
// stores/auth.js
import { defineStore } from 'pinia';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    sessions: [],
    isAuthenticated: false,
    loading: false,
  }),

  actions: {
    async login(credentials) {
      this.loading = true;
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Device-ID': this.getDeviceId(),
          },
          body: JSON.stringify(credentials),
        });

        const data = await response.json();

        if (data.success) {
          this.user = data.data.user;
          this.isAuthenticated = true;
          return { success: true };
        } else {
          return { success: false, message: data.message };
        }
      } catch (error) {
        return { success: false, message: 'Network error' };
      } finally {
        this.loading = false;
      }
    },

    async fetchSessions() {
      try {
        const response = await fetch('/api/auth/sessions', {
          credentials: 'include',
        });
        const data = await response.json();

        if (data.success) {
          this.sessions = data.data;
        }
      } catch (error) {
        console.error('Failed to fetch sessions:', error);
      }
    },

    async revokeSession(sessionId) {
      try {
        const response = await fetch('/api/auth/revoke-session', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({ sessionId }),
        });

        if (response.ok) {
          this.sessions = this.sessions.filter((s) => s.id !== sessionId);
        }
      } catch (error) {
        console.error('Failed to revoke session:', error);
      }
    },

    getDeviceId() {
      let deviceId = localStorage.getItem('deviceId');
      if (!deviceId) {
        deviceId = 'device_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('deviceId', deviceId);
      }
      return deviceId;
    },
  },
});
```

## 🔍 **Error Handling Examples**

### Rate Limiting Response

```json
HTTP 429 Too Many Requests
{
  "statusCode": 429,
  "message": "ThrottlerException: Too Many Requests",
  "error": "Too Many Requests"
}
```

### Account Locked Response

```json
HTTP 401 Unauthorized
{
  "statusCode": 401,
  "message": "Account is temporarily locked due to too many failed login attempts. Please try again later.",
  "error": "Unauthorized"
}
```

### Invalid Token Response

```json
HTTP 401 Unauthorized
{
  "statusCode": 401,
  "message": "Invalid or expired access token",
  "error": "Unauthorized"
}
```

### Session Not Found Response

```json
HTTP 401 Unauthorized
{
  "statusCode": 401,
  "message": "Session not found",
  "error": "Unauthorized"
}
```

## 📊 **Monitoring Integration**

### Health Check Endpoint

```bash
GET http://auth-service:3000/health
```

**Response:**

```json
{
  "status": "ok",
  "info": {
    "database": { "status": "up" },
    "redis": { "status": "up" }
  },
  "error": {},
  "details": {
    "database": { "status": "up" },
    "redis": { "status": "up" }
  }
}
```

### Metrics Endpoint (Custom)

```bash
GET http://auth-service:3000/metrics
```

**Response:**

```json
{
  "activeUsers": 1250,
  "activeSessions": 3420,
  "loginAttemptsToday": 8950,
  "failedLoginsToday": 125,
  "lockedAccountsToday": 5,
  "averageSessionDuration": "2h 15m",
  "tokenRefreshRate": "15.2/min"
}
```

This practical guide provides everything you need to successfully integrate and consume the auth microservice in your application architecture! 🚀
