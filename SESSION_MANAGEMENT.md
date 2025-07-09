# Quick Start Guide - Session Management & Enhanced Security

This guide covers the new session management features and enhanced security improvements.

## 🚀 Quick Setup

### 1. Environment Configuration

```bash
# Copy the environment template
cp .env.example .env

# Edit with your values
nano .env
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Start Services

```bash
# Using Docker Compose
docker-compose up -d

# Or start locally (requires MongoDB and Redis)
npm run start:dev
```

## 🔐 New Session Management Features

### Enhanced Login Response

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJfaWQiOiI1MzRjNTU4NC1lYWI0LTRhN..."
}
```

### Device Tracking Headers

Send these optional headers for better device tracking:

```bash
X-Device-ID: unique-device-identifier
User-Agent: Your-App/1.0.0 (iOS 15.0; iPhone 13)
```

### Session Management Endpoints

#### Get Active Sessions

```bash
GET /auth/sessions
Authorization: Bearer <access_token>
```

Response:

```json
[
  {
    "id": "session-id-123",
    "deviceName": "Mobile Device",
    "deviceId": "device-456",
    "userAgent": "Mozilla/5.0...",
    "ipAddress": "192.168.1.1",
    "lastUsedAt": "2023-12-01T10:30:00Z",
    "expiresAt": "2023-12-08T10:30:00Z"
  }
]
```

#### Logout from All Devices

```bash
POST /auth/logout-all
Authorization: Bearer <access_token>
```

#### Logout from Other Devices

```bash
POST /auth/logout-others
Authorization: Bearer <access_token>
```

#### Revoke Specific Session

```bash
POST /auth/revoke-session
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "sessionId": "session-id-to-revoke"
}
```

### Refresh Token Rotation

The `/auth/refresh` endpoint now automatically rotates refresh tokens:

```bash
POST /auth/refresh
Authorization: Bearer <refresh_token>
```

Response:

```json
{
  "accessToken": "new-access-token...",
  "refreshToken": "new-refresh-token..."
}
```

**Important**: Always use the new refresh token for subsequent requests!

## 📊 Logging & Monitoring

### Log Files

- `logs/combined.log` - All application logs
- `logs/error.log` - Error logs only

### Log Format

```json
{
  "level": "info",
  "message": "HTTP Request",
  "timestamp": "2023-12-01T10:30:00.000Z",
  "service": "auth-microservice",
  "method": "POST",
  "url": "/auth/login",
  "ip": "192.168.1.1",
  "userAgent": "Mozilla/5.0..."
}
```

### Security Events

The system automatically logs:

- Login attempts (success/failure)
- Account lockouts
- Token refresh events
- Session revocations
- Suspicious activities

## 🛡️ Security Best Practices

### Token Management

1. **Store securely**: Never store tokens in localStorage in browsers
2. **Use HTTPS**: Always transmit tokens over secure connections
3. **Rotation**: Refresh tokens are automatically rotated
4. **Expiration**: Access tokens expire in 30 minutes, refresh tokens in 7 days

### Session Security

1. **Monitor sessions**: Regularly check active sessions
2. **Revoke suspicious sessions**: Use session management endpoints
3. **Device tracking**: Provide device information for better security
4. **IP validation**: Sessions are tied to IP addresses for security

### Production Deployment

1. **Environment variables**: Set strong, unique secrets
2. **HTTPS**: Enable SSL/TLS encryption
3. **Monitoring**: Set up log monitoring and alerting
4. **Backup**: Regular database and configuration backups

## 🔧 Configuration Options

### Rate Limiting

```env
RATE_LIMIT_TTL=60000          # Time window in ms
RATE_LIMIT_MAX=100           # Max requests per window
AUTH_RATE_LIMIT_MAX=5        # Max auth attempts per window
```

### Security Settings

```env
MAX_LOGIN_ATTEMPTS=5         # Failed attempts before lockout
LOCKOUT_TIME=900000         # Lockout duration in ms (15 minutes)
BCRYPT_ROUNDS=12            # Password hashing strength
```

### Logging

```env
LOG_LEVEL=info              # Log level (error, warn, info, debug)
NODE_ENV=production         # Environment (affects logging behavior)
```

## 🚨 Production Checklist

- [ ] Set strong, unique JWT secrets
- [ ] Configure CORS with specific origins
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Set up log monitoring and alerting
- [ ] Configure Redis with authentication
- [ ] Set MongoDB authentication and encryption
- [ ] Test session management flows
- [ ] Verify rate limiting is working
- [ ] Check Swagger is disabled in production
- [ ] Monitor session cleanup scheduled tasks

## 🆘 Troubleshooting

### Common Issues

**Token rotation not working**

- Ensure you're using the new refresh token from the response
- Check that the session exists and hasn't expired

**Session not found**

- Verify the session ID is correct
- Check if the session has been revoked or expired

**Rate limiting triggering**

- Reduce request frequency
- Check if IP is making too many requests

**Logs not appearing**

- Ensure `logs/` directory exists and is writable
- Check LOG_LEVEL environment variable

### Debug Commands

```bash
# Check running containers
docker-compose ps

# View application logs
docker-compose logs app

# Check Redis connection
redis-cli ping

# Check MongoDB connection
mongosh mongodb://root:password@localhost:27017/nestdb?authSource=admin
```

## 📈 Performance Considerations

### Session Storage

- Sessions are stored in MongoDB for persistence
- Consider session cleanup frequency based on usage
- Monitor database size and performance

### Logging

- Log files can grow large in production
- Implement log rotation strategies
- Consider centralized logging solutions

### Caching

- Redis is used for token blacklisting
- Monitor Redis memory usage
- Configure appropriate TTL values

For more detailed information, see the main [SECURITY.md](./SECURITY.md) file.
