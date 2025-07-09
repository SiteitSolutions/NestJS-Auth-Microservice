import { registerAs } from '@nestjs/config';

export default registerAs('security', () => ({
  jwt: {
    secret:
      process.env.JWT_SECRET || 'your-fallback-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '30m',
  },
  refreshToken: {
    secret:
      process.env.REFRESH_TOKEN_SECRET ||
      'your-fallback-refresh-secret-change-in-production',
    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d',
  },
  bcrypt: {
    rounds: parseInt(process.env.BCRYPT_ROUNDS || '12'),
  },
  rateLimit: {
    ttl: parseInt(process.env.RATE_LIMIT_TTL || '60000'),
    max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
    authMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '5'),
  },
  account: {
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
    lockoutTime: parseInt(process.env.LOCKOUT_TIME || '900000'), // 15 minutes
  },
  cors: {
    allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
    ],
  },
}));
