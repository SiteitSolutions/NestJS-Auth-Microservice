import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Cache } from 'cache-manager';
import { plainToInstance } from 'class-transformer';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UserEntity } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import { SessionService } from './services/session.service';
import { LoggingService } from 'src/common/services/logging.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private sessionService: SessionService,
    private loggingService: LoggingService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  // Generate Access and Refresh Tokens with Session Management
  async generateTokensWithSession(
    payload: any,
    deviceInfo: {
      userAgent?: string;
      ipAddress?: string;
      deviceId?: string;
      deviceName?: string;
    },
  ): Promise<{ accessToken: string; refreshToken: string; sessionId: string }> {
    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '30m', // Short-lived access token (30 minutes)
    });

    const refreshToken = this.jwtService.sign(
      { ...payload, sessionId: payload.sessionId },
      {
        secret: process.env.REFRESH_TOKEN_SECRET,
        expiresIn: '7d', // Long-lived refresh token (7 days)
      },
    );

    // Create session
    const session = await this.sessionService.createSession({
      userId: payload._id,
      refreshToken,
      deviceId: deviceInfo.deviceId,
      deviceName: deviceInfo.deviceName,
      userAgent: deviceInfo.userAgent,
      ipAddress: deviceInfo.ipAddress,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    return { accessToken, refreshToken, sessionId: session._id };
  }

  // Legacy method for backward compatibility
  async generateTokens(
    payload: any,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const result = await this.generateTokensWithSession(payload, {});
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    };
  }

  // Verify Refresh Token
  async verifyRefreshToken(
    token: string,
  ): Promise<{ _id: string; email: string }> {
    try {
      return this.jwtService.verify(token, {
        secret: process.env.REFRESH_TOKEN_SECRET,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async validateUser(email: string, pass: string): Promise<UserEntity | null> {
    const userDocument = await this.usersService.findOne({ email });

    if (!userDocument) {
      return null;
    }

    // Check if account is locked
    if (userDocument.isLocked && userDocument.isLocked()) {
      throw new UnauthorizedException(
        'Account is temporarily locked due to too many failed login attempts. Please try again later.',
      );
    }

    // Check if password is correct
    const isPasswordValid = userDocument.comparePassword(pass);

    if (!isPasswordValid) {
      // Increment login attempts
      await userDocument.incLoginAttempts();
      return null;
    }

    // Reset login attempts on successful login
    await userDocument.resetLoginAttempts();

    // Check if account is active
    if (!userDocument.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    return plainToInstance(UserEntity, userDocument.toObject());
  }

  async validateJwt(payload: any): Promise<UserEntity | null> {
    const userDocument = await this.usersService.findOne({
      _id: payload._id,
      email: payload.email,
    });

    if (userDocument) {
      return plainToInstance(UserEntity, userDocument.toObject());
    }

    return null;
  }

  async register(body: CreateUserDto): Promise<UserEntity | null> {
    const userDocument = await this.usersService.create(body);

    if (userDocument) {
      return plainToInstance(UserEntity, userDocument.toObject());
    }

    return null;
  }

  // Blacklist access token
  async invalidateAccessToken(token: string): Promise<void> {
    const expiresIn = parseInt(process.env.REDIS_TTL ?? '900_000'); // 15 minutes in seconds
    await this.cacheManager.set(`blacklisted:${token}`, true, expiresIn);
  }

  // Check if access token is blacklisted
  async isAccessTokenBlacklisted(token: string): Promise<boolean> {
    const result = await this.cacheManager.get(`blacklisted:${token}`);
    return result === true;
  }

  // Session Management Methods
  async refreshTokenWithRotation(
    oldRefreshToken: string,
    deviceInfo: {
      userAgent?: string;
      ipAddress?: string;
    },
  ): Promise<{ accessToken: string; refreshToken: string }> {
    // Find and validate session
    const session =
      await this.sessionService.findSessionByRefreshToken(oldRefreshToken);
    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Verify the refresh token
    const payload = await this.verifyRefreshToken(oldRefreshToken);

    // Generate new tokens
    const newAccessToken = this.jwtService.sign(
      { _id: payload._id, email: payload.email },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: '30m',
      },
    );

    const newRefreshToken = this.jwtService.sign(
      { _id: payload._id, email: payload.email, sessionId: session._id },
      {
        secret: process.env.REFRESH_TOKEN_SECRET,
        expiresIn: '7d',
      },
    );

    // Rotate the refresh token in the session
    await this.sessionService.rotateRefreshToken(
      oldRefreshToken,
      newRefreshToken,
    );

    // Log the token refresh
    this.loggingService.info('Refresh token rotated', {
      userId: payload._id,
      sessionId: session._id,
      ipAddress: deviceInfo.ipAddress,
      userAgent: deviceInfo.userAgent,
    });

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async getUserSessions(userId: string) {
    return this.sessionService.findUserSessions(userId);
  }

  async revokeSession(refreshToken: string): Promise<void> {
    await this.sessionService.revokeSession(refreshToken);
    this.loggingService.info('Session revoked', {
      refreshToken: refreshToken.substring(0, 10) + '...',
    });
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    await this.sessionService.revokeAllUserSessions(userId);
    this.loggingService.info('All user sessions revoked', { userId });
  }

  async revokeOtherUserSessions(
    userId: string,
    currentRefreshToken: string,
  ): Promise<void> {
    await this.sessionService.revokeOtherUserSessions(
      userId,
      currentRefreshToken,
    );
    this.loggingService.info('Other user sessions revoked', { userId });
  }
}
