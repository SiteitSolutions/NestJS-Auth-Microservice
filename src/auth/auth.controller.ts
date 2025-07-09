import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { Request } from 'express';
import { UserEntity } from 'src/users/entities/user.entity';
import { plainToInstance } from 'class-transformer';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AccessTokenEntity } from './entities/access-token.entity';
import { LocalAuthDto } from './dto/local-auth.dto';
import { LocalAuthEntity } from './entities/local-auth.entity';
import { Throttle } from '@nestjs/throttler';
import { RevokeSessionDto, SessionResponseDto } from './dto/session.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 attempts per minute
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({
    status: 201,
    description: 'Login successful',
    type: LocalAuthEntity,
    example: {
      accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC...',
      refreshToken: 'eyJfaWQiOiI1MzRjNTU4NC1lYWI0LTRhN...',
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request',
    example: new BadRequestException().getResponse(),
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    example: new UnauthorizedException().getResponse(),
  })
  async login(
    @Req() req: Request,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    @Body() body: LocalAuthDto,
  ): Promise<LocalAuthEntity> {
    const user = plainToInstance(UserEntity, req.user);

    // Get device information
    const userAgent = req.get('User-Agent');
    const ipAddress = req.ip || req.connection.remoteAddress;
    const deviceId = req.get('X-Device-ID'); // Optional header for device tracking

    const tokens = await this.authService.generateTokensWithSession(
      {
        _id: user._id,
        email: user.email,
      },
      {
        userAgent,
        ipAddress,
        deviceId,
        deviceName: userAgent
          ? await this.getDeviceName(userAgent)
          : 'Unknown Device',
      },
    );

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  private async getDeviceName(userAgent: string): Promise<string> {
    // Simple device detection - can be enhanced with a library like ua-parser-js
    if (
      userAgent.includes('Mobile') ||
      userAgent.includes('Android') ||
      userAgent.includes('iPhone')
    ) {
      return 'Mobile Device';
    } else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) {
      return 'Tablet';
    } else {
      return 'Desktop';
    }
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiOperation({ summary: 'Logout' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 201,
    description: 'Logged out successfully',
    example: { message: 'Logged out successfully' },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    example: new UnauthorizedException().getResponse(),
  })
  async logout(@Req() request: Request) {
    const authHeader = request.headers.authorization;
    const accessToken = authHeader?.split(' ')[1]; // Extract access token

    if (accessToken) {
      await this.authService.invalidateAccessToken(accessToken); // Blacklist the access token
    }

    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get user profile' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: UserEntity,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    example: new UnauthorizedException().getResponse(),
  })
  async getProfile(@Req() req) {
    const user = plainToInstance(UserEntity, req.user);
    return user;
  }

  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 201,
    description: 'Access token refreshed successfully',
    type: AccessTokenEntity,
    example: {
      accessToken:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI1MzRjNTU4NC1lYWI0LTRhNWItYTE0OC1iYTFiZTkxOTg2MWMiLCJlbWFpbCI6ImNhbWVyb25sdWNhc0BzaXRlaXRzb2x1dGlvbnMuY29tIiwiaWF0IjoxNzM2MTIxMzk3LCJleHAiOjE3MzYxMjMxOTd9.wjRpe3BZvIXC9EcPuV5buTHkkwnGdPZCNTMi2BtKNko',
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    example: new UnauthorizedException().getResponse(),
  })
  async refresh(
    @Req() req: Request,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const authHeader = req.headers['authorization'];
    const refreshToken = authHeader?.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : null;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    // Use refresh token rotation for enhanced security
    const tokens = await this.authService.refreshTokenWithRotation(
      refreshToken,
      {
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip || req.connection.remoteAddress,
      },
    );

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  @Post('register')
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 registrations per minute
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    type: UserEntity,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request',
    example: new BadRequestException().getResponse(),
  })
  async register(@Body() body: CreateUserDto): Promise<UserEntity | null> {
    return this.authService.register(body);
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  @ApiOperation({ summary: 'Get user active sessions' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 200,
    description: 'User sessions retrieved successfully',
    type: [SessionResponseDto],
  })
  async getUserSessions(@Req() req: Request): Promise<SessionResponseDto[]> {
    const user = plainToInstance(UserEntity, req.user);
    const sessions = await this.authService.getUserSessions(user._id);

    // Don't expose full refresh tokens, just metadata
    return sessions.map((session) => ({
      id: session._id,
      deviceName: session.deviceName,
      deviceId: session.deviceId,
      userAgent: session.userAgent,
      ipAddress: session.ipAddress,
      location: session.location,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
    }));
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  @ApiOperation({ summary: 'Logout from all devices' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 201,
    description: 'Logged out from all devices successfully',
  })
  async logoutAll(@Req() req: Request) {
    const user = plainToInstance(UserEntity, req.user);
    await this.authService.revokeAllUserSessions(user._id);
    return { message: 'Logged out from all devices successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-others')
  @ApiOperation({ summary: 'Logout from all other devices' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 201,
    description: 'Logged out from other devices successfully',
  })
  async logoutOthers(@Req() req: Request) {
    const user = plainToInstance(UserEntity, req.user);
    const authHeader = req.headers['authorization'];
    const currentToken = authHeader?.split(' ')[1];

    if (!currentToken) {
      throw new UnauthorizedException('Current token not found');
    }

    // Find current session to preserve it
    await this.authService.revokeOtherUserSessions(user._id, currentToken);

    return { message: 'Logged out from other devices successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('revoke-session')
  @ApiOperation({ summary: 'Revoke a specific session' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 201,
    description: 'Session revoked successfully',
  })
  async revokeSession(@Req() req: Request, @Body() body: RevokeSessionDto) {
    const user = plainToInstance(UserEntity, req.user);
    const sessions = await this.authService.getUserSessions(user._id);

    // Find the session to revoke
    const sessionToRevoke = sessions.find((s) => s._id === body.sessionId);
    if (!sessionToRevoke) {
      throw new UnauthorizedException('Session not found');
    }

    await this.authService.revokeSession(sessionToRevoke.refreshToken);
    return { message: 'Session revoked successfully' };
  }
}
