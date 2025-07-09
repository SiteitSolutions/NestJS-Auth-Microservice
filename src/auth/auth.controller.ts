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
    const tokens = await this.authService.generateTokens({
      _id: user._id,
      email: user.email,
    });

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
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
  async refresh(@Req() req: Request): Promise<{ accessToken: string }> {
    const authHeader = req.headers['authorization'];
    const refreshToken = authHeader?.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : null;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    // Check if the refresh token is blacklisted
    const isBlacklisted =
      await this.authService.isAccessTokenBlacklisted(refreshToken);
    if (isBlacklisted) {
      throw new UnauthorizedException(
        'Refresh token has been invalidated. Please log in again.',
      );
    }

    const payload = await this.authService.verifyRefreshToken(refreshToken);
    const tokens = await this.authService.generateTokens({
      _id: payload._id,
      email: payload.email,
    });

    return { accessToken: tokens.accessToken };
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
}
