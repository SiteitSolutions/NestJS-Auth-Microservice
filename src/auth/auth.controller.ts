import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { Request, Response } from 'express';
import { UserEntity } from 'src/users/entities/user.entity';
import { plainToInstance } from 'class-transformer';
import { Roles } from './decorators/role.decorator';
import { UserRole } from 'src/users/enums/enums';
import { RolesGuard } from './guards/roles.guard';
import {
  ApiBearerAuth,
  ApiCookieAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { AccessTokenEntity } from './entities/access-token.entity';
import { LocalAuthDto } from './dto/local-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({
    status: 201,
    description: 'Login successful',
    type: AccessTokenEntity,
    example: {
      accessToken:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI1MzRjNTU4NC1lYWI0LTRhNWItYTE0OC1iYTFiZTkxOTg2MWMiLCJlbWFpbCI6ImNhbWVyb25sdWNhc0BzaXRlaXRzb2x1dGlvbnMuY29tIiwiaWF0IjoxNzM2MTIxMzk3LCJleHAiOjE3MzYxMjMxOTd9.wjRpe3BZvIXC9EcPuV5buTHkkwnGdPZCNTMi2BtKNko',
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
    @Res({ passthrough: true }) res: Response,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    @Body() body: LocalAuthDto,
  ): Promise<{ accessToken: string }> {
    const user = plainToInstance(UserEntity, req.user);
    const tokens = await this.authService.generateTokens({
      _id: user._id,
      email: user.email,
    });

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true, // Prevent access by JavaScript
      secure: process.env.NODE_ENV === 'production', // Only HTTPS in production
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return { accessToken: tokens.accessToken };
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
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const authHeader = request.headers.authorization;
    const accessToken = authHeader?.split(' ')[1]; // Extract access token

    if (accessToken) {
      await this.authService.invalidateAccessToken(accessToken); // Blacklist the access token
    }

    // Clear the refresh token cookie
    response.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.USER)
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
  @ApiCookieAuth('refreshToken')
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
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies['refreshToken'];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const payload = await this.authService.verifyRefreshToken(refreshToken);
    const tokens = await this.authService.generateTokens({
      _id: payload._id,
      email: payload.email,
    });

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { accessToken: tokens.accessToken };
  }

  @Post('register')
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
