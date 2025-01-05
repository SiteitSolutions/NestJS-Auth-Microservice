import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Cache } from 'cache-manager';
import { plainToClass, plainToInstance } from 'class-transformer';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UserEntity } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  // Generate Access and Refresh Tokens
  async generateTokens(
    payload: any,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '30m', // Short-lived access token (30 minutes)
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.REFRESH_TOKEN_SECRET,
      expiresIn: '7d', // Long-lived refresh token (7 days)
    });

    return { accessToken, refreshToken };
  }

  // Verify Refresh Token
  async verifyRefreshToken(
    token: string,
  ): Promise<{ _id: string; email: string }> {
    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.REFRESH_TOKEN_SECRET,
      });
      return payload;
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async validateUser(email: string, pass: string): Promise<UserEntity | null> {
    const userDocument = await this.usersService.findOne({ email });

    if (userDocument && userDocument.comparePassword(pass)) {
      return plainToInstance(UserEntity, userDocument.toObject());
    }

    return null;
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
      return plainToClass(UserEntity, userDocument.toObject());
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
}
