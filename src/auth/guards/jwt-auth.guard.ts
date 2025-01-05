import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private jwtService: JwtService,
    private readonly authService: AuthService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<any> {
    const request: Request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('No access token provided');
    }

    if (await this.authService.isAccessTokenBlacklisted(token)) {
      throw new UnauthorizedException('Access token has been invalidated.');
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });

      if (!!payload) {
        return await super.canActivate(context);
      } else {
        throw new UnauthorizedException('Invalid or expired access token');
      }
    } catch {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }
}
