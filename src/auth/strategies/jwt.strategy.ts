import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { UserEntity } from 'src/users/entities/user.entity';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: async (request, token, done) => {
        if (await this.authService.isAccessTokenBlacklisted(token)) {
          return done(
            new UnauthorizedException('Access token has been invalidated.'),
            null,
          );
        }

        return done(null, process.env.JWT_SECRET);
      },
    });
  }

  async validate(payload: any): Promise<UserEntity | null> {
    const user = await this.authService.validateJwt(payload);

    if (!user) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    // Validate session if sessionId is present in the token
    if (payload.sessionId) {
      const isSessionValid = await this.authService.validateSession(
        payload.sessionId,
      );
      
      if (!isSessionValid) {
        throw new UnauthorizedException('Session has been revoked or expired');
      }

      // Update session last used timestamp
      try {
        await this.authService.updateSessionLastUsed(payload.sessionId);
      } catch (error) {
        // Log error but don't fail authentication - session tracking is not critical
        this.logger.error('Failed to update session last used:', error);
      }
    } else {
      // For older tokens without sessionId, check environment configuration
      const requireSessionId = process.env.REQUIRE_SESSION_ID === 'true';
      
      if (requireSessionId) {
        throw new UnauthorizedException(
          'Access token must contain session information. Please re-authenticate.',
        );
      }
      
      // Log warning for monitoring purposes
      this.logger.warn(
        'Access token without sessionId detected - consider forcing re-authentication',
        { userId: payload._id, email: payload.email },
      );
    }

    return user;
  }
}
