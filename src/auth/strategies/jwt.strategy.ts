import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserEntity } from 'src/users/entities/user.entity';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
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

    return user;
  }
}
