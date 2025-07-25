import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { CacheModule, CacheStore } from '@nestjs/cache-manager';
import { redisStore } from 'cache-manager-redis-yet';
import { JwtModule } from '@nestjs/jwt';
import { RequestLoggingMiddleware } from './common/services/logging.service';
import { ScheduleModule } from '@nestjs/schedule';
import { SessionCleanupService } from './tasks/session-cleanup.service';

@Module({
  imports: [
    ConfigModule.forRoot(),
    ScheduleModule.forRoot(),
    MongooseModule.forRoot(process.env.MONGO_URI),
    CacheModule.registerAsync({
      useFactory: async () => {
        const store = await redisStore({
          socket: {
            host: process.env.REDIS_HOST ?? 'localhost',
            port: parseInt(process.env.REDIS_PORT ?? '6379'),
          },
        });

        return {
          store: store as unknown as CacheStore,
          ttl: parseInt(process.env.REDIS_TTL ?? '900_000'),
        };
      },
      isGlobal: true,
    }),
    JwtModule.register({ global: true }),
    UsersModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService, SessionCleanupService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestLoggingMiddleware).forRoutes('*');
  }
}
