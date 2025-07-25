import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import * as fs from 'fs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security headers
  app.use(helmet());

  // Enable CORS with security considerations
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Enable class-transformer globally with enhanced validation
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true, // Strip unknown properties
      forbidNonWhitelisted: true, // Throw error for unknown properties
      disableErrorMessages: process.env.NODE_ENV === 'production', // Hide validation details in production
    }),
  );

  // Enable cookie parser
  app.use(cookieParser());

  // Create logs directory if it doesn't exist
  if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs');
  }

  // Swagger setup - ONLY in development
  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Auth Microservice API')
      .setDescription(
        `Open-source authentication and authorization microservice API built with NestJS and PassportJS. This API is designed to provide robust user authentication and role-based access control (RBAC). It supports multiple authentication strategies such as JWT, Local, Google, Facebook, Twitter, GitHub, and more. The service uses MongoDB for data persistence and Redis for caching and token invalidation. It offers out-of-the-box support for: Local authentication for email and password-based logins. RBAC (Role-Based Access Control) for fine-grained permission management. JWT with token blacklisting to ensure compromised tokens can be invalidated. JWT refresh and access tokens for session management, ensuring minimal downtime and secure re-authentication. This microservice is highly customizable and provides endpoints for login, logout, access token refreshing, and protected resource management, making it ideal for integration into any scalable application.`,
      )
      .setVersion('1.0')
      .addBearerAuth()
      .addTag('auth')
      .addTag('sessions')
      .build();
    const documentFactory = () => SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, documentFactory);
  }

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
