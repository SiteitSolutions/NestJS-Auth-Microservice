import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as winston from 'winston';

@Injectable()
export class LoggingService {
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
      ),
      defaultMeta: { service: 'auth-microservice' },
      transports: [
        new winston.transports.File({
          filename: 'logs/error.log',
          level: 'error',
        }),
        new winston.transports.File({
          filename: 'logs/combined.log',
        }),
      ],
    });

    // Add console transport for development
    if (process.env.NODE_ENV !== 'production') {
      this.logger.add(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple(),
          ),
        }),
      );
    }
  }

  info(message: string, meta?: any) {
    this.logger.info(message, meta);
  }

  error(message: string, meta?: any) {
    this.logger.error(message, meta);
  }

  warn(message: string, meta?: any) {
    this.logger.warn(message, meta);
  }

  debug(message: string, meta?: any) {
    this.logger.debug(message, meta);
  }

  logAuthAttempt(
    email: string,
    success: boolean,
    ip: string,
    userAgent?: string,
  ) {
    this.info('Authentication attempt', {
      email,
      success,
      ip,
      userAgent,
      timestamp: new Date().toISOString(),
    });
  }

  logSecurityEvent(event: string, details: any) {
    this.warn(`Security event: ${event}`, {
      ...details,
      timestamp: new Date().toISOString(),
    });
  }
}

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  constructor(private loggingService: LoggingService) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    const { method, originalUrl, ip } = req;
    const userAgent = req.get('User-Agent') || '';

    // Log request
    this.loggingService.info('HTTP Request', {
      method,
      url: originalUrl,
      ip,
      userAgent,
      timestamp: new Date().toISOString(),
    });

    // Override res.end to log response
    const originalEnd = res.end;
    res.end = function (...args: any[]) {
      const duration = Date.now() - startTime;

      // Don't log response body for security reasons, just metadata
      this.loggingService.info('HTTP Response', {
        method,
        url: originalUrl,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        ip,
        timestamp: new Date().toISOString(),
      });

      originalEnd.apply(res, args);
    }.bind(this);

    next();
  }
}
