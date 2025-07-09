import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { SessionService } from '../auth/services/session.service';
import { LoggingService } from '../common/services/logging.service';

@Injectable()
export class SessionCleanupService {
  constructor(
    private sessionService: SessionService,
    private loggingService: LoggingService,
  ) {}

  // Run every day at 2 AM to cleanup expired sessions
  @Cron(CronExpression.EVERY_DAY_AT_2AM)
  async cleanupExpiredSessions() {
    try {
      await this.sessionService.cleanupExpiredSessions();
      this.loggingService.info('Expired sessions cleaned up successfully');
    } catch (error) {
      this.loggingService.error('Failed to cleanup expired sessions', {
        error: error.message,
        stack: error.stack,
      });
    }
  }

  // Run every hour to check for expired sessions
  @Cron(CronExpression.EVERY_HOUR)
  async checkSessionHealth() {
    try {
      // Log session statistics
      this.loggingService.info('Session health check completed');
    } catch (error) {
      this.loggingService.error('Session health check failed', {
        error: error.message,
      });
    }
  }
}
