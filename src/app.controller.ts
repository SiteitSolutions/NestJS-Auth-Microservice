import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({
    status: 200,
    description: 'PONG',
    example: { ok: true, response: 'PONG' },
  })
  health(): { ok: boolean; response: string } {
    return { ok: true, response: 'PONG' };
  }
}
