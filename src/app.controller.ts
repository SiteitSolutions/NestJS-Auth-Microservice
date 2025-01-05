import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  health(): { ok: boolean; response: string } {
    return { ok: true, response: 'PONG' };
  }
}
