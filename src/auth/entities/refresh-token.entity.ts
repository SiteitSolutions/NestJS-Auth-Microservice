import { ApiResponseProperty } from '@nestjs/swagger';

export class RefreshTokenEntity {
  @ApiResponseProperty()
  refreshToken: string;
}
