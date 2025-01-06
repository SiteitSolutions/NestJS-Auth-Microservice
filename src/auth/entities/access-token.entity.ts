import { ApiResponseProperty } from '@nestjs/swagger';

export class AccessTokenEntity {
  @ApiResponseProperty()
  accessToken: string;
}
