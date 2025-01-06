import { ApiResponseProperty } from '@nestjs/swagger';
import { AccessTokenEntity } from './access-token.entity';

export class LocalAuthEntity extends AccessTokenEntity {
  @ApiResponseProperty()
  refreshToken: string;
}
