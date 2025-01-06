import { ApiProperty } from '@nestjs/swagger';

export class LocalAuthDto {
  @ApiProperty({
    description: 'User email',
    example: 'johndoe@example.com',
    required: true,
  })
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'password123',
    required: true,
    maxLength: 8,
  })
  password: string;
}
