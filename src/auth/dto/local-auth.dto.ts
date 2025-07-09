import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches, MinLength } from 'class-validator';

export class LocalAuthDto {
  @IsEmail()
  @ApiProperty({
    description: 'User email address',
    example: 'johndoe@example.com',
    required: true,
  })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long.' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
  })
  @ApiProperty({
    description: 'User password (must meet complexity requirements)',
    example: 'Password123!',
    required: true,
    minLength: 8,
  })
  password: string;
}
