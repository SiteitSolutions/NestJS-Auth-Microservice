import {
  IsEmail,
  IsString,
  IsOptional,
  IsEnum,
  MinLength,
  IsArray,
  Matches,
} from 'class-validator';
import { UserRole, Gender } from '../enums/enums';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateUserDto {
  @IsEmail()
  @ApiProperty({
    description: 'User email address',
    example: 'johndoe@example.com',
    required: true,
  })
  email: string; // User's unique email address

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
  password: string; // User's password

  @IsString()
  @ApiProperty({
    description: 'User first name',
    example: 'John',
    required: true,
  })
  givenName: string; // First name of the user

  @IsString()
  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    required: true,
  })
  familyName: string; // Last name of the user

  @IsOptional()
  @IsString()
  @ApiPropertyOptional({
    description: 'User middle name',
    example: 'Smith',
    required: false,
  })
  middleName?: string; // Middle name (optional)

  @IsOptional()
  @IsEnum(Gender, {
    message: 'Gender must be male, female, non-binary, or other.',
  })
  @ApiPropertyOptional({
    description: "User's gender",
    example: Gender.NON_BINARY,
    type: String,
    enum: Gender,
  })
  gender?: Gender; // User's gender (optional)

  @IsOptional()
  @ApiPropertyOptional({
    description: 'User birth date',
    example: '1990-01-01',
    required: false,
  })
  birthDate?: Date; // Birth date of the user (optional)

  @IsOptional()
  @IsArray()
  @IsEnum(UserRole, {
    each: true,
    message: 'Each role must be one of user, admin, or moderator.',
  })
  @ApiPropertyOptional({
    description: 'User roles',
    example: [UserRole.USER],
    required: false,
    type: [String],
    enum: UserRole,
    default: [UserRole.USER],
  })
  roles?: UserRole[]; // Array of user roles (optional, default: ['user'])

  @IsOptional()
  @IsString()
  @ApiPropertyOptional({
    description: 'URL to the user profile picture',
    example: 'https://via.placeholder.com/150x150',
    required: false,
  })
  profilePictureUrl?: string; // URL to the user's profile picture (optional)
}
