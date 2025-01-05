import {
  IsEmail,
  IsString,
  IsOptional,
  IsEnum,
  MinLength,
  IsArray,
} from 'class-validator';
import { UserRole, Gender } from '../enums/enums';

export class CreateUserDto {
  @IsEmail()
  email: string; // User's unique email address

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long.' })
  password: string; // User's password

  @IsString()
  givenName: string; // First name of the user

  @IsString()
  familyName: string; // Last name of the user

  @IsOptional()
  @IsString()
  middleName?: string; // Middle name (optional)

  @IsOptional()
  @IsEnum(Gender, {
    message: 'Gender must be male, female, non-binary, or other.',
  })
  gender?: Gender; // User's gender (optional)

  @IsOptional()
  birthDate?: Date; // Birth date of the user (optional)

  @IsOptional()
  @IsArray()
  @IsEnum(UserRole, {
    each: true,
    message: 'Each role must be one of user, admin, or moderator.',
  })
  roles?: UserRole[]; // Array of user roles (optional, default: ['user'])

  @IsOptional()
  @IsString()
  profilePictureUrl?: string; // URL to the user's profile picture (optional)
}
