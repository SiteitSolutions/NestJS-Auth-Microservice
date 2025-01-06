import { Exclude } from 'class-transformer';
import { Gender, UserRole } from '../enums/enums';
import { ApiResponseProperty } from '@nestjs/swagger';

export class UserEntity {
  @ApiResponseProperty()
  _id: string;

  @ApiResponseProperty()
  email: string;

  @Exclude() // Exclude the password from responses
  password: string;

  @ApiResponseProperty()
  givenName: string;

  @ApiResponseProperty()
  familyName: string;

  @ApiResponseProperty()
  middleName?: string;

  @ApiResponseProperty()
  gender?: Gender;

  @ApiResponseProperty()
  birthDate?: Date;

  @ApiResponseProperty()
  roles: UserRole[];

  @ApiResponseProperty()
  isActive: boolean;

  @ApiResponseProperty()
  profilePictureUrl?: string;

  constructor(partial: Partial<UserEntity>) {
    Object.assign(this, partial); // Populate the class instance with the object properties
  }
}
