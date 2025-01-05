import { Exclude } from 'class-transformer';
import { Gender, UserRole } from '../enums/enums';

export class UserEntity {
  _id: string;
  email: string;

  @Exclude() // Exclude the password from responses
  password: string;

  givenName: string;
  familyName: string;
  middleName?: string;
  gender?: Gender;
  birthDate?: Date;
  role: UserRole;
  isActive: boolean;
  profilePictureUrl?: string;

  constructor(partial: Partial<UserEntity>) {
    Object.assign(this, partial); // Populate the class instance with the object properties
  }
}
