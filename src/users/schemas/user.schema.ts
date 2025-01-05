import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcryptjs';
import { Gender, UserRole } from '../enums/enums';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
  @Prop({
    type: String, // UUID is a string
    default: uuidv4, // Automatically generate a new UUID
  })
  _id: string; // MongoDB ID will be a UUID string

  @Prop({
    type: String,
    required: true,
    unique: true, // Enforce unique emails
  })
  email: string; // User's email

  @Prop({ type: String, required: true })
  password: string; // Store the hashed password

  @Prop({ type: String, required: true })
  givenName: string; // First name (Google style)

  @Prop({ type: String, required: true })
  familyName: string; // Last name (Google style)

  @Prop({ type: String })
  middleName?: string; // Optional middle name

  @Prop({
    type: String,
    enum: Gender,
    required: false,
  })
  gender?: string; // Optional gender

  @Prop({ type: Date })
  birthDate?: Date; // Optional birth date

  @Prop({
    type: String,
    enum: UserRole,
    default: UserRole.USER,
  })
  role: string; // Role for access control

  @Prop({ default: true })
  isActive: boolean; // Can be used for account activation status

  @Prop()
  profilePictureUrl?: string; // URL to profile picture

  async hashPassword(): Promise<void> {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  }

  async comparePassword(plaintextPassword: string): Promise<boolean> {
    return bcrypt.compare(plaintextPassword, this.password);
  }
}

export const UserSchema = SchemaFactory.createForClass(User);

// Middleware to hash password before save
UserSchema.pre<UserDocument>('save', async function (next) {
  if (this.isModified('password')) {
    await this.hashPassword();
  }
  next();
});
