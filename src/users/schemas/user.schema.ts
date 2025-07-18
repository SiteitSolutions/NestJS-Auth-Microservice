import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Query } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcryptjs';
import { Gender, UserRole } from '../enums/enums';

export type UserDocument = HydratedDocument<User & UserMethods>;

type UserMethods = {
  comparePassword(plaintextPassword: string): boolean;
  hashPassword(): void;
  isLocked(): boolean;
  incLoginAttempts(): Promise<UserDocument>;
  resetLoginAttempts(): Promise<UserDocument>;
};

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
    type: [String],
    enum: UserRole,
    default: [UserRole.USER],
  })
  roles: string[]; // Role for access control

  @Prop({ default: true })
  isActive: boolean; // Can be used for account activation status

  @Prop({ default: false })
  emailVerified: boolean; // Email verification status

  @Prop({ type: Date })
  lastLoginAt?: Date; // Track last login

  @Prop({ type: Number, default: 0 })
  loginAttempts: number; // Track failed login attempts

  @Prop({ type: Date })
  lockUntil?: Date; // Account lockout timestamp

  @Prop()
  profilePictureUrl?: string; // URL to profile picture

  @Prop({ type: Date, default: null })
  deletedAt: Date | null; // Soft delete timestamp
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.methods.comparePassword = function (
  plaintextPassword: string,
): boolean {
  return bcrypt.compareSync(plaintextPassword, this.password);
};

// Check if account is locked
UserSchema.methods.isLocked = function (): boolean {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Increment login attempts
UserSchema.methods.incLoginAttempts = function (): Promise<UserDocument> {
  const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
  const LOCK_TIME = parseInt(process.env.LOCKOUT_TIME || '900000'); // 15 minutes

  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 },
    });
  }

  const updates: any = { $inc: { loginAttempts: 1 } };

  // If we're already at max attempts and it's not locked, lock the account
  if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked()) {
    updates.$set = { lockUntil: Date.now() + LOCK_TIME };
  }

  return this.updateOne(updates);
};

// Reset login attempts
UserSchema.methods.resetLoginAttempts = function (): Promise<UserDocument> {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 },
    $set: { lastLoginAt: new Date() },
  });
};

// Middleware to hash password before save
UserSchema.pre<UserDocument>('save', async function (next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

// Middleware to hash password before update
UserSchema.pre('findOneAndUpdate', async function (next) {
  const update = this.getUpdate() as User;
  if (update?.password) {
    const salt = await bcrypt.genSalt(12);
    update.password = await bcrypt.hash(update.password, salt);
    this.setUpdate(update);
  }
  next();
});

// Add a query middleware to automatically filter out soft-deleted users
UserSchema.pre<Query<UserDocument, UserDocument>>(/^find/, function (next) {
  const filter = this.getQuery();
  if (!filter.includeDeleted) {
    this.setQuery({ ...filter, deletedAt: null });
  } else {
    // Remove the includeDeleted flag from the query
    delete filter.includeDeleted;
    this.setQuery({ ...filter });
  }
  next();
});
