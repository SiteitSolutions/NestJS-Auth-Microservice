import { BadRequestException, Injectable } from '@nestjs/common';
import { User, UserDocument } from './schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserEntity } from './entities/user.entity';
import { plainToInstance } from 'class-transformer';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async create(userDto: CreateUserDto): Promise<UserDocument | null> {
    try {
      const existingUser = await this.findOne({ email: userDto.email });

      if (existingUser) {
        throw new BadRequestException('A user with that email already exists.');
      }

      const user = new this.userModel(userDto);

      await user.save();

      return user;
    } catch (error) {
      console.error(error);
      throw new BadRequestException(error.message);
    }
  }

  async update(
    updateUserDto: UpdateUserDto,
    id: string,
  ): Promise<UserEntity | null> {
    try {
      const updatedUser = await this.userModel.findByIdAndUpdate(
        id,
        updateUserDto,
        {
          new: true,
        },
      );

      if (!updatedUser) {
        throw new BadRequestException('Unable to find and update user.');
      }

      return plainToInstance(UserEntity, updatedUser.toObject());
    } catch (error) {
      console.error(error);
      throw new BadRequestException(error.message);
    }
  }

  findOne(filter: object): Promise<UserDocument | undefined> {
    try {
      return this.userModel.findOne(filter);
    } catch (error) {
      console.error(error);
      throw new BadRequestException(error.message);
    }
  }
}
