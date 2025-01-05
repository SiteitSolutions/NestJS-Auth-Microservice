import { Injectable } from '@nestjs/common';
import { User, UserDocument } from './schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async create(userDto: CreateUserDto): Promise<UserDocument | null> {
    try {
      const user = new this.userModel(userDto);

      await user.save();

      return user;
    } catch (error) {
      console.error(error);
      return null;
    }
  }

  findOne(filter: object): Promise<UserDocument | undefined> {
    return this.userModel.findOne(filter);
  }
}
