import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { plainToClass, plainToInstance } from 'class-transformer';
import e from 'express';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UserEntity } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<UserEntity | null> {
    const userDocument = await this.usersService.findOne({ email });

    if (userDocument && userDocument.comparePassword(pass)) {
      return plainToInstance(UserEntity, userDocument.toObject());
    }

    return null;
  }

  async validateJwt(payload: any): Promise<UserEntity | null> {
    const userDocument = await this.usersService.findOne({
      _id: payload._id,
      email: payload.email,
    });

    if (userDocument) {
      return plainToInstance(UserEntity, userDocument.toObject());
    }

    return null;
  }

  async login(user: UserEntity): Promise<{ access_token: string }> {
    return {
      access_token: this.jwtService.sign(
        { _id: user._id, email: user.email },
        { expiresIn: '1d' },
      ),
    };
  }

  async register(body: CreateUserDto): Promise<UserEntity | null> {
    const userDocument = await this.usersService.create(body);

    if (userDocument) {
      return plainToClass(UserEntity, userDocument.toObject());
    }

    return null;
  }
}
