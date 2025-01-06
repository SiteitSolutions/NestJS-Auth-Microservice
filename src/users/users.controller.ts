import {
  Body,
  Controller,
  Delete,
  Param,
  Patch,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { UserEntity } from './entities/user.entity';
import { Request } from 'express';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  @ApiOperation({ summary: 'Update user' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 201,
    description: 'The user has been successfully updated.',
    type: UserEntity,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    example: new UnauthorizedException().getResponse(),
  })
  async update(
    @Param('id') id: string,
    @Body() body: UpdateUserDto,
    @Req() req: Request,
  ): Promise<UserEntity> {
    if ((req.user as UserEntity)._id !== id) {
      throw new UnauthorizedException();
    }
    return this.userService.update(body, id);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  @ApiOperation({ summary: 'Delete user' })
  @ApiBearerAuth()
  @ApiResponse({
    status: 200,
    description: 'The user has been successfully deleted.',
    type: UserEntity,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
    example: new UnauthorizedException().getResponse(),
  })
  async remove(
    @Param('id') id: string,
    @Req() req: Request,
  ): Promise<UserEntity> {
    if ((req.user as UserEntity)._id !== id) {
      throw new UnauthorizedException();
    }
    return this.userService.remove(id);
  }
}
