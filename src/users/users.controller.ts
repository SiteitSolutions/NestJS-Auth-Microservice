import {
  Body,
  Controller,
  Param,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { UserEntity } from './entities/user.entity';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Post(':id')
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
  ): Promise<UserEntity> {
    return this.userService.update(body, id);
  }
}
