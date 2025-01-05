import { Body, Controller, Param, Post, UseGuards } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Post(':id')
  async update(@Param('id') id: string, @Body() body: UpdateUserDto) {
    return this.userService.update(body, id);
  }
}
