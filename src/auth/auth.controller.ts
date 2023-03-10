import { UserDTO } from './../dto/user.dto';
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup() {
    return await this.authService.signup();
  }

  @Post('signin')
  async signin(@Body() data: UserDTO) {
    return await this.authService.signin(data);
  }
}
