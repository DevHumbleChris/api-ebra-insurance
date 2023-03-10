import { PrismaService } from './../../prisma/prisma.service';
import { Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private prisma: PrismaService,
  ) {}

  @Post('signup')
  async signup() {
    return await this.authService.signup();
  }

  @Post('signin')
  async signin() {
    return await this.authService.signin();
  }
}
