import { UserDTO } from './../dto/user.dto';
import { PrismaService } from './../../prisma/prisma.service';
import { BadRequestException, Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup() {
    return 'Signed up route';
  }

  async signin(data: UserDTO) {
    const { email, password } = data;

    // Check if user exists.
    const user = await this.getUserByEmail(email);

    if (!user) {
      throw new BadRequestException("Email Doesn't Exits!");
    }

    return 'Signed in routed';
  }

  async getUserByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
  }
}
