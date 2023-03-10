import { UserDTO } from './../dto/user.dto';
import { PrismaService } from './../../prisma/prisma.service';
import { BadRequestException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(data: UserDTO) {
    const { email, password } = data;

    // Check if user exists.
    const user = await this.getUserByEmail(email);

    if (user) {
      throw new BadRequestException('Email Already Exits!');
    }

    const hashedPassword = await this.hashPassword(password);

    return hashedPassword;
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

  // Get User By Email.
  async getUserByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
  }

  // Hash Password.
  async hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  }
}
