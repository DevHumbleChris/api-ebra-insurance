/* eslint-disable prettier/prettier */
import { jwtSecret } from './../utils/constants';
import { UserDTO } from './../dto/user.dto';
import { PrismaService } from './../../prisma/prisma.service';
import { BadRequestException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}
  async signup(data: UserDTO) {
    const { email, password } = data;

    // Check if user exists.
    const user = await this.getUserByEmail(email);

    if (user) {
      throw new BadRequestException('Email Already Exits!');
    }

    // Hashed Password.
    const hashedPassword = await this.hashPassword(password);

    // access token.
    const accessToken = await this.signTokens({ email })

    // todo: Create new user.

    return {
      hashedPassword,
      accessToken,
    }
  }

  async signin(data: UserDTO) {
    const { email, password } = data;

    // Check if user exists.
    const user = await this.getUserByEmail(email);

    if (!user) {
      throw new BadRequestException("Email Doesn't Exits!");
    }

    // Check Password is correct.
    const isPasswordCorrect = await this.checkPasswordMatch({
      password,
      hashedPassword: user.password,
    });

    if (!isPasswordCorrect) {
      throw new BadRequestException('Password is incorrect!');
    }

    return 'Signed in routed';
  }

  // Get User By Email.
  async getUserByEmail(email: string): Promise<User | null | undefined> {
    return await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
  }

  // Hash Password.
  async hashPassword(password): Promise<string> {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  }

  // Sign Tokens.
  async signTokens(args: { email: string }): Promise<string> {
    return await this.jwtService.sign(
      { email: args.email },
      {
        secret: jwtSecret,
      },
    );
  }

  // Check if password matches.
  async checkPasswordMatch(args: {
    password: string;
    hashedPassword: string;
  }): Promise<boolean> {
    return await bcrypt.compare(args.password, args.hashedPassword);
  }

  // Create New User.
  async createNewUser(args: {
    email: string;
    password: string;
    accessToken: string;
  }): Promise<User> {
    return await this.prisma.user.create({
      data: {
        email: args.email,
        password: args.password,
        accessToken: args.accessToken,
      },
    });
  }
}
