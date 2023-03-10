/* eslint-disable prettier/prettier */
import { IsEmail, IsNotEmpty, Length, IsString } from 'class-validator';

export class UserDTO {
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @IsString()
  @Length(6, 30, { message: 'Password should be between 6 - 30 characters.' })
  public password: string;
}
