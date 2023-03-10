import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  async signup() {
    return 'Signed up route';
  }

  async signin() {
    return 'Signed in routed';
  }
}
