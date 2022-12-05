import { Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';
import * as argon from 'argon2';
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signIn(dto: AuthDto) {
    const hash = await argon.hash(dto.password);
    const userData = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
    delete userData.hash;
    return userData;
  }
  signUp() {
    return { msg: 'I Have Sign Up' };
  }
}
