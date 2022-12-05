import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signUp(dto: AuthDto) {
    const hash = await argon.hash(dto.password);
    try {
      const userData = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete userData.hash;
      return userData;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email Exist');
        }
      }
      throw error;
    }
  }
  async signIn(dto: AuthDto) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
         email: dto.email
        },
      });
      if (!user) throw new ForbiddenException('No Email');
      const pwMatches = await argon.verify(user.hash, dto.password);

      if (!pwMatches) throw new ForbiddenException('Wrong Password');
      delete user.hash;
      return user;
    } catch (e) {
      throw new ForbiddenException(`${e}`);
    }
  }
}
