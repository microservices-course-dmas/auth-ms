import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayloadI } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger("Auth Service");

    constructor(
        private jwtService: JwtService
    ) {
        super();
    }


    onModuleInit() {
        this.$connect();
        this.logger.log(`Mongo connected`);
    }


    async signJwt(payload: JwtPayloadI) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerDto: RegisterUserDto) {
        const { email, password, name } = registerDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (user) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'User already exists.'
                })
            }

            const newUser = await this.user.create({
                data: {
                    ...registerDto,
                    password: bcrypt.hashSync(password, 10)
                }
            });

            const { password: __, ...rest } = newUser;

            return {
                user: {
                    ...rest
                },
                jwt: await this.signJwt(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: HttpStatus.BAD_REQUEST,
                message: error.message
            })
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (!user) {
                throw new RpcException({
                    status: HttpStatus.UNAUTHORIZED,
                    message: 'User or password not valid'
                })
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password)

            if (!isPasswordValid) {
                throw new RpcException({
                    status: HttpStatus.UNAUTHORIZED,
                    message: 'User or password not valid'
                })
            }
            const { password: __, ...rest } = user;

            return {
                user: {
                    ...rest
                },
                jwt: await this.signJwt(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: HttpStatus.BAD_REQUEST,
                message: error.message
            })
        }
    }

    async verifyUser(token: string) {
        try {
            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            });
            return {
                user,
                token: await this.signJwt(user)
            }

        } catch (error) {
            console.log(error);
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: error.message
            })
        }
    }

}
