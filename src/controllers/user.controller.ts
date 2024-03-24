import {
  Controller,
  Get,
  UseGuards,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from '../services/user.service';
import {
  AuthZGuard,
  AuthActionVerb,
  AuthPossession,
  UsePermissions,
  AuthZRBACService,
} from 'nest-authz';

import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';

import { Resource } from '../resources';

import { Request } from 'express';

@ApiTags('User')
@ApiBearerAuth()
@Controller()
export class UserController {
  constructor(
    private readonly usersSrv: UserService,
    private readonly rbacSrv: AuthZRBACService) {}

  @ApiOperation({
    summary: 'Find all users',
  })
  @Get('users')
  @UseGuards(AuthGuard(), AuthZGuard)
  @UsePermissions({
    action: AuthActionVerb.READ,
    resource: Resource.USERS_LIST,
    possession: AuthPossession.ANY,
  })
  async findUsers() {
    return await this.usersSrv.findAll();
  }

  @ApiOperation({
    summary: 'Get own info',
  })
  @Get('users/me')
  @UseGuards(AuthGuard())
  async printCurrentUser(@Req() request: Request) {
    return request.user;
  }

  @ApiOperation({
    summary: 'Find all users, inject and use `AuthzRBACService`',
  })
  @UseGuards(AuthGuard())
  @Get('all-users')
  async findAllUsers(@Req() request: Request<any>) {
    let username = request.user['username'];
    // There is a policy  `p, root, user, read:any` in policy.csv
    // thus user root can do this operation
    const isPermitted = await this.rbacSrv.hasPermissionForUser(username, "user", "read:any");
    if (!isPermitted) {
      throw new UnauthorizedException(
        'You are not authorized to read users list'
      );
    }
    // A user can not reach this point if he/she is not granted for permission read users
    return await this.usersSrv.findAll();
  }
}
