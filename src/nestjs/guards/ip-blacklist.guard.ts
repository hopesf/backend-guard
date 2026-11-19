import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
} from "@nestjs/common";

import { createIpMatcher, type IpMatcher } from "../../core/ip";
import type { BackendGuardOptions } from "../../types";
import { BACKEND_GUARD_OPTIONS } from "../nestjs.constants";

/**
 * Guard that blocks requests from IP addresses in the blacklist.
 *
 * Registered as APP_GUARD so it runs globally before any route handler.
 * Reads client IP from req.ip (Express populates this from X-Forwarded-For
 * when trust proxy is enabled, or from the socket address otherwise).
 *
 * @example
 * // Activated automatically when ipBlacklist option is set:
 * BackendGuardModule.forRoot({ ipBlacklist: ["1.2.3.4", "5.6.7.8"] })
 */
@Injectable()
export class IpBlacklistGuard implements CanActivate {
  // Set<string> for O(1) lookups — much faster than Array.includes()
  private readonly isBlocked: IpMatcher;

  constructor(
    @Inject(BACKEND_GUARD_OPTIONS)
    options: BackendGuardOptions,
  ) {
    this.isBlocked = createIpMatcher(options.ipBlacklist ?? []);
  }

  canActivate(context: ExecutionContext): boolean {
    const req = context
      .switchToHttp()
      .getRequest<{ ip?: string; socket?: { remoteAddress?: string } }>();

    if (this.isBlocked(req.ip ?? req.socket?.remoteAddress)) {
      throw new ForbiddenException("Your IP address has been blocked.");
    }

    return true;
  }
}
