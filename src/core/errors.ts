/** Why a call failed, in terms an operator (or a model) can act on. */
export type ErrorKind = 'policy' | 'auth' | 'timeout' | 'connect' | 'not-found' | 'device' | 'busy' | 'config' | 'internal';

/** The command or argument was refused by the read-only policy (deny-by-default). Never reaches a device. */
export class PolicyDenied extends Error {
  readonly kind: ErrorKind = 'policy';
  constructor(message: string) { super(message); this.name = 'PolicyDenied'; }
}

/** The device could not be located in the inventory (unknown or ambiguous reference). */
export class DeviceNotFound extends Error {
  readonly kind: ErrorKind = 'not-found';
  constructor(message: string) { super(message); this.name = 'DeviceNotFound'; }
}

/** TCP/TLS connection failed before any login was attempted: the only case that may fall back to an alternate path. */
export class ConnectError extends Error {
  readonly kind: ErrorKind = 'connect';
  constructor(message: string) { super(message); this.name = 'ConnectError'; }
}

/** The device rejected the credentials. Never retried automatically (account lock-out protection). */
export class LoginDeniedError extends Error {
  readonly kind: ErrorKind = 'auth';
  constructor(message = 'login denied by device') { super(message); this.name = 'LoginDeniedError'; }
}

export class DeviceTimeout extends Error {
  readonly kind: ErrorKind = 'timeout';
  constructor(message: string) { super(message); this.name = 'DeviceTimeout'; }
}

export class BusyError extends Error {
  readonly kind: ErrorKind = 'busy';
  constructor(message: string) { super(message); this.name = 'BusyError'; }
}

export function errorKindOf(e: unknown): ErrorKind {
  if (e && typeof e === 'object' && 'kind' in e && typeof (e as { kind: unknown }).kind === 'string') return (e as { kind: ErrorKind }).kind;
  return 'device';
}

/** An established session died (peer reset, idle cut by NAT…). The pool replaces a stale session once. */
export class ConnectionLostError extends Error {
  readonly kind: ErrorKind = 'device';
  constructor(message: string) { super(message); this.name = 'ConnectionLostError'; }
}
