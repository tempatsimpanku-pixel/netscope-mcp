import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SshOutcome, SshRunner, SshTarget } from './types.js';

/** SSH (used only for `export hide-sensitive`) through the OpenSSH client with a persistent control master.
 *
 * Host keys are ALWAYS checked: either pinned by SHA-256 fingerprint (the key is fetched with ssh-keyscan, compared, and only then
 * written to a per-device known_hosts file used with StrictHostKeyChecking=yes), or trust-on-first-use (`accept-new`) in the state
 * directory. `StrictHostKeyChecking=no` and `/dev/null` known_hosts never appear.
 *
 * Authentication: a private key file is preferred. Otherwise the password is handed to OpenSSH through `SSH_ASKPASS` (OpenSSH >= 8.4,
 * `SSH_ASKPASS_REQUIRE=force`): a tiny fixed helper script in the private state directory prints the password from the environment
 * of the ssh child, and only when the prompt asks for a password. The password never appears in argv (so not in /proc/<pid>/cmdline),
 * never on disk, and no `sshpass` binary is needed. The environment of a process is readable only by its own user (and root). */

export const SSH_PERSIST_S = 45;
/** Name of the environment variable that carries the password to the askpass helper (child process only). */
export const ASKPASS_ENV = 'NETSCOPE_SSH_PASSWORD';
const ASKPASS_SCRIPT = `#!/bin/sh
# netscope-mcp askpass helper: answers a password prompt only, from the environment of the ssh child. Holds no secret itself.
case "$1" in
  *[Pp]assword*) [ -n "$${ASKPASS_ENV}" ] || exit 1; printf '%s\\n' "$${ASKPASS_ENV}" ;;
  *) exit 1 ;;
esac
`;
/** Create (or refresh) the helper inside the private state directory; returns its path. */
export function ensureAskpass(dir: string): string {
  const file = path.join(dir, 'askpass.sh');
  let current = '';
  try { current = fs.readFileSync(file, 'utf8'); } catch { /* not there yet */ }
  if (current !== ASKPASS_SCRIPT) { fs.rmSync(file, { force: true }); fs.writeFileSync(file, ASKPASS_SCRIPT, { mode: 0o700 }); }
  fs.chmodSync(file, 0o700);
  return file;
}
export interface SshOptions {
  /** Directory (mode 0700) holding known_hosts, pinned host keys and control sockets. */
  stateDir?: string;
  persistSeconds?: number;
  connectTimeoutS?: number;
  /** Test hook: run a binary. */
  exec?: (file: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs: number) => Promise<SshOutcome>;
}

/** SHA-256 fingerprint of an OpenSSH public key line (`host type base64 [comment]`), formatted `SHA256:<base64 no padding>`. */
export function sshKeyFingerprint(line: string): string | null {
  const parts = line.trim().split(/\s+/);
  const blob = parts.find((p, i) => i >= 1 && /^[A-Za-z0-9+/]{20,}={0,2}$/.test(p) && !/^(ssh-|ecdsa-|sk-)/.test(p));
  if (!blob) return null;
  return `SHA256:${createHash('sha256').update(Buffer.from(blob, 'base64')).digest('base64').replace(/=+$/, '')}`;
}
const normPin = (p: string) => (p.startsWith('SHA256:') ? p : `SHA256:${p}`).replace(/=+$/, '');

function defaultStateDir(): string { return path.join(os.tmpdir(), `netscope-ssh-${process.getuid?.() ?? 0}`); }

/** Max length of the control directory: ControlPath = `<dir>/<40 hex %C>` and OpenSSH appends `.` + 16 random chars while binding;
 * a unix socket path must stay under 108 bytes, so 108 - 1 - 40 - 17 - 1 (NUL) = 49. */
export const MAX_CONTROL_DIR = 49;

/** A short, private directory for the ControlMaster sockets (independent of how long `state_dir` is). */
export function controlDirFor(stateDir: string): string {
  const uid = process.getuid?.() ?? 0;
  const tag = createHash('sha256').update(stateDir).digest('hex').slice(0, 8);
  const candidates = [process.env.XDG_RUNTIME_DIR, '/tmp', os.tmpdir()].filter((b): b is string => !!b && path.isAbsolute(b));
  for (const base of candidates) {
    const dir = path.join(base, `nsc-${uid}-${tag}`);
    if (dir.length > MAX_CONTROL_DIR) continue;
    try { return ensureStateDir(dir); } catch { /* try the next base */ }
  }
  throw new Error(`no short private directory is available for SSH control sockets (needs a path of at most ${MAX_CONTROL_DIR} characters under XDG_RUNTIME_DIR or /tmp).`);
}

export function ensureStateDir(dir: string): string {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || (st.mode & 0o077) !== 0 || (process.getuid && st.uid !== process.getuid())) throw new Error('SSH state directory is not private (needs mode 0700 and your ownership).');
  return dir;
}

/** The exact ssh argv (pure: unit-tested). */
export function buildSshArgs(t: SshTarget, remote: string, o: { knownHosts: string; strict: 'yes' | 'accept-new'; controlDir: string; persistSeconds: number; connectTimeoutS: number }): string[] {
  const args = [
    '-o', `StrictHostKeyChecking=${o.strict}`, '-o', `UserKnownHostsFile=${o.knownHosts}`, '-o', 'HashKnownHosts=no', '-o', 'LogLevel=ERROR',
    '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=' + o.connectTimeoutS,
    '-o', 'ControlMaster=auto', '-o', `ControlPath=${o.controlDir}/%C`, '-o', `ControlPersist=${o.persistSeconds}`,
  ];
  if (t.keyFile) args.push('-i', t.keyFile, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no');
  else args.push('-o', 'PubkeyAuthentication=no', '-o', 'BatchMode=no');
  args.push('-p', String(t.port), `${t.user}@${t.host}`, remote);
  return args;
}

const run = (file: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs: number): Promise<SshOutcome> => new Promise((resolve) => {
  execFile(file, args, { timeout: timeoutMs, maxBuffer: 4_000_000, env, windowsHide: true }, (error, stdout, stderr) => {
    const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : 255) : 0;
    const missing = error && (error as { code?: unknown }).code === 'ENOENT';
    resolve({ code, stdout: String(stdout || ''), stderr: missing ? `ENOENT: ${file} not found` : error && (error as { killed?: boolean }).killed ? 'timed out' : String(stderr || '').slice(0, 300) });
  });
});

export function createSshRunner(opts: SshOptions = {}): SshRunner {
  const exec = opts.exec ?? run;
  const persist = opts.persistSeconds ?? SSH_PERSIST_S;
  const connectS = opts.connectTimeoutS ?? 6;
  return async (t, remote, timeoutMs) => {
    let dir: string;
    try { dir = ensureStateDir(opts.stateDir ?? defaultStateDir()); } catch (e) { return { code: 255, stdout: '', stderr: (e as Error).message }; }
    let ctl: string;
    try { ctl = controlDirFor(dir); } catch (e) { return { code: 255, stdout: '', stderr: (e as Error).message }; }
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C.UTF-8' };
    let knownHosts = path.join(dir, 'known_hosts');
    let strict: 'yes' | 'accept-new' = 'accept-new';
    if (t.hostKeySha256) {
      const pinDir = path.join(dir, 'pinned'); fs.mkdirSync(pinDir, { recursive: true, mode: 0o700 });
      const file = path.join(pinDir, `${createHash('sha256').update(t.deviceId).digest('hex').slice(0, 24)}.known_hosts`);
      const scan = await exec('ssh-keyscan', ['-T', String(connectS), '-p', String(t.port), t.host], env, (connectS + 4) * 1000);
      const lines = scan.stdout.split('\n').filter((l) => l.trim() && !l.startsWith('#'));
      const match = lines.find((l) => sshKeyFingerprint(l) === normPin(t.hostKeySha256!));
      if (!match) return { code: 255, stdout: '', stderr: lines.length ? 'SSH host key does not match the pinned fingerprint.' : 'could not read the SSH host key (ssh-keyscan failed).' };
      fs.writeFileSync(file, `${match}\n`, { mode: 0o600 });
      knownHosts = file; strict = 'yes';
    }
    const args = buildSshArgs(t, remote, { knownHosts, strict, controlDir: ctl, persistSeconds: persist, connectTimeoutS: connectS });
    if (t.keyFile) return exec('ssh', args, env, timeoutMs);
    if (!t.password) return { code: 255, stdout: '', stderr: 'no SSH credentials (configure a key file or a password).' };
    // Password mode: no controlling terminal is needed, OpenSSH asks the helper (SSH_ASKPASS_REQUIRE=force, OpenSSH >= 8.4).
    env.SSH_ASKPASS = ensureAskpass(dir);
    env.SSH_ASKPASS_REQUIRE = 'force';
    env.DISPLAY = env.DISPLAY || 'netscope:0';
    env[ASKPASS_ENV] = t.password;
    return exec('ssh', args, env, timeoutMs);
  };
}
