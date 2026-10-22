import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ASKPASS_ENV, buildSshArgs, createSshRunner, ensureAskpass, sshKeyFingerprint, type SshOutcome, type SshTarget } from '../../src/core/index.js';

const dirs: string[] = [];
const mkdir = (mode = 0o700) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'netscope-ssht-')); fs.chmodSync(d, mode); dirs.push(d); return d; };
afterEach(() => { dirs.splice(0).forEach((d) => fs.rmSync(d, { recursive: true, force: true })); });

const base: SshTarget = { host: '192.0.2.10', port: 2222, user: 'ro-user', deviceId: 'rtr-core-1', password: 'LAB-PASSWORD-ONE' };
type Call = { file: string; args: string[]; env: NodeJS.ProcessEnv };
const recorder = (answers: Array<Partial<SshOutcome>> = []) => {
  const calls: Call[] = [];
  const exec = async (file: string, args: string[], env: NodeJS.ProcessEnv): Promise<SshOutcome> => { calls.push({ file, args, env: { ...env } }); return { code: 0, stdout: '', stderr: '', ...(answers.shift() ?? {}) }; };
  return { calls, exec };
};

describe('buildSshArgs (pure)', () => {
  const args = buildSshArgs(base, '/ip address export hide-sensitive', { knownHosts: '/state/known_hosts', strict: 'accept-new', controlDir: '/state/ctl', persistSeconds: 45, connectTimeoutS: 6 });
  it('never disables host key checking or points known_hosts at /dev/null', () => {
    const joined = args.join(' ');
    expect(joined).not.toMatch(/StrictHostKeyChecking=no/i); expect(joined).not.toContain('/dev/null'); expect(joined).toContain('StrictHostKeyChecking=accept-new');
    expect(joined).toContain('UserKnownHostsFile=/state/known_hosts');
  });
  it('keeps the password out of argv; remote command is the last argument', () => {
    expect(args.join(' ')).not.toContain('LAB-PASSWORD-ONE'); expect(args.at(-1)).toBe('/ip address export hide-sensitive'); expect(args.at(-2)).toBe('ro-user@192.0.2.10');
    expect(args).toContain('PubkeyAuthentication=no');
  });
  it('key mode: identity file, no password prompts', () => {
    const a = buildSshArgs({ ...base, keyFile: '/keys/k' }, 'x', { knownHosts: 'k', strict: 'yes', controlDir: 'c', persistSeconds: 1, connectTimeoutS: 1 });
    expect(a).toContain('-i'); expect(a).toContain('/keys/k'); expect(a).toContain('PasswordAuthentication=no'); expect(a).toContain('IdentitiesOnly=yes'); expect(a).toContain('StrictHostKeyChecking=yes');
  });
});

describe('sshKeyFingerprint', () => {
  it('matches ssh-keygen for a real key', () => {
    const d = mkdir(); const key = path.join(d, 'k');
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key], { stdio: 'ignore' });
    const pub = fs.readFileSync(`${key}.pub`, 'utf8').trim();
    const expected = execFileSync('ssh-keygen', ['-lf', `${key}.pub`], { encoding: 'utf8' }).split(' ')[1]!;
    expect(sshKeyFingerprint(`192.0.2.10 ${pub}`)).toBe(expected);
    expect(sshKeyFingerprint('garbage')).toBeNull();
  });
});

describe('createSshRunner', () => {
  it('password auth: SSH_ASKPASS helper, password only in the child environment (never argv), trust-on-first-use known_hosts in the state dir', async () => {
    const d = mkdir(); const r = recorder();
    const run = createSshRunner({ stateDir: d, exec: r.exec });
    await run(base, '/ip address export hide-sensitive', 5000);
    const c = r.calls[0]!;
    expect(c.file).toBe('ssh'); expect(c.env[ASKPASS_ENV]).toBe('LAB-PASSWORD-ONE'); expect(c.env.SSHPASS).toBeUndefined();
    expect(c.env.SSH_ASKPASS).toBe(path.join(d, 'askpass.sh')); expect(c.env.SSH_ASKPASS_REQUIRE).toBe('force');
    expect(c.args.join(' ')).not.toContain('LAB-PASSWORD-ONE'); expect(c.file + c.args.join(' ')).not.toContain('sshpass');
    expect(c.args.join(' ')).toContain(`UserKnownHostsFile=${path.join(d, 'known_hosts')}`); expect(c.args.join(' ')).toContain('StrictHostKeyChecking=accept-new');
  });
  it('the askpass helper holds no secret, is private, answers a password prompt only, and fails closed', () => {
    const d = mkdir(); const file = ensureAskpass(d);
    expect(fs.statSync(file).mode & 0o777).toBe(0o700); expect(fs.readFileSync(file, 'utf8')).not.toContain('LAB-PASSWORD-ONE');
    const ask = (prompt: string, pw?: string) => spawnSync(file, [prompt], { env: { PATH: '/usr/bin:/bin', ...(pw === undefined ? {} : { [ASKPASS_ENV]: pw }) }, encoding: 'utf8' });
    const ok = ask("ro-user@192.0.2.10's password: ", 'LAB-PASSWORD-ONE'); expect(ok.status).toBe(0); expect(ok.stdout).toBe('LAB-PASSWORD-ONE\n');
    const special = ask('Password:', 'a b\\n$x"y'); expect(special.stdout).toBe('a b\\n$x"y\n');
    const hostKey = ask('Are you sure you want to continue connecting (yes/no/[fingerprint])? ', 'LAB-PASSWORD-ONE'); expect(hostKey.status).toBe(1); expect(hostKey.stdout).toBe('');
    const passphrase = ask('Enter passphrase for key /k: ', 'LAB-PASSWORD-ONE'); expect(passphrase.status).toBe(1); expect(passphrase.stdout).toBe('');
    const none = ask('Password:'); expect(none.status).toBe(1); expect(none.stdout).toBe('');
    expect(ensureAskpass(d)).toBe(file); // idempotent
  });
  it('a tampered helper is rewritten', () => {
    const d = mkdir(); const file = ensureAskpass(d); fs.writeFileSync(file, '#!/bin/sh\necho pwned\n', { mode: 0o755 });
    ensureAskpass(d); expect(fs.readFileSync(file, 'utf8')).not.toContain('pwned'); expect(fs.statSync(file).mode & 0o777).toBe(0o700);
  });
  it('key auth: plain ssh, no SSHPASS', async () => {
    const d = mkdir(); const r = recorder();
    await createSshRunner({ stateDir: d, exec: r.exec })({ ...base, password: undefined, keyFile: '/keys/k' }, 'x', 5000);
    expect(r.calls[0]!.file).toBe('ssh'); expect(r.calls[0]!.env[ASKPASS_ENV]).toBeUndefined(); expect(r.calls[0]!.env.SSH_ASKPASS).toBeUndefined();
  });
  it('no credentials at all: refuses without running anything', async () => {
    const r = recorder();
    const out = await createSshRunner({ stateDir: mkdir(), exec: r.exec })({ ...base, password: undefined }, 'x', 5000);
    expect(out.code).toBe(255); expect(r.calls).toHaveLength(0);
  });
  it('pinned host key: scanned key must match, is written to a private per-device file, and used with StrictHostKeyChecking=yes', async () => {
    const d = mkdir(); const k = path.join(d, 'gen'); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', k], { stdio: 'ignore' });
    const line = `192.0.2.10 ${fs.readFileSync(`${k}.pub`, 'utf8').trim().split(' ').slice(0, 2).join(' ')}`;
    const pin = sshKeyFingerprint(line)!;
    const state = mkdir(); const r = recorder([{ stdout: `# comment\n${line}\n` }]);
    const out = await createSshRunner({ stateDir: state, exec: r.exec })({ ...base, hostKeySha256: pin }, 'x', 5000);
    expect(out.code).toBe(0); expect(r.calls[0]!.file).toBe('ssh-keyscan'); expect(r.calls[1]!.file).toBe('ssh');
    const arg = r.calls[1]!.args.join(' '); expect(arg).toContain('StrictHostKeyChecking=yes');
    const khFile = /UserKnownHostsFile=(\S+)/.exec(arg)![1]!;
    expect(khFile.startsWith(path.join(state, 'pinned'))).toBe(true); expect(fs.readFileSync(khFile, 'utf8').trim()).toBe(line); expect(fs.statSync(khFile).mode & 0o777).toBe(0o600);
  });
  it('pinned host key that does not match: connection is never attempted', async () => {
    const d = mkdir(); const k = path.join(d, 'gen'); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', k], { stdio: 'ignore' });
    const line = `192.0.2.10 ${fs.readFileSync(`${k}.pub`, 'utf8').trim().split(' ').slice(0, 2).join(' ')}`;
    const r = recorder([{ stdout: `${line}\n` }]);
    const out = await createSshRunner({ stateDir: mkdir(), exec: r.exec })({ ...base, hostKeySha256: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, 'x', 5000);
    expect(out.code).toBe(255); expect(out.stderr).toMatch(/does not match the pinned/); expect(r.calls.map((c) => c.file)).toEqual(['ssh-keyscan']);
  });
  it('pinned but unreadable host key: refuses', async () => {
    const r = recorder([{ stdout: '', code: 1 }]);
    const out = await createSshRunner({ stateDir: mkdir(), exec: r.exec })({ ...base, hostKeySha256: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, 'x', 5000);
    expect(out.code).toBe(255); expect(r.calls).toHaveLength(1);
  });
  it('a state directory that is not private is refused', async () => {
    const r = recorder();
    const out = await createSshRunner({ stateDir: mkdir(0o755), exec: r.exec })(base, 'x', 5000);
    expect(out.code).toBe(255); expect(out.stderr).toMatch(/not private/); expect(r.calls).toHaveLength(0);
  });
});

describe('long state_dir', () => {
  it('keeps ControlPath short (< 108 bytes with the OpenSSH suffix) however long state_dir is', async () => {
    const long = path.join(mkdir(), 'x'.repeat(90), 'y'.repeat(60));
    fs.mkdirSync(long, { recursive: true, mode: 0o700 });
    const r = recorder();
    await createSshRunner({ stateDir: long, exec: r.exec })(base, '/ip service export hide-sensitive', 5000);
    const cp = r.calls[0]!.args.find((a) => a.startsWith('ControlPath='))!.slice('ControlPath='.length);
    expect(long.length).toBeGreaterThan(120);
    expect(cp.replace('%C', 'a'.repeat(40)).length + 17).toBeLessThan(108);
    expect(cp.startsWith(long)).toBe(false);
    expect(fs.statSync(path.dirname(cp)).mode & 0o077).toBe(0);
  });
});
