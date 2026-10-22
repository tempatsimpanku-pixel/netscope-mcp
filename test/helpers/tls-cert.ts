import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Generate a throw-away self-signed certificate (SAN: 127.0.0.1) with the openssl CLI. Nothing is stored in the repository. */
export function makeCert(cn = 'rtr-core-1.lab.invalid'): { key: string; cert: string; fingerprint256: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netscope-cert-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '2', '-subj', `/CN=${cn}`, '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
    const key = fs.readFileSync(path.join(dir, 'k.pem'), 'utf8');
    const cert = fs.readFileSync(path.join(dir, 'c.pem'), 'utf8');
    return { key, cert, fingerprint256: new X509Certificate(cert).fingerprint256 };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
