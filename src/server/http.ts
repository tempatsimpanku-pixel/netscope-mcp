import { createHash, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { RateLimiter } from '../core/limits.js';

/** Streamable HTTP front-end (stateless: one MCP server + transport per request).
 *
 * Defences, in order: Host header allowlist (DNS rebinding) → Origin must be absent or allowlisted → bearer token (constant time) →
 * POST only → rate limit → body limit. No CORS headers are ever sent. Binds to 127.0.0.1 unless `allowRemote` is set. */

export const MIN_TOKEN_LENGTH = 32;
export const MAX_BODY_BYTES = 4 * 1024 * 1024;

export interface HttpOptions {
  /** Factory called per request. */
  createServer: () => McpServer;
  token: string;
  host?: string;
  port?: number;
  /** Required to bind a non-loopback address. */
  allowRemote?: boolean;
  /** Extra accepted `Host` header values (host or host:port). */
  allowedHosts?: string[];
  /** Accepted `Origin` values. A request with an Origin that is not listed is refused. */
  allowedOrigins?: string[];
  maxBodyBytes?: number;
  ratePerMinute?: number;
  log?: (line: string) => void;
}

export interface RunningHttp { server: http.Server; host: string; port: number; close: () => Promise<void> }

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
const digest = (s: string) => createHash('sha256').update(s).digest();

export function isLoopbackHost(host: string): boolean { return LOOPBACK.has(host.toLowerCase()) || /^127\./.test(host); }

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store', ...headers });
  res.end(text);
}
const rpcError = (code: number, message: string) => ({ jsonrpc: '2.0', error: { code, message }, id: null });

function readBody(req: http.IncomingMessage, max: number): Promise<Buffer | 'too-large'> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > max) { req.resume(); return resolve('too-large'); }
    const chunks: Buffer[] = []; let size = 0; let over = false;
    req.on('data', (c: Buffer) => { size += c.length; if (size > max) { over = true; chunks.length = 0; } else if (!over) chunks.push(c); });
    req.on('end', () => resolve(over ? 'too-large' : Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export async function startHttpServer(opts: HttpOptions): Promise<RunningHttp> {
  const host = opts.host ?? '127.0.0.1';
  if (opts.token.length < MIN_TOKEN_LENGTH) throw new Error(`the bearer token must be at least ${MIN_TOKEN_LENGTH} characters.`);
  if (!isLoopbackHost(host) && !opts.allowRemote) throw new Error('refusing to bind a non-loopback address without --allow-remote (and a TLS-terminating proxy in front).');
  const max = opts.maxBodyBytes ?? MAX_BODY_BYTES;
  const limiter = new RateLimiter(opts.ratePerMinute ?? 60);
  const tokenDigest = digest(opts.token);
  const log = opts.log ?? (() => undefined);
  let boundPort = 0;
  const hostOk = (h: string | undefined): boolean => {
    if (!h) return false;
    const v = h.toLowerCase();
    const accepted = new Set<string>([...(opts.allowedHosts ?? []).map((x) => x.toLowerCase())]);
    for (const n of isLoopbackHost(host) ? ['127.0.0.1', 'localhost', '[::1]'] : [host.toLowerCase()]) { accepted.add(n); accepted.add(`${n}:${boundPort}`); }
    return accepted.has(v);
  };
  /** No Origin (non-browser client), an allowlisted Origin, or a same-origin one (http/https on an accepted Host). */
  const originOk = (o: string | undefined): boolean => {
    if (o === undefined) return true;
    if ((opts.allowedOrigins ?? []).includes(o)) return true;
    try { const u = new URL(o); return (u.protocol === 'http:' || u.protocol === 'https:') && u.origin === o && hostOk(u.host); } catch { return false; }
  };

  const server = http.createServer(async (req, res) => {
    try {
      if (!hostOk(req.headers.host)) { req.resume(); return send(res, 403, rpcError(-32000, 'forbidden host')); }
      if (!originOk(req.headers.origin)) { req.resume(); return send(res, 403, rpcError(-32000, 'forbidden origin')); }
      const auth = req.headers.authorization ?? '';
      const m = /^Bearer (.+)$/.exec(auth);
      if (!m || !timingSafeEqual(digest(m[1]!), tokenDigest)) { req.resume(); return send(res, 401, rpcError(-32001, 'unauthorized'), { 'www-authenticate': 'Bearer' }); }
      if (req.method !== 'POST') { req.resume(); return send(res, 405, rpcError(-32000, 'method not allowed'), { allow: 'POST' }); }
      if (!/^\/mcp\/?$/.test((req.url ?? '').split('?')[0]!)) { req.resume(); return send(res, 404, rpcError(-32000, 'not found')); }
      if (!limiter.take()) { req.resume(); return send(res, 429, rpcError(-32000, 'rate limit exceeded'), { 'retry-after': '5' }); }
      const body = await readBody(req, max);
      if (body === 'too-large') return send(res, 413, rpcError(-32000, 'request body too large'));
      let parsed: unknown;
      try { parsed = JSON.parse(body.toString('utf8')); } catch { return send(res, 400, rpcError(-32700, 'parse error')); }
      const mcp = opts.createServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => { void transport.close(); void mcp.close(); });
      await mcp.connect(transport);
      await transport.handleRequest(req, res, parsed);
    } catch (e) {
      log(`[http] request error: ${(e as Error).name}`);
      if (!res.headersSent) send(res, 500, rpcError(-32603, 'internal error')); else res.end();
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;

  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(opts.port ?? 0, host, () => resolve()); });
  boundPort = (server.address() as AddressInfo).port;
  return {
    server, host, port: boundPort,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}
