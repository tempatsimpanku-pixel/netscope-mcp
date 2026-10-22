import { NetScope } from '../../src/core/engine.js';
import { startHttpServer } from '../../src/server/http.js';
import { createMcpServer } from '../../src/server/mcp.js';
import { staticCreds, staticSource } from './fixtures.js';

export interface HttpTestServer { port: number; token: string; close(): Promise<void> }

/** Start the real Streamable HTTP front-end on 127.0.0.1 with synthetic inventory and a random token. */
export async function startHttpTestServer(): Promise<HttpTestServer> {
  const token = `t${'0123456789abcdef'.repeat(3)}`;
  const scope = new NetScope({ devices: staticSource(), credentials: staticCreds() });
  const running = await startHttpServer({ createServer: () => createMcpServer(scope, 'test'), token, host: '127.0.0.1', port: 0, ratePerMinute: 100_000 });
  return { port: running.port, token, close: async () => { await running.close(); scope.close(); } };
}
