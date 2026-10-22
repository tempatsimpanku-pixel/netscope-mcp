import net from 'node:net';
import tls from 'node:tls';
import { decodeSentence, encodeSentence } from '../../src/core/wire.js';

type Row = Record<string, string>;
export interface FakeRosOptions {
  user?: string;
  password?: string;
  /** Reject every login (trap, then close). */
  reject?: boolean;
  /** Never answer commands. */
  hang?: boolean;
  rowsPerPrint?: number;
  /** Delay before answering each command (ms). */
  latencyMs?: number;
  tls?: { key: string; cert: string };
  /** Rows per API path; a function receives the command words. */
  handlers?: Record<string, Row[] | ((words: string[]) => Row[])>;
}

/** A synthetic RouterOS API server: login, equality `?where` filters, `.proplist`, `count-only`, unknown command → trap.
 * It records every command sentence so tests can prove no write verb ever reached a device. */
export async function fakeRos(opts: FakeRosOptions = {}) {
  const user = opts.user ?? 'ro-user';
  const password = opts.password ?? 'lab-password-1';
  const st = { logins: 0, cmds: 0, open: 0, maxOpen: 0, sockets: new Set<net.Socket>(), sentences: [] as string[][], logins_seen: [] as Array<{ user: string }> };
  const onSocket = (sock: net.Socket) => {
    st.open++; st.maxOpen = Math.max(st.maxOpen, st.open); st.sockets.add(sock);
    let buf = Buffer.alloc(0);
    sock.on('close', () => { st.open--; st.sockets.delete(sock); });
    sock.on('error', () => undefined);
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const s = decodeSentence(buf); if (!s) return; buf = buf.subarray(s.used);
        if (s.words[0] === '/login') {
          st.logins++;
          const name = s.words.find((w) => w.startsWith('=name='))?.slice(6) ?? '';
          const pass = s.words.find((w) => w.startsWith('=password='))?.slice(10) ?? '';
          st.logins_seen.push({ user: name });
          const ok = !opts.reject && name === user && pass === password;
          sock.write(encodeSentence(ok ? ['!done'] : ['!trap', '=message=invalid user name or password (6)']));
          if (!ok) sock.end();
          continue;
        }
        st.cmds++; st.sentences.push(s.words);
        if (opts.hang) continue;
        const answer = () => {
          const path = s.words[0]!;
          const h = opts.handlers?.[path];
          let rows: Row[] | undefined = typeof h === 'function' ? h(s.words) : h;
          if (!rows) {
            if (path.endsWith('/print') || path.endsWith('/monitor') || path === '/ping' || path === '/tool/traceroute') {
              if (opts.rowsPerPrint !== undefined) rows = Array.from({ length: opts.rowsPerPrint }, (_v, i) => ({ name: `row${i}`, 'cpu-load': '3' }));
              else if (path === '/system/resource/print') rows = [{ 'board-name': 'RB-LAB', version: '7.15 (stable)', uptime: '1d', 'cpu-load': '3', 'free-memory': '500', 'total-memory': '1000' }];
              else { sock.write(encodeSentence(['!trap', '=message=no such command prefix'])); sock.write(encodeSentence(['!done'])); return; }
            } else { sock.write(encodeSentence(['!trap', '=message=no such command prefix'])); sock.write(encodeSentence(['!done'])); return; }
          }
          for (const w of s.words) {
            if (w.startsWith('?-')) { const k = w.slice(2); rows = rows.filter((r) => r[k] !== 'true'); }
            else if (w.startsWith('?')) { const [k, v] = [w.slice(1).split('=')[0]!, w.includes('=') ? w.slice(w.indexOf('=') + 1) : undefined]; rows = rows.filter((r) => (v === undefined ? r[k] !== undefined : r[k] === v)); }
          }
          if (s.words.includes('=count-only=')) { sock.write(encodeSentence(['!done', `=ret=${rows.length}`])); return; }
          const prop = s.words.find((w) => w.startsWith('=.proplist='))?.slice(11).split(',');
          for (const r of rows) {
            const keep = prop ? Object.entries(r).filter(([k]) => prop.includes(k)) : Object.entries(r);
            sock.write(encodeSentence(['!re', ...keep.map(([k, v]) => `=${k}=${v}`)]));
          }
          sock.write(encodeSentence(['!done']));
        };
        if (opts.latencyMs) setTimeout(answer, opts.latencyMs); else answer();
      }
    });
  };
  const server = opts.tls ? tls.createServer({ key: opts.tls.key, cert: opts.tls.cert, minVersion: 'TLSv1.2' }, onSocket as unknown as (s: tls.TLSSocket) => void) : net.createServer(onSocket);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: (server.address() as net.AddressInfo).port, st, user, password,
    close: () => new Promise<void>((r) => { for (const s of st.sockets) s.destroy(); server.close(() => r()); }),
    dropSockets: () => { for (const s of st.sockets) s.destroy(); },
    /** Command paths seen (without /login), e.g. "/ip/address/print". */
    paths: () => st.sentences.map((w) => w[0]!),
  };
}
export type FakeRos = Awaited<ReturnType<typeof fakeRos>>;
