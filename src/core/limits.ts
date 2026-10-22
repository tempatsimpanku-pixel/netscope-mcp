import { BusyError } from './errors.js';

/** FIFO semaphore: at most `max` jobs at once; the rest WAIT for a slot (in arrival order) up to `waitMs`, then are refused. */
export class Gate {
  private active = 0;
  private readonly waiters: Array<{ grant: () => void }> = [];
  constructor(readonly max = 10, readonly waitMs = 30_000) {}

  get inflight(): number { return this.active; }

  private acquire(): Promise<void> {
    if (this.active < this.max && !this.waiters.length) { this.active++; return Promise.resolve(); }
    return new Promise<void>((resolve, reject) => {
      const waiter = { grant: () => { clearTimeout(timer); resolve(); } };
      const timer = setTimeout(() => {
        const i = this.waiters.indexOf(waiter);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new BusyError(`queue full: waited more than ${this.waitMs / 1000} s for a slot (${this.max} commands running); try again shortly.`));
      }, this.waitMs);
      timer.unref?.();
      this.waiters.push(waiter);
    });
  }

  /** The slot moves straight to the first waiter (active stays), or is given back when nobody waits. */
  private release(): void {
    const next = this.waiters.shift();
    if (next) next.grant(); else this.active--;
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try { return await fn(); } finally { this.release(); }
  }
}

/** One job at a time per key (one API session per device: weak switches choke on parallel logins). */
export class KeyedQueue {
  private readonly chains = new Map<string, Promise<unknown>>();

  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.chains.get(key) || Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => undefined);
    this.chains.set(key, tail);
    void tail.then(() => { if (this.chains.get(key) === tail) this.chains.delete(key); });
    return run;
  }
}

/** Token bucket (calls per minute) for the HTTP front-end. */
export class RateLimiter {
  private tokens: number;
  private last: number;
  constructor(private readonly perMinute: number, private readonly now: () => number = Date.now) { this.tokens = perMinute; this.last = now(); }
  take(): boolean {
    const t = this.now();
    this.tokens = Math.min(this.perMinute, this.tokens + ((t - this.last) / 60_000) * this.perMinute);
    this.last = t;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}
