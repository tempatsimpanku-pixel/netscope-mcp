import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BusyError, Gate, KeyedQueue, RateLimiter } from '../../src/core/index.js';

const tick = () => new Promise((r) => setTimeout(r, 0));
function latch() { let open!: () => void; const p = new Promise<void>((r) => { open = r; }); return { p, open }; }

describe('Gate: FIFO semaphore', () => {
  it('12 concurrent calls: at most 10 at once, none refused, all complete', async () => {
    const gate = new Gate(10);
    let active = 0; let peak = 0;
    const results = await Promise.allSettled(Array.from({ length: 12 }, (_, i) => gate.run(async () => { active++; peak = Math.max(peak, active); await new Promise((r) => setTimeout(r, 15)); active--; return i; })));
    expect(peak).toBe(10);
    expect(results.map((r) => (r as PromiseFulfilledResult<number>).value)).toEqual(Array.from({ length: 12 }, (_, i) => i));
    expect(gate.inflight).toBe(0);
  });
  it('waiters are served in arrival order', async () => {
    const gate = new Gate(10); const hold = latch(); const order: number[] = [];
    const busy = Array.from({ length: 10 }, () => gate.run(() => hold.p));
    const queued = [0, 1, 2].map((i) => gate.run(async () => { order.push(i); }));
    await tick(); expect(order).toEqual([]);
    hold.open(); await Promise.all([...busy, ...queued]);
    expect(order).toEqual([0, 1, 2]);
  });
  it('releases the slot when the job throws', async () => {
    const gate = new Gate(10);
    await Promise.allSettled(Array.from({ length: 10 }, () => gate.run(async () => { throw new Error('boom'); })));
    const hold = latch(); let started = 0;
    const again = Array.from({ length: 10 }, () => gate.run(async () => { started++; await hold.p; }));
    await tick(); expect(started).toBe(10);
    hold.open(); await Promise.all(again);
  });

  describe('wait limit', () => {
    beforeEach(() => { vi.useFakeTimers(); });
    afterEach(() => { vi.useRealTimers(); });
    it('refuses after the wait limit with a clear BusyError and keeps the full slots intact', async () => {
      const gate = new Gate(10, 30_000); const hold = latch();
      const busy = Array.from({ length: 10 }, () => gate.run(() => hold.p));
      let ran = false;
      const caught = gate.run(async () => { ran = true; }).catch((e: Error) => e);
      await vi.advanceTimersByTimeAsync(29_999); expect(ran).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      const err = await caught;
      expect(err).toBeInstanceOf(BusyError); expect((err as Error).message).toMatch(/waited more than 30 s/);
      hold.open(); await Promise.all(busy);
      let started = 0; const hold2 = latch();
      const again = Array.from({ length: 10 }, () => gate.run(async () => { started++; await hold2.p; }));
      await vi.advanceTimersByTimeAsync(0); expect(started).toBe(10);
      hold2.open(); await Promise.all(again);
    });
    it('a waiter that got a slot in time is not refused later', async () => {
      const gate = new Gate(10, 30_000); const hold = latch();
      const busy = Array.from({ length: 10 }, () => gate.run(() => hold.p));
      const late = gate.run(async () => 'ok');
      await vi.advanceTimersByTimeAsync(15_000); hold.open(); await Promise.all(busy);
      await vi.advanceTimersByTimeAsync(30_000);
      await expect(late).resolves.toBe('ok');
    });
  });
});

describe('KeyedQueue', () => {
  it('same key runs in order, different keys overlap', async () => {
    const q = new KeyedQueue(); const gate = new Gate(10);
    const active = new Map<string, number>(); const peakPer = new Map<string, number>(); let total = 0; let peakTotal = 0;
    const job = (id: string) => q.run(id, () => gate.run(async () => {
      active.set(id, (active.get(id) || 0) + 1); total++;
      peakPer.set(id, Math.max(peakPer.get(id) || 0, active.get(id)!)); peakTotal = Math.max(peakTotal, total);
      await new Promise((r) => setTimeout(r, 15));
      active.set(id, active.get(id)! - 1); total--;
    }));
    await Promise.all(['a', 'a', 'a', 'b', 'b', 'c'].map(job));
    expect([peakPer.get('a'), peakPer.get('b'), peakPer.get('c')]).toEqual([1, 1, 1]);
    expect(peakTotal).toBe(3);
  });
  it('a failing job does not block the next one', async () => {
    const q = new KeyedQueue();
    await expect(q.run('k', async () => { throw new Error('x'); })).rejects.toThrow('x');
    await expect(q.run('k', async () => 'fine')).resolves.toBe('fine');
  });
});

describe('RateLimiter', () => {
  it('allows the burst, refuses beyond it, refills over time', () => {
    let t = 0; const rl = new RateLimiter(60, () => t);
    for (let i = 0; i < 60; i++) expect(rl.take()).toBe(true);
    expect(rl.take()).toBe(false);
    t += 1000; expect(rl.take()).toBe(true); expect(rl.take()).toBe(false);
  });
});
