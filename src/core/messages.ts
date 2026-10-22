/** Operator-facing sentences the server builds itself (headers, errors, footers). Command-policy explanations
 * (the reason a command was denied) and router output stay as produced; only the frame around them is translated.
 * Embedders may pass `locale` or inject a partial dictionary through `NetScopeOptions.messages`. */
export type Locale = 'en' | 'id';
export const LOCALES: readonly Locale[] = ['en', 'id'];

export interface Messages {
  refused(tool: string, detail: string): string;
  failed(tool: string, detail: string): string;
  /** Per-item refusal inside a combined result. */
  refusedItem(detail: string): string;
  failedOn(tool: string, device: string, detail: string): string;
  /** Marker for a failed line/section inside a combined result (batch, recipe). */
  error: string;
  ok: string;
  footer(ms: number, route: string): string;
  noRows: string;
  noHops: string;
  credentialsEmpty(tool: string): string;
  sshNotConfigured(tool: string, device: string): string;
  sshClosed(tool: string, device: string): string;
  sshFailed(tool: string, device: string, detail: string): string;
  /** Appended when the router answers "no such command". */
  missingCommandHint: string;
  noSnapshotYet: string;
  noSnapshotForDevice(device: string): string;
  snapshotDisabled: string;
  batchSummary(ok: number, bad: number, total: number, ms: number): string;
  batchNeedsItems: string;
  batchTooMany(max: number, got: number): string;
  deviceCount(n: number, filter: string): string;
  /** Per-device list_devices fragments. */
  toolsLabel: string;
  exportOverSsh: string;
  exportPort(port: number): string;
  exportUnavailable: string;
  narrowFilter: string;
  recipeNotFound(name: string, routers: number): string;
  recipeChecked(list: string): string;
  recipeEdges(n: number): string;
  recipeUnknown(list: string): string;
}

const en: Messages = {
  refused: (tool, detail) => `${tool} refused: ${detail}`,
  failed: (tool, detail) => `${tool} failed: ${detail}`,
  refusedItem: (detail) => `refused: ${detail}`,
  failedOn: (tool, device, detail) => `${tool} failed [${device}]: ${detail}`,
  error: 'ERROR',
  ok: 'ok',
  footer: (ms, route) => `(${ms} ms, read-only${route})`,
  noRows: '(no rows)',
  noHops: '(no hops)',
  credentialsEmpty: (tool) => `${tool} failed: device credentials are empty.`,
  sshNotConfigured: (tool, device) => `${tool}: SSH port of ${device} is not configured, export is unavailable (the port is never guessed). Use print per menu.`,
  sshClosed: (tool, device) => `${tool}: SSH of ${device} is closed from here, export is unavailable. Use print per menu.`,
  sshFailed: (tool, device, detail) => `${tool}: export over SSH failed for ${device} (${detail}).`,
  missingCommandHint: ' (this menu/command does not exist on this device model or RouterOS version; it is not a connection problem)',
  noSnapshotYet: '[mikrotik_snapshot] no snapshot yet (the worker just started, or every router failed). Use mikrotik_read / mikrotik_recipe (live).',
  noSnapshotForDevice: (device) => `[mikrotik_snapshot] ${device}: no snapshot yet (the worker has not fetched it, or the device family is not covered). Use mikrotik_read (live).`,
  snapshotDisabled: 'mikrotik_snapshot is not enabled: start the server with --snapshot <file>. Use mikrotik_read / mikrotik_recipe (live).',
  batchSummary: (ok, bad, total, ms) => `[mikrotik_batch] ${ok} ok, ${bad} error(s) of ${total} items (${ms} ms, read-only)`,
  batchNeedsItems: '`items` must contain at least one {device, command}.',
  batchTooMany: (max, got) => `at most ${max} items per call (got ${got}).`,
  toolsLabel: 'tools',
  exportOverSsh: 'export over SSH',
  exportPort: (port) => `port ${port}`,
  exportUnavailable: 'unavailable',
  deviceCount: (n, filter) => `${n} device(s)${filter ? ` matching "${filter}"` : ''}:`,
  narrowFilter: '… (narrow with filter)',
  recipeNotFound: (name, routers) => `"${name}" not found on ${routers} router(s).`,
  recipeChecked: (list) => `(checked without a hit: ${list})`,
  recipeEdges: (n) => `(total ${n} edges)`,
  recipeUnknown: (list) => `recipe must be one of ${list}.`,
};

const id: Messages = {
  refused: (tool, detail) => `${tool} ditolak: ${detail}`,
  failed: (tool, detail) => `${tool} gagal: ${detail}`,
  refusedItem: (detail) => `ditolak: ${detail}`,
  failedOn: (tool, device, detail) => `${tool} gagal [${device}]: ${detail}`,
  error: 'GALAT',
  ok: 'ok',
  footer: (ms, route) => `(${ms} ms, hanya baca${route})`,
  noRows: '(tidak ada baris)',
  noHops: '(tidak ada hop)',
  credentialsEmpty: (tool) => `${tool} gagal: kredensial perangkat kosong.`,
  sshNotConfigured: (tool, device) => `${tool}: port SSH ${device} belum dikonfigurasi, export tidak tersedia (port tidak pernah ditebak). Pakai print per menu.`,
  sshClosed: (tool, device) => `${tool}: SSH ${device} tertutup dari sini, export tidak tersedia. Pakai print per menu.`,
  sshFailed: (tool, device, detail) => `${tool}: export lewat SSH gagal untuk ${device} (${detail}).`,
  missingCommandHint: ' (menu/perintah ini tidak ada di model perangkat atau versi RouterOS ini; bukan masalah koneksi)',
  noSnapshotYet: '[mikrotik_snapshot] belum ada snapshot (worker baru mulai, atau semua router gagal). Pakai mikrotik_read / mikrotik_recipe (langsung).',
  noSnapshotForDevice: (device) => `[mikrotik_snapshot] ${device}: belum ada snapshot (worker belum mengambilnya, atau jenis perangkat tidak tercakup). Pakai mikrotik_read (langsung).`,
  snapshotDisabled: 'mikrotik_snapshot tidak aktif: jalankan server dengan --snapshot <berkas>. Pakai mikrotik_read / mikrotik_recipe (langsung).',
  batchSummary: (ok, bad, total, ms) => `[mikrotik_batch] ${ok} ok, ${bad} galat dari ${total} item (${ms} ms, hanya baca)`,
  batchNeedsItems: '`items` harus berisi minimal satu {device, command}.',
  batchTooMany: (max, got) => `maksimal ${max} item per panggilan (diterima ${got}).`,
  toolsLabel: 'alat',
  exportOverSsh: 'export lewat SSH',
  exportPort: (port) => `port ${port}`,
  exportUnavailable: 'tidak tersedia',
  deviceCount: (n, filter) => `${n} perangkat${filter ? ` cocok dengan "${filter}"` : ''}:`,
  narrowFilter: '… (persempit dengan filter)',
  recipeNotFound: (name, routers) => `"${name}" tidak ditemukan di ${routers} router.`,
  recipeChecked: (list) => `(diperiksa tanpa hasil: ${list})`,
  recipeEdges: (n) => `(total ${n} sambungan)`,
  recipeUnknown: (list) => `resep harus salah satu dari ${list}.`,
};

export const MESSAGES: Record<Locale, Messages> = { en, id };

export function resolveMessages(locale: Locale | undefined, overrides?: Partial<Messages>): Messages {
  const base = MESSAGES[locale ?? 'en'];
  if (!base) throw new Error(`unknown locale "${String(locale).slice(0, 20)}" (use ${LOCALES.join(' or ')}).`);
  return overrides ? { ...base, ...overrides } : base;
}
