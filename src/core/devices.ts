import { DeviceNotFound } from './errors.js';
import type { DeviceFamily, DeviceInfo } from './types.js';

export type Pool = 'ros' | 'switch' | 'snmp';

const POOLS: Record<Pool, (d: DeviceInfo) => boolean> = {
  ros: (d) => d.family === 'routeros' || d.family === 'switch',
  switch: (d) => d.family === 'switch' || d.family === 'swos',
  snmp: () => true,
};
const POOL_LABEL: Record<Pool, string> = { ros: 'RouterOS router/switch', switch: 'switch', snmp: 'SNMP-capable device' };

/** Resolve a name/IP/id to a known device. Free-form hosts are never accepted: the inventory is the only source of targets. */
export function resolveDevice(devices: DeviceInfo[], ref: unknown, pool: Pool): DeviceInfo {
  const q = typeof ref === 'string' ? ref.trim() : typeof ref === 'number' ? String(ref) : '';
  if (!q) throw new DeviceNotFound('device parameter is required (name, IP or id from list_devices).');
  const candidates = devices.filter(POOLS[pool]);
  const lower = q.toLowerCase().replace(/^id:/, '');
  const hit = (pred: (d: DeviceInfo) => boolean) => candidates.filter(pred);
  let found = hit((d) => d.id.toLowerCase() === lower);
  if (!found.length) found = hit((d) => d.name.toLowerCase() === lower);
  if (!found.length) found = hit((d) => d.host.toLowerCase() === lower);
  if (!found.length) found = hit((d) => d.name.toLowerCase().includes(lower) || d.id.toLowerCase().includes(lower)).slice(0, 25);
  if (!found.length) throw new DeviceNotFound(`device "${q.slice(0, 60)}" is not in the known list (${POOL_LABEL[pool]}). Use list_devices.`);
  if (found.length > 1) throw new DeviceNotFound(`"${q.slice(0, 60)}" is ambiguous: ${found.map((d) => `id=${d.id} ${d.name}`).join('; ')}. Repeat with the id.`);
  return found[0]!;
}

export const familyTools = (family: DeviceFamily): string => {
  if (family === 'swos') return 'switch_read (SNMP only), snmp_get';
  if (family === 'switch') return 'mikrotik_read, switch_read, ping, snmp_get';
  if (family === 'snmp') return 'snmp_get';
  return 'mikrotik_read, ping, traceroute, snmp_get';
};
