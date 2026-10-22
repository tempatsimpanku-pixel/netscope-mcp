import type { CredentialSource, DeviceCredentials, DeviceInfo, DeviceSource } from '../../src/core/types.js';

/** Synthetic inventory: documentation address ranges only (RFC 5737), invented names. */
export const DEVICES: DeviceInfo[] = [
  { id: 'rtr-core-1', name: 'rtr-core-1', host: '192.0.2.10', port: 8729, family: 'routeros', group: 'backbone', labels: { role: 'core' }, ssh: { port: 22 } },
  { id: 'rtr-edge-1', name: 'rtr-edge-1', host: '192.0.2.11', port: 8729, family: 'routeros', group: 'edge', ssh: { port: null } },
  { id: 'rtr-edge-2', name: 'rtr-edge-2', host: '192.0.2.12', port: 8729, family: 'routeros', group: 'edge' },
  { id: 'sw-crs-1', name: 'sw-crs-1', host: '198.51.100.21', port: 8729, family: 'switch', group: 'access' },
  { id: 'sw-css-1', name: 'sw-css-1', host: '198.51.100.22', port: 8729, family: 'swos', group: 'access' },
  { id: 'ap-snmp-1', name: 'ap-snmp-1', host: '198.51.100.23', port: 161, family: 'snmp', group: 'access' },
];

export const CREDS: DeviceCredentials = { user: 'ro-user', secret: 'LAB-PASSWORD-ONE', community: 'LAB-COMMUNITY-ONE' };

export function staticSource(devices: DeviceInfo[] = DEVICES): DeviceSource {
  return { list: async () => devices };
}
export function staticCreds(cred: DeviceCredentials = CREDS, log?: string[]): CredentialSource {
  return { credentials: async (id) => { log?.push(id); return { ...cred }; } };
}
export const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
