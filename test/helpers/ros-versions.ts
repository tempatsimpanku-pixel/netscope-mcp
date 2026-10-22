/** Anonymous RouterOS answers in the two shapes seen in the field (v6 and v7). Documentation addresses, invented names. */
type Row = Record<string, string>;

/** RouterOS 6.x (long-term): flat `/system health`, `oct/22/2026` dates, no `address4`/`interface-name` on neighbors. */
export const V6: Record<string, Row[]> = {
  '/system/resource/print': [{ uptime: '3w2d4h', version: '6.48.6 (long-term)', 'free-memory': '212000000', 'total-memory': '268435456', 'cpu-load': '2', 'cpu-count': '4', 'architecture-name': 'mipsbe', 'board-name': 'RB-LAB-V6', platform: 'MikroTik' }],
  '/system/health/print': [{ voltage: '24.2', temperature: '38' }],
  '/system/clock/print': [{ time: '13:43:43', date: 'oct/22/2026', 'time-zone-name': 'UTC' }],
  '/interface/ethernet/print': [{ name: 'ether1', running: 'true', disabled: 'false' }, { name: 'ether2', running: 'false', disabled: 'false' }],
  '/ip/neighbor/print': [{ interface: 'ether1', identity: 'sw-crs-1', address: '198.51.100.21', 'mac-address': '02:00:5E:00:53:2A', platform: 'MikroTik', version: '6.48.6', board: 'CRS-LAB' }],
  '/ip/arp/print': [{ interface: 'ether1', address: '192.0.2.50', 'mac-address': '02:00:5E:00:53:01', complete: 'true' }],
  '/interface/print': [{ name: 'ether1', type: 'ether', running: 'true', disabled: 'false' }, { name: 'ether2', type: 'ether', running: 'false', disabled: 'false' }],
};

/** RouterOS 7.x: `/system health` as name/value/type rows, ISO dates, extra neighbor and interface columns. */
export const V7: Record<string, Row[]> = {
  '/system/resource/print': [{ uptime: '1w1d', version: '7.23.8 (long-term)', 'free-memory': '900000000', 'total-memory': '1073741824', 'cpu-load': '1', 'cpu-count': '2', 'architecture-name': 'arm', 'board-name': 'RB-LAB-V7', platform: 'MikroTik' }],
  '/system/health/print': [{ name: 'voltage', value: '24.2', type: 'V' }, { name: 'temperature', value: '32', type: 'C' }],
  '/system/clock/print': [{ time: '13:43:43', date: '2026-10-22', 'time-zone-name': 'UTC' }],
  '/interface/ethernet/print': [{ name: 'ether1', running: 'true', disabled: 'false' }, { name: 'sfp-sfpplus1', running: 'true', disabled: 'false', '.id': '*2' }],
  '/interface/ethernet/monitor': [{ status: 'link-ok', rate: '10Gbps', 'sfp-module-present': 'true', 'sfp-rx-power': '-2.1', 'sfp-tx-power': '-1.9' }],
  '/ip/neighbor/print': [{ interface: 'ether1,bridge-lab', identity: 'sw-crs-1', address: '198.51.100.21', address4: '198.51.100.21', 'mac-address': '02:00:5E:00:53:2A', 'interface-name': 'ether1', 'system-caps': 'bridge,router', platform: 'MikroTik', version: '7.23.8', board: 'CRS-LAB' }],
  '/ip/arp/print': [{ interface: 'ether1', address: '192.0.2.50', 'mac-address': '02:00:5E:00:53:01', complete: 'true' }, { interface: '1. ether1', address: '192.0.2.51', complete: 'false' }],
  '/interface/print': [{ name: 'ether1', type: 'ether', running: 'true', disabled: 'false', 'rx-drop': '0', 'tx-error': '0' }],
};
