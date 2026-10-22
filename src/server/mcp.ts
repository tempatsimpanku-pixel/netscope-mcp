import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { RECIPES, type NetScope } from '../core/engine.js';
import type { NetResult } from '../core/types.js';

export const SERVER_NAME = 'netscope-mcp';

const device = z.string().min(1).max(80).describe('Device id, name or IP exactly as shown by list_devices.');
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

function toResult(r: NetResult): CallToolResult {
  return {
    content: [{ type: 'text', text: r.text }],
    structuredContent: { ok: !r.isError, ...(r.action ? { action: r.action } : {}), ...(r.errorKind ? { error: r.errorKind } : {}), ...(r.data !== undefined ? { data: r.data } : {}) },
    ...(r.isError ? { isError: true } : {}),
  };
}

/** Build one MCP server exposing the read-only tools of a NetScope. Safe to call per request (stateless HTTP). */
export function createMcpServer(scope: NetScope, version: string): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version }, {
    instructions: 'Read-only network visibility for ISP/NOC operators. Every tool only reads: write commands are refused by an allowlist. '
      + 'Start with list_devices. Prefer mikrotik_recipe (one call replaces many reads) and mikrotik_batch for several commands. '
      + 'mikrotik_snapshot is periodic data (its age is always reported); confirm with a live tool before acting on it.',
  });

  server.registerTool('list_devices', {
    title: 'List devices',
    description: 'List the configured network devices (id, name, host, family, group, which tools apply). No credentials are ever shown.',
    inputSchema: { filter: z.string().max(60).optional().describe('Substring of id/name/host/family/group.'), group: z.string().max(64).optional().describe('Exact group name.') },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.listDevices(a)));

  server.registerTool('mikrotik_read', {
    title: 'Read one RouterOS command',
    description: 'Run ONE read-only command on a MikroTik RouterOS router/switch: `print` (full menu path from the positive list, no abbreviations; `where key=value`, `proplist=`, `count-only`; large tables such as /ip route need count-only or where), '
      + '`monitor … once` (ethernet, bonding, vrrp, wireless, wifi, cpu, health), `export hide-sensitive` (over SSH, per-device port), `ping`, `traceroute`. '
      + 'Everything else (set/add/remove/reset/reboot/script/import/fetch/file=/sniffer/torch/follow…) is refused. Secrets are redacted. /log print returns the 60 newest entries (tail=N ≤ 200) and is disabled while redact_pii is on.',
    inputSchema: {
      device,
      command: z.string().min(1).max(300).describe('RouterOS CLI, e.g. "/system resource print", "/ip address print where interface=ether1", "/interface ethernet monitor sfp-sfpplus1 once", "/ppp active print count-only", "/ip firewall nat export hide-sensitive terse".'),
      tail: z.number().int().min(1).max(200).optional().describe('Only for /log print: number of newest entries.'),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.read({ device: a.device, command: a.tail !== undefined && /^\/?log\s+print\s*$/i.test(a.command.trim()) ? `${a.command.trim()} tail=${a.tail}` : a.command })));

  server.registerTool('mikrotik_batch', {
    title: 'Read many RouterOS commands',
    description: 'Run up to 30 read-only commands (each {device, command}) in ONE call. Different routers run in parallel, commands on one router run in order over a single reused session. '
      + 'Every item passes the same allowlist as mikrotik_read; one failing item never fails the others.',
    inputSchema: { items: z.array(z.object({ device, command: z.string().min(1).max(300).describe('Read-only RouterOS command.') })).min(1).max(30) },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.batch({ items: a.items })));

  server.registerTool('mikrotik_recipe', {
    title: 'Diagnosis recipe',
    description: 'Structured read-only diagnosis in one call. `health`: resource + health + SFP optics + down ports. `neighbors-map`: neighbors + ARP counts + down interfaces, matched against known devices (1–8 devices). '
      + '`pppoe-lookup`: customer name → ppp active / safe secret columns / dynamic interface; without `device` it searches every router.',
    inputSchema: {
      recipe: z.enum(RECIPES),
      device: z.union([device, z.array(device).max(8)]).optional().describe('Device(s); required for health and neighbors-map.'),
      name: z.string().max(64).optional().describe('pppoe-lookup: PPPoE username (letters, digits, . _ @ -).'),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.recipe(a)));

  server.registerTool('ping', {
    title: 'Ping',
    description: 'Ping a literal IP address from a router (or "local" = the MCP host, only if enabled). Host names, loopback, link-local, multicast and broadcast targets are refused. 1–10 packets.',
    inputSchema: {
      from: z.string().min(1).max(80).describe('Device id/name, or "local".'), target: z.string().min(2).max(45).describe('Literal IPv4/IPv6 address.'),
      count: z.number().int().min(1).max(10).optional(), size: z.number().int().min(28).max(1400).optional(),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.ping(a)));

  server.registerTool('traceroute', {
    title: 'Traceroute',
    description: 'Traceroute to a literal IP address from a router (or "local" if enabled). One probe per hop, at most 20 hops; can take 10–45 s.',
    inputSchema: {
      from: z.string().min(1).max(80).describe('Device id/name, or "local".'), target: z.string().min(2).max(45).describe('Literal IPv4/IPv6 address.'),
      max_hops: z.number().int().min(1).max(20).optional(),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.traceroute(a)));

  server.registerTool('snmp_get', {
    title: 'SNMP get/walk',
    description: 'SNMP v2c GET or walk on a configured device (no SET exists). Use `name` (sysUpTime, sysName, sysDescr, ifName, ifDescr, ifOperStatus, ifHCInOctets, ifHCOutOctets, ifHighSpeed, ifAlias, hrProcessorLoad; "ifOperStatus.5" = one index; a table name = walk) '
      + 'or a numeric `oid` inside the readable subtrees (system, interfaces, hrProcessorLoad/hrStorage, IP/ARP, bridge, sensors, UCD load/mem/cpu, vendor 14988.1.1). At most 500 rows, 10 s.',
    inputSchema: {
      device, name: z.string().max(40).optional().describe('SNMP name, e.g. ifOperStatus or sysUpTime.0.'),
      oid: z.string().max(200).optional().describe('Alternative: numeric OID, e.g. 1.3.6.1.2.1.1.3.0.'), walk: z.boolean().optional().describe('Force a walk for a numeric OID.'),
      limit: z.number().int().min(1).max(500).optional().describe('Max rows (default 100).'),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.snmpGet(a)));

  server.registerTool('switch_read', {
    title: 'Read a switch',
    description: 'Ready-made reads for MikroTik switches: `resource`, `health`, `ethernet-all`, `ethernet` (counters), `bridge-port`, `bridge-vlan`, `bridge-host` (FDB; give a filter), `mac-table-count`, `poe`, `neighbor`. '
      + 'SwOS switches are read over SNMP only: `sysinfo`, `interfaces`. Optional filter `field=value`, e.g. on-interface=sfp-sfpplus1.',
    inputSchema: {
      device, command: z.enum(['resource', 'health', 'ethernet-all', 'ethernet', 'bridge-port', 'bridge-vlan', 'bridge-host', 'mac-table-count', 'poe', 'neighbor', 'sysinfo', 'interfaces']),
      filter: z.string().max(120).optional().describe('field=value, e.g. vid=99 or on-interface=sfp-sfpplus1.'),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.switchRead(a)));

  server.registerTool('mikrotik_snapshot', {
    title: 'Periodic snapshot / cross-router search',
    description: 'Read the periodic snapshot (not live; milliseconds, touches no router; its AGE is always reported, older than 30 min = STALE): resource, interfaces (down/disabled/speed), neighbors, ARP (counts, failed, gateway), PPP active count. '
      + 'No arguments = summary of all routers; `device` (+`section`) = detail of one; `search` = find an interface name, neighbor identity or IP/MAC across ALL routers (PPP names/IPs/MACs only when the server stores customer data). Needs the server to run with --snapshot.',
    inputSchema: {
      device: device.optional(), section: z.enum(['summary', 'resource', 'interface', 'neighbor', 'arp', 'ppp']).optional().describe('With device: part to detail (default summary).'),
      search: z.string().min(2).max(64).optional().describe('Substring / IP / MAC to look for in every router.'), limit: z.number().int().min(1).max(200).optional(),
    },
    annotations: READ_ONLY,
  }, async (a) => toResult(await scope.snapshot(a)));

  return server;
}
