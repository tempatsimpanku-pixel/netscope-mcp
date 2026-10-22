/* global console, process, URL */
// Validate server.json against the vendored official MCP registry schema
// (https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json)
// and check that it agrees with package.json. Offline; used by `npm run check:server-json` and CI.
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const schema = read('./server.schema.2025-12-11.json');
const server = read('../server.json');
const pkg = read('../package.json');

const problems = [];
if (server.$schema !== schema.$id) problems.push(`$schema (${server.$schema}) != vendored schema id (${schema.$id})`);

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(schema);
if (!validate(server)) {
  for (const e of validate.errors ?? []) problems.push(`schema: ${e.instancePath || '/'} ${e.message} ${JSON.stringify(e.params)}`);
}

if (server.name !== pkg.mcpName) problems.push(`server.json name (${server.name}) != package.json mcpName (${pkg.mcpName})`);
if (server.version !== pkg.version) problems.push(`server.json version (${server.version}) != package.json version (${pkg.version})`);
for (const [i, p] of (server.packages ?? []).entries()) {
  if (p.registryType === 'npm') {
    if (p.identifier !== pkg.name) problems.push(`packages[${i}].identifier (${p.identifier}) != package name (${pkg.name})`);
    if (p.version !== pkg.version) problems.push(`packages[${i}].version (${p.version}) != package version (${pkg.version})`);
  }
}

if (problems.length) {
  console.error('server.json check FAILED:\n- ' + problems.join('\n- '));
  process.exit(1);
}
console.log(`server.json OK (${server.name}@${server.version}, schema ${schema.$id.split('/').at(-2)})`);
