import fs from 'node:fs';

/** Package version, read from package.json (single source of truth; ships in every npm tarball).
 * Resolves from both src/ (tests) and dist/ (published build), which sit one level below the package root. */
export const VERSION: string = (JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;
