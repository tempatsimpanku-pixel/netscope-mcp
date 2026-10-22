import { execFileSync } from 'node:child_process';
import path from 'node:path';

/** Integration tests spawn dist/cli.js: build once before the run. */
export default function setup(): void {
  const root = path.resolve(import.meta.dirname, '..', '..');
  execFileSync(process.execPath, [path.join(root, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.build.json'], { cwd: root, stdio: 'inherit' });
}
