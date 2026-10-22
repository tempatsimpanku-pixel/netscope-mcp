import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseConfig } from '../../src/server/config.js';

const root = new URL('../../', import.meta.url);
const read = (p: string) => fs.readFileSync(new URL(p, root), 'utf8');
const ENV = {
  ROS_CORE1_USER: 'u', ROS_CORE1_PASS: 'p', ROS_EDGE1_USER: 'u', ROS_EDGE1_PASS: 'p',
  ROS_SW1_USER: 'u', ROS_SW1_PASS: 'p', SNMP_CORE1_COMMUNITY: 'c', SNMP_SW2_COMMUNITY: 'c',
};

describe('documented configs stay runnable as written', () => {
  it('routers.example.yaml passes --check unchanged (only env vars needed)', () => {
    const cfg = parseConfig(read('routers.example.yaml'), { env: ENV, baseDir: '/nonexistent' });
    expect(cfg.routers).toHaveLength(4);
  });
  for (const readme of ['README.md', 'README.id.md']) {
    it(`${readme} quickstart YAML passes --check unchanged`, () => {
      const m = /```yaml\n((?:settings:|routers:)[\s\S]*?)```/.exec(read(readme));
      expect(m, 'quickstart yaml block').not.toBeNull();
      const cfg = parseConfig(m![1]!, { env: ENV, baseDir: '/nonexistent' });
      expect(cfg.routers.length).toBeGreaterThan(0);
    });
  }
});
