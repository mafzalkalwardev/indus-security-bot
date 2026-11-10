import { expect, it } from 'vitest';
import { fixAllowed, parseListeners, parseSsh } from '../src/logic';

it('only allowlists known fixes and reads ssh posture', () => {
  expect(fixAllowed('fail2ban-reload')).toBe(true);
  expect(fixAllowed('rm-rf')).toBe(false);
  expect(parseSsh('PermitRootLogin yes\nPasswordAuthentication no\n')).toEqual(['Root SSH login is enabled.']);
  expect(parseListeners('LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:9100 0.0.0.0:*\n')).toEqual(['9100']);
});
