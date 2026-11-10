import { execCommand, type TaskContext, type TaskResult } from '@indus/bot-core';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export const SAFE_FIXES = ['fail2ban-reload', 'nginx-headers-snippet'] as const;
const UNIT = /^[a-zA-Z0-9][a-zA-Z0-9:@._-]{0,80}$/;

export function parseSsh(text: string): string[] {
  const issues: string[] = [];
  if (/^\s*PermitRootLogin\s+yes/im.test(text)) issues.push('Root SSH login is enabled.');
  if (/^\s*PasswordAuthentication\s+yes/im.test(text)) issues.push('SSH password login is enabled.');
  return issues;
}

export function parseListeners(text: string): string[] {
  return [...new Set(text.split('\n').map((line) => {
    const match = /:(\d+)\s/.exec(line);
    return match ? match[1] : '';
  }).filter((port) => port && port !== '22' && port !== '80' && port !== '443'))];
}

export function fixAllowed(key: string): boolean {
  return (SAFE_FIXES as readonly string[]).includes(key);
}

const HEADERS = `add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
`;

export async function run(ctx: TaskContext): Promise<TaskResult> {
  if (ctx.task === 'instruct') {
    const reply = await ctx.llm('You are the INDUS security bot. Propose fixes. Do not claim you changed the server.', String(ctx.payload.message || ''));
    return { summary: reply.text.slice(0, 300) };
  }
  const ssh = await execCommand('sshd', ['-T']);
  const sshText = ssh.stdout || '';
  const issues = [
    ...parseSsh(sshText),
    ...(await execCommand('ufw', ['status'])).code === 0 ? [] : ['ufw status could not be read.'],
  ];
  const listeners = parseListeners((await execCommand('ss', ['-lnt'])).stdout);
  if (listeners.length) issues.push(`Listening ports outside 22/80/443: ${listeners.join(', ')}.`);
  const failed = await execCommand('lastb', ['-n', '20']);
  if (failed.code === 0 && failed.stdout.trim()) issues.push('Recent failed logins are in lastb.');
  const updates = await execCommand('apt-get', ['-s', 'upgrade']);
  const security = (updates.stdout.match(/security/gi) || []).length;
  if (security) issues.push(`${security} simulated upgrade lines mention security.`);
  for (const issue of issues) {
    const key = issue.includes('fail2ban') ? 'fail2ban-reload' : issue.toLowerCase().includes('header') ? 'nginx-headers-snippet' : '';
    ctx.propose({ type: 'security_fix', title: issue, summary: 'Nothing is applied until you approve an allowlisted fix.', body: issue, payload: { fix: key } });
  }
  if (!issues.length) ctx.log('info', 'No obvious findings.');
  return { summary: issues.length ? `${issues.length} findings. Fixes wait for approval.` : 'No obvious findings.', details: { issues, listeners } };
}

export async function resolve(item: { payload: Record<string, unknown> }, _input: Record<string, unknown>, deps: { settings: () => Record<string, unknown>; dataDir: string }) {
  const fix = String(item.payload.fix || '');
  if (!fixAllowed(fix)) throw new Error('That fix is not on the allowlist.');
  if (fix === 'fail2ban-reload') {
    const result = await execCommand('fail2ban-client', ['reload']);
    if (result.code !== 0) throw new Error(result.stderr || 'fail2ban-client failed.');
    return { applied: fix };
  }
  const dir = String(deps.settings().snippetDir || '');
  if (!dir.startsWith('/etc/nginx/') || dir.includes('..')) throw new Error('Snippet directory must live under /etc/nginx.');
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, 'indus-security-headers.conf'), HEADERS, { mode: 0o644 });
  return { applied: fix, file: path.join(dir, 'indus-security-headers.conf') };
}
