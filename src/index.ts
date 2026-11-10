import { createBotService } from '@indus/bot-core';
import { resolve, run } from './logic';

createBotService({
  id: 'security',
  name: 'Security',
  description: 'Reads the VPS posture and applies only an allowlisted fix after you approve it.',
  accent: '#d36b5c',
  defaultPort: 41751,
  capabilities: ['audit'],
  defaultSettings: { snippetDir: '/etc/nginx/snippets' },
  fields: [{ key: 'snippetDir', label: 'Nginx snippet directory', type: 'text' }],
  desired: [{ key: 'audit', task: 'audit', cron: '15 */6 * * *', group: 'default' }],
  autoTask: 'audit',
  runTask: run,
  resolveApproval: resolve,
}).start().catch((error) => { console.error(error); process.exit(1); });
