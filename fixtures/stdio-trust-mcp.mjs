import { createInterface } from 'node:readline';
import { writeFileSync } from 'node:fs';

const marker = process.argv[2];
const startupDelayMs = Number(process.argv[3] ?? 0);
if (marker) writeFileSync(marker, JSON.stringify({
  pid: process.pid,
  inheritedSecret: process.env.DSH_MM_PARENT_SECRET,
  explicitValue: process.env.DSH_MM_EXPLICIT_VALUE,
  hasPath: Boolean(process.env.PATH),
  hasHome: Boolean(process.env.HOME || process.env.USERPROFILE)
}));

const lines = createInterface({ input: process.stdin });

lines.on('line', line => {
  const message = JSON.parse(line);
  if (message.id === undefined) return;

  let result;
  if (message.method === 'initialize') {
    result = {
      protocolVersion: '2025-03-26',
      capabilities: { tools: {} },
      serverInfo: { name: 'stdio-trust-fixture', version: '1' }
    };
  } else if (message.method === 'tools/list') {
    result = {
      tools: [{
        name: 'fixture_echo',
        inputSchema: { type: 'object', properties: {} }
      }]
    };
  } else {
    result = { content: [{ type: 'text', text: 'ok' }] };
  }

  const response = JSON.stringify({
    jsonrpc: '2.0',
    id: message.id,
    result
  }) + '\n';

  if (message.method === 'initialize' && startupDelayMs > 0) {
    setTimeout(() => process.stdout.write(response), startupDelayMs);
  } else {
    process.stdout.write(response);
  }
});
