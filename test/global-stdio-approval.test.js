import assert from 'node:assert/strict';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, it } from 'node:test';

const scratchHome = mkdtempSync(join(tmpdir(), 'dsh-mm-global-stdio-'));
const previousHome = process.env.HOME;
const previousUserProfile = process.env.USERPROFILE;
const previousDshHome = process.env.DSH_HOME;

process.env.HOME = scratchHome;
process.env.USERPROFILE = scratchHome;
process.env.DSH_HOME = join(scratchHome, '.dsh');

mkdirSync(process.env.DSH_HOME, { recursive: true });
const statePath = join(process.env.DSH_HOME, 'mcp-manager.json');
const { apply } = await import('../lib/index.js');

const routes = [];
const ctx = {
  logger: { info() {}, warn() {}, error() {} },
  tools: {
    guard: () => () => {},
    register: () => () => {},
    restrict: () => () => {},
    execute: async () => ({})
  },
  webServer: {
    register: route => { routes.push(route); return () => {}; }
  },
  get: () => undefined,
  on: () => () => {},
  inject: (names, callback) => {
    if (typeof callback === 'function' && names.includes('webServer')) {
      callback({
        webServer: ctx.webServer,
        connection: { requestRejection: () => undefined },
        reflect: { get: name => name === 'connection'
          ? { requestRejection: () => undefined }
          : undefined },
        get: () => undefined,
        effect: fn => {
          const dispose = fn();
          return () => { if (typeof dispose === 'function') dispose(); };
        }
      });
    }
    return { dispose: () => {} };
  },
  effect: fn => {
    const dispose = fn();
    return () => { if (typeof dispose === 'function') dispose(); };
  }
};

apply(ctx);
const handler = routes[0]?.handler;
assert.equal(typeof handler, 'function', 'API route should be mounted');

async function request(method, path, body) {
  const payload = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url: path,
    headers: { host: '127.0.0.1:3080' },
    async *[Symbol.asyncIterator]() {
      for (const chunk of payload) yield chunk;
    }
  };
  const res = {
    code: 0,
    body: '',
    writeHead(code) { this.code = code; },
    end(chunk) { this.body = chunk ?? ''; }
  };
  await handler(req, res);
  return { code: res.code, json: res.body ? JSON.parse(res.body) : undefined };
}

const fixture = join(process.cwd(), 'fixtures', 'stdio-trust-mcp.mjs');
const api = '/mcp-manager/api';
const createdIds = new Set();

async function createStdio(name, marker, extra = {}) {
  const result = await request('POST', `${api}/servers`, {
    name,
    type: 'stdio',
    command: process.execPath,
    args: [fixture, marker],
    cwd: scratchHome,
    ...extra
  });
  assert.equal(result.code, 201, JSON.stringify(result.json));
  createdIds.add(result.json.server.id);
  return result.json.server;
}

after(async () => {
  for (const id of createdIds) {
    try { await request('DELETE', `${api}/servers/${id}`); } catch {}
  }
  rmSync(scratchHome, { recursive: true, force: true });
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  if (previousUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = previousUserProfile;
  if (previousDshHome === undefined) delete process.env.DSH_HOME;
  else process.env.DSH_HOME = previousDshHome;
});

it('blocks global stdio until approval, redacts secrets, and preserves omitted env on edit', async t => {
  const firstMarker = join(scratchHome, 'global-first.marker');
  const secondMarker = join(scratchHome, 'global-second.marker');
  const server = await createStdio('global-trust', firstMarker, {
    env: { DSH_MM_PRIVATE_TOKEN: 'keep-this-secret' }
  });

  t.after(async () => {
    await request('DELETE', `${api}/servers/${server.id}`);
  });

  assert.equal(server.status, 'approval-required');
  assert.equal(existsSync(firstMarker), false);

  const listed = await request('GET', `${api}/servers`);
  assert.equal(listed.code, 200);
  const listedServer = listed.json.servers.find(item => item.id === server.id);
  assert.ok(listedServer.envNames.includes('DSH_MM_PRIVATE_TOKEN'));
  assert.equal('env' in listedServer, false);
  assert.equal(JSON.stringify(listedServer).includes('keep-this-secret'), false);

  const manual = await request('POST', `${api}/servers/${server.id}/connect`);
  assert.equal(manual.code, 200);
  assert.equal(manual.json.server.status, 'approval-required');
  assert.equal(existsSync(firstMarker), false);

  const approved = await request('POST', `${api}/servers/${server.id}/trust`);
  assert.equal(approved.code, 200, JSON.stringify(approved.json));
  assert.equal(approved.json.server.status, 'connected');
  assert.equal(existsSync(firstMarker), true);

  const updated = await request('PUT', `${api}/servers/${server.id}`, {
    name: 'global-trust',
    type: 'stdio',
    command: process.execPath,
    args: [fixture, secondMarker],
    cwd: scratchHome
    // Deliberately omit env: this must preserve the stored secret.
  });
  assert.equal(updated.code, 200, JSON.stringify(updated.json));
  assert.equal(updated.json.server.status, 'approval-required');
  assert.equal(existsSync(secondMarker), false);

  const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
  const stored = persisted.servers.find(item => item.id === server.id);
  assert.equal(stored.env.DSH_MM_PRIVATE_TOKEN, 'keep-this-secret');
  assert.equal(persisted.globalStdioApprovals[server.id], undefined);

  const reapproved = await request('POST', `${api}/servers/${server.id}/trust`);
  assert.equal(reapproved.code, 200, JSON.stringify(reapproved.json));
  assert.equal(reapproved.json.server.status, 'connected');
  assert.equal(existsSync(secondMarker), true);
});


it('preserves, replaces, removes, and adds global stdio environment secrets safely', async t => {
  const originalMarker = join(scratchHome, 'global-env-original.marker');
  const preservedMarker = join(scratchHome, 'global-env-preserved.marker');
  const replacedMarker = join(scratchHome, 'global-env-replaced.marker');
  const removedMarker = join(scratchHome, 'global-env-removed.marker');
  const addedMarker = join(scratchHome, 'global-env-added.marker');
  const server = await createStdio('global-env-merge', originalMarker, {
    env: { DSH_MM_EXPLICIT_VALUE: 'original-secret' }
  });
  t.after(async () => {
    await request('DELETE', `${api}/servers/${server.id}`);
  });

  const persistedEnv = () => {
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    return state.servers.find(item => item.id === server.id)?.env ?? {};
  };

  const edit = async (marker, env) => {
    const result = await request('PUT', `${api}/servers/${server.id}`, {
      name: 'global-env-merge',
      type: 'stdio',
      command: process.execPath,
      args: [fixture, marker],
      cwd: scratchHome,
      env
    });
    assert.equal(result.code, 200, JSON.stringify(result.json));
    assert.equal(result.json.server.status, 'approval-required');
    assert.equal(existsSync(marker), false, 'edited server must not execute before approval');
    assert.equal('env' in result.json.server, false);
    return result;
  };

  const approveAndReadMarker = async marker => {
    const approved = await request('POST', `${api}/servers/${server.id}/trust`);
    assert.equal(approved.code, 200, JSON.stringify(approved.json));
    assert.equal(approved.json.server.status, 'connected');
    assert.equal(existsSync(marker), true, 'approved server should execute');
    return JSON.parse(readFileSync(marker, 'utf8'));
  };

  await approveAndReadMarker(originalMarker);
  assert.equal(JSON.parse(readFileSync(originalMarker, 'utf8')).explicitValue, 'original-secret');

  const preserved = await edit(preservedMarker, {
    DSH_MM_EXPLICIT_VALUE: ''
  });
  assert.equal(persistedEnv().DSH_MM_EXPLICIT_VALUE, 'original-secret');
  assert.equal(JSON.stringify(preserved.json).includes('original-secret'), false);
  assert.equal((await approveAndReadMarker(preservedMarker)).explicitValue, 'original-secret');

  const replaced = await edit(replacedMarker, {
    DSH_MM_EXPLICIT_VALUE: 'replacement-secret'
  });
  assert.equal(persistedEnv().DSH_MM_EXPLICIT_VALUE, 'replacement-secret');
  assert.equal(JSON.stringify(replaced.json).includes('replacement-secret'), false);
  assert.equal((await approveAndReadMarker(replacedMarker)).explicitValue, 'replacement-secret');

  await edit(removedMarker, {});
  assert.equal('DSH_MM_EXPLICIT_VALUE' in persistedEnv(), false);
  assert.equal((await approveAndReadMarker(removedMarker)).explicitValue, undefined);

  const added = await edit(addedMarker, {
    DSH_MM_PARENT_SECRET: 'added-secret'
  });
  assert.equal(persistedEnv().DSH_MM_PARENT_SECRET, 'added-secret');
  assert.equal(JSON.stringify(added.json).includes('added-secret'), false);
  assert.equal((await approveAndReadMarker(addedMarker)).inheritedSecret, 'added-secret');
});

it('removes global stdio approval on deletion so re-adding requires approval', async t => {
  const firstMarker = join(scratchHome, 'global-delete-first.marker');
  const secondMarker = join(scratchHome, 'global-delete-second.marker');
  const first = await createStdio('global-delete', firstMarker);

  const approved = await request('POST', `${api}/servers/${first.id}/trust`);
  assert.equal(approved.code, 200);
  assert.equal(existsSync(firstMarker), true);

  const deleted = await request('DELETE', `${api}/servers/${first.id}`);
  assert.equal(deleted.code, 200);
  const afterDelete = JSON.parse(readFileSync(statePath, 'utf8'));
  assert.equal(afterDelete.globalStdioApprovals[first.id], undefined);

  const second = await createStdio('global-delete', secondMarker);
  t.after(async () => {
    await request('DELETE', `${api}/servers/${second.id}`);
  });

  assert.notEqual(second.id, first.id);
  assert.equal(second.status, 'approval-required');
  assert.equal(existsSync(secondMarker), false);
});

it('does not require stdio execution approval for HTTP servers', async () => {
  const created = await request('POST', `${api}/servers`, {
    name: 'global-http-noauth',
    type: 'http',
    url: 'http://127.0.0.1:9/mcp',
    authMode: 'none'
  });
  assert.equal(created.code, 201);
  createdIds.add(created.json.server.id);
  assert.notEqual(created.json.server.status, 'approval-required');

  const trust = await request('POST', `${api}/servers/${created.json.server.id}/trust`);
  assert.equal(trust.code, 400);
});
