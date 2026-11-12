import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import dns from 'node:dns';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, it } from 'node:test';

// STATE_PATH is derived from homedir() at module evaluation: HOME on POSIX,
// USERPROFILE on Windows. Pin both before importing; DSH_HOME alone is not enough.
const scratchHome = mkdtempSync(join(tmpdir(), 'dsh-mm-oauth-'));
process.env.HOME = scratchHome;
process.env.USERPROFILE = scratchHome;
process.env.DSH_HOME = join(scratchHome, '.dsh');
after(() => rmSync(scratchHome, { recursive: true, force: true }));

// Fail before loading the plugin if isolation regresses (issue #16). Check the
// Windows variable even on POSIX so every platform catches a missing assignment.
assert.equal(process.env.USERPROFILE, scratchHome, 'USERPROFILE must use the scratch home');
assert.equal(homedir(), scratchHome, 'homedir() must resolve to the scratch home');
mkdirSync(join(scratchHome, '.dsh'), { recursive: true });
const statePath = join(scratchHome, '.dsh', 'mcp-manager.json');

const { apply } = await import('../lib/index.js');

/** Minimal ctx: enough for apply() to mount its route without a real harness. */
function makeCtx(config = {}) {
  let connectionRejection;
  const connection = { requestRejection: () => connectionRejection };
  const routes = [];
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    tools: { guard: () => () => {}, register: () => () => {}, restrict: () => () => {}, execute: async () => ({}) },
    webServer: { register: (route) => { routes.push(route); return () => {}; } },
    get: () => undefined,
    on: () => () => {},
    inject: (names, callback) => {
      if (typeof callback === 'function' && names.includes('webServer')) {
        callback({
          webServer: ctx.webServer,
          connection,
          reflect: { get: (name) => name === 'connection' ? connection : undefined },
          get: () => undefined,
          effect: (fn) => { const dispose = fn(); return () => { if (typeof dispose === 'function') dispose(); }; },
        });
      }
      return { dispose: () => {} };
    },
    effect: (fn) => { const dispose = fn(); return () => { if (typeof dispose === 'function') dispose(); }; },
  };
  apply(ctx, config);
  return { routes, handler: routes[0]?.handler, connection, setConnectionRejection: (value) => { connectionRejection = value; } };
}

/** Call the mounted route with a minimal req/res pair; returns the raw body too. */
async function request(handler, method, path, body, headers = {}) {
  const payload = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  const req = {
    method,
    url: path,
    headers: { host: '127.0.0.1:3080', ...headers },
    async *[Symbol.asyncIterator]() { for (const chunk of payload) yield chunk; },
  };
  const res = {
    code: 0,
    body: '',
    writeHead(code) { this.code = code; },
    end(chunk) { this.body = chunk ?? ''; },
  };
  await handler(req, res);
  let json;
  try { json = res.body ? JSON.parse(res.body) : undefined; } catch {}
  return { code: res.code, json, text: String(res.body) };
}

it('rejects cross-origin browser writes, including simple text/plain JSON requests', async () => {
  const { handler } = makeCtx();
  const rejected = await request(
    handler,
    'POST',
    '/mcp-manager/api/settings/on-demand',
    { enabled: true },
    { origin: 'https://attacker.example', 'content-type': 'text/plain' },
  );
  assert.equal(rejected.code, 403, rejected.text);
  assert.equal(rejected.json.error, 'untrusted request origin');
  const unchanged = await request(handler, 'GET', '/mcp-manager/api/settings');
  assert.equal(unchanged.json.onDemandToolInjection, false);

  for (const origin of ['null', 'https://127.0.0.1:3080.evil.example', 'http://127.0.0.1:3080/path']) {
    const invalid = await request(
      handler,
      'POST',
      '/mcp-manager/api/settings/on-demand',
      { enabled: true },
      { origin },
    );
    assert.equal(invalid.code, 403, `origin ${origin} should be rejected`);
  }

  const sameOrigin = await request(
    handler,
    'POST',
    '/mcp-manager/api/settings/on-demand',
    { enabled: true },
    { origin: 'http://127.0.0.1:3080' },
  );
  assert.equal(sameOrigin.code, 200, sameOrigin.text);
});


it('requires DSH authentication for API requests but permits a valid OAuth callback without it', async (t) => {
  const stub = await startStub({ advertiseRegistration: true, requiredApplicationType: 'native' });
  const ctx = makeCtx();
  const { handler, setConnectionRejection } = ctx;
  let id;

  t.after(async () => {
    setConnectionRejection(undefined);
    if (id) await request(handler, 'DELETE', `/mcp-manager/api/servers/${id}`);
    await stub.close();
  });

  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'session-auth-roundtrip',
    type: 'http',
    url: stub.mcpUrl,
  });
  assert.equal(created.code, 201, created.text);
  id = created.json.server.id;

  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);
  const state = new URL(auth.json.authorizeUrl).searchParams.get('state');

  setConnectionRejection(401);
  assert.equal((await request(handler, 'GET', '/mcp-manager/api/ping')).code, 401);

  setConnectionRejection(403);
  assert.equal((await request(handler, 'GET', '/mcp-manager/api/ping')).code, 403);

  const callback = await request(
    handler,
    'GET',
    `/mcp-manager/callback/${id}?code=synthetic-code&state=${state}`,
  );
  assert.match(callback.text, /Authorized/);
  assert.equal(stub.forms.length, 1);

  assert.equal((await request(handler, 'GET', '/mcp-manager/api/ping')).code, 403);
});

/**
 * One dependency-free server playing both roles from the GitHub MCP topology:
 * the MCP endpoint 401s with a resource_metadata pointer, the protected-resource
 * document names a *path-carrying* authorization server, and the AS metadata is
 * only served at the RFC 8414 path-inserted URL. It records every request so a
 * test can prove which URLs were probed.
 */
function startStub({ advertiseRegistration = false, tokenBody = null, registrationBody = null, requiredApplicationType = '', metadataOverrides = {}, metadataResponseMode = 'normal', resourceMetadataRedirect = '', authorizationServers = null, resourceMetadataHost = '', closeRedirectConnection = false } = {}) {

  const seen = [];
  const forms = [];
  const registrations = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      seen.push(req.method + ' ' + req.url + ' host=' + req.headers.host + ' socket=' + req.socket.remotePort);
      const send = (code, body, headers = {}) => {
        res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
        res.end(typeof body === 'string' ? body : JSON.stringify(body));
      };
      const base = `http://127.0.0.1:${server.address().port}`;

      if (req.url === '/mcp') {
        if (requiredApplicationType && req.headers.authorization === 'Bearer example-access-token') {
          const message = JSON.parse(raw || '{}');
          if (message.id === undefined) return send(202, '');
          const result = message.method === 'initialize'
            ? { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'strict-oauth', version: '1' } }
            : message.method === 'tools/list' ? { tools: [{ name: 'echo', inputSchema: { type: 'object' } }] } : {};
          return send(200, { jsonrpc: '2.0', id: message.id, result });
        }
        const metadataBase = resourceMetadataHost
          ? `http://${resourceMetadataHost}:${server.address().port}`
          : base;
        return send(401, { error: 'unauthorized' }, {
          'WWW-Authenticate': `Bearer error="invalid_request", error_description="No access token was provided in this request", resource_metadata="${metadataBase}/.well-known/oauth-protected-resource/mcp"`,
        });
      }
      if (req.url === '/.well-known/oauth-protected-resource/mcp') {
        if (resourceMetadataRedirect) {
          res.writeHead(302, {
            Location: resourceMetadataRedirect,
            ...(closeRedirectConnection ? { Connection: 'close' } : {}),
          });
          return res.end();
        }
        return send(200, { resource: `${base}/mcp`, authorization_servers: authorizationServers ?? [`${base}/login/oauth`] });
      }
      if (req.url === '/metadata-redirect-target') {

        return send(200, { resource: `${base}/mcp`, authorization_servers: [`${base}/login/oauth`] });
      }
      if (req.url === '/.well-known/oauth-protected-resource') return send(404, { error: 'not found' });
      if (req.url === '/.well-known/oauth-authorization-server/login/oauth') {
        const md = {
          issuer: `${base}/login/oauth`,
          authorization_endpoint: `${base}/login/oauth/authorize`,
          token_endpoint: `${base}/login/oauth/access_token`,
          code_challenge_methods_supported: ['S256'],
        };
        if (advertiseRegistration) md.registration_endpoint = `${base}/register`;
        Object.assign(md, metadataOverrides);
        if (metadataResponseMode === 'length' || metadataResponseMode === 'chunked') {
          const responseBody = JSON.stringify(md);
          if (metadataResponseMode === 'length') {
            res.writeHead(200, {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(responseBody),
            });
            return res.end(responseBody);
          }
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Transfer-Encoding': 'chunked',
          });
          res.write(responseBody.slice(0, 600000));
          return res.end(responseBody.slice(600000));
        }
        return send(200, md);
      }
      if (req.url === '/.well-known/oauth-authorization-server') return send(404, { error: 'not found' });
      if (req.url === '/register') {
        if (!advertiseRegistration) return send(404, '404 page not found');
        let payload = {};
        try { payload = JSON.parse(raw || '{}'); } catch {}
        registrations.push(payload);
        if (!Array.isArray(payload.redirect_uris) || payload.redirect_uris.length === 0) return send(400, { error: 'invalid_client_metadata' });
        if (requiredApplicationType && payload.application_type !== requiredApplicationType) {
          return send(400, { error: 'invalid_client_metadata', error_description: `application_type must be ${requiredApplicationType}` });
        }
        return send(201, registrationBody ?? { client_id: 'dcr-client', redirect_uris: payload.redirect_uris });
      }
      if (req.url === '/login/oauth/access_token') {
        forms.push(new URLSearchParams(raw));
        if (tokenBody) return send(400, tokenBody);
        return send(200, { access_token: 'example-access-token', refresh_token: 'example-refresh-token', token_type: 'bearer', expires_in: 3600 });
      }
      return send(404, { error: 'not found' });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const base = `http://127.0.0.1:${server.address().port}`;
      resolve({
        base,
        mcpUrl: `${base}/mcp`,
        seen,
        forms,
        registrations,
        async close() {
          server.closeAllConnections?.();
          await new Promise((done) => server.close(done));
        },
      });
    });
  });
}

const state = () => JSON.parse(readFileSync(statePath, 'utf8'));

// Records requests to an advertised endpoint but deliberately returns an
// invalid response, allowing tests to verify the destination without completing
// registration or token exchange.
async function startSink() {
  const requests = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      requests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'deliberate_test_sink' }));
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  return {
    url: `http://127.0.0.1:${server.address().port}/sink`,
    requests,
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

it('rejects cross-origin redirects when fetching protected-resource metadata', async (t) => {
  const sink = await startSink();
  const stub = await startStub({ resourceMetadataRedirect: sink.url });
  t.after(async () => {
    await stub.close();
    await sink.close();
  });

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'metadata-cross-origin-redirect',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  assert.equal(sink.requests.length, 0, 'the cross-origin redirect destination must not receive a request');
});

it('allows same-origin redirects when fetching protected-resource metadata', async (t) => {
  const stub = await startStub({ resourceMetadataRedirect: '/metadata-redirect-target' });
  t.after(() => stub.close());

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'metadata-same-origin-redirect',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  assert.ok(stub.seen.some(entry => entry.startsWith('GET /metadata-redirect-target')), 'the same-origin redirect destination should receive a request');
});

it('rejects unsafe dynamic client registration endpoints before sending registration data', async (t) => {
  const sink = await startSink();
  t.after(() => sink.close());

  const cases = [
    ['non-loopback HTTP', 'http://example.invalid/unexpected'],
    ['embedded credentials', `http://user:pass@127.0.0.1:${new URL(sink.url).port}/unexpected`],
    ['URL fragment', `${sink.url}#unexpected`],
  ];

  let caseNumber = 0;
  for (const [label, registrationEndpoint] of cases) {
    caseNumber += 1;
    const stub = await startStub({
      advertiseRegistration: true,
      metadataOverrides: { registration_endpoint: registrationEndpoint },
    });
    t.after(() => stub.close());

    const { handler } = makeCtx();
    const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
      name: `unsafe-reg-${caseNumber}`,
      type: 'http',
      url: stub.mcpUrl,
      authMode: 'oauth',
    });
    assert.equal(created.code, 201, created.text);

    const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${created.json.server.id}/auth`);
    assert.equal(auth.code, 500, `${label} should be rejected`);
    assert.match(auth.json.error, /Unsafe OAuth registration endpoint/, `${label} should fail validation explicitly`);
    assert.equal(sink.requests.length, 0, `${label} must not reach the loopback sink`);
  }
});

it('allows HTTPS cross-host dynamic client registration', async (t) => {
  const registrationUrl = 'https://registration.example.test/register';
  const registrationRequests = [];
  const originalFetch = globalThis.fetch;

  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    if (String(url) === registrationUrl) {
      registrationRequests.push({ url: String(url), ...options });
      return new Response(JSON.stringify({ client_id: 'https-cross-host-client' }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return originalFetch(url, options);
  });

  const stub = await startStub({
    advertiseRegistration: true,
    metadataOverrides: { registration_endpoint: registrationUrl },
  });
  t.after(async () => {
    await stub.close();
  });

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'https-cross-host-registration',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
  });
  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  assert.equal(registrationRequests.length, 1, 'the HTTPS registration endpoint should receive one request');
  assert.equal(registrationRequests[0].url, registrationUrl);
  assert.equal(registrationRequests[0].method, 'POST');

  const registration = JSON.parse(registrationRequests[0].body);
  assert.match(registration.client_name, /^dsh-mcp-manager-/);
  assert.deepEqual(registration.redirect_uris, [`http://127.0.0.1:3080/mcp-manager/callback/${id}`]);
  assert.equal(registration.token_endpoint_auth_method, 'none');
});

it('sends dynamic client registration to the advertised endpoint', async (t) => {
  const sink = await startSink();
  const stub = await startStub({
    advertiseRegistration: true,
    metadataOverrides: { registration_endpoint: sink.url },
  });
  t.after(async () => {
    await stub.close();
    await sink.close();
  });

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'registration-endpoint-review',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
  });
  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 500, 'the sink does not return a valid registration response');

  assert.equal(sink.requests.length, 1, 'the advertised registration endpoint received the request');
  assert.equal(sink.requests[0].method, 'POST');
  const registration = JSON.parse(sink.requests[0].body);
  assert.match(registration.client_name, /^dsh-mcp-manager-/);
  assert.deepEqual(registration.redirect_uris, [`http://127.0.0.1:3080/mcp-manager/callback/${id}`]);
  assert.equal(registration.token_endpoint_auth_method, 'none');
});



it('posts authorization codes to the advertised token endpoint', async (t) => {
  const sink = await startSink();
  const stub = await startStub({
    metadataOverrides: { token_endpoint: sink.url },
  });
  t.after(async () => {
    await stub.close();
    await sink.close();
  });

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'token-endpoint-review',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  const flowState = new URL(auth.json.authorizeUrl).searchParams.get('state');
  await request(handler, 'GET', `/mcp-manager/callback/${id}?code=synthetic-code&state=${flowState}`);

  assert.equal(sink.requests.length, 1, 'the advertised token endpoint received the exchange');
  assert.equal(sink.requests[0].method, 'POST');
  const form = new URLSearchParams(sink.requests[0].body);
  assert.equal(form.get('grant_type'), 'authorization_code');
  assert.equal(form.get('code'), 'synthetic-code');
  assert.equal(form.get('client_id'), 'synthetic-client');
  assert.ok(form.get('code_verifier'), 'the PKCE verifier was sent to the advertised endpoint');
});




it('rejects an unsafe token endpoint before sending a refresh token', async (t) => {
  const metadataOverrides = {};
  const fetchCalls = [];
  const originalFetch = globalThis.fetch;

  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    const target = String(url);
    fetchCalls.push(target);

    // Never make a real request if the unsafe endpoint is reached.
    if (target === 'http://example.com/token') {
      return new Response('{}', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return originalFetch(url, options);
  });

  const stub = await startStub({ metadataOverrides });

  t.after(async () => {
    await stub.close();
  });

  const { handler } = makeCtx();

  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'unsafe-refresh-endpoint',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });

  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;

  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  const flowState = new URL(auth.json.authorizeUrl).searchParams.get('state');

  await request(
    handler,
    'GET',
    `/mcp-manager/callback/${id}?code=synthetic-code&state=${flowState}`,
  );

  const requestsBeforeUnsafeRefresh = stub.forms.length;

  metadataOverrides.token_endpoint = 'http://example.com/token';

  const connected = await request(
    handler,
    'POST',
    `/mcp-manager/api/servers/${id}/connect`,
  );

  assert.equal(connected.code, 200, connected.text);
  assert.equal(connected.json.server.status, 'error');
  assert.match(connected.json.server.error, /Unsafe OAuth token endpoint/);

  assert.equal(
    fetchCalls.includes('http://example.com/token'),
    false,
    'fetch must never be called with the unsafe token endpoint',
  );

  assert.equal(
    stub.forms.length,
    requestsBeforeUnsafeRefresh,
    'no refresh-token request should be sent after the endpoint becomes unsafe',
  );
});


// SEP-837: a strict OIDC registration endpoint distinguishes locally hosted
// clients from remote web clients. These are synthetic Host headers only;
// every network request goes to the loopback stub, never to these hostnames.
for (const [host, applicationType] of [
  ['localhost:3080', 'native'],
  ['127.0.0.1:3080', 'native'],
  ['127.0.0.2:3080', 'native'],
  ['[::1]:3080', 'native'],
  ['remote.example.test:3080', 'web'],
  ['localhost.example.test:3080', 'web'],
  ['127.example.test:3080', 'web'],
]) {
  it(`issue #21: registers ${host} as ${applicationType}`, async (t) => {
    const stub = await startStub({ advertiseRegistration: true, requiredApplicationType: applicationType });
    t.after(() => stub.close());
    // Test-only origins also satisfy hosts that require an explicit allowlist.
    const { handler } = makeCtx({ publicOrigins: [`http://${host}`] });
    const created = await request(handler, 'POST', '/mcp-manager/api/servers', { name: `type-${host.replace(/[^A-Za-z0-9_-]/g, '_')}`, type: 'http', url: stub.mcpUrl });
    assert.equal(created.code, 201, created.text);
    const id = created.json.server.id;
    const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`, undefined, { host });
    assert.equal(auth.code, 200, auth.text);
    assert.equal(stub.registrations.length, 1);
    assert.equal(stub.registrations[0].application_type, applicationType);
    assert.deepEqual(stub.registrations[0].redirect_uris, [`http://${host}/mcp-manager/callback/${id}`]);
    assert.equal(new URL(auth.json.authorizeUrl).searchParams.get('client_id'), 'dcr-client');
  });
}

it('issue #21: strict native registration completes PKCE, connects, and reuses only the same redirect', async (t) => {
  const stub = await startStub({ advertiseRegistration: true, requiredApplicationType: 'native' });
  const { handler } = makeCtx();
  let id;
  t.after(async () => {
    if (id) await request(handler, 'DELETE', `/mcp-manager/api/servers/${id}`);
    await stub.close();
  });
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', { name: 'native-roundtrip', type: 'http', url: stub.mcpUrl });
  assert.equal(created.code, 201, created.text);
  id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);
  const authorize = new URL(auth.json.authorizeUrl);
  const redirect = `http://127.0.0.1:3080/mcp-manager/callback/${id}`;
  assert.equal(authorize.searchParams.get('redirect_uri'), redirect);
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(stub.registrations[0].token_endpoint_auth_method, 'none');
  assert.match(stub.registrations[0].client_name, /^dsh-mcp-manager-/);
  const forgedError = await request(handler, 'GET', `/mcp-manager/callback/${id}?error=access_denied&state=wrong`);
  assert.match(forgedError.text, /expired or invalid/);
  assert.equal(stub.forms.length, 0, 'a forged OAuth error must not consume the pending flow');

  const invalid = await request(handler, 'GET', `/mcp-manager/callback/${id}?code=synthetic-code&state=wrong`);
  assert.match(invalid.text, /expired or invalid/);
  assert.equal(stub.forms.length, 0, 'an invalid state must never exchange a code');
  const callback = await request(handler, 'GET', `/mcp-manager/callback/${id}?code=synthetic-code&state=${authorize.searchParams.get('state')}`);
  assert.match(callback.text, /Authorized/);
  assert.equal(stub.forms.length, 1);
  assert.equal(stub.forms[0].get('redirect_uri'), redirect);
  assert.equal(stub.forms[0].get('client_id'), 'dcr-client');
  assert.equal(stub.forms[0].get('client_secret'), null);
  assert.equal(createHash('sha256').update(stub.forms[0].get('code_verifier')).digest('base64url'), authorize.searchParams.get('code_challenge'));
  const view = await request(handler, 'GET', '/mcp-manager/api/servers');
  const connected = view.json.servers.find((server) => server.id === id);
  assert.equal(connected.status, 'connected');
  assert.equal(connected.toolCount, 1);
  assert.equal(state().servers.find((server) => server.id === id).oauth.clientId, 'dcr-client');
  assert.equal(stub.registrations.length, 1, 'callback must reuse the registered redirect');
  assert.equal((await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`)).code, 200);
  assert.equal(stub.registrations.length, 1, 'a second login on the same origin reuses the client');
  const changed = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`, undefined, { host: 'localhost:3081' });
  assert.equal(changed.code, 200, changed.text);
  assert.equal(stub.registrations.length, 2, 'changing origin requires registration for the new exact redirect');
  assert.deepEqual(stub.registrations[1].redirect_uris, [`http://localhost:3081/mcp-manager/callback/${id}`]);
});

it('issue #21: reports a provider metadata rejection without assuming DCR is unsupported or retrying it', async (t) => {
  const stub = await startStub({ advertiseRegistration: true, requiredApplicationType: 'native' });
  t.after(() => stub.close());
  const { handler } = makeCtx({ publicOrigins: ['http://remote.example.test:3080'] });
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', { name: 'rejected-web', type: 'http', url: stub.mcpUrl });
  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`, undefined, { host: 'remote.example.test:3080' });
  assert.equal(auth.code, 500);
  assert.match(auth.json.error, /HTTP 400.*invalid_client_metadata/);
  assert.ok(!auth.json.error.includes('may not support'));
  assert.equal(stub.registrations.length, 1, 'do not retry with another identity or application type');
  assert.equal(stub.forms.length, 0);
  const logs = await request(handler, 'GET', `/mcp-manager/api/servers/${id}/logs`);
  assert.ok(logs.json.logs.some((entry) => entry.phase === 'register' && entry.status === 400 && entry.detail.includes('invalid_client_metadata')));
});

it('discovers a path-carrying authorization server and honours a manual client id', async () => {
  const stub = await startStub();
  const { handler } = makeCtx();

  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'github', type: 'http', url: stub.mcpUrl, authMode: 'oauth', clientId: 'test-client', scope: 'repo read:org',
  });
  assert.equal(created.code, 201);
  assert.equal(created.json.server.clientId, 'test-client');
  assert.equal(created.json.server.scope, 'repo read:org');

  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${created.json.server.id}/auth`);
  assert.equal(auth.code, 200);
  const authorize = new URL(auth.json.authorizeUrl);
  assert.equal(authorize.origin + authorize.pathname, `${stub.base}/login/oauth/authorize`, 'the RFC 8414 path-inserted AS metadata must win');
  assert.equal(authorize.searchParams.get('client_id'), 'test-client');
  assert.equal(authorize.searchParams.get('scope'), 'repo read:org');
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(authorize.searchParams.get('code_challenge'), 'PKCE challenge must be sent');
  assert.equal(authorize.searchParams.get('redirect_uri'), `http://127.0.0.1:3080/mcp-manager/callback/${created.json.server.id}`);

  // The chain used the advertised pointer, never guessed an origin-level AS URL,
  // and never attempted dynamic registration for a manually configured client.
  assert.ok(stub.seen.some(entry => entry.startsWith('GET /.well-known/oauth-protected-resource/mcp')));
  assert.ok(stub.seen.some(entry => entry.startsWith('GET /.well-known/oauth-authorization-server/login/oauth')));
  assert.ok(!stub.seen.some(entry => entry.startsWith('GET /.well-known/oauth-authorization-server ')), 'the naive origin-level probe must not be needed here');
  assert.ok(!stub.seen.some((entry) => entry.includes('/register')), 'a manual client id must skip RFC 7591 registration');

  const persisted = state().servers.find((s) => s.name === 'github');
  assert.equal(persisted.clientId, 'test-client');
  assert.equal(persisted.oauth.authorizationServer, `${stub.base}/login/oauth`);
  assert.equal(persisted.oauth.resourceMetadataUrl, `${stub.base}/.well-known/oauth-protected-resource/mcp`);

  await stub.close();
});

it('rejects oversized OAuth metadata with and without Content-Length', async (t) => {
  for (const mode of ['length', 'chunked']) {
    const stub = await startStub({
      metadataOverrides: { padding: 'x'.repeat(1024 * 1024) },
      metadataResponseMode: mode,
    });
    t.after(() => stub.close());

    const { handler } = makeCtx();
    const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
      name: `large-metadata-${mode}`,
      type: 'http',
      url: stub.mcpUrl,
      authMode: 'oauth',
      clientId: 'manual-client',
    });
    assert.equal(created.code, 201, created.text);

    const id = created.json.server.id;
    const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
    assert.equal(auth.code, 200, auth.text);

    const logs = await request(handler, 'GET', `/mcp-manager/api/servers/${id}/logs`);
    assert.equal(logs.code, 200, logs.text);
    assert.ok(
      logs.json.logs.some((entry) =>
        entry.phase === 'discovery' &&
        entry.detail.includes('Response body exceeds limit of 1048576 bytes')),
      `oversized ${mode} metadata response should be recorded as a failed discovery probe`,
    );
  }
});

it('rejects an oversized dynamic client registration response', async (t) => {
  const stub = await startStub({
    advertiseRegistration: true,
    registrationBody: JSON.stringify({
      client_id: 'oversized-registration',
      padding: 'x'.repeat(1024 * 1024),
    }),
  });
  t.after(() => stub.close());

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'large-registration',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
  });
  assert.equal(created.code, 201, created.text);

  const auth = await request(
    handler,
    'POST',
    `/mcp-manager/api/servers/${created.json.server.id}/auth`,
  );
  assert.equal(auth.code, 500, auth.text);
  assert.match(auth.json.error, /Response body exceeds limit of 1048576 bytes/);
  assert.ok(stub.seen.some((entry) => entry.startsWith('POST /register')));
});

it('rejects an oversized OAuth token response without persisting tokens', async (t) => {
  const stub = await startStub({
    tokenBody: {
      error: 'invalid_grant',
      padding: 'x'.repeat(1024 * 1024),
    },
  });
  t.after(() => stub.close());

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'large-token-response',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'manual-client',
  });
  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  const flowState = new URL(auth.json.authorizeUrl).searchParams.get('state');
  const callback = await request(
    handler,
    'GET',
    `/mcp-manager/callback/${id}?code=stub-code&state=${flowState}`,
  );
  assert.match(callback.text, /Response body exceeds limit of 1048576 bytes/);
  assert.equal(state().servers.find((server) => server.id === id)?.oauth?.tokens, undefined);
});

it('falls back to dynamic client registration when the AS advertises it', async () => {
  const stub = await startStub({ advertiseRegistration: true });
  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', { name: 'dcr', type: 'http', url: stub.mcpUrl, authMode: 'oauth' });
  assert.equal(created.code, 201);
  assert.equal(created.json.server.clientId, '');

  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${created.json.server.id}/auth`);
  assert.equal(auth.code, 200, auth.text);
  const authorize = new URL(auth.json.authorizeUrl);
  assert.equal(authorize.searchParams.get('client_id'), 'dcr-client', 'registration must supply the client id');
  assert.ok(stub.seen.some(entry => entry.startsWith('POST /register')), 'RFC 7591 registration must be attempted when advertised');
  assert.equal(authorize.searchParams.get('scope'), null, 'no scope is sent unless one is configured');

  await stub.close();
});

it('explains an AS without dynamic registration instead of reporting a bare HTTP 404', async () => {
  const stub = await startStub();
  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', { name: 'nodcr', type: 'http', url: stub.mcpUrl, authMode: 'oauth' });
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${created.json.server.id}/auth`);
  assert.equal(auth.code, 500);
  assert.match(auth.json.error, /dynamic client registration|Client ID/);
  assert.ok(!/HTTP 404\b/.test(auth.json.error) || /dynamic client registration/.test(auth.json.error));

  const logs = await request(handler, 'GET', `/mcp-manager/api/servers/${created.json.server.id}/logs`);
  assert.equal(logs.code, 200);
  const register = logs.json.logs.find((entry) => entry.phase === 'register');
  assert.ok(register, 'the failed registration must be traced');
  assert.equal(register.status, 404);

  await stub.close();
});

it('sends client_secret only when its environment variable resolves', async () => {
  const stub = await startStub();
  const { handler } = makeCtx();
  process.env.DSH_MM_TEST_SECRET = 'example-secret';
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'secret', type: 'http', url: stub.mcpUrl, authMode: 'oauth', clientId: 'secret-client', clientSecretEnv: 'DSH_MM_TEST_SECRET',
  });
  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);
  assert.equal(auth.code, 200);
  const flowState = new URL(auth.json.authorizeUrl).searchParams.get('state');

  const callback = await request(handler, 'GET', `/mcp-manager/callback/${id}?code=stub-code&state=${flowState}`);
  const exchanges = stub.forms.filter(form => form.get('grant_type') === 'authorization_code');
  assert.equal(exchanges.length, 1);
  assert.equal(exchanges[0].get('client_secret'), 'example-secret');
  assert.equal(exchanges[0].get('client_id'), 'secret-client');
  assert.equal(exchanges[0].get('code_verifier')?.length > 20, true, 'PKCE verifier must be sent');
  assert.match(callback.text, /Authorized/);
  assert.ok(!callback.text.includes('example-secret'), 'the secret must never reach the browser');

  // A configured-but-unset variable fails by name and never leaks a value.
  const second = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'unset', type: 'http', url: stub.mcpUrl, authMode: 'oauth', clientId: 'c2', clientSecretEnv: 'DSH_MM_MISSING_SECRET',
  });
  const secondId = second.json.server.id;
  const secondAuth = await request(handler, 'POST', `/mcp-manager/api/servers/${secondId}/auth`);
  const secondState = new URL(secondAuth.json.authorizeUrl).searchParams.get('state');
  const failed = await request(handler, 'GET', `/mcp-manager/callback/${secondId}?code=stub-code&state=${secondState}`);
  assert.match(failed.text, /DSH_MM_MISSING_SECRET/);
  delete process.env.DSH_MM_TEST_SECRET;

  await stub.close();
});

it('exposes a redacted attempt log for a failed connection', async (t) => {
  const stub = await startStub({ tokenBody: 'client_secret=SUPERSECRET rejected' });
  // A failing assertion must not leave the stub listening, or the file hangs.
  t.after(() => stub.close());
  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', { name: 'logger', type: 'http', url: stub.mcpUrl, authMode: 'oauth' });
  const id = created.json.server.id;

  const connected = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/connect`);
  assert.equal(connected.json.server.status, 'needs-auth');
  // The 401 reason prefers the provider's own wording (upstream behaviour).
  assert.equal(connected.json.server.error, 'HTTP 401: unauthorized');

  const logs = await request(handler, 'GET', `/mcp-manager/api/servers/${id}/logs`);
  assert.equal(logs.code, 200);
  assert.ok(Array.isArray(logs.json.logs) && logs.json.logs.length > 0, 'a failed connect must leave a trace');
  const init = logs.json.logs.find((entry) => entry.phase === 'initialize');
  assert.ok(init, 'the failed initialize must be logged');
  assert.equal(init.url, stub.mcpUrl);
  assert.ok(logs.json.logs.every((entry) => typeof entry.at === 'number' && typeof entry.phase === 'string'));

  // The 401 pointer is cached, so the next authorize reuses it.
  const persisted = state().servers.find((s) => s.name === 'logger');
  assert.equal(persisted.oauth.resourceMetadataUrl, `${stub.base}/.well-known/oauth-protected-resource/mcp`);

  const serialized = JSON.stringify(logs.json.logs);
  assert.ok(!serialized.includes('SUPERSECRET'), 'secrets echoed by a provider must be redacted');
  assert.ok(!/Bearer\s+[A-Za-z0-9]/.test(serialized), 'bearer values must never be stored');
  assert.ok(!serialized.includes('client_secret=top'), 'secret-bearing query values must be redacted');

  // Unknown ids 404 like every other id-addressed route.
  const missing = await request(handler, 'GET', '/mcp-manager/api/servers/does-not-exist/logs');
  assert.equal(missing.code, 404);
});

it('records the stderr tail of a stdio process that exits immediately', async () => {
  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'boom', type: 'stdio', command: process.execPath, args: ['-e', "console.error('boom client_secret=STDIO_SUPERSECRET'); process.exit(3)"],
  });
  assert.equal(created.code, 201);
  const id = created.json.server.id;

  const approved = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/trust`);
  assert.equal(approved.code, 200, approved.text);
  const connected = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/connect`);
  assert.equal(connected.json.server.status, 'error');
  assert.match(connected.json.server.error, /boom/);
  assert.ok(!connected.json.server.error.includes('STDIO_SUPERSECRET'), 'stderr credentials must not reach connection errors');

  const logs = await request(handler, 'GET', `/mcp-manager/api/servers/${id}/logs`);
  const exit = logs.json.logs.find((entry) => entry.phase === 'stdio-exit');
  assert.ok(exit, 'the stdio exit must be logged');
  assert.equal(exit.status, 3);
  assert.match(exit.detail, /boom/);
  assert.ok(!exit.detail.includes('STDIO_SUPERSECRET'), 'stderr credentials must not be stored in attempt logs');
});

it('drops the manual OAuth fields when the server stops using OAuth', async () => {
  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'dropme', type: 'http', url: 'http://127.0.0.1:9317/mcp', authMode: 'oauth', clientId: 'c1', clientSecretEnv: 'SOME_SECRET', scope: 'repo',
  });
  const id = created.json.server.id;
  const updated = await request(handler, 'PUT', `/mcp-manager/api/servers/${id}`, { name: 'dropme', type: 'http', url: 'http://127.0.0.1:9317/mcp', authMode: 'none' });
  assert.equal(updated.code, 200);
  assert.equal(updated.json.server.clientId, '');
  const persisted = state().servers.find((s) => s.name === 'dropme');
  for (const key of ['clientId', 'clientSecretEnv', 'scope', 'oauth']) assert.equal(key in persisted, false, key + ' must be gone');

  const bad = await request(handler, 'POST', '/mcp-manager/api/servers', { name: 'badsecret', type: 'http', url: 'http://127.0.0.1:9317/mcp', authMode: 'oauth', clientSecretEnv: 'not a name!' });
  assert.equal(bad.code, 400);
  assert.match(bad.json.error, /environment variable/);
});

it('rejects non-loopback HTTP authorization-server issuers before fetching them', async (t) => {
  const issuer = 'http://issuer.example.test/login/oauth';
  const fetchCalls = [];
  const originalFetch = globalThis.fetch;

  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    fetchCalls.push(String(url));
    return originalFetch(url, options);
  });

  const stub = await startStub({ authorizationServers: [issuer] });
  t.after(() => stub.close());

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'unsafe-http-issuer',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });

  assert.equal(created.code, 201, created.text);

  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${created.json.server.id}/auth`);
  assert.equal(auth.code, 200, auth.text);

  assert.equal(
    fetchCalls.some((url) => url.startsWith('http://issuer.example.test/')),
    false,
    'the non-loopback HTTP issuer must be rejected before fetch',
  );
});

it('rejects authorization-server metadata with a mismatched issuer', async (t) => {
  const stub = await startStub({
    metadataOverrides: { issuer: 'https://attacker.example' },
  });
  t.after(() => stub.close());

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'issuer-mismatch-review',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });

  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);

  assert.equal(auth.code, 200, auth.text);
  assert.equal(
    new URL(auth.json.authorizeUrl).pathname,
    '/oauth/authorize',
    'the mismatched metadata endpoint must not be used; fallback endpoints are used instead',
  );
  assert.ok(stub.seen.some(entry => entry.startsWith('GET /.well-known/oauth-authorization-server/login/oauth')));
});

it('rejects an issuer with a trailing slash difference', async (t) => {
  const metadataOverrides = {};
  const stub = await startStub({ metadataOverrides });
  metadataOverrides.issuer = `${stub.base}/login/oauth/`;
  t.after(() => stub.close());

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'issuer-trailing-slash',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });

  assert.equal(created.code, 201, created.text);

  const id = created.json.server.id;
  const auth = await request(handler, 'POST', `/mcp-manager/api/servers/${id}/auth`);

  assert.equal(auth.code, 200, auth.text);
  assert.equal(new URL(auth.json.authorizeUrl).pathname, '/oauth/authorize');
});


it('allows localhost requests when every DNS answer is loopback', async (t) => {
  const stub = await startStub();
  t.after(() => stub.close());

  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    assert.equal(hostname, 'localhost');
    callback(null, [{ address: '127.0.0.1', family: 4 }]);
  });

  const { handler } = makeCtx();
  const localUrl = stub.mcpUrl.replace('127.0.0.1', 'localhost');

  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'dns-loopback-allowed',
    type: 'http',
    url: localUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  const auth = await request(
    handler,
    'POST',
    `/mcp-manager/api/servers/${created.json.server.id}/auth`
  );
  assert.equal(auth.code, 200, auth.text);
  assert.ok(
    stub.seen.some((entry) => entry.startsWith('GET /.well-known/oauth-protected-resource')),
    'the loopback server should receive the metadata request'
  );
});

it('rejects localhost requests when DNS returns mixed loopback and public addresses', async (t) => {
  const stub = await startStub();
  t.after(() => stub.close());

  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    assert.equal(hostname, 'localhost');
    callback(null, [
      { address: '127.0.0.1', family: 4 },
      { address: '8.8.8.8', family: 4 },
    ]);
  });

  const { handler } = makeCtx();
  const localUrl = stub.mcpUrl.replace('127.0.0.1', 'localhost');

  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'dns-mixed-addresses-rejected',
    type: 'http',
    url: localUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  await request(
    handler,
    'POST',
    `/mcp-manager/api/servers/${created.json.server.id}/auth`
  );

  assert.equal(
    stub.seen.length,
    0,
    'no request should reach the server when any DNS answer is non-loopback'
  );
});


it('rejects a public-looking HTTPS hostname that resolves to loopback', async (t) => {
  const providerHost = 'provider.example.test';
  const issuer = `https://${providerHost}/login/oauth`;
  const originalLookup = dns.lookup;
  const originalFetch = globalThis.fetch;
  const fetchCalls = [];

  const stub = await startStub({ authorizationServers: [issuer] });
  t.after(() => stub.close());

  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    if (hostname === providerHost) {
      return callback(null, [{ address: '127.0.0.1', family: 4 }]);
    }
    return originalLookup(hostname, options, callback);
  });

  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    fetchCalls.push(String(url));
    return originalFetch(url, options);
  });

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'dns-host-loopback',
    type: 'http',
    url: stub.mcpUrl,
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  await request(
    handler,
    'POST',
    `/mcp-manager/api/servers/${created.json.server.id}/auth`
  );

  assert.ok(
    fetchCalls.some((url) => url.startsWith(`https://${providerHost}/`)),
    'the test should reach the attempted HTTPS provider request'
  );
  assert.equal(
    stub.seen.some((entry) => entry.includes('oauth-authorization-server')),
    false,
    'the provider metadata request must not reach the local MCP stub'
  );
});


it('rejects non-public HTTPS IP literals before making outbound requests', async (t) => {
  const blockedHosts = [
    '10.0.0.1',
    '169.254.169.254',
    '100.64.0.1',
    '192.0.2.1',
    '224.0.0.1',
    '[fc00::1]',
    '[::ffff:127.0.0.1]',
  ];

  const fetchCalls = [];
  const originalFetch = globalThis.fetch;

  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    fetchCalls.push(String(url));
    return originalFetch(url, options);
  });

  const { handler } = makeCtx();

  for (let i = 0; i < blockedHosts.length; i++) {
    const host = blockedHosts[i];
    const issuer = `https://${host}/login/oauth`;
    const stub = await startStub({ authorizationServers: [issuer] });

    try {
      const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
        name: `ip-block-${i}`,
        type: 'http',
        url: stub.mcpUrl,
        authMode: 'oauth',
        clientId: 'synthetic-client',
      });
      assert.equal(created.code, 201, created.text);

      await request(
        handler,
        'POST',
        `/mcp-manager/api/servers/${created.json.server.id}/auth`
      );

      const normalizedHost = new URL(issuer).hostname;
      assert.equal(
        fetchCalls.some((url) => new URL(url).hostname === normalizedHost),
        false,
        `must not send a request to ${host}`
      );
    } finally {
      await stub.close();
    }
  }
});

it('rechecks DNS on same-origin metadata redirects', async (t) => {
  const originalLookup = dns.lookup;
  let localhostLookups = 0;
  const dnsAnswers = [];

  const stub = await startStub({
    resourceMetadataHost: 'localhost',
    resourceMetadataRedirect: '/metadata-redirect-target',
    closeRedirectConnection: true,
  });
  t.after(() => stub.close());

  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    if (hostname === 'localhost') {
      localhostLookups += 1;
      const address = localhostLookups === 1 ? '127.0.0.1' : '10.0.0.1';
      dnsAnswers.push(address);
      return callback(null, [{ address, family: 4 }]);
    }
    return originalLookup(hostname, options, callback);
  });

  const { handler } = makeCtx();
  const created = await request(handler, 'POST', '/mcp-manager/api/servers', {
    name: 'dns-redirect-recheck',
    type: 'http',
    url: stub.mcpUrl.replace('127.0.0.1', 'localhost'),
    authMode: 'oauth',
    clientId: 'synthetic-client',
  });
  assert.equal(created.code, 201, created.text);

  await request(
    handler,
    'POST',
    `/mcp-manager/api/servers/${created.json.server.id}/auth`
  );

  assert.ok(localhostLookups >= 2, 'DNS should be checked again for the redirect');
  assert.equal(dnsAnswers[0], '127.0.0.1', 'the initial lookup should resolve to loopback');
  assert.ok(
    dnsAnswers.slice(1).includes('10.0.0.1'),
    'a subsequent lookup should return a private address'
  );
  assert.ok(
    stub.seen.some(entry => entry.startsWith('GET /.well-known/oauth-protected-resource/mcp')),
    'the initial metadata request should reach the stub'
  );
  assert.equal(
    stub.seen.some(entry => entry.startsWith('GET /metadata-redirect-target')),
    false,
    'the redirect destination must not be contacted after DNS changes to a private address'
  );
});
