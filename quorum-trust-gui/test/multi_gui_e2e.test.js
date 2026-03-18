const http = require('http');
const path = require('path');
const supertest = require('supertest');

// Utility to start a mock RPC server that emulates a single QuorumMark node.
function startMockRpcServer(port, nodeName, activeMembers, proposals = [], files = []) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);

    // Basic API key check (must be present, any value).
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'missing api key' }));
    }

    if (url.pathname === '/api/status' && req.method === 'GET') {
      const nodeDigest = `${nodeName}-digest`;
      const isActive = activeMembers.some(m => m.identity?.digest === nodeDigest && m.status === 'Active');
      const body = {
        node_name: nodeName,
        network_name: 'gui-e2e',
        active_members: activeMembers.length,
        pending_proposals: proposals.filter(p => p.status === 'Pending').length,
        proposals_awaiting_my_vote: isActive ? proposals.filter(p => p.status === 'Pending').length : 0,
        is_active_member: isActive,
        node_digest: nodeDigest,
        node_public_key: `${nodeName}-pk`,
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(body));
    }

    if (url.pathname === '/api/members' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(activeMembers));
    }

    if (url.pathname === '/api/proposals' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(proposals));
    }

    if (url.pathname === '/api/files' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(files));
    }

    if (url.pathname === '/api/files/read' && req.method === 'GET') {
      const pathParam = url.searchParams.get('path');
      const f = files.find((x) => x.path === pathParam);
      if (f) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ path: pathParam, content: '# Mock content\n' }));
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'not found' }));
    }

    if (url.pathname === '/api/identity' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        digest: `${nodeName}-digest`,
        public_key: `${nodeName}-pk`,
      }));
    }

    if (url.pathname.startsWith('/api/proposals/') &&
        url.pathname.endsWith('/vote') &&
        req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'Accepted' }));
    }

    if (url.pathname === '/api/governance/propose-member' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const json = body ? JSON.parse(body) : {};
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          proposal_id: `p-add-${Date.now()}`,
          public_key_hex: json.public_key_hex || '',
          display_name: json.display_name || null,
        }));
      });
      return;
    }

    if (url.pathname === '/api/governance/propose-expel' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ proposal_id: `p-expel-${Date.now()}` }));
    }

    if (url.pathname === '/api/files/add' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const json = body ? JSON.parse(body) : {};
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          proposal_id: `p-addfile-${Date.now()}`,
          path: json.path || '',
          content_hash: 'mock-hash',
        }));
      });
      return;
    }

    if (url.pathname === '/api/files/edit' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const json = body ? JSON.parse(body) : {};
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          diff: `--- a/${json.path}\n+++ b/${json.path}\n@@ -1 +1 @@\n-${json.new_content?.slice(0, 20) || ''}\n+edited`,
          additions: 1,
          deletions: 1,
        }));
      });
      return;
    }

    if (url.pathname === '/api/files/fork' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const json = body ? JSON.parse(body) : {};
        const newName = json.new_name || 'doc-fork.md';
        const parent = (json.path || 'doc.md').replace(/\/[^/]+$/, '/') || '';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ forked_path: parent + newName }));
      });
      return;
    }

    if (url.pathname === '/api/files/finalize' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ path: 'docs/charter.md', status: 'Final' }));
    }

    // Everything else: simple 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

// Helper to start a GUI server instance on a given port, pointing at a mock RPC.
function startGuiServer(guiPort, rpcPort) {
  const serverModulePath = path.join(__dirname, '..', 'server.js');
  // eslint-disable-next-line global-require, import/no-dynamic-require
  const { startServer } = require(serverModulePath);

  const server = startServer({
    rpcHost: 'http://127.0.0.1',
    rpcPort,
    apiKey: 'test-key',
    guiPort,
    quiet: true,
  });

  const agent = supertest(`http://127.0.0.1:${guiPort}`);
  return { server, agent };
}

describe('multi GUI + node e2e (proxy layer)', () => {
  let rpcAlice;
  let rpcBob;
  let guiAliceServer;
  let guiBobServer;

  beforeAll(async () => {
    const aliceMembers = [
      {
        identity: {
          digest: 'alice-digest',
          public_key_hex: 'alice-pk',
          display_name: 'Alice',
        },
        status: 'Active',
        joined_at: null,
        expelled_at: null,
      },
      {
        identity: {
          digest: 'bob-digest',
          public_key_hex: 'bob-pk',
          display_name: 'Bob',
        },
        status: 'Active',
        joined_at: null,
        expelled_at: null,
      },
    ];

    const bobMembers = [
      {
        identity: {
          digest: 'alice-digest',
          public_key_hex: 'alice-pk',
          display_name: 'Alice',
        },
        status: 'Active',
        joined_at: null,
        expelled_at: null,
      },
      {
        identity: {
          digest: 'bob-digest',
          public_key_hex: 'bob-pk',
          display_name: 'Bob',
        },
        status: 'Active',
        joined_at: null,
        expelled_at: null,
      },
    ];

    const proposals = [
      {
        id: 'p-add-file',
        proposal_type: {
          AddFile: { path: 'docs/charter.md', content_hash: 'hash1' },
        },
        status: 'Pending',
        votes: {
          'alice-digest': { choice: 'Accept' },
        },
      },
    ];

    const files = [
      {
        path: 'docs/charter.md',
        is_dir: false,
        tracking_status: 'Tracked',
        version: 1,
        doc_status: { Draft: {} },
      },
    ];

    rpcAlice = await startMockRpcServer(9501, 'Alice', aliceMembers, proposals, files);
    rpcBob = await startMockRpcServer(9502, 'Bob', bobMembers, proposals, files);
  });

  afterEach(async () => {
    if (guiAliceServer) {
      await new Promise((resolve) => guiAliceServer.close(resolve));
      guiAliceServer = null;
    }
    if (guiBobServer) {
      await new Promise((resolve) => guiBobServer.close(resolve));
      guiBobServer = null;
    }
  });

  afterAll(async () => {
    if (rpcAlice) {
      await new Promise((resolve) => rpcAlice.close(resolve));
    }
    if (rpcBob) {
      await new Promise((resolve) => rpcBob.close(resolve));
    }
  });

  test('two GUI servers show consistent governance view for each node', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3101, 9501);
    const { server: s2, agent: guiBob } = startGuiServer(3102, 9502);
    guiAliceServer = s1;
    guiBobServer = s2;

    // Alice GUI status reflects Alice as node, 2 members, 1 pending proposal.
    const aliceStatus = await guiAlice.get('/api/status').set('x-api-key', 'test-key');
    expect(aliceStatus.status).toBe(200);
    expect(aliceStatus.body.node_name).toBe('Alice');
    expect(aliceStatus.body.active_members).toBe(2);
    expect(aliceStatus.body.pending_proposals).toBe(1);

    // Bob GUI status reflects Bob as node but same member count/proposals.
    const bobStatus = await guiBob.get('/api/status').set('x-api-key', 'test-key');
    expect(bobStatus.status).toBe(200);
    expect(bobStatus.body.node_name).toBe('Bob');
    expect(bobStatus.body.active_members).toBe(2);
    expect(bobStatus.body.pending_proposals).toBe(1);

    // Members endpoint: both GUIs should list Alice and Bob with matching digests.
    const aliceMembersResp = await guiAlice.get('/api/members').set('x-api-key', 'test-key');
    const bobMembersResp = await guiBob.get('/api/members').set('x-api-key', 'test-key');

    expect(aliceMembersResp.status).toBe(200);
    expect(bobMembersResp.status).toBe(200);

    const aliceDigests = aliceMembersResp.body.map((m) => m.identity.digest).sort();
    const bobDigests = bobMembersResp.body.map((m) => m.identity.digest).sort();
    expect(aliceDigests).toEqual(bobDigests);

    // Proposals endpoint: both GUIs should surface the same pending AddFile proposal.
    const aliceProps = await guiAlice.get('/api/proposals').set('x-api-key', 'test-key');
    const bobProps = await guiBob.get('/api/proposals').set('x-api-key', 'test-key');

    expect(aliceProps.status).toBe(200);
    expect(bobProps.status).toBe(200);
    expect(aliceProps.body.length).toBe(1);
    expect(bobProps.body.length).toBe(1);
    expect(aliceProps.body[0].id).toBe(bobProps.body[0].id);
    expect(aliceProps.body[0].proposal_type.AddFile.path).toBe(
      'docs/charter.md',
    );
  });

  test('GUI forwards vote actions to RPC and surfaces Accepted status', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3201, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/proposals/p-add-file/vote')
      .set('x-api-key', 'test-key')
      .send({ choice: 'accept' });

    expect(resp.status).toBe(200);
    expect(resp.body.status).toBe('Accepted');
  });

  test('GUI forwards file listing to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3301, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice.get('/api/files').set('x-api-key', 'test-key');
    expect(resp.status).toBe(200);
    expect(Array.isArray(resp.body)).toBe(true);
    expect(resp.body[0].path).toBe('docs/charter.md');
  });

  test('GUI forwards identity to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3401, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice.get('/api/identity').set('x-api-key', 'test-key');
    expect(resp.status).toBe(200);
    expect(resp.body.digest).toBe('Alice-digest');
    expect(resp.body.public_key).toBe('Alice-pk');
  });

  test('GUI forwards files/read to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3501, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .get('/api/files/read?path=docs/charter.md')
      .set('x-api-key', 'test-key');
    expect(resp.status).toBe(200);
    expect(resp.body.path).toBe('docs/charter.md');
    expect(resp.body.content).toContain('Mock content');
  });

  test('GUI forwards propose-member to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3601, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/governance/propose-member')
      .set('x-api-key', 'test-key')
      .send({ public_key_hex: 'new-pk-hex', display_name: 'Carol' });

    expect(resp.status).toBe(200);
    expect(resp.body.proposal_id).toBeDefined();
    expect(resp.body.public_key_hex).toBe('new-pk-hex');
    expect(resp.body.display_name).toBe('Carol');
  });

  test('GUI forwards files/add to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3701, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/files/add')
      .set('x-api-key', 'test-key')
      .send({ path: 'docs/new.md', content: '# New doc\n' });

    expect(resp.status).toBe(200);
    expect(resp.body.proposal_id).toBeDefined();
    expect(resp.body.path).toBe('docs/new.md');
  });

  test('GUI forwards files/edit to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3801, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/files/edit')
      .set('x-api-key', 'test-key')
      .send({ path: 'docs/charter.md', new_content: '# Charter v2\n' });

    expect(resp.status).toBe(200);
    expect(resp.body.diff).toBeDefined();
    expect(resp.body.additions).toBe(1);
    expect(resp.body.deletions).toBe(1);
  });

  test('GUI forwards files/fork to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(3901, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/files/fork')
      .set('x-api-key', 'test-key')
      .send({ path: 'docs/charter.md', new_name: 'charter-v2.md', share: false });

    expect(resp.status).toBe(200);
    expect(resp.body.forked_path).toContain('charter-v2');
  });

  test('GUI forwards propose-expel to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(4001, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/governance/propose-expel')
      .set('x-api-key', 'test-key')
      .send({ member_digest: 'bob-digest' });

    expect(resp.status).toBe(200);
    expect(resp.body.proposal_id).toBeDefined();
  });

  test('GUI forwards files/finalize to RPC', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(4101, 9501);
    guiAliceServer = s1;

    const resp = await guiAlice
      .post('/api/files/finalize')
      .set('x-api-key', 'test-key')
      .send({ path: 'docs/charter.md' });

    expect(resp.status).toBe(200);
    expect(resp.body.path).toBe('docs/charter.md');
    expect(resp.body.status).toBe('Final');
  });

  test('GUI returns 502 when RPC is unavailable', async () => {
    const { server: s1, agent: guiAlice } = startGuiServer(4201, 59999);
    guiAliceServer = s1;

    const resp = await guiAlice.get('/api/status').set('x-api-key', 'test-key');

    expect(resp.status).toBe(502);
    expect(resp.body.error).toContain('unavailable');
  });

  test('mock RPC returns 401 when API key missing', async () => {
    const resp = await supertest(`http://127.0.0.1:9501`)
      .get('/api/status');
    expect(resp.status).toBe(401);
    expect(resp.body.error).toBe('missing api key');
  });
});

