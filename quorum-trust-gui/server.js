const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function createServer(options = {}) {
  const app = express();

  const rpcHost = options.rpcHost || process.env.RPC_HOST || 'http://127.0.0.1';
  const rpcPort = options.rpcPort || process.env.RPC_PORT || '9401';
  const apiKey = options.apiKey || process.env.API_KEY || '';
  const rpcUrl = `${rpcHost}:${rpcPort}`;

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }));

  app.use(express.json({ limit: '1mb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use('/api/', limiter);

  async function rpcRequest(endpoint, method = 'GET', body = null) {
    const url = `${rpcUrl}${endpoint}`;
    const headers = {
      'x-api-key': apiKey,
      'Content-Type': 'application/json',
    };

    const opts = { method, headers };
    if (body) {
      opts.body = JSON.stringify(body);
    }

    const resp = await fetch(url, opts);
    if (!resp.ok) {
      throw new Error(`RPC error: ${resp.status} ${resp.statusText}`);
    }
    return resp.json();
  }

  // Proxy endpoints to RPC
  app.get('/api/status', async (req, res) => {
    try {
      const data = await rpcRequest('/api/status');
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Node unavailable', detail: e.message });
    }
  });

  app.get('/api/members', async (req, res) => {
    try {
      const data = await rpcRequest('/api/members');
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Node unavailable', detail: e.message });
    }
  });

  app.get('/api/proposals', async (req, res) => {
    try {
      const data = await rpcRequest('/api/proposals');
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Node unavailable', detail: e.message });
    }
  });

  app.post('/api/proposals/:id/vote', async (req, res) => {
    try {
      const choice = sanitizeInput(req.body.choice);
      const data = await rpcRequest(`/api/proposals/${req.params.id}/vote`, 'POST', { choice });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Vote failed', detail: e.message });
    }
  });

  app.get('/api/files', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files');
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Node unavailable', detail: e.message });
    }
  });

  app.get('/api/files/read', async (req, res) => {
    try {
      const filePath = sanitizeInput(req.query.path);
      const data = await rpcRequest(`/api/files/read?path=${encodeURIComponent(filePath)}`);
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Read failed', detail: e.message });
    }
  });

  app.post('/api/files/add', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/add', 'POST', {
        path: req.body.path,
        content: req.body.content,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Add failed', detail: e.message });
    }
  });

  app.post('/api/files/propose-add', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/propose-add', 'POST', {
        path: req.body.path,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Propose add failed', detail: e.message });
    }
  });

  app.post('/api/files/rename-local', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/rename-local', 'POST', {
        path: req.body.path,
        new_name: req.body.new_name,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Rename failed', detail: e.message });
    }
  });

  app.post('/api/files/propose-rename', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/propose-rename', 'POST', {
        path: req.body.path,
        new_name: req.body.new_name,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Propose rename failed', detail: e.message });
    }
  });

  app.post('/api/files/edit', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/edit', 'POST', {
        path: req.body.path,
        new_content: req.body.new_content,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Edit failed', detail: e.message });
    }
  });

  app.post('/api/files/fork', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/fork', 'POST', {
        path: req.body.path,
        new_name: req.body.new_name || null,
        share: req.body.share || false,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Fork failed', detail: e.message });
    }
  });

  app.post('/api/files/finalize', async (req, res) => {
    try {
      const data = await rpcRequest('/api/files/finalize', 'POST', {
        path: req.body.path,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Finalize failed', detail: e.message });
    }
  });

  app.post('/api/governance/propose-member', async (req, res) => {
    try {
      const data = await rpcRequest('/api/governance/propose-member', 'POST', {
        public_key_hex: req.body.public_key_hex,
        display_name: req.body.display_name || null,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Propose failed', detail: e.message });
    }
  });

  app.post('/api/governance/propose-expel', async (req, res) => {
    try {
      const data = await rpcRequest('/api/governance/propose-expel', 'POST', {
        member_digest: req.body.member_digest,
      });
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Propose expel failed', detail: e.message });
    }
  });

  app.post('/api/governance/sync', async (req, res) => {
    try {
      const data = await rpcRequest('/api/governance/sync', 'POST', {});
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Sync failed', detail: e.message });
    }
  });

  app.get('/api/identity', async (req, res) => {
    try {
      const data = await rpcRequest('/api/identity');
      res.json(data);
    } catch (e) {
      res.status(502).json({ error: 'Identity fetch failed', detail: e.message });
    }
  });

  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  return { app, rpcUrl };
}

function startServer(options = {}) {
  const { app, rpcUrl } = createServer(options);
  const port = options.guiPort || process.env.GUI_PORT || 3000;
  const server = app.listen(port, '127.0.0.1', () => {
    if (!options.quiet) {
      console.log(`QuorumMark GUI running at http://127.0.0.1:${port}`);
      console.log(`Connecting to RPC at ${rpcUrl}`);
    }
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = { createServer, startServer };
