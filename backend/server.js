import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

const ak = "0000000000";

function generateEncryptedKey() {
  const salt = uuidv4().replace(/-/g, '').substring(0, 12);
  const hash = crypto.createHmac('sha256', ak)
    .update(salt)
    .digest('hex')
    .substring(0, 24);
  return `ak_${ak}${hash}`;
}

const db = new Database('database.sqlite');
const JWT_SECRET = 'api-curl-builder-secret-key-2026';

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS cloned_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_url TEXT NOT NULL,
    cloned_path TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

async function startServer() {
  const app = express();
  const PORT = 5000;

  app.use(cors());
  app.use(express.json());
  app.use(cookieParser());

  // Request logging
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
  });

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  const apiRouter = express.Router();

  // Middleware to verify JWT
  const authenticateToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Forbidden' });
      req.user = user;
      next();
    });
  };

  // Auth Routes
  apiRouter.post('/auth/signup', async (req, res) => {
    const { name, email, phone, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const stmt = db.prepare('INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)');
      const result = stmt.run(name, email, phone, hashedPassword);
      const userId = result.lastInsertRowid;

      // Automatically generate initial API key
      const initialKey = generateEncryptedKey();
      db.prepare('INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)').run(userId, initialKey, 'Initial Key');

      res.status(201).json({ message: 'User created', userId });
    } catch (error) {
      console.error('Signup Error:', error);
      res.status(400).json({ error: 'User already exists or invalid data' });
    }
  });

  apiRouter.post('/auth/login', async (req, res) => {
    const { identifier, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(identifier, identifier);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' });
    res.json({ message: 'Logged in', user: { id: user.id, name: user.name, email: user.email } });
  });

  apiRouter.post('/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out' });
  });

  apiRouter.get('/auth/me', authenticateToken, (req, res) => {
    res.json({ user: req.user });
  });

  // API Key Management
  apiRouter.get('/keys', authenticateToken, (req, res) => {
    const keys = db.prepare('SELECT * FROM api_keys WHERE user_id = ? AND revoked = 0').all(req.user.id);
    res.json(keys);
  });

  apiRouter.post('/keys/generate', authenticateToken, (req, res) => {
    const key = generateEncryptedKey();
    const stmt = db.prepare('INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)');
    stmt.run(req.user.id, key, req.body.name || 'Default Key');
    res.json({ key });
  });

  apiRouter.post('/keys/revoke', authenticateToken, (req, res) => {
    const { keyId } = req.body;
    db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?').run(keyId, req.user.id);
    res.json({ message: 'Key revoked' });
  });

  // Endpoint Cloning
  apiRouter.post('/endpoints/clone', authenticateToken, (req, res) => {
    let { originalUrl } = req.body;
    if (!originalUrl) return res.status(400).json({ error: 'Original URL is required' });
    
    originalUrl = originalUrl.trim();
    if (!originalUrl.startsWith('http://') && !originalUrl.startsWith('https://')) {
      originalUrl = 'https://' + originalUrl;
    }
    
    let clonedPath;
    try {
      const urlObj = new URL(originalUrl);
      clonedPath = urlObj.pathname.startsWith('/') ? urlObj.pathname.substring(1) : urlObj.pathname;
      if (!clonedPath) clonedPath = uuidv4().split('-')[0];
    } catch (e) {
      console.error('[Clone Error] Invalid URL provided:', originalUrl);
      clonedPath = uuidv4().split('-')[0];
    }
    
    console.log(`[Clone] Creating endpoint: ${originalUrl} -> ${clonedPath}`);
    
    try {
      const stmt = db.prepare('INSERT INTO cloned_endpoints (user_id, original_url, cloned_path) VALUES (?, ?, ?)');
      stmt.run(req.user.id, originalUrl, clonedPath);
    } catch (err) {
      console.log('[Clone] Path collision, appending UUID');
      clonedPath = `${clonedPath}-${uuidv4().split('-')[0]}`;
      const stmt = db.prepare('INSERT INTO cloned_endpoints (user_id, original_url, cloned_path) VALUES (?, ?, ?)');
      stmt.run(req.user.id, originalUrl, clonedPath);
    }
    
    const finalClonedUrl = `${process.env.APP_URL || 'http://localhost:3000'}/pixnora/${clonedPath}`;
    console.log(`[Clone] Success: ${finalClonedUrl}`);
    res.json({ clonedUrl: finalClonedUrl });
  });

  apiRouter.get('/endpoints', authenticateToken, (req, res) => {
    const endpoints = db.prepare('SELECT * FROM cloned_endpoints WHERE user_id = ?').all(req.user.id);
    res.json(endpoints);
  });

  apiRouter.delete('/endpoints/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.prepare('DELETE FROM cloned_endpoints WHERE id = ? AND user_id = ?').run(id, req.user.id);
    res.json({ message: 'Endpoint deleted' });
  });

  // API Tester / cURL Runner
  apiRouter.post('/test/curl', authenticateToken, async (req, res) => {
    const { method, url, headers, body } = req.body;
    try {
      const response = await axios({
        method,
        url,
        headers,
        data: body
      });
      res.status(response.status).json(response.data);
    } catch (error) {
      res.status(error.response?.status || 500).json(error.response?.data || { error: 'Request failed' });
    }
  });

  app.use('/api', apiRouter);

    // Proxy / Cloned Endpoint Handler (Root level for /pixnora prefix)
  app.all('/pixnora/*', async (req, res) => {
    const clonedPath = req.params[0];
    // Check for proxy auth ONLY in X-Pixnora-Key
    const proxyKey = req.headers['x-pixnora-key'];

    console.log(`[Proxy] Request for path: ${clonedPath}`);

    if (!proxyKey) return res.status(401).json({ error: 'API Key required (X-Pixnora-Key)' });

    const validKey = db.prepare('SELECT * FROM api_keys WHERE key = ? AND revoked = 0').get(proxyKey);
    if (!validKey) return res.status(403).json({ error: 'Invalid or revoked Proxy API Key' });

    const endpoint = db.prepare('SELECT * FROM cloned_endpoints WHERE cloned_path = ?').get(clonedPath);
    if (!endpoint) {
      console.log(`[Proxy] Endpoint not found for path: ${clonedPath}`);
      return res.status(404).json({ error: 'Endpoint not found' });
    }

    console.log(`[Proxy] Forwarding to: ${endpoint.original_url}`);

    try {
      const forwardedHeaders = { ...req.headers };
      delete forwardedHeaders['host'];
      delete forwardedHeaders['connection'];
      delete forwardedHeaders['content-length'];
      
      // Inject default apikey for Stable Horde if not provided by client
      if (!forwardedHeaders['apikey']) {
        forwardedHeaders['apikey'] = '0000000000';
      }

      // We only remove the proxy-specific header.
      delete forwardedHeaders['x-pixnora-key'];

      const response = await axios({
        method: req.method,
        url: endpoint.original_url,
        data: (req.method !== 'GET' && Object.keys(req.body).length > 0) ? req.body : undefined,
        headers: forwardedHeaders,
        timeout: 30000, // Increased timeout for AI generation
        validateStatus: () => true // Allow forwarding all status codes
      });
      res.status(response.status).json(response.data);
    } catch (error) {
      console.error('[Proxy Error]:', error.message);
      if (error.response) {
        res.status(error.response.status).json(error.response.data);
      } else {
        res.status(500).json({ 
          error: 'Proxy request failed', 
          message: error.message,
          details: `Target URL: ${endpoint.original_url}. Ensure the original URL is accessible and valid.`
        });
      }
    }
  });

  // API 404 Handler
  app.all('/api/*', (req, res) => {
    res.status(404).json({ error: `API route not found: ${req.method} ${req.url}` });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
    // Test DB
    try {
      const row = db.prepare('SELECT 1 as test').get();
      console.log('Database connection successful:', row);
    } catch (err) {
      console.error('Database connection failed:', err);
    }
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
});
