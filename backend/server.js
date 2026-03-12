import express from 'express'
import path from 'path'
import { createServer as createViteServer } from 'vite'
import Database from 'better-sqlite3'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import axios from 'axios'
import { v4 as uuidv4 } from 'uuid'
import crypto from 'crypto'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import dotenv from 'dotenv'

dotenv.config()

/* ================================
   ENV VARIABLES
================================ */

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET
const APP_URL = process.env.APP_URL || "http://localhost:3000"
const STABLE_HORDE_KEY = process.env.STABLE_HORDE_KEY || "0000000000"

/* ================================
   DATABASE
================================ */

const db = new Database('database.sqlite')

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
`)

/* ================================
   API KEY GENERATOR
================================ */

function generateEncryptedKey() {
  const salt = uuidv4().replace(/-/g, '').substring(0, 12)

  const hash = crypto
    .createHmac('sha256', STABLE_HORDE_KEY)
    .update(salt)
    .digest('hex')
    .substring(0, 24)

  return `ak_${STABLE_HORDE_KEY}${hash}`
}

/* ================================
   SERVER START
================================ */

async function startServer() {

const app = express()

/* ================================
   SECURITY
================================ */

app.use(helmet())

app.use(
  cors({
    origin: process.env.FRONTEND_URL || true,
    credentials: true
  })
)

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
})

app.use(limiter)

app.use(express.json({ limit: "10mb" }))
app.use(cookieParser())

/* ================================
   LOGGER
================================ */

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
  next()
})

/* ================================
   HEALTH CHECK
================================ */

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' })
})

/* ================================
   AUTH MIDDLEWARE
================================ */

const authenticateToken = (req, res, next) => {

  const token =
    req.cookies.token ||
    req.headers['authorization']?.split(' ')[1]

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  try {

    const decoded = jwt.verify(token, JWT_SECRET)

    req.user = decoded
    next()

  } catch {
    return res.status(403).json({ error: 'Invalid token' })
  }
}

/* ================================
   API ROUTER
================================ */

const apiRouter = express.Router()

/* ================================
   SIGNUP
================================ */

apiRouter.post('/auth/signup', async (req, res) => {

  const { name, email, phone, password } = req.body

  try {

    const hashedPassword = await bcrypt.hash(password, 12)

    const result = db
      .prepare(
        'INSERT INTO users (name,email,phone,password) VALUES (?,?,?,?)'
      )
      .run(name, email, phone, hashedPassword)

    const userId = result.lastInsertRowid

    const initialKey = generateEncryptedKey()

    db.prepare(
      'INSERT INTO api_keys (user_id,key,name) VALUES (?,?,?)'
    ).run(userId, initialKey, 'Initial Key')

    res.status(201).json({
      message: 'User created',
      userId
    })

  } catch (err) {

    console.error(err)

    res.status(400).json({
      error: 'User already exists'
    })
  }
})

/* ================================
   LOGIN
================================ */

apiRouter.post('/auth/login', async (req, res) => {

  const { identifier, password } = req.body

  const user = db
    .prepare('SELECT * FROM users WHERE email=? OR phone=?')
    .get(identifier, identifier)

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const valid = await bcrypt.compare(password, user.password)

  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '24h' }
  )

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  })

  res.json({
    message: 'Logged in',
    user: {
      id: user.id,
      name: user.name,
      email: user.email
    }
  })
})

/* ================================
   API KEYS
================================ */

apiRouter.get('/keys', authenticateToken, (req, res) => {

  const keys = db
    .prepare(
      'SELECT * FROM api_keys WHERE user_id=? AND revoked=0'
    )
    .all(req.user.id)

  res.json(keys)
})

apiRouter.post('/keys/generate', authenticateToken, (req, res) => {

  const key = generateEncryptedKey()

  db.prepare(
    'INSERT INTO api_keys (user_id,key,name) VALUES (?,?,?)'
  ).run(req.user.id, key, req.body.name || 'Key')

  res.json({ key })
})

/* ================================
   CLONE ENDPOINT
================================ */

apiRouter.post('/endpoints/clone', authenticateToken, (req, res) => {

  let { originalUrl } = req.body

  if (!originalUrl) {
    return res.status(400).json({ error: 'URL required' })
  }

  if (!originalUrl.startsWith('http')) {
    originalUrl = `https://${originalUrl}`
  }

  let clonedPath = uuidv4().split('-')[0]

  db.prepare(
    'INSERT INTO cloned_endpoints (user_id,original_url,cloned_path) VALUES (?,?,?)'
  ).run(req.user.id, originalUrl, clonedPath)

  res.json({
    clonedUrl: `${APP_URL}/pixnora/${clonedPath}`
  })
})

app.use('/api', apiRouter)

/* ================================
   PROXY HANDLER
================================ */

app.all('/pixnora/*', async (req, res) => {

  const path = req.params[0]

  const proxyKey = req.headers['x-pixnora-key']

  if (!proxyKey) {
    return res.status(401).json({
      error: 'API key required'
    })
  }

  const validKey = db
    .prepare(
      'SELECT * FROM api_keys WHERE key=? AND revoked=0'
    )
    .get(proxyKey)

  if (!validKey) {
    return res.status(403).json({
      error: 'Invalid API key'
    })
  }

  const endpoint = db
    .prepare(
      'SELECT * FROM cloned_endpoints WHERE cloned_path=?'
    )
    .get(path)

  if (!endpoint) {
    return res.status(404).json({
      error: 'Endpoint not found'
    })
  }

  try {

    const response = await axios({
      method: req.method,
      url: endpoint.original_url,
      headers: {
        ...req.headers,
        apikey: req.headers.apikey || STABLE_HORDE_KEY
      },
      data: req.body,
      validateStatus: () => true
    })

    res.status(response.status).json(response.data)

  } catch (err) {

    console.error(err)

    res.status(500).json({
      error: 'Proxy failed'
    })
  }
})

/* ================================
   VITE / STATIC
================================ */

if (process.env.NODE_ENV !== 'production') {

  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa'
  })

  app.use(vite.middlewares)

} else {

  const distPath = path.join(process.cwd(), 'dist')

  app.use(express.static(distPath))

  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'))
  })
}

/* ================================
   START SERVER
================================ */

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on ${PORT}`)
})

}

startServer().catch(console.error)
