require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURACIÓN PARA RENDER (Importante) ====================
const dbDir = '/tmp';
const dbPath = path.join(dbDir, 'licenses.db');

// Crear carpeta temporal para la base de datos
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

console.log(`💾 Usando base de datos en: ${dbPath}`);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta más tarde.' }
});
app.use('/api/', limiter);

// Database setup
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error connecting to database:', err.message);
  } else {
    console.log('✅ Conectado a SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )`);

    // Licenses table
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_key TEXT UNIQUE NOT NULL,
      license_type TEXT NOT NULL,
      duration_months INTEGER,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      activated_at DATETIME,
      user_email TEXT,
      device_id TEXT,
      last_validated DATETIME,
      validation_count INTEGER DEFAULT 0
    )`);

    // License requests table
    db.run(`CREATE TABLE IF NOT EXISTS license_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      processed_at DATETIME,
      assigned_license_key TEXT
    )`);

    // Audit log table
    db.run(`CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      user_id INTEGER,
      license_id INTEGER,
      details TEXT,
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create default admin user
    const defaultAdmin = {
      username: process.env.ADMIN_USERNAME || 'Admin',
      password: process.env.ADMIN_PASSWORD || 'Dur@n2506.',
      email: process.env.ADMIN_EMAIL || 'algenis2506@gmail.com'
    };

    db.get('SELECT * FROM users WHERE username = ?', [defaultAdmin.username], async (err, user) => {
      if (!user) {
        const hashedPassword = await bcrypt.hash(defaultAdmin.password, 12);
        db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
          [defaultAdmin.username, hashedPassword, defaultAdmin.email],
          (err) => {
            if (err) {
              console.error('Error creating default admin:', err.message);
            } else {
              console.log('✅ Admin creado correctamente');
              console.log('Usuario:', defaultAdmin.username);
              console.log('Contraseña:', defaultAdmin.password);
              console.log('¡CAMBIAR ESTAS CREDENCIALES EN .ENV!');
            }
          }
        );
      }
    });
  });
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Generate secure license key
function generateLicenseKey() {
  const segments = [];
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  for (let i = 0; i < 4; i++) {
    let segment = '';
    for (let j = 0; j < 4; j++) {
      segment += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    segments.push(segment);
  }
  return segments.join('-');
}

// Calculate expiration date
function calculateExpirationDate(type) {
  const now = new Date();
  switch (type) {
    case '1month': now.setMonth(now.getMonth() + 1); break;
    case '1year': now.setFullYear(now.getFullYear() + 1); break;
    case 'unlimited': return null;
    default: now.setMonth(now.getMonth() + 1);
  }
  return now;
}

// ==================== RUTAS (Mantengo las tuyas) ====================

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { username: user.username } });
  });
});

// Validate license (para la extensión)
app.post('/api/licenses/validate', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ valid: false, message: 'License key required' });

  db.get('SELECT * FROM licenses WHERE license_key = ?', [key], (err, license) => {
    if (err || !license || license.status !== 'active') {
      return res.json({ valid: false, message: 'Invalid or expired license' });
    }

    if (license.expires_at) {
      if (new Date() > new Date(license.expires_at)) {
        db.run('UPDATE licenses SET status = "expired" WHERE id = ?', [license.id]);
        return res.json({ valid: false, message: 'License expired' });
      }
    }

    res.json({ valid: true, type: license.license_type, expiresAt: license.expires_at });
  });
});

// Create license
app.post('/api/licenses', authenticateToken, (req, res) => {
  const { licenseType, userEmail } = req.body;
  const licenseKey = generateLicenseKey();
  const expiresAt = calculateExpirationDate(licenseType);

  db.run('INSERT INTO licenses (license_key, license_type, expires_at, user_email, status) VALUES (?, ?, ?, ?, "active")',
    [licenseKey, licenseType, expiresAt ? expiresAt.toISOString() : null, userEmail],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create license' });
      res.json({ success: true, licenseKey });
    });
});

// Servir panel administrativo
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.send('<h2>✅ StreetOTP License Server está funcionando en Render!</h2><p><a href="/login">Ir al Panel Administrativo</a></p>');
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 StreetOTP License Server running on port ${PORT}`);
  console.log(`🌐 Panel: https://${process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost:' + PORT}`);
});
