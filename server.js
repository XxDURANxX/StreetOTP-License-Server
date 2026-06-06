const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Database setup
const dbPath = process.env.DB_PATH || path.join(__dirname, 'database', 'licenses.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error connecting to database:', err.message);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table for admin authentication
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

    // Create default admin user if not exists
    const defaultAdmin = {
      username: process.env.ADMIN_USERNAME || 'admin',
      password: process.env.ADMIN_PASSWORD || 'admin123',
      email: process.env.ADMIN_EMAIL || 'admin@streetotp.com'
    };

    db.get('SELECT * FROM users WHERE username = ?', [defaultAdmin.username], async (err, user) => {
      if (!user) {
        const hashedPassword = await bcrypt.hash(defaultAdmin.password, 12);
        db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
          [defaultAdmin.username, hashedPassword, defaultAdmin.email],
          (err) => {
            if (err) {
              console.error('Error creating default admin user:', err.message);
            } else {
              console.log('Default admin user created');
              console.log('Username:', defaultAdmin.username);
              console.log('Password:', defaultAdmin.password);
              console.log('PLEASE CHANGE THESE CREDENTIALS IN .env FILE!');
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
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Middleware to log actions
function logAction(req, action, details = '') {
  const userId = req.user ? req.user.id : null;
  const licenseId = req.body.licenseId || req.params.id || null;
  const ipAddress = req.ip || req.connection.remoteAddress;

  db.run('INSERT INTO audit_log (action, user_id, license_id, details, ip_address) VALUES (?, ?, ?, ?, ?)',
    [action, userId, licenseId, details, ipAddress],
    (err) => {
      if (err) console.error('Error logging action:', err.message);
    }
  );
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

// Calculate expiration date based on license type
function calculateExpirationDate(type) {
  const now = new Date();
  
  switch (type) {
    case '1month':
      now.setMonth(now.getMonth() + 1);
      break;
    case '1year':
      now.setFullYear(now.getFullYear() + 1);
      break;
    case 'unlimited':
      return null; // No expiration
    default:
      now.setMonth(now.getMonth() + 1);
  }
  
  return now;
}

// API Routes

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  });
});

// Verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Create license
app.post('/api/licenses', authenticateToken, (req, res) => {
  const { licenseType, userEmail } = req.body;

  if (!licenseType) {
    return res.status(400).json({ error: 'License type required' });
  }

  const validTypes = ['1month', '1year', 'unlimited'];
  if (!validTypes.includes(licenseType)) {
    return res.status(400).json({ error: 'Invalid license type' });
  }

  const licenseKey = generateLicenseKey();
  const expiresAt = calculateExpirationDate(licenseType);
  const durationMonths = licenseType === '1month' ? 1 : licenseType === '1year' ? 12 : null;

  db.run(
    'INSERT INTO licenses (license_key, license_type, duration_months, expires_at, user_email) VALUES (?, ?, ?, ?, ?)',
    [licenseKey, licenseType, durationMonths, expiresAt, userEmail || null],
    function(err) {
      if (err) {
        console.error('Error creating license:', err.message);
        return res.status(500).json({ error: 'Failed to create license' });
      }

      logAction(req, 'CREATE_LICENSE', `Created license ${licenseKey} of type ${licenseType}`);

      res.json({
        success: true,
        license: {
          id: this.lastID,
          licenseKey,
          licenseType,
          durationMonths,
          expiresAt,
          status: 'active',
          createdAt: new Date().toISOString()
        }
      });
    }
  );
});

// Get all licenses
app.get('/api/licenses', authenticateToken, (req, res) => {
  const { status, page = 1, limit = 50 } = req.query;
  const offset = (page - 1) * limit;

  let query = 'SELECT * FROM licenses';
  let params = [];

  if (status) {
    query += ' WHERE status = ?';
    params.push(status);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  db.all(query, params, (err, licenses) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM licenses';
    let countParams = [];
    if (status) {
      countQuery += ' WHERE status = ?';
      countParams.push(status);
    }

    db.get(countQuery, countParams, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        licenses,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: result.total,
          pages: Math.ceil(result.total / limit)
        }
      });
    });
  });
});

// Get single license
app.get('/api/licenses/:id', authenticateToken, (req, res) => {
  db.get('SELECT * FROM licenses WHERE id = ?', [req.params.id], (err, license) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!license) {
      return res.status(404).json({ error: 'License not found' });
    }

    res.json({ license });
  });
});

// Validate license (for extension)
app.post('/api/licenses/validate', (req, res) => {
  const { key } = req.body;

  if (!key) {
    return res.status(400).json({ error: 'License key required' });
  }

  db.get('SELECT * FROM licenses WHERE license_key = ?', [key], (err, license) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!license) {
      logAction(req, 'VALIDATE_LICENSE', `Failed validation: license not found - ${key}`);
      return res.json({ valid: false, message: 'License not found' });
    }

    // Check if license is active
    if (license.status !== 'active') {
      logAction(req, 'VALIDATE_LICENSE', `Failed validation: license inactive - ${key}`);
      return res.json({ valid: false, message: 'License is not active' });
    }

    // Check expiration
    if (license.expires_at) {
      const expiresAt = new Date(license.expires_at);
      const now = new Date();
      if (now > expiresAt) {
        // Update status to expired
        db.run('UPDATE licenses SET status = ? WHERE id = ?', ['expired', license.id]);
        logAction(req, 'VALIDATE_LICENSE', `Failed validation: license expired - ${key}`);
        return res.json({ valid: false, message: 'License has expired' });
      }
    }

    // Update validation count and last validated
    db.run(
      'UPDATE licenses SET validation_count = validation_count + 1, last_validated = CURRENT_TIMESTAMP WHERE id = ?',
      [license.id]
    );

    logAction(req, 'VALIDATE_LICENSE', `Successful validation - ${key}`);

    res.json({
      valid: true,
      license: {
        type: license.license_type,
        expiresAt: license.expires_at,
        status: license.status
      }
    });
  });
});

// Activate license
app.post('/api/licenses/activate', (req, res) => {
  const { key, deviceId, userEmail } = req.body;

  if (!key) {
    return res.status(400).json({ error: 'License key required' });
  }

  db.get('SELECT * FROM licenses WHERE license_key = ?', [key], (err, license) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!license) {
      return res.status(404).json({ error: 'License not found' });
    }

    // Check if already activated
    if (license.activated_at) {
      return res.json({
        success: true,
        message: 'License already activated',
        license: {
          type: license.license_type,
          expiresAt: license.expires_at,
          status: license.status
        }
      });
    }

    // Activate license
    db.run(
      'UPDATE licenses SET activated_at = CURRENT_TIMESTAMP, device_id = ?, user_email = ? WHERE id = ?',
      [deviceId || null, userEmail || null, license.id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to activate license' });
        }

        logAction(req, 'ACTIVATE_LICENSE', `Activated license ${key}`);

        res.json({
          success: true,
          message: 'License activated successfully',
          license: {
            type: license.license_type,
            expiresAt: license.expires_at,
            status: license.status
          }
        });
      }
    );
  });
});

// Update license
app.put('/api/licenses/:id', authenticateToken, (req, res) => {
  const { status, licenseType, userEmail } = req.body;
  const { id } = req.params;

  let updates = [];
  let params = [];

  if (status) {
    updates.push('status = ?');
    params.push(status);
  }

  if (licenseType) {
    updates.push('license_type = ?');
    params.push(licenseType);
    
    const expiresAt = calculateExpirationDate(licenseType);
    if (expiresAt) {
      updates.push('expires_at = ?');
      params.push(expiresAt.toISOString());
    }
  }

  if (userEmail !== undefined) {
    updates.push('user_email = ?');
    params.push(userEmail);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  params.push(id);

  db.run(`UPDATE licenses SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update license' });
    }

    logAction(req, 'UPDATE_LICENSE', `Updated license ${id}`);

    res.json({ success: true, message: 'License updated successfully' });
  });
});

// Delete license
app.delete('/api/licenses/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM licenses WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete license' });
    }

    logAction(req, 'DELETE_LICENSE', `Deleted license ${req.params.id}`);

    res.json({ success: true, message: 'License deleted successfully' });
  });
});

// License requests
app.post('/api/license-requests', (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email required' });
  }

  db.run(
    'INSERT INTO license_requests (name, email, message) VALUES (?, ?, ?)',
    [name, email, message || ''],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create request' });
      }

      res.json({
        success: true,
        message: 'License request submitted successfully',
        requestId: this.lastID
      });
    }
  );
});

app.get('/api/license-requests', authenticateToken, (req, res) => {
  const { status } = req.query;

  let query = 'SELECT * FROM license_requests';
  let params = [];

  if (status) {
    query += ' WHERE status = ?';
    params.push(status);
  }

  query += ' ORDER BY created_at DESC';

  db.all(query, params, (err, requests) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ requests });
  });
});

app.put('/api/license-requests/:id', authenticateToken, (req, res) => {
  const { status, assignedLicenseKey } = req.body;

  db.run(
    'UPDATE license_requests SET status = ?, processed_at = CURRENT_TIMESTAMP, assigned_license_key = ? WHERE id = ?',
    [status, assignedLicenseKey || null, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update request' });
      }

      res.json({ success: true, message: 'Request updated successfully' });
    }
  );
});

// Audit log
app.get('/api/audit-log', authenticateToken, (req, res) => {
  const { limit = 100 } = req.query;

  db.all(
    'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?',
    [limit],
    (err, logs) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({ logs });
    }
  );
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  db.all(`
    SELECT 
      (SELECT COUNT(*) FROM licenses WHERE status = 'active') as active_licenses,
      (SELECT COUNT(*) FROM licenses WHERE status = 'expired') as expired_licenses,
      (SELECT COUNT(*) FROM licenses) as total_licenses,
      (SELECT COUNT(*) FROM license_requests WHERE status = 'pending') as pending_requests,
      (SELECT COUNT(*) FROM users) as total_users
  `, (err, stats) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ stats: stats[0] });
  });
});

// Serve admin panel
app.use(express.static(path.join(__dirname, 'public')));

// Scheduled task to check for expiring licenses (runs daily at 9 AM)
cron.schedule('0 9 * * *', () => {
  console.log('Running daily license expiration check...');
  
  // Check licenses expiring in 7 days
  const sevenDaysFromNow = new Date();
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);

  db.all(
    'SELECT * FROM licenses WHERE expires_at <= ? AND status = "active" AND expires_at > CURRENT_TIMESTAMP',
    [sevenDaysFromNow.toISOString()],
    (err, licenses) => {
      if (err) {
        console.error('Error checking expiring licenses:', err.message);
        return;
      }

      console.log(`Found ${licenses.length} licenses expiring soon`);
      // Here you would send email notifications
      // For now, just log them
      licenses.forEach(license => {
        console.log(`License ${license.license_key} expires on ${license.expires_at}`);
      });
    }
  );

  // Mark expired licenses
  db.run(
    'UPDATE licenses SET status = "expired" WHERE expires_at < CURRENT_TIMESTAMP AND status = "active"',
    (err) => {
      if (err) {
        console.error('Error updating expired licenses:', err.message);
      } else {
        console.log('Updated expired licenses');
      }
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`StreetOTP License Server running on port ${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}`);
  console.log(`API: http://localhost:${PORT}/api`);
});
