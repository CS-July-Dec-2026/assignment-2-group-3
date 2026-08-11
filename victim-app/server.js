/**
 * VICTIM APP  —  "BankDash"
 * ---------------------------------------------------------
 * A tiny fake banking dashboard used to demonstrate a
 * CORS MISCONFIGURATION vulnerability for a security assignment.
 *
 * DELIBERATE FLAW (see the "VULNERABLE CORS MIDDLEWARE" block
 * below): the server reflects whatever Origin header the
 * browser sends back in Access-Control-Allow-Origin, AND sets
 * Access-Control-Allow-Credentials: true. That combination
 * means ANY website on the internet can make a credentialed
 * request to this API using a logged-in victim's session
 * cookie, and actually read the JSON response back in
 * JavaScript.
 *
 * Run with:  npm install && npm start
 * Visit:     http://localhost:4000
 * ---------------------------------------------------------
 */

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 4000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'bankdash-demo-secret-key',   // fine for a classroom demo
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,     // demo runs on http://localhost
    sameSite: 'lax',   // NOTE: SameSite=Lax does NOT stop this attack,
                        // because the request is a normal cross-origin
                        // fetch from a page the victim is actively
                        // visiting in their own browser — the browser
                        // still attaches first-party cookies for that.
  }
}));

// --- Fake user "database" ------------------------------------------------
const USERS = {
  'alice@example.com': {
    password: 'hunter2',
    profile: {
      name: 'Alice Johnson',
      email: 'alice@example.com',
      accountNumber: 'IN29 8842 1123 9981',
      balance: '₹4,52,300.00',
      ssnLike: 'PAN: AXJPK4321L',
      apiKey: 'sk_live_bankdash_9f83jd82jf92jf82'
    }
  }
};

// --- State management for CORS Security Lab Demo ------------------------
let corsMode = 'vulnerable'; // Default state: 'vulnerable' | 'fixed'
const ALLOWED_ORIGINS = ['http://localhost:4000'];

// =====================================================================
//  DYNAMIC CORS MIDDLEWARE  (supports live toggling for Security Lab)
// =====================================================================
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (origin) {
    if (corsMode === 'vulnerable') {
      // BUG: reflects ANY requesting origin back as allowed + allows credentials
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
    } else {
      // FIXED: validates requesting origin against allowlist & adds Vary: Origin
      if (ALLOWED_ORIGINS.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Vary', 'Origin');
      }
    }
  }
  
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
// =====================================================================

// --- Admin / Security Lab Control Endpoints --------------------------
app.get('/api/admin/cors-config', (req, res) => {
  res.json({ corsMode, allowedOrigins: ALLOWED_ORIGINS });
});

app.post('/api/admin/toggle-cors', (req, res) => {
  const requestedMode = req.body && req.body.mode;
  if (requestedMode === 'vulnerable' || requestedMode === 'fixed') {
    corsMode = requestedMode;
  } else {
    corsMode = corsMode === 'vulnerable' ? 'fixed' : 'vulnerable';
  }
  res.json({ corsMode, allowedOrigins: ALLOWED_ORIGINS });
});


// --- Auth routes -----------------------------------------------------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = USERS[email];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.user = email;
  res.json({ message: 'Logged in', email });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

app.get('/api/session', (req, res) => {
  if (!req.session.user) return res.status(401).json({ loggedIn: false });
  res.json({ loggedIn: true, email: req.session.user });
});

// --- Sensitive endpoint (the thing the attacker wants) ---------------
app.get('/api/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  const data = USERS[req.session.user].profile;
  res.json(data);
});

app.listen(PORT, () => {
  console.log(`BankDash (victim app) running at http://localhost:${PORT}`);
});
