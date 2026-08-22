const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { google } = require('googleapis');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;

const DATA_DIR =
  process.env.DATA_DIR || path.join(__dirname, 'data');

fs.mkdirSync(DATA_DIR, { recursive: true });

const SECRET_FILE = path.join(DATA_DIR, '.jwt-secret');

function getJwtSecret() {
  if (
    process.env.JWT_SECRET &&
    process.env.JWT_SECRET.length >= 32
  ) {
    return process.env.JWT_SECRET;
  }

  try {
    if (fs.existsSync(SECRET_FILE)) {
      const existing = fs
        .readFileSync(SECRET_FILE, 'utf8')
        .trim();

      if (existing.length >= 32) {
        return existing;
      }
    }

    const generated = crypto
      .randomBytes(48)
      .toString('base64url');

    fs.writeFileSync(
      SECRET_FILE,
      generated,
      { mode: 0o600 }
    );

    return generated;
  } catch {
    return crypto
      .randomBytes(48)
      .toString('base64url');
  }
}

const JWT_SECRET = getJwtSecret();

const DB_FILE =
  process.env.DATA_FILE ||
  path.join(DATA_DIR, 'data.json');

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

const oauthStates = new Map();

function oauthState(provider) {
  const state = crypto
    .randomBytes(24)
    .toString('hex');

  oauthStates.set(state, {
    provider,
    expiresAt:
      Date.now() + OAUTH_STATE_TTL_MS
  });

  return state;
}

function takeOAuthState(state, provider) {
  const x = oauthStates.get(state);

  oauthStates.delete(state);

  return (
    x &&
    x.provider === provider &&
    x.expiresAt > Date.now()
  );
}

function oauthUser({
  provider,
  providerId,
  email,
  name
}) {
  let u = db.users.find(
    x =>
      x.oauthProvider === provider &&
      x.oauthId === providerId
  );

  if (!u && email) {
    u = db.users.find(
      x =>
        x.email &&
        x.email.toLowerCase() ===
          String(email).toLowerCase()
    );
  }

  if (!u) {
    let base = String(
      name || provider + 'user'
    )
      .replace(/[^a-zA-Z0-9_]/g, '')
      .slice(0, 18);

    base = base || provider + 'user';

    let username = base;
    let n = 1;

    while (
      db.users.some(
        x =>
          x.username.toLowerCase() ===
          username.toLowerCase()
      )
    ) {
      username = base + n++;
    }

    u = {
      id: id('u'),
      mobile: null,
      username,
      email: email || null,
      passwordHash: null,
      oauthProvider: provider,
      oauthId: providerId,
      coins: 12050,
      diamonds: 560,
      followers: 0,
      following: 0,
      likes: 0,
      createdAt: Date.now()
    };

    db.users.push(u);
  } else {
    u.oauthProvider = provider;
    u.oauthId = providerId;

    if (email) {
      u.email = email;
    }

    if (
      name &&
      u.username === provider + 'user'
    ) {
      u.username = name;
    }
  }

  saveDb();

  return u;
}

function oauthRedirect(token) {
  return (
    'xena://oauth?token=' +
    encodeURIComponent(token)
  );
}

function loadDb() {
  const emptyDb = {
    users: [],
    rooms: [],
    messages: [],
    transactions: [],
    follows: [],
    blocks: [],
    reports: []
  };

  if (!fs.existsSync(DB_FILE)) {
    return emptyDb;
  }

  try {
    const data = JSON.parse(
      fs.readFileSync(DB_FILE, 'utf8')
    );

    return {
      ...emptyDb,
      ...data,
      users: data.users || [],
      rooms: data.rooms || [],
      messages: data.messages || [],
      transactions: data.transactions || [],
      follows: data.follows || [],
      blocks: data.blocks || [],
      reports: data.reports || []
    };
  } catch {
    return emptyDb;
  }
}

let db = loadDb();

db.blocks = db.blocks || [];
db.reports = db.reports || [];

function saveDb() {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2)
  );
}

function id(prefix) {
  return (
    prefix +
    '_' +
    Math.random().toString(36).slice(2, 10) +
    Date.now().toString(36)
  );
}

function safeUser(u) {
  return {
    id: u.id,
    username: u.username,
    mobile: u.mobile,
    coins: u.coins,
    diamonds: u.diamonds,
    followers: u.followers,
    following: u.following,
    likes: u.likes
  };
}

function tokenFor(u) {
  return jwt.sign(
    { id: u.id },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  const h =
    req.headers.authorization || '';

  if (!h.startsWith('Bearer ')) {
    return res
      .status(401)
      .json({
        error: 'Login required'
      });
  }

  try {
    req.user = jwt.verify(
      h.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    return res
      .status(401)
      .json({
        error:
          'Invalid or expired token'
      });
  }
}

function findUser(userId) {
  return db.users.find(
    u => u.id === userId
  );
}

function publicRoom(room) {
  return {
    ...room,
    viewerCount:
      room.viewerCount || 0
  };
}

const app = express();

app.use(
  helmet({
    crossOriginEmbedderPolicy: false
  })
);

const corsOrigins = (
  process.env.CORS_ORIGINS || ''
)
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

if (corsOrigins.length) {
  app.use(
    cors({
      origin: corsOrigins,
      credentials: true
    })
  );
}

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.set(
      'Cache-Control',
      'no-store'
    );
  }

  next();
});

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 240,
    standardHeaders: true,
    legacyHeaders: false
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error:
      'Too many login attempts. Please try again later.'
  }
});

/* =========================
   GOOGLE LOGIN
========================= */

app.get('/auth/google', (req, res) => {
  const clientId =
    process.env.GOOGLE_CLIENT_ID;

  const secret =
    process.env.GOOGLE_CLIENT_SECRET;

  const redirect =
    process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !secret || !redirect) {
    return res
      .status(503)
      .send(
        'Google Login is not configured on this server.'
      );
  }

  const state =
    oauthState('google');

  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirect,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account',
    state
  });

  res.redirect(
    'https://accounts.google.com/o/oauth2/v2/auth?' +
      q.toString()
  );
});

app.get(
  '/auth/google/callback',
  async (req, res) => {
    try {
      if (
        !takeOAuthState(
          req.query.state,
          'google'
        )
      ) {
        return res
          .status(400)
          .send(
            'Invalid or expired OAuth state.'
          );
      }

      if (req.query.error) {
        return res
          .status(400)
          .send(
            'Google login cancelled.'
          );
      }

      const oauth2 =
        new google.auth.OAuth2(
          process.env.GOOGLE_CLIENT_ID,
          process.env.GOOGLE_CLIENT_SECRET,
          process.env.GOOGLE_REDIRECT_URI
        );

      const { tokens } =
        await oauth2.getToken(
          String(req.query.code)
        );

      oauth2.setCredentials(tokens);

      const ticket =
        await oauth2.getTokenInfo(
          tokens.access_token
        );

      const info = await fetch(
        'https://openidconnect.googleapis.com/v1/userinfo',
        {
          headers: {
            Authorization:
              'Bearer ' +
              tokens.access_token
          }
        }
      ).then(r => r.json());

      const u = oauthUser({
        provider: 'google',
        providerId: String(
          info.sub || ticket.sub
        ),
        email: info.email,
        name:
          info.name ||
          info.given_name
      });

      res.redirect(
        oauthRedirect(
          tokenFor(u)
        )
      );
    } catch (e) {
      console.error(
        'google oauth',
        e
      );

      res
        .status(502)
        .send(
          'Google login failed.'
        );
    }
  }
);

/* =========================
   FACEBOOK LOGIN
========================= */

app.get(
  '/auth/facebook',
  (req, res) => {
    const appId =
      process.env.FACEBOOK_APP_ID;

    const secret =
      process.env.FACEBOOK_APP_SECRET;

    const redirect =
      process.env.FACEBOOK_REDIRECT_URI;

    if (
      !appId ||
      !secret ||
      !redirect
    ) {
      return res
        .status(503)
        .send(
          'Facebook Login is not configured on this server.'
        );
    }

    const state =
      oauthState('facebook');

    const q = new URLSearchParams({
      client_id: appId,
      redirect_uri: redirect,
      state,
      scope:
        'email,public_profile'
    });

    res.redirect(
      'https://www.facebook.com/v23.0/dialog/oauth?' +
        q.toString()
    );
  }
);

app.get(
  '/auth/facebook/callback',
  async (req, res) => {
    try {
      if (
        !takeOAuthState(
          req.query.state,
          'facebook'
        )
      ) {
        return res
          .status(400)
          .send(
            'Invalid or expired OAuth state.'
          );
      }

      if (req.query.error) {
        return res
          .status(400)
          .send(
            'Facebook login cancelled.'
          );
      }

      const base =
        'https://graph.facebook.com/v23.0/oauth/access_token';

      const q =
        new URLSearchParams({
          client_id:
            process.env.FACEBOOK_APP_ID,

          client_secret:
            process.env.FACEBOOK_APP_SECRET,

          redirect_uri:
            process.env.FACEBOOK_REDIRECT_URI,

          code:
            String(req.query.code)
        });

      const tok =
        await fetch(
          base + '?' + q.toString()
        ).then(r => r.json());

      if (!tok.access_token) {
        throw new Error(
          'No Facebook access token'
        );
      }

      const info =
        await fetch(
          'https://graph.facebook.com/me?fields=id,name,email&access_token=' +
            encodeURIComponent(
              tok.access_token
            )
        ).then(r => r.json());

      if (!info.id) {
        throw new Error(
          'Facebook profile unavailable'
        );
      }

      const u = oauthUser({
        provider: 'facebook',
        providerId: String(info.id),
        email: info.email,
        name: info.name
      });

      res.redirect(
        oauthRedirect(
          tokenFor(u)
        )
      );
    } catch (e) {
      console.error(
        'facebook oauth',
        e
      );

      res
        .status(502)
        .send(
          'Facebook login failed.'
        );
    }
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  '/health',
  (req, res) => {
    res.json({
      ok: true,
      name: 'Xena Live India',
      version: '3.1.0',
      storage:
        process.env.DATA_FILE
          ? 'file'
          : 'managed-data-dir',
      time:
        new Date().toISOString()
    });
  }
);

app.get(
  '/api/version',
  (req, res) => {
    res.json({
      name: 'Xena Live India',
      version: '3.1.0'
    });
  }
);

app.get(
  '/api/config',
  (req, res) => {
    res.json({
      iceServers: [
        {
          urls: [
            'stun:stun.l.google.com:19302'
          ]
        },

        ...(process.env.TURN_URL
          ? [
              {
                urls:
                  process.env.TURN_URL
                    .split(',')
                    .map(x =>
                      x.trim()
                    ),

                username:
                  process.env
                    .TURN_USERNAME || '',

                credential:
                  process.env
                    .TURN_CREDENTIAL || ''
              }
            ]
          : [])
      ]
    });
  }
);

/* =========================
   STATIC WEBSITE
========================= */

/*
   IMPORTANT:
   index.html tumhare GitHub
   repository ke ROOT me hai.

   Isliye public/index.html nahi,
   balki __dirname/index.html
   use kiya gaya hai.
*/

app.use(
  express.static(__dirname)
);

app.get('/', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'index.html'
    )
  );
});

app.get('/app', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'index.html'
    )
  );
});

/* =========================
   AUTH - SIGNUP
========================= */

app.post(
  '/api/auth/signup',
  authLimiter,
  async (req, res) => {
    const {
      mobile,
      username,
      password
    } = req.body || {};

    if (
      !mobile ||
      !username ||
      !password
    ) {
      return res
        .status(400)
        .json({
          error:
            'Mobile, username and password are required'
        });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({
          error:
            'Password must be at least 6 characters'
        });
    }

    if (
      db.users.some(
        u =>
          u.mobile === mobile ||
          u.username.toLowerCase() ===
            username.toLowerCase()
      )
    ) {
      return res
        .status(409)
        .json({
          error:
            'Mobile or username already exists'
        });
    }

    const u = {
      id: id('u'),
      mobile,
      username,
      passwordHash:
        await bcrypt.hash(
          password,
          10
        ),
      coins: 12050,
      diamonds: 560,
      followers: 0,
      following: 0,
      likes: 0,
      createdAt: Date.now()
    };

    db.users.push(u);

    saveDb();

    res.json({
      token: tokenFor(u),
      user: safeUser(u)
    });
  }
);

/* =========================
   AUTH - LOGIN
========================= */

app.post(
  '/api/auth/login',
  authLimiter,
  async (req, res) => {
    const {
      mobile,
      password
    } = req.body || {};

    const u = db.users.find(
      x => x.mobile === mobile
    );

    if (
      !u ||
      !u.passwordHash ||
      !(await bcrypt.compare(
        password || '',
        u.passwordHash
      ))
    ) {
      return res
        .status(401)
        .json({
          error:
            'Invalid mobile or password'
        });
    }

    res.json({
      token: tokenFor(u),
      user: safeUser(u)
    });
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  '/api/me',
  auth,
  (req, res) => {
    const u = findUser(
      req.user.id
    );

    if (!u) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    res.json({
      user: safeUser(u)
    });
  }
);

/* =========================
   ROOMS
========================= */

app.get(
  '/api/rooms',
  auth,
  (req, res) => {
    res.json({
      rooms: db.rooms
        .filter(
          r => r.status === 'live'
        )
        .map(publicRoom)
    });
  }
);

app.post(
  '/api/rooms',
  auth,
  (req, res) => {
    const {
      title = 'My Live Stream',
      category = 'Music'
    } = req.body || {};

    db.rooms
      .filter(
        r =>
          r.hostId ===
            req.user.id &&
          r.status === 'live'
      )
      .forEach(
        r => (r.status = 'ended')
      );

    const u = findUser(
      req.user.id
    );

    if (!u) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    const room = {
      id: id('room'),
      hostId: u.id,
      hostName: u.username,
      title,
      category,
      status: 'live',
      viewerCount: 0,
      createdAt: Date.now()
    };

    db.rooms.push(room);

    saveDb();

    res.json({
      room: publicRoom(room)
    });
  }
);

app.post(
  '/api/rooms/:roomId/end',
  auth,
  (req, res) => {
    const r = db.rooms.find(
      x =>
        x.id ===
          req.params.roomId &&
        x.hostId ===
          req.user.id
    );

    if (!r) {
      return res
        .status(404)
        .json({
          error:
            'Room not found'
        });
    }

    r.status = 'ended';

    saveDb();

    res.json({
      ok: true
    });
  }
);

/* =========================
   ROOM MESSAGES
========================= */

app.get(
  '/api/rooms/:roomId/messages',
  auth,
  (req, res) => {
    res.json({
      messages: db.messages
        .filter(
          m =>
            m.roomId ===
            req.params.roomId
        )
        .slice(-100)
    });
  }
);

app.post(
  '/api/rooms/:roomId/messages',
  auth,
  (req, res) => {
    const u = findUser(
      req.user.id
    );

    if (!u) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    const text = String(
      req.body?.text || ''
    ).trim();

    if (!text) {
      return res
        .status(400)
        .json({
          error:
            'Message required'
        });
    }

    const m = {
      id: id('msg'),
      roomId:
        req.params.roomId,
      userId: u.id,
      username: u.username,
      text: text.slice(0, 500),
      createdAt: Date.now()
    };

    db.messages.push(m);

    if (
      db.messages.length >
      5000
    ) {
      db.messages =
        db.messages.slice(-5000);
    }

    saveDb();

    if (io) {
      io
        .to(req.params.roomId)
        .emit(
          'chat:message',
          m
        );
    }

    res.json({
      message: m
    });
  }
);

/* =========================
   FOLLOW
========================= */

app.post(
  '/api/users/:userId/follow',
  auth,
  (req, res) => {
    const me = findUser(
      req.user.id
    );

    const target = findUser(
      req.params.userId
    );

    if (!me || !target) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    if (me.id === target.id) {
      return res
        .status(400)
        .json({
          error:
            'Cannot follow yourself'
        });
    }

    const exists =
      db.follows.some(
        f =>
          f.from === me.id &&
          f.to === target.id
      );

    if (exists) {
      db.follows =
        db.follows.filter(
          f =>
            !(
              f.from === me.id &&
              f.to === target.id
            )
        );

      target.followers =
        Math.max(
          0,
          target.followers - 1
        );

      me.following =
        Math.max(
          0,
          me.following - 1
        );
    } else {
      db.follows.push({
        from: me.id,
        to: target.id
      });

      target.followers++;
      me.following++;
    }

    saveDb();

    res.json({
      following: !exists,
      user: safeUser(target)
    });
  }
);

/* =========================
   BLOCK
========================= */

app.post(
  '/api/users/:userId/block',
  auth,
  (req, res) => {
    const me = findUser(
      req.user.id
    );

    const target = findUser(
      req.params.userId
    );

    if (!target) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    if (me.id === target.id) {
      return res
        .status(400)
        .json({
          error:
            'Cannot block yourself'
        });
    }

    db.blocks =
      db.blocks || [];

    const exists =
      db.blocks.some(
        b =>
          b.from === me.id &&
          b.to === target.id
      );

    if (exists) {
      db.blocks =
        db.blocks.filter(
          b =>
            !(
              b.from === me.id &&
              b.to === target.id
            )
        );
    } else {
      db.blocks.push({
        from: me.id,
        to: target.id,
        createdAt: Date.now()
      });
    }

    saveDb();

    res.json({
      blocked: !exists
    });
  }
);

/* =========================
   REPORT
========================= */

app.post(
  '/api/reports',
  auth,
  (req, res) => {
    const {
      targetUserId,
      roomId,
      messageId,
      reason
    } = req.body || {};

    if (
      !reason ||
      String(reason).trim()
        .length < 3
    ) {
      return res
        .status(400)
        .json({
          error:
            'Report reason is required'
        });
    }

    db.reports =
      db.reports || [];

    const report = {
      id: id('report'),
      reporterId:
        req.user.id,
      targetUserId:
        targetUserId || null,
      roomId:
        roomId || null,
      messageId:
        messageId || null,
      reason:
        String(reason).slice(
          0,
          500
        ),
      status: 'open',
      createdAt: Date.now()
    };

    db.reports.push(report);

    saveDb();

    res.json({
      ok: true,
      reportId:
        report.id
    });
  }
);

/* =========================
   DELETE ACCOUNT
========================= */

app.delete(
  '/api/me',
  auth,
  (req, res) => {
    const uid =
      req.user.id;

    db.users =
      db.users.filter(
        u => u.id !== uid
      );

    db.rooms =
      db.rooms.filter(
        r =>
          r.hostId !== uid
      );

    db.messages =
      db.messages.filter(
        m =>
          m.userId !== uid
      );

    db.transactions =
      db.transactions.filter(
        t =>
          t.userId !== uid &&
          t.senderId !== uid &&
          t.receiverId !== uid
      );

    db.follows =
      db.follows.filter(
        f =>
          f.from !== uid &&
          f.to !== uid
      );

    db.blocks =
      (db.blocks || [])
        .filter(
          b =>
            b.from !== uid &&
            b.to !== uid
        );

    db.reports =
      (db.reports || [])
        .filter(
          r =>
            r.reporterId !== uid
        );

    saveDb();

    res.json({
      ok: true
    });
  }
);

/* =========================
   GOOGLE PLAY BILLING
========================= */

app.post(
  '/api/billing/verify',
  auth,
  async (req, res) => {
    try {
      const {
        productId,
        purchaseToken
      } = req.body || {};

      const coinMap = {
        coins_100: 100,
        coins_500: 500,
        coins_1000: 1000,
        coins_5000: 5000
      };

      const amount =
        coinMap[productId];

      if (
        !amount ||
        !purchaseToken
      ) {
        return res
          .status(400)
          .json({
            error:
              'Invalid purchase'
          });
      }

      if (
        db.transactions.some(
          t =>
            t.type ===
              'play_purchase' &&
            t.purchaseToken ===
              purchaseToken
        )
      ) {
        return res.json({
          ok: true,
          alreadyProcessed:
            true
        });
      }

      const raw =
        process.env
          .GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;

      if (!raw) {
        return res
          .status(503)
          .json({
            error:
              'Google Play verification is not configured'
          });
      }

      const credentials =
        JSON.parse(raw);

      const authClient =
        new google.auth.GoogleAuth({
          credentials,
          scopes: [
            'https://www.googleapis.com/auth/androidpublisher'
          ]
        });

      const publisher =
        google.androidpublisher({
          version: 'v3',
          auth: authClient
        });

      const packageName =
        process.env
          .ANDROID_PACKAGE_NAME ||
        'com.xenalive.india';

      const result =
        await publisher.purchases.products.get(
          {
            packageName,
            productId,
            token:
              purchaseToken
          }
        );

      const purchase =
        result.data;

      if (
        Number(
          purchase.purchaseState
        ) !== 0
      ) {
        return res
          .status(400)
          .json({
            error:
              'Purchase is not completed'
          });
      }

      const u = findUser(
        req.user.id
      );

      if (!u) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      u.coins += amount;

      db.transactions.push({
        id: id('tx'),
        userId: u.id,
        type:
          'play_purchase',
        amount,
        productId,
        purchaseToken,
        createdAt:
          Date.now(),
        description:
          `Google Play ${productId}`
      });

      saveDb();

      try {
        await publisher.purchases.products.consume(
          {
            packageName,
            productId,
            token:
              purchaseToken
          }
        );
      } catch (e) {
        console.error(
          'Google purchase consume error',
          e
        );
      }

      res.json({
        ok: true,
        coins: u.coins,
        credited: amount
      });
    } catch (e) {
      console.error(
        'billing verify',
        e
      );

      res
        .status(502)
        .json({
          error:
            'Purchase verification failed'
        });
    }
  }
);

/* =========================
   WALLET
========================= */

app.get(
  '/api/wallet',
  auth,
  (req, res) => {
    const u = findUser(
      req.user.id
    );

    if (!u) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    res.json({
      coins: u.coins,
      diamonds:
        u.diamonds,

      transactions:
        db.transactions
          .filter(
            t =>
              t.userId === u.id
          )
          .slice(-100)
          .reverse()
    });
  }
);

/* =========================
   GIFTS
========================= */

app.post(
  '/api/gifts',
  auth,
  (req, res) => {
    const {
      roomId,
      receiverId,
      coins = 100,
      gift = '🎁'
    } = req.body || {};

    const amount = Math.max(
      1,
      Math.floor(
        Number(coins)
      )
    );

    const sender =
      findUser(req.user.id);

    const receiver =
      findUser(receiverId);

    if (!sender || !receiver) {
      return res
        .status(404)
        .json({
          error:
            'Receiver not found'
        });
    }

    if (
      sender.coins <
      amount
    ) {
      return res
        .status(400)
        .json({
          error:
            'Not enough coins'
        });
    }

    sender.coins -= amount;

    const diamonds =
      Math.max(
        1,
        Math.floor(
          amount / 10
        )
      );

    receiver.diamonds +=
      diamonds;

    const tx = {
      id: id('tx'),
      userId: sender.id,
      type: 'gift_sent',
      amount: -amount,
      roomId,
      receiverId,
      createdAt:
        Date.now(),
      description:
        `${gift} gift sent`
    };

    db.transactions.push(tx);

    db.transactions.push({
      id: id('tx'),
      userId:
        receiver.id,
      type:
        'gift_received',
      amount: diamonds,
      roomId,
      senderId:
        sender.id,
      createdAt:
        Date.now(),
      description:
        `${gift} gift received`
    });

    saveDb();

    if (io) {
      io
        .to(roomId)
        .emit(
          'gift:sent',
          {
            from:
              sender.username,
            to:
              receiver.username,
            gift,
            coins:
              amount
          }
        );
    }

    res.json({
      ok: true,
      coins:
        sender.coins,
      diamonds:
        receiver.diamonds
    });
  }
);

/* =========================
   HTTP + SOCKET.IO
========================= */

const server =
  http.createServer(app);

const ioOptions =
  corsOrigins.length
    ? {
        cors: {
          origin:
            corsOrigins,
          credentials:
            true
        }
      }
    : {};

const io =
  new Server(
    server,
    ioOptions
  );

const sockets =
  new Map();

/* =========================
   SOCKET AUTH
========================= */

io.use(
  (socket, next) => {
    try {
      const token =
        socket.handshake
          .auth?.token;

      if (!token) {
        return next(
          new Error(
            'Unauthorized'
          )
        );
      }

      socket.user =
        jwt.verify(
          token,
          JWT_SECRET
        );

      next();
    } catch {
      next(
        new Error(
          'Unauthorized'
        )
      );
    }
  }
);

/* =========================
   SOCKET CONNECTION
========================= */

io.on(
  'connection',
  socket => {
    sockets.set(
      socket.id,
      socket
    );

    socket.on(
      'room:join',
      ({ roomId }) => {
        const r =
          db.rooms.find(
            x =>
              x.id ===
                roomId &&
              x.status ===
                'live'
          );

        if (!r) {
          return socket.emit(
            'room:error',
            'Room is not live'
          );
        }

        socket.join(roomId);

        socket.data.roomId =
          roomId;

        socket.data.role =
          socket.user.id ===
          r.hostId
            ? 'host'
            : 'viewer';

        r.viewerCount =
          (r.viewerCount ||
            0) + 1;

        saveDb();

        io.to(roomId).emit(
          'room:count',
          {
            count:
              r.viewerCount
          }
        );

        if (
          socket.data.role ===
          'viewer'
        ) {
          io.to(r.id).emit(
            'webrtc:viewer-joined',
            {
              viewerId:
                socket.id
            }
          );
        }
      }
    );

    socket.on(
      'room:leave',
      () => leave(socket)
    );

    socket.on(
      'chat:message',
      ({ roomId, text }) => {
        const r =
          db.rooms.find(
            x =>
              x.id ===
                roomId &&
              x.status ===
                'live'
          );

        if (!r) return;

        const u =
          findUser(
            socket.user.id
          );

        if (!u) return;

        const cleanText =
          String(
            text || ''
          )
            .trim()
            .slice(0, 500);

        if (!cleanText)
          return;

        const m = {
          id: id('msg'),
          roomId,
          userId: u.id,
          username:
            u.username,
          text:
            cleanText,
          createdAt:
            Date.now()
        };

        db.messages.push(m);

        if (
          db.messages.length >
          5000
        ) {
          db.messages =
            db.messages.slice(
              -5000
            );
        }

        saveDb();

        io.to(roomId).emit(
          'chat:message',
          m
        );
      }
    );

    socket.on(
      'webrtc:offer',
      ({
        viewerId,
        offer
      }) => {
        io.to(
          viewerId
        ).emit(
          'webrtc:offer',
          {
            hostId:
              socket.id,
            offer
          }
        );
      }
    );

    socket.on(
      'webrtc:answer',
      ({
        hostId,
        answer
      }) => {
        io.to(
          hostId
        ).emit(
          'webrtc:answer',
          {
            viewerId:
              socket.id,
            answer
          }
        );
      }
    );

    socket.on(
      'webrtc:candidate',
      ({
        targetId,
        candidate
      }) => {
        io.to(
          targetId
        ).emit(
          'webrtc:candidate',
          {
            fromId:
              socket.id,
            candidate
          }
        );
      }
    );

    socket.on(
      'disconnect',
      () => leave(socket)
    );
  }
);

/* =========================
   LEAVE ROOM
========================= */

function leave(socket) {
  const roomId =
    socket.data.roomId;

  if (!roomId) return;

  const r =
    db.rooms.find(
      x =>
        x.id === roomId
    );

  if (r) {
    r.viewerCount =
      Math.max(
        0,
        (r.viewerCount ||
          1) - 1
      );

    if (
      socket.data.role ===
      'host'
    ) {
      r.status = 'ended';
    }

    saveDb();

    io.to(roomId).emit(
      'room:count',
      {
        count:
          r.viewerCount
      }
    );
  }

  socket.data.roomId =
    null;
}

/* =========================
   PROCESS SHUTDOWN
========================= */

process.on(
  'SIGTERM',
  () => {
    server.close(
      () =>
        process.exit(0)
    );
  }
);

process.on(
  'SIGINT',
  () => {
    server.close(
      () =>
        process.exit(0)
    );
  }
);

/* =========================
   START SERVER
========================= */

server.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Xena Live India server listening on ${PORT}`
    );
  }
);
