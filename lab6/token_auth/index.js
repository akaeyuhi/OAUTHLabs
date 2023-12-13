const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const request = require('request');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const port = 3000;
dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

class AuthService {
  adminToken = null;

  async init() {
    if (!this.adminToken) {
      const payload = await this.getAdminToken();
      console.log(payload);
      this.adminToken = payload.access_token;
    }
  }

  async login(username, password) {
    const options = {
      method: 'POST',
      url: `${process.env.DOMAIN}/oauth/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      form: {
        grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
        realm: process.env.CONNECTION,
        scope: 'offline_access',
        username: username,
        password: password,
        audience: process.env.AUDIENCE,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
      },
    };
    try {
      const response = await fetch(options.url, {
        method: options.method,
        headers: options.headers,
        body: new URLSearchParams(options.form),
      });
      return await response.json();
    } catch (e) {
      console.log(e);
    }
  }

  async getAdminToken() {
    const options = {
      method: 'POST',
      url: `${process.env.DOMAIN}/oauth/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      form: {
        grant_type: 'client_credentials',
        audience: process.env.AUDIENCE,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
      },
    };
    try {
      const response = await fetch(options.url, {
        method: options.method,
        headers: options.headers,
        body: new URLSearchParams(options.form),
      });
      return await response.json();
    } catch (e) {
      console.log(e);
    }
  }

  async register(login, password) {
    const data = {
      email: login,
      connection: process.env.CONNECTION,
      password,
    };
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${this.adminToken}`,
    };
    const url = process.env.AUDIENCE + 'users';
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(data),
      });
      return await response.json();
    } catch (e) {
      console.log(e);
    }
  }
  async refresh(refreshToken) {
    const options = {
      method: 'POST',
      url: `${process.env.DOMAIN}/oauth/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      form: {
        grant_type: 'refresh_token',
        scope: 'offline_access',
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        refresh_token: refreshToken,
      },
    };
    try {
      const response = await fetch(options.url, {
        method: options.method,
        headers: options.headers,
        body: new URLSearchParams(options.form),
      });
      return await response.json();
    } catch (e) {
      console.log(e);
    }
  }
  async codeLogin(code) {
    const options = {
      method: 'POST',
      url: `${process.env.DOMAIN}/oauth/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      form: {
        client_id: process.env.CLIENT_ID,
        audience: process.env.AUDIENCE,
        client_secret: process.env.CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: 'http://localhost:3000/',
      },
    };
    try {
      const response = await fetch(options.url, {
        method: options.method,
        headers: options.headers,
        body: new URLSearchParams(options.form),
      });
      return await response.json();
    } catch (e) {
      console.log(e);
    }
  }
}

class Session {
  #sessions = {};

  constructor() {
    try {
      this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
      this.#sessions = JSON.parse(this.#sessions.trim());

      console.log(this.#sessions);
    } catch (e) {
      this.#sessions = {};
    }
  }

  #storeSessions() {
    fs.writeFileSync(
      './sessions.json',
      JSON.stringify(this.#sessions),
      'utf-8'
    );
  }

  set(key, value) {
    if (!value) {
      value = {};
    }
    this.#sessions[key] = value;
    this.#storeSessions();
  }

  get(key) {
    return this.#sessions[key];
  }

  destroy(req, res) {
    const sessionId = req.sessionId;
    delete this.#sessions[sessionId];
    this.#storeSessions();
  }
}

const sessions = new Session();
const authService = new AuthService();
let publicKey = null;
const SESSION_KEY = 'Authorization';

const getPublicKey = async () => {
  await request('https://kpi.eu.auth0.com/pem', function (err, response, body) {
    publicKey = body;
  });
};

app.use(async (req, res, next) => {
  let currentSession = {};
  let sessionId = req.get(SESSION_KEY);
  if (sessionId) {
    try {
      const tokenValue = jwt.verify(sessionId, publicKey);
      console.log({ tokenValue });
    } catch (err) {
      console.error(err);
      return res.status(401).end();
    }
    currentSession = sessions.get(sessionId);
  }
  req.session = currentSession;
  req.sessionId = sessionId;
  next();
});

app.get('/', (req, res) => {
  if (req.session.username) {
    return res.json({
      username: req.session.username,
      logout: 'http://localhost:3000/logout',
    });
  }
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/login', (req, res) => {
  return res.redirect(
    `${process.env.DOMAIN}/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A3000&scope=offline_access&response_type=code&audience=${process.env.AUDIENCE}&response_mode=query`
  );
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname + '/register.html'));
});

app.get('/logout', (req, res) => {
  sessions.destroy(req, res);
  res.redirect('/');
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const payload = await authService.login(login, password);
    console.log(payload);
    const { access_token, expires_in, refresh_token } = payload;
    sessions.set(access_token, { username: login });
    res.send({ token: access_token, expires_in, refresh_token });
  } catch (e) {
    console.log(e);
    res.status(401).send();
  }
});

app.post('/api/codelogin', async (req, res) => {
  const { code } = req.body;
  try {
    const payload = await authService.codeLogin(code);
    const { access_token, expires_in, refresh_token } = payload;
    sessions.set(access_token, { username: 'user' });
    res.send({ token: access_token, expires_in, refresh_token });
  } catch (e) {
    console.log(e);
    res.status(401).send();
  }
});

app.post('/api/refresh', async (req, res) => {
  const { refreshToken, username } = req.body;
  try {
    const { access_token, expires_in, refresh_token } =
      await authService.refresh(refreshToken);
    sessions.set(access_token, { username });
    res.send({ token: access_token, expires_in, refresh_token });
  } catch (e) {
    console.log(e);
    res.status(401).send();
  }
});

app.post('/api/register', async (req, res) => {
  const { login, password } = req.body;
  try {
    await authService.init();
    const response = await authService.register(login, password);
    res.send(response);
  } catch (e) {
    console.log(e);
    res.status(400).json({ message: 'Error', error: e });
  }
});

app.listen(port, async () => {
  await getPublicKey();
  console.log(`Example app listening on port ${port}`);
});
