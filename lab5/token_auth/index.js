const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const { auth } = require('express-oauth2-jwt-bearer');
const port = 3000;
dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const checkJwt = auth({
  issuerBaseURL: process.env.DOMAIN,
  audience: process.env.AUDIENCE,
});

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
}

const authService = new AuthService();

app.get('/getData', checkJwt, (req, res) => {
  return res.json({
    payload: req.auth.payload,
    logout: 'http://localhost:3000/logout',
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname + '/login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname + '/register.html'));
});

app.get('/logout', checkJwt, (req, res) => {
  res.redirect('/login');
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const payload = await authService.login(login, password);
    console.log(payload);
    const { access_token, expires_in, refresh_token } = payload;
    res.send({ token: access_token, expires_in, refresh_token });
  } catch (e) {
    console.log(e);
    res.status(401).send();
  }
});

app.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  try {
    const { access_token, expires_in, refresh_token } =
      await authService.refresh(refreshToken);
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

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
