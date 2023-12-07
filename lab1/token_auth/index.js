const uuid = require('uuid');
const jwt = require('jsonwebtoken');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';
const jwtSecret = 'verySecretKey';

function generateAccessToken(payload) {
  const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
  return token;
}

app.use((req, res, next) => {
  let token = req.get(SESSION_KEY);
  let payload = null;
  if (token) {
    try {
      payload = jwt.verify(token, jwtSecret);
      req.session = payload;
    } catch (e) {
      res.status(401).send();
    }
  }
  next();
});

app.get('/', (req, res) => {
  if (req.session && req.session.username) {
    return res.json({
      username: req.session.username,
      logout: 'http://localhost:3000/logout',
    });
  }
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
  res.redirect('/');
});

const users = [
  {
    login: 'Login',
    password: 'Password',
    username: 'Username',
  },
  {
    login: 'Login1',
    password: 'Password1',
    username: 'Username1',
  },
];

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  const user = users.find((user) => {
    if (user.login == login && user.password == password) {
      return true;
    }
    return false;
  });

  if (user) {
    const token = generateAccessToken({
      username: user.username,
      login: user.login,
    });
    res.json({ token });
  }

  res.status(401).send();
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
