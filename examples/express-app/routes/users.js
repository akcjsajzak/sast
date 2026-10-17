const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const _ = require('lodash');
const router = express.Router();

// SQL injection: request data concatenated into a query.
router.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ' + req.query.id, cb);
});

// Command injection: request data passed to a shell.
router.get('/ping', (req, res) => {
  cp.exec('ping -c 1 ' + req.query.host, cb);
});

// Path traversal: request data used as a filesystem path.
router.get('/file', (req, res) => {
  fs.readFile(req.query.name, (e, d) => res.send(d));
});

// Open redirect.
router.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

// SSRF.
router.get('/fetch', (req, res) => {
  fetch(req.query.url).then((r) => r.text()).then((t) => res.send(t));
});

// Prototype pollution via a deep merge of request data.
router.post('/settings', (req, res) => {
  _.merge({}, req.body);
});

// NoSQL injection.
router.post('/search', (req, res) => {
  User.find(req.body.filter);
});

module.exports = router;
