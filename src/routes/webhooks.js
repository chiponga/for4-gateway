// src/routes/webhooks.js
const express = require('express');
const router = express.Router();

router.post('/:provider', (req, res) => {
  res.json({ success: true, message: 'Webhook recebido' });
});