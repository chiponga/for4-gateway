// src/routes/financial.js
const express = require('express');
const router = express.Router();

router.get('/balance', (req, res) => {
  res.json({
    success: true,
    data: {
      available: 0,
      pending: 0,
      total: 0
    }
  });
});

router.get('/withdrawals', (req, res) => {
  res.json({ success: true, data: [] });
});

module.exports = router;

