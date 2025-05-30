// src/routes/dashboard.js
const express = require('express');
const router = express.Router();

// Overview do dashboard
router.get('/overview', (req, res) => {
  res.json({
    success: true,
    data: {
      sales_today: { value: 0, variation: 0 },
      available_balance: 0,
      pending_balance: 0,
      billing_goal: { current: 0, target: 10000, percentage: 0 },
      payment_methods: {
        pix: { percentage: 45, value: 0 },
        card: { percentage: 35, value: 0 },
        boleto: { percentage: 15, value: 0 },
        crypto: { percentage: 5, value: 0 }
      }
    }
  });
});

// Performance
router.get('/performance', (req, res) => {
  const period = req.query.period || '7d';
  
  res.json({
    success: true,
    data: {
      period,
      revenue: [],
      sales_count: [],
      labels: []
    }
  });
});

// Extrato
router.get('/statement', (req, res) => {
  res.json({
    success: true,
    data: {
      statements: []
    }
  });
});

module.exports = router;