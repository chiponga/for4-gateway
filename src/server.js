// src/server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { createServer } = require('http');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 5000;

// Middlewares de segurança
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 requests por IP
  message: {
    error: 'Muitas requisições. Tente novamente em alguns minutos.'
  }
});
app.use('/api/', limiter);

// Middlewares
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Rotas básicas inline para teste
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  // Usuário de teste
  if (email === 'admin@for4.com' && password === '123456') {
    res.json({
      success: true,
      message: 'Login realizado com sucesso',
      token: 'test-token-123',
      user: {
        id: 1,
        name: 'Admin For4',
        email: 'admin@for4.com'
      }
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Credenciais inválidas'
    });
  }
});

app.get('/api/auth/verify', (req, res) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (token === 'test-token-123') {
    res.json({
      success: true,
      user: {
        id: 1,
        name: 'Admin For4',
        email: 'admin@for4.com'
      }
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Token inválido'
    });
  }
});

// Dashboard routes
app.get('/api/dashboard/overview', (req, res) => {
  // Simular dados mais realistas
  const currentDate = new Date();
  const salesValue = 1250.50 + (Math.random() * 500);
  const variation = (Math.random() - 0.5) * 30; // -15% a +15%
  
  res.json({
    success: true,
    data: {
      sales_today: { 
        value: salesValue, 
        variation: variation 
      },
      available_balance: 5432.10 + (Math.random() * 1000),
      pending_balance: 890.75 + (Math.random() * 200),
      billing_goal: { 
        current: 8500 + (Math.random() * 1000), 
        target: 10000, 
        percentage: 85 + (Math.random() * 10) 
      },
      payment_methods: {
        pix: { percentage: 45, value: 3825.23 + (Math.random() * 500) },
        card: { percentage: 35, value: 2975.17 + (Math.random() * 400) },
        boleto: { percentage: 15, value: 1275.07 + (Math.random() * 200) },
        crypto: { percentage: 5, value: 425.02 + (Math.random() * 100) }
      },
      // Novas métricas
      visitors_today: Math.floor(1000 + Math.random() * 500),
      conversion_rate: 2.5 + (Math.random() * 2),
      average_ticket: 180 + (Math.random() * 100),
      active_products: Math.floor(40 + Math.random() * 20),
      pending_count: Math.floor(3 + Math.random() * 10)
    }
  });
});

app.get('/api/dashboard/performance', (req, res) => {
  const period = req.query.period || '7d';
  
  // Gerar dados mais realistas baseados no período
  const days = period === '30d' ? 30 : period === '15d' ? 15 : period === '7d' ? 7 : 1;
  const labels = [];
  const revenue = [];
  const sales_count = [];
  const visitors = [];
  const conversions = [];
  
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    
    labels.push(date.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' }));
    
    // Dados mais realistas com tendências
    const baseRevenue = 800 + Math.random() * 2000 + (Math.sin(i * 0.5) * 300);
    const baseSales = 8 + Math.random() * 25 + (Math.sin(i * 0.3) * 5);
    const baseVisitors = Math.floor(baseSales * 12 + Math.random() * 100);
    const baseConversions = Math.floor(baseSales * 0.8 + Math.random() * 3);
    
    revenue.push(Math.max(0, Math.round(baseRevenue)));
    sales_count.push(Math.max(0, Math.round(baseSales)));
    visitors.push(Math.max(0, baseVisitors));
    conversions.push(Math.max(0, baseConversions));
  }
  
  res.json({
    success: true,
    data: {
      period,
      revenue,
      sales_count,
      visitors,
      conversions,
      labels
    }
  });
});

// Financial routes
app.get('/api/financial/balance', (req, res) => {
  res.json({
    success: true,
    data: {
      available: 5432.10,
      pending: 890.75,
      total: 6322.85,
      approved_sales: 4800.00,
      commissions: 632.10,
      refunds: 0,
      pending_approval: 500.00,
      processing: 390.75,
      growth_percentage: 12.5,
      last_withdrawal: {
        date: '2024-01-28T10:30:00Z'
      }
    }
  });
});

app.get('/api/financial/withdrawals', (req, res) => {
  res.json({
    success: true,
    data: [
      {
        id: 1,
        amount: 1000.00,
        bank_account: 'Banco do Brasil - ***1234',
        status: 'completed',
        created_at: '2024-01-25T14:30:00Z',
        completed_at: '2024-01-26T09:15:00Z'
      },
      {
        id: 2,
        amount: 500.00,
        bank_account: 'Nubank - ***5678',
        status: 'processing',
        created_at: '2024-01-28T16:45:00Z',
        completed_at: null
      }
    ]
  });
});

// Outras rotas básicas
app.get('/api/products', (req, res) => {
  res.json({ success: true, data: [] });
});

app.get('/api/affiliates', (req, res) => {
  res.json({ success: true, data: [] });
});

app.get('/api/integrations', (req, res) => {
  res.json({ success: true, data: [] });
});

// Socket.IO para tempo real
io.on('connection', (socket) => {
  console.log('Cliente conectado:', socket.id);

  socket.on('join_user_room', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`Usuário ${userId} entrou na sala`);
    
    // Simular vendas em tempo real a cada 30 segundos
    const salesSimulation = setInterval(() => {
      const saleData = {
        id: Date.now(),
        amount: 50 + Math.random() * 500,
        customer: `Cliente ${Math.floor(Math.random() * 1000)}`,
        product: `Produto ${Math.floor(Math.random() * 50)}`,
        method: ['pix', 'card', 'boleto'][Math.floor(Math.random() * 3)]
      };
      
      socket.emit('new_sale', saleData);
    }, 30000); // A cada 30 segundos
    
    // Simular transações financeiras a cada 45 segundos
    const financialSimulation = setInterval(() => {
      const transactions = [
        {
          type: 'payment_received',
          data: {
            id: Date.now(),
            amount: 100 + Math.random() * 300,
            type: 'payment',
            description: 'Pagamento recebido',
            customer: `Cliente ${Math.floor(Math.random() * 1000)}`
          }
        },
        {
          type: 'withdrawal_processed',
          data: {
            id: Date.now(),
            amount: 200 + Math.random() * 800,
            type: 'withdrawal',
            description: 'Saque processado',
            bank_account: 'Banco ****1234'
          }
        }
      ];
      
      const randomTransaction = transactions[Math.floor(Math.random() * transactions.length)];
      socket.emit(randomTransaction.type, randomTransaction.data);
    }, 45000); // A cada 45 segundos
    
    // Limpar os intervalos quando o socket desconectar
    socket.on('disconnect', () => {
      clearInterval(salesSimulation);
      clearInterval(financialSimulation);
    });
  });

  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

// Rota 404
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Rota não encontrada',
    path: req.originalUrl
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('🚨 Erro:', err);
  
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Erro interno do servidor',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Iniciar servidor
server.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
  console.log(`📱 Frontend: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Recebido SIGTERM. Fechando servidor...');
  server.close(() => {
    console.log('✅ Servidor fechado');
    process.exit(0);
  });
});

module.exports = { app, server, io };