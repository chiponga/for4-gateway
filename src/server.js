// src/server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const bodyParserErrorHandler = require('express-body-parser-error-handler');
const cron = require('node-cron');

// Criação dos servidores
const app = express();
const WebServer = require('http').createServer(app);
const io = require('socket.io')(WebServer, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Importar componentes
const Database = require('./database/Database');
const NovoCliente = require('./handlers/NovoCliente');

const PORT = process.env.PORT || 5000;
const db = new Database();

// Diretório para imagens
const imagesDir = path.join(process.cwd(), 'uploads', 'imagens');

// Garantir que o diretório de imagens exista
if (!fs.existsSync(imagesDir)) {
  fs.mkdirSync(imagesDir, { recursive: true });
}

// Middlewares de segurança
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

// Configuração de parsing do body
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParserErrorHandler());

// Middleware de logging
app.use(morgan('combined'));

// Rastreamento de conexões ativas
let conexoes = [];

// Configurar o Socket.io para ouvir por conexões
io.on('connection', (Socket) => {
  // Rastrear conexão
  conexoes.push({ Token: Socket.id });
  console.log(`[SOCKETS] - [CONECTADO] = ${Socket.id} - [Socket Ativos] = ${conexoes.length}`);

  // Eventos de autenticação
  Socket.on('Login', (data) => new NovoCliente(data, Socket).handleLogin());
  Socket.on('EnviarRegistro', (data) => new NovoCliente(data, Socket).handleRegistro());
  Socket.on('VerificarToken', (data) => new NovoCliente(data, Socket).handleVerificarToken());

  // Eventos do Dashboard
  Socket.on('DadosDashboard', (data) => new NovoCliente(data, Socket).handleDadosDashboard());
  Socket.on('PerformanceDashboard', (data) => new NovoCliente(data, Socket).handlePerformanceDashboard());
  Socket.on('StatementDashboard', (data) => new NovoCliente(data, Socket).handleStatementDashboard());

  // Eventos financeiros
  Socket.on('GetBalance', (data) => new NovoCliente(data, Socket).handleGetBalance());
  Socket.on('GetWithdrawals', (data) => new NovoCliente(data, Socket).handleGetWithdrawals());
  Socket.on('RequestWithdrawal', (data) => new NovoCliente(data, Socket).handleRequestWithdrawal());

  // Eventos de produtos
  Socket.on('GetProducts', (data) => new NovoCliente(data, Socket).handleGetProducts());
  Socket.on('CreateProduct', (data) => new NovoCliente(data, Socket).handleCreateProduct());
  Socket.on('UpdateProduct', (data) => new NovoCliente(data, Socket).handleUpdateProduct());
  Socket.on('DeleteProduct', (data) => new NovoCliente(data, Socket).handleDeleteProduct());

  // Eventos de pedidos/transações
  Socket.on('GetOrders', (data) => new NovoCliente(data, Socket).handleGetOrders());
  Socket.on('GetTransactions', (data) => new NovoCliente(data, Socket).handleGetTransactions());
  Socket.on('ProcessPayment', (data) => new NovoCliente(data, Socket).handleProcessPayment());

  // Eventos de perfil e configurações
  Socket.on('GetProfile', (data) => new NovoCliente(data, Socket).handleGetProfile());
  Socket.on('UpdateProfile', (data) => new NovoCliente(data, Socket).handleUpdateProfile());
  Socket.on('UpdateSettings', (data) => new NovoCliente(data, Socket).handleUpdateSettings());

  // Eventos de afiliados
  Socket.on('GetAffiliates', (data) => new NovoCliente(data, Socket).handleGetAffiliates());
  Socket.on('AddAffiliate', (data) => new NovoCliente(data, Socket).handleAddAffiliate());
  Socket.on('RemoveAffiliate', (data) => new NovoCliente(data, Socket).handleRemoveAffiliate());

  // Desconexão
  Socket.on('disconnect', () => {
    conexoes = conexoes.filter((e) => e.Token !== Socket.id);
    console.log(`[SOCKETS] - [DESCONECTADO] = ${Socket.id} - [Socket Ativos] = ${conexoes.length}`);
  });
});

// Rota para servir imagens
app.use('/images', express.static(imagesDir));

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Endpoint para webhooks de pagamento
app.post('/webhook/pagamentos', async (req, res) => {
  try {
    const { event, payment } = req.body;
    console.log(`Webhook recebido: ${event}`);
    
    if (event === 'PAYMENT_UPDATED') {
      await new NovoCliente(req.body, null).handlePaymentWebhook();
    }
    
    res.sendStatus(200);
  } catch (error) {
    console.error('Erro no webhook:', error);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Agendamento de tarefas (cron jobs)
cron.schedule('0 */12 * * *', async () => {
  console.log('\n🕐 [CRON] === INÍCIO EXECUÇÃO ===');
  console.log(`📅 Horário: ${new Date().toLocaleString('pt-BR')}`);
  
  try {
    await new NovoCliente([], null).checkPendingPayments();
    console.log('✅ [CRON] Verificação de pagamentos pendentes concluída');
  } catch (error) {
    console.error('❌ [CRON] Erro:', error);
  }
  
  console.log('🕐 [CRON] === FIM EXECUÇÃO ===\n');
}, {
  timezone: "America/Sao_Paulo"
});

// Tratamento de erros globais
process.on('uncaughtException', (err) => {
  console.error('🚨 [UNCAUGHT] Erro não tratado capturado:');
  console.error('📍 Stack trace completo:', err.stack);
  console.error('📍 Mensagem:', err.message);
  console.error('📍 Nome do erro:', err.name);
  console.error('📍 Horário:', new Date().toISOString());
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 [UNHANDLED PROMISE] Promise rejeitada não tratada:');
  console.error('📍 Motivo:', reason);
  console.error('📍 Stack:', reason?.stack);
  console.error('📍 Promise:', promise);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Recebido SIGTERM. Fechando servidor...');
  WebServer.close(() => {
    console.log('✅ Servidor fechado');
    process.exit(0);
  });
});

// Iniciar servidor
WebServer.listen(PORT, async () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
  console.log(`📱 Frontend: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  
  // Carregar imagens iniciais
  try {
    const Query = "SELECT * FROM images";
    const resultado = await db.query(Query);
    console.log(`📸 Carregadas ${resultado.length} imagens`);
  } catch (error) {
    console.log('⚠️ Não foi possível carregar imagens iniciais:', error.message);
  }
});

module.exports = { app, WebServer, io };