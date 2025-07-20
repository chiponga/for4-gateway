// src/server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Criação dos servidores
const app = express();
const WebServer = require('http').createServer(app);

const io = require('socket.io')(WebServer, {
    cors: {
        origin: process.env.FRONTEND_URL || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true
    }
});
const { Criptografar, Descriptografar } = require('./utils/crypto');

const { ApiAuthMiddleware } = require('./gateway/ApiKeysHandler');
const GatewayTransactionHandler = require('./gateway/GatewayTransactionHandler');
const apiAuth = new ApiAuthMiddleware();

const Database = require('./config/database');
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
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Configuração de parsing do body
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Middleware de logging
app.use(morgan('combined'));

// Rastreamento de conexões ativas
let conexoes = [];


// Configurar o Socket.io para ouvir por conexões
io.on('connection', (Socket) => {
    // Rastrear conexão
    conexoes.push({ Token: Socket.id });
    console.log(`[SOCKETS] - [CONECTADO] = ${Socket.id} - [Socket Ativos] = ${conexoes.length}`);

    Socket.on('Login', (data) => new NovoCliente(data, Socket).handleLogin());
    Socket.on('Register', (data) => new NovoCliente(data, Socket).handleRegistro());
    Socket.on('VerificarToken', (data) => new NovoCliente(data, Socket).handleVerificarToken());
    Socket.on('ForgotPassword', (data) => new NovoCliente(data, Socket).handleForgotPassword());
    Socket.on('ResetPassword', (data) => new NovoCliente(data, Socket).handleResetPassword());

    Socket.on('DadosDashboard', (data) => new NovoCliente(data, Socket).handleDadosDashboard());
    Socket.on('PerformanceDashboard', (data) => new NovoCliente(data, Socket).handlePerformanceDashboard());
    Socket.on('StatementDashboard', (data) => new NovoCliente(data, Socket).handleStatementDashboard());
    Socket.on('GetNotifications', (data) => new NovoCliente(data, Socket).handleGetNotifications());
    Socket.on('MarkNotificationRead', (data) => new NovoCliente(data, Socket).handleMarkNotificationRead());

    Socket.on('GetBalance', (data) => new NovoCliente(data, Socket).handleGetBalance());
    Socket.on('GetWithdrawals', (data) => new NovoCliente(data, Socket).handleGetWithdrawals());
    Socket.on('RequestWithdrawal', (data) => new NovoCliente(data, Socket).handleRequestWithdrawal());
    Socket.on('GetBankAccounts', (data) => new NovoCliente(data, Socket).handleGetBankAccounts());
    Socket.on('CreateBankAccount', (data) => new NovoCliente(data, Socket).handleCreateBankAccount());
    Socket.on('UpdateBankAccount', (data) => new NovoCliente(data, Socket).handleUpdateBankAccount());
    Socket.on('DeleteBankAccount', (data) => new NovoCliente(data, Socket).handleDeleteBankAccount());
    Socket.on('GetStatements', (data) => new NovoCliente(data, Socket).handleGetStatements());
    Socket.on('RequestAdvancement', (data) => new NovoCliente(data, Socket).handleRequestAdvancement());
    Socket.on('GetReceivables', (data) => new NovoCliente(data, Socket).handleGetReceivables());

    Socket.on('GetProducts', (data) => new NovoCliente(data, Socket).handleGetProducts());
    Socket.on('CreateProduct', (data) => new NovoCliente(data, Socket).handleCreateProduct());
    Socket.on('UpdateProduct', (data) => new NovoCliente(data, Socket).handleUpdateProduct());
    Socket.on('DeleteProduct', (data) => new NovoCliente(data, Socket).handleDeleteProduct());
    Socket.on('GetProductDetails', (data) => new NovoCliente(data, Socket).handleGetProductDetails());

    Socket.on('GetOrders', (data) => new NovoCliente(data, Socket).handleGetOrders());
    Socket.on('GetTransactions', (data) => new NovoCliente(data, Socket).handleGetTransactions());
    Socket.on('ProcessPayment', (data) => new NovoCliente(data, Socket).handleProcessPayment());

    Socket.on('GetProfile', (data) => new NovoCliente(data, Socket).handleGetProfile());
    Socket.on('UpdateProfile', (data) => new NovoCliente(data, Socket).handleUpdateProfile());
    Socket.on('UpdateSettings', (data) => new NovoCliente(data, Socket).handleUpdateSettings());

    Socket.on('GetAffiliates', (data) => new NovoCliente(data, Socket).handleGetAffiliates());
    Socket.on('AddAffiliate', (data) => new NovoCliente(data, Socket).handleAddAffiliate());
    Socket.on('RemoveAffiliate', (data) => new NovoCliente(data, Socket).handleRemoveAffiliate());

    Socket.on('GetOffers', (data) => new NovoCliente(data, Socket).handleGetOffers());
    Socket.on('CreateOffer', (data) => new NovoCliente(data, Socket).handleCreateOffer());
    Socket.on('UpdateOffer', (data) => new NovoCliente(data, Socket).handleUpdateOffer());
    Socket.on('DeleteOffer', (data) => new NovoCliente(data, Socket).handleDeleteOffer());
    Socket.on('ReorderOffers', (data) => new NovoCliente(data, Socket).handleReorderOffers());

    Socket.on('GetCheckoutSettings', (data) => new NovoCliente(data, Socket).handleGetCheckoutSettings());
    Socket.on('UpdateCheckoutSettings', (data) => new NovoCliente(data, Socket).handleUpdateCheckoutSettings());
    Socket.on('AddCustomField', (data) => new NovoCliente(data, Socket).handleAddCustomField());
    Socket.on('RemoveCustomField', (data) => new NovoCliente(data, Socket).handleRemoveCustomField());
    Socket.on('PreviewCheckout', (data) => new NovoCliente(data, Socket).handlePreviewCheckout());
    Socket.on('SaveCheckoutDesign', (data) => new NovoCliente(data, Socket).handleSaveCheckoutDesign());

    Socket.on('GetFunnels', (data) => new NovoCliente(data, Socket).handleGetFunnels());
    Socket.on('CreateFunnel', (data) => new NovoCliente(data, Socket).handleCreateFunnel());
    Socket.on('UpdateFunnel', (data) => new NovoCliente(data, Socket).handleUpdateFunnel());
    Socket.on('DeleteFunnel', (data) => new NovoCliente(data, Socket).handleDeleteFunnel());
    Socket.on('GetFunnelSteps', (data) => new NovoCliente(data, Socket).handleGetFunnelSteps());
    Socket.on('CreateFunnelStep', (data) => new NovoCliente(data, Socket).handleCreateFunnelStep());
    Socket.on('UpdateFunnelStep', (data) => new NovoCliente(data, Socket).handleUpdateFunnelStep());
    Socket.on('DeleteFunnelStep', (data) => new NovoCliente(data, Socket).handleDeleteFunnelStep());
    Socket.on('GetFunnelAnalytics', (data) => new NovoCliente(data, Socket).handleGetFunnelAnalytics());
    Socket.on('GenerateFunnelScripts', (data) => new NovoCliente(data, Socket).handleGenerateFunnelScripts());
    Socket.on('GetFunnelAnalyticsDetailed', (data) => new NovoCliente(data, Socket).handleGetFunnelAnalyticsDetailed());

    Socket.on('GetSales', (data) => new NovoCliente(data, Socket).handleGetSales());
    Socket.on('GetSalesStats', (data) => new NovoCliente(data, Socket).handleGetSalesStats());
    Socket.on('ExportSales', (data) => new NovoCliente(data, Socket).handleExportSales());
    Socket.on('GetSaleDetails', (data) => new NovoCliente(data, Socket).handleGetSaleDetails());
    Socket.on('UpdateSaleStatus', (data) => new NovoCliente(data, Socket).handleUpdateSaleStatus());
    Socket.on('GetSalesByPeriod', (data) => new NovoCliente(data, Socket).handleGetSalesByPeriod());
    Socket.on('GetTopProducts', (data) => new NovoCliente(data, Socket).handleGetTopProducts());
    Socket.on('GetSalesByPaymentMethod', (data) => new NovoCliente(data, Socket).handleGetSalesByPaymentMethod());
    Socket.on('GetUsersFilter', (data) => new NovoCliente(data, Socket).handleGetUsersFilter());

    Socket.on('GetUsers', (data) => new NovoCliente(data, Socket).handleGetUsers());
    Socket.on('GetUserPermissions', (data) => new NovoCliente(data, Socket).handleGetUserPermissions());
    Socket.on('UpdateUserPermissions', (data) => new NovoCliente(data, Socket).handleUpdateUserPermissions());
    Socket.on('ToggleUserStatus', (data) => new NovoCliente(data, Socket).handleToggleUserStatus());
    Socket.on('GetUserInfo', (data) => new NovoCliente(data, Socket).handleGetUserInfo());
    Socket.on('UpdateUserInfo', (data) => new NovoCliente(data, Socket).handleUpdateUserInfo());
    Socket.on('GetUserDocuments', (data) => new NovoCliente(data, Socket).handleGetUserDocuments());
    Socket.on('RequestNewDocuments', (data) => new NovoCliente(data, Socket).handleRequestNewDocuments());
    Socket.on('ImpersonateUser', (data) => new NovoCliente(data, Socket).handleImpersonateUser());
    Socket.on('EndImpersonation', (data) => new NovoCliente(data, Socket).handleEndImpersonation());

    Socket.on('CheckDocumentVerification', (data) => new NovoCliente(data, Socket).handleCheckDocumentVerification());
    Socket.on('UploadDocumentVerification', (data) => new NovoCliente(data, Socket).handleUploadDocumentVerification());
    Socket.on('SubmitDocumentsVerification', (data) => new NovoCliente(data, Socket).handleSubmitDocumentsVerification());
    Socket.on('GetDocumentsVerification', (data) => new NovoCliente(data, Socket).handleGetDocumentsVerification());
    Socket.on('GetUsersAdmin', (data) => new NovoCliente(data, Socket).handleGetUsersAdmin());
    Socket.on('AdminRequestDocuments', (data) => new NovoCliente(data, Socket).handleAdminRequestDocuments());
    Socket.on('AdminReviewDocument', (data) => new NovoCliente(data, Socket).handleAdminReviewDocument());
    Socket.on('GetDocumentContent', (data) => new NovoCliente(data, Socket).handleGetDocumentContent());
    Socket.on('DownloadDocument', (data) => new NovoCliente(data, Socket).handleDownloadDocument());

    Socket.on('GetPaymentProviders', (data) => new NovoCliente(data, Socket).handleGetPaymentProviders());
    Socket.on('SavePaymentProviders', (data) => new NovoCliente(data, Socket).handleSavePaymentProviders());
    Socket.on('ProcessPaymentMultiProvider', (data) => new NovoCliente(data, Socket).handleProcessPaymentMultiProvider());
    // No server.js, adicionar novos listeners:
    Socket.on('GetUserAssignedProviders', (data) => new NovoCliente(data, Socket).handleGetUserAssignedProviders());
    Socket.on('UpdateUserAssignedProviders', (data) => new NovoCliente(data, Socket).handleUpdateUserAssignedProviders());
    Socket.on('GetAvailableProviders', (data) => new NovoCliente(data, Socket).handleGetAvailableProviders());


    Socket.on('GetApiKeys', (data) => new NovoCliente(data, Socket).handleGetApiKeys());
    Socket.on('CreateApiKey', (data) => new NovoCliente(data, Socket).handleCreateApiKey());
    Socket.on('UpdateApiKey', (data) => new NovoCliente(data, Socket).handleUpdateApiKey());
    Socket.on('DeleteApiKey', (data) => new NovoCliente(data, Socket).handleDeleteApiKey());
    Socket.on('RegenerateSecretKey', (data) => new NovoCliente(data, Socket).handleRegenerateSecretKey());
    Socket.on('GetApiKeyStats', (data) => new NovoCliente(data, Socket).handleGetApiKeyStats());

    // Gateway Transactions
    Socket.on('GetGatewayTransactions', (data) => new NovoCliente(data, Socket).handleGetGatewayTransactions());
    Socket.on('GetGatewayTransactionDetails', (data) => new NovoCliente(data, Socket).handleGetGatewayTransactionDetails());
    Socket.on('GetGatewayDashboard', (data) => new NovoCliente(data, Socket).handleGetGatewayDashboard());



    // Desconexão
    Socket.on('disconnect', () => {
        conexoes = conexoes.filter((e) => e.Token !== Socket.id);
        console.log(`[SOCKETS] - [DESCONECTADO] = ${Socket.id} - [Socket Ativos] = ${conexoes.length}`);
    });
});



// Middleware que renova se necessário
const autoRenovarToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];


    if (!token) return next();

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const tempoRestante = decoded.exp - Date.now() / 1000;

        // Renova se resta menos de 20 minutos
        if (tempoRestante < 1200) {
            const novoToken = jwt.sign(
                { id: decoded.id, email: decoded.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            res.setHeader('x-new-token', novoToken);
        }

        req.usuario = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token inválido' });
    }
};



app.get('/api/admin/documents/:documentId', async (req, res) => {
    try {
        const { documentId } = req.params;
        const { token } = req.query;

        if (!token) {
            return res.status(401).json({ error: 'Token de autenticação obrigatório' });
        }

        // Verificar se o token é de um admin (implementar validação conforme seu sistema)
        // const user = await validateToken(token);
        // if (!user || user.role !== 'admin') {
        //   return res.status(403).json({ error: 'Acesso negado' });
        // }

        // Buscar documento no banco
        const documents = await db.query(
            'SELECT file_path, file_name, mime_type FROM user_documents WHERE id = ?',
            [documentId]
        );

        if (documents.length === 0) {
            return res.status(404).json({ error: 'Documento não encontrado' });
        }

        const document = documents[0];
        const filePath = path.join(process.cwd(), document.file_path);

        // Verificar se arquivo existe
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Arquivo não encontrado no servidor' });
        }

        // Configurar headers para exibição
        res.setHeader('Content-Type', document.mime_type);
        res.setHeader('Content-Disposition', `inline; filename="${document.file_name}"`);

        // Enviar arquivo
        res.sendFile(filePath);

    } catch (error) {
        console.error('Erro ao servir documento:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
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


app.use('/api/funnel/track', (req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// 2. ENDPOINT CORRIGIDO
app.post('/api/funnel/track', async (req, res) => {
    try {
        console.log('📊 Tracking recebido:', req.body); // Log para debug

        const {
            funnel_id,
            step_id,
            action_type,
            customer_email,
            amount,
            ip_address,
            user_agent,
            session_data
        } = req.body;

        // Validações básicas
        if (!funnel_id || !action_type) {
            return res.status(400).json({
                success: false,
                message: 'funnel_id e action_type são obrigatórios'
            });
        }

        // Obter IP do cliente (corrigido)
        const clientIp = ip_address ||
            req.headers['x-forwarded-for']?.split(',')[0] ||
            req.headers['x-real-ip'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            '127.0.0.1';

        console.log('💾 Salvando evento:', { funnel_id, step_id, action_type, clientIp });

        // Inserir no banco de dados
        await db.query(
            `INSERT INTO funnel_analytics 
             (funnel_id, step_id, customer_email, action_type, amount, ip_address, user_agent, session_data, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [
                funnel_id,
                step_id || null,
                customer_email || null,
                action_type,
                parseFloat(amount) || 0, // Garantir que seja número
                clientIp,
                user_agent || req.headers['user-agent'],
                JSON.stringify(session_data || {})
            ]
        );

        // Atualizar estatísticas da etapa - CORRIGIDO
        if (step_id) {
            if (action_type === 'view') {
                await db.query(
                    `UPDATE funnel_steps 
                     SET views = views + 1,
                         conversion_rate = CASE 
                             WHEN views + 1 > 0 THEN (conversions / (views + 1)) * 100
                             ELSE 0 
                         END
                     WHERE id = ?`,
                    [step_id]
                );
                console.log('👁️ View atualizada para step:', step_id);
            }

            if (action_type === 'click_yes') {
                await db.query(
                    `UPDATE funnel_steps 
                     SET conversions = conversions + 1, 
                         revenue = revenue + ?,
                         conversion_rate = CASE 
                             WHEN views > 0 THEN ((conversions + 1) / views) * 100
                             ELSE 0 
                         END
                     WHERE id = ?`,
                    [parseFloat(amount) || 0, step_id]
                );
                console.log('✅ Conversão registrada para step:', step_id, 'Valor:', amount);
            }
        }

        // Atualizar estatísticas gerais do funil
        await db.query(
            `UPDATE product_funnels 
             SET total_conversions = (
                 SELECT COALESCE(SUM(conversions), 0) 
                 FROM funnel_steps 
                 WHERE funnel_id = ?
             ),
             total_revenue = (
                 SELECT COALESCE(SUM(revenue), 0) 
                 FROM funnel_steps 
                 WHERE funnel_id = ?
             ),
             updated_at = NOW()
             WHERE id = ?`,
            [funnel_id, funnel_id, funnel_id]
        );

        console.log('🎯 Totais do funil atualizados:', funnel_id);

        res.json({
            success: true,
            message: 'Evento rastreado com sucesso',
            data: {
                action_type,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('❌ Erro ao rastrear evento:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.get('/api/funnel/:funnelId/live-stats', async (req, res) => {
    try {
        const { funnelId } = req.params;

        // Buscar estatísticas atualizadas do funil
        const funnelStats = await db.query(
            `SELECT 
                f.id,
                f.name,
                f.total_conversions,
                f.total_revenue,
                COUNT(fs.id) as total_steps
            FROM product_funnels f
            LEFT JOIN funnel_steps fs ON f.id = fs.funnel_id
            WHERE f.id = ?
            GROUP BY f.id, f.name, f.total_conversions, f.total_revenue`,
            [funnelId]
        );

        // Buscar estatísticas por etapa
        const stepStats = await db.query(
            `SELECT 
                id,
                name,
                step_type,
                step_order,
                views,
                conversions,
                conversion_rate,
                revenue
            FROM funnel_steps 
            WHERE funnel_id = ?
            ORDER BY step_order`,
            [funnelId]
        );

        // Buscar eventos recentes (última hora)
        const recentEvents = await db.query(
            `SELECT 
                action_type,
                step_id,
                amount,
                created_at
            FROM funnel_analytics 
            WHERE funnel_id = ? 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ORDER BY created_at DESC
            LIMIT 20`,
            [funnelId]
        );

        res.json({
            success: true,
            data: {
                funnel: funnelStats[0] || null,
                steps: stepStats,
                recent_events: recentEvents,
                last_updated: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Erro ao buscar stats:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao buscar estatísticas'
        });
    }
});

if (process.env.NODE_ENV === 'development') {
    app.post('/api/funnel/test-tracking', async (req, res) => {
        const { funnelId, stepId } = req.body;

        try {
            // Simular eventos de teste
            const testUrl = `${req.protocol}://${req.get('host')}/api/funnel/track`;

            // Evento de view
            await fetch(testUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    funnel_id: funnelId,
                    step_id: stepId,
                    action_type: 'view',
                    customer_email: 'teste@exemplo.com'
                })
            });

            // Evento de conversão
            await fetch(testUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    funnel_id: funnelId,
                    step_id: stepId,
                    action_type: 'click_yes',
                    customer_email: 'teste@exemplo.com',
                    amount: 199.90
                })
            });

            res.json({
                success: true,
                message: 'Eventos de teste enviados',
                test_url: testUrl
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Erro no teste',
                error: error.message
            });
        }
    });
}


app.post('/webhook/pagamentos/:provider', async (req, res) => {
    try {
        const { provider } = req.params;
        const webhookData = req.body;

        console.log(`Webhook recebido de ${provider}:`, webhookData);

        // Determinar handler baseado no provedor
        const handlerClass = {
            'zendry': 'ZendryHandler',
            'hawkpay': 'HawkpayHandler',
            'mercadopago': 'MercadoPagoHandler'
        }[provider];

        if (!handlerClass) {
            return res.status(400).json({ error: 'Provedor não suportado' });
        }

        // Processar webhook
        await new NovoCliente(
            { provider, webhook_data: webhookData },
            null
        ).handlePaymentWebhook();

        res.sendStatus(200);
    } catch (error) {
        console.error(`Erro no webhook ${provider}:`, error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Middleware de autenticação para rotas da Gateway API
app.use('/api/v1/transaction*', apiAuth.authenticateApiKey.bind(apiAuth));

// Rotas da Gateway API
app.post('/api/v1/transaction.createCardToken', async (req, res) => {
const handler = new GatewayTransactionHandler(req, res);
    await handler.purchaseCreditCard();
});

app.post('/api/v1/transaction.purchase', async (req, res) => {
    const handler = new GatewayTransactionHandler(req, res);
    await handler.purchase();
});

app.get('/api/v1/transaction.getPayment', async (req, res) => {
    const handler = new GatewayTransactionHandler(req, res);
    await handler.getPayment();
});

app.post('/webhook/zendry', async (req, res) => {
    try {
        const { notification_type, message, md5 } = req.body;

        if (notification_type !== 'pix_payment' || !message) {
            return res.status(400).json({ error: 'Tipo de notificação inválido' });
        }

        const {
            reference_code,
            idempotent_id,
            value_cents,
            status
        } = message;

        // Buscar transação pelo código único
        const transactions = await db.query(`
  SELECT * FROM gateway_transactions 
  WHERE transaction_id = ?
`, [idempotent_id]);

        if (!transactions || transactions.length === 0) {
            return res.status(404).json({ error: 'Transação não encontrada' });
        }

        const transaction = transactions[0];



        // Buscar chave secreta na system_payment_providers
        const [providers] = await db.query(`
            SELECT * FROM system_payment_providers 
            WHERE provider_id = ? AND is_active = 1
        `, [transaction.provider_id]);

        if (!providers || providers.length === 0) {
            return res.status(400).json({ error: 'Provedor não encontrado ou inativo' });
        }




        const credentials = JSON.parse(providers.credentials);
        const secretKey = credentials["Chave privada"];

        // Gerar hash MD5 esperado
        const hashString = `payment.${reference_code}.${idempotent_id}.${value_cents}.${secretKey}`;

        const expectedMd5 = crypto.createHash('md5').update(hashString).digest('hex');

        if (expectedMd5 !== md5) {
            return res.status(401).json({ error: 'MD5 inválido' });
        }

        // Atualizar transação no banco
        await db.query(`
            UPDATE gateway_transactions 
            SET status = ?, updated_at = NOW() 
            WHERE transaction_id = ?
        `, [status == 'completed' ? 'APPROVED' : 'PENDING', transaction.transaction_id]);


        // Atualizar status do pedido
        await db.query(
            `UPDATE orders SET 
                        payment_status = ?, 
                        order_status = ?,
                        paid_at = ?,
                        updated_at = NOW() 
                    WHERE gateway_transaction_id = ?`,
            [
                status === 'completed' ? 'paid' : 'pending',
                status ,
                status === 'completed' ? new Date() : null,
                transaction.transaction_id
            ]
        );

        // Atualizar transação correspondente
        await db.query(
            `UPDATE transactions SET 
                        status = ?, 
                        processed_at = ?,
                        updated_at = NOW() 
                    WHERE gateway_transaction_id = ?`,
            [
                status,
                new Date(),
                transaction.transaction_id
            ]
        );



        // Exemplo: lógica adicional (saldo, histórico, notificações, etc.)
        console.log(`✅ Pagamento confirmado para user_id: ${transaction.user_id}, valor: R$${value_cents / 100}`);

        return res.status(200).json({ success: true });
    } catch (err) {
        console.error('Erro no webhook:', err);
        return res.status(500).json({ error: 'Erro interno' });
    }
});

app.get('/api/v1/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'Gateway API',
        timestamp: new Date().toISOString(),
        version: process.env.GATEWAY_API_VERSION || '1.0.0'
    });
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

});

module.exports = { app, WebServer, io };