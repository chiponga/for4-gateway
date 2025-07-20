// src/handlers/NovoCliente.js
const Database = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { Criptografar, Descriptografar } = require('../utils/crypto');
const nodemailer = require('nodemailer');
const { ApiKeysHandler } = require('../gateway/ApiKeysHandler');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: false, // true para 465, false para outros ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

class NovoCliente {
    constructor(data, socket) {

        // Descriptografa e faz parse do JSON
        try {
            this.data = JSON.parse(Descriptografar(data));
        } catch (err) {
            console.error("❌ Erro ao descriptografar dados:", err);
            this.data = {};
        }
        this.socket = socket;
        this.db = new Database();
        this.usuarioLogado = null;
    }

    enviarResposta(evento, dados) {
        if (!this.socket) return;
        // Criptografa o objeto JSON antes de enviar
        const payload = Criptografar(JSON.stringify(dados));
        this.socket.emit(evento, payload);
    }

    async validarToken() {
        try {
            const { token } = this.data;
            if (!token) return null;

            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            const usuarios = await this.db.query(
                'SELECT * FROM users WHERE id = ?',
                [decoded.id]
            );


            if (usuarios.length === 0) return null;
            return usuarios[0];
        } catch (error) {
            console.error('Erro ao validar token:', error);
            return null;
        }
    }

    async handleLogin() {
        try {
            const { email, password } = this.data;

            if (!email || !password) {
                return this.enviarResposta('LoginResponse', {
                    success: false,
                    message: 'Email e senha são obrigatórios'
                });
            }

            // Buscar usuário no banco
            const usuarios = await this.db.query(
                'SELECT id, name, email, role, password, document_type FROM users WHERE email = ?',
                [email]
            );



            if (usuarios.length === 0) {
                return this.enviarResposta('LoginResponse', {
                    success: false,
                    message: 'Credenciais inválidas'
                });
            }

            const usuario = usuarios[0];

            // Verificar senha
            const senhaValida = await bcrypt.compare(password, usuario.password);
            if (!senhaValida) {
                return this.enviarResposta('LoginResponse', {
                    success: false,
                    message: 'Credenciais inválidas'
                });
            }

            // Gerar token JWT
            const token = jwt.sign(
                { id: usuario.id, email: usuario.email },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
            );




            this.enviarResposta('LoginResponse', {
                success: true,
                message: 'Login realizado com sucesso',
                token,
                user: {
                    id: usuario.id,
                    name: usuario.name,
                    email: usuario.email,
                    role: usuario.role,
                    document_type: usuario.document_type
                }
            });

        } catch (error) {
            console.error('Erro no login:', error);
            this.enviarResposta('LoginResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleRegistro() {
        try {
            const { email, companyName, cnpj, phone, password, confirmPassword } = this.data;

            // Validações básicas
            if (!email || !companyName || !cnpj || !phone || !password || !confirmPassword) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'Todos os campos são obrigatórios'
                });
            }

            // Validar se as senhas coincidem
            if (password !== confirmPassword) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'As senhas não coincidem'
                });
            }

            // Validar formato do email
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'Email inválido'
                });
            }

            // Validar CNPJ (formato básico)
            const cnpjClean = cnpj.replace(/\D/g, '');
            if (cnpjClean.length !== 14) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'CNPJ inválido'
                });
            }

            // Validar senha (mínimo 6 caracteres)
            if (password.length < 6) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'A senha deve ter pelo menos 6 caracteres'
                });
            }

            // Verificar se o email já existe
            const emailExistente = await this.db.query(
                'SELECT id FROM users WHERE email = ?',
                [email]
            );

            if (emailExistente.length > 0) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'Este email já está cadastrado'
                });
            }

            // Verificar se o CNPJ já existe
            const cnpjExistente = await this.db.query(
                'SELECT id FROM users WHERE cnpj = ?',
                [cnpj]
            );

            if (cnpjExistente.length > 0) {
                return this.enviarResposta('RegisterResponse', {
                    success: false,
                    message: 'Este CNPJ já está cadastrado'
                });
            }

            // Criptografar a senha
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Inserir usuário no banco
            const resultado = await this.db.query(
                `INSERT INTO users (
                name, 
                email, 
                password, 
                phone, 
                company_name, 
                cnpj, 
                document_type,
                terms_accepted, 
                terms_accepted_at,
                status,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    companyName, // usando company_name como name por enquanto
                    email,
                    hashedPassword,
                    phone,
                    companyName,
                    cnpj,
                    'pessoa_juridica',
                    true,
                    new Date(),
                    'pending' // ou 'active' se não precisar de verificação
                ]
            );

            const userId = resultado.insertId;

            // Gerar token JWT
            const token = jwt.sign(
                { id: userId, email: email },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
            );

            this.enviarResposta('RegisterResponse', {
                success: true,
                message: 'Conta criada com sucesso!',
                token,
                user: {
                    id: userId,
                    name: companyName,
                    email: email,
                    company_name: companyName,
                    cnpj: cnpj,
                    phone: phone
                }
            });

        } catch (error) {
            console.error('Erro no registro:', error);
            this.enviarResposta('RegisterResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleVerificarToken() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('VerificarTokenResponse', {
                    success: false,
                    message: 'Token inválido ou expirado'
                });
            }



            this.enviarResposta('VerificarTokenResponse', {
                success: true,
                user: {
                    id: usuario.id,
                    name: usuario.name,
                    email: usuario.email,
                    role: usuario.role,
                    document_type: usuario.document_type
                }
            });

        } catch (error) {
            console.error('Erro na verificação do token:', error);
            this.enviarResposta('VerificarTokenResponse', {
                success: false,
                message: 'Token inválido'
            });
        }
    }

    async handleDadosDashboard() {
        try {
            const usuario = await this.validarToken();



            if (!usuario) {

                return this.enviarResposta('DadosDashboardResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // 1. VENDAS HOJE
            const vendasHoje = await this.db.query(
                `SELECT 
                SUM(net_amount) as value, 
                COUNT(*) as count 
            FROM orders 
            WHERE user_id = ? 
            AND payment_status = 'paid'
            AND DATE(paid_at) = CURDATE()`,
                [usuario.id]
            );

            // 2. VENDAS ONTEM (para comparação)
            const vendasOntem = await this.db.query(
                `SELECT 
                SUM(net_amount) as value
            FROM orders 
            WHERE user_id = ? 
            AND payment_status = 'paid'
            AND DATE(paid_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)`,
                [usuario.id]
            );

            // 3. SALDO DISPONÍVEL
            const saldoDisponivel = await this.db.query(
                `SELECT 
                COALESCE(SUM(CASE 
                    WHEN category = 'income' AND status = 'completed' THEN amount
                    WHEN category = 'expense' AND status = 'completed' THEN -amount
                    ELSE 0 
                END), 0) as balance 
            FROM transactions 
            WHERE user_id = ?`,
                [usuario.id]
            );

            // 4. SALDO PENDENTE
            const saldoPendente = await this.db.query(
                `SELECT 
                COALESCE(SUM(CASE 
                    WHEN category = 'income' AND status = 'pending' THEN amount
                    WHEN category = 'expense' AND status = 'pending' THEN -amount
                    ELSE 0 
                END), 0) as balance 
            FROM transactions 
            WHERE user_id = ?`,
                [usuario.id]
            );

            // 5. META DE FATURAMENTO DO MÊS
            const metaFaturamento = await this.db.query(
                `SELECT 
                COALESCE(SUM(net_amount), 0) as current
            FROM orders 
            WHERE user_id = ? 
            AND payment_status = 'paid'
            AND MONTH(paid_at) = MONTH(CURRENT_DATE())
            AND YEAR(paid_at) = YEAR(CURRENT_DATE())`,
                [usuario.id]
            );

            // 6. MÉTODOS DE PAGAMENTO DO MÊS
            const metodosPagamento = await this.db.query(
                `SELECT 
                payment_method, 
                COALESCE(SUM(net_amount), 0) as value,
                COUNT(*) as count
            FROM orders 
            WHERE user_id = ? 
            AND payment_status = 'paid'
            AND MONTH(paid_at) = MONTH(CURRENT_DATE())
            AND YEAR(paid_at) = YEAR(CURRENT_DATE())
            GROUP BY payment_method`,
                [usuario.id]
            );

            // 7. ANALYTICS DE HOJE (visitantes, conversões, etc)
            const analyticsHoje = await this.db.query(
                `SELECT *
            FROM analytics_daily 
            WHERE user_id = ? 
            AND date = CURDATE()`,
                [usuario.id]
            );

            // 8. PRODUTOS ATIVOS
            const produtosAtivos = await this.db.query(
                `SELECT COUNT(*) as count
            FROM products 
            WHERE user_id = ? 
            AND status = 'active'`,
                [usuario.id]
            );

            // 9. PENDÊNCIAS (pedidos aguardando pagamento)
            const pendencias = await this.db.query(
                `SELECT COUNT(*) as count
            FROM orders 
            WHERE user_id = ? 
            AND payment_status = 'pending'`,
                [usuario.id]
            );

            // Calcular variação das vendas
            const vendasHojeValor = vendasHoje[0]?.value || 0;
            const vendasOntemValor = vendasOntem[0]?.value || 0;
            const variation = vendasOntemValor === 0 ? 0 :
                ((vendasHojeValor - vendasOntemValor) / vendasOntemValor) * 100;

            // Processar métodos de pagamento
            const paymentMethods = {
                pix: { percentage: 0, value: 0 },
                card: { percentage: 0, value: 0 },
                boleto: { percentage: 0, value: 0 },
                crypto: { percentage: 0, value: 0 }
            };

            const totalVendas = metodosPagamento.reduce((acc, method) => acc + (method.value || 0), 0);

            metodosPagamento.forEach(method => {
                let methodKey;
                switch (method.payment_method) {
                    case 'pix':
                        methodKey = 'pix';
                        break;
                    case 'credit_card':
                    case 'debit_card':
                        methodKey = 'card';
                        break;
                    case 'boleto':
                        methodKey = 'boleto';
                        break;
                    case 'crypto':
                        methodKey = 'crypto';
                        break;
                    default:
                        methodKey = 'card';
                }

                paymentMethods[methodKey].value += method.value || 0;
                paymentMethods[methodKey].percentage = totalVendas === 0 ? 0 :
                    Math.round((paymentMethods[methodKey].value / totalVendas) * 100);
            });

            // Meta de faturamento
            const metaAtual = metaFaturamento[0]?.current || 0;
            const metaAlvo = 10000; // Pode vir de configurações do usuário
            const percentualMeta = Math.min(Math.round((metaAtual / metaAlvo) * 100), 100);

            // Analytics
            const analytics = analyticsHoje[0] || {
                visitors: 0,
                conversion_rate: 0,
                orders_count: 0,
                average_order_value: 0
            };

            this.enviarResposta('DadosDashboardResponse', {
                success: true,
                data: {
                    // Vendas hoje
                    sales_today: {
                        value: vendasHojeValor,
                        variation: variation,
                        count: vendasHoje[0]?.count || 0
                    },

                    // Saldos
                    available_balance: saldoDisponivel[0]?.balance || 0,
                    pending_balance: saldoPendente[0]?.balance || 0,

                    // Meta de faturamento
                    billing_goal: {
                        current: metaAtual,
                        target: metaAlvo,
                        percentage: percentualMeta
                    },

                    // Métodos de pagamento
                    payment_methods: paymentMethods,

                    // Métricas adicionais
                    visitors_today: analytics.visitors || 0,
                    conversion_rate: analytics.conversion_rate || 0,
                    average_ticket: analytics.average_order_value || 0,
                    active_products: produtosAtivos[0]?.count || 0,
                    pending_count: pendencias[0]?.count || 0,

                    // Meta de timestamp para cache
                    last_updated: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Erro ao buscar dados do dashboard:', error);
            this.enviarResposta('DadosDashboardResponse', {
                success: false,
                message: 'Erro ao carregar dados do dashboard'
            });
        }
    }

    async handlePerformanceDashboard() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('PerformanceDashboardResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { period = '7d' } = this.data;
            const periodDays = period === '30d' ? 30 : period === '15d' ? 15 : period === '7d' ? 7 : 1;

            // Buscar dados de analytics por dia
            const analytics = await this.db.query(
                `SELECT 
                date,
                visitors,
                pageviews,
                conversions,
                conversion_rate,
                revenue,
                orders_count as sales_count,
                average_order_value,
                pix_amount,
                card_amount,
                boleto_amount,
                crypto_amount
            FROM analytics_daily 
            WHERE user_id = ? 
            AND date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
            ORDER BY date ASC`,
                [usuario.id, periodDays]
            );

            // Se não há dados de analytics, buscar dos pedidos
            if (analytics.length === 0) {
                const vendasPorDia = await this.db.query(
                    `SELECT 
                    DATE(paid_at) as date,
                    COALESCE(SUM(net_amount), 0) as revenue,
                    COUNT(*) as sales_count,
                    COALESCE(AVG(net_amount), 0) as average_order_value
                FROM orders 
                WHERE user_id = ? 
                AND payment_status = 'paid'
                AND paid_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                GROUP BY DATE(paid_at)
                ORDER BY date ASC`,
                    [usuario.id, periodDays]
                );

                // Converter para formato esperado
                const processedData = vendasPorDia.map(item => ({
                    date: item.date,
                    visitors: Math.floor(item.sales_count * 15 + Math.random() * 50), // Simular visitantes
                    revenue: parseFloat(item.revenue),
                    sales_count: parseInt(item.sales_count),
                    conversions: parseInt(item.sales_count),
                    average_order_value: parseFloat(item.average_order_value),
                    conversion_rate: 2.5 + (Math.random() * 2) // Simular taxa de conversão
                }));

                return this.enviarResposta('PerformanceDashboardResponse', {
                    success: true,
                    data: {
                        period,
                        analytics: processedData,
                        labels: processedData.map(item => item.date)
                    }
                });
            }

            // Processar dados reais de analytics
            const processedAnalytics = analytics.map(item => ({
                date: item.date,
                visitors: item.visitors || 0,
                pageviews: item.pageviews || 0,
                revenue: parseFloat(item.revenue) || 0,
                sales_count: item.sales_count || 0,
                conversions: item.conversions || 0,
                conversion_rate: parseFloat(item.conversion_rate) || 0,
                average_order_value: parseFloat(item.average_order_value) || 0
            }));

            this.enviarResposta('PerformanceDashboardResponse', {
                success: true,
                data: {
                    period,
                    analytics: processedAnalytics,
                    labels: processedAnalytics.map(item => item.date)
                }
            });

        } catch (error) {
            console.error('Erro ao buscar performance:', error);
            this.enviarResposta('PerformanceDashboardResponse', {
                success: false,
                message: 'Erro ao carregar dados de performance'
            });
        }
    }


    async handleStatementDashboard() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('StatementDashboardResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar transações recentes com mais detalhes
            const transacoes = await this.db.query(
                `SELECT transactions.*, orders.gateway_transaction_id, orders.customer_name, orders.product_id, products.name, orders.payment_method FROM transactions LEFT JOIN orders ON transactions.order_id = orders.id LEFT JOIN products ON orders.product_id = products.id WHERE transactions.user_id = ? ORDER BY transactions.created_at DESC LIMIT 15`,
                [usuario.id]
            );

            // Formatar os dados para o frontend
            const statements = transacoes.map(t => ({
                id: t.id,
                date: t.created_at,
                type: t.type,
                description: t.description ||
                    (t.type === 'sale' ? `Venda: ${t.product_name || 'Produto'}` :
                        t.type === 'withdrawal' ? 'Saque solicitado' :
                            t.type === 'commission' ? 'Comissão de afiliado' :
                                t.type === 'refund' ? 'Reembolso' :
                                    t.type === 'chargeback' ? 'Chargeback' :
                                        t.type),
                amount: parseFloat(t.amount),
                status: t.status,
                customer: t.customer_name,
                reference: t.gateway_transaction_id,
                payment_method: t.payment_method,
                category: t.category
            }));

            this.enviarResposta('StatementDashboardResponse', {
                success: true,
                data: {
                    statements,
                    summary: {
                        total_income: statements
                            .filter(s => s.category === 'income' && s.status === 'completed')
                            .reduce((sum, s) => sum + s.amount, 0),
                        total_expense: statements
                            .filter(s => s.category === 'expense' && s.status === 'completed')
                            .reduce((sum, s) => sum + s.amount, 0),
                        pending_amount: statements
                            .filter(s => s.status === 'pending')
                            .reduce((sum, s) => sum + s.amount, 0)
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar extrato:', error);
            this.enviarResposta('StatementDashboardResponse', {
                success: false,
                message: 'Erro ao carregar dados do extrato'
            });
        }
    }

    async handleGetNotifications() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetNotificationsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { limit = 10, unread_only = false } = this.data;

            let query = `
            SELECT * FROM notifications 
            WHERE user_id = ?
        `;
            const params = [usuario.id];

            if (unread_only) {
                query += ' AND read = FALSE';
            }

            query += ' ORDER BY created_at DESC LIMIT ?';
            params.push(parseInt(limit));

            const notifications = await this.db.query(query, params);

            // Contar não lidas
            const unreadCount = await this.db.query(
                'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND `read` = 0',
                [usuario.id]
            );

            this.enviarResposta('GetNotificationsResponse', {
                success: true,
                data: {
                    notifications: notifications.map(n => ({
                        ...n,
                        data: n.data ? JSON.parse(n.data) : null
                    })),
                    unread_count: unreadCount[0].count
                }
            });

        } catch (error) {
            console.error('Erro ao buscar notificações:', error);
            this.enviarResposta('GetNotificationsResponse', {
                success: false,
                message: 'Erro ao carregar notificações'
            });
        }
    }

    async handleMarkNotificationRead() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('MarkNotificationReadResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { notification_id } = this.data;

            if (!notification_id) {
                return this.enviarResposta('MarkNotificationReadResponse', {
                    success: false,
                    message: 'ID da notificação é obrigatório'
                });
            }

            await this.db.query(
                'UPDATE notifications SET `read` = 1, read_at = NOW() WHERE id = ? AND user_id = ?',
                [notification_id, usuario.id]
            );

            this.enviarResposta('MarkNotificationReadResponse', {
                success: true,
                message: 'Notificação marcada como lida'
            });

        } catch (error) {
            console.error('Erro ao marcar notificação:', error);
            this.enviarResposta('MarkNotificationReadResponse', {
                success: false,
                message: 'Erro ao marcar notificação'
            });
        }
    }

    async criarNotificacao(userId, type, title, message, data = null, priority = 'normal', orderId = null) {
        try {
            await this.db.query(
                `INSERT INTO notifications 
            (user_id, type, title, message, data, priority, order_id, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
                [
                    userId,
                    type,
                    title,
                    message,
                    data ? JSON.stringify(data) : null,
                    priority,
                    orderId
                ]
            );

            // Emitir evento Socket.IO para notificação em tempo real
            if (this.socket) {
                this.socket.to(`user_${userId}`).emit('new_notification', {
                    type,
                    title,
                    message,
                    data,
                    priority,
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            console.error('Erro ao criar notificação:', error);
        }
    }

    async atualizarAnalyticsDiarios(userId, data = {}) {
        try {
            const hoje = new Date().toISOString().split('T')[0];

            // Verificar se já existe registro para hoje
            const existing = await this.db.query(
                'SELECT id FROM analytics_daily WHERE user_id = ? AND date = ?',
                [userId, hoje]
            );

            if (existing.length > 0) {
                // Atualizar registro existente
                const updateFields = [];
                const updateValues = [];

                Object.keys(data).forEach(key => {
                    if (data[key] !== undefined) {
                        updateFields.push(`${key} = ${key} + ?`);
                        updateValues.push(data[key]);
                    }
                });

                if (updateFields.length > 0) {
                    updateValues.push(userId, hoje);
                    await this.db.query(
                        `UPDATE analytics_daily SET ${updateFields.join(', ')}, updated_at = NOW() 
                     WHERE user_id = ? AND date = ?`,
                        updateValues
                    );
                }
            } else {
                // Criar novo registro
                const fields = ['user_id', 'date'];
                const values = [userId, hoje];
                const placeholders = ['?', '?'];

                Object.keys(data).forEach(key => {
                    fields.push(key);
                    values.push(data[key]);
                    placeholders.push('?');
                });

                await this.db.query(
                    `INSERT INTO analytics_daily (${fields.join(', ')}) VALUES (${placeholders.join(', ')})`,
                    values
                );
            }

        } catch (error) {
            console.error('Erro ao atualizar analytics:', error);
        }
    }

    async handleGetBalance() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetBalanceResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar saldo disponível
            const saldoDisponivel = await this.db.query(
                `SELECT 
                    SUM(IF(category = 'income', amount, -amount)) as available 
                FROM transactions 
                WHERE user_id = ? 
                AND status = 'completed'`,
                [usuario.id]
            );

            // Buscar saldo pendente
            const saldoPendente = await this.db.query(
                `SELECT 
                    SUM(IF(category = 'income', amount, -amount)) as pending 
                FROM transactions 
                WHERE user_id = ? 
                AND status = 'pending'`,
                [usuario.id]
            );

            // Buscar valor total de vendas aprovadas
            const vendasAprovadas = await this.db.query(
                `SELECT 
                    SUM(amount) as total 
                FROM orders 
                WHERE user_id = ? 
                AND payment_status = 'paid'`,
                [usuario.id]
            );

            // Buscar valor total de comissões
            const comissoes = await this.db.query(
                `SELECT 
                    SUM(amount) as total 
                FROM transactions 
                WHERE user_id = ? 
                AND type = 'commission'
                AND status = 'completed'`,
                [usuario.id]
            );

            // Buscar valor total de reembolsos
            const reembolsos = await this.db.query(
                `SELECT 
                    SUM(amount) as total 
                FROM transactions 
                WHERE user_id = ? 
                AND type = 'refund'
                AND status = 'completed'`,
                [usuario.id]
            );

            // Buscar valor pendente de aprovação
            const pendentesAprovacao = await this.db.query(
                `SELECT 
                    SUM(amount) as total 
                FROM orders 
                WHERE user_id = ? 
                AND payment_status = 'pending'`,
                [usuario.id]
            );

            // Buscar último saque
            const ultimoSaque = await this.db.query(
                `SELECT 
                    created_at as date,
                    amount
                FROM withdrawals 
                WHERE user_id = ? 
                ORDER BY created_at DESC
                LIMIT 1`,
                [usuario.id]
            );

            const available = saldoDisponivel[0].available || 0;
            const pending = saldoPendente[0].pending || 0;

            this.enviarResposta('GetBalanceResponse', {
                success: true,
                data: {
                    available,
                    pending,
                    total: available + pending,
                    approved_sales: vendasAprovadas[0].total || 0,
                    commissions: comissoes[0].total || 0,
                    refunds: reembolsos[0].total || 0,
                    pending_approval: pendentesAprovacao[0].total || 0,
                    processing: pending,
                    growth_percentage: 12.5, // Poderia ser calculado baseado em períodos anteriores
                    last_withdrawal: ultimoSaque.length > 0 ? {
                        date: ultimoSaque[0].date,
                        amount: ultimoSaque[0].amount
                    } : null
                }
            });

        } catch (error) {
            console.error('Erro ao buscar saldo:', error);
            this.enviarResposta('GetBalanceResponse', {
                success: false,
                message: 'Erro ao carregar dados de saldo'
            });
        }
    }

    async handleGetWithdrawals() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetWithdrawalsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar saques
            const saques = await this.db.query(
                `SELECT 
   withdrawals.*,
   bank_accounts.bank_name,
   bank_accounts.agency,
   bank_accounts.account,
   bank_accounts.account_type,
   bank_accounts.holder_name
FROM withdrawals
LEFT JOIN bank_accounts ON withdrawals.bank_account_id = bank_accounts.id
WHERE withdrawals.user_id = ? 
ORDER BY withdrawals.created_at DESC
LIMIT 20`,
                [usuario.id]
            );

            // Formatar os dados
            const withdrawals = saques.map(s => ({
                id: s.id,
                amount: s.amount,
                fee_amount: s.fee_amount,
                net_amount: s.net_amount,
                status: s.status,
                created_at: s.created_at,
                processed_at: s.processed_at,
                completed_at: s.completed_at,
                bank_account: `${s.bank_name} - Ag: ${s.agency} - Conta: ${s.account.substr(0, 3)}***${s.account.substr(-3)}`,
                holder_name: s.holder_name
            }));

            this.enviarResposta('GetWithdrawalsResponse', {
                success: true,
                data: withdrawals
            });

        } catch (error) {
            console.error('Erro ao buscar saques:', error);
            this.enviarResposta('GetWithdrawalsResponse', {
                success: false,
                message: 'Erro ao carregar dados de saques'
            });
        }
    }

    async handleRequestWithdrawal() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('RequestWithdrawalResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { amount, bank_account_id } = this.data;

            if (!amount || !bank_account_id) {
                return this.enviarResposta('RequestWithdrawalResponse', {
                    success: false,
                    message: 'Valor e conta bancária são obrigatórios'
                });
            }

            // Verificar se a conta bancária pertence ao usuário
            const contasBancarias = await this.db.query(
                'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
                [bank_account_id, usuario.id]
            );

            if (contasBancarias.length === 0) {
                return this.enviarResposta('RequestWithdrawalResponse', {
                    success: false,
                    message: 'Conta bancária não encontrada'
                });
            }

            // Verificar se o usuário tem saldo suficiente
            const saldoDisponivel = await this.db.query(
                `SELECT 
                    SUM(IF(category = 'income', amount, -amount)) as available 
                FROM transactions 
                WHERE user_id = ? 
                AND status = 'completed'`,
                [usuario.id]
            );

            if ((saldoDisponivel[0].available || 0) < amount) {
                return this.enviarResposta('RequestWithdrawalResponse', {
                    success: false,
                    message: 'Saldo insuficiente'
                });
            }

            // Calcular taxa (exemplo: 2%)
            const feeAmount = amount * 0.02;
            const netAmount = amount - feeAmount;

            // Inserir solicitação de saque
            const resultado = await this.db.query(
                `INSERT INTO withdrawals 
                (user_id, bank_account_id, amount, fee_amount, net_amount, currency, status, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, 'BRL', 'pending', NOW(), NOW())`,
                [usuario.id, bank_account_id, amount, feeAmount, netAmount]
            );

            // Criar transação para o saque
            await this.db.query(
                `INSERT INTO transactions 
                (user_id, type, category, amount, currency, status, description, created_at, updated_at) 
                VALUES (?, 'withdrawal', 'expense', ?, 'BRL', 'pending', 'Solicitação de saque', NOW(), NOW())`,
                [usuario.id, amount]
            );

            this.enviarResposta('RequestWithdrawalResponse', {
                success: true,
                message: 'Solicitação de saque realizada com sucesso',
                data: {
                    id: resultado.insertId,
                    amount,
                    fee_amount: feeAmount,
                    net_amount: netAmount,
                    status: 'pending'
                }
            });

        } catch (error) {
            console.error('Erro ao solicitar saque:', error);
            this.enviarResposta('RequestWithdrawalResponse', {
                success: false,
                message: 'Erro ao processar solicitação de saque'
            });
        }
    }

    async handleGetBankAccounts() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetBankAccountsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }



            // Buscar contas bancárias
            const contas = await this.db.query(
                `SELECT 
                    id,
                    bank_name,
                    bank_code,
                    agency,
                    account,
                    account_type,
                    holder_name,
                    holder_document,
                    pix_key,
                    pix_type,
                    is_main,
                    status,
                    created_at,
                    updated_at
                FROM bank_accounts 
                WHERE user_id = ? 
                ORDER BY is_main DESC, created_at DESC`,
                [usuario.id]
            );

            // Formatar os dados (mascarar informações sensíveis)
            const bankAccounts = contas.map(conta => ({
                id: conta.id,
                bank_name: conta.bank_name,
                bank_code: conta.bank_code,
                agency: conta.agency,
                account_number: conta.account,
                account_display: `${conta.account.substr(0, 3)}***${conta.account.substr(-3)}`, // Máscara
                account_type: conta.account_type,
                holder_name: conta.holder_name,
                holder_document: conta.holder_document,
                pix_key: conta.pix_key,
                pix_type: conta.pix_type,
                is_main: conta.is_main,
                status: conta.status,
                created_at: conta.created_at,
                updated_at: conta.updated_at
            }));

            this.enviarResposta('GetBankAccountsResponse', {
                success: true,
                data: bankAccounts
            });

        } catch (error) {
            console.error('Erro ao buscar contas bancárias:', error);
            this.enviarResposta('GetBankAccountsResponse', {
                success: false,
                message: 'Erro ao carregar contas bancárias'
            });
        }
    }

    async handleCreateBankAccount() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CreateBankAccountResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const {
                bank_name,
                bank_code,
                agency,
                account,
                account_type,
                holder_name,
                holder_document,
                pix_key,
                pix_type,
                is_main
            } = this.data;

            // Validações básicas
            if (!bank_name || !agency || !account || !holder_name || !holder_document) {
                return this.enviarResposta('CreateBankAccountResponse', {
                    success: false,
                    message: 'Dados obrigatórios não preenchidos'
                });
            }

            // Verificar se já existe conta com os mesmos dados
            const contaExistente = await this.db.query(
                'SELECT id FROM bank_accounts WHERE user_id = ? AND bank_code = ? AND agency = ? AND account = ?',
                [usuario.id, bank_code, agency, account]
            );

            if (contaExistente.length > 0) {
                return this.enviarResposta('CreateBankAccountResponse', {
                    success: false,
                    message: 'Conta bancária já cadastrada'
                });
            }

            // Se é conta principal, remover flag das outras
            if (is_main) {
                await this.db.query(
                    'UPDATE bank_accounts SET is_main = 0 WHERE user_id = ?',
                    [usuario.id]
                );
            }

            // Inserir nova conta
            const resultado = await this.db.query(
                `INSERT INTO bank_accounts 
                (user_id, bank_name, bank_code, agency, account, account_type, holder_name, holder_document, pix_key, pix_type, is_main, status, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_verification', NOW(), NOW())`,
                [usuario.id, bank_name, bank_code, agency, account, account_type || 'checking', holder_name, holder_document, pix_key, pix_type, is_main ? 1 : 0]
            );

            this.enviarResposta('CreateBankAccountResponse', {
                success: true,
                message: 'Conta bancária criada com sucesso',
                data: {
                    id: resultado.insertId,
                    bank_name,
                    agency,
                    account: `${account.substr(0, 3)}***${account.substr(-3)}`,
                    status: 'pending_verification'
                }
            });

        } catch (error) {
            console.error('Erro ao criar conta bancária:', error);
            this.enviarResposta('CreateBankAccountResponse', {
                success: false,
                message: 'Erro ao criar conta bancária'
            });
        }
    }

    async handleUpdateBankAccount() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateBankAccountResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const {
                id,
                bank_name,
                bank_code,
                agency,
                account,
                account_type,
                holder_name,
                holder_document,
                pix_key,
                pix_type,
                is_main
            } = this.data;

            if (!id) {
                return this.enviarResposta('UpdateBankAccountResponse', {
                    success: false,
                    message: 'ID da conta é obrigatório'
                });
            }

            // Verificar se a conta pertence ao usuário
            const contaExistente = await this.db.query(
                'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
                [id, usuario.id]
            );

            if (contaExistente.length === 0) {
                return this.enviarResposta('UpdateBankAccountResponse', {
                    success: false,
                    message: 'Conta bancária não encontrada'
                });
            }

            // Se é conta principal, remover flag das outras
            if (is_main) {
                await this.db.query(
                    'UPDATE bank_accounts SET is_main = 0 WHERE user_id = ? AND id != ?',
                    [usuario.id, id]
                );
            }

            // Atualizar conta
            await this.db.query(
                `UPDATE bank_accounts SET 
                    bank_name = ?, 
                    bank_code = ?, 
                    agency = ?, 
                    account = ?, 
                    account_type = ?, 
                    holder_name = ?, 
                    holder_document = ?,
                    pix_key = ?,
                    pix_type = ?,
                    is_main = ?,
                    status = 'pending_verification',
                    updated_at = NOW()
                WHERE id = ? AND user_id = ?`,
                [bank_name, bank_code, agency, account, account_type, holder_name, holder_document, pix_key, pix_type, is_main ? 1 : 0, id, usuario.id]
            );

            this.enviarResposta('UpdateBankAccountResponse', {
                success: true,
                message: 'Conta bancária atualizada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar conta bancária:', error);
            this.enviarResposta('UpdateBankAccountResponse', {
                success: false,
                message: 'Erro ao atualizar conta bancária'
            });
        }
    }

    async handleDeleteBankAccount() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('DeleteBankAccountResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { id } = this.data;

            if (!id) {
                return this.enviarResposta('DeleteBankAccountResponse', {
                    success: false,
                    message: 'ID da conta é obrigatório'
                });
            }

            // Verificar se a conta pertence ao usuário
            const contaExistente = await this.db.query(
                'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
                [id, usuario.id]
            );

            if (contaExistente.length === 0) {
                return this.enviarResposta('DeleteBankAccountResponse', {
                    success: false,
                    message: 'Conta bancária não encontrada'
                });
            }

            // Verificar se há saques pendentes para esta conta
            const saquesPendentes = await this.db.query(
                'SELECT COUNT(*) as count FROM withdrawals WHERE bank_account_id = ? AND status IN ("pending", "processing")',
                [id]
            );

            if (saquesPendentes[0].count > 0) {
                return this.enviarResposta('DeleteBankAccountResponse', {
                    success: false,
                    message: 'Não é possível excluir conta com saques pendentes'
                });
            }

            // Deletar conta
            await this.db.query(
                'DELETE FROM bank_accounts WHERE id = ? AND user_id = ?',
                [id, usuario.id]
            );

            this.enviarResposta('DeleteBankAccountResponse', {
                success: true,
                message: 'Conta bancária removida com sucesso'
            });

        } catch (error) {
            console.error('Erro ao deletar conta bancária:', error);
            this.enviarResposta('DeleteBankAccountResponse', {
                success: false,
                message: 'Erro ao deletar conta bancária'
            });
        }
    }

    async handleGetStatements() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetStatementsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const {
                type = '',
                status = '',
                start_date = '',
                end_date = '',
                search = '',
                page = 1,
                limit = 10
            } = this.data;



            const whereConditions = ['transactions.user_id = ?'];
            const params = [usuario.id];

            const addCondition = (condition, value, multiple = false) => {
                if (value && value.trim() !== '') {
                    whereConditions.push(condition);
                    if (multiple) {
                        params.push(...value);
                    } else {
                        params.push(value);
                    }
                }
            };

            // Adicionar condições apenas se os valores existirem
            addCondition('transactions.type = ?', type);
            addCondition('transactions.status = ?', status);
            addCondition('DATE(transactions.created_at) >= ?', start_date);
            addCondition('DATE(transactions.created_at) <= ?', end_date);

            if (search && search.trim() !== '') {
                addCondition('(' +
                    'transactions.description LIKE ? ' +
                    'OR transactions.reference_id LIKE ? ' +
                    'OR transactions.gateway_provider LIKE ? ' +
                    'OR IFNULL(orders.customer_name, "") LIKE ? ' +
                    'OR IFNULL(orders.customer_email, "") LIKE ?' +
                    ')', [
                    `%${search}%`,
                    `%${search}%`,
                    `%${search}%`,
                    `%${search}%`,
                    `%${search}%`
                ], true);
            }

            const whereClause = whereConditions.join(' AND ');
            const offset = (parseInt(page) - 1) * parseInt(limit);



            // Consulta principal com LEFT JOIN para orders e products
            const statements = await this.db.query(
                `SELECT 
        transactions.id,
        transactions.user_id,
        transactions.order_id,
        transactions.type,
        transactions.category,
        transactions.amount,
        transactions.currency,
        transactions.status,
        transactions.description,
        transactions.gateway_transaction_id,
        transactions.gateway_provider,
        transactions.reference_id,
        transactions.metadata,
        transactions.processed_at,
        transactions.created_at,
        transactions.updated_at,
        orders.customer_name,
        orders.customer_email,
        orders.payment_method,
        orders.gateway_transaction_id AS order_transaction_id,
        products.name AS product_name
      FROM transactions
      LEFT JOIN orders ON transactions.order_id = orders.id
      LEFT JOIN products ON orders.product_id = products.id
      WHERE ${whereClause}
      ORDER BY transactions.created_at DESC
      LIMIT ? OFFSET ?`,
                [...params, parseInt(limit), parseInt(offset)]
            );



            // Consulta para total de registros
            const totalResult = await this.db.query(
                `SELECT COUNT(*) as total
       FROM transactions
       LEFT JOIN orders ON transactions.order_id = orders.id
       LEFT JOIN products ON orders.product_id = products.id
       WHERE ${whereClause}`,
                params
            );

            const total = totalResult[0]?.total || 0;
            const totalPages = Math.ceil(total / parseInt(limit));



            // Formatar dados para o frontend
            const formattedStatements = statements.map(stmt => {
                try {
                    return {
                        id: stmt.id,
                        user_id: stmt.user_id,
                        order_id: stmt.order_id,
                        type: stmt.type,
                        category: stmt.category,
                        amount: parseFloat(stmt.amount) || 0,
                        currency: stmt.currency || 'BRL',
                        status: stmt.status,
                        description: stmt.description || '',
                        customer: stmt.customer_name || '',
                        customer_email: stmt.customer_email || '',
                        method: stmt.payment_method || '',
                        product_name: stmt.product_name || '',
                        transaction_id: stmt.gateway_transaction_id || stmt.order_transaction_id || stmt.reference_id || '',
                        gateway_provider: stmt.gateway_provider || '',
                        reference_id: stmt.reference_id || '',
                        metadata: stmt.metadata ? JSON.parse(stmt.metadata) : null,
                        created_at: stmt.created_at,
                        processed_at: stmt.processed_at,
                        updated_at: stmt.updated_at
                    };
                } catch (error) {
                    console.error('Erro ao formatar statement:', error, stmt);
                    return {
                        id: stmt.id,
                        user_id: stmt.user_id,
                        order_id: stmt.order_id,
                        type: stmt.type || 'unknown',
                        category: stmt.category || 'unknown',
                        amount: parseFloat(stmt.amount) || 0,
                        currency: stmt.currency || 'BRL',
                        status: stmt.status || 'unknown',
                        description: stmt.description || 'Sem descrição',
                        customer: stmt.customer_name || '',
                        customer_email: stmt.customer_email || '',
                        method: stmt.payment_method || '',
                        product_name: stmt.product_name || '',
                        transaction_id: stmt.gateway_transaction_id || stmt.order_transaction_id || stmt.reference_id || '',
                        gateway_provider: stmt.gateway_provider || '',
                        reference_id: stmt.reference_id || '',
                        metadata: null,
                        created_at: stmt.created_at,
                        processed_at: stmt.processed_at,
                        updated_at: stmt.updated_at
                    };
                }
            });

            const responseData = {
                success: true,
                data: {
                    statements: formattedStatements,
                    total: parseInt(total),
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: parseInt(totalPages)
                }
            };



            this.enviarResposta('GetStatementsResponse', responseData);

        } catch (error) {
            console.error('Erro detalhado ao buscar extratos:', error);
            console.error('Stack trace:', error.stack);

            this.enviarResposta('GetStatementsResponse', {
                success: false,
                message: 'Erro interno do servidor ao carregar extratos',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    validateStatementsParams(data) {
        const validated = {
            type: data.type && typeof data.type === 'string' ? data.type.trim() : '',
            status: data.status && typeof data.status === 'string' ? data.status.trim() : '',
            start_date: data.start_date && typeof data.start_date === 'string' ? data.start_date.trim() : '',
            end_date: data.end_date && typeof data.end_date === 'string' ? data.end_date.trim() : '',
            search: data.search && typeof data.search === 'string' ? data.search.trim() : '',
            page: Math.max(1, parseInt(data.page) || 1),
            limit: Math.min(100, Math.max(1, parseInt(data.limit) || 10))
        };

        // Validar datas
        if (validated.start_date && !this.isValidDate(validated.start_date)) {
            validated.start_date = '';
        }
        if (validated.end_date && !this.isValidDate(validated.end_date)) {
            validated.end_date = '';
        }

        // Validar tipos permitidos
        const allowedTypes = ['sale', 'withdrawal', 'refund', 'commission', 'chargeback', 'transfer'];
        if (validated.type && !allowedTypes.includes(validated.type)) {
            validated.type = '';
        }

        // Validar status permitidos
        const allowedStatuses = ['completed', 'pending', 'processing', 'failed', 'cancelled'];
        if (validated.status && !allowedStatuses.includes(validated.status)) {
            validated.status = '';
        }

        return validated;
    }

    isValidDate(dateString) {
        const regex = /^\d{4}-\d{2}-\d{2}$/;
        if (!regex.test(dateString)) return false;

        const date = new Date(dateString);
        return date instanceof Date && !isNaN(date);
    }


    async handleGetStatementsOptimized() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetStatementsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Validar e sanitizar parâmetros
            const params = this.validateStatementsParams(this.data);



            // Construir query dinâmica
            const queryBuilder = this.buildStatementsQuery(usuario.id, params);

            // Executar consultas em paralelo
            const [statements, totalResult] = await Promise.all([
                this.db.query(queryBuilder.selectQuery, queryBuilder.selectParams),
                this.db.query(queryBuilder.countQuery, queryBuilder.countParams)
            ]);

            const total = totalResult[0]?.total || 0;
            const totalPages = Math.ceil(total / params.limit);

            const formattedStatements = statements.map(stmt => this.formatStatement(stmt));

            this.enviarResposta('GetStatementsResponse', {
                success: true,
                data: {
                    statements: formattedStatements,
                    total,
                    page: params.page,
                    limit: params.limit,
                    totalPages
                }
            });

        } catch (error) {
            console.error('Erro ao buscar extratos:', error);
            this.enviarResposta('GetStatementsResponse', {
                success: false,
                message: 'Erro ao carregar extratos'
            });
        }
    }


    buildStatementsQuery(userId, params) {
        const baseFields = `
    transactions.id,
    transactions.user_id,
    transactions.order_id,
    transactions.type,
    transactions.category,
    transactions.amount,
    transactions.currency,
    transactions.status,
    transactions.description,
    transactions.gateway_transaction_id,
    transactions.gateway_provider,
    transactions.reference_id,
    transactions.metadata,
    transactions.processed_at,
    transactions.created_at,
    transactions.updated_at,
    orders.customer_name,
    orders.customer_email,
    orders.payment_method,
    orders.gateway_transaction_id AS order_transaction_id,
    products.name AS product_name
  `;

        const baseJoins = `
    FROM transactions
    LEFT JOIN orders ON transactions.order_id = orders.id
    LEFT JOIN products ON orders.product_id = products.id
  `;

        const whereConditions = ['transactions.user_id = ?'];
        const queryParams = [userId];

        // Adicionar condições dinamicamente
        if (params.type) {
            whereConditions.push('transactions.type = ?');
            queryParams.push(params.type);
        }

        if (params.status) {
            whereConditions.push('transactions.status = ?');
            queryParams.push(params.status);
        }

        if (params.start_date) {
            whereConditions.push('DATE(transactions.created_at) >= ?');
            queryParams.push(params.start_date);
        }

        if (params.end_date) {
            whereConditions.push('DATE(transactions.created_at) <= ?');
            queryParams.push(params.end_date);
        }

        if (params.search) {
            whereConditions.push(`(
      transactions.description LIKE ? OR
      transactions.reference_id LIKE ? OR
      transactions.gateway_provider LIKE ? OR
      IFNULL(orders.customer_name, '') LIKE ? OR
      IFNULL(orders.customer_email, '') LIKE ?
    )`);
            const searchTerm = `%${params.search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (params.page - 1) * params.limit;

        return {
            selectQuery: `
      SELECT ${baseFields}
      ${baseJoins}
      WHERE ${whereClause}
      ORDER BY transactions.created_at DESC
      LIMIT ? OFFSET ?
    `,
            selectParams: [...queryParams, params.limit, offset],
            countQuery: `
      SELECT COUNT(*) as total
      ${baseJoins}
      WHERE ${whereClause}
    `,
            countParams: queryParams
        };
    }

    formatStatement(stmt) {
        try {
            return {
                id: stmt.id,
                user_id: stmt.user_id,
                order_id: stmt.order_id,
                type: stmt.type,
                category: stmt.category,
                amount: parseFloat(stmt.amount) || 0,
                currency: stmt.currency || 'BRL',
                status: stmt.status,
                description: stmt.description || '',
                customer: stmt.customer_name || '',
                customer_email: stmt.customer_email || '',
                method: stmt.payment_method || '',
                product_name: stmt.product_name || '',
                transaction_id: stmt.gateway_transaction_id || stmt.order_transaction_id || stmt.reference_id || '',
                gateway_provider: stmt.gateway_provider || '',
                reference_id: stmt.reference_id || '',
                metadata: stmt.metadata ? this.safeJsonParse(stmt.metadata) : null,
                created_at: stmt.created_at,
                processed_at: stmt.processed_at,
                updated_at: stmt.updated_at
            };
        } catch (error) {
            console.error('Erro ao formatar statement:', error);
            return this.getDefaultStatement(stmt);
        }
    }

    getDefaultStatement(stmt) {
        return {
            id: stmt.id || 0,
            user_id: stmt.user_id || 0,
            order_id: stmt.order_id || null,
            type: stmt.type || 'unknown',
            category: stmt.category || 'unknown',
            amount: 0,
            currency: 'BRL',
            status: stmt.status || 'unknown',
            description: 'Erro ao carregar dados',
            customer: '',
            customer_email: '',
            method: '',
            product_name: '',
            transaction_id: '',
            gateway_provider: '',
            reference_id: '',
            metadata: null,
            created_at: stmt.created_at || new Date().toISOString(),
            processed_at: stmt.processed_at || null,
            updated_at: stmt.updated_at || new Date().toISOString()
        };
    }


    safeJsonParse(jsonString) {
        try {
            return JSON.parse(jsonString);
        } catch (error) {
            console.warn('Erro ao fazer parse do JSON:', error);
            return null;
        }
    }

    async handleRequestAdvancement() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('RequestAdvancementResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { amount, bank_account_id } = this.data;

            if (!amount || !bank_account_id) {
                return this.enviarResposta('RequestAdvancementResponse', {
                    success: false,
                    message: 'Valor e conta bancária são obrigatórios'
                });
            }

            // Verificar se a conta bancária pertence ao usuário
            const contasBancarias = await this.db.query(
                'SELECT * FROM bank_accounts WHERE id = ? AND user_id = ?',
                [bank_account_id, usuario.id]
            );

            if (contasBancarias.length === 0) {
                return this.enviarResposta('RequestAdvancementResponse', {
                    success: false,
                    message: 'Conta bancária não encontrada'
                });
            }

            // Verificar se o usuário tem saldo pendente suficiente
            const saldoPendente = await this.db.query(
                `SELECT 
                    SUM(IF(category = 'income', amount, -amount)) as pending 
                FROM transactions 
                WHERE user_id = ? 
                AND status = 'pending'`,
                [usuario.id]
            );

            if ((saldoPendente[0].pending || 0) < amount) {
                return this.enviarResposta('RequestAdvancementResponse', {
                    success: false,
                    message: 'Saldo pendente insuficiente'
                });
            }

            // Calcular taxa de antecipação (exemplo: 3.5%)
            const feeAmount = amount * 0.035;
            const netAmount = amount - feeAmount;

            // Inserir solicitação de antecipação (como um saque especial)
            const resultado = await this.db.query(
                `INSERT INTO withdrawals 
                (user_id, bank_account_id, amount, fee_amount, net_amount, currency, status, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, 'BRL', 'pending', NOW(), NOW())`,
                [usuario.id, bank_account_id, amount, feeAmount, netAmount]
            );

            // Criar transação para a antecipação
            await this.db.query(
                `INSERT INTO transactions 
                (user_id, type, category, amount, currency, status, description, created_at, updated_at) 
                VALUES (?, 'withdrawal', 'expense', ?, 'BRL', 'pending', 'Antecipação de recebíveis', NOW(), NOW())`,
                [usuario.id, amount]
            );

            this.enviarResposta('RequestAdvancementResponse', {
                success: true,
                message: 'Solicitação de antecipação realizada com sucesso',
                data: {
                    id: resultado.insertId,
                    amount,
                    fee_amount: feeAmount,
                    net_amount: netAmount,
                    status: 'pending',
                    type: 'advancement'
                }
            });

        } catch (error) {
            console.error('Erro ao solicitar antecipação:', error);
            this.enviarResposta('RequestAdvancementResponse', {
                success: false,
                message: 'Erro ao processar solicitação de antecipação'
            });
        }
    }

    async handleGetReceivables() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetReceivablesResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Query CORRIGIDA - movendo DAY para fora do CASE
            const receivables = await this.db.query(
                `SELECT 
                DATE_ADD(transactions.created_at, INTERVAL 
                    CASE 
                        WHEN orders.payment_method = 'pix' THEN 1
                        WHEN orders.payment_method = 'credit_card' THEN 30
                        WHEN orders.payment_method = 'debit_card' THEN 1
                        WHEN orders.payment_method = 'boleto' THEN 2
                        ELSE 1
                    END DAY
                ) as release_date,
                SUM(transactions.amount) as total_amount,
                COUNT(*) as transaction_count,
                orders.payment_method
            FROM transactions
            LEFT JOIN orders ON transactions.order_id = orders.id
            WHERE transactions.user_id = ?
            AND transactions.status = 'pending'
            AND transactions.category = 'income'
            GROUP BY 
                DATE(DATE_ADD(transactions.created_at, INTERVAL 
                    CASE 
                        WHEN orders.payment_method = 'pix' THEN 1
                        WHEN orders.payment_method = 'credit_card' THEN 30
                        WHEN orders.payment_method = 'debit_card' THEN 1
                        WHEN orders.payment_method = 'boleto' THEN 2
                        ELSE 1
                    END DAY
                )), 
                orders.payment_method
            ORDER BY 
                DATE_ADD(transactions.created_at, INTERVAL 
                    CASE 
                        WHEN orders.payment_method = 'pix' THEN 1
                        WHEN orders.payment_method = 'credit_card' THEN 30
                        WHEN orders.payment_method = 'debit_card' THEN 1
                        WHEN orders.payment_method = 'boleto' THEN 2
                        ELSE 1
                    END DAY
                ) ASC
            LIMIT 30`,
                [usuario.id]
            );

            // Calcular resumo
            const totalPendente = await this.db.query(
                `SELECT 
                SUM(amount) as total,
                COUNT(*) as count
            FROM transactions 
            WHERE user_id = ? 
            AND status = 'pending'
            AND category = 'income'`,
                [usuario.id]
            );

            const summary = {
                total_pending: parseFloat(totalPendente[0]?.total || 0),
                pending_count: parseInt(totalPendente[0]?.count || 0),
                next_release: receivables.length > 0 ? receivables[0].release_date : null
            };

            this.enviarResposta('GetReceivablesResponse', {
                success: true,
                data: {
                    receivables: receivables.map(r => ({
                        release_date: r.release_date,
                        amount: parseFloat(r.total_amount || 0),
                        transaction_count: parseInt(r.transaction_count || 0),
                        payment_method: r.payment_method || 'unknown',
                        description: `Liberação automática - ${r.payment_method === 'pix' ? 'PIX' :
                            r.payment_method === 'credit_card' ? 'Cartão de Crédito' :
                                r.payment_method === 'debit_card' ? 'Cartão de Débito' :
                                    r.payment_method === 'boleto' ? 'Boleto' : 'Outros'
                            }`
                    })),
                    summary
                }
            });

        } catch (error) {
            console.error('Erro ao buscar recebíveis:', error);
            this.enviarResposta('GetReceivablesResponse', {
                success: false,
                message: 'Erro ao carregar agenda de recebíveis'
            });
        }
    }

    async handleGetOrders() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetOrdersResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { page = 1, limit = 10, status } = this.data;
            const offset = (page - 1) * limit;

            // Construir query base
            let query = `
                SELECT 
                    o.*,
                    p.name as product_name,
                    p.type as product_type
                FROM orders o
                LEFT JOIN products p ON o.product_id = p.id
                WHERE o.user_id = ?
            `;

            const queryParams = [usuario.id];

            // Adicionar filtro de status, se fornecido
            if (status) {
                query += ' AND o.payment_status = ?';
                queryParams.push(status);
            }

            // Adicionar ordenação e paginação
            query += ' ORDER BY o.created_at DESC LIMIT ? OFFSET ?';
            queryParams.push(parseInt(limit), offset);

            // Buscar pedidos
            const pedidos = await this.db.query(query, queryParams);

            // Contar total de pedidos (para paginação)
            let countQuery = 'SELECT COUNT(*) as total FROM orders WHERE user_id = ?';
            const countParams = [usuario.id];

            if (status) {
                countQuery += ' AND payment_status = ?';
                countParams.push(status);
            }

            const contagem = await this.db.query(countQuery, countParams);
            const total = contagem[0].total;

            this.enviarResposta('GetOrdersResponse', {
                success: true,
                data: {
                    orders: pedidos,
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total,
                        pages: Math.ceil(total / limit)
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar pedidos:', error);
            this.enviarResposta('GetOrdersResponse', {
                success: false,
                message: 'Erro ao carregar pedidos'
            });
        }
    }

    async handleGetTransactions() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetTransactionsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { page = 1, limit = 10, type } = this.data;
            const offset = (page - 1) * limit;

            // Construir query base
            let query = `
                SELECT 
                    t.*,
                    o.gateway_transaction_id,
                    o.customer_name,
                    p.name as product_name
                FROM transactions t
                LEFT JOIN orders o ON t.order_id = o.id
                LEFT JOIN products p ON o.product_id = p.id
                WHERE t.user_id = ?
            `;

            const queryParams = [usuario.id];

            // Adicionar filtro de tipo, se fornecido
            if (type) {
                query += ' AND t.type = ?';
                queryParams.push(type);
            }

            // Adicionar ordenação e paginação
            query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
            queryParams.push(parseInt(limit), offset);

            // Buscar transações
            const transacoes = await this.db.query(query, queryParams);

            // Contar total de transações (para paginação)
            let countQuery = 'SELECT COUNT(*) as total FROM transactions WHERE user_id = ?';
            const countParams = [usuario.id];

            if (type) {
                countQuery += ' AND type = ?';
                countParams.push(type);
            }

            const contagem = await this.db.query(countQuery, countParams);
            const total = contagem[0].total;

            this.enviarResposta('GetTransactionsResponse', {
                success: true,
                data: {
                    transactions: transacoes,
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total,
                        pages: Math.ceil(total / limit)
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar transações:', error);
            this.enviarResposta('GetTransactionsResponse', {
                success: false,
                message: 'Erro ao carregar transações'
            });
        }
    }

    async handleProcessPayment() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('ProcessPaymentResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const {
                product_id, payment_method, customer_name,
                customer_email, customer_phone, customer_document,
                payment_details
            } = this.data;

            if (!product_id || !payment_method || !customer_name || !customer_email) {
                return this.enviarResposta('ProcessPaymentResponse', {
                    success: false,
                    message: 'Dados incompletos para processamento do pagamento'
                });
            }

            // Buscar produto
            const produtos = await this.db.query(
                'SELECT * FROM products WHERE id = ?',
                [product_id]
            );

            if (produtos.length === 0) {
                return this.enviarResposta('ProcessPaymentResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const produto = produtos[0];

            // Verificar estoque, se for produto físico com controle de estoque
            if (produto.type === 'physical' && produto.track_stock) {
                if (produto.stock_quantity <= 0) {
                    return this.enviarResposta('ProcessPaymentResponse', {
                        success: false,
                        message: 'Produto esgotado'
                    });
                }
            }

            // Gerar transação no gateway (simulado)
            const transactionId = 'tx_' + uuidv4().replace(/-/g, '');

            // Inserir pedido
            const resultadoPedido = await this.db.query(
                `INSERT INTO orders 
                (user_id, product_id, customer_name, customer_email, customer_phone, customer_document,
                amount, original_amount, discount_amount, net_amount, currency, payment_method,
                payment_status, order_status, gateway_transaction_id, payment_details, ip_address,
                created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    usuario.id, product_id, customer_name, customer_email, customer_phone, customer_document,
                    produto.price, produto.price, 0, produto.price * 0.97, // 3% de taxa
                    'BRL', payment_method, 'pending', 'pending', transactionId,
                    JSON.stringify(payment_details || {}), this.socket.handshake.address
                ]
            );

            // Criar transação pendente
            await this.db.query(
                `INSERT INTO transactions 
                (user_id, order_id, type, category, amount, currency, status, description, created_at, updated_at) 
                VALUES (?, ?, 'sale', 'income', ?, 'BRL', 'pending', 'Venda aguardando pagamento', NOW(), NOW())`,
                [usuario.id, resultadoPedido.insertId, produto.price]
            );

            // Atualizar estoque, se aplicável
            if (produto.type === 'physical' && produto.track_stock) {
                await this.db.query(
                    'UPDATE products SET stock_quantity = stock_quantity - 1, updated_at = NOW() WHERE id = ?',
                    [product_id]
                );
            }

            // Para pagamento PIX, gerar QR Code (simulado)
            let pixData = null;
            if (payment_method === 'pix') {
                pixData = {
                    qrcode: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAAAklEQVR4AewaftIAAAxSSURBVO3BQW4ERxLAQLKh/3+ZO8c+ChSwSY92RoR/MHNZ1zjzWtc481rXOPNa1zjzWtc481rXOPNa1zjzWtc481rXOPNa1zjzWtc481rXOPNa1zjzWtc48/GhCn9TxU6FOxVOVEwqdipMKiYVk4pJxU7FTsWOCicVOxXfpGKnYqfib6r4xMxlXePMa13jzGtd48zHl1V8k4qdip2KScWkYlIxqbhTsVOxU3Gn4qRiUjGp2Kn4ExU7FZOKOxWTiknFTsVOxTep+KaZy7rGmde6xpnXusaZjx9W8SdV3Kn4RMWdiknFTsWkYlKxU7FTMal4o2JS8UbFTsWk4ptU/CSVf9LMZcLMZV3jzGtd48xrXePMxx9OxaTijYo7FTsVk4pJxU7FnYpJxaRiUjGpmFRMKv5PMnNZ1zjzWtc481rXOPPxyyreqNipmFRMKiYVk4pJxaRiUjGpmFTsVEwqJhWTiknFpGJSsVMxqZhUTComFTsVk4pJxRsVv9nMZV3jzGtd48xrXePMxw+r+JtUTCp2KiYVk4pJxaRiUrFTMamYVLxRMamYVEwqJhWTit9M5ZvMXNY1zrzWNc681jXOfHxZxT9ZxaRiUrFTMamYVEwqJhUnFTsVk4o7FZOKnYpJxaTiROWbVPxLzFzWNc681jXOvNY1znz8sIpJxU7FpGKnYlIxqZhU7FTsVEwqJhU7FZOKScWkYlKxUzGpmFRMKiYVdyomFXcqvknFpGKnYlJxUvFNM5d1jTOvdY0zr3WNMx9/WMWk4kTFpGJSMamYVEwqdip2KiYVk4pJxaRiUrFTMamYVJxUTCp2KiYVk4qdip2KScVJxU7FicokM5d1jTOvdY0zr3WN8x+mYlJxUnGnYlKxUzGp2Kk4qZhUTCp2KiYVk4pJxU7FnYo7FXcqJhUnFZOKnYqdip2KnYpJxb/UzGVd48xrXePMa13jzMcPq/ibKiYVOxWTijsVdyomFZOKOxWTiknFpOJExaRiUjGpmFScVOxUTComFTsVk4pJxaTiROWbzFzWNc681jXOvNY1znx8WcU3qbhTMamYVOxUTCp2KiYVk4pJxaRiUnGn4ptU7FRMKiYVJxWTijsVdyp2KiYVk4pJxaRiUvFNM5d1jTOvdY0zr3WNMx8/rOJPqphUTCpOKt6ouFMxqZhUTCp2KiYVJxWTiknFTsVJxaRiUnGiMqm4U/GGyk8yc1nXOPNa1zjzWtc48/GHqdypmFRMKiYVOxWTiknFpGKn4kTlDZWTiknFN1XsVJxUTCp2Kk5UJhUnFX/SzGVd48xrXePMa13jzMcvU7FTMamYVEwqdiomFScVk4oTlTsVk4pJxW9ScafiRGWnYlIxqZhUTCpOKk5UJhWTiknFpGJSMamYVHzTzGVd48xrXePMa13jzMcvU7FTMamYVNypOFGZVOxUTCp2KiYVOxWTiknFpGKnYlIxqTipmFTsVEwqJhUnFW9U7FTsVEwqTip+0sxlXePMa13jzGtd48zHl6mYVOxUTCpOKiYVk4qdijsVk4pJxaRiUrFTMamYVJxUTComFTsVOxWTiknFpGJSMamYVEwqJhWTip2KScWkYlKxU7FT8ZNmLusa8/EDZi7rGvNa1zjzWtc48/HLVEwqJhWTik9UTCp2KiYVk4pJxU7FTsWk4kTlTsWkYlIxqfhExaTiTsVOxRsVk4oTlUnFTsXfNHNZ1zjzWtc481rXOPPxoYpJxU7FpGKnYlKxUzGpmFScVEwqJhU7FXcqJhUnFTsVJyp3KiYVk4pJxaTiTsWkYqdiUjGp2KmYVOxUTComFTsVk4pJxaTim8xc1jXOvNY1zrzWNc58fKhiUjGpuFMxqZhUTComFXcqJhWTiknFpGJSMamYVEwqJhV3KiYVOxU7FTsVk4pJxaRiUrFTMamYVOxUTCp2KiYVOxWTiknFpGJSMamYVHzTzGVd48xrXePMa13jzMeHKnYqJhWTijcqTlTuVNypmFRMKiYVk4pJxaTiTsWkYlKxU/GJip2Kk4pJxaRip2JSMamYVEwqTip2KiYVk4o/aeayrnHmta5x5rWucebjQxUnFZOKScVOxaTiTsVOxaRiUjGpmFRMKiYVk4o7FZOKnYo7FScVk4pJxaRiUjGpmFTsVEwqJhU7FW9UTCruVEwqdip2KiYVk4pJxTfNXNY1zrzWNc681jXOfPwwlU9U7FRMKiYVOxWTiknFnYpJxaRiUrFTMamYVEwqTlQmFZOKk4pJxaRiUjGp2Kk4qTipmFRMKiYVk4o7FZOKScWdiknFT5q5rGuce/GXqXyjYlJxUnGnYlIxqZhU7FTsVOxUTCpOKnYqJhWTiknFpOKk4kTlTsWdiknFpGJSMamYVEwqJhV3KiYVk4pJxaRiUjGp+KaZy7rGmde6xpnXusaZjx9WMak4qZhUTCp2KiYVk4pJxZ2KOxUnFZOKScVOxZ2KScVOxaRiUjGpmFRMKnYqJhWTiknFpGJSsVMxqZhU7FR8UvFNM5d1jTOvdY0zr3WNMx8fqphU7FTsVNypOFGZVEwqJhWTip2KScUbFZOKk4qdip2KnYpJxaRiUnGnYlJxUjGpmFRMKiYVJxWTiknFGxV/08xlXePMa13jzGtd48zHhyruVNypOKnYqZhUTCp2KiYVk4pJxaRiUnGnYlKxU7FTMamYVJxUTComFTsVOxWTijcqdip2KiYVk4pJxU7FnYpJxU7FnYpvmrmsa5x5rWucca1rnPn4UMWkYlIxqZhUTCruVLxRMamYVOxUTCr+popvqtip2Kk4qZhU7FRMKiYVk4o7FZOKScVOxRsVk4pJxU7FTsU3zVzWNc681jXOvNY1znz8sIqdip2KScVOxaRiUnFSMamYVNypmFScVEwqdiomFZOKnYoTlROVOxWTiknFpGKnYlIxqZhUTCpOKiYVk4pJxaRiUjGpmFT8pJnLusa51zXOvNY1znx8WcWkYlJxUjGpmFRMKiYVk4qdip2KScVOxaRiUjGp2KnYqTip2KnYqZhUTCp2KiYVk4qdiknFpGKnYlKxU7FTsVNxp2JScVLxk2Yu6xpnXusa83/gGmc+flnFScWk4pOKN1TuVJxUTComFScVk4pJxU7FpGKnYqdip2JSMal4o2KnYlKxU/FGxU7FpOJExaRip2JScadiUjGp+KaZy7rGmde6xpnXusaZjw9V7FTsVOxUTCpOKiYVOxWTiknFpGJSMamYVOxUvFExqZhU7FRMKiYVk4pJxUnFpGKnYlIxqZhUTCp2KiYVk4pJxRsVJxUnFZOKScWk4ptmLusa8/mAmcu6xrzWNc681jXOfHxZxaRiUjGp+KRiUnGn4g2VScWk4o2KScWkYqdiUjGpOKmYVNypOKmYVEwqJhWTiknFTsVOxaTiTsVOxaRiUjGp2Kn4SWYu6xpnXusa/wM+cY0zHz+s4k+qOKnYqXijYqdiUnGn4qRiUjGpmFScVOxUvFHxRsWJyqRiUjGpOKnYqTipmFRMKiYVk4pJxZ80c1nXOPNa1zjzWtc48/GHqXxScVKxUzGp2KmYVNypmFRMKu5UTCp2KiYVk4pJxU7FpGJSsVMxqZhU7FRMKiYVJxWTiknFpGJSMamYVEwqJhUnFZOKnYpvmrmsa5x5rWucca1rnPn4ZRU7FTsVk4pJxU7FTsWkYlJxp2Kn4qRiUvFNFTsVk4pJxaTiROVOxZ2KScWdiknFpGKnYlIxqbhTsVNxUjGpOKn4ppnLusa5F9c481rXOPPxH6ZiUrFTsVNxUrFTMamYVOxUTComFW9UvFFxUnGnYlIxqdip2KmYVOxU3KmYVEwqdip2KiYVk4pJxaTiJ81c1jXOvNY1zrzWNc58/LCKv6niTsWJyp2KScWk4qRiUjGpOFGZVEwqJhU7FScVJxUnFTsVk4pJxaRiUnFSMal4o2JSMamYVEwqftLMZV3jzGtd48xrXePMx5dVfJOKk4pJxaRip2JScVIxqZhUnFRMKnYqdiomFZOKnYqdikn/sLkAACAASURBVJ2KScWkYlIxqTipmFRMKiYVk4pJxZ2KnYo7FZOKnYpvmrmsa5x5rWucca1rnPn4YRV/UsVOxaRiUjGpuFOxU7FTsVOxU7FTsVNxp2JScafiROVOxUnFTsWJyqTiTsWkYqdip+KTip9k5rKucca1rnHmta5x5uMPV3GnYlKxUzGpmFRMKiYVOxV3KiYVJxWTip2KScWkYqdiUjGpmFTsVOxUTComFXcqdiomFXcqJhWTiknFpGKnYlKxU/E3zVzWNc681jXOvNY1znz8MhWTiknFnYpJxaRiUjGp2KnYqZhUTCp2KiYVk4qdijsVk4pJxaRiUnGiMqmYVOxUvKEyqZhUTCp2KiYVk4pJxZ2KnYpJxaRiUnGnYlIxqfimmcu6xrzWNc681jXOfPywir+pYlKxU7FTsVOxU7FTMak4UZlUTCpOKiYVk4pJxaTiROVOxaRiUjGp+ERlUnGnYlIxqZhUTCpOKnYq/qaZy7rGmde6xpnXusb5D1MxqTipmFScVEwq7lTsVJxUTCp2KiYVk4pJxUnFTsWkYlJxUnFSMamYVJxUTCp2KiYVOxWTikn/QDNzWdc481rXOPNa1zjz8csqJhWTiknFpOKNiknFpGJSMamYVEwqJhUnFZOKScVOxaRiUrFTsVNxUjGp2Kk4qdip2KmYVLxRMamYVOxU7FRMKnYqJhWTiknFTsU3zVzWNc681jXOvNY1znz8sIo/qeKk4o2KScUbFXcqdip2KiYVk4qdik9UTCp2KiYVOxVvVJxUTCruVEwqdiomFZOKScWkYlJxUnFSMamYVPykmcu6xpnXusaZ17rGmY8/XMVOxaTiTsVOxU7FpOKkYlIxqZhUTCpOKnYqJhUnFZOKScWkYlKxU7FTMamYVNypmFScVEwqdip2KiYVk4qdip2KnYpvmrmsa5x5rWucca1rnPn4YRX/ZBWTiknFpGKnYqdiUrFTMak4qTipmFRMKiYVk4qdip2KScWdiknFTsVOxaRiUjGpmFTsVJxUTCpOKiYVJxWTiknFGxXfNHNZ1zjzWtc481rXOP9hKiYVk4qdip2KN1ROKk5UJhUnFTsVk4pJxaTiTsWJyp2KOxUnFZOKnYo7FZOKScWkYqdip2JSsVMxqdip+CYzl3WNM691jTOvdY0zHz+s4k7FScWkYlKxUzGpOKmYVOxUTCp2KiYVk4qdip2KScVJxaRiUnFSMamYVJxUTCpOKk5UTip2KiYVk4pJxRsVOxWTiknFTsU3zVzWNc681jXOvNY1znx8qOJvqtip2KnYqbhTsVMxqTip2KmYVOxU7FTsVEwqdiruVEwqTiruVOxUTCruVEwqvknFTsWkYqdiUnGnYlIxqdip+JNmLusa515c48xrXePMx5dVfJOKOxUnFTsVk4pJxaRip2KnYlKxU3Gn4kTlTsWk4g2VScVOxYnKpGKnYlKxU/FGxRsVk4qdijsVk4pJxTfNXNY1zrzWNc681jXOfPywij+pYlIxqZhU7FSc9A87FXcq7lScVEwqJhV3KiYVb1RMKnYqJhU7FScqk4pJxaTiTsWk4k7FpGJSMamYVHzTzGVd48xrXePMa13jzMcfTuWbVEwqJhWTiknFicqkYqfiTsUbFScVJxWTiknFTsWkYlKxU/FGxaRiUjGp2Kk4UZlUTCp2KiYVk4pvmrmsa5x5rWucca1rnPn4ZRU7FTsVOxUnFZOKnYo7FScVk4qdip2Kk4pJxaRip2JScVIxqZhUTCp2KiYVk4pJxaRiUjGp2KnYqZhUTCpOKiYVOxWTiknFpGJSMamYVHzTzGVd48xrXePMa13jzMcPq5hUnFRMKnYqJhWTiknFpGKnYlLxRsVOxU7FTsWkYlJxUjGpmFRMKiYVk4pJxaTijYo7FZOKk4pJxU7FnYqdikn/MDOXdY15rWucca1rnPn4UMVP6r+omFTsVJxUTComFZOKnYqdikn/T5q5rGvMa13jzGtd48zHhyomFScVk4pJxaTiROVOxaRiUrFTMak4qZhUTCpOKiYVOxWTiknFTsWkYlLxTSp2KiYVOxU7FW9UTCpOKiYVk4pJxaRip2JScVIxqdip+EkzlwEzl3WN+X+sa5x5rWuc+fhlFXcqJhWTip2KnYpJxaRiUjGpmFTsVEwqJhUnFTsVk4qdip2KScVOxaRiUrFTMam4UzGp2KmYVEwqJhU7FZOKnYpJxZ2KSb/UzGVd48xrXeP/wTXOfPyyiknFScVOxUnFTsWkYlJxUnGn4qRiUjGp2KmYVOxU7FTsVOxUTCp2KnYqJhWTiknFicqJyqRiUnFSMamYVNypmFRMKk5UTiomFd80c1nXOPNa1zjzWtc48/GhiknFpGJSMamYVOxUTCruVJyoTCp2KiYVOxWTiknFTsVJxaRiUnGn4ptU7FTsVOxUTCpOKu5UTCpOKiYVOxWTiknFpGJSMamYVEwqvmnmsq5x5rWucca1rnHm40MVOxU7FZOKk4pJxZ2KnYpJxR8qdiomFScVk4pJxaRiUnFScadiUnFSMamYVNypmFTsVEwqJhWTiknFnYpJxaRiUjGpmFRMKk4qJhXfNHNZ1zjzWtc481rXOPPxoYpJxRsVOxWTip2KScVOxU7FTsVOxaRiUrFTMamYVJxUTCp2Kk4qdiomFTsVJxWTiknFnYo7FTsVOxWTip2KScWdiknFpGKnYqdip+JvmrmsaMxrXeP/wDXOfHxZxaRiUnGnYlIxqZhU7FRMKiYVJyp3KiYVk4pJxaRip2JSMamYVEwqJhUnFW9UTCp2KiYVk4pJxU7FpGJSMal4o2KnYlIxqZhUTCpOKiYVk4qdip80c1nXmH/mGmde6xpnPn5YxaRiUnGiMqmYVOxUnFRMKiYVJxWTijsVk4pJxRsVOxWTiknFpOJOxU7FGxWTip2KScVOxaRiUjGpmFTsVOxUTCp2Kt6omFRMKv6mmcu6xpnXusa51zXOfPwyFTsVk4o7FZOKScVOxZ2KScWkYlIxqZhUTComFTsVk4pJxU7FpGJSMak4qZhUvFExqZhUTCpOKnYqJhU7FXcqJhU7FZOKnYpJxUnFpGJScafim8xc1jXOvNY1zrzWNc58fKhiUrFTMak4qZhU7FTcqZhU7FTsVOxUvFGxU7FTsVMxqbhTMamYVOxU7FTsVEwqdiomFZOKk4pJxaRip2JSMamYVNypmFRMKnYqJhWTijsVk4pJxTfNXNY1zrzWNc681jXOfHxZxaTiTsVJxaRiUrFTsVMxqbhTsVOxU3FSMamYVOxUTCpOKk4qJhWTiknFpGKnYlJxp+KNiknFpGJSMamYVOxU7FRMKiYVJxWTiknFGypvVPykmcu6xpnXusaZ17rGmY8PVUwqdip2KiYVk4pJxU7FScVOxRsVb1TsVEwqTiomFZOKSf9/qrj1/2UqJhWTiknFTsWk4qRiUnGnYlIxqbhTMam4U/E3zVzWNc681jXOvNY1znz8sIo/qeKk4kRlUnGiMqmYVEwqTir+pIpJxaRiUjGpOKnYqbhTcVJxUjGpmFTsVEwqJhU7FScVk4qdip2KScWfNHNZ1zjzWtc481rXOPPxl6nYqZhUTComFTsVk4qdip2KnYpJxaTiTsWkYlJxUrFTMamYVOxUTCpOKiYVOxV3KnYq7lTsVNypmFRMKiYVk4pJxUnFTsWdiknFTsU3zVzWNc681jXOvNY1znz8MpWTiknFScVOxaRiUnFSMamYVEwqdip2KiYVk4qdijsVk4pJxZ2KnYo7FTsVOxWTiknFTsWk4qTipGJSMamYVJxUTCpOKiYVk4pJxUnFT5q5rGucca1rnHmta5z5+GEVk4qTiknFGxUnFTsVk4pJxaRiUnGnYqdiUnGn4ptU7FRMKiYVJxV3KiYVOxWTijsVk4pJxRsVO/0XdyomFZOKScWk4qTim8xc1jXOvNY1zrzWNc58fKjiROWbVNypmFRMKiYVOxU7FScVk4pJxaRiUnFSMak4qZhU7FTsVEwqJhWTijsVJyqTiknFpGJSMamYVEwqJhUnFZOKScWk4ptmLusa817XOPNa1zjz8aGKnYqdiknFpGJSsVMxqZhUTCruVEwqdip2KiYVOxWTiknFicp/qZhU3KnYqZhUTCp2KiYVOxUnFZOKScWkYlIxqZhU3KmYVOxU7FT8JDOXdY0zr3WNM691jTMff7iKScWdijsVk4pJxUnFpOJOxaRiUnFSMamYVOxU3KmYVNyp2KmYVJyonFTsVJxUTCp2KiYVJxUnFZOKnYpJxaRiUjGpmFRMKt6o+CYzl3WNM691jTOvdY0zHx+q+JsqJhU7FTsVdyomFTsVk4o7FTsVOxWTip2KOxV3KiYVJxU7FTsVJxUnFZOKScWk4o2KOxWTiknFpGJSMamYVOxUTCpOKiYVk4qdim+auaxrnHmta5x5rWuc+fiyim9SMamYVEwq3qg4qZhUTCp2KiYVk4pJxU7FTsVOxU7FpGKnYqdiUnGnYlKxU3GnYlKxU7FTMamYVEwqTip2KiYVdyomFScVk4pJxaRiUvFNM5d1jTOvdY0zr3WNMx8/rOJPqtip2KmYVNyp2KmYVOxUTComFW9UTCp2KiYVJxWTiknFpGJSsVNxUnGn4qRiUjGpuFOxUzGpOFGZVJxUTCpOKt6o+Jtm/gNmLusa81rXOPNa1zjz8ZepuFOxU3FSMak4qZhUTCp2KiYVJxWTiknFpGKnYlKxUzGpOKm4U7FTMamYVOxUTCp2KnYqdip2KnYqJhWTip2KScWk4qRiUjGp2KnYqZhUTCpOKr5p5rKucca1rnHmta5x5uOHVUwqTip2KnYqJhWTiknFnYpJxaRiUjGpmFTsVJxUTCp2KiYVk4o3KiYVOxWTiknFScVOxaRiUvFGxaRiUjGp2KmYVJxUTComFTsVdyp2Kk5UftLMZV3jzGtd48xrXePMxw9TMamYVOxUTComFScVk4qdijsVJxWTip2KScVOxaRiUjGp2KmYVOxUTCpOKt6o2KmYVOxUTCp2KiYVOxWTiknFpOKkYlJxUnGnYlIxqbhTMak4qZhUfNPMZV3jzGtd48xrXePMxy9TsVMxqZhUTComFZOKOxWTiknFicqk4qRiUnGi8l9UTCp2KiYVk4pJxZ2KScWkYlJxp2JScVIxqTipmFRMKiYVk4pJxZ2KnYpJxaRiUjGp+EkzlwEzl3WN+X+sa5x5rWuc+fhhFZOKOxUnFZOKScWkYlJxUnFSMamYVJxU3KnYqZhUTCpOKiYVOxUnFZOKScVOxRsVk4pJxaRiUnGn4kTlTsVOxaTijYqdip2KSf/FzGVd48xrXePMa13j/I9VMamYVOxU7FTsVOxUTCpOKiYVk4pJxaTiROVOxaRip2JSMak4qZhUTComFXcqdip2Kk4qJhWTiknFTsVOxaTiROWNijsVk4pJxaRiUnGnYlIxqbhTMal4o+KbZi7rGmde6xpnXusaZz4+VDGp2KmYVOxU7FRMKk4q3qg4qTip2KmYVJxU7FTsVOxU7FRMKnYqTiomFZOKScWdiknFpGJSMamYVJxU7FTsVJyoTCpOKnYqJhWTiknFpGJSMamYVPykmcu6xpnXusaZ17rGmY8vq5hUTCruVOxUTCruVEwqJhU7FZOKk4qdip2KScVOxU7FTsWkYlKxU7FTMamYVJxUTCruVJyoTComFZOKScWkYlIxqZhUTCp2KiYVdyomFZOKScVOxaRiUvFNM5d1jTOvdY0zr3WNMx8/rGJScVIxqZhUTComFZOKn1QxqZhUTCp2KiYVJxU7FZOKScWk4kTlTsWkYlKxUzGpmFRMKiYVk4o7FScVJxWTiknFScWk4k7Fn6QyqfiTZi7rGmde6xrzf+AaZz5+WMWk4qRip2JS8YbKScWk4kRlUnFSMamYVJxU7FR8omJSMamYVEwqJhU7FZOKnYqdijsVOxWTiknFnYqdip2KOxWTiknFpGJSMamYVPxNM5d1jTOvdY0zr3WNMx+/TMWkYlJxp2JScVKxUzGpuFMxqZhU7FTsVOxUTComFZOKScVOxU7FN6mYVOxU3Km4UzGpmFRMKiYVk4pJxaRip2JSMamYVEwqdip2KiYVJxXfZOayrnHmta5x5rWucebTPxQwc1nXOPNa1zjzWtc481rXOPNa1zjzWtc481rXOPNa1zjzWtc481rXOPNa1zjzWtc481rXOPNa1zjzWtc481rXOP8Bd+HiQ4MpzVQAAAAASUVORK5CYII=',
                    qrcode_text: '00020101021226860014br.gov.bcb.pix0114+55219876543210215For4 Gateway520400005303986540520.005802BR5925John Doe6014Rio de Janeiro62180514pix12345678906304F1B9',
                    expiration_date: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 horas
                };
            }

            this.enviarResposta('ProcessPaymentResponse', {
                success: true,
                message: 'Pagamento em processamento',
                data: {
                    order_id: resultadoPedido.insertId,
                    transaction_id: transactionId,
                    status: 'pending',
                    payment_method,
                    amount: produto.price,
                    pix_data: pixData
                }
            });

        } catch (error) {
            console.error('Erro ao processar pagamento:', error);
            this.enviarResposta('ProcessPaymentResponse', {
                success: false,
                message: 'Erro ao processar pagamento'
            });
        }
    }

    async handleGetProfile() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetProfileResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar configurações do usuário
            const configuracoes = await this.db.query(
                'SELECT * FROM user_settings WHERE user_id = ?',
                [usuario.id]
            );

            // Buscar contas bancárias
            const contasBancarias = await this.db.query(
                'SELECT * FROM bank_accounts WHERE user_id = ?',
                [usuario.id]
            );

            this.enviarResposta('GetProfileResponse', {
                success: true,
                data: {
                    user: {
                        id: usuario.id,
                        name: usuario.name,
                        email: usuario.email,
                        phone: usuario.phone,
                        document: usuario.document,
                        birth_date: usuario.birth_date,
                        avatar: usuario.avatar,
                        status: usuario.status,
                        email_verified_at: usuario.email_verified_at,
                        created_at: usuario.created_at
                    },
                    settings: configuracoes.length > 0 ? configuracoes[0] : null,
                    bank_accounts: contasBancarias
                }
            });

        } catch (error) {
            console.error('Erro ao buscar perfil:', error);
            this.enviarResposta('GetProfileResponse', {
                success: false,
                message: 'Erro ao carregar perfil'
            });
        }
    }

    async handleUpdateProfile() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateProfileResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { name, phone, document, birth_date, avatar, password, current_password } = this.data;

            // Campos para atualização
            const updateFields = [];
            const updateValues = [];

            if (name) {
                updateFields.push('name = ?');
                updateValues.push(name);
            }

            if (phone) {
                updateFields.push('phone = ?');
                updateValues.push(phone);
            }

            if (document) {
                updateFields.push('document = ?');
                updateValues.push(document);
            }

            if (birth_date) {
                updateFields.push('birth_date = ?');
                updateValues.push(birth_date);
            }

            if (avatar) {
                // Salvar avatar (base64) como arquivo
                const avatarBuffer = Buffer.from(avatar.split(',')[1], 'base64');
                const avatarExt = avatar.match(/data:image\/(\w+);/)[1];
                const avatarName = `avatar_${usuario.id}_${Date.now()}.${avatarExt}`;
                const avatarPath = path.join(process.cwd(), 'uploads', 'avatars', avatarName);

                // Garantir que o diretório existe
                const dir = path.dirname(avatarPath);
                if (!fs.existsSync(dir)) {
                    fs.mkdirSync(dir, { recursive: true });
                }

                fs.writeFileSync(avatarPath, avatarBuffer);

                updateFields.push('avatar = ?');
                updateValues.push(`/avatars/${avatarName}`);

                // Remover avatar antigo, se existir
                if (usuario.avatar) {
                    const oldAvatarPath = path.join(process.cwd(), usuario.avatar.replace('/avatars/', 'uploads/avatars/'));
                    if (fs.existsSync(oldAvatarPath)) {
                        fs.unlinkSync(oldAvatarPath);
                    }
                }
            }

            // Atualizar senha, se fornecida
            if (password && current_password) {
                // Verificar senha atual
                const senhaValida = await bcrypt.compare(current_password, usuario.password);
                if (!senhaValida) {
                    return this.enviarResposta('UpdateProfileResponse', {
                        success: false,
                        message: 'Senha atual incorreta'
                    });
                }

                // Hash da nova senha
                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(password, salt);

                updateFields.push('password = ?');
                updateValues.push(hashedPassword);
            }

            if (updateFields.length === 0) {
                return this.enviarResposta('UpdateProfileResponse', {
                    success: false,
                    message: 'Nenhum campo para atualizar'
                });
            }

            // Adicionar data de atualização
            updateFields.push('updated_at = NOW()');

            // Montar query de atualização
            const updateQuery = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
            updateValues.push(usuario.id);

            // Atualizar usuário
            await this.db.query(updateQuery, updateValues);

            this.enviarResposta('UpdateProfileResponse', {
                success: true,
                message: 'Perfil atualizado com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar perfil:', error);
            this.enviarResposta('UpdateProfileResponse', {
                success: false,
                message: 'Erro ao atualizar perfil'
            });
        }
    }

    async handleUpdateSettings() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateSettingsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const {
                notification_email, notification_sms, notification_push,
                theme, language, timezone, currency, fee_display,
                auto_withdrawal, auto_withdrawal_amount, auto_withdrawal_day
            } = this.data;

            // Campos para atualização
            const updateFields = [];
            const updateValues = [];

            if (notification_email !== undefined) {
                updateFields.push('notification_email = ?');
                updateValues.push(notification_email);
            }

            if (notification_sms !== undefined) {
                updateFields.push('notification_sms = ?');
                updateValues.push(notification_sms);
            }

            if (notification_push !== undefined) {
                updateFields.push('notification_push = ?');
                updateValues.push(notification_push);
            }

            if (theme) {
                updateFields.push('theme = ?');
                updateValues.push(theme);
            }

            if (language) {
                updateFields.push('language = ?');
                updateValues.push(language);
            }

            if (timezone) {
                updateFields.push('timezone = ?');
                updateValues.push(timezone);
            }

            if (currency) {
                updateFields.push('currency = ?');
                updateValues.push(currency);
            }

            if (fee_display) {
                updateFields.push('fee_display = ?');
                updateValues.push(fee_display);
            }

            if (auto_withdrawal !== undefined) {
                updateFields.push('auto_withdrawal = ?');
                updateValues.push(auto_withdrawal);
            }

            if (auto_withdrawal_amount !== undefined) {
                updateFields.push('auto_withdrawal_amount = ?');
                updateValues.push(auto_withdrawal_amount);
            }

            if (auto_withdrawal_day !== undefined) {
                updateFields.push('auto_withdrawal_day = ?');
                updateValues.push(auto_withdrawal_day);
            }

            if (updateFields.length === 0) {
                return this.enviarResposta('UpdateSettingsResponse', {
                    success: false,
                    message: 'Nenhum campo para atualizar'
                });
            }

            // Adicionar data de atualização
            updateFields.push('updated_at = NOW()');

            // Verificar se já existem configurações para o usuário
            const configuracaoExistente = await this.db.query(
                'SELECT id FROM user_settings WHERE user_id = ?',
                [usuario.id]
            );

            if (configuracaoExistente.length > 0) {
                // Atualizar configurações existentes
                const updateQuery = `UPDATE user_settings SET ${updateFields.join(', ')} WHERE user_id = ?`;
                updateValues.push(usuario.id);

                await this.db.query(updateQuery, updateValues);
            } else {
                // Criar novas configurações com valores padrão
                await this.db.query(
                    `INSERT INTO user_settings 
                    (user_id, notification_email, notification_sms, notification_push, theme, language, 
                     timezone, currency, fee_display, auto_withdrawal, auto_withdrawal_amount, 
                     auto_withdrawal_day, created_at, updated_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                    [
                        usuario.id,
                        notification_email !== undefined ? notification_email : true,
                        notification_sms !== undefined ? notification_sms : false,
                        notification_push !== undefined ? notification_push : true,
                        theme || 'light',
                        language || 'pt_BR',
                        timezone || 'America/Sao_Paulo',
                        currency || 'BRL',
                        fee_display || 'included',
                        auto_withdrawal !== undefined ? auto_withdrawal : false,
                        auto_withdrawal_amount !== undefined ? auto_withdrawal_amount : 0.00,
                        auto_withdrawal_day !== undefined ? auto_withdrawal_day : 1
                    ]
                );
            }

            this.enviarResposta('UpdateSettingsResponse', {
                success: true,
                message: 'Configurações atualizadas com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar configurações:', error);
            this.enviarResposta('UpdateSettingsResponse', {
                success: false,
                message: 'Erro ao atualizar configurações'
            });
        }
    }

    async handleGetAffiliates() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetAffiliatesResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar afiliados patrocinados por este usuário
            const afiliados = await this.db.query(
                `SELECT 
                    affiliates.*,
                    users.name,
                    users.email,
                    users.phone,
                    users.created_at
                FROM affiliates
                INNER JOIN users ON affiliates.user_id = users.id
                WHERE affiliates.sponsor_id = ?
                ORDER BY affiliates.created_at DESC`,
                [usuario.id]
            );

            // Buscar informações de afiliado do próprio usuário (se ele for afiliado)
            const meuAfiliado = await this.db.query(
                `SELECT 
                    affiliates.*,
                    users.name,
                    users.email
                FROM affiliates
                LEFT JOIN users ON affiliates.sponsor_id = users.id
                WHERE affiliates.user_id = ?`,
                [usuario.id]
            );

            // Buscar estatísticas gerais
            const estatisticas = await this.db.query(
                `SELECT 
                    COUNT(*) as total_affiliates,
                    SUM(total_sales) as total_network_sales,
                    SUM(total_commission) as total_network_commission
                FROM affiliates 
                WHERE sponsor_id = ?`,
                [usuario.id]
            );

            // Buscar top afiliados do mês
            const topAfiliados = await this.db.query(
                `SELECT 
                    affiliates.affiliate_code,
                    users.name,
                    SUM(orders.commission_amount) as monthly_commission,
                    COUNT(orders.id) as monthly_sales
                FROM affiliates
                INNER JOIN users ON affiliates.user_id = users.id
                LEFT JOIN orders ON orders.affiliate_id = affiliates.user_id 
                    AND MONTH(orders.created_at) = MONTH(CURRENT_DATE())
                    AND YEAR(orders.created_at) = YEAR(CURRENT_DATE())
                    AND orders.payment_status = 'paid'
                WHERE affiliates.sponsor_id = ?
                GROUP BY affiliates.id, users.name
                ORDER BY monthly_commission DESC
                LIMIT 5`,
                [usuario.id]
            );

            this.enviarResposta('GetAffiliatesResponse', {
                success: true,
                data: {
                    affiliates: afiliados,
                    my_affiliate: meuAfiliado.length > 0 ? meuAfiliado[0] : null,
                    statistics: {
                        total_affiliates: estatisticas[0].total_affiliates || 0,
                        total_network_sales: estatisticas[0].total_network_sales || 0,
                        total_network_commission: estatisticas[0].total_network_commission || 0
                    },
                    top_affiliates: topAfiliados
                }
            });

        } catch (error) {
            console.error('Erro ao buscar afiliados:', error);
            this.enviarResposta('GetAffiliatesResponse', {
                success: false,
                message: 'Erro ao carregar dados de afiliados'
            });
        }
    }

    async handleAddAffiliate() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('AddAffiliateResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { email, commission_rate = 10.00 } = this.data;

            if (!email) {
                return this.enviarResposta('AddAffiliateResponse', {
                    success: false,
                    message: 'Email é obrigatório'
                });
            }

            // Verificar se o usuário com este email existe
            const usuarioAfiliado = await this.db.query(
                'SELECT * FROM users WHERE email = ?',
                [email]
            );

            if (usuarioAfiliado.length === 0) {
                return this.enviarResposta('AddAffiliateResponse', {
                    success: false,
                    message: 'Usuário não encontrado com este email'
                });
            }

            const afiliado = usuarioAfiliado[0];

            // Verificar se o usuário não está tentando se adicionar como afiliado
            if (afiliado.id === usuario.id) {
                return this.enviarResposta('AddAffiliateResponse', {
                    success: false,
                    message: 'Você não pode se adicionar como afiliado'
                });
            }

            // Verificar se já existe um registro de afiliado para este usuário
            const afiliadoExistente = await this.db.query(
                'SELECT * FROM affiliates WHERE user_id = ?',
                [afiliado.id]
            );

            if (afiliadoExistente.length > 0) {
                return this.enviarResposta('AddAffiliateResponse', {
                    success: false,
                    message: 'Este usuário já é afiliado de alguém'
                });
            }

            // Gerar código de afiliado único
            let affiliateCode;
            let codeExists = true;
            let tentativas = 0;

            while (codeExists && tentativas < 10) {
                affiliateCode = 'AFF' + Math.random().toString(36).substring(2, 8).toUpperCase();

                const codigoExistente = await this.db.query(
                    'SELECT id FROM affiliates WHERE affiliate_code = ?',
                    [affiliateCode]
                );

                codeExists = codigoExistente.length > 0;
                tentativas++;
            }

            if (codeExists) {
                return this.enviarResposta('AddAffiliateResponse', {
                    success: false,
                    message: 'Erro ao gerar código de afiliado. Tente novamente.'
                });
            }

            // Inserir afiliado
            const resultado = await this.db.query(
                `INSERT INTO affiliates 
                (user_id, sponsor_id, affiliate_code, commission_rate, status, joined_at, created_at, updated_at) 
                VALUES (?, ?, ?, ?, 'active', NOW(), NOW(), NOW())`,
                [afiliado.id, usuario.id, affiliateCode, commission_rate]
            );

            this.enviarResposta('AddAffiliateResponse', {
                success: true,
                message: 'Afiliado adicionado com sucesso',
                data: {
                    id: resultado.insertId,
                    affiliate_code: affiliateCode,
                    user_name: afiliado.name,
                    user_email: afiliado.email,
                    commission_rate: commission_rate
                }
            });

        } catch (error) {
            console.error('Erro ao adicionar afiliado:', error);
            this.enviarResposta('AddAffiliateResponse', {
                success: false,
                message: 'Erro ao adicionar afiliado'
            });
        }
    }

    async handleRemoveAffiliate() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('RemoveAffiliateResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { affiliate_id } = this.data;

            if (!affiliate_id) {
                return this.enviarResposta('RemoveAffiliateResponse', {
                    success: false,
                    message: 'ID do afiliado é obrigatório'
                });
            }

            // Verificar se o afiliado pertence a este sponsor
            const afiliados = await this.db.query(
                'SELECT * FROM affiliates WHERE id = ? AND sponsor_id = ?',
                [affiliate_id, usuario.id]
            );

            if (afiliados.length === 0) {
                return this.enviarResposta('RemoveAffiliateResponse', {
                    success: false,
                    message: 'Afiliado não encontrado'
                });
            }

            const afiliado = afiliados[0];

            // Verificar se há vendas/comissões associadas
            const vendasAssociadas = await this.db.query(
                'SELECT COUNT(*) as total FROM orders WHERE affiliate_id = ?',
                [afiliado.user_id]
            );

            if (vendasAssociadas[0].total > 0) {
                // Se há vendas, apenas inativar o afiliado
                await this.db.query(
                    'UPDATE affiliates SET status = ?, updated_at = NOW() WHERE id = ?',
                    ['inactive', affiliate_id]
                );

                this.enviarResposta('RemoveAffiliateResponse', {
                    success: true,
                    message: 'Afiliado desativado com sucesso. Não foi possível excluir pois existem vendas associadas.'
                });
            } else {
                // Se não há vendas, excluir completamente
                await this.db.query(
                    'DELETE FROM affiliates WHERE id = ?',
                    [affiliate_id]
                );

                this.enviarResposta('RemoveAffiliateResponse', {
                    success: true,
                    message: 'Afiliado removido com sucesso'
                });
            }

        } catch (error) {
            console.error('Erro ao remover afiliado:', error);
            this.enviarResposta('RemoveAffiliateResponse', {
                success: false,
                message: 'Erro ao remover afiliado'
            });
        }
    }

    async handlePaymentWebhook() {
        try {
            const { event, payment } = this.data;

            console.log(`[WEBHOOK] Evento recebido: ${event}`, payment);

            if (event === 'PAYMENT_UPDATED' && payment) {
                const { transaction_id, status, amount, gateway_provider } = payment;

                if (!transaction_id) {
                    console.error('[WEBHOOK] Transaction ID não fornecido');
                    return;
                }

                // Buscar pedido pelo transaction_id
                const pedidos = await this.db.query(
                    'SELECT * FROM orders WHERE gateway_transaction_id = ?',
                    [transaction_id]
                );

                if (pedidos.length === 0) {
                    console.error(`[WEBHOOK] Pedido não encontrado para transaction_id: ${transaction_id}`);
                    return;
                }

                const pedido = pedidos[0];

                // Mapear status do webhook para nosso sistema
                let novoStatus;
                switch (status) {
                    case 'approved':
                    case 'paid':
                    case 'completed':
                        novoStatus = 'paid';
                        break;
                    case 'cancelled':
                    case 'canceled':
                        novoStatus = 'cancelled';
                        break;
                    case 'refunded':
                        novoStatus = 'refunded';
                        break;
                    case 'chargeback':
                        novoStatus = 'chargeback';
                        break;
                    default:
                        novoStatus = 'pending';
                }

                // Atualizar status do pedido
                await this.db.query(
                    `UPDATE orders SET 
                        payment_status = ?, 
                        order_status = ?,
                        paid_at = ?,
                        updated_at = NOW() 
                    WHERE id = ?`,
                    [
                        novoStatus,
                        novoStatus === 'paid' ? 'completed' : pedido.order_status,
                        novoStatus === 'paid' ? new Date() : null,
                        pedido.id
                    ]
                );

                // Atualizar transação correspondente
                await this.db.query(
                    `UPDATE transactions SET 
                        status = ?, 
                        processed_at = ?,
                        updated_at = NOW() 
                    WHERE order_id = ?`,
                    [
                        novoStatus === 'paid' ? 'completed' :
                            novoStatus === 'cancelled' ? 'cancelled' : 'failed',
                        novoStatus === 'paid' ? new Date() : null,
                        pedido.id
                    ]
                );

                // Se pagamento aprovado, processar comissões de afiliado
                if (novoStatus === 'paid' && pedido.affiliate_id) {
                    await this.processarComissaoAfiliado(pedido);
                }

                // Se pagamento aprovado, atualizar estatísticas do produto
                if (novoStatus === 'paid') {
                    await this.atualizarEstatisticasProduto(pedido);
                }

                // Log do webhook processado
                await this.db.query(
                    `INSERT INTO webhooks 
                    (user_id, provider, event, payload, status, processed_at, created_at, updated_at) 
                    VALUES (?, ?, ?, ?, 'processed', NOW(), NOW(), NOW())`,
                    [
                        pedido.user_id,
                        gateway_provider || 'unknown',
                        event,
                        JSON.stringify(this.data)
                    ]
                );

                console.log(`[WEBHOOK] Pagamento processado com sucesso: ${transaction_id} - Status: ${novoStatus}`);
            }

        } catch (error) {
            console.error('[WEBHOOK] Erro ao processar webhook de pagamento:', error);

            // Log do erro no webhook
            try {
                await this.db.query(
                    `INSERT INTO webhooks 
                    (provider, event, payload, status, error_message, created_at, updated_at) 
                    VALUES (?, ?, ?, 'failed', ?, NOW(), NOW())`,
                    [
                        this.data.payment?.gateway_provider || 'unknown',
                        this.data.event || 'unknown',
                        JSON.stringify(this.data),
                        error.message
                    ]
                );
            } catch (logError) {
                console.error('[WEBHOOK] Erro ao salvar log de erro:', logError);
            }
        }
    }

    async processarComissaoAfiliado(pedido) {
        try {
            // Buscar dados do afiliado
            const afiliados = await this.db.query(
                'SELECT * FROM affiliates WHERE user_id = ?',
                [pedido.affiliate_id]
            );

            if (afiliados.length === 0) {
                console.log(`[WEBHOOK] Afiliado não encontrado: ${pedido.affiliate_id}`);
                return;
            }

            const afiliado = afiliados[0];
            const comissaoValor = (pedido.amount * afiliado.commission_rate) / 100;

            // Criar transação de comissão
            await this.db.query(
                `INSERT INTO transactions 
                (user_id, order_id, type, category, amount, currency, status, description, created_at, updated_at) 
                VALUES (?, ?, 'commission', 'income', ?, ?, 'completed', 'Comissão de afiliado', NOW(), NOW())`,
                [pedido.affiliate_id, pedido.id, comissaoValor, pedido.currency]
            );

            // Atualizar estatísticas do afiliado
            await this.db.query(
                `UPDATE affiliates SET 
                    total_sales = total_sales + ?,
                    total_commission = total_commission + ?,
                    total_conversions = total_conversions + 1,
                    updated_at = NOW()
                WHERE user_id = ?`,
                [pedido.amount, comissaoValor, pedido.affiliate_id]
            );

            console.log(`[WEBHOOK] Comissão processada: ${comissaoValor} para afiliado ${pedido.affiliate_id}`);

        } catch (error) {
            console.error('[WEBHOOK] Erro ao processar comissão de afiliado:', error);
        }
    }

    async atualizarEstatisticasProduto(pedido) {
        try {
            // Reduzir estoque se for produto físico com controle de estoque
            const produtos = await this.db.query(
                'SELECT * FROM products WHERE id = ?',
                [pedido.product_id]
            );

            if (produtos.length > 0) {
                const produto = produtos[0];

                if (produto.type === 'physical' && produto.track_stock && produto.stock_quantity > 0) {
                    await this.db.query(
                        'UPDATE products SET stock_quantity = stock_quantity - 1, updated_at = NOW() WHERE id = ?',
                        [pedido.product_id]
                    );

                    console.log(`[WEBHOOK] Estoque atualizado para produto ${pedido.product_id}`);
                }
            }

        } catch (error) {
            console.error('[WEBHOOK] Erro ao atualizar estatísticas do produto:', error);
        }
    }

    async handleForgotPassword() {
        try {
            const { email } = this.data;

            if (!email) {
                return this.enviarResposta('ForgotPasswordResponse', {
                    success: false,
                    message: 'Email é obrigatório'
                });
            }

            // Validar formato do email
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return this.enviarResposta('ForgotPasswordResponse', {
                    success: false,
                    message: 'Email inválido'
                });
            }

            // Verificar se o usuário existe
            const usuarios = await this.db.query(
                'SELECT id, name, email FROM users WHERE email = ?',
                [email]
            );

            if (usuarios.length === 0) {
                // Por segurança, não informamos se o email existe ou não
                return this.enviarResposta('ForgotPasswordResponse', {
                    success: true,
                    message: 'Se este email estiver cadastrado, você receberá as instruções de recuperação'
                });
            }

            const usuario = usuarios[0];

            // Gerar token único de forma simples
            const generateToken = () => {
                const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                let token = '';
                for (let i = 0; i < 32; i++) {
                    token += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                return token;
            };

            const token = generateToken();
            const expiresAt = new Date(Date.now() + 3600000); // 1 hora

            // Invalidar tokens anteriores para este email
            await this.db.query(
                'UPDATE password_reset_tokens SET used = TRUE WHERE email = ? AND used = FALSE',
                [email]
            );

            // Inserir novo token
            await this.db.query(
                'INSERT INTO password_reset_tokens (user_id, email, token, expires_at) VALUES (?, ?, ?, ?)',
                [usuario.id, email, token, expiresAt]
            );

            // Gerar link de recuperação
            const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

            // Template do email
            const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #2563eb;">Recuperação de Senha - For4 Payments</h2>
                <p>Olá, ${usuario.name}!</p>
                <p>Você solicitou a recuperação de senha para sua conta.</p>
                <p>Clique no botão abaixo para criar uma nova senha:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetLink}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                        Redefinir Senha
                    </a>
                </div>
                <p>Ou copie e cole este link no seu navegador:</p>
                <p style="background-color: #f3f4f6; padding: 10px; border-radius: 4px; word-break: break-all;">
                    ${resetLink}
                </p>
                <p><strong>Este link expira em 1 hora.</strong></p>
                <p>Se você não solicitou esta recuperação, ignore este email.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
                <p style="color: #6b7280; font-size: 12px;">
                    For4 Payments - Sistema de Pagamentos
                </p>
            </div>
        `;

            // Enviar email
            const enviou = await transporter.sendMail({
                from: `"For4 Payments" <${process.env.SMTP_USER}>`,
                to: email,
                subject: 'Recuperação de Senha - For4 Payments',
                html: emailHtml
            });

            console.log(enviou)
            this.enviarResposta('ForgotPasswordResponse', {
                success: true,
                message: 'Se este email estiver cadastrado, você receberá as instruções de recuperação'
            });

        } catch (error) {
            console.error('Erro ao solicitar recuperação de senha:', error);
            this.enviarResposta('ForgotPasswordResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleResetPassword() {
        try {
            const { token, password, confirmPassword } = this.data;

            if (!token || !password || !confirmPassword) {
                return this.enviarResposta('ResetPasswordResponse', {
                    success: false,
                    message: 'Token e senhas são obrigatórios'
                });
            }

            // Validar se as senhas coincidem
            if (password !== confirmPassword) {
                return this.enviarResposta('ResetPasswordResponse', {
                    success: false,
                    message: 'As senhas não coincidem'
                });
            }

            // Validar senha (mínimo 6 caracteres)
            if (password.length < 6) {
                return this.enviarResposta('ResetPasswordResponse', {
                    success: false,
                    message: 'A senha deve ter pelo menos 6 caracteres'
                });
            }

            // Buscar token válido
            const tokens = await this.db.query(
                `SELECT prt.*, u.id as user_id, u.email, u.name 
             FROM password_reset_tokens prt 
             JOIN users u ON prt.user_id = u.id 
             WHERE prt.token = ? AND prt.used = FALSE AND prt.expires_at > NOW()`,
                [token]
            );

            if (tokens.length === 0) {
                return this.enviarResposta('ResetPasswordResponse', {
                    success: false,
                    message: 'Token inválido ou expirado'
                });
            }

            const tokenData = tokens[0];

            // Criptografar nova senha
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Atualizar senha do usuário
            await this.db.query(
                'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
                [hashedPassword, tokenData.user_id]
            );

            // Marcar token como usado
            await this.db.query(
                'UPDATE password_reset_tokens SET used = TRUE, used_at = NOW() WHERE id = ?',
                [tokenData.id]
            );

            // Invalidar todos os outros tokens do usuário
            await this.db.query(
                'UPDATE password_reset_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE',
                [tokenData.user_id]
            );

            this.enviarResposta('ResetPasswordResponse', {
                success: true,
                message: 'Senha alterada com sucesso!'
            });

        } catch (error) {
            console.error('Erro ao redefinir senha:', error);
            this.enviarResposta('ResetPasswordResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleGetProducts() {
        try {
            const usuario = await this.validarToken();


            if (!usuario) {
                return this.enviarResposta('GetProductsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const category = data.category;

            // Query base
            let query = `SELECT products.*, COUNT(DISTINCT orders.id) as sales_count, COALESCE(SUM(orders.net_amount), 0) as total_revenue, COALESCE(AVG(orders.net_amount), 0) as average_order_value FROM products LEFT JOIN orders ON products.id = orders.product_id AND orders.payment_status = 'paid' WHERE products.user_id = ?`;
            const queryParams = [usuario.id];

            // Filtrar por categoria se especificado
            if (category && category !== 'todos') {
                query += ` AND products.category = ?`;
                queryParams.push(category);
            }

            query += `
GROUP BY products.id
ORDER BY products.created_at DESC
        `;

            const products = await this.db.query(query, queryParams);

            // Buscar dados adicionais para cada produto
            const productsWithDetails = await Promise.all(products.map(async (product) => {
                // Contar ofertas ativas
                const offers = await this.db.query(
                    `SELECT COUNT(*) as count FROM product_offers WHERE product_id = ? AND status = 'ativo'`,
                    [product.id]
                );

                // Buscar último pedido
                const lastOrder = await this.db.query(
                    `SELECT paid_at FROM orders WHERE product_id = ? AND payment_status = 'paid' ORDER BY paid_at DESC LIMIT 1`,
                    [product.id]
                );

                return {
                    ...product,
                    offers_count: offers[0]?.count || 0,
                    last_sale: lastOrder[0]?.paid_at || null,
                    sales_count: parseInt(product.sales_count) || 0,
                    total_revenue: parseFloat(product.total_revenue) || 0,
                    average_order_value: parseFloat(product.average_order_value) || 0
                };
            }));

            this.enviarResposta('GetProductsResponse', {
                success: true,
                data: {
                    products: productsWithDetails,
                    total: productsWithDetails.length,
                    by_category: {
                        autorais: productsWithDetails.filter(p => p.category === 'autorais').length,
                        afiliados: productsWithDetails.filter(p => p.category === 'afiliados').length,
                        coproducao: productsWithDetails.filter(p => p.category === 'coproducao').length
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar produtos:', error);
            this.enviarResposta('GetProductsResponse', {
                success: false,
                message: 'Erro ao carregar produtos'
            });
        }
    }

    async handleCreateProduct() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CreateProductResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { name, description, category, language, currency } = data;

            // Validações
            if (!name || !description || !category) {
                return this.enviarResposta('CreateProductResponse', {
                    success: false,
                    message: 'Nome, descrição e categoria são obrigatórios'
                });
            }

            if (!['autorais', 'afiliados', 'coproducao'].includes(category)) {
                return this.enviarResposta('CreateProductResponse', {
                    success: false,
                    message: 'Categoria inválida'
                });
            }

            // Inserir produto
            const result = await this.db.query(
                `INSERT INTO products (user_id, name, description, category, language, currency, status, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?, 'ativo', NOW(), NOW())`,
                [usuario.id, name, description, category, language || 'pt-br', currency || 'BRL']
            );

            // Buscar produto criado
            const newProduct = await this.db.query(
                `SELECT * FROM products WHERE id = ?`,
                [result.insertId]
            );

            const product = {
                ...newProduct[0],
                sales_count: 0,
                total_revenue: 0,
                average_order_value: 0,
                offers_count: 0,
                last_sale: null
            };

            this.enviarResposta('CreateProductResponse', {
                success: true,
                data: { product },
                message: 'Produto criado com sucesso'
            });

            // Emitir evento para outros usuários (se necessário)
            // this.broadcastToUser(usuario.id, 'new_product', product);

        } catch (error) {
            console.error('Erro ao criar produto:', error);
            this.enviarResposta('CreateProductResponse', {
                success: false,
                message: 'Erro ao criar produto'
            });
        }
    }

    async handleUpdateProduct() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateProductResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { product_id, ...updateFields } = data;

            if (!product_id) {
                return this.enviarResposta('UpdateProductResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            // Verificar se o produto existe e pertence ao usuário
            const existingProduct = await this.db.query(
                `SELECT * FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            if (existingProduct.length === 0) {
                return this.enviarResposta('UpdateProductResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            // Construir query de update dinamicamente
            const allowedFields = ['name', 'description', 'category', 'language', 'currency', 'status'];
            const updateData = {};
            const queryParams = [];

            Object.keys(updateFields).forEach(field => {
                if (allowedFields.includes(field) && updateFields[field] !== undefined) {
                    updateData[field] = updateFields[field];
                    queryParams.push(updateFields[field]);
                }
            });

            if (queryParams.length === 0) {
                return this.enviarResposta('UpdateProductResponse', {
                    success: false,
                    message: 'Nenhum campo válido para atualizar'
                });
            }

            // Construir SQL
            const setClauses = Object.keys(updateData).map(field => `${field} = ?`).join(', ');
            queryParams.push(product_id, usuario.id);

            await this.db.query(
                `UPDATE products SET ${setClauses}, updated_at = NOW() WHERE id = ? AND user_id = ?`,
                queryParams
            );

            // Buscar produto atualizado
            const updatedProduct = await this.db.query(
                `SELECT * FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            this.enviarResposta('UpdateProductResponse', {
                success: true,
                data: { product: updatedProduct[0] },
                message: 'Produto atualizado com sucesso'
            });

            // Emitir evento de atualização
            // this.broadcastToUser(usuario.id, 'product_updated', updatedProduct[0]);

        } catch (error) {
            console.error('Erro ao atualizar produto:', error);
            this.enviarResposta('UpdateProductResponse', {
                success: false,
                message: 'Erro ao atualizar produto'
            });
        }
    }

    async handleDeleteProduct() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('DeleteProductResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data
            const { product_id } = data;

            if (!product_id) {
                return this.enviarResposta('DeleteProductResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            // Verificar se o produto existe e pertence ao usuário
            const existingProduct = await this.db.query(
                `SELECT * FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            if (existingProduct.length === 0) {
                return this.enviarResposta('DeleteProductResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            // Verificar se há pedidos associados
            const hasOrders = await this.db.query(
                `SELECT COUNT(*) as count FROM orders WHERE product_id = ?`,
                [product_id]
            );

            if (hasOrders[0].count > 0) {
                // Se há pedidos, apenas inativar o produto
                await this.db.query(
                    `UPDATE products SET status = 'inativo', updated_at = NOW() WHERE id = ? AND user_id = ?`,
                    [product_id, usuario.id]
                );

                this.enviarResposta('DeleteProductResponse', {
                    success: true,
                    message: 'Produto inativado (possui vendas associadas)',
                    data: { inactivated: true }
                });
            } else {
                // Se não há pedidos, deletar completamente
                await this.db.query(
                    `DELETE FROM products WHERE id = ? AND user_id = ?`,
                    [product_id, usuario.id]
                );

                this.enviarResposta('DeleteProductResponse', {
                    success: true,
                    message: 'Produto removido com sucesso',
                    data: { deleted: true }
                });
            }

            // Emitir evento de remoção
            // this.broadcastToUser(usuario.id, 'product_deleted', { product_id });

        } catch (error) {
            console.error('Erro ao deletar produto:', error);
            this.enviarResposta('DeleteProductResponse', {
                success: false,
                message: 'Erro ao remover produto'
            });
        }
    }

    async handleGetProductDetails() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetProductDetailsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data
            const { product_id } = data;

            if (!product_id) {
                return this.enviarResposta('GetProductDetailsResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            // Buscar produto com detalhes completos
            const product = await this.db.query(
                `SELECT * FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            if (product.length === 0) {
                return this.enviarResposta('GetProductDetailsResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            // Buscar ofertas
            const offers = await this.db.query(
                `SELECT * FROM product_offers WHERE product_id = ? ORDER BY created_at DESC`,
                [product_id]
            );

            // Buscar configurações de checkout
            const checkoutSettings = await this.db.query(
                `SELECT * FROM product_checkout_settings WHERE product_id = ?`,
                [product_id]
            );

            // Buscar pixels de rastreamento
            const trackingPixels = await this.db.query(
                `SELECT * FROM product_tracking_pixels WHERE product_id = ? ORDER BY created_at DESC`,
                [product_id]
            );

            // Buscar funnels (upsell/downsell)
            const funnels = await this.db.query(
                `SELECT * FROM product_funnels WHERE product_id = ? ORDER BY created_at DESC`,
                [product_id]
            );

            // Buscar cupons
            const coupons = await this.db.query(
                `SELECT * FROM product_coupons WHERE product_id = ? ORDER BY created_at DESC`,
                [product_id]
            );

            // Buscar estatísticas
            const stats = await this.db.query(
                `SELECT 
   COUNT(DISTINCT orders.id) as total_sales,
   COALESCE(SUM(orders.net_amount), 0) as total_revenue,
   COALESCE(AVG(orders.net_amount), 0) as average_order_value,
   COUNT(DISTINCT DATE(orders.paid_at)) as sales_days
FROM orders
WHERE orders.product_id = ? AND orders.payment_status = 'paid'`,
                [product_id]
            );

            const productDetails = {
                ...product[0],
                offers: offers,
                checkout_settings: checkoutSettings[0] || null,
                tracking_pixels: trackingPixels,
                funnels: funnels,
                coupons: coupons,
                stats: {
                    total_sales: parseInt(stats[0]?.total_sales) || 0,
                    total_revenue: parseFloat(stats[0]?.total_revenue) || 0,
                    average_order_value: parseFloat(stats[0]?.average_order_value) || 0,
                    sales_days: parseInt(stats[0]?.sales_days) || 0
                }
            };

            this.enviarResposta('GetProductDetailsResponse', {
                success: true,
                data: { product: productDetails }
            });

        } catch (error) {
            console.error('Erro ao buscar detalhes do produto:', error);
            this.enviarResposta('GetProductDetailsResponse', {
                success: false,
                message: 'Erro ao carregar detalhes do produto'
            });
        }
    }

    async handleGetOffers() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetOffersResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { product_id } = data;

            if (!product_id) {
                return this.enviarResposta('GetOffersResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            const productOwnership = await this.db.query(
                `SELECT id FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            if (productOwnership.length === 0) {
                return this.enviarResposta('GetOffersResponse', {
                    success: false,
                    message: 'Produto não encontrado ou não pertence ao usuário'
                });
            }

            const offers = await this.db.query(
                `SELECT 
                product_offers.id,
                product_offers.product_id,
                product_offers.name,
                product_offers.price,
                product_offers.discount_price,
                product_offers.status,
                product_offers.sort_order,
                product_offers.created_at,
                product_offers.updated_at,
                COUNT(DISTINCT orders.id) AS sales_count,
                COALESCE(SUM(CASE WHEN orders.payment_status = 'paid' THEN orders.net_amount ELSE 0 END), 0) AS total_revenue,
                COALESCE(AVG(CASE WHEN orders.payment_status = 'paid' THEN orders.net_amount ELSE NULL END), 0) AS avg_order_value
            FROM product_offers
            LEFT JOIN orders 
                ON product_offers.product_id = orders.product_id 
                AND product_offers.price = orders.amount 
                AND orders.payment_status = 'paid'
            WHERE product_offers.product_id = ?
            GROUP BY product_offers.id
            ORDER BY product_offers.sort_order ASC, product_offers.created_at DESC`,
                [product_id]
            );

            const offersWithStats = offers.map(offer => ({
                ...offer,
                sales_count: parseInt(offer.sales_count) || 0,
                total_revenue: parseFloat(offer.total_revenue) || 0,
                avg_order_value: parseFloat(offer.avg_order_value) || 0,
                conversion_rate: this.calculateConversionRate(offer.sales_count, product_id),
                discount_percentage: offer.discount_price ?
                    Math.round(((offer.price - offer.discount_price) / offer.price) * 100) : 0
            }));

            this.enviarResposta('GetOffersResponse', {
                success: true,
                data: {
                    offers: offersWithStats,
                    total: offersWithStats.length,
                    active_offers: offersWithStats.filter(o => o.status === 'ativo').length
                }
            });

        } catch (error) {
            console.error('Erro ao buscar ofertas:', error);
            this.enviarResposta('GetOffersResponse', {
                success: false,
                message: 'Erro ao carregar ofertas'
            });
        }
    }

    async handleCreateOffer() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CreateOfferResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { product_id, name, price, discount_price, status } = data;

            if (!product_id || !name || !price) {
                return this.enviarResposta('CreateOfferResponse', {
                    success: false,
                    message: 'Produto, nome e preço são obrigatórios'
                });
            }

            if (parseFloat(price) <= 0) {
                return this.enviarResposta('CreateOfferResponse', {
                    success: false,
                    message: 'Preço deve ser maior que zero'
                });
            }

            if (discount_price && parseFloat(discount_price) >= parseFloat(price)) {
                return this.enviarResposta('CreateOfferResponse', {
                    success: false,
                    message: 'Preço com desconto deve ser menor que o preço original'
                });
            }

            const productOwnership = await this.db.query(
                `SELECT id FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            if (productOwnership.length === 0) {
                return this.enviarResposta('CreateOfferResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const maxOrder = await this.db.query(
                `SELECT COALESCE(MAX(sort_order), 0) as max_order FROM product_offers WHERE product_id = ?`,
                [product_id]
            );

            const sortOrder = (maxOrder[0]?.max_order || 0) + 1;

            const result = await this.db.query(
                `INSERT INTO product_offers (product_id, name, price, discount_price, status, sort_order, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [product_id, name, parseFloat(price), discount_price ? parseFloat(discount_price) : null, status || 'ativo', sortOrder]
            );

            const newOffer = await this.db.query(
                `SELECT * FROM product_offers WHERE id = ?`,
                [result.insertId]
            );

            const offer = {
                ...newOffer[0],
                sales_count: 0,
                total_revenue: 0,
                avg_order_value: 0,
                conversion_rate: 0,
                discount_percentage: discount_price ?
                    Math.round(((parseFloat(price) - parseFloat(discount_price)) / parseFloat(price)) * 100) : 0
            };

            this.enviarResposta('CreateOfferResponse', {
                success: true,
                data: { offer },
                message: 'Oferta criada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao criar oferta:', error);
            this.enviarResposta('CreateOfferResponse', {
                success: false,
                message: 'Erro ao criar oferta'
            });
        }
    }

    async handleUpdateOffer() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) return this.enviarResposta('UpdateOfferResponse', { success: false, message: 'Usuário não autenticado' });

            const data = this.data;
            const { offer_id, name, price, discount_price, status } = data;

            if (!offer_id) return this.enviarResposta('UpdateOfferResponse', { success: false, message: 'ID da oferta é obrigatório' });

            const offerOwnership = await this.db.query(
                `SELECT product_offers.* FROM product_offers JOIN products ON product_offers.product_id = products.id WHERE product_offers.id = ? AND products.user_id = ?`,
                [offer_id, usuario.id]
            );

            if (offerOwnership.length === 0) return this.enviarResposta('UpdateOfferResponse', { success: false, message: 'Oferta não encontrada' });

            if (price && parseFloat(price) <= 0) return this.enviarResposta('UpdateOfferResponse', { success: false, message: 'Preço deve ser maior que zero' });

            if (discount_price && price && parseFloat(discount_price) >= parseFloat(price)) {
                return this.enviarResposta('UpdateOfferResponse', {
                    success: false,
                    message: 'Preço com desconto deve ser menor que o preço original'
                });
            }

            const updates = [];
            const values = [];
            if (name !== undefined) { updates.push('name = ?'); values.push(name); }
            if (price !== undefined) { updates.push('price = ?'); values.push(parseFloat(price)); }
            if (discount_price !== undefined) { updates.push('discount_price = ?'); values.push(discount_price ? parseFloat(discount_price) : null); }
            if (status !== undefined) { updates.push('status = ?'); values.push(status); }

            if (updates.length === 0) return this.enviarResposta('UpdateOfferResponse', { success: false, message: 'Nenhum campo para atualizar' });

            values.push(offer_id);
            await this.db.query(`UPDATE product_offers SET ${updates.join(', ')} WHERE id = ?`, values);

            const updatedOffer = await this.db.query(
                `SELECT product_offers.*, COUNT(DISTINCT orders.id) as sales_count, COALESCE(SUM(CASE WHEN orders.payment_status = 'paid' THEN orders.net_amount ELSE 0 END), 0) as total_revenue
             FROM product_offers
             LEFT JOIN orders ON product_offers.product_id = orders.product_id AND product_offers.price = orders.amount AND orders.payment_status = 'paid'
             WHERE product_offers.id = ?
             GROUP BY product_offers.id`,
                [offer_id]
            );

            const offer = {
                ...updatedOffer[0],
                sales_count: parseInt(updatedOffer[0].sales_count) || 0,
                total_revenue: parseFloat(updatedOffer[0].total_revenue) || 0,
                conversion_rate: this.calculateConversionRate(updatedOffer[0].sales_count, updatedOffer[0].product_id),
                discount_percentage: updatedOffer[0].discount_price ?
                    Math.round(((updatedOffer[0].price - updatedOffer[0].discount_price) / updatedOffer[0].price) * 100) : 0
            };

            this.enviarResposta('UpdateOfferResponse', {
                success: true,
                data: { offer },
                message: 'Oferta atualizada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar oferta:', error);
            this.enviarResposta('UpdateOfferResponse', {
                success: false,
                message: 'Erro ao atualizar oferta'
            });
        }
    }

    async handleDeleteOffer() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) return this.enviarResposta('DeleteOfferResponse', { success: false, message: 'Usuário não autenticado' });

            const data = this.data;
            const { offer_id } = data;

            if (!offer_id) return this.enviarResposta('DeleteOfferResponse', { success: false, message: 'ID da oferta é obrigatório' });

            const offerOwnership = await this.db.query(
                `SELECT product_offers.*, products.user_id FROM product_offers JOIN products ON product_offers.product_id = products.id WHERE product_offers.id = ? AND products.user_id = ?`,
                [offer_id, usuario.id]
            );

            if (offerOwnership.length === 0) return this.enviarResposta('DeleteOfferResponse', { success: false, message: 'Oferta não encontrada' });

            const offer = offerOwnership[0];

            const hasOrders = await this.db.query(
                `SELECT COUNT(*) as count FROM orders WHERE product_id = ? AND amount = ? AND payment_status IN ('paid', 'pending')`,
                [offer.product_id, offer.price]
            );

            if (hasOrders[0].count > 0) {
                await this.db.query(`UPDATE product_offers SET status = 'inativo' WHERE id = ?`, [offer_id]);
                this.enviarResposta('DeleteOfferResponse', { success: true, message: 'Oferta inativada (possui vendas associadas)', data: { inactivated: true, offer_id } });
            } else {
                await this.db.query(`DELETE FROM product_offers WHERE id = ?`, [offer_id]);
                this.enviarResposta('DeleteOfferResponse', { success: true, message: 'Oferta removida com sucesso', data: { deleted: true, offer_id } });
            }
        } catch (error) {
            console.error('Erro ao deletar oferta:', error);
            this.enviarResposta('DeleteOfferResponse', { success: false, message: 'Erro ao remover oferta' });
        }
    }

    async handleReorderOffers() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) return this.enviarResposta('ReorderOffersResponse', { success: false, message: 'Usuário não autenticado' });

            const data = this.data;
            const { product_id, offer_ids } = data;

            if (!product_id || !Array.isArray(offer_ids)) return this.enviarResposta('ReorderOffersResponse', { success: false, message: 'Dados inválidos para reordenação' });

            const productOwnership = await this.db.query(`SELECT id FROM products WHERE id = ? AND user_id = ?`, [product_id, usuario.id]);
            if (productOwnership.length === 0) return this.enviarResposta('ReorderOffersResponse', { success: false, message: 'Produto não encontrado' });

            let ordem = 1;
            for (const offer_id of offer_ids) {
                await this.db.query(`UPDATE product_offers SET name = name WHERE id = ? AND product_id = ?`, [offer_id, product_id]);
                ordem++;
            }

            this.enviarResposta('ReorderOffersResponse', { success: true, message: 'Reordenação registrada (simulada)', data: { product_id, offer_ids } });
        } catch (error) {
            console.error('Erro ao reordenar ofertas:', error);
            this.enviarResposta('ReorderOffersResponse', { success: false, message: 'Erro ao reordenar ofertas' });
        }
    }

    calculateConversionRate(sales_count, product_id) {
        // Aqui você implementaria a lógica real baseada em analytics
        // Por exemplo, calculando com base em visitantes únicos
        if (sales_count === 0) return 0;
        return Math.min(Math.random() * 5 + 1, 10); // Simulated 1-10%
    }

    async handleGetCheckoutSettings() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('GetCheckoutSettingsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { product_id } = this.data;
            if (!product_id) {
                return this.enviarResposta('GetCheckoutSettingsResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            const productOwnership = await this.db.query(
                `SELECT id, name FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );
            if (productOwnership.length === 0) {
                return this.enviarResposta('GetCheckoutSettingsResponse', {
                    success: false,
                    message: 'Produto não encontrado ou não pertence ao usuário'
                });
            }

            let settingsResult = await this.db.query(
                `SELECT * FROM product_checkout_settings WHERE product_id = ?`,
                [product_id]
            );

            if (settingsResult.length === 0) {
                const defaultSettings = {
                    product_id,
                    checkout_type: 'simples',
                    custom_fields: '[]',
                    thank_you_page: `Obrigado por adquirir o ${productOwnership[0].name}! Você receberá o acesso em até 24 horas no seu email.`,
                    redirect_url: null,
                    design_template: 'moderno',
                    payment_methods: '["pix","credit_card","boleto"]',
                    auto_redirect: false,
                    redirect_delay: 5,
                    collect_phone: true,
                    collect_cpf: false,
                    collect_address: false,
                    terms_required: true,
                    newsletter_optin: false
                };

                await this.db.query(
                    `INSERT INTO product_checkout_settings 
                 (product_id, checkout_type, custom_fields, thank_you_page, redirect_url, design_template, payment_methods, 
                  auto_redirect, redirect_delay, collect_phone, collect_cpf, collect_address, terms_required, newsletter_optin, 
                  created_at, updated_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                    Object.values(defaultSettings)
                );

                settingsResult = await this.db.query(
                    `SELECT * FROM product_checkout_settings WHERE product_id = ?`,
                    [product_id]
                );
            }

            const settings = settingsResult[0];
            const processedSettings = {
                ...settings,
                custom_fields: JSON.parse(settings.custom_fields || '[]'),
                payment_methods: JSON.parse(settings.payment_methods || '[]')
            };

            const conversionStats = await this.db.query(
                `SELECT 
                COUNT(CASE WHEN payment_status = 'paid' THEN 1 END) as completed_orders,
                COUNT(CASE WHEN payment_status = 'pending' THEN 1 END) as pending_orders,
                COUNT(CASE WHEN payment_status = 'failed' THEN 1 END) as failed_orders,
                COUNT(*) as total_attempts,
                ROUND((COUNT(CASE WHEN payment_status = 'paid' THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0)), 2) as conversion_rate
             FROM orders 
             WHERE product_id = ? 
             AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)`,
                [product_id]
            );

            const stats = conversionStats[0] || {};
            this.enviarResposta('GetCheckoutSettingsResponse', {
                success: true,
                data: {
                    settings: processedSettings,
                    product: productOwnership[0],
                    stats: {
                        completed_orders: parseInt(stats.completed_orders) || 0,
                        pending_orders: parseInt(stats.pending_orders) || 0,
                        failed_orders: parseInt(stats.failed_orders) || 0,
                        total_attempts: parseInt(stats.total_attempts) || 0,
                        conversion_rate: parseFloat(stats.conversion_rate) || 0
                    }
                }
            });
        } catch (error) {
            console.error('Erro ao buscar configurações do checkout:', error);
            this.enviarResposta('GetCheckoutSettingsResponse', {
                success: false,
                message: 'Erro ao carregar configurações do checkout'
            });
        }
    }

    async handleUpdateCheckoutSettings() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('UpdateCheckoutSettingsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { product_id, settings } = this.data;
            if (!product_id || !settings) {
                return this.enviarResposta('UpdateCheckoutSettingsResponse', {
                    success: false,
                    message: 'ID do produto e configurações são obrigatórios'
                });
            }

            const productOwnership = await this.db.query(
                `SELECT id FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );
            if (productOwnership.length === 0) {
                return this.enviarResposta('UpdateCheckoutSettingsResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const updateFields = [];
            const updateValues = [];

            const allowed = [
                'checkout_type', 'thank_you_page', 'redirect_url', 'design_template',
                'auto_redirect', 'redirect_delay', 'collect_phone', 'collect_cpf',
                'collect_address', 'terms_required', 'newsletter_optin'
            ];

            for (const key of allowed) {
                if (settings[key] !== undefined) {
                    updateFields.push(`${key} = ?`);
                    updateValues.push(settings[key]);
                }
            }

            if (settings.custom_fields !== undefined) {
                updateFields.push('custom_fields = ?');
                updateValues.push(JSON.stringify(settings.custom_fields || []));
            }

            if (settings.payment_methods !== undefined) {
                updateFields.push('payment_methods = ?');
                updateValues.push(JSON.stringify(settings.payment_methods || []));
            }

            if (updateFields.length === 0) {
                return this.enviarResposta('UpdateCheckoutSettingsResponse', {
                    success: false,
                    message: 'Nenhum campo válido para atualizar'
                });
            }

            updateFields.push('updated_at = NOW()');
            updateValues.push(product_id);

            await this.db.query(
                `UPDATE product_checkout_settings SET ${updateFields.join(', ')} WHERE product_id = ?`,
                updateValues
            );

            const updated = await this.db.query(
                `SELECT * FROM product_checkout_settings WHERE product_id = ?`,
                [product_id]
            );

            this.enviarResposta('UpdateCheckoutSettingsResponse', {
                success: true,
                data: {
                    settings: {
                        ...updated[0],
                        custom_fields: JSON.parse(updated[0].custom_fields || '[]'),
                        payment_methods: JSON.parse(updated[0].payment_methods || '[]')
                    }
                },
                message: 'Configurações do checkout atualizadas com sucesso'
            });
        } catch (error) {
            console.error('Erro ao atualizar configurações do checkout:', error);
            this.enviarResposta('UpdateCheckoutSettingsResponse', {
                success: false,
                message: 'Erro ao atualizar configurações do checkout'
            });
        }
    }

    async handleAddCustomField() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { product_id, field } = this.data;
            if (!product_id || !field) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'ID do produto e dados do campo são obrigatórios'
                });
            }

            if (!field.name || !field.label || !field.type) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'Nome, label e tipo do campo são obrigatórios'
                });
            }

            const allowedTypes = ['text', 'email', 'tel', 'select', 'textarea', 'checkbox'];
            if (!allowedTypes.includes(field.type)) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'Tipo de campo inválido'
                });
            }

            const product = await this.db.query(
                `SELECT id FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );
            if (product.length === 0) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const result = await this.db.query(
                `SELECT custom_fields FROM product_checkout_settings WHERE product_id = ?`,
                [product_id]
            );
            if (result.length === 0) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'Configurações do checkout não encontradas'
                });
            }

            const customFields = JSON.parse(result[0].custom_fields || '[]');

            if (customFields.some(f => f.name === field.name)) {
                return this.enviarResposta('AddCustomFieldResponse', {
                    success: false,
                    message: 'Já existe um campo com este nome'
                });
            }

            const newField = {
                id: Date.now(),
                name: field.name,
                label: field.label,
                type: field.type,
                required: Boolean(field.required),
                placeholder: field.placeholder || '',
                options: field.options || []
            };

            customFields.push(newField);

            await this.db.query(
                `UPDATE product_checkout_settings SET custom_fields = ?, updated_at = NOW() WHERE product_id = ?`,
                [JSON.stringify(customFields), product_id]
            );

            this.enviarResposta('AddCustomFieldResponse', {
                success: true,
                data: { field: newField, custom_fields: customFields },
                message: 'Campo personalizado adicionado com sucesso'
            });

        } catch (error) {
            console.error('Erro ao adicionar campo personalizado:', error);
            this.enviarResposta('AddCustomFieldResponse', {
                success: false,
                message: 'Erro ao adicionar campo personalizado'
            });
        }
    }

    async handleRemoveCustomField() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('RemoveCustomFieldResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { product_id, field_id } = this.data;
            if (!product_id || !field_id) {
                return this.enviarResposta('RemoveCustomFieldResponse', {
                    success: false,
                    message: 'ID do produto e ID do campo são obrigatórios'
                });
            }

            const product = await this.db.query(
                `SELECT id FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );
            if (product.length === 0) {
                return this.enviarResposta('RemoveCustomFieldResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const result = await this.db.query(
                `SELECT custom_fields FROM product_checkout_settings WHERE product_id = ?`,
                [product_id]
            );
            if (result.length === 0) {
                return this.enviarResposta('RemoveCustomFieldResponse', {
                    success: false,
                    message: 'Configurações do checkout não encontradas'
                });
            }

            const currentFields = JSON.parse(result[0].custom_fields || '[]');
            const updatedFields = currentFields.filter(field => field.id != field_id);

            if (currentFields.length === updatedFields.length) {
                return this.enviarResposta('RemoveCustomFieldResponse', {
                    success: false,
                    message: 'Campo não encontrado'
                });
            }

            await this.db.query(
                `UPDATE product_checkout_settings SET custom_fields = ?, updated_at = NOW() WHERE product_id = ?`,
                [JSON.stringify(updatedFields), product_id]
            );

            this.enviarResposta('RemoveCustomFieldResponse', {
                success: true,
                data: { custom_fields: updatedFields },
                message: 'Campo personalizado removido com sucesso'
            });

        } catch (error) {
            console.error('Erro ao remover campo personalizado:', error);
            this.enviarResposta('RemoveCustomFieldResponse', {
                success: false,
                message: 'Erro ao remover campo personalizado'
            });
        }
    }

    async handlePreviewCheckout() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('PreviewCheckoutResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { product_id } = this.data;
            if (!product_id) {
                return this.enviarResposta('PreviewCheckoutResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            const productData = await this.db.query(
                `SELECT * FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            const settingsData = await this.db.query(
                `SELECT * FROM product_checkout_settings WHERE product_id = ?`,
                [product_id]
            );

            if (productData.length === 0) {
                return this.enviarResposta('PreviewCheckoutResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const offers = await this.db.query(
                `SELECT * FROM product_offers WHERE product_id = ? AND status = 'ativo' ORDER BY sort_order ASC`,
                [product_id]
            );

            const product = productData[0];
            const settings = settingsData[0] || {};

            this.enviarResposta('PreviewCheckoutResponse', {
                success: true,
                data: {
                    product: {
                        id: product.id,
                        name: product.name,
                        description: product.description
                    },
                    offers,
                    settings: {
                        checkout_type: settings.checkout_type || 'simples',
                        custom_fields: JSON.parse(settings.custom_fields || '[]'),
                        payment_methods: JSON.parse(settings.payment_methods || '["pix","credit_card"]'),
                        design_template: settings.design_template || 'moderno',
                        collect_phone: !!settings.collect_phone,
                        collect_cpf: !!settings.collect_cpf,
                        collect_address: !!settings.collect_address,
                        terms_required: !!settings.terms_required,
                        newsletter_optin: !!settings.newsletter_optin
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao gerar preview do checkout:', error);
            this.enviarResposta('PreviewCheckoutResponse', {
                success: false,
                message: 'Erro ao gerar preview do checkout'
            });
        }
    }

    async handleGetFunnels() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetFunnelsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const productId = data.product_id;

            // Query base para buscar funis
            let query = `SELECT * FROM product_funnels WHERE user_id = ?`;
            const queryParams = [usuario.id];

            // Filtrar por produto específico se informado
            if (productId) {
                query += ` AND product_id = ?`;
                queryParams.push(productId);
            }

            query += ` ORDER BY created_at DESC`;

            const funnels = await this.db.query(query, queryParams);

            // Buscar produtos disponíveis para upsell/downsell
            const availableProducts = await this.db.query(
                `SELECT id, name, category, currency FROM products WHERE user_id = ? AND status = 'ativo' ORDER BY name`,
                [usuario.id]
            );

            // Buscar estatísticas de cada funil
            const funnelsWithStats = await Promise.all(funnels.map(async (funnel) => {
                const stats = await this.db.query(
                    `SELECT 
                    COUNT(*) as total_steps,
                    COALESCE(SUM(conversions), 0) as total_conversions,
                    COALESCE(SUM(revenue), 0) as total_revenue,
                    COALESCE(SUM(views), 0) as total_views
                FROM funnel_steps 
                WHERE funnel_id = ?`,
                    [funnel.id]
                );

                return {
                    ...funnel,
                    total_conversions: parseInt(stats[0]?.total_conversions) || 0,
                    total_revenue: parseFloat(stats[0]?.total_revenue) || 0,
                    total_views: parseInt(stats[0]?.total_views) || 0,
                    total_steps: parseInt(stats[0]?.total_steps) || 0
                };
            }));

            this.enviarResposta('GetFunnelsResponse', {
                success: true,
                data: {
                    funnels: funnelsWithStats,
                    availableProducts: availableProducts
                }
            });

        } catch (error) {
            console.error('Erro ao buscar funis:', error);
            this.enviarResposta('GetFunnelsResponse', {
                success: false,
                message: 'Erro ao carregar funis'
            });
        }
    }

    async handleCreateFunnel() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CreateFunnelResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const {
                product_id,
                name,
                description,
                trigger_condition,
                payment_methods,
                settings,
                status = 'rascunho'
            } = data;

            // Validações
            if (!product_id || !name) {
                return this.enviarResposta('CreateFunnelResponse', {
                    success: false,
                    message: 'ID do produto e nome são obrigatórios'
                });
            }

            // Verificar se o produto existe e pertence ao usuário
            const product = await this.db.query(
                `SELECT * FROM products WHERE id = ? AND user_id = ?`,
                [product_id, usuario.id]
            );

            if (product.length === 0) {
                return this.enviarResposta('CreateFunnelResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            // Inserir funil
            const result = await this.db.query(
                `INSERT INTO product_funnels 
             (user_id, product_id, name, description, status, trigger_condition, payment_methods, settings, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    usuario.id,
                    product_id,
                    name,
                    description,
                    status,
                    trigger_condition || 'after_purchase',
                    JSON.stringify(payment_methods || ['pix', 'credit_card', 'boleto']),
                    JSON.stringify(settings || {})
                ]
            );

            // Buscar funil criado
            const newFunnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ?`,
                [result.insertId]
            );

            const funnel = {
                ...newFunnel[0],
                total_conversions: 0,
                total_revenue: 0,
                total_views: 0,
                total_steps: 0
            };

            this.enviarResposta('CreateFunnelResponse', {
                success: true,
                data: { funnel },
                message: 'Funil criado com sucesso'
            });

        } catch (error) {
            console.error('Erro ao criar funil:', error);
            this.enviarResposta('CreateFunnelResponse', {
                success: false,
                message: 'Erro ao criar funil'
            });
        }
    }

    async handleUpdateFunnel() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateFunnelResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { funnel_id, ...updateFields } = data;

            if (!funnel_id) {
                return this.enviarResposta('UpdateFunnelResponse', {
                    success: false,
                    message: 'ID do funil é obrigatório'
                });
            }

            // Verificar se o funil existe e pertence ao usuário
            const existingFunnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (existingFunnel.length === 0) {
                return this.enviarResposta('UpdateFunnelResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Construir query de update dinamicamente
            const allowedFields = ['name', 'description', 'status', 'trigger_condition', 'payment_methods', 'settings', 'redirect_url'];
            const updateData = {};
            const queryParams = [];

            Object.keys(updateFields).forEach(field => {
                if (allowedFields.includes(field) && updateFields[field] !== undefined) {
                    if (field === 'payment_methods' || field === 'settings') {
                        updateData[field] = JSON.stringify(updateFields[field]);
                    } else {
                        updateData[field] = updateFields[field];
                    }
                    queryParams.push(updateData[field]);
                }
            });

            if (queryParams.length === 0) {
                return this.enviarResposta('UpdateFunnelResponse', {
                    success: false,
                    message: 'Nenhum campo válido para atualizar'
                });
            }

            // Construir SQL
            const setClauses = Object.keys(updateData).map(field => `${field} = ?`).join(', ');
            queryParams.push(funnel_id, usuario.id);

            await this.db.query(
                `UPDATE product_funnels SET ${setClauses}, updated_at = NOW() WHERE id = ? AND user_id = ?`,
                queryParams
            );

            // Buscar funil atualizado
            const updatedFunnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            this.enviarResposta('UpdateFunnelResponse', {
                success: true,
                data: { funnel: updatedFunnel[0] },
                message: 'Funil atualizado com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar funil:', error);
            this.enviarResposta('UpdateFunnelResponse', {
                success: false,
                message: 'Erro ao atualizar funil'
            });
        }
    }

    async handleDeleteFunnel() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('DeleteFunnelResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { funnel_id } = data;

            if (!funnel_id) {
                return this.enviarResposta('DeleteFunnelResponse', {
                    success: false,
                    message: 'ID do funil é obrigatório'
                });
            }

            // Verificar se o funil existe e pertence ao usuário
            const existingFunnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (existingFunnel.length === 0) {
                return this.enviarResposta('DeleteFunnelResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Deletar funil (CASCADE irá remover etapas, analytics, etc.)
            await this.db.query(
                `DELETE FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            this.enviarResposta('DeleteFunnelResponse', {
                success: true,
                message: 'Funil removido com sucesso'
            });

        } catch (error) {
            console.error('Erro ao deletar funil:', error);
            this.enviarResposta('DeleteFunnelResponse', {
                success: false,
                message: 'Erro ao remover funil'
            });
        }
    }

    async handleGetFunnelSteps() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetFunnelStepsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { funnel_id } = data;

            if (!funnel_id) {
                return this.enviarResposta('GetFunnelStepsResponse', {
                    success: false,
                    message: 'ID do funil é obrigatório'
                });
            }

            // Verificar se o funil pertence ao usuário
            const funnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (funnel.length === 0) {
                return this.enviarResposta('GetFunnelStepsResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Buscar etapas do funil
            const steps = await this.db.query(
                `SELECT * FROM funnel_steps WHERE funnel_id = ? ORDER BY step_order ASC`,
                [funnel_id]
            );

            this.enviarResposta('GetFunnelStepsResponse', {
                success: true,
                data: {
                    steps: steps
                }
            });

        } catch (error) {
            console.error('Erro ao buscar etapas do funil:', error);
            this.enviarResposta('GetFunnelStepsResponse', {
                success: false,
                message: 'Erro ao carregar etapas do funil'
            });
        }
    }

    async handleCreateFunnelStep() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CreateFunnelStepResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const {
                funnel_id,
                step_type,
                name,
                description,
                target_product_id,
                target_offer_id,
                discount_percentage = 0,
                fixed_discount = 0,
                special_price = 0,
                page_url,
                success_redirect_url,
                failure_redirect_url,
                conditions,
                status = 'ativo'
            } = data;

            // Validações
            if (!funnel_id || !step_type || !name) {
                return this.enviarResposta('CreateFunnelStepResponse', {
                    success: false,
                    message: 'ID do funil, tipo da etapa e nome são obrigatórios'
                });
            }

            // Verificar se o funil pertence ao usuário
            const funnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (funnel.length === 0) {
                return this.enviarResposta('CreateFunnelStepResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Definir ordem da etapa automaticamente
            const lastStep = await this.db.query(
                `SELECT MAX(step_order) as max_order FROM funnel_steps WHERE funnel_id = ?`,
                [funnel_id]
            );
            const stepOrder = (lastStep[0]?.max_order || 0) + 1;

            // Inserir etapa
            const result = await this.db.query(
                `INSERT INTO funnel_steps 
             (funnel_id, step_order, step_type, name, description, target_product_id, target_offer_id,
              discount_percentage, fixed_discount, special_price, page_url, success_redirect_url, 
              failure_redirect_url, conditions, status, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    funnel_id, stepOrder, step_type, name, description, target_product_id, target_offer_id,
                    discount_percentage, fixed_discount, special_price, page_url, success_redirect_url,
                    failure_redirect_url, JSON.stringify(conditions || {}), status
                ]
            );

            // Buscar etapa criada
            const newStep = await this.db.query(
                `SELECT * FROM funnel_steps WHERE id = ?`,
                [result.insertId]
            );

            this.enviarResposta('CreateFunnelStepResponse', {
                success: true,
                data: { step: newStep[0] },
                message: 'Etapa criada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao criar etapa do funil:', error);
            this.enviarResposta('CreateFunnelStepResponse', {
                success: false,
                message: 'Erro ao criar etapa'
            });
        }
    }

    async handleUpdateFunnelStep() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateFunnelStepResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { step_id, ...updateFields } = data;

            if (!step_id) {
                return this.enviarResposta('UpdateFunnelStepResponse', {
                    success: false,
                    message: 'ID da etapa é obrigatório'
                });
            }

            // Verificar se a etapa existe e o funil pertence ao usuário
            const existingStep = await this.db.query(
                `SELECT funnel_steps.*, product_funnels.user_id 
             FROM funnel_steps
             JOIN product_funnels ON funnel_steps.funnel_id = product_funnels.id
             WHERE funnel_steps.id = ? AND product_funnels.user_id = ?`,
                [step_id, usuario.id]
            );

            if (existingStep.length === 0) {
                return this.enviarResposta('UpdateFunnelStepResponse', {
                    success: false,
                    message: 'Etapa não encontrada'
                });
            }

            // Construir query de update dinamicamente
            const allowedFields = [
                'step_type', 'name', 'description', 'target_product_id', 'target_offer_id',
                'discount_percentage', 'fixed_discount', 'special_price', 'page_url',
                'success_redirect_url', 'failure_redirect_url', 'conditions', 'status'
            ];
            const updateData = {};
            const queryParams = [];

            Object.keys(updateFields).forEach(field => {
                if (allowedFields.includes(field) && updateFields[field] !== undefined) {
                    if (field === 'conditions') {
                        updateData[field] = JSON.stringify(updateFields[field]);
                    } else {
                        updateData[field] = updateFields[field];
                    }
                    queryParams.push(updateData[field]);
                }
            });

            if (queryParams.length === 0) {
                return this.enviarResposta('UpdateFunnelStepResponse', {
                    success: false,
                    message: 'Nenhum campo válido para atualizar'
                });
            }

            // Construir SQL
            const setClauses = Object.keys(updateData).map(field => `${field} = ?`).join(', ');
            queryParams.push(step_id);

            await this.db.query(
                `UPDATE funnel_steps SET ${setClauses}, updated_at = NOW() WHERE id = ?`,
                queryParams
            );

            // Recalcular taxa de conversão
            await this.db.query(
                `UPDATE funnel_steps 
             SET conversion_rate = CASE 
                 WHEN views > 0 THEN (conversions / views) * 100 
                 ELSE 0 
             END
             WHERE id = ?`,
                [step_id]
            );

            // Buscar etapa atualizada
            const updatedStep = await this.db.query(
                `SELECT * FROM funnel_steps WHERE id = ?`,
                [step_id]
            );

            this.enviarResposta('UpdateFunnelStepResponse', {
                success: true,
                data: { step: updatedStep[0] },
                message: 'Etapa atualizada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar etapa:', error);
            this.enviarResposta('UpdateFunnelStepResponse', {
                success: false,
                message: 'Erro ao atualizar etapa'
            });
        }
    }

    async handleDeleteFunnelStep() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('DeleteFunnelStepResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { step_id } = data;

            if (!step_id) {
                return this.enviarResposta('DeleteFunnelStepResponse', {
                    success: false,
                    message: 'ID da etapa é obrigatório'
                });
            }

            // Verificar se a etapa existe e o funil pertence ao usuário
            const existingStep = await this.db.query(
                `SELECT funnel_steps.*, product_funnels.user_id 
             FROM funnel_steps
             JOIN product_funnels ON funnel_steps.funnel_id = product_funnels.id
             WHERE funnel_steps.id = ? AND product_funnels.user_id = ?`,
                [step_id, usuario.id]
            );

            if (existingStep.length === 0) {
                return this.enviarResposta('DeleteFunnelStepResponse', {
                    success: false,
                    message: 'Etapa não encontrada'
                });
            }

            // Deletar etapa
            await this.db.query(
                `DELETE FROM funnel_steps WHERE id = ?`,
                [step_id]
            );

            this.enviarResposta('DeleteFunnelStepResponse', {
                success: true,
                message: 'Etapa removida com sucesso'
            });

        } catch (error) {
            console.error('Erro ao deletar etapa:', error);
            this.enviarResposta('DeleteFunnelStepResponse', {
                success: false,
                message: 'Erro ao remover etapa'
            });
        }
    }

    async handleGetFunnelAnalytics() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetFunnelAnalyticsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { funnel_id, date_range } = data;

            if (!funnel_id) {
                return this.enviarResposta('GetFunnelAnalyticsResponse', {
                    success: false,
                    message: 'ID do funil é obrigatório'
                });
            }

            // Verificar se o funil pertence ao usuário
            const funnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (funnel.length === 0) {
                return this.enviarResposta('GetFunnelAnalyticsResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Construir filtro de data
            let dateFilter = '';
            const queryParams = [funnel_id];

            if (date_range && date_range.start && date_range.end) {
                dateFilter = ' AND created_at BETWEEN ? AND ?';
                queryParams.push(date_range.start, date_range.end);
            }

            // Buscar analytics por etapa
            const stepAnalytics = await this.db.query(
                `SELECT 
                funnel_steps.id as step_id,
                funnel_steps.name as step_name,
                funnel_steps.step_type,
                funnel_steps.step_order,
                COUNT(CASE WHEN funnel_analytics.action_type = 'view' THEN 1 END) as views,
                COUNT(CASE WHEN funnel_analytics.action_type = 'click_yes' THEN 1 END) as yes_clicks,
                COUNT(CASE WHEN funnel_analytics.action_type = 'click_no' THEN 1 END) as no_clicks,
                COUNT(CASE WHEN funnel_analytics.action_type = 'purchase' THEN 1 END) as purchases,
                COALESCE(SUM(CASE WHEN funnel_analytics.action_type = 'purchase' THEN funnel_analytics.amount END), 0) as revenue
             FROM funnel_steps
             LEFT JOIN funnel_analytics ON funnel_steps.id = funnel_analytics.step_id ${dateFilter}
             WHERE funnel_steps.funnel_id = ?
             GROUP BY funnel_steps.id, funnel_steps.name, funnel_steps.step_type, funnel_steps.step_order
             ORDER BY funnel_steps.step_order ASC`,
                queryParams
            );

            // Buscar ações por dia (últimos 30 dias)
            const dailyAnalytics = await this.db.query(
                `SELECT 
                DATE(created_at) as date,
                COUNT(CASE WHEN action_type = 'view' THEN 1 END) as views,
                COUNT(CASE WHEN action_type = 'click_yes' THEN 1 END) as conversions,
                COALESCE(SUM(CASE WHEN action_type = 'purchase' THEN amount END), 0) as revenue
             FROM funnel_analytics
             WHERE funnel_id = ? 
             AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
             GROUP BY DATE(created_at)
             ORDER BY date DESC`,
                [funnel_id]
            );

            // Buscar top customers
            const topCustomers = await this.db.query(
                `SELECT 
                customer_email,
                COUNT(*) as interactions,
                COUNT(CASE WHEN action_type = 'purchase' THEN 1 END) as purchases,
                COALESCE(SUM(CASE WHEN action_type = 'purchase' THEN amount END), 0) as total_spent
             FROM funnel_analytics
             WHERE funnel_id = ? ${dateFilter}
             AND customer_email IS NOT NULL
             GROUP BY customer_email
             ORDER BY total_spent DESC
             LIMIT 10`,
                queryParams
            );

            this.enviarResposta('GetFunnelAnalyticsResponse', {
                success: true,
                data: {
                    analytics: {
                        step_analytics: stepAnalytics,
                        daily_analytics: dailyAnalytics,
                        top_customers: topCustomers,
                        summary: {
                            total_views: stepAnalytics.reduce((sum, step) => sum + step.views, 0),
                            total_conversions: stepAnalytics.reduce((sum, step) => sum + step.yes_clicks, 0),
                            total_revenue: stepAnalytics.reduce((sum, step) => sum + parseFloat(step.revenue), 0),
                            conversion_rate: stepAnalytics.length > 0 ?
                                (stepAnalytics.reduce((sum, step) => sum + step.yes_clicks, 0) /
                                    stepAnalytics.reduce((sum, step) => sum + step.views, 0) * 100) : 0
                        }
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar analytics do funil:', error);
            this.enviarResposta('GetFunnelAnalyticsResponse', {
                success: false,
                message: 'Erro ao carregar analytics'
            });
        }
    }

    async handleGenerateFunnelScripts() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GenerateFunnelScriptsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { funnel_id } = data;

            if (!funnel_id) {
                return this.enviarResposta('GenerateFunnelScriptsResponse', {
                    success: false,
                    message: 'ID do funil é obrigatório'
                });
            }

            // Verificar se o funil pertence ao usuário
            const funnel = await this.db.query(
                `SELECT f.*, p.name as product_name
             FROM product_funnels f
             JOIN products p ON f.product_id = p.id
             WHERE f.id = ? AND f.user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (funnel.length === 0) {
                return this.enviarResposta('GenerateFunnelScriptsResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Buscar etapas do funil
            const steps = await this.db.query(
                `SELECT * FROM funnel_steps WHERE funnel_id = ? ORDER BY step_order ASC`,
                [funnel_id]
            );

            const funnelData = funnel[0];
            const baseUrl = process.env.API_URL || 'https://api.for4gateway.com';

            // Gerar scripts
            const scripts = {
                head_script: {
                    name: 'Script HEAD',
                    description: 'Adicione este script no <head> de todas as páginas do funil',
                    code: this.generateHeadScript(funnelData, baseUrl)
                },
                tracking_script: {
                    name: 'Script de Rastreamento',
                    description: 'Script para rastrear visualizações e ações',
                    code: this.generateTrackingScript(funnelData, baseUrl)
                }
            };

            // Primeiro, limpar widgets antigos deste funil
            await this.db.query(
                `DELETE FROM funnel_widgets WHERE funnel_id = ?`,
                [funnel_id]
            );

            // Salvar scripts gerais (sem step_id específico)
            for (const [key, script] of Object.entries(scripts)) {
                const hash = require('crypto').createHash('md5').update(`${funnel_id}_${key}_${Date.now()}`).digest('hex');

                await this.db.query(
                    `INSERT INTO funnel_widgets (funnel_id, step_id, widget_type, script_content, widget_hash, created_at, updated_at)
                 VALUES (?, NULL, ?, ?, ?, NOW(), NOW())`,
                    [funnel_id, key, script.code, hash]
                );
            }

            // Gerar scripts para cada etapa
            for (const step of steps) {
                // Script do botão SIM
                const yesButtonScript = {
                    name: `Botão SIM - ${step.name}`,
                    description: `Botão para aceitar a oferta da etapa ${step.step_order}`,
                    code: this.generateYesButtonScript(step, funnelData, baseUrl)
                };

                // Script do botão NÃO
                const noButtonScript = {
                    name: `Botão NÃO - ${step.name}`,
                    description: `Botão para recusar a oferta da etapa ${step.step_order}`,
                    code: this.generateNoButtonScript(step, funnelData, baseUrl)
                };

                // Adicionar aos scripts retornados
                scripts[`step_${step.id}_yes`] = yesButtonScript;
                scripts[`step_${step.id}_no`] = noButtonScript;

                // Salvar no banco com step_id
                const yesHash = require('crypto').createHash('md5').update(`${funnel_id}_${step.id}_yes_${Date.now()}`).digest('hex');
                const noHash = require('crypto').createHash('md5').update(`${funnel_id}_${step.id}_no_${Date.now()}`).digest('hex');

                await this.db.query(
                    `INSERT INTO funnel_widgets (funnel_id, step_id, widget_type, script_content, widget_hash, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
                    [funnel_id, step.id, 'yes_button', yesButtonScript.code, yesHash]
                );

                await this.db.query(
                    `INSERT INTO funnel_widgets (funnel_id, step_id, widget_type, script_content, widget_hash, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
                    [funnel_id, step.id, 'no_button', noButtonScript.code, noHash]
                );
            }

            this.enviarResposta('GenerateFunnelScriptsResponse', {
                success: true,
                data: { scripts }
            });

        } catch (error) {
            console.error('Erro ao gerar scripts do funil:', error);
            this.enviarResposta('GenerateFunnelScriptsResponse', {
                success: false,
                message: 'Erro ao gerar scripts'
            });
        }
    }

    async handleGetFunnelAnalyticsDetailed() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('GetFunnelAnalyticsDetailedResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { funnel_id, date_range } = data;

            // Verificar se funil pertence ao usuário
            const funnel = await this.db.query(
                `SELECT * FROM product_funnels WHERE id = ? AND user_id = ?`,
                [funnel_id, usuario.id]
            );

            if (funnel.length === 0) {
                return this.enviarResposta('GetFunnelAnalyticsDetailedResponse', {
                    success: false,
                    message: 'Funil não encontrado'
                });
            }

            // Filtro de data
            let dateFilter = '';
            const queryParams = [funnel_id];

            if (date_range) {
                const days = parseInt(date_range) || 30;
                dateFilter = ' AND fa.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)';
                queryParams.push(days);
            }

            // Buscar métricas por etapa
            const stepMetrics = await this.db.query(
                `SELECT 
                fs.id,
                fs.name,
                fs.step_type,
                fs.step_order,
                COUNT(CASE WHEN fa.action_type = 'view' THEN 1 END) as views,
                COUNT(CASE WHEN fa.action_type = 'click_yes' THEN 1 END) as conversions,
                COALESCE(SUM(CASE WHEN fa.action_type = 'click_yes' THEN fa.amount END), 0) as revenue,
                CASE 
                    WHEN COUNT(CASE WHEN fa.action_type = 'view' THEN 1 END) > 0 
                    THEN (COUNT(CASE WHEN fa.action_type = 'click_yes' THEN 1 END) / COUNT(CASE WHEN fa.action_type = 'view' THEN 1 END)) * 100
                    ELSE 0 
                END as conversion_rate
            FROM funnel_steps fs
            LEFT JOIN funnel_analytics fa ON fs.id = fa.step_id ${dateFilter}
            WHERE fs.funnel_id = ?
            GROUP BY fs.id, fs.name, fs.step_type, fs.step_order
            ORDER BY fs.step_order`,
                queryParams
            );

            // Buscar dados temporais (por dia)
            const dailyMetrics = await this.db.query(
                `SELECT 
                DATE(fa.created_at) as date,
                COUNT(CASE WHEN fa.action_type = 'view' THEN 1 END) as views,
                COUNT(CASE WHEN fa.action_type = 'click_yes' THEN 1 END) as conversions,
                COALESCE(SUM(CASE WHEN fa.action_type = 'click_yes' THEN fa.amount END), 0) as revenue
            FROM funnel_analytics fa
            WHERE fa.funnel_id = ? ${dateFilter}
            GROUP BY DATE(fa.created_at)
            ORDER BY date DESC
            LIMIT 30`,
                queryParams
            );

            // Buscar top clientes
            const topCustomers = await this.db.query(
                `SELECT 
                fa.customer_email,
                COUNT(CASE WHEN fa.action_type = 'click_yes' THEN 1 END) as purchases,
                COALESCE(SUM(CASE WHEN fa.action_type = 'click_yes' THEN fa.amount END), 0) as total_spent,
                MAX(fa.created_at) as last_activity
            FROM funnel_analytics fa
            WHERE fa.funnel_id = ? ${dateFilter}
            AND fa.customer_email IS NOT NULL
            GROUP BY fa.customer_email
            HAVING purchases > 0
            ORDER BY total_spent DESC
            LIMIT 10`,
                queryParams
            );

            // Atualizar estatísticas das etapas no banco
            for (const metric of stepMetrics) {
                await this.db.query(
                    `UPDATE funnel_steps 
                 SET views = ?, conversions = ?, conversion_rate = ?, revenue = ?
                 WHERE id = ?`,
                    [metric.views, metric.conversions, metric.conversion_rate, metric.revenue, metric.id]
                );
            }

            this.enviarResposta('GetFunnelAnalyticsDetailedResponse', {
                success: true,
                data: {
                    step_metrics: stepMetrics,
                    daily_metrics: dailyMetrics,
                    top_customers: topCustomers,
                    period_days: parseInt(date_range) || 30
                }
            });

        } catch (error) {
            console.error('Erro ao buscar analytics detalhadas:', error);
            this.enviarResposta('GetFunnelAnalyticsDetailedResponse', {
                success: false,
                message: 'Erro ao carregar analytics'
            });
        }
    }

    async handleGetSales() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetSalesResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { filters, userRole, userId } = data;

            // Query base para buscar vendas
            let query = `
                SELECT 
                    o.*,
                    p.name as product_name,
                    u.name as seller_name,
                    u.email as seller_email
                FROM orders o
                LEFT JOIN products p ON o.product_id = p.id
                LEFT JOIN users u ON o.user_id = u.id
                WHERE 1=1
            `;
            const queryParams = [];

            // Filtrar por usuário baseado no papel
            if (userRole !== 'admin') {
                query += ` AND o.user_id = ?`;
                queryParams.push(userId);
            } else if (filters.userId) {
                query += ` AND o.user_id = ?`;
                queryParams.push(filters.userId);
            }

            // Aplicar filtros
            if (filters.dateStart) {
                query += ` AND DATE(o.created_at) >= ?`;
                queryParams.push(filters.dateStart);
            }

            if (filters.dateEnd) {
                query += ` AND DATE(o.created_at) <= ?`;
                queryParams.push(filters.dateEnd);
            }

            if (filters.status) {
                query += ` AND o.payment_status = ?`;
                queryParams.push(filters.status);
            }

            if (filters.paymentMethod) {
                query += ` AND o.payment_method = ?`;
                queryParams.push(filters.paymentMethod);
            }

            if (filters.productId) {
                query += ` AND o.product_id = ?`;
                queryParams.push(filters.productId);
            }

            if (filters.minAmount) {
                query += ` AND o.amount >= ?`;
                queryParams.push(parseFloat(filters.minAmount));
            }

            if (filters.maxAmount) {
                query += ` AND o.amount <= ?`;
                queryParams.push(parseFloat(filters.maxAmount));
            }

            if (filters.customerSearch) {
                query += ` AND (o.customer_name LIKE ? OR o.customer_email LIKE ?)`;
                const searchTerm = `%${filters.customerSearch}%`;
                queryParams.push(searchTerm, searchTerm);
            }

            // Ordenar por data mais recente
            query += ` ORDER BY o.created_at DESC`;

            const sales = await this.db.query(query, queryParams);

            // Buscar estatísticas
            const stats = await this.getSalesStats(filters, userRole, userId);

            this.enviarResposta('GetSalesResponse', {
                success: true,
                data: {
                    sales,
                    stats,
                    total: sales.length
                }
            });

        } catch (error) {
            console.error('Erro ao buscar vendas:', error);
            this.enviarResposta('GetSalesResponse', {
                success: false,
                message: 'Erro ao carregar vendas'
            });
        }
    }

    async handleGetSalesStats() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetSalesStatsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { filters, userRole, userId } = data;

            const stats = await this.getSalesStats(filters, userRole, userId);

            this.enviarResposta('GetSalesStatsResponse', {
                success: true,
                data: stats
            });

        } catch (error) {
            console.error('Erro ao buscar estatísticas:', error);
            this.enviarResposta('GetSalesStatsResponse', {
                success: false,
                message: 'Erro ao carregar estatísticas'
            });
        }
    }

    async handleGetUsersFilter() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetUsersFilterResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { userRole } = data;

            // Verificar se é admin
            if (userRole !== 'admin') {
                return this.enviarResposta('GetUsersFilterResponse', {
                    success: false,
                    message: 'Acesso negado. Apenas administradores podem visualizar usuários.'
                });
            }

            // Query para buscar usuários
            const query = `
            SELECT 
                id,
                name,
                email,
                role,
                created_at,
                status
            FROM users 
            WHERE status = 'active'
            ORDER BY name ASC
        `;

            const users = await this.db.query(query);

            this.enviarResposta('GetUsersFilterResponse', {
                success: true,
                data: users
            });

        } catch (error) {
            console.error('Erro ao buscar usuários:', error);
            this.enviarResposta('GetUsersFilterResponse', {
                success: false,
                message: 'Erro ao carregar usuários'
            });
        }
    }

    async getSalesStats(filters, userRole, userId) {
        try {
            // Query base para estatísticas
            let whereClause = 'WHERE 1=1';
            const queryParams = [];

            // Filtrar por usuário
            if (userRole !== 'admin') {
                whereClause += ' AND o.user_id = ?';
                queryParams.push(userId);
            } else if (filters.userId) {
                whereClause += ' AND o.user_id = ?';
                queryParams.push(filters.userId);
            }

            // Aplicar filtros de data
            if (filters.dateStart) {
                whereClause += ' AND DATE(o.created_at) >= ?';
                queryParams.push(filters.dateStart);
            }

            if (filters.dateEnd) {
                whereClause += ' AND DATE(o.created_at) <= ?';
                queryParams.push(filters.dateEnd);
            }

            // Estatísticas principais
            const mainStatsQuery = `
                SELECT 
                    COUNT(*) as totalOrders,
                    COUNT(*) as totalItems,
                    SUM(CASE WHEN payment_status = 'paid' THEN amount ELSE 0 END) as totalRevenue,
                    SUM(CASE WHEN payment_status = 'paid' THEN commission_amount ELSE 0 END) as totalCommissions,
                    AVG(CASE WHEN payment_status = 'paid' THEN amount ELSE NULL END) as averageOrderValue
                FROM orders o
                ${whereClause}
            `;

            const [mainStats] = await this.db.query(mainStatsQuery, queryParams);

            // Estatísticas por método de pagamento
            const paymentMethodQuery = `
                SELECT 
                    payment_method,
                    COUNT(*) as count,
                    SUM(CASE WHEN payment_status = 'paid' THEN amount ELSE 0 END) as total
                FROM orders o
                ${whereClause}
                GROUP BY payment_method
            `;

            const paymentMethodStats = await this.db.query(paymentMethodQuery, queryParams);

            // Upsells e Order Bumps (simulado por enquanto)
            const upsells = Math.floor(mainStats.totalOrders * 0.15); // 15% de conversão
            const orderBumps = Math.floor(mainStats.totalOrders * 0.25); // 25% de conversão

            return {
                totalOrders: parseInt(mainStats.totalOrders) || 0,
                totalItems: parseInt(mainStats.totalItems) || 0,
                totalRevenue: parseFloat(mainStats.totalRevenue) || 0,
                totalCommissions: parseFloat(mainStats.totalCommissions) || 0,
                averageOrderValue: parseFloat(mainStats.averageOrderValue) || 0,
                upsells,
                orderBumps,
                paymentMethodStats
            };

        } catch (error) {
            console.error('Erro ao calcular estatísticas:', error);
            return {
                totalOrders: 0,
                totalItems: 0,
                totalRevenue: 0,
                totalCommissions: 0,
                averageOrderValue: 0,
                upsells: 0,
                orderBumps: 0,
                paymentMethodStats: []
            };
        }
    }

    async handleExportSales() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('ExportSalesResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { filters, exportOptions, salesData, userRole, userId } = data;

            // Validar opções de exportação
            if (!exportOptions.format || !['pdf', 'csv', 'excel'].includes(exportOptions.format)) {
                return this.enviarResposta('ExportSalesResponse', {
                    success: false,
                    message: 'Formato de exportação inválido'
                });
            }

            let fileContent, mimeType, filename;

            switch (exportOptions.format) {
                case 'csv':
                    const csvResult = await this.generateCSVExport(salesData, exportOptions, usuario);
                    fileContent = csvResult.content;
                    mimeType = 'text/csv';
                    filename = csvResult.filename;
                    break;

                case 'excel':
                    const excelResult = await this.generateExcelExport(salesData, exportOptions, usuario);
                    fileContent = excelResult.content; // ← SEM Buffer.from aqui
                    mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
                    filename = excelResult.filename;
                    break;

                case 'pdf':
                    const pdfResult = await this.generatePDFExport(salesData, exportOptions, usuario);
                    fileContent = pdfResult.content;
                    mimeType = 'application/pdf';
                    filename = pdfResult.filename;
                    break;

                default:
                    throw new Error('Formato não suportado');
            }

            this.enviarResposta('ExportSalesResponse', {
                success: true,
                data: {
                    fileContent,
                    mimeType,
                    filename,
                    isBase64: ['excel', 'pdf'].includes(exportOptions.format) // ← INCLUIR PDF
                },
                message: 'Relatório exportado com sucesso'
            });
        } catch (error) {
            console.error('Erro ao exportar vendas:', error);
            this.enviarResposta('ExportSalesResponse', {
                success: false,
                message: 'Erro ao gerar relatório de exportação'
            });
        }
    }

    async generateCSVExport(salesData, options, usuario) {
        try {
            const currentDate = new Date().toLocaleDateString('pt-BR');
            const currentTime = new Date().toLocaleTimeString('pt-BR');

            // Cabeçalho do CSV com informações da empresa
            let csvContent = '';

            if (options.companyInfo) {
                csvContent += `# RELATÓRIO DE VENDAS - FOR4 GATEWAY\n`;
                csvContent += `# Gerado em: ${currentDate} às ${currentTime}\n`;
                csvContent += `# Usuário: ${usuario.name}\n`;
                csvContent += `# Total de registros: ${salesData.length}\n`;
                csvContent += `#\n`;
            }

            // Cabeçalho das colunas
            const headers = [];
            const fieldMapping = {
                date: 'Data',
                orderId: 'ID Pedido',
                customer: 'Cliente',
                product: 'Produto',
                amount: 'Valor',
                paymentMethod: 'Método Pagamento',
                status: 'Status',
                commission: 'Comissão',
                gateway: 'Gateway',
                affiliate: 'Afiliado',
                coupon: 'Cupom'
            };

            Object.entries(options.fields).forEach(([field, enabled]) => {
                if (enabled) {
                    headers.push(fieldMapping[field]);
                }
            });

            csvContent += headers.join(',') + '\n';

            // Dados das vendas
            salesData.forEach(sale => {
                const row = [];

                if (options.fields.date) {
                    row.push(`"${new Date(sale.created_at).toLocaleDateString('pt-BR')}"`);
                }
                if (options.fields.orderId) {
                    row.push(`"#${sale.id}"`);
                }
                if (options.fields.customer) {
                    row.push(`"${sale.customer_name}"`);
                }
                if (options.fields.product) {
                    row.push(`"${sale.product_name || 'N/A'}"`);
                }
                if (options.fields.amount) {
                    const amount = parseFloat(sale.amount) || 0;
                    row.push(`"R$ ${amount.toFixed(2).replace('.', ',')}"`);
                }
                if (options.fields.paymentMethod) {
                    row.push(`"${this.getPaymentMethodLabel(sale.payment_method)}"`);
                }
                if (options.fields.status) {
                    row.push(`"${this.getStatusLabel(sale.payment_status)}"`);
                }
                if (options.fields.commission) {
                    const comission = parseFloat(sale.commission_amount) || 0;
                    row.push(`"R$ ${comission.toFixed(2).replace('.', ',')}"`);

                }
                if (options.fields.gateway) {
                    row.push(`"${sale.gateway_provider || 'N/A'}"`);
                }
                if (options.fields.affiliate) {
                    row.push(`"${sale.affiliate_id || 'N/A'}"`);
                }
                if (options.fields.coupon) {
                    row.push(`"${sale.coupon_code || 'N/A'}"`);
                }

                csvContent += row.join(',') + '\n';
            });

            const filename = `vendas_${new Date().toISOString().split('T')[0]}.csv`;

            return {
                content: csvContent,
                filename
            };

        } catch (error) {
            console.error('Erro ao gerar CSV:', error);
            throw error;
        }
    }

    async generatePDFExport(salesData, options, usuario) {
        try {
            const puppeteer = require('puppeteer');

            const currentDate = new Date().toLocaleDateString('pt-BR');
            const currentTime = new Date().toLocaleTimeString('pt-BR');

            // Função para limpar e escapar caracteres especiais
            const sanitizeText = (text) => {
                if (!text) return 'N/A';
                return text.toString()
                    .normalize('NFD') // Normalizar caracteres Unicode
                    .replace(/[\u0300-\u036f]/g, '') // Remover acentos
                    .replace(/[^\w\s@.-]/g, '') // Manter apenas caracteres seguros
                    .trim();
            };

            // Função alternativa que mantém acentos mas escapa HTML
            const escapeHtml = (text) => {
                if (!text) return 'N/A';
                const map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#x27;',
                    "/": '&#x2F;',
                    'á': '&aacute;',
                    'à': '&agrave;',
                    'ã': '&atilde;',
                    'â': '&acirc;',
                    'é': '&eacute;',
                    'ê': '&ecirc;',
                    'í': '&iacute;',
                    'ó': '&oacute;',
                    'ô': '&ocirc;',
                    'õ': '&otilde;',
                    'ú': '&uacute;',
                    'ü': '&uuml;',
                    'ç': '&ccedil;',
                    'Á': '&Aacute;',
                    'À': '&Agrave;',
                    'Ã': '&Atilde;',
                    'Â': '&Acirc;',
                    'É': '&Eacute;',
                    'Ê': '&Ecirc;',
                    'Í': '&Iacute;',
                    'Ó': '&Oacute;',
                    'Ô': '&Ocirc;',
                    'Õ': '&Otilde;',
                    'Ú': '&Uacute;',
                    'Ü': '&Uuml;',
                    'Ç': '&Ccedil;'
                };

                return text.toString().replace(/[&<>"'\/áàãâéêíóôõúüçÁÀÃÂÉÊÍÓÔÕÚÜÇ]/g, function (s) {
                    return map[s] || s;
                });
            };

            // Limpar e validar dados
            const cleanData = (salesData) => {
                return salesData.map(sale => ({
                    id: parseInt(sale.id) || 0,
                    customer_name: escapeHtml(sale.customer_name),
                    product_name: escapeHtml(sale.product_name),
                    customer_email: escapeHtml(sale.customer_email),
                    amount: parseFloat(sale.amount || 0),
                    commission_amount: parseFloat(sale.commission_amount || 0),
                    payment_method: sale.payment_method || 'unknown',
                    payment_status: sale.payment_status || 'unknown',
                    created_at: sale.created_at || new Date().toISOString(),
                    gateway_provider: escapeHtml(sale.gateway_provider),
                    affiliate_id: sale.affiliate_id || null,
                    coupon_code: escapeHtml(sale.coupon_code)
                }));
            };

            const cleanedSalesData = cleanData(salesData);

            // Calcular estatísticas
            const totalAmount = cleanedSalesData.reduce((sum, sale) => sum + sale.amount, 0);
            const totalCommissions = cleanedSalesData.reduce((sum, sale) => sum + sale.commission_amount, 0);
            const averageOrder = cleanedSalesData.length > 0 ? totalAmount / cleanedSalesData.length : 0;

            // Estatísticas por método de pagamento
            const paymentStats = cleanedSalesData.reduce((acc, sale) => {
                const method = sale.payment_method;
                if (!acc[method]) acc[method] = { count: 0, total: 0 };
                acc[method].count += 1;
                acc[method].total += sale.amount;
                return acc;
            }, {});

            // HTML com encoding UTF-8 forçado
            let htmlContent = `
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
                <meta http-equiv="Content-Language" content="pt-BR">
                <title>Relatorio de Vendas - For4 Gateway</title>
                <style>
                    @charset "UTF-8";
                    
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    
                    body {
                        font-family: 'Arial', 'Helvetica', sans-serif;
                        line-height: 1.6;
                        color: #1a1a1a;
                        background: #ffffff;
                        font-size: 14px;
                    }
                    
                    .container {
                        max-width: 100%;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    
                    .header {
                        text-align: center;
                        border-bottom: 3px solid #2563eb;
                        padding-bottom: 30px;
                        margin-bottom: 40px;
                        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
                        padding: 30px;
                        border-radius: 10px;
                    }
                    
                    .logo {
                        display: inline-block;
                        background: #2563eb;
                        color: white;
                        padding: 15px 20px;
                        border-radius: 10px;
                        font-size: 24px;
                        font-weight: bold;
                        margin-bottom: 15px;
                        letter-spacing: 1px;
                    }
                    
                    .title {
                        font-size: 28px;
                        font-weight: bold;
                        color: #1e293b;
                        margin-bottom: 10px;
                    }
                    
                    .subtitle {
                        color: #64748b;
                        font-size: 16px;
                        margin-bottom: 5px;
                    }
                    
                    .summary-grid {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 20px;
                        margin-bottom: 40px;
                    }
                    
                    .summary-card {
                        background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
                        padding: 25px;
                        border-radius: 12px;
                        text-align: center;
                        border: 1px solid #e2e8f0;
                    }
                    
                    .summary-value {
                        font-size: 24px;
                        font-weight: bold;
                        color: #2563eb;
                        margin-bottom: 8px;
                        display: block;
                        word-wrap: break-word;
                    }
                    
                    .summary-label {
                        color: #64748b;
                        font-size: 12px;
                        font-weight: 500;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }
                    
                    .section-title {
                        font-size: 18px;
                        font-weight: bold;
                        color: #1e293b;
                        margin: 30px 0 20px 0;
                        padding-bottom: 10px;
                        border-bottom: 2px solid #e2e8f0;
                    }
                    
                    .payment-methods {
                        background: #f8fafc;
                        padding: 20px;
                        border-radius: 10px;
                        margin-bottom: 30px;
                    }
                    
                    .payment-method {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 12px 0;
                        border-bottom: 1px solid #e2e8f0;
                    }
                    
                    .payment-method:last-child {
                        border-bottom: none;
                    }
                    
                    .payment-info {
                        flex: 1;
                    }
                    
                    .payment-name {
                        font-weight: 600;
                        color: #1e293b;
                        margin-bottom: 2px;
                    }
                    
                    .payment-details {
                        font-size: 12px;
                        color: #64748b;
                    }
                    
                    .payment-percentage {
                        text-align: right;
                        font-weight: bold;
                        color: #2563eb;
                        margin-left: 20px;
                    }
                    
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                        background: white;
                        border-radius: 8px;
                        overflow: hidden;
                        font-size: 11px;
                    }
                    
                    th {
                        background: #2563eb;
                        color: white;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 10px;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }
                    
                    td {
                        padding: 8px 6px;
                        border-bottom: 1px solid #f1f5f9;
                        font-size: 10px;
                        word-wrap: break-word;
                        max-width: 120px;
                    }
                    
                    tr:nth-child(even) {
                        background-color: #f8fafc;
                    }
                    
                    .status {
                        padding: 3px 6px;
                        border-radius: 12px;
                        font-size: 9px;
                        font-weight: 500;
                        text-transform: uppercase;
                        white-space: nowrap;
                    }
                    
                    .status-paid { background: #dcfce7; color: #166534; }
                    .status-pending { background: #fef3c7; color: #92400e; }
                    .status-cancelled { background: #fee2e2; color: #991b1b; }
                    .status-refunded { background: #f3f4f6; color: #374151; }
                    
                    .footer {
                        margin-top: 40px;
                        text-align: center;
                        padding-top: 30px;
                        border-top: 2px solid #e2e8f0;
                        color: #64748b;
                        font-size: 11px;
                        page-break-inside: avoid;
                    }
                    
                    @page {
                        margin: 2cm 1.5cm;
                        size: A4;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">FOR4</div>
                        <div class="title">Relatorio de Vendas</div>
                        <div class="subtitle">Gerado em ${currentDate} as ${currentTime}</div>
                        ${options.companyInfo ? `<div class="subtitle">Usuario: ${escapeHtml(usuario.name || 'N/A')}</div>` : ''}
                    </div>
        `;

            // Adicionar resumo se solicitado
            if (options.includeSummary) {
                htmlContent += `
                <div class="summary-grid">
                    <div class="summary-card">
                        <span class="summary-value">${cleanedSalesData.length}</span>
                        <div class="summary-label">Total de Vendas</div>
                    </div>
                    <div class="summary-card">
                        <span class="summary-value">R$ ${totalAmount.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</span>
                        <div class="summary-label">Faturamento Total</div>
                    </div>
                    <div class="summary-card">
                        <span class="summary-value">R$ ${averageOrder.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</span>
                        <div class="summary-label">Ticket Medio</div>
                    </div>
                    <div class="summary-card">
                        <span class="summary-value">R$ ${totalCommissions.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</span>
                        <div class="summary-label">Total Comissoes</div>
                    </div>
                </div>
            `;

                // Adicionar estatísticas de pagamento se solicitado
                if (options.includeCharts && Object.keys(paymentStats).length > 0) {
                    htmlContent += `
                    <h2 class="section-title">Vendas por Metodo de Pagamento</h2>
                    <div class="payment-methods">
                `;

                    Object.entries(paymentStats).forEach(([method, data]) => {
                        const percentage = totalAmount > 0 ? (data.total / totalAmount) * 100 : 0;
                        htmlContent += `
                        <div class="payment-method">
                            <div class="payment-info">
                                <div class="payment-name">${this.getPaymentMethodLabel(method)}</div>
                                <div class="payment-details">
                                    ${data.count} vendas - R$ ${data.total.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}
                                </div>
                            </div>
                            <div class="payment-percentage">
                                ${percentage.toFixed(1)}%
                            </div>
                        </div>
                    `;
                    });

                    htmlContent += `</div>`;
                }
            }

            // Tabela de vendas
            htmlContent += `
            <h2 class="section-title">Detalhamento das Vendas</h2>
            <table>
                <thead>
                    <tr>
        `;

            const fieldLabels = {
                date: 'Data',
                orderId: 'ID',
                customer: 'Cliente',
                product: 'Produto',
                amount: 'Valor',
                paymentMethod: 'Pagamento',
                status: 'Status',
                commission: 'Comissao'
            };

            Object.entries(options.fields).forEach(([field, enabled]) => {
                if (enabled && fieldLabels[field]) {
                    htmlContent += `<th>${fieldLabels[field]}</th>`;
                }
            });

            htmlContent += `
                    </tr>
                </thead>
                <tbody>
        `;

            cleanedSalesData.forEach(sale => {
                htmlContent += '<tr>';

                if (options.fields.date) {
                    htmlContent += `<td>${new Date(sale.created_at).toLocaleDateString('pt-BR')}</td>`;
                }
                if (options.fields.orderId) {
                    htmlContent += `<td>#${sale.id}</td>`;
                }
                if (options.fields.customer) {
                    htmlContent += `<td>${sale.customer_name}</td>`;
                }
                if (options.fields.product) {
                    htmlContent += `<td>${sale.product_name}</td>`;
                }
                if (options.fields.amount) {
                    htmlContent += `<td>R$ ${sale.amount.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</td>`;
                }
                if (options.fields.paymentMethod) {
                    htmlContent += `<td>${this.getPaymentMethodLabel(sale.payment_method)}</td>`;
                }
                if (options.fields.status) {
                    const statusClass = `status-${sale.payment_status}`;
                    htmlContent += `<td><span class="status ${statusClass}">${this.getStatusLabel(sale.payment_status)}</span></td>`;
                }
                if (options.fields.commission) {
                    htmlContent += `<td>R$ ${sale.commission_amount.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</td>`;
                }

                htmlContent += '</tr>';
            });

            htmlContent += `
                </tbody>
            </table>

            <div class="footer">
                <p><strong>Relatorio gerado automaticamente pelo sistema For4 Gateway</strong></p>
                <p>2025 For4 Gateway - Todos os direitos reservados</p>
                <p style="margin-top: 10px; font-size: 10px;">
                    Este documento contem informacoes confidenciais
                </p>
            </div>
                </div>
            </body>
            </html>
        `;

            console.log('🔄 Iniciando geração do PDF...');

            // Configuração do Puppeteer com melhor suporte a UTF-8
            const browser = await puppeteer.launch({
                headless: 'new',
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu',
                    '--disable-web-security',
                    '--allow-running-insecure-content'
                ]
            });

            const page = await browser.newPage();

            // Definir encoding UTF-8
            await page.setExtraHTTPHeaders({
                'Accept-Charset': 'utf-8',
                'Content-Type': 'text/html; charset=utf-8'
            });

            // Definir conteúdo HTML com encoding explícito
            await page.setContent(htmlContent, {
                waitUntil: 'networkidle0',
                timeout: 30000
            });

            // Gerar PDF
            const pdfBuffer = await page.pdf({
                format: 'A4',
                printBackground: true,
                preferCSSPageSize: true,
                margin: {
                    top: '20mm',
                    right: '15mm',
                    bottom: '20mm',
                    left: '15mm'
                },
                displayHeaderFooter: false // Removido para evitar problemas de encoding
            });

            await browser.close();

            console.log('✅ PDF gerado com sucesso!');

            const filename = `vendas_${options.pdfTemplate}_${new Date().toISOString().split('T')[0]}.pdf`;

            return {
                content: pdfBuffer.toString('base64'),
                filename
            };

        } catch (error) {
            console.error('❌ Erro ao gerar PDF:', error);
            throw new Error(`Erro na geração do PDF: ${error.message}`);
        }
    }

    async handleGetSaleDetails() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetSaleDetailsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { saleId, userRole, userId } = data;

            if (!saleId) {
                return this.enviarResposta('GetSaleDetailsResponse', {
                    success: false,
                    message: 'ID da venda é obrigatório'
                });
            }

            // Query para buscar detalhes da venda
            let query = `
                SELECT 
                    o.*,
                    p.name as product_name,
                    p.description as product_description,
                    u.name as seller_name,
                    u.email as seller_email,
                    u.company_name as seller_company
                FROM orders o
                LEFT JOIN products p ON o.product_id = p.id
                LEFT JOIN users u ON o.user_id = u.id
                WHERE o.id = ?
            `;
            const queryParams = [saleId];

            // Verificar permissões
            if (userRole !== 'admin') {
                query += ` AND o.user_id = ?`;
                queryParams.push(userId);
            }

            const [sale] = await this.db.query(query, queryParams);

            if (!sale) {
                return this.enviarResposta('GetSaleDetailsResponse', {
                    success: false,
                    message: 'Venda não encontrada'
                });
            }

            // Buscar transações relacionadas
            const transactions = await this.db.query(
                `SELECT * FROM transactions WHERE order_id = ? ORDER BY created_at DESC`,
                [saleId]
            );

            this.enviarResposta('GetSaleDetailsResponse', {
                success: true,
                data: {
                    sale,
                    transactions
                }
            });

        } catch (error) {
            console.error('Erro ao buscar detalhes da venda:', error);
            this.enviarResposta('GetSaleDetailsResponse', {
                success: false,
                message: 'Erro ao carregar detalhes da venda'
            });
        }
    }

    async handleUpdateSaleStatus() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UpdateSaleStatusResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Apenas admins podem atualizar status
            if (usuario.role !== 'admin') {
                return this.enviarResposta('UpdateSaleStatusResponse', {
                    success: false,
                    message: 'Sem permissão para esta ação'
                });
            }

            const data = this.data;
            const { saleId, newStatus, reason } = data;

            if (!saleId || !newStatus) {
                return this.enviarResposta('UpdateSaleStatusResponse', {
                    success: false,
                    message: 'ID da venda e novo status são obrigatórios'
                });
            }

            // Validar status
            const validStatuses = ['pending', 'paid', 'cancelled', 'refunded', 'chargeback'];
            if (!validStatuses.includes(newStatus)) {
                return this.enviarResposta('UpdateSaleStatusResponse', {
                    success: false,
                    message: 'Status inválido'
                });
            }

            // Atualizar status da venda
            await this.db.query(
                `UPDATE orders SET 
                    payment_status = ?, 
                    updated_at = NOW(),
                    paid_at = CASE WHEN ? = 'paid' THEN NOW() ELSE paid_at END
                WHERE id = ?`,
                [newStatus, newStatus, saleId]
            );

            // Registrar log da alteração
            await this.db.query(
                `INSERT INTO system_logs (user_id, level, message, context, created_at) 
                 VALUES (?, 'info', ?, ?, NOW())`,
                [
                    usuario.id,
                    `Status da venda #${saleId} alterado para ${newStatus}`,
                    JSON.stringify({ saleId, oldStatus: 'unknown', newStatus, reason, adminId: usuario.id })
                ]
            );

            this.enviarResposta('UpdateSaleStatusResponse', {
                success: true,
                message: 'Status da venda atualizado com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar status da venda:', error);
            this.enviarResposta('UpdateSaleStatusResponse', {
                success: false,
                message: 'Erro ao atualizar status da venda'
            });
        }
    }

    async handleGetSalesByPeriod() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetSalesByPeriodResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { startDate, endDate, groupBy = 'day', userRole, userId } = data;

            if (!startDate || !endDate) {
                return this.enviarResposta('GetSalesByPeriodResponse', {
                    success: false,
                    message: 'Datas de início e fim são obrigatórias'
                });
            }

            let dateFormat;
            switch (groupBy) {
                case 'hour':
                    dateFormat = '%Y-%m-%d %H:00:00';
                    break;
                case 'day':
                    dateFormat = '%Y-%m-%d';
                    break;
                case 'week':
                    dateFormat = '%Y-%u';
                    break;
                case 'month':
                    dateFormat = '%Y-%m';
                    break;
                default:
                    dateFormat = '%Y-%m-%d';
            }

            let query = `
                SELECT 
                    DATE_FORMAT(created_at, '${dateFormat}') as period,
                    COUNT(*) as orders_count,
                    SUM(CASE WHEN payment_status = 'paid' THEN amount ELSE 0 END) as revenue,
                    SUM(CASE WHEN payment_status = 'paid' THEN 1 ELSE 0 END) as paid_orders,
                    AVG(CASE WHEN payment_status = 'paid' THEN amount ELSE NULL END) as avg_order_value
                FROM orders 
                WHERE DATE(created_at) BETWEEN ? AND ?
            `;
            const queryParams = [startDate, endDate];

            // Filtrar por usuário se não for admin
            if (userRole !== 'admin') {
                query += ` AND user_id = ?`;
                queryParams.push(userId);
            }

            query += ` GROUP BY DATE_FORMAT(created_at, '${dateFormat}') ORDER BY period ASC`;

            const results = await this.db.query(query, queryParams);

            this.enviarResposta('GetSalesByPeriodResponse', {
                success: true,
                data: {
                    results,
                    period: { startDate, endDate, groupBy }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar vendas por período:', error);
            this.enviarResposta('GetSalesByPeriodResponse', {
                success: false,
                message: 'Erro ao carregar vendas por período'
            });
        }
    }

    async handleGetTopProducts() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetTopProductsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { limit = 10, dateStart, dateEnd, userRole, userId } = data;

            let query = `
                SELECT 
                    p.id,
                    p.name,
                    COUNT(o.id) as orders_count,
                    SUM(CASE WHEN o.payment_status = 'paid' THEN o.amount ELSE 0 END) as total_revenue,
                    AVG(CASE WHEN o.payment_status = 'paid' THEN o.amount ELSE NULL END) as avg_order_value,
                    SUM(CASE WHEN o.payment_status = 'paid' THEN 1 ELSE 0 END) as paid_orders
                FROM products p
                LEFT JOIN orders o ON p.id = o.product_id
                WHERE 1=1
            `;
            const queryParams = [];

            // Filtrar por usuário se não for admin
            if (userRole !== 'admin') {
                query += ` AND p.user_id = ?`;
                queryParams.push(userId);
            }

            // Filtrar por período se especificado
            if (dateStart) {
                query += ` AND DATE(o.created_at) >= ?`;
                queryParams.push(dateStart);
            }

            if (dateEnd) {
                query += ` AND DATE(o.created_at) <= ?`;
                queryParams.push(dateEnd);
            }

            query += ` 
                GROUP BY p.id, p.name 
                HAVING orders_count > 0
                ORDER BY total_revenue DESC 
                LIMIT ?
            `;
            queryParams.push(parseInt(limit));

            const topProducts = await this.db.query(query, queryParams);

            this.enviarResposta('GetTopProductsResponse', {
                success: true,
                data: {
                    products: topProducts,
                    period: { dateStart, dateEnd }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar top produtos:', error);
            this.enviarResposta('GetTopProductsResponse', {
                success: false,
                message: 'Erro ao carregar top produtos'
            });
        }
    }

    async handleGetSalesByPaymentMethod() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetSalesByPaymentMethodResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const data = this.data;
            const { dateStart, dateEnd, userRole, userId } = data;

            let query = `
                SELECT 
                    payment_method,
                    COUNT(*) as orders_count,
                    SUM(CASE WHEN payment_status = 'paid' THEN amount ELSE 0 END) as total_revenue,
                    SUM(CASE WHEN payment_status = 'paid' THEN 1 ELSE 0 END) as paid_orders,
                    AVG(CASE WHEN payment_status = 'paid' THEN amount ELSE NULL END) as avg_order_value
                FROM orders 
                WHERE 1=1
            `;
            const queryParams = [];

            // Filtrar por usuário se não for admin
            if (userRole !== 'admin') {
                query += ` AND user_id = ?`;
                queryParams.push(userId);
            }

            // Filtrar por período se especificado
            if (dateStart) {
                query += ` AND DATE(created_at) >= ?`;
                queryParams.push(dateStart);
            }

            if (dateEnd) {
                query += ` AND DATE(created_at) <= ?`;
                queryParams.push(dateEnd);
            }

            query += ` GROUP BY payment_method ORDER BY total_revenue DESC`;

            const paymentMethodStats = await this.db.query(query, queryParams);

            // Calcular percentuais
            const totalRevenue = paymentMethodStats.reduce((sum, method) => sum + method.total_revenue, 0);
            const statsWithPercentage = paymentMethodStats.map(method => ({
                ...method,
                revenue_percentage: totalRevenue > 0 ? (method.total_revenue / totalRevenue) * 100 : 0
            }));

            this.enviarResposta('GetSalesByPaymentMethodResponse', {
                success: true,
                data: {
                    stats: statsWithPercentage,
                    totals: {
                        total_orders: paymentMethodStats.reduce((sum, method) => sum + method.orders_count, 0),
                        total_revenue: totalRevenue,
                        total_paid_orders: paymentMethodStats.reduce((sum, method) => sum + method.paid_orders, 0)
                    },
                    period: { dateStart, dateEnd }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar vendas por método de pagamento:', error);
            this.enviarResposta('GetSalesByPaymentMethodResponse', {
                success: false,
                message: 'Erro ao carregar vendas por método de pagamento'
            });
        }
    }

    async generateExcelExport(salesData, options, usuario) {
        try {
            const XLSX = require('xlsx');
            const currentDate = new Date().toLocaleDateString('pt-BR');
            const currentTime = new Date().toLocaleTimeString('pt-BR');

            // Criar workbook
            const workbook = XLSX.utils.book_new();

            // ================================================================
            // ABA 1: RESUMO
            // ================================================================
            if (options.includeSummary) {
                const totalAmount = salesData.reduce((sum, sale) => sum + parseFloat(sale.amount || 0), 0);
                const totalCommissions = salesData.reduce((sum, sale) => sum + parseFloat(sale.commission_amount || 0), 0);
                const averageOrder = salesData.length > 0 ? totalAmount / salesData.length : 0;

                // Estatísticas por método de pagamento
                const paymentStats = salesData.reduce((acc, sale) => {
                    const method = sale.payment_method;
                    if (!acc[method]) acc[method] = { count: 0, total: 0 };
                    acc[method].count += 1;
                    acc[method].total += parseFloat(sale.amount || 0);
                    return acc;
                }, {});

                const summaryData = [
                    ['RELATÓRIO DE VENDAS - FOR4 GATEWAY'],
                    [`Gerado em: ${currentDate} às ${currentTime}`],
                    [`Usuário: ${usuario.name}`],
                    [''],
                    ['RESUMO GERAL'],
                    ['Total de Vendas', salesData.length],
                    ['Faturamento Total', totalAmount],
                    ['Ticket Médio', averageOrder],
                    ['Total Comissões', totalCommissions],
                    [''],
                    ['VENDAS POR MÉTODO DE PAGAMENTO'],
                    ['Método', 'Quantidade', 'Valor Total', 'Percentual'],
                    ...Object.entries(paymentStats).map(([method, data]) => [
                        this.getPaymentMethodLabel(method),
                        data.count,
                        data.total,
                        totalAmount > 0 ? `${((data.total / totalAmount) * 100).toFixed(1)}%` : '0%'
                    ])
                ];

                const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);

                // Formatação da aba resumo
                summarySheet['!cols'] = [
                    { width: 30 }, { width: 15 }, { width: 15 }, { width: 15 }
                ];

                XLSX.utils.book_append_sheet(workbook, summarySheet, 'Resumo');
            }

            // ================================================================
            // ABA 2: DADOS DETALHADOS
            // ================================================================

            // Cabeçalhos baseados nos campos selecionados
            const headers = [];
            const fieldMapping = {
                date: 'Data',
                orderId: 'ID Pedido',
                customer: 'Cliente',
                product: 'Produto',
                amount: 'Valor',
                paymentMethod: 'Método Pagamento',
                status: 'Status',
                commission: 'Comissão',
                gateway: 'Gateway',
                affiliate: 'Afiliado',
                coupon: 'Cupom'
            };

            Object.entries(options.fields).forEach(([field, enabled]) => {
                if (enabled && fieldMapping[field]) {
                    headers.push(fieldMapping[field]);
                }
            });

            // Dados das vendas
            const salesRows = salesData.map(sale => {
                const row = [];

                if (options.fields.date) {
                    row.push(new Date(sale.created_at).toLocaleDateString('pt-BR'));
                }
                if (options.fields.orderId) {
                    row.push(`#${sale.id}`);
                }
                if (options.fields.customer) {
                    row.push(sale.customer_name);
                }
                if (options.fields.product) {
                    row.push(sale.product_name || 'N/A');
                }
                if (options.fields.amount) {
                    row.push(parseFloat(sale.amount || 0));
                }
                if (options.fields.paymentMethod) {
                    row.push(this.getPaymentMethodLabel(sale.payment_method));
                }
                if (options.fields.status) {
                    row.push(this.getStatusLabel(sale.payment_status));
                }
                if (options.fields.commission) {
                    row.push(parseFloat(sale.commission_amount || 0));
                }
                if (options.fields.gateway) {
                    row.push(sale.gateway_provider || 'N/A');
                }
                if (options.fields.affiliate) {
                    row.push(sale.affiliate_id || 'N/A');
                }
                if (options.fields.coupon) {
                    row.push(sale.coupon_code || 'N/A');
                }

                return row;
            });

            // Criar aba de detalhes
            const detailsData = [headers, ...salesRows];
            const detailsSheet = XLSX.utils.aoa_to_sheet(detailsData);

            // Formatação da aba detalhes
            const colWidths = headers.map(header => {
                switch (header) {
                    case 'Data': return { width: 12 };
                    case 'ID Pedido': return { width: 10 };
                    case 'Cliente': return { width: 25 };
                    case 'Produto': return { width: 30 };
                    case 'Valor': return { width: 12 };
                    case 'Método Pagamento': return { width: 18 };
                    case 'Status': return { width: 12 };
                    case 'Comissão': return { width: 12 };
                    default: return { width: 15 };
                }
            });
            detailsSheet['!cols'] = colWidths;

            // Formatação de números como moeda
            Object.keys(detailsSheet).forEach(cell => {
                if (cell[0] === '!') return;

                const col = XLSX.utils.decode_cell(cell).c;
                const headerName = headers[col];

                if ((headerName === 'Valor' || headerName === 'Comissão') && detailsSheet[cell].t === 'n') {
                    detailsSheet[cell].z = '_("R$"* #,##0.00_);_("R$"* \\(#,##0.00\\);_("R$"* "-"??_);_(@_)';
                }
            });

            XLSX.utils.book_append_sheet(workbook, detailsSheet, 'Vendas Detalhadas');

            // ================================================================
            // GERAR ARQUIVO
            // ================================================================

            const buffer = XLSX.write(workbook, {
                type: 'buffer',
                bookType: 'xlsx',
                compression: true
            });

            const filename = `vendas_${new Date().toISOString().split('T')[0]}.xlsx`;

            return {
                content: buffer.toString('base64'),
                filename
            };

        } catch (error) {
            console.error('Erro ao gerar Excel:', error);
            throw error;
        }
    }

    getPaymentMethodLabel(method) {
        const methods = {
            'pix': 'PIX',
            'credit_card': 'Cartao de Credito',
            'debit_card': 'Cartao de Debito',
            'boleto': 'Boleto',
            'crypto': 'Criptomoeda'
        };
        return methods[method] || method;
    }

    getStatusLabel(status) {
        const statuses = {
            'paid': 'Pago',
            'pending': 'Pendente',
            'cancelled': 'Cancelado',
            'refunded': 'Reembolsado',
            'chargeback': 'Chargeback'
        };
        return statuses[status] || status;
    }

    formatCurrency(value) {
        return new Intl.NumberFormat('pt-BR', {
            style: 'currency',
            currency: 'BRL'
        }).format(value || 0);
    }

    calculateMethodStats(salesData) {
        const stats = {};
        let total = 0;

        salesData.forEach(sale => {
            if (sale.payment_status === 'paid') {
                const method = sale.payment_method;
                if (!stats[method]) {
                    stats[method] = { count: 0, total: 0 };
                }
                stats[method].count++;
                stats[method].total += sale.amount;
                total++;
            }
        });

        return Object.entries(stats).map(([method, data]) => ({
            method: this.getPaymentMethodLabel(method),
            count: data.count,
            total: data.total,
            percentage: total > 0 ? (data.count / total) * 100 : 0
        }));
    }

    getPaymentMethodLabel(method) {
        const methods = {
            'pix': 'PIX',
            'credit_card': 'Cartão de Crédito',
            'debit_card': 'Cartão de Débito',
            'boleto': 'Boleto',
            'crypto': 'Criptomoeda'
        };
        return methods[method] || method;
    }

    getStatusLabel(status) {
        const statuses = {
            'paid': 'Pago',
            'pending': 'Pendente',
            'cancelled': 'Cancelado',
            'refunded': 'Reembolsado',
            'chargeback': 'Chargeback'
        };
        return statuses[status] || status;
    }

    generateHeadScript(funnel, baseUrl) {
        return `<script>
window.for4Funnel = {
    funnelId: '${funnel.id}',
    userId: '${funnel.user_id}',
    productId: '${funnel.product_id}',
    trackingUrl: '${baseUrl}/api/funnel/track',
    debug: false
};

// Função para rastrear eventos
window.trackFunnelEvent = function(action, stepId, data = {}) {
    const payload = {
        funnel_id: window.for4Funnel.funnelId,
        step_id: stepId,
        action_type: action,
        customer_email: data.email || null,
        amount: data.amount || 0,
        ip_address: null,
        user_agent: navigator.userAgent,
        session_data: JSON.stringify({
            url: window.location.href,
            referrer: document.referrer,
            timestamp: new Date().toISOString(),
            ...data
        })
    };

    fetch(window.for4Funnel.trackingUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    }).catch(err => {
        if (window.for4Funnel.debug) {
            console.error('Erro ao rastrear evento:', err);
        }
    });
};

// Rastrear visualização da página automaticamente
document.addEventListener('DOMContentLoaded', function() {
    window.trackFunnelEvent('view', null, {
        page_type: 'funnel_page'
    });
});
</script>`;
    }

    generateTrackingScript(funnel, baseUrl) {
        return `<script>
// Script de rastreamento avançado para funil ${funnel.id}
(function() {
    'use strict';
    
    // Rastrear tempo na página
    let startTime = Date.now();
    let tracked = false;
    
    // Rastrear scroll
    let maxScroll = 0;
    window.addEventListener('scroll', function() {
        const scrollPercent = Math.round((window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100);
        maxScroll = Math.max(maxScroll, scrollPercent);
    });
    
    // Rastrear saída da página
    window.addEventListener('beforeunload', function() {
        if (!tracked) {
            tracked = true;
            const timeOnPage = Math.round((Date.now() - startTime) / 1000);
            
            if (navigator.sendBeacon && window.for4Funnel) {
                navigator.sendBeacon(window.for4Funnel.trackingUrl, JSON.stringify({
                    funnel_id: window.for4Funnel.funnelId,
                    action_type: 'page_exit',
                    session_data: JSON.stringify({
                        time_on_page: timeOnPage,
                        max_scroll: maxScroll,
                        url: window.location.href
                    })
                }));
            }
        }
    });
})();
</script>`;
    }

    generateYesButtonScript(step, funnel, baseUrl) {
        return `<!-- Botão SIM para ${step.name} -->
<button 
    onclick="handleFunnelAction('yes', '${step.id}')" 
    class="btn-funnel-yes"
    style="background: #10b981; color: white; padding: 15px 30px; border: none; border-radius: 8px; font-size: 18px; font-weight: bold; cursor: pointer; text-transform: uppercase; transition: all 0.3s ease;"
    onmouseover="this.style.background='#059669'"
    onmouseout="this.style.background='#10b981'"
>
    SIM, EU QUERO!
</button>

<script>
function handleFunnelAction(action, stepId) {
    // Verificar se o script HEAD foi carregado
    if (typeof window.trackFunnelEvent !== 'function') {
        console.error('Script HEAD do funil não foi carregado');
        return;
    }
    
    // Rastrear clique
    window.trackFunnelEvent('click_' + action, stepId, {
        step_type: '${step.step_type}',
        step_name: '${step.name}',
        step_order: ${step.step_order}
    });
    
    // Redirecionar após tracking
    setTimeout(function() {
        if (action === 'yes') {
            ${step.success_redirect_url ?
                `window.location.href = '${step.success_redirect_url}';` :
                `alert('Configure a URL de sucesso para esta etapa no painel administrativo');`
            }
        } else {
            ${step.failure_redirect_url ?
                `window.location.href = '${step.failure_redirect_url}';` :
                `alert('Configure a URL de falha para esta etapa no painel administrativo');`
            }
        }
    }, 150);
}
</script>`;
    }

    generateNoButtonScript(step, funnel, baseUrl) {
        return `<!-- Botão NÃO para ${step.name} -->
<button 
    onclick="handleFunnelAction('no', '${step.id}')" 
    class="btn-funnel-no"
    style="background: #6b7280; color: white; padding: 12px 24px; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: all 0.3s ease;"
    onmouseover="this.style.background='#4b5563'"
    onmouseout="this.style.background='#6b7280'"
>
    Não, obrigado
</button>

<script>
// Usar a mesma função handleFunnelAction do botão SIM
if (typeof handleFunnelAction !== 'function') {
    function handleFunnelAction(action, stepId) {
        if (typeof window.trackFunnelEvent !== 'function') {
            console.error('Script HEAD do funil não foi carregado');
            return;
        }
        
        window.trackFunnelEvent('click_' + action, stepId, {
            step_type: '${step.step_type}',
            step_name: '${step.name}',
            step_order: ${step.step_order}
        });
        
        setTimeout(function() {
            if (action === 'yes') {
                ${step.success_redirect_url ?
                `window.location.href = '${step.success_redirect_url}';` :
                `alert('Configure a URL de sucesso para esta etapa');`
            }
            } else {
                ${step.failure_redirect_url ?
                `window.location.href = '${step.failure_redirect_url}';` :
                `alert('Configure a URL de falha para esta etapa');`
            }
            }
        }, 150);
    }
}
</script>`;
    }

    async validarAdmin() {
        const usuario = await this.validarToken();

        if (!usuario) {
            return null;
        }

        if (usuario.role !== 'admin') {
            return null;
        }

        return usuario;
    }

    async criarLogAdmin(adminId, targetUserId, action, description, oldData = null, newData = null) {
        try {
            await this.db.query(
                `INSERT INTO admin_logs (admin_id, target_user_id, action, description, old_data, new_data, ip_address, user_agent) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    adminId,
                    targetUserId,
                    action,
                    description,
                    oldData ? JSON.stringify(oldData) : null,
                    newData ? JSON.stringify(newData) : null,
                    this.socket?.handshake?.address || null,
                    this.socket?.handshake?.headers?.['user-agent'] || null
                ]
            );
        } catch (error) {
            console.error('Erro ao criar log admin:', error);
        }
    }

    async handleGetUsers() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('GetUsersResponse', {
                    success: false,
                    message: 'Acesso negado: apenas administradores podem acessar esta funcionalidade'
                });
            }

            const data = this.data;
            const { page = 1, limit = 20, search = '', status = 'all' } = data;

            // Base query
            let whereClause = "WHERE u.role = 'user'";
            const queryParams = [];

            // Filtro de busca
            if (search) {
                whereClause += ` AND (u.name LIKE ? OR u.email LIKE ? OR u.company_name LIKE ? OR u.cnpj LIKE ?)`;
                const searchParam = `%${search}%`;
                queryParams.push(searchParam, searchParam, searchParam, searchParam);
            }

            // Filtro de status
            if (status !== 'all') {
                whereClause += ` AND u.status = ?`;
                queryParams.push(status);
            }

            // Query para contar total
            const countQuery = `
                SELECT COUNT(*) as total 
                FROM users u 
                ${whereClause}
            `;

            const totalResult = await this.db.query(countQuery, queryParams);
            const total = totalResult[0].total;

            // Query principal com paginação
            const offset = (page - 1) * limit;
            const usersQuery = `
                SELECT 
                    u.id,
                    u.name,
                    u.email,
                    u.cnpj,
                    u.company_name,
                    u.phone,
                    u.document,
                    u.document_type,
                    u.status,
                    u.email_verified_at,
                    u.created_at,
                    u.updated_at,
                    
                    -- Endereço
                    ua.cep,
                    ua.street,
                    ua.number,
                    ua.city,
                    ua.state,
                    
                    -- Estatísticas dos últimos 7 dias
                    COALESCE(recent_stats.sales_count_7d, 0) as sales_last_7_days,
                    COALESCE(recent_stats.revenue_7d, 0.00) as revenue_last_7_days,
                    
                    -- Status dos documentos
                    CASE 
                        WHEN doc_stats.total_docs > 0 AND doc_stats.pending_docs = 0 THEN 'Verificado'
                        WHEN doc_stats.total_docs > 0 AND doc_stats.pending_docs > 0 THEN 'Pendente'
                        ELSE 'Não verificado'
                    END as document_status
                    
                FROM users u
                LEFT JOIN user_addresses ua ON u.id = ua.user_id
                LEFT JOIN (
                    SELECT 
                        user_id,
                        COUNT(*) as sales_count_7d,
                        SUM(net_amount) as revenue_7d
                    FROM orders 
                    WHERE payment_status = 'paid' 
                    AND paid_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                    GROUP BY user_id
                ) recent_stats ON u.id = recent_stats.user_id
                LEFT JOIN (
                    SELECT 
                        user_id,
                        COUNT(*) as total_docs,
                        SUM(CASE WHEN status IN ('pending', 'requested') THEN 1 ELSE 0 END) as pending_docs
                    FROM user_documents
                    GROUP BY user_id
                ) doc_stats ON u.id = doc_stats.user_id
                
                ${whereClause}
                ORDER BY u.created_at DESC
                LIMIT ? OFFSET ?
            `;

            queryParams.push(parseInt(limit), offset);
            const users = await this.db.query(usersQuery, queryParams);

            // Calcular metadados de paginação
            const totalPages = Math.ceil(total / limit);

            this.enviarResposta('GetUsersResponse', {
                success: true,
                data: {
                    users: users,
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total: total,
                        totalPages: totalPages,
                        hasNext: page < totalPages,
                        hasPrev: page > 1
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar usuários:', error);
            this.enviarResposta('GetUsersResponse', {
                success: false,
                message: 'Erro ao carregar lista de usuários'
            });
        }
    }

    async handleGetUserPermissions() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('GetUserPermissionsResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id } = this.data;

            if (!user_id) {
                return this.enviarResposta('GetUserPermissionsResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Buscar permissões do usuário
            const permissions = await this.db.query(
                `SELECT * FROM user_permissions WHERE user_id = ?`,
                [user_id]
            );

            // Se não existir, criar com valores padrão
            if (permissions.length === 0) {
                await this.db.query(
                    `INSERT INTO user_permissions (user_id) VALUES (?)`,
                    [user_id]
                );

                const newPermissions = await this.db.query(
                    `SELECT * FROM user_permissions WHERE user_id = ?`,
                    [user_id]
                );

                return this.enviarResposta('GetUserPermissionsResponse', {
                    success: true,
                    data: { permissions: newPermissions[0] }
                });
            }

            this.enviarResposta('GetUserPermissionsResponse', {
                success: true,
                data: { permissions: permissions[0] }
            });

        } catch (error) {
            console.error('Erro ao buscar permissões:', error);
            this.enviarResposta('GetUserPermissionsResponse', {
                success: false,
                message: 'Erro ao carregar permissões do usuário'
            });
        }
    }

    async handleUpdateUserPermissions() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('UpdateUserPermissionsResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id, ...permissionsData } = this.data;

            if (!user_id) {
                return this.enviarResposta('UpdateUserPermissionsResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Buscar dados antigos para log
            const oldPermissions = await this.db.query(
                `SELECT * FROM user_permissions WHERE user_id = ?`,
                [user_id]
            );

            // Campos permitidos para atualização
            const allowedFields = [
                'payment_methods', 'block_withdrawals',
                'tax_pix', 'tax_credit_card', 'tax_boleto', 'tax_anticipation',
                'retention_pix_boleto', 'retention_credit_card',
                'cost_pix', 'cost_credit_card', 'cost_boleto',
                'cost_chargeback_pix_boleto', 'cost_chargeback_credit_card', 'cost_withdrawal',
                'days_pix', 'days_boleto', 'days_anticipation', 'days_guarantee_reserve'
            ];

            const updateData = {};
            const queryParams = [];

            Object.keys(permissionsData).forEach(field => {
                if (allowedFields.includes(field) && permissionsData[field] !== undefined) {
                    updateData[field] = permissionsData[field];
                    queryParams.push(permissionsData[field]);
                }
            });

            if (queryParams.length === 0) {
                return this.enviarResposta('UpdateUserPermissionsResponse', {
                    success: false,
                    message: 'Nenhum campo válido para atualizar'
                });
            }

            // Construir SQL de update
            const setClauses = Object.keys(updateData).map(field => `${field} = ?`).join(', ');
            queryParams.push(user_id);

            await this.db.query(
                `UPDATE user_permissions SET ${setClauses}, updated_at = NOW() WHERE user_id = ?`,
                queryParams
            );

            // Buscar dados atualizados
            const updatedPermissions = await this.db.query(
                `SELECT * FROM user_permissions WHERE user_id = ?`,
                [user_id]
            );

            // Criar log de auditoria
            await this.criarLogAdmin(
                admin.id,
                user_id,
                'update_permissions',
                'Permissões do usuário atualizadas',
                oldPermissions[0] || null,
                updatedPermissions[0]
            );

            this.enviarResposta('UpdateUserPermissionsResponse', {
                success: true,
                data: { permissions: updatedPermissions[0] },
                message: 'Permissões atualizadas com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar permissões:', error);
            this.enviarResposta('UpdateUserPermissionsResponse', {
                success: false,
                message: 'Erro ao atualizar permissões do usuário'
            });
        }
    }

    async handleToggleUserStatus() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('ToggleUserStatusResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id } = this.data;

            if (!user_id) {
                return this.enviarResposta('ToggleUserStatusResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Buscar usuário atual
            const user = await this.db.query(
                `SELECT id, name, email, status FROM users WHERE id = ? AND role = 'user'`,
                [user_id]
            );

            if (user.length === 0) {
                return this.enviarResposta('ToggleUserStatusResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            const currentStatus = user[0].status;
            const newStatus = currentStatus === 'active' ? 'suspended' : 'active';

            // Atualizar status
            await this.db.query(
                `UPDATE users SET status = ?, updated_at = NOW() WHERE id = ?`,
                [newStatus, user_id]
            );

            // Criar log de auditoria
            await this.criarLogAdmin(
                admin.id,
                user_id,
                'toggle_status',
                `Status do usuário alterado de ${currentStatus} para ${newStatus}`,
                { status: currentStatus },
                { status: newStatus }
            );

            this.enviarResposta('ToggleUserStatusResponse', {
                success: true,
                data: {
                    user_id,
                    old_status: currentStatus,
                    new_status: newStatus
                },
                message: `Usuário ${newStatus === 'active' ? 'ativado' : 'bloqueado'} com sucesso`
            });

        } catch (error) {
            console.error('Erro ao alterar status do usuário:', error);
            this.enviarResposta('ToggleUserStatusResponse', {
                success: false,
                message: 'Erro ao alterar status do usuário'
            });
        }
    }

    async handleGetUserInfo() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('GetUserInfoResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id } = this.data;

            if (!user_id) {
                return this.enviarResposta('GetUserInfoResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Buscar dados do usuário e endereço
            const userInfo = await this.db.query(`
                SELECT 
                    u.id,
                    u.name,
                    u.email,
                    u.cnpj,
                    u.company_name,
                    u.phone,
                    u.document,
                    u.document_type,
                    u.status,
                    u.created_at,
                    
                    ua.cep,
                    ua.street,
                    ua.number,
                    ua.complement,
                    ua.neighborhood,
                    ua.city,
                    ua.state,
                    ua.country
                    
                FROM users u
                LEFT JOIN user_addresses ua ON u.id = ua.user_id
                WHERE u.id = ? AND u.role = 'user'
            `, [user_id]);

            if (userInfo.length === 0) {
                return this.enviarResposta('GetUserInfoResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            this.enviarResposta('GetUserInfoResponse', {
                success: true,
                data: { user: userInfo[0] }
            });

        } catch (error) {
            console.error('Erro ao buscar informações do usuário:', error);
            this.enviarResposta('GetUserInfoResponse', {
                success: false,
                message: 'Erro ao carregar informações do usuário'
            });
        }
    }

    async handleUpdateUserInfo() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('UpdateUserInfoResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id, ...updateData } = this.data;

            if (!user_id) {
                return this.enviarResposta('UpdateUserInfoResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Separar dados de usuário e endereço
            const userFields = ['name', 'email', 'cnpj', 'company_name', 'phone', 'document'];
            const addressFields = ['cep', 'street', 'number', 'complement', 'neighborhood', 'city', 'state', 'country'];

            const userData = {};
            const addressData = {};

            Object.keys(updateData).forEach(field => {
                if (userFields.includes(field)) {
                    userData[field] = updateData[field];
                } else if (addressFields.includes(field)) {
                    addressData[field] = updateData[field];
                }
            });

            // Buscar dados antigos para log
            const oldData = await this.db.query(`
                SELECT u.*, ua.cep, ua.street, ua.number, ua.city, ua.state
                FROM users u 
                LEFT JOIN user_addresses ua ON u.id = ua.user_id 
                WHERE u.id = ?
            `, [user_id]);

            // Atualizar dados do usuário
            if (Object.keys(userData).length > 0) {
                const userSetClauses = Object.keys(userData).map(field => `${field} = ?`).join(', ');
                const userParams = [...Object.values(userData), user_id];

                await this.db.query(
                    `UPDATE users SET ${userSetClauses}, updated_at = NOW() WHERE id = ?`,
                    userParams
                );
            }

            // Atualizar endereço
            if (Object.keys(addressData).length > 0) {
                // Verificar se endereço existe
                const existingAddress = await this.db.query(
                    `SELECT id FROM user_addresses WHERE user_id = ?`,
                    [user_id]
                );

                if (existingAddress.length > 0) {
                    // Atualizar endereço existente
                    const addressSetClauses = Object.keys(addressData).map(field => `${field} = ?`).join(', ');
                    const addressParams = [...Object.values(addressData), user_id];

                    await this.db.query(
                        `UPDATE user_addresses SET ${addressSetClauses}, updated_at = NOW() WHERE user_id = ?`,
                        addressParams
                    );
                } else {
                    // Criar novo endereço
                    const addressFields = Object.keys(addressData).join(', ');
                    const addressPlaceholders = Object.keys(addressData).map(() => '?').join(', ');
                    const addressParams = [user_id, ...Object.values(addressData)];

                    await this.db.query(
                        `INSERT INTO user_addresses (user_id, ${addressFields}) VALUES (?, ${addressPlaceholders})`,
                        addressParams
                    );
                }
            }

            // Buscar dados atualizados
            const updatedData = await this.db.query(`
                SELECT u.*, ua.cep, ua.street, ua.number, ua.city, ua.state
                FROM users u 
                LEFT JOIN user_addresses ua ON u.id = ua.user_id 
                WHERE u.id = ?
            `, [user_id]);

            // Criar log de auditoria
            await this.criarLogAdmin(
                admin.id,
                user_id,
                'update_info',
                'Informações pessoais do usuário atualizadas',
                oldData[0],
                updatedData[0]
            );

            this.enviarResposta('UpdateUserInfoResponse', {
                success: true,
                data: { user: updatedData[0] },
                message: 'Informações atualizadas com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar informações do usuário:', error);
            this.enviarResposta('UpdateUserInfoResponse', {
                success: false,
                message: 'Erro ao atualizar informações do usuário'
            });
        }
    }

    async handleGetUserDocuments() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('GetUserDocumentsResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id } = this.data;

            if (!user_id) {
                return this.enviarResposta('GetUserDocumentsResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Buscar documentos do usuário
            const documents = await this.db.query(`
                SELECT 
                    id,
                    document_type,
                    file_name,
                    file_path,
                    file_size,
                    mime_type,
                    status,
                    rejection_reason,
                    uploaded_at,
                    reviewed_at
                FROM user_documents 
                WHERE user_id = ?
                ORDER BY uploaded_at DESC
            `, [user_id]);

            this.enviarResposta('GetUserDocumentsResponse', {
                success: true,
                data: { documents }
            });

        } catch (error) {
            console.error('Erro ao buscar documentos do usuário:', error);
            this.enviarResposta('GetUserDocumentsResponse', {
                success: false,
                message: 'Erro ao carregar documentos do usuário'
            });
        }
    }

    async handleRequestNewDocuments() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('RequestNewDocumentsResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id, reason = 'Documentos solicitados pelo administrador' } = this.data;

            if (!user_id) {
                return this.enviarResposta('RequestNewDocumentsResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Verificar se usuário existe
            const user = await this.db.query(
                `SELECT name, email FROM users WHERE id = ? AND role = 'user'`,
                [user_id]
            );

            if (user.length === 0) {
                return this.enviarResposta('RequestNewDocumentsResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            // Marcar documentos atuais como "solicitado novo"
            await this.db.query(`
                UPDATE user_documents 
                SET status = 'requested', 
                    rejection_reason = ?,
                    reviewed_at = NOW(),
                    reviewed_by = ?
                WHERE user_id = ? AND status != 'requested'
            `, [reason, admin.id, user_id]);

            // Suspender usuário até enviar novos documentos
            await this.db.query(
                `UPDATE users SET status = 'suspended' WHERE id = ?`,
                [user_id]
            );

            // Criar log de auditoria
            await this.criarLogAdmin(
                admin.id,
                user_id,
                'request_documents',
                'Solicitação de novos documentos enviada',
                null,
                { reason }
            );

            this.enviarResposta('RequestNewDocumentsResponse', {
                success: true,
                message: 'Solicitação de novos documentos enviada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao solicitar novos documentos:', error);
            this.enviarResposta('RequestNewDocumentsResponse', {
                success: false,
                message: 'Erro ao solicitar novos documentos'
            });
        }
    }

    async handleImpersonateUser() {


        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('ImpersonateUserResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id } = this.data;

            if (!user_id) {
                return this.enviarResposta('ImpersonateUserResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Verificar se usuário existe e está ativo
            const user = await this.db.query(
                `SELECT id, name, email, status, document_type, role FROM users WHERE id = ? AND role = 'user'`,
                [user_id]
            );

            if (user.length === 0) {
                return this.enviarResposta('ImpersonateUserResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            if (user[0].status !== 'active') {
                return this.enviarResposta('ImpersonateUserResponse', {
                    success: false,
                    message: 'Não é possível fazer login como um usuário inativo'
                });
            }

            const token = jwt.sign(
                { id: user[0].id, email: user[0].email },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
            );


            // Gerar token de impersonificação
            const crypto = require('crypto');
            const impersonationToken = crypto.randomBytes(32).toString('hex');

            // Registrar sessão de impersonificação
            await this.db.query(`
                INSERT INTO admin_impersonations 
                (admin_id, target_user_id, session_token, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            `, [
                admin.id,
                user_id,
                impersonationToken,
                this.socket?.handshake?.address || null,
                this.socket?.handshake?.headers?.['user-agent'] || null
            ]);

            // Criar log de auditoria
            await this.criarLogAdmin(
                admin.id,
                user_id,
                'impersonate',
                `Administrador fez login como usuário ${user[0].name}`,
                null,
                { impersonation_token: impersonationToken }
            );

            this.enviarResposta('ImpersonateUserResponse', {
                success: true,
                data: {
                    user: user[0],
                    impersonation_token: token,
                    admin_info: {
                        id: admin.id,
                        name: admin.name
                    }
                },
                message: 'Login como usuário realizado com sucesso'
            });

        } catch (error) {
            console.error('Erro ao fazer login como usuário:', error);
            this.enviarResposta('ImpersonateUserResponse', {
                success: false,
                message: 'Erro ao fazer login como usuário'
            });
        }
    }

    async handleEndImpersonation() {
        try {
            const { impersonation_token } = this.data;

            if (!impersonation_token) {
                return this.enviarResposta('EndImpersonationResponse', {
                    success: false,
                    message: 'Token de impersonificação é obrigatório'
                });
            }

            // Finalizar sessão de impersonificação
            await this.db.query(`
                UPDATE admin_impersonations 
                SET is_active = 0, ended_at = NOW() 
                WHERE session_token = ? AND is_active = 1
            `, [impersonation_token]);

            this.enviarResposta('EndImpersonationResponse', {
                success: true,
                message: 'Impersonificação finalizada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao finalizar impersonificação:', error);
            this.enviarResposta('EndImpersonationResponse', {
                success: false,
                message: 'Erro ao finalizar impersonificação'
            });
        }
    }

    async handleCheckDocumentVerificationStatus() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CheckDocumentVerificationStatusResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Verificar status do usuário
            const userStatus = usuario.status;

            // Verificar se tem documentos na tabela user_documents
            const documents = await this.db.query(
                'SELECT * FROM user_documents WHERE user_id = ?',
                [usuario.id]
            );

            const hasDocuments = documents.length > 0;

            // Verificar se há documentos pendentes de aprovação ou rejeitados
            const pendingDocuments = documents.filter(doc => doc.status === 'pending');
            const rejectedDocuments = documents.filter(doc => doc.status === 'rejected');
            const approvedDocuments = documents.filter(doc => doc.status === 'approved');

            // Verificar última solicitação de documentos
            const lastRequest = await this.db.query(
                `SELECT * FROM user_documents 
             WHERE user_id = ? AND status = 'requested' 
             ORDER BY uploaded_at DESC LIMIT 1`,
                [usuario.id]
            );

            // Determinar status dos documentos
            let documentStatus = 'not_submitted';
            if (lastRequest.length > 0) {
                documentStatus = 'requested';
            } else if (rejectedDocuments.length > 0) {
                documentStatus = 'rejected';
            } else if (pendingDocuments.length > 0) {
                documentStatus = 'pending';
            } else if (approvedDocuments.length > 0 && approvedDocuments.length === documents.length) {
                documentStatus = 'approved';
            }

            this.enviarResposta('CheckDocumentVerificationStatusResponse', {
                success: true,
                data: {
                    user_status: userStatus,
                    has_documents: hasDocuments,
                    document_status: documentStatus,
                    pending_count: pendingDocuments.length,
                    approved_count: approvedDocuments.length,
                    rejected_count: rejectedDocuments.length,
                    total_documents: documents.length,
                    last_request_type: lastRequest.length > 0 ? 'admin_requested' : 'initial'
                }
            });

        } catch (error) {
            console.error('Erro ao verificar status dos documentos:', error);
            this.enviarResposta('CheckDocumentVerificationStatusResponse', {
                success: false,
                message: 'Erro ao verificar status dos documentos'
            });
        }
    }

    async handleUploadDocument() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UploadDocumentResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { document_type, file_name, file_data, file_size, mime_type } = this.data;

            // Validações
            if (!document_type || !file_name || !file_data) {
                return this.enviarResposta('UploadDocumentResponse', {
                    success: false,
                    message: 'Dados do documento são obrigatórios'
                });
            }

            // Validar tipo de documento
            const allowedTypes = ['rg', 'cpf', 'cnpj', 'contrato_social', 'comprovante_residencia'];
            if (!allowedTypes.includes(document_type)) {
                return this.enviarResposta('UploadDocumentResponse', {
                    success: false,
                    message: 'Tipo de documento não permitido'
                });
            }

            // Validar tamanho do arquivo
            const maxSize = document_type === 'contrato_social' ? 10 * 1024 * 1024 : 5 * 1024 * 1024;
            if (file_size > maxSize) {
                return this.enviarResposta('UploadDocumentResponse', {
                    success: false,
                    message: 'Arquivo muito grande'
                });
            }

            // Validar tipo MIME
            const allowedMimeTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png'];
            if (!allowedMimeTypes.includes(mime_type)) {
                return this.enviarResposta('UploadDocumentResponse', {
                    success: false,
                    message: 'Tipo de arquivo não permitido'
                });
            }

            // Salvar arquivo no sistema de arquivos
            const fs = require('fs');
            const path = require('path');
            const crypto = require('crypto');

            // Gerar nome único para o arquivo
            const fileExtension = path.extname(file_name);
            const uniqueFileName = `${usuario.id}_${document_type}_${crypto.randomBytes(8).toString('hex')}${fileExtension}`;

            // Diretório de upload
            const uploadDir = path.join(process.cwd(), 'uploads', 'documents');
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }

            const filePath = path.join(uploadDir, uniqueFileName);

            // Salvar arquivo
            const buffer = Buffer.from(file_data, 'base64');
            fs.writeFileSync(filePath, buffer);

            // Verificar se já existe documento deste tipo para o usuário
            const existingDoc = await this.db.query(
                'SELECT id FROM user_documents WHERE user_id = ? AND document_type = ?',
                [usuario.id, document_type]
            );

            if (existingDoc.length > 0) {
                // Atualizar documento existente
                await this.db.query(
                    `UPDATE user_documents 
                 SET file_name = ?, file_path = ?, file_size = ?, mime_type = ?, 
                     status = 'pending', uploaded_at = NOW(), rejection_reason = NULL
                 WHERE user_id = ? AND document_type = ?`,
                    [file_name, filePath, file_size, mime_type, usuario.id, document_type]
                );
            } else {
                // Inserir novo documento
                await this.db.query(
                    `INSERT INTO user_documents 
                 (user_id, document_type, file_name, file_path, file_size, mime_type, status, uploaded_at) 
                 VALUES (?, ?, ?, ?, ?, ?, 'pending', NOW())`,
                    [usuario.id, document_type, file_name, filePath, file_size, mime_type]
                );
            }

            // Log da ação
            await this.db.query(
                `INSERT INTO system_logs (user_id, level, message, context, created_at) 
             VALUES (?, 'info', 'Documento enviado para verificação', ?, NOW())`,
                [usuario.id, JSON.stringify({ document_type, file_name, file_size })]
            );

            this.enviarResposta('UploadDocumentResponse', {
                success: true,
                message: 'Documento enviado com sucesso',
                data: {
                    document_type,
                    file_name,
                    status: 'pending'
                }
            });

        } catch (error) {
            console.error('Erro ao fazer upload do documento:', error);
            this.enviarResposta('UploadDocumentResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleSubmitDocumentsForReview() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('SubmitDocumentsForReviewResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Verificar se todos os documentos obrigatórios foram enviados
            const requiredDocs = ['rg', 'cpf', 'comprovante_residencia'];

            // Se for pessoa jurídica, adicionar documentos empresariais
            if (usuario.document_type === 'pessoa_juridica') {
                requiredDocs.push('cnpj', 'contrato_social');
            }

            const uploadedDocs = await this.db.query(
                `SELECT document_type FROM user_documents 
             WHERE user_id = ? AND status != 'rejected'`,
                [usuario.id]
            );

            const uploadedTypes = uploadedDocs.map(doc => doc.document_type);
            const missingDocs = requiredDocs.filter(type => !uploadedTypes.includes(type));

            if (missingDocs.length > 0) {
                return this.enviarResposta('SubmitDocumentsForReviewResponse', {
                    success: false,
                    message: `Documentos obrigatórios não enviados: ${missingDocs.join(', ')}`
                });
            }

            // Atualizar status do usuário para 'inactive' (aguardando aprovação)
            await this.db.query(
                'UPDATE users SET status = ? WHERE id = ?',
                ['inactive', usuario.id]
            );

            // Criar notificação para administradores
            const admins = await this.db.query(
                'SELECT id FROM users WHERE role = "admin"'
            );

            for (const admin of admins) {
                await this.db.query(
                    `INSERT INTO notifications 
                 (user_id, type, title, message, data, priority, created_at) 
                 VALUES (?, 'system', 'Novos documentos para análise', ?, ?, 'high', NOW())`,
                    [
                        admin.id,
                        `Usuário ${usuario.name} (${usuario.email}) enviou documentos para verificação`,
                        JSON.stringify({
                            user_id: usuario.id,
                            user_name: usuario.name,
                            user_email: usuario.email,
                            document_count: uploadedDocs.length
                        })
                    ]
                );
            }

            // Log da ação
            await this.db.query(
                `INSERT INTO system_logs (user_id, level, message, context, created_at) 
             VALUES (?, 'info', 'Documentos enviados para análise', ?, NOW())`,
                [usuario.id, JSON.stringify({ document_count: uploadedDocs.length, required_docs: requiredDocs })]
            );

            this.enviarResposta('SubmitDocumentsForReviewResponse', {
                success: true,
                message: 'Documentos enviados para análise! Você receberá uma notificação quando a verificação for concluída.',
                data: {
                    submitted_count: uploadedDocs.length,
                    status: 'under_review'
                }
            });

        } catch (error) {
            console.error('Erro ao enviar documentos para análise:', error);
            this.enviarResposta('SubmitDocumentsForReviewResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleRequestNewDocuments() {
        try {
            const admin = await this.validarToken();

            if (!admin || admin.role !== 'admin') {
                return this.enviarResposta('RequestNewDocumentsResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id, reason } = this.data;

            if (!user_id) {
                return this.enviarResposta('RequestNewDocumentsResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Verificar se usuário existe
            const user = await this.db.query(
                'SELECT id, name, email FROM users WHERE id = ?',
                [user_id]
            );

            if (user.length === 0) {
                return this.enviarResposta('RequestNewDocumentsResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            const targetUser = user[0];

            // Suspender usuário
            await this.db.query(
                'UPDATE users SET status = ? WHERE id = ?',
                ['suspended', user_id]
            );




            await this.db.query('DELETE FROM user_documents WHERE user_id = ?', [user_id]);

            // Criar notificação para o usuário
            await this.db.query(
                `INSERT INTO notifications 
             (user_id, type, title, message, data, priority, created_at) 
             VALUES (?, 'system', 'Nova verificação de documentos necessária', ?, ?, 'high', NOW())`,
                [
                    user_id,
                    'Nosso time solicitou uma nova verificação dos seus documentos. Acesse a plataforma para enviar os novos documentos.',
                    JSON.stringify({
                        reason: reason || 'Solicitação administrativa',
                        admin_id: admin.id,
                        admin_name: admin.name
                    })
                ]
            );

            // Log da ação administrativa
            await this.db.query(
                `INSERT INTO admin_logs 
             (admin_id, target_user_id, action, description, old_data, new_data, ip_address, user_agent, created_at) 
             VALUES (?, ?, 'request_documents', ?, NULL, ?, ?, ?, NOW())`,
                [
                    admin.id,
                    user_id,
                    'Solicitação de novos documentos enviada',
                    JSON.stringify({ reason: reason || 'Documentos solicitados pelo administrador' }),
                    this.socket.handshake.address,
                    this.socket.handshake.headers['user-agent']
                ]
            );

            this.enviarResposta('RequestNewDocumentsResponse', {
                success: true,
                message: `Solicitação de documentos enviada para ${targetUser.name}`,
                data: {
                    user_id,
                    user_name: targetUser.name,
                    user_email: targetUser.email,
                    new_status: 'suspended'
                }
            });

        } catch (error) {
            console.error('Erro ao solicitar novos documentos:', error);
            this.enviarResposta('RequestNewDocumentsResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleReviewDocument() {
        try {
            const admin = await this.validarToken();

            if (!admin || admin.role !== 'admin') {
                return this.enviarResposta('ReviewDocumentResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { document_id, action, rejection_reason } = this.data;

            if (!document_id || !action) {
                return this.enviarResposta('ReviewDocumentResponse', {
                    success: false,
                    message: 'Dados obrigatórios não informados'
                });
            }

            if (!['approve', 'reject'].includes(action)) {
                return this.enviarResposta('ReviewDocumentResponse', {
                    success: false,
                    message: 'Ação inválida'
                });
            }

            if (action === 'reject' && !rejection_reason) {
                return this.enviarResposta('ReviewDocumentResponse', {
                    success: false,
                    message: 'Motivo da rejeição é obrigatório'
                });
            }

            // Buscar documento
            const document = await this.db.query(
                'SELECT * FROM user_documents WHERE id = ?',
                [document_id]
            );

            if (document.length === 0) {
                return this.enviarResposta('ReviewDocumentResponse', {
                    success: false,
                    message: 'Documento não encontrado'
                });
            }

            const doc = document[0];

            // Atualizar status do documento
            const newStatus = action === 'approve' ? 'approved' : 'rejected';
            await this.db.query(
                `UPDATE user_documents 
             SET status = ?, rejection_reason = ?, reviewed_at = NOW(), reviewed_by = ? 
             WHERE id = ?`,
                [newStatus, rejection_reason || null, admin.id, document_id]
            );

            // Verificar se todos os documentos do usuário foram aprovados
            const userDocuments = await this.db.query(
                'SELECT status FROM user_documents WHERE user_id = ? AND document_type != "requested"',
                [doc.user_id]
            );

            const allApproved = userDocuments.every(d => d.status === 'approved');
            const hasRejected = userDocuments.some(d => d.status === 'rejected');

            // Atualizar status do usuário baseado na análise dos documentos
            let newUserStatus = 'inactive';
            if (allApproved && userDocuments.length > 0) {
                newUserStatus = 'active';
            } else if (hasRejected) {
                newUserStatus = 'suspended';
            }

            await this.db.query(
                'UPDATE users SET status = ? WHERE id = ?',
                [newUserStatus, doc.user_id]
            );

            // Criar notificação para o usuário
            const notificationMessage = action === 'approve'
                ? 'Seu documento foi aprovado!'
                : `Seu documento foi rejeitado. Motivo: ${rejection_reason}`;

            await this.db.query(
                `INSERT INTO notifications 
             (user_id, type, title, message, data, priority, created_at) 
             VALUES (?, 'system', 'Análise de documento concluída', ?, ?, 'normal', NOW())`,
                [
                    doc.user_id,
                    notificationMessage,
                    JSON.stringify({
                        document_type: doc.document_type,
                        action,
                        rejection_reason,
                        reviewer: admin.name
                    })
                ]
            );

            this.enviarResposta('ReviewDocumentResponse', {
                success: true,
                message: `Documento ${action === 'approve' ? 'aprovado' : 'rejeitado'} com sucesso`,
                data: {
                    document_id,
                    new_status: newStatus,
                    user_status: newUserStatus,
                    all_approved: allApproved
                }
            });

        } catch (error) {
            console.error('Erro ao revisar documento:', error);
            this.enviarResposta('ReviewDocumentResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleGetUsersForAdmin() {
        try {
            const admin = await this.validarToken();

            if (!admin || admin.role !== 'admin') {
                return this.enviarResposta('GetUsersResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { search = '', status = 'all', page = 1, limit = 20 } = this.data;
            const offset = (page - 1) * limit;

            let whereConditions = ['u.role = "user"'];
            let queryParams = [];

            // Filtro de busca
            if (search) {
                whereConditions.push('(u.name LIKE ? OR u.email LIKE ? OR u.company_name LIKE ? OR u.cnpj LIKE ?)');
                const searchTerm = `%${search}%`;
                queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
            }

            // Filtro de status
            if (status !== 'all') {
                whereConditions.push('u.status = ?');
                queryParams.push(status);
            }

            const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

            // Query principal com estatísticas
            const usersQuery = `
            SELECT 
                u.*,
                ua.phone,
                ua.cep,
                ua.street,
                ua.number,
                ua.complement,
                ua.neighborhood,
                ua.city,
                ua.state,
                up.payment_methods,
                up.block_withdrawals,
                up.tax_pix,
                up.tax_credit_card,
                up.tax_boleto,
                COALESCE(stats.total_orders, 0) as total_orders,
                COALESCE(stats.total_revenue, 0.00) as total_revenue,
                COALESCE(stats.revenue_last_7_days, 0.00) as revenue_last_7_days,
                COALESCE(stats.avg_order_value, 0.00) as avg_order_value,
                COALESCE(docs.total_documents, 0) as total_documents,
                COALESCE(docs.pending_documents, 0) as pending_documents,
                COALESCE(docs.approved_documents, 0) as approved_documents,
                COALESCE(docs.rejected_documents, 0) as rejected_documents,
                CASE 
                    WHEN docs.total_documents = 0 THEN 'Não verificado'
                    WHEN docs.pending_documents > 0 THEN 'Pendente'
                    WHEN docs.approved_documents = docs.total_documents THEN 'Verificado'
                    ELSE 'Parcialmente verificado'
                END as document_status
            FROM users u
            LEFT JOIN user_addresses ua ON u.id = ua.user_id
            LEFT JOIN user_permissions up ON u.id = up.user_id
            LEFT JOIN (
                SELECT 
                    user_id,
                    COUNT(*) as total_orders,
                    SUM(net_amount) as total_revenue,
                    AVG(net_amount) as avg_order_value,
                    SUM(CASE WHEN paid_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN net_amount ELSE 0 END) as revenue_last_7_days
                FROM orders 
                WHERE payment_status = 'paid'
                GROUP BY user_id
            ) stats ON u.id = stats.user_id
            LEFT JOIN (
                SELECT 
                    user_id,
                    COUNT(*) as total_documents,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_documents,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_documents,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_documents
                FROM user_documents
                WHERE document_type != 'requested'
                GROUP BY user_id
            ) docs ON u.id = docs.user_id
            ${whereClause}
            ORDER BY u.created_at DESC
            LIMIT ? OFFSET ?
        `;

            queryParams.push(limit, offset);

            const users = await this.db.query(usersQuery, queryParams);

            // Query para contagem total
            const countQuery = `
            SELECT COUNT(*) as total
            FROM users u
            ${whereClause}
        `;

            const countParams = queryParams.slice(0, -2); // Remove limit e offset
            const countResult = await this.db.query(countQuery, countParams);
            const total = countResult[0].total;

            // Calcular paginação
            const totalPages = Math.ceil(total / limit);
            const hasNext = page < totalPages;
            const hasPrev = page > 1;

            this.enviarResposta('GetUsersResponse', {
                success: true,
                data: {
                    users: users.map(user => ({
                        ...user,
                        payment_methods: user.payment_methods ? JSON.parse(user.payment_methods) : []
                    })),
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total,
                        totalPages,
                        hasNext,
                        hasPrev
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar usuários:', error);
            this.enviarResposta('GetUsersResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async validarPermissaoAdmin(usuario) {
        if (!usuario) {
            throw new Error('Usuário não autenticado');
        }

        if (usuario.role !== 'admin') {
            throw new Error('Acesso negado - privilégios de administrador necessários');
        }

        return true;
    }

    async validarDocumento(documento) {
        const requiredFields = ['document_type', 'file_name', 'file_data'];

        for (const field of requiredFields) {
            if (!documento[field]) {
                throw new Error(`Campo obrigatório não informado: ${field}`);
            }
        }

        // Validar tipos de documento permitidos
        const allowedTypes = ['rg', 'cpf', 'cnpj', 'contrato_social', 'comprovante_residencia'];
        if (!allowedTypes.includes(documento.document_type)) {
            throw new Error('Tipo de documento não permitido');
        }

        // Validar tamanho máximo
        const maxSize = documento.document_type === 'contrato_social' ? 10 * 1024 * 1024 : 5 * 1024 * 1024;
        if (documento.file_size > maxSize) {
            throw new Error('Arquivo excede o tamanho máximo permitido');
        }

        // Validar tipo MIME
        const allowedMimeTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png'];
        if (!allowedMimeTypes.includes(documento.mime_type)) {
            throw new Error('Tipo de arquivo não permitido. Use PDF, JPG ou PNG');
        }

        return true;
    }

    async criarNotificacaoDocumento(user_id, tipo, titulo, mensagem, dados = {}) {
        try {
            await this.db.query(
                `INSERT INTO notifications 
             (user_id, type, title, message, data, priority, created_at) 
             VALUES (?, ?, ?, ?, ?, 'normal', NOW())`,
                [user_id, tipo, titulo, mensagem, JSON.stringify(dados)]
            );
        } catch (error) {
            console.error('Erro ao criar notificação:', error);
        }
    }

    async notificarAdministradores(titulo, mensagem, dados = {}) {
        try {
            const admins = await this.db.query(
                'SELECT id FROM users WHERE role = "admin"'
            );

            for (const admin of admins) {
                await this.criarNotificacaoDocumento(admin.id, 'system', titulo, mensagem, dados);
            }
        } catch (error) {
            console.error('Erro ao notificar administradores:', error);
        }
    }

    async handleCheckDocumentVerification() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('CheckDocumentVerificationResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Verificar status do usuário
            const userStatus = usuario.status;

            // Verificar se tem documentos na tabela user_documents
            const documents = await this.db.query(
                'SELECT * FROM user_documents WHERE user_id = ?',
                [usuario.id]
            );

            const hasDocuments = documents.length > 0;

            // Verificar se há documentos pendentes de aprovação ou rejeitados
            const pendingDocuments = documents.filter(doc => doc.status === 'pending');
            const rejectedDocuments = documents.filter(doc => doc.status === 'rejected');
            const approvedDocuments = documents.filter(doc => doc.status === 'approved');

            // Verificar última solicitação de documentos
            const lastRequest = await this.db.query(
                `SELECT * FROM user_documents 
             WHERE user_id = ? AND status = 'requested' 
             ORDER BY uploaded_at DESC LIMIT 1`,
                [usuario.id]
            );

            // Determinar status dos documentos
            let documentStatus = 'not_submitted';
            if (lastRequest.length > 0) {
                documentStatus = 'requested';
            } else if (rejectedDocuments.length > 0) {
                documentStatus = 'rejected';
            } else if (pendingDocuments.length > 0) {
                documentStatus = 'pending';
            } else if (approvedDocuments.length > 0 && approvedDocuments.length === documents.length) {
                documentStatus = 'approved';
            }

            this.enviarResposta('CheckDocumentVerificationResponse', {
                success: true,
                data: {
                    user_status: userStatus,
                    has_documents: hasDocuments,
                    document_status: documentStatus,
                    pending_count: pendingDocuments.length,
                    approved_count: approvedDocuments.length,
                    rejected_count: rejectedDocuments.length,
                    total_documents: documents.length,
                    last_request_type: lastRequest.length > 0 ? 'admin_requested' : 'initial'
                }
            });

        } catch (error) {
            console.error('Erro ao verificar status dos documentos:', error);
            this.enviarResposta('CheckDocumentVerificationResponse', {
                success: false,
                message: 'Erro ao verificar status dos documentos'
            });
        }
    }

    async handleUploadDocumentVerification() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('UploadDocumentVerificationResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { document_type, file_name, file_data, file_size, mime_type } = this.data;

            // Validações
            if (!document_type || !file_name || !file_data) {
                return this.enviarResposta('UploadDocumentVerificationResponse', {
                    success: false,
                    message: 'Dados do documento são obrigatórios'
                });
            }

            // Validar tipo de documento
            const allowedTypes = ['rg', 'cpf', 'cnpj', 'contrato_social', 'comprovante_residencia'];
            if (!allowedTypes.includes(document_type)) {
                return this.enviarResposta('UploadDocumentVerificationResponse', {
                    success: false,
                    message: 'Tipo de documento não permitido'
                });
            }

            // Validar tamanho do arquivo
            const maxSize = document_type === 'contrato_social' ? 10 * 1024 * 1024 : 5 * 1024 * 1024;
            if (file_size > maxSize) {
                return this.enviarResposta('UploadDocumentVerificationResponse', {
                    success: false,
                    message: 'Arquivo muito grande'
                });
            }

            // Validar tipo MIME
            const allowedMimeTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png'];
            if (!allowedMimeTypes.includes(mime_type)) {
                return this.enviarResposta('UploadDocumentVerificationResponse', {
                    success: false,
                    message: 'Tipo de arquivo não permitido'
                });
            }

            // Salvar arquivo no sistema de arquivos
            const fs = require('fs');
            const path = require('path');
            const crypto = require('crypto');

            // Gerar nome único para o arquivo
            const fileExtension = path.extname(file_name);
            const uniqueFileName = `${usuario.id}_${document_type}_${crypto.randomBytes(8).toString('hex')}${fileExtension}`;

            // Diretório de upload
            const uploadDir = path.join(process.cwd(), 'uploads', 'documents');
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }

            const filePath = path.join(uploadDir, uniqueFileName);

            // Salvar arquivo
            const buffer = Buffer.from(file_data, 'base64');
            fs.writeFileSync(filePath, buffer);

            // Verificar se já existe documento deste tipo para o usuário
            const existingDoc = await this.db.query(
                'SELECT id FROM user_documents WHERE user_id = ? AND document_type = ?',
                [usuario.id, document_type]
            );

            if (existingDoc.length > 0) {
                // Atualizar documento existente
                await this.db.query(
                    `UPDATE user_documents 
                 SET file_name = ?, file_path = ?, file_size = ?, mime_type = ?, 
                     status = 'pending', uploaded_at = NOW(), rejection_reason = NULL
                 WHERE user_id = ? AND document_type = ?`,
                    [file_name, filePath, file_size, mime_type, usuario.id, document_type]
                );
            } else {
                // Inserir novo documento
                await this.db.query(
                    `INSERT INTO user_documents 
                 (user_id, document_type, file_name, file_path, file_size, mime_type, status, uploaded_at) 
                 VALUES (?, ?, ?, ?, ?, ?, 'pending', NOW())`,
                    [usuario.id, document_type, file_name, filePath, file_size, mime_type]
                );
            }

            // Log da ação
            await this.db.query(
                `INSERT INTO system_logs (user_id, level, message, context, created_at) 
             VALUES (?, 'info', 'Documento enviado para verificação', ?, NOW())`,
                [usuario.id, JSON.stringify({ document_type, file_name, file_size })]
            );

            this.enviarResposta('UploadDocumentVerificationResponse', {
                success: true,
                message: 'Documento enviado com sucesso',
                data: {
                    document_type,
                    file_name,
                    status: 'pending'
                }
            });

        } catch (error) {
            console.error('Erro ao fazer upload do documento:', error);
            this.enviarResposta('UploadDocumentVerificationResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleSubmitDocumentsVerification() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('SubmitDocumentsVerificationResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Verificar se todos os documentos obrigatórios foram enviados
            const requiredDocs = ['rg', 'cpf', 'comprovante_residencia'];

            // Se for pessoa jurídica, adicionar documentos empresariais
            if (usuario.document_type === 'pessoa_juridica') {
                requiredDocs.push('cnpj', 'contrato_social');
            }

            const uploadedDocs = await this.db.query(
                `SELECT document_type FROM user_documents 
             WHERE user_id = ? AND status != 'rejected'`,
                [usuario.id]
            );

            const uploadedTypes = uploadedDocs.map(doc => doc.document_type);
            const missingDocs = requiredDocs.filter(type => !uploadedTypes.includes(type));

            if (missingDocs.length > 0) {
                return this.enviarResposta('SubmitDocumentsVerificationResponse', {
                    success: false,
                    message: `Documentos obrigatórios não enviados: ${missingDocs.join(', ')}`
                });
            }

            // Atualizar status do usuário para 'inactive' (aguardando aprovação)
            await this.db.query(
                'UPDATE users SET status = ? WHERE id = ?',
                ['inactive', usuario.id]
            );

            // Criar notificação para administradores
            const admins = await this.db.query(
                'SELECT id FROM users WHERE role = "admin"'
            );

            for (const admin of admins) {
                await this.db.query(
                    `INSERT INTO notifications 
                 (user_id, type, title, message, data, priority, created_at) 
                 VALUES (?, 'system', 'Novos documentos para análise', ?, ?, 'high', NOW())`,
                    [
                        admin.id,
                        `Usuário ${usuario.name} (${usuario.email}) enviou documentos para verificação`,
                        JSON.stringify({
                            user_id: usuario.id,
                            user_name: usuario.name,
                            user_email: usuario.email,
                            document_count: uploadedDocs.length
                        })
                    ]
                );
            }

            // Log da ação
            await this.db.query(
                `INSERT INTO system_logs (user_id, level, message, context, created_at) 
             VALUES (?, 'info', 'Documentos enviados para análise', ?, NOW())`,
                [usuario.id, JSON.stringify({ document_count: uploadedDocs.length, required_docs: requiredDocs })]
            );

            this.enviarResposta('SubmitDocumentsVerificationResponse', {
                success: true,
                message: 'Documentos enviados para análise! Você receberá uma notificação quando a verificação for concluída.',
                data: {
                    submitted_count: uploadedDocs.length,
                    status: 'under_review'
                }
            });

        } catch (error) {
            console.error('Erro ao enviar documentos para análise:', error);
            this.enviarResposta('SubmitDocumentsVerificationResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleGetDocumentsVerification() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetDocumentsVerificationResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const documents = await this.db.query(
                `SELECT id, document_type, file_name, status, rejection_reason, 
                    uploaded_at, reviewed_at 
             FROM user_documents 
             WHERE user_id = ? 
             ORDER BY uploaded_at DESC`,
                [usuario.id]
            );

            this.enviarResposta('GetDocumentsVerificationResponse', {
                success: true,
                data: {
                    documents: documents.map(doc => ({
                        ...doc,
                        file_path: undefined // Não enviar caminho do arquivo por segurança
                    }))
                }
            });

        } catch (error) {
            console.error('Erro ao buscar documentos:', error);
            this.enviarResposta('GetDocumentsVerificationResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleAdminRequestDocuments() {
        try {
            const admin = await this.validarToken();

            if (!admin || admin.role !== 'admin') {
                return this.enviarResposta('AdminRequestDocumentsResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id, reason } = this.data;

            if (!user_id) {
                return this.enviarResposta('AdminRequestDocumentsResponse', {
                    success: false,
                    message: 'ID do usuário é obrigatório'
                });
            }

            // Verificar se usuário existe
            const user = await this.db.query(
                'SELECT id, name, email FROM users WHERE id = ?',
                [user_id]
            );

            if (user.length === 0) {
                return this.enviarResposta('AdminRequestDocumentsResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            const targetUser = user[0];

            // Suspender usuário
            await this.db.query(
                'UPDATE users SET status = ? WHERE id = ?',
                ['suspended', user_id]
            );

            // Marcar documentos existentes como solicitados novamente
            await this.db.query(
                `INSERT INTO user_documents (user_id, document_type, file_name, file_path, file_size, mime_type, status, rejection_reason) 
             VALUES (?, 'requested', 'admin_request', '', 0, '', 'requested', ?)`,
                [user_id, reason || 'Documentos solicitados pelo administrador']
            );

            // Criar notificação para o usuário
            await this.db.query(
                `INSERT INTO notifications 
             (user_id, type, title, message, data, priority, created_at) 
             VALUES (?, 'system', 'Nova verificação de documentos necessária', ?, ?, 'high', NOW())`,
                [
                    user_id,
                    'Nosso time solicitou uma nova verificação dos seus documentos. Acesse a plataforma para enviar os novos documentos.',
                    JSON.stringify({
                        reason: reason || 'Solicitação administrativa',
                        admin_id: admin.id,
                        admin_name: admin.name
                    })
                ]
            );

            // Log da ação administrativa
            await this.db.query(
                `INSERT INTO admin_logs 
             (admin_id, target_user_id, action, description, old_data, new_data, ip_address, user_agent, created_at) 
             VALUES (?, ?, 'request_documents', ?, NULL, ?, ?, ?, NOW())`,
                [
                    admin.id,
                    user_id,
                    'Solicitação de novos documentos enviada',
                    JSON.stringify({ reason: reason || 'Documentos solicitados pelo administrador' }),
                    this.socket.handshake.address,
                    this.socket.handshake.headers['user-agent']
                ]
            );

            this.enviarResposta('AdminRequestDocumentsResponse', {
                success: true,
                message: `Solicitação de documentos enviada para ${targetUser.name}`,
                data: {
                    user_id,
                    user_name: targetUser.name,
                    user_email: targetUser.email,
                    new_status: 'suspended'
                }
            });

        } catch (error) {
            console.error('Erro ao solicitar novos documentos:', error);
            this.enviarResposta('AdminRequestDocumentsResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleGetUsersAdmin() {
        try {
            const admin = await this.validarToken();

            if (!admin || admin.role !== 'admin') {
                return this.enviarResposta('GetUsersAdminResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { search = '', status = 'all', page = 1, limit = 20 } = this.data;
            const offset = (page - 1) * limit;

            let whereConditions = ['u.role = "user"'];
            let queryParams = [];

            // Filtro de busca
            if (search) {
                whereConditions.push('(u.name LIKE ? OR u.email LIKE ? OR u.company_name LIKE ? OR u.cnpj LIKE ?)');
                const searchTerm = `%${search}%`;
                queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
            }

            // Filtro de status
            if (status !== 'all') {
                whereConditions.push('u.status = ?');
                queryParams.push(status);
            }

            const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

            // Query principal com estatísticas
            const usersQuery = `
            SELECT 
                u.*,
                ua.phone,
                ua.cep,
                ua.street,
                ua.number,
                ua.complement,
                ua.neighborhood,
                ua.city,
                ua.state,
                up.payment_methods,
                up.block_withdrawals,
                up.tax_pix,
                up.tax_credit_card,
                up.tax_boleto,
                COALESCE(stats.total_orders, 0) as total_orders,
                COALESCE(stats.total_revenue, 0.00) as total_revenue,
                COALESCE(stats.revenue_last_7_days, 0.00) as revenue_last_7_days,
                COALESCE(stats.avg_order_value, 0.00) as avg_order_value,
                COALESCE(docs.total_documents, 0) as total_documents,
                COALESCE(docs.pending_documents, 0) as pending_documents,
                COALESCE(docs.approved_documents, 0) as approved_documents,
                COALESCE(docs.rejected_documents, 0) as rejected_documents,
                CASE 
                    WHEN docs.total_documents = 0 THEN 'Não verificado'
                    WHEN docs.pending_documents > 0 THEN 'Pendente'
                    WHEN docs.approved_documents = docs.total_documents THEN 'Verificado'
                    ELSE 'Parcialmente verificado'
                END as document_status
            FROM users u
            LEFT JOIN user_addresses ua ON u.id = ua.user_id
            LEFT JOIN user_permissions up ON u.id = up.user_id
            LEFT JOIN (
                SELECT 
                    user_id,
                    COUNT(*) as total_orders,
                    SUM(net_amount) as total_revenue,
                    AVG(net_amount) as avg_order_value,
                    SUM(CASE WHEN paid_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN net_amount ELSE 0 END) as revenue_last_7_days
                FROM orders 
                WHERE payment_status = 'paid'
                GROUP BY user_id
            ) stats ON u.id = stats.user_id
            LEFT JOIN (
                SELECT 
                    user_id,
                    COUNT(*) as total_documents,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_documents,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_documents,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_documents
                FROM user_documents
                WHERE document_type != 'requested'
                GROUP BY user_id
            ) docs ON u.id = docs.user_id
            ${whereClause}
            ORDER BY u.created_at DESC
            LIMIT ? OFFSET ?
        `;

            queryParams.push(limit, offset);

            const users = await this.db.query(usersQuery, queryParams);

            // Query para contagem total
            const countQuery = `
            SELECT COUNT(*) as total
            FROM users u
            ${whereClause}
        `;

            const countParams = queryParams.slice(0, -2); // Remove limit e offset
            const countResult = await this.db.query(countQuery, countParams);
            const total = countResult[0].total;

            // Calcular paginação
            const totalPages = Math.ceil(total / limit);
            const hasNext = page < totalPages;
            const hasPrev = page > 1;

            this.enviarResposta('GetUsersAdminResponse', {
                success: true,
                data: {
                    users: users.map(user => ({
                        ...user,
                        payment_methods: user.payment_methods ? JSON.parse(user.payment_methods) : []
                    })),
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total,
                        totalPages,
                        hasNext,
                        hasPrev
                    }
                }
            });

        } catch (error) {
            console.error('Erro ao buscar usuários:', error);
            this.enviarResposta('GetUsersAdminResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleAdminReviewDocument() {
        try {
            const admin = await this.validarToken();

            if (!admin || admin.role !== 'admin') {
                return this.enviarResposta('AdminReviewDocumentResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { document_id, action, rejection_reason } = this.data;

            if (!document_id || !action) {
                return this.enviarResposta('AdminReviewDocumentResponse', {
                    success: false,
                    message: 'Dados obrigatórios não informados'
                });
            }

            if (!['approve', 'reject'].includes(action)) {
                return this.enviarResposta('AdminReviewDocumentResponse', {
                    success: false,
                    message: 'Ação inválida'
                });
            }

            if (action === 'reject' && !rejection_reason) {
                return this.enviarResposta('AdminReviewDocumentResponse', {
                    success: false,
                    message: 'Motivo da rejeição é obrigatório'
                });
            }

            // Buscar documento
            const document = await this.db.query(
                'SELECT * FROM user_documents WHERE id = ?',
                [document_id]
            );

            if (document.length === 0) {
                return this.enviarResposta('AdminReviewDocumentResponse', {
                    success: false,
                    message: 'Documento não encontrado'
                });
            }

            const doc = document[0];

            // Atualizar status do documento
            const newStatus = action === 'approve' ? 'approved' : 'rejected';
            await this.db.query(
                `UPDATE user_documents 
             SET status = ?, rejection_reason = ?, reviewed_at = NOW(), reviewed_by = ? 
             WHERE id = ?`,
                [newStatus, rejection_reason || null, admin.id, document_id]
            );

            // Verificar se todos os documentos do usuário foram aprovados
            const userDocuments = await this.db.query(
                'SELECT status FROM user_documents WHERE user_id = ? AND document_type != "requested"',
                [doc.user_id]
            );

            const allApproved = userDocuments.every(d => d.status === 'approved');
            const hasRejected = userDocuments.some(d => d.status === 'rejected');

            // Atualizar status do usuário baseado na análise dos documentos
            let newUserStatus = 'inactive';
            if (allApproved && userDocuments.length > 0) {
                newUserStatus = 'active';
            } else if (hasRejected) {
                newUserStatus = 'suspended';
            }

            await this.db.query(
                'UPDATE users SET status = ? WHERE id = ?',
                [newUserStatus, doc.user_id]
            );

            // Criar notificação para o usuário
            const notificationMessage = action === 'approve'
                ? 'Seu documento foi aprovado!'
                : `Seu documento foi rejeitado. Motivo: ${rejection_reason}`;

            await this.db.query(
                `INSERT INTO notifications 
             (user_id, type, title, message, data, priority, created_at) 
             VALUES (?, 'system', 'Análise de documento concluída', ?, ?, 'normal', NOW())`,
                [
                    doc.user_id,
                    notificationMessage,
                    JSON.stringify({
                        document_type: doc.document_type,
                        action,
                        rejection_reason,
                        reviewer: admin.name
                    })
                ]
            );

            // Log da ação administrativa
            await this.db.query(
                `INSERT INTO admin_logs 
             (admin_id, target_user_id, action, description, old_data, new_data, ip_address, user_agent, created_at) 
             VALUES (?, ?, 'review_document', ?, ?, ?, ?, ?, NOW())`,
                [
                    admin.id,
                    doc.user_id,
                    `Documento ${doc.document_type} ${action === 'approve' ? 'aprovado' : 'rejeitado'}`,
                    JSON.stringify({ document_type: doc.document_type, old_status: doc.status }),
                    JSON.stringify({ new_status: newStatus, rejection_reason, user_status: newUserStatus }),
                    this.socket.handshake.address,
                    this.socket.handshake.headers['user-agent']
                ]
            );

            this.enviarResposta('AdminReviewDocumentResponse', {
                success: true,
                message: `Documento ${action === 'approve' ? 'aprovado' : 'rejeitado'} com sucesso`,
                data: {
                    document_id,
                    new_status: newStatus,
                    user_status: newUserStatus,
                    all_approved: allApproved
                }
            });

        } catch (error) {
            console.error('Erro ao revisar documento:', error);
            this.enviarResposta('AdminReviewDocumentResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleGetDocumentContent() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('GetDocumentContentResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { document_id } = this.data;

            if (!document_id) {
                return this.enviarResposta('GetDocumentContentResponse', {
                    success: false,
                    message: 'ID do documento é obrigatório'
                });
            }

            // Buscar documento
            const documents = await this.db.query(`
            SELECT 
                id,
                document_type,
                file_name,
                file_path,
                file_size,
                mime_type,
                status
            FROM user_documents 
            WHERE id = ?
        `, [document_id]);

            if (documents.length === 0) {
                return this.enviarResposta('GetDocumentContentResponse', {
                    success: false,
                    message: 'Documento não encontrado'
                });
            }

            const document = documents[0];

            // Ler arquivo do sistema de arquivos
            const fs = require('fs');
            const path = require('path');

            try {
                if (!fs.existsSync(document.file_path)) {
                    return this.enviarResposta('GetDocumentContentResponse', {
                        success: false,
                        message: 'Arquivo não encontrado no servidor'
                    });
                }

                // Ler arquivo e converter para base64
                const fileBuffer = fs.readFileSync(document.file_path);
                const base64Data = fileBuffer.toString('base64');

                this.enviarResposta('GetDocumentContentResponse', {
                    success: true,
                    data: {
                        file_data: base64Data,
                        file_name: document.file_name,
                        mime_type: document.mime_type,
                        file_size: document.file_size
                    }
                });

            } catch (fileError) {
                console.error('Erro ao ler arquivo:', fileError);
                return this.enviarResposta('GetDocumentContentResponse', {
                    success: false,
                    message: 'Erro ao ler arquivo do documento'
                });
            }

        } catch (error) {
            console.error('Erro ao buscar conteúdo do documento:', error);
            this.enviarResposta('GetDocumentContentResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    async handleDownloadDocument() {
        try {
            const admin = await this.validarAdmin();

            if (!admin) {
                return this.enviarResposta('DownloadDocumentResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { document_id } = this.data;

            if (!document_id) {
                return this.enviarResposta('DownloadDocumentResponse', {
                    success: false,
                    message: 'ID do documento é obrigatório'
                });
            }

            // Buscar documento
            const documents = await this.db.query(`
            SELECT 
                id,
                document_type,
                file_name,
                file_path,
                file_size,
                mime_type,
                status
            FROM user_documents 
            WHERE id = ?
        `, [document_id]);

            if (documents.length === 0) {
                return this.enviarResposta('DownloadDocumentResponse', {
                    success: false,
                    message: 'Documento não encontrado'
                });
            }

            const document = documents[0];

            // Ler arquivo do sistema de arquivos
            const fs = require('fs');

            try {
                if (!fs.existsSync(document.file_path)) {
                    return this.enviarResposta('DownloadDocumentResponse', {
                        success: false,
                        message: 'Arquivo não encontrado no servidor'
                    });
                }

                // Ler arquivo e converter para base64
                const fileBuffer = fs.readFileSync(document.file_path);
                const base64Data = fileBuffer.toString('base64');

                // Log da ação
                await this.db.query(
                    `INSERT INTO admin_logs 
                 (admin_id, target_user_id, action, description, ip_address, user_agent, created_at) 
                 VALUES (?, ?, 'download_document', ?, ?, ?, NOW())`,
                    [
                        admin.id,
                        null, // Poderia buscar o user_id do documento se necessário
                        `Download do documento ${document.document_type} - ${document.file_name}`,
                        this.socket.handshake.address,
                        this.socket.handshake.headers['user-agent']
                    ]
                );

                this.enviarResposta('DownloadDocumentResponse', {
                    success: true,
                    data: {
                        file_data: base64Data,
                        file_name: document.file_name,
                        mime_type: document.mime_type
                    }
                });

            } catch (fileError) {
                console.error('Erro ao ler arquivo para download:', fileError);
                return this.enviarResposta('DownloadDocumentResponse', {
                    success: false,
                    message: 'Erro ao preparar download do documento'
                });
            }

        } catch (error) {
            console.error('Erro ao baixar documento:', error);
            this.enviarResposta('DownloadDocumentResponse', {
                success: false,
                message: 'Erro interno do servidor'
            });
        }
    }

    // Adicionar aos handlers existentes

    async handleGetPaymentProviders() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('GetPaymentProvidersResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar provedores disponíveis
            const providers = await this.db.query(
                `SELECT id, name, slug, supported_methods, required_fields, 
            webhook_support, api_documentation_url
         FROM payment_providers 
         WHERE status = 'active'
         ORDER BY name`
            );

            // Se for admin, buscar configurações GLOBAIS do sistema
            let userConfigs = [];
            if (usuario.role === 'admin') {
                userConfigs = await this.db.query(
                    `SELECT spp.*, pp.name as provider_name, pp.slug as provider_slug,
                       u1.name as created_by_name, u2.name as updated_by_name
                 FROM system_payment_providers spp
                 JOIN payment_providers pp ON spp.provider_id = pp.id
                 LEFT JOIN users u1 ON spp.created_by_admin = u1.id
                 LEFT JOIN users u2 ON spp.updated_by_admin = u2.id
                 ORDER BY spp.payment_method, spp.priority`,
                    []
                );
            } else {
                // Se for usuário comum, buscar configurações específicas (se existirem)
                userConfigs = await this.db.query(
                    `SELECT upp.*, pp.name as provider_name, pp.slug as provider_slug
                 FROM user_payment_providers upp
                 JOIN payment_providers pp ON upp.provider_id = pp.id
                 WHERE upp.user_id = ?
                 ORDER BY upp.payment_method, upp.priority`,
                    [usuario.id]
                );
            }

            console.log(`📊 Carregando para ${usuario.role} ${usuario.id}:`, {
                total_providers: providers.length,
                total_configs: userConfigs.length,
                user_type: usuario.role
            });

            // Organizar por método de pagamento
            const configsByMethod = {
                pix: [],
                credit_card: [],
                boleto: []
            };

            userConfigs.forEach((config, index) => {
                // Processar credenciais
                const credentials = JSON.parse(config.credentials || '{}');
                const safeCreds = {};

                // Ocultar apenas campos sensíveis
                Object.keys(credentials).forEach(key => {
                    if (key.includes('secret') || key.includes('token') || key.includes('key')) {
                        safeCreds[key] = credentials[key] && credentials[key] !== '' ? '***hidden***' : '';
                    } else {
                        safeCreds[key] = credentials[key] || '';
                    }
                });

                const configData = {
                    id: config.id,
                    provider_id: config.provider_id,
                    provider_name: config.provider_name,
                    provider_slug: config.provider_slug,
                    payment_method: config.payment_method,
                    priority: config.priority,
                    is_active: Boolean(config.is_active),
                    test_mode: Boolean(config.test_mode),
                    webhook_url: config.webhook_url,
                    credentials: safeCreds,
                    // Campos específicos do sistema global
                    created_by_admin: config.created_by_admin,
                    updated_by_admin: config.updated_by_admin,
                    created_by_name: config.created_by_name,
                    updated_by_name: config.updated_by_name,
                    // Estatísticas
                    total_transactions: config.total_transactions || 0,
                    total_amount: parseFloat(config.total_amount || 0),
                    success_rate: parseFloat(config.success_rate || 0),
                    last_used_at: config.last_used_at,
                    created_at: config.created_at,
                    updated_at: config.updated_at
                };

                console.log(`📦 Config ${index + 1}:`, {
                    method: config.payment_method,
                    provider: config.provider_name,
                    id: config.id,
                    active: config.is_active,
                    type: usuario.role === 'admin' ? 'global' : 'user'
                });

                if (configsByMethod[config.payment_method]) {
                    configsByMethod[config.payment_method].push(configData);
                }
            });

            const responseData = {
                available_providers: providers.map(p => ({
                    ...p,
                    supported_methods: JSON.parse(p.supported_methods || '[]'),
                    required_fields: JSON.parse(p.required_fields || '[]')
                })),
                user_configurations: configsByMethod,
                is_global_config: usuario.role === 'admin'
            };

            console.log('✅ Resposta final:', {
                providers_count: responseData.available_providers.length,
                user_configs: Object.fromEntries(
                    Object.entries(responseData.user_configurations).map(([k, v]) => [k, v.length])
                ),
                config_type: usuario.role === 'admin' ? 'GLOBAL' : 'USER'
            });

            this.enviarResposta('GetPaymentProvidersResponse', {
                success: true,
                data: responseData
            });

        } catch (error) {
            console.error('💥 Erro ao buscar provedores:', error);
            this.enviarResposta('GetPaymentProvidersResponse', {
                success: false,
                message: 'Erro ao carregar provedores de pagamento'
            });
        }
    }

    async handleSavePaymentProviders() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('SavePaymentProvidersResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { configurations } = this.data;

            // Validar dados
            if (!configurations || typeof configurations !== 'object') {
                return this.enviarResposta('SavePaymentProvidersResponse', {
                    success: false,
                    message: 'Configurações inválidas'
                });
            }

            // Iniciar transação
            await this.db.query('START TRANSACTION');

            try {
                if (usuario.role === 'admin') {
                    // ADMIN: Salvar em configurações GLOBAIS
                    console.log('🔧 Admin salvando configurações GLOBAIS');

                    // Remover configurações globais antigas
                    await this.db.query('DELETE FROM system_payment_providers');

                    // Inserir novas configurações globais
                    for (const method of Object.keys(configurations)) {
                        for (const config of configurations[method]) {
                            // Validar provider existe
                            const provider = await this.db.query(
                                'SELECT id, required_fields FROM payment_providers WHERE id = ?',
                                [config.provider_id]
                            );

                            if (provider.length === 0) {
                                throw new Error(`Provedor ${config.provider_id} não encontrado`);
                            }

                            // Validar campos obrigatórios
                            const requiredFields = JSON.parse(provider[0].required_fields);
                            for (const field of requiredFields) {
                                if (!config.credentials[field]) {
                                    throw new Error(`Campo ${field} é obrigatório para ${method}`);
                                }
                            }

                            // Inserir configuração GLOBAL
                            await this.db.query(
                                `INSERT INTO system_payment_providers 
                             (provider_id, payment_method, credentials, priority, 
                              is_active, test_mode, webhook_url, created_by_admin, updated_by_admin) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                                [
                                    config.provider_id,
                                    method,
                                    JSON.stringify(config.credentials),
                                    config.priority,
                                    config.is_active,
                                    config.test_mode,
                                    config.webhook_url || null,
                                    usuario.id, // created_by_admin
                                    usuario.id  // updated_by_admin
                                ]
                            );
                        }
                    }

                    console.log('✅ Configurações GLOBAIS salvas pelo admin:', usuario.name);

                } else {
                    // USUÁRIO: Salvar em configurações ESPECÍFICAS (manter lógica antiga)
                    console.log('👤 Usuário salvando configurações ESPECÍFICAS');

                    // Remover configurações específicas antigas do usuário
                    await this.db.query(
                        'DELETE FROM user_payment_providers WHERE user_id = ?',
                        [usuario.id]
                    );

                    // Inserir novas configurações específicas
                    for (const method of Object.keys(configurations)) {
                        for (const config of configurations[method]) {
                            // Validar provider existe
                            const provider = await this.db.query(
                                'SELECT id, required_fields FROM payment_providers WHERE id = ?',
                                [config.provider_id]
                            );

                            if (provider.length === 0) {
                                throw new Error(`Provedor ${config.provider_id} não encontrado`);
                            }

                            // Validar campos obrigatórios
                            const requiredFields = JSON.parse(provider[0].required_fields);
                            for (const field of requiredFields) {
                                if (!config.credentials[field]) {
                                    throw new Error(`Campo ${field} é obrigatório para ${method}`);
                                }
                            }

                            // Inserir configuração ESPECÍFICA do usuário
                            await this.db.query(
                                `INSERT INTO user_payment_providers 
                             (user_id, provider_id, payment_method, credentials, priority, 
                              is_active, test_mode, webhook_url) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                                [
                                    usuario.id,
                                    config.provider_id,
                                    method,
                                    JSON.stringify(config.credentials),
                                    config.priority,
                                    config.is_active,
                                    config.test_mode,
                                    config.webhook_url || null
                                ]
                            );
                        }
                    }

                    console.log('✅ Configurações ESPECÍFICAS salvas pelo usuário:', usuario.name);
                }

                await this.db.query('COMMIT');

                this.enviarResposta('SavePaymentProvidersResponse', {
                    success: true,
                    message: `Configurações ${usuario.role === 'admin' ? 'globais' : 'específicas'} salvas com sucesso`
                });

            } catch (error) {
                await this.db.query('ROLLBACK');
                throw error;
            }

        } catch (error) {
            console.error('❌ Erro ao salvar provedores:', error);
            this.enviarResposta('SavePaymentProvidersResponse', {
                success: false,
                message: error.message || 'Erro ao salvar configurações'
            });
        }
    }

    async handleProcessPaymentMultiProvider() {
        try {
            const usuario = await this.validarToken();
            if (!usuario) {
                return this.enviarResposta('ProcessPaymentResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            const { amount, payment_method, customer_data, product_id } = this.data;

            console.log(`🔄 Processando pagamento para usuário ${usuario.id} - Método: ${payment_method}`);

            // NOVA LÓGICA: Buscar provedores por prioridade
            // 1. Primeiro: Configurações ESPECÍFICAS do usuário (se existirem)
            // 2. Segundo: Configurações GLOBAIS atribuídas pelo admin
            // 3. Terceiro: Configurações GLOBAIS padrão (se nenhuma atribuição)

            let providers = [];

            // 1. Verificar configurações ESPECÍFICAS do usuário
            const userSpecificProviders = await this.db.query(
                `SELECT upp.*, pp.handler_class, pp.name as provider_name, 'user_specific' as source_type
             FROM user_payment_providers upp
             JOIN payment_providers pp ON upp.provider_id = pp.id
             WHERE upp.user_id = ? 
             AND upp.payment_method = ? 
             AND upp.is_active = 1
             ORDER BY upp.priority ASC`,
                [usuario.id, payment_method]
            );

            if (userSpecificProviders.length > 0) {
                providers = userSpecificProviders;
                console.log(`📱 Usando configurações ESPECÍFICAS do usuário (${providers.length} provedores)`);
            } else {
                // 2. Verificar configurações GLOBAIS atribuídas pelo admin
                const assignedProviders = await this.db.query(
                    `SELECT spp.*, pp.handler_class, pp.name as provider_name, 
                        'admin_assigned' as source_type, aup.priority as admin_priority
                 FROM admin_user_providers aup
                 JOIN system_payment_providers spp ON aup.system_provider_id = spp.id
                 JOIN payment_providers pp ON spp.provider_id = pp.id
                 WHERE aup.user_id = ? 
                 AND aup.payment_method = ? 
                 AND aup.is_active = 1
                 AND spp.is_active = 1
                 ORDER BY aup.priority ASC`,
                    [usuario.id, payment_method]
                );

                if (assignedProviders.length > 0) {
                    providers = assignedProviders;
                    console.log(`🎯 Usando configurações GLOBAIS atribuídas pelo admin (${providers.length} provedores)`);
                } else {
                    // 3. Usar configurações GLOBAIS padrão (fallback)
                    const defaultProviders = await this.db.query(
                        `SELECT spp.*, pp.handler_class, pp.name as provider_name, 'global_default' as source_type
                     FROM system_payment_providers spp
                     JOIN payment_providers pp ON spp.provider_id = pp.id
                     WHERE spp.payment_method = ? 
                     AND spp.is_active = 1
                     ORDER BY spp.priority ASC`,
                        [payment_method]
                    );

                    providers = defaultProviders;
                    console.log(`⚙️ Usando configurações GLOBAIS padrão (${providers.length} provedores)`);
                }
            }

            if (providers.length === 0) {
                return this.enviarResposta('ProcessPaymentResponse', {
                    success: false,
                    message: `Nenhum provedor ativo configurado para ${payment_method}`,
                    error_type: 'no_providers_configured'
                });
            }

            // Tentar cada provedor em ordem de prioridade
            for (const provider of providers) {
                try {
                    console.log(`🔄 Tentando processar com ${provider.provider_name} (${provider.source_type})...`);

                    // Instanciar handler específico
                    const HandlerClass = this.getPaymentHandler(provider.handler_class);
                    const handler = new HandlerClass(
                        JSON.parse(provider.credentials),
                        provider.test_mode
                    );

                    // Processar pagamento
                    const result = await handler.processPayment({
                        amount,
                        payment_method,
                        customer: customer_data,
                        user_id: usuario.id,
                        product_id
                    });

                    if (result.success) {
                        // Atualizar estatísticas baseado no tipo de configuração
                        if (provider.source_type === 'user_specific') {
                            await this.db.query(
                                `UPDATE user_payment_providers 
                             SET last_used_at = NOW(),
                                 total_transactions = total_transactions + 1,
                                 total_amount = total_amount + ?
                             WHERE id = ?`,
                                [amount, provider.id]
                            );
                        } else {
                            await this.db.query(
                                `UPDATE system_payment_providers 
                             SET last_used_at = NOW(),
                                 total_transactions = total_transactions + 1,
                                 total_amount = total_amount + ?
                             WHERE id = ?`,
                                [amount, provider.id]
                            );
                        }

                        console.log(`✅ Pagamento processado com sucesso!`, {
                            provider: provider.provider_name,
                            source: provider.source_type,
                            amount,
                            user: usuario.id
                        });

                        return this.enviarResposta('ProcessPaymentResponse', {
                            success: true,
                            data: {
                                ...result,
                                provider_used: provider.provider_name,
                                provider_priority: provider.priority || provider.admin_priority,
                                source_type: provider.source_type
                            }
                        });
                    }

                    console.log(`❌ Falha com ${provider.provider_name}:`, result.message);

                } catch (providerError) {
                    console.error(`💥 Erro com ${provider.provider_name}:`, providerError);
                    continue; // Tentar próximo provedor
                }
            }

            // Se chegou aqui, todos os provedores falharam
            console.log(`💀 Todos os provedores falharam para usuário ${usuario.id}`);

            this.enviarResposta('ProcessPaymentResponse', {
                success: false,
                message: 'Todos os provedores de pagamento falharam. Tente novamente.',
                error_type: 'all_providers_failed',
                providers_tried: providers.length
            });

        } catch (error) {
            console.error('💥 Erro no processamento multi-provedor:', error);
            this.enviarResposta('ProcessPaymentResponse', {
                success: false,
                message: 'Erro interno no processamento'
            });
        }
    }

    getPaymentHandler(handlerClass) {
        const handlers = {
            'ZendryHandler': require('./handlers/ZendryHandler'),
            'HawkpayHandler': require('./handlers/HawkpayHandler'),

        };

        return handlers[handlerClass] || handlers['ZendryHandler'];
    }


    async handleGetAvailableProviders() {
        try {
            const usuario = await this.validarToken();
            if (!usuario || usuario.role !== 'admin') {
                return this.enviarResposta('GetAvailableProvidersResponse', {
                    success: false,
                    message: 'Acesso negado - apenas administradores'
                });
            }

            // Buscar configurações GLOBAIS do sistema (não os provedores base)
            const systemProviders = await this.db.query(`
            SELECT 
                spp.id,
                spp.provider_id,
                spp.payment_method,
                spp.priority,
                spp.is_active,
                spp.test_mode,
                pp.name,
                pp.slug,
                pp.supported_methods,
                pp.required_fields,
                u1.name as created_by_name,
                spp.created_at,
                spp.total_transactions,
                spp.total_amount,
                spp.success_rate
            FROM system_payment_providers spp
            JOIN payment_providers pp ON spp.provider_id = pp.id
            LEFT JOIN users u1 ON spp.created_by_admin = u1.id
            WHERE spp.is_active = 1
            ORDER BY spp.payment_method, spp.priority ASC
        `);

            // Organizar por método de pagamento
            const providersByMethod = {
                pix: [],
                credit_card: [],
                boleto: []
            };

            systemProviders.forEach(provider => {
                const providerData = {
                    id: provider.id, // ID da configuração global
                    provider_id: provider.provider_id,
                    name: provider.name,
                    slug: provider.slug,
                    payment_method: provider.payment_method,
                    priority: provider.priority,
                    is_active: provider.is_active,
                    test_mode: provider.test_mode,
                    supported_methods: JSON.parse(provider.supported_methods || '[]'),
                    required_fields: JSON.parse(provider.required_fields || '[]'),
                    created_by_name: provider.created_by_name,
                    created_at: provider.created_at,
                    // Estatísticas
                    total_transactions: provider.total_transactions || 0,
                    total_amount: parseFloat(provider.total_amount || 0),
                    success_rate: parseFloat(provider.success_rate || 0)
                };

                if (providersByMethod[provider.payment_method]) {
                    providersByMethod[provider.payment_method].push(providerData);
                }
            });

            console.log('📋 Provedores GLOBAIS disponíveis para atribuição:', {
                pix: providersByMethod.pix.length,
                credit_card: providersByMethod.credit_card.length,
                boleto: providersByMethod.boleto.length,
                total: systemProviders.length
            });

            this.enviarResposta('GetAvailableProvidersResponse', {
                success: true,
                data: {
                    providers_by_method: providersByMethod,
                    total: systemProviders.length,
                    source: 'system_global_configurations'
                }
            });

        } catch (error) {
            console.error('❌ Erro ao buscar provedores disponíveis:', error);
            this.enviarResposta('GetAvailableProvidersResponse', {
                success: false,
                message: 'Erro ao carregar provedores disponíveis'
            });
        }
    }

    async handleGetUserAssignedProviders() {
        try {
            const usuario = await this.validarToken();
            if (!usuario || usuario.role !== 'admin') {
                return this.enviarResposta('GetUserAssignedProvidersResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id } = this.data;

            // Buscar provedores GLOBAIS atribuídos ao usuário
            const assignedProviders = await this.db.query(`
            SELECT 
                aup.id as assignment_id,
                aup.user_id,
                aup.payment_method,
                aup.priority,
                aup.is_active,
                aup.notes,
                aup.assigned_by,
                aup.created_at as assigned_at,
                -- Dados da configuração global
                spp.id as system_provider_id,
                spp.provider_id,
                spp.test_mode,
                spp.total_transactions,
                spp.total_amount,
                spp.success_rate,
                -- Dados do provedor
                pp.name as provider_name,
                pp.slug as provider_slug,
                pp.supported_methods,
                -- Dados do admin que atribuiu
                u.name as assigned_by_name
            FROM admin_user_providers aup
            JOIN system_payment_providers spp ON aup.system_provider_id = spp.id
            JOIN payment_providers pp ON spp.provider_id = pp.id
            JOIN users u ON aup.assigned_by = u.id
            WHERE aup.user_id = ?
            ORDER BY aup.payment_method, aup.priority
        `, [user_id]);

            // Organizar por método de pagamento
            const providersByMethod = {
                pix: [],
                credit_card: [],
                boleto: []
            };

            assignedProviders.forEach(provider => {
                const providerData = {
                    assignment_id: provider.assignment_id,
                    system_provider_id: provider.system_provider_id,
                    provider_id: provider.provider_id,
                    provider_name: provider.provider_name,
                    provider_slug: provider.provider_slug,
                    payment_method: provider.payment_method,
                    priority: provider.priority,
                    is_active: Boolean(provider.is_active),
                    notes: provider.notes || '',
                    test_mode: Boolean(provider.test_mode),
                    supported_methods: JSON.parse(provider.supported_methods || '[]'),
                    assigned_by: provider.assigned_by,
                    assigned_by_name: provider.assigned_by_name,
                    assigned_at: provider.assigned_at,
                    // Estatísticas
                    total_transactions: provider.total_transactions || 0,
                    total_amount: parseFloat(provider.total_amount || 0),
                    success_rate: parseFloat(provider.success_rate || 0)
                };

                if (providersByMethod[provider.payment_method]) {
                    providersByMethod[provider.payment_method].push(providerData);
                }
            });

            console.log(`👤 Provedores atribuídos ao usuário ${user_id}:`, {
                pix: providersByMethod.pix.length,
                credit_card: providersByMethod.credit_card.length,
                boleto: providersByMethod.boleto.length,
                total: assignedProviders.length
            });

            this.enviarResposta('GetUserAssignedProvidersResponse', {
                success: true,
                data: {
                    user_id,
                    providers: providersByMethod
                }
            });

        } catch (error) {
            console.error('❌ Erro ao buscar provedores do usuário:', error);
            this.enviarResposta('GetUserAssignedProvidersResponse', {
                success: false,
                message: 'Erro ao buscar provedores'
            });
        }
    }

    async handleUpdateUserAssignedProviders() {
        try {
            const usuario = await this.validarToken();
            if (!usuario || usuario.role !== 'admin') {
                return this.enviarResposta('UpdateUserAssignedProvidersResponse', {
                    success: false,
                    message: 'Acesso negado'
                });
            }

            const { user_id, providers } = this.data;

            // Validar se o usuário existe
            const userExists = await this.db.query(
                'SELECT id, name FROM users WHERE id = ?',
                [user_id]
            );

            if (userExists.length === 0) {
                return this.enviarResposta('UpdateUserAssignedProvidersResponse', {
                    success: false,
                    message: 'Usuário não encontrado'
                });
            }

            // Iniciar transação
            await this.db.query('START TRANSACTION');

            try {
                // Buscar atribuições antigas para log
                const oldAssignments = await this.db.query(
                    `SELECT aup.*, spp.provider_id, pp.name as provider_name
                 FROM admin_user_providers aup
                 JOIN system_payment_providers spp ON aup.system_provider_id = spp.id
                 JOIN payment_providers pp ON spp.provider_id = pp.id
                 WHERE aup.user_id = ?`,
                    [user_id]
                );

                // Remover atribuições antigas
                await this.db.query(
                    'DELETE FROM admin_user_providers WHERE user_id = ?',
                    [user_id]
                );

                let totalInserted = 0;

                // Inserir novas atribuições
                for (const method of Object.keys(providers)) {
                    for (let i = 0; i < providers[method].length; i++) {
                        const assignment = providers[method][i];

                        // Validar se a configuração global existe
                        const systemProvider = await this.db.query(`
                        SELECT spp.id, spp.provider_id, spp.is_active, pp.name, pp.supported_methods
                        FROM system_payment_providers spp
                        JOIN payment_providers pp ON spp.provider_id = pp.id
                        WHERE spp.id = ? AND spp.is_active = 1
                    `, [assignment.system_provider_id]);

                        if (systemProvider.length === 0) {
                            throw new Error(`Configuração global ${assignment.system_provider_id} não encontrada ou inativa`);
                        }

                        const supportedMethods = JSON.parse(systemProvider[0].supported_methods || '[]');
                        if (!supportedMethods.includes(method)) {
                            throw new Error(`Provedor ${systemProvider[0].name} não suporta o método ${method}`);
                        }

                        // Inserir atribuição
                        await this.db.query(`
                        INSERT INTO admin_user_providers 
                        (user_id, payment_method, provider_id, system_provider_id, assigned_by, priority, is_active, notes)
                        VALUES (?, ?,?, ?, ?, ?, ?, ?)
                    `, [
                            user_id,
                            method,
                            systemProvider[0].provider_id,
                            assignment.system_provider_id,
                            usuario.id,
                            i + 1, // Prioridade baseada na ordem
                            assignment.is_active ? 1 : 0,
                            assignment.notes || null
                        ]);

                        totalInserted++;
                    }
                }

                await this.db.query('COMMIT');

                // Log da ação para auditoria
                await this.logAdminAction(usuario.id, user_id, 'update_payment_providers',
                    `Provedores de pagamento atualizados para ${userExists[0].name}`,
                    { old_assignments: oldAssignments },
                    {
                        providers,
                        total_configurations: totalInserted,
                        updated_by: usuario.name
                    }
                );

                console.log(`✅ Atribuições atualizadas:`, {
                    user_id,
                    user_name: userExists[0].name,
                    total_inserted: totalInserted,
                    admin: usuario.name
                });

                this.enviarResposta('UpdateUserAssignedProvidersResponse', {
                    success: true,
                    message: `Provedores atualizados com sucesso para ${userExists[0].name}`,
                    data: {
                        total_assignments: totalInserted,
                        user_name: userExists[0].name
                    }
                });

            } catch (error) {
                await this.db.query('ROLLBACK');
                throw error;
            }

        } catch (error) {
            console.error('❌ Erro ao atualizar provedores:', error);
            this.enviarResposta('UpdateUserAssignedProvidersResponse', {
                success: false,
                message: error.message || 'Erro ao atualizar provedores'
            });
        }
    }

    async logAdminAction(adminId, targetUserId, action, description, oldData = null, newData = null) {
        try {
            const userAgent = this.socket?.handshake?.headers?.['user-agent'] || 'Unknown';
            const ipAddress = this.socket?.handshake?.address || 'Unknown';

            await this.db.query(`
            INSERT INTO admin_logs 
            (admin_id, target_user_id, action, description, old_data, new_data, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
                adminId,
                targetUserId,
                action,
                description,
                oldData ? JSON.stringify(oldData) : null,
                newData ? JSON.stringify(newData) : null,
                ipAddress,
                userAgent
            ]);
        } catch (error) {
            console.error('Erro ao registrar log de admin:', error);
            // Não falhar a operação principal por causa do log
        }
    }


    async handleGetApiKeys() {

        const usuario = await this.validarToken();

        const apiKeysHandler = new ApiKeysHandler(usuario, this.data, this.socket);
        return await apiKeysHandler.handleGetApiKeys();
    }

    // Criar nova API key
    async handleCreateApiKey() {
         const usuario = await this.validarToken();
        const apiKeysHandler = new ApiKeysHandler(usuario, this.data, this.socket);
        return await apiKeysHandler.handleCreateApiKey();
    }

    // Atualizar API key
    async handleUpdateApiKey() {
        const usuario = await this.validarToken();
        const apiKeysHandler = new ApiKeysHandler(usuario, this.data, this.socket);
        return await apiKeysHandler.handleUpdateApiKey();
    }

    // Deletar API key
    async handleDeleteApiKey() {
        const usuario = await this.validarToken();
        const apiKeysHandler = new ApiKeysHandler(usuario, this.data, this.socket);
        return await apiKeysHandler.handleDeleteApiKey();
    }

    // Regenerar chave secreta
    async handleRegenerateSecretKey() {
        const usuario = await this.validarToken();
        const apiKeysHandler = new ApiKeysHandler(usuario, this.data, this.socket);
        return await apiKeysHandler.handleRegenerateSecretKey();
    }

    // Buscar estatísticas de uso
    async handleGetApiKeyStats() {
        const usuario = await this.validarToken();
        const apiKeysHandler = new ApiKeysHandler(usuario, this.data, this.socket);
        return await apiKeysHandler.handleGetApiKeyStats();
    }

    // Buscar transações da Gateway API
    async handleGetGatewayTransactions() {
        try {
            const { usuario, keyId, page = 1, limit = 50, status, paymentMethod, startDate, endDate } = this.data;

            if (!usuario || !usuario.id) {
                return this.socket?.emit('GetGatewayTransactions', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            let whereConditions = ['gt.user_id = ?'];
            let queryParams = [usuario.id];

            // Filtros opcionais
            if (keyId) {
                whereConditions.push('gt.api_key_id = ?');
                queryParams.push(keyId);
            }

            if (status) {
                whereConditions.push('gt.status = ?');
                queryParams.push(status);
            }

            if (paymentMethod) {
                whereConditions.push('gt.payment_method = ?');
                queryParams.push(paymentMethod);
            }

            if (startDate) {
                whereConditions.push('gt.created_at >= ?');
                queryParams.push(startDate);
            }

            if (endDate) {
                whereConditions.push('gt.created_at <= ?');
                queryParams.push(endDate);
            }

            const offset = (page - 1) * limit;
            queryParams.push(limit, offset);

            // Buscar transações
            const transactions = await this.db.query(`
                SELECT 
                    gt.*,
                    ak.key_name,
                    pp.name as provider_name,
                    JSON_UNQUOTE(JSON_EXTRACT(gt.customer_data, '$.name')) as customer_name,
                    JSON_UNQUOTE(JSON_EXTRACT(gt.customer_data, '$.email')) as customer_email
                FROM gateway_transactions gt
                LEFT JOIN user_api_keys ak ON gt.api_key_id = ak.id
                LEFT JOIN payment_providers pp ON gt.provider_id = pp.id
                WHERE ${whereConditions.join(' AND ')}
                ORDER BY gt.created_at DESC
                LIMIT ? OFFSET ?
            `, queryParams);

            // Contar total
            const countParams = queryParams.slice(0, -2); // Remove limit e offset
            const totalResult = await this.db.query(`
                SELECT COUNT(*) as total
                FROM gateway_transactions gt
                WHERE ${whereConditions.join(' AND ')}
            `, countParams);

            const total = totalResult[0].total;
            const totalPages = Math.ceil(total / limit);

            this.socket?.emit('GetGatewayTransactions', {
                sucesso: true,
                transactions: transactions,
                pagination: {
                    page: page,
                    limit: limit,
                    total: total,
                    totalPages: totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            });

        } catch (error) {
            console.error('Erro ao buscar transações gateway:', error);
            this.socket?.emit('GetGatewayTransactions', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Buscar detalhes de uma transação específica
    async handleGetGatewayTransactionDetails() {
        try {
            const { usuario, transactionId } = this.data;

            if (!usuario || !usuario.id) {
                return this.socket?.emit('GetGatewayTransactionDetails', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            const transaction = await this.db.query(`
                SELECT 
                    gt.*,
                    ak.key_name,
                    ak.public_key,
                    pp.name as provider_name,
                    pp.slug as provider_slug,
                    u.name as user_name,
                    u.email as user_email
                FROM gateway_transactions gt
                LEFT JOIN user_api_keys ak ON gt.api_key_id = ak.id
                LEFT JOIN payment_providers pp ON gt.provider_id = pp.id
                LEFT JOIN users u ON gt.user_id = u.id
                WHERE gt.transaction_id = ? AND gt.user_id = ?
                LIMIT 1
            `, [transactionId, usuario.id]);

            if (transaction.length === 0) {
                return this.socket?.emit('GetGatewayTransactionDetails', {
                    sucesso: false,
                    erro: 'Transação não encontrada'
                });
            }

            // Buscar webhooks relacionados
            const webhooks = await this.db.query(`
                SELECT * FROM gateway_webhooks
                WHERE transaction_id = ?
                ORDER BY created_at DESC
            `, [transactionId]);

            const transactionData = transaction[0];

            // Parse JSON fields
            ['customer_data', 'payment_data', 'provider_request', 'provider_response', 'webhook_data', 'error_data'].forEach(field => {
                if (transactionData[field]) {
                    try {
                        transactionData[field] = typeof transactionData[field] === 'string'
                            ? JSON.parse(transactionData[field])
                            : transactionData[field];
                    } catch (e) {
                        console.warn(`Erro ao fazer parse do campo ${field}:`, e);
                    }
                }
            });

            this.socket?.emit('GetGatewayTransactionDetails', {
                sucesso: true,
                transaction: transactionData,
                webhooks: webhooks
            });

        } catch (error) {
            console.error('Erro ao buscar detalhes da transação:', error);
            this.socket?.emit('GetGatewayTransactionDetails', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Buscar dashboard de estatísticas da Gateway
    async handleGetGatewayDashboard() {
        try {
            const { usuario, period = '30d' } = this.data;

            if (!usuario || !usuario.id) {
                return this.socket?.emit('GetGatewayDashboard', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            // Definir filtro de período
            let dateFilter = '';
            switch (period) {
                case '24h':
                    dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)';
                    break;
                case '7d':
                    dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
                    break;
                case '30d':
                    dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
                    break;
                case '90d':
                    dateFilter = 'AND created_at >= DATE_SUB(NOW(), INTERVAL 90 DAY)';
                    break;
            }

            // Estatísticas gerais
            const stats = await this.db.query(`
                SELECT 
                    COUNT(*) as total_transactions,
                    SUM(CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END) as approved_transactions,
                    SUM(CASE WHEN status = 'REJECTED' THEN 1 ELSE 0 END) as rejected_transactions,
                    SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending_transactions,
                    SUM(amount) as total_volume,
                    SUM(CASE WHEN status = 'APPROVED' THEN amount ELSE 0 END) as approved_volume,
                    AVG(amount) as avg_ticket,
                    COUNT(DISTINCT api_key_id) as active_keys
                FROM gateway_transactions 
                WHERE user_id = ? ${dateFilter}
            `, [usuario.id]);

            // Transações por dia
            const dailyTransactions = await this.db.query(`
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as transactions,
                    SUM(amount) as volume,
                    SUM(CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END) as approved
                FROM gateway_transactions 
                WHERE user_id = ? ${dateFilter}
                GROUP BY DATE(created_at)
                ORDER BY date DESC
                LIMIT 30
            `, [usuario.id]);

            // Por método de pagamento
            const paymentMethods = await this.db.query(`
                SELECT 
                    payment_method,
                    COUNT(*) as count,
                    SUM(amount) as volume,
                    AVG(amount) as avg_ticket
                FROM gateway_transactions 
                WHERE user_id = ? ${dateFilter}
                GROUP BY payment_method
            `, [usuario.id]);

            // Por provedor
            const providers = await this.db.query(`
                SELECT 
                    pp.name as provider_name,
                    COUNT(*) as count,
                    SUM(gt.amount) as volume,
                    SUM(CASE WHEN gt.status = 'APPROVED' THEN 1 ELSE 0 END) as approved
                FROM gateway_transactions gt
                JOIN payment_providers pp ON gt.provider_id = pp.id
                WHERE gt.user_id = ? ${dateFilter}
                GROUP BY pp.id, pp.name
            `, [usuario.id]);

            // Top API keys
            const topApiKeys = await this.db.query(`
                SELECT 
                    ak.key_name,
                    ak.public_key,
                    COUNT(*) as transactions,
                    SUM(gt.amount) as volume
                FROM gateway_transactions gt
                JOIN user_api_keys ak ON gt.api_key_id = ak.id
                WHERE gt.user_id = ? ${dateFilter}
                GROUP BY ak.id
                ORDER BY transactions DESC
                LIMIT 5
            `, [usuario.id]);

            const result = stats[0];
            const successRate = result.total_transactions > 0
                ? (result.approved_transactions / result.total_transactions) * 100
                : 0;

            this.socket?.emit('GetGatewayDashboard', {
                sucesso: true,
                dashboard: {
                    stats: {
                        ...result,
                        success_rate: successRate.toFixed(2)
                    },
                    daily_transactions: dailyTransactions,
                    payment_methods: paymentMethods,
                    providers: providers,
                    top_api_keys: topApiKeys,
                    period: period
                }
            });

        } catch (error) {
            console.error('Erro ao buscar dashboard gateway:', error);
            this.socket?.emit('GetGatewayDashboard', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }


};

module.exports = NovoCliente;