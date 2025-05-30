// src/handlers/NovoCliente.js
const Database = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

class NovoCliente {
    constructor(data, socket) {
        this.data = data || {};
        this.socket = socket;
        this.db = new Database();
        this.usuarioLogado = null;
    }

    // Método para enviar resposta pelo socket
    enviarResposta(evento, dados) {
        if (this.socket) {
            this.socket.emit(evento, dados);
        }
    }

    // Método para validar token e obter usuário
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

    //=================================================================
    // MÉTODOS DE AUTENTICAÇÃO
    //=================================================================

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
                'SELECT * FROM users WHERE email = ?',
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
                { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
            );

            this.enviarResposta('LoginResponse', {
                success: true,
                message: 'Login realizado com sucesso',
                token,
                user: {
                    id: usuario.id,
                    name: usuario.name,
                    email: usuario.email
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
            const { name, email, password } = this.data;

            if (!name || !email || !password) {
                return this.enviarResposta('RegistroResponse', {
                    success: false,
                    message: 'Nome, email e senha são obrigatórios'
                });
            }

            // Verificar se o email já existe
            const usuariosExistentes = await this.db.query(
                'SELECT * FROM users WHERE email = ?',
                [email]
            );

            if (usuariosExistentes.length > 0) {
                return this.enviarResposta('RegistroResponse', {
                    success: false,
                    message: 'Este email já está em uso'
                });
            }

            // Hash da senha
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Inserir usuário no banco
            const resultado = await this.db.query(
                'INSERT INTO users (name, email, password, status, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())',
                [name, email, hashedPassword, 'active']
            );

            // Criar configurações iniciais para o usuário
            await this.db.query(
                'INSERT INTO user_settings (user_id, created_at, updated_at) VALUES (?, NOW(), NOW())',
                [resultado.insertId]
            );

            this.enviarResposta('RegistroResponse', {
                success: true,
                message: 'Conta criada com sucesso'
            });

        } catch (error) {
            console.error('Erro no registro:', error);
            this.enviarResposta('RegistroResponse', {
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
                    email: usuario.email
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

    //=================================================================
    // MÉTODOS DE DASHBOARD
    //=================================================================

    async handleDadosDashboard() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('DadosDashboardResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar dados do dashboard
            const vendasHoje = await this.db.query(
                `SELECT 
                    SUM(amount) as value, 
                    COUNT(*) as count 
                FROM orders 
                WHERE user_id = ? 
                AND DATE(created_at) = CURDATE()`,
                [usuario.id]
            );

            const vendasOntem = await this.db.query(
                `SELECT 
                    SUM(amount) as value
                FROM orders 
                WHERE user_id = ? 
                AND DATE(created_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)`,
                [usuario.id]
            );

            const saldoDisponivel = await this.db.query(
                `SELECT 
                    SUM(IF(category = 'income', amount, -amount)) as balance 
                FROM transactions 
                WHERE user_id = ? 
                AND status = 'completed'`,
                [usuario.id]
            );

            const saldoPendente = await this.db.query(
                `SELECT 
                    SUM(IF(category = 'income', amount, -amount)) as balance 
                FROM transactions 
                WHERE user_id = ? 
                AND status = 'pending'`,
                [usuario.id]
            );

            const metaFaturamento = await this.db.query(
                `SELECT 
                    SUM(amount) as current
                FROM orders 
                WHERE user_id = ? 
                AND MONTH(created_at) = MONTH(CURRENT_DATE())
                AND YEAR(created_at) = YEAR(CURRENT_DATE())
                AND payment_status = 'paid'`,
                [usuario.id]
            );

            // Obter métodos de pagamento
            const metodosPagamento = await this.db.query(
                `SELECT 
                    payment_method, 
                    SUM(amount) as value,
                    COUNT(*) as count
                FROM orders 
                WHERE user_id = ? 
                AND payment_status = 'paid'
                AND MONTH(created_at) = MONTH(CURRENT_DATE())
                AND YEAR(created_at) = YEAR(CURRENT_DATE())
                GROUP BY payment_method`,
                [usuario.id]
            );

            // Calcular variação percentual em relação ao dia anterior
            const vendasHojeValor = vendasHoje[0].value || 0;
            const vendasOntemValor = vendasOntem[0].value || 0;
            const variation = vendasOntemValor === 0 ? 0 :
                Math.round(((vendasHojeValor - vendasOntemValor) / vendasOntemValor) * 100);

            // Organizar métodos de pagamento
            const paymentMethods = {
                pix: { percentage: 0, value: 0 },
                card: { percentage: 0, value: 0 },
                boleto: { percentage: 0, value: 0 },
                crypto: { percentage: 0, value: 0 }
            };

            const totalVendas = metodosPagamento.reduce((acc, method) => acc + (method.value || 0), 0);

            metodosPagamento.forEach(method => {
                const methodKey = method.payment_method.includes('pix') ? 'pix' :
                    method.payment_method.includes('card') ? 'card' :
                        method.payment_method.includes('boleto') ? 'boleto' : 'crypto';

                paymentMethods[methodKey].value = method.value || 0;
                paymentMethods[methodKey].percentage = totalVendas === 0 ? 0 :
                    Math.round((method.value / totalVendas) * 100);
            });

            // Meta de faturamento mensal (definida como 10000)
            const metaAtual = metaFaturamento[0].current || 0;
            const metaAlvo = 10000;
            const percentualMeta = Math.min(Math.round((metaAtual / metaAlvo) * 100), 100);

            this.enviarResposta('DadosDashboardResponse', {
                success: true,
                data: {
                    sales_today: {
                        value: vendasHojeValor,
                        variation: variation
                    },
                    available_balance: saldoDisponivel[0].balance || 0,
                    pending_balance: saldoPendente[0].balance || 0,
                    billing_goal: {
                        current: metaAtual,
                        target: metaAlvo,
                        percentage: percentualMeta
                    },
                    payment_methods: paymentMethods,
                    // Métricas adicionais
                    visitors_today: Math.floor(1000 + Math.random() * 500),
                    conversion_rate: 2.5 + (Math.random() * 2),
                    average_ticket: vendasHoje[0].count > 0 ?
                        vendasHojeValor / vendasHoje[0].count : 0,
                    active_products: Math.floor(40 + Math.random() * 20),
                    pending_count: Math.floor(3 + Math.random() * 10)
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
            const periodDays = period === '30d' ? 30 : period === '15d' ? 15 : 7;

            // Buscar dados de vendas por dia
            const vendasPorDia = await this.db.query(
                `SELECT 
                    DATE(created_at) as date,
                    SUM(amount) as revenue,
                    COUNT(*) as sales_count
                FROM orders 
                WHERE user_id = ? 
                AND created_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
                GROUP BY DATE(created_at)
                ORDER BY date ASC`,
                [usuario.id, periodDays]
            );

            // Preparar arrays para o gráfico
            const labels = [];
            const revenue = [];
            const sales_count = [];
            const visitors = [];
            const conversions = [];

            // Preencher dias faltantes
            for (let i = periodDays - 1; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                const dateString = date.toISOString().split('T')[0];

                labels.push(dateString);

                // Encontrar dados para esta data
                const dadosData = vendasPorDia.find(v => v.date === dateString);

                if (dadosData) {
                    revenue.push(Number(dadosData.revenue) || 0);
                    sales_count.push(Number(dadosData.sales_count) || 0);
                } else {
                    revenue.push(0);
                    sales_count.push(0);
                }

                // Simular dados de visitantes e conversões
                const baseVisitors = Math.floor(sales_count[sales_count.length - 1] * 12 + Math.random() * 100);
                visitors.push(baseVisitors);
                conversions.push(sales_count[sales_count.length - 1]);
            }

            this.enviarResposta('PerformanceDashboardResponse', {
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

            // Buscar transações recentes
            const transacoes = await this.db.query(
                `SELECT 
                    t.*,
                    o.gateway_transaction_id,
                    o.customer_name,
                    o.product_id,
                    p.name as product_name
                FROM transactions t
                LEFT JOIN orders o ON t.order_id = o.id
                LEFT JOIN products p ON o.product_id = p.id
                WHERE t.user_id = ? 
                ORDER BY t.created_at DESC
                LIMIT 10`,
                [usuario.id]
            );

            // Formatar os dados
            const statements = transacoes.map(t => ({
                id: t.id,
                date: t.created_at,
                type: t.type,
                description: t.description ||
                    (t.type === 'sale' ? `Venda: ${t.product_name || 'Produto'}` :
                        t.type === 'withdrawal' ? 'Saque' :
                            t.type === 'commission' ? 'Comissão de afiliado' :
                                t.type === 'refund' ? 'Reembolso' : t.type),
                amount: t.amount,
                status: t.status,
                customer: t.customer_name,
                reference: t.gateway_transaction_id
            }));

            this.enviarResposta('StatementDashboardResponse', {
                success: true,
                data: {
                    statements
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

    //=================================================================
    // MÉTODOS FINANCEIROS
    //=================================================================

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
                    w.*,
                    b.bank_name,
                    b.agency,
                    b.account,
                    b.account_type,
                    b.holder_name
                FROM withdrawals w
                LEFT JOIN bank_accounts b ON w.bank_account_id = b.id
                WHERE w.user_id = ? 
                ORDER BY w.created_at DESC
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

    //=================================================================
    // MÉTODOS DE PRODUTOS
    //=================================================================

    async handleGetProducts() {
        try {
            const usuario = await this.validarToken();

            if (!usuario) {
                return this.enviarResposta('GetProductsResponse', {
                    success: false,
                    message: 'Usuário não autenticado'
                });
            }

            // Buscar produtos
            const produtos = await this.db.query(
                `SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC`,
                [usuario.id]
            );

            this.enviarResposta('GetProductsResponse', {
                success: true,
                data: produtos
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

            const {
                name, description, type, price, category,
                image, digital_file, stock_quantity = null,
                allow_affiliates = false, commission_rate = 0
            } = this.data;

            if (!name || !type || !price) {
                return this.enviarResposta('CreateProductResponse', {
                    success: false,
                    message: 'Nome, tipo e preço são obrigatórios'
                });
            }

            // Processar imagem, se fornecida
            let image_url = null;
            if (image) {
                // Salvar imagem no servidor
                const imageBuffer = Buffer.from(image.split(',')[1], 'base64');
                const imageExt = image.match(/data:image\/(\w+);/)[1];
                const imageName = `product_${Date.now()}.${imageExt}`;
                const imagePath = path.join(process.cwd(), 'uploads', 'imagens', imageName);

                fs.writeFileSync(imagePath, imageBuffer);
                image_url = `/images/${imageName}`;
            }

            // Processar arquivo digital, se fornecido
            let digital_file_url = null;
            if (digital_file && type === 'digital') {
                // Salvar arquivo no servidor
                const fileBuffer = Buffer.from(digital_file.split(',')[1], 'base64');
                const fileExt = digital_file.match(/data:application\/(\w+);/)[1];
                const fileName = `digital_${Date.now()}.${fileExt}`;
                const filePath = path.join(process.cwd(), 'uploads', 'arquivos', fileName);

                // Garantir que o diretório existe
                const dir = path.dirname(filePath);
                if (!fs.existsSync(dir)) {
                    fs.mkdirSync(dir, { recursive: true });
                }

                fs.writeFileSync(filePath, fileBuffer);
                digital_file_url = `/files/${fileName}`;
            }

            // Inserir produto
            const resultado = await this.db.query(
                `INSERT INTO products 
                (user_id, name, description, type, category, price, status, image_url, digital_file_url, 
                stock_quantity, track_stock, allow_affiliates, commission_rate, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    usuario.id, name, description, type, category, price,
                    image_url, digital_file_url, stock_quantity,
                    stock_quantity !== null, allow_affiliates, commission_rate
                ]
            );

            this.enviarResposta('CreateProductResponse', {
                success: true,
                message: 'Produto criado com sucesso',
                data: {
                    id: resultado.insertId,
                    name,
                    type,
                    price
                }
            });

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

            const {
                id, name, description, type, price, category,
                image, digital_file, stock_quantity,
                allow_affiliates, commission_rate, status
            } = this.data;

            if (!id || !name || !type || !price) {
                return this.enviarResposta('UpdateProductResponse', {
                    success: false,
                    message: 'ID, nome, tipo e preço são obrigatórios'
                });
            }

            // Verificar se o produto pertence ao usuário
            const produtos = await this.db.query(
                'SELECT * FROM products WHERE id = ? AND user_id = ?',
                [id, usuario.id]
            );

            if (produtos.length === 0) {
                return this.enviarResposta('UpdateProductResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const produto = produtos[0];

            // Processar imagem, se fornecida
            let image_url = produto.image_url;
            if (image && image.startsWith('data:image')) {
                // Salvar imagem no servidor
                const imageBuffer = Buffer.from(image.split(',')[1], 'base64');
                const imageExt = image.match(/data:image\/(\w+);/)[1];
                const imageName = `product_${Date.now()}.${imageExt}`;
                const imagePath = path.join(process.cwd(), 'uploads', 'imagens', imageName);

                fs.writeFileSync(imagePath, imageBuffer);
                image_url = `/images/${imageName}`;

                // Remover imagem antiga, se existir
                if (produto.image_url && produto.image_url !== image_url) {
                    const oldImagePath = path.join(process.cwd(), produto.image_url.replace('/images/', 'uploads/imagens/'));
                    if (fs.existsSync(oldImagePath)) {
                        fs.unlinkSync(oldImagePath);
                    }
                }
            }

            // Processar arquivo digital, se fornecido
            let digital_file_url = produto.digital_file_url;
            if (digital_file && digital_file.startsWith('data:') && type === 'digital') {
                // Salvar arquivo no servidor
                const fileBuffer = Buffer.from(digital_file.split(',')[1], 'base64');
                const fileExt = digital_file.match(/data:application\/(\w+);/)[1];
                const fileName = `digital_${Date.now()}.${fileExt}`;
                const filePath = path.join(process.cwd(), 'uploads', 'arquivos', fileName);

                // Garantir que o diretório existe
                const dir = path.dirname(filePath);
                if (!fs.existsSync(dir)) {
                    fs.mkdirSync(dir, { recursive: true });
                }

                fs.writeFileSync(filePath, fileBuffer);
                digital_file_url = `/files/${fileName}`;

                // Remover arquivo antigo, se existir
                if (produto.digital_file_url && produto.digital_file_url !== digital_file_url) {
                    const oldFilePath = path.join(process.cwd(), produto.digital_file_url.replace('/files/', 'uploads/arquivos/'));
                    if (fs.existsSync(oldFilePath)) {
                        fs.unlinkSync(oldFilePath);
                    }
                }
            }

            // Atualizar produto
            await this.db.query(
                `UPDATE products SET
                name = ?, 
                description = ?, 
                type = ?, 
                category = ?, 
                price = ?, 
                status = ?,
                image_url = ?, 
                digital_file_url = ?, 
                stock_quantity = ?, 
                track_stock = ?, 
                allow_affiliates = ?, 
                commission_rate = ?,
                updated_at = NOW()
                WHERE id = ? AND user_id = ?`,
                [
                    name, description, type, category, price, status || produto.status,
                    image_url, digital_file_url, stock_quantity,
                    stock_quantity !== null, allow_affiliates, commission_rate,
                    id, usuario.id
                ]
            );

            this.enviarResposta('UpdateProductResponse', {
                success: true,
                message: 'Produto atualizado com sucesso',
                data: {
                    id,
                    name,
                    type,
                    price,
                    status: status || produto.status
                }
            });

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

            const { id } = this.data;

            if (!id) {
                return this.enviarResposta('DeleteProductResponse', {
                    success: false,
                    message: 'ID do produto é obrigatório'
                });
            }

            // Verificar se o produto pertence ao usuário
            const produtos = await this.db.query(
                'SELECT * FROM products WHERE id = ? AND user_id = ?',
                [id, usuario.id]
            );

            if (produtos.length === 0) {
                return this.enviarResposta('DeleteProductResponse', {
                    success: false,
                    message: 'Produto não encontrado'
                });
            }

            const produto = produtos[0];

            // Verificar se há pedidos associados a este produto
            const pedidos = await this.db.query(
                'SELECT COUNT(*) as total FROM orders WHERE product_id = ?',
                [id]
            );

            if (pedidos[0].total > 0) {
                // Não excluir, apenas inativar o produto
                await this.db.query(
                    'UPDATE products SET status = ?, updated_at = NOW() WHERE id = ?',
                    ['inactive', id]
                );

                this.enviarResposta('DeleteProductResponse', {
                    success: true,
                    message: 'Produto inativado com sucesso. Não foi possível excluir pois existem pedidos associados a ele.'
                });
            } else {
                // Excluir imagem e arquivo digital, se existirem
                if (produto.image_url) {
                    const imagePath = path.join(process.cwd(), produto.image_url.replace('/images/', 'uploads/imagens/'));
                    if (fs.existsSync(imagePath)) {
                        fs.unlinkSync(imagePath);
                    }
                }

                if (produto.digital_file_url) {
                    const filePath = path.join(process.cwd(), produto.digital_file_url.replace('/files/', 'uploads/arquivos/'));
                    if (fs.existsSync(filePath)) {
                        fs.unlinkSync(filePath);
                    }
                }

                // Excluir produto
                await this.db.query(
                    'DELETE FROM products WHERE id = ?',
                    [id]
                );

                this.enviarResposta('DeleteProductResponse', {
                    success: true,
                    message: 'Produto excluído com sucesso'
                });
            }

        } catch (error) {
            console.error('Erro ao excluir produto:', error);
            this.enviarResposta('DeleteProductResponse', {
                success: false,
                message: 'Erro ao excluir produto'
            });
        }
    }

    //=================================================================
    // MÉTODOS DE PEDIDOS/TRANSAÇÕES
    //=================================================================

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
                    qrcode: 'data:image/png;base64,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',
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

    //=================================================================
    // MÉTODOS DE PERFIL E CONFIGURAÇÕES
    //=================================================================

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

    // Adicione estes métodos à classe NovoCliente no arquivo src/handlers/NovoCliente.js

    //=================================================================
    // MÉTODOS DE CONFIGURAÇÕES
    //=================================================================

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

    //=================================================================
    // MÉTODOS DE AFILIADOS
    //=================================================================

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

    //=================================================================
    // MÉTODO DE WEBHOOK DE PAGAMENTO (ADICIONAL)
    //=================================================================

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

    //=================================================================
    // MÉTODOS AUXILIARES PARA WEBHOOKS
    //=================================================================

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

};

module.exports = NovoCliente;