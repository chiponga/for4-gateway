const crypto = require('crypto');
const Database = require('../config/database');
const ZendryProvider = require('./ZendryProvider');
const HawkpayProvider = require('./HawkpayProvider');

class GatewayTransactionHandler {
    constructor(req, res) {
        this.req = req;
        this.res = res;
        this.db = new Database();
        this.user = req.user; // Vem do middleware de autenticação
        this.apiKey = req.apiKey; // Vem do middleware de autenticação
    }



    /**
     * POST /api/v1/transaction.purchaseCreditCard
     * Processa uma transação de CARTÃO DE CRÉDITO via HawkPay
     */
    async purchaseCreditCard() {
        try {
            /*───────────────
              1. EXTRAI E VALIDA O PAYLOAD
            ───────────────*/
            const {
                token,                // token do cartão (encrypt front-end)
                installments = 1,
                amount,               // em centavos
                name, email, cpf, phone,
                items,
                traceable = true,
                postbackUrl,
                externalId,
                metadata = {},
                // endereço (opcional)
                cep, complement, number, street, district, city, state
            } = this.req.body;

            if (!token) return this.errorResponse(400, 'Token do cartão obrigatório');
            if (!amount || amount < 100) return this.errorResponse(400, 'Valor mínimo R$ 1,00');
            if (!items || !items.length) return this.errorResponse(400, 'Pelo menos um item é obrigatório');

            /*───────────────
              2. BUSCA PROVEDOR HAWKPAY
            ───────────────*/
            const provider = await this.getHawkpayProviderForUser();
            if (!provider)
                return this.errorResponse(400, 'Provedor HawkPay não configurado para este usuário');

            const { public_key, secret_key } = provider.credentials;
            const hawkpay = new HawkpayProvider(public_key, secret_key);

            /*───────────────
              3. CRIA TRANSACÃO LOCAL
            ───────────────*/
            const transactionId = this.generateTransactionId();
            const customerData = {
                name, email, cpf, phone,
                address: { cep, complement, number, street, district, city, state }
            };

            const gatewayTxId = await this.createGatewayTransaction({
                transactionId,
                externalId,
                providerId: provider.provider_id,
                paymentMethod: 'credit_card',
                amount,
                customerData,
                items,
                metadata: { traceable, postbackUrl, ...metadata }
            });

            /*───────────────
              4. DISPARA PARA HAWKPAY
            ───────────────*/
            const hawkPayload = {
                amount,
                paymentMethod: 'credit_card',
                installments,
                card: { token },
                customer: {
                    name,
                    email,
                    phone,
                    document: { type: 'cpf', number: cpf },
                    address: {
                        street,
                        streetNumber: number,
                        complement,
                        zipCode: cep,
                        neighborhood: district,
                        city,
                        state,
                        country: 'BR'
                    }
                },
                items,
                postbackUrl,
                externalRef: transactionId,
                metadata
            };

            const hpRes = await hawkpay.createTransaction(hawkPayload);

            /*───────────────
              5. ATUALIZA TRANSACÃO LOCAL
            ───────────────*/
            await this.updateGatewayTransaction(gatewayTxId, {
                provider_transaction_id: hpRes.id,
                provider_response: JSON.stringify(hpRes),
                status: this.mapHawkpayStatus(hpRes.status)
            });

            /*───────────────
              6. RESPOSTA PADRÃO PARA CLIENTE
            ───────────────*/
            return this.successResponse({
                id: transactionId,
                installments,
                transactionId: hpRes.id,
                status: this.mapHawkpayStatus(hpRes.status),
                secureUrl: hpRes.secureUrl || null,
                amount,
                transactionFee: await this.calculateFee(amount, 0), // usa sua lógica
                metadata,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            });
        } catch (err) {
            console.error('Erro cartão HawkPay:', err);
            await this.logError('purchase_cc_error', err.message, {
                user_id: this.user.id,
                api_key_id: this.apiKey.id
            });
            return this.errorResponse(500, 'Erro interno ao processar cartão');
        }
    }

    /**
     * POST /api/v1/transaction.purchase
     * Processa uma transação PIX via Zendry
     */
    async purchase() {
        try {
            const {
                name, email, cpf, phone, paymentMethod,
                amount, traceable, items,
                cep, complement, number, street, district, city, state,
                utmQuery, checkoutUrl, referrerUrl, externalId, postbackUrl
            } = this.req.body;

            // Validação: apenas PIX por enquanto
            if (paymentMethod !== 'PIX') {
                return this.errorResponse(400, 'Apenas pagamentos PIX são suportados no momento');
            }

            // Validação dos dados obrigatórios
            const validationError = this.validatePurchaseData({
                name, email, cpf, phone, paymentMethod, amount, traceable, items
            });

            if (validationError) {
                return this.errorResponse(400, validationError);
            }

            // Gerar ID único da transação
            const transactionId = this.generateTransactionId();

            // Buscar provedor Zendry configurado para este usuário
            const provider = await this.getZendryProviderForUser();
            if (!provider) {
                return this.errorResponse(400, 'Provedor Zendry não configurado para este usuário');
            }

            // Preparar dados do cliente
            const customerData = {
                name, email, cpf, phone,
                address: { cep, complement, number, street, district, city, state }
            };

            // Salvar transação inicial no banco
            const gatewayTransactionId = await this.createGatewayTransaction({
                transactionId,
                externalId,
                providerId: provider.provider_id,
                paymentMethod: 'PIX',
                amount,
                customerData,
                items,
                metadata: {
                    utmQuery, checkoutUrl, referrerUrl, postbackUrl, traceable
                }
            });

            // Processar PIX com a Zendry
            const zendryProvider = new ZendryProvider(provider.credentials);
            const providerResponse = await zendryProvider.createPixQrCode({
                transactionId,
                amount,
                customerData,
                items,
                webhookUrl: provider.webhook_url
            });




            // Atualizar transação com resposta do provedor
            await this.updateGatewayTransaction(gatewayTransactionId, {
                gateway_transaction_id: providerResponse.transaction_id,
                provider_response: JSON.stringify(providerResponse),
                status: this.mapZendryStatus(providerResponse.status)
            });

            // Resposta padronizada
            const response = {
                id: transactionId,
                customId: externalId,
                installments: null,
                transactionId: providerResponse.transaction_id,
                chargeId: null,
                expiresAt: providerResponse.expires_at,
                dueAt: null,
                approvedAt: null,
                refundedAt: null,
                rejectedAt: null,
                chargebackAt: null,
                paymentProvider: "Zendry",
                availableAt: null,
                pixQrCode: providerResponse.qr_code,
                pixCode: providerResponse.pix_code,
                qr_code_base64: providerResponse.qr_code_base64,
                billetUrl: null,
                billetCode: null,
                customerId: `cust_${this.user.id}`,
                status: this.mapZendryStatus(providerResponse.status),
                address: customerData.address.street,
                district: customerData.address.district,
                number: customerData.address.number,
                complement: customerData.address.complement,
                city: customerData.address.city,
                state: customerData.address.state,
                zipCode: customerData.address.cep,
                amount: amount,
                transactionFee: await this.calculateFee(amount),
                taxSeller: this.calculateTax(amount),
                taxPlatform: 0,
                amountSeller: amount - this.calculateFee(amount),
                amountPlatform: 0,
                amountMaster: 0,
                amountGarantee: 0,
                taxGarantee: 0,
                garanteeReleaseAt: null,
                approvedEmailSentAt: null,
                traceable: traceable,
                method: "PIX",
                deliveryStatus: null,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                utmQuery: utmQuery,
                checkoutUrl: checkoutUrl,
                referrerUrl: referrerUrl,
                externalId: externalId,
                postbackUrl: postbackUrl
            };

            return this.successResponse(response);

        } catch (error) {
            console.error('Erro ao processar pagamento PIX:', error);

            // Log do erro no sistema
            await this.logError('purchase_error', error.message, {
                user_id: this.user.id,
                api_key_id: this.apiKey.id,
                payment_method: 'PIX'
            });

            return this.errorResponse(500, 'Erro interno do servidor');
        }
    }

    /**
     * GET /api/v1/transaction.getPayment
     * Obtém detalhes de uma transação
     */
    async getPayment() {
        try {
            const { id } = this.req.query;

            if (!id) {
                return this.errorResponse(400, 'ID da transação é obrigatório');
            }

            // Buscar transação no banco
            const transaction = await this.db.query(`
                SELECT 
                    gt.*,
                    pp.name as provider_name,
                    u.name as user_name
                FROM gateway_transactions gt
                LEFT JOIN payment_providers pp ON gt.provider_id = pp.id
                LEFT JOIN users u ON gt.user_id = u.id
                WHERE gt.transaction_id = ? AND gt.user_id = ?
            `, [id, this.user.id]);

            if (transaction.length === 0) {
                return this.errorResponse(404, 'Transação não encontrada');
            }

            const txn = transaction[0];
            const customerData = JSON.parse(txn.customer_data || '{}');
            const paymentData = JSON.parse(txn.payment_data || '{}');
            const providerResponse = JSON.parse(txn.provider_response || '{}');

            // Resposta padronizada
            const response = {
                id: txn.transaction_id,
                amount: parseFloat(txn.amount),
                status: txn.status,
                method: txn.payment_method,
                billetCode: null,
                billetUrl: null,
                pixCode: providerResponse.pix_code || null,
                pixQrCode: providerResponse.qr_code || null,
                customId: txn.external_id,
                dueAt: null,
                expiresAt: txn.expires_at,
                installments: null,
                items: this.parseItems(paymentData.items),
                customer: {
                    name: customerData.name,
                    email: customerData.email,
                    cpf: customerData.cpf,
                    phone: customerData.phone
                },
                deliveryStatus: null,
                trackingCode: null,
                createdAt: txn.created_at,
                updatedAt: txn.updated_at
            };

            return this.successResponse(response);

        } catch (error) {
            console.error('Erro ao buscar transação:', error);
            return this.errorResponse(500, 'Erro interno do servidor');
        }
    }

    /**
     * Busca o provedor Zendry configurado para o usuário
     */
    async getZendryProviderForUser() {
        try {
            const provider = await this.db.query(`
                SELECT 
                    aup.*,
                    pp.slug as provider_slug,
                    spp.credentials,
                    spp.webhook_url
                FROM admin_user_providers aup
                INNER JOIN payment_providers pp ON aup.provider_id = pp.id
                INNER JOIN system_payment_providers spp ON aup.system_provider_id = spp.id
                WHERE aup.user_id = ? 
                AND aup.payment_method = 'pix' 
                AND pp.slug = 'zendry'
                AND aup.is_active = 1
                ORDER BY aup.priority ASC
                LIMIT 1
            `, [this.user.id]);

            if (provider.length === 0) {
                return null;
            }

            const providerData = provider[0];
            return {
                ...providerData,
                credentials: JSON.parse(providerData.credentials)
            };

        } catch (error) {
            console.error('Erro ao buscar provedor:', error);
            return null;
        }
    }

    /**
     * Cria uma nova transação no banco
     */
    async createGatewayTransaction(data) {
        try {

            const valor = data.amount
            const taxas = await this.calculateFee(valor)


            const result = await this.db.query(`
                INSERT INTO gateway_transactions (
                    user_id, api_key_id, transaction_id, external_id,
                    provider_id, payment_method, amount, currency,
                    customer_data, payment_data, client_ip, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                this.user.id,
                this.apiKey.id,
                data.transactionId,
                data.externalId,
                data.providerId,
                data.paymentMethod,
                (valor - taxas),
                'BRL',
                JSON.stringify(data.customerData),
                JSON.stringify({
                    items: data.items,
                    metadata: data.metadata
                }),
                this.getClientIP(),
                this.req.headers['user-agent']
            ]);



            const resultadoPedido = await this.db.query(
                `INSERT INTO orders 
                (user_id, product_id, customer_name, customer_email, customer_phone, customer_document,
                amount, original_amount, discount_amount, net_amount, currency, payment_method,
                payment_status, order_status, gateway_transaction_id, payment_details, ip_address,
                created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    this.user.id, data?.externalId, data.customerData.name, data.customerData.email, data.customerData.phone, data.customerData.cpf,
                    (valor - taxas) / 100, valor / 100, 0, taxas / 100, // 3% de taxa
                    'BRL', data.paymentMethod, 'pending', 'pending', data.transactionId,
                    JSON.stringify(data.customerData || {}), this.getClientIP()
                ]
            );


            // Criar transação pendente
            await this.db.query(
                `INSERT INTO transactions 
                (user_id, order_id, type, category, amount, currency, status,gateway_transaction_id, description, created_at, updated_at) 
                VALUES (?, ?, 'sale', 'income', ?, 'BRL', 'pending',? , ?, NOW(), NOW())`,
                [this.user.id, resultadoPedido.insertId, (valor - taxas) / 100, data.transactionId, data?.externalId]
            );



            return result.insertId;

        } catch (error) {
            console.error('Erro ao criar transação:', error);
            throw error;
        }
    }

    /**
     * Atualiza uma transação existente
     */
    async updateGatewayTransaction(id, data) {
        try {
            const fields = [];
            const values = [];

            Object.keys(data).forEach(key => {
                fields.push(`${key} = ?`);
                values.push(data[key]);
            });

            values.push(id);

            await this.db.query(`
                UPDATE gateway_transactions 
                SET ${fields.join(', ')}, updated_at = NOW()
                WHERE id = ?
            `, values);

        } catch (error) {
            console.error('Erro ao atualizar transação:', error);
            throw error;
        }
    }

    /**
     * Validação dos dados de compra
     */
    validatePurchaseData(data) {
        const required = ['name', 'email', 'cpf', 'phone', 'paymentMethod', 'amount', 'items'];

        for (const field of required) {
            if (!data[field]) {
                return `Campo obrigatório: ${field}`;
            }
        }

        // Validar email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(data.email)) {
            return 'Email inválido';
        }

        // Validar CPF (11 dígitos)
        if (!/^\d{11}$/.test(data.cpf.replace(/\D/g, ''))) {
            return 'CPF deve conter 11 dígitos';
        }

        // Validar telefone (8-12 dígitos)
        const phoneDigits = data.phone.replace(/\D/g, '');
        if (phoneDigits.length < 8 || phoneDigits.length > 12) {
            return 'Telefone deve conter entre 8 e 12 dígitos';
        }

        // Validar valor mínimo (R$ 5,00 = 500 centavos)
        if (data.amount < 5) {
            return 'Valor mínimo da transação é R$ 5,00';
        }

        // Validar items
        if (!Array.isArray(data.items) || data.items.length === 0) {
            return 'Pelo menos um item é obrigatório';
        }

        return null;
    }

    /**
     * Gera ID único da transação
     */
    generateTransactionId() {
        const timestamp = Date.now();
        const random = crypto.randomBytes(4).toString('hex');
        return `txn_${timestamp}_${random}`;
    }

    /**
     * Mapeia status da Zendry para padrão interno
     */
    mapZendryStatus(zendryStatus) {
        const statusMap = {
            'pending': 'PENDING',
            'paid': 'APPROVED',
            'expired': 'EXPIRED',
            'cancelled': 'CANCELLED'
        };

        return statusMap[zendryStatus] || 'PENDING';
    }

    /**
     * Calcula taxa da transação
     */
    async calculateFee(amount, fixedFee = 0) {
        try {
            const [resultado] = await this.db.query(
                `SELECT * FROM user_permissions WHERE user_id = ?`,
                [this.user.id]
            );

            if (!resultado || resultado.length === 0) {
                return fixedFee;
            }

            const taxPixRaw = resultado.tax_pix?.toString().replace(',', '.');
            const taxPix = parseFloat(taxPixRaw);

            if (isNaN(taxPix)) {
                console.warn('Taxa PIX inválida, usando apenas taxa fixa.');
                return fixedFee;
            }

            const percentageFee = Math.floor(amount * (taxPix / 100));
            const totalFee = percentageFee + fixedFee;

            return totalFee; // em centavos
        } catch (error) {
            console.error('Erro ao calcular taxa:', error);
            return fixedFee;
        }
    }

    /**
     * Calcula imposto
     */
    calculateTax(amount) {
        // Taxa percentual de 5.99% para PIX
        return Math.round(amount * 0.0599);
    }

    /**
     * Parse dos items
     */
    parseItems(items) {
        if (!items || !Array.isArray(items)) return [];

        return items.map((item, index) => ({
            id: `item_${index + 1}`,
            unitPrice: item.unitPrice,
            quantity: item.quantity,
            title: item.title,
            tangible: item.tangible || false
        }));
    }

    /**
     * Obtém IP do cliente
     */
    getClientIP() {
        return this.req.headers['x-forwarded-for']?.split(',')[0] ||
            this.req.headers['x-real-ip'] ||
            this.req.connection.remoteAddress ||
            this.req.socket.remoteAddress ||
            '127.0.0.1';
    }

    /**
     * Log de erro no sistema
     */
    async logError(type, message, context = {}) {
        try {
            await this.db.query(`
                INSERT INTO system_logs (user_id, level, message, context, ip_address, user_agent)
                VALUES (?, 'error', ?, ?, ?, ?)
            `, [
                this.user.id,
                `Gateway API Error - ${type}: ${message}`,
                JSON.stringify(context),
                this.getClientIP(),
                this.req.headers['user-agent']
            ]);
        } catch (error) {
            console.error('Erro ao salvar log:', error);
        }
    }

    /**
     * Resposta de sucesso padronizada
     */
    successResponse(data) {
        this.res.status(200).json(data);
    }

    /**
     * Resposta de erro padronizada
     */
    errorResponse(status, message) {
        this.res.status(status).json({
            error: message,
            timestamp: new Date().toISOString()
        });
    }

    /**
 * Busca provedor HawkPay configurado para o usuário
 */
    async getHawkpayProviderForUser() {
        const rows = await this.db.query(`
    SELECT aup.*, pp.slug, spp.credentials
    FROM admin_user_providers aup
      INNER JOIN payment_providers pp ON aup.provider_id = pp.id
      INNER JOIN system_payment_providers spp ON aup.system_provider_id = spp.id
    WHERE aup.user_id = ? AND pp.slug = 'hawkpay' AND aup.payment_method = 'credit_card' AND aup.is_active = 1
    LIMIT 1
  `, [this.user.id]);

        if (!rows.length) return null;
        return { ...rows[0], credentials: JSON.parse(rows[0].credentials) };
    }

    mapHawkpayStatus(status) {
        const map = {
            waiting_payment: 'PENDING',
            pending: 'PENDING',
            approved: 'APPROVED',
            paid: 'APPROVED',
            refused: 'REJECTED',
            cancelled: 'CANCELLED',
            chargeback: 'CHARGEBACK',
            refunded: 'REFUNDED',
            in_protest: 'IN_DISPUTE'
        };
        return map[status] || 'PENDING';
    }
}

module.exports = GatewayTransactionHandler;