const axios = require('axios');
const Database = require('../config/database');

class ZendryProvider {
    constructor(credentials) {
        this.clientId = credentials.client_id || credentials['Chave pública'];
        this.clientSecret = credentials.client_secret || credentials['Chave privada'];
        this.baseUrl = 'https://api.zendry.com.br/v1';
        this.db = new Database();
        this.accessToken = null;
        this.tokenExpiry = null;
    }

    async getAccessToken() {
        const cached = await this.getCachedToken();
        if (cached && cached.expires_at > new Date()) {
            this.accessToken = cached.token;
            return this.accessToken;
        }

        try {
            const authString = `${this.clientId}:${this.clientSecret}`;
            const encoded = Buffer.from(authString).toString('base64');

            const response = await axios.post('https://api.zendry.com.br/auth/generate_token', {
                grant_type: 'client_credentials'
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Basic ${encoded}`
                }
            });

            console.log(response)

            const { access_token, expires_in } = response.data;
            this.accessToken = access_token;
            this.tokenExpiry = new Date(Date.now() + (expires_in - 300) * 1000); // 5 min antes do expirar
            await this.cacheToken(this.accessToken, this.tokenExpiry);
            return this.accessToken;

        } catch (err) {
            console.error('Erro ao obter token:', err.response?.data || err.message);
            throw new Error('Autenticação falhou');
        }
    }

    async createPixPayment(data) {
        const token = await this.getAccessToken();

        const payload = {
            initiation_type: 'dict',
            idempotent_id: data.transactionId,
            receiver_name: data.customerData.name,
            receiver_document: data.customerData.cpf.replace(/\D/g, ''),
            value_cents: data.amount,
            pix_key_type: 'cpf',
            pix_key: data.customerData.cpf.replace(/\D/g, ''),
            authorized: false
        };

        try {
            const response = await axios.post(`${this.baseUrl}/pix/payments`, payload, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            const payment = response.data.payment;

            return {
                transaction_id: payment.reference_code,
                status: payment.status,
                value_cents: payment.value_cents,
                pix_key: payment.pix_key,
                raw_response: response.data
            };

        } catch (err) {
            console.error('Erro ao criar pagamento:', err.response?.data || err.message);
            throw new Error('Falha ao criar pagamento Pix');
        }
    }

    async createPixQrCode(data) {
        const token = await this.getAccessToken();

        const payload = {
            value_cents: data.amount, // valor em centavos (ex: 10000 = R$100)
            generator_name: data.customerData.name,
            generator_document: data.customerData.cpf.replace(/\D/g, ''),
            expiration_time: 1800, // expira em 30 minutos
            external_reference: data.transactionId // seu código interno de rastreio
        };

        try {
            const response = await axios.post(`${this.baseUrl}/pix/qrcodes`, payload, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            const qrCode = response.data.qrcode;

            return {
                reference_code: qrCode.reference_code,
                external_reference: qrCode.external_reference,
                pix_code: qrCode.content, // código copia e cola
                qr_code_base64: qrCode.image_base64 || null, // pode ser null
                raw_response: response.data
            };

        } catch (err) {
            console.error('Erro ao gerar QR Code Pix:', err.response?.data || err.message);
            throw new Error('Falha ao gerar cobrança Pix');
        }
    }


    async getPaymentStatus(transactionId) {
        const token = await this.getAccessToken();

        try {
            const response = await axios.get(`${this.baseUrl}/pix/payments/${transactionId}`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });

            return {
                transaction_id: response.data.id,
                status: response.data.status,
                amount: response.data.amount * 100,
                paid_at: response.data.paid_at,
                raw_response: response.data
            };
        } catch (err) {
            console.error('Erro ao consultar status:', err.response?.data || err.message);
            throw new Error('Erro ao consultar pagamento');
        }
    }

    async processWebhook(data) {
        const payload = data.data || data;
        return {
            transaction_id: payload.id,
            external_id: payload.external_id,
            status: payload.status,
            amount: payload.amount * 100,
            paid_at: payload.paid_at,
            event_type: data.event || 'payment.updated',
            raw_data: data
        };
    }

    async getCachedToken() {
        const rows = await this.db.query(`
            SELECT token_hash, expires_at FROM provider_tokens
            WHERE provider_id = (SELECT id FROM payment_providers WHERE slug = 'zendry')
              AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1
        `);
        if (rows.length > 0) {
            return {
                token: rows[0].token_hash,
                expires_at: new Date(rows[0].expires_at)
            };
        }
        return null;
    }

    async cacheToken(token, expires_at) {
        const providers = await this.db.query(`
            SELECT id FROM payment_providers WHERE slug = 'zendry' LIMIT 1
        `);
        if (providers.length === 0) return;
        const providerId = providers[0].id;

        await this.db.query(`
            DELETE FROM provider_tokens WHERE provider_id = ? AND expires_at <= NOW()
        `, [providerId]);

        await this.db.query(`
            INSERT INTO provider_tokens (provider_id, user_id, token_hash, token_type, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `, [providerId, 1, token, 'Bearer', expires_at]);
    }

    async clearTokenCache() {
        await this.db.query(`
            DELETE FROM provider_tokens WHERE provider_id = (
                SELECT id FROM payment_providers WHERE slug = 'zendry'
            )
        `);
        this.accessToken = null;
        this.tokenExpiry = null;
    }

    mapStatus(zendryStatus) {
        const map = {
            pending: 'PENDING',
            processing: 'PENDING',
            paid: 'APPROVED',
            cancelled: 'CANCELLED',
            expired: 'EXPIRED',
            failed: 'REJECTED',
            refunded: 'REFUNDED',
            chargeback: 'CHARGEBACK'
        };
        return map[zendryStatus] || 'PENDING';
    }

    formatError(error) {
        if (error.response?.data) {
            return {
                code: error.response.status,
                message: error.response.data.message || 'Erro na Zendry',
                details: error.response.data
            };
        }
        return {
            code: 500,
            message: error.message || 'Erro interno',
            details: null
        };
    }
}

module.exports = ZendryProvider;
