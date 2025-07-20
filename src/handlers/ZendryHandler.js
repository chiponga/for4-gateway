// handlers/ZendryHandler.js
const { Criptografar, Descriptografar } = require('../utils/crypto');

class ZendryHandler {
    constructor(credentials, testMode = false) {
        this.clientId = credentials.client_id;
        this.clientSecret = credentials.client_secret;
        this.testMode = testMode;
        this.baseUrl = testMode 
            ? 'https://api-sandbox.zendry.com.br' 
            : 'https://api.zendry.com.br';
    }

    async generateAccessToken() {
        try {
            const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
            
            const response = await fetch(`${this.baseUrl}/auth/generate_token`, {
                method: 'POST',
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    grant_type: 'client_credentials'
                })
            });

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Erro ao gerar token');
            }

            return data.access_token;
        } catch (error) {
            console.error('Erro ao gerar token Zendry:', error);
            throw error;
        }
    }

    async processPayment(paymentData) {
        try {
            const token = await this.generateAccessToken();
            
            const payload = {
                amount: paymentData.amount,
                currency: 'BRL',
                payment_method: paymentData.payment_method,
                customer: {
                    name: paymentData.customer.name,
                    email: paymentData.customer.email,
                    document: paymentData.customer.document
                },
                metadata: {
                    user_id: paymentData.user_id,
                    product_id: paymentData.product_id,
                    platform: 'for4gateway'
                }
            };

            const response = await fetch(`${this.baseUrl}/payments`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (!response.ok) {
                return {
                    success: false,
                    message: result.message || 'Erro no processamento Zendry',
                    error_code: result.error_code
                };
            }

            return {
                success: true,
                transaction_id: result.id,
                status: result.status,
                payment_url: result.payment_url,
                qr_code: result.qr_code,
                expires_at: result.expires_at,
                provider: 'zendry'
            };

        } catch (error) {
            console.error('Erro no processamento Zendry:', error);
            return {
                success: false,
                message: 'Erro de conexão com Zendry',
                error: error.message
            };
        }
    }

    async handleWebhook(webhookData) {
        try {
            // Validar assinatura do webhook
            const isValid = this.validateWebhookSignature(webhookData);
            
            if (!isValid) {
                throw new Error('Assinatura do webhook inválida');
            }

            return {
                success: true,
                event: webhookData.event,
                payment_id: webhookData.payment.id,
                status: webhookData.payment.status,
                amount: webhookData.payment.amount
            };

        } catch (error) {
            console.error('Erro no webhook Zendry:', error);
            return {
                success: false,
                message: error.message
            };
        }
    }

    validateWebhookSignature(webhookData) {
        // Implementar validação específica da Zendry
        return true; // Placeholder
    }
}

module.exports = ZendryHandler;