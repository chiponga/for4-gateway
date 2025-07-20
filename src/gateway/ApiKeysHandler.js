// ==========================================
// SISTEMA DE API KEYS - BACKEND COMPLETO
// ==========================================

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('../config/database')

// ==========================================
// 1. GERADOR DE API KEYS SEGURAS
// ==========================================
class ApiKeyGenerator {
    static generate(environment = 'test', type = 'secret') {
        const randomBytes = crypto.randomBytes(32);
        const keyData = randomBytes.toString('hex');

        const prefix = type === 'secret'
            ? (environment === 'live' ? 'sk_live_' : 'sk_test_')
            : (environment === 'live' ? 'pk_live_' : 'pk_test_');

        return prefix + keyData;
    }

    static async hashSecretKey(secretKey) {
        return await bcrypt.hash(secretKey, 12);
    }

    static async validateSecretKey(secretKey, hash) {
        return await bcrypt.compare(secretKey, hash);
    }

    static extractEnvironment(key) {
        if (key.startsWith('sk_live_') || key.startsWith('pk_live_')) return 'live';
        if (key.startsWith('sk_test_') || key.startsWith('pk_test_')) return 'test';
        return null;
    }

    static isValidKeyFormat(key) {
        const patterns = [
            /^sk_test_[a-f0-9]{64}$/,
            /^sk_live_[a-f0-9]{64}$/,
            /^pk_test_[a-f0-9]{64}$/,
            /^pk_live_[a-f0-9]{64}$/
        ];
        return patterns.some(pattern => pattern.test(key));
    }
}

// ==========================================
// 2. HANDLER PRINCIPAL DE API KEYS
// ==========================================
class ApiKeysHandler {
    constructor(usuarioAuth, data, socket) {
        this.data = data;
        this.user = usuarioAuth;
        this.socket = socket;
        this.db = new db();
    }

    // Buscar API keys do usuário
    async handleGetApiKeys() {
        try {



            if (!this.user || !this.user.id) {
                return this.socket?.emit('GetApiKeys', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            const apiKeys = await this.db.query(`
                SELECT 
                    ak.*,
                    COALESCE(stats.transaction_count, 0) as transaction_count,
                    COALESCE(stats.total_amount, 0.00) as total_amount,
                    COALESCE(stats.success_rate, 0.00) as success_rate
                FROM user_api_keys ak
                LEFT JOIN (
                    SELECT 
                        api_key_id,
                        COUNT(*) as transaction_count,
                        SUM(amount) as total_amount,
                        (COUNT(CASE WHEN status = 'APPROVED' THEN 1 END) / COUNT(*)) * 100 as success_rate
                    FROM gateway_transactions
                    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                    GROUP BY api_key_id
                ) stats ON ak.id = stats.api_key_id
                WHERE ak.user_id = ? 
                ORDER BY ak.created_at DESC
            `, [this.user.id]);

            // Mascarar chaves secretas para segurança
            const maskedKeys = apiKeys.map(key => ({
                ...key,
                secret_key_hash: undefined, // Remove o hash
                public_key_masked: this.maskKey(key.public_key),
                permissions: typeof key.permissions === 'string'
                    ? JSON.parse(key.permissions)
                    : key.permissions
            }));

            this.socket?.emit('GetApiKeys', {
                sucesso: true,
                apiKeys: maskedKeys
            });

        } catch (error) {
            console.error('Erro ao buscar API keys:', error);
            this.socket?.emit('GetApiKeys', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Criar nova API key
    async handleCreateApiKey() {
        try {
            const { keyName, environment, permissions, allowedIps } = this.data;

            if (!this.user || !this.user.id) {
                return this.socket?.emit('CreateApiKey', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            // Validações
            if (!keyName || keyName.trim().length < 3) {
                return this.socket?.emit('CreateApiKey', {
                    sucesso: false,
                    erro: 'Nome da chave deve ter pelo menos 3 caracteres'
                });
            }

            if (!environment || !['test', 'live'].includes(environment)) {
                return this.socket?.emit('CreateApiKey', {
                    sucesso: false,
                    erro: 'Ambiente deve ser test ou live'
                });
            }

            // Verificar se nome já existe para o usuário
            const existingKey = await this.db.query(`
                SELECT id FROM user_api_keys 
                WHERE user_id = ? AND key_name = ?
            `, [this.user.id, keyName.trim()]);

            if (existingKey.length > 0) {
                return this.socket?.emit('CreateApiKey', {
                    sucesso: false,
                    erro: 'Já existe uma chave com este nome'
                });
            }

            // Gerar chaves
            const publicKey = ApiKeyGenerator.generate(environment, 'public');
            const secretKey = ApiKeyGenerator.generate(environment, 'secret');
            const secretKeyHash = await ApiKeyGenerator.hashSecretKey(secretKey);

            // Permissões padrão
            const defaultPermissions = {
                create_tokens: true,
                process_payments: true,
                view_transactions: true,
                receive_webhooks: true,
                ...permissions
            };

            // Inserir no banco
            const result = await this.db.query(`
                INSERT INTO user_api_keys (
                    user_id, key_name, public_key, secret_key_hash, 
                    environment, permissions, allowed_ips
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
                this.user.id,
                keyName.trim(),
                publicKey,
                secretKeyHash,
                environment,
                JSON.stringify(defaultPermissions),
                allowedIps ? JSON.stringify(allowedIps) : null
            ]);

            // Log da criação
            await this.db.query(`
                INSERT INTO system_logs (user_id, level, message, context) 
                VALUES (?, 'info', 'Nova API key criada', ?)
            `, [
                this.user.id,
                JSON.stringify({
                    key_name: keyName,
                    environment: environment,
                    public_key: publicKey
                })
            ]);

            this.socket?.emit('CreateApiKey', {
                sucesso: true,
                apiKey: {
                    id: result.insertId,
                    key_name: keyName,
                    public_key: publicKey,
                    secret_key: secretKey, // Só retorna na criação!
                    environment: environment,
                    permissions: defaultPermissions,
                    created_at: new Date()
                },
                mensagem: 'API key criada com sucesso! Guarde a chave secreta, ela não será exibida novamente.'
            });

        } catch (error) {
            console.error('Erro ao criar API key:', error);
            this.socket?.emit('CreateApiKey', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Atualizar API key
    async handleUpdateApiKey() {
        try {
            const { keyId, keyName, permissions, allowedIps, isActive } = this.data;

            if (!this.user || !this.user.id) {
                return this.socket?.emit('UpdateApiKey', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            // Verificar se a key pertence ao usuário
            const existingKey = await this.db.query(`
                SELECT * FROM user_api_keys 
                WHERE id = ? AND user_id = ?
            `, [keyId, this.user.id]);

            if (existingKey.length === 0) {
                return this.socket?.emit('UpdateApiKey', {
                    sucesso: false,
                    erro: 'API key não encontrada'
                });
            }

            const updateFields = [];
            const updateValues = [];

            if (keyName !== undefined) {
                // Verificar se novo nome já existe
                const nameCheck = await this.db.query(`
                    SELECT id FROM user_api_keys 
                    WHERE user_id = ? AND key_name = ? AND id != ?
                `, [this.user.id, keyName.trim(), keyId]);

                if (nameCheck.length > 0) {
                    return this.socket?.emit('UpdateApiKey', {
                        sucesso: false,
                        erro: 'Já existe uma chave com este nome'
                    });
                }

                updateFields.push('key_name = ?');
                updateValues.push(keyName.trim());
            }

            if (permissions !== undefined) {
                updateFields.push('permissions = ?');
                updateValues.push(JSON.stringify(permissions));
            }

            if (allowedIps !== undefined) {
                updateFields.push('allowed_ips = ?');
                updateValues.push(allowedIps ? JSON.stringify(allowedIps) : null);
            }

            if (isActive !== undefined) {
                updateFields.push('is_active = ?');
                updateValues.push(isActive ? 1 : 0);
            }

            if (updateFields.length === 0) {
                return this.socket?.emit('UpdateApiKey', {
                    sucesso: false,
                    erro: 'Nenhum campo para atualizar'
                });
            }

            updateValues.push(keyId, this.user.id);

            await this.db.query(`
                UPDATE user_api_keys 
                SET ${updateFields.join(', ')}, updated_at = NOW()
                WHERE id = ? AND user_id = ?
            `, updateValues);

            this.socket?.emit('UpdateApiKey', {
                sucesso: true,
                mensagem: 'API key atualizada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao atualizar API key:', error);
            this.socket?.emit('UpdateApiKey', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Deletar API key
    async handleDeleteApiKey() {
        try {
            const { keyId } = this.data;

            if (!this.user || !this.user.id) {
                return this.socket?.emit('DeleteApiKey', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            // Verificar se a key pertence ao usuário
            const existingKey = await this.db.query(`
                SELECT * FROM user_api_keys 
                WHERE id = ? AND user_id = ?
            `, [keyId, this.user.id]);

            if (existingKey.length === 0) {
                return this.socket?.emit('DeleteApiKey', {
                    sucesso: false,
                    erro: 'API key não encontrada'
                });
            }

            // Verificar se há transações recentes (últimos 30 dias)
            const recentTransactions = await this.db.query(`
                SELECT COUNT(*) as count FROM gateway_transactions 
                WHERE api_key_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            `, [keyId]);

            if (recentTransactions[0].count > 0) {
                return this.socket?.emit('DeleteApiKey', {
                    sucesso: false,
                    erro: `Não é possível deletar. Esta chave foi usada em ${recentTransactions[0].count} transações nos últimos 30 dias.`,
                    canDeactivate: true
                });
            }

            // Deletar a key
            await this.db.query(`
                DELETE FROM user_api_keys 
                WHERE id = ? AND user_id = ?
            `, [keyId, this.user.id]);

            // Log da exclusão
            await this.db.query(`
                INSERT INTO system_logs (user_id, level, message, context) 
                VALUES (?, 'info', 'API key deletada', ?)
            `, [
                this.user.id,
                JSON.stringify({
                    key_id: keyId,
                    key_name: existingKey[0].key_name
                })
            ]);

            this.socket?.emit('DeleteApiKey', {
                sucesso: true,
                mensagem: 'API key deletada com sucesso'
            });

        } catch (error) {
            console.error('Erro ao deletar API key:', error);
            this.socket?.emit('DeleteApiKey', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Regenerar chave secreta
    async handleRegenerateSecretKey() {
        try {
            const { usuario, keyId } = this.data;

            if (!this.user || !this.user.id) {
                return this.socket?.emit('RegenerateSecretKey', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            // Verificar se a key pertence ao usuário
            const existingKey = await this.db.query(`
                SELECT * FROM user_api_keys 
                WHERE id = ? AND user_id = ?
            `, [keyId, this.user.id]);

            if (existingKey.length === 0) {
                return this.socket?.emit('RegenerateSecretKey', {
                    sucesso: false,
                    erro: 'API key não encontrada'
                });
            }

            const key = existingKey[0];

            // Gerar nova chave secreta
            const newSecretKey = ApiKeyGenerator.generate(key.environment, 'secret');
            const newSecretKeyHash = await ApiKeyGenerator.hashSecretKey(newSecretKey);

            // Atualizar no banco
            await this.db.query(`
                UPDATE user_api_keys 
                SET secret_key_hash = ?, updated_at = NOW()
                WHERE id = ? AND user_id = ?
            `, [newSecretKeyHash, keyId, this.user.id]);

            // Log da regeneração
            await this.db.query(`
                INSERT INTO system_logs (user_id, level, message, context) 
                VALUES (?, 'warning', 'Chave secreta regenerada', ?)
            `, [
                usuario.id,
                JSON.stringify({
                    key_id: keyId,
                    key_name: key.key_name
                })
            ]);

            this.socket?.emit('RegenerateSecretKey', {
                sucesso: true,
                newSecretKey: newSecretKey,
                mensagem: 'Nova chave secreta gerada! Atualize suas integrações imediatamente.'
            });

        } catch (error) {
            console.error('Erro ao regenerar chave secreta:', error);
            this.socket?.emit('RegenerateSecretKey', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }

    // Buscar estatísticas de uso
    async handleGetApiKeyStats() {
        try {
            const { keyId, period = '30d' } = this.data;

            if (!this.user || !this.user.id) {
                return this.socket?.emit('GetApiKeyStats', {
                    sucesso: false,
                    erro: 'Usuário não autenticado'
                });
            }

            // Definir período
            let dateFilter = '';
            switch (period) {
                case '24h':
                    dateFilter = 'AND gt.created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)';
                    break;
                case '7d':
                    dateFilter = 'AND gt.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
                    break;
                case '30d':
                    dateFilter = 'AND gt.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
                    break;
                case '90d':
                    dateFilter = 'AND gt.created_at >= DATE_SUB(NOW(), INTERVAL 90 DAY)';
                    break;
            }

            // Buscar estatísticas gerais
            const stats = await this.db.query(`
            SELECT 
                COUNT(*) as total_transactions,
                SUM(CASE WHEN gt.status = 'APPROVED' THEN 1 ELSE 0 END) as approved_transactions,
                SUM(CASE WHEN gt.status = 'REJECTED' THEN 1 ELSE 0 END) as rejected_transactions,
                SUM(gt.amount) as total_amount,
                SUM(CASE WHEN gt.status = 'APPROVED' THEN gt.amount ELSE 0 END) as approved_amount,
                AVG(gt.amount) as avg_amount,
                COUNT(DISTINCT DATE(gt.created_at)) as active_days
            FROM gateway_transactions AS gt
            WHERE gt.api_key_id = ? ${dateFilter}
        `, [keyId]);

            // Transações por dia
            const dailyStats = await this.db.query(`
            SELECT 
                DATE(gt.created_at) as date,
                COUNT(*) as transactions,
                SUM(gt.amount) as amount,
                SUM(CASE WHEN gt.status = 'APPROVED' THEN 1 ELSE 0 END) as approved
            FROM gateway_transactions AS gt
            WHERE gt.api_key_id = ? ${dateFilter}
            GROUP BY DATE(gt.created_at)
            ORDER BY date DESC
            LIMIT 30
        `, [keyId]);

            // Por método de pagamento
            const methodStats = await this.db.query(`
            SELECT 
                gt.payment_method,
                COUNT(*) as count,
                SUM(gt.amount) as amount
            FROM gateway_transactions AS gt
            WHERE gt.api_key_id = ? ${dateFilter}
            GROUP BY gt.payment_method
        `, [keyId]);

            const result = stats[0];
            const successRate = result.total_transactions > 0
                ? (result.approved_transactions / result.total_transactions) * 100
                : 0;

            this.socket?.emit('GetApiKeyStats', {
                sucesso: true,
                stats: {
                    ...result,
                    success_rate: successRate.toFixed(2),
                    daily_stats: dailyStats,
                    method_stats: methodStats,
                    period: period
                }
            });

        } catch (error) {
            console.error('Erro ao buscar estatísticas:', error);
            this.socket?.emit('GetApiKeyStats', {
                sucesso: false,
                erro: 'Erro interno do servidor'
            });
        }
    }


    // Utilitário para mascarar chaves
    maskKey(key) {
        if (!key || key.length < 8) return key;
        const start = key.substring(0, 8);
        const end = key.substring(key.length - 4);
        return `${start}****${end}`;
    }
}

// ==========================================
// 3. MIDDLEWARE DE AUTENTICAÇÃO
// ==========================================
class ApiAuthMiddleware {
    constructor() {
        this.db = new db();
    }

    /**
     * Middleware para autenticar API Keys nos endpoints REST
     */
    authenticateApiKey = async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;

            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return this.unauthorizedResponse(res, 'Token de autorização obrigatório');
            }

            const secretKey = authHeader.split(' ')[1];

            if (!secretKey) {
                return this.unauthorizedResponse(res, 'Token inválido');
            }
            
            // Validar formato da secret key
            if (!this.isValidSecretKeyFormat(secretKey)) {
                return this.unauthorizedResponse(res, 'Formato de token inválido');
            }

            // Buscar API key no banco
            const apiKeyData = await this.findApiKey(secretKey);

            if (!apiKeyData) {
                return this.unauthorizedResponse(res, 'Token não encontrado');
            }

            // Verificar se a key está ativa
            if (!apiKeyData.is_active) {
                return this.unauthorizedResponse(res, 'Token desativado');
            }

            // Verificar rate limiting
            const rateLimitOk = await this.checkRateLimit(apiKeyData.id);
            if (!rateLimitOk) {
                return this.rateLimitResponse(res);
            }

            // Buscar dados do usuário
            const userData = await this.getUserData(apiKeyData.user_id);
            if (!userData) {
                return this.unauthorizedResponse(res, 'Usuário não encontrado');
            }

            // Verificar se usuário está ativo
            if (userData.status !== 'active') {
                return this.unauthorizedResponse(res, 'Usuário inativo');
            }

            // Atualizar estatísticas de uso
            await this.updateApiKeyUsage(apiKeyData.id, req);

            // Adicionar dados ao request
            req.user = userData;
            req.apiKey = apiKeyData;
            req.environment = apiKeyData.environment;

            next();

        } catch (error) {
            console.error('Erro na autenticação API:', error);
            return this.errorResponse(res, 500, 'Erro interno de autenticação');
        }
    };

    /**
     * Busca API key no banco
     */
    async findApiKey(secretKey) {
        try {
            const environment = ApiKeyGenerator.extractEnvironment(secretKey);


      
            if (!environment) return null;

            const result = await this.db.query(`
            SELECT 
                ak.*, 
                u.name as user_name,
                u.email as user_email,
                u.status as user_status
            FROM user_api_keys ak
            INNER JOIN users u ON ak.user_id = u.id
            WHERE ak.environment = ?
        `, [environment]);

       

            for (const row of result) {
                const isMatch = await ApiKeyGenerator.validateSecretKey(secretKey, row.secret_key_hash);
                if (isMatch) {
                    row.permissions = JSON.parse(row.permissions || '{}');
                    return row;
                }
            }

            return null;

        } catch (error) {
            console.error('Erro ao buscar API key:', error);
            return null;
        }
    }


    /**
     * Busca dados completos do usuário
     */
    async getUserData(userId) {
        try {
            const result = await this.db.query(`
                SELECT 
                    u.*,
                    up.payment_methods,
                    up.tax_pix,
                    up.tax_credit_card,
                    up.cost_pix,
                    up.cost_credit_card
                FROM users u
                LEFT JOIN user_permissions up ON u.id = up.user_id
                WHERE u.id = ?
                LIMIT 1
            `, [userId]);

            if (result.length === 0) {
                return null;
            }

            const user = result[0];

            // Parse das permissões
            if (user.payment_methods) {
                user.payment_methods = JSON.parse(user.payment_methods);
            }

            return user;

        } catch (error) {
            console.error('Erro ao buscar dados do usuário:', error);
            return null;
        }
    }

    /**
     * Verifica rate limiting
     */
    async checkRateLimit(apiKeyId) {
        try {
            const now = new Date();
            const windowStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), now.getMinutes());

            // Buscar uso atual na janela de 1 minuto
            const usage = await this.db.query(`
                SELECT request_count 
                FROM api_key_usage_limits 
                WHERE api_key_id = ? 
                AND time_window = 'minute' 
                AND window_start = ?
            `, [apiKeyId, windowStart]);

            const currentCount = usage.length > 0 ? usage[0].request_count : 0;
            const limit = 1000; // 1000 requests por minuto

            if (currentCount >= limit) {
                return false;
            }

            // Atualizar/inserir contador
            if (usage.length > 0) {
                await this.db.query(`
                    UPDATE api_key_usage_limits 
                    SET request_count = request_count + 1, 
                        last_request_at = NOW(),
                        updated_at = NOW()
                    WHERE api_key_id = ? AND time_window = 'minute' AND window_start = ?
                `, [apiKeyId, windowStart]);
            } else {
                await this.db.query(`
                    INSERT INTO api_key_usage_limits 
                    (api_key_id, time_window, window_start, request_count, last_request_at)
                    VALUES (?, 'minute', ?, 1, NOW())
                `, [apiKeyId, windowStart]);
            }

            return true;

        } catch (error) {
            console.error('Erro ao verificar rate limit:', error);
            // Em caso de erro, permitir a requisição
            return true;
        }
    }

    /**
     * Atualiza estatísticas de uso da API key
     */
    async updateApiKeyUsage(apiKeyId, req) {
        try {
            const clientIp = this.getClientIP(req);

            await this.db.query(`
                UPDATE user_api_keys 
                SET 
                    usage_count = usage_count + 1,
                    last_used_at = NOW(),
                    last_used_ip = ?
                WHERE id = ?
            `, [clientIp, apiKeyId]);

        } catch (error) {
            console.error('Erro ao atualizar uso da API key:', error);
        }
    }

    /**
     * Valida formato da secret key
     */
    isValidSecretKeyFormat(secretKey) {
        // Formato: sk_test_xxx ou sk_live_xxx
        const regex = /^sk_(test|live)_[a-zA-Z0-9]{32,}$/;
        return regex.test(secretKey);
    }

    /**
     * Obtém IP do cliente
     */
    getClientIP(req) {
        return req.headers['x-forwarded-for']?.split(',')[0] ||
            req.headers['x-real-ip'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            '127.0.0.1';
    }

    /**
     * Log de tentativa de acesso
     */
    async logAccessAttempt(type, message, context = {}) {
        try {
            await this.db.query(`
                INSERT INTO system_logs (level, message, context, ip_address, created_at)
                VALUES ('warning', ?, ?, ?, NOW())
            `, [
                `API Auth - ${type}: ${message}`,
                JSON.stringify(context),
                context.ip || '0.0.0.0'
            ]);
        } catch (error) {
            console.error('Erro ao salvar log de acesso:', error);
        }
    }

    /**
     * Resposta de não autorizado
     */
    unauthorizedResponse(res, message) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: message,
            code: 'AUTH_FAILED',
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Resposta de rate limit
     */
    rateLimitResponse(res) {
        return res.status(429).json({
            error: 'Rate Limit Exceeded',
            message: 'Muitas requisições. Tente novamente em alguns minutos.',
            code: 'RATE_LIMIT',
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Resposta de erro genérica
     */
    errorResponse(res, status, message) {
        return res.status(status).json({
            error: 'Internal Error',
            message: message,
            code: 'INTERNAL_ERROR',
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Middleware específico para verificar permissões
     */
    requirePermission = (permission) => {
        return (req, res, next) => {
            if (!req.apiKey || !req.apiKey.permissions) {
                return this.unauthorizedResponse(res, 'Permissões não encontradas');
            }

            if (!req.apiKey.permissions[permission]) {
                return res.status(403).json({
                    error: 'Forbidden',
                    message: `Permissão '${permission}' necessária`,
                    code: 'PERMISSION_DENIED',
                    timestamp: new Date().toISOString()
                });
            }

            next();
        };
    };

    /**
     * Middleware para verificar ambiente (test/live)
     */
    requireEnvironment = (environment) => {
        return (req, res, next) => {
            if (!req.apiKey || req.apiKey.environment !== environment) {
                return this.unauthorizedResponse(res, `Ambiente '${environment}' necessário`);
            }

            next();
        };
    };
}

// ==========================================
// 4. CACHE DE TOKENS DOS PROVEDORES
// ==========================================
class ProviderTokenCache {
    constructor() {
        this.db = require('../config/database');
        this.memoryCache = new Map(); // Cache em memória
    }

    // Buscar token válido do provedor para o usuário
    async getValidToken(providerId, userId) {
        try {
            const cacheKey = `${providerId}_${userId}`;

            // Verificar cache em memória primeiro
            if (this.memoryCache.has(cacheKey)) {
                const cached = this.memoryCache.get(cacheKey);
                if (new Date() < cached.expires_at) {
                    return cached.token;
                } else {
                    this.memoryCache.delete(cacheKey);
                }
            }

            // Buscar no banco
            const tokens = await this.db.query(`
                SELECT token_hash, expires_at FROM provider_tokens
                WHERE provider_id = ? AND user_id = ? AND expires_at > NOW()
                ORDER BY created_at DESC LIMIT 1
            `, [providerId, userId]);

            if (tokens.length > 0) {
                return this.decryptToken(tokens[0].token_hash);
            }

            return null;

        } catch (error) {
            console.error('Erro ao buscar token do provedor:', error);
            return null;
        }
    }

    // Salvar novo token
    async saveToken(providerId, userId, token, tokenType = 'Bearer', expiresIn = 1800) {
        try {
            const expiresAt = new Date(Date.now() + (expiresIn * 1000));
            const tokenHash = this.encryptToken(token);

            // Salvar no banco
            await this.db.query(`
                INSERT INTO provider_tokens (provider_id, user_id, token_hash, token_type, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                token_hash = VALUES(token_hash),
                token_type = VALUES(token_type),
                expires_at = VALUES(expires_at),
                updated_at = NOW()
            `, [providerId, userId, tokenHash, tokenType, expiresAt]);

            // Salvar no cache em memória
            const cacheKey = `${providerId}_${userId}`;
            this.memoryCache.set(cacheKey, {
                token: token,
                expires_at: expiresAt
            });

            return true;

        } catch (error) {
            console.error('Erro ao salvar token do provedor:', error);
            return false;
        }
    }

    // Invalidar token
    async invalidateToken(providerId, userId) {
        try {
            const cacheKey = `${providerId}_${userId}`;
            this.memoryCache.delete(cacheKey);

            await this.db.query(`
                DELETE FROM provider_tokens
                WHERE provider_id = ? AND user_id = ?
            `, [providerId, userId]);

        } catch (error) {
            console.error('Erro ao invalidar token:', error);
        }
    }

    // Criptografia simples para tokens (use uma chave mais segura em produção)
    encryptToken(token) {
        const algorithm = 'aes-256-cbc';
        const key = process.env.TOKEN_ENCRYPTION_KEY || 'your-32-character-secret-key-here';
        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipher(algorithm, key);
        let encrypted = cipher.update(token, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return iv.toString('hex') + ':' + encrypted;
    }

    decryptToken(encryptedToken) {
        const algorithm = 'aes-256-cbc';
        const key = process.env.TOKEN_ENCRYPTION_KEY || 'your-32-character-secret-key-here';

        const parts = encryptedToken.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];

        const decipher = crypto.createDecipher(algorithm, key);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}

// ==========================================
// 5. EXPORTAÇÕES
// ==========================================
module.exports = {
    ApiKeyGenerator,
    ApiKeysHandler,
    ApiAuthMiddleware,
    ProviderTokenCache
};