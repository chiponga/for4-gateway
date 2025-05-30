// src/config/redis.js
const redis = require('redis');

let client = null;

// Configuração do Redis (opcional)
if (process.env.REDIS_URL) {
  try {
    client = redis.createClient({
      url: process.env.REDIS_URL
    });

    client.on('error', (err) => {
      console.error('❌ Erro no Redis:', err);
    });

    client.on('connect', () => {
      console.log('✅ Redis conectado');
    });

    // Conectar ao Redis
    client.connect().catch((err) => {
      console.error('❌ Erro ao conectar no Redis:', err);
      client = null;
    });

  } catch (error) {
    console.error('❌ Erro na configuração do Redis:', error);
    client = null;
  }
} else {
  console.log('⚠️ Redis não configurado (REDIS_URL não definida)');
}

module.exports = client;