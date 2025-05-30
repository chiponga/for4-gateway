// src/config/database.js
const knex = require('knex');

const config = {
  client: 'mysql2',
  connection: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'for4_gateway',
    charset: 'utf8mb4',
    timezone: 'UTC'
  },
  pool: {
    min: 2,
    max: 10,
    createTimeoutMillis: 3000,
    acquireTimeoutMillis: 30000,
    idleTimeoutMillis: 30000,
    reapIntervalMillis: 1000,
    createRetryIntervalMillis: 100,
  },
  migrations: {
    directory: './migrations',
    tableName: 'knex_migrations'
  },
  seeds: {
    directory: './seeds'
  }
};

let db;

try {
  db = knex(config);
  
  // Testar conexão
  db.raw('SELECT 1+1 as result')
    .then(() => {
      console.log('✅ Conexão com MySQL estabelecida');
    })
    .catch((err) => {
      console.error('❌ Erro na conexão com MySQL:', err.message);
    });
    
} catch (error) {
  console.error('❌ Erro ao configurar banco de dados:', error.message);
}

module.exports = db;