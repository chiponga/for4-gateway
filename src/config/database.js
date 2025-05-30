const mysql = require('mysql2/promise');



class Database {
    constructor() {
        if (!Database.instance) {
            this.pool = mysql.createPool({
                //host: '99839993.railway.internal',
                host: 'localhost',
                user: 'root',
                password: '',
                database: 'for4_gateway',
                port: 3306,
                //port: 16800,
                waitForConnections: true,
                connectionLimit: 50,
                queueLimit: 0
            });

            this.keepAliveInterval = 60000; // Intervalo de 60 segundos para o keep-alive
            this.startKeepAlive();

            Database.instance = this;
        }
        return Database.instance;
    }

    async query(sql, values = []) {
        let connection;
        try {
            connection = await this.pool.getConnection();
            const [rows, fields] = await connection.query(sql, values);
            return rows;
        } catch (error) {
            console.error('Erro na consulta:', error);
            if (error.code === 'ECONNRESET' || error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Tentativa de reconectar se a conexão foi perdida
                connection = await this.pool.getConnection();
                const [rows, fields] = await connection.query(sql, values);
                return rows;
            }
            throw error;
        } finally {
            if (connection) {
                connection.release();
            }
        }
    }

    startKeepAlive() {
        setInterval(async () => {
            try {
                const connection = await this.pool.getConnection();
                await connection.ping();
                connection.release();
            } catch (err) {
                console.error('Keep-alive error:', err);
            }
        }, this.keepAliveInterval);
    }
}


module.exports = Database;