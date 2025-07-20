const axios = require('axios');

class HawkpayProvider {
  constructor(publicKey, secretKey) {
    this.baseURL = 'https://api.hawkpaybrasil.com/v1';
    this.auth = 'Basic ' + Buffer.from(`${publicKey}:${secretKey}`).toString('base64');
  }

  /**
   * Cria uma nova transação de pagamento (Cartão, PIX ou Boleto)
   * @param {Object} payload - Dados da transação (token do cartão, valor, cliente, etc.)
   * @returns {Object} - Resposta da Hawkpay
   */
  async createTransaction(payload) {
    try {
      const response = await axios.post(`${this.baseURL}/transactions`, payload, {
        headers: {
          Authorization: this.auth,
          'Content-Type': 'application/json'
        }
      });
      return response.data;
    } catch (error) {
      console.error('Erro ao criar transação na Hawkpay:', error?.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Consulta uma transação por ID
   * @param {string|number} transactionId
   * @returns {Object} - Detalhes da transação
   */
  async getTransaction(transactionId) {
    try {
      const response = await axios.get(`${this.baseURL}/transactions/${transactionId}`, {
        headers: {
          Authorization: this.auth
        }
      });
      return response.data;
    } catch (error) {
      console.error('Erro ao buscar transação Hawkpay:', error?.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Solicita um saque via Pix
   * @param {Object} data - Dados da transferência (valor, chave pix, etc.)
   * @param {string} withdrawKey - Chave de saque fornecida pela Hawkpay
   * @returns {Object}
   */
  async createWithdraw(data, withdrawKey) {
    try {
      const response = await axios.post(`${this.baseURL}/transfers`, data, {
        headers: {
          Authorization: this.auth,
          'Content-Type': 'application/json',
          'x-withdraw-key': withdrawKey
        }
      });
      return response.data;
    } catch (error) {
      console.error('Erro ao solicitar saque Hawkpay:', error?.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Cancela um saque pendente
   * @param {number|string} withdrawId - ID do saque
   * @param {string} withdrawKey - Chave de saque
   */
  async cancelWithdraw(withdrawId, withdrawKey) {
    try {
      const response = await axios.post(`${this.baseURL}/transfers/${withdrawId}/cancel`, {}, {
        headers: {
          Authorization: this.auth,
          'x-withdraw-key': withdrawKey
        }
      });
      return response.data;
    } catch (error) {
      console.error('Erro ao cancelar saque Hawkpay:', error?.response?.data || error.message);
      throw error;
    }
  }
}

module.exports = HawkpayProvider;
