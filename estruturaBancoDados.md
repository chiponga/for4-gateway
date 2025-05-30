# Manual da Estrutura do Banco de Dados

Este documento descreve a estrutura do banco de dados utilizada no projeto, contemplando definições de tabelas, colunas, tipos, chaves primárias e estrangeiras, relacionamentos e índices. Destinado aos desenvolvedores responsáveis pela manutenção e evolução da aplicação.

---

## Visão Geral

* Banco de dados: MySQL
* Convenções de nomenclatura: tabelas no plural, colunas em snake\_case
* Datas e horários: `DATETIME` para todos registros, usando `DEFAULT CURRENT_TIMESTAMP` quando aplicável
* Controle de integridade referencial: todas as chaves estrangeiras com `ON DELETE CASCADE` ou `SET NULL`, conforme especificado

---

## 1. Tabela `users`

**Descrição**: armazena dados dos usuários do sistema.

| Coluna               | Tipo                                  | Atributos                                               |
| -------------------- | ------------------------------------- | ------------------------------------------------------- |
| `id`                 | INT                                   | PK, AUTO\_INCREMENT                                     |
| `name`               | VARCHAR(255)                          | NOT NULL                                                |
| `email`              | VARCHAR(255)                          | UNIQUE, NOT NULL                                        |
| `password`           | VARCHAR(255)                          | NOT NULL                                                |
| `phone`              | VARCHAR(20)                           | NULL                                                    |
| `document`           | VARCHAR(20)                           | NULL                                                    |
| `birth_date`         | DATE                                  | NULL                                                    |
| `avatar`             | VARCHAR(500)                          | NULL                                                    |
| `status`             | ENUM('active','inactive','suspended') | DEFAULT 'active'                                        |
| `email_verified_at`  | TIMESTAMP                             | NULL                                                    |
| `two_factor_enabled` | BOOLEAN                               | DEFAULT FALSE                                           |
| `created_at`         | DATETIME                              | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`         | DATETIME                              | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_email` sobre `email`
* `idx_status` sobre `status`

---

## 2. Tabela `user_settings`

**Descrição**: armazena preferências e configurações de cada usuário.

| Coluna                   | Tipo                        | Atributos                                               |
| ------------------------ | --------------------------- | ------------------------------------------------------- |
| `id`                     | INT                         | PK, AUTO\_INCREMENT                                     |
| `user_id`                | INT                         | FK → `users.id` ON DELETE CASCADE                       |
| `notification_email`     | BOOLEAN                     | DEFAULT TRUE                                            |
| `notification_sms`       | BOOLEAN                     | DEFAULT FALSE                                           |
| `notification_push`      | BOOLEAN                     | DEFAULT TRUE                                            |
| `theme`                  | ENUM('light','dark','auto') | DEFAULT 'light'                                         |
| `language`               | VARCHAR(5)                  | DEFAULT 'pt\_BR'                                        |
| `timezone`               | VARCHAR(50)                 | DEFAULT 'America/Sao\_Paulo'                            |
| `currency`               | VARCHAR(3)                  | DEFAULT 'BRL'                                           |
| `fee_display`            | ENUM('included','separate') | DEFAULT 'included'                                      |
| `auto_withdrawal`        | BOOLEAN                     | DEFAULT FALSE                                           |
| `auto_withdrawal_amount` | DECIMAL(10,2)               | DEFAULT 0.00                                            |
| `auto_withdrawal_day`    | INT                         | DEFAULT 1                                               |
| `created_at`             | DATETIME                    | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`             | DATETIME                    | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índice**:

* Único `uk_user_settings` sobre `user_id`

---

## 3. Tabela `bank_accounts`

**Descrição**: armazena contas bancárias e chaves PIX dos usuários.

| Coluna            | Tipo                                              | Atributos                                               |
| ----------------- | ------------------------------------------------- | ------------------------------------------------------- |
| `id`              | INT                                               | PK, AUTO\_INCREMENT                                     |
| `user_id`         | INT                                               | FK → `users.id` ON DELETE CASCADE                       |
| `bank_name`       | VARCHAR(255)                                      | NOT NULL                                                |
| `bank_code`       | VARCHAR(10)                                       | NULL                                                    |
| `agency`          | VARCHAR(20)                                       | NOT NULL                                                |
| `account`         | VARCHAR(30)                                       | NOT NULL                                                |
| `account_type`    | ENUM('checking','savings')                        | DEFAULT 'checking'                                      |
| `holder_name`     | VARCHAR(255)                                      | NOT NULL                                                |
| `holder_document` | VARCHAR(20)                                       | NOT NULL                                                |
| `pix_key`         | VARCHAR(255)                                      | NULL                                                    |
| `pix_type`        | ENUM('cpf','cnpj','email','phone','random')       | NULL                                                    |
| `is_main`         | BOOLEAN                                           | DEFAULT FALSE                                           |
| `status`          | ENUM('active','inactive','pending\_verification') | DEFAULT 'pending\_verification'                         |
| `created_at`      | DATETIME                                          | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`      | DATETIME                                          | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id` sobre `user_id`
* `idx_status` sobre `status`

---

## 4. Tabela `products`

**Descrição**: produtos oferecidos (digitais, físicos, serviços ou cursos).

| Coluna             | Tipo                                          | Atributos                                               |
| ------------------ | --------------------------------------------- | ------------------------------------------------------- |
| `id`               | INT                                           | PK, AUTO\_INCREMENT                                     |
| `user_id`          | INT                                           | FK → `users.id` ON DELETE CASCADE                       |
| `name`             | VARCHAR(255)                                  | NOT NULL                                                |
| `description`      | TEXT                                          | NULL                                                    |
| `type`             | ENUM('digital','physical','service','course') | DEFAULT 'digital'                                       |
| `category`         | VARCHAR(100)                                  | NULL                                                    |
| `price`            | DECIMAL(10,2)                                 | NOT NULL, DEFAULT 0.00                                  |
| `currency`         | VARCHAR(3)                                    | DEFAULT 'BRL'                                           |
| `status`           | ENUM('active','inactive','draft','rejected')  | DEFAULT 'draft'                                         |
| `rejection_reason` | TEXT                                          | NULL                                                    |
| `image_url`        | VARCHAR(500)                                  | NULL                                                    |
| `digital_file_url` | VARCHAR(500)                                  | NULL                                                    |
| `download_limit`   | INT                                           | NULL                                                    |
| `has_trial`        | BOOLEAN                                       | DEFAULT FALSE                                           |
| `trial_days`       | INT                                           | NULL                                                    |
| `commission_rate`  | DECIMAL(5,2)                                  | DEFAULT 0.00                                            |
| `allow_affiliates` | BOOLEAN                                       | DEFAULT FALSE                                           |
| `stock_quantity`   | INT                                           | NULL                                                    |
| `track_stock`      | BOOLEAN                                       | DEFAULT FALSE                                           |
| `weight`           | DECIMAL(8,3)                                  | NULL                                                    |
| `dimensions`       | JSON                                          | NULL                                                    |
| `tags`             | JSON                                          | NULL                                                    |
| `seo_title`        | VARCHAR(255)                                  | NULL                                                    |
| `seo_description`  | TEXT                                          | NULL                                                    |
| `created_at`       | DATETIME                                      | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`       | DATETIME                                      | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id` sobre `user_id`
* `idx_status` sobre `status`
* `idx_category` sobre `category`
* `idx_type` sobre `type`
* FULLTEXT `idx_search` sobre (`name`, `description`)

---

## 5. Tabela `orders`

**Descrição**: registro de vendas/pedidos realizados.

| Coluna                   | Tipo                                                       | Atributos                                               |
| ------------------------ | ---------------------------------------------------------- | ------------------------------------------------------- |
| `id`                     | INT                                                        | PK, AUTO\_INCREMENT                                     |
| `user_id`                | INT                                                        | FK → `users.id` ON DELETE CASCADE                       |
| `product_id`             | INT                                                        | FK → `products.id` ON DELETE CASCADE                    |
| `customer_name`          | VARCHAR(255)                                               | NOT NULL                                                |
| `customer_email`         | VARCHAR(255)                                               | NOT NULL                                                |
| `customer_phone`         | VARCHAR(20)                                                | NULL                                                    |
| `customer_document`      | VARCHAR(20)                                                | NULL                                                    |
| `amount`                 | DECIMAL(10,2)                                              | NOT NULL                                                |
| `original_amount`        | DECIMAL(10,2)                                              | NOT NULL                                                |
| `discount_amount`        | DECIMAL(10,2)                                              | DEFAULT 0.00                                            |
| `commission_amount`      | DECIMAL(10,2)                                              | DEFAULT 0.00                                            |
| `net_amount`             | DECIMAL(10,2)                                              | NOT NULL                                                |
| `currency`               | VARCHAR(3)                                                 | DEFAULT 'BRL'                                           |
| `payment_method`         | ENUM('pix','credit\_card','debit\_card','boleto','crypto') | NOT NULL                                                |
| `payment_status`         | ENUM('pending','paid','cancelled','refunded','chargeback') | DEFAULT 'pending'                                       |
| `order_status`           | ENUM('pending','processing','completed','cancelled')       | DEFAULT 'pending'                                       |
| `gateway_transaction_id` | VARCHAR(255)                                               | NULL                                                    |
| `gateway_provider`       | VARCHAR(50)                                                | NULL                                                    |
| `payment_details`        | JSON                                                       | NULL                                                    |
| `affiliate_id`           | INT                                                        | FK → `users.id` ON DELETE SET NULL                      |
| `coupon_code`            | VARCHAR(50)                                                | NULL                                                    |
| `ip_address`             | VARCHAR(45)                                                | NULL                                                    |
| `user_agent`             | TEXT                                                       | NULL                                                    |
| `utm_source`             | VARCHAR(100)                                               | NULL                                                    |
| `utm_medium`             | VARCHAR(100)                                               | NULL                                                    |
| `utm_campaign`           | VARCHAR(100)                                               | NULL                                                    |
| `expires_at`             | DATETIME                                                   | NULL                                                    |
| `paid_at`                | DATETIME                                                   | NULL                                                    |
| `created_at`             | DATETIME                                                   | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`             | DATETIME                                                   | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id`, `idx_product_id`, `idx_payment_status`, `idx_order_status`, `idx_payment_method`, `idx_created_at`, `idx_affiliate_id`, `idx_gateway_transaction_id`

---

## 6. Tabela `transactions`

**Descrição**: movimentos financeiros (recebimentos, saques, reembolsos, etc.).

| Coluna                   | Tipo                                                                            | Atributos                                               |
| ------------------------ | ------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `id`                     | INT                                                                             | PK, AUTO\_INCREMENT                                     |
| `user_id`                | INT                                                                             | FK → `users.id` ON DELETE CASCADE                       |
| `order_id`               | INT                                                                             | FK → `orders.id` ON DELETE SET NULL                     |
| `type`                   | ENUM('sale','commission','withdrawal','chargeback','refund','fee','adjustment') | NOT NULL                                                |
| `category`               | ENUM('income','expense')                                                        | NOT NULL                                                |
| `amount`                 | DECIMAL(10,2)                                                                   | NOT NULL                                                |
| `currency`               | VARCHAR(3)                                                                      | DEFAULT 'BRL'                                           |
| `status`                 | ENUM('pending','completed','failed','cancelled')                                | DEFAULT 'pending'                                       |
| `description`            | TEXT                                                                            | NULL                                                    |
| `gateway_transaction_id` | VARCHAR(255)                                                                    | NULL                                                    |
| `gateway_provider`       | VARCHAR(50)                                                                     | NULL                                                    |
| `reference_id`           | VARCHAR(255)                                                                    | NULL                                                    |
| `metadata`               | JSON                                                                            | NULL                                                    |
| `processed_at`           | DATETIME                                                                        | NULL                                                    |
| `created_at`             | DATETIME                                                                        | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`             | DATETIME                                                                        | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id`, `idx_order_id`, `idx_type`, `idx_status`, `idx_created_at`, `idx_gateway_transaction_id`

---

## 7. Tabela `withdrawals`

**Descrição**: solicitações de saque realizadas pelos usuários.

| Coluna                   | Tipo                                                          | Atributos                                               |
| ------------------------ | ------------------------------------------------------------- | ------------------------------------------------------- |
| `id`                     | INT                                                           | PK, AUTO\_INCREMENT                                     |
| `user_id`                | INT                                                           | FK → `users.id` ON DELETE CASCADE                       |
| `bank_account_id`        | INT                                                           | FK → `bank_accounts.id` ON DELETE CASCADE               |
| `amount`                 | DECIMAL(10,2)                                                 | NOT NULL                                                |
| `fee_amount`             | DECIMAL(10,2)                                                 | DEFAULT 0.00                                            |
| `net_amount`             | DECIMAL(10,2)                                                 | NOT NULL                                                |
| `currency`               | VARCHAR(3)                                                    | DEFAULT 'BRL'                                           |
| `status`                 | ENUM('pending','processing','completed','failed','cancelled') | DEFAULT 'pending'                                       |
| `gateway_transaction_id` | VARCHAR(255)                                                  | NULL                                                    |
| `gateway_provider`       | VARCHAR(50)                                                   | NULL                                                    |
| `failure_reason`         | TEXT                                                          | NULL                                                    |
| `processed_at`           | DATETIME                                                      | NULL                                                    |
| `completed_at`           | DATETIME                                                      | NULL                                                    |
| `created_at`             | DATETIME                                                      | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`             | DATETIME                                                      | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id`, `idx_status`, `idx_created_at`

---

## 8. Tabela `affiliates`

**Descrição**: informações de afiliados e métricas associadas.

| Coluna              | Tipo                                  | Atributos                                               |
| ------------------- | ------------------------------------- | ------------------------------------------------------- |
| `id`                | INT                                   | PK, AUTO\_INCREMENT                                     |
| `user_id`           | INT                                   | FK → `users.id` ON DELETE CASCADE                       |
| `sponsor_id`        | INT                                   | FK → `users.id` ON DELETE SET NULL                      |
| `affiliate_code`    | VARCHAR(50)                           | UNIQUE, NOT NULL                                        |
| `commission_rate`   | DECIMAL(5,2)                          | DEFAULT 10.00                                           |
| `total_sales`       | DECIMAL(10,2)                         | DEFAULT 0.00                                            |
| `total_commission`  | DECIMAL(10,2)                         | DEFAULT 0.00                                            |
| `total_clicks`      | INT                                   | DEFAULT 0                                               |
| `total_conversions` | INT                                   | DEFAULT 0                                               |
| `conversion_rate`   | DECIMAL(5,2)                          | DEFAULT 0.00                                            |
| `status`            | ENUM('active','inactive','suspended') | DEFAULT 'active'                                        |
| `joined_at`         | DATETIME                              | DEFAULT CURRENT\_TIMESTAMP                              |
| `created_at`        | DATETIME                              | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`        | DATETIME                              | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `uk_user_affiliate` (único) sobre `user_id`
* `idx_affiliate_code`, `idx_sponsor_id`, `idx_status`

---

## 9. Tabela `coupons`

**Descrição**: cupons de desconto vinculados a usuários e produtos.

| Coluna                     | Tipo                                | Atributos                                               |
| -------------------------- | ----------------------------------- | ------------------------------------------------------- |
| `id`                       | INT                                 | PK, AUTO\_INCREMENT                                     |
| `user_id`                  | INT                                 | FK → `users.id` ON DELETE CASCADE                       |
| `product_id`               | INT                                 | FK → `products.id` ON DELETE CASCADE                    |
| `code`                     | VARCHAR(50)                         | UNIQUE, NOT NULL                                        |
| `type`                     | ENUM('percentage','fixed\_amount')  | NOT NULL                                                |
| `value`                    | DECIMAL(10,2)                       | NOT NULL                                                |
| `min_amount`               | DECIMAL(10,2)                       | DEFAULT 0.00                                            |
| `max_discount`             | DECIMAL(10,2)                       | NULL                                                    |
| `usage_limit`              | INT                                 | NULL                                                    |
| `usage_count`              | INT                                 | DEFAULT 0                                               |
| `usage_limit_per_customer` | INT                                 | DEFAULT 1                                               |
| `starts_at`                | DATETIME                            | DEFAULT CURRENT\_TIMESTAMP                              |
| `expires_at`               | DATETIME                            | NULL                                                    |
| `status`                   | ENUM('active','inactive','expired') | DEFAULT 'active'                                        |
| `created_at`               | DATETIME                            | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`               | DATETIME                            | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_code`, `idx_user_id`, `idx_product_id`, `idx_status`, `idx_expires_at`

---

## 10. Tabela `integrations`

**Descrição**: configurações de integrações com serviços externos (Stripe, Shopify etc.).

| Coluna          | Tipo                              | Atributos                                               |
| --------------- | --------------------------------- | ------------------------------------------------------- |
| `id`            | INT                               | PK, AUTO\_INCREMENT                                     |
| `user_id`       | INT                               | FK → `users.id` ON DELETE CASCADE                       |
| `provider`      | VARCHAR(100)                      | NOT NULL                                                |
| `name`          | VARCHAR(255)                      | NOT NULL                                                |
| `status`        | ENUM('active','inactive','error') | DEFAULT 'inactive'                                      |
| `credentials`   | JSON                              | NULL                                                    |
| `settings`      | JSON                              | NULL                                                    |
| `last_sync_at`  | DATETIME                          | NULL                                                    |
| `error_message` | TEXT                              | NULL                                                    |
| `created_at`    | DATETIME                          | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`    | DATETIME                          | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id`, `idx_provider`, `idx_status`

---

## 11. Tabela `webhooks`

**Descrição**: registro de eventos recebidos e seu processamento.

| Coluna          | Tipo                                 | Atributos                                               |
| --------------- | ------------------------------------ | ------------------------------------------------------- |
| `id`            | INT                                  | PK, AUTO\_INCREMENT                                     |
| `user_id`       | INT                                  | FK → `users.id` ON DELETE SET NULL                      |
| `provider`      | VARCHAR(100)                         | NOT NULL                                                |
| `event`         | VARCHAR(255)                         | NOT NULL                                                |
| `payload`       | JSON                                 | NOT NULL                                                |
| `status`        | ENUM('pending','processed','failed') | DEFAULT 'pending'                                       |
| `attempts`      | INT                                  | DEFAULT 0                                               |
| `max_attempts`  | INT                                  | DEFAULT 3                                               |
| `processed_at`  | DATETIME                             | NULL                                                    |
| `error_message` | TEXT                                 | NULL                                                    |
| `created_at`    | DATETIME                             | DEFAULT CURRENT\_TIMESTAMP                              |
| `updated_at`    | DATETIME                             | DEFAULT CURRENT\_TIMESTAMP ON UPDATE CURRENT\_TIMESTAMP |

**Índices**:

* `idx_user_id`, `idx_provider`, `idx_status`, `idx_created_at`

---

## 12. Tabela `system_logs`

**Descrição**: armazena logs de nível debug/info/warning/etc.

| Coluna       | Tipo                                              | Atributos                          |
| ------------ | ------------------------------------------------- | ---------------------------------- |
| `id`         | INT                                               | PK, AUTO\_INCREMENT                |
| `user_id`    | INT                                               | FK → `users.id` ON DELETE SET NULL |
| `level`      | ENUM('debug','info','warning','error','critical') | NOT NULL                           |
| `message`    | TEXT                                              | NOT NULL                           |
| `context`    | JSON                                              | NULL                               |
| `ip_address` | VARCHAR(45)                                       | NULL                               |
| `user_agent` | TEXT                                              | NULL                               |
| `created_at` | DATETIME                                          | DEFAULT CURRENT\_TIMESTAMP         |

**Índices**:

* `idx_user_id`, `idx_level`, `idx_created_at`

---

## 13. Tabela `sessions`

**Descrição**: controla sessões de login/auth.

| Coluna          | Tipo         | Atributos                            |
| --------------- | ------------ | ------------------------------------ |
| `id`            | VARCHAR(255) | PK                                   |
| `user_id`       | INT          | FK → `users.id` ON DELETE CASCADE    |
| `ip_address`    | VARCHAR(45)  | NULL                                 |
| `user_agent`    | TEXT         | NULL                                 |
| `payload`       | JSON         | NULL                                 |
| `last_activity` | DATETIME     | NOT NULL, DEFAULT CURRENT\_TIMESTAMP |
| `expires_at`    | DATETIME     | NOT NULL                             |
| `created_at`    | DATETIME     | DEFAULT CURRENT\_TIMESTAMP           |

**Índices**:

* `idx_user_id`, `idx_last_activity`, `idx_expires_at`

---

### Diagramas e Relacionamentos

* Todas as tabelas filhas referenciam `users.id`.
* `orders` → `products.id`
* `transactions` → `orders.id`
* `withdrawals` → `bank_accounts.id`
* `affiliates` auto-relacionamento entre usuários (`sponsor_id`).

Para visualizar o modelo ER completo, utilize ferramentas como MySQL Workbench ou DBeaver importando este script de criação.

---

Este manual serve como referência para novos desenvolvedores implementarem ou estenderem funcionalidades, garantindo consistência e integridade dos dados.
