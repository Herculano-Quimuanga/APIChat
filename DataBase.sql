CREATE DATABASE chatbox DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_general_ci;

USE chatbox;

-- Tabela de usuários
CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT,
    nome VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL,
    photo VARCHAR(255) NOT NULL,
    CONSTRAINT PRIMARY KEY (id)
);

-- Tabela de conversas
CREATE TABLE conversas (
    id INT NOT NULL AUTO_INCREMENT,
    usuario1_id INT NOT NULL,
    usuario2_id INT, -- Pode ser null no caso de conversa com IA
    eh_ia BOOLEAN DEFAULT FALSE,
    criada_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT PRIMARY KEY (id),
    CONSTRAINT fk_conversa_usuario1 FOREIGN KEY (usuario1_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_conversa_usuario2 FOREIGN KEY (usuario2_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Tabela de mensagens
CREATE TABLE mensagens (
    id INT NOT NULL AUTO_INCREMENT,
    conversa_id INT NOT NULL,
    remetente_id INT NOT NULL,
    texto TEXT NOT NULL,
    enviada_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT PRIMARY KEY (id),
    CONSTRAINT fk_mensagem_conversa FOREIGN KEY (conversa_id) REFERENCES conversas (id) ON DELETE CASCADE,
    CONSTRAINT fk_mensagem_remetente FOREIGN KEY (remetente_id) REFERENCES users (id) ON DELETE CASCADE
);