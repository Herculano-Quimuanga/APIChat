-- Criação e seleção do banco de dados
CREATE DATABASE IF NOT EXISTS railway DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_general_ci;
USE railway;

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    nome VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL,
    photo VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);

-- Tabela de conversas
CREATE TABLE IF NOT EXISTS conversas (
    id INT NOT NULL AUTO_INCREMENT,
    usuario1_id INT NOT NULL,
    usuario2_id INT,
    eh_ia BOOLEAN DEFAULT FALSE,
    criada_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (usuario1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (usuario2_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabela de mensagens
CREATE TABLE IF NOT EXISTS mensagens (
    id INT NOT NULL AUTO_INCREMENT,
    conversa_id INT NOT NULL,
    remetente_id INT NOT NULL,
    texto TEXT NOT NULL,
    enviada_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (conversa_id) REFERENCES conversas(id) ON DELETE CASCADE,
    FOREIGN KEY (remetente_id) REFERENCES users(id) ON DELETE CASCADE
);
