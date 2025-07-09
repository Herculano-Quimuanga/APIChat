// backend/server.js
import express from "express";
import mysql from "mysql2";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GoogleGenerativeAI } from "@google/generative-ai";

console.log(
  // eslint-disable-next-line no-undef
  "Chave da genAI:",
  process.env.GEMINI_API_KEY ? "Carregada" : "Não encontrada"
);
const app = express();
app.use(cors());
app.use(express.json());
dotenv.config();
// Conexão com banco de dados
const connection = mysql.createConnection({
  // eslint-disable-next-line no-undef
  host: process.env.DB_HOST,
  // eslint-disable-next-line no-undef
  user: process.env.DB_USER,
  // eslint-disable-next-line no-undef
  password: process.env.DB_PASSWORD,
  // eslint-disable-next-line no-undef
  database: process.env.DB_NAME,
});

connection.connect((err) => {
  if (err) {
    console.error("Erro ao conectar ao banco de dados Mysql:", err);
    return;
  }
  console.log("Conexão estabelecida com o banco de dados Mysql");
});

// Função para gerar token
function gerarToken(usuarioId) {
  // eslint-disable-next-line no-undef
  return jwt.sign({ id: usuarioId }, process.env.JWT_SECRET, {
    expiresIn: "2h",
  });
}

// Middleware para proteger rotas
function autenticar(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token ausente" });

  // eslint-disable-next-line no-undef
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.usuarioId = decoded.id;
    next();
  });
}

app.get("/", (req, res) => {
  res.send("API do ChatBox está online");
});

// Login com Google
app.post("/api/usuarios/google", (req, res) => {
  const { nome, email, photo } = req.body;

  if (!nome || !email || !photo) {
    return res.status(400).json({ error: "Dados incompletos" });
  }

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.error("Erro no banco (Google):", err);
        return res
          .status(500)
          .json({ error: "Erro no banco de dados", details: err.message });
      }

      if (results.length > 0) {
        const token = gerarToken(results[0].id);
        return res
          .status(200)
          .json({ status: "login", user: results[0], token });
      }

      connection.query(
        "INSERT INTO users (nome, email, photo) VALUES (?, ?, ?)",
        [nome, email, photo],
        (err2, result2) => {
          if (err2)
            return res.status(500).json({ error: "Erro ao cadastrar usuário" });

          const novoUsuario = { id: result2.insertId, nome, email, photo };
          const token = gerarToken(novoUsuario.id);
          return res
            .status(201)
            .json({ status: "cadastrado", user: novoUsuario, token });
        }
      );
    }
  );
});

// Cadastro manual
app.post("/api/usuarios/register", async (req, res) => {
  const { nome, email, senha } = req.body;

  if (!nome || !email || !senha) {
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });
  }

  const hashed = await bcrypt.hash(senha, 10);

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.error("Erro no banco:", err);
        return res
          .status(500)
          .json({ error: "Erro no banco de dados", details: err.message });
      }
      if (results.length > 0)
        return res.status(400).json({ error: "Email já cadastrado" });

      connection.query(
        "INSERT INTO users (nome, email, senha) VALUES (?, ?, ?)",
        [nome, email, hashed],
        (err2, result2) => {
          if (err2) return res.status(500).json({ error: "Erro ao cadastrar" });

          const token = gerarToken(result2.insertId);
          return res.status(201).json({
            status: "cadastrado",
            user: { id: result2.insertId, nome, email },
            token,
          });
        }
      );
    }
  );
});

// Login manual
app.post("/api/usuarios/login", (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ error: "Email e senha obrigatórios" });
  }

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.error("Erro no banco:", err);
        return res
          .status(500)
          .json({ error: "Erro no banco de dados", details: err.message });
      }
      if (results.length === 0)
        return res.status(404).json({ error: "Usuário não encontrado" });

      const user = results[0];
      const senhaCorreta = await bcrypt.compare(senha, user.senha);

      if (!senhaCorreta)
        return res.status(401).json({ error: "Senha incorreta" });

      const token = gerarToken(user.id);
      res.status(200).json({ status: "logado", user, token });
    }
  );
});

// Rota protegida: buscar usuário autenticado
app.get("/api/usuarios/me", autenticar, (req, res) => {
  const id = req.usuarioId;

  connection.query(
    "SELECT id, nome, email, photo FROM users WHERE id = ?",
    [id],
    (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ error: "Erro ao buscar usuário", details: err.message });
      if (results.length === 0)
        return res.status(404).json({ error: "Usuário não encontrado" });
      res.status(200).json({ user: results[0] });
    }
  );
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Enviar mensagem e obter resposta da IA
app.post("/api/chat", async (req, res) => {
  const { user_id, mensagem } = req.body;

  if (!user_id || !mensagem) {
    return res.status(400).json({ error: "Dados incompletos" });
  }

  try {
    console.log(" Mensagem recebida do usuário:", mensagem);

    const model = genAI.getGenerativeModel({ model: "gemini-pro" });

    const result = await model.generateContent(mensagem);
    const resposta = result.response.text();

    //  Salvar pergunta e resposta no banco
    connection.query(
      "INSERT INTO sms (user_id, mensagem, resposta) VALUES (?, ?, ?)",
      [user_id, mensagem, resposta],
      (err) => {
        if (err) {
          console.error(" Erro ao salvar no banco:", err);
          return res.status(500).json({
            error: "Erro ao salvar no banco de dados",
            details: err.message,
          });
        }

        return res.status(200).json({ resposta });
      }
    );
  } catch (err) {
    console.error(" Erro ao gerar resposta com Gemini:", err);
    return res.status(500).json({
      error: "Erro ao gerar resposta com Gemini",
      details: err.message,
    });
  }
});

// Buscar histórico de conversas por usuário
app.get("/api/chat/:userId", (req, res) => {
  const userId = req.params.userId;

  connection.query(
    "SELECT mensagem, resposta FROM sms WHERE user_id = ? ORDER BY data_envio ASC",
    [userId],
    (err, results) => {
      if (err) {
        console.error(" Erro ao buscar mensagens:", err);
        return res.status(500).json({
          error: "Erro ao buscar mensagens",
          details: err.message,
        });
      }

      const historico = results.flatMap((row) => {
        const blocos = [{ sender: "user", text: row.mensagem }];
        if (row.resposta) {
          blocos.push({ sender: "ia", text: row.resposta });
        }
        return blocos;
      });

      return res.status(200).json(historico);
    }
  );
});

app.listen(3000, () => {
  console.log("Servidor rodando na porta 3000");
});
