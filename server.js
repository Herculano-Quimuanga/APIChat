// server.js
import express from "express";
import mysql from "mysql2";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Conexão com banco de dados
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

connection.connect((err) => {
  if (err) return console.error("Erro ao conectar ao banco:", err);
  console.log("Conectado ao banco de dados MySQL");
});

// Inicializa a IA Gemini
const IA_GEMINI = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// Função para gerar resposta com Gemini 2.5 Flash
async function gerarRespostaGemini(pergunta) {
  try {
    const response = await IA_GEMINI.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: pergunta }] }],
    });
    return response.text();
  } catch (error) {
    console.error("Erro na Gemini:", error);
    throw new Error("Erro ao gerar resposta com Gemini");
  }
}

// Gera token JWT
function gerarToken(usuarioId) {
  return jwt.sign({ id: usuarioId }, process.env.JWT_SECRET, {
    expiresIn: "2h",
  });
}

// Middleware de autenticação
function autenticar(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token ausente" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.usuarioId = decoded.id;
    next();
  });
}

// Rota de status
app.get("/", (req, res) => {
  res.send("API do ChatBox está online com Gemini 2.5");
});

// Login com Google
app.post("/api/usuarios/google", (req, res) => {
  const { nome, email, photo } = req.body;
  if (!nome || !email || !photo)
    return res.status(400).json({ error: "Dados incompletos" });

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ error: "Erro no banco", details: err.message });

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
          if (err2) return res.status(500).json({ error: "Erro ao cadastrar" });

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
  if (!nome || !email || !senha)
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });

  const hashed = await bcrypt.hash(senha, 10);

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ error: "Erro no banco", details: err.message });
      if (results.length > 0)
        return res.status(400).json({ error: "Email já cadastrado" });

      connection.query(
        "INSERT INTO users (nome, email, senha) VALUES (?, ?, ?)",
        [nome, email, hashed],
        (err2, result2) => {
          if (err2) return res.status(500).json({ error: "Erro ao cadastrar" });

          const token = gerarToken(result2.insertId);
          res.status(201).json({
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
  if (!email || !senha)
    return res.status(400).json({ error: "Email e senha obrigatórios" });

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ error: "Erro no banco", details: err.message });
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

// Buscar perfil do usuário autenticado
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

// Enviar mensagem para IA Gemini
app.post("/api/chat", async (req, res) => {
  const { user_id, mensagem } = req.body;
  if (!user_id || !mensagem)
    return res.status(400).json({ error: "Dados incompletos" });

  try {
    const resposta = await gerarRespostaGemini(mensagem);

    connection.query(
      "INSERT INTO sms (user_id, mensagem, resposta) VALUES (?, ?, ?)",
      [user_id, mensagem, resposta],
      (err) => {
        if (err)
          return res
            .status(500)
            .json({ error: "Erro ao salvar no banco", details: err.message });

        res.status(200).json({ resposta });
      }
    );
  } catch (error) {
    res.status(500).json({
      error: "Erro ao gerar resposta com Gemini",
      details: error.message,
    });
  }
});

// Buscar histórico de mensagens
app.get("/api/chat/:userId", (req, res) => {
  const userId = req.params.userId;

  connection.query(
    "SELECT mensagem, resposta FROM sms WHERE user_id = ? ORDER BY data_envio ASC",
    [userId],
    (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ error: "Erro ao buscar mensagens", details: err.message });

      const historico = results.flatMap((row) => [
        { sender: "user", text: row.mensagem },
        ...(row.resposta ? [{ sender: "ia", text: row.resposta }] : []),
      ]);

      res.status(200).json(historico);
    }
  );
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
