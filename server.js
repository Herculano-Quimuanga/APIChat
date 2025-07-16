import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// IA Gemini
const IA_GEMINI = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

async function gerarRespostaGemini(pergunta) {
  try {
    const response = await IA_GEMINI.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: pergunta }] }],
    });

    return (
      response?.response?.candidates?.[0]?.content?.parts?.[0]?.text ||
      "Sem resposta da IA no momento. Tente novamente mais tarde."
    );
  } catch (error) {
    console.error("Erro na Gemini:", error);
    throw new Error("Erro ao gerar resposta com Gemini");
  }
}

// Banco de dados - usando pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// JWT
function gerarToken(usuarioId) {
  return jwt.sign({ id: usuarioId }, process.env.JWT_SECRET, {
    expiresIn: "2h",
  });
}

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

// Rotas
app.get("/", (_, res) => {
  res.send("API do ChatBox está online com Gemini 2.5");
});

app.post("/api/usuarios/google", async (req, res) => {
  const { nome, email, photo } = req.body;
  if (!nome || !email || !photo)
    return res.status(400).json({ error: "Dados incompletos" });

  try {
    const [results] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);

    if (results.length > 0) {
      const token = gerarToken(results[0].id);
      return res.status(200).json({ status: "login", user: results[0], token });
    }

    const [insertResult] = await pool.query(
      "INSERT INTO users (nome, email, photo) VALUES (?, ?, ?)",
      [nome, email, photo]
    );

    const novoUsuario = { id: insertResult.insertId, nome, email, photo };
    const token = gerarToken(novoUsuario.id);
    res.status(201).json({ status: "cadastrado", user: novoUsuario, token });
  } catch (err) {
    res.status(500).json({ error: "Erro no banco", details: err.message });
  }
});

app.post("/api/usuarios/register", async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha)
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });

  try {
    const hashed = await bcrypt.hash(senha, 10);
    const [results] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);

    if (results.length > 0)
      return res.status(400).json({ error: "Email já cadastrado" });

    const [insert] = await pool.query(
      "INSERT INTO users (nome, email, senha) VALUES (?, ?, ?)",
      [nome, email, hashed]
    );

    const token = gerarToken(insert.insertId);
    res.status(201).json({ status: "cadastrado", user: { id: insert.insertId, nome, email }, token });
  } catch (err) {
    res.status(500).json({ error: "Erro no banco", details: err.message });
  }
});

app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha)
    return res.status(400).json({ error: "Email e senha obrigatórios" });

  try {
    const [results] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (results.length === 0)
      return res.status(404).json({ error: "Usuário não encontrado" });

    const user = results[0];
    const senhaCorreta = await bcrypt.compare(senha, user.senha);
    if (!senhaCorreta)
      return res.status(401).json({ error: "Senha incorreta" });

    const token = gerarToken(user.id);
    res.status(200).json({ status: "logado", user, token });
  } catch (err) {
    res.status(500).json({ error: "Erro no banco", details: err.message });
  }
});

app.get("/api/usuarios/me", autenticar, async (req, res) => {
  try {
    const [results] = await pool.query("SELECT id, nome, email, photo FROM users WHERE id = ?", [req.usuarioId]);
    if (results.length === 0)
      return res.status(404).json({ error: "Usuário não encontrado" });

    res.status(200).json({ user: results[0] });
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar usuário", details: err.message });
  }
});

app.post("/api/chat", async (req, res) => {
  const { user_id, mensagem } = req.body;
  if (!user_id || !mensagem)
    return res.status(400).json({ error: "Dados incompletos" });

  try {
    const resposta = await gerarRespostaGemini(mensagem);

    await pool.query(
      "INSERT INTO mensagens (user_id, mensagem, resposta) VALUES (?, ?, ?)",
      [user_id, mensagem, resposta]
    );

    res.status(200).json({ resposta });
  } catch (error) {
    res.status(500).json({ error: "Erro ao gerar resposta com Gemini", details: error.message });
  }
});

app.get("/api/chat/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const [results] = await pool.query(
      "SELECT mensagem, resposta FROM mensagens WHERE user_id = ? ORDER BY data_envio ASC",
      [userId]
    );

    const historico = results.flatMap((row) => [
      { sender: "user", text: row.mensagem },
      ...(row.resposta ? [{ sender: "ia", text: row.resposta }] : []),
    ]);

    res.status(200).json(historico);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar mensagens", details: err.message });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
