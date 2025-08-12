import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";

dotenv.config();

const app = express();

/* ============================== CORS CORRIGIDO ============================== */
const allowedOrigins = [
  process.env.FRONTEND_URL?.trim(),
  "http://localhost:5173",
  "http://localhost:3000",
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn("Origin bloqueada pelo CORS:", origin);
      callback(new Error("Origin não permitida"));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json());

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Credentials", "true");
  }
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

/* ============================== MySQL POOL ============================== */
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✅ Conectado ao MySQL");
    conn.release();
  } catch (err) {
    console.error("❌ Erro ao conectar ao MySQL:", err.message);
    process.exit(1);
  }
})();

/* ============================== JWT CORRIGIDO ============================== */
function gerarToken(usuarioId) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET não definido no .env");
  }
  return jwt.sign({ id: usuarioId }, process.env.JWT_SECRET, {
    expiresIn: "2h",
  });
}

function autenticar(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.warn("❌ Header Authorization ausente");
    return res.status(401).json({ error: "Token ausente" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.usuarioId = decoded.id;
    next();
  });
}

/* ============================== Gemini API (fetch) ============================== */
async function gerarRespostaGemini(pergunta) {
  const MODEL = "gemini-1.5-flash";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${process.env.GEMINI_API_KEY}`;

  const body = {
    contents: [{ role: "user", parts: [{ text: pergunta }] }],
  };

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const erro = await res.text();
      console.error("❌ Erro Gemini:", res.status, erro);
      throw new Error("Erro ao gerar resposta IA");
    }

    const data = await res.json();
    const texto = data?.candidates?.[0]?.content?.parts
      ?.map((p) => p.text)
      .filter(Boolean)
      .join("\n")
      .trim();

    return texto || "Sem resposta processável.";
  } catch (err) {
    console.error("❌ Erro na Gemini:", err.message);
    return "Ocorreu um erro ao tentar responder.";
  }
}

/* ============================== Verificação do Usuário IA ============================== */
let AI_USER_ID = null;
const AI_USER_NAME = process.env.AI_USER_NAME || "ChatBox AI";
const AI_USER_EMAIL = process.env.AI_USER_EMAIL || "chatbox-ai@system.local";
const AI_USER_PHOTO =
  process.env.AI_USER_PHOTO || "/images/favicon.png";

async function ensureAIUser() {
  const [rows] = await pool.query("SELECT id FROM users WHERE email = ?", [
    AI_USER_EMAIL,
  ]);
  if (rows.length > 0) {
    AI_USER_ID = rows[0].id;
    return;
  }

  const hashed = await bcrypt.hash("ai-system", 10);
  const [insert] = await pool.query(
    "INSERT INTO users (nome, email, senha, photo) VALUES (?, ?, ?, ?)",
    [AI_USER_NAME, AI_USER_EMAIL, hashed, AI_USER_PHOTO]
  );
  AI_USER_ID = insert.insertId;
  console.log("✅ Usuário IA criado com ID:", AI_USER_ID);
}

ensureAIUser().catch((err) =>
  console.error("❌ Falha ao criar usuário IA:", err.message)
);

/* ============================== Helpers Conversas ============================== */
async function getOrCreateIAConversation(userId) {
  const [rows] = await pool.query(
    "SELECT id FROM conversas WHERE usuario1_id = ? AND eh_ia = TRUE LIMIT 1",
    [userId]
  );
  if (rows.length > 0) return rows[0].id;

  if (!AI_USER_ID) await ensureAIUser();

  const [insert] = await pool.query(
    "INSERT INTO conversas (usuario1_id, usuario2_id, eh_ia) VALUES (?, ?, TRUE)",
    [userId, AI_USER_ID]
  );
  return insert.insertId;
}

async function getOrCreateUserConversation(userA, userB) {
  const u1 = Math.min(userA, userB);
  const u2 = Math.max(userA, userB);
  const [rows] = await pool.query(
    "SELECT id FROM conversas WHERE eh_ia = FALSE AND ((usuario1_id=? AND usuario2_id=?) OR (usuario1_id=? AND usuario2_id=?)) LIMIT 1",
    [u1, u2, u2, u1]
  );
  if (rows.length > 0) return rows[0].id;
  const [insert] = await pool.query(
    "INSERT INTO conversas (usuario1_id, usuario2_id, eh_ia) VALUES (?, ?, FALSE)",
    [u1, u2]
  );
  return insert.insertId;
}

async function inserirMensagem(conversaId, remetenteId, texto) {
  await pool.query(
    "INSERT INTO mensagens (conversa_id, remetente_id, texto) VALUES (?, ?, ?)",
    [conversaId, remetenteId, texto]
  );
}

async function carregarMensagens(conversaId) {
  const [rows] = await pool.query(
    "SELECT id, remetente_id, texto, enviada_em FROM mensagens WHERE conversa_id = ? ORDER BY enviada_em ASC",
    [conversaId]
  );
  return rows;
}

/* ============================== Rotas Base ============================== */
app.get("/", (_, res) => {
  res.send("API do ChatBox online (conversas + Gemini)");
});

/* ============================== Rotas Usuários / Auth ============================== */
app.post("/api/usuarios/google", async (req, res) => {
  const { nome, email, photo } = req.body;
  if (!nome || !email || !photo)
    return res.status(400).json({ error: "Dados incompletos" });

  try {
    const [results] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (results.length > 0) {
      const token = gerarToken(results[0].id);
      return res.status(200).json({ status: "login", user: results[0], token });
    }

    const hashed = await bcrypt.hash("google-user", 10);
    const [insertResult] = await pool.query(
      "INSERT INTO users (nome, email, senha, photo) VALUES (?, ?, ?, ?)",
      [nome, email, hashed, photo]
    );

    const novoUsuario = { id: insertResult.insertId, nome, email, photo };
    const token = gerarToken(novoUsuario.id);
    res.status(201).json({ status: "cadastrado", user: novoUsuario, token });
  } catch (err) {
    res.status(500).json({ error: "Erro no banco", details: err.message });
  }
});

app.post("/api/usuarios/register", async (req, res) => {
  const { nome, email, senha, photo } = req.body;
  if (!nome || !email || !senha)
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });

  try {
    const [results] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (results.length > 0)
      return res.status(400).json({ error: "Email já cadastrado" });

    const hashed = await bcrypt.hash(senha, 10);
    const fotoFinal = photo || "";
    const [insert] = await pool.query(
      "INSERT INTO users (nome, email, senha, photo) VALUES (?, ?, ?, ?)",
      [nome, email, hashed, fotoFinal]
    );

    const token = gerarToken(insert.insertId);
    res.status(201).json({
      status: "cadastrado",
      user: { id: insert.insertId, nome, email, photo: fotoFinal },
      token,
    });
  } catch (err) {
    res.status(500).json({ error: "Erro no banco", details: err.message });
  }
});

app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha)
    return res.status(400).json({ error: "Email e senha obrigatórios" });

  try {
    const [results] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
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
    const [results] = await pool.query(
      "SELECT id, nome, email, photo FROM users WHERE id = ?",
      [req.usuarioId]
    );
    if (results.length === 0)
      return res.status(404).json({ error: "Usuário não encontrado" });

    res.status(200).json({ user: results[0] });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao buscar usuário", details: err.message });
  }
});

/* ========================= Todos usuarios ====================== */
app.get("/api/usuarios", autenticar, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, nome, email, photo FROM users WHERE id != ?",
      [req.usuarioId]
    );
    res.status(200).json(rows);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao listar usuários", details: err.message });
  }
});

/* ============================== Conversas ============================== */
app.post("/api/conversas", autenticar, async (req, res) => {
  const { destinatarioId, eh_ia } = req.body;
  const userId = req.usuarioId;

  try {
    let conversaId;
    if (eh_ia) {
      conversaId = await getOrCreateIAConversation(userId);
    } else {
      if (!destinatarioId)
        return res.status(400).json({
          error: "destinatarioId obrigatório para conversa entre usuários.",
        });
      conversaId = await getOrCreateUserConversation(userId, destinatarioId);
    }
    res.status(200).json({ conversaId });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao criar/obter conversa", details: err.message });
  }
});

app.get("/api/conversas", autenticar, async (req, res) => {
  const userId = req.usuarioId;
  try {
    const [rows] = await pool.query(
      `SELECT c.id,
              c.eh_ia,
              c.usuario1_id,
              c.usuario2_id,
              u1.nome AS usuario1_nome,
              u1.photo AS usuario1_photo,
              u2.nome AS usuario2_nome,
              u2.photo AS usuario2_photo
         FROM conversas c
         LEFT JOIN users u1 ON u1.id = c.usuario1_id
         LEFT JOIN users u2 ON u2.id = c.usuario2_id
        WHERE c.usuario1_id = ? OR c.usuario2_id = ?`,
      [userId, userId]
    );

    const lista = rows.map((c) => {
      if (c.eh_ia) {
        return {
          id: c.id,
          eh_ia: true,
          nome: AI_USER_NAME,
          photo: AI_USER_PHOTO,
        };
      } else {
        const souUser1 = c.usuario1_id === userId;
        return {
          id: c.id,
          eh_ia: false,
          nome: souUser1 ? c.usuario2_nome : c.usuario1_nome,
          photo: souUser1 ? c.usuario2_photo : c.usuario1_photo,
        };
      }
    });

    res.status(200).json(lista);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao listar conversas", details: err.message });
  }
});

app.get("/api/conversas/:conversaId/mensagens", autenticar, async (req, res) => {
  const conversaId = Number(req.params.conversaId);
  const userId = req.usuarioId;

  try {
    const [conv] = await pool.query(
      "SELECT * FROM conversas WHERE id = ? AND (usuario1_id = ? OR usuario2_id = ?)",
      [conversaId, userId, userId]
    );
    if (conv.length === 0)
      return res.status(403).json({ error: "Você não participa desta conversa." });

    const msgs = await carregarMensagens(conversaId);
    res.status(200).json(
      msgs.map((m) => ({
        id: m.id,
        sender: m.remetente_id === userId ? "user" : "outro",
        remetente_id: m.remetente_id,
        texto: m.texto,
        enviada_em: m.enviada_em,
      }))
    );
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao carregar mensagens", details: err.message });
  }
});

app.post("/api/conversas/:conversaId/mensagens", autenticar, async (req, res) => {
  const conversaId = Number(req.params.conversaId);
  const userId = req.usuarioId;
  const { texto } = req.body;

  if (!texto?.trim())
    return res.status(400).json({ error: "Texto obrigatório" });

  try {
    const [convRows] = await pool.query("SELECT * FROM conversas WHERE id = ?", [
      conversaId,
    ]);
    if (convRows.length === 0)
      return res.status(404).json({ error: "Conversa não encontrada" });

    const conversa = convRows[0];
    if (conversa.usuario1_id !== userId && conversa.usuario2_id !== userId)
      return res.status(403).json({ error: "Você não participa desta conversa." });

    await inserirMensagem(conversaId, userId, texto);

    let respostaIA = null;
    if (conversa.eh_ia) {
      if (!AI_USER_ID) await ensureAIUser();
      respostaIA = await gerarRespostaGemini(texto);
      await inserirMensagem(conversaId, AI_USER_ID, respostaIA);
    }

    res.status(201).json({
      ok: true,
      ia: conversa.eh_ia ? respostaIA : null,
    });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao enviar mensagem", details: err.message });
  }
});

/* ============================== Rotas Legadas /api/chat ============================== */
app.post("/api/chat", async (req, res) => {
  const { user_id, mensagem } = req.body;
  if (!user_id || !mensagem)
    return res.status(400).json({ error: "Dados incompletos" });

  try {
    const conversaId = await getOrCreateIAConversation(user_id);
    await inserirMensagem(conversaId, user_id, mensagem);
    const resposta = await gerarRespostaGemini(mensagem);
    await inserirMensagem(conversaId, AI_USER_ID, resposta);
    res.status(200).json({ resposta, conversaId });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao gerar resposta com Gemini", details: err.message });
  }
});

app.get("/api/chat/:userId", async (req, res) => {
  const userId = Number(req.params.userId);
  try {
    const conversaId = await getOrCreateIAConversation(userId);
    const msgs = await carregarMensagens(conversaId);
    const historico = msgs.map((m) => ({
      sender: m.remetente_id === userId ? "user" : "ia",
      text: m.texto,
      enviada_em: m.enviada_em,
    }));
    res.status(200).json(historico);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erro ao carregar histórico", details: err.message });
  }
});

/* ============================== Rota de Teste IA ============================== */
app.get("/api/test-ia", async (req, res) => {
  try {
    const resposta = await gerarRespostaGemini("Diga olá com estilo.");
    res.json({ ok: true, resposta });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============================== Start ============================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
