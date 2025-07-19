import axios from "axios";

const API_URL = "https://apichat-1gr1.onrender.com/api/chat"; // Troque para o teu endpoint

async function testarIA() {
  try {
    const res = await axios.post(API_URL, {
      user_id: 1, // Coloca um user_id válido existente na tua base
      mensagem: "Olá IA, tudo bem?"
    });

    console.log("Resposta da API:", res.data);
  } catch (error) {
    console.error("Erro ao chamar a API:", error.response?.data || error.message);
  }
}

testarIA();
