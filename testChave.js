// testGeminiRaw.js
import 'dotenv/config';

const API_KEY = process.env.GEMINI_API_KEY; // garante que .env está carregado
if (!API_KEY) {
    console.error("❌ GEMINI_API_KEY ausente");
    process.exit(1);
}

const MODEL = "gemini-1.5-flash"; // modelo estável

async function callGemini(prompt) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${API_KEY}`;

    const body = {
        contents: [
            {
                role: "user",
                parts: [{ text: prompt }]
            }
        ]
    };

    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status} - ${errText}`);
    }

    const data = await res.json();
    const text =
        data?.candidates?.[0]?.content?.parts
            ?.map(p => p.text)
            .filter(Boolean)
            .join("\n")
            .trim() || "(sem texto)";

    return text;
}

(async () => {
    try {
        console.log("➡️ Enviando prompt...");
        const resposta = await callGemini("Resuma em uma frase o que é IA.");
        console.log("✅ Resposta:", resposta);
    } catch (e) {
        console.error("❌ Falhou:", e.message);
    }
})();
