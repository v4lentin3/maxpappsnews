const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ================================
// CONFIGURAÇÕES
// ================================
const TEMPO_EXPIRACAO = 2 * 60 * 1000; // 2 minutos
const MAX_TENTATIVAS = 3;

// ================================
// MEMÓRIA DE SEGURANÇA
// ================================
const sessoes = new Map();     // ip => { expira, usado }
const tentativas = new Map(); // ip => tentativas

// ================================
// ✅ CRIA SESSÃO PARA QUALQUER USUÁRIO
// ================================
app.get("/", (req, res, next) => {
  const ip = req.ip;

  sessoes.set(ip, {
    expira: Date.now() + TEMPO_EXPIRACAO,
    usado: false
  });

  tentativas.delete(ip);

  next();
});

// ================================
// ✅ GERA MD5 COM SEGURANÇA
// ================================
app.post("/hash", (req, res) => {
  const ip = req.ip;

  // 🔒 Sessão obrigatória
  const sessao = sessoes.get(ip);
  if (!sessao) {
    return res.status(401).json({
      sucesso: false,
      erro: "Sessão inválida. Atualize a página."
    });
  }

  // 🔒 Expiração
  if (Date.now() > sessao.expira) {
    sessoes.delete(ip);
    return res.status(401).json({
      sucesso: false,
      erro: "Sessão expirada."
    });
  }

  // 🔒 Só pode gerar 1 vez
  if (sessao.usado) {
    return res.status(429).json({
      sucesso: false,
      erro: "Você já gerou um código nesta visita."
    });
  }

  // 🔒 Anti-força-bruta
  const tent = tentativas.get(ip) || 0;
  if (tent >= MAX_TENTATIVAS) {
    return res.status(429).json({
      sucesso: false,
      erro: "Muitas tentativas."
    });
  }

  const { codigo } = req.body;

  if (!codigo) {
    tentativas.set(ip, tent + 1);
    return res.status(403).json({
      sucesso: false,
      erro: "Código inválido."
    });
  }

  // ✅ GERA MD5
  const md5 = crypto
    .createHash("md5")
    .update(codigo)
    .digest("hex");

  // 🔒 Marca sessão como usada
  sessao.usado = true;
  sessoes.set(ip, sessao);

  res.json({
    sucesso: true,
    md5
  });
});

// ================================
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em: http://localhost:${PORT}`);
});
