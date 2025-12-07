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
const DOMINIO_PERMITIDO = /^https?:\/\/([a-z0-9-]+\.)*wolfpayment\.com\.br/i;
const TEMPO_EXPIRACAO = 2 * 60 * 1000; // 2 minutos
const MAX_TENTATIVAS = 3;

// ================================
// MEMÓRIA DE SEGURANÇA
// ================================
const sessoes = new Map();    // ip => { token, expira, usado }
const tentativas = new Map(); // ip => tentativas

// ================================
// ✅ CRIA SESSÃO SOMENTE SE VEIO DO SITE
// ================================
app.get("/", (req, res, next) => {
  const referer = req.get("referer");
  const ip = req.ip;

  // 🔒 BLOQUEIA se digitou direto na barra
  if (!referer || !DOMINIO_PERMITIDO.test(referer)) {
    return res.status(403).send("Acesso negado. Entre apenas pelo site oficial.");
  }

  // ✅ Cria nova sessão ao acessar pelo site
  const token = crypto.randomBytes(32).toString("hex");

  sessoes.set(ip, {
    token,
    expira: Date.now() + TEMPO_EXPIRACAO,
    usado: false
  });

  tentativas.delete(ip);

  next(); // continua para servir o HTML
});

// ================================
// ✅ GERA MD5 COM SEGURANÇA TOTAL
// ================================
app.post("/hash", (req, res) => {
  const referer = req.get("referer");
  const ip = req.ip;

  // 🔒 Domínio obrigatório
  if (!referer || !DOMINIO_PERMITIDO.test(referer)) {
    return res.status(403).json({
      sucesso: false,
      erro: "Acesso negado."
    });
  }

  // 🔒 Sessão obrigatória
  const sessao = sessoes.get(ip);
  if (!sessao) {
    return res.status(401).json({
      sucesso: false,
      erro: "Sessão inválida. Volte ao site."
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

  const { codigo, token } = req.body;

  if (!codigo || !token || token !== sessao.token) {
    tentativas.set(ip, tent + 1);
    return res.status(403).json({
      sucesso: false,
      erro: "Token inválido."
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
  console.log(`✅ Servidor seguro rodando em: http://localhost:${PORT}`);
});
