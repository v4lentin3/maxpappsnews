const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ✅ ROTA PROTEGIDA DE GERAÇÃO DE HASH
app.get("/hash", (req, res) => {
  const referer = req.get("referer");

  // 🔒 BLOQUEIA se acesso direto
  if (!referer) {
    return res.status(403).json({
      erro: "Acesso direto não permitido."
    });
  }

  const { id, func } = req.query;

  if (!id) {
    return res.status(400).json({
      erro: "Acesso direto não permitido."
    });
  }

  // ✅ Geração do MD5
  let valorParaHash = func ? func + id : id;

  const md5 = crypto
    .createHash("md5")
    .update(valorParaHash)
    .digest("hex");

  res.json({
    sucesso: true,
    id,
    func: func || null,
    usadoNoHash: valorParaHash,
    md5,
    origem: referer
  });
});

// ✅ ROTA DE TESTE (opcional)
app.get("/", (req, res) => {
  res.send("✅ Servidor online e protegido!");
});

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em: http://localhost:${PORT}`);
});
