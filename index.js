const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ================================
// GERA MD5 SEM NENHUMA VALIDAÇÃO
// ================================
app.post("/hash", (req, res) => {
  const { codigo } = req.body;

  // Se codigo estiver vazio, ainda assim gera MD5
  const md5 = crypto
    .createHash("md5")
    .update(codigo || "")
    .digest("hex");

  res.json({
    sucesso: true,
    md5
  });
});

// ================================
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em: http://localhost:${PORT}`);
});
