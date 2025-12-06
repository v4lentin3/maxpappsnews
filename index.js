const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Rota da API de hash
app.get("/hash", (req, res) => {
  const { id, func } = req.query;

  if (!id) {
    return res.status(400).json({ erro: "Parâmetro 'id' é obrigatório" });
  }

  let valorParaHash = func ? func + id : id;

  const md5 = crypto
    .createHash("md5")
    .update(valorParaHash)
    .digest("hex");

  res.json({
    id,
    func: func || null,
    usadoNoHash: valorParaHash,
    md5
  });
});

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em: http://localhost:${PORT}`);
});
