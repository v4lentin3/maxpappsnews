// ✅ Memória de controle por IP
const acessos = new Map();

app.post("/hash", (req, res) => {
  const referer = req.get("referer");
  const ip = req.ip;

  // 🔒 Permite apenas wolfpayment.com.br
  const dominioPermitido = /^https?:\/\/([a-z0-9-]+\.)*wolfpayment\.com\.br/i;

  if (!referer || !dominioPermitido.test(referer)) {
    return res.status(403).json({
      sucesso: false,
      erro: "Acesso negado: você precisa vir do site oficial."
    });
  }

  // 🔒 BLOQUEIA se já gerou nesta visita
  if (acessos.has(ip)) {
    return res.status(429).json({
      sucesso: false,
      erro: "Você já gerou um código. Volte ao site novamente para gerar outro."
    });
  }

  const { codigo } = req.body;

  if (!codigo) {
    return res.status(400).json({
      sucesso: false,
      erro: "Código não informado."
    });
  }

  // ✅ Gera o MD5
  const md5 = crypto
    .createHash("md5")
    .update(codigo)
    .digest("hex");

  // ✅ Marca que esse IP já usou
  acessos.set(ip, true);

  res.json({
    sucesso: true,
    md5
  });
});


// ✅ Libera novamente quando a pessoa voltar ao site
app.get("/reset", (req, res) => {
  const referer = req.get("referer");
  const ip = req.ip;

  const dominioPermitido = /^https?:\/\/([a-z0-9-]+\.)*wolfpayment\.com\.br/i;

  if (referer && dominioPermitido.test(referer)) {
    acessos.delete(ip);
  }

  res.sendStatus(204);
});
