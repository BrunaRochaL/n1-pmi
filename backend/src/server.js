const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { MongoClient } = require("mongodb");
require("dotenv").config({ path: "../.env" });

const app = express();
const port = process.env.PORT || 3002;

// Middleware
app.use(bodyParser.json());

// Conectar ao MongoDB
const uri = process.env.MONGODB_URI;
let db;
MongoClient.connect(uri, (err, client) => {
  if (err) return console.error(err);
  console.log("Conectado ao MongoDB");
  db = client.db("Datashield");
});

app.get("/", (req, res) => {
  res.send(
    "Servidor rodando. Use a rota POST /analisar-url para verificar URLs."
  );
});

// Rota de exemplo para análise de URL
app.post("/analisar-url", async (req, res) => {
  const { url } = req.body;
  try {
    const data = {
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content:
            "Você irá ler a URL e o conteúdo da página e irá analisar qual a porcentagem da chance de ser uma página com conteudo de phishing ou de golpe, traga a resposta em porcentagem e de forma resumida. Resuma em até 50 caracteres e traga a porcentagem da possibilidade de ter conteudo de phishing.Antes de trazer a resposta faça uma análise do conteudo para dar a resposta",
        },
        {
          role: "user",
          content: `url: ${url}`,
        },
      ],
    };

    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      data,
      {
        headers: {
          Authorization: `Bearer ${process.env.API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    const resultado = response.data.choices[0].message.content;
    res.json({ url, resultado });
  } catch (error) {
    console.error(
      "Erro ao fazer a requisição:",
      error.response ? error.response.data : error.message
    );
    res.status(500).send({ error: error.message });
  }
});

// Iniciar o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
