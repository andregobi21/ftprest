require('dotenv').config();
const express = require("express");
const JSFtp = require("jsftp");
const { Readable } = require("stream");
const jwt = require("jsonwebtoken");
const bodyParser = require('body-parser');
const app = express();
const secret = process.env.SECRET; // chave secreta para assinar e verificar o token JWT

app.use(bodyParser.json());

// middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// rota de autenticação para obter um token JWT
app.post("/auth", function(req, res) {
  // verificar as credenciais do usuário e gerar um token JWT
  const { username, password } = req.body;
  if (username !== process.env.USERAPI || password !== process.env.PASS) {
    return res.sendStatus(401);
  }

  const user = { username };
  const token = jwt.sign(user, secret);
  res.json({ token });
});

// rota protegida que retorna uma lista de arquivos no servidor FTP
app.get("/files", authenticateToken, function(req, res) {
  const ftp = new JSFtp({
    host: process.env.HOSTFTP,
    port: process.env.PORTFTP,
    user: process.env.USERFTP,
    pass: process.env.PASSFTP
  });

  ftp.ls(".", function(err, files) {
    if (err) throw err;
    res.json(files);
  });
});

// rota protegida que retorna o conteúdo de um arquivo transcrito em base64
app.get("/file", authenticateToken, function(req, res) {
  const { filename } = req.query;
  const ftp = new JSFtp({
    host: process.env.HOSTFTP,
    port: process.env.PORTFTP,
    user: process.env.USERFTP,
    pass: process.env.PASSFTP
  });

  ftp.get(filename, function(err, socket) {
    if (err) throw err;

    const chunks = [];
    socket.on("data", function(d) {
      chunks.push(d);
    });

    socket.on("close", function() {
      const content = Buffer.concat(chunks);
      const base64Content = content.toString("base64");
      res.json({ filename, content: base64Content });
    });

    socket.resume();
  });
});

app.post("/delete", function(req, res) {
  const { filepath } = req.query;
  const ftp = new JSFtp({
    host: process.env.HOSTFTP,
    port: process.env.PORTFTP,
    user: process.env.USERFTP,
    pass: process.env.PASSFTP
  });
  
  ftp.raw("DELE /" + filepath, (err) => {
  if (err) {
    return res.sendStatus(400);
  } else {
    return res.sendStatus(200);
  };
});
});


app.listen(3000, function() {
  console.log("API FTP iniciada na porta 3000");
});