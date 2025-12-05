require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const crypto = require("crypto");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuração do Swagger
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Vulnerable API - SAST Demo",
      version: "1.0.0",
      description:
        "API vulnerável para demonstração de ferramentas SAST. **NÃO USE EM PRODUÇÃO!**",
      contact: {
        name: "Security Testing Team",
        email: "security@example.com",
      },
    },
    servers: [
      {
        url: "https://projeto-p2-api.onrender.com",
        description: "Production server",
      },
      {
        url: "http://localhost:3000",
        description: "Development server",
      },
    ],
    tags: [
      {
        name: "SQL Injection",
        description: "Endpoints vulneráveis a SQL Injection",
      },
      {
        name: "Command Injection",
        description: "Endpoints vulneráveis a Command Injection",
      },
      {
        name: "XSS",
        description: "Endpoints vulneráveis a Cross-Site Scripting",
      },
      {
        name: "SSRF",
        description: "Endpoints vulneráveis a Server-Side Request Forgery",
      },
      {
        name: "Code Injection",
        description: "Endpoints vulneráveis a Code Injection",
      },
      {
        name: "File Operations",
        description: "Endpoints com vulnerabilidades em operações de arquivo",
      },
      {
        name: "Cryptography",
        description: "Endpoints com criptografia fraca",
      },
      {
        name: "Other",
        description: "Outras vulnerabilidades",
      },
    ],
  },
  apis: ["./src/app.js"],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// VULNERABILIDADE 1: Credenciais hardcoded
const DB_PASSWORD = "SuperSecret123!";
const API_KEY = "sk_live_51234567890abcdef";
const JWT_SECRET = "my-secret-key";

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect((err) => {
  if (err) {
    console.error("Erro ao conectar no banco:", err);
  } else {
    console.log("Conectado ao banco de dados MySQL na nuvem!");

    // Cria tabela users se não existir
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255),
        password VARCHAR(255)
      )
    `;
    db.query(createTableQuery, (err) => {
      if (err) console.error("Erro tabela:", err);
      else console.log("Tabela users pronta.");
    });
  }
});

// VULNERABILIDADE 3: SQL Injection
/**
 * @swagger
 * /users/{id}:
 *   get:
 *     summary: Buscar usuário por ID (Vulnerável a SQL Injection)
 *     tags: [SQL Injection]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID do usuário (vulnerável a SQL injection)
 *         example: "1 OR 1=1"
 *     responses:
 *       200:
 *         description: Lista de usuários
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *       500:
 *         description: Erro no servidor
 */
app.get("/users/:id", (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Buscar usuários
 *     tags: [SQL Injection]
 *     responses:
 *       200:
 *         description: Lista de usuários
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *       500:
 *         description: Erro no servidor
 */
app.get("/users", (req, res) => {
  const query = `SELECT * FROM users`;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// VULNERABILIDADE 4: Command Injection
/**
 * @swagger
 * /execute:
 *   post:
 *     summary: Executar comando (Vulnerável a Command Injection)
 *     tags: [Command Injection]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               command:
 *                 type: string
 *                 description: Comando a ser executado
 *                 example: "; cat /etc/passwd"
 *     responses:
 *       200:
 *         description: Resultado do comando
 *       500:
 *         description: Erro na execução
 */
app.post("/execute", (req, res) => {
  const command = req.body.command;
  exec(`ls ${command}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json({ output: stdout });
  });
});

// VULNERABILIDADE 5: Path Traversal
/**
 * @swagger
 * /download:
 *   get:
 *     summary: Download de arquivo (Vulnerável a Path Traversal)
 *     tags: [File Operations]
 *     parameters:
 *       - in: query
 *         name: file
 *         required: true
 *         schema:
 *           type: string
 *         description: Nome do arquivo
 *         example: "../../etc/passwd"
 *     responses:
 *       200:
 *         description: Arquivo encontrado
 *       404:
 *         description: Arquivo não encontrado
 */
app.get("/download", (req, res) => {
  const filename = req.query.file;
  const filepath = path.join(__dirname, "files", filename);

  res.sendFile(filepath);
});

// VULNERABILIDADE 6: XSS através de template sem sanitização
/**
 * @swagger
 * /search:
 *   get:
 *     summary: Buscar conteúdo (Vulnerável a XSS)
 *     tags: [XSS]
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *         description: Termo de busca
 *         example: "<script>alert('XSS')</script>"
 *     responses:
 *       200:
 *         description: Resultado da busca
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 */
app.get("/search", (req, res) => {
  const searchTerm = req.query.q;
  const html = `
    <html>
      <body>
        <h1>Resultados para: ${searchTerm}</h1>
      </body>
    </html>
  `;
  res.send(html);
});

// VULNERABILIDADE 7: Weak Cryptography
/**
 * @swagger
 * /encrypt:
 *   post:
 *     summary: Criptografar dados (Usa algoritmo fraco e chave hardcoded)
 *     tags: [Cryptography]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               data:
 *                 type: string
 *                 description: Dados para criptografar
 *                 example: "senha123"
 *     responses:
 *       200:
 *         description: Dados criptografados
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 encrypted:
 *                   type: string
 */
app.post("/encrypt", (req, res) => {
  const data = req.body.data;
  // Vulnerabilidade: MD5 é fraco, chave hardcoded, sem salt
  const weakKey = "weak-key-12345";
  const encrypted = crypto
    .createHash("md5")
    .update(data + weakKey)
    .digest("hex");
  res.json({ encrypted, algorithm: "md5", key: weakKey });
});

// VULNERABILIDADE 8: Ausência de rate limiting
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login de usuário (Sem rate limiting, vulnerável a SQL Injection)
 *     tags: [SQL Injection]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: "admin' OR '1'='1"
 *               password:
 *                 type: string
 *                 example: "anything"
 *     responses:
 *       200:
 *         description: Login bem-sucedido
 *       401:
 *         description: Credenciais inválidas
 */
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length > 0) {
      res.json({ success: true, token: "fake-jwt-token" });
    } else {
      res.status(401).json({ success: false });
    }
  });
});

// VULNERABILIDADE 9: Exposição de informações sensíveis em logs
app.use((err, req, res, next) => {
  console.log("Error details:", err.stack);
  console.log("Request body:", req.body);
  console.log("Database password:", DB_PASSWORD);
  res.status(500).json({ error: err.message, stack: err.stack });
});

// VULNERABILIDADE 10: SSRF (Server-Side Request Forgery)
/**
 * @swagger
 * /fetch-url:
 *   get:
 *     summary: Buscar URL externa (Vulnerável a SSRF)
 *     tags: [SSRF]
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *         description: URL para buscar
 *         example: "http://localhost:22"
 *     responses:
 *       200:
 *         description: Conteúdo da URL
 *       500:
 *         description: Erro ao buscar URL
 */
app.get("/fetch-url", (req, res) => {
  const url = req.query.url;
  const http = require("http");

  http
    .get(url, (response) => {
      let data = "";
      response.on("data", (chunk) => (data += chunk));
      response.on("end", () => res.send(data));
    })
    .on("error", (err) => res.status(500).json({ error: err.message }));
});

// VULNERABILIDADE 11: Uso de eval()
/**
 * @swagger
 * /calculate:
 *   post:
 *     summary: Calcular expressão (Vulnerável a Code Injection via eval)
 *     tags: [Code Injection]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               expression:
 *                 type: string
 *                 description: Expressão matemática
 *                 example: "process.version"
 *     responses:
 *       200:
 *         description: Resultado da expressão
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 result:
 *                   type: string
 */
app.post("/calculate", (req, res) => {
  const expression = req.body.expression;
  const result = eval(expression);
  res.json({ result });
});

// VULNERABILIDADE 12: Regex DoS (ReDoS)
/**
 * @swagger
 * /validate-email:
 *   get:
 *     summary: Validar email (Vulnerável a ReDoS)
 *     tags: [Other]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *         description: Email para validar
 *         example: "test@example.com"
 *     responses:
 *       200:
 *         description: Resultado da validação
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 valid:
 *                   type: boolean
 */
app.get("/validate-email", (req, res) => {
  const email = req.query.email;
  const regex =
    /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  const isValid = regex.test(email);
  res.json({ valid: isValid });
});

// VULNERABILIDADE 13: Insecure Random
/**
 * @swagger
 * /generate-token:
 *   get:
 *     summary: Gerar token (Usa Math.random inseguro)
 *     tags: [Cryptography]
 *     responses:
 *       200:
 *         description: Token gerado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 */
app.get("/generate-token", (req, res) => {
  const token = Math.random().toString(36).substring(7);
  res.json({ token });
});

// VULNERABILIDADE 14: Prototype Pollution
/**
 * @swagger
 * /merge:
 *   post:
 *     summary: Mesclar objetos (Vulnerável a Prototype Pollution)
 *     tags: [Other]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             example:
 *               __proto__:
 *                 isAdmin: true
 *     responses:
 *       200:
 *         description: Objeto mesclado
 */
app.post("/merge", (req, res) => {
  const target = {};
  const source = req.body;

  function merge(target, source) {
    for (let key in source) {
      if (typeof source[key] === "object") {
        target[key] = merge(target[key] || {}, source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  const result = merge(target, source);
  res.json(result);
});

// VULNERABILIDADE 15: XXE (XML External Entity)
/**
 * @swagger
 * /parse-xml:
 *   post:
 *     summary: Parse XML (Vulnerável a XXE)
 *     tags: [Other]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               xml:
 *                 type: string
 *                 example: '<?xml version="1.0"?><root><item>test</item></root>'
 *     responses:
 *       200:
 *         description: XML parseado
 *       400:
 *         description: Erro ao parsear XML
 */
app.post("/parse-xml", (req, res) => {
  const xml2js = require("xml2js");
  const parser = new xml2js.Parser({
    explicitArray: false,
  });

  parser.parseString(req.body.xml, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(result);
  });
});

// VULNERABILIDADE 16: Insecure File Upload
/**
 * @swagger
 * /upload:
 *   post:
 *     summary: Upload de arquivo (Sem validação de tipo)
 *     tags: [File Operations]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               filename:
 *                 type: string
 *                 example: "malicious.php"
 *               content:
 *                 type: string
 *                 example: "<?php system($_GET['cmd']); ?>"
 *     responses:
 *       200:
 *         description: Arquivo enviado com sucesso
 */
app.post("/upload", (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;

  fs.writeFileSync(path.join(__dirname, "uploads", filename), content);
  res.json({ success: true, path: filename });
});

// VULNERABILIDADE 17: Mass Assignment
/**
 * @swagger
 * /users:
 *   post:
 *     summary: Criar usuário (Vulnerável a Mass Assignment)
 *     tags: [SQL Injection]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: "hacker"
 *               password:
 *                 type: string
 *                 example: "password"
 *               isAdmin:
 *                 type: boolean
 *                 example: true
 *               role:
 *                 type: string
 *                 example: "admin"
 *     responses:
 *       200:
 *         description: Usuário criado
 *       500:
 *         description: Erro ao criar usuário
 */
app.post("/users", (req, res) => {
  const newUser = req.body;
  const query = `INSERT INTO users SET ?`;

  db.query(query, newUser, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: result.insertId, ...newUser });
  });
});

// VULNERABILIDADE 18: Timing Attack
/**
 * @swagger
 * /verify-token:
 *   post:
 *     summary: Verificar token (Vulnerável a Timing Attack)
 *     tags: [Other]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 example: "super-secret-token-12345"
 *     responses:
 *       200:
 *         description: Resultado da verificação
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 valid:
 *                   type: boolean
 */
app.post("/verify-token", (req, res) => {
  const token = req.body.token;
  const validToken = "super-secret-token-12345";

  if (token === validToken) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});

/**
 * @swagger
 * /:
 *   get:
 *     summary: Página inicial da API
 *     tags: [Other]
 *     responses:
 *       200:
 *         description: Mensagem de boas-vindas
 */
app.get("/", (req, res) => {
  res.json({
    message: "API v2.0 - Deploy via Merge Develop->Main! 🚀",
    status: "Online",
    documentation: "/api-docs",
    warning:
      "⚠️ Esta API contém vulnerabilidades intencionais. NÃO USE EM PRODUÇÃO!",
  });
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API Documentation: http://localhost:${PORT}/api-docs`);
  console.log(`API Key: ${API_KEY}`);
});

module.exports = app;
