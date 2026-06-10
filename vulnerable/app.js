/**
 *  MINI-LABORATÓRIO OWASP - APLICAÇÃO VULNERÁVEL
 *  ATENÇÃO: Este código contém vulnerabilidades INTENCIONAIS
 *  para fins educacionais. NÃO USE EM PRODUÇÃO.
 * ============================================================
 *
 * Vulnerabilidades demonstradas:
 *  A01 — Broken Access Control (sem verificação de roles)
 *  A05 — Injection (SQL Injection + XSS Refletido)
 *  A07 — Authentication Failures (JWT sem expiração, senhas fracas)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// BANCO DE DADOS SIMULADO (em memória)
const users = [
  { id: 1, username: 'admin',  password: '123',      role: 'admin',  email: 'admin@empresa.com' },
  { id: 2, username: 'joao',   password: 'password', role: 'user',   email: 'joao@empresa.com'  },
  { id: 3, username: 'maria',  password: 'abc123',   role: 'user',   email: 'maria@empresa.com' },
];

const orders = [
  { id: 1, userId: 1, product: 'Notebook Pro', value: 4500.00 },
  { id: 2, userId: 2, product: 'Mouse Gamer',  value:  150.00 },
  { id: 3, userId: 3, product: 'Teclado Mec.', value:  350.00 },
];

// A07 — AUTHENTICATION FAILURES
// VULNERABILIDADE 1: Chave secreta fraca e hardcoded no código
// VULNERABILIDADE 2: Token JWT sem expiração (exp ausente)
// VULNERABILIDADE 3: Senhas em texto puro (sem hash)
const JWT_SECRET = 'secret'; // chave trivial e exposta no código-fonte

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Comparação direta — senhas não estão hasheadas
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // Token sem expiração: um token roubado é válido para sempre
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);

  res.json({ token, message: `Bem-vindo, ${user.username}!` });
});

// MIDDLEWARE DE AUTENTICAÇÃO — também vulnerável
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token ausente' });

  try {
    // Não verifica algoritmo — susceptível a "alg: none" attack
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido' });
  }
}

// A01 — BROKEN ACCESS CONTROL
// VULNERABILIDADE: Qualquer usuário autenticado acessa dados de
//                  outros usuários apenas passando ?userId=X
app.get('/meu-perfil', authenticate, (req, res) => {
  // Aceita userId da query string — qualquer user pode ver qualquer perfil
  const userId = req.query.userId || req.user.id;
  const user = users.find(u => u.id === parseInt(userId));

  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  // Retorna TODOS os dados, incluindo a senha
  res.json(user);
});

// Rota administrativa sem verificação de role
app.get('/admin/users', authenticate, (req, res) => {
  // Qualquer usuário autenticado chega aqui — não há checagem de role: 'admin'
  res.json({ users });
});

// A05 — INJECTION: SQL INJECTION SIMULADO
// (simula a lógica de um query builder vulnerável)
function simulateSqlQuery(filter) {
  // Concatenação direta de input do usuário na "query"
  const query = `SELECT * FROM orders WHERE product LIKE '%${filter}%'`;
  console.log('[SQL QUERY]:', query);

  // Simulação: se o filtro fechar a string e injetar condição sempre-verdadeira
  // Ex: filter = "' OR '1'='1" → retorna todos os registros
  if (filter.includes("' OR '") || filter.includes("' or '")) {
    return orders; // SQL Injection bem-sucedida — retorna tudo
  }
  return orders.filter(o =>
    o.product.toLowerCase().includes(filter.toLowerCase())
  );
}

app.get('/pedidos', authenticate, (req, res) => {
  const { filter } = req.query;

  if (!filter) return res.json({ orders });

  const result = simulateSqlQuery(filter);
  res.json({ query_executada: `SELECT * FROM orders WHERE product LIKE '%${filter}%'`, results: result });
});

// A05 — INJECTION: XSS REFLETIDO
app.get('/buscar', (req, res) => {
  const { q } = req.query;

  // Input do usuário refletido diretamente no HTML sem sanitização
  res.send(`
    <html>
      <body>
        <h2>Resultados para: ${q}</h2>
        <p>Nenhum resultado encontrado.</p>
        <a href="/buscar">Nova busca</a>
      </body>
    </html>
  `);
});

// ROTA DE DEMONSTRAÇÃO — mostra as vulnerabilidades disponíveis
app.get('/', (req, res) => {
  res.json({
    app: 'OWASP Lab — Aplicação VULNERÁVEL',
    aviso: 'SOMENTE PARA FINS EDUCACIONAIS',
    vulnerabilidades: {
      'A07_login_senha_fraca':       'POST /login  { username: "admin", password: "123" }',
      'A07_token_sem_expiracao':     'O token gerado em /login nunca expira',
      'A01_broken_access_control':   'GET /meu-perfil?userId=1  (com token de outro usuário)',
      'A01_admin_sem_role_check':    'GET /admin/users  (com token de user comum)',
      'A05_sql_injection':           "GET /pedidos?filter=' OR '1'='1",
      'A05_xss_refletido':           'GET /buscar?q=<script>alert("XSS")</script>',
    }
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n  App VULNERÁVEL rodando em http://localhost:${PORT}`);
  console.log('   SOMENTE PARA FINS EDUCACIONAIS!\n');
});

module.exports = app;
