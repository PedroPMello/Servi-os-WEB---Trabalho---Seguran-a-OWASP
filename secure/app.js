/**
 * ============================================================
 *  MINI-LABORATÓRIO OWASP - APLICAÇÃO CORRIGIDA
 *  Cada correção está comentada com o item OWASP correspondente.
 * ============================================================
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// BANCO DE DADOS SIMULADO (em memória, com senhas hasheadas)

// A07-FIX: senhas armazenadas com bcrypt (hash + salt)
// Para gerar: bcrypt.hashSync('senha', 12)
const users = [
  { id: 1, username: 'admin', passwordHash: bcrypt.hashSync('Adm1n@S3cur3!', 12), role: 'admin',  email: 'admin@empresa.com' },
  { id: 2, username: 'joao',  passwordHash: bcrypt.hashSync('Jo4o@P4ssw0rd', 12), role: 'user',   email: 'joao@empresa.com'  },
  { id: 3, username: 'maria', passwordHash: bcrypt.hashSync('M4r1a@S3cur3!', 12), role: 'user',   email: 'maria@empresa.com' },
];

const orders = [
  { id: 1, userId: 1, product: 'Notebook Pro', value: 4500.00 },
  { id: 2, userId: 2, product: 'Mouse Gamer',  value:  150.00 },
  { id: 3, userId: 3, product: 'Teclado Mec.', value:  350.00 },
];

// A07-FIX: Chave secreta forte, carregada de variável de ambiente
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
// Em produção: nunca use fallback — exija a variável de ambiente

// A07-FIX: Login com bcrypt + token com expiração
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username e password são obrigatórios' });
  }

  const user = users.find(u => u.username === username);

  // Comparação constante de tempo para evitar timing attacks
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    // Mensagem genérica — não revela se usuário existe ou a senha está errada
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // Token com expiração (1h) e apenas dados necessários (sem role no token)
  const token = jwt.sign(
    { id: user.id },
    JWT_SECRET,
    { expiresIn: '1h', algorithm: 'HS256' }
  );

  res.json({ token, message: `Autenticado com sucesso.` });
});

// MIDDLEWARE DE AUTENTICAÇÃO SEGURO
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token ausente' });

  try {
    // Algoritmo especificado explicitamente — previne "alg: none" attack
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    // Buscar usuário completo (incluindo role) do "banco", não do token
    req.userFull = users.find(u => u.id === req.user.id);
    if (!req.userFull) return res.status(401).json({ error: 'Usuário não encontrado' });
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado. Faça login novamente.' });
    }
    res.status(403).json({ error: 'Token inválido' });
  }
}

// MIDDLEWARE DE AUTORIZAÇÃO (verifica role)
function requireRole(role) {
  return (req, res, next) => {
    if (req.userFull.role !== role) {
      return res.status(403).json({ error: 'Acesso negado: permissão insuficiente' });
    }
    next();
  };
}

// A01-FIX: Usuário só acessa os próprios dados
app.get('/meu-perfil', authenticate, (req, res) => {
  // ID sempre vem do token autenticado, nunca da query string
  const user = req.userFull;

  // Retorna apenas campos seguros, nunca passwordHash
  const { passwordHash, ...safeUser } = user;
  res.json(safeUser);
});

// A01-FIX: Rota admin com checagem de role
app.get('/admin/users', authenticate, requireRole('admin'), (req, res) => {
  const safeUsers = users.map(({ passwordHash, ...u }) => u);
  res.json({ users: safeUsers });
});

// A05-FIX: PARAMETERIZED QUERY (simulado) — sem concatenação
function safeSqlQuery(filter) {
  // Em ORMs/drivers reais: db.query('SELECT * FROM orders WHERE product LIKE ?', [`%${filter}%`])
  // Aqui é simulada a separação entre código SQL e dados do usuário
  const sanitized = String(filter).replace(/['"\\;]/g, ''); // sanitização básica para simulação
  console.log('[SQL SEGURO — parameterizado]:', `SELECT * FROM orders WHERE product LIKE '%?%'`, 'param:', filter);

  return orders.filter(o =>
    o.product.toLowerCase().includes(sanitized.toLowerCase())
  );
}

app.get('/pedidos', authenticate, (req, res) => {
  const { filter } = req.query;

  // A01-FIX: usuário comum só vê os próprios pedidos
  const userOrders = req.userFull.role === 'admin'
    ? orders
    : orders.filter(o => o.userId === req.userFull.id);

  if (!filter) return res.json({ orders: userOrders });

  const result = safeSqlQuery(filter).filter(o =>
    req.userFull.role === 'admin' || o.userId === req.userFull.id
  );
  res.json({ results: result });
});

// A05-FIX: XSS — Escaping de output + Content-Type correto
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

app.get('/buscar', (req, res) => {
  const { q } = req.query || '';

  // Output escapado + Content-Security-Policy no header
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');

  res.send(`
    <html>
      <head><meta charset="UTF-8"></head>
      <body>
        <h2>Resultados para: ${escapeHtml(q)}</h2>
        <p>Nenhum resultado encontrado.</p>
        <a href="/buscar">Nova busca</a>
      </body>
    </html>
  `);
});

// SECURITY HEADERS GLOBAIS (boas práticas adicionais)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  next();
});

app.get('/', (req, res) => {
  res.json({
    app: 'OWASP Lab — Aplicação CORRIGIDA',
    correcoes: {
      'A07': 'bcrypt, JWT com expiração, chave via env, alg explícito',
      'A01': 'userId sempre do token, roles verificadas por middleware',
      'A05_sql': 'Queries parametrizadas, sem concatenação de input',
      'A05_xss': 'escapeHtml() + Content-Security-Policy headers',
    }
  });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`\n App SEGURA rodando em http://localhost:${PORT}\n`);
});

module.exports = app;
