# Serviços WEB - Mini-Laboratório OWASP
## Aluno: Pedro Pizzolato Mello

> **ATENÇÃO:** Este código contém vulnerabilidades **INTENCIONAIS** para fins educacionais.  
> Nunca use em ambiente de produção.

## Vulnerabilidades demonstradas

| Categoria | Localização | Descrição |
|-----------|-------------|-----------|
| **A01** — Broken Access Control | `vulnerable/app.js` | IDOR via `?userId=X` e rota admin sem checagem de role |
| **A05** — Injection (SQL) | `vulnerable/app.js` | Concatenação de input em query SQL → bypass por `' OR '1'='1` |
| **A05** — Injection (XSS) | `vulnerable/app.js` | Input refletido sem escape em HTML |
| **A07** — Authentication Failures | `vulnerable/app.js` | Senha `123`, JWT sem expiração, chave trivial hardcoded |

## Como executar

### 1. Instalar dependências
```bash
npm install
```

### 2. App vulnerável (porta 3000)
```bash
npm run vulnerable
# ou: node vulnerable/app.js
```

### 3. Executar demo de ataques (em outro terminal)
```bash
npm run demo
# ou: node demo-attacks.js
```

### 4. App corrigida (porta 3001)
```bash
npm run secure
# ou: node secure/app.js
```

## Roteiro de demonstração

### Passo 1 — A07: Login com senha trivial
```bash
$body = '{\"username\":\"admin\",\"password\":\"123\"}'
curl.exe -X POST http://localhost:3000/login -H "Content-Type: application/json" -d $body
```

### Passo 2 — A01: IDOR (acessar dados de outro usuário)
```bash
# Obtenha o token do passo 1, depois:
$token = "SEU_TOKEN_AQUI"
curl.exe -X GET "http://localhost:3000/meu-perfil?userId=2" -H "Authorization: Bearer $token"
```

### Passo 3 — A01: Escalada de privilégios
```bash
# Token de usuário comum (joao / password):
$token = "TOKEN_DO_JOAO"
curl.exe -X GET "http://localhost:3000/admin/users" -H "Authorization: Bearer $token"
```

### Passo 4 — A05: SQL Injection
```bash
$token = "SEU_TOKEN_AQUI"
curl.exe -X GET "http://localhost:3000/pedidos?filter=%27%20OR%20%271%27%3D%271" -H "Authorization: Bearer $token"
# filter decodificado: ' OR '1'='1
```

### Passo 5 — A05: XSS Refletido
Abra no browser:
```
http://localhost:3000/buscar?q=<script>alert('XSS')</script>
```

## Comparativo: Vulnerável vs. Corrigido

| Aspecto | `vulnerable/app.js` | `secure/app.js` |
|---------|---------------------|-----------------|
| Senhas | Texto puro | bcrypt (hash + salt) |
| JWT | Sem expiração, chave `"secret"` | `exp: 1h`, chave do env, `alg: HS256` |
| Controle de acesso | Sem verificação de role | Middleware `requireRole()` |
| IDOR | `userId` da query string | `userId` sempre do token |
| SQL | Concatenação direta | Queries parametrizadas |
| XSS | Input refletido sem escape | `escapeHtml()` + CSP headers |

## Ferramentas para varredura automatizada

- **OWASP ZAP**: `docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:3000`
- **Burp Suite Community**: configure proxy e intercepte as requisições

## Estrutura do projeto

```
owasp-lab/
├── vulnerable/
│   └── app.js          ← App com vulnerabilidades intencionais
├── secure/
│   └── app.js          ← App com correções aplicadas
├── demo-attacks.js     ← Script de demonstração dos ataques
├── package.json
└── README.md
```

## Referências e Materiais de Apoio

Este projeto e o desenvolvimento do laboratório prático foram fundamentados nas seguintes diretrizes e padrões globais de segurança da informação:

* **OWASP Foundation (2025).** *OWASP Top 10:2025 — The Ten Most Critical Web Application Security Risks*. Disponível em: [owasp.org/www-project-top-ten](https://owasp.org/www-project-top-ten/)
* **OWASP Foundation (2021).** *OWASP Top 10:2021 — Project Archives*. Disponível em: [owasp.org/Top10/](https://owasp.org/Top10/)
* **OWASP Cheat Sheet Series.** *Developer-Focused Security Cheat Sheets (SQLi, XSS, and Authentication Prevention)*. Disponível em: [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/)
* **NIST - National Institute of Standards and Technology (2020).** *Special Publication 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management*. Disponível em: [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
* **Auth0 / IETF (2020).** *JSON Web Token Best Current Practices (RFC 8725)*. Disponível em: [auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
* **PortSwigger Web Security Academy.** *SQL Injection & Cross-Site Scripting (XSS) Learning Paths*. Disponível em: [portswigger.net/web-security](https://portswigger.net/web-security/)
* **Snyk (2024).** *State of Open Source Security Report 2024 — Supply Chain Impacts*. Disponível em: [snyk.io/state-of-open-source-security](https://snyk.io/state-of-open-source-security/)
