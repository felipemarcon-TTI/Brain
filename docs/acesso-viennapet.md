# Dar e revogar acesso ao ViennaPet

O ViennaPet é **um único MCP** que já reúne Bling + WooCommerce + WordPress (site)
+ Meta orgânico + **Ads**. Portanto, **um único Bearer token = produto completo**.
Dar acesso a alguém = entregar a URL SSE + um token. Revogar = remover esse token.

## URL do MCP (a mesma para todos)

```
https://viennapet-mcp-production.up.railway.app/sse
```

## Modelo: um token por pessoa (`MCP_USERS`)

O servidor aceita dois tipos de credencial (ver `viennapet/server.py`, função
`_load_users`):

- `MCP_AUTH_TOKEN` — token **admin** (role `write`). Use só para você. Não compartilhe.
- `MCP_USERS` — JSON com **um token por pessoa**, cada um revogável individualmente:

```json
[
  {"id": "cliente-acme", "role": "read",  "token": "<token-unico>"},
  {"id": "socio-joao",   "role": "write", "token": "<outro-token>"}
]
```

- `role: "read"` → só leitura (não executa tools de escrita: criar/atualizar pedido,
  cupom, pausar/ativar anúncio, etc.).
- `role: "write"` → leitura + escrita.

### Dar acesso a uma pessoa

1. Gere um token aleatório forte. Ex. (qualquer um):
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
2. No Railway → serviço **ViennaPet** → Variables → `MCP_USERS`, adicione uma entrada
   com `id` (identificador da pessoa), `role` e o `token` gerado. Salve (redeploy).
3. Entregue à pessoa: a **URL SSE** acima + o **Bearer token**. Pronto — ela tem o
   produto completo (Bling/Woo/Site/Meta/Ads), limitado pelo `role`.

### Revogar acesso

Remova a entrada daquela pessoa de `MCP_USERS` e salve (redeploy). Os demais tokens
continuam funcionando. (Para cortar TODOS de uma vez, troque o `MCP_AUTH_TOKEN`.)

## Alternativa: Admin API (em memória)

O servidor expõe rotas administrativas (requerem Bearer admin com role `write`):

- `GET  /admin/users` — lista usuários (id + role).
- `POST /admin/users` `{"id": "...", "role": "read|write"}` — cria usuário e **retorna
  o token gerado**.
- `DELETE /admin/users/{id}` — remove um usuário.
- `GET  /admin/export` — exporta os usuários no formato de `MCP_USERS`.

⚠️ Usuários criados por essa API ficam **em memória** e somem no próximo deploy. Para
persistir, use `/admin/export` e cole o resultado na env var `MCP_USERS` do Railway.

## Escrita protegida (defesa em profundidade)

Operações que gastam/alteram têm dois gates:

- **Role** `write` (acima).
- **Kill-switches** por env var, default desligados:
  - `WC_WRITES_ENABLED=true` libera escrita no WooCommerce.
  - `ADS_WRITES_ENABLED=true` libera pausar/ativar campanhas (Ads).
