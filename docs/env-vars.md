# Variáveis de ambiente (por serviço)

⚠️ **Valores ficam SÓ no Railway.** Nunca commitar `.env` aqui. Esta página é só o
catálogo do que cada serviço usa.

## ViennaPet (`viennapet/`)

### Acesso ao MCP
- `MCP_AUTH_TOKEN` — token admin (role write). Não compartilhar.
- `MCP_USERS` — JSON de tokens por pessoa. Ver [acesso-viennapet.md](acesso-viennapet.md).
- `MCP_OAUTH_CLIENT_ID` — client id do conector OAuth do Claude (browser).

### WooCommerce / WordPress
- `WC_URL`, `WC_CONSUMER_KEY`, `WC_CONSUMER_SECRET`
- `WP_USER`, `WP_PASS`
- `WC_WRITES_ENABLED` — `true` libera escrita no WooCommerce (default off).

### Bling
- `BLING_CLIENT_ID`, `BLING_CLIENT_SECRET`, `BLING_REDIRECT_URI`
- `BLING_TOKEN_PATH` / tokens persistidos: `BLING_ACCESS_TOKEN`, `BLING_REFRESH_TOKEN`

### Meta (Instagram/Facebook + Ads)
- `META_APP_ID`, `META_APP_SECRET`, `META_REDIRECT_URI`
- `META_WEBHOOK_VERIFY_TOKEN`
- Preenchidos automaticamente após `/meta/auth` (persistidos via Railway API):
  `META_PAGE_TOKEN`, `META_PAGE_ID`, `META_IG_ID`, `META_PAGE_NAME`,
  **`META_USER_TOKEN`**, **`META_AD_ACCOUNT_ID`** (estes dois habilitam os Ads).
- `ADS_WRITES_ENABLED` — `true` libera pausar/ativar campanhas (default off).

### Railway (persistência de tokens via GraphQL)
- `RAILWAY_API_TOKEN`, `RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT_ID`, `RAILWAY_SERVICE_ID`
- `RAILWAY_PUBLIC_DOMAIN`, `PORT` (geridos pelo Railway)

### Google Sheets (cupons/afiliados)
- `SHEETS_WEBHOOK_URL`, `SHEETS_SECRET`

## ExpansaoPet (`expansaopet/`) — isolado, Bling-only

- `MCP_AUTH_TOKEN`, `MCP_USERS`
- `BLING_CLIENT_ID`, `BLING_CLIENT_SECRET`, `BLING_REDIRECT_URI`, `BLING_TOKEN_FILE`
- `RAILWAY_API_TOKEN`, `RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT_ID`, `RAILWAY_SERVICE_ID`
- `RAILWAY_PUBLIC_DOMAIN`, `PORT`

> ExpansaoPet **não tem** nenhuma var de WooCommerce/WordPress/Meta — e não deve ter.
> Mantém o isolamento total em relação ao ViennaPet.

## Novas vars a configurar para os Ads (ViennaPet)

Ao ativar os Ads, garanta no serviço ViennaPet:
- `ADS_WRITES_ENABLED` (= `false` no começo; `true` quando quiser pausar/ativar).
- `META_USER_TOKEN` e `META_AD_ACCOUNT_ID` → criados automaticamente ao refazer
  `/meta/auth` concedendo `ads_read`/`ads_management`. Não precisa preencher à mão.
