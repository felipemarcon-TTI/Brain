# Deploy (Railway)

Cada pasta deste monorepo é um serviço **independente** no Railway. O segredo é o
**Root Directory**: cada serviço builda/roda apenas a sua subpasta.

| Serviço Railway | Repo   | Root Directory | Start                |
|-----------------|--------|----------------|----------------------|
| ViennaPet MCP   | `Brain`| `viennapet`    | `python server.py`   |
| ExpansaoPet MCP | `Brain`| `expansaopet`  | `python server.py`   |

Cada pasta já tem `railway.toml` (builder nixpacks, `startCommand = python server.py`),
`Procfile` e `requirements.txt`.

## Migrar um serviço existente do repo antigo para o Brain

> Faça **um serviço de cada vez** e valide antes de seguir. O serviço antigo continua
> no ar até o novo build passar (deploy é blue/green no Railway).

1. Railway → serviço (ex. ViennaPet) → **Settings → Source**.
2. Troque o repositório conectado de `felipemarcon-TTI/viennapet-mcp` para
   `felipemarcon-TTI/Brain`.
3. Em **Settings → Source → Root Directory**, defina `viennapet` (ou `expansaopet`).
4. As **env vars não migram com o código** — elas já estão no serviço e permanecem.
   Só adicione as novas (ver [env-vars.md](env-vars.md)).
5. Trigger deploy (ou push no `Brain`). Acompanhe o build.
6. Valide: `GET /version` e `GET /health/sistema` respondem OK.

## Verificação pós-deploy

- `GET https://viennapet-mcp-production.up.railway.app/health/sistema`
  → deve trazer `status: ok` e os campos `woocommerce_writes` / `ads_writes`.
- `GET .../version` → confirma a versão no ar.
- Conectar pelo Claude e testar uma tool de cada domínio
  (`listar_produtos_bling`, `listar_produtos_wc`, `instagram_resumo`, `ads_insights`).

## Aposentar os repos antigos

Só **depois** de confirmar os dois serviços rodando do `Brain`: arquive
`viennapet-mcp` e `expansaopet-mcp` no GitHub (Settings → Archive). **Não apague** —
eles ficam como arquivo histórico. O histórico de commits também já foi preservado
aqui via `git subtree`.
