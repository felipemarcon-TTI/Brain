# Brain

Monorepo privado com os MCPs (Model Context Protocol) da operação. Fonte única de
verdade — cada pasta é um deployable **independente e isolado**, com seu próprio
serviço no Railway.

## Produtos

| Pasta          | Produto    | Integrações                                              | Railway (Root Directory) |
|----------------|------------|---------------------------------------------------------|--------------------------|
| `viennapet/`   | ViennaPet  | Bling + WooCommerce + WordPress (site) + Meta + **Ads**  | `viennapet`              |
| `expansaopet/` | ExpansaoPet| Bling (somente)                                         | `expansaopet`            |

**ViennaPet e ExpansaoPet são softwares diferentes e isolados.** Não compartilham
tokens, contas, env vars nem código. Cada serviço Railway aponta para a sua pasta
via *Root Directory*.

## ViennaPet = produto completo num único token

Quem recebe acesso ao MCP do ViennaPet (URL SSE + Bearer token) passa a ter, no
mesmo token, todas as ferramentas: catálogo/estoque/pedidos (Bling), loja
(WooCommerce), site (WordPress), redes sociais orgânicas (Meta/Instagram/Facebook,
DMs) e **anúncios** (Meta Ads). Ver [docs/acesso-viennapet.md](docs/acesso-viennapet.md).

## Documentação

- [docs/acesso-viennapet.md](docs/acesso-viennapet.md) — dar/revogar acesso por pessoa (`MCP_USERS`).
- [docs/deploy.md](docs/deploy.md) — como cada pasta deploya no Railway.
- [docs/env-vars.md](docs/env-vars.md) — catálogo de variáveis de ambiente por serviço.

## Regras

- Editar **somente** o código aqui no Git (deploy automático via Railway). Não manter
  cópias locais soltas.
- Segredos **nunca** entram no repo — ficam só nas env vars do Railway. Os `.env` são
  ignorados pelo `.gitignore`.
