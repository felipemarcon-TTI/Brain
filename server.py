import base64
import json
import os
import re
import secrets
from datetime import date
from pathlib import Path

import anyio
import requests
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

# ── Config ────────────────────────────────────────────────────────────────────

WC_URL             = os.environ.get("WC_URL", "").rstrip("/")
WC_CONSUMER_KEY    = os.environ.get("WC_CONSUMER_KEY", "")
WC_CONSUMER_SECRET = os.environ.get("WC_CONSUMER_SECRET", "")
WP_USER            = os.environ.get("WP_USER", "")
WP_PASS            = os.environ.get("WP_PASS", "")

BLING_CLIENT_ID     = os.environ.get("BLING_CLIENT_ID", "")
BLING_CLIENT_SECRET = os.environ.get("BLING_CLIENT_SECRET", "")
BLING_BASE_URL      = "https://www.bling.com.br/Api/v3"
BLING_TOKEN_FILE    = Path.home() / ".bling" / "tokens.json"

_PORT          = int(os.environ.get("PORT", 8000))
_PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
_BASE_URL      = f"https://{_PUBLIC_DOMAIN}" if _PUBLIC_DOMAIN else f"http://localhost:{_PORT}"
BLING_REDIRECT_URI = os.environ.get("BLING_REDIRECT_URI", f"{_BASE_URL}/bling/callback")

mcp = FastMCP("ViennaPet MCP", host="0.0.0.0", port=_PORT)

_bling_pending_state: dict[str, str] = {}


# ── WooCommerce helpers ───────────────────────────────────────────────────────

def _wc_auth():
    return (WC_CONSUMER_KEY, WC_CONSUMER_SECRET)

def _wp_auth():
    return (WP_USER, WP_PASS)

def _wc_get(endpoint: str, params: dict | None = None) -> dict | list:
    resp = requests.get(f"{WC_URL}/wp-json/wc/v3/{endpoint}", auth=_wc_auth(), params=params or {}, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _wc_put(endpoint: str, data: dict) -> dict:
    resp = requests.put(f"{WC_URL}/wp-json/wc/v3/{endpoint}", auth=_wc_auth(), json=data, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _wc_post(endpoint: str, data: dict) -> dict:
    resp = requests.post(f"{WC_URL}/wp-json/wc/v3/{endpoint}", auth=_wc_auth(), json=data, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _wc_get_all(endpoint: str, params: dict | None = None) -> list:
    params = params or {}
    params.setdefault("per_page", 100)
    results, page = [], 1
    while True:
        params["page"] = page
        batch = _wc_get(endpoint, params)
        if not batch:
            break
        results.extend(batch)
        if len(batch) < params["per_page"]:
            break
        page += 1
    return results

def _limpar_html(texto: str) -> str:
    return re.sub(r"<[^>]+>", "", texto or "").strip()

def _wp_get(endpoint: str, params: dict | None = None) -> dict | list:
    resp = requests.get(f"{WC_URL}/wp-json/{endpoint}", auth=_wp_auth(), params=params or {}, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _wp_post(endpoint: str, data: dict) -> dict:
    resp = requests.post(f"{WC_URL}/wp-json/{endpoint}", auth=_wp_auth(), json=data, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ── Bling helpers ─────────────────────────────────────────────────────────────

def _bling_credentials_header() -> str:
    raw = f"{BLING_CLIENT_ID}:{BLING_CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()

def _bling_save_tokens(data: dict) -> None:
    BLING_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLING_TOKEN_FILE.write_text(json.dumps(data))

def _bling_load_tokens() -> dict | None:
    if BLING_TOKEN_FILE.exists():
        return json.loads(BLING_TOKEN_FILE.read_text())
    access  = os.environ.get("BLING_ACCESS_TOKEN", "")
    refresh = os.environ.get("BLING_REFRESH_TOKEN", "")
    if refresh:
        return {"access_token": access, "refresh_token": refresh}
    return None

def _bling_refresh_token() -> str:
    tokens = _bling_load_tokens()
    if not tokens:
        raise RuntimeError("Não autenticado. Use a ferramenta `autenticar` primeiro.")
    resp = requests.post(
        f"{BLING_BASE_URL}/oauth/token",
        headers={"Authorization": _bling_credentials_header(), "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
    )
    resp.raise_for_status()
    new_tokens = resp.json()
    _bling_save_tokens(new_tokens)
    return new_tokens["access_token"]

def _bling_get_token() -> str:
    tokens = _bling_load_tokens()
    if not tokens:
        raise RuntimeError("Não autenticado. Use a ferramenta `autenticar` primeiro.")
    return tokens["access_token"]

def _bling_get(path: str, params: dict | None = None) -> dict:
    token = _bling_get_token()
    resp = requests.get(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
    if resp.status_code == 401:
        token = _bling_refresh_token()
        resp = requests.get(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
    resp.raise_for_status()
    return resp.json()

def _bling_put(path: str, body: dict) -> dict:
    token = _bling_get_token()
    resp = requests.put(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if resp.status_code == 401:
        token = _bling_refresh_token()
        resp = requests.put(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}

def _bling_post(path: str, body: dict) -> dict:
    token = _bling_get_token()
    resp = requests.post(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if resp.status_code == 401:
        token = _bling_refresh_token()
        resp = requests.post(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


# ── WooCommerce Tools ─────────────────────────────────────────────────────────

@mcp.tool()
def listar_produtos_wc(status: str = "publish") -> str:
    """Lista todos os produtos da loja WooCommerce."""
    produtos = _wc_get_all("products", {"status": status})
    if not produtos:
        return "Nenhum produto encontrado."
    linhas = [
        f"- [#{p['id']}] {p['name']} | R$ {p['price']} | Estoque: {p.get('stock_quantity', '?')} | SKU: {p.get('sku') or 'sem SKU'}"
        for p in produtos
    ]
    return f"**{len(produtos)} produto(s):**\n" + "\n".join(linhas)


@mcp.tool()
def buscar_produto_wc(produto_id: int) -> str:
    """Retorna todos os detalhes de um produto WooCommerce pelo ID."""
    p = _wc_get(f"products/{produto_id}")
    atributos = "; ".join(f"{a['name']}: {', '.join(a['options'])}" for a in p.get("attributes", []))
    return (
        f"**#{p['id']} — {p['name']}**\n"
        f"- Tipo: {p['type']} | Status: {p['status']}\n"
        f"- SKU: {p.get('sku') or 'sem SKU'}\n"
        f"- Preço regular: R$ {p.get('regular_price') or p.get('price')} | Promoção: R$ {p.get('sale_price') or '-'}\n"
        f"- Estoque: {p.get('stock_quantity')} ({p.get('stock_status')})\n"
        f"- Categorias: {', '.join(c['name'] for c in p.get('categories', []))}\n"
        f"- Atributos: {atributos or '-'}\n"
        f"- Variações: {len(p.get('variations', []))}\n"
        f"- Descrição curta: {_limpar_html(p.get('short_description', '')) or '(vazia)'}\n"
        f"- URL: {p.get('permalink')}"
    )


@mcp.tool()
def atualizar_produto_wc(produto_id: int, nome: str = "", preco: str = "", estoque: int = -1,
                         descricao_curta: str = "", sku: str = "") -> str:
    """Atualiza campos de um produto WooCommerce. Deixe em branco os campos que não quer alterar."""
    dados = {}
    if nome:            dados["name"] = nome
    if preco:           dados["regular_price"] = preco
    if estoque >= 0:    dados["stock_quantity"] = estoque
    if descricao_curta: dados["short_description"] = descricao_curta
    if sku:             dados["sku"] = sku
    if not dados:
        return "Nenhum campo informado para atualizar."
    p = _wc_put(f"products/{produto_id}", dados)
    return f"✓ Produto #{p['id']} atualizado: {p['name']}"


@mcp.tool()
def listar_variacoes(produto_id: int) -> str:
    """Lista todas as variações de um produto variável com seus IDs, SKUs, atributos e preços."""
    variacoes = _wc_get_all(f"products/{produto_id}/variations")
    if not variacoes:
        return f"Nenhuma variação encontrada para o produto #{produto_id}."
    linhas = [
        f"- [var#{v['id']}] SKU: {v.get('sku') or 'sem SKU'} | "
        f"{', '.join(a['option'] for a in v.get('attributes', []))} | "
        f"R$ {v.get('regular_price') or v.get('price') or '-'} | "
        f"Estoque: {v.get('stock_quantity', '?')}"
        for v in variacoes
    ]
    return f"**{len(variacoes)} variação(ões) do produto #{produto_id}:**\n" + "\n".join(linhas)


@mcp.tool()
def atualizar_variacao(produto_id: int, variacao_id: int, sku: str = "", preco: str = "", estoque: int = -1) -> str:
    """Atualiza SKU, preço e/ou estoque de uma variação específica de um produto variável."""
    dados = {}
    if sku:          dados["sku"] = sku
    if preco:        dados["regular_price"] = preco
    if estoque >= 0: dados["stock_quantity"] = estoque
    if not dados:
        return "Nenhum campo informado para atualizar."
    v = _wc_put(f"products/{produto_id}/variations/{variacao_id}", dados)
    atribs = ", ".join(a["option"] for a in v.get("attributes", []))
    return f"✓ Variação #{v['id']} ({atribs}) do produto #{produto_id} atualizada | SKU: {v.get('sku') or 'sem SKU'}"


@mcp.tool()
def criar_pedido_wc(nome: str, email: str, produto_id: int, quantidade: int = 1,
                    variacao_id: int = 0, telefone: str = "", observacao: str = "") -> str:
    """Cria um pedido no WooCommerce simulando uma compra de cliente."""
    partes = nome.strip().split(" ", 1)
    line_item = {"product_id": produto_id, "quantity": quantidade}
    if variacao_id > 0:
        line_item["variation_id"] = variacao_id
    dados = {
        "payment_method": "bacs",
        "payment_method_title": "Transferência Bancária",
        "set_paid": False,
        "status": "pending",
        "billing": {
            "first_name": partes[0],
            "last_name": partes[1] if len(partes) > 1 else "",
            "email": email,
            "phone": telefone,
            "address_1": "Endereço de Teste",
            "city": "São Paulo",
            "state": "SP",
            "postcode": "01310-100",
            "country": "BR",
        },
        "line_items": [line_item],
        "customer_note": observacao,
    }
    p = _wc_post("orders", dados)
    return f"✓ Pedido #{p['id']} criado | Status: {p['status']} | Total: R$ {p['total']} | Cliente: {nome} <{email}>"


@mcp.tool()
def listar_pedidos_wc(status: str = "any") -> str:
    """Lista pedidos WooCommerce. Status: any, pending, processing, completed, cancelled, refunded."""
    params = {} if status == "any" else {"status": status}
    pedidos = _wc_get_all("orders", params)
    if not pedidos:
        return "Nenhum pedido encontrado."
    linhas = [
        f"- [#{p['id']}] {p['date_created'][:10]} | {p.get('billing', {}).get('first_name', '')} {p.get('billing', {}).get('last_name', '')} | R$ {p['total']} | {p['status']}"
        for p in pedidos
    ]
    return f"**{len(pedidos)} pedido(s):**\n" + "\n".join(linhas)


@mcp.tool()
def buscar_pedido_wc(pedido_id: int) -> str:
    """Retorna detalhes completos de um pedido WooCommerce pelo ID."""
    p = _wc_get(f"orders/{pedido_id}")
    itens = "\n".join(f"  - {i['name']} x{i['quantity']} = R$ {i['total']}" for i in p.get("line_items", []))
    return (
        f"**Pedido #{p['id']}** — {p['status']}\n"
        f"- Data: {p['date_created'][:10]}\n"
        f"- Cliente: {p['billing'].get('first_name')} {p['billing'].get('last_name')} | {p['billing'].get('email')}\n"
        f"- Total: R$ {p['total']} (frete: R$ {p.get('shipping_total', '0')})\n"
        f"- Itens:\n{itens}"
    )


@mcp.tool()
def atualizar_status_pedido_wc(pedido_id: int, status: str) -> str:
    """Atualiza o status de um pedido WooCommerce. Status válidos: pending, processing, on-hold, completed, cancelled, refunded."""
    p = _wc_put(f"orders/{pedido_id}", {"status": status})
    return f"✓ Pedido #{p['id']} → status: {p['status']}"


@mcp.tool()
def relatorio_vendas_wc() -> str:
    """Retorna resumo de vendas WooCommerce: total de pedidos, receita e produtos mais vendidos."""
    pedidos = _wc_get_all("orders", {"status": "completed"})
    total = sum(float(p["total"]) for p in pedidos)
    contagem: dict[str, int] = {}
    for p in pedidos:
        for item in p.get("line_items", []):
            contagem[item["name"]] = contagem.get(item["name"], 0) + item["quantity"]
    top = sorted(contagem.items(), key=lambda x: -x[1])[:5]
    top_str = "\n".join(f"  {i+1}. {nome} ({qtd}x)" for i, (nome, qtd) in enumerate(top))
    return (
        f"**Resumo de Vendas (pedidos concluídos)**\n"
        f"- Total de pedidos: {len(pedidos)}\n"
        f"- Receita total: R$ {total:.2f}\n"
        f"- Ticket médio: R$ {(total/len(pedidos) if pedidos else 0):.2f}\n\n"
        f"**Top produtos:**\n{top_str or 'Sem dados'}"
    )


@mcp.tool()
def listar_clientes_wc(busca: str = "") -> str:
    """Lista clientes WooCommerce. Use busca para filtrar por nome ou email."""
    params = {"search": busca} if busca else {}
    clientes = _wc_get_all("customers", params)
    if not clientes:
        return "Nenhum cliente encontrado."
    linhas = [
        f"- [#{c['id']}] {c['first_name']} {c['last_name']} | {c['email']} | {c.get('billing', {}).get('phone', '-')}"
        for c in clientes
    ]
    return f"**{len(clientes)} cliente(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_paginas_wp() -> str:
    """Lista todas as páginas do WordPress."""
    paginas = _wp_get("wp/v2/pages", {"per_page": 100})
    if not paginas:
        return "Nenhuma página encontrada."
    linhas = [f"- [#{p['id']}] {p['title']['rendered']} | {p['status']} | {p['link']}" for p in paginas]
    return f"**{len(paginas)} página(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_plugins_wp() -> str:
    """Lista todos os plugins instalados no WordPress e seus status."""
    plugins = _wp_get("wp/v2/plugins", {"per_page": 100})
    if not plugins:
        return "Nenhum plugin encontrado."
    ativos   = [p for p in plugins if p.get("status") == "active"]
    inativos = [p for p in plugins if p.get("status") != "active"]
    linhas = (
        [f"- ✓ {p['name']} v{p.get('version', '?')}" for p in ativos] +
        [f"- ✗ {p['name']} v{p.get('version', '?')} (inativo)" for p in inativos]
    )
    return f"**{len(plugins)} plugin(s) — {len(ativos)} ativo(s):**\n" + "\n".join(linhas)


@mcp.tool()
def criar_redirect_wp(url_antiga: str, url_nova: str) -> str:
    """Cria um redirecionamento 301 via plugin Redirection."""
    _wp_post("redirection/v1/redirect", {
        "url": url_antiga,
        "action_type": "url",
        "action_data": {"url": url_nova},
        "match_type": "url",
        "group_id": 1,
        "code": 301,
    })
    return f"✓ Redirect criado: {url_antiga} → {url_nova}"


@mcp.tool()
def listar_redirects_wp() -> str:
    """Lista todos os redirecionamentos cadastrados no plugin Redirection."""
    data = _wp_get("redirection/v1/redirect", {"per_page": 100})
    items = data.get("items", []) if isinstance(data, dict) else []
    if not items:
        return "Nenhum redirecionamento encontrado."
    linhas = [f"- [{r['id']}] {r['url']} → {r.get('action_data', {}).get('url', '?')} ({r.get('action_code', '?')})" for r in items]
    return f"**{len(items)} redirect(s):**\n" + "\n".join(linhas)


# ── Health check ─────────────────────────────────────────────────────────────

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> HTMLResponse:
    return HTMLResponse("ViennaPet MCP OK", status_code=200)


@mcp.custom_route("/version", methods=["GET"])
async def version(request: Request) -> HTMLResponse:
    return HTMLResponse("v7 - debug return in consultar_estoque", status_code=200)


# ── Bling OAuth Routes ────────────────────────────────────────────────────────

@mcp.custom_route("/bling/auth", methods=["GET"])
async def bling_auth_route(request: Request) -> RedirectResponse:
    state = secrets.token_urlsafe(16)
    _bling_pending_state[state] = "pending"
    auth_url = (
        f"https://www.bling.com.br/Api/v3/oauth/authorize"
        f"?response_type=code&client_id={BLING_CLIENT_ID}"
        f"&redirect_uri={BLING_REDIRECT_URI}&state={state}"
    )
    return RedirectResponse(auth_url)


@mcp.custom_route("/bling/callback", methods=["GET"])
async def bling_callback_route(request: Request) -> HTMLResponse:
    code  = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code:
        return HTMLResponse("<h2>Erro: código de autorização não recebido.</h2>", status_code=400)
    if state and state not in _bling_pending_state:
        return HTMLResponse("<h2>Erro: estado inválido (possível CSRF).</h2>", status_code=400)
    if state:
        del _bling_pending_state[state]

    def _exchange():
        resp = requests.post(
            f"{BLING_BASE_URL}/oauth/token",
            headers={"Authorization": _bling_credentials_header(), "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": BLING_REDIRECT_URI},
        )
        resp.raise_for_status()
        return resp.json()

    tokens = await anyio.to_thread.run_sync(_exchange)
    _bling_save_tokens(tokens)
    refresh = tokens.get("refresh_token", "")
    access  = tokens.get("access_token", "")
    html = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:40px auto;padding:20px">
<h2 style="color:green">Bling! conectado com sucesso!</h2>
<p>Salve o <strong>Refresh Token</strong> abaixo como variável <code>BLING_REFRESH_TOKEN</code> no Railway
para que o servidor se autentique automaticamente após restarts:</p>
<textarea rows="4" style="width:100%;font-family:monospace;font-size:12px" onclick="this.select()">{refresh}</textarea>
<p style="color:#888;font-size:13px">Access Token (expira em breve — não precisa salvar):<br>
<code style="font-size:11px;word-break:break-all">{access}</code></p>
<p>Pode fechar esta aba.</p>
</body></html>"""
    return HTMLResponse(html)


# ── Bling Tools ───────────────────────────────────────────────────────────────

@mcp.tool()
def autenticar_bling() -> str:
    """Inicia o fluxo OAuth com o Bling! e salva os tokens localmente."""
    if not BLING_CLIENT_ID or not BLING_CLIENT_SECRET:
        return "Configure as variáveis BLING_CLIENT_ID e BLING_CLIENT_SECRET antes de autenticar."
    state = secrets.token_urlsafe(16)
    _bling_pending_state[state] = "pending"
    auth_url = (
        f"https://www.bling.com.br/Api/v3/oauth/authorize"
        f"?response_type=code&client_id={BLING_CLIENT_ID}"
        f"&redirect_uri={BLING_REDIRECT_URI}&state={state}"
    )
    return (
        f"Abra esta URL no browser para autenticar com o Bling!:\n\n{auth_url}\n\n"
        f"Após autorizar, você será redirecionado para {BLING_REDIRECT_URI} automaticamente."
    )


@mcp.tool()
def listar_produtos_bling(nome: str = "", pagina: int = 1, limite: int = 100) -> str:
    """Lista produtos do Bling!. Filtra por nome se informado."""
    params: dict = {"pagina": pagina, "limite": limite}
    if nome:
        params["nome"] = nome
    produtos = _bling_get("/produtos", params).get("data", [])
    if not produtos:
        return "Nenhum produto encontrado."
    linhas = [
        f"- [{p['id']}] {p['nome']} | Código: {p.get('codigo') or '-'} | Preço: R$ {p.get('preco', 0):.2f}"
        for p in produtos
    ]
    return f"**{len(produtos)} produto(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_contatos_bling(nome: str = "", pagina: int = 1, limite: int = 100) -> str:
    """Lista contatos (clientes/fornecedores) do Bling!. Filtra por nome se informado."""
    params: dict = {"pagina": pagina, "limite": limite}
    if nome:
        params["nome"] = nome
    contatos = _bling_get("/contatos", params).get("data", [])
    if not contatos:
        return "Nenhum contato encontrado."
    linhas = [
        f"- [{c['id']}] {c['nome']} | {c.get('email') or '-'} | {c.get('telefone') or '-'}"
        for c in contatos
    ]
    return f"**{len(contatos)} contato(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_pedidos_venda_bling(pagina: int = 1, limite: int = 100, situacao: int = 0) -> str:
    """
    Lista pedidos de venda do Bling!.
    situacao: 0=todos, 6=em aberto, 9=atendido, 12=cancelado
    """
    params: dict = {"pagina": pagina, "limite": limite}
    if situacao:
        params["idSituacao"] = situacao
    pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
    if not pedidos:
        return "Nenhum pedido encontrado."
    linhas = [
        f"- [{p['id']}] {p.get('data', '-')} | {p.get('contato', {}).get('nome', '?')} | "
        f"R$ {p.get('totalProdutos', 0):.2f} | {p.get('situacao', {}).get('nome', '-')}"
        for p in pedidos
    ]
    return f"**{len(pedidos)} pedido(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def consultar_estoque_bling(id_produto: int) -> str:
    """Consulta o saldo de estoque de um produto pelo seu ID."""
    return f"[DEBUG-v7] URL que seria chamada: {BLING_BASE_URL}/estoques/saldos?idsProdutos[]={id_produto}"
    token = _bling_get_token()
    # Endpoint correto: /estoques/saldos com idsProdutos[] como query param literal
    url = f"{BLING_BASE_URL}/estoques/saldos?idsProdutos[]={id_produto}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 401:
        token = _bling_refresh_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    items = resp.json().get("data", [])
    if not items:
        return f"Produto {id_produto} não encontrado no estoque."
    saldo_fisico  = sum(i.get("saldoFisicoTotal",  i.get("saldoFisico",  0)) for i in items)
    saldo_virtual = sum(i.get("saldoVirtualTotal", i.get("saldoVirtual", 0)) for i in items)
    depositos = [
        f"  - {i.get('deposito', {}).get('descricao', 'Geral')}: "
        f"{i.get('saldoFisicoTotal', i.get('saldoFisico', 0))} unid."
        for i in items
    ]
    return (
        f"**Estoque do produto {id_produto}:**\n"
        f"- Saldo físico total: {saldo_fisico}\n"
        f"- Saldo virtual total: {saldo_virtual}\n"
        f"- Por depósito:\n" + "\n".join(depositos)
    )


@mcp.tool()
def atualizar_produto_bling(id_produto: int, preco: float = 0.0, nome: str = "", codigo: str = "") -> str:
    """Atualiza preço, nome e/ou código de um produto no Bling! pelo seu ID."""
    if not preco and not nome and not codigo:
        return "Nenhum campo informado para atualizar."
    # GET atual para montar o body completo que a API exige no PUT
    produto = _bling_get(f"/produtos/{id_produto}").get("data", {})
    if not produto:
        return f"Produto {id_produto} não encontrado."
    if preco > 0:
        produto["preco"] = preco
    if nome:
        produto["nome"] = nome
    if codigo:
        produto["codigo"] = codigo
    _bling_put(f"/produtos/{id_produto}", produto)
    partes = []
    if preco > 0: partes.append(f"preço=R$ {preco:.2f}")
    if nome:      partes.append(f"nome={nome}")
    if codigo:    partes.append(f"código={codigo}")
    return f"✓ Produto [{id_produto}] atualizado | {' | '.join(partes)}"


@mcp.tool()
def criar_pedido_venda_bling(id_contato: int, itens: list, numero_pedido_externo: str = "", observacoes: str = "") -> str:
    """
    Cria um pedido de venda no Bling!.
    itens: lista de dicts com {id_produto_bling, descricao, quantidade, valor}
    Use id_produto_bling para referenciar produtos já cadastrados no Bling.
    """
    bling_itens = []
    for item in itens:
        i: dict = {
            "quantidade": item.get("quantidade", 1),
            "valor":      item.get("valor", 0),
            "tipo":       item.get("tipo", "P"),
            "unidade":    item.get("unidade", "UN"),
        }
        if item.get("id_produto_bling"):
            i["produto"] = {"id": item["id_produto_bling"]}
        else:
            i["descricao"] = item.get("descricao", "")
        bling_itens.append(i)
    body: dict = {
        "contato": {"id": id_contato},
        "data":    date.today().isoformat(),
        "itens":   bling_itens,
    }
    if numero_pedido_externo:
        body["numeroPedidoCompra"] = numero_pedido_externo
    if observacoes:
        body["observacoes"] = observacoes
    pedido = _bling_post("/pedidos/vendas", body).get("data", {})
    return (
        f"✓ Pedido de venda #{pedido.get('id', '?')} criado no Bling! | "
        f"Referência WooCommerce: {numero_pedido_externo or '-'}"
    )


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="sse")
