import os
import re

import requests
from mcp.server.fastmcp import FastMCP

WC_URL            = os.environ.get("WC_URL", "").rstrip("/")
WC_CONSUMER_KEY   = os.environ.get("WC_CONSUMER_KEY", "")
WC_CONSUMER_SECRET = os.environ.get("WC_CONSUMER_SECRET", "")
WP_USER           = os.environ.get("WP_USER", "")
WP_PASS           = os.environ.get("WP_PASS", "")

mcp = FastMCP("WooCommerce")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wc_auth():
    return (WC_CONSUMER_KEY, WC_CONSUMER_SECRET)

def _wp_auth():
    return (WP_USER, WP_PASS)

def _get(endpoint: str, params: dict | None = None) -> dict | list:
    resp = requests.get(f"{WC_URL}/wp-json/wc/v3/{endpoint}", auth=_wc_auth(), params=params or {}, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _put(endpoint: str, data: dict) -> dict:
    resp = requests.put(f"{WC_URL}/wp-json/wc/v3/{endpoint}", auth=_wc_auth(), json=data, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _post(endpoint: str, data: dict) -> dict:
    resp = requests.post(f"{WC_URL}/wp-json/wc/v3/{endpoint}", auth=_wc_auth(), json=data, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _get_all(endpoint: str, params: dict | None = None) -> list:
    params = params or {}
    params.setdefault("per_page", 100)
    results, page = [], 1
    while True:
        params["page"] = page
        batch = _get(endpoint, params)
        if not batch:
            break
        results.extend(batch)
        if len(batch) < params["per_page"]:
            break
        page += 1
    return results

def _limpar_html(texto: str) -> str:
    return re.sub(r"<[^>]+>", "", texto or "").strip()


# ── Produtos ──────────────────────────────────────────────────────────────────

@mcp.tool()
def listar_produtos(status: str = "publish") -> str:
    """Lista todos os produtos da loja WooCommerce."""
    produtos = _get_all("products", {"status": status})
    if not produtos:
        return "Nenhum produto encontrado."
    linhas = [
        f"- [#{p['id']}] {p['name']} | R$ {p['price']} | Estoque: {p.get('stock_quantity', '?')} | SKU: {p.get('sku') or 'sem SKU'}"
        for p in produtos
    ]
    return f"**{len(produtos)} produto(s):**\n" + "\n".join(linhas)


@mcp.tool()
def buscar_produto(produto_id: int) -> str:
    """Retorna todos os detalhes de um produto pelo ID."""
    p = _get(f"products/{produto_id}")
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
def atualizar_produto(produto_id: int, nome: str = "", preco: str = "", estoque: int = -1,
                      descricao_curta: str = "", sku: str = "") -> str:
    """Atualiza campos de um produto. Deixe em branco os campos que não quer alterar."""
    dados = {}
    if nome:            dados["name"] = nome
    if preco:           dados["regular_price"] = preco
    if estoque >= 0:    dados["stock_quantity"] = estoque
    if descricao_curta: dados["short_description"] = descricao_curta
    if sku:             dados["sku"] = sku
    if not dados:
        return "Nenhum campo informado para atualizar."
    p = _put(f"products/{produto_id}", dados)
    return f"✓ Produto #{p['id']} atualizado: {p['name']}"


@mcp.tool()
def criar_pedido(nome: str, email: str, produto_id: int, quantidade: int = 1,
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
    p = _post("orders", dados)
    return (
        f"✓ Pedido #{p['id']} criado | Status: {p['status']} | "
        f"Total: R$ {p['total']} | Cliente: {nome} <{email}>"
    )


@mcp.tool()
def listar_variacoes(produto_id: int) -> str:
    """Lista todas as variações de um produto variável com seus IDs, SKUs, atributos e preços."""
    variacoes = _get_all(f"products/{produto_id}/variations")
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
    v = _put(f"products/{produto_id}/variations/{variacao_id}", dados)
    atribs = ", ".join(a["option"] for a in v.get("attributes", []))
    return f"✓ Variação #{v['id']} ({atribs}) do produto #{produto_id} atualizada | SKU: {v.get('sku') or 'sem SKU'}"


# ── Pedidos ───────────────────────────────────────────────────────────────────

@mcp.tool()
def listar_pedidos(status: str = "any") -> str:
    """Lista pedidos. Status: any, pending, processing, completed, cancelled, refunded."""
    params = {} if status == "any" else {"status": status}
    pedidos = _get_all("orders", params)
    if not pedidos:
        return "Nenhum pedido encontrado."
    linhas = [
        f"- [#{p['id']}] {p['date_created'][:10]} | {p.get('billing', {}).get('first_name', '')} {p.get('billing', {}).get('last_name', '')} | R$ {p['total']} | {p['status']}"
        for p in pedidos
    ]
    return f"**{len(pedidos)} pedido(s):**\n" + "\n".join(linhas)


@mcp.tool()
def buscar_pedido(pedido_id: int) -> str:
    """Retorna detalhes completos de um pedido pelo ID."""
    p = _get(f"orders/{pedido_id}")
    itens = "\n".join(f"  - {i['name']} x{i['quantity']} = R$ {i['total']}" for i in p.get("line_items", []))
    return (
        f"**Pedido #{p['id']}** — {p['status']}\n"
        f"- Data: {p['date_created'][:10]}\n"
        f"- Cliente: {p['billing'].get('first_name')} {p['billing'].get('last_name')} | {p['billing'].get('email')}\n"
        f"- Total: R$ {p['total']} (frete: R$ {p.get('shipping_total', '0')})\n"
        f"- Itens:\n{itens}"
    )


@mcp.tool()
def atualizar_status_pedido(pedido_id: int, status: str) -> str:
    """Atualiza o status de um pedido. Status válidos: pending, processing, on-hold, completed, cancelled, refunded."""
    p = _put(f"orders/{pedido_id}", {"status": status})
    return f"✓ Pedido #{p['id']} → status: {p['status']}"


# ── Clientes ──────────────────────────────────────────────────────────────────

@mcp.tool()
def listar_clientes(busca: str = "") -> str:
    """Lista clientes cadastrados. Use busca para filtrar por nome ou email."""
    params = {"search": busca} if busca else {}
    clientes = _get_all("customers", params)
    if not clientes:
        return "Nenhum cliente encontrado."
    linhas = [
        f"- [#{c['id']}] {c['first_name']} {c['last_name']} | {c['email']} | {c.get('billing', {}).get('phone', '-')}"
        for c in clientes
    ]
    return f"**{len(clientes)} cliente(s):**\n" + "\n".join(linhas)


# ── Relatórios ────────────────────────────────────────────────────────────────

@mcp.tool()
def relatorio_vendas() -> str:
    """Retorna resumo de vendas: total de pedidos, receita e produtos mais vendidos."""
    pedidos = _get_all("orders", {"status": "completed"})
    total = sum(float(p["total"]) for p in pedidos)
    contagem_produtos: dict[str, int] = {}
    for p in pedidos:
        for item in p.get("line_items", []):
            contagem_produtos[item["name"]] = contagem_produtos.get(item["name"], 0) + item["quantity"]
    top = sorted(contagem_produtos.items(), key=lambda x: -x[1])[:5]
    top_str = "\n".join(f"  {i+1}. {nome} ({qtd}x)" for i, (nome, qtd) in enumerate(top))
    return (
        f"**Resumo de Vendas (pedidos concluídos)**\n"
        f"- Total de pedidos: {len(pedidos)}\n"
        f"- Receita total: R$ {total:.2f}\n"
        f"- Ticket médio: R$ {(total/len(pedidos)):.2f}\n\n"
        f"**Top produtos:**\n{top_str or 'Sem dados'}"
    )


# ── WordPress ─────────────────────────────────────────────────────────────────

def _wp_get(endpoint: str, params: dict | None = None) -> dict | list:
    resp = requests.get(f"{WC_URL}/wp-json/{endpoint}", auth=_wp_auth(), params=params or {}, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _wp_post(endpoint: str, data: dict) -> dict:
    resp = requests.post(f"{WC_URL}/wp-json/{endpoint}", auth=_wp_auth(), json=data, timeout=30)
    resp.raise_for_status()
    return resp.json()


@mcp.tool()
def listar_paginas() -> str:
    """Lista todas as páginas do WordPress."""
    paginas = _wp_get("wp/v2/pages", {"per_page": 100})
    if not paginas:
        return "Nenhuma página encontrada."
    linhas = [f"- [#{p['id']}] {p['title']['rendered']} | {p['status']} | {p['link']}" for p in paginas]
    return f"**{len(paginas)} página(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_plugins() -> str:
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
def criar_redirect(url_antiga: str, url_nova: str) -> str:
    """Cria um redirecionamento 301 via plugin Redirection."""
    resultado = _wp_post("redirection/v1/redirect", {
        "url": url_antiga,
        "action_type": "url",
        "action_data": {"url": url_nova},
        "match_type": "url",
        "group_id": 1,
        "code": 301,
    })
    return f"✓ Redirect criado: {url_antiga} → {url_nova}"


@mcp.tool()
def listar_redirects() -> str:
    """Lista todos os redirecionamentos cadastrados no plugin Redirection."""
    data = _wp_get("redirection/v1/redirect", {"per_page": 100})
    items = data.get("items", []) if isinstance(data, dict) else []
    if not items:
        return "Nenhum redirecionamento encontrado."
    linhas = [f"- [{r['id']}] {r['url']} → {r.get('action_data', {}).get('url', '?')} ({r.get('action_code', '?')})" for r in items]
    return f"**{len(items)} redirect(s):**\n" + "\n".join(linhas)


if __name__ == "__main__":
    mcp.run()
