import base64
import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests
from mcp.server.fastmcp import FastMCP

CLIENT_ID = os.environ.get("BLING_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("BLING_CLIENT_SECRET", "")
REDIRECT_URI = "http://localhost:8080/callback"
BASE_URL = "https://www.bling.com.br/Api/v3"
TOKEN_FILE = Path.home() / ".bling" / "tokens.json"

mcp = FastMCP("Bling!")


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _credentials_header() -> str:
    raw = f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _save_tokens(data: dict) -> None:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(data))


def _load_tokens() -> dict | None:
    if TOKEN_FILE.exists():
        return json.loads(TOKEN_FILE.read_text())
    return None


def _refresh_access_token() -> str:
    tokens = _load_tokens()
    if not tokens:
        raise RuntimeError("Não autenticado. Use a ferramenta `autenticar` primeiro.")

    resp = requests.post(
        f"{BASE_URL}/oauth/token",
        headers={
            "Authorization": _credentials_header(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
    )
    resp.raise_for_status()
    new_tokens = resp.json()
    _save_tokens(new_tokens)
    return new_tokens["access_token"]


def _get_access_token() -> str:
    tokens = _load_tokens()
    if not tokens:
        raise RuntimeError("Não autenticado. Use a ferramenta `autenticar` primeiro.")
    return tokens["access_token"]


def _bling_get(path: str, params: dict | None = None) -> dict:
    token = _get_access_token()
    resp = requests.get(
        f"{BASE_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        params=params or {},
    )
    if resp.status_code == 401:
        token = _refresh_access_token()
        resp = requests.get(
            f"{BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
    resp.raise_for_status()
    return resp.json()


def _bling_post(path: str, body: dict) -> dict:
    token = _get_access_token()
    resp = requests.post(
        f"{BASE_URL}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
    )
    if resp.status_code == 401:
        token = _refresh_access_token()
        resp = requests.post(
            f"{BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        )
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


def _bling_put(path: str, body: dict) -> dict:
    token = _get_access_token()
    resp = requests.put(
        f"{BASE_URL}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
    )
    if resp.status_code == 401:
        token = _refresh_access_token()
        resp = requests.put(
            f"{BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        )
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


# ── OAuth callback server ─────────────────────────────────────────────────────

_auth_code: str | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global _auth_code
        parsed = urlparse(self.path)
        if parsed.path == "/callback":
            qs = parse_qs(parsed.query)
            _auth_code = qs.get("code", [None])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<h2>Bling! conectado! Pode fechar esta aba.</h2>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # silencia logs do servidor HTTP


# ── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def autenticar() -> str:
    """Inicia o fluxo OAuth com o Bling! e salva os tokens localmente."""
    global _auth_code
    _auth_code = None

    if not CLIENT_ID or not CLIENT_SECRET:
        return (
            "Configure as variáveis de ambiente BLING_CLIENT_ID e BLING_CLIENT_SECRET "
            "antes de autenticar."
        )

    auth_url = (
        f"https://www.bling.com.br/Api/v3/oauth/authorize"
        f"?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state=mcp"
    )

    server = HTTPServer(("localhost", 8080), _CallbackHandler)
    server.timeout = 120

    webbrowser.open(auth_url)

    # Aguarda o callback por até 2 minutos
    while _auth_code is None:
        server.handle_request()

    server.server_close()

    resp = requests.post(
        f"{BASE_URL}/oauth/token",
        headers={
            "Authorization": _credentials_header(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "authorization_code",
            "code": _auth_code,
            "redirect_uri": REDIRECT_URI,
        },
    )
    resp.raise_for_status()
    _save_tokens(resp.json())
    return "Autenticado com sucesso! Tokens salvos em ~/.bling/tokens.json"


@mcp.tool()
def listar_produtos(nome: str = "", pagina: int = 1, limite: int = 100) -> str:
    """Lista produtos do Bling!. Filtra por nome se informado."""
    params = {"pagina": pagina, "limite": limite}
    if nome:
        params["nome"] = nome
    data = _bling_get("/produtos", params)
    produtos = data.get("data", [])
    if not produtos:
        return "Nenhum produto encontrado."
    linhas = [f"- [{p['id']}] {p['nome']} | Código: {p.get('codigo', '-')} | Preço: R$ {p.get('preco', 0):.2f}" for p in produtos]
    return f"**{len(produtos)} produto(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_pedidos_venda(pagina: int = 1, limite: int = 100, situacao: int = 0) -> str:
    """
    Lista pedidos de venda do Bling!.
    situacao: 0=todos, 6=em aberto, 9=atendido, 12=cancelado
    """
    params = {"pagina": pagina, "limite": limite}
    if situacao:
        params["idSituacao"] = situacao
    data = _bling_get("/pedidos/vendas", params)
    pedidos = data.get("data", [])
    if not pedidos:
        return "Nenhum pedido encontrado."
    linhas = [
        f"- [{p['id']}] {p.get('data', '-')} | {p.get('contato', {}).get('nome', '?')} | R$ {p.get('totalProdutos', 0):.2f} | {p.get('situacao', {}).get('nome', '-')}"
        for p in pedidos
    ]
    return f"**{len(pedidos)} pedido(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_contatos(nome: str = "", pagina: int = 1, limite: int = 100) -> str:
    """Lista contatos (clientes/fornecedores) do Bling!. Filtra por nome se informado."""
    params = {"pagina": pagina, "limite": limite}
    if nome:
        params["nome"] = nome
    data = _bling_get("/contatos", params)
    contatos = data.get("data", [])
    if not contatos:
        return "Nenhum contato encontrado."
    linhas = [
        f"- [{c['id']}] {c['nome']} | {c.get('email', '-')} | {c.get('telefone', '-')}"
        for c in contatos
    ]
    return f"**{len(contatos)} contato(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def consultar_estoque(id_produto: int) -> str:
    """Consulta o saldo de estoque de um produto pelo seu ID."""
    token = _get_access_token()
    # Endpoint correto: /estoques/saldos — URL manual para preservar colchetes literais
    url = f"{BASE_URL}/estoques/saldos?idsProdutos[]={id_produto}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 401:
        token = _refresh_access_token()
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
def criar_pedido_venda(id_contato: int, itens: list, numero_pedido_externo: str = "", observacoes: str = "") -> str:
    """
    Cria um pedido de venda no Bling!.
    itens: lista de dicts com {id_produto_bling, descricao, quantidade, valor}
    Use id_produto_bling para referenciar produtos já cadastrados no Bling.
    """
    from datetime import date
    bling_itens = []
    for item in itens:
        i = {
            "quantidade": item.get("quantidade", 1),
            "valor": item.get("valor", 0),
            "tipo": item.get("tipo", "P"),
            "unidade": item.get("unidade", "UN"),
        }
        if item.get("id_produto_bling"):
            i["produto"] = {"id": item["id_produto_bling"]}
        else:
            i["descricao"] = item.get("descricao", "")
        bling_itens.append(i)

    body = {
        "contato": {"id": id_contato},
        "data": date.today().isoformat(),
        "itens": bling_itens,
    }
    if numero_pedido_externo:
        body["numeroPedidoCompra"] = numero_pedido_externo
    if observacoes:
        body["observacoes"] = observacoes
    data = _bling_post("/pedidos/vendas", body)
    pedido = data.get("data", {})
    return (
        f"✓ Pedido de venda #{pedido.get('id', '?')} criado no Bling! | "
        f"Referência WooCommerce: {numero_pedido_externo or '-'}"
    )


@mcp.tool()
def atualizar_produto(id_produto: int, preco: float = 0.0, nome: str = "", codigo: str = "") -> str:
    """Atualiza preço, nome e/ou código de um produto no Bling! pelo seu ID."""
    data = _bling_get(f"/produtos/{id_produto}")
    produto = data.get("data", {})
    if not produto:
        return f"Produto {id_produto} não encontrado no Bling!."

    # Produto variável: busca dados completos incluindo variacoes via endpoint específico.
    if produto.get("formato") == "V":
        var_data = _bling_get(f"/produtos/variacoes/{id_produto}")
        produto_completo = var_data.get("data", {})
        variacoes = produto_completo.get("variacoes", [])
        if not variacoes:
            return (
                f"Produto [{id_produto}] é variável (formato=V) mas não possui variações "
                f"cadastradas inline — atualize o preço diretamente em cada variação no Bling ou "
                f"use o ID de uma variação específica em vez do produto pai."
            )
        produto = produto_completo

    if preco > 0:
        produto["preco"] = preco
    if nome:
        produto["nome"] = nome
    if codigo:
        produto["codigo"] = codigo

    _bling_put(f"/produtos/{id_produto}", produto)
    novo_preco = produto.get("preco", 0)
    return f"✓ Produto [{id_produto}] {produto.get('nome', '')} atualizado | Preço: R$ {novo_preco:.2f}"


if __name__ == "__main__":
    mcp.run()
