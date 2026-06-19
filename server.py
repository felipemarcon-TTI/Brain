import base64
import contextvars
import json
import os
import re
import secrets
import threading
from datetime import date
from pathlib import Path

import anyio
import requests
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

# ── Config ────────────────────────────────────────────────────────────────────

WC_URL             = os.environ.get("WC_URL", "").rstrip("/")
WC_CONSUMER_KEY    = os.environ.get("WC_CONSUMER_KEY", "")
WC_CONSUMER_SECRET = os.environ.get("WC_CONSUMER_SECRET", "")
WP_USER            = os.environ.get("WP_USER", "")
WP_PASS            = os.environ.get("WP_PASS", "")

BLING_CLIENT_ID     = os.environ.get("BLING_CLIENT_ID", "")
BLING_CLIENT_SECRET = os.environ.get("BLING_CLIENT_SECRET", "")
BLING_BASE_URL      = "https://www.bling.com.br/Api/v3"
# Caminho configurável: aponte para um volume persistente do Railway (ex.: /data/bling-tokens.json)
# para que os tokens rotacionados sobrevivam a restarts/redeploys sem reautenticação manual.
BLING_TOKEN_FILE    = Path(os.environ.get("BLING_TOKEN_PATH", str(Path.home() / ".bling" / "tokens.json")))

_PORT          = int(os.environ.get("PORT", 8000))
_PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
_BASE_URL      = f"https://{_PUBLIC_DOMAIN}" if _PUBLIC_DOMAIN else f"http://localhost:{_PORT}"
BLING_REDIRECT_URI = os.environ.get("BLING_REDIRECT_URI", f"{_BASE_URL}/bling/callback")
MCP_AUTH_TOKEN      = "".join(os.environ.get("MCP_AUTH_TOKEN", "").split())
MCP_OAUTH_CLIENT_ID = os.environ.get("MCP_OAUTH_CLIENT_ID", "")

# ── Multi-user auth ───────────────────────────────────────────────────────────

_current_user: contextvars.ContextVar[dict | None] = contextvars.ContextVar("current_user", default=None)


def _load_users() -> tuple[dict, dict]:
    by_token: dict[str, dict] = {}
    by_id:    dict[str, dict] = {}
    if MCP_AUTH_TOKEN:
        admin = {"id": "admin", "role": "write", "token": MCP_AUTH_TOKEN}
        by_token[MCP_AUTH_TOKEN] = admin
        by_id["admin"] = admin
    raw = os.environ.get("MCP_USERS", "[]")
    try:
        for u in json.loads(raw):
            token = "".join(u.get("token", "").split())
            uid   = u.get("id", "")
            role  = u.get("role", "read")
            if token and uid:
                user = {"id": uid, "role": role, "token": token}
                by_token[token] = user
                by_id[uid]      = user
    except Exception:
        pass
    return by_token, by_id


_users_by_token, _users_by_id = _load_users()

# ── Auth middleware ───────────────────────────────────────────────────────────

_OPEN_PATHS = frozenset({
    "/", "/version", "/bling/callback", "/bling/persist-status", "/health/sistema",
    "/.well-known/oauth-authorization-server", "/oauth/authorize", "/oauth/token",
})

class _AuthMiddleware:
    """Exige Bearer token em todas as rotas exceto health checks e OAuth callback."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path", "")
            if path not in _OPEN_PATHS:
                headers = dict(scope.get("headers", []))
                auth = headers.get(b"authorization", b"").decode("latin-1")
                bearer = auth[7:] if auth.startswith("Bearer ") else ""

                # /bling/auth também aceita ?token= para abrir no browser
                if not bearer and path == "/bling/auth":
                    import urllib.parse
                    qs = scope.get("query_string", b"").decode()
                    bearer = dict(urllib.parse.parse_qsl(qs)).get("token", "")

                user = _users_by_token.get(bearer) if bearer else None
                if not user:
                    body = b'{"error":"Unauthorized"}'
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", b'Bearer realm="ViennaPet MCP"'),
                        ],
                    })
                    await send({"type": "http.response.body", "body": body, "more_body": False})
                    return
                scope["_user"] = user
                _current_user.set(user)
        await self.app(scope, receive, send)

mcp = FastMCP("ViennaPet MCP", host="0.0.0.0", port=_PORT)

_bling_pending_state: dict[str, str] = {}


def _require_write() -> None:
    user = _current_user.get()
    if not user or user.get("role") != "write":
        uid = user.get("id", "?") if user else "anon"
        raise PermissionError(f"Usuário '{uid}' tem acesso somente leitura.")


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


# ── Google Sheets (planilhas de Cupons e Afiliados) ───────────────────────────
# A planilha é o REGISTRO. A tool grava nela via Service Account (GOOGLE_SA_JSON).
# Compartilhe as 2 planilhas com o e-mail do service account (como Editor).

CUPONS_SHEET_ID    = os.environ.get("CUPONS_SHEET_ID", "1RBzTk8hG-bZCfOYnxFFuENifKaGEycMYBVCmLity2bw")
AFILIADOS_SHEET_ID = os.environ.get("AFILIADOS_SHEET_ID", "1XTRoCdnBjZ2ZZw6ixCuVuBDIOilTTrjW18-F8aDLHfM")

_CUPONS_HEADER    = ["Código do Cupom", "Data de Validade", "Desconto (%)", "@ Dono do Cupom", "Observação"]
_AFILIADOS_HEADER = ["@ da Pessoa", "URL do Link"]


def _gspread_ws(sheet_id: str, header: list[str]):
    """Abre a primeira aba da planilha e garante o cabeçalho. Requer GOOGLE_SA_JSON."""
    import gspread
    from google.oauth2.service_account import Credentials

    raw = os.environ.get("GOOGLE_SA_JSON", "")
    if not raw:
        raise RuntimeError("GOOGLE_SA_JSON não configurado no Railway (Service Account).")
    info = json.loads(raw)
    creds = Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    ws = gspread.authorize(creds).open_by_key(sheet_id).sheet1
    # Normaliza o cabeçalho (idempotente)
    first = ws.row_values(1)
    if [c.strip() for c in first][: len(header)] != header:
        ws.update(f"A1:{chr(64 + len(header))}1", [header])
    return ws


def _sheet_append_cupom(row: list) -> None:
    ws = _gspread_ws(CUPONS_SHEET_ID, _CUPONS_HEADER)
    ws.append_row([str(c) for c in row], value_input_option="USER_ENTERED")


def _sheet_append_afiliado(row: list) -> None:
    ws = _gspread_ws(AFILIADOS_SHEET_ID, _AFILIADOS_HEADER)
    ws.append_row([str(c) for c in row], value_input_option="USER_ENTERED")


def _sheet_revogar_cupom(codigo: str, nova_validade: str, observacao: str) -> bool:
    """Acha a linha do cupom (col A) e atualiza Validade (col B) e Observação (col E)."""
    ws = _gspread_ws(CUPONS_SHEET_ID, _CUPONS_HEADER)
    try:
        cell = ws.find(codigo)
    except Exception:
        cell = None
    if not cell:
        return False
    ws.update_cell(cell.row, 2, nova_validade)   # B = Validade
    ws.update_cell(cell.row, 5, observacao)       # E = Observação
    return True


# ── Bling helpers ─────────────────────────────────────────────────────────────

def _bling_credentials_header() -> str:
    raw = f"{BLING_CLIENT_ID}:{BLING_CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()

# Bling rotaciona o refresh_token a CADA refresh. A fonte de verdade é, em ordem:
#   1. cache em memória desta instância (tokens mais recentes)
#   2. arquivo persistido (sobrevive entre requests; entre restarts se em volume)
#   3. env var BLING_REFRESH_TOKEN — usada APENAS como bootstrap inicial
# A env var nunca tem prioridade sobre tokens já rotacionados, senão tentaríamos
# reusar um refresh_token que o Bling já invalidou (causa do erro 400).
_bling_lock = threading.Lock()
_bling_tokens_cache: dict | None = None
_last_persist_result: str = "ainda não tentou"

def _persist_refresh_token_to_railway(refresh_token: str) -> bool:
    """Persiste o refresh_token rotacionado na env var BLING_REFRESH_TOKEN do próprio
    serviço Railway (via API GraphQL). Como o disco do Railway é efêmero, isso garante
    que, após um restart/redeploy, o container faça bootstrap com o token mais recente —
    sem reautenticação manual e sem volume. variableUpsert NÃO dispara redeploy: o valor
    novo só é lido no próximo start, então não há loop de restart.

    Usa RAILWAY_* deste serviço (ViennaPet) — isolado do ExpansaoPet."""
    api_token      = os.environ.get("RAILWAY_API_TOKEN", "")
    project_id     = os.environ.get("RAILWAY_PROJECT_ID", "")
    environment_id = os.environ.get("RAILWAY_ENVIRONMENT_ID", "")
    service_id     = os.environ.get("RAILWAY_SERVICE_ID", "")
    global _last_persist_result
    missing = [k for k, v in {
        "RAILWAY_API_TOKEN": api_token, "RAILWAY_PROJECT_ID": project_id,
        "RAILWAY_ENVIRONMENT_ID": environment_id, "RAILWAY_SERVICE_ID": service_id,
    }.items() if not v]
    if missing or not refresh_token:
        _last_persist_result = f"ignorado - faltam vars: {missing}"
        print(f"[railway] persist ignorado - faltam vars: {missing}")
        return False
    query = "mutation variableUpsert($input: VariableUpsertInput!) { variableUpsert(input: $input) }"
    variables = {"input": {
        "projectId": project_id, "environmentId": environment_id, "serviceId": service_id,
        "name": "BLING_REFRESH_TOKEN", "value": refresh_token,
    }}
    try:
        resp = requests.post(
            "https://backboard.railway.app/graphql/v2",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            json={"query": query, "variables": variables},
            timeout=10,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            _last_persist_result = f"erro GraphQL: {str(body['errors'])[:200]}"
            print(f"[railway] variableUpsert errors: {body['errors']}")
            return False
        _last_persist_result = "OK"
        print("[railway] variableUpsert OK - BLING_REFRESH_TOKEN atualizado")
        return True
    except Exception as e:
        _last_persist_result = f"exception: {str(e)[:200]}"
        print(f"[railway] variableUpsert exception: {e}")
        return False

def _bling_save_tokens(data: dict) -> None:
    global _bling_tokens_cache
    _bling_tokens_cache = data
    try:
        BLING_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        BLING_TOKEN_FILE.write_text(json.dumps(data))
    except Exception as e:  # disco efêmero/sem permissão: o cache em memória ainda funciona
        print(f"[bling] aviso: não foi possível persistir tokens em disco: {e}")
    # Persiste na env var do Railway para sobreviver a restarts (sem volume)
    _persist_refresh_token_to_railway(data.get("refresh_token", ""))

def _bling_load_tokens() -> dict | None:
    global _bling_tokens_cache
    if _bling_tokens_cache:
        return _bling_tokens_cache
    if BLING_TOKEN_FILE.exists():
        try:
            _bling_tokens_cache = json.loads(BLING_TOKEN_FILE.read_text())
            return _bling_tokens_cache
        except Exception as e:
            print(f"[bling] aviso: arquivo de tokens corrompido: {e}")
    refresh = os.environ.get("BLING_REFRESH_TOKEN", "")
    if refresh:
        _bling_tokens_cache = {
            "access_token": os.environ.get("BLING_ACCESS_TOKEN", ""),
            "refresh_token": refresh,
        }
        return _bling_tokens_cache
    return None

def _bling_refresh_token(stale_access: str | None = None) -> str:
    """Renova o access_token. `stale_access` é o token que recebeu 401: se outra
    thread já renovou (token em cache mudou), reusamos em vez de consumir o
    refresh_token de novo (que o Bling invalidaria)."""
    with _bling_lock:
        tokens = _bling_load_tokens()
        if not tokens:
            raise RuntimeError("Não autenticado. Use a ferramenta `autenticar` primeiro.")
        # Outra thread já renovou enquanto esperávamos o lock
        if stale_access and tokens.get("access_token") and tokens["access_token"] != stale_access:
            return tokens["access_token"]
        resp = requests.post(
            f"{BLING_BASE_URL}/oauth/token",
            headers={"Authorization": _bling_credentials_header(), "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        )
        if not resp.ok:
            raise RuntimeError(
                f"Falha ao renovar token Bling ({resp.status_code}): {resp.text.strip()}. "
                "O refresh_token pode ter expirado — use `autenticar` novamente."
            )
        new_tokens = resp.json()
        # Garantia: se o Bling não devolver um refresh_token novo, preserva o atual
        if not new_tokens.get("refresh_token") and tokens.get("refresh_token"):
            new_tokens["refresh_token"] = tokens["refresh_token"]
        _bling_save_tokens(new_tokens)
        return new_tokens["access_token"]

def _bling_get_token() -> str:
    tokens = _bling_load_tokens()
    if not tokens:
        raise RuntimeError("Não autenticado. Use a ferramenta `autenticar` primeiro.")
    # Sem access_token (bootstrap só com refresh): força um refresh imediato
    if not tokens.get("access_token"):
        return _bling_refresh_token()
    return tokens["access_token"]

def _bling_get(path: str, params: dict | None = None) -> dict:
    token = _bling_get_token()
    resp = requests.get(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
    if resp.status_code == 401:
        token = _bling_refresh_token(stale_access=token)
        resp = requests.get(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
    resp.raise_for_status()
    return resp.json()

def _bling_put(path: str, body: dict) -> dict:
    token = _bling_get_token()
    resp = requests.put(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if resp.status_code == 401:
        token = _bling_refresh_token(stale_access=token)
        resp = requests.put(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}

def _bling_post(path: str, body: dict) -> dict:
    token = _bling_get_token()
    resp = requests.post(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if resp.status_code == 401:
        token = _bling_refresh_token(stale_access=token)
        resp = requests.post(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


def _bling_find_or_create_contact(email: str, nome: str, phone: str = "", cpf: str = "") -> int:
    """Encontra contato no Bling por email/nome ou cria um novo."""
    # Busca por email
    if email:
        try:
            data = _bling_get("/contatos", {"email": email})
            contacts = data.get("data", [])
            if contacts:
                return contacts[0]["id"]
        except Exception:
            pass
    # Busca por nome
    if nome:
        try:
            data = _bling_get("/contatos", {"nome": nome})
            contacts = data.get("data", [])
            for c in contacts:
                if not email or (c.get("email") or "").lower() == email.lower():
                    return c["id"]
        except Exception:
            pass
    # Cria novo contato
    body: dict = {"nome": nome or email, "tipoPessoa": "F", "indicadorIE": 9, "situacao": "A"}
    if email:
        body["email"] = email
    if phone:
        body["telefone"] = re.sub(r"\D", "", phone)[:20]
    if cpf:
        cpf_clean = re.sub(r"\D", "", cpf)
        if len(cpf_clean) == 11:
            body["cpf"] = cpf_clean
    result = _bling_post("/contatos", body)
    return result.get("data", {}).get("id")


def _bling_find_product_by_sku(sku: str) -> int | None:
    """Busca produto no Bling pelo código/SKU. Retorna o ID ou None."""
    if not sku:
        return None
    try:
        data = _bling_get("/produtos", {"codigo": sku})
        produtos = data.get("data", [])
        if produtos:
            return produtos[0]["id"]
    except Exception:
        pass
    return None


# ── Cupons & Afiliados (criam no WooCommerce + registram na planilha) ─────────

@mcp.tool()
def criar_cupom(codigo: str, data_validade: str, desconto_percentual: float, dono_arroba: str) -> str:
    """Cria um cupom de desconto no WooCommerce e registra na planilha de Cupons.
    TODOS os campos são obrigatórios.

    codigo: código do cupom (ex.: PRIMEIRA10)
    data_validade: data de expiração no formato AAAA-MM-DD (ex.: 2026-12-31)
    desconto_percentual: porcentagem de desconto (ex.: 10 para 10%)
    dono_arroba: @ da pessoa dona do cupom (ex.: @joao) — usado para creditar o afiliado
    """
    _require_write()
    codigo = (codigo or "").strip()
    data_validade = (data_validade or "").strip()
    dono_arroba = (dono_arroba or "").strip()
    if not codigo or not data_validade or not desconto_percentual or not dono_arroba:
        return "Erro: todos os campos são obrigatórios (codigo, data_validade, desconto_percentual, dono_arroba)."
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", data_validade):
        return "Erro: data_validade deve estar no formato AAAA-MM-DD."
    if not dono_arroba.startswith("@"):
        dono_arroba = "@" + dono_arroba

    # 1) cria no WooCommerce (token [afiliado:@x] na descrição credita o dono na venda)
    try:
        novo = _wc_post("coupons", {
            "code": codigo,
            "discount_type": "percent",
            "amount": str(desconto_percentual),
            "date_expires": data_validade,
            "description": f"[afiliado:{dono_arroba}]",
            "individual_use": False,
        })
    except Exception as e:
        return f"Erro ao criar cupom no WooCommerce: {e}"
    wc_id = novo.get("id")

    # 2) registra na planilha
    try:
        _sheet_append_cupom([codigo, data_validade, desconto_percentual, dono_arroba, ""])
        reg = "registrado na planilha"
    except Exception as e:
        reg = f"⚠️ criado no WC (#{wc_id}) mas FALHOU registrar na planilha: {e}"

    return (
        f"✅ Cupom **{codigo}** criado no WooCommerce (#{wc_id}): "
        f"{desconto_percentual}% até {data_validade}, dono {dono_arroba}. {reg}."
    )


@mcp.tool()
def revogar_cupom(codigo: str, motivo: str = "") -> str:
    """Revoga um cupom: muda a validade para hoje no WooCommerce (expira imediatamente)
    e anota na planilha (validade + observação 'REVOGADO').

    codigo: código do cupom a revogar
    motivo: (opcional) motivo da revogação
    """
    _require_write()
    codigo = (codigo or "").strip()
    if not codigo:
        return "Erro: informe o código do cupom."
    encontrados = _wc_get("coupons", {"code": codigo})
    if not encontrados or not isinstance(encontrados, list):
        return f"Cupom '{codigo}' não encontrado no WooCommerce."
    cid = encontrados[0]["id"]
    hoje = date.today().isoformat()
    try:
        _wc_put(f"coupons/{cid}", {"date_expires": hoje})
    except Exception as e:
        return f"Erro ao revogar no WooCommerce: {e}"

    obs = f"REVOGADO em {hoje}" + (f" — {motivo}" if motivo else "")
    try:
        ok = _sheet_revogar_cupom(codigo, hoje, obs)
        reg = "planilha atualizada" if ok else "⚠️ não achei a linha na planilha (atualize manualmente)"
    except Exception as e:
        reg = f"⚠️ revogado no WC mas falhou atualizar planilha: {e}"

    return f"✅ Cupom **{codigo}** revogado (expira em {hoje}). {reg}."


@mcp.tool()
def criar_afiliado(arroba: str) -> str:
    """Gera o link de afiliado (UTM) e registra na planilha de Afiliados. NÃO expira.

    arroba: @ da pessoa (ex.: @joao)
    """
    _require_write()
    arroba = (arroba or "").strip()
    if not arroba:
        return "Erro: informe o @ da pessoa."
    if not arroba.startswith("@"):
        arroba = "@" + arroba
    handle = arroba.lstrip("@")
    url = f"https://www.viennapet.com.br/?utm_source={handle}&utm_medium=affiliate&utm_campaign=afiliados"
    try:
        _sheet_append_afiliado([arroba, url])
        reg = "registrado na planilha"
    except Exception as e:
        reg = f"⚠️ link gerado mas FALHOU registrar na planilha: {e}"
    return f"✅ Afiliado **{arroba}** — link: {url}. {reg}."


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
    imagens   = [img["src"] for img in p.get("images", []) if img.get("src")]
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
        f"- Imagens: {chr(10).join(imagens) if imagens else '(sem imagens)'}\n"
        f"- URL: {p.get('permalink')}"
    )


@mcp.tool()
def atualizar_produto_wc(produto_id: int, nome: str = "", preco: str = "", estoque: int = -1,
                         descricao_curta: str = "", sku: str = "") -> str:
    """Atualiza campos de um produto WooCommerce. Deixe em branco os campos que não quer alterar."""
    _require_write()
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
    _require_write()
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
    _require_write()
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
    _require_write()
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
    _require_write()
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
    return HTMLResponse("v21 - tools criar_cupom/criar_afiliado/revogar_cupom + /health/sistema", status_code=200)


@mcp.custom_route("/health/sistema", methods=["GET"])
async def health_sistema(request: Request) -> JSONResponse:
    """Health check de ponta a ponta (público, sem segredos): WooCommerce, Bling,
    frete (Store API), planilhas (Service Account) e site. Evita reprocessar tudo
    manualmente — uma chamada valida o sistema inteiro."""
    def _run():
        out: dict = {}
        try:
            p = _wc_get("products", {"per_page": 1})
            out["woocommerce"] = "ok" if isinstance(p, list) else "falha"
        except Exception as e:
            out["woocommerce"] = f"erro: {str(e)[:80]}"
        try:
            d = _bling_get("/contatos", {"limite": 1})
            out["bling"] = "ok" if isinstance(d, dict) and d.get("data") is not None else "falha"
        except Exception as e:
            out["bling"] = f"erro: {str(e)[:80]}"
        try:
            r = requests.post(
                "https://www.viennapet.com.br/api/calcular-frete",
                json={"postcode": "01310100", "items": [{"id": 282, "quantity": 1}]},
                timeout=20,
            )
            rates = r.json() if r.ok else []
            paid = [x for x in rates if float(x.get("cost", 0) or 0) > 0]
            out["frete"] = f"ok ({len(rates)} opções)" if paid else "falha (sem taxa paga)"
        except Exception as e:
            out["frete"] = f"erro: {str(e)[:80]}"
        try:
            _gspread_ws(CUPONS_SHEET_ID, _CUPONS_HEADER)
            _gspread_ws(AFILIADOS_SHEET_ID, _AFILIADOS_HEADER)
            out["planilhas"] = "ok"
        except Exception as e:
            out["planilhas"] = f"erro: {str(e)[:80]}"
        try:
            s = requests.get("https://www.viennapet.com.br/", timeout=15)
            out["site"] = "ok" if s.status_code == 200 else f"http {s.status_code}"
        except Exception as e:
            out["site"] = f"erro: {str(e)[:80]}"
        return out

    checks = await anyio.to_thread.run_sync(_run)
    all_ok = all(str(v).startswith("ok") for v in checks.values())
    return JSONResponse({"status": "ok" if all_ok else "atencao", "checks": checks})


@mcp.custom_route("/bling/persist-status", methods=["GET"])
async def bling_persist_status(request: Request) -> JSONResponse:
    """Diagnóstico público: mostra se a persistência no Railway está configurada.
    NÃO expõe valores de segredos."""
    ultimo = _last_persist_result
    dica = None
    if "Not Authorized" in ultimo:
        dica = (
            "RAILWAY_API_TOKEN precisa ser um Personal Access Token "
            "(railway.app > Account Settings > API > Generate Token). "
            "Tokens de projeto/deploy NÃO têm permissão para variableUpsert. "
            "Após corrigir o token, chame POST /bling/force-persist (com Bearer auth)."
        )
    return JSONResponse({
        "RAILWAY_API_TOKEN_present":     bool(os.environ.get("RAILWAY_API_TOKEN")),
        "RAILWAY_PROJECT_ID_present":     bool(os.environ.get("RAILWAY_PROJECT_ID")),
        "RAILWAY_ENVIRONMENT_ID_present": bool(os.environ.get("RAILWAY_ENVIRONMENT_ID")),
        "RAILWAY_SERVICE_ID_present":     bool(os.environ.get("RAILWAY_SERVICE_ID")),
        "ultimo_resultado_persist":      ultimo,
        "tem_token_em_cache":            _bling_tokens_cache is not None,
        **({"dica": dica} if dica else {}),
    })


@mcp.custom_route("/bling/force-persist", methods=["POST"])
async def bling_force_persist(request: Request) -> JSONResponse:
    """Força uma nova tentativa de persistir o refresh_token atual no Railway.
    Use isso após corrigir o RAILWAY_API_TOKEN para que a rotação sobreviva
    ao próximo restart sem nova autenticação OAuth."""
    tokens = _bling_tokens_cache
    if not tokens or not tokens.get("refresh_token"):
        return JSONResponse({"ok": False, "erro": "Nenhum token em cache. Autentique via /bling/auth primeiro."}, status_code=400)
    ok = await anyio.to_thread.run_sync(lambda: _persist_refresh_token_to_railway(tokens["refresh_token"]))
    return JSONResponse({"ok": ok, "resultado": _last_persist_result})


# ── MCP OAuth2 (para claude.ai browser connector) ────────────────────────────

import hashlib
import urllib.parse as _urlparse

_auth_codes: dict[str, dict] = {}


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": _BASE_URL,
        "authorization_endpoint": f"{_BASE_URL}/oauth/authorize",
        "token_endpoint": f"{_BASE_URL}/oauth/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "response_types_supported": ["code"],
    })


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request: Request) -> RedirectResponse:
    client_id             = request.query_params.get("client_id", "")
    redirect_uri          = request.query_params.get("redirect_uri", "")
    code_challenge        = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "plain")
    state                 = request.query_params.get("state", "")

    if not redirect_uri:
        return HTMLResponse("redirect_uri obrigatorio", status_code=400)

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "challenge": code_challenge,
        "method":    code_challenge_method,
        "redirect_uri": redirect_uri,
    }
    params = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{_urlparse.urlencode(params)}")


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    if not MCP_AUTH_TOKEN:
        return JSONResponse({"error": "server_error"}, status_code=500)
    try:
        form       = await request.form()
        grant_type = form.get("grant_type", "")
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    if grant_type == "authorization_code":
        code          = form.get("code", "")
        code_verifier = form.get("code_verifier", "")
        if code not in _auth_codes:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        stored = _auth_codes.pop(code)
        method = stored.get("method", "plain")
        if method == "S256":
            digest    = hashlib.sha256(code_verifier.encode()).digest()
            challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        else:
            challenge = code_verifier
        if stored["challenge"] and challenge != stored["challenge"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        user = _users_by_id.get(stored.get("client_id", ""))
        access_token = user["token"] if user else MCP_AUTH_TOKEN
        return JSONResponse({
            "access_token": access_token,
            "token_type":   "Bearer",
            "expires_in":   86400,
        })

    elif grant_type == "client_credentials":
        client_id     = form.get("client_id", "")
        client_secret = "".join(form.get("client_secret", "").split())
        user = _users_by_id.get(client_id)
        if not user or not secrets.compare_digest(client_secret.encode(), user["token"].encode()):
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        return JSONResponse({
            "access_token": user["token"],
            "token_type":   "Bearer",
            "expires_in":   86400,
        })

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


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
    # O state vive em memória e some quando o container reinicia (ex.: redeploy durante
    # a janela de autorização). Se não encontrarmos, apenas avisamos e prosseguimos: o
    # `code` é emitido pelo Bling SÓ após o admin autorizar e é de uso único — essa é a
    # real proteção. Se o state existir e bater, consumimos normalmente.
    if state and state in _bling_pending_state:
        del _bling_pending_state[state]
    elif state:
        print(f"[bling] aviso: state '{state}' não encontrado (provável restart); prosseguindo com o code do Bling")

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


# ── Sync Route (chamada pelo Vercel após pagamento aprovado) ──────────────────

@mcp.custom_route("/sync/pedido", methods=["POST"])
async def sync_pedido_bling(request: Request) -> JSONResponse:
    """Cria pedido de venda no Bling a partir de um pedido WooCommerce aprovado."""
    try:
        body = await request.json()
        wc_order_id = body.get("wc_order_id")
        billing     = body.get("billing", {})
        items       = body.get("items", [])
        discount    = float(body.get("discount", 0) or 0)
        shipping    = float(body.get("shipping", 0) or 0)
        coupon      = body.get("coupon", "") or ""
        # Atribuição de afiliado/campanha — vai SÓ em observacoesInternas (fora da NF)
        coupon_owner = body.get("coupon_owner", "") or ""
        affiliate    = body.get("affiliate", "") or ""
        utm_source   = body.get("utm_source", "") or ""
        utm_medium   = body.get("utm_medium", "") or ""
        utm_campaign = body.get("utm_campaign", "") or ""

        if not wc_order_id or not items:
            return JSONResponse({"error": "wc_order_id e items são obrigatórios"}, status_code=400)

        def _run():
            email = billing.get("email", "")
            nome  = f"{billing.get('first_name', '')} {billing.get('last_name', '')}".strip()
            contact_id = _bling_find_or_create_contact(
                email, nome, billing.get("phone", ""), billing.get("cpf", "")
            )

            bling_items = []
            for item in items:
                bi: dict = {
                    "quantidade": item.get("quantity", 1),
                    "valor":      float(item.get("unit_price", 0)),
                    "tipo":       "P",
                    "unidade":    "UN",
                }
                produto_id = _bling_find_product_by_sku(item.get("sku", ""))
                if produto_id:
                    bi["produto"] = {"id": produto_id}
                else:
                    bi["descricao"] = item.get("name", "Produto")
                bling_items.append(bi)

            obs = f"Pedido via site novo (WC #{wc_order_id})"
            if coupon:
                obs += f" | Cupom: {coupon}"
            if shipping:
                obs += f" | Frete: R$ {shipping:.2f}"

            # Observações Internas (NÃO saem na NF) — atribuição completa p/ consistência.
            # Cupom também entra aqui (além de observacoes) conforme pedido.
            internas = []
            if coupon:       internas.append(f"Cupom: {coupon}")
            if coupon_owner: internas.append(f"Dono do cupom: {coupon_owner}")
            if affiliate:    internas.append(f"Afiliado: {affiliate}")
            if utm_source:   internas.append(f"utm_source: {utm_source}")
            if utm_medium:   internas.append(f"utm_medium: {utm_medium}")
            if utm_campaign: internas.append(f"utm_campaign: {utm_campaign}")

            payload: dict = {
                "contato":             {"id": contact_id},
                "data":                date.today().isoformat(),
                "itens":               bling_items,
                "numeroPedidoCompra":  str(wc_order_id),
                "observacoes":         obs,
            }
            if internas:
                payload["observacoesInternas"] = " | ".join(internas)
            # Desconto do cupom: itens vão a preço cheio e o abatimento entra aqui,
            # para o total do Bling bater com o total pago no site.
            if discount > 0:
                payload["desconto"] = {"valor": round(discount, 2), "unidade": "REAL"}
            # Frete (quando houver): reflete no transporte do pedido Bling
            if shipping > 0:
                payload["transporte"] = {"frete": round(shipping, 2)}

            pedido = _bling_post("/pedidos/vendas", payload).get("data", {})
            return pedido.get("id")

        bling_order_id = await anyio.to_thread.run_sync(_run)
        print(f"[sync_pedido_bling] WC #{wc_order_id} → Bling #{bling_order_id}")
        return JSONResponse({"ok": True, "bling_order_id": bling_order_id, "wc_order_id": wc_order_id})

    except Exception as e:
        print(f"[sync_pedido_bling] error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Bling Tools ───────────────────────────────────────────────────────────────

@mcp.tool()
def autenticar_bling() -> str:
    """Inicia o fluxo OAuth com o Bling! e salva os tokens localmente."""
    _require_write()
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
    token = _bling_get_token()
    # Endpoint correto: /estoques/saldos — URL manual para preservar colchetes literais
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
    _require_write()
    if not preco and not nome and not codigo:
        return "Nenhum campo informado para atualizar."
    produto = _bling_get(f"/produtos/{id_produto}").get("data", {})
    if not produto:
        return f"Produto {id_produto} não encontrado."
    # Produto variável: GET simples retorna variacoes=[]. Usar endpoint específico.
    if produto.get("formato") == "V":
        var_data = _bling_get(f"/produtos/variacoes/{id_produto}")
        produto_completo = var_data.get("data", {})
        variacoes = produto_completo.get("variacoes", [])
        if not variacoes:
            return (
                f"Produto [{id_produto}] é variável (formato=V) mas não possui variações "
                f"cadastradas inline — use o ID de uma variação específica em vez do produto pai."
            )
        produto = produto_completo
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
    _require_write()
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


# ── Admin API ─────────────────────────────────────────────────────────────────

@mcp.custom_route("/admin/users", methods=["GET", "POST"])
async def admin_users(request: Request) -> JSONResponse:
    caller = request.scope.get("_user", {})
    if caller.get("role") != "write":
        return JSONResponse({"error": "Requer permissão write"}, status_code=403)

    if request.method == "GET":
        users = [{"id": u["id"], "role": u["role"]} for u in _users_by_id.values()]
        return JSONResponse(users)

    # POST — create user
    try:
        body = await request.json()
        uid  = body.get("id", "").strip()
        role = body.get("role", "read")
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if not uid:
        return JSONResponse({"error": "id é obrigatório"}, status_code=400)
    if uid in _users_by_id:
        return JSONResponse({"error": f"Usuário '{uid}' já existe"}, status_code=409)
    if role not in ("read", "write"):
        role = "read"
    token = secrets.token_urlsafe(32)
    new_user = {"id": uid, "role": role, "token": token}
    _users_by_token[token] = new_user
    _users_by_id[uid]      = new_user
    return JSONResponse({"id": uid, "token": token, "role": role}, status_code=201)


@mcp.custom_route("/admin/users/{user_id}", methods=["DELETE"])
async def admin_delete_user(request: Request) -> JSONResponse:
    caller = request.scope.get("_user", {})
    if caller.get("role") != "write":
        return JSONResponse({"error": "Requer permissão write"}, status_code=403)
    uid = request.path_params.get("user_id", "")
    if uid == "admin":
        return JSONResponse({"error": "Não é possível deletar o admin"}, status_code=400)
    target = _users_by_id.pop(uid, None)
    if not target:
        return JSONResponse({"error": f"Usuário '{uid}' não encontrado"}, status_code=404)
    _users_by_token.pop(target["token"], None)
    return JSONResponse({"deleted": uid})


@mcp.custom_route("/admin/export", methods=["GET"])
async def admin_export(request: Request) -> JSONResponse:
    caller = request.scope.get("_user", {})
    if caller.get("role") != "write":
        return JSONResponse({"error": "Requer permissão write"}, status_code=403)
    users = [
        {"id": u["id"], "token": u["token"], "role": u["role"]}
        for u in _users_by_id.values()
        if u["id"] != "admin"
    ]
    return JSONResponse(users)


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(_AuthMiddleware(mcp.sse_app()), host="0.0.0.0", port=_PORT)
