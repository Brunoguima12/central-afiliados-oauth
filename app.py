
import os
import secrets
import json
import urllib.parse
import urllib.request
import urllib.error

from flask import Flask, request, redirect, session, jsonify

app = Flask(__name__)

# Chave secreta cadastrada nas variáveis de ambiente do Render
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")

# Configuração segura da sessão para o fluxo OAuth
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

CLIENT_ID = os.environ.get("MERCADOLIVRE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("MERCADOLIVRE_CLIENT_SECRET", "").strip()

REDIRECT_URI = (
    "https://bruno-central-oauth-2026.onrender.com/oauth/callback"
)

AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"


@app.get("/")
def home():
    if not app.secret_key:
        return (
            "Erro de configuração: FLASK_SECRET_KEY não cadastrada no Render.",
            500,
        )

    if not CLIENT_ID or not CLIENT_SECRET:
        return (
            "Erro de configuração: confira as variáveis "
            "MERCADOLIVRE_CLIENT_ID e MERCADOLIVRE_CLIENT_SECRET.",
            500,
        )

    return """
    <!doctype html>
    <html lang="pt-br">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Central de Afiliados</title>
    </head>
    <body style="font-family:Arial,sans-serif;
                 max-width:720px;margin:60px auto;padding:20px">
        <h1>Central de Afiliados</h1>
        <p>Conecte sua conta do Mercado Livre para iniciar a integração.</p>
        <a href="/oauth/login"
           style="display:inline-block;background:#3483fa;color:white;
                  padding:12px 20px;text-decoration:none;border-radius:6px">
            Conectar ao Mercado Livre
        </a>
    </body>
    </html>
    """


@app.get("/oauth/login")
def oauth_login():
    if not app.secret_key or not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({
            "status": "erro",
            "mensagem": "Confira as variáveis de ambiente no Render.",
        }), 500

    # Gera um state novo para esta tentativa
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    authorization_url = AUTH_URL + "?" + urllib.parse.urlencode(params)
    response = redirect(authorization_url)

    # Evita manter uma cópia antiga do cookie no navegador
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/oauth/callback")
def oauth_callback():
    error = request.args.get("error")

    if error:
        return jsonify({
            "status": "erro_de_autorizacao",
            "mensagem": "O Mercado Livre não autorizou a conexão.",
            "detalhe": error,
        }), 400

    code = request.args.get("code")
    received_state = request.args.get("state")

    if not code:
        return jsonify({
            "status": "erro",
            "mensagem": (
                "Código de autorização não recebido. "
                "Acesse a página inicial e clique em Conectar."
            ),
        }), 400

    # Recupera o state da sessão iniciada antes do redirecionamento
    expected_state = session.pop("oauth_state", None)

    if not expected_state or not received_state:
        response = jsonify({
            "status": "erro_validacao_state",
            "mensagem": (
                "A sessão OAuth não foi encontrada. "
                "Volte à página inicial e tente novamente."
            ),
            "diagnostico": "state_ausente_ou_sessao_perdida",
        })
        response.status_code = 400
        response.headers["Cache-Control"] = "no-store"
        return response

    if not secrets.compare_digest(expected_state, received_state):
        response = jsonify({
            "status": "erro_validacao_state",
            "mensagem": (
                "A validação de segurança falhou. "
                "Inicie uma nova conexão pela página inicial."
            ),
            "diagnostico": "state_diferente_do_esperado",
        })
        response.status_code = 400
        response.headers["Cache-Control"] = "no-store"
        return response

    # Troca o código temporário pelos tokens OAuth
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as result:
            token_response = json.loads(
                result.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:
        # Extrai somente mensagens de erro; nunca devolve tokens
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {}

        safe_error = body.get("error", "erro_http")
        safe_description = body.get(
            "error_description",
            "O Mercado Livre recusou a troca do código pelo token.",
        )

        response = jsonify({
            "status": "erro_na_troca_do_token",
            "http_status": exc.code,
            "erro": safe_error,
            "mensagem": safe_description,
            "orientacao": (
                "Confira Client ID, Client Secret, Redirect URI "
                "e se o código de autorização é novo."
            ),
        })
        response.status_code = 400
        response.headers["Cache-Control"] = "no-store"
        return response

    except (urllib.error.URLError, TimeoutError):
        return jsonify({
            "status": "erro_de_conexao",
            "mensagem": (
                "Não foi possível conectar à API do Mercado Livre. "
                "Tente novamente."
            ),
        }), 502

    except (ValueError, UnicodeDecodeError):
        return jsonify({
            "status": "erro",
            "mensagem": "A resposta da API não pôde ser interpretada.",
        }), 502

    # Não exibe nem salva os tokens nesta etapa
    if not token_response.get("access_token"):
        return jsonify({
            "status": "erro",
            "mensagem": (
                "A API respondeu, mas não retornou um access token."
            ),
        }), 502

    response = jsonify({
        "status": "conectado",
        "mensagem": (
            "Autorização concluída com sucesso. "
            "Os tokens ainda não foram armazenados."
        ),
        "usuario_id": token_response.get("user_id"),
        "expira_em_segundos": token_response.get("expires_in"),
        "proxima_etapa": (
            "Configurar armazenamento seguro e renovação dos tokens."
        ),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
    )
